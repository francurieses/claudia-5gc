// Package server implements the Nbsf_Management SBI server for the BSF.
//
// Endpoints (3GPP TS 29.521 v17):
//
//	POST   /nbsf-management/v1/pcfBindings                      Nbsf_Management_Register
//	DELETE /nbsf-management/v1/pcfBindings/{bindingId}          Nbsf_Management_DeRegister
//	GET    /nbsf-management/v1/pcfBindings                      Nbsf_Management_Discovery
//	GET    /healthz                                              Liveness probe
//	GET    /metrics                                              Prometheus metrics
//
// All SBI endpoints are served over HTTP/2 + mTLS (TS 29.500 §4.4.1).
// In-process tests use the plain-HTTP handler returned by Handler().
//
// Ref: TS 29.521 §5, TS 23.501 §6.2.16
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/bsf/internal/config"
	bsfsbi "github.com/francurieses/claudia-5gc/nf/bsf/internal/sbi"
	"github.com/francurieses/claudia-5gc/nf/bsf/internal/store"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// Server is the BSF Nbsf_Management SBI server.
type Server struct {
	cfg     *config.Config
	logger  *slog.Logger
	store   *store.Store
	httpSrv *http.Server

	// profile gates the supportedFeatures wire behaviour (decisions D1/D2,
	// dev/REL19_PROGRAM.md §2); nil behaves as rel17.
	profile *capability.Profile
	// cat is the Nbsf_Management producer catalog.
	cat *features.Catalog
}

// Attribute / parameter names of the Nbsf_Management supported-features value.
// Ref: TS 29.521 §5.8; PcfBinding.suppFeat and the discovery query "supp-feat"
// (specs/3gpp-openapi TS29521_Nbsf_Management.yaml).
const (
	// attrSuppFeat is the JSON attribute name of the features value.
	attrSuppFeat = "suppFeat"
	// paramSuppFeat is the invalidParams "param" for a bad suppFeat: a JSON
	// Pointer to the attribute (TS 29.571 §5.2.4.6).
	paramSuppFeat = "/" + attrSuppFeat
	// querySuppFeat is the optional discovery query parameter.
	querySuppFeat = "supp-feat"
	// causeMandatoryQueryParamMissing is the ProblemDetails cause for a missing
	// mandatory query parameter. Ref: TS 29.500 §5.2.7.2 Table 5.2.7.2-1.
	causeMandatoryQueryParamMissing = "MANDATORY_QUERY_PARAM_MISSING"
	// paramQuerySuppFeat is the invalidParams "param" for a bad query value
	// ("query <name>", TS 29.571 §5.2.4.6).
	paramQuerySuppFeat = "query " + querySuppFeat
)

// SetProfile wires the release profile used for supportedFeatures negotiation.
// Must be called before Start(). Ref: TS 29.500 §6.6.2.
func (s *Server) SetProfile(p *capability.Profile) { s.profile = p }

// SetCatalog replaces the Nbsf_Management catalog (tests inject catalogs with
// Implemented entries); nil restores the default. Must be called before Start().
func (s *Server) SetCatalog(c *features.Catalog) {
	if c == nil {
		c = bsfsbi.NbsfManagementCatalog()
	}
	s.cat = c
}

// New constructs the BSF SBI server. Call Start or Handler() to serve requests.
func New(cfg *config.Config, logger *slog.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		logger: logger,
		store:  store.New(),
		cat:    bsfsbi.NbsfManagementCatalog(),
	}

	mux := http.NewServeMux()
	// Nbsf_Management routes — TS 29.521 §5.2
	mux.HandleFunc("POST /nbsf-management/v1/pcfBindings", s.handleRegister)
	mux.HandleFunc("DELETE /nbsf-management/v1/pcfBindings/{bindingId}", s.handleDeregister)
	mux.HandleFunc("GET /nbsf-management/v1/pcfBindings", s.handleDiscover)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.Handle("GET /metrics", promhttp.Handler())

	s.httpSrv = &http.Server{
		Addr:              cfg.SBI.Address,
		Handler:           s.middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// Handler returns the HTTP handler for in-process testing (no TLS / h2c).
// Use this as the test seam: httptest.NewServer(srv.Handler()).
func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }

// Start starts the SBI server. If TLS cert/key are configured, it listens
// with mTLS + HTTP/2 (h2 ALPN). Otherwise it falls back to plain h2c.
//
// ALPN invariant: TLSConfig.NextProtos = ["h2"] is set BEFORE ConfigureServer.
// Ref: TS 29.500 §4.4.2 — SBA always mTLS. See docs/memory/http2_alpn_conformance.md.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutCtx)
	}()

	if s.cfg.SBI.TLS.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.SBI.TLS.CertFile, s.cfg.SBI.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("bsf: server: load TLS cert: %w", err)
		}
		caPEM, err := os.ReadFile(s.cfg.SBI.TLS.CAFile)
		if err != nil {
			return fmt.Errorf("bsf: server: load CA: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
			// NextProtos MUST be set before ConfigureServer (ALPN invariant).
			// Ref: docs/memory/http2_alpn_conformance.md
			NextProtos: []string{"h2"},
		}
		s.httpSrv.TLSConfig = tlsCfg
		if err := http2.ConfigureServer(s.httpSrv, &http2.Server{}); err != nil {
			return fmt.Errorf("bsf: server: configure http2: %w", err)
		}
		s.logger.Info("BSF SBI listening (mTLS + HTTP/2)",
			"addr", s.cfg.SBI.Address,
			"service", "nbsf-management",
			"spec_ref", "TS 29.521 §5",
		)
		if err := s.httpSrv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("bsf: server: listen: %w", err)
		}
		return nil
	}

	// No TLS — use h2c for in-process functional tests.
	s.httpSrv.Handler = h2c.NewHandler(s.httpSrv.Handler, &http2.Server{})
	s.logger.Info("BSF SBI listening (plain h2c — no TLS configured)",
		"addr", s.cfg.SBI.Address,
		"service", "nbsf-management",
	)
	if err := s.httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("bsf: server: listen: %w", err)
	}
	return nil
}

// ServeH2C starts the server on the given pre-bound listener using plain HTTP/2 (h2c).
// Intended for in-process functional tests that bind their own listener.
func (s *Server) ServeH2C(ln net.Listener) error {
	h2Srv := &http2.Server{}
	handler := h2c.NewHandler(s.httpSrv.Handler, h2Srv)
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	return srv.Serve(ln)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// ---- middleware ----------------------------------------------------------------

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corr := r.Header.Get("X-Correlation-Id")
		if corr == "" {
			corr = strconv.FormatInt(time.Now().UnixNano(), 36)
			r.Header.Set("X-Correlation-Id", corr)
		}
		w.Header().Set("X-Correlation-Id", corr)
		next.ServeHTTP(w, r)
	})
}

// ---- Register (POST /nbsf-management/v1/pcfBindings) --------------------------

// handleRegister implements Nbsf_Management_Register.
// POST /nbsf-management/v1/pcfBindings
// Ref: TS 29.521 §5.2.2.2
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "PcfBindingRegister").With(
		"nf", "BSF",
		"interface", "Nbsf",
		"direction", "IN",
		"spec_ref", "TS 29.521 §5.2.2.2",
	)

	peerNF := features.PeerNFTypeFromUserAgent(r.UserAgent(), "PCF")
	var binding store.PcfBinding
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&binding); err != nil {
		if features.IsTypeErrorOn(err, attrSuppFeat) {
			s.rejectSuppFeat(ctx, w, peerNF, "<non-string>", err)
			return
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			payloadTooLarge(log, w)
			return
		}
		// A malformed request body is MANDATORY_IE_INCORRECT, not _MISSING.
		// Ref: TS 29.500 §5.2.7.2 (ProblemDetails cause for a syntactically invalid body).
		log.Warn("register: malformed JSON body",
			"result", "REJECT", "cause", "MANDATORY_IE_INCORRECT", "error", err)
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingRegister", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid JSON body")
		return
	}

	// suppFeat must be schema-valid before any state is touched.
	// Ref: TS 29.500 §5.2.7.2, §6.6.2.
	if err := features.Validate(binding.SuppFeat); err != nil {
		s.rejectSuppFeat(ctx, w, peerNF, binding.SuppFeat, err)
		return
	}
	// Producer side (decision D1): the intersection, absent under rel17 when
	// the request had none, "0" under rel19. The consumer's value is replaced
	// by the negotiated one on the stored resource.
	// Ref: TS 29.521 §5.8; TS 29.500 §6.6.2.
	peerSuppFeat := binding.SuppFeat
	suppAnswer, suppSet := features.Answer(s.cat, s.profile, peerSuppFeat)
	binding.SuppFeat, binding.Features = suppAnswer, suppSet

	// Validate mandatory IEs: dnn and snssai are always required.
	// Ref: TS 29.521 §5.2.2.2 — dnn (M), snssai (M), plus at least one IP/MAC key.
	if binding.Dnn == "" {
		log.Warn("register: mandatory IE dnn missing",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingRegister", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"dnn is mandatory (TS 29.521 §6.2.6)")
		return
	}
	// snssai.sst == 0 is a valid value in some specs but SST=0 is reserved; treat
	// a completely absent snssai as missing by checking if dnn is set but snssai is zero.
	// We check that at least the sst field has been explicitly provided (non-zero sst
	// or non-empty sd is sufficient to confirm the snssai was present in JSON).
	// For simplicity per the feature spec, require snssai.sst to be non-zero.
	if binding.Snssai.Sst == 0 {
		log.Warn("register: mandatory IE snssai missing or sst=0",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingRegister", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"snssai (sst) is mandatory (TS 29.521 §6.2.6)")
		return
	}
	// At least one of ipv4Addr / ipv6Prefix / macAddr48 is required.
	// Ref: TS 29.521 §6.2.6 (conditional — at least one IP/MAC address key must be present)
	if binding.Ipv4Addr == "" && binding.Ipv6Prefix == "" && binding.MacAddr48 == "" {
		log.Warn("register: no IP/MAC address key provided",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingRegister", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"at least one of ipv4Addr, ipv6Prefix, macAddr48 is required")
		return
	}
	// At least one of pcfFqdn / pcfIpEndPoints must be present so the consumer can reach the PCF.
	// Ref: TS 29.521 §6.2.6
	if binding.PcfFqdn == "" && len(binding.PcfIpEndPoints) == 0 {
		log.Warn("register: no PCF endpoint provided (pcfFqdn or pcfIpEndPoints required)",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingRegister", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"at least one of pcfFqdn, pcfIpEndPoints is required (TS 29.521 §6.2.6)")
		return
	}

	// Mint a bindingId (UUID).
	binding.BindingID = uuid.NewString()

	created, ok := s.store.Create(&binding)
	if !ok {
		// Duplicate binding for this (ipv4Addr, ipDomain) key.
		log.Warn("register: duplicate binding detected",
			"result", "REJECT", "cause", "EXISTING_BINDING_INFO_FOUND",
			"ipv4_addr", binding.Ipv4Addr,
			"dnn", binding.Dnn,
		)
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingRegister", "REJECT").Inc()
		s.problem(w, http.StatusForbidden, "EXISTING_BINDING_INFO_FOUND",
			"a binding already exists for the given address key (TS 29.521 §5.2.2.2.4)")
		return
	}

	// Request accepted: record the negotiation (TS 29.500 §6.6.2).
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "BSF",
		Interface: "Nbsf", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.cat.Supported(s.profile), Peer: peerSuppFeat,
		PeerPresent: peerSuppFeat != "", Negotiated: suppSet,
	})

	// Build the Location header.
	// apiRoot = https://<bsfFqdn or bsfAddr>/nbsf-management/v1
	fqdn := s.cfg.SBI.FQDN
	if fqdn == "" {
		fqdn = r.Host
	}
	location := fmt.Sprintf("https://%s/nbsf-management/v1/pcfBindings/%s", fqdn, created.BindingID)

	log.Info("register: PCF binding created",
		"binding_id", created.BindingID,
		"supi", created.Supi,
		"ipv4_addr", created.Ipv4Addr,
		"dnn", created.Dnn,
		"pcf_fqdn", created.PcfFqdn,
		"result", "OK",
	)
	metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingRegister", "OK").Inc()
	metrics.BSFBindingsActive.Inc()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

// ---- Deregister (DELETE /nbsf-management/v1/pcfBindings/{bindingId}) ----------

// handleDeregister implements Nbsf_Management_DeRegister.
// DELETE /nbsf-management/v1/pcfBindings/{bindingId}
// Ref: TS 29.521 §5.2.2.3
func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request) {
	bindingID := r.PathValue("bindingId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "PcfBindingDeregister").With(
		"nf", "BSF",
		"interface", "Nbsf",
		"direction", "IN",
		"spec_ref", "TS 29.521 §5.2.2.3",
		"binding_id", bindingID,
	)

	if !s.store.Delete(bindingID) {
		log.Warn("deregister: binding not found",
			"result", "REJECT")
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingDeregister", "REJECT").Inc()
		s.problem(w, http.StatusNotFound, "",
			fmt.Sprintf("no binding found for bindingId %s (TS 29.521 §5.2.2.3.4)", bindingID))
		return
	}

	log.Info("deregister: PCF binding removed",
		"result", "OK",
	)
	metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingDeregister", "OK").Inc()
	metrics.BSFBindingsActive.Dec()
	w.WriteHeader(http.StatusNoContent)
}

// ---- Discovery (GET /nbsf-management/v1/pcfBindings) --------------------------

// handleDiscover implements Nbsf_Management_Discovery.
// GET /nbsf-management/v1/pcfBindings?ipv4Addr=… (200 match, 204 no match)
// Ref: TS 29.521 §5.2.2.4
func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "PcfBindingDiscovery").With(
		"nf", "BSF",
		"interface", "Nbsf",
		"direction", "IN",
		"spec_ref", "TS 29.521 §5.2.2.4",
	)

	q := parseDiscoveryQuery(r)

	// At least one binding-identifying parameter is required; a missing query
	// parameter is MANDATORY_QUERY_PARAM_MISSING (not an IE of a body).
	// Ref: TS 29.521 §5.2.2.4.4; TS 29.500 §5.2.7.2 (Table 5.2.7.2-1)
	if !q.HasAnyParam() {
		log.Warn("discover: no query parameter supplied",
			"result", "REJECT", "cause", causeMandatoryQueryParamMissing)
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingDiscovery", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, causeMandatoryQueryParamMissing,
			"at least one binding-identifying query parameter is required (TS 29.521 §5.2.2.4)")
		return
	}

	// Optional "supp-feat" query parameter ("may include", TS 29.500 §6.6.2):
	// a non-hex value is OPTIONAL_QUERY_PARAM_INCORRECT. Absent = no
	// negotiation on this GET.
	peerSuppFeat := r.URL.Query().Get(querySuppFeat)
	peerNF := features.PeerNFTypeFromUserAgent(r.UserAgent(), "NEF")
	if err := features.Validate(peerSuppFeat); err != nil {
		features.LogNegotiation(ctx, s.logger, features.Negotiation{
			NF:        "BSF",
			Interface: "Nbsf", Direction: "IN", PeerNF: peerNF,
			SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: features.CauseOptionalQueryParamIncorrect,
			Local: s.cat.Supported(s.profile), Peer: peerSuppFeat, PeerPresent: true,
		}, "error", err)
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingDiscovery", "REJECT").Inc()
		s.problemInvalidParam(w, features.CauseOptionalQueryParamIncorrect, paramQuerySuppFeat,
			"supp-feat is not a valid hexadecimal string")
		return
	}

	log = log.With(
		"ipv4_addr", q.Ipv4Addr,
		"supi", q.Supi,
		"dnn", q.Dnn,
	)

	binding, found := s.store.FindByQuery(q)
	if !found {
		// No match is not an error: 204 No Content, empty body.
		// Ref: TS 29.521 §4.2.4.2; Rel-17 YAML GetPCFBindings response '204'.
		log.Info("discover: no binding found",
			"result", "OK", "status", http.StatusNoContent)
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingDiscovery", "OK").Inc()
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.Info("discover: binding found",
		"binding_id", binding.BindingID,
		"pcf_fqdn", binding.PcfFqdn,
		"pcf_id", binding.PcfId,
		"result", "OK",
	)
	metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingDiscovery", "OK").Inc()

	// The GET response carries suppFeat when the query carried supp-feat
	// (TS 29.521 §5.6.2 PcfBinding.suppFeat): the BSF catalog intersected with
	// the consumer's value. Otherwise the stored (negotiated) value is
	// returned as is.
	if peerSuppFeat != "" {
		ans, set := features.Answer(s.cat, s.profile, peerSuppFeat)
		binding.SuppFeat, binding.Features = ans, set
		features.LogNegotiation(ctx, s.logger, features.Negotiation{
			NF:        "BSF",
			Interface: "Nbsf", Direction: "IN", PeerNF: peerNF,
			SpecRef: features.SpecRef, Result: "OK",
			Local: s.cat.Supported(s.profile), Peer: peerSuppFeat,
			PeerPresent: true, Negotiated: set,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(binding)
}

// ---- Health -------------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

// ---- helpers ------------------------------------------------------------------

// problem writes a 3GPP-style application/problem+json response.
// When cause is empty (e.g. 404 with no specific cause per TS 29.521 §5.2.2.3.4),
// the cause field is omitted from the body.
// Ref: TS 29.500 §5.2.4 (ProblemDetails), TS 29.571 §5.2.7
func (s *Server) problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{
		"status": status,
		"detail": detail,
	}
	if cause != "" {
		body["cause"] = cause
	}
	_ = json.NewEncoder(w).Encode(body)
}

// rejectSuppFeat answers a schema-invalid suppFeat with 400 INVALID_MSG_FORMAT
// and invalidParams[{param: /suppFeat}] and logs the REJECT negotiation record.
// Ref: TS 29.500 §5.2.7.2; TS 29.571 §5.2.4.6.
func (s *Server) rejectSuppFeat(ctx context.Context, w http.ResponseWriter, peerNF, shown string, cause error) {
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "BSF",
		Interface: "Nbsf", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: features.CauseInvalidMsgFormat,
		Local: s.cat.Supported(s.profile), Peer: shown, PeerPresent: true,
	}, "error", cause)
	metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingRegister", "REJECT").Inc()
	s.problemInvalidParam(w, features.CauseInvalidMsgFormat, paramSuppFeat,
		"suppFeat is not a valid hexadecimal string")
}

// problemInvalidParam writes a 400 ProblemDetails with one invalidParams entry.
// Ref: TS 29.571 §5.2.4.1 (ProblemDetails), §5.2.4.6 (InvalidParam).
func (s *Server) problemInvalidParam(w http.ResponseWriter, cause, param, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusBadRequest,
		"cause":  cause,
		"detail": detail,
		"invalidParams": []map[string]string{
			{"param": param},
		},
	})
}

// payloadTooLarge answers a body over features.MaxRequestBodyBytes with 413 and
// a ProblemDetails without a cause (no 413 cause is defined), after logging one
// REJECT record and counting it.
// Ref: TS 29.500 §5.2.7.1; TS 29.571 §5.2.4.1.
func payloadTooLarge(log *slog.Logger, w http.ResponseWriter) {
	log.Warn("request body too large",
		"result", "REJECT", "cause", "PAYLOAD_TOO_LARGE")
	metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingRegister", "REJECT").Inc()
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusRequestEntityTooLarge,
		"detail": "request body too large",
	})
}

// parseDiscoveryQuery extracts Nbsf_Management_Discovery query parameters from r.
// Ref: TS 29.521 §5.2.2.4.3.1
func parseDiscoveryQuery(r *http.Request) *store.DiscoveryQuery {
	q := &store.DiscoveryQuery{}
	params := r.URL.Query()
	q.Ipv4Addr = params.Get("ipv4Addr")
	q.Ipv6Prefix = params.Get("ipv6Prefix")
	q.MacAddr48 = params.Get("macAddr48")
	q.Supi = params.Get("supi")
	q.Gpsi = params.Get("gpsi")
	q.Dnn = params.Get("dnn")
	q.IpDomain = params.Get("ipDomain")
	// snssai is passed as a composite query param snssai={"sst":1,"sd":"000001"} or
	// as individual params sst= and sd=. The 3GPP YAML uses an object encoding; for
	// simplicity we support both the JSON-encoded snssai param and individual sst/sd params.
	if raw := params.Get("snssai"); raw != "" {
		var sn store.Snssai
		if err := json.Unmarshal([]byte(raw), &sn); err == nil {
			q.Snssai = &sn
		}
	} else if sst := params.Get("sst"); sst != "" {
		sn := &store.Snssai{}
		if v, err := strconv.Atoi(sst); err == nil {
			sn.Sst = v
		}
		sn.Sd = params.Get("sd")
		q.Snssai = sn
	}
	return q
}
