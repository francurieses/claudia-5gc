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

	"github.com/francurieses/5gc-rel17/nf/bsf/internal/config"
	"github.com/francurieses/5gc-rel17/nf/bsf/internal/store"
	"github.com/francurieses/5gc-rel17/shared/logging"
	"github.com/francurieses/5gc-rel17/shared/observability/metrics"
)

// Server is the BSF Nbsf_Management SBI server.
type Server struct {
	cfg     *config.Config
	logger  *slog.Logger
	store   *store.Store
	httpSrv *http.Server
}

// New constructs the BSF SBI server. Call Start or Handler() to serve requests.
func New(cfg *config.Config, logger *slog.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		logger: logger,
		store:  store.New(),
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

	var binding store.PcfBinding
	if err := json.NewDecoder(r.Body).Decode(&binding); err != nil {
		// A malformed request body is MANDATORY_IE_INCORRECT, not _MISSING.
		// Ref: TS 29.500 §5.2.7.2 (ProblemDetails cause for a syntactically invalid body).
		log.Warn("register: malformed JSON body",
			"result", "REJECT", "cause", "MANDATORY_IE_INCORRECT", "error", err)
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingRegister", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid JSON body")
		return
	}

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
// GET /nbsf-management/v1/pcfBindings?ipv4Addr=…
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

	// At least one binding-identifying parameter is required.
	// Ref: TS 29.521 §5.2.2.4.4
	if !q.HasAnyParam() {
		log.Warn("discover: no query parameter supplied",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingDiscovery", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"at least one binding-identifying query parameter is required (TS 29.521 §5.2.2.4)")
		return
	}

	log = log.With(
		"ipv4_addr", q.Ipv4Addr,
		"supi", q.Supi,
		"dnn", q.Dnn,
	)

	binding, found := s.store.FindByQuery(q)
	if !found {
		log.Info("discover: no binding found",
			"result", "REJECT")
		metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingDiscovery", "REJECT").Inc()
		s.problem(w, http.StatusNotFound, "",
			"no PCF binding matches the given query parameters (TS 29.521 §5.2.2.4.4)")
		return
	}

	log.Info("discover: binding found",
		"binding_id", binding.BindingID,
		"pcf_fqdn", binding.PcfFqdn,
		"pcf_id", binding.PcfId,
		"result", "OK",
	)
	metrics.ProcedureTotal.WithLabelValues("BSF", "PcfBindingDiscovery", "OK").Inc()

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
