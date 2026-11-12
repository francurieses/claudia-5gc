// Package server implements the NEF Nnef_AFsessionWithQoS SBI server.
//
// Northbound routes (TS 29.522 §4.4.13 — all require OAuth2 bearer token):
//
//	POST   /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions              Create
//	GET    /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subId}      Get
//	DELETE /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subId}      Delete
//	GET    /healthz                                                            Liveness
//	GET    /metrics                                                            Prometheus
//
// All SBI endpoints are served over HTTP/2 + mTLS (TS 29.500 §4.4.1).
// Northbound additionally requires an OAuth2 bearer token with scope
// "3gpp-as-session-with-qos" (TS 29.522 §6).
//
// Ref: TS 29.522, TS 23.501 §6.2.5, TS 29.514, TS 29.521
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/nef/internal/config"
	nefsbi "github.com/francurieses/claudia-5gc/nf/nef/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	oauth2pkg "github.com/francurieses/claudia-5gc/shared/oauth2"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// requiredScope is the OAuth2 scope required on all northbound Nnef requests.
// Ref: TS 29.522 §6
const requiredScope = "3gpp-as-session-with-qos"

// AsSessionWithQoSSubscription is the resource created/returned by the NEF
// for an AF's AsSessionWithQoS request. Stored in the subscription map.
// Ref: TS 29.522 §5.14.2.1.2
//
// oapi: TS29122_AsSessionWithQoS.yaml#/components/schemas/AsSessionWithQoSSubscription
type AsSessionWithQoSSubscription struct {
	// Self is the resource URI (the Location header value), set under the rel19
	// (spec-literal) profile only: it is the spec home of the subscriptionId and
	// scsAsId path segments. Ref: TS 29.122 AsSessionWithQoSSubscription.self
	Self string `json:"self,omitempty"`
	// SubscriptionID is the NEF-minted unique identifier for this subscription.
	// Internal record field; under rel17 / no profile it is also sent as the
	// project member "subscriptionId" (see MarshalJSON), under rel19 only via Self.
	SubscriptionID string `json:"-"`
	// ScsAsId is the AF/SCS path segment identifier. Same wire rule as SubscriptionID.
	ScsAsId string `json:"-"`
	// UeIpv4Addr is the UE IPv4 address — the BSF discovery key.
	UeIpv4Addr string `json:"ueIpv4Addr,omitempty"`
	// UeIpv6Addr is the UE IPv6 address (alternative to UeIpv4Addr).
	UeIpv6Addr string `json:"ueIpv6Addr,omitempty"`
	// AfAppId is the application identifier supplied by the AF.
	// oapi-ext: the spec home exterAppId is gated by feature AppId, which the NEF does not offer (known deviation, nef/CLAUDE.md §12); afAppId is an AF-side input the NEF maps to the PCF afAppId.
	AfAppId string `json:"afAppId,omitempty"`
	// QosReference is the pre-provisioned QoS profile reference (mandatory).
	// Ref: TS 29.522 §5.14.2.1.2
	QosReference string `json:"qosReference,omitempty"`
	// AltQoSReferences are ordered fallback QoS references. Accepted, baseline uses first only.
	AltQoSReferences []string `json:"altQoSReferences,omitempty"`
	// NotificationDestination is the AF callback URI for QoS notifications.
	// Stored but not used in the baseline (notifications out of scope).
	NotificationDestination string `json:"notificationDestination,omitempty"`
	// Dnn optionally narrows BSF discovery.
	Dnn string `json:"dnn,omitempty"`
	// Snssai optionally narrows BSF discovery.
	Snssai *BindingSnssai `json:"snssai,omitempty"`
	// FlowInfo describes the IP flow(s) the QoS applies to.
	FlowInfo []FlowInfo `json:"flowInfo,omitempty"`
	// SupportedFeatures is the wire representation of the features negotiated
	// for this resource (TS 29.500 §6.6.2: the producer includes the
	// intersection in the resource representation it returns). It is always
	// overwritten by the server from features.Answer, never trusted from the AF.
	// The typed negotiated Set lives in subscriptionRecord.negotiated.
	SupportedFeatures string `json:"supportedFeatures,omitempty"`

	// Internal fields — not serialised to the AF.
	// specWire selects the rel19 representation (self instead of
	// subscriptionId/scsAsId); set on the answer copy by wireFor.
	specWire bool
}

// wireFor returns a copy that marshals in the spec-literal shape when
// specLiteral (rel19 profile) is true and in the frozen rel17 shape otherwise.
func (a AsSessionWithQoSSubscription) wireFor(specLiteral bool) AsSessionWithQoSSubscription {
	a.specWire = specLiteral
	return a
}

// UnmarshalJSON accepts both shapes: the project members subscriptionId /
// scsAsId, or the identifiers taken from the last path segments of self
// (".../{scsAsId}/subscriptions/{subscriptionId}"). Type errors keep their
// field name, so features.IsTypeError still sees "supportedFeatures".
func (a *AsSessionWithQoSSubscription) UnmarshalJSON(b []byte) error {
	type plain AsSessionWithQoSSubscription
	aux := struct {
		*plain
		SubscriptionID string `json:"subscriptionId"`
		ScsAsId        string `json:"scsAsId"`
	}{plain: (*plain)(a)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	a.SubscriptionID, a.ScsAsId = aux.SubscriptionID, aux.ScsAsId
	if a.Self != "" {
		seg := strings.Split(strings.TrimRight(a.Self, "/"), "/")
		if n := len(seg); n >= 4 && seg[n-2] == "subscriptions" {
			if a.SubscriptionID == "" {
				a.SubscriptionID = seg[n-1]
			}
			if a.ScsAsId == "" {
				a.ScsAsId = seg[n-3]
			}
		}
	}
	return nil
}

// MarshalJSON emits subscriptionId and scsAsId first (rel17 / no profile, byte
// identical to the pre-change encoding) or omits them in favour of self (rel19).
func (a AsSessionWithQoSSubscription) MarshalJSON() ([]byte, error) {
	type plain AsSessionWithQoSSubscription
	if a.specWire {
		b, err := json.Marshal(plain(a))
		if err != nil {
			return nil, fmt.Errorf("nef: marshal AsSessionWithQoSSubscription: %w", err)
		}
		return b, nil
	}
	a.Self = ""
	b, err := json.Marshal(struct {
		SubscriptionID string `json:"subscriptionId,omitempty"`
		ScsAsId        string `json:"scsAsId,omitempty"`
		plain
	}{a.SubscriptionID, a.ScsAsId, plain(a)})
	if err != nil {
		return nil, fmt.Errorf("nef: marshal AsSessionWithQoSSubscription: %w", err)
	}
	return b, nil
}

// FlowInfo describes a single IP flow within an AsSessionWithQoS subscription.
// Ref: TS 29.522 §5.14.2.x
//
// oapi: TS29122_CommonData.yaml#/components/schemas/FlowInfo
type FlowInfo struct {
	FlowID           int      `json:"flowId"`
	FlowDescriptions []string `json:"flowDescriptions,omitempty"`
}

// subscriptionRecord is the internal store record.
// It extends AsSessionWithQoSSubscription with PCF state needed for Delete.
type subscriptionRecord struct {
	sub          AsSessionWithQoSSubscription
	pcfBaseURI   string
	appSessionID string
	// negotiated is the typed supportedFeatures set of this resource. It is
	// in-memory only (the store is never serialised), kept so later optional
	// behaviour can be gated on it.
	negotiated features.Set
	// pcfNegotiated is the supportedFeatures set negotiated with the PCF for
	// the Npcf_PolicyAuthorization app-session (TS 29.514 §5.8). In-memory
	// only, never serialised.
	pcfNegotiated features.Set
}

// Server is the NEF Nnef_AFsessionWithQoS SBI server.
type Server struct {
	cfg       *config.Config
	logger    *slog.Logger
	httpSrv   *http.Server
	bsfClient BSFClient
	pcfClient PolicyAuthorizationClient

	mu            sync.RWMutex
	subscriptions map[string]*subscriptionRecord // key: subscriptionId

	// profile gates the supportedFeatures wire behaviour (decisions D1/D2,
	// dev/REL19_PROGRAM.md §2); nil behaves as rel17.
	profile *capability.Profile
	// sessCat is the AsSessionWithQoS producer catalog.
	sessCat *features.Catalog
}

// SetProfile wires the release profile used for supportedFeatures negotiation.
// Must be called before Start(). Ref: TS 29.500 §6.6.2.
func (s *Server) SetProfile(p *capability.Profile) { s.profile = p }

// SetCatalog replaces the AsSessionWithQoS catalog (tests inject catalogs with
// Implemented entries); nil restores the default. Must be called before Start().
func (s *Server) SetCatalog(c *features.Catalog) {
	if c == nil {
		c = nefsbi.AsSessionWithQoSCatalog()
	}
	s.sessCat = c
}

// New constructs the NEF SBI server with injected BSF and PCF clients.
// Pass nil clients to use default HTTP implementations (requires cfg peers to be set).
// Call Start or Handler() to begin serving.
func New(cfg *config.Config, logger *slog.Logger, bsfClient BSFClient, pcfClient PolicyAuthorizationClient) *Server {
	s := &Server{
		cfg:           cfg,
		logger:        logger.With("nf", "NEF"),
		bsfClient:     bsfClient,
		pcfClient:     pcfClient,
		subscriptions: make(map[string]*subscriptionRecord),
		sessCat:       nefsbi.AsSessionWithQoSCatalog(),
	}

	mux := http.NewServeMux()
	// Nnef_AFsessionWithQoS routes — TS 29.522 §4.4.13
	mux.HandleFunc("POST /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions", s.handleCreateSubscription)
	mux.HandleFunc("GET /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subscriptionId}", s.handleGetSubscription)
	mux.HandleFunc("DELETE /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subscriptionId}", s.handleDeleteSubscription)
	// Npcf_PolicyAuthorization callbacks (NEF is the AF) - TS 29.514 §5.5.2.2
	// Registered without a method so non-POST gets a 405 + Allow ProblemDetails.
	mux.HandleFunc(pcfNotifyBasePath+"/notify", s.handlePCFEventNotify)
	mux.HandleFunc(pcfNotifyBasePath+"/terminate", s.handlePCFTerminate)
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
// Use httptest.NewServer(srv.Handler()) in tests.
func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }

// Start starts the SBI server. If TLS cert/key are configured, it listens
// with mTLS + HTTP/2 (h2 ALPN). Otherwise falls back to plain h2c.
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
			return fmt.Errorf("nef: server: load TLS cert: %w", err)
		}
		caPEM, err := os.ReadFile(s.cfg.SBI.TLS.CAFile)
		if err != nil {
			return fmt.Errorf("nef: server: load CA: %w", err)
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
			return fmt.Errorf("nef: server: configure http2: %w", err)
		}
		s.logger.Info("NEF SBI listening (mTLS + HTTP/2)",
			"addr", s.cfg.SBI.Address,
			"service", "3gpp-as-session-with-qos",
			"spec_ref", "TS 29.522 §4.4.13",
		)
		if err := s.httpSrv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("nef: server: listen: %w", err)
		}
		return nil
	}

	// No TLS — use h2c for in-process functional tests.
	s.httpSrv.Handler = h2c.NewHandler(s.httpSrv.Handler, &http2.Server{})
	s.logger.Info("NEF SBI listening (plain h2c — no TLS configured)",
		"addr", s.cfg.SBI.Address,
		"service", "3gpp-as-session-with-qos",
	)
	if err := s.httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("nef: server: listen: %w", err)
	}
	return nil
}

// ServeH2C starts the server on the given pre-bound listener using plain HTTP/2 (h2c).
// Intended for in-process functional tests.
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

// middleware injects a correlation ID and strips/preserves the X-Correlation-Id header.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corr := r.Header.Get("X-Correlation-Id")
		if corr == "" {
			corr = uuid.NewString()
			r.Header.Set("X-Correlation-Id", corr)
		}
		w.Header().Set("X-Correlation-Id", corr)
		next.ServeHTTP(w, r)
	})
}

// ---- OAuth2 helper -------------------------------------------------------------

// verifyBearer extracts and validates the Bearer token from the Authorization header.
// Returns (claims, "") on success, or ("", cause) on failure where cause is the
// ProblemDetails cause string to return to the AF.
//
// Rules (TS 29.522 §6):
//   - Missing/empty Authorization header → 401 UNAUTHORIZED
//   - Valid token but missing required scope → 403 UNAUTHORIZED_AF
//   - Invalid/expired token → 401 UNAUTHORIZED
//
// Ref: TS 29.500 §5.2.7.2, TS 29.522 §6
func (s *Server) verifyBearer(r *http.Request) (*oauth2pkg.Claims, int, string) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, http.StatusUnauthorized, "UNAUTHORIZED"
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, http.StatusUnauthorized, "UNAUTHORIZED"
	}
	tokenStr := strings.TrimSpace(parts[1])
	if tokenStr == "" {
		return nil, http.StatusUnauthorized, "UNAUTHORIZED"
	}

	secret := []byte(s.cfg.OAuth2.Secret)
	claims, err := oauth2pkg.ValidateToken(secret, tokenStr)
	if err != nil {
		return nil, http.StatusUnauthorized, "UNAUTHORIZED"
	}

	// Check scope includes the required service name.
	// Ref: TS 29.522 §6, TS 33.501 §13.4.1
	if !strings.Contains(claims.Scope, requiredScope) {
		return nil, http.StatusForbidden, "UNAUTHORIZED_AF"
	}

	return claims, 0, ""
}

// ---- Create subscription (POST /…/{scsAsId}/subscriptions) --------------------

// handleCreateSubscription implements Nnef_AFsessionWithQoS_Create.
// POST /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions
// Ref: TS 29.522 §4.4.13.2.5
func (s *Server) handleCreateSubscription(w http.ResponseWriter, r *http.Request) {
	scsAsId := r.PathValue("scsAsId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)
	log := logging.NewProcedureLogger(ctx, s.logger, "AsSessionWithQoSCreate").With(
		"nf", "NEF",
		"interface", "Nnef",
		"direction", "IN",
		"spec_ref", "TS 29.522 §4.4.13.2.5",
		"scs_as_id", scsAsId,
		"correlation_id", corrID,
	)

	// ---- OAuth2 verification ---------------------------------------------------
	// Ref: TS 29.522 §6
	claims, httpStatus, cause := s.verifyBearer(r)
	if cause != "" {
		log.Warn("create: bearer token verification failed",
			"result", "REJECT", "cause", cause, "http_status", httpStatus)
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "REJECT").Inc()
		s.problem(w, httpStatus, cause, "OAuth2 bearer token verification failed")
		return
	}
	log = log.With("af_subject", claims.Subject)

	// ---- Decode request body ---------------------------------------------------
	var sub AsSessionWithQoSSubscription
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
		if features.IsTypeError(err) {
			s.rejectSupportedFeatures(ctx, w, "<non-string>", err)
			return
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			log.Warn("create: request body too large", "result", "REJECT", "http_status", http.StatusRequestEntityTooLarge)
			metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "REJECT").Inc()
			s.problem(w, http.StatusRequestEntityTooLarge, "", "request body too large")
			return
		}
		log.Warn("create: malformed JSON body",
			"result", "REJECT", "cause", "MANDATORY_IE_INCORRECT", "error", err)
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid JSON body")
		return
	}
	sub.ScsAsId = scsAsId

	// ---- supportedFeatures negotiation (producer) ------------------------------
	// Must be schema-valid before any state is touched. The answer replaces
	// whatever the AF sent: the representation carries the intersection, absent
	// under rel17 when the request had none (decision D1).
	// Ref: TS 29.500 §5.2.7.2, §6.6.2; TS 29.122 §5.2.7.
	if err := features.Validate(sub.SupportedFeatures); err != nil {
		s.rejectSupportedFeatures(ctx, w, sub.SupportedFeatures, err)
		return
	}
	sfPeer := sub.SupportedFeatures
	sfAnswer, sfSet := features.Answer(s.sessCat, s.profile, sfPeer)
	sub.SupportedFeatures = sfAnswer
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "NEF",
		Interface: "Nnef", Direction: "IN", PeerNF: "AF",
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.sessCat.Supported(s.profile), Peer: sfPeer, PeerPresent: sfPeer != "", Negotiated: sfSet,
	}, "scs_as_id", scsAsId)

	// ---- Validate mandatory IEs -----------------------------------------------
	// At least one UE address key is required: ueIpv4Addr, ueIpv6Addr, or macAddr.
	// Ref: TS 29.522 §5.14.2.1.2
	if sub.UeIpv4Addr == "" && sub.UeIpv6Addr == "" {
		log.Warn("create: no UE address key provided",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"at least one of ueIpv4Addr or ueIpv6Addr is required (TS 29.522 §5.14.2.1.2)")
		return
	}
	// qosReference is mandatory (TS 29.522 §5.14.2.1.2).
	if sub.QosReference == "" {
		log.Warn("create: qosReference missing",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"qosReference is mandatory (TS 29.522 §5.14.2.1.2)")
		return
	}

	// flowInfo is validated under the spec-literal profile only; rel17 keeps its
	// historical acceptance. Ref: TS 29.122 FlowInfo (flowId unique, flowDescriptions 1..2).
	if features.SpecLiteral(s.profile) {
		if fe := validateFlowInfo(sub.FlowInfo); fe != nil {
			log.Warn("create: invalid flowInfo",
				"result", "REJECT", "cause", features.CauseInvalidMsgFormat, "error", fe,
				"spec_ref", "TS 29.122 FlowInfo")
			metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "REJECT").Inc()
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":        http.StatusBadRequest,
				"cause":         features.CauseInvalidMsgFormat,
				"detail":        fe.detail,
				"invalidParams": []map[string]string{{"param": fe.param}},
			})
			return
		}
		if flowIDFallback(sub.FlowInfo) {
			log.Info("create: flowInfo entry without flowId, numbering by position",
				"spec_ref", "TS 29.122 FlowInfo", "result", "OK")
		}
	}

	log = log.With("ue_ipv4", sub.UeIpv4Addr, "qos_reference", sub.QosReference)
	log.Info("create: AsSessionWithQoS request received")

	// ---- BSF Discovery — find serving PCF by UE IP ----------------------------
	// Ref: TS 29.521 §5.2.2.4
	log.Info("create: discovering PCF via BSF",
		"interface", "Nbsf",
		"direction", "OUT",
		"spec_ref", "TS 29.521 §5.2.2.4",
	)
	binding, err := s.bsfClient.Discover(ctx, sub.UeIpv4Addr)
	if err != nil {
		if errors.Is(err, ErrPcfBindingNotFound) {
			log.Info("create: no PCF binding for UE IP",
				"result", "REJECT", "cause", "PCF_BINDING_NOT_FOUND",
				"interface", "Nbsf", "direction", "IN",
				"spec_ref", "TS 29.521 §5.2.2.4.4",
			)
			metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "REJECT").Inc()
			s.problem(w, http.StatusNotFound, "PCF_BINDING_NOT_FOUND",
				"no PCF binding found for UE IP "+sub.UeIpv4Addr+" (TS 29.521 §5.2.2.4.4)")
			return
		}
		log.Error("create: BSF discovery failed",
			"error", err, "result", "FAILURE",
			"interface", "Nbsf", "direction", "IN",
		)
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "FAILURE").Inc()
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE",
			"BSF discovery failed: "+err.Error())
		return
	}

	pcfURI := pcfBaseURI(binding)
	if pcfURI == "" {
		log.Error("create: PCF binding has no usable endpoint",
			"binding_id", binding.BindingID, "result", "FAILURE")
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "FAILURE").Inc()
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE",
			"PCF binding found but has no pcfFqdn or pcfIpEndPoints")
		return
	}

	log = log.With("pcf_id", binding.PcfId, "pcf_uri", pcfURI)
	log.Info("create: PCF binding discovered",
		"binding_id", binding.BindingID,
		"interface", "Nbsf",
		"direction", "IN",
		"spec_ref", "TS 29.521 §5.2.2.4",
	)

	// ---- PCF Policy Authorization Create --------------------------------------
	// Ref: TS 29.514 §5.2.2.2
	pcfReq := &AppSessionContextReqData{
		AspId:     scsAsId,
		AfAppId:   sub.AfAppId,
		UeIpv4:    sub.UeIpv4Addr,
		UeIpv6:    sub.UeIpv6Addr,
		Dnn:       binding.Dnn,
		SliceInfo: binding.Snssai,
	}
	if !features.SpecLiteral(s.profile) {
		// rel17 / no profile: frozen top-level ascReqData.qosReference. Under
		// rel19 the reference travels in medComponents[].qosReference.
		pcfReq.QosReference = sub.QosReference
		pcfReq.qosTopLevel = true
	}
	pcfReq.MedComponents = buildMedComponents(sub.FlowInfo, features.SpecLiteral(s.profile), sub.QosReference)
	if features.SpecLiteral(s.profile) {
		// notifUri is required by AppSessionContextReqData (TS 29.514 §5.6.2.3);
		// legacy profiles keep the pre-REL19-3.5 bytes (no notifUri).
		// The base is the NEF apiRoot (config.APIRoot: NRF-advertised FQDN +
		// SBI listen port), never the client-controlled Host header. Without a
		// configured endpoint notifUri is omitted (WARN) rather than failing
		// the AF request.
		if root := s.cfg.APIRoot(); root != "" {
			pcfReq.NotifUri = root + pcfNotifyBasePath
		} else {
			log.Warn("create: NEF apiRoot not configured (sbi.fqdn/sbi.address), omitting ascReqData.notifUri",
				"spec_ref", "TS 29.514 §5.6.2.3",
				"result", "FAILURE",
				"cause", "NOTIF_URI_UNAVAILABLE",
			)
		}
	}

	log.Info("create: sending Npcf_PolicyAuthorization_Create to PCF",
		"interface", "Npcf",
		"direction", "OUT",
		"spec_ref", "TS 29.514 §5.2.2.2",
	)
	appSessionID, pcfSet, err := s.pcfClient.CreateAppSession(ctx, pcfURI, pcfReq)
	if err != nil {
		if strings.HasPrefix(err.Error(), "403") {
			log.Warn("create: PCF rejected policy authorization",
				"result", "REJECT", "cause", "UNAUTHORIZED_AF",
				"interface", "Npcf", "direction", "IN",
				"spec_ref", "TS 29.514 §5.2.2.2.4",
			)
			// Create-authorization rejection → UNAUTHORIZED_AF (not the modify-op
			// cause MODIFICATION_NOT_ALLOWED). Aligns the wire cause with the log
			// cause. Ref: TS 29.522 §6, TS 29.514 §5.2.2.2.4 (SPEC-VERIFIER finding 2).
			metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "REJECT").Inc()
			s.problem(w, http.StatusForbidden, "UNAUTHORIZED_AF",
				"PCF rejected the policy authorization (TS 29.514 §5.2.2.2.4)")
			return
		}
		log.Error("create: PCF app-session create failed",
			"error", err, "result", "FAILURE",
			"interface", "Npcf", "direction", "IN",
		)
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "FAILURE").Inc()
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE",
			"PCF policy authorization failed: "+err.Error())
		return
	}

	// ---- Store subscription + mint subscriptionId -----------------------------
	subscriptionID := uuid.NewString()
	sub.SubscriptionID = subscriptionID

	// Build Location header (also the rel19 self link).
	fqdn := s.cfg.SBI.FQDN
	if fqdn == "" {
		fqdn = r.Host
	}
	location := fmt.Sprintf("https://%s/3gpp-as-session-with-qos/v1/%s/subscriptions/%s",
		fqdn, scsAsId, subscriptionID)
	specLiteral := features.SpecLiteral(s.profile)
	if specLiteral {
		sub.Self = location
	}

	s.mu.Lock()
	s.subscriptions[subscriptionID] = &subscriptionRecord{
		sub:           sub,
		pcfBaseURI:    pcfURI,
		appSessionID:  appSessionID,
		negotiated:    sfSet,
		pcfNegotiated: pcfSet,
	}
	s.mu.Unlock()

	log.Info("create: AsSessionWithQoS subscription created",
		"subscription_id", subscriptionID,
		"app_session_id", appSessionID,
		"result", "OK",
		"interface", "Npcf",
		"direction", "IN",
		"spec_ref", "TS 29.522 §4.4.13.2.5",
	)
	metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "OK").Inc()
	metrics.NEFSubscriptionsActive.Inc()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(sub.wireFor(specLiteral))
}

// ---- Get subscription (GET /…/{scsAsId}/subscriptions/{subscriptionId}) -------

// handleGetSubscription implements Nnef_AFsessionWithQoS_Get.
// GET /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subscriptionId}
// Ref: TS 29.522 §4.4.13.2.5
func (s *Server) handleGetSubscription(w http.ResponseWriter, r *http.Request) {
	scsAsId := r.PathValue("scsAsId")
	subscriptionID := r.PathValue("subscriptionId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)
	log := logging.NewProcedureLogger(ctx, s.logger, "AsSessionWithQoSGet").With(
		"nf", "NEF",
		"interface", "Nnef",
		"direction", "IN",
		"spec_ref", "TS 29.522 §4.4.13.2.5",
		"scs_as_id", scsAsId,
		"subscription_id", subscriptionID,
		"correlation_id", corrID,
	)

	// OAuth2 verification.
	_, httpStatus, cause := s.verifyBearer(r)
	if cause != "" {
		log.Warn("get: bearer token verification failed",
			"result", "REJECT", "cause", cause)
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSGet", "REJECT").Inc()
		s.problem(w, httpStatus, cause, "OAuth2 bearer token verification failed")
		return
	}

	s.mu.RLock()
	rec, ok := s.subscriptions[subscriptionID]
	s.mu.RUnlock()

	if !ok {
		log.Info("get: subscription not found", "result", "REJECT")
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSGet", "REJECT").Inc()
		s.problem(w, http.StatusNotFound, "",
			fmt.Sprintf("no subscription found for subscriptionId %s (TS 29.522 §4.4.13.2.5)", subscriptionID))
		return
	}

	log.Info("get: subscription found", "result", "OK")
	metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSGet", "OK").Inc()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rec.sub.wireFor(features.SpecLiteral(s.profile)))
}

// ---- Delete subscription (DELETE /…/{scsAsId}/subscriptions/{subscriptionId}) -

// handleDeleteSubscription implements Nnef_AFsessionWithQoS_Delete.
// DELETE /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subscriptionId}
// Ref: TS 29.522 §4.4.13.2.5 + TS 29.514 §4.2.4.2
func (s *Server) handleDeleteSubscription(w http.ResponseWriter, r *http.Request) {
	scsAsId := r.PathValue("scsAsId")
	subscriptionID := r.PathValue("subscriptionId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)
	log := logging.NewProcedureLogger(ctx, s.logger, "AsSessionWithQoSDelete").With(
		"nf", "NEF",
		"interface", "Nnef",
		"direction", "IN",
		"spec_ref", "TS 29.522 §4.4.13.2.5",
		"scs_as_id", scsAsId,
		"subscription_id", subscriptionID,
		"correlation_id", corrID,
	)

	// OAuth2 verification.
	_, httpStatus, cause := s.verifyBearer(r)
	if cause != "" {
		log.Warn("delete: bearer token verification failed",
			"result", "REJECT", "cause", cause)
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSDelete", "REJECT").Inc()
		s.problem(w, httpStatus, cause, "OAuth2 bearer token verification failed")
		return
	}

	s.mu.Lock()
	rec, ok := s.subscriptions[subscriptionID]
	if ok {
		delete(s.subscriptions, subscriptionID)
	}
	s.mu.Unlock()

	if !ok {
		log.Info("delete: subscription not found", "result", "REJECT")
		metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSDelete", "REJECT").Inc()
		s.problem(w, http.StatusNotFound, "",
			fmt.Sprintf("no subscription found for subscriptionId %s (TS 29.522 §4.4.13.2.5)", subscriptionID))
		return
	}

	// Relay deletion to the PCF.
	// Ref: TS 29.514 §4.2.4.2
	log.Info("delete: relaying deletion to PCF",
		"app_session_id", rec.appSessionID,
		"interface", "Npcf",
		"direction", "OUT",
		"spec_ref", "TS 29.514 §4.2.4.2",
	)
	if err := s.pcfClient.DeleteAppSession(ctx, rec.pcfBaseURI, rec.appSessionID); err != nil {
		log.Warn("delete: PCF app-session delete failed (subscription already removed)",
			"error", err, "result", "FAILURE",
			"interface", "Npcf",
			"direction", "IN",
		)
		// Fail-open: subscription is already removed from the NEF store.
		// Return 204 to the AF regardless — the NEF's subscription is gone.
	} else {
		log.Info("delete: PCF app-session deleted",
			"app_session_id", rec.appSessionID,
			"result", "OK",
			"interface", "Npcf",
			"direction", "IN",
			"spec_ref", "TS 29.514 §4.2.4.2",
		)
	}

	log.Info("delete: AsSessionWithQoS subscription deleted",
		"result", "OK",
		"interface", "Nnef",
		"direction", "OUT",
		"spec_ref", "TS 29.522 §4.4.13.2.5",
	)
	metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSDelete", "OK").Inc()
	metrics.NEFSubscriptionsActive.Dec()
	w.WriteHeader(http.StatusNoContent)
}

// ---- Npcf_PolicyAuthorization callbacks ------------------------------------------

// pcfNotifyBasePath is the NEF callback base advertised to the PCF as
// ascReqData.notifUri; the PCF appends "/notify" and "/terminate" to the
// notification URI it was given.
// Ref: TS 29.514 §5.5.2.2 (callback URIs)
const pcfNotifyBasePath = "/npcf-policyauthorization-notify/v1"

// maxPCFNotifyBodyBytes bounds the PCF notification body read.
const maxPCFNotifyBodyBytes = 1 << 20

// handlePCFEventNotify accepts Npcf_PolicyAuthorization_Notify (events).
// Ref: TS 29.514 §4.2.5.2
func (s *Server) handlePCFEventNotify(w http.ResponseWriter, r *http.Request) {
	s.handlePCFCallback(w, r, "PolicyAuthorizationNotify", "EventNotification", "TS 29.514 §4.2.5.2")
}

// handlePCFTerminate accepts the PCF request for termination of an app-session.
// Ref: TS 29.514 §4.2.5.3
func (s *Server) handlePCFTerminate(w http.ResponseWriter, r *http.Request) {
	s.handlePCFCallback(w, r, "PolicyAuthorizationTerminate", "TerminationRequest", "TS 29.514 §4.2.5.3")
}

// handlePCFCallback acknowledges a PCF callback with 204. The body is read
// under a hard size cap and logged by size only: the NEF takes no action on it
// in the baseline. Oversized body -> 413, read error -> 400, non-POST -> 405,
// all as application/problem+json.
// Ref: TS 29.571 §5.2.4.1 (ProblemDetails)
func (s *Server) handlePCFCallback(w http.ResponseWriter, r *http.Request, procedure, msgType, specRef string) {
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, procedure)
	fields := []any{
		"nf", "NEF", "interface", "Npcf", "direction", "IN",
		"spec_ref", specRef, "message_type", msgType,
		"correlation_id", logging.CorrelationID(ctx), "path", r.URL.Path,
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		log.Warn("pcf callback rejected", append(fields, "result", "REJECT", "cause", "METHOD_NOT_ALLOWED")...)
		s.problem(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "only POST is allowed")
		return
	}
	n, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, maxPCFNotifyBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			log.Warn("pcf callback rejected", append(fields, "result", "REJECT", "cause", "BODY_TOO_LARGE")...)
			s.problem(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body too large")
			return
		}
		log.Warn("pcf callback rejected", append(fields, "result", "REJECT", "cause", "BODY_READ_ERROR", "error", err)...)
		s.problem(w, http.StatusBadRequest, "BODY_READ_ERROR", "cannot read request body")
		return
	}
	log.Info("pcf callback received", append(fields, "body_bytes", n, "result", "OK")...)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Health -------------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

// ---- helpers ------------------------------------------------------------------

// rejectSupportedFeatures answers a schema-invalid supportedFeatures with 400
// INVALID_MSG_FORMAT and invalidParams[{param: /supportedFeatures}] and logs
// the REJECT negotiation record. Ref: TS 29.500 §5.2.7.2; TS 29.571 §5.2.4.6.
func (s *Server) rejectSupportedFeatures(ctx context.Context, w http.ResponseWriter, shown string, cause error) {
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "NEF",
		Interface: "Nnef", Direction: "IN", PeerNF: "AF",
		SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: features.CauseInvalidMsgFormat,
		Local: s.sessCat.Supported(s.profile), Peer: shown, PeerPresent: true,
	}, "error", cause)
	metrics.ProcedureTotal.WithLabelValues("NEF", "AsSessionWithQoSCreate", "REJECT").Inc()
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusBadRequest,
		"cause":  features.CauseInvalidMsgFormat,
		"detail": "supportedFeatures is not a valid hexadecimal string",
		"invalidParams": []map[string]string{
			{"param": features.ParamSupportedFeatures},
		},
	})
}

// problem writes a 3GPP-style application/problem+json response.
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
