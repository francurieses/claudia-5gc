// Package server implements the LMF Nlmf_Location SBI server.
//
// Routes (TS 29.572 §5.2.2.2 + §5.2.3 + §5.2.2.4.2):
//
//	POST   /nlmf-loc/v1/determine-location → DetermineLocation
//	POST   /nlmf-loc/v1/subscriptions                               → EventSubscription Create
//	GET    /nlmf-loc/v1/subscriptions/{subId}                       → EventSubscription Get
//	DELETE /nlmf-loc/v1/subscriptions/{subId}                       → EventSubscription Delete
//	POST   /nlmf-loc/v1/cancel-location    → CancelLocation
//	GET    /healthz                                                   → liveness
//	GET    /metrics                                                   → Prometheus
//
// All SBI endpoints are served over HTTP/2 + mTLS (TS 29.500 §4.4.1).
//
// ALPN invariant: TLSConfig.NextProtos = ["h2"] set BEFORE http2.ConfigureServer.
// Ref: docs/memory/http2_alpn_conformance.md
//
// Ref: TS 29.572 §5.2.2.2, TS 29.572 §5.2.3, TS 23.273 §7.2, TS 23.501 §6.2.18
package server

import (
	"bytes"
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
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	lmfsbi "github.com/francurieses/claudia-5gc/nf/lmf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// Server is the LMF Nlmf_Location SBI server.
type Server struct {
	cfg       *config.Config
	logger    *slog.Logger
	httpSrv   *http.Server
	amfClient AMFLocationClient
	udmClient UDMSDMClient // nil = privacy check disabled (fail-open)
	mobility  *mobilityModel

	// nrppaClient relays opaque NRPPa PDUs to gNBs via the AMF (LMF-004).
	// Injected via SetNRPPAClient; nil disables E-CID and always uses Cell-ID.
	// Ref: TS 38.455 §8; TS 29.518 §5.2.2.6 (dl-nrppa-info); TS 23.273 §6.2.9.
	nrppaClient DLNRPPASender

	// lppClient relays opaque LPP PDUs to the UE via the AMF NAS N1 relay
	// (LMF-005). Injected via SetLPPClient; nil disables GNSS/LPP and
	// downgrades to E-CID (or Cell-ID if that is also unwired).
	// Ref: TS 37.355 §6; TS 29.518 §5.2.2.6 (dl-lpp-info); TS 23.273 §6.2.10.
	lppClient LPPSender

	// lppState tracks the per-SUPI LPP state machine state (IDLE →
	// CAPS_REQUESTED → ASSIST_SENT → MEASURE_RECEIVED → FIXED/FALLBACK) for
	// introspection/logging. Ref: docs/procedures/LPPRelay.md.
	lppState lppStateTracker

	// registry holds active EventSubscription resources (LMF-003).
	// Ref: TS 29.572 §5.2.3.
	registry *subscriptionRegistry

	// notifClient posts LocationNotification bodies to subscriber URIs.
	// Injected so tests can supply a mock sink.
	// Ref: TS 29.572 §6.1.6.2.4.
	notifClient NotificationClient

	// pendingLoc maps ueContextId → context.CancelFunc for in-progress
	// DetermineLocation requests. Used by CancelLocation (TS 29.572 §5.2.2.4.2).
	pendingLoc sync.Map

	// baseLogger is the process logger exactly as passed to New (it already
	// carries nf): the FeatureNegotiation record is built from it, not from
	// logger, which adds nf again.
	baseLogger *slog.Logger
	// profile gates the supportedFeatures wire behaviour (decisions D1/D2,
	// dev/REL19_PROGRAM.md §2); nil behaves as rel17.
	profile *capability.Profile
	// cat is the Nlmf_Location producer catalog.
	cat *features.Catalog

	// bgMu/bg/bgClosed track the deferred-location goroutines so shutdown can
	// drain them (see goBG / drainBG).
	bgMu     sync.Mutex
	bg       sync.WaitGroup
	bgClosed bool
	// timeUnit scales every seconds-valued deferred-location parameter
	// (reportingDuration, intervals, max duration). Zero means time.Second;
	// tests shorten it to keep the suite fast.
	timeUnit time.Duration
	// deferredLimit bounds concurrent deferred sessions; zero means
	// maxDeferredSessions (tests lower it).
	deferredLimit int
}

// SetProfile wires the release profile used for supportedFeatures negotiation.
// Must be called before Start(). Ref: TS 29.500 §6.6.2.
func (s *Server) SetProfile(p *capability.Profile) { s.profile = p }

// SetCatalog replaces the Nlmf_Location catalog (tests inject catalogs with
// Implemented entries); nil restores the default. Must be called before Start().
func (s *Server) SetCatalog(c *features.Catalog) {
	if c == nil {
		c = lmfsbi.NlmfLocationCatalog()
	}
	s.cat = c
}

// SetNRPPAClient injects the DLNRPPASender used for E-CID NRPPa positioning (LMF-004).
// Call this after NewWithNotifClient, before Start. Concurrent-safe only before the
// server starts serving requests — thereafter the field is read-only.
//
// When nil (default), E-CID is disabled and every DetermineLocation request uses
// the Cell-ID (LMF-001) path regardless of the requested hAccuracy.
//
// Production wiring (cmd/lmf/main.go):
//
//	srv.SetNRPPAClient(amfClient)  // HTTPAMFLocationClient implements both interfaces
//
// Ref: TS 23.273 §6.2.9 (E-CID quality-driven selection); TS 38.455 §8 (NRPPa).
func (s *Server) SetNRPPAClient(c DLNRPPASender) { s.nrppaClient = c }

// SetLPPClient injects the LPPSender used for GNSS/LPP positioning (LMF-005).
// Call this after NewWithNotifClient, before Start. Concurrent-safe only
// before the server starts serving requests — thereafter the field is
// read-only.
//
// When nil (default), GNSS/LPP is disabled and every DetermineLocation
// request with hAccuracy < 50 m downgrades to E-CID (or Cell-ID if that is
// also unwired) regardless of the requested hAccuracy.
//
// Production wiring (cmd/lmf/main.go):
//
//	srv.SetLPPClient(amfClient)  // HTTPAMFLocationClient implements both interfaces
//
// Ref: TS 23.273 §6.2.10 (GNSS quality-driven selection); TS 37.355 §6 (LPP).
func (s *Server) SetLPPClient(c LPPSender) { s.lppClient = c }

// New constructs the LMF SBI server with injected AMF and UDM clients.
// Pass a real HTTPAMFLocationClient / HTTPUDMSDMClient in production or
// test doubles in tests. Call Start or Handler() to begin serving.
//
// notifClient is the notification delivery client (HTTPNotificationClient in
// production, a mock in tests). When nil a no-op client is used.
func New(cfg *config.Config, logger *slog.Logger, amfClient AMFLocationClient, udmClient UDMSDMClient) *Server {
	return NewWithNotifClient(cfg, logger, amfClient, udmClient, nil)
}

// NewWithNotifClient constructs the LMF SBI server with an explicit notification client.
// This is the primary constructor; New() delegates here with notifClient=nil (no-op).
func NewWithNotifClient(cfg *config.Config, logger *slog.Logger, amfClient AMFLocationClient, udmClient UDMSDMClient, notifClient NotificationClient) *Server {
	if notifClient == nil {
		notifClient = &noopNotificationClient{}
	}
	s := &Server{
		cfg:         cfg,
		logger:      logger.With("nf", "LMF"),
		amfClient:   amfClient,
		udmClient:   udmClient,
		mobility:    newMobilityModel(cfg),
		registry:    newRegistry(),
		notifClient: notifClient,
		baseLogger:  logger,
		cat:         lmfsbi.NlmfLocationCatalog(),
	}

	mux := http.NewServeMux()
	// Nlmf_Location DetermineLocation — TS 29.572 §5.2.2.2.
	// Path per TS29572_Nlmf_Location.yaml (/determine-location); the UE is
	// identified by supi/gpsi in the InputData body, not by a path segment.
	mux.HandleFunc("POST /nlmf-loc/v1/determine-location", s.handleDetermineLocation)
	// Nlmf_Location EventSubscription — TS 29.572 §5.2.3.
	mux.HandleFunc("POST /nlmf-loc/v1/subscriptions", s.handleCreateSubscription)
	mux.HandleFunc("GET /nlmf-loc/v1/subscriptions/{subId}", s.handleGetSubscription)
	mux.HandleFunc("DELETE /nlmf-loc/v1/subscriptions/{subId}", s.handleDeleteSubscription)
	// CancelLocation one-shot — TS 29.572 §5.2.2.4.2.
	// Path per TS29572_Nlmf_Location.yaml (/cancel-location).
	mux.HandleFunc("POST /nlmf-loc/v1/cancel-location", s.handleCancelLocation)
	// UL NRPPa receive stub — forward-compatibility for the async relay model (LMF-005+).
	// In the synchronous AMF relay model (LMF-004 MVP) this endpoint is not exercised.
	// Returns 202 Accepted and discards the body.
	// Ref: NRPPaRelay.md §Endpoints; TS 29.518 §5.2.2.6.
	mux.HandleFunc("POST /nlmf-loc/v1/ue-contexts/{ueContextId}/ul-nrppa-info", s.handleULNRPPa)
	// UL LPP receive stub — forward-compatibility for the async relay model (LMF-005+).
	// In the synchronous AMF relay model (LMF-005 MVP) this endpoint is not exercised.
	// Returns 202 Accepted and discards the body.
	// Ref: docs/procedures/LPPRelay.md §Endpoints; TS 29.518 §5.2.2.6.
	mux.HandleFunc("POST /nlmf-loc/v1/ue-contexts/{ueContextId}/ul-lpp-info", s.handleULLPP)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.Handle("GET /metrics", promhttp.Handler())

	s.httpSrv = &http.Server{
		Addr:              cfg.SBI.Address,
		Handler:           s.middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// noopNotificationClient is the default notification client when none is injected.
// It silently discards notifications (suitable when the NF is built without TLS
// and the notificationUri is not reachable).
type noopNotificationClient struct{}

func (n *noopNotificationClient) PostNotification(_ context.Context, _ string, _ LocationNotification) error {
	return nil
}

// PostEventNotify implements EventNotifier (discards the callback).
func (n *noopNotificationClient) PostEventNotify(_ context.Context, _ string, _ EventNotifyData) error {
	return nil
}

// Handler returns the HTTP handler for in-process testing (no TLS / h2c).
// Use httptest.NewServer(srv.Handler()) in tests.
func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }

// Start starts the SBI server. If TLS cert/key are configured, it listens
// with mTLS + HTTP/2 (h2 ALPN). Otherwise falls back to plain h2c (suitable
// for unit and functional tests).
//
// ALPN invariant: TLSConfig.NextProtos = ["h2"] MUST be set BEFORE ConfigureServer.
// Ref: TS 29.500 §4.4.2; docs/memory/http2_alpn_conformance.md.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		// Same sequence as an explicit Shutdown so the two paths cannot diverge.
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(shutCtx)
	}()

	if s.cfg.SBI.TLS.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.SBI.TLS.CertFile, s.cfg.SBI.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("lmf: server: load TLS cert: %w", err)
		}
		caPEM, err := os.ReadFile(s.cfg.SBI.TLS.CAFile)
		if err != nil {
			return fmt.Errorf("lmf: server: load CA: %w", err)
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
			return fmt.Errorf("lmf: server: configure http2: %w", err)
		}
		s.logger.Info("LMF SBI listening (mTLS + HTTP/2)",
			"addr", s.cfg.SBI.Address,
			"service", "nlmf-loc",
			"spec_ref", "TS 29.572 §5.2.2.2",
		)
		if err := s.httpSrv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("lmf: server: listen: %w", err)
		}
		return nil
	}

	// No TLS — use h2c for in-process functional tests.
	s.httpSrv.Handler = h2c.NewHandler(s.httpSrv.Handler, &http2.Server{})
	s.logger.Info("LMF SBI listening (plain h2c — no TLS configured)",
		"addr", s.cfg.SBI.Address,
		"service", "nlmf-loc",
	)
	if err := s.httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("lmf: server: listen: %w", err)
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

// Shutdown gracefully stops the server in every profile: all subscription /
// deferred-location sessions are cancelled first, the HTTP server stops, and
// the tracked goroutines (legacy and deferred) are awaited until they exit or
// ctx expires. No notification is POSTed after Shutdown returns (unless ctx
// expired first).
func (s *Server) Shutdown(ctx context.Context) error {
	s.registry.cancelAll()
	err := s.httpSrv.Shutdown(ctx)
	// A Create that registered a session after the first cancelAll but before
	// the HTTP server stopped is cancelled by this second sweep. A Create that
	// registers after this sweep but before drainBG closes the tracker can still
	// start a goroutine; it is bounded by its own duration/ctx, and drainBG
	// then waits for it (until ctx expires).
	s.registry.cancelAll()
	s.drainBG(ctx)
	return err
}

// ---- middleware ----------------------------------------------------------------

// middleware injects a correlation ID from / into the X-Correlation-Id header.
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

// ---- DetermineLocation (POST /nlmf-loc/v1/determine-location) ----

// nlmfRequest is the request body for Nlmf_Location_DetermineLocation.
// The body (InputData) carries the UE identifier (supi/gpsi) plus QoS/priority.
//
// Ref: TS 29.572 §6.1.6.2.x (RequestLocInfo for Nlmf_Location)
//
// oapi: TS29572_Nlmf_Location.yaml#/components/schemas/InputData
type nlmfRequest struct {
	// Supi is the UE permanent identity. One of Supi/Gpsi must be present.
	Supi string `json:"supi,omitempty"`
	// Gpsi is the Generic Public Subscription Identifier (alternative to Supi).
	Gpsi string `json:"gpsi,omitempty"`
	// LocationQoS holds accuracy/response-time hints (optional).
	LocationQoS *locationQoS `json:"locationQoS,omitempty"`
	// Priority is the LCS priority hint (optional).
	Priority string `json:"priority,omitempty"`
	// SupportedFeatures: TS 29.572 §6.1.6.2.2 (InputData.supportedFeatures),
	// negotiated per TS 29.500 §6.6.2 against Table 6.1.9-1.
	SupportedFeatures string `json:"supportedFeatures,omitempty"`
}

// locationQoS holds optional location quality-of-service parameters.
// Ref: TS 29.572 §6.1.6.2.x (LocationQoS).
//
// oapi: TS29572_Nlmf_Location.yaml#/components/schemas/LocationQoS
type locationQoS struct {
	HAccuracy    float64 `json:"hAccuracy,omitempty"`
	VAccuracy    float64 `json:"vAccuracy,omitempty"`
	ResponseTime string  `json:"responseTime,omitempty"`
}

// handleDetermineLocation implements Nlmf_Location_DetermineLocation (POST).
//
// Flow:
//  1. Validate request — at least one of supi/gpsi must be present.
//  2. Register request in pendingLoc so cancel-location can abort it.
//  3. Call s.locate() (shared with EventSubscription goroutines).
//  4. Return 200 LocationData, or an appropriate ProblemDetails on error.
//
// Ref: TS 29.572 §5.2.2.2; TS 23.273 §7.2.
func (s *Server) handleDetermineLocation(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)

	log := logging.NewProcedureLogger(ctx, s.logger, "DetermineLocation").With(
		"nf", "LMF",
		"interface", "Nlmf",
		"direction", "IN",
		"spec_ref", "TS 29.572 §5.2.2.2",
		"correlation_id", corrID,
	)

	log.Info("DetermineLocation request received")

	// ---- Validate request body ------------------------------------------------
	// supi or gpsi is required to identify the UE.
	// Ref: TS 29.572 §5.2.2.2; error table: "UE not identifiable → 400 MANDATORY_IE_MISSING".
	peerNF := features.PeerNFTypeFromUserAgent(r.UserAgent(), "AMF")
	var req nlmfRequest
	// The UE identity is carried in the body (InputData.supi / gpsi); a body
	// with neither is rejected with 400 below. We decode what's there and check. Only a type error on
	// supportedFeatures and an over-long body are errors; any other decode
	// error keeps the legacy tolerance.
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	// The raw bytes are kept (Rel-19 only) to read the deferred-location
	// attributes of the same InputData without a second body read.
	var rawBody bytes.Buffer
	var bodyReader io.Reader = r.Body
	specLiteral := features.SpecLiteral(s.profile)
	if specLiteral {
		bodyReader = io.TeeReader(r.Body, &rawBody)
	}
	dec := json.NewDecoder(bodyReader)
	if err := dec.Decode(&req); err != nil {
		if features.IsTypeError(err) {
			s.rejectSupportedFeatures(ctx, w, peerNF, "<non-string>", err)
			return
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			payloadTooLarge(log, w)
			return
		}
	} else if specLiteral {
		// Rel-19: anything after the JSON value makes the body invalid; it
		// must not silently turn a deferred request into an immediate one.
		// Ref: TS 29.500 §5.2.7.2 (INVALID_MSG_FORMAT).
		if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
			var mbe *http.MaxBytesError
			if errors.As(terr, &mbe) {
				payloadTooLarge(log, w)
				return
			}
			log.Warn("DetermineLocation: trailing data after the JSON body",
				"result", "REJECT", "cause", "INVALID_MSG_FORMAT", "error", terr)
			metrics.LMFLocateTotal.WithLabelValues("REJECT").Inc()
			s.problemInvalid(w, "INVALID_MSG_FORMAT", "request body has trailing data after the JSON value")
			return
		}
	}

	// supportedFeatures must be schema-valid before any state is touched.
	// Ref: TS 29.500 §5.2.7.2, §6.6.2.
	if err := features.Validate(req.SupportedFeatures); err != nil {
		s.rejectSupportedFeatures(ctx, w, peerNF, req.SupportedFeatures, err)
		return
	}
	// Producer side (decision D1): the intersection, absent under rel17 when
	// the request had none, "0" under rel19. The location is stateless, so the
	// answer only goes into the LocationData of the 200 response.
	sfAnswer, sfSet := features.Answer(s.cat, s.profile, req.SupportedFeatures)

	if req.Supi == "" && req.Gpsi == "" {
		log.Warn("DetermineLocation: missing UE identity (supi and gpsi both absent)",
			"result", "REJECT",
			"cause", "MANDATORY_IE_MISSING",
		)
		metrics.LMFLocateTotal.WithLabelValues("REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"at least one of supi or gpsi is required (TS 29.572 §5.2.2.2)")
		return
	}

	// Deferred (periodic / area-event) location: Rel-19 profile only. Under
	// rel17 / no profile the attributes are ignored (immediate location).
	// Ref: TS 29.572 §5.2.2.2, TS29572_Nlmf_Location.yaml InputData.
	var deferred *deferredInputData
	if specLiteral {
		d, derr := decodeDeferred(rawBody.Bytes())
		if derr != nil {
			log.Warn("DetermineLocation: invalid deferred-location attribute type",
				"result", "REJECT", "cause", "INVALID_MSG_FORMAT", "error", derr)
			metrics.LMFLocateTotal.WithLabelValues("REJECT").Inc()
			s.problemInvalid(w, "INVALID_MSG_FORMAT", "request body has an attribute of the wrong type")
			return
		}
		if d != nil && d.isDeferred() {
			if d.unsupportedEvent() {
				log.Warn("DetermineLocation: motion event reporting is not supported",
					"result", "REJECT", "cause", "UNSUPPORTED_EVENT_TYPE",
					"spec_ref", "TS 29.572 §5.2.2.2.2")
				metrics.LMFLocateTotal.WithLabelValues("REJECT").Inc()
				procDeferred("REJECT")
				s.problem(w, http.StatusNotImplemented, "UNSUPPORTED_EVENT_TYPE",
					"the requested event type is not supported by the LMF (TS 29.572 Table 6.1.6.3.14-1)")
				return
			}
			if bad := validateDeferred(d); len(bad) > 0 {
				log.Warn("DetermineLocation: invalid deferred-location request",
					"result", "REJECT", "cause", "MANDATORY_IE_INCORRECT",
					"spec_ref", "TS 29.572 §5.2.2.2")
				metrics.LMFLocateTotal.WithLabelValues("REJECT").Inc()
				procDeferred("REJECT")
				s.problemInvalid(w, "MANDATORY_IE_INCORRECT",
					"deferred location request is invalid (TS 29.572 InputData)", bad...)
				return
			}
			deferred = d
		}
	}

	supi := req.Supi
	if supi == "" {
		supi = req.Gpsi
	}
	// The UE context identifier used towards the AMF (Namf_Location) and as the
	// pendingLoc key is the resolved SUPI (or GPSI) from the request body.
	ueContextID := supi
	log = log.With("supi", supi, "ue_context_id", ueContextID)

	// ---- Location privacy check (TS 23.273 §9.1) ---------------------------------
	// Query UDM lcsData before disclosing the UE's location to the LCS client.
	// A BLOCK_ALL policy results in 403 PRIVACY_EXCEPTION_DENIED; any other value
	// (ALLOW_ALL, ALLOW_PLMN_OPERATOR_SERVICES, or unknown) allows the request.
	// The check is skipped when PrivacyCheck is false or udmClient is nil.
	// Ref: TS 29.503 §5.2.2, TS 29.572 §5.2.2.2 error table.
	if s.cfg.PrivacyCheck && s.udmClient != nil {
		priv, err := s.udmClient.GetLcsPrivacyData(ctx, supi)
		if err != nil {
			log.Warn("DetermineLocation: UDM lcsData fetch failed — proceeding (fail-open)",
				"error", err, "supi", supi)
		} else if priv != nil && priv.LocationPrivacy == "BLOCK_ALL" {
			log.Warn("DetermineLocation: location blocked by subscriber privacy policy",
				"supi", supi, "result", "REJECT", "cause", "PRIVACY_EXCEPTION_DENIED",
				"spec_ref", "TS 23.273 §9.1",
			)
			metrics.LMFLocateTotal.WithLabelValues("REJECT").Inc()
			s.problem(w, http.StatusForbidden, "PRIVACY_EXCEPTION_DENIED",
				"location disclosure blocked by subscriber privacy settings")
			return
		}
	}

	if deferred != nil {
		if s.startDeferredLocation(ctx, w, deferred, ueContextID, supi, sfAnswer) {
			features.LogNegotiation(ctx, s.baseLogger, features.Negotiation{
				NF:        "LMF",
				Interface: "Nlmf", Direction: "IN", PeerNF: peerNF,
				SpecRef: features.SpecRef, Result: "OK",
				Local: s.cat.Supported(s.profile), Peer: req.SupportedFeatures,
				PeerPresent: req.SupportedFeatures != "", Negotiated: sfSet,
			})
		}
		return
	}

	// ---- Register in pendingLoc for CancelLocation (TS 29.572 §5.2.2.4.2) -------
	locCtx, locCancel := context.WithCancel(ctx)
	defer locCancel()
	s.pendingLoc.Store(ueContextID, locCancel)
	defer s.pendingLoc.Delete(ueContextID)

	// ---- Quality-driven method selection (TS 23.273 §6.2.9 / §6.2.10) --------
	// hAccuracy from the request body determines the positioning method:
	//   ≤ 0 or > 200 m → Cell-ID (LMF-001)
	//   50 ≤ x ≤ 200 m → E-CID via NRPPa relay (LMF-004)
	//   0 < x < 50 m   → GNSS via LPP relay (LMF-005)
	// Each method is only attempted when its client is wired; an unwired
	// client downgrades one tier at a time: GNSS → E-CID → Cell-ID.
	// Ref: TS 23.273 §6.2.9 / §6.2.10; TS 29.572 §5.2.2.2.
	var hAccuracy float64
	if req.LocationQoS != nil {
		hAccuracy = req.LocationQoS.HAccuracy
	}
	method := selectMethod(hAccuracy)
	if method == methodLPP && s.lppClient == nil {
		// LPP client not wired — downgrade to E-CID.
		// Ref: docs/procedures/LPPRelay.md §Implementation notes (graceful downgrade).
		log.Info("DetermineLocation: GNSS/LPP requested but LPP client not wired — using E-CID",
			"h_accuracy_m", hAccuracy,
			"spec_ref", "TS 23.273 §6.2.10",
		)
		method = methodECID
	}
	if method == methodECID && s.nrppaClient == nil {
		// NRPPa client not wired — downgrade to Cell-ID.
		// Ref: NRPPaRelay.md §Implementation notes (graceful downgrade).
		log.Info("DetermineLocation: E-CID requested but NRPPa client not wired — using Cell-ID",
			"h_accuracy_m", hAccuracy,
			"spec_ref", "TS 23.273 §6.2.9",
		)
		method = methodCellID
	}
	log.Info("DetermineLocation: positioning method selected",
		"method", method.String(),
		"h_accuracy_m", hAccuracy,
		"spec_ref", "TS 23.273 §6.2.9 / §6.2.10",
	)

	// ---- Dispatch to positioning method ----------------------------------------
	var (
		locResp *LocationData
		cause   string
		err     error
	)
	switch method {
	case methodLPP:
		// GNSS: LPP capability + assistance + measurement rounds via AMF NAS
		// relay (LMF-005). On any LPP failure, performLPPOrFallback
		// transparently falls back to E-CID then Cell-ID.
		// Ref: TS 37.355 §6; TS 23.273 §6.2.10.
		log.Info("DetermineLocation: dispatching to GNSS/LPP positioning",
			"interface", "Namf",
			"direction", "OUT",
			"spec_ref", "TS 29.518 §5.2.2.6 / TS 37.355 §6",
		)
		locResp, cause, err = s.performLPPOrFallback(locCtx, ueContextID, supi)
	case methodECID:
		// E-CID: NRPPa capability + measurement rounds via AMF relay (LMF-004).
		// On any NRPPa failure, performECIDOrFallback transparently calls s.locate().
		// Ref: TS 38.455 §8; TS 23.273 §6.2.9.
		log.Info("DetermineLocation: dispatching to E-CID positioning",
			"interface", "Namf",
			"direction", "OUT",
			"spec_ref", "TS 29.518 §5.2.2.6 / TS 38.455 §8",
		)
		locResp, cause, err = s.performECIDOrFallback(locCtx, ueContextID, supi)
	default:
		// Cell-ID: delegate to AMF Namf_Location ProvideLocationInfo (LMF-001).
		// Ref: TS 29.518 §5.2.2.6; TS 23.273 §7.2.
		log.Info("DetermineLocation: calling AMF Namf_Location (Cell-ID)",
			"interface", "Namf",
			"direction", "OUT",
			"spec_ref", "TS 29.518 §5.2.2.6",
		)
		locResp, cause, err = s.locate(locCtx, ueContextID, supi)
	}
	if err != nil {
		s.locateFailed(log, w, err, cause, start)
		return
	}

	durationMs := time.Since(start).Milliseconds()
	log.Info("DetermineLocation: success",
		"interface", "Nlmf",
		"direction", "OUT",
		"spec_ref", "TS 29.572 §5.2.2.2",
		"nr_cell_id", locResp.NRCellId,
		"result", "OK",
		"duration_ms", durationMs,
	)
	metrics.LMFLocateTotal.WithLabelValues("OK").Inc()

	// Request accepted: record the negotiation (TS 29.500 §6.6.2).
	features.LogNegotiation(ctx, s.baseLogger, features.Negotiation{
		NF:        "LMF",
		Interface: "Nlmf", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.cat.Supported(s.profile), Peer: req.SupportedFeatures,
		PeerPresent: req.SupportedFeatures != "", Negotiated: sfSet,
	})

	// Answer on a copy: locResp may be shared with the positioning method.
	out := locResp.wireFor(features.SpecLiteral(s.profile))
	out.SupportedFeatures = sfAnswer
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(&out)
}

// locateFailed answers a failed positioning attempt: 404 when the AMF has no
// UE context, 504 for any other location failure.
//
// Ref: TS 29.572 §5.2.2.2; TS 29.518 §5.2.2.6.
func (s *Server) locateFailed(log *slog.Logger, w http.ResponseWriter, err error, cause string, start time.Time) {
	durationMs := time.Since(start).Milliseconds()
	if errors.Is(err, ErrUEContextNotFound) {
		log.Info("DetermineLocation: UE context not found in AMF",
			"interface", "Namf",
			"direction", "IN",
			"spec_ref", "TS 29.572 §5.2.2.2",
			"result", "FAILURE",
			"cause", cause,
			"duration_ms", durationMs,
		)
		metrics.LMFLocateTotal.WithLabelValues("FAILURE").Inc()
		s.problem(w, http.StatusNotFound, cause, "UE context not found in AMF")
		return
	}
	// Location failure (timeout, CM-IDLE, gNB error, unreachable, or ctx cancelled).
	log.Warn("DetermineLocation: AMF location request failed",
		"interface", "Namf",
		"direction", "IN",
		"spec_ref", "TS 29.572 §5.2.2.2",
		"result", "FAILURE",
		"cause", cause,
		"error", err,
		"duration_ms", durationMs,
	)
	metrics.LMFLocateTotal.WithLabelValues("FAILURE").Inc()
	s.problem(w, http.StatusGatewayTimeout, cause, "AMF location request failed: "+err.Error())
}

// rejectSupportedFeatures answers a schema-invalid supportedFeatures with 400
// INVALID_MSG_FORMAT and invalidParams[{param: /supportedFeatures}] and logs
// the REJECT negotiation record. Ref: TS 29.500 §5.2.7.2; TS 29.571 §5.2.4.6.
func (s *Server) rejectSupportedFeatures(ctx context.Context, w http.ResponseWriter, peerNF, shown string, cause error) {
	features.LogNegotiation(ctx, s.baseLogger, features.Negotiation{
		NF:        "LMF",
		Interface: "Nlmf", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: features.CauseInvalidMsgFormat,
		Local: s.cat.Supported(s.profile), Peer: shown, PeerPresent: true,
	}, "error", cause)
	metrics.LMFLocateTotal.WithLabelValues("REJECT").Inc()
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

// payloadTooLarge answers a body over features.MaxRequestBodyBytes with 413 and
// a ProblemDetails without a cause (no 413 cause is defined), after logging one
// REJECT record and counting it.
// Ref: TS 29.500 §5.2.7.1; TS 29.571 §5.2.4.1.
func payloadTooLarge(log *slog.Logger, w http.ResponseWriter) {
	log.Warn("request body too large",
		"result", "REJECT", "cause", "PAYLOAD_TOO_LARGE")
	metrics.LMFLocateTotal.WithLabelValues("REJECT").Inc()
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusRequestEntityTooLarge,
		"detail": "request body too large",
	})
}

// locate is the shared internal positioning method used by both handleDetermineLocation
// and the EventSubscription goroutines. It calls the AMF Namf_Location service and
// synthesizes a WGS84 coordinate via the mobility model.
//
// Returns (LocationData, "", nil) on success.
// Returns (nil, cause, error) on any failure.
//
// The privacy gate is NOT applied here — callers are responsible for checking privacy
// before calling locate (once at Create for subscriptions, at handler entry for one-shots).
//
// Ref: TS 29.572 §5.2.2.2; TS 29.518 §5.2.2.6; TS 23.273 §7.2.
func (s *Server) locate(ctx context.Context, ueContextID, supi string) (*LocationData, string, error) {
	amfLoc, cause, err := s.amfClient.ProvideLocationInfo(ctx, ueContextID)
	if err != nil {
		return nil, cause, err
	}

	// Build the LocationEstimate.
	// If the AMF already carries a valid POINT with non-zero coordinates (e.g. from
	// a scripted test client or a future AMF that includes GAD shapes), prefer it.
	// Otherwise synthesize a WGS84 coordinate via the mobility model.
	// Ref: TS 29.572 §6.1.6.2.2 (locationEstimate, GeographicArea shape=POINT).
	var locationEstimate *GeographicArea
	if amfLoc.LocationEstimate != nil &&
		amfLoc.LocationEstimate.Point != nil &&
		(amfLoc.LocationEstimate.Point.Lat != 0 || amfLoc.LocationEstimate.Point.Lon != 0) {
		// Use the AMF-provided coordinate directly.
		locationEstimate = amfLoc.LocationEstimate
	} else {
		lat, lon, accuracyM := s.mobility.position(supi, amfLoc.NRCellId, time.Now())
		locationEstimate = &GeographicArea{
			Shape:       "POINT",
			Point:       &LatLon{Lat: lat, Lon: lon},
			Uncertainty: accuracyM,
		}
	}

	loc := &LocationData{
		LocationEstimate:      locationEstimate,
		NRCellId:              amfLoc.NRCellId,
		Tai:                   amfLoc.Tai,
		AgeOfLocationEstimate: 0,
	}
	return loc, "", nil
}

// ---- Health -------------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

// ---- helpers ------------------------------------------------------------------

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
