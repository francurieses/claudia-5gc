// Package server implements the LMF Nlmf_Location SBI server.
//
// Routes (TS 29.572 §5.2.2.2):
//
//	POST /nlmf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info → DetermineLocation
//	GET  /healthz                                                  → liveness
//	GET  /metrics                                                  → Prometheus
//
// All SBI endpoints are served over HTTP/2 + mTLS (TS 29.500 §4.4.1).
//
// ALPN invariant: TLSConfig.NextProtos = ["h2"] set BEFORE http2.ConfigureServer.
// Ref: docs/memory/http2_alpn_conformance.md
//
// Ref: TS 29.572 §5.2.2.2, TS 23.273 §7.2, TS 23.501 §6.2.18
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
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// Server is the LMF Nlmf_Location SBI server.
type Server struct {
	cfg       *config.Config
	logger    *slog.Logger
	httpSrv   *http.Server
	amfClient AMFLocationClient
}

// New constructs the LMF SBI server with an injected AMF location client.
// Pass a real HTTPAMFLocationClient in production or a test double in tests.
// Call Start or Handler() to begin serving.
func New(cfg *config.Config, logger *slog.Logger, amfClient AMFLocationClient) *Server {
	s := &Server{
		cfg:       cfg,
		logger:    logger.With("nf", "LMF"),
		amfClient: amfClient,
	}

	mux := http.NewServeMux()
	// Nlmf_Location DetermineLocation — TS 29.572 §5.2.2.2.
	mux.HandleFunc("POST /nlmf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info", s.handleDetermineLocation)
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
// with mTLS + HTTP/2 (h2 ALPN). Otherwise falls back to plain h2c (suitable
// for unit and functional tests).
//
// ALPN invariant: TLSConfig.NextProtos = ["h2"] MUST be set BEFORE ConfigureServer.
// Ref: TS 29.500 §4.4.2; docs/memory/http2_alpn_conformance.md.
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

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
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

// ---- DetermineLocation (POST /nlmf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info) ----

// nlmfRequest is the request body for Nlmf_Location_DetermineLocation.
// The ueContextId is in the path; the body carries QoS/priority and the UE identifier.
//
// Ref: TS 29.572 §6.1.6.2.x (RequestLocInfo for Nlmf_Location)
type nlmfRequest struct {
	// Supi is the UE permanent identity. One of Supi/Gpsi must be present.
	Supi string `json:"supi,omitempty"`
	// Gpsi is the Generic Public Subscription Identifier (alternative to Supi).
	Gpsi string `json:"gpsi,omitempty"`
	// LocationQoS holds accuracy/response-time hints (optional).
	LocationQoS *locationQoS `json:"locationQoS,omitempty"`
	// Priority is the LCS priority hint (optional).
	Priority string `json:"priority,omitempty"`
}

// locationQoS holds optional location quality-of-service parameters.
// Ref: TS 29.572 §6.1.6.2.x (LocationQoS).
type locationQoS struct {
	HAccuracy    float64 `json:"hAccuracy,omitempty"`
	VAccuracy    float64 `json:"vAccuracy,omitempty"`
	ResponseTime string  `json:"responseTime,omitempty"`
}

// handleDetermineLocation implements Nlmf_Location_DetermineLocation (POST).
//
// Flow:
//  1. Validate request — at least one of supi/gpsi must be present.
//  2. Call AMF Namf_Location_ProvideLocationInfo.
//  3. Map AMF response to Nlmf LocationData; apply NRCGI→coord lookup.
//  4. Return 200 LocationData, or an appropriate ProblemDetails on error.
//
// Ref: TS 29.572 §5.2.2.2; TS 23.273 §7.2.
func (s *Server) handleDetermineLocation(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ueContextID := r.PathValue("ueContextId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)

	log := logging.NewProcedureLogger(ctx, s.logger, "DetermineLocation").With(
		"nf", "LMF",
		"interface", "Nlmf",
		"direction", "IN",
		"spec_ref", "TS 29.572 §5.2.2.2",
		"ue_context_id", ueContextID,
		"correlation_id", corrID,
	)

	log.Info("DetermineLocation request received")

	// ---- Validate request body ------------------------------------------------
	// supi or gpsi is required to identify the UE.
	// Ref: TS 29.572 §5.2.2.2; error table: "UE not identifiable → 400 MANDATORY_IE_MISSING".
	var req nlmfRequest
	// An empty body is valid per spec (ueContextId in path is the identity);
	// but the feature file scenario 5 tests a body with neither supi nor gpsi
	// and expects 400. We decode what's there and check.
	_ = json.NewDecoder(r.Body).Decode(&req) // tolerate empty/missing body

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

	supi := req.Supi
	if supi == "" {
		supi = req.Gpsi
	}
	log = log.With("supi", supi)

	// ---- Call AMF Namf_Location_ProvideLocationInfo ----------------------------
	// Ref: TS 29.518 §5.2.2.6; TS 23.273 §7.2.
	log.Info("DetermineLocation: calling AMF Namf_Location",
		"interface", "Namf",
		"direction", "OUT",
		"spec_ref", "TS 29.518 §5.2.2.6",
	)

	amfLoc, cause, err := s.amfClient.ProvideLocationInfo(ctx, ueContextID)
	if err != nil {
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
		// Location failure (timeout, CM-IDLE, gNB error, unreachable).
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
		return
	}

	// ---- Build Nlmf_Location response -----------------------------------------
	// Map NRCGI → WGS84 coordinate from config; fall back to 0,0.
	// Ref: TS 29.572 §6.1.6.2.2 (locationEstimate, GeographicArea shape=POINT).
	lat, lon := s.lookupCoord(amfLoc.NRCellId)
	locResp := LocationData{
		LocationEstimate: &GeographicArea{
			Shape: "POINT",
			Point: &LatLon{Lat: lat, Lon: lon},
		},
		NRCellId:              amfLoc.NRCellId,
		Tai:                   amfLoc.Tai,
		AgeOfLocationEstimate: 0,
	}

	durationMs := time.Since(start).Milliseconds()
	log.Info("DetermineLocation: success",
		"interface", "Nlmf",
		"direction", "OUT",
		"spec_ref", "TS 29.572 §5.2.2.2",
		"nr_cell_id", amfLoc.NRCellId,
		"result", "OK",
		"duration_ms", durationMs,
	)
	metrics.LMFLocateTotal.WithLabelValues("OK").Inc()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(locResp)
}

// lookupCoord returns the configured lat/lon for the given nrCellId hex string.
// Returns (0, 0) when no entry is found (placeholder; authoritative output is nrCellId).
// Ref: TS 29.572 §6.1.6.2.2
func (s *Server) lookupCoord(nrCellId string) (float64, float64) {
	if coord, ok := s.cfg.CellCoordinates[nrCellId]; ok {
		return coord.Lat, coord.Lon
	}
	return 0, 0
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
