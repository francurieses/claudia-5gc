// Package server implements the HTTP/2 SBI server for the NRF.
//
// Endpoints implemented (3GPP TS 29.510 v17):
//
//   PUT    /nnrf-nfm/v1/nf-instances/{nfInstanceId}      NFRegister
//   PATCH  /nnrf-nfm/v1/nf-instances/{nfInstanceId}      NFUpdate
//   DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceId}      NFDeregister
//   GET    /nnrf-nfm/v1/nf-instances/{nfInstanceId}      NFProfileRetrieve
//   GET    /nnrf-disc/v1/nf-instances                    NFDiscover
//   GET    /healthz                                      Liveness probe
//   GET    /metrics                                      Prometheus metrics
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
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/nrf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/nrf/internal/registry"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// Server is the NRF HTTP/2 SBI server.
type Server struct {
	cfg          *config.Config
	reg          registry.Registry
	subs         *registry.SubscriptionStore
	logger       *slog.Logger
	sbiSrv       *http.Server
	metrics      *http.Server
	oauth2Secret []byte
	// httpClient is used for sending NFStatusNotify callbacks to subscribers.
	httpClient *http.Client
}

// New constructs a Server.
func New(cfg *config.Config, reg registry.Registry, logger *slog.Logger) (*Server, error) {
	// Build the outbound client used for NFStatusNotify callbacks.
	// Must use mTLS so subscriber NFs (which require client certs) accept the connection.
	// Ref: TS 29.500 §4.4.1, TS 33.501 §13
	var notifyClient *http.Client
	if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" {
		nc, err := sbi.NewMTLSClient(cfg.SBI.TLS.CAFile, cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("sbi: build notify client: %w", err)
		}
		notifyClient = nc
	} else {
		notifyClient = newH2CClient()
	}

	mux := http.NewServeMux()
	s := &Server{
		cfg:          cfg,
		reg:          reg,
		subs:         registry.NewSubscriptionStore(),
		logger:       logger.With("component", "sbi-server"),
		oauth2Secret: []byte(cfg.OAuth2Secret),
		httpClient:   notifyClient,
	}

	// SBI routes
	mux.HandleFunc("GET /nnrf-nfm/v1/nf-instances", s.handleList)
	mux.HandleFunc("PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}", s.handleRegister)
	mux.HandleFunc("PATCH /nnrf-nfm/v1/nf-instances/{nfInstanceId}", s.handleUpdate)
	mux.HandleFunc("DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceId}", s.handleDeregister)
	mux.HandleFunc("GET /nnrf-nfm/v1/nf-instances/{nfInstanceId}", s.handleGet)
	mux.HandleFunc("GET /nnrf-disc/v1/nf-instances", s.handleDiscover)
	// NFStatusSubscribe/Unsubscribe — TS 29.510 §5.2.2.7-9
	mux.HandleFunc("POST /nnrf-nfm/v1/subscriptions", s.handleSubscribe)
	mux.HandleFunc("DELETE /nnrf-nfm/v1/subscriptions/{subscriptionId}", s.handleUnsubscribe)
	// OAuth2 token endpoint — TS 33.501 §13.4.1
	mux.HandleFunc("POST /oauth2/v1/token", s.handleToken)
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	tlsCfg, err := loadTLSConfig(cfg.SBI.TLS)
	if err != nil {
		return nil, fmt.Errorf("sbi: load TLS config: %w", err)
	}
	if tlsCfg == nil {
		s.logger.Warn("TLS not configured, using H2C cleartext (DEV ONLY)")
	}

	s.sbiSrv = &http.Server{
		Addr:              cfg.SBI.Address,
		Handler:           otelhttp.NewHandler(s.middleware(mux), "NRF"),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Metrics server (separado para no exponer Prometheus en SBI)
	mmux := http.NewServeMux()
	mmux.Handle("/metrics", promhttp.Handler())
	s.metrics = &http.Server{
		Addr:              cfg.Metrics.Address,
		Handler:           mmux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// Start runs both servers until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		s.logger.Info("metrics server listening", "addr", s.cfg.Metrics.Address)
		if err := s.metrics.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("metrics server", "error", err)
		}
	}()

	s.logger.Info("SBI server listening", "addr", s.cfg.SBI.Address, "tls", s.sbiSrv.TLSConfig != nil)
	if s.sbiSrv.TLSConfig != nil {
		_ = http2.ConfigureServer(s.sbiSrv, &http2.Server{})
		return s.sbiSrv.ListenAndServeTLS("", "")
	}
	s.sbiSrv.Handler = h2c.NewHandler(s.sbiSrv.Handler, &http2.Server{})
	return s.sbiSrv.ListenAndServe()
}

// Shutdown stops both servers gracefully.
func (s *Server) Shutdown(ctx context.Context) error {
	_ = s.metrics.Shutdown(ctx)
	return s.sbiSrv.Shutdown(ctx)
}

// ServeH2C serves HTTP/2 cleartext on an already-bound net.Listener.
// Useful for tests that need a pre-allocated port.
func (s *Server) ServeH2C(ln net.Listener) error {
	s.sbiSrv.Handler = h2c.NewHandler(s.sbiSrv.Handler, &http2.Server{})
	return s.sbiSrv.Serve(ln)
}

// middleware adds correlation IDs, structured access logs, and soft Bearer
// token validation to every request. Token validation is in soft mode (logs
// WARN but does not reject) to allow gradual rollout. Set
// OAUTH2_ENFORCE=true to reject requests without valid tokens.
func (s *Server) middleware(next http.Handler) http.Handler {
	enforce := os.Getenv("OAUTH2_ENFORCE") == "true"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corr := r.Header.Get("X-Correlation-Id")
		if corr == "" {
			corr = ulid.Make().String()
			r.Header.Set("X-Correlation-Id", corr)
		}
		w.Header().Set("X-Correlation-Id", corr)

		// Bearer token validation (skip for /healthz and /oauth2/v1/token).
		if r.URL.Path != "/healthz" && !strings.HasPrefix(r.URL.Path, "/oauth2/") {
			authHdr := r.Header.Get("Authorization")
			if strings.HasPrefix(authHdr, "Bearer ") {
				token := strings.TrimPrefix(authHdr, "Bearer ")
				if _, err := validateBearerToken(s.oauth2Secret, token); err != nil {
					s.logger.Warn("invalid Bearer token",
						"path", r.URL.Path,
						"error", err,
						"enforce", enforce,
						"spec_ref", "TS 33.501 §13.4.1",
					)
					if enforce {
						problem(w, http.StatusUnauthorized, "INVALID_TOKEN", err.Error())
						return
					}
				}
			} else if enforce && authHdr == "" {
				problem(w, http.StatusUnauthorized, "MISSING_TOKEN",
					"Authorization: Bearer required")
				return
			}
		}

		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		s.logger.Info("sbi access",
			"correlation_id", corr,
			"interface", "Nnrf",
			"direction", "IN",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }

// ---- Handlers ----------------------------------------------------------

// handleListAll implements GET /nnrf-nfm/v1/nf-instances (TS 29.510 §5.2.2.6 NFListRetrieval).
// Returns all registered NF profiles in SearchResult format for portal/tooling use.
func (s *Server) handleListAll(w http.ResponseWriter, r *http.Request) {
	profiles := s.reg.ListAll()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"nfInstances": profiles,
	})
}

// handleRegister implements PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}
// (TS 29.510 §5.2.2.2.2 — NFRegister).
// The response always carries heartBeatTimer so NFs know the expected interval.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("nfInstanceId")
	var p registry.NFProfile
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	if p.NFInstanceID != "" && p.NFInstanceID != id {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "nfInstanceId in body and URI mismatch")
		return
	}
	p.NFInstanceID = id
	if p.HeartBeatTimer == 0 {
		p.HeartBeatTimer = registry.DefaultHeartbeatTimer
	}
	if err := s.reg.Register(&p); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	metrics.NFInstancesRegistered.WithLabelValues(string(p.NFType)).Inc()
	go s.notifySubscribers(registry.NFEventRegistered, &p)
	w.Header().Set("Location", fmt.Sprintf("/nnrf-nfm/v1/nf-instances/%s", id))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // TS 29.510: 201 on create, 200 on update
	_ = json.NewEncoder(w).Encode(p)
}

// handleUpdate — TS 29.510 §5.2.2.3 (PATCH).
// If the body is a JSON Patch array (starts with '['), it is treated as a
// heartbeat per TS 29.510 §5.2.2.3.4. Otherwise, full profile replace.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("nfInstanceId")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		// JSON Patch heartbeat — TS 29.510 §5.2.2.3.4
		if err := s.reg.Heartbeat(id); err != nil {
			problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Full profile replace
	var p registry.NFProfile
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&p); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	if err := s.reg.Update(id, &p); err != nil {
		problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
		return
	}
	go s.notifySubscribers(registry.NFEventProfileChanged, &p)
	w.WriteHeader(http.StatusNoContent)
}

// handleDeregister — TS 29.510 §5.2.2.4.
func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("nfInstanceId")
	// Snapshot profile before deregistering for notification.
	p, existed := s.reg.Get(id)
	if err := s.reg.Deregister(id); err != nil {
		problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
		return
	}
	if existed {
		metrics.NFInstancesRegistered.WithLabelValues(string(p.NFType)).Dec()
		go s.notifySubscribers(registry.NFEventDeregistered, p)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGet — TS 29.510 §5.2.2.5.
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("nfInstanceId")
	p, ok := s.reg.Get(id)
	if !ok {
		problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", "unknown nfInstanceId")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

// handleDiscover — TS 29.510 §5.3.2.2.2.
func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := q.Get("target-nf-type")
	requester := q.Get("requester-nf-type")
	if target == "" || requester == "" {
		problem(w, http.StatusBadRequest, "MANDATORY_QUERY_PARAM_INCORRECT",
			"target-nf-type and requester-nf-type are mandatory")
		return
	}
	filter := registry.DiscoveryFilter{
		TargetNFType:    registry.NFType(target),
		RequesterNFType: registry.NFType(requester),
		ServiceNames:    splitNonEmpty(q.Get("service-names")),
	}
	// Parse optional snssais filter (JSON-encoded array per TS 29.510 §6.2.3.2.3.1)
	if raw := q.Get("snssais"); raw != "" {
		var snssais []registry.SNSSAI
		if err := json.Unmarshal([]byte(raw), &snssais); err == nil {
			filter.SNSSAIs = snssais
		}
	}
	// Parse optional dnn filter (TS 29.510 §6.2.3.2.3.1)
	if dnn := q.Get("dnn"); dnn != "" {
		filter.DNN = dnn
	}
	results := s.reg.Discover(filter)
	discResult := "EMPTY"
	if len(results) > 0 {
		discResult = "OK"
	}
	metrics.NFDiscoveryTotal.WithLabelValues(target, discResult).Inc()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"validityPeriod":    3600,
		"nfInstances":       results,
		"searchId":          ulid.Make().String(),
		"numNfInstComplete": len(results),
	})
}

// handleList implements NFListRetrieval (TS 29.510 §5.2.2.6): returns the set of
// registered NF instances. By default it returns the instance ids; with
// ?detail=true it inlines the full NF profiles. Read-only; consumed by the MCP
// server's nf_list tool.
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	all := s.reg.Discover(registry.DiscoveryFilter{})
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Query().Get("detail") == "true" {
		_ = json.NewEncoder(w).Encode(map[string]any{"nfInstances": all})
	} else {
		ids := make([]string, 0, len(all))
		for _, p := range all {
			ids = append(ids, p.NFInstanceID)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"nfInstances": ids})
	}
	s.logger.Info("NF list retrieval",
		"procedure", "NFListRetrieval",
		"interface", "Nnrf",
		"direction", "IN",
		"results", len(all),
		"spec_ref", "TS 29.510 §5.2.2.6",
	)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

// handleToken implements POST /oauth2/v1/token (client_credentials grant).
// Ref: TS 33.501 §13.4.1
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		problem(w, http.StatusBadRequest, "UNSUPPORTED_GRANT_TYPE",
			"only client_credentials is supported")
		return
	}
	nfInstanceID := r.FormValue("nfInstanceId")
	scope := r.FormValue("scope")
	if nfInstanceID == "" {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "nfInstanceId required")
		return
	}
	token, err := issueJWT(s.oauth2Secret, s.cfg.NFInstanceID, nfInstanceID, scope)
	if err != nil {
		s.logger.Error("issue JWT", "error", err)
		problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", "token issue failed")
		return
	}
	s.logger.Info("access token issued",
		"procedure", "OAuthToken",
		"interface", "Nnrf",
		"subject", nfInstanceID,
		"scope", scope,
		"spec_ref", "TS 33.501 §13.4.1",
	)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(tokenTTL.Seconds()),
	})
}

// ---- helpers -----------------------------------------------------------

// problem encodes an RFC 7807 ProblemDetails payload (TS 29.500 §5.2.7.2).
func problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"cause":  cause,
		"detail": detail,
	})
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	out := strings.Split(s, ",")
	r := out[:0]
	for _, x := range out {
		if x = strings.TrimSpace(x); x != "" {
			r = append(r, x)
		}
	}
	return r
}

func loadTLSConfig(cfg config.TLS) (*tls.Config, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, nil // no TLS; caller will use H2C
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}
	if cfg.CAFile != "" {
		caData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("no certs found in CA file %s", cfg.CAFile)
		}
		// Require and verify client certificates (mutual TLS — TS 33.501 §13).
		tlsCfg.ClientCAs = caPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if path := os.Getenv("SSLKEYLOGFILE"); path != "" {
		if f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
			tlsCfg.KeyLogWriter = f
		}
	}
	return tlsCfg, nil
}

// ---- NFStatusSubscribe / NFStatusNotify (TS 29.510 §5.2.2.7-9) ----------

// handleSubscribe handles POST /nnrf-nfm/v1/subscriptions.
// Creates an NF status subscription; NRF will POST NotificationData to
// the given notificationUri when matching NF profiles change.
// Ref: TS 29.510 §5.2.2.7
func (s *Server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With("procedure", "NFStatusSubscribe", "correlation_id", corrID,
		"interface", "Nnrf", "direction", "IN",
		"spec_ref", "TS 29.510 §5.2.2.7")

	var req struct {
		NotificationURI string `json:"nfStatusNotificationUri"`
		ReqNFType       string `json:"reqNfType,omitempty"`
		ReqNFInstanceID string `json:"reqNfInstanceId,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.NotificationURI == "" {
		http.Error(w, "nfStatusNotificationUri required", http.StatusBadRequest)
		return
	}

	sub := &registry.Subscription{
		NotificationURI: req.NotificationURI,
		ReqNFType:       registry.NFType(req.ReqNFType),
		ReqNFInstanceID: req.ReqNFInstanceID,
	}
	subID := s.subs.Add(sub)

	log.Info("NFStatusSubscription created",
		"subscriptionId", subID,
		"notificationUri", req.NotificationURI,
		"reqNFType", req.ReqNFType,
		"direction", "OUT", "result", "OK",
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/nnrf-nfm/v1/subscriptions/"+subID)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"subscriptionId": subID})
}

// handleUnsubscribe handles DELETE /nnrf-nfm/v1/subscriptions/{subscriptionId}.
// Ref: TS 29.510 §5.2.2.9
func (s *Server) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("subscriptionId")
	s.subs.Delete(subID)
	s.logger.Info("NFStatusSubscription deleted",
		"procedure", "NFStatusUnsubscribe",
		"subscriptionId", subID,
		"spec_ref", "TS 29.510 §5.2.2.9",
	)
	w.WriteHeader(http.StatusNoContent)
}

// notifySubscribers dispatches an NFStatusNotify to all matching subscribers.
// Fire-and-forget — runs in a goroutine, logs failures.
// Ref: TS 29.510 §5.2.2.8
func (s *Server) notifySubscribers(event registry.NFEvent, profile *registry.NFProfile) {
	subs := s.subs.Matching(profile.NFType, profile.NFInstanceID)
	if len(subs) == 0 {
		return
	}

	data := registry.NotificationData{
		Event:         event,
		NFInstanceURI: "/nnrf-nfm/v1/nf-instances/" + profile.NFInstanceID,
	}
	if event != registry.NFEventDeregistered {
		data.NFProfile = profile
	}

	body, err := json.Marshal(data)
	if err != nil {
		s.logger.Error("NFStatusNotify: marshal failed", "error", err)
		return
	}

	for _, sub := range subs {
		sub := sub
		go func() {
			req, err := http.NewRequestWithContext(context.Background(),
				http.MethodPost, sub.NotificationURI, bytes.NewReader(body))
			if err != nil {
				s.logger.Warn("NFStatusNotify: build request failed",
					"subscriptionId", sub.SubscriptionID, "error", err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := s.httpClient.Do(req)
			if err != nil {
				s.logger.Warn("NFStatusNotify: POST failed",
					"procedure", "NFStatusNotify",
					"subscriptionId", sub.SubscriptionID,
					"notificationUri", sub.NotificationURI,
					"event", event,
					"nfInstanceId", profile.NFInstanceID,
					"error", err,
					"spec_ref", "TS 29.510 §5.2.2.8",
				)
				return
			}
			resp.Body.Close()
			s.logger.Info("NFStatusNotify sent",
				"procedure", "NFStatusNotify",
				"subscriptionId", sub.SubscriptionID,
				"notificationUri", sub.NotificationURI,
				"event", event,
				"nfInstanceId", profile.NFInstanceID,
				"nfType", profile.NFType,
				"spec_ref", "TS 29.510 §5.2.2.8",
			)
		}()
	}
}

// newH2CClient returns an HTTP/2 cleartext client for sending notifications.
func newH2CClient() *http.Client {
	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}
