package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	"github.com/francurieses/claudia-5gc/mcp/internal/jsonrpc"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// keepAliveInterval bounds idle time on an SSE stream; a comment frame keeps
// proxies and clients from dropping the connection.
const keepAliveInterval = 15 * time.Second

// SSE is the HTTP Server-Sent-Events transport for network/remote MCP clients.
// It serves an identical tool surface to stdio via the same Dispatcher.
//
// Endpoints:
//
//	POST /mcp           client→server JSON-RPC; response is pushed to the
//	                    caller's SSE stream when ?session=<id> is supplied,
//	                    otherwise returned inline (stateless convenience).
//	GET  /mcp/sse       server→client event stream (one per client session).
//	GET  /mcp/health    liveness probe (always open, no auth).
//	GET  /mcp/tools     tool manifest (JSON).
//	GET  /mcp/sessions  live session list (debug only).
type SSE struct {
	disp    *server.Dispatcher
	reg     *registry.Registry
	mgr     *session.Manager
	cfg     *config.Config
	logger  *slog.Logger
	mux     *http.ServeMux
	httpSrv *http.Server
}

// NewSSE builds the SSE transport.
func NewSSE(disp *server.Dispatcher, reg *registry.Registry, mgr *session.Manager, cfg *config.Config, logger *slog.Logger) *SSE {
	s := &SSE{
		disp:   disp,
		reg:    reg,
		mgr:    mgr,
		cfg:    cfg,
		logger: logger.With("transport", "sse"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mcp/health", s.handleHealth)
	mux.HandleFunc("GET /mcp/tools", s.auth(s.handleTools))
	mux.HandleFunc("GET /mcp/sse", s.auth(s.handleSSE))
	// MCP 2024-11-05 Streamable HTTP: clients open GET /mcp for server→client SSE.
	mux.HandleFunc("GET /mcp", s.auth(s.handleSSE))
	mux.HandleFunc("POST /mcp", s.auth(s.handlePost))
	// OPTIONS on /mcp is required for Electron/Chromium CORS preflight.
	mux.HandleFunc("OPTIONS /mcp", s.handleCORS)
	if cfg.SSE.Debug {
		mux.HandleFunc("GET /mcp/sessions", s.auth(s.handleSessions))
	}
	s.mux = mux
	s.httpSrv = &http.Server{
		Addr:              cfg.SSE.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// Handler exposes the SSE mux for in-process testing (httptest).
func (s *SSE) Handler() http.Handler { return s.mux }

// Start runs the SSE HTTP server until ctx is cancelled. Returns
// http.ErrServerClosed on graceful shutdown.
func (s *SSE) Start(ctx context.Context) error {
	tlsCfg, err := s.loadTLS()
	if err != nil {
		return fmt.Errorf("sse: load TLS: %w", err)
	}
	s.httpSrv.TLSConfig = tlsCfg
	s.logger.Info("SSE transport listening",
		"addr", s.cfg.SSE.ListenAddr,
		"tls", tlsCfg != nil,
		"auth", s.cfg.Auth.Enabled(),
		"debug", s.cfg.SSE.Debug,
	)
	if tlsCfg != nil {
		return s.httpSrv.ListenAndServeTLS("", "")
	}
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the SSE server.
func (s *SSE) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// loadTLS mirrors the NRF SBI TLS loader: nil ⇒ plain HTTP; ca_file ⇒ mTLS.
func (s *SSE) loadTLS() (*tls.Config, error) {
	t := s.cfg.SSE.TLS
	if !t.Enabled() {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if t.CAFile != "" {
		caData, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("no certs in CA file %s", t.CAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// auth wraps a handler with optional Bearer-token enforcement. /mcp/health is
// never wrapped so liveness probes succeed regardless of auth config.
func (s *SSE) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Auth.Enabled() {
			if r.Header.Get("Authorization") != "Bearer "+s.cfg.Auth.BearerToken {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// corsHeaders sets permissive CORS headers required by Electron/Chromium-based
// MCP clients (e.g. Claude Desktop) that enforce same-origin policy on localhost.
func corsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id")
}

// handleCORS responds to OPTIONS preflight requests from Chromium-based clients.
func (s *SSE) handleCORS(w http.ResponseWriter, _ *http.Request) {
	corsHeaders(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *SSE) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"sessions": s.mgr.Count(),
		"tools":    len(s.reg.List()),
	})
}

func (s *SSE) handleTools(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"tools": s.reg.Manifest()})
}

func (s *SSE) handleSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"sessions": s.mgr.Views()})
}

// handleSSE opens a server→client event stream for one client session.
// Handles both GET /mcp/sse (legacy) and GET /mcp (MCP 2024-11-05 Streamable HTTP).
func (s *SSE) handleSSE(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	sess := s.mgr.Register(r.RemoteAddr, r.UserAgent())
	defer s.mgr.Deregister(sess.ID)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Mcp-Session-Id", sess.ID)
	w.WriteHeader(http.StatusOK)

	// Per MCP HTTP+SSE convention, first event tells the client where to POST.
	// Use an absolute URL so clients that don't resolve relative URLs still work.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	postURL := fmt.Sprintf("%s://%s/mcp?session=%s", scheme, r.Host, sess.ID)
	writeSSE(w, flusher, "endpoint", []byte(postURL))

	keepalive := time.NewTicker(keepAliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-sess.Events():
			if !open {
				return
			}
			writeSSE(w, flusher, ev.Name, ev.Data)
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// handlePost handles a client→server JSON-RPC message. If ?session=<id> names a
// live SSE session, the response is pushed onto that stream and the POST returns
// 202 Accepted; otherwise the response is returned inline for stateless callers.
func (s *SSE) handlePost(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	body, err := readBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest,
			jsonrpc.NewError(nil, mcperr.Newf(mcperr.CodeParse, nil, "read body: %v", err)))
		return
	}
	req, perr := jsonrpc.ParseRequest(body)
	if perr != nil {
		writeJSON(w, http.StatusOK, jsonrpc.NewError(nil, perr))
		return
	}

	sid := sessionID(r)
	ctx := r.Context()
	if sid != "" {
		ctx = session.WithID(ctx, sid)
	}
	resp := s.disp.Dispatch(ctx, req)

	if req.IsNotification() {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Stream-routed delivery when the caller owns a live SSE session.
	if sess, ok := s.mgr.Get(sid); ok {
		sess.Touch()
		frame, _ := jsonrpc.WriteFrame(resp)
		if s.mgr.SendTo(sid, session.Event{Name: "message", Data: frame}) {
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}
	// Inline delivery (curl / stateless clients).
	writeJSON(w, http.StatusOK, resp)
}

// sessionID extracts the session id from the query string or header.
func sessionID(r *http.Request) string {
	if v := r.URL.Query().Get("session"); v != "" {
		return v
	}
	return r.Header.Get("Mcp-Session-Id")
}

// ---- small HTTP helpers ---------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSSE(w http.ResponseWriter, f http.Flusher, event string, data []byte) {
	if event != "" {
		fmt.Fprintf(w, "event: %s\n", event)
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
	f.Flush()
}

const maxBodyBytes = 4 << 20 // 4 MiB

func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
}
