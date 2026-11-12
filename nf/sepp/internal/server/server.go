// Package server implements the SEPP HTTP/2 servers: the SBI server (health,
// metrics, correlation-id middleware) and the N32 listener that carries only
// the N32-c exchange-capability route (REL19-9.4); N32-f is added by REL19-9.5.
//
// Ref: TS 23.501 §6.2.17 (SEPP), TS 29.573 (N32), TS 29.500 §4.4 (HTTP/2 + TLS).
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32c"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32f"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

const (
	// readHeaderTimeout bounds request header reads (slowloris guard).
	readHeaderTimeout = 5 * time.Second
	// shutdownTimeout bounds graceful shutdown.
	shutdownTimeout = 5 * time.Second
	// n32ReadTimeout bounds a whole N32 request read.
	n32ReadTimeout = 10 * time.Second
	// n32WriteTimeout bounds an N32 response write.
	n32WriteTimeout = 10 * time.Second
	// n32IdleTimeout bounds an idle N32 connection.
	n32IdleTimeout = 60 * time.Second
	// n32MaxHeaderBytes bounds N32 request headers.
	n32MaxHeaderBytes = 16 << 10
	// n32MinTLSVersion: N32 accepts TLS 1.2 and 1.3. Ref: TS 33.210 §6.2.
	n32MinTLSVersion = tls.VersionTLS12
)

// mounted caches the N32-f handlers of the mounted forwarder.
type mounted struct{ out, in http.Handler }

// Server is the SEPP SBI server.
type Server struct {
	cfg     *config.Config
	logger  *slog.Logger
	httpSrv *http.Server
	n32Srv  *http.Server
	n32     *n32c.Service
	n32Err  error
	// fwd is the N32-f forwarder, mounted after construction (MountForwarder).
	fwd atomic.Pointer[mounted]
	// plainN32 allows the N32 listener without certificates (tests only).
	plainN32 bool
}

// AllowPlainN32ForTests lets StartN32 serve h2c without certificates. It
// exists for tests only; production refuses to start the N32 listener without
// TLS (TS 33.501 §13.1: N32 is always TLS-protected).
func (s *Server) AllowPlainN32ForTests() { s.plainN32 = true }

// New constructs the SEPP server.
func New(cfg *config.Config, logger *slog.Logger) *Server {
	s := &Server{cfg: cfg, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.Handle("GET /metrics", promhttp.Handler())
	// Own endpoints accept GET only; never forward them to a peer.
	notAllowed := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
	mux.HandleFunc("/healthz", notAllowed)
	mux.HandleFunc("/metrics", notAllowed)
	// Everything that is not the SEPP's own endpoints is traffic from local NFs
	// towards a roaming peer: N32-f outbound. Ref: TS 29.573 §5.3, TS 23.501 §6.2.17.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if f := s.fwd.Load(); f != nil {
			f.out.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
	s.httpSrv = &http.Server{
		Addr:              cfg.SBI.Address,
		Handler:           s.middleware(mux),
		ReadHeaderTimeout: readHeaderTimeout,
	}

	// N32 listener: only the N32-c route (the SBI mux is never exposed here).
	partners := make([]n32c.PlmnId, 0, len(cfg.N32.RoamingPartners))
	for _, p := range cfg.N32.RoamingPartners {
		partners = append(partners, n32c.PlmnId{Mcc: p.MCC, Mnc: p.MNC})
	}
	svc, err := n32c.New(n32c.Config{
		LocalPLMN:              n32c.PlmnId{Mcc: cfg.PLMN.MCC, Mnc: cfg.PLMN.MNC},
		LocalFQDN:              cfg.SBI.FQDN,
		Partners:               partners,
		Profile:                capability.ProfileFrom(nil),
		TargetAPIRootSupported: cfg.N32.TargetAPIRootSupported,
		Logger:                 logger,
	})
	if err != nil {
		s.n32Err = fmt.Errorf("sepp: server: n32c service: %w", err)
		logger.Error("N32-c service disabled", "error", err, "spec_ref", "TS 29.573 §5.2.2")
	} else {
		s.n32 = svc
		s.n32Srv = &http.Server{
			Addr:              cfg.N32.Address,
			Handler:           s.middleware(s.n32Mux(svc)),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       n32ReadTimeout,
			WriteTimeout:      n32WriteTimeout,
			IdleTimeout:       n32IdleTimeout,
			MaxHeaderBytes:    n32MaxHeaderBytes,
		}
	}
	return s
}

// n32Mux serves the N32-c route and, once mounted, N32-f inbound for every
// other path (SBI mux is never exposed on the N32 listener).
func (s *Server) n32Mux(svc *n32c.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(svc.RoutePattern(), svc.HandleExchangeCapability)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if f := s.fwd.Load(); f != nil {
			f.in.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

// MountForwarder mounts the N32-f forwarder on both listeners and wires it as
// the N32-c terminator. Call before Start/StartN32. Ref: TS 29.573 §5.2.2, §5.3.
func (s *Server) MountForwarder(f *n32f.Forwarder) {
	s.fwd.Store(&mounted{out: f.Outbound(), in: f.Inbound()})
	if s.n32 != nil {
		s.n32.SetTerminator(f.Terminate)
	}
}

// N32 returns the N32-c service (nil if the configuration was invalid).
func (s *Server) N32() *n32c.Service { return s.n32 }

// N32Handler returns the N32 listener handler for in-process tests (no TLS).
func (s *Server) N32Handler() http.Handler {
	if s.n32Srv == nil {
		return http.NotFoundHandler()
	}
	return s.n32Srv.Handler
}

// StartN32 serves the N32 listener until ctx is cancelled: mTLS with client
// certificate verification (TLS 1.2+, h2) when certificates are configured,
// plain h2c otherwise (tests only). Ref: TS 33.210 §6.2, TS 29.573 §5.2.1.
func (s *Server) StartN32(ctx context.Context) error {
	if s.n32Srv == nil {
		if s.n32Err != nil {
			return s.n32Err
		}
		return errors.New("sepp: server: N32 listener not configured")
	}
	f := s.cfg.N32TLS()
	if f.CertFile == "" && !s.plainN32 {
		return errors.New("sepp: server: N32 listener requires TLS certificates (n32.tls or sbi.tls)")
	}
	return s.serve(ctx, s.n32Srv, f, n32MinTLSVersion, "N32")
}

// Handler returns the HTTP handler for in-process tests (no TLS).
func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }

// Start serves the SBI listener until ctx is cancelled. With TLS configured it
// requires client certificates (mTLS) and negotiates h2; otherwise it serves
// plain h2c (tests only).
func (s *Server) Start(ctx context.Context) error {
	return s.serve(ctx, s.httpSrv, config.TLSFiles{
		CertFile: s.cfg.SBI.TLS.CertFile, KeyFile: s.cfg.SBI.TLS.KeyFile, CAFile: s.cfg.SBI.TLS.CAFile,
	}, tls.VersionTLS13, "SBI")
}

// serve runs srv with the shared TLS material.
// ALPN invariant: NextProtos is set before http2.ConfigureServer.
func (s *Server) serve(ctx context.Context, srv *http.Server, files config.TLSFiles, minVersion uint16, label string) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if files.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(files.CertFile, files.KeyFile)
		if err != nil {
			return fmt.Errorf("sepp: server: load TLS cert: %w", err)
		}
		caPEM, err := os.ReadFile(files.CAFile)
		if err != nil {
			return fmt.Errorf("sepp: server: load CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("sepp: server: %s CA file %q has no valid certificate", label, files.CAFile)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   minVersion,
			NextProtos:   []string{"h2"},
		}
		if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
			return fmt.Errorf("sepp: server: configure http2: %w", err)
		}
		s.logger.Info("SEPP "+label+" listening (mTLS + HTTP/2)", "addr", srv.Addr)
		if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("sepp: server: listen: %w", err)
		}
		return nil
	}

	srv.Handler = h2c.NewHandler(srv.Handler, &http2.Server{})
	s.logger.Info("SEPP "+label+" listening (plain h2c — no TLS configured)", "addr", srv.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("sepp: server: listen: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.n32Srv != nil {
		_ = s.n32Srv.Shutdown(ctx)
	}
	return s.httpSrv.Shutdown(ctx)
}

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

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
