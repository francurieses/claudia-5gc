package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/api"
	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/assets"
	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/config"
	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/nrf"
	promclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/prometheus"
	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	addr := envOr("LISTEN_ADDR", ":8080")
	dbURL := envOr("DATABASE_URL", "postgres://5gc:5gc-dev@postgres:5432/5gc?sslmode=disable")
	nrfURL := envOr("NRF_URL", "https://nrf:8000")
	promURL := envOr("PROMETHEUS_URL", "http://prometheus:9090")
	smfURL := envOr("SMF_URL", "https://smf:8004")
	amfURL := envOr("AMF_URL", "http://amf:9002")
	udmURL := envOr("UDM_URL", "https://udm:8003")
	pcfURL := envOr("PCF_URL", "https://pcf:8006")
	lmfURL := envOr("LMF_URL", "https://lmf:8012")
	nfConfigsPath := envOr("NF_CONFIGS_PATH", "/app/nf-configs")
	certFile := envOr("PORTAL_CERT_FILE", "")
	keyFile := envOr("PORTAL_KEY_FILE", "")

	sbiClient := newSBIClient(certFile, keyFile)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("mgmt-portal starting", "addr", addr)

	// PostgreSQL store (gracefully degrade if unavailable)
	db, err := store.New(ctx, dbURL)
	if err != nil {
		slog.Warn("postgres unavailable — subscriber/session features disabled", "err", err)
	} else {
		slog.Info("postgres connected")
		defer db.Close()
		if err := db.Migrate(ctx); err != nil {
			slog.Warn("store migrate failed", "err", err)
		} else if err := db.SeedDefaultTemplates(ctx); err != nil {
			slog.Warn("seed default templates failed", "err", err)
		} else {
			slog.Info("policy templates ready")
		}
	}

	// Docker client (gracefully degrade if socket not mounted)
	docker, err := dockerclient.New()
	if err != nil {
		slog.Warn("docker socket unavailable — services feature disabled", "err", err)
	} else {
		slog.Info("docker client ready")
		defer docker.Close()
	}

	deps := api.Deps{
		Store:      db,
		Docker:     docker,
		NRF:        nrf.New(nrfURL, sbiClient),
		Prometheus: promclient.New(promURL),
		Config:     config.New(nfConfigsPath),
		SMFBaseURL: smfURL,
		AMFBaseURL: amfURL,
		UDMBaseURL: udmURL,
		PCFBaseURL: pcfURL,
		LMFBaseURL: lmfURL,
		MTLSClient: sbiClient,
	}

	handler := api.NewRouter(deps, http.FS(assets.FS()))

	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // no timeout — WebSocket log streaming requires indefinite writes
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("http server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server error", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	srv.Shutdown(shutCtx) //nolint:errcheck
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// newSBIClient builds an HTTP/2-capable client that presents the portal's
// mTLS client certificate when connecting to NFs that enforce mutual TLS.
// Server certificate verification is intentionally skipped (dev tool, self-signed CA).
func newSBIClient(certFile, keyFile string) *http.Client {
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			slog.Warn("portal mTLS cert load failed — NRF/AMF healthz will show red", "err", err)
		} else {
			tlsCfg.Certificates = []tls.Certificate{cert}
			slog.Info("portal mTLS client cert loaded", "cert", certFile)
		}
	} else {
		slog.Warn("PORTAL_CERT_FILE/PORTAL_KEY_FILE not set — NRF/AMF healthz probes will fail mTLS")
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: true,
		},
	}
}
