// Package main is the entry point of the SEPP (Security Edge Protection Proxy).
// 3GPP TS 23.501 §6.2.17 — SEPP functional description.
// 3GPP TS 29.573 — N32 interface (n32c-handshake, n32f forwarding; REL19-9.4/9.5).
// 3GPP TS 29.510 §6.1.6.2.2 — NRF registration (NFType SEPP).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	seppsbi "github.com/francurieses/claudia-5gc/nf/sepp/internal/sbi"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/server"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}

	// ---- Logger ---------------------------------------------------------------
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logging.Level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(time.Now().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	}))
	logger = logger.With("nf", "SEPP")
	slog.SetDefault(logger)

	// ---- Config ---------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "error", err)
		os.Exit(1)
	}
	logger = logger.With("nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)

	// ---- Release profile (REL19-2.1/2.7) ----------------------------------------
	// Gates the wire behaviour of supportedFeatures negotiation: rel17 (the
	// default, also when the release: block is absent) is byte-identical to
	// the pre-negotiation baseline. Ref: TS 29.500 §6.6.2.
	relProfile, err := capability.NewProfile(cfg.Release, nil)
	if err != nil {
		logger.Error("loading release profile", "error", err)
		os.Exit(1)
	}
	capability.SetDefault(relProfile)
	logger.Info("release profile loaded", "release_profile", relProfile.Name())

	// ---- Tracing (OTel → Jaeger) ----------------------------------------------
	otlpEndpoint := getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
	tp, err := tracing.Init(context.Background(), "SEPP", otlpEndpoint)
	if err != nil {
		logger.Warn("tracing init failed", "error", err)
	} else if tp != nil {
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tp.Shutdown(shutCtx)
		}()
	}

	// ---- Metrics server (Prometheus) ------------------------------------------
	metricsSrv := metrics.MetricsServerWithAdmin(cfg.Metrics.Address, logging.NewLevelAdmin(logging.Level, logger))
	go func() {
		logger.Info("metrics server listening", "addr", cfg.Metrics.Address)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server error", "error", err)
		}
	}()

	// ---- mTLS HTTP/2 client (for NRF) -----------------------------------------
	var httpClient *http.Client
	if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" {
		httpClient, err = sbi.NewMTLSClient(cfg.SBI.TLS.CAFile, cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
	} else {
		httpClient, err = sbi.NewHTTP2Client(cfg.SBI.TLS.CAFile)
	}
	if err != nil {
		logger.Warn("building http2 client failed — some outbound calls may fail",
			"error", err)
		httpClient = http.DefaultClient
	}

	// ---- SBI server -----------------------------------------------------------
	srv := server.New(cfg, logger)

	if n32 := srv.N32(); n32 != nil {
		// Initiator side (Exchange/Teardown): mTLS with the N32 trust material.
		f := cfg.N32TLS()
		n32Client, cerr := sbi.NewMTLSClient(f.CAFile, f.CertFile, f.KeyFile)
		if cerr != nil {
			logger.Warn("building N32 mTLS client failed — outgoing exchange-capability disabled", "error", cerr)
		} else {
			n32.SetHTTPClient(n32Client)
		}
	}

	// ---- NRF client (registration + N32-f local NF discovery) -------------------
	var nrfClient *nrf.Client
	if cfg.Peers.NRF != "" {
		nrfClient = nrf.New("https://"+cfg.Peers.NRF, httpClient, logger)
	}

	// ---- N32-f forwarder (TS 29.573 §5.3) ----------------------------------------
	if err := mountForwarder(cfg, srv, nrfClient, logger); err != nil {
		logger.Error("N32-f forwarder required but unavailable", "error", err, "result", "FAILURE", "spec_ref", "TS 29.573 §5.3")
		os.Exit(1)
	}

	// ---- Signal + context -----------------------------------------------------
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ---- NRF registration + heartbeat -----------------------------------------
	// Ref: TS 29.510 §5.2.2.2 (NFRegister), TS 29.573 §6.1 (n32c-handshake)
	if cfg.Peers.NRF != "" {
		nrfAddr := "https://" + cfg.Peers.NRF
		profile := seppsbi.BuildNFProfile(cfg.NFInstanceID, relProfile, cfg.N32.RoamingPartners)
		if err := nrfClient.RegisterAndStartHeartbeat(ctx, profile, 45*time.Second); err != nil {
			logger.Warn("NRF registration failed (continuing without NRF)",
				"nrf_addr", nrfAddr, "error", err,
				"spec_ref", "TS 29.510 §5.2.2.2.2",
			)
		} else {
			logger.Info("SEPP registered in NRF",
				"nf_type", "SEPP",
				"nf_instance_id", cfg.NFInstanceID,
				"spec_ref", "TS 29.510 §5.2.2.2",
			)
		}
	} else {
		logger.Warn("NRF peer not configured — SEPP will not register")
	}

	// ---- Start SBI server -----------------------------------------------------
	go func() {
		if err := srv.Start(ctx); err != nil {
			logger.Error("SEPP SBI server error", "error", err)
		}
	}()

	// ---- Start N32 listener (N32-c exchange-capability) -------------------------
	n32Failed := make(chan struct{})
	go func() {
		if err := srv.StartN32(ctx); err != nil {
			logger.Error("SEPP N32 server error", "error", err)
			close(n32Failed)
			cancel()
		}
	}()

	// ---- N32-c initiator toward configured peers (TS 29.573 §5.2.2 step 1) --------
	waitInitiator := srv.StartInitiator(ctx)

	logger.Info("SEPP ready",
		"sbi_addr", cfg.SBI.Address,
		"nf_instance_id", cfg.NFInstanceID,
		"spec_ref", "TS 23.501 §6.2.17",
	)

	// ---- Graceful shutdown ----------------------------------------------------
	<-ctx.Done()
	logger.Info("SEPP shutdown signal received")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)
	_ = srv.Shutdown(shutCtx)
	waitInitiator()

	select {
	case <-n32Failed:
		logger.Error("SEPP stopped: N32 listener failed")
		os.Exit(1)
	default:
	}
	logger.Info("SEPP stopped cleanly")
}

// mountForwarder builds and mounts the N32-f forwarder. When roaming is
// configured (n32.peers or n32.roaming_partners) a missing NRF client or an
// unbuildable forwarder is an error (fail fast); with no roaming configuration
// it only warns. Ref: TS 29.573 §5.3.
func mountForwarder(cfg *config.Config, srv *server.Server, nrfClient *nrf.Client, logger *slog.Logger) error {
	n32 := srv.N32()
	if n32 == nil {
		return nil
	}
	required := cfg.HasRoamingConfig()
	if nrfClient == nil {
		if required {
			return errors.New("sepp: n32-f forwarder: roaming configured but peers.nrf is not set")
		}
		logger.Warn("N32-f forwarder disabled: no NRF configured", "spec_ref", "TS 29.573 §5.3")
		return nil
	}
	fwd, err := server.NewForwarder(cfg, n32.Store(), nrfClient, logger)
	if err != nil {
		if required {
			return fmt.Errorf("sepp: n32-f forwarder: %w", err)
		}
		logger.Warn("N32-f forwarder disabled", "error", err, "spec_ref", "TS 29.573 §5.3")
		return nil
	}
	srv.MountForwarder(fwd)
	return nil
}

// healthcheck probes the local SBI /healthz over mTLS (container HEALTHCHECK,
// distroless has no curl). Exit 0 when healthy.
func healthcheck() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: load config:", err)
		return 1
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // loopback probe, dev self-signed
	if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "healthcheck: load client cert:", err)
			return 1
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	_, port, err := net.SplitHostPort(cfg.SBI.Address)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: sbi.address:", err)
		return 1
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: 2 * time.Second}
	resp, err := client.Get("https://127.0.0.1:" + port + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
