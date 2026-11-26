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

	"golang.org/x/net/http2"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/admin"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32trust"
	seppsbi "github.com/francurieses/claudia-5gc/nf/sepp/internal/sbi"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/server"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// n32ClientTimeout bounds one N32-c request (same bound as the SBI clients).
const n32ClientTimeout = 10 * time.Second

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
		logger.Error("config load failed", "error", err.Error(), "cause", "config_invalid", "result", "FAILURE",
			"spec_ref", "TS 33.501 §13.1")
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

	// ---- N32 trust: partner anchors + local N32 certificate (SEPP-005) ----------
	if cfg.PartnersFileLoaded {
		logger.Info("roaming partners file loaded", "path", cfg.PartnersFilePath, "partners", len(cfg.N32Partners()),
			"spec_ref", "TS 33.501 §13.1.2")
	} else {
		if os.Getenv(config.PartnersFileEnv) != "" {
			logger.Info("ROAMING_PARTNERS_FILE names a file that does not exist: no file partners",
				"path", cfg.PartnersFilePath, "spec_ref", "TS 33.501 §13.1.2")
		}
		logger.Info("no roaming partners file, using inline partners only", "path", cfg.PartnersFilePath,
			"partners", len(cfg.N32Partners()), "spec_ref", "TS 33.501 §13.1.2")
	}
	n32tls, err := server.LoadN32TLS(cfg, logger)
	if err != nil {
		logger.Error("N32 trust configuration invalid", "error", err, "cause", "config_invalid", "result", "FAILURE",
			"spec_ref", "TS 33.501 §13.1")
		os.Exit(1)
	}

	// ---- SBI server -----------------------------------------------------------
	srv := server.New(cfg, logger)
	srv.SetN32TLS(n32tls)

	if n32 := srv.N32(); n32 != nil && n32tls != nil {
		// Initiator side (Exchange/Teardown): mTLS with the local N32 certificate,
		// peers verified against their PLMN anchor and partner FQDN.
		base := &http.Client{Transport: &http2.Transport{TLSClientConfig: n32tls.ClientTLSConfig()}, Timeout: n32ClientTimeout}
		n32Client, cerr := server.NewPeerIdentityClient(base, cfg.Initiators())
		if cerr != nil {
			logger.Error("building N32 mTLS client failed", "error", cerr, "cause", "config_invalid", "result", "FAILURE")
			os.Exit(1)
		}
		n32.SetHTTPClient(n32Client)
	}

	// ---- NRF client (registration + N32-f local NF discovery) -------------------
	var nrfClient *nrf.Client
	if cfg.Peers.NRF != "" {
		nrfClient = nrf.New("https://"+cfg.Peers.NRF, httpClient, logger)
	}

	// ---- N32-f forwarder (TS 29.573 §5.3) ----------------------------------------
	if err := mountForwarder(cfg, srv, nrfClient, n32tls, logger); err != nil {
		logger.Error("N32-f forwarder required but unavailable", "error", err, "result", "FAILURE", "spec_ref", "TS 29.573 §5.3")
		os.Exit(1)
	}

	// ---- Metrics server (Prometheus) + N32 admin view (PORTAL-UI-22) ---------------
	// The admin routes have no authentication: internal metrics port only.
	var n32Admin admin.N32
	if n := srv.N32(); n != nil {
		n32Admin = n
	}
	var anchors []n32trust.AnchorInfo
	if n32tls != nil {
		anchors = n32tls.Verifier.Anchors()
	}
	n32Handler := admin.NewHandler(n32Admin, admin.Info{
		ReleaseProfile: relProfile.Name(), TopologyHiding: cfg.TopologyHidingEnabled(),
		Partners: cfg.N32Partners(), Anchors: anchors,
	}, logger)
	metricsSrv := metrics.MetricsServerWithAdmin(cfg.Metrics.Address, logging.NewLevelAdmin(logging.Level, logger),
		metrics.AdminRoute{Pattern: admin.ContextsPath, Handler: n32Handler},
		metrics.AdminRoute{Pattern: admin.ContextsSubtree, Handler: n32Handler},
		metrics.AdminRoute{Pattern: admin.PartnersPath, Handler: http.HandlerFunc(n32Handler.ServePartners)})
	go func() {
		logger.Info("metrics server listening", "addr", cfg.Metrics.Address)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server error", "error", err)
		}
	}()

	// ---- Signal + context -----------------------------------------------------
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ---- NRF registration + heartbeat -----------------------------------------
	// Ref: TS 29.510 §5.2.2.2 (NFRegister), TS 29.573 §6.1 (n32c-handshake)
	if cfg.Peers.NRF != "" {
		nrfAddr := "https://" + cfg.Peers.NRF
		var remote []config.PLMN
		for _, p := range cfg.N32Partners() {
			remote = append(remote, p.PLMN)
		}
		profile := seppsbi.BuildNFProfile(cfg.NFInstanceID, relProfile, remote)
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
	// Started only with the local N32 certificate; without it (and without
	// partners) one INFO line, SEPP stays healthy. Ref: TS 33.501 §13.1.
	n32Failed := make(chan struct{})
	if n32tls != nil {
		go func() {
			if err := srv.StartN32(ctx); err != nil {
				logger.Error("SEPP N32 server error", "error", err)
				close(n32Failed)
				cancel()
			}
		}()
	} else {
		logger.Info("N32 listener not started: no local N32 certificate and no roaming partner",
			"cert_file", cfg.N32.TLS.CertFile, "spec_ref", "TS 33.501 §13.1")
	}

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

// mountForwarder builds and mounts the N32-f forwarder. It needs the N32 TLS
// material: without it (no partners, no local N32 certificate) there is no N32
// and nothing is mounted. When partners exist a missing NRF client or an
// unbuildable forwarder is an error (fail fast); otherwise it logs INFO only.
// Ref: TS 29.573 §5.3.
func mountForwarder(cfg *config.Config, srv *server.Server, nrfClient *nrf.Client, n32tls *server.N32TLS, logger *slog.Logger) error {
	n32 := srv.N32()
	if n32 == nil || n32tls == nil {
		return nil
	}
	required := cfg.HasRoamingConfig()
	if nrfClient == nil {
		if required {
			return errors.New("sepp: n32-f forwarder: roaming configured but peers.nrf is not set")
		}
		logger.Info("N32-f forwarder not mounted: no NRF configured", "spec_ref", "TS 29.573 §5.3")
		return nil
	}
	fwd, err := server.NewForwarder(cfg, n32.Store(), nrfClient, n32tls, logger)
	if err != nil {
		if required {
			return fmt.Errorf("sepp: n32-f forwarder: %w", err)
		}
		logger.Info("N32-f forwarder not mounted", "error", err, "spec_ref", "TS 29.573 §5.3")
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
