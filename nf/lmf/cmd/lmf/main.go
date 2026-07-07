// Package main is the entry point of the LMF (Location Management Function).
//
// The LMF is the 5GC NF responsible for UE positioning (TS 23.501 §6.2.18).
// It provides the Nlmf_Location service (TS 29.572) and for Cell-ID positioning
// consumes the Namf_Location service from the AMF (TS 29.518 §5.2.2.6).
// The AMF acts as the NGAP relay to the gNB; the LMF never has a direct N2
// (NGAP/SCTP) association.
//
// Refs:
//   - TS 23.501 §6.2.18 — LMF functional description
//   - TS 23.273 §7.2    — UE positioning procedure (Cell-ID method)
//   - TS 29.572 §5.2.2.2 — Nlmf_Location DetermineLocation (Stage 3)
//   - TS 29.510 §6.1.6.3.3 — NRF registration (NFType LMF)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/lmf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

func main() {
	// ---- Logger ---------------------------------------------------------------
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(time.Now().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	}))
	logger = logger.With("nf", "LMF")
	slog.SetDefault(logger)

	// ---- Config ---------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "error", err)
		os.Exit(1)
	}
	logger = logger.With("nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)

	// ---- Tracing (OTel → Jaeger) ----------------------------------------------
	// Ref: TS 29.500 §4.4 — SBA observability (OTel / Jaeger)
	otlpEndpoint := getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
	tp, err := tracing.Init(context.Background(), "LMF", otlpEndpoint)
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
	metricsSrv := metrics.MetricsServer(cfg.Metrics.Address)
	go func() {
		logger.Info("metrics server listening", "addr", cfg.Metrics.Address)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server error", "error", err)
		}
	}()

	// ---- mTLS HTTP/2 client (for outbound NRF + AMF calls) --------------------
	// Build a TLS-capable client when cert+key are present (prod), else plain h2c
	// (dev / functional-test mode). Ref: TS 29.500 §4.4.1 — SBA always mTLS.
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

	// ---- Construct AMF location client ----------------------------------------
	// The AMF provides Namf_Location_ProvideLocationInfo on its SBI server.
	// Ref: TS 29.518 §5.2.2.6
	amfClient := &server.HTTPAMFLocationClient{
		BaseURL: "https://" + cfg.Peers.AMF,
		Client:  httpClient,
		Logger:  logger,
	}

	// ---- Construct UDM SDM client (location privacy check) --------------------
	// The UDM provides Nudm_SDM lcs-privacy-data queried before disclosing location.
	// Ref: TS 29.503 §5.2.2; TS 23.273 §9.1.
	var udmClient server.UDMSDMClient
	if cfg.Peers.UDM != "" {
		udmClient = &server.HTTPUDMSDMClient{
			BaseURL: "https://" + cfg.Peers.UDM,
			Client:  httpClient,
		}
	}

	// ---- Notification client (EventSubscription LocationNotification delivery) -
	// Posts LocationNotification bodies to subscriber notificationUris over the
	// same mTLS HTTP/2 client. Ref: TS 29.572 §6.1.6.2.4; TS 29.500 §4.4.1.
	notifClient := &server.HTTPNotificationClient{Client: httpClient}

	// ---- SBI server -----------------------------------------------------------
	srv := server.NewWithNotifClient(cfg, logger, amfClient, udmClient, notifClient)

	// ---- Wire NRPPa relay client (E-CID positioning, LMF-004) ----------------
	// HTTPAMFLocationClient implements both AMFLocationClient (Cell-ID) and
	// DLNRPPASender (E-CID NRPPa relay). Setting the client here enables E-CID
	// quality-driven method selection for DetermineLocation requests with
	// hAccuracy ≤ 200 m. When nil, the server silently falls back to Cell-ID.
	// Ref: TS 23.273 §6.2.9; TS 29.518 §5.2.2.6 (dl-nrppa-info).
	srv.SetNRPPAClient(amfClient)

	// ---- Wire LPP relay client (GNSS positioning, LMF-005) --------------------
	// HTTPAMFLocationClient also implements LPPSender (dl-lpp-info). Setting the
	// client here enables GNSS/LPP quality-driven method selection for
	// DetermineLocation requests with hAccuracy < 50 m. When nil, the server
	// silently downgrades to E-CID (or Cell-ID if that is also unwired).
	// Ref: TS 23.273 §6.2.10; TS 29.518 §5.2.2.6 (dl-lpp-info).
	srv.SetLPPClient(amfClient)

	// ---- Signal + context -----------------------------------------------------
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ---- NRF registration + heartbeat -----------------------------------------
	// Ref: TS 29.510 §5.2.2.2 (NFRegister), §6.1.6.3.3 (NFType LMF)
	if cfg.Peers.NRF != "" {
		nrfAddr := "https://" + cfg.Peers.NRF
		nrfClient := nrf.New(nrfAddr, httpClient, logger)
		profile := &nrf.NFProfile{
			NFInstanceID: cfg.NFInstanceID,
			NFType:       "LMF",
			NFStatus:     "REGISTERED",
			FQDN:         cfg.SBI.FQDN,
			NFServices: []nrf.NFService{{
				ServiceInstanceID: cfg.NFInstanceID + "-nlmf-loc",
				ServiceName:       "nlmf-loc",
				Scheme:            "https",
				NFServiceStatus:   "REGISTERED",
				Versions: []nrf.NFServiceVersion{
					{APIVersionInURI: "v1", APIFullVersion: "1.0.0"},
				},
			}},
		}
		if err := nrfClient.RegisterAndStartHeartbeat(ctx, profile, 45*time.Second); err != nil {
			logger.Warn("NRF registration failed (continuing without NRF)",
				"nrf_addr", nrfAddr,
				"error", err,
				"spec_ref", "TS 29.510 §5.2.2.2",
			)
		} else {
			logger.Info("LMF registered in NRF",
				"nf_type", "LMF",
				"nf_instance_id", cfg.NFInstanceID,
				"service", "nlmf-loc",
				"spec_ref", "TS 29.510 §6.1.6.3.3",
			)
		}
	} else {
		logger.Warn("NRF peer not configured — LMF will not register")
	}

	// ---- Start SBI server -----------------------------------------------------
	go func() {
		if err := srv.Start(ctx); err != nil {
			logger.Error("LMF SBI server error", "error", err)
		}
	}()

	logger.Info("LMF ready",
		"sbi_addr", cfg.SBI.Address,
		"nf_instance_id", cfg.NFInstanceID,
		"service", "nlmf-loc",
		"spec_ref", "TS 23.501 §6.2.18",
	)

	// ---- Graceful shutdown ----------------------------------------------------
	<-ctx.Done()
	logger.Info("LMF shutdown signal received")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)
	_ = srv.Shutdown(shutCtx)

	logger.Info("LMF stopped cleanly")
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
