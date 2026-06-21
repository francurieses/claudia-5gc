// Package main is the entry point of the SMSF (Short Message Service Function).
// 3GPP TS 29.540 — Nsmsf_SMService.
// 3GPP TS 23.502 §4.13 — SMS over NAS procedures.
// 3GPP TS 24.501 §8.2.10 / §8.2.11 — UL/DL NAS Transport (SMS payload).
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

	"github.com/francurieses/claudia-5gc/nf/smsf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/smsf/internal/server"
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
	logger = logger.With("nf", "SMSF")
	slog.SetDefault(logger)

	// ---- Config ---------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "error", err)
		os.Exit(1)
	}
	logger = logger.With("nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)

	// ---- Tracing (OTel → Jaeger) ---------------------------------------------
	otlpEndpoint := getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
	tp, err := tracing.Init(context.Background(), "SMSF", otlpEndpoint)
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

	// ---- mTLS HTTP/2 client (shared across NRF, UDM, AMF) --------------------
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

	// Wire AMF client for MT SMS delivery.
	// Ref: TS 29.518 §5.2.2.3
	amfClient := server.NewHTTPAMFClient(httpClient)
	srv.WithAMFClient(amfClient)

	// Wire UDM client for UECM registration on Activate.
	// Ref: TS 29.503 §5.3.2
	if cfg.Peers.UDM != "" {
		udmClient := server.NewHTTPUDMClient(cfg.Peers.UDM, httpClient)
		srv.WithUDMClient(udmClient)
		logger.Info("UDM UECM client configured",
			"udm_addr", cfg.Peers.UDM,
			"spec_ref", "TS 29.503 §5.3.2",
		)
	} else {
		logger.Warn("UDM peer not configured — SMSF UECM registration will be skipped")
	}

	// ---- Signal + context -----------------------------------------------------
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ---- NRF registration + heartbeat ----------------------------------------
	// Ref: TS 29.510 §5.2.2.2
	if cfg.Peers.NRF != "" {
		nrfAddr := "https://" + cfg.Peers.NRF
		nrfClient := nrf.New(nrfAddr, httpClient, logger)
		profile := &nrf.NFProfile{
			NFInstanceID: cfg.NFInstanceID,
			NFType:       "SMSF",
			NFStatus:     "REGISTERED",
			NFServices: []nrf.NFService{{
				ServiceInstanceID: cfg.NFInstanceID + "-nsmsf-sms",
				ServiceName:       "nsmsf-sms",
				Scheme:            "https",
				NFServiceStatus:   "REGISTERED",
				Versions: []nrf.NFServiceVersion{
					{APIVersionInURI: "v2", APIFullVersion: "2.0.0"},
				},
			}},
		}
		if err := nrfClient.RegisterAndStartHeartbeat(ctx, profile, 45*time.Second); err != nil {
			logger.Warn("NRF registration failed (continuing without NRF)",
				"nrf_addr", nrfAddr, "error", err,
				"spec_ref", "TS 29.510 §5.2.2.2.2",
			)
		} else {
			logger.Info("SMSF registered in NRF",
				"nf_type", "SMSF",
				"nf_instance_id", cfg.NFInstanceID,
				"spec_ref", "TS 29.510 §5.2.2.2",
			)
		}
	} else {
		logger.Warn("NRF peer not configured — SMSF will not register")
	}

	// ---- Start SBI server -----------------------------------------------------
	go func() {
		if err := srv.Start(ctx); err != nil {
			logger.Error("SMSF SBI server error", "error", err)
		}
	}()

	logger.Info("SMSF ready",
		"sbi_addr", cfg.SBI.Address,
		"nf_instance_id", cfg.NFInstanceID,
		"spec_ref", "TS 23.502 §4.13",
	)

	// ---- Graceful shutdown ----------------------------------------------------
	<-ctx.Done()
	logger.Info("SMSF shutdown signal received")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)
	_ = srv.Shutdown(shutCtx)

	logger.Info("SMSF stopped cleanly")
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
