// Package main is the entry point of the BSF (Binding Support Function).
// 3GPP TS 23.501 §6.2.16 — BSF functional description.
// 3GPP TS 29.521 §5 — Nbsf_Management service (Register / Deregister / Discovery).
// 3GPP TS 29.510 §6.1.6.2.2 — NRF registration (NFType BSF).
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

	"github.com/francurieses/5gc-rel17/nf/bsf/internal/config"
	"github.com/francurieses/5gc-rel17/nf/bsf/internal/server"
	"github.com/francurieses/5gc-rel17/shared/nrf"
	"github.com/francurieses/5gc-rel17/shared/observability/metrics"
	"github.com/francurieses/5gc-rel17/shared/observability/tracing"
	"github.com/francurieses/5gc-rel17/shared/sbi"
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
	logger = logger.With("nf", "BSF")
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
	otlpEndpoint := getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
	tp, err := tracing.Init(context.Background(), "BSF", otlpEndpoint)
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

	// ---- Signal + context -----------------------------------------------------
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ---- NRF registration + heartbeat -----------------------------------------
	// Ref: TS 29.510 §5.2.2.2 (NFRegister), TS 29.521 §5 (Nbsf_Management)
	if cfg.Peers.NRF != "" {
		nrfAddr := "https://" + cfg.Peers.NRF
		nrfClient := nrf.New(nrfAddr, httpClient, logger)
		profile := &nrf.NFProfile{
			NFInstanceID: cfg.NFInstanceID,
			NFType:       "BSF",
			NFStatus:     "REGISTERED",
			NFServices: []nrf.NFService{{
				ServiceInstanceID: cfg.NFInstanceID + "-nbsf-management",
				ServiceName:       "nbsf-management",
				Scheme:            "https",
				NFServiceStatus:   "REGISTERED",
				Versions: []nrf.NFServiceVersion{
					{APIVersionInURI: "v1", APIFullVersion: "1.0.0"},
				},
			}},
		}
		if err := nrfClient.RegisterAndStartHeartbeat(ctx, profile, 45*time.Second); err != nil {
			logger.Warn("NRF registration failed (continuing without NRF)",
				"nrf_addr", nrfAddr, "error", err,
				"spec_ref", "TS 29.510 §5.2.2.2.2",
			)
		} else {
			logger.Info("BSF registered in NRF",
				"nf_type", "BSF",
				"nf_instance_id", cfg.NFInstanceID,
				"spec_ref", "TS 29.510 §5.2.2.2",
			)
		}
	} else {
		logger.Warn("NRF peer not configured — BSF will not register")
	}

	// ---- Start SBI server -----------------------------------------------------
	go func() {
		if err := srv.Start(ctx); err != nil {
			logger.Error("BSF SBI server error", "error", err)
		}
	}()

	logger.Info("BSF ready",
		"sbi_addr", cfg.SBI.Address,
		"nf_instance_id", cfg.NFInstanceID,
		"spec_ref", "TS 23.501 §6.2.16",
	)

	// ---- Graceful shutdown ----------------------------------------------------
	<-ctx.Done()
	logger.Info("BSF shutdown signal received")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)
	_ = srv.Shutdown(shutCtx)

	logger.Info("BSF stopped cleanly")
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
