// Package main is the entry point of the NEF (Network Exposure Function).
//
// The NEF is the 5GC's secure gateway between the trusted core and external
// Application Functions (AFs). It exposes selected core capabilities northbound
// over the Nnef API surface (TS 29.522) while shielding internal NFs and hiding
// network topology. AFs know only UE IP addresses; the NEF discovers the serving
// PCF via the BSF (Nbsf_Management_Discovery) and maps AF requests onto PCF
// policy operations (Npcf_PolicyAuthorization).
//
// Refs:
//   - TS 23.501 §6.2.5  — NEF functional description
//   - TS 29.522 §4.4.13 — Nnef_AFsessionWithQoS (Stage 3)
//   - TS 29.510 §6.1.6.2.2 — NRF registration (NFType NEF)
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

	"github.com/francurieses/claudia-5gc/nf/nef/internal/config"
	nefsbi "github.com/francurieses/claudia-5gc/nf/nef/internal/sbi"
	"github.com/francurieses/claudia-5gc/nf/nef/internal/server"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
)

func main() {
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
	logger = logger.With("nf", "NEF")
	slog.SetDefault(logger)

	// ---- Config ---------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "error", err)
		os.Exit(1)
	}
	logger = logger.With("nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)

	// ---- Release profile (REL19-2.1/2.7) --------------------------------------
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
	// Ref: TS 29.500 §4.4 — SBA observability (OTel / Jaeger)
	otlpEndpoint := getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
	tp, err := tracing.Init(context.Background(), "NEF", otlpEndpoint)
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

	// ---- mTLS HTTP/2 client (for outbound NRF, BSF, PCF calls) ---------------
	// Build a TLS-capable client when cert+key are present (prod), else plain h2c
	// (dev / functional-test mode). Ref: TS 29.500 §4.4.1 — SBA always mTLS.
	httpClient, err := server.NewOutboundClient(cfg.SBI.TLS.CAFile, cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile, logger)
	if err != nil {
		logger.Warn("building http2 client failed — some outbound calls may fail",
			"error", err)
	}

	// ---- Construct BSF + PCF clients ------------------------------------------
	// BSF client: discover serving PCF by UE IP via Nbsf_Management_Discovery.
	// Ref: TS 29.521 §5.2.2.4
	bsfClient := &server.HTTPBSFClient{
		BaseURL: "https://" + cfg.Peers.BSF,
		Client:  httpClient,
		Logger:  logger,
	}
	bsfClient.WithFeatures(relProfile, logger)

	// PCF client: map AF AsSessionWithQoS → Npcf_PolicyAuthorization.
	// Target URI comes from the BSF-returned PcfBinding (not NRF discovery).
	// Ref: TS 29.514 §5.2.2.2 (Create), §5.2.2.4 (Delete)
	pcfClient := &server.HTTPPolicyAuthClient{
		Client: httpClient,
		Logger: logger,
	}
	pcfClient.WithFeatures(relProfile, logger)

	// ---- SBI server -----------------------------------------------------------
	srv := server.New(cfg, logger, bsfClient, pcfClient)
	srv.SetProfile(relProfile)

	// ---- Signal + context -----------------------------------------------------
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ---- NRF registration + heartbeat -----------------------------------------
	// Ref: TS 29.510 §5.2.2.2 (NFRegister), §6.1.6.2.2 (NFType NEF)
	if cfg.Peers.NRF != "" {
		nrfAddr := "https://" + cfg.Peers.NRF
		nrfClient := nrf.New(nrfAddr, httpClient, logger)
		profile := nefsbi.BuildNFProfile(cfg.NFInstanceID, cfg.SBI.FQDN, relProfile, nefsbi.AsSessionWithQoSCatalog())
		if err := nrfClient.RegisterAndStartHeartbeat(ctx, profile, 45*time.Second); err != nil {
			logger.Warn("NRF registration failed (continuing without NRF)",
				"nrf_addr", nrfAddr,
				"error", err,
				"spec_ref", "TS 29.510 §5.2.2.2.2",
			)
		} else {
			logger.Info("NEF registered in NRF",
				"nf_type", "NEF",
				"nf_instance_id", cfg.NFInstanceID,
				"service", "3gpp-as-session-with-qos",
				"spec_ref", "TS 29.510 §6.1.6.2.2",
			)
		}
	} else {
		logger.Warn("NRF peer not configured — NEF will not register")
	}

	// ---- Start SBI server -----------------------------------------------------
	go func() {
		if err := srv.Start(ctx); err != nil {
			logger.Error("NEF SBI server error", "error", err)
		}
	}()

	logger.Info("NEF ready",
		"sbi_addr", cfg.SBI.Address,
		"nf_instance_id", cfg.NFInstanceID,
		"service", "3gpp-as-session-with-qos",
		"spec_ref", "TS 23.501 §6.2.5",
	)

	// ---- Graceful shutdown ----------------------------------------------------
	<-ctx.Done()
	logger.Info("NEF shutdown signal received")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)
	_ = srv.Shutdown(shutCtx)

	logger.Info("NEF stopped cleanly")
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
