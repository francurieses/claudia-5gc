package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/pcf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(time.Now().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	}))
	logger = logger.With("nf", "PCF", "nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)

	tp, err := tracing.Init(context.Background(), "PCF", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if err != nil {
		logger.Error("tracing init failed", "error", err)
	}
	if tp != nil {
		defer tp.Shutdown(context.Background())
	}

	logger.Info("PCF starting", "instance_id", cfg.NFInstanceID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	metricsSrv := metrics.MetricsServer(cfg.Metrics.Address)
	go func() {
		logger.Info("metrics server listening", "addr", cfg.Metrics.Address)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server error", "error", err)
		}
	}()

	sbiSrv, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("SBI server creation failed", "error", err)
		os.Exit(1)
	}

	// ---- UDR client (N36 — per-subscriber URSP policy lookup) -----------
	var httpClient *http.Client
	if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" {
		httpClient, err = sbi.NewMTLSClient(cfg.SBI.TLS.CAFile, cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
	} else {
		httpClient, err = sbi.NewHTTP2Client(cfg.SBI.TLS.CAFile)
	}
	if err != nil {
		logger.Warn("building http2 client", "error", err)
	} else {
		if cfg.Peers.UDR != "" {
			udrBaseURL := "https://" + cfg.Peers.UDR
			sbiSrv.WithUDRClient(server.NewHTTPUDRClient(udrBaseURL, httpClient))
			logger.Info("UDR client configured", "udr", udrBaseURL, "interface", "N36")
		}
		// ---- BSF client (Nbsf_Management — PCF binding register/deregister) ---
		// Only constructed when cfg.Peers.BSF is configured; absent = fail-open (disabled).
		// Ref: TS 29.521 §5, TS 23.501 §6.2.16
		if cfg.Peers.BSF != "" {
			bsfBaseURL := "https://" + cfg.Peers.BSF
			sbiSrv.WithBSFClient(&server.HTTPBSFClient{
				BaseURL: bsfBaseURL,
				Client:  httpClient,
				Logger:  logger,
				PcfFqdn: cfg.SBI.FQDN,
				PcfId:   cfg.NFInstanceID,
			})
			logger.Info("BSF client configured",
				"bsf", bsfBaseURL, "interface", "Nbsf",
				"spec_ref", "TS 29.521 §5",
			)
		}
	}

	go func() {
		if err := sbiSrv.Start(ctx); err != nil {
			logger.Error("SBI server error", "error", err)
		}
	}()

	// ---- NRF registration + heartbeat ------------------------------------
	if cfg.Peers.NRF != "" {
		nrfAddr := "https://" + cfg.Peers.NRF
		nrfHTTPClient := httpClient
		if nrfHTTPClient == nil {
			if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" {
				nrfHTTPClient, _ = sbi.NewMTLSClient(cfg.SBI.TLS.CAFile, cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
			} else {
				nrfHTTPClient, _ = sbi.NewHTTP2Client(cfg.SBI.TLS.CAFile)
			}
		}
		if nrfHTTPClient != nil {
			nrfClient := nrf.New(nrfAddr, nrfHTTPClient, logger)
			profile := &nrf.NFProfile{
				NFInstanceID: cfg.NFInstanceID,
				NFType:       "PCF",
				NFStatus:     "REGISTERED",
				NFServices: []nrf.NFService{
					{
						ServiceInstanceID: cfg.NFInstanceID + "-npcf-smpolicycontrol",
						ServiceName:       "npcf-smpolicycontrol",
						Scheme:            "https",
						NFServiceStatus:   "REGISTERED",
						Versions:          []nrf.NFServiceVersion{{APIVersionInURI: "v1", APIFullVersion: "1.0.0"}},
					},
					{
						ServiceInstanceID: cfg.NFInstanceID + "-npcf-ue-policy-control",
						ServiceName:       "npcf-ue-policy-control",
						Scheme:            "https",
						NFServiceStatus:   "REGISTERED",
						Versions:          []nrf.NFServiceVersion{{APIVersionInURI: "v1", APIFullVersion: "1.0.0"}},
					},
				},
			}
			if err := nrfClient.RegisterAndStartHeartbeat(ctx, profile, 45*time.Second); err != nil {
				logger.Warn("NRF registration failed (continuing without NRF)",
					"nrf_addr", nrfAddr, "error", err,
					"spec_ref", "TS 29.510 §5.2.2.2.2",
				)
			}
		}
	}

	logger.Info("PCF ready")

	<-sigCh
	logger.Info("shutdown signal received")
	cancel()

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)

	logger.Info("PCF shutdown complete")
}
