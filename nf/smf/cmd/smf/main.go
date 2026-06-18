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

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/smf/internal/server"
	"github.com/francurieses/claudia-5gc/nf/smf/internal/store"
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
	logger = logger.With("nf", "SMF", "nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)

	tp, err := tracing.Init(context.Background(), "SMF", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if err != nil {
		logger.Error("tracing init failed", "error", err)
	}
	if tp != nil {
		defer tp.Shutdown(context.Background())
	}

	logger.Info("SMF starting", "instance_id", cfg.NFInstanceID)

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

	// ---- Persistent store (PostgreSQL) ------------------------------------
	var smfStore store.Store
	if dsn := getEnvOrDefault("DATABASE_URL", ""); dsn != "" {
		pg, err := store.NewPostgres(context.Background(), dsn)
		if err != nil {
			logger.Warn("SMF PostgreSQL unavailable — running in-memory only",
				"error", err)
		} else {
			smfStore = pg
			defer pg.Close()
			logger.Info("SMF PostgreSQL store connected")
		}
	}

	sbiSrv, err := server.New(cfg, logger, smfStore)
	if err != nil {
		logger.Error("SBI server creation failed", "error", err)
		os.Exit(1)
	}

	go func() {
		if err := sbiSrv.Start(ctx); err != nil {
			logger.Error("SBI server error", "error", err)
		}
	}()

	// ---- NRF registration + heartbeat ------------------------------------
	if cfg.Peers.NRF != "" {
		var httpClient *http.Client
		var err error
		if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" {
			httpClient, err = sbi.NewMTLSClient(cfg.SBI.TLS.CAFile, cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
		} else {
			httpClient, err = sbi.NewHTTP2Client(cfg.SBI.TLS.CAFile)
		}
		if err != nil {
			logger.Warn("building http2 client for NRF", "error", err)
		} else {
			nrfAddr := "https://" + cfg.Peers.NRF
			nrfClient := nrf.New(nrfAddr, httpClient, logger)
			var snssais []nrf.SNSSAIEntry
			for _, s := range cfg.SNSSAIs {
				snssais = append(snssais, nrf.SNSSAIEntry{SST: s.SST, SD: s.SD})
			}
			if len(snssais) == 0 {
				snssais = []nrf.SNSSAIEntry{{SST: 1, SD: "000001"}}
			}
			// Advertise all configured DNNs to NRF (TS 29.510 §6.1.6.2.28).
			var dnnList []string
			for _, d := range cfg.DNNs {
				dnnList = append(dnnList, d.Name)
			}
			if len(dnnList) == 0 {
				dnnList = []string{"internet"}
			}
			profile := &nrf.NFProfile{
				NFInstanceID: cfg.NFInstanceID,
				NFType:       "SMF",
				NFStatus:     "REGISTERED",
				SNSSAIs:      snssais,
				DNNList:      dnnList,
				NFServices: []nrf.NFService{{
					ServiceInstanceID: cfg.NFInstanceID + "-nsmf-pdusession",
					ServiceName:       "nsmf-pdusession",
					Scheme:            "https",
					NFServiceStatus:   "REGISTERED",
					Versions: []nrf.NFServiceVersion{{APIVersionInURI: "v1", APIFullVersion: "1.0.0"}},
				}},
			}
			if err := nrfClient.RegisterAndStartHeartbeat(ctx, profile, 45*time.Second); err != nil {
				logger.Warn("NRF registration failed (continuing without NRF)",
					"nrf_addr", nrfAddr, "error", err,
					"spec_ref", "TS 29.510 §5.2.2.2.2",
				)
			}
		}
	}

	logger.Info("SMF ready")

	<-sigCh
	logger.Info("shutdown signal received")
	cancel()

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)

	logger.Info("SMF shutdown complete")
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
