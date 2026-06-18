package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
	"github.com/francurieses/claudia-5gc/nf/udr/internal/server"
	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(time.Now().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	}))
	logger = logger.With("nf", "UDR")
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("loading config", "error", err)
		os.Exit(1)
	}

	var st store.Store
	if dsn := getEnvDefault("DATABASE_URL", ""); dsn != "" {
		pgStore, err := store.NewPostgres(context.Background(), dsn)
		if err != nil {
			logger.Error("connecting to postgres", "error", err)
			os.Exit(1)
		}
		defer pgStore.Close()
		st = pgStore
		logger.Info("UDR using PostgreSQL backend")
	} else {
		logger.Warn("DATABASE_URL not set — using in-memory store (DEV ONLY, data lost on restart)")
		st = store.NewInMemory()
	}

	// Seed development subscribers only if they do not already exist.
	// Existing provisioned data (e.g. from the management portal) is preserved.
	// IMSIs are consecutive starting at imsi-001010000000001, mirroring how
	// UERANSIM `nr-ue -n <count>` generates UEs (same key, incrementing IMSI).
	// UE_COUNT controls how many are seeded (default 1).
	// K:    465b5ce8b199b49faa5f0a2ee238a6bc  (TS 35.207 Set 1 vector)
	// OPc:  cd63cb71954a9f4e48a5994e37a02baf
	// AMF:  b9b9
	// SQN:  000000000020
	//
	// Multi-slice profiles (cyclic for UE_COUNT > 4):
	//   UE 1: internet only     SST=1 SD=000001
	//   UE 2: internet + gold   SST=1 SD=000001, SST=1 SD=000002
	//   UE 3: internet + silver SST=1 SD=000001, SST=2 SD=000001
	//   UE 4: internet + bronze SST=1 SD=000001, SST=3 SD=000001
	//
	// Slice identifiers come from config/operator.yaml (single source of truth).
	// Falls back to the default 4-slice set when the operator file is absent.
	opSlices := []operatorcfg.SNSSAIEntry{
		{SST: 1, SD: "000001"},
		{SST: 1, SD: "000002"},
		{SST: 2, SD: "000001"},
		{SST: 3, SD: "000001"},
	}
	if op, err := operatorcfg.LoadOperator(""); err == nil && op != nil && len(op.Slices()) > 0 {
		opSlices = op.Slices()
	}
	internet := store.SNSSAISubscribed{SST: uint8(opSlices[0].SST), SD: opSlices[0].SD}
	sliceProfiles := [][]store.SNSSAISubscribed{{internet}}
	for _, s := range opSlices[1:] {
		sliceProfiles = append(sliceProfiles,
			[]store.SNSSAISubscribed{internet, {SST: uint8(s.SST), SD: s.SD}})
	}
	ueCount := getEnvIntDefault("UE_COUNT", 1)
	for i := 1; i <= ueCount; i++ {
		supi := fmt.Sprintf("imsi-00101%010d", i)
		// Do not overwrite data already provisioned (e.g. via management portal).
		if existing, _ := st.GetAuthSubscription(supi); existing != nil {
			logger.Info("subscriber already provisioned, skipping seed", "supi", supi)
			continue
		}
		profile := sliceProfiles[(i-1)%len(sliceProfiles)]
		if err := store.SeedTestSubscriberWithNSSAI(st,
			supi,
			"465b5ce8b199b49faa5f0a2ee238a6bc",
			"cd63cb71954a9f4e48a5994e37a02baf",
			"b9b9",
			"000000000020",
			profile,
		); err != nil {
			logger.Error("seed subscriber failed", "supi", supi, "error", err)
			continue
		}
		snssaiLog := make([]string, len(profile))
		for j, s := range profile {
			snssaiLog[j] = fmt.Sprintf("SST=%d/SD=%s", s.SST, s.SD)
		}
		logger.Info("seeded test subscriber", "supi", supi, "snssais", snssaiLog)
	}

	// ---- Tracing ---------------------------------------------------------
	otlpEndpoint := getEnvDefault("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
	if tp, err := tracing.Init(context.Background(), "UDR", otlpEndpoint); err != nil {
		logger.Warn("tracing init failed", "error", err)
	} else {
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tp.Shutdown(shutCtx)
		}()
	}

	// ---- Metrics server --------------------------------------------------
	metricsAddr := getEnvDefault("METRICS_ADDRESS", "0.0.0.0:9104")
	metricsSrv := metrics.MetricsServer(metricsAddr)
	go func() {
		logger.Info("metrics server listening", "addr", metricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server", "error", err)
		}
	}()

	srv, err := server.New(cfg.SBI.Address, server.TLSConfig{
		CertFile: cfg.SBI.TLS.CertFile,
		KeyFile:  cfg.SBI.TLS.KeyFile,
		CAFile:   cfg.SBI.TLS.CAFile,
	}, st, logger)
	if err != nil {
		logger.Error("building SBI server", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ---- NRF registration + heartbeat ------------------------------------
	if cfg.Peers.NRF != "" {
		nrfAddr := "https://" + cfg.Peers.NRF
		var httpClient *http.Client
		var err error
		if cfg.SBI.TLS.CAFile != "" {
			httpClient, err = sbi.NewMTLSClient(cfg.SBI.TLS.CAFile, cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
		} else {
			httpClient, err = sbi.NewHTTP2Client("")
		}
		if err != nil {
			logger.Warn("building NRF HTTP client failed", "err", err)
		} else {
			nrfClient := nrf.New(nrfAddr, httpClient, logger)
			profile := &nrf.NFProfile{
				NFInstanceID: cfg.NFInstanceID,
				NFType:       "UDR",
				NFStatus:     "REGISTERED",
				NFServices: []nrf.NFService{{
					ServiceInstanceID: cfg.NFInstanceID + "-nudr-dr",
					ServiceName:       "nudr-dr",
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

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(ctx); !errors.Is(err, http.ErrServerClosed) && err != nil {
			errCh <- err
		}
	}()

	logger.Info("UDR ready", "addr", cfg.SBI.Address, "spec_ref", "TS 29.504 §5")

	select {
	case <-ctx.Done():
	case err := <-errCh:
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)
	logger.Info("UDR stopped")
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvIntDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

type Config struct {
	NFInstanceID string `yaml:"nf_instance_id"`
	SBI          struct {
		Address string `yaml:"address"`
		TLS     struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
			CAFile   string `yaml:"ca_file"`
		} `yaml:"tls"`
	} `yaml:"sbi"`
	Metrics struct {
		Address string `yaml:"address"`
	} `yaml:"metrics"`
	Peers struct {
		NRF string `yaml:"nrf"`
	} `yaml:"peers"`
}

func loadConfig() (*Config, error) {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "/etc/5gc/config.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c := &Config{}
			c.SBI.Address = "0.0.0.0:8005"
			c.Metrics.Address = "0.0.0.0:9104"
			return c, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.SBI.Address == "" {
		c.SBI.Address = "0.0.0.0:8005"
	}
	return &c, nil
}
