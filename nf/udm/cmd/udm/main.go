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

	"gopkg.in/yaml.v3"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
	udmsrv "github.com/francurieses/claudia-5gc/nf/udm/internal/server"
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
	logger = logger.With("nf", "UDM")
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		logger.Error("loading config", "error", err)
		os.Exit(1)
	}
	logger = logger.With("nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)

	udrAddr := cfg.Peers.UDR
	sbiAddr := cfg.SBI.Address
	mcc := cfg.PLMN.MCC
	mnc := cfg.PLMN.MNC
	snName := fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", zeroPad(mnc, 3), mcc)

	// ---- Tracing ---------------------------------------------------------
	otlpEndpoint := getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
	if tp, err := tracing.Init(context.Background(), "UDM", otlpEndpoint); err != nil {
		logger.Warn("tracing init failed", "error", err)
	} else {
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tp.Shutdown(shutCtx)
		}()
	}

	// ---- Metrics server --------------------------------------------------
	metricsAddr := getEnv("METRICS_ADDRESS", "0.0.0.0:9103")
	metricsSrv := metrics.MetricsServer(metricsAddr)
	go func() {
		logger.Info("metrics server listening", "addr", metricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server", "error", err)
		}
	}()

	// Build mTLS client when cert/key are configured; fall back to TLS-only.
	var httpClient *http.Client
	if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" {
		httpClient, err = sbi.NewMTLSClient(cfg.SBI.TLS.CAFile, cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
	} else {
		httpClient, err = sbi.NewHTTP2Client(cfg.SBI.TLS.CAFile)
	}
	if err != nil {
		logger.Error("building http2 client", "error", err)
		os.Exit(1)
	}

	udrClient := udmsrv.NewHTTPUDRClient(udrAddr, httpClient)
	srv, err := udmsrv.New(sbiAddr, snName, udmsrv.TLSConfig{
		CertFile: cfg.SBI.TLS.CertFile,
		KeyFile:  cfg.SBI.TLS.KeyFile,
		CAFile:   cfg.SBI.TLS.CAFile,
	}, udrClient, logger)
	if err != nil {
		logger.Error("building SBI server", "error", err)
		os.Exit(1)
	}

	// Load SUCI Profile A (X25519) home-network private key if configured.
	// Set hn_private_key_x25519 in config.yaml or HN_PRIVATE_KEY_X25519 env var.
	// Ref: TS 33.501 §6.12, Annex C.3
	hnPrivKey := cfg.HNPrivKeyX25519
	if hnPrivKey == "" {
		hnPrivKey = os.Getenv("HN_PRIVATE_KEY_X25519")
	}
	if err := srv.WithHomeNetPrivKeyA(hnPrivKey); err != nil {
		logger.Error("SUCI Profile A key load failed", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ---- NRF registration + heartbeat ------------------------------------
	if cfg.Peers.NRF != "" {
		nrfAddr := "https://" + cfg.Peers.NRF
		nrfClient := nrf.New(nrfAddr, httpClient, logger)
		profile := &nrf.NFProfile{
			NFInstanceID: cfg.NFInstanceID,
			NFType:       "UDM",
			NFStatus:     "REGISTERED",
			NFServices: []nrf.NFService{{
				ServiceInstanceID: cfg.NFInstanceID + "-nudm-ueau",
				ServiceName:       "nudm-ueau",
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

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(ctx); err != nil {
			errCh <- err
		}
	}()
	logger.Info("UDM ready", "addr", sbiAddr, "udr", udrAddr)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)
	logger.Info("UDM stopped")
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func zeroPad(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

type Config struct {
	NFInstanceID string `yaml:"nf_instance_id"`
	PLMN         struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`
	SBI struct {
		Address string `yaml:"address"`
		TLS struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
			CAFile   string `yaml:"ca_file"`
		} `yaml:"tls"`
	} `yaml:"sbi"`
	Peers struct {
		NRF string `yaml:"nrf"`
		UDR string `yaml:"udr"`
	} `yaml:"peers"`
	Metrics struct {
		Address string `yaml:"address"`
	} `yaml:"metrics"`
	// HNPrivKeyX25519 is the Home Network X25519 private key (hex) for SUCI Profile A.
	// Also readable from HN_PRIVATE_KEY_X25519 env var.
	// Ref: TS 33.501 §6.12, Annex C.3
	HNPrivKeyX25519 string `yaml:"hn_private_key_x25519"`
}

func loadConfig() (*Config, error) {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "/etc/5gc/config.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c := &Config{NFInstanceID: "00000000-0000-4003-8000-000000000001"}
			c.SBI.Address = "0.0.0.0:8003"
			c.Peers.UDR = "udr:8005"
			c.Metrics.Address = "0.0.0.0:9103"
			if op, _ := operatorcfg.LoadOperator(""); op != nil {
				c.PLMN.MCC = op.PLMN.MCC
				c.PLMN.MNC = op.PLMN.MNC
			}
			return c, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	// Seed PLMN from operator config before per-NF YAML overwrites.
	var c Config
	if op, err := operatorcfg.LoadOperator(""); err != nil {
		return nil, fmt.Errorf("operator config: %w", err)
	} else if op != nil {
		c.PLMN.MCC = op.PLMN.MCC
		c.PLMN.MNC = op.PLMN.MNC
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if c.SBI.Address == "" {
		c.SBI.Address = "0.0.0.0:8003"
	}
	if c.Metrics.Address == "" {
		c.Metrics.Address = "0.0.0.0:9103"
	}
	return &c, nil
}
