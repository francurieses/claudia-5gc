package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"gopkg.in/yaml.v3"

	ausfsrv "github.com/francurieses/claudia-5gc/nf/ausf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/aka"
	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
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
	logger = logger.With("nf", "AUSF")
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		logger.Error("loading config", "error", err)
		os.Exit(1)
	}
	logger = logger.With("nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)

	udmAddr := cfg.Peers.UDM
	sbiAddr := cfg.SBI.Address
	mcc := cfg.PLMN.MCC
	mnc := cfg.PLMN.MNC
	snName := fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", zeroPad(mnc, 3), mcc)

	// ---- Tracing ---------------------------------------------------------
	otlpEndpoint := getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
	tracingCtx := context.Background()
	if tp, err := tracing.Init(tracingCtx, "AUSF", otlpEndpoint); err != nil {
		logger.Warn("tracing init failed", "error", err)
	} else {
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tp.Shutdown(shutCtx)
		}()
	}

	// ---- Metrics server --------------------------------------------------
	metricsAddr := getEnv("METRICS_ADDRESS", "0.0.0.0:9102")
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
	httpClient.Transport = otelhttp.NewTransport(httpClient.Transport)

	// Server config
	serverCfg := ausfsrv.Config{
		NFInstanceID:       cfg.NFInstanceID,
		SBIAddress:         sbiAddr,
		ServingNetworkName: snName,
	}
	serverCfg.TLS.CertFile = cfg.SBI.TLS.CertFile
	serverCfg.TLS.KeyFile = cfg.SBI.TLS.KeyFile
	serverCfg.TLS.CAFile = cfg.SBI.TLS.CAFile

	// Auth context store: Redis when REDIS_URL is set, in-memory otherwise.
	var authStore aka.AuthStore
	if redisAddr := getEnv("REDIS_URL", ""); redisAddr != "" {
		rs, err := aka.NewRedisStore(redisAddr)
		if err != nil {
			logger.Warn("Redis unavailable — using in-memory auth store", "addr", redisAddr, "error", err)
		} else {
			authStore = rs
			defer rs.Close()
			logger.Info("AUSF auth store backed by Redis", "addr", redisAddr, "ttl", "5m")
		}
	}

	udmClient := &HTTPUDMClient{address: udmAddr, client: httpClient}
	srv, err := ausfsrv.New(serverCfg, udmClient, authStore, logger)
	if err != nil {
		logger.Error("building SBI server", "error", err)
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
			NFType:       "AUSF",
			NFStatus:     "REGISTERED",
			NFServices: []nrf.NFService{{
				ServiceInstanceID: cfg.NFInstanceID + "-nausf-auth",
				ServiceName:       "nausf-auth",
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
	logger.Info("AUSF ready", "addr", sbiAddr, "udm", udmAddr)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)
	logger.Info("AUSF stopped")
}

// HTTPUDMClient implements ausfsrv.UDMClient via HTTP calls to UDM.
type HTTPUDMClient struct {
	address string
	client  *http.Client
}

func (c *HTTPUDMClient) GenerateAuthData(ctx context.Context, supi string, req *ausfsrv.UDMAuthDataRequest) (*ausfsrv.UDMAuthDataResponse, error) {
	payload := map[string]any{
		"servingNetworkName": req.ServingNetworkName,
		"ausfInstanceId":     req.AUSFInstanceID,
	}
	if req.ResynchronizationInfo != nil {
		payload["resynchronizationInfo"] = map[string]string{
			"rand": req.ResynchronizationInfo.RAND,
			"auts": req.ResynchronizationInfo.AUTS,
		}
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://%s/nudm-ueau/v1/%s/security-information/generate-auth-data", c.address, supi)
	httpReq, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("udm: generate auth data: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("udm: status %d", resp.StatusCode)
	}
	var result ausfsrv.UDMAuthDataResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("udm: decode: %w", err)
	}
	return &result, nil
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
		UDM string `yaml:"udm"`
	} `yaml:"peers"`
	Metrics struct {
		Address string `yaml:"address"`
	} `yaml:"metrics"`
}

func loadConfig() (*Config, error) {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "/etc/5gc/config.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c := &Config{NFInstanceID: "00000000-0000-4002-8000-000000000001"}
			c.SBI.Address = "0.0.0.0:8002"
			c.Peers.UDM = "udm:8003"
			c.Metrics.Address = "0.0.0.0:9102"
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
		c.SBI.Address = "0.0.0.0:8002"
	}
	if c.Metrics.Address == "" {
		c.Metrics.Address = "0.0.0.0:9102"
	}
	return &c, nil
}
