// Package main is the entry point of the NRF (Network Repository Function).
// 3GPP TS 29.510 — Network Function Repository Services.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/francurieses/claudia-5gc/nf/nrf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/nrf/internal/registry"
	"github.com/francurieses/claudia-5gc/nf/nrf/internal/server"
)

const nfName = "NRF"

func main() {
	// Subcomandos
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "version":
			fmt.Println("nrf v0.1.0 (3GPP TS 29.510 Rel-17)")
			os.Exit(0)
		}
	}

	// Logger estructurado JSON a stdout (CLAUDE.md §5)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(time.Now().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	}))
	logger = logger.With("nf", nfName)
	slog.SetDefault(logger)

	// Cargar configuración
	cfg, err := config.Load(os.Getenv("CONFIG_PATH"))
	if err != nil {
		logger.Error("loading config", "error", err)
		os.Exit(1)
	}
	logger = logger.With("nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)
	logger.Info("starting NRF",
		"version", "0.1.0",
		"sbi_addr", cfg.SBI.Address,
		"plmn", cfg.PLMN,
	)

	// Construir registry: Redis si REDIS_URL está configurado, InMemory en otro caso.
	evictionTimeout := time.Duration(cfg.HeartbeatTimeoutSec) * time.Second

	var reg registry.Registry
	if redisAddr := getEnv("REDIS_URL", ""); redisAddr != "" {
		rr, err := registry.NewRedis(redisAddr, evictionTimeout, logger)
		if err != nil {
			logger.Warn("Redis unavailable — falling back to in-memory registry",
				"addr", redisAddr, "error", err)
			reg = registry.NewInMemory(logger)
		} else {
			reg = rr
			logger.Info("NRF registry backed by Redis",
				"addr", redisAddr, "ttl_sec", cfg.HeartbeatTimeoutSec)
		}
	} else {
		reg = registry.NewInMemory(logger)
	}

	// Construir HTTP server
	srv, err := server.New(cfg, reg, logger)
	if err != nil {
		logger.Error("building SBI server", "error", err)
		os.Exit(1)
	}

	// Arranque
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ---- Tracing (OTel → Jaeger) ------------------------------------------
	otlpEndpoint := getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
	if shutdown, err := initTracing(ctx, "NRF", otlpEndpoint); err != nil {
		logger.Warn("tracing init failed, running without traces", "error", err)
	} else {
		defer func() {
			shutCtx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer tcancel()
			_ = shutdown(shutCtx)
		}()
		logger.Info("OTel tracer initialised", "endpoint", otlpEndpoint)
	}

	// TTL eviction — InMemory only; RedisRegistry relies on key TTL natively.
	// Ref: TS 29.510 §5.2.2.3.4
	type evictable interface {
		StartEviction(ctx context.Context, timeout time.Duration)
	}
	if ev, ok := reg.(evictable); ok {
		ev.StartEviction(ctx, evictionTimeout)
		logger.Info("NF eviction active",
			"timeout_sec", cfg.HeartbeatTimeoutSec,
			"spec_ref", "TS 29.510 §5.2.2.3.4",
		)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	logger.Info("NRF ready",
		"procedure", "Bootstrap",
		"spec_ref", "TS 29.510 §5",
	)

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", "error", err)
		os.Exit(1)
	}
	type closeable interface{ Close() error }
	if cl, ok := reg.(closeable); ok {
		_ = cl.Close()
	}
	logger.Info("NRF stopped cleanly")
}

// healthcheck performs a quick self-test for Docker HEALTHCHECK.
// It presents the NRF's own cert as client certificate because the SBI
// listener requires mTLS (tls.RequireAndVerifyClientCert).
func healthcheck() int {
	addr := os.Getenv("HEALTHCHECK_ADDR")
	if addr == "" {
		addr = "https://127.0.0.1:8000/healthz"
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // self-signed in dev

	cfg, err := config.Load(os.Getenv("CONFIG_PATH"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: load config:", err)
		return 1
	}
	if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "healthcheck: load client cert:", err)
			return 1
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	tr := &http.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := client.Get(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
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

func initTracing(ctx context.Context, serviceName, otlpEndpoint string) (func(context.Context) error, error) {
	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(otlpEndpoint+"/v1/traces"),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: create OTLP exporter: %w", err)
	}
	res, _ := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
			attribute.String("service.version", "rel17"),
		),
	)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	return tp.Shutdown, nil
}
