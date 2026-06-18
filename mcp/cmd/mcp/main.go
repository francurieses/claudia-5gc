// Package main is the entry point of the MCP (Model Context Protocol) server.
// It exposes the 5G core's NAS codec, NF lifecycle, UE context and trace/metrics
// tools to LLM clients over two concurrent transports (stdio and HTTP SSE),
// serving an identical tool registry on both.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
	"github.com/francurieses/claudia-5gc/mcp/internal/server/transport"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	cryptotools "github.com/francurieses/claudia-5gc/mcp/internal/tools/crypto"
	metricstools "github.com/francurieses/claudia-5gc/mcp/internal/tools/metrics"
	nastools "github.com/francurieses/claudia-5gc/mcp/internal/tools/nas"
	nftools "github.com/francurieses/claudia-5gc/mcp/internal/tools/nf"
	qostools "github.com/francurieses/claudia-5gc/mcp/internal/tools/qos"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	tracetools "github.com/francurieses/claudia-5gc/mcp/internal/tools/trace"
	uetools "github.com/francurieses/claudia-5gc/mcp/internal/tools/ue"
	ueransimtools "github.com/francurieses/claudia-5gc/mcp/internal/tools/ueransim"
	ueclient "github.com/francurieses/claudia-5gc/mcp/internal/ueransim"
)

const nfName = "MCP"

func main() {
	configFlag := flag.String("config", "", "path to config YAML (overrides CONFIG_PATH env var)")
	flag.Parse()

	if flag.NArg() > 0 {
		switch flag.Arg(0) {
		case "healthcheck":
			os.Exit(healthcheck())
		case "version":
			fmt.Println("mcp v0.1.0 (5GC Rel-17 MCP server)")
			os.Exit(0)
		}
	}
	if *configFlag != "" {
		os.Setenv("CONFIG_PATH", *configFlag)
	}

	// Logs go to STDERR: stdout is reserved for the stdio JSON-RPC protocol.
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
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

	cfg, err := config.Load(os.Getenv("CONFIG_PATH"))
	if err != nil {
		logger.Error("loading config", "error", err)
		os.Exit(1)
	}
	logger.Info("starting MCP server",
		"version", "0.1.0",
		"transport", cfg.Transport,
		"sse_addr", cfg.SSE.ListenAddr,
	)

	// Build the single shared registry and register every tool group once.
	reg := registry.New()
	if err := registerTools(reg, cfg, logger); err != nil {
		logger.Error("registering tools", "error", err)
		os.Exit(1)
	}
	logger.Info("tools registered", "count", len(reg.List()))

	disp := server.NewDispatcher(reg, logger)
	mgr := session.NewManager(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	var sse *transport.SSE
	if cfg.RunsSSE() {
		sse = transport.NewSSE(disp, reg, mgr, cfg, logger)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sse.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("sse transport: %w", err)
			}
		}()
	}

	if cfg.RunsStdio() {
		stdio := transport.NewStdio(disp, os.Stdin, os.Stdout, logger)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := stdio.Run(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				errCh <- fmt.Errorf("stdio transport: %w", err)
				return
			}
			// stdin reached EOF: the local client disconnected. If stdio is the
			// only transport, shut the server down; otherwise keep SSE serving.
			if !cfg.RunsSSE() {
				logger.Info("stdin closed; shutting down (stdio-only)")
				cancel()
			}
		}()
	}

	logger.Info("MCP server ready", "procedure", "Bootstrap")

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		logger.Error("transport error", "error", err)
		cancel()
	}

	// Graceful shutdown of the SSE listener; stdio unwinds on ctx cancel/EOF.
	if sse != nil {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		if err := sse.Shutdown(shutCtx); err != nil {
			logger.Error("sse shutdown", "error", err)
		}
	}
	wg.Wait()
	logger.Info("MCP server stopped cleanly")
}

// registerTools wires every tool group into the shared registry. Group A (NAS
// codec) is pure; Groups B/C/D bind upstream clients built from config.
func registerTools(reg *registry.Registry, cfg *config.Config, logger *slog.Logger) error {
	// Group A: NAS codec (pure, no network I/O)
	if err := reg.RegisterAll(nastools.All()...); err != nil {
		return fmt.Errorf("group A (nas): %w", err)
	}

	// Group E: 5G-AKA crypto (pure, no network I/O)
	if err := reg.RegisterAll(cryptotools.All()...); err != nil {
		return fmt.Errorf("group E (crypto): %w", err)
	}

	// NRF SBI enforces mTLS HTTP/2; AMF management API and Jaeger/Prometheus are
	// plain HTTP, so use a standard client for those.
	sbiClient, err := clients.NewSBIClient(cfg.CAFile, cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return fmt.Errorf("build SBI client: %w", err)
	}
	plainClient := clients.NewPlainClient()
	nrfClient := clients.NewNRF(cfg.NRFAddr, sbiClient)
	amfClient := clients.NewAMF(cfg.AMFAddr, plainClient)
	obsClient := clients.NewObs(cfg.JaegerAddr, cfg.PrometheusAddr, plainClient)

	if err := reg.RegisterAll(nftools.All(nrfClient)...); err != nil {
		return fmt.Errorf("group B (nf): %w", err)
	}
	if err := reg.RegisterAll(uetools.All(amfClient)...); err != nil {
		return fmt.Errorf("group C (ue): %w", err)
	}
	if err := reg.RegisterAll(tracetools.All(obsClient)...); err != nil {
		return fmt.Errorf("group D (trace): %w", err)
	}

	// Group F: UERANSIM orchestration
	ueDockerClient := ueclient.NewDockerClient(
		cfg.UERANSIM.ContainerName,
		time.Duration(cfg.UERANSIM.ExecTimeoutSec)*time.Second,
		logger,
	)
	if err := reg.RegisterAll(ueransimtools.All(ueDockerClient)...); err != nil {
		return fmt.Errorf("group F (ueransim): %w", err)
	}

	// Group G: Prometheus metrics
	prom := promclient.New(cfg.EffectivePrometheusAddr(), plainClient,
		time.Duration(cfg.Prometheus.QueryTimeoutSec)*time.Second)
	if err := reg.RegisterAll(metricstools.All(prom)...); err != nil {
		return fmt.Errorf("group G (metrics): %w", err)
	}

	// Group H: QoS policy write operations (PCF overrides + PDU session with QoS)
	pcfClient := clients.NewPCF(cfg.PCFAddr, sbiClient)
	if err := reg.RegisterAll(qostools.All(pcfClient, amfClient, ueDockerClient)...); err != nil {
		return fmt.Errorf("group H (qos): %w", err)
	}

	// Group I: PDU session QoS management (SMF session store + UDM SDM).
	// SMF management endpoints share the SBI listener (mTLS); UDM SDM is mTLS.
	smfClient := clients.NewSMF(cfg.SMFAddr, sbiClient)
	udmClient := clients.NewUDM(cfg.UDMAddr, sbiClient)
	if err := reg.RegisterAll(qostools.Sessions(smfClient, udmClient)...); err != nil {
		return fmt.Errorf("group I (qos sessions): %w", err)
	}

	return nil
}

// healthcheck performs a liveness probe against the SSE /mcp/health endpoint for
// the Docker HEALTHCHECK directive.
func healthcheck() int {
	addr := os.Getenv("HEALTHCHECK_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:9300/mcp/health"
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // dev self-signed
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
