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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
	"github.com/francurieses/claudia-5gc/mcp/internal/server/transport"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	analysistools "github.com/francurieses/claudia-5gc/mcp/internal/tools/analysis"
	controltools "github.com/francurieses/claudia-5gc/mcp/internal/tools/control"
	cryptotools "github.com/francurieses/claudia-5gc/mcp/internal/tools/crypto"
	metricstools "github.com/francurieses/claudia-5gc/mcp/internal/tools/metrics"
	nastools "github.com/francurieses/claudia-5gc/mcp/internal/tools/nas"
	nftools "github.com/francurieses/claudia-5gc/mcp/internal/tools/nf"
	qostools "github.com/francurieses/claudia-5gc/mcp/internal/tools/qos"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	runtimetools "github.com/francurieses/claudia-5gc/mcp/internal/tools/runtimecfg"
	statustools "github.com/francurieses/claudia-5gc/mcp/internal/tools/status"
	tracetools "github.com/francurieses/claudia-5gc/mcp/internal/tools/trace"
	uetools "github.com/francurieses/claudia-5gc/mcp/internal/tools/ue"
	"github.com/francurieses/claudia-5gc/shared/oauth2"
)

const nfName = "MCP"

// mcpNFInstanceID identifies the MCP server as the OAuth2 client in NRF token requests
// (TS 29.510 §6.3.5.2.3 nfInstanceId). The MCP is not an NRF-registered NF.
const mcpNFInstanceID = "6d63702d-0000-4000-8000-000000000010"

// nefAFSessionScope is the OAuth2 scope of Nnef_AFsessionWithQoS (TS 29.522 §6.1).
const nefAFSessionScope = "nnef-afsessionwithqos"

// version is the MCP server release reported by `version`, the startup log and mcp_info.
const version = "0.1.0"

// buildCommit is the git revision of this build, set at link time with
// -ldflags "-X main.buildCommit=<sha>". It reads "unknown" for an unstamped build.
var buildCommit = "unknown"

func main() {
	configFlag := flag.String("config", "", "path to config YAML (overrides CONFIG_PATH env var)")
	flag.Parse()

	if flag.NArg() > 0 {
		switch flag.Arg(0) {
		case "healthcheck":
			os.Exit(healthcheck())
		case "version":
			fmt.Printf("mcp v%s (%s) (5GC Rel-17 MCP server)\n", version, buildCommit)
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
		"version", version,
		"build_commit", buildCommit,
		"transport", cfg.Transport,
		"sse_addr", cfg.SSE.ListenAddr,
	)

	mode, err := guard.ParseAccessMode(cfg.AccessMode)
	if err != nil {
		logger.Error("access mode", "error", err)
		os.Exit(1)
	}
	if !cfg.Auth.Enabled() {
		logger.Warn("SSE authentication is disabled: every caller acts as operator",
			"access_mode", string(mode))
	}
	g := guard.New(guard.Options{
		Mode:           mode,
		MinInterval:    time.Duration(cfg.Guardrails.MinIntervalMs) * time.Millisecond,
		AuditSize:      cfg.Guardrails.AuditSize,
		MaxResultBytes: cfg.Guardrails.MaxResultBytes,
	}, logger)

	// Build the single shared registry and register every tool group once.
	reg := registry.New()
	if err := registerTools(reg, cfg, g, logger); err != nil {
		logger.Error("registering tools", "error", err)
		os.Exit(1)
	}
	logger.Info("tools registered", "count", len(reg.List()),
		"visible", len(reg.ManifestFor(g.Ceiling())), "access_mode", string(mode))

	disp := server.NewDispatcher(reg, g, logger)
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

// registerTools wires every tool group into the shared registry. Each upstream
// client is built once here and shared by the groups that use it. Groups A and E
// are pure and need no client.
func registerTools(reg *registry.Registry, cfg *config.Config, g *guard.Guard, logger *slog.Logger) error {
	// Group A: NAS, NGAP and PFCP codecs (pure, no network I/O)
	if err := reg.RegisterAll(nastools.All()...); err != nil {
		return fmt.Errorf("group A (nas): %w", err)
	}

	// Group E: 5G-AKA crypto (pure, no network I/O)
	if err := reg.RegisterAll(cryptotools.All()...); err != nil {
		return fmt.Errorf("group E (crypto): %w", err)
	}

	// NRF SBI enforces mTLS HTTP/2; AMF management API, the portal, Loki, Jaeger
	// and Prometheus are plain HTTP, so use a standard client for those.
	sbiClient, err := clients.NewSBIClient(cfg.CAFile, cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return fmt.Errorf("build SBI client: %w", err)
	}
	plainClient := clients.NewPlainClient()
	nrfClient := clients.NewNRF(cfg.NRFAddr, sbiClient)
	amfClient := clients.NewAMF(cfg.AMFAddr, plainClient)
	obsClient := clients.NewObs(cfg.JaegerAddr, cfg.PrometheusAddr, plainClient)
	pcfClient := clients.NewPCF(cfg.PCFAddr, sbiClient)
	smfClient := clients.NewSMF(cfg.SMFAddr, sbiClient)
	udmClient := clients.NewUDM(cfg.UDMAddr, sbiClient)
	portal := clients.NewPortal(cfg.PortalAddr, plainClient)
	bsfClient := clients.NewBSF(cfg.BSFAddr, sbiClient)
	smsfClient := clients.NewSMSF(cfg.SMSFAddr, sbiClient)
	// The NEF needs an NRF access token (scope nnef-afsessionwithqos, TS 33.501 §13.4.1).
	nefTokens := oauth2.NewTokenCache(sbiClient, strings.TrimRight(cfg.NRFAddr, "/")+"/oauth2/v1/token",
		mcpNFInstanceID, nefAFSessionScope)
	nefClient := clients.NewNEF(cfg.NEFAddr, sbiClient, nefTokens)
	loki := clients.NewLoki(cfg.LokiAddr, plainClient)
	prom := promclient.New(cfg.EffectivePrometheusAddr(), plainClient,
		time.Duration(cfg.Prometheus.QueryTimeoutSec)*time.Second)

	targets := clients.NewTargets(prom, cfg.MetricsHostOverride)

	if err := reg.RegisterAll(nftools.All(nrfClient)...); err != nil {
		return fmt.Errorf("group B (nf): %w", err)
	}
	if err := reg.RegisterAll(uetools.All(amfClient)...); err != nil {
		return fmt.Errorf("group C (ue): %w", err)
	}
	if err := reg.RegisterAll(tracetools.All(obsClient)...); err != nil {
		return fmt.Errorf("group D (trace): %w", err)
	}

	// Group F: Prometheus metrics
	if err := reg.RegisterAll(metricstools.All(prom)...); err != nil {
		return fmt.Errorf("group F (metrics): %w", err)
	}

	// Group H: QoS policy overrides in the PCF.
	if err := reg.RegisterAll(qostools.All(pcfClient)...); err != nil {
		return fmt.Errorf("group H (qos): %w", err)
	}

	// Group I: PDU session QoS management (SMF session store + UDM SDM), plus the
	// deprecated pdu_session_qos_modify alias that drives the SMF.
	if err := reg.RegisterAll(qostools.Sessions(smfClient, udmClient, pcfClient)...); err != nil {
		return fmt.Errorf("group I (qos sessions): %w", err)
	}

	// Group J: status (core health, deployment, subscribers, config, PWS).
	if err := reg.RegisterAll(statustools.All(statustools.Deps{
		NRF: nrfClient, Portal: portal, Prom: prom, HTTP: plainClient, Targets: targets,
		AMF: amfClient, SMF: smfClient, BSF: bsfClient, SBI: sbiClient,
		Registry: reg, Guard: g, Version: version, BuildCommit: buildCommit,
		Upstreams: []statustools.Upstream{
			{Name: "nrf", Addr: cfg.NRFAddr, MTLS: true},
			{Name: "amf", Addr: cfg.AMFAddr},
			{Name: "smf", Addr: cfg.SMFAddr, MTLS: true},
			{Name: "udm", Addr: cfg.UDMAddr, MTLS: true},
			{Name: "pcf", Addr: cfg.PCFAddr, MTLS: true},
			{Name: "bsf", Addr: cfg.BSFAddr, MTLS: true},
			{Name: "nef", Addr: cfg.NEFAddr, MTLS: true},
			{Name: "smsf", Addr: cfg.SMSFAddr, MTLS: true},
			{Name: "portal", Addr: cfg.PortalAddr},
			{Name: "prometheus", Addr: cfg.EffectivePrometheusAddr()},
			{Name: "loki", Addr: cfg.LokiAddr},
			{Name: "jaeger", Addr: cfg.JaegerAddr},
		},
		Probes: []statustools.Probe{
			{Name: "loki", URL: strings.TrimRight(cfg.LokiAddr, "/") + "/ready"},
			{Name: "jaeger", URL: strings.TrimRight(cfg.JaegerAddr, "/") + "/"},
		},
	})...); err != nil {
		return fmt.Errorf("group J (status): %w", err)
	}

	// Group L: core-side control (deregister, release, policy push, page, NSSAA, PWS).
	// Each tool is Disruptive: the guard returns a dry-run unless confirm is true.
	if err := reg.RegisterAll(controltools.All(controltools.Deps{
		AMF: amfClient, SMF: smfClient, Portal: portal, NEF: nefClient, SMSF: smsfClient,
	})...); err != nil {
		return fmt.Errorf("group L (control): %w", err)
	}

	// Group M: runtime configuration (slice AMBR, RFSP, URSP, NF service control,
	// NF log level, AMF timers, subscriber provisioning) and the audit-log reader.
	if err := reg.RegisterAll(runtimetools.All(runtimetools.Deps{
		Portal: portal, AMF: amfClient, Guard: g, AllowServiceControl: cfg.AllowServiceControl,
		Prom: prom, Targets: targets, HTTP: plainClient,
	})...); err != nil {
		return fmt.Errorf("group M (runtime): %w", err)
	}

	// Group K: analysis (logs, procedure timeline, UE diagnosis, procedure stats)
	// and PCAP control.
	if err := reg.RegisterAll(analysistools.All(analysistools.Deps{
		Loki: loki, Obs: obsClient, Prom: prom, AMF: amfClient, SMF: smfClient,
		PCF: pcfClient, UDM: udmClient, Portal: portal, Targets: targets, HTTP: plainClient,
	})...); err != nil {
		return fmt.Errorf("group K (analysis): %w", err)
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
