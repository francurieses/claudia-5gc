package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/upf/internal/gtpu"
	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
	"github.com/francurieses/claudia-5gc/nf/upf/internal/tun"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: config.LogLevelFromEnv(),
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(time.Now().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	}))
	logger = logger.With("nf", "UPF", "nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)

	tp, err := tracing.Init(context.Background(), "UPF", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if err != nil {
		logger.Error("tracing init failed", "error", err)
	}
	if tp != nil {
		defer tp.Shutdown(context.Background())
	}

	var dnnNames []string
	for _, d := range cfg.DNNs {
		dnnNames = append(dnnNames, d.Name)
	}
	logger.Info("UPF starting",
		"instance_id", cfg.NFInstanceID,
		"n4_address", cfg.N4.Address,
		"n3_address", cfg.N3.Address,
		"dnns", dnnNames,
	)

	logger.Info("UPF runtime",
		"procedure", "Startup",
		"gomaxprocs", runtime.GOMAXPROCS(0),
		"num_cpu", runtime.NumCPU(),
		"gogc", os.Getenv("GOGC"),
		"log_level", config.LogLevelFromEnv().String(),
		"qos_mbr_enforcement", cfg.QoSMBREnforcement(),
		"qos_burst_ms", cfg.QoSBurstMs())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Optional CPU/heap profiling (UPF_PPROF_ADDR), off by default. Not published
	// to the host: fetch it from inside the UPF network namespace.
	if addr := config.PprofAddrFromEnv(); addr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		go func() {
			logger.Info("pprof listening", "addr", addr)
			if err := http.ListenAndServe(addr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("pprof server error", "error", err)
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Metrics server
	metricsSrv := metrics.MetricsServer(cfg.Metrics.Address)
	go func() {
		logger.Info("metrics server listening", "addr", cfg.Metrics.Address)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server error", "error", err)
		}
	}()

	// Shared session table
	sessionTable := pfcp.NewSessionTable()

	// N6 TUN interface setup — one TUN per DNN for subnet isolation.
	// Each TUN is bound to a distinct UE subnet; packets are routed to the
	// correct TUN based on the UE IP address.
	// Ref: TS 23.501 §5.6.5, TS 29.244 §6.3.3.14
	var tunEntries []gtpu.TUNEntry
	for _, dnn := range cfg.DNNs {
		if dnn.TunName == "" {
			logger.Warn("UPF: DNN has no tun_name, skipping N6 for this DNN", "dnn", dnn.Name)
			continue
		}
		f, err := tun.Open(dnn.TunName)
		if err != nil {
			logger.Error("TUN open failed — N6 forwarding disabled for DNN",
				"dnn", dnn.Name, "tun", dnn.TunName, "error", err)
			continue
		}
		if err := tun.Setup(dnn.TunName, dnn.TunAddr, dnn.UEIPPool); err != nil {
			logger.Error("TUN setup failed — N6 forwarding disabled for DNN",
				"dnn", dnn.Name, "tun", dnn.TunName, "error", err)
			f.Close()
			continue
		}
		// IPv6 N6 forwarding (TS 23.501 §5.8.2.2) for DNNs that delegate an
		// IPv6 prefix — best-effort: a failure here leaves IPv4 N6 intact and
		// only disables IPv6 egress for this DNN.
		if dnn.UEIPv6Prefix != "" {
			if err := tun.SetupIPv6(dnn.TunName, dnn.UEIPv6Prefix); err != nil {
				logger.Error("TUN IPv6 setup failed — IPv6 N6 egress disabled for DNN",
					"dnn", dnn.Name, "tun", dnn.TunName, "prefix", dnn.UEIPv6Prefix, "error", err)
			} else {
				logger.Info("N6 TUN IPv6 ready",
					"dnn", dnn.Name, "dev", dnn.TunName, "ue_ipv6_prefix", dnn.UEIPv6Prefix)
			}
		}
		if err := tun.SetLinkParams(dnn.TunName, cfg.N6.TunMTU, cfg.N6.TunTxQueueLen); err != nil {
			logger.Error("TUN link tuning failed", "dnn", dnn.Name, "tun", dnn.TunName, "error", err)
		}
		if cfg.N6.TCPMSSClamp {
			if err := tun.SetupMSSClamp(dnn.TunName, dnn.UEIPv6Prefix != ""); err != nil {
				logger.Error("TCP MSS clamp setup failed", "dnn", dnn.Name, "tun", dnn.TunName, "error", err)
			}
		}
		logger.Info("N6 TUN ready",
			"dnn", dnn.Name, "dev", dnn.TunName,
			"addr", dnn.TunAddr, "ue_pool", dnn.UEIPPool,
			"mtu", cfg.N6.TunMTU, "txqueuelen", cfg.N6.TunTxQueueLen, "tcp_mss_clamp", cfg.N6.TCPMSSClamp)
		tunEntries = append(tunEntries, gtpu.TUNEntry{
			DNN:     dnn.Name,
			Subnet:  dnn.UEIPPool,
			Subnet6: dnn.UEIPv6Prefix,
			TunFile: f,
		})
	}

	// Per-DNN IPv6 anchor (TS 23.501 §5.8.2.2), mirroring the SMF's per-DNN
	// IPv6 pool config — used by the PFCP server only as a config-drift
	// guard/log around Router Advertisement delivery.
	dnnIPv6Prefixes := make(map[string]string)
	for _, dnn := range cfg.DNNs {
		if dnn.UEIPv6Prefix != "" {
			dnnIPv6Prefixes[dnn.Name] = dnn.UEIPv6Prefix
		}
	}

	// PFCP server (N4)
	pfcpCfg := pfcp.Config{
		Address:         cfg.N4.Address,
		NodeIP:          cfg.N3.IP,
		DNNIPv6Prefixes: dnnIPv6Prefixes,
		// MBR / Session-AMBR enforcement (UPF-005): TS 23.501 §5.7.1.8.
		QoS: pfcp.QoSConfig{MBRDisabled: !cfg.QoSMBREnforcement(), BurstMs: cfg.QoSBurstMs()},
	}
	pfcpSrv, err := pfcp.New(pfcpCfg, logger, sessionTable)
	if err != nil {
		logger.Error("PFCP server creation failed", "error", err)
		os.Exit(1)
	}

	// GTP-U server (N3) — passes per-DNN TUN entries for N6 routing
	gtpuCfg := gtpu.Config{
		Address: cfg.N3.Address,
		N3IP:    cfg.N3.IP,

		SocketBufferBytes: cfg.N3.SocketBufferBytes,

		L4ChecksumRepair: cfg.N6L4ChecksumRepair(),
	}
	logger.Info("N6 downlink L4 checksum repair",
		"procedure", "DownlinkChecksum",
		"interface", "N6",
		"enabled", gtpuCfg.L4ChecksumRepair,
		"spec_ref", "RFC 1071; TS 29.281 §5")
	gtpuSrv, err := gtpu.New(gtpuCfg, logger, sessionTable, tunEntries)
	if err != nil {
		logger.Error("GTP-U server creation failed", "error", err)
		os.Exit(1)
	}
	// Pre-resolve the counter children once (no label lookup per repair).
	tcp4 := metrics.UPFL4ChecksumRepairedTotal.WithLabelValues("tcp", "v4")
	tcp6 := metrics.UPFL4ChecksumRepairedTotal.WithLabelValues("tcp", "v6")
	udp4 := metrics.UPFL4ChecksumRepairedTotal.WithLabelValues("udp", "v4")
	udp6 := metrics.UPFL4ChecksumRepairedTotal.WithLabelValues("udp", "v6")
	gtpuSrv.SetL4RepairHook(func(proto, ipver string) {
		switch {
		case proto == "tcp" && ipver == "v4":
			tcp4.Inc()
		case proto == "tcp" && ipver == "v6":
			tcp6.Inc()
		case proto == "udp" && ipver == "v4":
			udp4.Inc()
		case proto == "udp" && ipver == "v6":
			udp6.Inc()
		}
	})

	// Wire the N4 (PFCP) / N3 (GTP-U) seam for IPv6 prefix delegation Router
	// Advertisements (TS 23.501 §5.8.2.2.2) before either server starts
	// receiving traffic: the PFCP server's per-session RA advertiser sends
	// downlink via the GTP-U server, and the GTP-U server triggers a
	// solicited RA back into PFCP when it decapsulates a Router Solicitation
	// on the uplink.
	pfcpSrv.SetRASender(gtpuSrv)
	gtpuSrv.SetPFCPServer(pfcpSrv)

	go func() {
		if err := pfcpSrv.Start(ctx); err != nil {
			logger.Error("PFCP server error", "error", err)
		}
	}()
	go func() {
		if err := gtpuSrv.Start(ctx); err != nil {
			logger.Error("GTP-U server error", "error", err)
		}
	}()

	logger.Info("UPF ready")

	<-sigCh
	logger.Info("shutdown signal received")
	cancel()

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)

	logger.Info("UPF shutdown complete")
}
