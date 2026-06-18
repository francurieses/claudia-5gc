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
		Level: slog.LevelInfo,
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		logger.Info("N6 TUN ready",
			"dnn", dnn.Name, "dev", dnn.TunName,
			"addr", dnn.TunAddr, "ue_pool", dnn.UEIPPool)
		tunEntries = append(tunEntries, gtpu.TUNEntry{
			DNN:     dnn.Name,
			Subnet:  dnn.UEIPPool,
			TunFile: f,
		})
	}

	// PFCP server (N4)
	pfcpCfg := pfcp.Config{
		Address: cfg.N4.Address,
		NodeIP:  cfg.N3.IP,
	}
	pfcpSrv, err := pfcp.New(pfcpCfg, logger, sessionTable)
	if err != nil {
		logger.Error("PFCP server creation failed", "error", err)
		os.Exit(1)
	}
	go func() {
		if err := pfcpSrv.Start(ctx); err != nil {
			logger.Error("PFCP server error", "error", err)
		}
	}()

	// GTP-U server (N3) — passes per-DNN TUN entries for N6 routing
	gtpuCfg := gtpu.Config{
		Address: cfg.N3.Address,
		N3IP:    cfg.N3.IP,
	}
	gtpuSrv, err := gtpu.New(gtpuCfg, logger, sessionTable, tunEntries)
	if err != nil {
		logger.Error("GTP-U server creation failed", "error", err)
		os.Exit(1)
	}
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
