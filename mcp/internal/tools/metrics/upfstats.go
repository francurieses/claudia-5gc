package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

const (
	// upfStatsDefaultWindow is the look-back for rates and increases when window is omitted.
	upfStatsDefaultWindow = 5 * time.Minute
	// upfStatsMaxWindow is the largest accepted window.
	upfStatsMaxWindow = time.Hour
)

// upfStatsTool reports the UPF data-plane counters. Every NF exports every shared
// gauge (at 0 when it does not own it), so each query filters nf="UPF".
// Spec context: TS 29.244 §5.2 (PFCP session context the counters describe).
type upfStatsTool struct{ prom *promclient.Client }

func (upfStatsTool) Name() string        { return "upf_stats" }
func (upfStatsTool) Risk() registry.Risk { return registry.ReadOnly }
func (upfStatsTool) Description() string {
	return "UPF data-plane statistics from Prometheus (series fivegc_upf_*{nf=\"UPF\"}): active PFCP sessions " +
		"(current), throughput_bps per DNN (rate of GTP-U bytes x 8, ul/dl), packets_pps (ul/dl, all DNNs), " +
		"drops per reason, usage_reports and l4_checksum_repaired (increase over the window). " +
		"A value with no data is null with a reason under \"unavailable\", never 0. " +
		"The dnn filter applies to throughput only (packet counters carry no dnn label). " +
		"Spec context: TS 29.244 §5.2 (PFCP sessions), TS 29.281 (GTP-U)."
}
func (upfStatsTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"window":{"type":"string","description":"look-back window for rates and increases, e.g. 5m (default 5m, max 1h)"},
"dnn":{"type":"string","description":"only report throughput for this DNN, e.g. internet"}}}`)
}
func (upfStatsTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"pfcp_sessions_active":{},"throughput_bps":{},"packets_pps":{},"drops":{},"usage_reports":{},"l4_checksum_repaired":{},"window":{"type":"string"},"unavailable":{"type":"object"}}}`)
}

// promRange renders a duration as a PromQL range selector body: 5m, 1h, 90s.
func promRange(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", int64(d/time.Minute))
	default:
		return fmt.Sprintf("%ds", int64(d.Seconds()))
	}
}

// upfSamples drops samples that belong to another NF. The queries already filter
// nf="UPF"; this keeps a misbehaving upstream from leaking other NFs' zeros in.
func upfSamples(res *promclient.QueryResult) []promclient.VectorSample {
	out := make([]promclient.VectorSample, 0, len(res.Data.Result))
	for _, s := range res.Data.Result {
		if nf, ok := s.Metric["nf"]; ok && nf != "UPF" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func (t upfStatsTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		Window string `json:"window"`
		DNN    string `json:"dnn"`
	}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &a); err != nil {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "upf_stats args: %v", err)
		}
	}
	window := upfStatsDefaultWindow
	if a.Window != "" {
		d, err := time.ParseDuration(a.Window)
		if err != nil || d <= 0 {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"window": a.Window},
				"window must be a positive duration such as 5m, got %q", a.Window)
		}
		if d > upfStatsMaxWindow {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"window": a.Window},
				"window %s is above the %s maximum", a.Window, upfStatsMaxWindow)
		}
		window = d
	}
	if a.DNN != "" {
		if perr := toolutil.ValidDNN(a.DNN); perr != nil {
			return nil, perr
		}
	}
	w := promRange(window)
	bytesSel := `nf="UPF"`
	if a.DNN != "" {
		bytesSel += `,dnn="` + a.DNN + `"`
	}

	unavailable := map[string]string{}
	failures, queries := 0, 0
	run := func(field, q string) []promclient.VectorSample {
		queries++
		res, err := t.prom.Query(ctx, q, time.Time{})
		if err != nil {
			failures++
			unavailable[field] = "prometheus query failed: " + err.Error()
			return nil
		}
		s := upfSamples(res)
		if len(s) == 0 {
			unavailable[field] = "no data: Prometheus has no matching series"
			return nil
		}
		return s
	}

	out := map[string]any{
		"window":               window.String(),
		"pfcp_sessions_active": nil,
		"throughput_bps":       nil,
		"packets_pps":          nil,
		"drops":                nil,
		"usage_reports":        nil,
		"l4_checksum_repaired": nil,
	}

	if s := run("pfcp_sessions_active", `fivegc_upf_pfcp_sessions_active{nf="UPF"}`); s != nil {
		out["pfcp_sessions_active"] = finiteOrNil(s[0].Float64())
	}

	if s := run("throughput_bps", fmt.Sprintf(
		`sum by (dnn, direction) (rate(fivegc_upf_gtp_bytes_total{%s}[%s])) * 8`, bytesSel, w)); s != nil {
		per := map[string]map[string]*float64{}
		for _, x := range s {
			dnn := x.Metric["dnn"]
			if per[dnn] == nil {
				per[dnn] = map[string]*float64{"ul": nil, "dl": nil}
			}
			if k := dirKey(x.Metric["direction"]); k != "" {
				per[dnn][k] = finiteOrNil(x.Float64())
			}
		}
		out["throughput_bps"] = per
	}

	if s := run("packets_pps", fmt.Sprintf(
		`sum by (direction) (rate(fivegc_upf_gtp_packets_total{nf="UPF"}[%s]))`, w)); s != nil {
		pp := map[string]*float64{"ul": nil, "dl": nil}
		for _, x := range s {
			if k := dirKey(x.Metric["direction"]); k != "" {
				pp[k] = finiteOrNil(x.Float64())
			}
		}
		out["packets_pps"] = pp
	}

	if s := run("drops", fmt.Sprintf(
		`sum by (reason) (increase(fivegc_upf_packet_drops_total{nf="UPF"}[%s]))`, w)); s != nil {
		drops := map[string]*float64{}
		for _, x := range s {
			drops[x.Metric["reason"]] = finiteOrNil(x.Float64())
		}
		out["drops"] = drops
	}

	if s := run("usage_reports", fmt.Sprintf(
		`sum(increase(fivegc_upf_usage_reports_total{nf="UPF"}[%s]))`, w)); s != nil {
		out["usage_reports"] = finiteOrNil(s[0].Float64())
	}
	if s := run("l4_checksum_repaired", fmt.Sprintf(
		`sum(increase(fivegc_upf_l4_checksum_repaired_total{nf="UPF"}[%s]))`, w)); s != nil {
		out["l4_checksum_repaired"] = finiteOrNil(s[0].Float64())
	}

	if failures == queries {
		return nil, mcperr.ToolError(fmt.Errorf("upf_stats: prometheus unreachable: %s", firstReason(unavailable)), nil)
	}
	if len(unavailable) > 0 {
		out["unavailable"] = unavailable
	}
	slog.InfoContext(ctx, "upf stats read", "nf", "MCP", "procedure", "McpStatusAnalysisWave2",
		"tool_name", "upf_stats", "interface", "Prometheus", "direction", "OUT",
		"spec_ref", "TS 29.244 §5.2", "window", window.String(), "latency_ms", time.Since(start).Milliseconds())
	return out, nil
}

// dirKey maps the UPF direction label to the short ul/dl key.
func dirKey(direction string) string {
	switch strings.ToLower(direction) {
	case "uplink", "ul":
		return "ul"
	case "downlink", "dl":
		return "dl"
	}
	return ""
}

func firstReason(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return m[keys[0]]
}
