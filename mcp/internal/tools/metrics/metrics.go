// Package metrics implements MCP Group G tools: Prometheus query and KPI tools.
// They wrap the Prometheus HTTP API via mcp/internal/prometheus. No external
// Prometheus client library is used — only net/http.
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// All returns the three Group G tools bound to a Prometheus client.
func All(prom *promclient.Client) []registry.Tool {
	return []registry.Tool{
		metricQueryTool{prom},
		kpiSnapshotTool{prom},
		alertListTool{prom},
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

func logInvoke(ctx context.Context, toolName, promql string, resultCount int, start time.Time, err error) {
	truncated := promql
	if len(truncated) > 200 {
		truncated = truncated[:200] + "…"
	}
	attrs := []any{
		"tool_name", toolName,
		"promql", truncated,
		"result_count", resultCount,
		"latency_ms", time.Since(start).Milliseconds(),
	}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	slog.InfoContext(ctx, "tool invoked", attrs...)
}

// ---- metric_query ----------------------------------------------------------

type metricQueryTool struct{ prom *promclient.Client }

func (metricQueryTool) Name() string { return "metric_query" }
func (metricQueryTool) Description() string {
	return "Execute an instant PromQL query against Prometheus. Returns a list of metric " +
		"time series with their current values. No restrictions on queryable metrics — " +
		"use metric names exported by NFs (prefix: fivegc_). " +
		"Example queries: " +
		"'fivegc_ue_registered{nf=\"AMF\"}', " +
		"'rate(fivegc_sbi_requests_total[5m])', " +
		"'histogram_quantile(0.99, fivegc_sbi_request_duration_seconds_bucket)'. " +
		"Spec: Prometheus HTTP API /api/v1/query."
}
func (metricQueryTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "promql": {"type":"string","description":"PromQL instant query expression"},
  "time":   {"type":"string","description":"Evaluation timestamp RFC3339 (default: now)"}
},
"required":["promql"]}`)
}
func (metricQueryTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"results":{"type":"array"},"query":{"type":"string"}}}`)
}
func (t metricQueryTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		PromQL string `json:"promql"`
		Time   string `json:"time"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "metric_query args: %v", err)
	}
	if a.PromQL == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "promql is required", nil)
	}

	var ts time.Time
	if a.Time != "" {
		var err error
		ts, err = time.Parse(time.RFC3339, a.Time)
		if err != nil {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"time": a.Time}, "time must be RFC3339: %v", err)
		}
	}

	res, err := t.prom.Query(ctx, a.PromQL, ts)
	logInvoke(ctx, t.Name(), a.PromQL, func() int {
		if res != nil {
			return len(res.Data.Result)
		}
		return 0
	}(), start, err)
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInternal, map[string]any{"promql": a.PromQL}, "prometheus query: %v", err)
	}

	type row struct {
		Metric    map[string]string `json:"metric"`
		Value     float64           `json:"value"`
		Timestamp int64             `json:"timestamp"`
	}
	rows := make([]row, 0, len(res.Data.Result))
	for _, r := range res.Data.Result {
		var ts int64
		_ = json.Unmarshal(r.Value[0], &ts)
		rows = append(rows, row{
			Metric:    r.Metric,
			Value:     r.Float64(),
			Timestamp: ts,
		})
	}
	return map[string]any{
		"results": rows,
		"query":   a.PromQL,
	}, nil
}

// ---- kpi_snapshot ----------------------------------------------------------

type kpiSnapshotTool struct{ prom *promclient.Client }

func (kpiSnapshotTool) Name() string { return "kpi_snapshot" }
func (kpiSnapshotTool) Description() string {
	return "Return a pre-built snapshot of core 5GC KPIs without requiring PromQL knowledge. " +
		"Queries 6 metrics in parallel with a 5s total timeout. NaN values mean the metric " +
		"has no data yet. Metric names: fivegc_procedure_total, fivegc_ue_registered, " +
		"fivegc_sbi_requests_total, fivegc_sbi_request_duration_seconds_bucket."
}
func (kpiSnapshotTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "nf":{"type":"string","enum":["all","nrf","amf","udm","udr","ausf","mcp"],"description":"NF filter (default all)"}
}}`)
}
func (kpiSnapshotTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"registration_success_rate":{},"auth_success_rate":{},
"avg_registration_latency_ms":{},"active_ue_contexts":{},
"sbi_error_rate":{},"snapshot_time":{}}}`)
}
func (t kpiSnapshotTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		NF string `json:"nf"`
	}
	_ = json.Unmarshal(in, &a) // optional field, ignore parse errors
	if a.NF == "" {
		a.NF = "all"
	}
	nfFilter := ""
	if a.NF != "all" {
		nfFilter = fmt.Sprintf(`{nf="%s"}`, strings.ToUpper(a.NF))
	}

	type kv struct {
		key string
		val float64
		err error
	}

	queries := map[string]string{
		"reg_ok_rate": fmt.Sprintf(
			`sum(fivegc_procedure_total%s{procedure="InitialRegistration",result="OK"}) / `+
				`sum(fivegc_procedure_total%s{procedure="InitialRegistration"})`,
			nfFilter, nfFilter),
		"auth_ok_rate": fmt.Sprintf(
			`sum(fivegc_procedure_total%s{procedure="Authentication",result="OK"}) / `+
				`sum(fivegc_procedure_total%s{procedure="Authentication"})`,
			nfFilter, nfFilter),
		"reg_latency_p50": `histogram_quantile(0.5, sum by (le) (fivegc_sbi_request_duration_seconds_bucket{nf="AMF"}))`,
		"active_ues":      `sum(fivegc_ue_registered{nf="AMF"})`,
		"sbi_error_rate": `sum(fivegc_sbi_requests_total{status_code="5xx"}) / ` +
			`sum(fivegc_sbi_requests_total)`,
	}

	results := make(map[string]float64, len(queries))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for k, q := range queries {
		k, q := k, q
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := t.prom.QueryScalar(ctx, q)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				results[k] = 0
			} else {
				results[k] = v
			}
		}()
	}
	wg.Wait()

	slog.InfoContext(ctx, "tool invoked",
		"tool_name", t.Name(),
		"promql", "kpi_snapshot("+a.NF+")",
		"result_count", len(results),
		"latency_ms", time.Since(start).Milliseconds(),
	)
	return map[string]any{
		"registration_success_rate":   results["reg_ok_rate"],
		"auth_success_rate":           results["auth_ok_rate"],
		"avg_registration_latency_ms": results["reg_latency_p50"] * 1000,
		"active_ue_contexts":          int(results["active_ues"]),
		"sbi_error_rate":              results["sbi_error_rate"],
		"snapshot_time":               time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// ---- alert_list ------------------------------------------------------------

type alertListTool struct{ prom *promclient.Client }

func (alertListTool) Name() string { return "alert_list" }
func (alertListTool) Description() string {
	return "List Prometheus alerts filtered by state. Returns label sets, annotations, " +
		"severity, and activation time for each alert. Uses /api/v1/alerts."
}
func (alertListTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "state":{"type":"string","enum":["all","firing","pending","inactive"],"description":"Filter by alert state (default all)"}
}}`)
}
func (alertListTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"alerts":{"type":"array"}}}`)
}
func (t alertListTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		State string `json:"state"`
	}
	_ = json.Unmarshal(in, &a)
	if a.State == "" {
		a.State = "all"
	}

	alerts, err := t.prom.Alerts(ctx)
	logInvoke(ctx, t.Name(), "alerts", len(alerts), start, err)
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInternal, nil, "alert_list: %v", err)
	}

	type alertRow struct {
		Name        string            `json:"name"`
		State       string            `json:"state"`
		Severity    string            `json:"severity"`
		Since       string            `json:"since"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	}
	out := make([]alertRow, 0, len(alerts))
	for _, al := range alerts {
		if a.State != "all" && al.State != a.State {
			continue
		}
		row := alertRow{
			Name:        al.Labels["alertname"],
			State:       al.State,
			Severity:    al.Labels["severity"],
			Since:       al.ActiveAt,
			Labels:      al.Labels,
			Annotations: al.Annotations,
		}
		if row.Name == "" {
			row.Name = "(unnamed)"
		}
		out = append(out, row)
	}
	return map[string]any{"alerts": out}, nil
}
