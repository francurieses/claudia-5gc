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
	"strconv"
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
		upfStatsTool{prom},
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

func (metricQueryTool) Name() string        { return "metric_query" }
func (metricQueryTool) Risk() registry.Risk { return registry.ReadOnly }
func (metricQueryTool) Description() string {
	return "Execute a PromQL query against Prometheus. Without start, an instant query returns the " +
		"current value of each series. With start (RFC3339) it runs a range query from start to end " +
		"(default now) at step seconds, with the step raised so there are at most 11 000 points per " +
		"series. At most max_series series are returned (default 50); truncated:true marks a cut. " +
		"Metrics exported today: fivegc_procedure_total, fivegc_authentication_total, fivegc_ue_registered, " +
		"fivegc_ue_connected, fivegc_pdu_sessions_active, fivegc_pdu_session_total, fivegc_upf_pfcp_sessions_active, " +
		"fivegc_nf_instances_registered, fivegc_handover_total, fivegc_nas_messages_total. " +
		"Every NF exports every shared gauge (most at 0), so filter by the owning NF, e.g. nf=\"AMF\". " +
		"Example queries: 'fivegc_ue_registered{nf=\"AMF\"}', 'increase(fivegc_procedure_total{nf=\"AMF\",result=\"REJECT\"}[5m])'. " +
		"Spec: Prometheus HTTP API /api/v1/query and /api/v1/query_range."
}
func (metricQueryTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "promql":     {"type":"string","description":"PromQL expression"},
  "time":       {"type":"string","description":"Instant query evaluation time, RFC3339 (default: now). Ignored in range mode."},
  "start":      {"type":"string","description":"Range mode: start time, RFC3339."},
  "end":        {"type":"string","description":"Range mode: end time, RFC3339 (default: now)."},
  "step":       {"type":"integer","description":"Range mode: step in seconds (default 60, raised as needed to stay under 11 000 points)."},
  "max_series": {"type":"integer","description":"Maximum series returned (1-500, default 50)."}
},
"required":["promql"]}`)
}
func (metricQueryTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"results":{"type":"array"},"query":{"type":"string"},"truncated":{"type":"boolean"},"mode":{"type":"string"}}}`)
}

const (
	defaultMaxSeries = 50
	maxSeriesCap     = 500
	defaultRangeStep = 60
)

func (t metricQueryTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		PromQL    string `json:"promql"`
		Time      string `json:"time"`
		Start     string `json:"start"`
		End       string `json:"end"`
		Step      int    `json:"step"`
		MaxSeries int    `json:"max_series"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "metric_query args: %v", err)
	}
	if a.PromQL == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "promql is required", nil)
	}
	if a.MaxSeries == 0 {
		a.MaxSeries = defaultMaxSeries
	}
	if a.MaxSeries < 1 || a.MaxSeries > maxSeriesCap {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "max_series must be 1-%d, got %d", maxSeriesCap, a.MaxSeries)
	}

	if a.Start != "" {
		return t.rangeQuery(ctx, a.PromQL, a.Start, a.End, a.Step, a.MaxSeries, start)
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
		Value     *float64          `json:"value"` // null for NaN / ±Inf
		Timestamp int64             `json:"timestamp"`
	}
	truncated := len(res.Data.Result) > a.MaxSeries
	series := res.Data.Result
	if truncated {
		series = series[:a.MaxSeries]
	}
	rows := make([]row, 0, len(series))
	for _, r := range series {
		var ts int64
		_ = json.Unmarshal(r.Value[0], &ts)
		rows = append(rows, row{
			Metric:    r.Metric,
			Value:     finiteOrNil(r.Float64()),
			Timestamp: ts,
		})
	}
	return map[string]any{
		"mode":      "instant",
		"results":   rows,
		"query":     a.PromQL,
		"truncated": truncated,
	}, nil
}

// rangeQuery runs the range mode of metric_query. Samples are returned per series
// with their timestamps; the effective step is reported so the caller can see any
// raise made to stay under the point limit.
func (t metricQueryTool) rangeQuery(ctx context.Context, promql, startS, endS string, stepS, maxSeries int, started time.Time) (any, error) {
	from, err := time.Parse(time.RFC3339, startS)
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"start": startS}, "start must be RFC3339: %v", err)
	}
	to := time.Now()
	if endS != "" {
		to, err = time.Parse(time.RFC3339, endS)
		if err != nil {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"end": endS}, "end must be RFC3339: %v", err)
		}
	}
	if !to.After(from) {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "end must be after start", nil)
	}
	if window := to.Sub(from); window > 24*time.Hour*7 {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "range window %s is above 7 days; narrow start/end", window)
	}
	if stepS <= 0 {
		stepS = defaultRangeStep
	}

	series, step, err := t.prom.QueryRange(ctx, promql, from, to, time.Duration(stepS)*time.Second)
	logInvoke(ctx, t.Name(), promql, len(series), started, err)
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInternal, map[string]any{"promql": promql}, "prometheus range query: %v", err)
	}

	truncated := len(series) > maxSeries
	if truncated {
		series = series[:maxSeries]
	}
	return map[string]any{
		"mode":      "range",
		"query":     promql,
		"start":     from.UTC().Format(time.RFC3339),
		"end":       to.UTC().Format(time.RFC3339),
		"step_s":    int64(step.Seconds()),
		"results":   rangeRows(series),
		"truncated": truncated,
	}, nil
}

// finiteOrNil returns a pointer to v, or nil when v is NaN or ±Inf (JSON cannot
// carry those; the sample is reported as null).
func finiteOrNil(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	return &v
}

// rangeSample is one range-query point: [unix seconds, value|null].
type rangeSample [2]any

// rangeSeries is one range-query series with numeric sample values.
type rangeSeries struct {
	Metric map[string]string `json:"metric"`
	Values []rangeSample     `json:"values"`
}

// rangeRows converts the Prometheus string samples to numbers; NaN, ±Inf and
// unparsable samples become null, matching the instant mode.
func rangeRows(series []promclient.MatrixSeries) []rangeSeries {
	out := make([]rangeSeries, 0, len(series))
	for _, s := range series {
		rs := rangeSeries{Metric: s.Metric, Values: make([]rangeSample, 0, len(s.Values))}
		for _, p := range s.Values {
			var v *float64
			if str, ok := p[1].(string); ok {
				if f, err := strconv.ParseFloat(str, 64); err == nil {
					v = finiteOrNil(f)
				}
			}
			rs.Values = append(rs.Values, rangeSample{p[0], v})
		}
		out = append(out, rs)
	}
	return out
}

// ---- kpi_snapshot ----------------------------------------------------------

type kpiSnapshotTool struct{ prom *promclient.Client }

func (kpiSnapshotTool) Name() string        { return "kpi_snapshot" }
func (kpiSnapshotTool) Risk() registry.Risk { return registry.ReadOnly }
func (kpiSnapshotTool) Description() string {
	return "Return a pre-built snapshot of core 5GC KPIs without requiring PromQL knowledge. " +
		"Queries the KPIs in parallel with a 5s total timeout. A KPI with no data (no series, NaN, or a " +
		"metric no NF exports) is JSON null and the sibling object 'unavailable' maps its name to a reason " +
		"string: no data is never reported as 0. KPIs: registration_success_rate (fivegc_procedure_total), " +
		"auth_success_rate (fivegc_authentication_total{nf=AUSF}), active_ue_contexts (fivegc_ue_registered{nf=AMF}), " +
		"ue_connected (fivegc_ue_connected{nf=AMF}), pdu_sessions_active (fivegc_pdu_sessions_active{nf=SMF}), " +
		"upf_pfcp_sessions_active (fivegc_upf_pfcp_sessions_active{nf=UPF}). avg_registration_latency_ms and " +
		"sbi_error_rate are always null: no NF exports an SBI request or latency metric yet."
}
func (kpiSnapshotTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "nf":{"type":"string","enum":["all","nrf","amf","udm","udr","ausf","mcp"],"description":"NF filter for registration_success_rate only (default all). InitialRegistration is exported by the AMF, so any other NF gives a null KPI with a reason."}
}}`)
}
func (kpiSnapshotTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"registration_success_rate":{"type":["number","null"]},"auth_success_rate":{"type":["number","null"]},
"avg_registration_latency_ms":{"type":["number","null"]},"active_ue_contexts":{"type":["integer","null"]},
"ue_connected":{"type":["integer","null"]},"pdu_sessions_active":{"type":["integer","null"]},
"upf_pfcp_sessions_active":{"type":["integer","null"]},"sbi_error_rate":{"type":["number","null"]},
"unavailable":{"type":"object","description":"KPI name -> reason, for every KPI whose value is null","additionalProperties":{"type":"string"}},
"snapshot_time":{"type":"string"}}}`)
}

// kpiNFs is the set of accepted kpi_snapshot nf values (the schema enum). Only
// these reach the PromQL text, so nothing user-supplied is interpolated unescaped.
var kpiNFs = map[string]bool{"all": true, "nrf": true, "amf": true, "udm": true, "udr": true, "ausf": true, "mcp": true}

// kpiNotExported is the reason given for KPIs whose backing metric no NF exports.
const kpiNotExported = "metric fivegc_sbi_requests_total / fivegc_sbi_request_duration_seconds_bucket is not exported by any NF"

// kpiDef is one KPI: a PromQL scalar and whether the value is an integer count.
// An empty query marks a KPI that has no backing series (reason is returned).
type kpiDef struct {
	name   string
	query  string
	isInt  bool
	reason string
}

// kpiResult is the outcome of one KPI query: a value or a reason it has none.
type kpiResult struct {
	value  *float64
	reason string
}

// kpiScalar runs a KPI query and returns a value, or nil plus a reason when the
// vector is empty, the sample is NaN/Inf, or the query fails.
func kpiScalar(ctx context.Context, prom *promclient.Client, q string) kpiResult {
	res, err := prom.Query(ctx, q, time.Time{})
	if err != nil {
		return kpiResult{reason: "query failed: " + err.Error()}
	}
	if len(res.Data.Result) == 0 {
		return kpiResult{reason: "no data: the query returned no series"}
	}
	v := res.Data.Result[0].Float64()
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return kpiResult{reason: "no data: the sample is NaN (empty denominator)"}
	}
	return kpiResult{value: &v}
}

func (t kpiSnapshotTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		NF string `json:"nf"`
	}
	_ = json.Unmarshal(in, &a) // optional field, ignore parse errors
	a.NF = strings.ToLower(a.NF)
	if a.NF == "" {
		a.NF = "all"
	}
	if !kpiNFs[a.NF] {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"nf": a.NF},
			"nf must be one of all, nrf, amf, udm, udr, ausf, mcp, got %q", a.NF)
	}
	// The nf matcher joins the same selector as the other matchers: a second
	// brace block after the metric name is invalid PromQL.
	nfMatcher := ""
	if a.NF != "all" {
		nfMatcher = fmt.Sprintf(`,nf="%s"`, strings.ToUpper(a.NF))
	}

	defs := []kpiDef{
		{name: "registration_success_rate", query: fmt.Sprintf(
			`sum(fivegc_procedure_total{procedure="InitialRegistration",result="OK"%s}) / `+
				`sum(fivegc_procedure_total{procedure="InitialRegistration"%s})`, nfMatcher, nfMatcher)},
		{name: "auth_success_rate", query: `sum(fivegc_authentication_total{nf="AUSF",result="OK"}) / ` +
			`sum(fivegc_authentication_total{nf="AUSF"})`},
		{name: "avg_registration_latency_ms", reason: kpiNotExported},
		{name: "active_ue_contexts", query: `sum(fivegc_ue_registered{nf="AMF"})`, isInt: true},
		{name: "ue_connected", query: `sum(fivegc_ue_connected{nf="AMF"})`, isInt: true},
		{name: "pdu_sessions_active", query: `sum(fivegc_pdu_sessions_active{nf="SMF"})`, isInt: true},
		{name: "upf_pfcp_sessions_active", query: `sum(fivegc_upf_pfcp_sessions_active{nf="UPF"})`, isInt: true},
		{name: "sbi_error_rate", reason: kpiNotExported},
	}

	results := make([]kpiResult, len(defs))
	var wg sync.WaitGroup
	for i, d := range defs {
		if d.query == "" {
			results[i] = kpiResult{reason: d.reason}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = kpiScalar(ctx, t.prom, d.query)
		}()
	}
	wg.Wait()

	out := map[string]any{}
	unavailable := map[string]string{}
	for i, d := range defs {
		r := results[i]
		switch {
		case r.value == nil:
			out[d.name] = nil
			unavailable[d.name] = r.reason
		case d.isInt:
			out[d.name] = int(math.Round(*r.value))
		case d.name == "avg_registration_latency_ms":
			out[d.name] = *r.value * 1000
		default:
			out[d.name] = *r.value
		}
	}
	out["unavailable"] = unavailable
	out["snapshot_time"] = time.Now().UTC().Format(time.RFC3339)

	slog.InfoContext(ctx, "tool invoked",
		"tool_name", t.Name(),
		"promql", "kpi_snapshot("+a.NF+")",
		"result_count", len(defs)-len(unavailable),
		"latency_ms", time.Since(start).Milliseconds(),
	)
	return out, nil
}

// ---- alert_list ------------------------------------------------------------

type alertListTool struct{ prom *promclient.Client }

func (alertListTool) Name() string        { return "alert_list" }
func (alertListTool) Risk() registry.Risk { return registry.ReadOnly }
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
