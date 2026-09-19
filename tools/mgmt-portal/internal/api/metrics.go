package api

// metrics.go — Prometheus-backed metrics endpoints for the portal dashboard.
//
// The instant summary is a fixed set of aggregate queries. The range endpoint
// is deliberately curated: the browser selects one of the whitelisted KEYS
// below, never an arbitrary PromQL expression. An unauthenticated UI able to
// submit free-form range queries is an injection/DoS surface (plan risk O2 — a
// range query over a long window is expensive), so the fixed expression is
// resolved and executed server-side.

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (d Deps) handleMetricsSummary(w http.ResponseWriter, r *http.Request) {
	summary := d.Prometheus.Summary(r.Context())
	writeJSON(w, http.StatusOK, summary)
}

const (
	// rangeRateToken in a curated expression is replaced by a rate()/increase()
	// range-selector window derived from the resolved step. That keeps a
	// downsampled series averaging over an interval proportional to how often it
	// is sampled, instead of an arbitrary fixed window.
	rangeRateToken = "$rate"

	// defaultRangePoints is the target point count per series when the caller
	// does not pick a step: step = (to - from) / defaultRangePoints.
	defaultRangePoints = 600
	// minStepSeconds / maxStepSeconds bound the Prometheus step: 1 s (the scrape
	// interval is 10 s, so a finer step only duplicates points) to 7 days.
	minStepSeconds = 1
	maxStepSeconds = 604800
	// maxRangeWindow caps a single query window. Prometheus keeps 15 days by
	// default (observability/prometheus + docker-compose set no retention
	// override), so a wider window can only return nothing — the 400 lets the UI
	// say "beyond retention" instead of drawing an empty frame (PRD §5.2).
	maxRangeWindow = 15 * 24 * time.Hour
)

// rangeMetric is one curated KPI. Expr is fixed PromQL and may contain
// rangeRateToken; a caller can only select the key.
type rangeMetric struct {
	Expr        string
	Description string
}

// rangeMetrics is the whitelist. The keys are the only metric identifiers the
// range endpoint accepts. Expressions must reference metrics from the shared
// registry (`shared/observability/metrics`) and keep their labels intact.
var rangeMetrics = map[string]rangeMetric{
	"ue_registered": {
		Expr:        `sum(fivegc_ue_registered)`,
		Description: "UEs currently in 5GMM-REGISTERED state (TS 24.501 §5).",
	},
	"ue_registered_by_slice": {
		Expr:        `sum by (sst, sd) (fivegc_ue_registered_by_slice)`,
		Description: "Registered UEs per S-NSSAI (NF slice deployment).",
	},
	"amf_registrations": {
		Expr:        `sum(rate(fivegc_procedure_total{nf="AMF",procedure="InitialRegistration"}[$rate]))`,
		Description: "AMF Initial Registration procedure rate (TS 23.502 §4.2.2.2).",
	},
	"registration_success_rate": {
		// KPI = successful / attempted registrations × 100 (TS 28.554 §5.1). A
		// window with no attempts yields 0/0 = NaN, which rangePoints drops, so
		// an idle network renders as a gap — never a misleading 0%/100% line.
		Expr:        `100 * sum(rate(fivegc_procedure_total{nf="AMF",procedure="InitialRegistration",result="OK"}[$rate])) / sum(rate(fivegc_procedure_total{nf="AMF",procedure="InitialRegistration"}[$rate]))`,
		Description: "Initial Registration success rate percentage = OK / attempts × 100 (TS 28.554 §5.1).",
	},
	"procedure_rates_by_result": {
		Expr:        `sum by (result) (rate(fivegc_procedure_total[$rate]))`,
		Description: "3GPP procedure completion rate split by OK / REJECT / FAILURE.",
	},
	"sbi_request_rate": {
		Expr:        `sum(rate(fivegc_sbi_requests_total[$rate]))`,
		Description: "SBI (HTTP/2) requests handled per second.",
	},
	"sbi_latency_p99": {
		Expr:        `histogram_quantile(0.99, sum by (le) (rate(fivegc_sbi_request_duration_seconds_bucket[$rate])))`,
		Description: "p99 SBI handler latency in seconds.",
	},
	"pdu_sessions_active": {
		Expr:        `sum(fivegc_pdu_sessions_active)`,
		Description: "Active PDU sessions (SMF).",
	},
	"authentication_rate": {
		Expr:        `sum by (result) (rate(fivegc_authentication_total[$rate]))`,
		Description: "5G-AKA authentication completions per second (AUSF).",
	},
	"upf_gtp_throughput": {
		// N3 user-plane throughput: inner-IP bytes forwarded over GTP-U per
		// second, ×8 to bits/s with one series per direction (UL/DL). Ref:
		// TS 28.554 §5.3 (UPF data-volume KPI), TS 29.281 (GTP-U).
		Expr:        `sum by (direction) (rate(fivegc_upf_gtp_bytes_total[$rate])) * 8`,
		Description: "User-plane (N3) GTP-U throughput in bits/s per direction (TS 28.554 §5.3).",
	},
}

// metricsRangeResponse is the chart-friendly response shape:
//
//	{"metric":"ue_registered","step":6,"series":[{"name":"ue_registered","points":[[t,v],...]}]}
type metricsRangeResponse struct {
	Metric string         `json:"metric"`
	Step   int            `json:"step"`
	Series []metricSeries `json:"series"`
}

// metricSeries is one named time series. Points are [unix_seconds, value].
type metricSeries struct {
	Name   string       `json:"name"`
	Points [][2]float64 `json:"points"`
}

// GET /api/v1/metrics/range?metric=<key>&from=<ts>&to=<ts>[&step=<seconds>]
//
// from/to accept RFC3339 (what Date.toISOString() produces) or Unix seconds.
// step is optional; with it omitted the server targets defaultRangePoints
// across the window. Non-finite samples are dropped, never coerced to zero.
func (d Deps) handleMetricsRange(w http.ResponseWriter, r *http.Request) {
	if d.Prometheus == nil {
		writeError(w, http.StatusServiceUnavailable, "prometheus unavailable")
		return
	}

	key := r.URL.Query().Get("metric")
	spec, ok := rangeMetrics[key]
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown metric %q", key))
		return
	}

	from, err := parseRangeTime(r.URL.Query().Get("from"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid from: "+err.Error())
		return
	}
	to, err := parseRangeTime(r.URL.Query().Get("to"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid to: "+err.Error())
		return
	}
	if !to.After(from) {
		writeError(w, http.StatusBadRequest, "to must be after from")
		return
	}
	if to.Sub(from) > maxRangeWindow {
		writeError(w, http.StatusBadRequest, "range exceeds the 15 day Prometheus retention")
		return
	}
	step, err := resolveRangeStep(from, to, r.URL.Query().Get("step"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	series, err := d.Prometheus.QueryRange(r.Context(), expandRangeExpr(spec.Expr, step), from, to, step)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	resp := metricsRangeResponse{Metric: key, Step: step, Series: make([]metricSeries, 0, len(series))}
	for _, s := range series {
		resp.Series = append(resp.Series, metricSeries{
			Name:   rangeSeriesName(key, s.Metric),
			Points: rangePoints(s.Values),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseRangeTime accepts RFC3339 (with optional fractional seconds) or an
// integer Unix timestamp in seconds.
func parseRangeTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, fmt.Errorf("missing")
	}
	if secs, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(secs, 0).UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("want RFC3339 or Unix seconds, got %q", raw)
	}
	return t.UTC(), nil
}

// resolveRangeStep returns the Prometheus step in seconds: the caller's value
// when supplied (validated against [minStepSeconds, maxStepSeconds]), otherwise
// defaultRangePoints across the window, clamped to the same bounds.
func resolveRangeStep(from, to time.Time, raw string) (int, error) {
	if raw == "" {
		return clampStep(int(to.Sub(from).Seconds()) / defaultRangePoints), nil
	}
	step, err := strconv.Atoi(raw)
	if err != nil || step < minStepSeconds || step > maxStepSeconds {
		return 0, fmt.Errorf("step must be an integer in [%d,%d] seconds", minStepSeconds, maxStepSeconds)
	}
	return step, nil
}

func clampStep(step int) int {
	if step < minStepSeconds {
		return minStepSeconds
	}
	if step > maxStepSeconds {
		return maxStepSeconds
	}
	return step
}

// rangeRateWindow is the range-selector window handed to rate()/increase():
// four steps (so each point averages over a full sample interval) and never
// below 30 s (≈3 scrapes at the 10 s default).
func rangeRateWindow(step int) time.Duration {
	w := 4 * time.Duration(step) * time.Second
	if w < 30*time.Second {
		w = 30 * time.Second
	}
	return w
}

// expandRangeExpr substitutes rangeRateToken with the resolved rate window.
func expandRangeExpr(expr string, step int) string {
	if !strings.Contains(expr, rangeRateToken) {
		return expr
	}
	return strings.ReplaceAll(expr, rangeRateToken, rangeRateWindow(step).String())
}

// rangePoints converts Prometheus matrix samples to JSON-safe [t, v] pairs,
// dropping non-finite values: JSON cannot encode NaN/±Inf and a gap is the
// truthful rendering of "no data" (PRD §5.2 — never a misleading zero line).
func rangePoints(values [][2]interface{}) [][2]float64 {
	points := make([][2]float64, 0, len(values))
	for _, v := range values {
		ts, ok := rangeNumber(v[0])
		if !ok {
			continue
		}
		val, ok := rangeNumber(v[1])
		if !ok || math.IsNaN(val) || math.IsInf(val, 0) {
			continue
		}
		points = append(points, [2]float64{ts, val})
	}
	return points
}

// rangeNumber reads a matrix coordinate: timestamps decode as JSON numbers and
// values as strings (Prometheus encodes sample values as strings).
func rangeNumber(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

// rangeSeriesName gives each matrix series a stable, Prometheus-style name. A
// collapsed expression (sum(...)) carries no labels and keeps the metric key;
// multi-series expressions append their identifying labels, sorted, so the name
// is deterministic and a chart legend can tell OK from FAILURE.
func rangeSeriesName(key string, metric map[string]string) string {
	labels := rangeSeriesLabels(metric)
	if len(labels) == 0 {
		return key
	}
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+strconv.Quote(v))
	}
	sort.Strings(parts)
	return key + "{" + strings.Join(parts, ",") + "}"
}

// rangeSeriesLabels drops labels that do not identify a logical series:
// __name__ (the metric name is already the key) and the scrape target labels.
func rangeSeriesLabels(metric map[string]string) map[string]string {
	labels := make(map[string]string, len(metric))
	for k, v := range metric {
		switch k {
		case "__name__", "job", "instance":
			continue
		}
		labels[k] = v
	}
	return labels
}
