package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	promclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/prometheus"
)

// rangeRouter builds the real router with a Prometheus client pointed at
// upstreamURL, so the tests exercise route registration and the handler wiring
// (Deps.Prometheus nil is the degraded case).
func rangeRouter(t *testing.T, upstreamURL string) http.Handler {
	t.Helper()
	var deps Deps
	if upstreamURL != "" {
		deps.Prometheus = promclient.New(upstreamURL)
	}
	return NewRouter(deps, http.FS(os.DirFS(t.TempDir())))
}

// fakePrometheus serves a fixed body/status on the range endpoint and reports
// whether it was called (validation tests assert it was not).
func fakePrometheus(t *testing.T, status int, body string) (*httptest.Server, *bool, *string) {
	t.Helper()
	hit := new(bool)
	query := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hit = true
		*query = r.URL.Query().Get("query")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, hit, query
}

const emptyMatrix = `{"status":"success","data":{"resultType":"matrix","result":[]}}`

// TestMetricsRange_RouteRegistered: an unknown metric is a 400, not the router's
// 404 fallback — proving GET /api/v1/metrics/range is wired.
func TestMetricsRange_RouteRegistered(t *testing.T) {
	rec := do(t, rangeRouter(t, "http://127.0.0.1:1"), http.MethodGet, "/api/v1/metrics/range?metric=nope&from=1&to=2", "")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 (route registered), got %d (%q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("want application/json, got %q", ct)
	}
}

// TestMetricsRange_Validation rejects every malformed request before touching
// Prometheus (the fake is never called).
func TestMetricsRange_Validation(t *testing.T) {
	srv, hit, _ := fakePrometheus(t, http.StatusOK, emptyMatrix)
	h := rangeRouter(t, srv.URL)

	valid := "from=1758000000&to=1758003600"
	cases := []struct {
		name  string
		query string
	}{
		{"missing metric", valid},
		{"unknown metric", "metric=drop_table&" + valid},
		{"missing from", "metric=ue_registered&to=1758003600"},
		{"missing to", "metric=ue_registered&from=1758000000"},
		{"invalid from", "metric=ue_registered&from=not-a-time&to=1758003600"},
		{"invalid to", "metric=ue_registered&from=1758000000&to=2026-09-16"},
		{"to before from", "metric=ue_registered&from=1758003600&to=1758000000"},
		{"to equals from", "metric=ue_registered&from=1758003600&to=1758003600"},
		{"step zero", "metric=ue_registered&" + valid + "&step=0"},
		{"step negative", "metric=ue_registered&" + valid + "&step=-5"},
		{"step not a number", "metric=ue_registered&" + valid + "&step=abc"},
		{"step above max", "metric=ue_registered&" + valid + "&step=604801"},
		{"range beyond retention", "metric=ue_registered&from=1758000000&to=1759296001"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, h, http.MethodGet, "/api/v1/metrics/range?"+tc.query, "")
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d (%q)", rec.Code, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("want application/json, got %q", ct)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
				t.Errorf("want JSON error body, got %q (err %v)", rec.Body.String(), err)
			}
			if *hit {
				t.Error("Prometheus was queried for an invalid request")
			}
		})
	}
}

// TestMetricsRange_Shape pins the chart-friendly response shape and the
// server-computed default step + injected rate window.
func TestMetricsRange_Shape(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"matrix","result":[
	  {"metric":{"result":"OK"},"values":[[1758000000,"1.5"],[1758000060,"2.5"]]},
	  {"metric":{"result":"FAILURE"},"values":[[1758000000,"0"]]}
	]}}`
	srv, _, query := fakePrometheus(t, http.StatusOK, body)
	h := rangeRouter(t, srv.URL)

	rec := do(t, h, http.MethodGet,
		"/api/v1/metrics/range?metric=procedure_rates_by_result&from=1758000000&to=1758003600", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%q)", rec.Code, rec.Body.String())
	}

	var got struct {
		Metric string `json:"metric"`
		Step   int    `json:"step"`
		Series []struct {
			Name   string       `json:"name"`
			Points [][2]float64 `json:"points"`
		} `json:"series"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v (%q)", err, rec.Body.String())
	}

	// 3600 s window / 600 target points = 6 s step; rate window = max(30s, 4*6s).
	if got.Step != 6 {
		t.Errorf("step = %d, want 6", got.Step)
	}
	if len(got.Series) != 2 {
		t.Fatalf("series len = %d, want 2", len(got.Series))
	}
	if got.Series[0].Name != `procedure_rates_by_result{result="OK"}` {
		t.Errorf("series[0].Name = %q", got.Series[0].Name)
	}
	if want := [][2]float64{{1758000000, 1.5}, {1758000060, 2.5}}; !reflect.DeepEqual(got.Series[0].Points, want) {
		t.Errorf("series[0].Points = %v, want %v", got.Series[0].Points, want)
	}
	if got.Series[1].Name != `procedure_rates_by_result{result="FAILURE"}` {
		t.Errorf("series[1].Name = %q", got.Series[1].Name)
	}

	if strings.Contains(*query, rangeRateToken) {
		t.Errorf("expression still contains %s: %q", rangeRateToken, *query)
	}
	if !strings.Contains(*query, "[30s]") {
		t.Errorf("expression rate window not injected: %q", *query)
	}
}

// TestMetricsRange_NewKeysAccepted: the two keys added for the 3GPP-grounded
// dashboard (PORTAL-UI-20) are accepted by the whitelist — a typo or a missing
// entry would surface as the 400 "unknown metric" instead of a chart.
func TestMetricsRange_NewKeysAccepted(t *testing.T) {
	srv, hit, _ := fakePrometheus(t, http.StatusOK, emptyMatrix)
	h := rangeRouter(t, srv.URL)

	for _, key := range []string{"registration_success_rate", "upf_gtp_throughput"} {
		t.Run(key, func(t *testing.T) {
			*hit = false
			rec := do(t, h, http.MethodGet,
				"/api/v1/metrics/range?metric="+key+"&from=1758000000&to=1758003600", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("want 200, got %d (%q)", rec.Code, rec.Body.String())
			}
			if !*hit {
				t.Error("Prometheus was not queried for an accepted key")
			}
		})
	}
}

// TestMetricsRange_RegistrationSuccessRateExpression pins the success-rate KPI
// formula: 100 × OK-rate / total-rate over the AMF InitialRegistration series,
// with the OK selector and the $rate window expanded (TS 28.554 §5.1).
func TestMetricsRange_RegistrationSuccessRateExpression(t *testing.T) {
	srv, _, query := fakePrometheus(t, http.StatusOK, emptyMatrix)

	rec := do(t, rangeRouter(t, srv.URL), http.MethodGet,
		"/api/v1/metrics/range?metric=registration_success_rate&from=1758000000&to=1758003600", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%q)", rec.Code, rec.Body.String())
	}

	expr := *query
	for _, want := range []string{
		`result="OK"`,
		`procedure="InitialRegistration"`,
		`nf="AMF"`,
		"[30s]",
		" / ",
	} {
		if !strings.Contains(expr, want) {
			t.Errorf("expression missing %q: %q", want, expr)
		}
	}
	if strings.Contains(expr, rangeRateToken) {
		t.Errorf("expression still contains %s: %q", rangeRateToken, expr)
	}
	// Numerator and denominator are each a sum(rate(...)) over the same series.
	if got := strings.Count(expr, "sum(rate("); got != 2 {
		t.Errorf("sum(rate(...)) count = %d, want 2: %q", got, expr)
	}
}

// TestMetricsRange_ThroughputDirections pins the direction-labelled series
// naming for the N3 throughput KPI and that the bits/s conversion + rate window
// survive expansion (TS 28.554 §5.3).
func TestMetricsRange_ThroughputDirections(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"matrix","result":[
	  {"metric":{"direction":"uplink","__name__":"fivegc_upf_gtp_bytes_total"},"values":[[1758000000,"1250"]]},
	  {"metric":{"direction":"downlink","__name__":"fivegc_upf_gtp_bytes_total"},"values":[[1758000000,"5000"]]}
	]}}`
	srv, _, query := fakePrometheus(t, http.StatusOK, body)

	rec := do(t, rangeRouter(t, srv.URL), http.MethodGet,
		"/api/v1/metrics/range?metric=upf_gtp_throughput&from=1758000000&to=1758003600", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%q)", rec.Code, rec.Body.String())
	}

	var got struct {
		Series []struct {
			Name string `json:"name"`
		} `json:"series"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v (%q)", err, rec.Body.String())
	}
	if len(got.Series) != 2 {
		t.Fatalf("series len = %d, want 2", len(got.Series))
	}
	if got.Series[0].Name != `upf_gtp_throughput{direction="uplink"}` {
		t.Errorf("series[0].Name = %q", got.Series[0].Name)
	}
	if got.Series[1].Name != `upf_gtp_throughput{direction="downlink"}` {
		t.Errorf("series[1].Name = %q", got.Series[1].Name)
	}
	for _, want := range []string{"sum by (direction)", "fivegc_upf_gtp_bytes_total", "[30s]", "* 8"} {
		if !strings.Contains(*query, want) {
			t.Errorf("expression missing %q: %q", want, *query)
		}
	}
	if strings.Contains(*query, rangeRateToken) {
		t.Errorf("expression still contains %s: %q", rangeRateToken, *query)
	}
}

// TestMetricsRange_EmptyResult: a metric that has never been emitted is a 200
// with no series — distinct from Prometheus being unavailable (503).
func TestMetricsRange_EmptyResult(t *testing.T) {
	srv, _, _ := fakePrometheus(t, http.StatusOK, emptyMatrix)

	rec := do(t, rangeRouter(t, srv.URL), http.MethodGet,
		"/api/v1/metrics/range?metric=ue_registered&from=1758000000&to=1758003600", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"series":[]`) {
		t.Errorf("want empty series array, got %q", rec.Body.String())
	}
}

// TestMetricsRange_DropsNonFinitePoints: NaN/Inf samples are omitted rather
// than coerced to 0 (PRD §5.2 — never a misleading zero line).
func TestMetricsRange_DropsNonFinitePoints(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"matrix","result":[
	  {"metric":{},"values":[[1,"NaN"],[2,"3"],[3,"+Inf"]]}
	]}}`
	srv, _, _ := fakePrometheus(t, http.StatusOK, body)

	rec := do(t, rangeRouter(t, srv.URL), http.MethodGet,
		"/api/v1/metrics/range?metric=ue_registered&from=1758000000&to=1758003600", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var got struct {
		Series []struct {
			Points [][2]float64 `json:"points"`
		} `json:"series"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Series) != 1 {
		t.Fatalf("series len = %d, want 1", len(got.Series))
	}
	if want := [][2]float64{{2, 3}}; !reflect.DeepEqual(got.Series[0].Points, want) {
		t.Errorf("points = %v, want only [[2,3]]", got.Series[0].Points)
	}
}

// TestMetricsRange_PrometheusUnavailable: a nil client is a 503, so the UI can
// distinguish "backend down" from "no data" (PRD S19 / §5.3).
func TestMetricsRange_PrometheusUnavailable(t *testing.T) {
	rec := do(t, rangeRouter(t, ""), http.MethodGet,
		"/api/v1/metrics/range?metric=ue_registered&from=1758000000&to=1758003600", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d (%q)", rec.Code, rec.Body.String())
	}
}

// TestMetricsRange_UpstreamFailure: a Prometheus error is surfaced as 502.
func TestMetricsRange_UpstreamFailure(t *testing.T) {
	srv, _, _ := fakePrometheus(t, http.StatusInternalServerError, `boom`)

	rec := do(t, rangeRouter(t, srv.URL), http.MethodGet,
		"/api/v1/metrics/range?metric=ue_registered&from=1758000000&to=1758003600", "")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d (%q)", rec.Code, rec.Body.String())
	}
}

// TestMetricsSummary_ExposesInstantSuccessRates: GET /api/v1/metrics/summary
// exposes the two PORTAL-UI-21 instant KPIs under their snake_case JSON keys —
// numeric when Prometheus has data, null (never 0/100) when the ratio is NaN.
func TestMetricsSummary_ExposesInstantSuccessRates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case q == "sum(fivegc_pdu_sessions_active) or vector(0)":
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"2"]}]}}`)
		case strings.Contains(q, "InitialRegistration"):
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"100"]}]}}`)
		case strings.Contains(q, "fivegc_pdu_session_total"):
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"NaN"]}]}}`)
		default:
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
		}
	}))
	defer srv.Close()

	rec := do(t, rangeRouter(t, srv.URL), http.MethodGet, "/api/v1/metrics/summary", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%q)", rec.Code, rec.Body.String())
	}

	var got struct {
		PDUSessions                int      `json:"pdu_sessions"`
		RegistrationSuccessPct     *float64 `json:"registration_success_pct"`
		PDUSessionEstablishmentPct *float64 `json:"pdu_session_establishment_success_pct"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%q)", err, rec.Body.String())
	}
	if got.PDUSessions != 2 {
		t.Errorf("pdu_sessions = %d, want 2 (summed from fivegc_pdu_sessions_active)", got.PDUSessions)
	}
	if got.RegistrationSuccessPct == nil || *got.RegistrationSuccessPct != 100 {
		t.Errorf("registration_success_pct = %v, want 100", got.RegistrationSuccessPct)
	}
	if got.PDUSessionEstablishmentPct != nil {
		t.Errorf("pdu_session_establishment_success_pct = %v, want null for a NaN ratio", *got.PDUSessionEstablishmentPct)
	}
	// Both keys must be present in the payload (nil must not be dropped).
	for _, key := range []string{`"registration_success_pct"`, `"pdu_session_establishment_success_pct"`} {
		if !strings.Contains(rec.Body.String(), key) {
			t.Errorf("summary JSON missing %s: %q", key, rec.Body.String())
		}
	}
}

// ---- unit tests for the pure helpers ----

func TestResolveRangeStep(t *testing.T) {
	from := time.Unix(1758000000, 0)
	to := time.Unix(1758003600, 0) // 3600 s

	if step, err := resolveRangeStep(from, to, ""); err != nil || step != 6 {
		t.Errorf("default step = %d/%v, want 6", step, err)
	}
	if step, err := resolveRangeStep(from, to, "60"); err != nil || step != 60 {
		t.Errorf("explicit step = %d/%v, want 60", step, err)
	}
	if _, err := resolveRangeStep(from, to, "0"); err == nil {
		t.Error("step 0 should be rejected")
	}
	if _, err := resolveRangeStep(from, to, "604801"); err == nil {
		t.Error("step above max should be rejected")
	}
	// A sub-minute window clamps the default step to the 1 s minimum.
	step, _ := resolveRangeStep(time.Unix(1758000000, 0), time.Unix(1758000060, 0), "")
	if step != minStepSeconds {
		t.Errorf("short-window step = %d, want %d", step, minStepSeconds)
	}
}

func TestParseRangeTime(t *testing.T) {
	if got, err := parseRangeTime("1758000000"); err != nil || got.Unix() != 1758000000 {
		t.Errorf("unix: got %v/%v", got, err)
	}
	want := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	if got, err := parseRangeTime("2026-09-16T10:00:00.000Z"); err != nil || !got.Equal(want) {
		t.Errorf("rfc3339: got %v/%v, want %v", got, err, want)
	}
	if _, err := parseRangeTime(""); err == nil {
		t.Error("empty should be rejected")
	}
	if _, err := parseRangeTime("yesterday"); err == nil {
		t.Error("garbage should be rejected")
	}
}

func TestRangeSeriesName(t *testing.T) {
	if got := rangeSeriesName("ue_registered", map[string]string{"__name__": "fivegc_ue_registered"}); got != "ue_registered" {
		t.Errorf("collapsed series name = %q", got)
	}
	got := rangeSeriesName("ue_registered_by_slice", map[string]string{"__name__": "x", "sd": "000001", "sst": "1", "job": "5gc-nfs", "instance": "amf:9101"})
	if got != `ue_registered_by_slice{sd="000001",sst="1"}` {
		t.Errorf("multi-label series name = %q", got)
	}
}

func TestRangePointsNonFinite(t *testing.T) {
	pts := rangePoints([][2]interface{}{
		{float64(1), "2.5"},
		{float64(2), "NaN"},
		{float64(3), "+Inf"},
		{"not-a-time", "4"},
		{float64(4), "not-a-number"},
		{float64(5), "6"},
	})
	want := [][2]float64{{1, 2.5}, {5, 6}}
	if len(pts) != len(want) || pts[0] != want[0] || pts[1] != want[1] {
		t.Errorf("rangePoints = %v, want %v", pts, want)
	}
}

func TestExpandRangeExpr(t *testing.T) {
	if got := expandRangeExpr(`sum(rate(x[5m]))`, 6); got != `sum(rate(x[5m]))` {
		t.Errorf("expression without token changed: %q", got)
	}
	if got := expandRangeExpr(`sum(rate(x[$rate]))`, 6); got != `sum(rate(x[30s]))` {
		t.Errorf("token not substituted: %q", got)
	}
	if got := expandRangeExpr(`sum(rate(x[$rate]))`, 120); got != `sum(rate(x[8m0s]))` {
		t.Errorf("proportional window wrong: %q", got)
	}
}
