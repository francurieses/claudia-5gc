package metrics_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	metricstools "github.com/francurieses/claudia-5gc/mcp/internal/tools/metrics"
)

// fakePrometheus returns an httptest.Server that responds to /api/v1/query
// and /api/v1/alerts with canned JSON.
func fakePrometheus(t *testing.T, queryBody, alertsBody string) (*httptest.Server, *promclient.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/alerts":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(alertsBody))
		case r.URL.Path == "/api/v1/query":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(queryBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	client := promclient.New(srv.URL, srv.Client(), 0)
	return srv, client
}

const sampleQueryResp = `{
  "status":"success",
  "data":{
    "resultType":"vector",
    "result":[
      {"metric":{"nf":"AMF","__name__":"fivegc_ue_registered"},"value":[1717000000,"3"]}
    ]
  }
}`

const sampleAlertsResp = `{
  "status":"success",
  "data":{
    "alerts":[
      {"labels":{"alertname":"HighSBILatency","severity":"warning"},"annotations":{"summary":"SBI latency high"},"state":"firing","activeAt":"2026-06-01T00:00:00Z","value":"0.5"},
      {"labels":{"alertname":"NoUEs","severity":"info"},"annotations":{},"state":"pending","activeAt":"2026-06-01T01:00:00Z","value":"0"}
    ]
  }
}`

func invoke(t *testing.T, prom *promclient.Client, toolName, input string) map[string]any {
	t.Helper()
	for _, tool := range metricstools.All(prom) {
		if tool.Name() != toolName {
			continue
		}
		res, err := tool.Invoke(context.Background(), json.RawMessage(input))
		if err != nil {
			t.Fatalf("%s.Invoke error: %v", toolName, err)
		}
		b, _ := json.Marshal(res)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	t.Fatalf("tool %q not found", toolName)
	return nil
}

func invokeErr(t *testing.T, prom *promclient.Client, toolName, input string) error {
	t.Helper()
	for _, tool := range metricstools.All(prom) {
		if tool.Name() != toolName {
			continue
		}
		_, err := tool.Invoke(context.Background(), json.RawMessage(input))
		if err == nil {
			t.Fatalf("%s.Invoke: expected error but got nil", toolName)
		}
		return err
	}
	t.Fatalf("tool %q not found", toolName)
	return nil
}

// ---- metric_query ----------------------------------------------------------

func TestMetricQueryReturnsResults(t *testing.T) {
	_, prom := fakePrometheus(t, sampleQueryResp, sampleAlertsResp)
	m := invoke(t, prom, "metric_query", `{"promql":"fivegc_ue_registered{nf=\"AMF\"}"}`)
	results, _ := m["results"].([]any)
	if len(results) == 0 {
		t.Error("expected at least one result")
	}
}

func TestMetricQueryMissingPromQL(t *testing.T) {
	_, prom := fakePrometheus(t, sampleQueryResp, sampleAlertsResp)
	invokeErr(t, prom, "metric_query", `{}`)
}

func TestMetricQueryBadTime(t *testing.T) {
	_, prom := fakePrometheus(t, sampleQueryResp, sampleAlertsResp)
	invokeErr(t, prom, "metric_query", `{"promql":"fivegc_ue_registered","time":"notadate"}`)
}

func TestMetricQueryPrometheusDown(t *testing.T) {
	prom := promclient.New("http://127.0.0.1:9", nil, 0) // nothing listening
	invokeErr(t, prom, "metric_query", `{"promql":"up"}`)
}

// ---- kpi_snapshot ----------------------------------------------------------

func TestKPISnapshotAllNF(t *testing.T) {
	_, prom := fakePrometheus(t, sampleQueryResp, sampleAlertsResp)
	m := invoke(t, prom, "kpi_snapshot", `{"nf":"all"}`)
	if m["snapshot_time"] == nil {
		t.Error("snapshot_time should be present")
	}
	// All numeric fields must be present (even if 0)
	for _, key := range []string{"registration_success_rate", "auth_success_rate",
		"avg_registration_latency_ms", "sbi_error_rate"} {
		if _, ok := m[key]; !ok {
			t.Errorf("kpi_snapshot: missing key %s", key)
		}
	}
}

func TestKPISnapshotNFFilter(t *testing.T) {
	_, prom := fakePrometheus(t, sampleQueryResp, sampleAlertsResp)
	m := invoke(t, prom, "kpi_snapshot", `{"nf":"amf"}`)
	if m["snapshot_time"] == nil {
		t.Error("snapshot_time should be present")
	}
}

// ---- alert_list ------------------------------------------------------------

func TestAlertListAll(t *testing.T) {
	_, prom := fakePrometheus(t, sampleQueryResp, sampleAlertsResp)
	m := invoke(t, prom, "alert_list", `{"state":"all"}`)
	alerts, _ := m["alerts"].([]any)
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(alerts))
	}
}

func TestAlertListFiringFilter(t *testing.T) {
	_, prom := fakePrometheus(t, sampleQueryResp, sampleAlertsResp)
	m := invoke(t, prom, "alert_list", `{"state":"firing"}`)
	alerts, _ := m["alerts"].([]any)
	if len(alerts) != 1 {
		t.Errorf("expected 1 firing alert, got %d", len(alerts))
	}
}

func TestAlertListDefaultState(t *testing.T) {
	_, prom := fakePrometheus(t, sampleQueryResp, sampleAlertsResp)
	m := invoke(t, prom, "alert_list", `{}`) // no state = all
	alerts, _ := m["alerts"].([]any)
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts with default state, got %d", len(alerts))
	}
}

func TestAlertListPrometheusDown(t *testing.T) {
	prom := promclient.New("http://127.0.0.1:9", nil, 0)
	invokeErr(t, prom, "alert_list", `{"state":"all"}`)
}

// TestKPIEmptyVectorIsNull: no series must give JSON null and a reason, never 0.
func TestKPIEmptyVectorIsNull(t *testing.T) {
	_, prom := fakePrometheus(t, `{"status":"success","data":{"resultType":"vector","result":[]}}`, sampleAlertsResp)
	m := invoke(t, prom, "kpi_snapshot", `{"nf":"all"}`)
	unavail, _ := m["unavailable"].(map[string]any)
	for _, key := range []string{"registration_success_rate", "auth_success_rate", "active_ue_contexts",
		"ue_connected", "pdu_sessions_active", "upf_pfcp_sessions_active",
		"avg_registration_latency_ms", "sbi_error_rate"} {
		v, ok := m[key]
		if !ok || v != nil {
			t.Errorf("%s = %v (present=%v), want null", key, v, ok)
		}
		if r, _ := unavail[key].(string); r == "" {
			t.Errorf("%s: missing unavailable reason", key)
		}
	}
}

// TestKPINaNIsNull: a NaN sample (zero denominator) is null, not 0.
func TestKPINaNIsNull(t *testing.T) {
	_, prom := fakePrometheus(t, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"NaN"]}]}}`, sampleAlertsResp)
	m := invoke(t, prom, "kpi_snapshot", `{}`)
	if m["auth_success_rate"] != nil {
		t.Errorf("auth_success_rate = %v, want null", m["auth_success_rate"])
	}
}

// TestKPIValuesAndAuthQuery: real values come through, ints are ints, and the
// auth KPI is read from fivegc_authentication_total{nf="AUSF"}.
func TestKPIValuesAndAuthQuery(t *testing.T) {
	var (
		mu      sync.Mutex
		queries []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.Query().Get("query"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"3"]}]}}`))
	}))
	defer srv.Close()
	m := invoke(t, promclient.New(srv.URL, srv.Client(), 0), "kpi_snapshot", `{}`)
	if m["active_ue_contexts"] != float64(3) || m["pdu_sessions_active"] != float64(3) {
		t.Errorf("counts: %v", m)
	}
	found := false
	for _, q := range queries {
		if strings.Contains(q, `fivegc_authentication_total{nf="AUSF",result="OK"}`) {
			found = true
		}
		if strings.Contains(q, `procedure="Authentication"`) {
			t.Errorf("auth KPI must not use fivegc_procedure_total: %s", q)
		}
	}
	if !found {
		t.Errorf("auth query missing: %v", queries)
	}
	if m["sbi_error_rate"] != nil || m["avg_registration_latency_ms"] != nil {
		t.Errorf("non-exported KPIs must be null: %v", m)
	}
}

// kpiQueries runs kpi_snapshot and returns the PromQL strings sent to Prometheus.
func kpiQueries(t *testing.T, input string) []string {
	t.Helper()
	var (
		mu      sync.Mutex
		queries []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.Query().Get("query"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"3"]}]}}`))
	}))
	defer srv.Close()
	invoke(t, promclient.New(srv.URL, srv.Client(), 0), "kpi_snapshot", input)
	return queries
}

func containsQuery(qs []string, want string) bool {
	for _, q := range qs {
		if q == want {
			return true
		}
	}
	return false
}

// TestKPIRegistrationQueryExact: the nf matcher shares one selector (a second
// brace block is a PromQL parse error) and no query has two brace blocks.
func TestKPIRegistrationQueryExact(t *testing.T) {
	cases := []struct{ input, want string }{
		{`{"nf":"all"}`, `sum(fivegc_procedure_total{procedure="InitialRegistration",result="OK"}) / ` +
			`sum(fivegc_procedure_total{procedure="InitialRegistration"})`},
		{`{"nf":"amf"}`, `sum(fivegc_procedure_total{procedure="InitialRegistration",result="OK",nf="AMF"}) / ` +
			`sum(fivegc_procedure_total{procedure="InitialRegistration",nf="AMF"})`},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			qs := kpiQueries(t, c.input)
			if !containsQuery(qs, c.want) {
				t.Errorf("missing exact query %q in %v", c.want, qs)
			}
			for _, q := range qs {
				if strings.Contains(q, "}{") {
					t.Errorf("double selector in %q", q)
				}
			}
		})
	}
}

func TestKPIRejectsUnknownNF(t *testing.T) {
	_, prom := fakePrometheus(t, sampleQueryResp, sampleAlertsResp)
	for _, nf := range []string{`smf`, `amf"} or vector(1) #`} {
		b, _ := json.Marshal(map[string]string{"nf": nf})
		err := invokeErr(t, prom, "kpi_snapshot", string(b))
		if !strings.Contains(err.Error(), "nf must be one of") {
			t.Errorf("nf %q: err = %v", nf, err)
		}
	}
}

// TestMetricQueryNaNIsNull: NaN / Inf samples are null; the call still succeeds.
func TestMetricQueryNaNIsNull(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"vector","result":[` +
		`{"metric":{"a":"1"},"value":[1,"NaN"]},{"metric":{"a":"2"},"value":[1,"+Inf"]},{"metric":{"a":"3"},"value":[1,"2.5"]}]}}`
	_, prom := fakePrometheus(t, body, sampleAlertsResp)
	m := invoke(t, prom, "metric_query", `{"promql":"x"}`)
	rows, _ := m["results"].([]any)
	if len(rows) != 3 {
		t.Fatalf("results: %v", m["results"])
	}
	for i, want := range []any{nil, nil, 2.5} {
		if got := rows[i].(map[string]any)["value"]; got != want {
			t.Errorf("row %d value = %v, want %v", i, got, want)
		}
	}
}

// TestMetricQueryRangeNaNIsNull: range samples are numbers, non-finite ones null.
func TestMetricQueryRangeNaNIsNull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
			`{"metric":{},"values":[[1,"NaN"],[2,"4"],[3,"-Inf"]]}]}}`))
	}))
	defer srv.Close()
	m := invoke(t, promclient.New(srv.URL, srv.Client(), 0), "metric_query",
		`{"promql":"x","start":"2026-01-01T00:00:00Z","end":"2026-01-01T00:10:00Z"}`)
	series := m["results"].([]any)
	vals := series[0].(map[string]any)["values"].([]any)
	got := []any{vals[0].([]any)[1], vals[1].([]any)[1], vals[2].([]any)[1]}
	if got[0] != nil || got[1] != float64(4) || got[2] != nil {
		t.Errorf("range values = %v", got)
	}
}
