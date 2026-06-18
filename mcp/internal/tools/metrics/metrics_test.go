package metrics_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
