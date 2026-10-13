package metrics_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	metricstools "github.com/francurieses/claudia-5gc/mcp/internal/tools/metrics"
)

func upfProm(t *testing.T, answer func(q string) string) (*promclient.Client, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		mu.Lock()
		queries = append(queries, q)
		mu.Unlock()
		_, _ = w.Write([]byte(answer(q)))
	}))
	t.Cleanup(srv.Close)
	return promclient.New(srv.URL, srv.Client(), 0), &queries
}

func vec(rows ...string) string {
	return `{"status":"success","data":{"resultType":"vector","result":[` + strings.Join(rows, ",") + `]}}`
}

func TestUPFStats(t *testing.T) {
	prom, queries := upfProm(t, func(q string) string {
		switch {
		case strings.HasPrefix(q, "fivegc_upf_pfcp_sessions_active"):
			return vec(`{"metric":{"nf":"SMF"},"value":[1,"0"]}`, `{"metric":{"nf":"UPF"},"value":[1,"2"]}`)
		case strings.Contains(q, "gtp_bytes_total"):
			return vec(`{"metric":{"dnn":"internet","direction":"uplink"},"value":[1,"1000"]}`,
				`{"metric":{"dnn":"internet","direction":"downlink"},"value":[1,"2000"]}`)
		case strings.Contains(q, "packet_drops_total"):
			return vec(`{"metric":{"reason":"no_route"},"value":[1,"3"]}`)
		default:
			return vec() // no series
		}
	})
	out := invoke(t, prom, "upf_stats", `{"dnn":"internet"}`)
	if got := out["pfcp_sessions_active"]; got != float64(2) {
		t.Errorf("pfcp_sessions_active = %v, want 2 (UPF series, not SMF)", got)
	}
	th := out["throughput_bps"].(map[string]any)["internet"].(map[string]any)
	if th["ul"] != float64(1000) || th["dl"] != float64(2000) {
		t.Errorf("throughput: %v", th)
	}
	if out["drops"].(map[string]any)["no_route"] != float64(3) {
		t.Errorf("drops: %v", out["drops"])
	}
	if out["packets_pps"] != nil || out["usage_reports"] != nil {
		t.Errorf("no-data fields must be null: %v %v", out["packets_pps"], out["usage_reports"])
	}
	un := out["unavailable"].(map[string]any)
	for _, k := range []string{"packets_pps", "usage_reports", "l4_checksum_repaired"} {
		if _, ok := un[k]; !ok {
			t.Errorf("missing unavailable reason for %s", k)
		}
	}
	if out["window"] != "5m0s" {
		t.Errorf("window: %v", out["window"])
	}
	if len(*queries) == 0 {
		t.Fatal("no query sent")
	}
	for _, q := range *queries {
		if !strings.Contains(q, `nf="UPF"`) {
			t.Errorf("query without nf=\"UPF\": %s", q)
		}
	}
	var sawWindow, sawDNN bool
	for _, q := range *queries {
		sawWindow = sawWindow || strings.Contains(q, "[5m]")
		sawDNN = sawDNN || strings.Contains(q, `dnn="internet"`)
	}
	if !sawWindow || !sawDNN {
		t.Errorf("window/dnn not applied: window=%v dnn=%v", sawWindow, sawDNN)
	}
}

func TestUPFStatsRejectsBadInput(t *testing.T) {
	prom, queries := upfProm(t, func(string) string { return vec() })
	for _, args := range []string{`{"window":"2h"}`, `{"window":"soon"}`, `{"dnn":"bad dnn!"}`} {
		for _, tool := range metricstools.All(prom) {
			if tool.Name() != "upf_stats" {
				continue
			}
			_, err := tool.Invoke(t.Context(), json.RawMessage(args))
			if err == nil || !strings.Contains(err.Error(), "-32602") {
				t.Errorf("%s: want -32602, got %v", args, err)
			}
		}
	}
	if len(*queries) != 0 {
		t.Errorf("rejected calls must not query Prometheus, got %d", len(*queries))
	}
}
