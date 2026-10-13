package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
)

// promFake answers query_range with n series of one point each and records the
// step the client asked for.
func promFake(t *testing.T, n int) (*promclient.Client, *string) {
	t.Helper()
	var gotStep string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotStep = r.URL.Query().Get("step")
		var series []string
		for i := 0; i < n; i++ {
			series = append(series, fmt.Sprintf(`{"metric":{"id":"%d"},"values":[[1,"1"]]}`, i))
		}
		_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":[%s]}}`,
			strings.Join(series, ","))
	}))
	t.Cleanup(srv.Close)
	return promclient.New(srv.URL, http.DefaultClient, 0), &gotStep
}

func TestRangeStepRaisedToPointLimit(t *testing.T) {
	prom, gotStep := promFake(t, 1)
	tool := metricQueryTool{prom}
	// A 7-day window needs at least ceil(604800/11000) = 55 s per point.
	out, err := tool.Invoke(context.Background(), json.RawMessage(
		`{"promql":"up","start":"2026-10-02T00:00:00Z","end":"2026-10-09T00:00:00Z","step":1}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	m := out.(map[string]any)
	if got := m["step_s"]; got != int64(55) {
		t.Errorf("step_s: got %v, want 55 (raised to stay under 11000 points)", got)
	}
	step, _ := strconv.Atoi(*gotStep)
	if points := 604800 / step; points > 11000 {
		t.Errorf("upstream step %d gives %d points, above 11000", step, points)
	}
}

func TestRangeRejectsWindowAboveSevenDays(t *testing.T) {
	prom, _ := promFake(t, 1)
	_, err := metricQueryTool{prom}.Invoke(context.Background(), json.RawMessage(
		`{"promql":"up","start":"2026-09-01T00:00:00Z","end":"2026-10-09T00:00:00Z"}`))
	if err == nil {
		t.Fatal("a window above 7 days must be refused")
	}
}

func TestMaxSeriesTruncatesAndFlags(t *testing.T) {
	prom, _ := promFake(t, 80)
	out, err := metricQueryTool{prom}.Invoke(context.Background(), json.RawMessage(
		`{"promql":"up","start":"2026-10-09T00:00:00Z","end":"2026-10-09T01:00:00Z"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	m := out.(map[string]any)
	rows := m["results"].([]rangeSeries)
	if len(rows) != 50 || m["truncated"] != true {
		t.Errorf("default cap: got %d rows, truncated=%v; want 50 and true", len(rows), m["truncated"])
	}
}

func TestMaxSeriesOutOfRangeIsInvalid(t *testing.T) {
	prom, _ := promFake(t, 1)
	for _, args := range []string{`{"promql":"up","max_series":-1}`, `{"promql":"up","max_series":501}`} {
		if _, err := (metricQueryTool{prom}).Invoke(context.Background(), json.RawMessage(args)); err == nil {
			t.Errorf("%s: want validation error", args)
		}
	}
}
