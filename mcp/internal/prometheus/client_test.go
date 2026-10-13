package prometheus

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func server(t *testing.T, status int, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, srv.Client(), time.Second)
}

func TestQueryInstantSuccess(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.Query().Get("query")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"nf":"AMF"},"value":[1,"3.5"]}]}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, srv.Client(), 0)
	res, err := c.Query(context.Background(), `up{nf="AMF"}`, time.Time{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if gotPath != "/api/v1/query" || gotQuery != `up{nf="AMF"}` {
		t.Errorf("request: %s %q", gotPath, gotQuery)
	}
	if len(res.Data.Result) != 1 || res.Data.Result[0].Float64() != 3.5 {
		t.Errorf("result: %+v", res)
	}
	if v, err := c.QueryScalar(context.Background(), "x"); err != nil || v != 3.5 {
		t.Errorf("scalar: %v %v", v, err)
	}
}

func TestQueryRangeSuccessAndStepRaise(t *testing.T) {
	var gotStep string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotStep = r.URL.Query().Get("step")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"nf":"AMF"},"values":[[1,"1"],[2,"2"]]}]}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, srv.Client(), 0)
	end := time.Now()
	series, step, err := c.QueryRange(context.Background(), "m", end.Add(-7*24*time.Hour), end, time.Second)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if len(series) != 1 || len(series[0].Values) != 2 {
		t.Errorf("series: %+v", series)
	}
	// 7d / 11000 points = 54.98s -> raised to 55s.
	if step != 55*time.Second || gotStep != "55" {
		t.Errorf("step = %v (sent %s), want 55s", step, gotStep)
	}
	if _, _, err := c.QueryRange(context.Background(), "m", end, end, time.Second); err == nil {
		t.Error("end == start must fail")
	}
}

func TestQueryHTTPError(t *testing.T) {
	c := server(t, http.StatusBadGateway, "upstream down")
	if _, err := c.Query(context.Background(), "up", time.Time{}); err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("query: want status 502 error, got %v", err)
	}
	if _, _, err := c.QueryRange(context.Background(), "up", time.Now().Add(-time.Hour), time.Now(), time.Minute); err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("range: want status 502 error, got %v", err)
	}
	if _, err := c.Alerts(context.Background()); err == nil {
		t.Error("alerts: want error")
	}
}

func TestQueryStatusErrorBody(t *testing.T) {
	// Prometheus answers 200 with status:"error" for some failures; a non-success
	// status must never be read as an empty result.
	c := server(t, http.StatusOK, `{"status":"error","errorType":"bad_data","error":"parse error"}`)
	if _, err := c.Query(context.Background(), "up", time.Time{}); err == nil {
		t.Error("query: want error for status=error")
	}
	if _, _, err := c.QueryRange(context.Background(), "up", time.Now().Add(-time.Hour), time.Now(), time.Minute); err == nil {
		t.Error("range: want error for status=error")
	}
	if _, err := c.QueryScalar(context.Background(), "up"); err == nil {
		t.Error("scalar: want error for status=error")
	}
}

func TestQueryMalformedBody(t *testing.T) {
	c := server(t, http.StatusOK, `not json`)
	if _, err := c.Query(context.Background(), "up", time.Time{}); err == nil {
		t.Error("want decode error")
	}
}

func TestQueryUnreachable(t *testing.T) {
	c := New("http://127.0.0.1:9", nil, 200*time.Millisecond)
	if _, err := c.Query(context.Background(), "up", time.Time{}); err == nil {
		t.Error("want connection error")
	}
}

func TestNaNSampleHandling(t *testing.T) {
	c := server(t, http.StatusOK, `{"status":"success","data":{"resultType":"vector","result":[
	  {"metric":{},"value":[1,"NaN"]},{"metric":{},"value":[1,"+Inf"]},{"metric":{},"value":[1,"oops"]}]}}`)
	res, err := c.Query(context.Background(), "x", time.Time{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if v := res.Data.Result[0].Float64(); !math.IsNaN(v) {
		t.Errorf("NaN sample = %v, want NaN", v)
	}
	if v := res.Data.Result[1].Float64(); !math.IsInf(v, 1) {
		t.Errorf("+Inf sample = %v, want +Inf", v)
	}
	if v := res.Data.Result[2].Float64(); !math.IsNaN(v) {
		t.Errorf("unparsable sample = %v, want NaN (never 0)", v)
	}
}

func TestQueryScalarEmptyVector(t *testing.T) {
	c := server(t, http.StatusOK, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	v, err := c.QueryScalar(context.Background(), "x")
	if err != nil || v != 0 {
		t.Errorf("empty vector: got (%v, %v), want (0, nil)", v, err)
	}
}
