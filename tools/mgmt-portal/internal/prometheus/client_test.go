package prometheus

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const matrixBody = `{
  "status": "success",
  "data": {
    "resultType": "matrix",
    "result": [
      {"metric": {"__name__": "fivegc_ue_registered", "nf": "AMF"},
       "values": [[1758000000, "3"], [1758000010, "4.5"]]}
    ]
  }
}`

// TestQueryRange_Success pins the HTTP contract: the path, the query/start/end
// parameters (Unix seconds) and the step duration, plus the matrix decode.
func TestQueryRange_Success(t *testing.T) {
	var gotPath string
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, matrixBody)
	}))
	defer srv.Close()

	expr := `sum(rate(fivegc_procedure_total{nf="AMF"}[5m]))`
	start := time.Unix(1758000000, 0)
	end := time.Unix(1758000100, 0)

	series, err := New(srv.URL).QueryRange(context.Background(), expr, start, end, 30)
	if err != nil {
		t.Fatalf("QueryRange: %v", err)
	}

	if gotPath != "/api/v1/query_range" {
		t.Errorf("path = %q, want /api/v1/query_range", gotPath)
	}
	if got := gotQuery.Get("query"); got != expr {
		t.Errorf("query = %q, want %q", got, expr)
	}
	if got := gotQuery.Get("start"); got != "1758000000" {
		t.Errorf("start = %q, want 1758000000", got)
	}
	if got := gotQuery.Get("end"); got != "1758000100" {
		t.Errorf("end = %q, want 1758000100", got)
	}
	if got := gotQuery.Get("step"); got != "30s" {
		t.Errorf("step = %q, want 30s", got)
	}

	if len(series) != 1 {
		t.Fatalf("series len = %d, want 1", len(series))
	}
	if series[0].Metric["nf"] != "AMF" || series[0].Metric["__name__"] != "fivegc_ue_registered" {
		t.Errorf("metric labels = %v", series[0].Metric)
	}
	if len(series[0].Values) != 2 {
		t.Fatalf("values len = %d, want 2", len(series[0].Values))
	}
	if ts, ok := series[0].Values[0][0].(float64); !ok || ts != 1758000000 {
		t.Errorf("values[0][0] = %v (%T), want 1758000000", series[0].Values[0][0], series[0].Values[0][0])
	}
	if v, ok := series[0].Values[1][1].(string); !ok || v != "4.5" {
		t.Errorf("values[1][1] = %v (%T), want \"4.5\"", series[0].Values[1][1], series[0].Values[1][1])
	}
}

// TestQueryRange_HTTPError: a non-200 from Prometheus is an error (the instant
// Query call deliberately does not need this because Summary ignores failures).
func TestQueryRange_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"status":"error","errorType":"bad_data","error":"invalid parameter \"step\""}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := New(srv.URL).QueryRange(context.Background(), "up", time.Unix(0, 0), time.Unix(60, 0), 15)
	if err == nil {
		t.Fatal("want error on HTTP 400, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error %q does not mention status 400", err)
	}
}

// TestQueryRange_DecodeError: a 200 with a non-JSON body is an error.
func TestQueryRange_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "not json")
	}))
	defer srv.Close()

	if _, err := New(srv.URL).QueryRange(context.Background(), "up", time.Unix(0, 0), time.Unix(60, 0), 15); err == nil {
		t.Fatal("want decode error, got nil")
	}
}

// TestQueryRange_EmptyResult: an empty matrix decodes to no series, not an error.
func TestQueryRange_EmptyResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
	}))
	defer srv.Close()

	series, err := New(srv.URL).QueryRange(context.Background(), "up", time.Unix(0, 0), time.Unix(60, 0), 15)
	if err != nil {
		t.Fatalf("QueryRange: %v", err)
	}
	if len(series) != 0 {
		t.Errorf("series len = %d, want 0", len(series))
	}
}

// instantVector renders a Prometheus instant-query success response with one
// scalar sample.
func instantVector(value string) string {
	return `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1758000000,"` + value + `"]}]}}`
}

// TestSummary_SuccessRatesAndFallback pins PORTAL-UI-21: the two instant
// success-rate KPIs parse as *float64 (a numeric Prometheus sample → pointer),
// the expressions carry the fixed [5m] window and the OK selector, and the
// stale PDU-session fallback now sums fivegc_pdu_sessions_active.
func TestSummary_SuccessRatesAndFallback(t *testing.T) {
	var pduFallbackExpr, regExpr, pduExpr string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(q, "up{instance="):
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
		case q == "sum(fivegc_ue_registered)":
			_, _ = io.WriteString(w, instantVector("5"))
		case q == "sum(fivegc_pdu_sessions_active) or vector(0)":
			pduFallbackExpr = q
			_, _ = io.WriteString(w, instantVector("3"))
		case strings.Contains(q, "InitialRegistration"):
			regExpr = q
			_, _ = io.WriteString(w, instantVector("87.5"))
		case strings.Contains(q, "fivegc_pdu_session_total"):
			pduExpr = q
			_, _ = io.WriteString(w, instantVector("NaN"))
		default:
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
		}
	}))
	defer srv.Close()

	s := New(srv.URL).Summary(context.Background())

	if s.PDUSessions != 3 {
		t.Errorf("PDUSessions = %d, want 3 (fallback must sum fivegc_pdu_sessions_active)", s.PDUSessions)
	}
	if pduFallbackExpr == "" {
		t.Error("the corrected PDU-session fallback expression was never queried")
	}
	if s.RegistrationSuccessPct == nil {
		t.Fatal("RegistrationSuccessPct = nil, want 87.5")
	}
	if *s.RegistrationSuccessPct != 87.5 {
		t.Errorf("RegistrationSuccessPct = %v, want 87.5", *s.RegistrationSuccessPct)
	}
	// A NaN ratio is "no data", not 0 — it must be nil so the UI shows "—".
	if s.PDUSessionEstablishmentPct != nil {
		t.Errorf("PDUSessionEstablishmentPct = %v, want nil for a NaN sample", *s.PDUSessionEstablishmentPct)
	}

	for _, want := range []string{"[5m]", `result="OK"`, `procedure="InitialRegistration"`, `nf="AMF"`} {
		if !strings.Contains(regExpr, want) {
			t.Errorf("registration expression missing %q: %q", want, regExpr)
		}
	}
	for _, want := range []string{"fivegc_pdu_session_total", `result="OK"`, "[5m]"} {
		if !strings.Contains(pduExpr, want) {
			t.Errorf("PDU-session expression missing %q: %q", want, pduExpr)
		}
	}
}

// TestSummary_SuccessRatesEmptyAreNil: when Prometheus returns an empty vector
// (metric never emitted) both instant KPIs are nil — the "—" card, never a
// fabricated 0%/100% (PORTAL-UI-21).
func TestSummary_SuccessRatesEmptyAreNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer srv.Close()

	s := New(srv.URL).Summary(context.Background())

	if s.RegistrationSuccessPct != nil {
		t.Errorf("RegistrationSuccessPct = %v, want nil on an empty result", *s.RegistrationSuccessPct)
	}
	if s.PDUSessionEstablishmentPct != nil {
		t.Errorf("PDUSessionEstablishmentPct = %v, want nil on an empty result", *s.PDUSessionEstablishmentPct)
	}
}
