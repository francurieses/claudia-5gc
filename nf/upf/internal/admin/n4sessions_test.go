package admin

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

type fakeSrc struct {
	calls int
	last  pfcp.DescribeFilter
	out   []pfcp.SessionDescription
}

func (f *fakeSrc) Describe(df pfcp.DescribeFilter) []pfcp.SessionDescription {
	f.calls++
	f.last = df
	return f.out
}

func do(t *testing.T, src *fakeSrc, method, target string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil)).With("nf", "UPF")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("X-Correlation-Id", "01HZZZZZZZZZZZZZZZZZZZZZZZ")
	NewN4SessionsHandler(src, log).ServeHTTP(rec, req)
	return rec, buf.String()
}

func TestN4SessionsOK(t *testing.T) {
	src := &fakeSrc{out: []pfcp.SessionDescription{{CPSEID: 9, UPSEID: 9}}}
	rec, logs := do(t, src, http.MethodGet, "/admin/v1/n4-sessions?seid=9")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	var body struct {
		Count    int               `json:"count"`
		Sessions []json.RawMessage `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Count != 1 || len(body.Sessions) != 1 {
		t.Fatalf("body %s err %v", rec.Body, err)
	}
	for _, want := range []string{`"procedure":"N4SessionInspection"`, `"interface":"OAM"`, `"direction":"IN"`,
		`"spec_ref":"TS 29.244 §5.2"`, `"result":"OK"`, `"count":1`, `"seid":"9"`,
		`"correlation_id":"01HZZZZZZZZZZZZZZZZZZZZZZZ"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("log missing %s: %s", want, logs)
		}
	}
	if strings.Count(logs, `"nf"`) != 1 {
		t.Errorf("nf key count: %s", logs)
	}
}

func TestN4SessionsEmptyIsArray(t *testing.T) {
	rec, _ := do(t, &fakeSrc{}, http.MethodGet, "/admin/v1/n4-sessions")
	if got := strings.TrimSpace(rec.Body.String()); got != `{"count":0,"sessions":[]}` {
		t.Fatalf("body %s", got)
	}
}

func TestN4SessionsSEIDParsing(t *testing.T) {
	ok := map[string]uint64{"9": 9, "0x9": 9, "0X9": 9, "010": 10, "0": 0, "0xffff": 0xffff,
		"18446744073709551615": 18446744073709551615}
	for in, want := range ok {
		src := &fakeSrc{}
		rec, _ := do(t, src, http.MethodGet, "/admin/v1/n4-sessions?seid="+in)
		if rec.Code != 200 || src.last.SEID != want {
			t.Errorf("seid %q: code %d seid %d", in, rec.Code, src.last.SEID)
		}
	}
	for _, in := range []string{"xyz", "-1", "0xZZ", "0x", "0o7", "0b1", "1.5", "+5",
		"18446744073709551616", "0x10000000000000000"} {
		src := &fakeSrc{}
		rec, logs := do(t, src, http.MethodGet, "/admin/v1/n4-sessions?seid="+in)
		if rec.Code != 400 || src.calls != 0 {
			t.Errorf("seid %q: code %d calls %d", in, rec.Code, src.calls)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("content-type %q", ct)
		}
		var pd problemDetails
		_ = json.Unmarshal(rec.Body.Bytes(), &pd)
		if pd.Cause != "INVALID_QUERY_PARAM" || len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != "seid" || pd.Status != 400 {
			t.Errorf("problem %+v", pd)
		}
		if !strings.Contains(logs, `"result":"REJECT"`) || !strings.Contains(logs, `"cause":"INVALID_QUERY_PARAM"`) {
			t.Errorf("log %s", logs)
		}
	}
}

func TestN4SessionsUEIP(t *testing.T) {
	src := &fakeSrc{}
	if rec, _ := do(t, src, http.MethodGet, "/admin/v1/n4-sessions?ue_ip=10.60.0.8"); rec.Code != 200 || src.last.UEIP.String() != "10.60.0.8" {
		t.Fatalf("v4: %d %v", rec.Code, src.last.UEIP)
	}
	if rec, _ := do(t, src, http.MethodGet, "/admin/v1/n4-sessions?ue_ip=2001:db8:60:1::1"); rec.Code != 200 {
		t.Fatalf("v6: %d", rec.Code)
	}
	for _, in := range []string{"not-an-ip", "10.60.0", "10.60.0.256", "2001:db8::zz", "10.60.0.0/24"} {
		s := &fakeSrc{}
		rec, _ := do(t, s, http.MethodGet, "/admin/v1/n4-sessions?ue_ip="+strings.ReplaceAll(in, "/", "%2F"))
		var pd problemDetails
		_ = json.Unmarshal(rec.Body.Bytes(), &pd)
		if rec.Code != 400 || s.calls != 0 || pd.InvalidParams[0].Param != "ue_ip" {
			t.Errorf("ue_ip %q: %d calls %d", in, rec.Code, s.calls)
		}
	}
}

func TestN4SessionsMethodNotAllowed(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "HEAD"} {
		src := &fakeSrc{}
		rec, _ := do(t, src, m, "/admin/v1/n4-sessions")
		if rec.Code != 405 || rec.Header().Get("Allow") != "GET" || src.calls != 0 {
			t.Errorf("%s: %d %q calls %d", m, rec.Code, rec.Header().Get("Allow"), src.calls)
		}
	}
}

func procCount(result string) float64 {
	return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("UPF", "N4SessionInspection", result))
}

func TestN4SessionsProcedureTotal(t *testing.T) {
	src := &fakeSrc{}
	ok0, rej0 := procCount("OK"), procCount("REJECT")

	do(t, src, http.MethodGet, "/admin/v1/n4-sessions")
	if got := procCount("OK") - ok0; got != 1 {
		t.Fatalf("OK delta = %v, want 1", got)
	}
	do(t, src, http.MethodGet, "/admin/v1/n4-sessions?seid=zzz")
	do(t, src, http.MethodGet, "/admin/v1/n4-sessions?ue_ip=nope")
	do(t, src, http.MethodPost, "/admin/v1/n4-sessions")
	if got := procCount("REJECT") - rej0; got != 3 {
		t.Fatalf("REJECT delta = %v, want 3", got)
	}
	if got := procCount("OK") - ok0; got != 1 {
		t.Fatalf("OK delta after rejects = %v, want 1", got)
	}
}
