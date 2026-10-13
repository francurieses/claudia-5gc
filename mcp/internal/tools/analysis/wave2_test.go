package analysis

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
)

func jsonServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func vector(rows ...string) string {
	return `{"status":"success","data":{"resultType":"vector","result":[` + strings.Join(rows, ",") + `]}}`
}

// consistencyDeps builds Deps over mocks. upf is the UPF gauge value ("" = no series).
func consistencyDeps(t *testing.T, amf, smf, upf string) (Deps, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var queries []string
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		mu.Lock()
		queries = append(queries, q)
		mu.Unlock()
		switch {
		case strings.Contains(q, "fivegc_upf_pfcp_sessions_active"):
			if upf == "" {
				_, _ = w.Write([]byte(vector()))
				return
			}
			_, _ = w.Write([]byte(vector(`{"metric":{"nf":"SMF"},"value":[1,"0"]}`, `{"metric":{"nf":"UPF"},"value":[1,"`+upf+`"]}`)))
		case strings.HasPrefix(q, "fivegc_bsf_bindings_active"):
			_, _ = w.Write([]byte(vector(`{"metric":{"nf":"BSF"},"value":[1,"2"]}`)))
		case strings.Contains(q, "fivegc_nf_instances_registered"):
			_, _ = w.Write([]byte(vector(`{"metric":{"nf":"NRF","nf_type":"AMF"},"value":[1,"1"]}`, `{"metric":{"nf":"NRF","nf_type":"SMF"},"value":[1,"1"]}`)))
		case strings.HasPrefix(q, "up{"):
			_, _ = w.Write([]byte(vector(
				`{"metric":{"nf":"AMF","instance":"amf:9101"},"value":[1,"1"]}`,
				`{"metric":{"nf":"SMF","instance":"smf:9105"},"value":[1,"1"]}`,
				`{"metric":{"nf":"UPF","instance":"upf:9107"},"value":[1,"1"]}`)))
		default:
			_, _ = w.Write([]byte(vector()))
		}
	}))
	t.Cleanup(prom.Close)
	pc := promclient.New(prom.URL, prom.Client(), 0)
	return Deps{
		AMF:  clients.NewAMF(jsonServer(t, amf).URL, http.DefaultClient),
		SMF:  clients.NewSMF(jsonServer(t, smf).URL, http.DefaultClient),
		Prom: pc,
	}, &queries
}

func smfBody(pairs ...string) string {
	var ss []string
	for i := 0; i+1 < len(pairs); i += 2 {
		ss = append(ss, `{"supi":"`+pairs[i]+`","pduSessionId":`+pairs[i+1]+`,"sessionState":"ACTIVE"}`)
	}
	return `{"count":` + string(rune('0'+len(ss))) + `,"sessions":[` + strings.Join(ss, ",") + `]}`
}

func TestConsistency(t *testing.T) {
	const u1, u2 = "imsi-001010000000001", "imsi-001010000000002"
	two := `[{"supi":"` + u1 + `","gmm_state":"5GMM-REGISTERED","pdu_session_ids":"AQ=="},{"supi":"` + u2 + `","pdu_session_ids":"AQ=="}]`
	tests := []struct {
		name, amf, smf, upf string
		wantErrChecks       []string
		wantNoError         bool
		wantAMFPSIs         int
	}{
		{"clean", two, smfBody(u1, "1", u2, "1"), "2", nil, true, 2},
		{"int array psi", `[{"supi":"` + u1 + `","pdu_session_ids":[1]}]`, smfBody(u1, "1"), "1", nil, true, 1},
		{"smf session without amf ue", `[{"supi":"` + u1 + `","pdu_session_ids":[1]}]`,
			smfBody(u1, "1", "imsi-001010000000077", "1"), "2", []string{"smf_session_without_amf_ue"}, false, 1},
		{"smf session psi not in amf ue", `[{"supi":"` + u1 + `","pdu_session_ids":[1]}]`,
			smfBody(u1, "1", u1, "2"), "2", []string{"smf_session_without_amf_psi"}, false, 1},
		{"amf ue without pdu_session_ids field skips psi check", `[{"supi":"` + u1 + `"}]`,
			smfBody(u1, "1"), "1", nil, true, 0},
		{"smf 2 vs upf 1", two, smfBody(u1, "1", u2, "1"), "1", []string{"smf_upf_session_count"}, false, 2},
		{"amf psi without smf session", `[{"supi":"` + u1 + `","pdu_session_ids":[1]}]`, smfBody(), "0",
			[]string{"amf_psi_without_smf_session"}, false, 1},
		{"deregistered ue holds no psi check", `[{"supi":"` + u1 + `","gmm_state":"5GMM-DEREGISTERED","pdu_session_ids":[1]}]`, smfBody(), "0",
			nil, true, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, queries := consistencyDeps(t, tc.amf, tc.smf, tc.upf)
			out, err := consistencyTool{d}.Invoke(context.Background(), json.RawMessage(`{}`))
			if err != nil {
				t.Fatalf("invoke: %v", err)
			}
			m := out.(map[string]any)
			fs := m["findings"].([]finding)
			errs := map[string]finding{}
			for _, f := range fs {
				if f.SpecRef == "" || f.Detail == "" {
					t.Errorf("finding without detail/spec_ref: %+v", f)
				}
				if f.Severity == sevError {
					errs[f.Check] = f
				}
			}
			if tc.wantNoError && len(errs) != 0 {
				t.Errorf("unexpected errors: %+v", errs)
			}
			for _, c := range tc.wantErrChecks {
				if _, ok := errs[c]; !ok {
					t.Errorf("missing error finding %s in %+v", c, fs)
				}
			}
			if got := m["counts"].(map[string]any)["amf_psis"]; got != tc.wantAMFPSIs {
				t.Errorf("amf_psis = %v, want %d", got, tc.wantAMFPSIs)
			}
			for _, q := range *queries {
				if !strings.Contains(q, `nf=`) {
					t.Errorf("query without nf filter: %s", q)
				}
			}
		})
	}
}

func TestConsistencyCountsAndNRF(t *testing.T) {
	const u1 = "imsi-001010000000001"
	d, _ := consistencyDeps(t, `[{"supi":"`+u1+`","pdu_session_ids":[1]}]`, smfBody(u1, "1"), "1")
	out, _ := consistencyTool{d}.Invoke(context.Background(), nil)
	m := out.(map[string]any)
	c := m["counts"].(map[string]any)
	if c["smf_sessions"] != 1 || c["upf_pfcp_sessions"] != 1 || c["bsf_bindings"] != 2 || c["nrf_instances"] != 2 || c["scrape_targets"] != 3 {
		t.Errorf("counts: %v", c)
	}
	// UPF target is exempt from NRF registration; AMF and SMF are registered: no findings.
	if fs := m["findings"].([]finding); len(fs) != 0 {
		t.Errorf("clean stack must have no findings: %+v", fs)
	}
}

func TestConsistencyUpstreamDownIsWarningNotError(t *testing.T) {
	d, _ := consistencyDeps(t, `[]`, smfBody(), "0")
	d.AMF = clients.NewAMF(deadURL(t), http.DefaultClient)
	out, err := consistencyTool{d}.Invoke(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	var saw bool
	for _, f := range m["findings"].([]finding) {
		if f.Severity == sevError {
			t.Errorf("no error may come from missing data: %+v", f)
		}
		saw = saw || f.Check == "amf_unreachable"
	}
	if !saw {
		t.Error("want amf_unreachable warning")
	}
	if m["counts"].(map[string]any)["amf_ues"] != nil {
		t.Error("unread count must be null")
	}
}

func TestErrorSummary(t *testing.T) {
	var mu sync.Mutex
	var metricQueries, rangeQueries []string
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/loki/api/v1/query":
			metricQueries = append(metricQueries, r.URL.Query().Get("query"))
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			 {"metric":{"nf":"AMF","procedure":"InitialRegistration","result":"REJECT","cause":"22","spec_ref":"TS 23.502 §4.2.2.2.2"},"value":[1,"3"]},
			 {"metric":{"nf":"SMF","procedure":"PduSessionEstablishment","result":"FAILURE","cause":"N4 timeout","spec_ref":"TS 23.502 §4.3.2.2.1"},"value":[1,"7"]}]}}`))
		case "/loki/api/v1/query_range":
			q := r.URL.Query().Get("query")
			rangeQueries = append(rangeQueries, q)
			if strings.Contains(q, `"SMF"`) {
				_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"nf":"SMF"},"values":[["1700000000000000000","{\"correlation_id\":\"01J0XYZ\"}"]]}]}}`))
				return
			}
			http.Error(w, "boom", http.StatusInternalServerError) // best effort: AMF example fails
		}
	}))
	defer loki.Close()
	tool := errorSummaryTool{Deps{Loki: clients.NewLoki(loki.URL, http.DefaultClient)}}

	out, err := tool.Invoke(context.Background(), json.RawMessage(`{"top":5}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	rows := out.(map[string]any)["rows"].([]errorRow)
	if len(rows) != 2 || rows[0].NF != "SMF" || rows[0].Count != 7 || rows[1].NF != "AMF" {
		t.Fatalf("rows not ordered by count desc: %+v", rows)
	}
	if rows[0].Example != "01J0XYZ" || rows[0].LastSeen == "" {
		t.Errorf("example not filled: %+v", rows[0])
	}
	if rows[1].Example != "" || rows[1].LastSeen != "" {
		t.Errorf("failed example lookup must leave fields empty: %+v", rows[1])
	}
	if len(metricQueries) != 1 || !strings.Contains(metricQueries[0], "count_over_time") ||
		!strings.Contains(metricQueries[0], "[15m]") || !strings.Contains(metricQueries[0], `{nf=~".+"}`) {
		t.Errorf("metric query: %v", metricQueries)
	}
	if len(rangeQueries) != 2 {
		t.Errorf("want one example query per row, got %d", len(rangeQueries))
	}

	// top cuts the rows; nf narrows the selector.
	metricQueries = nil
	out, err = tool.Invoke(context.Background(), json.RawMessage(`{"top":1,"nf":"SMF","window":"1h"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := out.(map[string]any)["rows"].([]errorRow); len(got) != 1 {
		t.Errorf("top=1: %d rows", len(got))
	}
	if !strings.Contains(metricQueries[0], `{nf="SMF"}`) || !strings.Contains(metricQueries[0], "[1h]") {
		t.Errorf("nf/window not applied: %s", metricQueries[0])
	}
}

func TestErrorSummaryRejectsBadInput(t *testing.T) {
	tool := errorSummaryTool{Deps{Loki: clients.NewLoki(deadURL(t), http.DefaultClient)}}
	for _, args := range []string{`{"window":"2h"}`, `{"top":0}`, `{"top":51}`, `{"nf":"amf"}`, `{"nf":"AMF\"}"}`} {
		_, err := tool.Invoke(context.Background(), json.RawMessage(args))
		if err == nil || code(t, err) != -32602 {
			t.Errorf("%s: want -32602, got %v", args, err)
		}
	}
}

func TestLogRange(t *testing.T) {
	for d, want := range map[time.Duration]string{15 * time.Minute: "15m", time.Hour: "1h", 90 * time.Second: "90s"} {
		if got := logRange(d); got != want {
			t.Errorf("logRange(%s) = %s, want %s", d, got, want)
		}
	}
}

func TestConsistencyTransitionDowngradesSessionCount(t *testing.T) {
	const u1 = "imsi-001010000000001"
	smf := `{"count":2,"sessions":[{"supi":"` + u1 + `","pduSessionId":1,"sessionState":"ACTIVE"},{"supi":"` + u1 + `","pduSessionId":2,"sessionState":"INACTIVE"}]}`
	d, _ := consistencyDeps(t, `[{"supi":"`+u1+`","pdu_session_ids":[1,2]}]`, smf, "0")
	out, err := consistencyTool{d}.Invoke(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	var got *finding
	for _, f := range m["findings"].([]finding) {
		if f.Check == "smf_upf_session_count" {
			f := f
			got = &f
		}
	}
	if got == nil || got.Severity != sevWarning || !strings.Contains(got.Detail, "transition") {
		t.Errorf("want warning in transition, got %+v", got)
	}
	if c := m["counts"].(map[string]any); c["smf_sessions"] != 2 || c["smf_sessions_active"] != 1 {
		t.Errorf("counts: %v", c)
	}
}
