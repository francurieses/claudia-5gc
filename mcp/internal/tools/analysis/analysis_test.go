package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
)

// deadServer is an address nothing listens on, so a call fails fast.
func deadURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	return u
}

func code(t *testing.T, err error) int {
	t.Helper()
	var e *mcperr.Error
	if !errors.As(err, &e) {
		t.Fatalf("want *mcperr.Error, got %T %v", err, err)
	}
	return e.Code
}

func TestLogQueryRejectsWindowAboveOneHour(t *testing.T) {
	d := Deps{Loki: clients.NewLoki(deadURL(t), http.DefaultClient)}
	_, err := logQueryTool{d}.Invoke(context.Background(), json.RawMessage(`{"query":"{nf=\"AMF\"}","window":"2h"}`))
	if code(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("window 2h: want -32602")
	}
}

func TestLogQueryRejectsLimitAboveCap(t *testing.T) {
	d := Deps{Loki: clients.NewLoki(deadURL(t), http.DefaultClient)}
	_, err := logQueryTool{d}.Invoke(context.Background(), json.RawMessage(`{"query":"{nf=\"AMF\"}","limit":501}`))
	if code(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("limit 501: want -32602")
	}
}

func TestParseWindowBoundaries(t *testing.T) {
	cases := map[string]bool{"": true, "15m": true, "1h": true, "61m": false, "0s": false, "-5m": false, "soon": false}
	for in, ok := range cases {
		_, perr := parseWindow(in, 15*time.Minute, time.Hour)
		if (perr == nil) != ok {
			t.Errorf("window %q: ok=%v, want %v", in, perr == nil, ok)
		}
	}
}

// TestProcedureTimelineOrdersAndFlagsFirstFailure feeds three log lines for one
// correlation id, one of them out of order, and a REJECT in the middle.
func TestProcedureTimelineOrdersAndFlagsFirstFailure(t *testing.T) {
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[
		 {"stream":{"nf":"AMF"},"values":[
		   ["3000000000","{\"nf\":\"AMF\",\"procedure\":\"InitialRegistration\",\"correlation_id\":\"01J0ABC\",\"result\":\"OK\",\"msg\":\"accept\"}"],
		   ["1000000000","{\"nf\":\"AMF\",\"procedure\":\"InitialRegistration\",\"correlation_id\":\"01J0ABC\",\"result\":\"\",\"msg\":\"start\"}"],
		   ["2000000000","{\"nf\":\"AMF\",\"procedure\":\"InitialRegistration\",\"correlation_id\":\"01J0ABC\",\"result\":\"REJECT\",\"spec_ref\":\"TS 24.501 §5.5.1.2.5\",\"msg\":\"reject\"}"],
		   ["2500000000","{\"nf\":\"AMF\",\"correlation_id\":\"OTHER\",\"result\":\"FAILURE\"}"]
		 ]}]}}`))
	}))
	defer loki.Close()
	obs := clients.NewObs(deadURL(t), deadURL(t), http.DefaultClient)
	tool := procedureTimelineTool{Deps{Loki: clients.NewLoki(loki.URL, http.DefaultClient), Obs: obs}}
	out, err := tool.Invoke(context.Background(), json.RawMessage(`{"correlation_id":"01J0ABC"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	m := out.(map[string]any)
	entries := m["entries"].([]timelineEntry)
	if len(entries) != 3 {
		t.Fatalf("want 3 entries for 01J0ABC (OTHER excluded), got %d", len(entries))
	}
	for i, want := range []string{"start", "reject", "accept"} {
		if entries[i].Msg != want {
			t.Errorf("entry %d: got %q, want %q (ordered by time)", i, entries[i].Msg, want)
		}
	}
	ff, ok := m["first_failure"].(*timelineEntry)
	if !ok || ff == nil {
		t.Fatalf("first_failure missing: %+v", m["first_failure"])
	}
	if ff.Msg != "reject" || ff.Spec != "TS 24.501 §5.5.1.2.5" {
		t.Errorf("first failure: %+v, want the REJECT with its spec_ref", ff)
	}
}

func TestProcedureTimelineNeedsExactlyOneKey(t *testing.T) {
	tool := procedureTimelineTool{Deps{}}
	for _, args := range []string{`{}`, `{"correlation_id":"x","supi":"imsi-001010000000001"}`} {
		if _, err := tool.Invoke(context.Background(), json.RawMessage(args)); code(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("%s: want -32602", args)
		}
	}
}

func TestProcedureTimelineRejectsInjectionInID(t *testing.T) {
	tool := procedureTimelineTool{Deps{}}
	_, err := tool.Invoke(context.Background(), json.RawMessage(`{"correlation_id":"x\"} |= \"y"}`))
	if code(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("a correlation id with LogQL metacharacters must be rejected")
	}
}

// TestUEDiagnoseKeepsPartialResults: the PCF is down, everything else answers.
// The CM-IDLE session produces the QoS-modification finding, and the PCF failure
// is listed in errors, not hidden.
func TestUEDiagnoseKeepsPartialResults(t *testing.T) {
	amf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"supi":"imsi-001010000000001","gmm_state":"REGISTERED","cm_state":"IDLE","guti":"g"}`))
	}))
	defer amf.Close()
	smf := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"supi":"imsi-001010000000001","pduSessionId":1,"dnn":"internet"}]`))
	}))
	defer smf.Close()
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[]}}`))
	}))
	defer loki.Close()

	d := Deps{
		AMF:  clients.NewAMF(amf.URL, http.DefaultClient),
		SMF:  clients.NewSMF(smf.URL, smf.Client()),
		PCF:  clients.NewPCF(deadURL(t), http.DefaultClient),
		UDM:  clients.NewUDM(deadURL(t), http.DefaultClient),
		Loki: clients.NewLoki(loki.URL, http.DefaultClient),
	}
	out, err := ueDiagnoseTool{d}.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	raw, _ := json.Marshal(out)
	s := string(raw)
	if !strings.Contains(s, "UE is CM-IDLE: this AMF does not page") {
		t.Errorf("missing CM-IDLE finding: %s", s)
	}
	if !strings.Contains(s, `"source":"pcf"`) {
		t.Errorf("PCF failure must be listed in errors: %s", s)
	}
	if !strings.Contains(s, `"gmm_state":"REGISTERED"`) {
		t.Errorf("AMF result lost: %s", s)
	}
}

// TestUEDiagnoseNoOverrideIsNotAFinding guards the typed-nil bug: an absent PCF
// override must not produce an "override is set" finding.
func TestUEDiagnoseNoOverrideIsNotAFinding(t *testing.T) {
	amf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"supi":"imsi-001010000000001","gmm_state":"REGISTERED","cm_state":"CONNECTED"}`))
	}))
	defer amf.Close()
	pcf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer pcf.Close()
	d := Deps{
		AMF:  clients.NewAMF(amf.URL, http.DefaultClient),
		SMF:  clients.NewSMF(deadURL(t), http.DefaultClient),
		PCF:  clients.NewPCF(pcf.URL, http.DefaultClient),
		UDM:  clients.NewUDM(deadURL(t), http.DefaultClient),
		Loki: clients.NewLoki(deadURL(t), http.DefaultClient),
	}
	out, _ := ueDiagnoseTool{d}.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "QoS override is set") {
		t.Errorf("no override must not be reported: %s", raw)
	}
}

func TestProcedureStatsBuildsQueryAndRates(t *testing.T) {
	var gotQuery string
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
		 {"metric":{"nf":"AMF","procedure":"InitialRegistration","result":"OK"},"value":[1,"9"]},
		 {"metric":{"nf":"AMF","procedure":"InitialRegistration","result":"REJECT"},"value":[1,"1"]}]}}`))
	}))
	defer prom.Close()
	d := Deps{Prom: promclient.New(prom.URL, http.DefaultClient, 0)}
	out, err := procedureStatsTool{d}.Invoke(context.Background(), json.RawMessage(`{"nf":"AMF","window":"1h"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !strings.Contains(gotQuery, `fivegc_procedure_total{nf="AMF"}[3600s]`) {
		t.Errorf("query: %s", gotQuery)
	}
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), `"success_pct":90`) {
		t.Errorf("success pct: %s", raw)
	}
}

func TestProcedureStatsRejectsBadLabels(t *testing.T) {
	d := Deps{}
	if _, err := (procedureStatsTool{d}).Invoke(context.Background(), json.RawMessage(`{"nf":"AMF}or{x=\"y"}`)); code(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("label injection must be rejected")
	}
}

func TestProcedureSummaryAliasRefusesRawQuery(t *testing.T) {
	_, err := mapSummaryLegacy(json.RawMessage(`{"query":"up"}`))
	if code(t, err) != mcperr.CodeInvalidParams || !strings.Contains(err.Error(), "metric_query") {
		t.Errorf("raw query must point to metric_query: %v", err)
	}
	if _, err := mapSummaryLegacy(json.RawMessage(`{"metric":"fivegc_procedure_total"}`)); err != nil {
		t.Errorf("procedure metric must map: %v", err)
	}
}

func TestPCAPControlRejectsUnknownAction(t *testing.T) {
	_, err := pcapControlTool{Deps{}}.Invoke(context.Background(), json.RawMessage(`{"nf":"AMF","action":"wipe"}`))
	if code(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("unknown action must be rejected")
	}
}

func TestPCAPControlIsMutating(t *testing.T) {
	if (pcapControlTool{}).Risk() == 0 {
		t.Error("pcap_control changes capture state and must not be read-only")
	}
}

// TestPCAPNFIsLowerCasedForPortal: the portal keys sidecars in lower case, so the
// tool must send /pcap/amf/rotate for "AMF" (a live run found the upper-case path refused).
func TestPCAPNFIsLowerCasedForPortal(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Method + " " + r.URL.Path
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	tool := pcapControlTool{Deps{Portal: clients.NewPortal(srv.URL, http.DefaultClient)}}
	if _, err := tool.Invoke(context.Background(), json.RawMessage(`{"nf":"AMF","action":"rotate"}`)); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if got != "POST /api/v1/pcap/amf/rotate" {
		t.Errorf("portal path: %s", got)
	}
}

// TestRegisteredStateAcceptsAMFNames: the AMF reports 5GMM-REGISTERED; a live run
// flagged a registered UE as "not REGISTERED" before this was normalised.
func TestRegisteredStateAcceptsAMFNames(t *testing.T) {
	for state, want := range map[string]bool{"5GMM-REGISTERED": true, "REGISTERED": true,
		"5GMM-DEREGISTERED": false, "5GMM-DEREGISTERED-INITIATED": false, "": false} {
		if got := registeredState(state); got != want {
			t.Errorf("%q: got %v, want %v", state, got, want)
		}
	}
}

// diagnoseDeps wires ue_diagnose to a mock AMF (cm state), an optional SMF
// session and a Loki mock serving the given stream values (newest first, as
// direction=backward does). gotDir receives the direction and limit queried.
func diagnoseDeps(t *testing.T, cm string, withSession bool, lokiValues string, gotQuery *map[string]string) Deps {
	t.Helper()
	amf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"supi":"imsi-001010000000001","gmm_state":"5GMM-REGISTERED","cm_state":"` + cm + `"}`))
	}))
	t.Cleanup(amf.Close)
	smf := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if withSession {
			_, _ = w.Write([]byte(`{"count":1,"sessions":[{"supi":"imsi-001010000000001","pduSessionId":1}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"count":0,"sessions":[]}`))
	}))
	t.Cleanup(smf.Close)
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotQuery != nil {
			*gotQuery = map[string]string{"direction": r.URL.Query().Get("direction"), "limit": r.URL.Query().Get("limit"), "query": r.URL.Query().Get("query")}
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[{"stream":{"nf":"AMF"},"values":[` + lokiValues + `]}]}}`))
	}))
	t.Cleanup(loki.Close)
	return Deps{
		AMF:  clients.NewAMF(amf.URL, http.DefaultClient),
		SMF:  clients.NewSMF(smf.URL, smf.Client()),
		PCF:  clients.NewPCF(deadURL(t), http.DefaultClient),
		UDM:  clients.NewUDM(deadURL(t), http.DefaultClient),
		Loki: clients.NewLoki(loki.URL, http.DefaultClient),
	}
}

// lokiLine renders one Loki value pair (timestamp in seconds) for an error record.
func lokiLine(sec int, nf, proc, res, msg string) string {
	rec := `{"nf":"` + nf + `","procedure":"` + proc + `","result":"` + res + `","spec_ref":"TS 24.501 §5.5.1","msg":"` + msg + `"}`
	b, _ := json.Marshal(rec)
	return `["` + strconv.Itoa(sec) + `000000000",` + string(b) + `]`
}

func runDiagnose(t *testing.T, d Deps) (findings []map[string]string, recent []errorGroup) {
	t.Helper()
	out, err := ueDiagnoseTool{d}.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	m := out.(map[string]any)
	return m["findings"].([]map[string]string), m["recent_errors"].([]errorGroup)
}

func hasFinding(fs []map[string]string, sub, spec string) bool {
	for _, f := range fs {
		if strings.Contains(f["message"], sub) && (spec == "" || f["spec_ref"] == spec) {
			return true
		}
	}
	return false
}

func TestDiagnoseCMIdle(t *testing.T) {
	cases := []struct {
		cm      string
		session bool
		want    bool
	}{
		{"CM-IDLE", true, true},
		{"IDLE", true, true},
		{"CM-CONNECTED", true, false},
		{"CM-IDLE", false, false},
	}
	for _, c := range cases {
		t.Run(c.cm, func(t *testing.T) {
			fs, _ := runDiagnose(t, diagnoseDeps(t, c.cm, c.session, ``, nil))
			if got := hasFinding(fs, "CM-IDLE", "TS 23.502 §4.3.3.2"); got != c.want {
				t.Errorf("CM-IDLE finding = %v, want %v: %v", got, c.want, fs)
			}
		})
	}
}

func TestDiagnoseGrouping(t *testing.T) {
	t.Run("25 identical lines make one row", func(t *testing.T) {
		var vals []string
		for i := 25; i >= 1; i-- { // newest first
			vals = append(vals, lokiLine(1000+i, "AMF", "InitialRegistration", "REJECT", "udm unreachable"))
		}
		var q map[string]string
		_, rows := runDiagnose(t, diagnoseDeps(t, "CM-CONNECTED", false, strings.Join(vals, ","), &q))
		if len(rows) != 1 || rows[0].Count != 25 {
			t.Fatalf("rows = %+v", rows)
		}
		if !rows[0].First.Before(rows[0].Last) || rows[0].First.IsZero() {
			t.Errorf("first/last = %v / %v", rows[0].First, rows[0].Last)
		}
		if q["limit"] != "200" {
			t.Errorf("loki limit = %q, want 200", q["limit"])
		}
	})
	t.Run("12 kinds give the top 10 by count", func(t *testing.T) {
		var vals []string
		sec := 1000
		for kind := 1; kind <= 12; kind++ {
			for n := 0; n < 13-kind; n++ { // kind 1 has 12 lines ... kind 12 has 1
				sec++
				vals = append(vals, lokiLine(sec, "AMF", "Proc", "REJECT", "kind"+strconv.Itoa(kind)))
			}
		}
		_, rows := runDiagnose(t, diagnoseDeps(t, "CM-CONNECTED", false, strings.Join(vals, ","), nil))
		if len(rows) != 10 {
			t.Fatalf("rows = %d, want 10", len(rows))
		}
		for i := 1; i < len(rows); i++ {
			if rows[i].Count > rows[i-1].Count {
				t.Errorf("rows not sorted by count desc at %d: %+v", i, rows)
			}
		}
		if rows[0].Msg != "kind1" || rows[0].Count != 12 {
			t.Errorf("top row = %+v", rows[0])
		}
	})
}

func TestDiagnoseNewest(t *testing.T) {
	// Newest first, as direction=backward returns them.
	vals := lokiLine(2000, "AMF", "ProcB", "REJECT", "B") + "," + lokiLine(1000, "AMF", "ProcA", "FAILURE", "A")
	var q map[string]string
	fs, _ := runDiagnose(t, diagnoseDeps(t, "CM-CONNECTED", false, vals, &q))
	if q["direction"] != "backward" {
		t.Errorf("direction = %q", q["direction"])
	}
	if !hasFinding(fs, "latest AMF ProcB: B", "") || hasFinding(fs, "ProcA", "") {
		t.Errorf("latest-error finding must name the newest line: %v", fs)
	}
}

func TestProcedureStatsIncludeZero(t *testing.T) {
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
		 {"metric":{"nf":"AMF","procedure":"InitialRegistration","result":"OK"},"value":[1,"10"]},
		 {"metric":{"nf":"AMF","procedure":"ServiceRequest","result":"OK"},"value":[1,"0"]},
		 {"metric":{"nf":"AMF","procedure":"ServiceRequest","result":"REJECT"},"value":[1,"0"]}]}}`))
	}))
	defer prom.Close()
	d := Deps{Prom: promclient.New(prom.URL, http.DefaultClient, 0)}
	for _, c := range []struct {
		args     string
		wantZero bool
	}{{`{"nf":"AMF"}`, false}, {`{"nf":"AMF","include_zero":false}`, false}, {`{"nf":"AMF","include_zero":true}`, true}} {
		out, err := procedureStatsTool{d}.Invoke(context.Background(), json.RawMessage(c.args))
		if err != nil {
			t.Fatalf("%s: %v", c.args, err)
		}
		raw, _ := json.Marshal(out)
		if !strings.Contains(string(raw), "InitialRegistration") {
			t.Errorf("%s: non-zero row lost: %s", c.args, raw)
		}
		if got := strings.Contains(string(raw), "ServiceRequest"); got != c.wantZero {
			t.Errorf("%s: zero row present = %v, want %v", c.args, got, c.wantZero)
		}
	}
	// The deprecated alias still maps onto procedure_stats.
	if mapped, err := mapSummaryLegacy(json.RawMessage(`{"metric":"fivegc_procedure_total"}`)); err != nil || string(mapped) != "{}" {
		t.Errorf("alias mapping: %s %v", mapped, err)
	}
}

// diagnoseRaw runs ue_diagnose and returns the whole output map.
func diagnoseRaw(t *testing.T, d Deps) map[string]any {
	t.Helper()
	out, err := ueDiagnoseTool{d}.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	return out.(map[string]any)
}

// TestDiagnoseLogsTruncated: a full page from Loki is reported as "at least N"
// with logs_truncated=true; a short page keeps the exact count.
func TestDiagnoseLogsTruncated(t *testing.T) {
	page := func(n int) string {
		var vals []string
		for i := n; i >= 1; i-- {
			vals = append(vals, lokiLine(1000+i, "AMF", "InitialRegistration", "REJECT", "x"))
		}
		return strings.Join(vals, ",")
	}
	cases := []struct {
		n         int
		truncated bool
		want      string
	}{
		{diagnoseLokiLimit, true, "at least 200 (capped at the query limit) REJECT/FAILURE log records in the last 15m"},
		{5, false, "5 REJECT/FAILURE log records in the last 15m"},
	}
	for _, c := range cases {
		m := diagnoseRaw(t, diagnoseDeps(t, "CM-CONNECTED", false, page(c.n), nil))
		if m["logs_truncated"] != c.truncated {
			t.Errorf("n=%d logs_truncated = %v", c.n, m["logs_truncated"])
		}
		if !hasFinding(m["findings"].([]map[string]string), c.want, "") {
			t.Errorf("n=%d: finding %q missing: %v", c.n, c.want, m["findings"])
		}
	}
}

// TestDiagnoseSkipsNonErrorResults: a line that matched the filter only as a
// substring (result not REJECT/FAILURE) is not counted, and the LogQL parses
// the JSON and filters on the result label.
func TestDiagnoseSkipsNonErrorResults(t *testing.T) {
	vals := lokiLine(2000, "AMF", "ProcB", "OK", "mentions REJECT in text") + "," +
		lokiLine(1000, "AMF", "ProcA", "FAILURE", "real")
	var q map[string]string
	fs, rows := runDiagnose(t, diagnoseDeps(t, "CM-CONNECTED", false, vals, &q))
	if len(rows) != 1 || rows[0].Proc != "ProcA" {
		t.Errorf("rows = %+v", rows)
	}
	if !hasFinding(fs, "1 REJECT/FAILURE log records", "") {
		t.Errorf("findings = %v", fs)
	}
	if !strings.Contains(q["query"], `| json | result=~"REJECT|FAILURE"`) {
		t.Errorf("logql = %q", q["query"])
	}
}

func TestDiagnoseCMIdleMessage(t *testing.T) {
	fs, _ := runDiagnose(t, diagnoseDeps(t, "CM-IDLE", true, ``, nil))
	if !hasFinding(fs, "this AMF does not page", "TS 23.502 §4.3.3.2") {
		t.Errorf("findings = %v", fs)
	}
}

// TestDiagnoseSMFSessionShapes: the SMF answers {"count":n,"sessions":[...]};
// sessionsOf extracts the UE's sessions from that object (and from a bare array),
// and returns an error for a malformed body, which ue_diagnose reports in errors.
func TestDiagnoseSMFSessionShapes(t *testing.T) {
	const supi = "imsi-001010000000001"
	cases := []struct {
		name    string
		body    string
		want    int
		wantErr bool
	}{
		{"object", `{"count":2,"sessions":[{"supi":"` + supi + `","pduSessionId":1},{"supi":"imsi-001010000000002","pduSessionId":1}]}`, 1, false},
		{"bare array", `[{"supi":"` + supi + `","pduSessionId":2}]`, 1, false},
		{"malformed", `{"sessions":"nope"}`, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := sessionsOf([]byte(c.body), supi)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if len(got) != c.want {
				t.Errorf("sessions = %d, want %d", len(got), c.want)
			}
		})
	}
}
