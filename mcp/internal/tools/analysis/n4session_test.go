package analysis

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

const (
	n4SMFQERs = `[{"qerId":1,"role":"session-ambr","gateUl":"OPEN","gateDl":"OPEN","mbrUlKbps":100000,"mbrDlKbps":100000},` +
		`{"qerId":2,"role":"qos-flow","qfi":1,"gateUl":"OPEN","gateDl":"OPEN"}]`
	n4SMFView = `{"session":{"supi":"imsi-001010000000001","pduSessionId":1,"seid":9,"upfTeid":4097,"ueIp":"10.60.0.2"},"pfcpQers":` + n4SMFQERs + `}`
	n4QER1    = `{"qer_id":1,"has_mbr":true,"mbr_ul_kbps":100000,"mbr_dl_kbps":100000,"gate_ul":"OPEN","gate_dl":"OPEN"}`
	n4QER2    = `{"qer_id":2,"qfi":1,"has_mbr":false,"gate_ul":"OPEN","gate_dl":"OPEN"}`
)

func upfSess(cp int, teid int, ip string, qers ...string) string {
	return `{"cp_seid":` + itoa(cp) + `,"up_seid":` + itoa(cp) + `,"ul_teid":` + itoa(teid) + `,"ue_ipv4":"` + ip + `","qers":[` + strings.Join(qers, ",") + `]}`
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

type n4Env struct {
	d         Deps
	mu        sync.Mutex
	smfPaths  []string
	upfReqs   []*http.Request
	upfServer *httptest.Server
}

// newN4Env wires SMF, Prometheus and UPF admin mocks. smfSession is the body of
// GET /sessions/1 (status smfStatus); upfBody is the UPF reply.
func newN4Env(t *testing.T, smfStatus int, smfSession string, smfList string, upfBody string, withTarget bool) *n4Env {
	t.Helper()
	e := &n4Env{}
	smf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.smfPaths = append(e.smfPaths, r.URL.Path)
		e.mu.Unlock()
		if r.URL.Path == "/nsmf-management/v1/sessions" {
			_, _ = w.Write([]byte(smfList))
			return
		}
		w.WriteHeader(smfStatus)
		_, _ = w.Write([]byte(smfSession))
	}))
	t.Cleanup(smf.Close)
	e.upfServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.upfReqs = append(e.upfReqs, r)
		e.mu.Unlock()
		_, _ = w.Write([]byte(upfBody))
	}))
	t.Cleanup(e.upfServer.Close)
	upfAddr := strings.TrimPrefix(e.upfServer.URL, "http://")
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !withTarget || !strings.Contains(r.URL.Query().Get("query"), `nf="UPF"`) {
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"nf":"UPF","instance":"` +
			upfAddr + `"},"value":[1,"1"]}]}}`))
	}))
	t.Cleanup(prom.Close)
	pc := promclient.New(prom.URL, prom.Client(), 0)
	e.d = Deps{SMF: clients.NewSMF(smf.URL, http.DefaultClient), Prom: pc, Targets: clients.NewTargets(pc, ""), HTTP: http.DefaultClient}
	return e
}

func upfWrap(sessions ...string) string {
	return `{"count":` + itoa(len(sessions)) + `,"sessions":[` + strings.Join(sessions, ",") + `]}`
}

func callN4(t *testing.T, d Deps, args string) (map[string]any, *mcperr.Error) {
	t.Helper()
	out, err := n4SessionTool{d}.Invoke(context.Background(), json.RawMessage(args))
	if err != nil {
		me, ok := err.(*mcperr.Error)
		if !ok {
			t.Fatalf("non-mcperr error %T: %v", err, err)
		}
		return nil, me
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	if jerr := json.Unmarshal(b, &m); jerr != nil {
		t.Fatal(jerr)
	}
	return m, nil
}

func mismatches(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	raw, ok := m["smf_mismatches"].([]any)
	if !ok {
		t.Fatalf("smf_mismatches is not an array: %v", m["smf_mismatches"])
	}
	var out []map[string]any
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

func TestN4SessionRisk(t *testing.T) {
	if (n4SessionTool{}).Risk() != registry.ReadOnly {
		t.Fatal("n4_session_get must be READ_ONLY")
	}
}

func TestN4SessionByPSIDiff(t *testing.T) {
	good := upfSess(9, 4097, "10.60.0.2", n4QER1, n4QER2)
	tests := []struct {
		name  string
		upf   string
		field string
		smf   any
		upfV  any
		count int
	}{
		{"agree", good, "", nil, nil, 0},
		{"has_mbr false compares as 0", upfSess(9, 4097, "10.60.0.2",
			`{"qer_id":1,"has_mbr":false,"gate_ul":"OPEN","gate_dl":"OPEN"}`, n4QER2), "qers[1].mbr_ul_kbps", 100000.0, 0.0, 2},
		{"mbr dl", upfSess(9, 4097, "10.60.0.2",
			`{"qer_id":1,"has_mbr":true,"mbr_ul_kbps":100000,"mbr_dl_kbps":30000,"gate_ul":"OPEN","gate_dl":"OPEN"}`, n4QER2),
			"qers[1].mbr_dl_kbps", 100000.0, 30000.0, 1},
		{"qfi", upfSess(9, 4097, "10.60.0.2", n4QER1,
			`{"qer_id":2,"qfi":5,"has_mbr":false,"gate_ul":"OPEN","gate_dl":"OPEN"}`), "qers[2].qfi", 1.0, 5.0, 1},
		{"qfi on ambr qer", upfSess(9, 4097, "10.60.0.2",
			`{"qer_id":1,"qfi":1,"has_mbr":true,"mbr_ul_kbps":100000,"mbr_dl_kbps":100000,"gate_ul":"OPEN","gate_dl":"OPEN"}`, n4QER2),
			"qers[1].qfi", nil, 1.0, 1},
		{"closed gate", upfSess(9, 4097, "10.60.0.2", n4QER1,
			`{"qer_id":2,"qfi":1,"has_mbr":false,"gate_ul":"OPEN","gate_dl":"CLOSED"}`), "qers[2].gate_dl", "OPEN", "CLOSED", 1},
		{"teid", upfSess(9, 4098, "10.60.0.2", n4QER1, n4QER2), "ul_teid", 4097.0, 4098.0, 1},
		{"ue ip", upfSess(9, 4097, "10.60.0.3", n4QER1, n4QER2), "ue_ip", "10.60.0.2", "10.60.0.3", 1},
		{"qer missing", upfSess(9, 4097, "10.60.0.2", n4QER1), "qers[2]", "present", nil, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newN4Env(t, 200, n4SMFView, "", upfWrap(tc.upf), true)
			m, err := callN4(t, e.d, `{"supi":"imsi-001010000000001","pdu_session_id":1}`)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			mm := mismatches(t, m)
			if len(mm) != tc.count {
				t.Fatalf("mismatches = %v, want %d", mm, tc.count)
			}
			if tc.field != "" {
				found := false
				for _, x := range mm {
					if x["field"] == tc.field {
						found = true
						if x["smf"] != tc.smf || x["upf"] != tc.upfV {
							t.Errorf("%s: smf=%v upf=%v, want smf=%v upf=%v", tc.field, x["smf"], x["upf"], tc.smf, tc.upfV)
						}
					}
				}
				if !found {
					t.Errorf("field %s not in %v", tc.field, mm)
				}
			}
			if len(e.upfReqs) != 1 || e.upfReqs[0].URL.Query().Get("seid") != "9" || e.upfReqs[0].Method != http.MethodGet {
				t.Errorf("unexpected UPF requests")
			}
		})
	}
}

func TestN4SessionQERCountMismatch(t *testing.T) {
	e := newN4Env(t, 200, n4SMFView, "", upfWrap(upfSess(9, 4097, "10.60.0.2", n4QER1)), true)
	m, _ := callN4(t, e.d, `{"pdu_session_id":1}`)
	got := map[string]bool{}
	for _, x := range mismatches(t, m) {
		got[x["field"].(string)] = true
	}
	if !got["qer_count"] || !got["qers[2]"] {
		t.Errorf("want qer_count and qers[2], got %v", got)
	}
}

func TestN4SessionPathB(t *testing.T) {
	list := `{"count":1,"sessions":[{"supi":"imsi-001010000000001","pduSessionId":1,"seid":9,"ueIp":"10.60.0.2"}]}`
	good := upfWrap(upfSess(9, 4097, "10.60.0.2", n4QER1, n4QER2))
	for _, args := range []string{`{"seid":9}`, `{"seid":"0x9"}`, `{"ue_ip":"10.60.0.2"}`} {
		e := newN4Env(t, 200, n4SMFView, list, good, true)
		m, err := callN4(t, e.d, args)
		if err != nil {
			t.Fatalf("%s: %v", args, err)
		}
		if len(mismatches(t, m)) != 0 {
			t.Errorf("%s: unexpected mismatches", args)
		}
		q := e.upfReqs[0].URL.Query()
		if strings.Contains(args, "seid") && q.Get("seid") != "9" || strings.Contains(args, "ue_ip") && q.Get("ue_ip") != "10.60.0.2" {
			t.Errorf("%s: query %v", args, q)
		}
	}

	// orphan UPF session
	e := newN4Env(t, 200, n4SMFView, `{"sessions":[]}`, upfWrap(upfSess(77, 5000, "10.60.0.9", `{"qer_id":1,"gate_ul":"OPEN","gate_dl":"OPEN"}`)), true)
	_, err := callN4(t, e.d, `{"seid":77}`)
	assertCode(t, err, "CONTEXT_NOT_FOUND")
	if err.Data["seid"] != uint64(77) || err.Data["upf"] == nil {
		t.Errorf("orphan data = %v", err.Data)
	}

	// nothing anywhere
	e = newN4Env(t, 200, n4SMFView, list, upfWrap(), true)
	_, err = callN4(t, e.d, `{"seid":4242}`)
	assertCode(t, err, "N4_SESSION_NOT_FOUND")
	if v, ok := err.Data["smf"]; !ok || v != nil {
		t.Errorf("smf should be present and nil: %v", err.Data)
	}

	// ambiguous
	e = newN4Env(t, 200, n4SMFView, list, upfWrap(upfSess(10, 1, "10.60.0.2"), upfSess(9, 4097, "10.60.0.2", n4QER1, n4QER2)), true)
	_, err = callN4(t, e.d, `{"ue_ip":"10.60.0.2"}`)
	assertCode(t, err, "AMBIGUOUS_N4_SESSION")
	if s, _ := json.Marshal(err.Data["seids"]); string(s) != "[9,10]" {
		t.Errorf("seids = %s", s)
	}
}

func assertCode(t *testing.T, err *mcperr.Error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error %s, got success", code)
	}
	if err.Code != mcperr.CodeToolError || err.Data["code"] != code {
		t.Fatalf("error = %d %v, want -32000 %s", err.Code, err.Data, code)
	}
}

func TestN4SessionErrors(t *testing.T) {
	t.Run("smf 404", func(t *testing.T) {
		e := newN4Env(t, 404, `{"cause":"CONTEXT_NOT_FOUND"}`, "", upfWrap(), true)
		_, err := callN4(t, e.d, `{"pdu_session_id":1}`)
		assertCode(t, err, "CONTEXT_NOT_FOUND")
		if len(e.upfReqs) != 0 {
			t.Error("UPF must not be queried")
		}
	})
	t.Run("smf 409", func(t *testing.T) {
		e := newN4Env(t, 409, `{"cause":"AMBIGUOUS_SESSION"}`, "", upfWrap(), true)
		_, err := callN4(t, e.d, `{"pdu_session_id":1}`)
		assertCode(t, err, "AMBIGUOUS_SESSION")
		if err.Data["pdu_session_id"] != 1 {
			t.Errorf("data = %v", err.Data)
		}
	})
	t.Run("smf 500", func(t *testing.T) {
		e := newN4Env(t, 500, `boom`, "", upfWrap(), true)
		_, err := callN4(t, e.d, `{"pdu_session_id":1}`)
		if err == nil || err.Data["upstream"] != "smf" || err.Data["status"] != 500 {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("upf count 0", func(t *testing.T) {
		e := newN4Env(t, 200, n4SMFView, "", upfWrap(), true)
		_, err := callN4(t, e.d, `{"supi":"imsi-001010000000001","pdu_session_id":1}`)
		assertCode(t, err, "N4_SESSION_NOT_FOUND")
		if err.Data["seid"] != uint64(9) || err.Data["smf"] == nil {
			t.Errorf("data = %v", err.Data)
		}
	})
	t.Run("no prometheus target", func(t *testing.T) {
		e := newN4Env(t, 200, n4SMFView, "", upfWrap(), false)
		_, err := callN4(t, e.d, `{"pdu_session_id":1}`)
		if err == nil || err.Code != mcperr.CodeToolError || err.Data["upstream"] != "prometheus" {
			t.Errorf("err = %v", err)
		}
		if len(e.upfReqs) != 0 {
			t.Error("UPF must not be queried")
		}
	})
	t.Run("upf unreachable", func(t *testing.T) {
		e := newN4Env(t, 200, n4SMFView, "", upfWrap(), true)
		e.upfServer.Close()
		_, err := callN4(t, e.d, `{"pdu_session_id":1}`)
		if err == nil || err.Code != mcperr.CodeToolError || err.Data["upstream"] != "upf" {
			t.Errorf("err = %v", err)
		}
	})
}

func TestN4SessionInvalidArgs(t *testing.T) {
	for _, args := range []string{
		`{}`, `{"supi":"imsi-001010000000001"}`,
		`{"supi":"imsi-001010000000001","pdu_session_id":1,"seid":9}`,
		`{"pdu_session_id":1,"ue_ip":"10.60.0.2"}`,
		`{"pdu_session_id":16}`, `{"pdu_session_id":0,"seid":9}`, `{"ue_ip":"not-an-ip"}`,
		`{"seid":0}`, `{"seid":"xyz"}`, `{"seid":"0o7"}`, `{"seid":-1}`,
		`{"supi":"bogus","pdu_session_id":1}`, `{"supi":"imsi-001010000000001","seid":9}`, `[1]`,
	} {
		e := newN4Env(t, 200, n4SMFView, "", upfWrap(), true)
		_, err := callN4(t, e.d, args)
		if err == nil || err.Code != mcperr.CodeInvalidParams {
			t.Errorf("%s: err = %v, want -32602", args, err)
		}
		if len(e.smfPaths) != 0 || len(e.upfReqs) != 0 {
			t.Errorf("%s: upstream was called", args)
		}
	}
}

func TestParseSEID(t *testing.T) {
	for in, want := range map[string]uint64{`9`: 9, `"9"`: 9, `"0x9"`: 9, `"0X1f"`: 31, `"010"`: 10, `18446744073709551615`: 18446744073709551615} {
		got, err := parseSEID(json.RawMessage(in))
		if err != nil || got != want {
			t.Errorf("%s: got %d, %v", in, got, err)
		}
	}
}
