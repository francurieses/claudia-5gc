package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// upstream records every request as "METHOD path" and answers with the status
// the test chose for that path, defaulting to 202.
type upstream struct {
	mu    sync.Mutex
	calls []string
	body  []string
	reply map[string]int
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.calls = append(u.calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	u.body = append(u.body, string(b))
	status, ok := u.reply[r.Method+" "+r.URL.Path]
	u.mu.Unlock()
	if !ok {
		status = http.StatusAccepted
	}
	if strings.HasPrefix(r.URL.Path, "/nsmf-management/v1/sessions/") && r.Method == http.MethodGet {
		_, _ = w.Write([]byte(`{"pduSessionId":1,"current5qi":9}`))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/amf/v1/ue-contexts/imsi-") && r.Method == http.MethodGet {
		_, _ = w.Write([]byte(`{"supi":"imsi-001010000000001","gmm_state":"REGISTERED","cm_state":"IDLE"}`))
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"detail":"stub"}`))
}

func (u *upstream) saw(prefix string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, c := range u.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// harness wires the control tools to one recording upstream that serves AMF, SMF
// and portal paths, and returns a guard in lab mode.
func harness(t *testing.T, reply map[string]int) (map[string]registry.Tool, *upstream, *guard.Guard) {
	t.Helper()
	up := &upstream{reply: reply}
	srv := httptest.NewServer(up)
	t.Cleanup(srv.Close)
	tools := map[string]registry.Tool{}
	for _, tl := range All(Deps{
		AMF:    clients.NewAMF(srv.URL, http.DefaultClient),
		SMF:    clients.NewSMF(srv.URL, http.DefaultClient),
		Portal: clients.NewPortal(srv.URL, http.DefaultClient),
	}) {
		tools[tl.Name()] = tl
	}
	g := guard.New(guard.Options{Mode: guard.ModeLab}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return tools, up, g
}

// operator is the caller role the stdio and tokenless SSE paths run as.
func operator() context.Context { return guard.WithRole(context.Background(), guard.RoleOperator) }

// run sends a call through the guard exactly as the dispatcher does.
func run(t *testing.T, g *guard.Guard, tl registry.Tool, args string) (any, *guard.Decision, error) {
	t.Helper()
	raw := json.RawMessage(args)
	d := g.Check(operator(), tl, raw)
	if d.Verdict != guard.Proceed {
		return nil, &d, nil
	}
	out, err := tl.Invoke(operator(), raw)
	g.Record(operator(), tl, raw, err)
	return out, &d, err
}

func codeOf(t *testing.T, err error) int {
	t.Helper()
	var e *mcperr.Error
	if !errors.As(err, &e) {
		t.Fatalf("want *mcperr.Error, got %T %v", err, err)
	}
	return e.Code
}

func TestEveryControlToolIsDisruptive(t *testing.T) {
	tools, _, _ := harness(t, nil)
	if len(tools) != 14 {
		t.Fatalf("control tools: got %d, want 14", len(tools))
	}
	for name, tl := range tools {
		if name == "af_qos_session_get" {
			if tl.Risk() != registry.ReadOnly {
				t.Errorf("%s: risk %s, want READ_ONLY", name, tl.Risk())
			}
			continue
		}
		if tl.Risk() != registry.Disruptive {
			t.Errorf("%s: risk %s, want DISRUPTIVE", name, tl.Risk())
		}
	}
}

// TestDryRunSendsNothing is the guard contract for control tools: without
// confirm, the state-changing upstream call is never made.
func TestDryRunSendsNothing(t *testing.T) {
	tools, up, g := harness(t, nil)
	for _, c := range []struct{ tool, args, forbidden string }{
		{"ue_deregister_nw", `{"supi":"imsi-001010000000001"}`, "DELETE /amf/v1/ue-contexts/imsi-001010000000001"},
		{"pdu_session_release_nw", `{"supi":"imsi-001010000000001","pdu_session_id":1}`, "DELETE /amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/1"},
		{"ue_policy_push", `{"supi":"imsi-001010000000001"}`, "POST /amf/v1/ue-contexts/imsi-001010000000001/push-policies"},
		{"ue_page", `{"pdu_session_id":1}`, "POST /nsmf-management/v1/sessions/1/dl-data-notification"},
		{"nssaa_trigger", `{"supi":"imsi-001010000000001","action":"revoke","sst":1}`, "POST /amf/v1/ue-contexts/imsi-001010000000001/nssaa/revoke"},
		{"pws_broadcast", `{"messageIdentifier":1,"serialNumber":2}`, "POST /api/v1/pws/broadcast"},
		{"pws_cancel", `{"messageIdentifier":1,"serialNumber":2}`, "POST /api/v1/pws/cancel"},
	} {
		out, d, err := run(t, g, tools[c.tool], c.args)
		if err != nil || out != nil {
			t.Fatalf("%s: dry-run must not execute (out=%v err=%v)", c.tool, out, err)
		}
		if d.Verdict != guard.DryRun {
			t.Errorf("%s: verdict %v, want DryRun", c.tool, d.Verdict)
		}
		if up.saw(c.forbidden) {
			t.Errorf("%s: dry-run reached the upstream: %s", c.tool, c.forbidden)
		}
	}
}

func TestDeregisterConfirmedSendsDELETE(t *testing.T) {
	tools, up, g := harness(t, nil)
	out, _, err := run(t, g, tools["ue_deregister_nw"], `{"supi":"imsi-001010000000001","confirm":true}`)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !up.saw("DELETE /amf/v1/ue-contexts/imsi-001010000000001?") {
		t.Errorf("DELETE not sent: %v", up.calls)
	}
	if out.(map[string]any)["spec_ref"] != "TS 23.502 §4.2.2.3.3" {
		t.Errorf("spec_ref missing: %v", out)
	}
}

func TestUnknownUEIsAnError(t *testing.T) {
	tools, _, g := harness(t, map[string]int{"DELETE /amf/v1/ue-contexts/imsi-001010000000009": http.StatusNotFound})
	_, _, err := run(t, g, tools["ue_deregister_nw"], `{"supi":"imsi-001010000000009","confirm":true}`)
	if codeOf(t, err) != mcperr.CodeToolError {
		t.Errorf("404 from the AMF must be a tool error")
	}
}

func TestReleaseSessionSendsPSIPath(t *testing.T) {
	tools, up, g := harness(t, nil)
	if _, _, err := run(t, g, tools["pdu_session_release_nw"], `{"supi":"imsi-001010000000001","pdu_session_id":3,"confirm":true}`); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !up.saw("DELETE /amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/3") {
		t.Errorf("PSI path wrong: %v", up.calls)
	}
}

func TestReleaseRejectsPSIOutsideRange(t *testing.T) {
	tools, _, _ := harness(t, nil)
	_, err := tools["pdu_session_release_nw"].Invoke(operator(), json.RawMessage(`{"supi":"imsi-001010000000001","pdu_session_id":16}`))
	if codeOf(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("PSI 16: want -32602")
	}
}

func TestPolicyPushCMIdleIsDeferredNotFailed(t *testing.T) {
	tools, _, g := harness(t, map[string]int{"POST /amf/v1/ue-contexts/imsi-001010000000001/push-policies": http.StatusConflict})
	out, _, err := run(t, g, tools["ue_policy_push"], `{"supi":"imsi-001010000000001","confirm":true}`)
	if err != nil {
		t.Fatalf("409 must not be an error: %v", err)
	}
	m := out.(map[string]any)
	if m["deferred"] != true || m["pushed"] != false {
		t.Errorf("want deferred:true pushed:false, got %v", m)
	}
}

func TestPageMapsSMFErrorCodes(t *testing.T) {
	tools, _, g := harness(t, map[string]int{"POST /nsmf-management/v1/sessions/5/dl-data-notification": http.StatusNotFound})
	_, _, err := run(t, g, tools["ue_page"], `{"pdu_session_id":5,"confirm":true}`)
	var e *mcperr.Error
	if !errors.As(err, &e) || e.Data["smf_code"] != "CONTEXT_NOT_FOUND" {
		t.Errorf("404 must carry CONTEXT_NOT_FOUND, got %v", err)
	}
}

func TestPageAcceptsSuccess(t *testing.T) {
	tools, up, g := harness(t, map[string]int{"POST /nsmf-management/v1/sessions/2/dl-data-notification": http.StatusOK})
	out, _, err := run(t, g, tools["ue_page"], `{"pdu_session_id":2,"supi":"imsi-001010000000001","confirm":true}`)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if out.(map[string]any)["paging"] != "triggered" {
		t.Errorf("result: %v", out)
	}
	if !up.saw("POST /nsmf-management/v1/sessions/2/dl-data-notification?supi=imsi-001010000000001") {
		t.Errorf("supi not sent: %v", up.calls)
	}
}

func TestNSSAAValidation(t *testing.T) {
	tools, _, _ := harness(t, nil)
	cases := map[string]string{
		"bad action": `{"supi":"imsi-001010000000001","action":"delete","sst":1}`,
		"bad sst":    `{"supi":"imsi-001010000000001","action":"revoke","sst":256}`,
		"bad sd":     `{"supi":"imsi-001010000000001","action":"revoke","sst":1,"sd":"12345"}`,
	}
	for name, args := range cases {
		if _, err := tools["nssaa_trigger"].Invoke(operator(), json.RawMessage(args)); codeOf(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("%s: want -32602", name)
		}
	}
}

func TestNSSAARevokeSendsSliceBody(t *testing.T) {
	tools, up, g := harness(t, map[string]int{"POST /amf/v1/ue-contexts/imsi-001010000000001/nssaa/revoke": http.StatusNoContent})
	if _, _, err := run(t, g, tools["nssaa_trigger"], `{"supi":"imsi-001010000000001","action":"revoke","sst":1,"sd":"000001","confirm":true}`); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	last := up.body[len(up.body)-1]
	if !strings.Contains(last, `"sst":1`) || !strings.Contains(last, `"sd":"000001"`) {
		t.Errorf("slice body: %s", last)
	}
}

func TestPWSBroadcastRequiresIdentifiers(t *testing.T) {
	tools, _, _ := harness(t, nil)
	if _, err := tools["pws_broadcast"].Invoke(operator(), json.RawMessage(`{"serialNumber":2}`)); codeOf(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("missing messageIdentifier: want -32602")
	}
}

func TestPWSBroadcastForwardsToPortal(t *testing.T) {
	tools, up, g := harness(t, map[string]int{"POST /api/v1/pws/broadcast": http.StatusOK})
	if _, _, err := run(t, g, tools["pws_broadcast"], `{"messageIdentifier":4370,"serialNumber":4096,"confirm":true}`); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !up.saw("POST /api/v1/pws/broadcast") {
		t.Errorf("portal not called: %v", up.calls)
	}
}
