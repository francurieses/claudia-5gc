package qos

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// call records one upstream request as "METHOD path?query".
type call struct {
	mu    sync.Mutex
	calls []string
	body  []string
}

func (c *call) record(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, r.Method+" "+r.URL.RequestURI())
	b, _ := io.ReadAll(r.Body)
	c.body = append(c.body, string(b))
}

func (c *call) has(prefix string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range c.calls {
		if strings.HasPrefix(x, prefix) {
			return true
		}
	}
	return false
}

// upstreams starts one fake SMF, PCF and AMF. Each records every request.
// pcfStatus sets the PCF status for override calls.
func upstreams(t *testing.T, pcfStatus int) (smf, pcf, amf *call, smfURL, pcfURL, amfURL string) {
	t.Helper()
	smf, pcf, amf = &call{}, &call{}, &call{}
	smfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		smf.record(r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/nsmf-management/v1/sessions/"):
			_, _ = w.Write([]byte(`{"pduSessionId":1,"current5qi":9,"qosSource":"subscription"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/qos"):
			_, _ = w.Write([]byte(`{"result":"accepted","previous5qi":9,"new5qi":7}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	pcfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pcf.record(r)
		if pcfStatus != 0 {
			w.WriteHeader(pcfStatus)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	amfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		amf.record(r)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(func() { smfSrv.Close(); pcfSrv.Close(); amfSrv.Close() })
	return smf, pcf, amf, smfSrv.URL, pcfSrv.URL, amfSrv.URL
}

func setTool(smfURL, pcfURL string) sessionQoSSetTool {
	return sessionQoSSetTool{
		smf: clients.NewSMF(smfURL, http.DefaultClient),
		pcf: clients.NewPCF(pcfURL, http.DefaultClient),
	}
}

// codeOf extracts the JSON-RPC code of an *mcperr.Error returned by a tool.
func codeOf(t *testing.T, err error) int {
	t.Helper()
	var e *mcperr.Error
	if !errors.As(err, &e) {
		t.Fatalf("want *mcperr.Error, got %T: %v", err, err)
	}
	return e.Code
}

func TestSetRejectsPSIOutsideRange(t *testing.T) {
	_, _, _, smfURL, pcfURL, _ := upstreams(t, 0)
	tool := setTool(smfURL, pcfURL)
	for _, psi := range []int{0, 16, 255} {
		args := json.RawMessage(`{"pdu_session_id":` + itoa(psi) + `,"new5qi":7,"reason":"test"}`)
		_, err := tool.Invoke(context.Background(), args)
		if codeOf(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("psi %d: want -32602", psi)
		}
	}
}

func TestSetRejectsBadArgs(t *testing.T) {
	_, _, _, smfURL, pcfURL, _ := upstreams(t, 0)
	tool := setTool(smfURL, pcfURL)
	cases := map[string]string{
		"bad 5qi":         `{"pdu_session_id":1,"new5qi":99,"reason":"x"}`,
		"no reason":       `{"pdu_session_id":1,"new5qi":7}`,
		"bad supi":        `{"pdu_session_id":1,"new5qi":7,"reason":"x","supi":"001010000000001"}`,
		"persist no supi": `{"pdu_session_id":1,"new5qi":7,"reason":"x","persist_policy":true}`,
		"bad dnn":         `{"pdu_session_id":1,"new5qi":7,"reason":"x","dnn":"-bad"}`,
	}
	for name, args := range cases {
		if _, err := tool.Invoke(context.Background(), json.RawMessage(args)); codeOf(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("%s: want -32602", name)
		}
	}
}

func TestSetPlanReadsSessionAndDoesNotChangeIt(t *testing.T) {
	smf, _, _, smfURL, pcfURL, _ := upstreams(t, 0)
	tool := setTool(smfURL, pcfURL)
	out, err := tool.Plan(context.Background(), json.RawMessage(`{"pdu_session_id":1,"new5qi":7,"reason":"x","supi":"imsi-001010000000001","persist_policy":true}`))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !smf.has("GET /nsmf-management/v1/sessions/1") {
		t.Errorf("plan must read the session, calls: %v", smf.calls)
	}
	if smf.has("POST") {
		t.Errorf("plan must not change the session: %v", smf.calls)
	}
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), `"current_session"`) || !strings.Contains(string(raw), `"current5qi":9`) {
		t.Errorf("plan lacks the current session: %s", raw)
	}
}

func TestSetPersistWritesPCFOverride(t *testing.T) {
	smf, pcf, _, smfURL, pcfURL, _ := upstreams(t, 0)
	tool := setTool(smfURL, pcfURL)
	out, err := tool.Invoke(context.Background(), json.RawMessage(
		`{"pdu_session_id":1,"new5qi":7,"reason":"x","supi":"imsi-001010000000001","dnn":"internet","persist_policy":true,"ambr_dl_mbps":200}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !smf.has("POST /nsmf-management/v1/sessions/1/qos") {
		t.Errorf("SMF not called: %v", smf.calls)
	}
	if !pcf.has("PUT /pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override") {
		t.Errorf("PCF override not written: %v", pcf.calls)
	}
	if !strings.Contains(pcf.body[0], `"dnn":"internet"`) || !strings.Contains(pcf.body[0], `"5qi":7`) {
		t.Errorf("PCF body: %s", pcf.body[0])
	}
	if m := out.(map[string]any); m["policy_persisted"] != true {
		t.Errorf("policy_persisted: %v", m["policy_persisted"])
	}
}

func TestSetWithoutPersistLeavesPCFAlone(t *testing.T) {
	_, pcf, _, smfURL, pcfURL, _ := upstreams(t, 0)
	tool := setTool(smfURL, pcfURL)
	if _, err := tool.Invoke(context.Background(), json.RawMessage(`{"pdu_session_id":1,"new5qi":7,"reason":"x"}`)); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if len(pcf.calls) != 0 {
		t.Errorf("PCF must not be called without persist_policy: %v", pcf.calls)
	}
}

// TestDeprecatedModifyUsesSMFNotAMF is the conformance guard for the old
// pdu_session_qos_modify path: the SMF initiates the modification (TS 23.502
// §4.3.3.2), so the alias must never send the AMF PATCH.
func TestDeprecatedModifyUsesSMFNotAMF(t *testing.T) {
	smf, pcf, amf, smfURL, pcfURL, _ := upstreams(t, 0)
	tools := Sessions(clients.NewSMF(smfURL, http.DefaultClient), nil, clients.NewPCF(pcfURL, http.DefaultClient))
	var alias registry.Tool
	for _, tl := range tools {
		if tl.Name() == "pdu_session_qos_modify" {
			alias = tl
		}
	}
	if alias == nil {
		t.Fatal("pdu_session_qos_modify alias not registered")
	}
	if !strings.HasPrefix(alias.Description(), "DEPRECATED: use pdu_session_qos_set") {
		t.Errorf("alias description: %q", alias.Description())
	}
	if alias.Risk() != registry.Disruptive {
		t.Errorf("alias risk: %s", alias.Risk())
	}
	_, err := alias.Invoke(context.Background(), json.RawMessage(
		`{"supi":"imsi-001010000000001","pdu_session_id":2,"5qi":7}`))
	if err != nil {
		t.Fatalf("alias invoke: %v", err)
	}
	if !smf.has("POST /nsmf-management/v1/sessions/2/qos") {
		t.Errorf("alias must drive SMF POST …/qos: %v", smf.calls)
	}
	if !pcf.has("PUT ") {
		t.Errorf("alias persists the override like the old tool: %v", pcf.calls)
	}
	if len(amf.calls) != 0 {
		t.Errorf("alias must never call the AMF: %v", amf.calls)
	}
	if !strings.Contains(smf.body[0], `"5qi":7`) || !strings.Contains(smf.body[0], `"ambr_dl_mbps":100`) {
		t.Errorf("alias defaults (AMBR 100) not applied: %s", smf.body[0])
	}
}

func TestPolicyGetHasNoInventedDefault(t *testing.T) {
	_, _, _, _, pcfURL, _ := upstreams(t, 0)
	tool := getPolicyTool{clients.NewPCF(pcfURL, http.DefaultClient)}
	out, err := tool.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	m := out.(map[string]any)
	if _, ok := m["5qi"]; ok {
		t.Errorf("no override must not invent a 5qi: %v", m)
	}
	if m["is_override"] != false {
		t.Errorf("is_override: %v", m["is_override"])
	}
}

func TestPolicyDNNScopeIsSentToPCF(t *testing.T) {
	_, pcf, _, _, pcfURL, _ := upstreams(t, 0)
	tool := deletePolicyTool{clients.NewPCF(pcfURL, http.DefaultClient)}
	if _, err := tool.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001","dnn":"ims"}`)); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !pcf.has("DELETE /pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override?dnn=ims") {
		t.Errorf("DNN scope not sent: %v", pcf.calls)
	}
}

func TestPolicySetRejectsBadFiveQI(t *testing.T) {
	_, _, _, _, pcfURL, _ := upstreams(t, 0)
	tool := setPolicyTool{clients.NewPCF(pcfURL, http.DefaultClient)}
	_, err := tool.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001","5qi":255}`))
	if codeOf(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("5qi 200 is neither standardised nor operator-defined: want -32602")
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
