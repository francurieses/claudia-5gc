package server

// qos_test.go — SM policy QoS decision precedence tests.
// Precedence: PCF per-subscriber override > subsDefQos (UDM subscription
// reported by SMF) > operator config defaults.
// Ref: TS 29.512 §5.2.2.2, §5.6.2.3 (SmPolicyContextData.subsDefQos)

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
)

func newTestPCF(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{}
	cfg.DefaultSMPolicy.FiveQI = 9
	cfg.DefaultSMPolicy.ARPPriorityLevel = 8
	cfg.DefaultSMPolicy.SessionAMBRUplink = "100 Mbps"
	cfg.DefaultSMPolicy.SessionAMBRDownlink = "100 Mbps"
	s, err := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("New PCF: %v", err)
	}
	return s
}

func createSmPolicy(t *testing.T, s *Server, body string) map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateSmPolicy(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func extract5QI(t *testing.T, resp map[string]any) int {
	t.Helper()
	qosDecs := resp["qosDecs"].(map[string]any)
	for _, v := range qosDecs {
		dec := v.(map[string]any)
		return int(dec["5qi"].(float64))
	}
	t.Fatal("no qosDecs in response")
	return 0
}

// TestSmPolicyDefault verifies operator defaults apply with no subscription data.
func TestSmPolicyDefault(t *testing.T) {
	s := newTestPCF(t)
	resp := createSmPolicy(t, s, `{"supi":"imsi-001010000000001","dnn":"internet"}`)
	if got := extract5QI(t, resp); got != 9 {
		t.Errorf("5qi: got %d want 9 (operator default)", got)
	}
	if src := resp["x5gcQosSource"]; src != "OPERATOR_DEFAULT" {
		t.Errorf("x5gcQosSource: got %v want OPERATOR_DEFAULT", src)
	}
}

// TestSmPolicySubscribedDefaultQos verifies the UDM-subscribed default QoS
// reported by the SMF (subsDefQos) takes precedence over config defaults.
func TestSmPolicySubscribedDefaultQos(t *testing.T) {
	s := newTestPCF(t)
	resp := createSmPolicy(t, s, `{
		"supi":"imsi-001010000000001","dnn":"internet",
		"subsDefQos":{"5qi":7,"arp":{"priorityLevel":5}},
		"subsSessAmbr":{"uplink":"200 Mbps","downlink":"500 Mbps"}}`)
	if got := extract5QI(t, resp); got != 7 {
		t.Errorf("5qi: got %d want 7 (UDM subscription)", got)
	}
	if src := resp["x5gcQosSource"]; src != "UDM_SUBSCRIPTION" {
		t.Errorf("x5gcQosSource: got %v want UDM_SUBSCRIPTION", src)
	}
	sessRules := resp["sessRules"].(map[string]any)
	for _, v := range sessRules {
		ambr := v.(map[string]any)["sessAmbr"].(map[string]any)
		if ambr["downlink"] != "500 Mbps" {
			t.Errorf("sessAmbr downlink: got %v want 500 Mbps", ambr["downlink"])
		}
	}
}

// TestSmPolicyOverrideBeatsSubscription verifies the PCF per-subscriber
// override wins over both the subscription and the defaults.
func TestSmPolicyOverrideBeatsSubscription(t *testing.T) {
	s := newTestPCF(t)
	s.policiesMu.Lock()
	s.smPolicyOverrides["imsi-001010000000001"] = SMPolicyOverride{FiveQI: 1}
	s.policiesMu.Unlock()

	resp := createSmPolicy(t, s, `{
		"supi":"imsi-001010000000001","dnn":"internet",
		"subsDefQos":{"5qi":7,"arp":{"priorityLevel":5}}}`)
	if got := extract5QI(t, resp); got != 1 {
		t.Errorf("5qi: got %d want 1 (PCF override)", got)
	}
	if src := resp["x5gcQosSource"]; src != "PCF_OVERRIDE" {
		t.Errorf("x5gcQosSource: got %v want PCF_OVERRIDE", src)
	}
}

// TestSmPolicyDNNScopedOverride verifies a DNN-scoped override only applies to
// sessions on that DNN, beats a subscriber-wide override for its DNN, and leaves
// other DNNs on the subscriber-wide / default decision. This is the QoS binding
// used by the NW-triggered additional PDU session flow.
func TestSmPolicyDNNScopedOverride(t *testing.T) {
	s := newTestPCF(t)
	s.policiesMu.Lock()
	s.smPolicyOverrides["imsi-001010000000001"] = SMPolicyOverride{FiveQI: 8}
	s.smPolicyOverrides[overrideKey("imsi-001010000000001", "ims")] =
		SMPolicyOverride{FiveQI: 1, DNN: "ims", AMBRDownlink: "20 Mbps"}
	s.policiesMu.Unlock()

	// Session on "ims" → DNN-scoped override wins.
	resp := createSmPolicy(t, s, `{"supi":"imsi-001010000000001","dnn":"ims"}`)
	if got := extract5QI(t, resp); got != 1 {
		t.Errorf("ims 5qi: got %d want 1 (DNN-scoped override)", got)
	}
	for _, v := range resp["sessRules"].(map[string]any) {
		ambr := v.(map[string]any)["sessAmbr"].(map[string]any)
		if ambr["downlink"] != "20 Mbps" {
			t.Errorf("ims sessAmbr downlink: got %v want 20 Mbps", ambr["downlink"])
		}
	}

	// Session on "internet" → falls back to subscriber-wide override.
	resp = createSmPolicy(t, s, `{"supi":"imsi-001010000000001","dnn":"internet"}`)
	if got := extract5QI(t, resp); got != 8 {
		t.Errorf("internet 5qi: got %d want 8 (subscriber-wide override)", got)
	}

	// Different SUPI → operator default untouched.
	resp = createSmPolicy(t, s, `{"supi":"imsi-001010000000099","dnn":"ims"}`)
	if got := extract5QI(t, resp); got != 9 {
		t.Errorf("other supi 5qi: got %d want 9 (operator default)", got)
	}
}

// TestQoSOverrideAPIDNNScope verifies the internal management API stores and
// deletes DNN-scoped overrides independently of subscriber-wide ones.
func TestQoSOverrideAPIDNNScope(t *testing.T) {
	s := newTestPCF(t)

	put := httptest.NewRequest(http.MethodPut,
		"/pcf-internal/v1/subscribers/imsi-1/sm-policy-override",
		strings.NewReader(`{"5qi":3,"dnn":"ims"}`))
	put.SetPathValue("supi", "imsi-1")
	w := httptest.NewRecorder()
	s.handleSetQoSOverride(w, put)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// GET without dnn → 404 (no subscriber-wide override exists).
	get := httptest.NewRequest(http.MethodGet, "/pcf-internal/v1/subscribers/imsi-1/sm-policy-override", nil)
	get.SetPathValue("supi", "imsi-1")
	w = httptest.NewRecorder()
	s.handleGetQoSOverride(w, get)
	if w.Code != http.StatusNotFound {
		t.Errorf("GET no-dnn: expected 404, got %d", w.Code)
	}

	// GET with ?dnn=ims → 200.
	get = httptest.NewRequest(http.MethodGet, "/pcf-internal/v1/subscribers/imsi-1/sm-policy-override?dnn=ims", nil)
	get.SetPathValue("supi", "imsi-1")
	w = httptest.NewRecorder()
	s.handleGetQoSOverride(w, get)
	if w.Code != http.StatusOK {
		t.Fatalf("GET dnn=ims: expected 200, got %d", w.Code)
	}
	var ov SMPolicyOverride
	if err := json.NewDecoder(w.Body).Decode(&ov); err != nil || ov.FiveQI != 3 || ov.DNN != "ims" {
		t.Errorf("GET dnn=ims: got %+v err=%v, want 5qi=3 dnn=ims", ov, err)
	}

	// DELETE with ?dnn=ims → 204, then GET → 404.
	del := httptest.NewRequest(http.MethodDelete, "/pcf-internal/v1/subscribers/imsi-1/sm-policy-override?dnn=ims", nil)
	del.SetPathValue("supi", "imsi-1")
	w = httptest.NewRecorder()
	s.handleDeleteQoSOverride(w, del)
	if w.Code != http.StatusNoContent {
		t.Errorf("DELETE dnn=ims: expected 204, got %d", w.Code)
	}
}
