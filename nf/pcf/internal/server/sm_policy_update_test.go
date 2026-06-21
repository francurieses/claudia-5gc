package server

// sm_policy_update_test.go — SM Policy Association Update authorization tests
// (TS 29.512 §5.2.2.3). Mirrors the scenarios in features/sm_policy_update.feature.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// createPolicyID creates an SM policy via the create handler and returns its smPolicyId.
func createPolicyID(t *testing.T, s *Server, supi, dnn string) string {
	t.Helper()
	resp := createSmPolicy(t, s, `{"supi":"`+supi+`","dnn":"`+dnn+`"}`)
	id, _ := resp["smPolicyId"].(string)
	if id == "" {
		t.Fatal("create did not return an smPolicyId")
	}
	return id
}

// doUpdate posts an SM policy update and returns the recorder.
func doUpdate(s *Server, smPolicyId, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost,
		"/npcf-smpolicycontrol/v1/sm-policies/"+smPolicyId+"/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("smPolicyId", smPolicyId)
	w := httptest.NewRecorder()
	s.handleUpdateSmPolicy(w, r)
	return w
}

func updateDecision5QI(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	return extract5QI(t, resp)
}

// TestSmPolicyUpdateAuthorizedFiveQI: a 5QI in the authorized set is granted (200).
func TestSmPolicyUpdateAuthorizedFiveQI(t *testing.T) {
	s := newTestPCF(t)
	s.cfg.DefaultSMPolicy.Authorized5QI = []int{7, 8, 9}
	id := createPolicyID(t, s, "imsi-001010000000001", "internet")

	w := doUpdate(s, id, `{"reqQos":{"5qi":7}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := updateDecision5QI(t, w); got != 7 {
		t.Errorf("decision 5qi: got %d want 7", got)
	}
}

// TestSmPolicyUpdateRejectedFiveQI: a 5QI outside the authorized set is rejected (403).
func TestSmPolicyUpdateRejectedFiveQI(t *testing.T) {
	s := newTestPCF(t)
	s.cfg.DefaultSMPolicy.Authorized5QI = []int{8, 9}
	id := createPolicyID(t, s, "imsi-001010000000001", "internet")

	w := doUpdate(s, id, `{"reqQos":{"5qi":1}}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["cause"] != "REQUESTED_QOS_NOT_AUTHORIZED" {
		t.Errorf("cause: got %v want REQUESTED_QOS_NOT_AUTHORIZED", resp["cause"])
	}
}

// TestSmPolicyUpdateRejectedAMBR: a Session-AMBR over the ceiling is rejected (403).
func TestSmPolicyUpdateRejectedAMBR(t *testing.T) {
	s := newTestPCF(t)
	s.cfg.DefaultSMPolicy.MaxSessionAMBRMbps = 100
	id := createPolicyID(t, s, "imsi-001010000000001", "internet")

	w := doUpdate(s, id, `{"reqQos":{"5qi":9,"ambr":{"uplink":"500 Mbps","downlink":"100 Mbps"}}}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSmPolicyUpdateNoRestriction: an empty authorized set allows any valid 5QI.
func TestSmPolicyUpdateNoRestriction(t *testing.T) {
	s := newTestPCF(t) // Authorized5QI unset, MaxSessionAMBRMbps 0
	id := createPolicyID(t, s, "imsi-001010000000001", "internet")

	w := doUpdate(s, id, `{"reqQos":{"5qi":5}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := updateDecision5QI(t, w); got != 5 {
		t.Errorf("decision 5qi: got %d want 5", got)
	}
}

// TestSmPolicyUpdateOverrideWins: a per-subscriber override supersedes the requested value.
func TestSmPolicyUpdateOverrideWins(t *testing.T) {
	s := newTestPCF(t)
	s.cfg.DefaultSMPolicy.Authorized5QI = []int{7, 8, 9} // 7 would be authorized anyway
	id := createPolicyID(t, s, "imsi-001010000000001", "internet")
	s.policiesMu.Lock()
	s.smPolicyOverrides["imsi-001010000000001"] = SMPolicyOverride{FiveQI: 2}
	s.policiesMu.Unlock()

	w := doUpdate(s, id, `{"reqQos":{"5qi":7}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := updateDecision5QI(t, w); got != 2 {
		t.Errorf("decision 5qi: got %d want 2 (override wins)", got)
	}
	var resp map[string]any
	w2 := doUpdate(s, id, `{"reqQos":{"5qi":7}}`)
	_ = json.NewDecoder(w2.Body).Decode(&resp)
	if resp["x5gcQosSource"] != "PCF_OVERRIDE" {
		t.Errorf("x5gcQosSource: got %v want PCF_OVERRIDE", resp["x5gcQosSource"])
	}
}

// TestSmPolicyUpdateUnknownPolicy: an update for an unknown smPolicyId is 404.
func TestSmPolicyUpdateUnknownPolicy(t *testing.T) {
	s := newTestPCF(t)
	w := doUpdate(s, "does-not-exist", `{"reqQos":{"5qi":7}}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["cause"] != "CONTEXT_NOT_FOUND" {
		t.Errorf("cause: got %v want CONTEXT_NOT_FOUND", resp["cause"])
	}
}
