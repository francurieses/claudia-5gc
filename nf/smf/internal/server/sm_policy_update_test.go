package server

// sm_policy_update_test.go — SMF consults PCF on PDU Session Modification
// (SM Policy Association Update, TS 29.512 §5.2.2.3). Verifies the NW-initiated
// path applies a PCF-granted change and aborts on a PCF rejection.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newMockPCF returns a TLS test server emulating the PCF SM policy update endpoint
// and wires the SMF's SBI client + PCF peer to it.
func newMockPCF(t *testing.T, s *Server, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/update") {
			t.Errorf("unexpected PCF call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(ts.Close)
	s.httpClient = ts.Client()
	s.cfg.Peers.PCF = strings.TrimPrefix(ts.URL, "https://")
	return ts
}

// nwModify drives the NW-initiated policyUpdate path of handleUpdateSMContext.
func nwModify(s *Server, ref string, fiveQI int) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{
		"policyUpdate": true,
		"pduSessionId": 1,
		"fiveQI":       fiveQI,
	})
	r := httptest.NewRequest(http.MethodPost,
		"/nsmf-pdusession/v1/sm-contexts/"+ref+"/modify", strings.NewReader(string(body)))
	r.SetPathValue("smContextRef", ref)
	w := httptest.NewRecorder()
	s.handleUpdateSMContext(w, r)
	return w
}

// TestUpdateSMPolicyNWRejected: PCF returns 403 → SMF aborts with 403 and the
// session QoS is left unchanged.
func TestUpdateSMPolicyNWRejected(t *testing.T) {
	s := newTestSMFServer(t)
	sess := seedTestSession(s, "ref-1", 1, "imsi-001010000000001")
	sess.SmPolicyID = "pol-1"
	newMockPCF(t, s, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"cause": "REQUESTED_QOS_NOT_AUTHORIZED"})
	})

	w := nwModify(s, "ref-1", 1)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	s.sessionMu.Lock()
	got := sess.FiveQI
	s.sessionMu.Unlock()
	if got != 9 {
		t.Errorf("session 5qi after rejected modify: got %d want 9 (unchanged)", got)
	}
}

// TestUpdateSMPolicyNWGranted: PCF returns 200 with a granted 5QI → SMF applies it.
func TestUpdateSMPolicyNWGranted(t *testing.T) {
	s := newTestSMFServer(t)
	sess := seedTestSession(s, "ref-1", 1, "imsi-001010000000001")
	sess.SmPolicyID = "pol-1"
	newMockPCF(t, s, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"x5gcQosSource": "PCF_AUTHORIZED",
			"qosDecs":       map[string]any{"qd-1": map[string]any{"5qi": 7}},
		})
	})

	w := nwModify(s, "ref-1", 7)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	s.sessionMu.Lock()
	got := sess.FiveQI
	s.sessionMu.Unlock()
	if got != 7 {
		t.Errorf("session 5qi after granted modify: got %d want 7", got)
	}
}

// TestUpdateSMPolicyFailOpenNoPCF: with no PCF peer the consult fails open and the
// requested change is applied (no regression when PCF is absent).
func TestUpdateSMPolicyFailOpenNoPCF(t *testing.T) {
	s := newTestSMFServer(t) // cfg.Peers.PCF == ""
	sess := seedTestSession(s, "ref-1", 1, "imsi-001010000000001")
	sess.SmPolicyID = "pol-1"

	w := nwModify(s, "ref-1", 6)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	s.sessionMu.Lock()
	got := sess.FiveQI
	s.sessionMu.Unlock()
	if got != 6 {
		t.Errorf("session 5qi (fail-open): got %d want 6", got)
	}
}
