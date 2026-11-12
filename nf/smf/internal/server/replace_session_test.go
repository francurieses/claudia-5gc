package server

// replace_session_test.go — a repeated PDU Session Establishment for the same
// SUPI + PDU Session ID replaces the old SM context (one session remains, old
// IP freed, old N4 session deleted).
// Ref: TS 23.502 §4.3.2.2.1 step 1, TS 24.501 §6.4.1.2.

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReleaseStaleSessions_SameSUPIAndPSI(t *testing.T) {
	s := newActivationTestServer(t)
	ip, err := s.ipPools["internet"].Allocate()
	if err != nil {
		t.Fatal(err)
	}
	other := net.ParseIP("10.60.0.200")
	s.sessionMu.Lock()
	s.sessions["old"] = &Session{SUPI: "imsi-1", PDUSessionID: 1, DNN: "internet", UEIP: ip, SEID: 5, N4Stale: true}
	s.sessions["psi2"] = &Session{SUPI: "imsi-1", PDUSessionID: 2, DNN: "internet", UEIP: other, N4Stale: true}
	s.sessions["supi2"] = &Session{SUPI: "imsi-2", PDUSessionID: 1, DNN: "internet", UEIP: other, N4Stale: true}
	s.sessionMu.Unlock()

	s.releaseStaleSessions(t.Context(), s.logger, "imsi-1", 1)

	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if _, ok := s.sessions["old"]; ok {
		t.Fatal("old session for same SUPI/PSI must be released")
	}
	if len(s.sessions) != 2 {
		t.Fatalf("other sessions must be untouched, have %d", len(s.sessions))
	}
	again, err := s.ipPools["internet"].Allocate()
	if err != nil || !again.Equal(ip) {
		t.Fatalf("old IP %v must be freed and reused, got %v (%v)", ip, again, err)
	}
}

func TestHandleCreateSMContext_ReestablishmentLeavesOneSession(t *testing.T) {
	s := newActivationTestServer(t)
	create := func() string {
		body := `{"supi":"imsi-001010000000001","dnn":"internet","pduSessionId":1,"snssai":{"sst":1}}`
		r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.handleCreateSMContext(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", w.Code, w.Body.String())
		}
		var resp struct {
			SmContextRef string `json:"smContextRef"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return resp.SmContextRef
	}
	first := create()
	// Mark N4 stale so the test sends no PFCP.
	s.sessionMu.Lock()
	first0 := s.sessions[first]
	first0.N4Stale = true
	ip1 := first0.UEIP.String()
	s.sessionMu.Unlock()
	second := create()
	time.Sleep(10 * time.Millisecond)

	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if len(s.sessions) != 1 || s.sessions[second] == nil || s.sessions[first] != nil {
		t.Fatalf("want exactly the new session, have %d", len(s.sessions))
	}
	if got := s.sessions[second].UEIP.String(); got != ip1 {
		t.Logf("note: IP changed %s -> %s", ip1, got)
	}
}
