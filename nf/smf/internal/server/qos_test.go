package server

// qos_test.go — tests for 5QI selection precedence, the /nsmf-management QoS
// API, and the NW-initiated modification flow with a mock AMF.
// Ref: TS 23.502 §4.3.3.2, TS 29.503 §6.1.6.2.7, TS 24.501 §9.11.4.12/.13

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

func seedTestSession(s *Server, ref string, psi uint8, supi string) *Session {
	sess := &Session{
		SUPI:         supi,
		PDUSessionID: psi,
		DNN:          "internet",
		UEIP:         net.ParseIP("10.60.0.5"),
		ULTEID:       7,
		SEID:         42,
		SliceID:      SliceID{SST: 1, SD: "000001"},
		FiveQI:       9,
		AMBRULMbps:   100,
		AMBRDLMbps:   100,
		QoSSource:    QoSSourcePCFOverride,
		State:        "ACTIVE",
		CreatedAt:    time.Now(),
	}
	s.sessionMu.Lock()
	s.sessions[ref] = sess
	s.sessionMu.Unlock()
	return sess
}

// TestCreateSMPolicyFallbackUsesSubscription verifies that when the PCF is not
// configured/reachable, the UDM-subscribed default QoS is selected, and that
// without subscription data the operator default (5QI=9) applies.
func TestCreateSMPolicyFallbackUsesSubscription(t *testing.T) {
	s := newTestSMFServer(t) // cfg.Peers.PCF == "" → no PCF
	sub := &subscribedQoS{FiveQI: 7, ARPPriority: 5, AMBRULMbps: 200, AMBRDLMbps: 500}

	_, qos := s.createSMPolicy(t.Context(), "imsi-001010000000001", "internet", "", SliceID{SST: 1}, sub)
	if qos.FiveQI != 7 || qos.Source != QoSSourceUDMSubscription {
		t.Errorf("with subscription: got 5qi=%d source=%s, want 5qi=7 source=UDM_SUBSCRIPTION", qos.FiveQI, qos.Source)
	}
	if qos.AMBRDLMbps != 500 {
		t.Errorf("AMBR DL: got %d want 500", qos.AMBRDLMbps)
	}

	_, qos = s.createSMPolicy(t.Context(), "imsi-001010000000001", "internet", "", SliceID{SST: 1}, nil)
	if qos.FiveQI != 9 || qos.Source != QoSSourceOperatorDefault {
		t.Errorf("without subscription: got 5qi=%d source=%s, want 5qi=9 source=OPERATOR_DEFAULT", qos.FiveQI, qos.Source)
	}
}

// TestValidFiveQI checks the standardised + operator-defined 5QI validation.
func TestValidFiveQI(t *testing.T) {
	for _, v := range []int{1, 5, 9, 65, 70, 82, 85, 86, 128, 254} {
		if !ValidFiveQI(v) {
			t.Errorf("5QI %d: want valid", v)
		}
	}
	for _, v := range []int{0, -1, 11, 64, 100, 127, 255, 300} {
		if ValidFiveQI(v) {
			t.Errorf("5QI %d: want invalid", v)
		}
	}
}

// TestMgmtListSessions verifies GET /nsmf-management/v1/sessions returns the
// session view with 5QI, source, AMBR and slice.
func TestMgmtListSessions(t *testing.T) {
	s := newTestSMFServer(t)
	seedTestSession(s, "ref-1", 1, "imsi-001010000000001")

	r := httptest.NewRequest(http.MethodGet, "/nsmf-management/v1/sessions", nil)
	w := httptest.NewRecorder()
	s.handleMgmtListSessions(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Count    int           `json:"count"`
		Sessions []sessionView `json:"sessions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 || len(resp.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", resp.Count)
	}
	v := resp.Sessions[0]
	if v.SUPI != "imsi-001010000000001" || v.PDUSessionID != 1 || v.FiveQI != 9 ||
		v.QoSSource != QoSSourcePCFOverride || v.SNSSAI.SST != 1 || v.State != "ACTIVE" {
		t.Errorf("unexpected session view: %+v", v)
	}
}

// TestMgmtSetQoSValidation verifies input validation on the management endpoint.
func TestMgmtSetQoSValidation(t *testing.T) {
	s := newTestSMFServer(t)
	seedTestSession(s, "ref-1", 1, "imsi-001010000000001")

	cases := []struct {
		name string
		psi  string
		body string
		want int
	}{
		{"invalid 5qi", "1", `{"5qi":100,"reason":"test"}`, http.StatusBadRequest},
		{"missing reason", "1", `{"5qi":7}`, http.StatusBadRequest},
		{"unknown session", "5", `{"5qi":7,"reason":"test"}`, http.StatusNotFound},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodPost, "/nsmf-management/v1/sessions/"+tc.psi+"/qos",
			strings.NewReader(tc.body))
		r.SetPathValue("pduSessionId", tc.psi)
		w := httptest.NewRecorder()
		s.handleMgmtSetQoS(w, r)
		if w.Code != tc.want {
			t.Errorf("%s: got %d want %d: %s", tc.name, w.Code, tc.want, w.Body.String())
		}
	}
}

// TestMgmtSetQoSFullFlow exercises the complete NW-initiated modification loop:
// the management endpoint delegates to a mock AMF, which (like the real one)
// calls back into Nsmf_PDUSession_UpdateSMContext with policyUpdate=true; the
// SMF updates the session, and returns the 5GSM Modification Command with the
// new QoS rules / flow descriptions / AMBR.
func TestMgmtSetQoSFullFlow(t *testing.T) {
	s := newTestSMFServer(t)
	seedTestSession(s, "ref-1", 1, "imsi-001010000000001")

	var n1SmCmd []byte
	mockAMF := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || !strings.Contains(r.URL.Path, "/pdu-sessions/1/qos") {
			t.Errorf("unexpected AMF call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body struct {
			FiveQI     int `json:"5qi"`
			AMBRDLMbps int `json:"ambr_dl_mbps"`
			AMBRULMbps int `json:"ambr_ul_mbps"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		// Simulate the AMF's callback: Nsmf UpdateSMContext with policyUpdate.
		cbBody, _ := json.Marshal(map[string]any{
			"policyUpdate": true,
			"pduSessionId": 1,
			"fiveQI":       body.FiveQI,
			"ambrDLMbps":   body.AMBRDLMbps,
			"ambrULMbps":   body.AMBRULMbps,
		})
		cb := httptest.NewRequest(http.MethodPost,
			"/nsmf-pdusession/v1/sm-contexts/ref-1/modify", strings.NewReader(string(cbBody)))
		cb.SetPathValue("smContextRef", "ref-1")
		cw := httptest.NewRecorder()
		s.handleUpdateSMContext(cw, cb)
		if cw.Code != http.StatusOK {
			t.Errorf("policyUpdate callback: got %d: %s", cw.Code, cw.Body.String())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var cbResp struct {
			N1SmMsg string `json:"n1SmMsg"`
		}
		_ = json.NewDecoder(cw.Body).Decode(&cbResp)
		n1SmCmd, _ = base64.StdEncoding.DecodeString(cbResp.N1SmMsg)

		w.WriteHeader(http.StatusAccepted)
	}))
	defer mockAMF.Close()
	s.cfg.Peers.AMFMgmt = strings.TrimPrefix(mockAMF.URL, "http://")

	reqBody := `{"5qi":7,"reason":"upgrade to streaming","ambr_dl_mbps":200}`
	r := httptest.NewRequest(http.MethodPost, "/nsmf-management/v1/sessions/1/qos",
		strings.NewReader(reqBody))
	r.SetPathValue("pduSessionId", "1")
	w := httptest.NewRecorder()
	s.handleMgmtSetQoS(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Result      string `json:"result"`
		Previous5QI int    `json:"previous5qi"`
		New5QI      int    `json:"new5qi"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Result != "success" || resp.Previous5QI != 9 || resp.New5QI != 7 {
		t.Errorf("response: %+v, want success 9→7", resp)
	}

	// Session state updated, source marked as manual.
	s.sessionMu.Lock()
	sess := s.sessions["ref-1"]
	s.sessionMu.Unlock()
	if sess.FiveQI != 7 || sess.AMBRDLMbps != 200 || sess.QoSSource != QoSSourceManualOverride {
		t.Errorf("session after modify: 5qi=%d ambrDL=%d source=%s", sess.FiveQI, sess.AMBRDLMbps, sess.QoSSource)
	}

	// The N1SM Modification Command must carry the 0x2A/0x7A/0x79 IEs with 5QI 7.
	if len(n1SmCmd) < 4 || nas.MessageType(n1SmCmd[3]) != nas.MsgTypePDUSessionModificationCommand {
		t.Fatalf("n1SmMsg is not a Modification Command: % x", n1SmCmd)
	}
	body := n1SmCmd[4:]
	if body[0] != nas.IEISessionAMBR {
		t.Errorf("first IE: got 0x%02X want 0x2A (Session-AMBR)", body[0])
	}
	found5QI := -1
	for i := 0; i < len(body)-1; i++ {
		if body[i] == nas.IEIAuthorizedQoSFlowDesc {
			// IEI | len(2) | QFI | op | E+num | paramId | paramLen | 5QI
			if i+8 < len(body) && body[i+6] == 0x01 {
				found5QI = int(body[i+8])
			}
		}
	}
	if found5QI != 7 {
		t.Errorf("Modification Command flow description 5QI: got %d want 7", found5QI)
	}
}
