package server

// capability_5gsm_test.go - the 5GSM capability IE of the PDU Session
// Establishment Request is stored on the Session (REL19-5.4).
// Ref: TS 24.501 §9.11.4.1

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestCreateSMContext_Stores5GSMCapability(t *testing.T) {
	s := newGoldenServer(t)
	n1 := append(buildEstablishmentRequest(1, 5), 0x28, 0x02, 0x07, 0x10) // RQoS|MH6|EPT-S1, ATSSS-LL=2
	w := postCreateSMContext(t, s, map[string]any{"n1SmMsg": base64.StdEncoding.EncodeToString(n1)})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	ref, _ := body["smContextRef"].(string)
	s.sessionMu.Lock()
	sess := s.sessions[ref]
	s.sessionMu.Unlock()
	if sess == nil || sess.Capability5GSM == nil {
		t.Fatalf("capability not stored: %+v", sess)
	}
	c := sess.Capability5GSM
	if !c.RQoS || !c.MH6PDU || !c.EPTS1 || c.ATSSSLL != 2 {
		t.Errorf("wrong decode: %+v", c)
	}
}

func TestCreateSMContext_No5GSMCapability(t *testing.T) {
	s := newGoldenServer(t)
	w := postCreateSMContext(t, s, nil)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	ref, _ := body["smContextRef"].(string)
	s.sessionMu.Lock()
	sess := s.sessions[ref]
	s.sessionMu.Unlock()
	if sess == nil || sess.Capability5GSM != nil {
		t.Fatalf("want session without capability, got %+v", sess)
	}
}

// TestSecondaryAuth_DeferredSessionKeeps5GSMCapability proves the Session
// created after secondary authorization carries the UE's 5GSM capability.
func TestSecondaryAuth_DeferredSessionKeeps5GSMCapability(t *testing.T) {
	s, _ := newSecondaryAuthTestServer(t, false)
	const supi = "imsi-001010000000003"
	const psi, pti uint8 = 1, 9
	n1 := append(buildEstablishmentRequest(psi, pti), 0x28, 0x02, 0x07, 0x10)
	reqBody, _ := json.Marshal(map[string]any{
		"supi":         supi,
		"dnn":          secondaryAuthDNN,
		"pduSessionId": float64(psi),
		"n1SmMsg":      base64.StdEncoding.EncodeToString(n1),
	})
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts", strings.NewReader(string(reqBody)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateSMContext(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	ref, _ := resp["smContextRef"].(string)
	if p := s.getPendingAuth(ref); p == nil || p.Capability5GSM == nil {
		t.Fatalf("pending auth lost capability: %+v", p)
	}
	w2 := sendAuthComplete(t, s, ref, psi, pti, eap.BuildIdentityResponse(1, "user@secure-corp"))
	if w2.Code != http.StatusOK {
		t.Fatalf("AUTH COMPLETE: %d: %s", w2.Code, w2.Body.String())
	}
	s.sessionMu.Lock()
	sess := s.sessions[ref]
	s.sessionMu.Unlock()
	if sess == nil || sess.Capability5GSM == nil {
		t.Fatalf("deferred session lost capability: %+v", sess)
	}
	if c := sess.Capability5GSM; !c.RQoS || !c.MH6PDU || !c.EPTS1 || c.ATSSSLL != 2 {
		t.Errorf("wrong capability: %+v", c)
	}
}

// TestCreateSMContext_Stores5GSMCapabilityRel18Rel19 sends a real PDU SESSION
// ESTABLISHMENT REQUEST (EPD, PSI, PTI, type 0xC1, max data rate, 5GSM
// capability IEI 0x28 with 3 octets) through the Nsmf CreateSMContext handler
// and checks the Rel-18/19 bits reach the stored Session (REL19-5.4).
// Octet 3 = 0x05 (RQoS, EPT-S1); octet 4 = 0xE6 (SDNAEPC, RTPMMII, MPTCP,
// MPQUIC-UDP, MPQUIC-IP); octet 5 = 0x03 (MPQUIC-E, E8PCPDEI).
// Ref: TS 24.501 §8.3.1, §9.11.4.1 Table 9.11.4.1.1
func TestCreateSMContext_Stores5GSMCapabilityRel18Rel19(t *testing.T) {
	s := newGoldenServer(t)
	n1 := append(buildEstablishmentRequest(1, 5), 0x28, 0x03, 0x05, 0xE6, 0x03)
	w := postCreateSMContext(t, s, map[string]any{"n1SmMsg": base64.StdEncoding.EncodeToString(n1)})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	ref, _ := body["smContextRef"].(string)
	s.sessionMu.Lock()
	sess := s.sessions[ref]
	s.sessionMu.Unlock()
	if sess == nil || sess.Capability5GSM == nil {
		t.Fatalf("capability not stored: %+v", sess)
	}
	c := sess.Capability5GSM
	if !c.RQoS || !c.EPTS1 || !c.SDNAEPC || !c.RTPMMII || !c.MPTCP || !c.MPQUICUDP || !c.MPQUICIP || !c.MPQUICE || !c.E8PCPDEI {
		t.Errorf("Rel-18/19 bits not decoded: %+v", c)
	}
	if c.MH6PDU || c.TPMIC || c.APMQF {
		t.Errorf("unset bits read as set: %+v", c)
	}
}

// TestSessionView_Capability5GSM: the management session view exposes the hex
// value and set-bit names ("" and [] when absent). Ref: TS 24.501 §9.11.4.1
func TestSessionView_Capability5GSM(t *testing.T) {
	s := newGoldenServer(t)
	v := s.sessionToView("ref", &Session{})
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), `"capability5gsm":""`) || !strings.Contains(string(b), `"capability5gsmBits":[]`) {
		t.Errorf("absent capability JSON: %s", b)
	}
	c, err := nas.Decode5GSMCapability([]byte{0x07, 0x10})
	if err != nil {
		t.Fatal(err)
	}
	v = s.sessionToView("ref", &Session{Capability5GSM: c})
	if v.Capability5GSM != "0710" || len(v.Capability5GSMBits) == 0 {
		t.Errorf("view = %q %v", v.Capability5GSM, v.Capability5GSMBits)
	}
}
