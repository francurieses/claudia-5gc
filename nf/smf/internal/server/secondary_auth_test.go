package server

// secondary_auth_test.go — Secondary Authentication / DN-AAA state machine
// tests (TS 23.501 §5.6.6, TS 23.502 §4.3.2.3).
//
// UERANSIM v3.2.8 has no secondary-authentication UE peer, so — like NSSAA
// and EAP-AKA' — these tests exercise the network-side state machine and NAS
// encoding directly against the HTTP handlers (same pattern as
// smf_modify_test.go / qos_test.go), not a live E2E UE round-trip. The
// N1N2MessageTransfer push towards the AMF is captured via the
// Server.n1n2Push test seam instead of a live mTLS peer.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// secondaryAuthDNN is the DNN configured with secondary_auth: true in the
// tests below.
const secondaryAuthDNN = "secure-corp"

// n1n2Call records one push made through Server.n1n2Push.
type n1n2Call struct {
	SUPI         string
	PSI          uint8
	N1SmMsg      []byte
	N2SmInfo     []byte
	N2SmInfoType string
}

func newSecondaryAuthTestServer(t *testing.T, dnaaaUnreachable bool) (*Server, *[]n1n2Call) {
	t.Helper()
	cfg := &config.Config{
		UEIPPool: "10.60.0.0/24",
		DNNs: []config.DNNConfig{
			{Name: "internet", UEIPPool: "10.60.0.0/24"},
			{Name: secondaryAuthDNN, UEIPPool: "10.70.0.0/24", SecondaryAuth: true, DNAAAUnreachable: dnaaaUnreachable},
		},
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)), nil)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	var calls []n1n2Call
	s.n1n2Push = func(_ context.Context, supi string, psi uint8, n1SmMsg, n2SmInfo []byte, n2SmInfoType string) (string, error) {
		calls = append(calls, n1n2Call{SUPI: supi, PSI: psi, N1SmMsg: n1SmMsg, N2SmInfo: n2SmInfo, N2SmInfoType: n2SmInfoType})
		return "N1_N2_TRANSFER_INITIATED", nil
	}
	return s, &calls
}

// buildEstablishmentRequest builds a minimal 5GSM PDU Session Establishment
// Request n1SmMsg (EPD|PSI|PTI|0xC1| 2-octet mandatory IPMDR, no optional IEs).
func buildEstablishmentRequest(psi, pti uint8) []byte {
	msg := []byte{nas.PDGroupSessionManagement, psi, pti, byte(nas.MsgTypePDUSessionEstablishmentRequest)}
	return append(msg, 0xFF, 0xFF) // Integrity Protection Max Data Rate (2B, don't-care)
}

func createSMContext(t *testing.T, s *Server, supi, dnn string, psi, pti uint8) *httptest.ResponseRecorder {
	t.Helper()
	reqBody, _ := json.Marshal(map[string]interface{}{
		"supi":         supi,
		"dnn":          dnn,
		"pduSessionId": float64(psi),
		"n1SmMsg":      base64.StdEncoding.EncodeToString(buildEstablishmentRequest(psi, pti)),
	})
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts", strings.NewReader(string(reqBody)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateSMContext(w, r)
	return w
}

func sendAuthComplete(t *testing.T, s *Server, smContextRef string, psi, pti uint8, eapResp []byte) *httptest.ResponseRecorder {
	t.Helper()
	n1SmMsg := nas.WrapPDUSessionAuthenticationCompleteBody(psi, pti, eapResp)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"n1SmMsg":      base64.StdEncoding.EncodeToString(n1SmMsg),
		"pduSessionId": float64(psi),
	})
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/"+smContextRef+"/modify", strings.NewReader(string(reqBody)))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("smContextRef", smContextRef)
	w := httptest.NewRecorder()
	s.handleUpdateSMContext(w, r)
	return w
}

// TestSecondaryAuth_NoRegressionWhenNotRequired proves a DNN without
// secondary_auth establishes exactly as before: no AUTH COMMAND, straight to
// an Establishment Accept with no EAP message IE and an immediate N4 session.
func TestSecondaryAuth_NoRegressionWhenNotRequired(t *testing.T) {
	s, calls := newSecondaryAuthTestServer(t, false)
	const supi = "imsi-001010000000001"

	w := createSMContext(t, s, supi, "internet", 1, 5)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	n1B64, ok := resp["n1SmMsg"].(string)
	if !ok || n1B64 == "" {
		t.Fatal("expected n1SmMsg (Establishment Accept) in the immediate CreateSMContext response")
	}
	n1Bytes, err := base64.StdEncoding.DecodeString(n1B64)
	if err != nil {
		t.Fatalf("base64 decode n1SmMsg: %v", err)
	}
	// The non-gated encoder returns the ACCEPT BODY only (no 5GSM header) —
	// unchanged historical convention; message-type framing is added by AMF.
	if len(n1Bytes) == 0 {
		t.Fatal("n1SmMsg body must not be empty")
	}
	if nas.IEIEAPMessage == n1Bytes[0] {
		t.Error("no EAP message IE should be present for a DNN that does not require secondary auth")
	}

	// No pending secondary auth was ever created, and no AUTH COMMAND pushed.
	if p := s.getPendingAuth("does-not-matter"); p != nil {
		t.Error("no pending secondary auth expected")
	}
	if len(*calls) != 0 {
		t.Errorf("no N1N2MessageTransfer push expected for a non-gated DNN, got %d", len(*calls))
	}

	// The session was created synchronously (ACTIVE) — no PENDING_SECONDARY_AUTH.
	s.sessionMu.Lock()
	var found *Session
	for _, sess := range s.sessions {
		if sess.SUPI == supi {
			found = sess
		}
	}
	s.sessionMu.Unlock()
	if found == nil || found.State != "ACTIVE" {
		t.Fatalf("expected an ACTIVE session immediately, got %+v", found)
	}
}

// TestSecondaryAuth_HappyPath_EAPSuccess exercises the full gated flow: AUTH
// COMMAND on CreateSMContext, AUTH COMPLETE with a non-"reject" identity
// authorized by the simulated DN-AAA, and the resulting ESTABLISHMENT ACCEPT
// carrying EAP-Success in IEI 0x78 plus an active ACTIVE session.
func TestSecondaryAuth_HappyPath_EAPSuccess(t *testing.T) {
	s, calls := newSecondaryAuthTestServer(t, false)
	const supi = "imsi-001010000000002"
	const psi, pti uint8 = 1, 9

	w := createSMContext(t, s, supi, secondaryAuthDNN, psi, pti)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var createResp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &createResp)
	smContextRef, _ := createResp["smContextRef"].(string)
	if smContextRef == "" {
		t.Fatal("expected smContextRef in response")
	}
	if _, present := createResp["n1SmMsg"]; present {
		t.Error("CreateSMContext response must not carry n1SmMsg while secondary auth is pending")
	}

	// AUTH COMMAND must have been pushed with EAP-Request/Identity.
	if len(*calls) != 1 {
		t.Fatalf("expected exactly 1 push (AUTH COMMAND), got %d", len(*calls))
	}
	authCmd := (*calls)[0]
	if len(authCmd.N1SmMsg) < 4 || nas.MessageType(authCmd.N1SmMsg[3]) != nas.MsgTypePDUSessionAuthenticationCommand {
		t.Fatalf("expected AUTH COMMAND (0xC5), got % X", authCmd.N1SmMsg)
	}
	eapReqPkt, err := nas.DecodePDUSessionAuthenticationCommandBody(authCmd.N1SmMsg[4:])
	if err != nil {
		t.Fatalf("decode AUTH COMMAND body: %v", err)
	}
	if code, _ := eap.Code(eapReqPkt); code != eap.CodeRequest {
		t.Errorf("expected EAP-Request, got code %d", code)
	}

	// Pending state recorded.
	pending := s.getPendingAuth(smContextRef)
	if pending == nil || pending.State != authStatePendingAuth {
		t.Fatalf("expected PENDING_AUTH state, got %+v", pending)
	}

	// UE responds with a non-reject identity — DN-AAA authorizes.
	eapResp := eap.BuildIdentityResponse(1, "user@secure-corp")
	w2 := sendAuthComplete(t, s, smContextRef, psi, pti, eapResp)
	if w2.Code != http.StatusOK {
		t.Fatalf("AUTH COMPLETE: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	if s.getPendingAuth(smContextRef) != nil {
		t.Error("pending secondary auth should be cleared after authorization")
	}
	if len(*calls) != 2 {
		t.Fatalf("expected 2 pushes (AUTH COMMAND + ESTABLISHMENT ACCEPT), got %d", len(*calls))
	}
	accept := (*calls)[1]
	if len(accept.N1SmMsg) < 4 || nas.MessageType(accept.N1SmMsg[3]) != nas.MsgTypePDUSessionEstablishmentAccept {
		t.Fatalf("expected ESTABLISHMENT ACCEPT (0xC2), got % X", accept.N1SmMsg)
	}
	if accept.N1SmMsg[1] != psi || accept.N1SmMsg[2] != pti {
		t.Errorf("PSI/PTI not echoed: got psi=%d pti=%d want psi=%d pti=%d",
			accept.N1SmMsg[1], accept.N1SmMsg[2], psi, pti)
	}
	if len(accept.N2SmInfo) == 0 {
		t.Error("expected non-empty N2SM Resource Setup Request Transfer on the ACCEPT push")
	}

	// The EAP message IE (0x78) must be ordered *before* the Authorized QoS
	// flow descriptions IE (0x79) and the DNN IE (0x25), per TS 24.501 §8.3.2
	// Table 8.3.2.1.1 — walk the optional IEs and assert the byte offsets are
	// strictly increasing in that order (regression test for the "EAP IE
	// appended last" wire-conformance bug).
	body := accept.N1SmMsg[4:]
	offsets := optionalIEOffsets(t, body)
	eapOffset, ok := offsets[nas.IEIEAPMessage]
	if !ok {
		t.Fatalf("expected EAP message IE (0x78) in the ACCEPT body: % X", body)
	}
	qosFlowOffset, ok := offsets[nas.IEIAuthorizedQoSFlowDesc]
	if !ok {
		t.Fatalf("expected Authorized QoS flow descriptions IE (0x79) in the ACCEPT body: % X", body)
	}
	dnnOffset, ok := offsets[nas.IEIDNN5GSM]
	if !ok {
		t.Fatalf("expected DNN IE (0x25) in the ACCEPT body: % X", body)
	}
	if !(eapOffset < qosFlowOffset && qosFlowOffset < dnnOffset) {
		t.Fatalf("IE order violation (TS 24.501 §8.3.2 Table 8.3.2.1.1): "+
			"want EAP(0x78)@%d < QoSFlowDesc(0x79)@%d < DNN(0x25)@%d",
			eapOffset, qosFlowOffset, dnnOffset)
	}

	eapTLVE := body[eapOffset:]
	eapIE, _, err := nas.DecodeEAPMessageTLVE(eapTLVE)
	if err != nil {
		t.Fatalf("decode EAP message TLV-E: %v", err)
	}
	if code, _ := eap.Code(eapIE); code != eap.CodeSuccess {
		t.Errorf("expected EAP-Success in ESTABLISHMENT ACCEPT, got code %d", code)
	}

	// The session is now ACTIVE with the reserved IP.
	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()
	if sess == nil || sess.State != "ACTIVE" || sess.UEIP == nil {
		t.Fatalf("expected an ACTIVE session with an allocated IP, got %+v", sess)
	}
	if !strings.HasPrefix(sess.UEIP.String(), "10.70.0.") {
		t.Errorf("UE IP not from the secure-corp pool: %s", sess.UEIP)
	}
}

// TestSecondaryAuth_EAPFailureRejects verifies the DN-AAA EAP-Failure branch:
// no N4 session, ESTABLISHMENT REJECT with 5GSM cause 29 and EAP-Failure in
// IEI 0x78, and the reserved UE IP released back to the pool.
func TestSecondaryAuth_EAPFailureRejects(t *testing.T) {
	s, calls := newSecondaryAuthTestServer(t, false)
	const supi = "imsi-001010000000003"
	const psi, pti uint8 = 1, 3

	w := createSMContext(t, s, supi, secondaryAuthDNN, psi, pti)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var createResp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &createResp)
	smContextRef := createResp["smContextRef"].(string)

	pending := s.getPendingAuth(smContextRef)
	if pending == nil {
		t.Fatal("expected pending secondary auth")
	}
	reservedIP := pending.IPv4.String()

	// Identity containing "reject" — the simulated DN-AAA returns EAP-Failure.
	eapResp := eap.BuildIdentityResponse(1, "reject@secure-corp")
	w2 := sendAuthComplete(t, s, smContextRef, psi, pti, eapResp)
	if w2.Code != http.StatusOK {
		t.Fatalf("AUTH COMPLETE: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	if s.getPendingAuth(smContextRef) != nil {
		t.Error("pending secondary auth should be cleared after rejection")
	}
	s.sessionMu.Lock()
	_, sessionExists := s.sessions[smContextRef]
	s.sessionMu.Unlock()
	if sessionExists {
		t.Error("no session should exist after a rejected secondary authentication")
	}

	if len(*calls) != 2 {
		t.Fatalf("expected 2 pushes (AUTH COMMAND + ESTABLISHMENT REJECT), got %d", len(*calls))
	}
	reject := (*calls)[1]
	if len(reject.N1SmMsg) < 5 || nas.MessageType(reject.N1SmMsg[3]) != nas.MsgTypePDUSessionEstablishmentReject {
		t.Fatalf("expected ESTABLISHMENT REJECT (0xC3), got % X", reject.N1SmMsg)
	}
	if reject.N1SmMsg[4] != nas.Cause5GSMUserAuthOrAuthorizationFailed {
		t.Errorf("5GSM cause: got %d want %d (29)", reject.N1SmMsg[4], nas.Cause5GSMUserAuthOrAuthorizationFailed)
	}
	if len(reject.N2SmInfo) != 0 {
		t.Error("no N2SM info should accompany a REJECT — no N4 session was created")
	}
	eapIE, _, err := nas.DecodeEAPMessageTLVE(reject.N1SmMsg[5:])
	if err != nil {
		t.Fatalf("decode EAP-Failure TLV-E: %v", err)
	}
	if code, _ := eap.Code(eapIE); code != eap.CodeFailure {
		t.Errorf("expected EAP-Failure in ESTABLISHMENT REJECT, got code %d", code)
	}

	// The reserved IP must have been released back to the pool.
	pool := s.ipPools[secondaryAuthDNN]
	if got, err := pool.Allocate(); err != nil || got.String() != reservedIP {
		t.Errorf("expected the released IP %s to be reallocated first, got %v (err=%v)", reservedIP, got, err)
	}
}

// TestSecondaryAuth_DNAAAUnreachableRejects verifies the timeout/unreachable
// branch: 5GSM cause 29, no N4 session, IP released — same as EAP-Failure but
// with no EAP message IE (optional, TS 24.501 §9.11.4.2).
func TestSecondaryAuth_DNAAAUnreachableRejects(t *testing.T) {
	s, calls := newSecondaryAuthTestServer(t, true /* DN-AAA unreachable */)
	const supi = "imsi-001010000000004"
	const psi, pti uint8 = 1, 4

	w := createSMContext(t, s, supi, secondaryAuthDNN, psi, pti)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var createResp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &createResp)
	smContextRef := createResp["smContextRef"].(string)

	eapResp := eap.BuildIdentityResponse(1, "user@secure-corp") // identity itself is fine — DN-AAA is unreachable
	w2 := sendAuthComplete(t, s, smContextRef, psi, pti, eapResp)
	if w2.Code != http.StatusOK {
		t.Fatalf("AUTH COMPLETE: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	s.sessionMu.Lock()
	_, sessionExists := s.sessions[smContextRef]
	s.sessionMu.Unlock()
	if sessionExists {
		t.Error("no session should exist after a DN-AAA-unreachable rejection")
	}

	if len(*calls) != 2 {
		t.Fatalf("expected 2 pushes (AUTH COMMAND + ESTABLISHMENT REJECT), got %d", len(*calls))
	}
	reject := (*calls)[1]
	if nas.MessageType(reject.N1SmMsg[3]) != nas.MsgTypePDUSessionEstablishmentReject {
		t.Fatalf("expected ESTABLISHMENT REJECT (0xC3), got % X", reject.N1SmMsg)
	}
	if reject.N1SmMsg[4] != nas.Cause5GSMUserAuthOrAuthorizationFailed {
		t.Errorf("5GSM cause: got %d want 29", reject.N1SmMsg[4])
	}
	// EAP message IE is optional and omitted on the unreachable/timeout path
	// (no terminal EAP packet was ever obtained from the DN-AAA).
	if len(reject.N1SmMsg) != 5 {
		t.Errorf("expected a 5-byte REJECT with no EAP IE, got %d bytes: % X", len(reject.N1SmMsg), reject.N1SmMsg)
	}
}

// decodeOptionalIEOffsets walks the PDU SESSION ESTABLISHMENT ACCEPT body
// (after the fixed EPD|PSI|PTI|MT header) past the mandatory Selected SSC
// mode/PDU-session-type octet, the mandatory Authorized QoS rules (LV-E) and
// the mandatory Session-AMBR (LV), then decodes each self-describing optional
// IE — TLV (1-octet length) for PDU address/S-NSSAI/DNN, TLV-E (2-octet
// length) for EAP message/Authorized QoS flow descriptions — recording the
// byte offset (within body) at which each IEI starts. Used by both the
// table-driven unit tests and the godog step definitions to assert IE
// ordering against TS 24.501 §8.3.2 Table 8.3.2.1.1 without hardcoding
// lengths that depend on QoS-rule/AMBR/PDU-address encoding details.
func decodeOptionalIEOffsets(body []byte) (map[byte]int, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("ACCEPT body too short: % X", body)
	}
	i := 1 // Selected SSC mode | Selected PDU session type

	if i+2 > len(body) {
		return nil, fmt.Errorf("ACCEPT body truncated before Authorized QoS rules length: % X", body)
	}
	qosRulesLen := int(body[i])<<8 | int(body[i+1])
	i += 2 + qosRulesLen

	if i+1 > len(body) {
		return nil, fmt.Errorf("ACCEPT body truncated before Session-AMBR length: % X", body)
	}
	ambrLen := int(body[i])
	i += 1 + ambrLen

	offsets := make(map[byte]int)
	for i < len(body) {
		iei := body[i]
		offsets[iei] = i
		switch iei {
		case nas.IEIPDUAddress, nas.IEISNSSAI5GSM, nas.IEIDNN5GSM:
			if i+1 >= len(body) {
				return nil, fmt.Errorf("TLV IE 0x%02X truncated at offset %d: % X", iei, i, body)
			}
			l := int(body[i+1])
			i += 2 + l
		case nas.IEICause5GSM: // TV: IEI + 1-octet cause value (session-type downgrade)
			i += 2
		case nas.IEIEAPMessage, nas.IEIAuthorizedQoSFlowDesc, nas.IEIEPCO:
			if i+2 >= len(body) {
				return nil, fmt.Errorf("TLV-E IE 0x%02X truncated at offset %d: % X", iei, i, body)
			}
			l := int(body[i+1])<<8 | int(body[i+2])
			i += 3 + l
		default:
			return nil, fmt.Errorf("unexpected optional IEI 0x%02X at offset %d in ACCEPT body: % X", iei, i, body)
		}
	}
	return offsets, nil
}

// optionalIEOffsets walks the PDU SESSION ESTABLISHMENT ACCEPT body via
// decodeOptionalIEOffsets and fails the test on any decode error. Test-only
// convenience wrapper — see decodeOptionalIEOffsets (secondary_auth.go
// helpers, shared with the godog step definitions) for the walking logic.
func optionalIEOffsets(t *testing.T, body []byte) map[byte]int {
	t.Helper()
	offsets, err := decodeOptionalIEOffsets(body)
	if err != nil {
		t.Fatal(err)
	}
	return offsets
}

// TestSecondaryAuthComplete_UnknownSmContext verifies a 404 when the AUTH
// COMPLETE arrives for an sm context with no pending secondary authentication.
func TestSecondaryAuthComplete_UnknownSmContext(t *testing.T) {
	s, _ := newSecondaryAuthTestServer(t, false)
	eapResp := eap.BuildIdentityResponse(1, "user@secure-corp")
	w := sendAuthComplete(t, s, "no-such-context", 1, 1, eapResp)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}
