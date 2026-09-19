package nas

import (
	"bytes"
	"testing"
)

// TestPDUSessionAuthenticationCommandRoundTrip verifies byte-exact
// encode/decode of the AUTH COMMAND (0xC5) body and full message.
// Ref: TS 24.501 §8.3.5.
func TestPDUSessionAuthenticationCommandRoundTrip(t *testing.T) {
	eapReq := []byte{0x01, 0x01, 0x00, 0x05, 0x01} // EAP-Request/Identity, id=1

	body := EncodePDUSessionAuthenticationCommandBody(eapReq)
	wantBody := []byte{0x00, 0x05, 0x01, 0x01, 0x00, 0x05, 0x01} // LV-E length(2) + EAP
	if !bytes.Equal(body, wantBody) {
		t.Fatalf("body: got % X want % X", body, wantBody)
	}

	decoded, err := DecodePDUSessionAuthenticationCommandBody(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded, eapReq) {
		t.Errorf("decoded EAP: got % X want % X", decoded, eapReq)
	}

	full := WrapPDUSessionAuthenticationCommandBody(1, 7, eapReq)
	wantFull := []byte{PDGroupSessionManagement, 1, 7, byte(MsgTypePDUSessionAuthenticationCommand)}
	wantFull = append(wantFull, wantBody...)
	if !bytes.Equal(full, wantFull) {
		t.Fatalf("full message: got % X want % X", full, wantFull)
	}
}

// TestPDUSessionAuthenticationCompleteRoundTrip verifies the AUTH COMPLETE
// (0xC6) codec. Ref: TS 24.501 §8.3.6.
func TestPDUSessionAuthenticationCompleteRoundTrip(t *testing.T) {
	eapResp := []byte{0x02, 0x01, 0x00, 0x0C, 0x01, 'u', 's', 'e', 'r', '@', 'd', 'n'} // EAP-Response/Identity

	full := WrapPDUSessionAuthenticationCompleteBody(3, 2, eapResp)
	if full[0] != PDGroupSessionManagement || full[1] != 3 || full[2] != 2 ||
		MessageType(full[3]) != MsgTypePDUSessionAuthenticationComplete {
		t.Fatalf("unexpected header: % X", full[:4])
	}

	decoded, err := DecodePDUSessionAuthenticationCompleteBody(full[4:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded, eapResp) {
		t.Errorf("decoded EAP: got % X want % X", decoded, eapResp)
	}
}

// TestPDUSessionAuthenticationResultRoundTrip verifies the AUTH RESULT
// (0xC7) codec. Ref: TS 24.501 §8.3.7.
func TestPDUSessionAuthenticationResultRoundTrip(t *testing.T) {
	eapSuccess := []byte{0x03, 0x01, 0x00, 0x04} // EAP-Success

	full := WrapPDUSessionAuthenticationResultBody(1, 0, eapSuccess)
	if MessageType(full[3]) != MsgTypePDUSessionAuthenticationResult {
		t.Fatalf("message type: got 0x%02X want 0x%02X", full[3], byte(MsgTypePDUSessionAuthenticationResult))
	}
	decoded, err := DecodePDUSessionAuthenticationResultBody(full[4:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded, eapSuccess) {
		t.Errorf("decoded EAP: got % X want % X", decoded, eapSuccess)
	}
}

// TestEAPMessageTLVERoundTrip verifies the optional TLV-E EAP message IE
// (IEI 0x78) used in ESTABLISHMENT ACCEPT/REJECT. Ref: TS 24.501 §9.11.2.2.
func TestEAPMessageTLVERoundTrip(t *testing.T) {
	eapSuccess := []byte{0x03, 0x01, 0x00, 0x04}

	ie := EncodeEAPMessageTLVE(eapSuccess)
	want := []byte{IEIEAPMessage, 0x00, 0x04, 0x03, 0x01, 0x00, 0x04}
	if !bytes.Equal(ie, want) {
		t.Fatalf("TLV-E: got % X want % X", ie, want)
	}
	if ie[0] != 0x78 {
		t.Errorf("IEI: got 0x%02X want 0x78 (TS 24.501 Table 8.3.2.1.1)", ie[0])
	}

	decoded, n, err := DecodeEAPMessageTLVE(ie)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(ie) {
		t.Errorf("consumed: got %d want %d", n, len(ie))
	}
	if !bytes.Equal(decoded, eapSuccess) {
		t.Errorf("decoded EAP: got % X want % X", decoded, eapSuccess)
	}

	if _, _, err := DecodeEAPMessageTLVE([]byte{0x25, 0x00, 0x01, 0xAA}); err == nil {
		t.Error("expected error decoding TLV-E with wrong IEI")
	}
}

// TestWrapPDUSessionEstablishmentRejectBody verifies the REJECT (0xC3) body:
// mandatory 5GSM cause (V, no IEI) plus the optional EAP-Failure TLV-E.
// Ref: TS 24.501 §8.3.3, §9.11.4.2.
func TestWrapPDUSessionEstablishmentRejectBody(t *testing.T) {
	eapFailure := []byte{0x04, 0x01, 0x00, 0x04} // EAP-Failure

	// With EAP-Failure (DN-AAA reachable, EAP-Failure branch).
	msg := WrapPDUSessionEstablishmentRejectBody(1, 5, Cause5GSMUserAuthOrAuthorizationFailed, eapFailure)
	want := []byte{PDGroupSessionManagement, 1, 5, byte(MsgTypePDUSessionEstablishmentReject), 0x1D}
	want = append(want, EncodeEAPMessageTLVE(eapFailure)...)
	if !bytes.Equal(msg, want) {
		t.Fatalf("reject with EAP-Failure: got % X want % X", msg, want)
	}
	if msg[4] != 29 {
		t.Errorf("5GSM cause: got %d want 29", msg[4])
	}

	// DN-AAA unreachable/timeout — EAP message IE is optional and omitted.
	msgNoEAP := WrapPDUSessionEstablishmentRejectBody(1, 5, Cause5GSMUserAuthOrAuthorizationFailed, nil)
	wantNoEAP := []byte{PDGroupSessionManagement, 1, 5, byte(MsgTypePDUSessionEstablishmentReject), 0x1D}
	if !bytes.Equal(msgNoEAP, wantNoEAP) {
		t.Fatalf("reject without EAP IE: got % X want % X", msgNoEAP, wantNoEAP)
	}
}

// TestCause5GSMUserAuthOrAuthorizationFailedValue pins the wire value of
// cause #29 per TS 24.501 §9.11.4.2 Table 9.11.4.2.1.
func TestCause5GSMUserAuthOrAuthorizationFailedValue(t *testing.T) {
	if Cause5GSMUserAuthOrAuthorizationFailed != 29 {
		t.Errorf("cause #29: got %d want 29", Cause5GSMUserAuthOrAuthorizationFailed)
	}
}
