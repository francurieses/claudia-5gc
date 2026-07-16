package nas

// peek_test.go — unit tests for PeekMessageType, the unauthenticated peek the
// AMF uses to pick the right reject for an initial NAS message whose 5G-GUTI it
// has no context for (Registration Reject vs. Service Reject are not
// interchangeable — the UE discards the wrong one and retries forever).
//
// Ref: TS 24.501 §4.4.5, §5.5.1.3.5, §5.6.1.5.2, §9.1.1.

import "testing"

func TestPeekMessageType_Plain(t *testing.T) {
	// Plain initial NAS message: EPD | SHT=0x00 | MT | body…
	pdu := []byte{PDMobilityManagement, 0x00, byte(MsgTypeRegistrationRequest), 0x79, 0x00}
	got, ok := PeekMessageType(pdu)
	if !ok || got != MsgTypeRegistrationRequest {
		t.Fatalf("plain PDU: got (0x%02X, %v), want (0x%02X, true)", byte(got), ok, byte(MsgTypeRegistrationRequest))
	}
}

// TestPeekMessageType_IntegrityProtected is the case that matters live: a UE
// with a valid security context sends its periodic registration update
// integrity protected but NOT ciphered (TS 24.501 §4.4.5), so the inner header
// is plaintext and the type is readable even though the AMF cannot verify the
// MAC.
func TestPeekMessageType_IntegrityProtected(t *testing.T) {
	for _, sht := range []SecurityHeaderType{
		SecurityHeaderIntegrityProtected,
		SecurityHeaderIntegrityProtectedAndCiphered,
	} {
		pdu := []byte{
			PDMobilityManagement, byte(sht),
			0xAA, 0xBB, 0xCC, 0xDD, // MAC
			0x05,                                                         // SQN
			PDMobilityManagement, 0x00, byte(MsgTypeRegistrationRequest), // inner (plaintext)
			0x79, 0x00,
		}
		got, ok := PeekMessageType(pdu)
		if !ok || got != MsgTypeRegistrationRequest {
			t.Errorf("SHT 0x%02X: got (0x%02X, %v), want RegistrationRequest/true", byte(sht), byte(got), ok)
		}
	}
}

func TestPeekMessageType_ServiceRequest(t *testing.T) {
	pdu := []byte{
		PDMobilityManagement, byte(SecurityHeaderIntegrityProtected),
		0x01, 0x02, 0x03, 0x04, 0x00,
		PDMobilityManagement, 0x00, byte(MsgTypeServiceRequest),
	}
	got, ok := PeekMessageType(pdu)
	if !ok || got != MsgTypeServiceRequest {
		t.Fatalf("got (0x%02X, %v), want ServiceRequest/true", byte(got), ok)
	}
}

// TestPeekMessageType_Unreadable asserts the helper refuses to guess: a
// ciphered inner header, a short PDU, or a non-5GMM PDU must report ok=false so
// the caller falls back rather than acting on a garbage message type.
func TestPeekMessageType_Unreadable(t *testing.T) {
	cases := map[string][]byte{
		"nil":            nil,
		"too short":      {PDMobilityManagement, 0x00},
		"not 5GMM":       {PDGroupSessionManagement, 0x00, 0x41},
		"sec but short":  {PDMobilityManagement, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, PDMobilityManagement, 0x00},
		"ciphered inner": {PDMobilityManagement, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x9F, 0x3C, 0x71, 0x42},
	}
	for name, pdu := range cases {
		if _, ok := PeekMessageType(pdu); ok {
			t.Errorf("%s: PeekMessageType reported readable, want ok=false", name)
		}
	}
}
