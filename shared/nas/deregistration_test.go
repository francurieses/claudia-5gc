package nas

import (
	"testing"
)

// TestDecodeDeregistrationRequest_SwitchOff tests decoding a Deregistration Request
// with the switch-off flag set (UE powering off). This is the most common case from
// UERANSIM when the UE container is stopped.
// Ref: TS 24.501 §8.2.11.1 Table 8.2.11.1-1
func TestDecodeDeregistrationRequest_SwitchOff(t *testing.T) {
	// Octet 4: NGKSI=0 (upper nibble) | SwitchOff=1(bit3) | AccessType=1(3GPP) → 0x09
	// Octet 5-6: LV-E length = 0x0007 (7 bytes for GUTI mobile identity)
	// Octet 7-13: GUTI mobile identity (simplified for test)
	//   Byte 0: 0xF6 (odd len + GUTI type=0x6)
	//   Bytes 1-2: MCC=001 → 0x00, 0xF1
	//   Byte 3: MNC=01 → 0x01 (2-digit MNC)
	//   Bytes 4-5: AMF RegionID=0x01, AMFSetID+AMFID nibbles
	//   Byte 6: TMSI byte 0
	gutiMI := []byte{
		0xF6,       // odd len marker + GUTI type
		0x00, 0xF1, // MCC 001
		0x01,       // MNC 01 (2-digit)
		0x01,       // AMF Region ID
		0x00, 0x01, // AMF Set ID (10b) + AMF ID (6b)
		0x00, 0x00, 0x00, 0x01, // 5G-TMSI
	}

	body := []byte{0x09} // combined byte: NGKSI=0, SwitchOff=1, AccessType=1
	// LV-E: 2-byte length
	body = append(body, 0x00, byte(len(gutiMI)))
	body = append(body, gutiMI...)

	req, err := DecodeDeregistrationRequest(body)
	if err != nil {
		t.Fatalf("DecodeDeregistrationRequest failed: %v", err)
	}
	if !req.SwitchOff {
		t.Error("expected SwitchOff=true")
	}
	if req.AccessType != 1 {
		t.Errorf("expected AccessType=1 (3GPP), got %d", req.AccessType)
	}
}

// TestDecodeDeregistrationRequest_Normal tests decoding without switch-off flag.
// In this case the AMF must send a Deregistration Accept back.
func TestDecodeDeregistrationRequest_Normal(t *testing.T) {
	// Octet 4: NGKSI=0 | SwitchOff=0 | AccessType=1 → 0x01
	gutiMI := []byte{
		0xF6,
		0x00, 0xF1,
		0x01,
		0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	}
	body := []byte{0x01}
	body = append(body, 0x00, byte(len(gutiMI)))
	body = append(body, gutiMI...)

	req, err := DecodeDeregistrationRequest(body)
	if err != nil {
		t.Fatalf("DecodeDeregistrationRequest failed: %v", err)
	}
	if req.SwitchOff {
		t.Error("expected SwitchOff=false")
	}
	if req.AccessType != 1 {
		t.Errorf("expected AccessType=1, got %d", req.AccessType)
	}
}

// TestEncodeDeregistrationAcceptUE verifies that the Accept body is empty
// (no IEs per TS 24.501 §8.2.12.1).
func TestEncodeDeregistrationAcceptUE(t *testing.T) {
	b, err := EncodeDeregistrationAcceptUE(&DeregistrationAcceptUE{})
	if err != nil {
		t.Fatalf("EncodeDeregistrationAcceptUE failed: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("expected 0 bytes, got %d: %x", len(b), b)
	}
}

// TestEncodeDeregistrationAcceptUE_RoundTrip verifies the full NAS encode/decode
// round-trip for a Deregistration Accept UE message.
func TestEncodeDeregistrationAcceptUE_RoundTrip(t *testing.T) {
	msg := &Message{
		Header: Header{
			ExtendedProtocolDiscriminator: PDMobilityManagement,
			SecurityHeaderType:            SecurityHeaderPlainNAS,
			MessageType:                   MsgTypeDeregistrationAcceptUE,
		},
		Body: &DeregistrationAcceptUE{},
	}
	pdu, err := Encode(msg)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	// 3-byte plain NAS header + 0-byte body
	if len(pdu) != 3 {
		t.Errorf("expected 3 bytes, got %d: %x", len(pdu), pdu)
	}
	// Verify decode
	decoded, err := Decode(pdu)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if decoded.Header.MessageType != MsgTypeDeregistrationAcceptUE {
		t.Errorf("expected MsgTypeDeregistrationAcceptUE, got %02x", decoded.Header.MessageType)
	}
}

// TestEncodeDeregistrationRequestNW_WithCause tests encoding a NW-initiated
// Deregistration Request with a 5GMM cause.
// Ref: TS 24.501 §8.2.13.1
func TestEncodeDeregistrationRequestNW_WithCause(t *testing.T) {
	r := &DeregistrationRequestNW{
		AccessType: 1, // 3GPP
		Cause5GMM:  0x16, // Deregistration
	}
	b, err := EncodeDeregistrationRequestNW(r)
	if err != nil {
		t.Fatalf("EncodeDeregistrationRequestNW failed: %v", err)
	}
	// byte 0: deregType; bytes 1-2: IEI 0x58 + cause value
	if len(b) != 3 {
		t.Errorf("expected 3 bytes, got %d: %x", len(b), b)
	}
	if b[1] != 0x58 {
		t.Errorf("expected IEI=0x58 for 5GMM cause, got %02x", b[1])
	}
	if b[2] != 0x16 {
		t.Errorf("expected cause=0x16, got %02x", b[2])
	}
}

// TestEncodeDeregistrationRequestNW_ReregRequired tests that the
// "re-registration required" flag sets bit 3 (0x04) of the de-registration
// type value — not bit 4 (0x08), which is "switch off".
// Ref: TS 24.501 §9.11.3.20
func TestEncodeDeregistrationRequestNW_ReregRequired(t *testing.T) {
	r := &DeregistrationRequestNW{
		AccessType:             1,
		ReregistrationRequired: true,
	}
	b, err := EncodeDeregistrationRequestNW(r)
	if err != nil {
		t.Fatalf("EncodeDeregistrationRequestNW failed: %v", err)
	}
	if len(b) != 1 {
		t.Fatalf("expected 1 byte, got %d: %x", len(b), b)
	}
	if b[0]&0x04 == 0 {
		t.Errorf("re-registration required bit (0x04) not set: %02x", b[0])
	}
	if b[0]&0x08 != 0 {
		t.Errorf("switch off bit (0x08) must not be set: %02x", b[0])
	}
	if b[0]&0x03 != 1 {
		t.Errorf("expected access type 1 (3GPP), got %02x", b[0]&0x03)
	}
}

// TestEncodeDeregistrationRequestNW_NoCause tests encoding without optional cause.
func TestEncodeDeregistrationRequestNW_NoCause(t *testing.T) {
	r := &DeregistrationRequestNW{
		AccessType: 1,
		Cause5GMM:  0,
	}
	b, err := EncodeDeregistrationRequestNW(r)
	if err != nil {
		t.Fatalf("EncodeDeregistrationRequestNW failed: %v", err)
	}
	if len(b) != 1 {
		t.Errorf("expected 1 byte (no cause IE), got %d: %x", len(b), b)
	}
}
