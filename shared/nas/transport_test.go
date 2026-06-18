package nas_test

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// TestDLNASTransport_UEPolicyContainer verifies URSP delivery framing: a DL NAS
// TRANSPORT carrying a UE policy container (payload container type 0x05).
// This is the spec-correct carrier for URSP — not the Configuration Update
// Command and not IEI 0x7B.
// Ref: TS 24.501 §8.7.2, §9.11.3.40; TS 23.502 §4.2.4.3
func TestDLNASTransport_UEPolicyContainer(t *testing.T) {
	container := []byte{0x80, 0x01, 0x00, 0x03, 0xAA, 0xBB, 0xCC} // stub UE policy container
	msg := &nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeUEPolicy,
		PayloadContainer:     container,
	}

	body, err := nas.EncodeDLNASTransport(msg)
	if err != nil {
		t.Fatalf("EncodeDLNASTransport: %v", err)
	}

	// Layout: payload container type(1=0x05) | length(2 big-endian) | container
	want := append([]byte{0x05, 0x00, byte(len(container))}, container...)
	if !bytes.Equal(body, want) {
		t.Fatalf("DL NAS Transport body:\n  got  %x\n  want %x", body, want)
	}

	if nas.PayloadContainerTypeUEPolicy != 0x05 {
		t.Errorf("PayloadContainerTypeUEPolicy: got %#x, want 0x05", nas.PayloadContainerTypeUEPolicy)
	}
}

// TestDLNASTransport_FullPDU round-trips a UE policy container DL NAS Transport
// through the full NAS PDU codec.
func TestDLNASTransport_FullPDU(t *testing.T) {
	container := []byte{0x80, 0x01, 0x00, 0x05, 0x00, 0x03, 0xF1, 0x10, 0x00}
	pdu := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			SecurityHeaderType:            nas.SecurityHeaderPlainNAS,
			MessageType:                   nas.MsgTypeDLNASTransport,
		},
		Body: &nas.DLNASTransport{
			PayloadContainerType: nas.PayloadContainerTypeUEPolicy,
			PayloadContainer:     container,
		},
	}

	encoded, err := nas.Encode(pdu)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Plain NAS: EPD | SHT | MsgType(0x68) | payload container type(0x05) | ...
	if encoded[2] != byte(nas.MsgTypeDLNASTransport) {
		t.Errorf("message type: got %#x, want %#x (DL NAS Transport)", encoded[2], nas.MsgTypeDLNASTransport)
	}
	if encoded[3] != nas.PayloadContainerTypeUEPolicy {
		t.Errorf("payload container type: got %#x, want 0x05", encoded[3])
	}
}
