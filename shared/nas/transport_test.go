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

// TestDLNASTransport_Cause5GMM verifies the 5GMM cause IE the AMF returns when
// it does not forward a 5GSM payload to the SMF (e.g. the UE requested an
// S-NSSAI outside its Allowed NSSAI). The IE is TV format — IEI 0x58 followed
// by the single cause byte, with no length octet — and per Table 8.7.2.1.1 it
// follows the PDU session ID IE.
// Ref: TS 24.501 §5.4.5.2.5, §8.7.2, §9.11.3.2
func TestDLNASTransport_Cause5GMM(t *testing.T) {
	container := []byte{0x2E, 0x01, 0x01, 0xC1} // echoed 5GSM message
	psi := uint8(3)
	cause := uint8(nas.CausePayloadNotForwarded)

	body, err := nas.EncodeDLNASTransport(&nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     container,
		PDUSessionID:         &psi,
		Cause5GMM:            &cause,
	})
	if err != nil {
		t.Fatalf("EncodeDLNASTransport: %v", err)
	}

	want := []byte{0x01, 0x00, 0x04} // container type | 2-byte length
	want = append(want, container...)
	want = append(want, 0x12, 0x03) // PDU session ID (TV)
	want = append(want, 0x58, 90)   // 5GMM cause (TV) — no length octet
	if !bytes.Equal(body, want) {
		t.Fatalf("DL NAS Transport body:\n  got  %x\n  want %x", body, want)
	}
}

// TestDLNASTransport_Cause5GMMOmitted guards against a stray IEI appearing on
// the normal accept path, which every PDU session establishment uses.
func TestDLNASTransport_Cause5GMMOmitted(t *testing.T) {
	body, err := nas.EncodeDLNASTransport(&nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     []byte{0xAA},
	})
	if err != nil {
		t.Fatalf("EncodeDLNASTransport: %v", err)
	}
	if bytes.Contains(body, []byte{nas.IEICause5GMM}) {
		t.Fatalf("5GMM cause IEI present when Cause5GMM is nil: %x", body)
	}
}

// TestCause5GMMValues pins the cause values used on the DL NAS Transport
// not-forwarded path. Ref: TS 24.501 Table 9.11.3.2.1
func TestCause5GMMValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  nas.Cause5GMM
		want byte
	}{
		{"payload not forwarded", nas.CausePayloadNotForwarded, 90},
		{"DNN not supported in slice", nas.CauseDNNNotSupportedInSlice, 91},
		{"insufficient UP resources", nas.CauseInsufficientUPResource, 92},
	} {
		if byte(tc.got) != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, byte(tc.got), tc.want)
		}
	}
}
