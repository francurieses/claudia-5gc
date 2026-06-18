package nas_test

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// tmsiLV is a spec-conformant mandatory 5G-S-TMSI IE (LV, TS 24.501 §8.2.16.1):
// length=7, identity-type octet 0xF4, AMF Set ID/Pointer, 5G-TMSI 0x00000010.
var tmsiLV = []byte{0x07, 0xF4, 0x00, 0x40, 0x00, 0x00, 0x00, 0x10}

func TestDecodeServiceRequest_Signalling(t *testing.T) {
	// ServiceType=Signalling(0x00) | NGKSI.Type=1 NGKSI.KSI=3 → combined byte: (0x00<<4)|(1<<3)|0x03 = 0x0B
	b := append([]byte{0x0B}, tmsiLV...)
	sr, err := nas.DecodeServiceRequest(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sr.ServiceType != nas.ServiceTypeSignalling {
		t.Errorf("ServiceType: got %d, want %d", sr.ServiceType, nas.ServiceTypeSignalling)
	}
	if sr.NGKSI.KeySetIdentifier != 3 {
		t.Errorf("KSI: got %d, want 3", sr.NGKSI.KeySetIdentifier)
	}
	if sr.TMSI != 0x00000010 {
		t.Errorf("TMSI: got %08x, want 00000010", sr.TMSI)
	}
	if sr.UplinkDataStatus != nil || sr.PDUSessionStatus != nil {
		t.Error("expected nil optional IEs")
	}
}

func TestDecodeServiceRequest_DataWithStatus(t *testing.T) {
	// ServiceType=Data(0x01) | NGKSI.Type=0 KSI=2 → (0x01<<4)|(0<<3)|0x02 = 0x12
	// 5G-S-TMSI mandatory LV, then:
	// UplinkDataStatus IEI=0x40 Len=2 Value=0x00,0x02
	// PDUSessionStatus IEI=0x50 Len=2 Value=0x00,0x04
	b := append([]byte{0x12}, tmsiLV...)
	b = append(b, 0x40, 0x02, 0x00, 0x02, 0x50, 0x02, 0x00, 0x04)
	sr, err := nas.DecodeServiceRequest(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sr.ServiceType != nas.ServiceTypeData {
		t.Errorf("ServiceType: got %d, want %d", sr.ServiceType, nas.ServiceTypeData)
	}
	if sr.UplinkDataStatus == nil || *sr.UplinkDataStatus != 0x0002 {
		t.Errorf("UplinkDataStatus: got %v, want 0x0002", sr.UplinkDataStatus)
	}
	if sr.PDUSessionStatus == nil || *sr.PDUSessionStatus != 0x0004 {
		t.Errorf("PDUSessionStatus: got %v, want 0x0004", sr.PDUSessionStatus)
	}
}

func TestDecodeServiceRequest_TooShort(t *testing.T) {
	_, err := nas.DecodeServiceRequest([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestEncodeServiceAccept(t *testing.T) {
	b, err := nas.EncodeServiceAccept(&nas.ServiceAccept{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("expected empty body, got %d bytes", len(b))
	}
}

func TestServiceRequestRoundTrip_ViaMessage(t *testing.T) {
	// Encode a plain Service Request NAS PDU and decode it back.
	raw := []byte{
		nas.PDMobilityManagement, // EPD
		0x00,                     // SHT = plain
		byte(nas.MsgTypeServiceRequest),
		0x01, // ServiceType=0 NGKSI.Type=0 KSI=1
	}
	msg, err := nas.Decode(raw)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	sr, ok := msg.Body.(*nas.ServiceRequest)
	if !ok {
		t.Fatalf("Body is not *ServiceRequest: %T", msg.Body)
	}
	if sr.NGKSI.KeySetIdentifier != 1 {
		t.Errorf("KSI: got %d, want 1", sr.NGKSI.KeySetIdentifier)
	}
}
