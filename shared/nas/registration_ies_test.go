package nas

import (
	"bytes"
	"reflect"
	"testing"
)

func regReqBase() []byte {
	// ngKSI/type, mobile identity LV-E (5G-GUTI-ish dummy: SUCI null type)
	return []byte{0x01, 0x00, 0x0B, 0xF2, 0x02, 0xF8, 0x39, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01}
}

func TestRegistrationRequestOptionalIEs(t *testing.T) {
	b := regReqBase()
	b = append(b, 0x40, 0x02, 0x04, 0x01) // uplink data status PSI2, PSI8
	b = append(b, 0x50, 0x02, 0x20, 0x00) // PDU session status PSI5
	b = append(b, 0x2B, 0x01, 0x01)       // UE status
	b = append(b, 0xB1)                   // MICO
	b = append(b, 0x53, 0x01, 0x02)       // 5GS update type
	b = append(b, 0x71, 0x00, 0x03, 0xAA, 0xBB, 0xCC)
	r, err := DecodeRegistrationRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(PSIsFromStatusBytes(r.UplinkDataStatus), []uint8{2, 8}) {
		t.Errorf("uplink %v", r.UplinkDataStatus)
	}
	if !reflect.DeepEqual(PSIsFromStatusBytes(r.PDUSessionStatus), []uint8{5}) || StatusMaskFromBytes(r.PDUSessionStatus) != PSIMask(5) {
		t.Errorf("status %v", r.PDUSessionStatus)
	}
	if r.UEStatus == nil || *r.UEStatus != 1 {
		t.Errorf("ue status")
	}
	if r.MICOIndication == nil || *r.MICOIndication != 1 {
		t.Errorf("mico")
	}
	if !bytes.Equal(r.FiveGSUpdateType, []byte{2}) {
		t.Errorf("update type")
	}
	if !bytes.Equal(r.NASMessageContainer, []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("container %x", r.NASMessageContainer)
	}
}

func TestRegistrationRequestTruncatedNASContainerAbsent(t *testing.T) {
	b := append(regReqBase(), 0x71, 0x00, 0x09, 0xAA)
	r, err := DecodeRegistrationRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.NASMessageContainer != nil {
		t.Errorf("want absent, got %x", r.NASMessageContainer)
	}
}

func TestRegistrationAcceptPDUSessionStatusOrder(t *testing.T) {
	base := &RegistrationAccept{RegistrationResult: 1, NetworkFeatureSupport: []byte{0x01, 0x00}, T3512Value: ptrByte(0x21)}
	legacy, _ := EncodeRegistrationAccept(base)
	golden := []byte{0x01, 0x01, 0x21, 0x02, 0x01, 0x00, 0x5E, 0x01, 0x21}
	if !bytes.Equal(legacy, golden) {
		t.Fatalf("legacy bytes changed: %x", legacy)
	}
	ra := *base
	ra.PDUSessionStatus = []byte{0x20, 0x00}
	ra.PDUSessionReactivationResult = []byte{0x00, 0x00}
	got, _ := EncodeRegistrationAccept(&ra)
	want := []byte{0x01, 0x01, 0x21, 0x02, 0x01, 0x00, 0x50, 0x02, 0x20, 0x00, 0x26, 0x02, 0x00, 0x00, 0x5E, 0x01, 0x21}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x", got)
	}
}

func ptrByte(b byte) *byte { return &b }
