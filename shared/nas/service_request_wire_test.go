package nas_test

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestDecodeServiceRequest_UERANSIMWireFormat(t *testing.T) {
	// Exact body bytes captured live from UERANSIM v3.2.8 (pcap frame, after the
	// EPD|SHT|MsgType header): the complete Service Request — with Uplink Data
	// Status (PSI 1) and PDU Session Status (PSI 1+2) — travels inside the NAS
	// message container IE (0x71, TLV-E); the outer message carries only
	// ngKSI + 5G-S-TMSI (LV-E). Ref: TS 24.501 §4.4.6, §9.11.3.33
	b := []byte{
		0x10,       // ServiceType=Data(1) | ngKSI=0
		0x00, 0x07, // 5G-S-TMSI LV-E length
		0xF4, 0x00, 0x41, 0x00, 0x00, 0x00, 0x05, // type|set/ptr|TMSI=5
		0x71, 0x00, 0x15, // NAS message container TLV-E, 21 bytes
		0x7E, 0x00, 0x4C, // inner plain SR header
		0x10,       // ServiceType|ngKSI
		0x00, 0x07, // TMSI LV-E
		0xF4, 0x00, 0x41, 0x00, 0x00, 0x00, 0x05,
		0x40, 0x02, 0x02, 0x00, // Uplink data status: PSI 1
		0x50, 0x02, 0x06, 0x00, // PDU session status: PSI 1+2
	}
	sr, err := nas.DecodeServiceRequest(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sr.TMSI != 0x00000005 {
		t.Errorf("TMSI: got %08x, want 00000005", sr.TMSI)
	}
	if sr.UplinkDataStatus == nil {
		t.Fatal("UplinkDataStatus lost — NAS message container (0x71) not parsed")
	}
	if !nas.PSIInStatus(*sr.UplinkDataStatus, 1) || nas.PSIInStatus(*sr.UplinkDataStatus, 2) {
		t.Errorf("UplinkDataStatus: got %04x, want PSI 1 only", *sr.UplinkDataStatus)
	}
	if sr.PDUSessionStatus == nil || !nas.PSIInStatus(*sr.PDUSessionStatus, 1) || !nas.PSIInStatus(*sr.PDUSessionStatus, 2) {
		t.Errorf("PDUSessionStatus: got %v, want PSI 1+2", sr.PDUSessionStatus)
	}
}
