package nas_test

// conformance_audit_test.go — regression tests for the 3GPP conformance audit
// fixes (Jul 2026): Requested NSSAI IEI 0x2F, Security Mode Command IMEISV
// request + Additional 5G security information (RINMR), TLV-E skip of the LADN
// indication in Registration Request, IMEI/IMEISV digit decoding.
// Ref: TS 24.501 Table 8.2.6.1.1, §8.2.25.1, §9.11.3.4, §9.11.3.12, §9.11.3.28

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// TestEncodeSecurityModeCommand_IMEISVAndRINMR verifies the SMC carries the
// IMEISV request (TV ½, IEI 0xE-) and Additional 5G security information
// (TLV, IEI 0x36) with the RINMR bit, in spec order, and that both survive a
// decode round-trip. Ref: TS 24.501 §8.2.25.1, §9.11.3.12, §9.11.3.28
func TestEncodeSecurityModeCommand_IMEISVAndRINMR(t *testing.T) {
	imeisvReq := nas.IMEISVRequested
	addInfo := nas.Additional5GSecInfoRINMR
	smc := &nas.SecurityModeCommand{
		SelectedNASSecurityAlgorithms: nas.NASSecurityAlgorithms{
			CipheringAlgorithmID: 2, IntegrityAlgorithmID: 2,
		},
		NGKSI: nas.NGKSI{KeySetIdentifier: 1},
		ReplayedUESecurityCapabilities: nas.UESecurityCapability{
			EA0: true, EA2: true, IA0: true, IA2: true,
		},
		IMEISVRequest:            &imeisvReq,
		Additional5GSecurityInfo: &addInfo,
	}
	b, err := nas.EncodeSecurityModeCommand(smc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// IMEISV request must precede Additional 5G security information
	// (TS 24.501 Table 8.2.25.1.1 order).
	idxIMEISV := bytes.IndexByte(b, 0xE1)
	idxAddInfo := bytes.Index(b, []byte{0x36, 0x01, nas.Additional5GSecInfoRINMR})
	if idxIMEISV < 0 {
		t.Fatal("IMEISV request IE (0xE1) not on the wire")
	}
	if idxAddInfo < 0 {
		t.Fatal("Additional 5G security information IE (0x36 01 02) not on the wire")
	}
	if idxIMEISV > idxAddInfo {
		t.Errorf("IE order: IMEISV request (idx %d) must precede Additional 5G security info (idx %d)",
			idxIMEISV, idxAddInfo)
	}

	dec, err := nas.DecodeSecurityModeCommand(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.IMEISVRequest == nil || *dec.IMEISVRequest != nas.IMEISVRequested {
		t.Error("IMEISVRequest did not round-trip")
	}
	if dec.Additional5GSecurityInfo == nil || *dec.Additional5GSecurityInfo != nas.Additional5GSecInfoRINMR {
		t.Error("Additional5GSecurityInfo did not round-trip")
	}
}

// TestDecodeRegistrationRequest_SkipsLADNIndicationTLVE verifies that the LADN
// indication (IEI 0x74, TLV-E with 2-octet length) is skipped without shifting
// the parser: the Requested NSSAI that follows must still decode.
// Ref: TS 24.501 §9.11.3.29, Table 8.2.6.1.1
func TestDecodeRegistrationRequest_SkipsLADNIndicationTLVE(t *testing.T) {
	body := []byte{0x11, 0x00, 0x01, 0x00}                  // ngKSI/reg-type + empty mobile identity
	body = append(body, 0x74, 0x00, 0x03, 0xAA, 0xBB, 0xCC) // LADN indication TLV-E len=3
	body = append(body, 0x2F, 0x02, 0x01, 0x42)             // Requested NSSAI SST=0x42
	pdu := append([]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationRequest)}, body...)

	msg, err := nas.Decode(pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rr, _ := msg.Body.(*nas.RegistrationRequest)
	if rr.RequestedNSSAI == nil || len(rr.RequestedNSSAI.SNSSAIs) != 1 {
		t.Fatal("RequestedNSSAI after LADN indication not decoded — TLV-E skip shifted the parser")
	}
	if rr.RequestedNSSAI.SNSSAIs[0].SST != 0x42 {
		t.Errorf("SST: got %x, want 42", rr.RequestedNSSAI.SNSSAIs[0].SST)
	}
}

// TestDecodeRegistrationRequest_5GMMCapability verifies the 5GMM capability IE
// (IEI 0x10, TLV) is stored. Ref: TS 24.501 §9.11.3.1
func TestDecodeRegistrationRequest_5GMMCapability(t *testing.T) {
	body := []byte{0x11, 0x00, 0x01, 0x00}
	body = append(body, 0x10, 0x01, 0x07) // 5GMM capability, 1 octet
	pdu := append([]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationRequest)}, body...)

	msg, err := nas.Decode(pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rr, _ := msg.Body.(*nas.RegistrationRequest)
	if len(rr.FiveGMMCapability) != 1 || rr.FiveGMMCapability[0] != 0x07 {
		t.Errorf("FiveGMMCapability: got %x, want [07]", rr.FiveGMMCapability)
	}
}

// TestDecodeMobileIdentity_IMEISV verifies BCD digit extraction for an IMEISV
// mobile identity (16 digits, even → trailing 0xF filler dropped).
// Ref: TS 24.501 §9.11.3.4 Figure 9.11.3.4.3
func TestDecodeMobileIdentity_IMEISV(t *testing.T) {
	// digits 1234567890123456: octet1 = digit1<<4 | evenBit(0) | type 101
	b := []byte{0x15, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0xF6}
	mi, err := nas.DecodeMobileIdentity(b)
	if err != nil {
		t.Fatalf("DecodeMobileIdentity: %v", err)
	}
	if mi.Type != nas.MobileIdentityIMEISV {
		t.Fatalf("type: got %d, want IMEISV", mi.Type)
	}
	if mi.IMEISV != "1234567890123456" {
		t.Errorf("IMEISV: got %q, want 1234567890123456", mi.IMEISV)
	}
}
