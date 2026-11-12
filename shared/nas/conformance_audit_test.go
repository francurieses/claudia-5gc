package nas_test

// conformance_audit_test.go — regression tests for the 3GPP conformance audit
// fixes (Jul 2026): Requested NSSAI IEI 0x2F, Security Mode Command IMEISV
// request + Additional 5G security information (RINMR), TLV-E skip of the LADN
// indication in Registration Request, IMEI/IMEISV digit decoding.
// Ref: TS 24.501 Table 8.2.6.1.1, §8.2.25.1, §9.11.3.4, §9.11.3.12, §9.11.3.28

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
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

// ---- REL19-5.4: 5GMM / 5GSM capability bit structs ------------------------

// capBitSpec is one hand-derived bit position: spec octet (3 = first value
// octet), bit (1 = LSB) and the struct field it must drive. Derived from the
// TS 24.501 V19.8.0 Figure/Table 9.11.3.1.1 and 9.11.4.1.1, independently of
// the decoder's own table.
type capBitSpec struct {
	octet, bit int
	field      string
}

var fiveGMMCapSpecBits = []capBitSpec{
	{3, 1, "S1Mode"},
	{3, 2, "HOAttach"},
	{3, 3, "LPP"},
	{3, 4, "RestrictEC"},
	{3, 5, "CPCIoT"},
	{3, 6, "N3DataNotSupported"},
	{3, 7, "IPHCCPCIoT"},
	{3, 8, "SGC"},
	{4, 1, "SRVCC5G"},
	{4, 2, "UPCIoT"},
	{4, 3, "V2XUu"},
	{4, 4, "V2XCEPC5"},
	{4, 5, "V2XCNPC5"},
	{4, 6, "LCS5G"},
	{4, 7, "NSSAA"},
	{4, 8, "RACS"},
	{5, 1, "CAG"},
	{5, 2, "WUSA"},
	{5, 3, "MultipleUP"},
	{5, 4, "EHCCPCIoT"},
	{5, 5, "ERNSSAI"},
	{5, 6, "ProSeDD"},
	{5, 7, "ProSeDC"},
	{5, 8, "ProSeL2Relay"},
	{6, 1, "ProSeL3Relay"},
	{6, 2, "ProSeL2Rmt"},
	{6, 3, "ProSeL3Rmt"},
	{6, 4, "NRPSSI"},
	{6, 5, "NCR"},
	{6, 6, "PIV"},
	{6, 7, "RPR"},
	{6, 8, "PR"},
	{7, 1, "NSSRG"},
	{7, 2, "MINT"},
	{7, 3, "EventNotification"},
	{7, 4, "SSNPNSI"},
	{7, 5, "ExCAG"},
	{7, 6, "NSAG"},
	{7, 7, "UAS"},
	{7, 8, "MPSIU"},
	{8, 1, "RCMAP"},
	{8, 2, "RCMAN"},
	{8, 3, "ESI"},
	{8, 4, "ECI"},
	{8, 5, "RANTiming"},
	{8, 6, "LADNDS"},
	{8, 7, "NSR"},
	{8, 8, "SBTS"},
	{9, 1, "A2XEPC5"},
	{9, 2, "A2XNPC5"},
	{9, 3, "UNPER"},
	{9, 4, "SBNS"},
	{9, 5, "RSLPS"},
	{9, 6, "ProSeL2U2URelay"},
	{9, 7, "ProSeL3U2URelay"},
	{9, 8, "ProSeL2End"},
	{10, 1, "ProSeL3End"},
	{10, 2, "RSLP"},
	{10, 3, "PNS"},
	{10, 4, "LCSUPP"},
	{10, 5, "SUPL"},
	{10, 6, "TempNS"},
	{10, 7, "SLVI"},
	{10, 8, "A2XUu"},
	{11, 1, "MCSIU"},
	{11, 2, "NVLSATNR"},
	{11, 3, "RSLPL"},
	{11, 4, "NSUC"},
	{11, 5, "RSLPVU"},
	{11, 6, "RSLPPU"},
	{11, 7, "ATUC"},
	{11, 8, "LPWUSPSAISI"},
	{12, 1, "OPHPAE"},
	{12, 2, "ProSeMCI"},
	{12, 3, "MLCSUP"},
	{12, 4, "ProSeL3IMRelay"},
	{12, 5, "ProSeL2IMRelay"},
	{12, 6, "MINTEPS"},
	{12, 7, "EF5L"},
	{12, 8, "LWD"},
	{13, 1, "NonSATLSP"},
	{13, 4, "LCSCDL"},
}

var fiveGSMCapSpecBits = []capBitSpec{
	{3, 1, "RQoS"},
	{3, 2, "MH6PDU"},
	{3, 3, "EPTS1"},
	{3, 8, "TPMIC"},
	{4, 1, "APMQF"},
	{4, 2, "SDNAEPC"},
	{4, 3, "RTPMMII"},
	{4, 6, "MPTCP"},
	{4, 7, "MPQUICUDP"},
	{4, 8, "MPQUICIP"},
	{5, 1, "MPQUICE"},
	{5, 2, "E8PCPDEI"},
}

// capVector returns a 13-octet value with only (octet, bit) set.
func capVector(octet, bit int) []byte {
	v := make([]byte, 13)
	v[octet-3] = 1 << (bit - 1)
	return v
}

// trueFields lists the names of all bool fields set in the struct pointed to by p.
func trueFields(p any) []string {
	var out []string
	rv := reflect.ValueOf(p).Elem()
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).Kind() == reflect.Bool && rv.Field(i).Bool() {
			out = append(out, rv.Type().Field(i).Name)
		}
	}
	return out
}

// Test5GMMCapabilityEveryBit sets each defined bit alone and checks that
// exactly the expected field becomes true. Ref: TS 24.501 Table 9.11.3.1.1
func Test5GMMCapabilityEveryBit(t *testing.T) {
	for _, s := range fiveGMMCapSpecBits {
		v := capVector(s.octet, s.bit)
		c, err := nas.Decode5GMMCapability(v)
		if err != nil {
			t.Fatalf("octet %d bit %d: %v", s.octet, s.bit, err)
		}
		if got := trueFields(c); len(got) != 1 || got[0] != s.field {
			t.Errorf("octet %d bit %d: got %v, want [%s]", s.octet, s.bit, got, s.field)
		}
		// Built from the fields (Raw cleared), the same bit must be emitted.
		c.Raw = nil
		enc, err := nas.Encode5GMMCapability(c)
		if err != nil {
			t.Fatalf("encode %s: %v", s.field, err)
		}
		if !bytes.Equal(enc, v[:s.octet-2]) {
			t.Errorf("%s: encode got %x, want %x", s.field, enc, v[:s.octet-2])
		}
	}
}

// Test5GMMCapabilitySpareBits checks that the spare bits (octet 13 bits 2,3,
// 5-8 and octets 14-15) decode to no field and survive in Raw.
func Test5GMMCapabilitySpareBits(t *testing.T) {
	in := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xE6, 0xFF, 0xFF} // len 14: beyond the spec maximum
	c, err := nas.Decode5GMMCapability(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := trueFields(c); len(got) != 0 {
		t.Errorf("spare bits set fields %v", got)
	}
	enc, err := nas.Encode5GMMCapability(c)
	if err != nil || !bytes.Equal(enc, in) {
		t.Errorf("Raw not preserved: %x err=%v", enc, err)
	}
}

// Test5GMMCapabilityLengths covers empty, 1-octet (Rel-15 UE), maximum and
// shorter-than-defined inputs. Ref: TS 24.501 §9.11.3.1, §7.7.1
func Test5GMMCapabilityLengths(t *testing.T) {
	if _, err := nas.Decode5GMMCapability(nil); err == nil {
		t.Error("empty value: want error")
	}
	// Rel-15 UE: 1 octet, S1 mode + HO attach + LPP.
	c, err := nas.Decode5GMMCapability([]byte{0x07})
	if err != nil || !c.S1Mode || !c.HOAttach || !c.LPP || c.ERNSSAI || c.SGC {
		t.Errorf("1-octet decode wrong: %+v err=%v", c, err)
	}
	// Golden vector: octet 3 = 0x80 (SGC), octet 4 = 0x80 (RACS), octet 5 = 0x10 (ER-NSSAI).
	c, err = nas.Decode5GMMCapability([]byte{0x80, 0x80, 0x10})
	if err != nil || !c.SGC || !c.RACS || !c.ERNSSAI || len(trueFields(c)) != 3 {
		t.Errorf("3-octet decode wrong: %v err=%v", trueFields(c), err)
	}
	// Encode without Raw trims to the highest used octet.
	enc, err := nas.Encode5GMMCapability(&nas.FiveGMMCapability{S1Mode: true})
	if err != nil || !bytes.Equal(enc, []byte{0x01}) {
		t.Errorf("minimal encode: %x err=%v", enc, err)
	}
	enc, _ = nas.Encode5GMMCapability(&nas.FiveGMMCapability{LCSCDL: true})
	if !bytes.Equal(enc, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08}) {
		t.Errorf("octet 13 bit 4 encode: %x", enc)
	}
	if _, err := nas.Encode5GMMCapability(nil); err == nil {
		t.Error("nil encode: want error")
	}
	// The legacy helper keeps its behaviour: bit 5 of octet 5 only.
	if nas.ERNSSAISupported([]byte{0xFF, 0xFF}) || nas.ERNSSAISupported(nil) || !nas.ERNSSAISupported([]byte{0, 0, 0x10}) || nas.ERNSSAISupported([]byte{0, 0, 0xEF}) {
		t.Error("ERNSSAISupported behaviour changed")
	}
}

// Test5GMMCapabilityRegistrationRequest checks the accessor on a decoded
// REGISTRATION REQUEST and the raw field staying intact.
func Test5GMMCapabilityRegistrationRequest(t *testing.T) {
	var rr *nas.RegistrationRequest
	if rr.Capability5GMM() != nil {
		t.Error("nil request must yield nil capability")
	}
	rr = &nas.RegistrationRequest{}
	if rr.Capability5GMM() != nil {
		t.Error("absent IE must yield nil capability")
	}
	rr.FiveGMMCapability = []byte{0x01, 0x00, 0x10}
	c := rr.Capability5GMM()
	if c == nil || !c.S1Mode || !c.ERNSSAI {
		t.Errorf("decoded capability wrong: %+v", c)
	}
}

// Test5GMMCapabilityPeerUE checks the capability.PeerUE adapter.
func Test5GMMCapabilityPeerUE(t *testing.T) {
	c, _ := nas.Decode5GMMCapability([]byte{0x00, 0x00, 0x10})
	bits := map[string]func(nas.FiveGMMCapability) bool{
		"er-nssai": func(c nas.FiveGMMCapability) bool { return c.ERNSSAI },
		"sgc":      func(c nas.FiveGMMCapability) bool { return c.SGC },
	}
	p := c.PeerUE(bits)
	if !p.Allows(capability.Feature{ID: "er-nssai"}) {
		t.Error("er-nssai bit set but not allowed")
	}
	if p.Allows(capability.Feature{ID: "sgc"}) || p.Allows(capability.Feature{ID: "unmapped"}) {
		t.Error("unset or unmapped feature must not be allowed")
	}
}

// Test5GSMCapabilityEveryBit is the 5GSM counterpart of Test5GMMCapabilityEveryBit.
// Ref: TS 24.501 Table 9.11.4.1.1
func Test5GSMCapabilityEveryBit(t *testing.T) {
	for _, s := range fiveGSMCapSpecBits {
		v := capVector(s.octet, s.bit)
		c, err := nas.Decode5GSMCapability(v)
		if err != nil {
			t.Fatalf("octet %d bit %d: %v", s.octet, s.bit, err)
		}
		if got := trueFields(c); len(got) != 1 || got[0] != s.field || c.ATSSSST != 0 || c.ATSSSLL != 0 {
			t.Errorf("octet %d bit %d: got %v, want [%s]", s.octet, s.bit, got, s.field)
		}
		c.Raw = nil
		enc, err := nas.Encode5GSMCapability(c)
		if err != nil || !bytes.Equal(enc, v[:s.octet-2]) {
			t.Errorf("%s: encode got %x want %x err=%v", s.field, enc, v[:s.octet-2], err)
		}
	}
}

// Test5GSMCapabilityATSSS checks the multi-bit ATSSS-ST (octet 3 bits 4-7)
// and ATSSS-LL (octet 4 bits 5,4) fields. Ref: TS 24.501 Table 9.11.4.1.1
func Test5GSMCapabilityATSSS(t *testing.T) {
	for st := 0; st <= 3; st++ {
		c, err := nas.Decode5GSMCapability([]byte{byte(st) << 3})
		if err != nil || int(c.ATSSSST) != st || c.TPMIC || c.EPTS1 || c.MH6PDU || c.RQoS {
			t.Errorf("ATSSS-ST %d: %+v err=%v", st, c, err)
		}
	}
	// 0x78 = bits 4..7 all set (reserved value 15) must still be reported.
	if c, _ := nas.Decode5GSMCapability([]byte{0x78}); c.ATSSSST != 0x0F {
		t.Errorf("ATSSS-ST 0x0F: got %d", c.ATSSSST)
	}
	cases := []struct {
		octet4 byte
		ll     uint8
	}{{0x00, 0}, {0x08, 1}, {0x10, 2}, {0x18, 3}}
	for _, tc := range cases {
		c, err := nas.Decode5GSMCapability([]byte{0x00, tc.octet4})
		if err != nil || c.ATSSSLL != tc.ll || len(trueFields(c)) != 0 {
			t.Errorf("ATSSS-LL octet4=%02x: %+v err=%v", tc.octet4, c, err)
		}
		c.Raw = nil
		enc, _ := nas.Encode5GSMCapability(c)
		want := []byte{0x00, tc.octet4}
		if tc.ll == 0 {
			want = want[:1]
		}
		if !bytes.Equal(enc, want) {
			t.Errorf("ATSSS-LL %d encode: %x want %x", tc.ll, enc, want)
		}
	}
}

// Test5GSMCapabilityLengths covers empty, truncated, oversized input and Raw
// preservation (spare bits in octet 5 and octets 6-15). Ref: TS 24.501 §9.11.4.1
func Test5GSMCapabilityLengths(t *testing.T) {
	if _, err := nas.Decode5GSMCapability(nil); err == nil {
		t.Error("empty value: want error")
	}
	if _, err := nas.Encode5GSMCapability(nil); err == nil {
		t.Error("nil encode: want error")
	}
	// Golden: RQoS|MH6|EPT-S1 (0x07), MPTCP|ATSSS-LL=2 (0x30), MPQUIC-E|E8PCPDEI (0x03).
	in := []byte{0x07, 0x30, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	c, err := nas.Decode5GSMCapability(in)
	if err != nil {
		t.Fatal(err)
	}
	if !c.RQoS || !c.MH6PDU || !c.EPTS1 || !c.MPTCP || c.ATSSSLL != 2 || !c.MPQUICE || !c.E8PCPDEI || c.ATSSSST != 0 || c.TPMIC {
		t.Errorf("golden decode wrong: %+v", c)
	}
	enc, err := nas.Encode5GSMCapability(c)
	if err != nil || !bytes.Equal(enc, in) {
		t.Errorf("Raw not preserved: %x err=%v", enc, err)
	}
	in[0] = 0xFF // mutating the input must not alias Raw
	if c.Raw[0] != 0x07 {
		t.Error("Raw aliases the caller's buffer")
	}
}

// Test5GSMCapabilityPDUSessionEstablishmentRequest checks IEI 0x28 parsing in
// the PDU SESSION ESTABLISHMENT REQUEST decoder, including truncated and empty
// IEs (treated as not present, TS 24.501 §7.7.1).
func Test5GSMCapabilityPDUSessionEstablishmentRequest(t *testing.T) {
	base := []byte{0xFF, 0xFF} // integrity protection maximum data rate (body of the 5GSM message)
	for _, tc := range []struct {
		name string
		ie   []byte
		want *byte // first value octet, nil = absent
	}{
		{"present", []byte{0x28, 0x01, 0x03}, ptrByte(0x03)},
		{"two octets", []byte{0x28, 0x02, 0x03, 0x30}, ptrByte(0x03)},
		{"empty IE", []byte{0x28, 0x00}, nil},
		{"truncated value", []byte{0x28, 0x03, 0x03}, nil},
		{"truncated length", []byte{0x28}, nil},
		{"absent", nil, nil},
	} {
		req, err := nas.DecodePDUSessionEstablishmentRequest(append(append([]byte{}, base...), tc.ie...))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		switch {
		case tc.want == nil && req.Capability5GSM != nil:
			t.Errorf("%s: want nil capability, got %+v", tc.name, req.Capability5GSM)
		case tc.want != nil && (req.Capability5GSM == nil || req.Capability5GSM.Raw[0] != *tc.want):
			t.Errorf("%s: capability not parsed: %+v", tc.name, req.Capability5GSM)
		}
	}
}

func ptrByte(b byte) *byte { return &b }
