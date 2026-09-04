package nas

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

// TestWrapPDUSessionEstablishmentAccept5GSMHeader verifies the 5GSM header is
// four full octets: EPD | PDU session identity | PTI | Message type.
// Packing PSI+PTI into one octet shifts the message type and makes the UE
// fail with "invalid NAS message type". Ref: TS 24.501 §9.1.1.
func TestWrapPDUSessionEstablishmentAccept5GSMHeader(t *testing.T) {
	body := []byte{0xAA, 0xBB}
	msg := WrapPDUSessionEstablishmentAcceptBody(5, 3, body)

	if len(msg) != 4+len(body) {
		t.Fatalf("expected %d-byte message, got %d", 4+len(body), len(msg))
	}
	want := []byte{PDGroupSessionManagement, 0x05, 0x03, byte(MsgTypePDUSessionEstablishmentAccept), 0xAA, 0xBB}
	for i := range want {
		if msg[i] != want[i] {
			t.Errorf("octet %d: got 0x%02X want 0x%02X", i, msg[i], want[i])
		}
	}
}

// TestEncodePDUSessionEstablishmentAcceptBodyFraming walks the encoded body the
// way UERANSIM's decoder does: the mandatory Authorized QoS rules IE is LV-E
// (2-octet length) and Session-AMBR is LV (1-octet length), neither carries an
// IEI. A mis-framed IE makes the UE read a bogus length and crash with
// "readOctetString: out of bounds". Ref: TS 24.501 §8.3.2.
func TestEncodePDUSessionEstablishmentAcceptBodyFraming(t *testing.T) {
	ip := net.ParseIP("10.60.0.7")
	body, err := EncodePDUSessionEstablishmentAcceptBody(PDUSessionTypeIPv4, SSCMode1, ip, "internet")
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	pos := 0
	// Octet 1: Selected SSC mode (high nibble) | Selected PDU session type (low nibble)
	if body[pos]>>4 != SSCMode1 || body[pos]&0x0F != PDUSessionTypeIPv4 {
		t.Errorf("octet1 0x%02X: ssc/pdutype nibbles wrong", body[pos])
	}
	pos++

	// Authorized QoS rules: LV-E (2-octet length)
	qosLen := (int(body[pos]) << 8) | int(body[pos+1])
	pos += 2
	if qosLen == 0 || pos+qosLen > len(body) {
		t.Fatalf("QoS rules length %d out of bounds (body %d, pos %d)", qosLen, len(body), pos)
	}
	pos += qosLen

	// Session-AMBR: LV (1-octet length)
	ambrLen := int(body[pos])
	pos++
	if ambrLen != 6 || pos+ambrLen > len(body) {
		t.Fatalf("Session-AMBR length %d invalid (expected 6)", ambrLen)
	}
	pos += ambrLen

	// PDU address: optional TLV, IEI 0x29
	if body[pos] != IEIPDUAddress {
		t.Fatalf("expected PDU address IEI 0x29, got 0x%02X", body[pos])
	}
	pos++
	addrLen := int(body[pos])
	pos++
	if pos+addrLen > len(body) {
		t.Fatalf("PDU address length out of bounds")
	}
	if body[pos] != 0x01 { // IPv4 session type
		t.Errorf("PDU address session type: got 0x%02X want 0x01", body[pos])
	}
	pos += addrLen

	// DNN: optional TLV, IEI 0x25
	if body[pos] != IEIDNN5GSM {
		t.Fatalf("expected DNN IEI 0x25, got 0x%02X", body[pos])
	}
	pos++
	dnnLen := int(body[pos])
	pos++
	pos += dnnLen

	if pos != len(body) {
		t.Errorf("body not fully consumed: pos %d, len %d", pos, len(body))
	}
}

// TestWrapPDUSessionModificationCommandBody5GSMHeader verifies the 5GSM header is
// four full octets: EPD | PDU session identity | PTI | 0xCB (Message type).
// Packing PSI+PTI into one octet shifts the message type and makes the UE fail.
// Ref: TS 24.501 §9.1.1, §8.3.6
func TestWrapPDUSessionModificationCommandBody5GSMHeader(t *testing.T) {
	body := []byte{0xAA, 0xBB}
	msg := WrapPDUSessionModificationCommandBody(5, 3, body)

	if len(msg) != 4+len(body) {
		t.Fatalf("expected %d-byte message, got %d", 4+len(body), len(msg))
	}
	want := []byte{PDGroupSessionManagement, 0x05, 0x03, byte(MsgTypePDUSessionModificationCommand), 0xAA, 0xBB}
	for i := range want {
		if msg[i] != want[i] {
			t.Errorf("octet %d: got 0x%02X want 0x%02X", i, msg[i], want[i])
		}
	}
}

// TestEncodePDUSessionModificationCommandBody verifies that the Modification Command body
// is empty — all IEs in the body are optional per TS 24.501 §8.3.6.
func TestEncodePDUSessionModificationCommandBody(t *testing.T) {
	body := EncodePDUSessionModificationCommandBody()
	if len(body) != 0 {
		t.Errorf("expected empty body, got %d bytes: %x", len(body), body)
	}
}

// TestPDUSessionModificationCommandWireFormat verifies the minimal wire-format message
// that the SMF delivers to the UE: 4 octets, no trailing IEs.
// UERANSIM's decoder reads the 4-octet header and then zero or more optional IEs.
// Ref: TS 24.501 §8.3.6, Table 8.3.6.1.1
func TestPDUSessionModificationCommandWireFormat(t *testing.T) {
	const psi uint8 = 1
	const pti uint8 = 7
	msg := WrapPDUSessionModificationCommandBody(psi, pti, EncodePDUSessionModificationCommandBody())

	if len(msg) != 4 {
		t.Fatalf("minimal command must be exactly 4 bytes, got %d", len(msg))
	}
	if msg[0] != PDGroupSessionManagement {
		t.Errorf("octet 0 (EPD): got 0x%02X want 0x%02X", msg[0], PDGroupSessionManagement)
	}
	if msg[1] != psi {
		t.Errorf("octet 1 (PSI): got 0x%02X want 0x%02X", msg[1], psi)
	}
	if msg[2] != pti {
		t.Errorf("octet 2 (PTI): got 0x%02X want 0x%02X", msg[2], pti)
	}
	if MessageType(msg[3]) != MsgTypePDUSessionModificationCommand {
		t.Errorf("octet 3 (MT): got 0x%02X want 0xCB", msg[3])
	}
}

// TestPDUSessionModificationPTIEchoed verifies that PSI and PTI from the UE's request
// are echoed back unchanged in the Modification Command, as required by TS 24.501 §8.1.2.
func TestPDUSessionModificationPTIEchoed(t *testing.T) {
	cases := []struct{ psi, pti uint8 }{
		{1, 1},
		{5, 127},
		{255, 0},
	}
	for _, tc := range cases {
		msg := WrapPDUSessionModificationCommandBody(tc.psi, tc.pti, nil)
		if msg[1] != tc.psi {
			t.Errorf("psi=%d: octet[1] got 0x%02X", tc.psi, msg[1])
		}
		if msg[2] != tc.pti {
			t.Errorf("pti=%d: octet[2] got 0x%02X", tc.pti, msg[2])
		}
		if MessageType(msg[3]) != MsgTypePDUSessionModificationCommand {
			t.Errorf("psi=%d pti=%d: message type 0x%02X != 0xCB", tc.psi, tc.pti, msg[3])
		}
	}
}

// TestBuildDefaultQoSRulesWireFormat walks the encoded QoS rule the way a
// spec-compliant decoder does. Ref: TS 24.501 §9.11.4.13, Figure 9.11.4.13.3.
func TestBuildDefaultQoSRulesWireFormat(t *testing.T) {
	const qfi uint8 = 1
	b := BuildDefaultQoSRules(qfi)

	if b[0] != 0x01 {
		t.Errorf("QoS rule identifier: got 0x%02X want 0x01", b[0])
	}
	ruleLen := (int(b[1]) << 8) | int(b[2])
	if ruleLen != len(b)-3 {
		t.Fatalf("rule length field %d != content length %d", ruleLen, len(b)-3)
	}

	hdr := b[3]
	if op := hdr >> 5; op != QoSRuleOpCreateNew {
		t.Errorf("rule operation code: got %03b want 001 (create new)", op)
	}
	if dqr := (hdr >> 4) & 0x01; dqr != 1 {
		t.Errorf("DQR bit: got %d want 1 (default rule)", dqr)
	}
	nFilters := int(hdr & 0x0F)
	if nFilters != 1 {
		t.Fatalf("number of packet filters: got %d want 1", nFilters)
	}

	// Packet filter 1: spare|direction(2b)|identifier(4b), then LV contents.
	pf := b[4]
	if dir := (pf >> 4) & 0x03; dir != 0x03 {
		t.Errorf("packet filter direction: got %02b want 11 (bidirectional)", dir)
	}
	pfLen := int(b[5])
	if pfLen != 1 || b[6] != 0x01 {
		t.Errorf("packet filter contents: got len=%d type=0x%02X want len=1 type=0x01 (match-all)", pfLen, b[6])
	}

	if prec := b[7]; prec != 0xFF {
		t.Errorf("QoS rule precedence: got %d want 255", prec)
	}
	last := b[8]
	if last&0xC0 != 0 {
		t.Errorf("spare/segregation bits set in QFI octet: 0x%02X", last)
	}
	if last&0x3F != qfi {
		t.Errorf("QFI: got %d want %d", last&0x3F, qfi)
	}
	if len(b) != 9 {
		t.Errorf("total length: got %d want 9", len(b))
	}
}

// TestBuildQoSFlowDescriptionsNonGBR verifies a non-GBR 5QI yields exactly one
// parameter (5QI) with E=1. Ref: TS 24.501 §9.11.4.12.
func TestBuildQoSFlowDescriptionsNonGBR(t *testing.T) {
	const qfi, fiveQI uint8 = 1, 9
	b := BuildQoSFlowDescriptions(qfi, fiveQI, 100, 100)

	if b[0]&0x3F != qfi {
		t.Errorf("QFI: got %d want %d", b[0]&0x3F, qfi)
	}
	if op := b[1] >> 5; op != QoSFlowOpCreateNew {
		t.Errorf("operation code: got %03b want 001 (create new)", op)
	}
	if e := (b[2] >> 6) & 0x01; e != 1 {
		t.Errorf("E bit: got %d want 1", e)
	}
	if n := b[2] & 0x3F; n != 1 {
		t.Fatalf("number of parameters: got %d want 1", n)
	}
	if b[3] != 0x01 || b[4] != 0x01 || b[5] != fiveQI {
		t.Errorf("5QI parameter: got id=0x%02X len=%d val=%d want id=0x01 len=1 val=%d", b[3], b[4], b[5], fiveQI)
	}
	if len(b) != 6 {
		t.Errorf("total length: got %d want 6", len(b))
	}
}

// TestBuildQoSFlowDescriptionsGBR verifies a GBR 5QI adds GFBR/MFBR UL+DL parameters.
func TestBuildQoSFlowDescriptionsGBR(t *testing.T) {
	b := BuildQoSFlowDescriptions(1, 1, 50, 200) // 5QI 1 = conversational voice (GBR)

	if n := b[2] & 0x3F; n != 5 {
		t.Fatalf("number of parameters: got %d want 5 (5QI + GFBR/MFBR UL+DL)", n)
	}
	// Walk parameters: id(1) len(1) content(len)
	pos := 3
	wantIDs := []uint8{0x01, 0x02, 0x03, 0x04, 0x05}
	for _, id := range wantIDs {
		if b[pos] != id {
			t.Fatalf("param id at %d: got 0x%02X want 0x%02X", pos, b[pos], id)
		}
		l := int(b[pos+1])
		if id == 0x01 && l != 1 {
			t.Errorf("5QI param length: got %d want 1", l)
		}
		if id != 0x01 && l != 3 {
			t.Errorf("bit-rate param 0x%02X length: got %d want 3 (unit + 2-byte value)", id, l)
		}
		pos += 2 + l
	}
	if pos != len(b) {
		t.Errorf("descriptions not fully consumed: pos %d len %d", pos, len(b))
	}
	// GFBR uplink (param 0x02, content at offset 8): unit 0x06 (1 Mbps), value 50
	if b[8] != 0x06 || b[9] != 0 || b[10] != 50 {
		t.Errorf("GFBR UL: got unit=0x%02X val=%d want unit=0x06 val=50", b[8], int(b[9])<<8|int(b[10]))
	}
}

// TestIs5QIGBR checks the resource-type classification per TS 23.501 Table 5.7.4-1.
func TestIs5QIGBR(t *testing.T) {
	gbr := []uint8{1, 2, 3, 4, 65, 66, 67, 71, 76, 82, 85}
	nonGBR := []uint8{5, 6, 7, 8, 9, 69, 70, 79, 80, 86}
	for _, q := range gbr {
		if !Is5QIGBR(q) {
			t.Errorf("5QI %d: want GBR", q)
		}
	}
	for _, q := range nonGBR {
		if Is5QIGBR(q) {
			t.Errorf("5QI %d: want non-GBR", q)
		}
	}
}

// TestEncodeModificationCommandBodyWithQoSFraming verifies the Modification Command
// body IEs use the Table 8.3.7.1.1 IEIs: 0x2A Session-AMBR (TLV), 0x7A Authorized
// QoS rules (TLV-E), 0x79 Authorized QoS flow descriptions (TLV-E).
func TestEncodeModificationCommandBodyWithQoSFraming(t *testing.T) {
	body := EncodePDUSessionModificationCommandBodyWithQoS(1, 7, 200, 50)

	pos := 0
	if body[pos] != IEISessionAMBR || IEISessionAMBR != 0x2A {
		t.Fatalf("expected Session-AMBR IEI 0x2A, got 0x%02X", body[pos])
	}
	pos++
	ambrLen := int(body[pos])
	pos++
	if ambrLen != 6 {
		t.Fatalf("Session-AMBR length: got %d want 6", ambrLen)
	}
	// DL = 200 Mbps, UL = 50 Mbps (unit 0x06 = 1 Mbps)
	if body[pos] != 0x06 || int(body[pos+1])<<8|int(body[pos+2]) != 200 {
		t.Errorf("AMBR DL: got %d want 200", int(body[pos+1])<<8|int(body[pos+2]))
	}
	if body[pos+3] != 0x06 || int(body[pos+4])<<8|int(body[pos+5]) != 50 {
		t.Errorf("AMBR UL: got %d want 50", int(body[pos+4])<<8|int(body[pos+5]))
	}
	pos += ambrLen

	if body[pos] != IEIAuthorizedQoSRules || IEIAuthorizedQoSRules != 0x7A {
		t.Fatalf("expected Authorized QoS rules IEI 0x7A, got 0x%02X", body[pos])
	}
	pos++
	rulesLen := (int(body[pos]) << 8) | int(body[pos+1])
	pos += 2
	// Rule operation must be "modify existing, replace all packet filters" (011).
	if op := body[pos+3] >> 5; op != QoSRuleOpModifyReplaceFilters {
		t.Errorf("rule operation: got %03b want 011 (modify existing)", op)
	}
	pos += rulesLen

	if body[pos] != IEIAuthorizedQoSFlowDesc {
		t.Fatalf("expected Authorized QoS flow descriptions IEI 0x79, got 0x%02X", body[pos])
	}
	pos++
	fdLen := (int(body[pos]) << 8) | int(body[pos+1])
	pos += 2
	if op := body[pos+1] >> 5; op != QoSFlowOpModifyExisting {
		t.Errorf("flow description operation: got %03b want 011 (modify existing)", op)
	}
	// 5QI parameter value must be 7.
	if body[pos+3] != 0x01 || body[pos+5] != 7 {
		t.Errorf("flow description 5QI: got %d want 7", body[pos+5])
	}
	pos += fdLen

	if pos != len(body) {
		t.Errorf("body not fully consumed: pos %d len %d", pos, len(body))
	}
}

// TestEstablishmentAcceptWithQoSIncludesFlowDescriptions verifies the Accept body
// carries IEI 0x79 with the assigned 5QI between S-NSSAI and DNN.
func TestEstablishmentAcceptWithQoSIncludesFlowDescriptions(t *testing.T) {
	ip := net.ParseIP("10.60.0.9")
	body, err := EncodePDUSessionEstablishmentAcceptBodyWithQoS(
		PDUSessionTypeIPv4, SSCMode1, ip, "internet", 1, 7, 200, 50,
		SNSSAI{SST: 1, SD: 0x000001})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Walk: SSC|type, QoS rules LV-E, AMBR LV, then TLVs.
	pos := 1
	pos += 2 + ((int(body[1]) << 8) | int(body[2])) // QoS rules
	pos += 1 + int(body[pos])                       // AMBR

	found5QI := -1
	for pos < len(body) {
		iei := body[pos]
		pos++
		switch iei {
		case IEIPDUAddress, IEISNSSAI5GSM, IEIDNN5GSM:
			l := int(body[pos])
			pos++
			pos += l
		case IEIAuthorizedQoSFlowDesc:
			l := (int(body[pos]) << 8) | int(body[pos+1])
			pos += 2
			fd := body[pos : pos+l]
			// fd[3]=param id (0x01=5QI), fd[5]=value
			if fd[3] == 0x01 {
				found5QI = int(fd[5])
			}
			pos += l
		case IEIEPCO:
			// Always present now (MTU is answered unconditionally, TS 24.008
			// §10.5.6.3 container 0x0010) even with no DNS servers configured.
			l := (int(body[pos]) << 8) | int(body[pos+1])
			pos += 2
			pos += l
		default:
			t.Fatalf("unexpected IEI 0x%02X at %d", iei, pos-1)
		}
	}
	if found5QI != 7 {
		t.Errorf("Authorized QoS flow descriptions 5QI: got %d want 7", found5QI)
	}
}

// TestEncodePCODNSIPv4 checks the raw (E)PCO content: Ext|spare|config-protocol
// octet, then one {container ID 0x000D, length 4, IPv4} block per address.
// Ref: TS 24.008 §10.5.6.3, Table 10.5.154.
func TestEncodePCODNSIPv4(t *testing.T) {
	out := EncodePCODNSIPv4(net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4"))
	want := []byte{
		0x80,             // Ext=1, spare=000, config protocol=0000
		0x00, 0x0D, 0x04, // container ID 0x000D, length 4
		8, 8, 8, 8,
		0x00, 0x0D, 0x04,
		8, 8, 4, 4,
	}
	if len(out) != len(want) {
		t.Fatalf("EncodePCODNSIPv4 length = %d, want %d (got % X)", len(out), len(want), out)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("octet %d: got 0x%02X want 0x%02X (full: % X)", i, out[i], want[i], out)
		}
	}
}

// TestEncodePCODNSIPv4EmptyIsNil ensures no EPCO IE is emitted (nil, not a
// zero-length slice with just the header octet) when no valid IPv4 DNS
// address is given — an empty EPCO body would still cost 3 header bytes in
// the Accept for zero benefit.
func TestEncodePCODNSIPv4EmptyIsNil(t *testing.T) {
	if out := EncodePCODNSIPv4(); out != nil {
		t.Errorf("EncodePCODNSIPv4() with no args = % X, want nil", out)
	}
	if out := EncodePCODNSIPv4(net.ParseIP("2001:db8::1")); out != nil {
		t.Errorf("EncodePCODNSIPv4(IPv6 only) = % X, want nil (IPv4 container only)", out)
	}
}

// TestEstablishmentAcceptDNSVariantOmitsEPCOWhenNoDNS confirms the DNS-aware
// encoder is byte-identical to the original when dns is empty — so every
// existing call site (and its tests) is unaffected by this addition.
func TestEstablishmentAcceptDNSVariantOmitsEPCOWhenNoDNS(t *testing.T) {
	ip := net.ParseIP("10.60.0.9")
	addr := PDUAddressInfo{SessionType: PDUSessionTypeIPv4, IPv4: ip}

	withoutDNS, err := EncodePDUSessionEstablishmentAcceptBodyWithQoSAddr(
		addr, SSCMode1, "internet", 1, 7, 200, 50, SNSSAI{SST: 1, SD: 0x000001})
	if err != nil {
		t.Fatalf("encode (legacy): %v", err)
	}
	viaDNSVariantNilDNS, err := EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNS(
		addr, SSCMode1, "internet", 1, 7, 200, 50, nil, SNSSAI{SST: 1, SD: 0x000001})
	if err != nil {
		t.Fatalf("encode (DNS variant, nil dns): %v", err)
	}
	if string(withoutDNS) != string(viaDNSVariantNilDNS) {
		t.Fatalf("legacy encoder and DNS-variant-with-nil-dns diverge:\nlegacy: % X\nvariant: % X", withoutDNS, viaDNSVariantNilDNS)
	}
}

// TestEstablishmentAcceptIncludesDNSInEPCO walks a full Accept body built with
// two DNS resolvers and confirms the EPCO IE (0x7B) is present, decodes back
// to the same two addresses in order, and — per TS 24.501 Table 8.3.2.1.1 —
// comes BEFORE the DNN IE (0x25).
//
// The "EPCO is the last IE" assertion this test used to make was wrong: the
// table lists several optional IEs after DNN, and EPCO itself precedes DNN.
// Open5GS's encoder (lib/nas/5gs/encoder.c#L3120-3148), pycrate's independent
// from-spec codec and a real captured Open5GS Accept all agree. See
// docs/ACCEPT-DIFF-open5gs-vs-claudia-2026-09-04.md §2a/§3b, finding #2.
func TestEstablishmentAcceptIncludesDNSInEPCO(t *testing.T) {
	ip := net.ParseIP("10.60.0.9")
	addr := PDUAddressInfo{SessionType: PDUSessionTypeIPv4, IPv4: ip}
	dns := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")}

	body, err := EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNS(
		addr, SSCMode1, "internet", 1, 7, 200, 50, dns, SNSSAI{SST: 1, SD: 0x000001})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	pos := 1
	pos += 2 + ((int(body[1]) << 8) | int(body[2])) // QoS rules
	pos += 1 + int(body[pos])                       // AMBR

	var gotEPCO []byte
	idxEPCO, idxDNN := -1, -1
	for pos < len(body) {
		iei := body[pos]
		ieiPos := pos
		pos++
		if iei == IEIDNN5GSM {
			idxDNN = ieiPos
		}
		switch iei {
		case IEIPDUAddress, IEISNSSAI5GSM, IEIDNN5GSM:
			l := int(body[pos])
			pos++
			pos += l
		case IEIAuthorizedQoSFlowDesc:
			l := (int(body[pos]) << 8) | int(body[pos+1])
			pos += 2
			pos += l
		case IEIEPCO:
			idxEPCO = ieiPos
			l := (int(body[pos]) << 8) | int(body[pos+1])
			pos += 2
			gotEPCO = body[pos : pos+l]
			pos += l
		default:
			t.Fatalf("unexpected IEI 0x%02X at %d", iei, pos-1)
		}
	}
	if pos != len(body) {
		t.Fatalf("IE walk did not consume the whole body: %d trailing bytes", len(body)-pos)
	}
	if gotEPCO == nil {
		t.Fatal("no EPCO IE (0x7B) found in the Accept body")
	}
	if idxDNN < 0 {
		t.Fatal("no DNN IE (0x25) found in the Accept body")
	}
	if idxEPCO > idxDNN {
		t.Errorf("IE order: EPCO 0x7B (offset %d) must precede DNN 0x25 (offset %d) per TS 24.501 Table 8.3.2.1.1",
			idxEPCO, idxDNN)
	}
	want := EncodePCODNSAndMTU(DefaultIPv4LinkMTU, dns...)
	if string(gotEPCO) != string(want) {
		t.Errorf("EPCO content = % X, want % X", gotEPCO, want)
	}
}

// TestEstablishmentAcceptIncludesMTUInEPCO confirms the Accept always answers
// the UE's IPv4 Link MTU request (container 0x0010) alongside DNS, even when
// no DNS servers are configured — this is the second half of the live OTA
// finding 2026-09-03: the Pixel 6a's PDU SESSION ESTABLISHMENT REQUEST asked
// for container 0x0010 (IPv4 link MTU) and the Accept never answered it.
func TestEstablishmentAcceptIncludesMTUInEPCO(t *testing.T) {
	ip := net.ParseIP("10.60.0.9")
	addr := PDUAddressInfo{SessionType: PDUSessionTypeIPv4, IPv4: ip}

	body, err := EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNS(
		addr, SSCMode1, "internet", 1, 7, 200, 50, nil, SNSSAI{SST: 1, SD: 0x000001})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// The EPCO IE (0x7B) must be present even with no DNS servers configured,
	// and must decode to just the MTU container. It now sits BEFORE the DNN
	// IE (TS 24.501 Table 8.3.2.1.1), so match the framed IE anywhere in the
	// body rather than at its tail.
	want := EncodePCODNSAndMTU(DefaultIPv4LinkMTU)
	if want == nil {
		t.Fatal("EncodePCODNSAndMTU(DefaultIPv4LinkMTU) = nil, want non-nil (MTU-only EPCO)")
	}
	wantIE := append([]byte{IEIEPCO, byte(len(want) >> 8), byte(len(want) & 0xFF)}, want...)
	idx := bytes.Index(body, wantIE)
	if idx < 0 {
		t.Fatalf("Accept body does not contain the expected MTU-only EPCO IE % X; body: % X", wantIE, body)
	}
	apn := encodeAPN("internet")
	dnnIE := append([]byte{IEIDNN5GSM, byte(len(apn))}, apn...)
	dnnIdx := bytes.Index(body, dnnIE)
	if dnnIdx < 0 {
		t.Fatalf("Accept body does not contain the DNN IE % X; body: % X", dnnIE, body)
	}
	if idx > dnnIdx {
		t.Errorf("EPCO IE at %d must precede the DNN IE at %d", idx, dnnIdx)
	}
}

// TestEncodePCODNSAndMTUGoldenHex decodes the exact bytes EncodePCODNSAndMTU
// produces against a golden hex string byte-by-byte (container ID, length,
// value for each container), independent of the encoder's own internals.
// The golden value matches what a Pixel 6a's DL NAS TRANSPORT (PDU SESSION
// ESTABLISHMENT ACCEPT, PSI 5, "internet") carried on the live OTA capture
// 2026-09-03 (evidence/gnb-ota-ngap.pcap record 51) once this fix landed:
// EPCO ext octet 0x80, IPv4 Link MTU=1400 (0x0578), then DNS 8.8.8.8 and
// 8.8.4.4.
func TestEncodePCODNSAndMTUGoldenHex(t *testing.T) {
	got := EncodePCODNSAndMTU(1400, net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4"))
	goldenHex := "80" + // Ext=1, spare=000, config protocol=0000
		"0010" + "02" + "0578" + // container 0x0010 (IPv4 Link MTU), len 2, value 1400
		"000d" + "04" + "08080808" + // container 0x000D (DNS), len 4, 8.8.8.8
		"000d" + "04" + "08080404" // container 0x000D (DNS), len 4, 8.8.4.4
	want, err := hex.DecodeString(goldenHex)
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodePCODNSAndMTU(1400, 8.8.8.8, 8.8.4.4) = % X, want % X", got, want)
	}

	// Independently re-decode the golden bytes container-by-container (this
	// is the same walk TS 24.008 §10.5.6.3 / a UE's PCO parser performs) to
	// confirm the IDs/lengths/values are self-consistent, not just that the
	// encoder's output matches a hardcoded string.
	if got[0] != 0x80 {
		t.Fatalf("ext/config-protocol octet = 0x%02X, want 0x80", got[0])
	}
	type container struct {
		id  uint16
		val []byte
	}
	var containers []container
	for i := 1; i < len(got); {
		id := uint16(got[i])<<8 | uint16(got[i+1])
		l := int(got[i+2])
		val := got[i+3 : i+3+l]
		containers = append(containers, container{id, val})
		i += 3 + l
	}
	if len(containers) != 3 {
		t.Fatalf("decoded %d containers, want 3 (MTU, DNS, DNS)", len(containers))
	}
	if containers[0].id != ContainerIDIPv4LinkMTU {
		t.Errorf("container 0 id = 0x%04X, want 0x%04X (IPv4 Link MTU)", containers[0].id, ContainerIDIPv4LinkMTU)
	}
	if mtu := uint16(containers[0].val[0])<<8 | uint16(containers[0].val[1]); mtu != 1400 {
		t.Errorf("decoded MTU = %d, want 1400", mtu)
	}
	wantDNS := []string{"8.8.8.8", "8.8.4.4"}
	for i, w := range wantDNS {
		c := containers[i+1]
		if c.id != ContainerIDDNSServerIPv4Address {
			t.Errorf("container %d id = 0x%04X, want 0x%04X (DNS)", i+1, c.id, ContainerIDDNSServerIPv4Address)
		}
		if got := net.IP(c.val).String(); got != w {
			t.Errorf("container %d DNS address = %s, want %s", i+1, got, w)
		}
	}
}

// buildIPCPConfigureRequestEPCO builds a raw (E)PCO value carrying exactly
// what the Pixel 6a's PDU SESSION ESTABLISHMENT REQUEST put in the (E)PCO IE
// on the live OTA capture 2026-09-03: an 0x8021 container with an IPCP
// Configure-Request (code 1), the given identifier, and Configure-Request
// options 0x81 (Primary-DNS) / 0x83 (Secondary-DNS) each carrying the
// RFC 1332 placeholder address 0.0.0.0 (the value the UE sends is
// irrelevant — only the option's presence signals what it wants back).
func buildIPCPConfigureRequestEPCO(identifier uint8, wantPrimary, wantSecondary bool) []byte {
	var opts []byte
	if wantPrimary {
		opts = append(opts, ipcpOptPrimaryDNS, 6, 0, 0, 0, 0)
	}
	if wantSecondary {
		opts = append(opts, ipcpOptSecondaryDNS, 6, 0, 0, 0, 0)
	}
	ipcpLen := 4 + len(opts)
	ipcp := []byte{ipcpCodeConfigureRequest, identifier, byte(ipcpLen >> 8), byte(ipcpLen & 0xFF)}
	ipcp = append(ipcp, opts...)

	container := []byte{byte(containerIDIPCP >> 8), byte(containerIDIPCP & 0xFF), byte(len(ipcp))}
	container = append(container, ipcp...)

	// Ext=1, spare=000, configuration protocol=0000, then the container.
	return append([]byte{0x80}, container...)
}

// TestParseIPCPFromEPCO_ConfigureRequest verifies the request-side decoder
// recognizes an IPCP Configure-Request (code 1) in container 0x8021 and
// reports which DNS options (0x81/0x83) it asked for, preserving the
// identifier that must be echoed back (RFC 1661 §5.1).
func TestParseIPCPFromEPCO_ConfigureRequest(t *testing.T) {
	epco := buildIPCPConfigureRequestEPCO(0x2A, true, true)

	req := ParseIPCPFromEPCO(epco)
	if req == nil {
		t.Fatal("ParseIPCPFromEPCO returned nil, want a Configure-Request")
	}
	if req.Identifier != 0x2A {
		t.Errorf("Identifier = 0x%02X, want 0x2A", req.Identifier)
	}
	if !req.WantsPrimaryDNS {
		t.Error("WantsPrimaryDNS = false, want true (option 0x81 present)")
	}
	if !req.WantsSecondaryDNS {
		t.Error("WantsSecondaryDNS = false, want true (option 0x83 present)")
	}
}

// TestParseIPCPFromEPCO_PrimaryOnly verifies a request asking for only the
// primary DNS option is reported as such (not both, not neither).
func TestParseIPCPFromEPCO_PrimaryOnly(t *testing.T) {
	req := ParseIPCPFromEPCO(buildIPCPConfigureRequestEPCO(0x07, true, false))
	if req == nil {
		t.Fatal("ParseIPCPFromEPCO returned nil, want a Configure-Request")
	}
	if !req.WantsPrimaryDNS || req.WantsSecondaryDNS {
		t.Errorf("WantsPrimaryDNS=%v WantsSecondaryDNS=%v, want true/false",
			req.WantsPrimaryDNS, req.WantsSecondaryDNS)
	}
}

// TestParseIPCPFromEPCO_NoIPCPContainer verifies an (E)PCO with no 0x8021
// container (e.g. only DNS/MTU requests) yields a nil IPCP request rather
// than a spurious match.
func TestParseIPCPFromEPCO_NoIPCPContainer(t *testing.T) {
	// container 0x000D (DNS request), zero-length value — no IPCP present.
	epco := []byte{0x80, 0x00, 0x0D, 0x00}
	if req := ParseIPCPFromEPCO(epco); req != nil {
		t.Errorf("ParseIPCPFromEPCO = %+v, want nil (no 0x8021 container)", req)
	}
}

// TestDecodePDUSessionEstablishmentRequest_IPCP verifies the full request
// decoder (not just the EPCO sub-parser) surfaces IPCPRequest, matching the
// live capture: the Pixel 6a's REQUEST ePco carried, among other containers,
// 0x8021 IPCP Configure-Request with options 0x81/0x83.
func TestDecodePDUSessionEstablishmentRequest_IPCP(t *testing.T) {
	epco := buildIPCPConfigureRequestEPCO(0x11, true, true)

	body := []byte{0, 0} // mandatory integrity protection max data rate (2 octets, value irrelevant)
	body = append(body, IEIEPCO, byte(len(epco)>>8), byte(len(epco)&0xFF))
	body = append(body, epco...)

	msg, err := DecodePDUSessionEstablishmentRequest(body)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if msg.IPCPRequest == nil {
		t.Fatal("IPCPRequest = nil, want non-nil (request ePco carried 0x8021 Configure-Request)")
	}
	if msg.IPCPRequest.Identifier != 0x11 {
		t.Errorf("IPCPRequest.Identifier = 0x%02X, want 0x11", msg.IPCPRequest.Identifier)
	}
	if !msg.IPCPRequest.WantsPrimaryDNS || !msg.IPCPRequest.WantsSecondaryDNS {
		t.Errorf("IPCPRequest = %+v, want both DNS options true", msg.IPCPRequest)
	}
}

// TestEncodeIPCPConfigAckContainerGoldenHex decodes
// EncodeIPCPConfigAckContainer's output against a golden hex string.
// Matches verified Open5GS behavior (src/smf/context.c smf_pco_build,
// case OGS_PCO_ID_INTERNET_PROTOCOL_CONTROL_PROTOCOL): the reply is IPCP
// code 2 (Configure-Ack), NOT code 3 (Configure-Nak) — see the doc comment
// on EncodeIPCPConfigAckContainer for the exact upstream lines/URL.
func TestEncodeIPCPConfigAckContainerGoldenHex(t *testing.T) {
	req := &IPCPConfigureRequest{Identifier: 0x2A, WantsPrimaryDNS: true, WantsSecondaryDNS: true}
	got := EncodeIPCPConfigAckContainer(req, net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4"))

	goldenHex := "8021" + // container ID 0x8021 (IPCP)
		"10" + // container length = 16 (4-byte IPCP header + 2*6-byte options)
		"02" + "2a" + "0010" + // IPCP code=2 (Configure-Ack), identifier=0x2A (echoed), length=16
		"81" + "06" + "08080808" + // option 129 (Primary-DNS), len 6, 8.8.8.8
		"83" + "06" + "08080404" // option 131 (Secondary-DNS), len 6, 8.8.4.4
	want, err := hex.DecodeString(goldenHex)
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeIPCPConfigAckContainer() = % X, want % X", got, want)
	}

	// Explicitly assert code 2 (Ack), not 3 (Nak) — the task hypothesis this
	// guards against. Container layout: ID(2) len(1) [code(1) identifier(1)
	// length(2) options...], so the IPCP code is at offset 3.
	if code := got[3]; code != ipcpCodeConfigureAck {
		t.Fatalf("IPCP code = %d, want %d (Configure-Ack, RFC 1661 §5.2) — must not be 3 (Configure-Nak)", code, ipcpCodeConfigureAck)
	}
}

// TestEncodeIPCPConfigAckContainer_IdentifierEchoed verifies the identifier
// in the Ack always matches the Request's, per RFC 1661 §5.2 ("the
// Identifier field MUST be copied from the Configure-Request").
func TestEncodeIPCPConfigAckContainer_IdentifierEchoed(t *testing.T) {
	for _, id := range []uint8{0x00, 0x07, 0xFF} {
		req := &IPCPConfigureRequest{Identifier: id, WantsPrimaryDNS: true}
		got := EncodeIPCPConfigAckContainer(req, net.ParseIP("1.1.1.1"), nil)
		if len(got) < 6 {
			t.Fatalf("id=0x%02X: container too short: % X", id, got)
		}
		if got[4] != id { // offset 4: ID(2) len(1) code(1) [identifier]
			t.Errorf("id=0x%02X: echoed identifier = 0x%02X, want 0x%02X", id, got[4], id)
		}
	}
}

// TestEncodeIPCPConfigAckContainer_OnlyRequestedOptions verifies the Ack
// includes only the DNS options the UE actually asked for (gated the same
// way Open5GS gates via ipcp_contains_option), not both unconditionally.
func TestEncodeIPCPConfigAckContainer_OnlyRequestedOptions(t *testing.T) {
	req := &IPCPConfigureRequest{Identifier: 0x01, WantsPrimaryDNS: true, WantsSecondaryDNS: false}
	got := EncodeIPCPConfigAckContainer(req, net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4"))
	// container(3) + ipcp header(4) + one option(6) = 13 bytes total.
	if len(got) != 13 {
		t.Fatalf("len = %d, want 13 (only primary DNS option)", len(got))
	}
	if !bytes.Contains(got, []byte{ipcpOptPrimaryDNS, 6, 8, 8, 8, 8}) {
		t.Errorf("missing primary DNS option in % X", got)
	}
	if bytes.Contains(got, []byte{ipcpOptSecondaryDNS, 6, 8, 8, 4, 4}) {
		t.Errorf("secondary DNS option present but was not requested: % X", got)
	}
}

// TestEncodeIPCPConfigAckContainer_NilRequest verifies no container is
// emitted when the UE never sent an IPCP Configure-Request.
func TestEncodeIPCPConfigAckContainer_NilRequest(t *testing.T) {
	if got := EncodeIPCPConfigAckContainer(nil, net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")); got != nil {
		t.Errorf("EncodeIPCPConfigAckContainer(nil, ...) = % X, want nil", got)
	}
}

// TestEncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNSIPCP_EndToEnd
// exercises the full path the SMF uses: decode a UE request carrying an
// IPCP Configure-Request, then encode the Accept body and confirm the EPCO
// carries both the plain 0x000D DNS container (unconditionally, as before)
// and the new 0x8021 IPCP Configure-Ack echoing the request's identifier.
func TestEncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNSIPCP_EndToEnd(t *testing.T) {
	reqEPCO := buildIPCPConfigureRequestEPCO(0x55, true, true)
	body := []byte{0, 0}
	body = append(body, IEIEPCO, byte(len(reqEPCO)>>8), byte(len(reqEPCO)&0xFF))
	body = append(body, reqEPCO...)

	reqMsg, err := DecodePDUSessionEstablishmentRequest(body)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if reqMsg.IPCPRequest == nil {
		t.Fatal("IPCPRequest = nil, want non-nil")
	}

	ip := net.ParseIP("10.60.0.2")
	accept, err := EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNSIPCP(
		PDUAddressInfo{SessionType: PDUSessionTypeIPv4, IPv4: ip}, SSCMode1, "internet",
		1, 9, 100, 100,
		[]net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		reqMsg.IPCPRequest,
	)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	// Find the EPCO IE (IEI 0x7B) in the accept body and re-parse its
	// containers independently of the encoder's internals.
	idx := bytes.IndexByte(accept, IEIEPCO)
	if idx < 0 {
		t.Fatal("accept body has no EPCO IE (0x7B)")
	}
	l := int(accept[idx+1])<<8 | int(accept[idx+2])
	epco := accept[idx+3 : idx+3+l]

	containers := parseEPCOContainers(epco)
	if _, ok := containers[ContainerIDDNSServerIPv4Address]; !ok {
		t.Error("accept EPCO missing plain 0x000D DNS container")
	}
	ipcpVal, ok := containers[containerIDIPCP]
	if !ok {
		t.Fatal("accept EPCO missing 0x8021 IPCP container")
	}
	if ipcpVal[0] != ipcpCodeConfigureAck {
		t.Errorf("accept IPCP code = %d, want %d (Configure-Ack)", ipcpVal[0], ipcpCodeConfigureAck)
	}
	if ipcpVal[1] != 0x55 {
		t.Errorf("accept IPCP identifier = 0x%02X, want 0x55 (echoed from request)", ipcpVal[1])
	}
}

// ---------------------------------------------------------------------------
// Regression tests for the 2026-09-04 Accept-structure fix
// (docs/ACCEPT-DIFF-open5gs-vs-claudia-2026-09-04.md, findings #1/#2/#3).
// ---------------------------------------------------------------------------

// pixel6aRequestBodyHex is the PDU SESSION ESTABLISHMENT REQUEST body (i.e.
// everything after the 5GSM header 2E 05 36 C1) that a Pixel 6a put on the air
// against this lab's own core, byte-for-byte from evidence/gnb-ota-ngap.pcap
// (PSI 5, DNN "internet"), decoded with pycrate. The ePCO container order is
// the load-bearing part: IPCP (0x8021) FIRST, then 0x0005, 0x000A, 0x000D,
// 0x0010, 0x0011.
const pixel6aRequestBodyHex = "ffff" + // integrity protection max data rate (V, 2 octets)
	"91" + // PDU session type = IPv4 (nibble IEI 0x9-)
	"a1" + // SSC mode 1 (nibble IEI 0xA-)
	"2801" + "00" + // 5GSM capability, len 1
	"5510" + "00" + // max supported packet filters (TV, 3 octets)
	"b0" + // always-on requested (nibble IEI 0xB-)
	"7b" + "0023" + // ePCO, TLV-E, len 0x23 = 35
	"80" + // ext=1, configuration protocol = 0000
	"8021" + "10" + "0100001081060000000083060000000" + "0" + // IPCP Configure-Request, id 0, opts 0x81/0x83
	"0005" + "00" +
	"000a" + "00" +
	"000d" + "00" +
	"0010" + "00" +
	"0011" + "00"

// decodePixel6aRequest decodes the captured Pixel 6a request body.
func decodePixel6aRequest(t *testing.T) *PDUSessionEstablishmentRequest {
	t.Helper()
	b, err := hex.DecodeString(pixel6aRequestBodyHex)
	if err != nil {
		t.Fatalf("bad request hex: %v", err)
	}
	req, err := DecodePDUSessionEstablishmentRequest(b)
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}
	return req
}

// TestDecodeRequestPreservesEPCOContainerOrder confirms the decoder records the
// UE's ePCO container IDs in the UE's own order (and its ext octet), which is
// what BuildEPCOReply replays. Ref: TS 24.008 §10.5.6.3.
func TestDecodeRequestPreservesEPCOContainerOrder(t *testing.T) {
	req := decodePixel6aRequest(t)

	want := []uint16{0x8021, 0x0005, 0x000A, 0x000D, 0x0010, 0x0011}
	if len(req.RequestedPCOContainerIDs) != len(want) {
		t.Fatalf("RequestedPCOContainerIDs = %#04x, want %#04x", req.RequestedPCOContainerIDs, want)
	}
	for i, id := range want {
		if req.RequestedPCOContainerIDs[i] != id {
			t.Errorf("container %d = 0x%04X, want 0x%04X (UE request order must be preserved)",
				i, req.RequestedPCOContainerIDs[i], id)
		}
	}
	if req.PCOConfigProtocolOctet != 0x80 {
		t.Errorf("PCOConfigProtocolOctet = 0x%02X, want 0x80 (echoed from the UE)", req.PCOConfigProtocolOctet)
	}
	if req.IPCPRequest == nil || !req.IPCPRequest.WantsPrimaryDNS || !req.IPCPRequest.WantsSecondaryDNS {
		t.Fatalf("IPCPRequest = %+v, want both DNS options requested", req.IPCPRequest)
	}
}

// TestBuildEPCOReplyAnswersInUERequestOrder is finding #1: the reply must
// answer the UE's containers in the UE's own order — IPCP first for this
// phone — exactly like Open5GS's single-pass smf_pco_build
// (src/smf/context.c#L3365) and like the real Open5GS Accept captured to a
// Moto Edge 30 Pro (IPCP, DNS, DNS, MTU).
func TestBuildEPCOReplyAnswersInUERequestOrder(t *testing.T) {
	req := decodePixel6aRequest(t)
	dns := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")}

	epco := BuildEPCOReply(EPCOReplyConfig{
		ConfigProtocolOctet: req.PCOConfigProtocolOctet,
		RequestedIDs:        req.RequestedPCOContainerIDs,
		IPCP:                req.IPCPRequest,
		DNSv4:               dns,
		MTU:                 DefaultIPv4LinkMTU,
	})
	if epco == nil {
		t.Fatal("BuildEPCOReply = nil, want containers")
	}
	if epco[0] != 0x80 {
		t.Errorf("ext/config-protocol octet = 0x%02X, want 0x80 echoed from the UE", epco[0])
	}

	var gotIDs []uint16
	for _, c := range parseEPCOContainerList(epco) {
		gotIDs = append(gotIDs, c.ID)
	}
	// IPCP first (as requested), then one 0x000D per resolver, then MTU, then
	// the zero-length 0x0011 echo. 0x0005 / 0x000A are unimplemented and
	// omitted, exactly as Open5GS omits them.
	want := []uint16{0x8021, 0x000D, 0x000D, 0x0010, 0x0011}
	if len(gotIDs) != len(want) {
		t.Fatalf("reply containers = %#04x, want %#04x", gotIDs, want)
	}
	for i := range want {
		if gotIDs[i] != want[i] {
			t.Fatalf("reply container %d = 0x%04X, want 0x%04X (order = UE request order)", i, gotIDs[i], want[i])
		}
	}

	// Golden bytes for the whole reply, matching the shape of the real
	// Open5GS Accept in §3b of the diff doc.
	wantHex := "80" +
		"8021" + "10" + "0200001081060808080883060808 0404" +
		"000d" + "04" + "08080808" +
		"000d" + "04" + "08080404" +
		"0010" + "02" + "0578" +
		"0011" + "00"
	golden, err := hex.DecodeString(strings.ReplaceAll(wantHex, " ", ""))
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	if !bytes.Equal(epco, golden) {
		t.Errorf("BuildEPCOReply = % X\nwant                 % X", epco, golden)
	}
}

// TestBuildEPCOReplyOmitsUnrequestedAndUnconfigured confirms the two remaining
// smf_pco_build rules: a container the UE did not ask for is never volunteered,
// and 0x0003 (DNS IPv6) is omitted when no IPv6 resolver is configured.
func TestBuildEPCOReplyOmitsUnrequestedAndUnconfigured(t *testing.T) {
	// UE asks only for DNS IPv6 + MTU; no IPv6 resolver configured.
	epco := BuildEPCOReply(EPCOReplyConfig{
		RequestedIDs: []uint16{ContainerIDDNSServerIPv6Address, ContainerIDIPv4LinkMTU},
		DNSv4:        []net.IP{net.ParseIP("8.8.8.8")},
		MTU:          1400,
	})
	var ids []uint16
	for _, c := range parseEPCOContainerList(epco) {
		ids = append(ids, c.ID)
	}
	if len(ids) != 1 || ids[0] != ContainerIDIPv4LinkMTU {
		t.Errorf("containers = %#04x, want just [0x0010] (no unrequested 0x000D, no unconfigured 0x0003)", ids)
	}

	// With an IPv6 resolver configured it is answered, 16 octets, in place.
	epco = BuildEPCOReply(EPCOReplyConfig{
		RequestedIDs: []uint16{ContainerIDDNSServerIPv6Address},
		DNSv6:        []net.IP{net.ParseIP("2001:4860:4860::8888")},
	})
	list := parseEPCOContainerList(epco)
	if len(list) != 1 || list[0].ID != ContainerIDDNSServerIPv6Address || len(list[0].Value) != 16 {
		t.Fatalf("IPv6 DNS container = %+v, want one 0x0003 with a 16-octet value", list)
	}

	// Nothing answerable at all → no IE.
	if got := BuildEPCOReply(EPCOReplyConfig{RequestedIDs: []uint16{0x0005, 0x000A}}); got != nil {
		t.Errorf("BuildEPCOReply(unimplemented ids only) = % X, want nil", got)
	}
}

// TestEstablishmentAcceptIEOrderEPCOBeforeDNN is finding #2, end to end from
// the captured Pixel 6a request: the Accept's top-level IEs must come out in
// TS 24.501 Table 8.3.2.1.1 order, with EPCO (0x7B) BEFORE DNN (0x25), and the
// ePCO inside it must still be in the UE's container order.
func TestEstablishmentAcceptIEOrderEPCOBeforeDNN(t *testing.T) {
	req := decodePixel6aRequest(t)
	body, err := EncodeEstablishmentAcceptBody(EstablishmentAcceptParams{
		Addr:    PDUAddressInfo{SessionType: PDUSessionTypeIPv4, IPv4: net.ParseIP("10.60.0.2")},
		SSCMode: SSCMode1, DNN: "internet",
		QFI: 1, FiveQI: 9, DLMbps: 100, ULMbps: 100,
		DNSv4:   []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		MTU:     DefaultIPv4LinkMTU,
		SNSSAI:  []SNSSAI{{SST: 1, SD: 0x000001}},
		Request: req,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	ieOrder, epco := walkAcceptBodyIEs(t, body)
	wantOrder := []uint8{IEIPDUAddress, IEISNSSAI5GSM, IEIAuthorizedQoSFlowDesc, IEIEPCO, IEIDNN5GSM}
	if len(ieOrder) != len(wantOrder) {
		t.Fatalf("IE order = %#02x, want %#02x", ieOrder, wantOrder)
	}
	for i := range wantOrder {
		if ieOrder[i] != wantOrder[i] {
			t.Fatalf("IE %d = 0x%02X, want 0x%02X (TS 24.501 Table 8.3.2.1.1: EPCO 0x7B before DNN 0x25)",
				i, ieOrder[i], wantOrder[i])
		}
	}
	if len(parseEPCOContainerList(epco)) == 0 {
		t.Fatal("EPCO IE carried no containers")
	}
	if first := parseEPCOContainerList(epco)[0].ID; first != containerIDIPCP {
		t.Errorf("first ePCO container = 0x%04X, want 0x8021 (the UE asked for IPCP first)", first)
	}
}

// TestEstablishmentAcceptCause50OnIPv4v6Downgrade is finding #3: when the UE
// asks for IPv4v6 and the network grants IPv4 only, the Accept must carry the
// 5GSM cause IE (IEI 0x59, TV) with cause #50 "PDU session type IPv4 only
// allowed", right after the Session-AMBR. Ref: TS 24.501 §9.11.4.2,
// Open5GS src/smf/gsm-build.c#L216-226; a real Open5GS Accept carries `59 32`.
func TestEstablishmentAcceptCause50OnIPv4v6Downgrade(t *testing.T) {
	v4v6 := PDUSessionTypeIPv4v6
	v4 := PDUSessionTypeIPv4

	for _, tc := range []struct {
		name      string
		requested *uint8
		granted   uint8
		wantCause uint8 // 0 = no cause IE
	}{
		{"IPv4v6 requested, IPv4 granted", &v4v6, PDUSessionTypeIPv4, Cause5GSMPDUSessionTypeIPv4OnlyAllowed},
		{"IPv4v6 requested, IPv6 granted", &v4v6, PDUSessionTypeIPv6, Cause5GSMPDUSessionTypeIPv6OnlyAllowed},
		{"IPv4v6 requested and granted", &v4v6, PDUSessionTypeIPv4v6, 0},
		{"IPv4 requested, IPv4 granted", &v4, PDUSessionTypeIPv4, 0},
		{"no type requested", nil, PDUSessionTypeIPv4, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := EncodeEstablishmentAcceptBody(EstablishmentAcceptParams{
				Addr: PDUAddressInfo{
					SessionType: tc.granted,
					IPv4:        net.ParseIP("10.60.0.2"),
					IPv6IID:     []byte{0, 0, 0, 0, 0, 0, 0, 1},
				},
				SSCMode: SSCMode1, DNN: "internet",
				QFI: 1, FiveQI: 9, DLMbps: 100, ULMbps: 100,
				Request: &PDUSessionEstablishmentRequest{PDUSessionType: tc.requested},
			})
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			// The cause IE sits between the Session-AMBR (LV) and the PDU
			// address IE, so it is the first byte after the AMBR value.
			pos := 1
			pos += 2 + ((int(body[1]) << 8) | int(body[2])) // QoS rules (LV-E)
			pos += 1 + int(body[pos])                       // Session-AMBR (LV)
			if tc.wantCause == 0 {
				if body[pos] == IEICause5GSM {
					t.Fatalf("unexpected 5GSM cause IE % X", body[pos:pos+2])
				}
				return
			}
			if body[pos] != IEICause5GSM {
				t.Fatalf("IE at %d = 0x%02X, want the 5GSM cause IEI 0x59; body: % X", pos, body[pos], body)
			}
			if body[pos+1] != tc.wantCause {
				t.Errorf("5GSM cause = 0x%02X (#%d), want 0x%02X (#%d)",
					body[pos+1], body[pos+1], tc.wantCause, tc.wantCause)
			}
		})
	}
}

// walkAcceptBodyIEs returns the optional IEIs of an Accept body in wire order,
// plus the EPCO IE's value. It re-implements the walk a UE's NAS parser does,
// independent of the encoder's internals.
func walkAcceptBodyIEs(t *testing.T, body []byte) ([]uint8, []byte) {
	t.Helper()
	pos := 1
	pos += 2 + ((int(body[1]) << 8) | int(body[2])) // QoS rules (LV-E)
	pos += 1 + int(body[pos])                       // Session-AMBR (LV)

	var order []uint8
	var epco []byte
	for pos < len(body) {
		iei := body[pos]
		order = append(order, iei)
		pos++
		switch iei {
		case IEICause5GSM: // TV, 1-octet value
			pos++
		case IEIPDUAddress, IEISNSSAI5GSM, IEIDNN5GSM: // TLV, 1-octet length
			l := int(body[pos])
			pos += 1 + l
		case IEIAuthorizedQoSFlowDesc: // TLV-E, 2-octet length
			l := (int(body[pos]) << 8) | int(body[pos+1])
			pos += 2 + l
		case IEIEPCO: // TLV-E, 2-octet length
			l := (int(body[pos]) << 8) | int(body[pos+1])
			epco = body[pos+2 : pos+2+l]
			pos += 2 + l
		default:
			t.Fatalf("unexpected IEI 0x%02X at offset %d; body: % X", iei, pos-1, body)
		}
	}
	if pos != len(body) {
		t.Fatalf("IE walk overran the body by %d bytes", pos-len(body))
	}
	return order, epco
}
