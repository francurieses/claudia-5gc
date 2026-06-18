package nas

import (
	"net"
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
		default:
			t.Fatalf("unexpected IEI 0x%02X at %d", iei, pos-1)
		}
	}
	if found5QI != 7 {
		t.Errorf("Authorized QoS flow descriptions 5QI: got %d want 7", found5QI)
	}
}
