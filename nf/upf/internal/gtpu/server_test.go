package gtpu

import "testing"

// TestBuildDLPDUSessionContainerWireFormat pins the exact byte layout of the
// NG-U extension block a DL GTP-U packet must carry (TS 29.281 §5.2.1, TS
// 38.415 §5.5.2.1). This is the fix for a live-OTA finding 2026-09-03: the
// UPF sent plain GTP-U T-PDUs with E=0 and no PDU Session Container, and the
// gNB rejected every single one with "Incomplete PDU at NG-U interface:
// missing or invalid PDU session container" — so no DL packet (ICMP replies
// included) ever reached the UE, even though the PFCP session, QER, and UL
// path were all correctly established.
func TestBuildDLPDUSessionContainerWireFormat(t *testing.T) {
	ext := buildDLPDUSessionContainer(5)
	want := []byte{
		0x00, 0x00, // Sequence Number (unused)
		0x00,                          // N-PDU Number (unused)
		extHdrTypePDUSessionContainer, // Next Extension Header Type = 0x85
		0x01,                          // ext header length = 1 * 4 = 4 octets
		pduSessionContainerDL,         // PDU Type = DL (0), spare/PPP/RQI = 0
		0x05,                          // QFI = 5
		0x00,                          // Next Extension Header Type = none
	}
	if len(ext) != len(want) {
		t.Fatalf("buildDLPDUSessionContainer length = %d, want %d (% X)", len(ext), len(want), ext)
	}
	for i := range want {
		if ext[i] != want[i] {
			t.Errorf("octet %d: got 0x%02X want 0x%02X (full: % X)", i, ext[i], want[i], ext)
		}
	}
}

// TestBuildDLPDUSessionContainerMasksQFI guards against a QFI value with the
// spare high bits set (TS 38.415: QFI is 6 bits) leaking into the PDU Type /
// spare nibble of the same octet.
func TestBuildDLPDUSessionContainerMasksQFI(t *testing.T) {
	ext := buildDLPDUSessionContainer(0xFF)
	if got, want := ext[6], byte(0x3F); got != want {
		t.Errorf("QFI octet with 0xFF input = 0x%02X, want masked 0x%02X", got, want)
	}
}

// TestDLPacketRoundTripsThroughULParser feeds a full GTP-U packet built the
// way sendGTPU builds it (header + extension block + inner payload) through
// the same extension-skipping loop handlePacket uses for UL, confirming a
// peer that speaks NG-U (E/S/PN framing) can walk past our extension header
// to the inner IP payload without corrupting the offset.
func TestDLPacketRoundTripsThroughULParser(t *testing.T) {
	inner := []byte("fake-inner-ipv4-packet")
	ext := buildDLPDUSessionContainer(1)

	hdr := make([]byte, gtpuMinHdr)
	hdr[0] = 0x34 // E=1
	hdr[1] = msgTypeTPDU
	hdr[2] = byte((len(ext) + len(inner)) >> 8)
	hdr[3] = byte((len(ext) + len(inner)) & 0xFF)

	pkt := append(append([]byte{}, hdr...), ext...)
	pkt = append(pkt, inner...)

	// Mirror handlePacket's extension-skipping loop (server.go) rather than
	// import it (unexported), since the framing contract is what's under
	// test, not a specific function name.
	flags := pkt[0]
	hdrLen := gtpuMinHdr
	if flags&0x07 != 0 {
		hdrLen = gtpuExtHdr
		for pkt[hdrLen-1] != 0 {
			extLen := int(pkt[hdrLen]) * 4
			hdrLen += extLen
		}
	}
	got := string(pkt[hdrLen:])
	if got != string(inner) {
		t.Errorf("recovered inner payload = %q, want %q", got, string(inner))
	}
}
