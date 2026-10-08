package gtp

import (
	"bytes"
	"net"
	"testing"
)

// TestTPDUGolden pins the byte-exact UL T-PDU header (TS 29.281 §5.1, TS 38.415 §5.5.2.1).
func TestTPDUGolden(t *testing.T) {
	inner := []byte{0xAA, 0xBB, 0xCC}
	got := BuildTPDU(nil, 0xB0000001, 1, PDUTypeUL, inner)
	want := []byte{
		0x34, 0xFF, 0x00, 0x0B, 0xB0, 0x00, 0x00, 0x01, // flags, type, length=8+3, TEID
		0x00, 0x00, 0x00, 0x85, // seq, N-PDU, next ext = PDU session container
		0x01, 0x10, 0x01, 0x00, // len 1*4, UL PDU type | spare, QFI 1, no more ext
		0xAA, 0xBB, 0xCC,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("T-PDU bytes\n got % X\nwant % X", got, want)
	}
}

func TestParseRoundTrip(t *testing.T) {
	inner := BuildInnerUDP(nil, net.IPv4(10, 60, 0, 200), net.IPv4(172, 30, 6, 51), 20000, 9000, 1400, 7, 42)
	pkt := BuildTPDU(nil, 0xB0000007, 5, PDUTypeDL, inner)
	tp, err := ParseTPDU(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if tp.TEID != 0xB0000007 || !tp.HasPDU || tp.PDUType != PDUTypeDL || tp.QFI != 5 {
		t.Fatalf("parsed %+v", tp)
	}
	if !bytes.Equal(tp.Inner, inner) {
		t.Fatal("inner mismatch")
	}
	flow, seq, ok := GetPayload(UDPPayload(tp.Inner))
	if !ok || flow != 7 || seq != 42 {
		t.Fatalf("payload flow=%d seq=%d ok=%v", flow, seq, ok)
	}
	if ipChecksum(inner[:20]) != 0 {
		t.Fatal("inner IPv4 header checksum invalid")
	}
}

func TestParseRejectsShort(t *testing.T) {
	if _, err := ParseTPDU([]byte{0x34, 0xFF, 0, 0}); err == nil {
		t.Fatal("want error")
	}
}
