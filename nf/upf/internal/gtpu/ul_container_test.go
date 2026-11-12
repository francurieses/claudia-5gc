package gtpu

import (
	"encoding/binary"
	"log/slog"
	"testing"
)

// ulFrame builds a GTP-U T-PDU (E=1) with the given extension-header chain
// (first byte of chain is already preceded by the next-ext-type octet at
// offset 11) followed by inner (TS 29.281 §5.2.1).
func ulFrame(teid uint32, firstExt byte, chain, inner []byte) []byte {
	h := make([]byte, 12, 12+len(chain)+len(inner))
	h[0], h[1] = 0x34, msgTypeTPDU
	binary.BigEndian.PutUint16(h[2:4], uint16(4+len(chain)+len(inner)))
	binary.BigEndian.PutUint32(h[4:8], teid)
	h[11] = firstExt
	return append(append(h, chain...), inner...)
}

// TestULContainerRel18Fields: a UL PDU Session Container longer than one
// 4-octet unit (Rel-18 fields, TS 38.415 §5.5.2.2) and a following PDU Set
// Information Container (0x04, TS 29.281 V19.2.0) must be skipped without
// affecting the inner payload offset (TS 29.281 §5.2.1).
func TestULContainerRel18Fields(t *testing.T) {
	const qfi = 9
	// UL PDU Session Container, 8 octets (len=2): len | type=1(UL)<<4 | QFI | 4 extra | next.
	ulCont := func(next byte) []byte {
		return []byte{0x02, 0x10, qfi, 0xA1, 0xA2, 0xA3, 0xA4, next}
	}
	// PDU Set Information Container, 8 octets (len=2), terminal.
	setInfo := []byte{0x02, 0x0A, 0x09, 0x00, 0x03, 0x01, 0x00, 0x00}
	legacy := []byte{0x01, 0x10, qfi, 0x00}
	// 12-octet container (len=3) with a 3-unit tail.
	long := append([]byte{0x03, 0x10, qfi}, append(make([]byte, 8), 0x00)...)

	tests := []struct {
		name      string
		chain     []byte
		wantQFIAt int  // offset of QFI within chain
		wantFwd   bool // inner expected to be accepted
	}{
		{"legacy 4-octet", legacy, 2, true},
		{"len 2 extra octets", ulCont(0x00), 2, true},
		{"len 3 extra octets", long, 2, true},
		{"len 2 then PDU Set Info 0x04", append(ulCont(extHdrTypePDUSetInfo), setInfo...), 2, true},
		{"truncated: len overruns frame", []byte{0x80, 0x10, qfi, 0x00}, 2, false},
		{"zero length ext header", []byte{0x00, 0x10, qfi, 0x00}, 2, false},
		{"chain ends mid-way (next!=0, no data)", ulCont(extHdrTypePDUSetInfo), 2, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, sess, _, _ := benchServer(t, slog.LevelInfo)
			sess.URRState.Installed = true
			inner := benchInnerUDP(sess.UEIP, 100)
			pkt := ulFrame(sess.ULTEID, extHdrTypePDUSessionContainer, tc.chain, inner)
			if got := tc.chain[tc.wantQFIAt]; got != qfi {
				t.Fatalf("test frame QFI octet = %d, want %d", got, qfi)
			}
			before := sess.URRState.ULVolume.Load()
			s.handlePacket(pkt) // must not panic
			got := sess.URRState.ULVolume.Load() - before
			if tc.wantFwd && got != uint64(len(inner)) {
				t.Errorf("accepted inner bytes = %d, want %d (offset wrong or dropped)", got, len(inner))
			}
			if !tc.wantFwd && got != 0 {
				t.Errorf("malformed frame accepted: %d bytes counted", got)
			}
		})
	}
}
