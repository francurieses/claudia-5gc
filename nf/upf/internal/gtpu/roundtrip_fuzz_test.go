package gtpu

// roundtrip_fuzz_test.go — fuzz targets for the GTP-U framing (CI-003). Test-only: the N3 hot path
// in server.go is exercised as is, not refactored.
//   - FuzzHandlePacket: handlePacket never panics on an arbitrary datagram, both for an unknown
//     TEID and with the TEID forced to a live session's UL TEID, so the extension-header walk and
//     the inner IPv4/IPv6 handling (ICMP replies, RA, TUN forwarding) all see fuzzed octets.
//   - FuzzDLHeader: putDLHeaderOpts writes a header that an independent TS 29.281 §5.1/§5.2 parser
//     walks to exactly dlHeaderLen(o), with the GTP-U Length covering extensions + inner payload,
//     the TEID and QFI intact, and every PDU Set Information field read back equal to its masked
//     input (TS 38.415 §5.5.2.1 DL PDU SESSION INFORMATION, §6.5.2.1 DL PDU SET INFORMATION).
// Ref: TS 29.281 §5.1, §5.2.1, §5.2.2.7, §5.2.2.8; TS 38.415 §5.5.2.1, §6.5.2.1.

import (
	"encoding/binary"
	"log/slog"
	"testing"
)

func FuzzHandlePacket(f *testing.F) {
	s, sess, _, _ := benchServer(f, slog.LevelInfo)
	inner := benchInnerUDP(sess.UEIP, 64)
	f.Add(benchGTPU(sess.ULTEID, inner), true)
	f.Add(benchGTPU(sess.ULTEID, inner)[:12], true)
	f.Add(benchGTPU(0xDEADBEEF, inner), false)
	var dl [dlHeadroom + 12]byte
	n := putDLHeaderOpts(dl[:], sess.ULTEID, 9, 0, &DLHeaderOptions{PDUSet: &PDUSetInfo{EDB: true, HasPSSize: true, PSSize: 1}})
	f.Add(append(dl[:n:n], inner...), true)
	f.Add([]byte{0x34, msgTypeTPDU, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0x85}, true) // E flag, chain runs off the end
	f.Add([]byte{0x34, msgTypeTPDU, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0x85, 0x00, 0, 0, 0}, true)
	f.Fuzz(func(t *testing.T, pkt []byte, ownTEID bool) {
		pkt = append([]byte(nil), pkt...)
		if ownTEID && len(pkt) >= gtpuMinHdr {
			binary.BigEndian.PutUint32(pkt[4:8], sess.ULTEID)
		}
		s.handlePacket(pkt) // property: no panic
	})
}

// parsedDL is what the reference parser extracts from a DL header.
type parsedDL struct {
	hdrLen, gtpLen int
	teid           uint32
	qfi            uint8
	pduSet         *PDUSetInfo
}

// parseDL is an independent reading of TS 29.281 §5.1/§5.2 and TS 38.415 §5.5.2 (not the
// handlePacket loop): it returns an error string instead of a value when the framing is invalid.
func parseDL(h []byte) (parsedDL, string) {
	var p parsedDL
	if len(h) < gtpuExtHdr || h[0] != 0x34 || h[1] != msgTypeTPDU {
		return p, "bad mandatory header (version 1, PT=1, E=1, T-PDU)"
	}
	p.gtpLen = int(binary.BigEndian.Uint16(h[2:4]))
	p.teid = binary.BigEndian.Uint32(h[4:8])
	next, off := h[11], gtpuExtHdr
	for next != 0 {
		if off >= len(h) {
			return p, "extension chain runs past the buffer"
		}
		l := int(h[off]) * 4
		if l < 4 || off+l > len(h) {
			return p, "extension length invalid"
		}
		c := h[off+1 : off+l-1] // content between the length octet and the next-type octet
		switch next {
		case extHdrTypePDUSessionContainer:
			if c[0]>>4 != pduSessionContainerDL {
				return p, "PDU Session Container is not DL PDU SESSION INFORMATION"
			}
			p.qfi = c[1] & 0x3F
		case extHdrTypePDUSetInfo:
			if c[0]>>4 != pduSetInfoPDUTypeDL {
				return p, "PDU Set Information is not DL"
			}
			ps := &PDUSetInfo{
				EDB: c[0]&pduSetInfoEDBBit != 0, EPDU: c[0]&pduSetInfoEPDUBit != 0,
				HasPSSize: c[0]&pduSetInfoPSSIBit != 0,
				PSSN:      uint16(c[1]&0x03)<<8 | uint16(c[2]),
				PSI:       c[3] & pduSetInfoPSIMask,
				PSN:       c[4],
			}
			if c[1]>>2 != p.qfi {
				return p, "QFI differs between the two containers"
			}
			if ps.HasPSSize {
				ps.PSSize = uint32(c[5])<<16 | uint32(c[6])<<8 | uint32(c[7])
			}
			p.pduSet = ps
		default:
			return p, "unexpected extension header type"
		}
		next = h[off+l-1]
		off += l
	}
	p.hdrLen = off
	return p, ""
}

func FuzzDLHeader(f *testing.F) {
	f.Add(uint32(0xDEADBEEF), uint8(9), uint16(100), false, false, false, false, uint8(0), uint16(0), uint8(0), uint32(0))
	f.Add(uint32(1), uint8(0xFF), uint16(0), true, true, true, true, uint8(0xFF), uint16(0xFFFF), uint8(0xFF), uint32(0xFFFFFFFF))
	f.Add(uint32(7), uint8(5), uint16(1400), true, false, true, false, uint8(3), uint16(1023), uint8(2), uint32(0))
	f.Fuzz(func(t *testing.T, teid uint32, qfi uint8, innerLen uint16, withSet, edb, epdu, hasSize bool,
		psi uint8, pssn uint16, psn uint8, size uint32) {
		if int(innerLen) > 0xFFFF-dlHeadroom-12 {
			return // the 16-bit GTP-U Length must also cover the extension headers
		}
		var o *DLHeaderOptions
		if withSet {
			o = &DLHeaderOptions{PDUSet: &PDUSetInfo{EDB: edb, EPDU: epdu, PSI: psi, PSSN: pssn, PSN: psn,
				HasPSSize: hasSize, PSSize: size}}
		}
		h := make([]byte, dlHeaderLen(o))
		for i := range h {
			h[i] = 0xA5 // garbage, so an octet the writer forgets to set is visible
		}
		n := putDLHeaderOpts(h, teid, qfi, int(innerLen), o)
		if n != dlHeaderLen(o) {
			t.Fatalf("putDLHeaderOpts returned %d, dlHeaderLen %d", n, dlHeaderLen(o))
		}
		p, bad := parseDL(h[:n])
		if bad != "" {
			t.Fatalf("%s\n header %x", bad, h[:n])
		}
		if p.hdrLen != n || p.gtpLen != n-gtpuMinHdr+int(innerLen) || p.teid != teid || p.qfi != qfi&0x3F {
			t.Fatalf("header fields: parsed %+v, want hdrLen %d gtpLen %d teid %#x qfi %d\n header %x",
				p, n, n-gtpuMinHdr+int(innerLen), teid, qfi&0x3F, h[:n])
		}
		if !withSet {
			if p.pduSet != nil {
				t.Fatalf("PDU Set Information present without options\n header %x", h[:n])
			}
			return
		}
		want := PDUSetInfo{EDB: edb, EPDU: epdu, PSI: psi & pduSetInfoPSIMask, PSSN: pssn & pduSetInfoPSSNMask,
			PSN: psn, HasPSSize: hasSize}
		if hasSize {
			want.PSSize = size & pduSetInfoPSSMask
		}
		if p.pduSet == nil || *p.pduSet != want {
			t.Fatalf("PDU Set Information: parsed %+v, want %+v\n header %x", p.pduSet, want, h[:n])
		}
	})
}
