// Package gtp builds and parses the GTP-U T-PDUs and inner IPv4/UDP packets used by
// gtpu-bench. Wire format per TS 29.281 §5.1/§5.2 with the NG-U PDU Session Container
// extension of TS 38.415 §5.5.2.1; nothing here is a bespoke format.
package gtp

import (
	"encoding/binary"
	"errors"
	"net"
)

// GTP-U constants (TS 29.281 §5.1, §5.2.1; TS 38.415 §5.5.2.1).
const (
	// Port is the registered GTP-U UDP port (TS 29.281 §4.4.2).
	Port = 2152
	// MsgTPDU is the G-PDU message type (TS 29.281 §6.1).
	MsgTPDU = 0xFF
	// ExtPDUSessionContainer is the PDU Session Container extension header type.
	ExtPDUSessionContainer = 0x85
	// PDUTypeDL / PDUTypeUL are the PDU Type nibble values (TS 38.415 Table 5.5.2.1-2).
	PDUTypeDL = 0
	PDUTypeUL = 1
	// HeaderLen is the mandatory 8 octets plus the 4-octet optional block (E=1).
	HeaderLen = 12
	// Overhead is what a UL/DL T-PDU adds to the inner packet: GTP-U 8 + opt 4 + PDU session container 4.
	Overhead = 16
)

// ErrShort / ErrNotTPDU describe parse failures.
var (
	ErrShort   = errors.New("gtp: packet too short")
	ErrNotTPDU = errors.New("gtp: not a T-PDU")
)

// BuildTPDU wraps inner in a GTP-U T-PDU with an NG-U PDU Session Container carrying
// pduType (PDUTypeUL for gNB→UPF, as UERANSIM sends it) and qfi. It appends to dst.
func BuildTPDU(dst []byte, teid uint32, qfi uint8, pduType uint8, inner []byte) []byte {
	ext := []byte{
		0x00, 0x00, // sequence number (unused)
		0x00,                   // N-PDU number (unused)
		ExtPDUSessionContainer, // next extension header type
		0x01,                   // length: 1 * 4 octets
		pduType << 4,           // PDU type (bits 8-5) | spare/PPP/RQI
		qfi & 0x3F,             // spare | QFI
		0x00,                   // next extension header type: none
	}
	var h [8]byte
	h[0] = 0x34 // version 1, PT=1, E=1
	h[1] = MsgTPDU
	binary.BigEndian.PutUint16(h[2:4], uint16(len(ext)+len(inner)))
	binary.BigEndian.PutUint32(h[4:8], teid)
	dst = append(dst, h[:]...)
	dst = append(dst, ext...)
	return append(dst, inner...)
}

// TPDU is a parsed GTP-U T-PDU.
type TPDU struct {
	TEID    uint32
	HasPDU  bool  // a PDU Session Container was present
	PDUType uint8 // valid when HasPDU
	QFI     uint8 // valid when HasPDU
	Inner   []byte
}

// ParseTPDU walks the (extension) headers like a conformant receiver and returns the inner packet.
func ParseTPDU(p []byte) (TPDU, error) {
	var t TPDU
	if len(p) < 8 {
		return t, ErrShort
	}
	if p[1] != MsgTPDU {
		return t, ErrNotTPDU
	}
	t.TEID = binary.BigEndian.Uint32(p[4:8])
	off := 8
	if p[0]&0x07 != 0 {
		if len(p) < HeaderLen {
			return t, ErrShort
		}
		off = HeaderLen
		next := p[11]
		for next != 0 {
			if len(p) <= off {
				return t, ErrShort
			}
			l := int(p[off]) * 4
			if l < 4 || off+l > len(p) {
				return t, ErrShort
			}
			if next == ExtPDUSessionContainer && l >= 4 {
				t.HasPDU = true
				t.PDUType = p[off+1] >> 4
				t.QFI = p[off+2] & 0x3F
			}
			next = p[off+l-1]
			off += l
		}
	}
	if len(p) <= off {
		return t, ErrShort
	}
	t.Inner = p[off:]
	return t, nil
}

// Payload layout carried in every inner UDP datagram (after the 8-octet UDP header):
// magic(4) | flow(2) | reserved(2) | seq(8).
const (
	magic      = 0x47424e43 // "GBNC"
	PayloadMin = 16
)

// BuildInnerUDP returns an IPv4/UDP packet of total length size (>= 20+8+PayloadMin)
// from src:sport to dst:dport whose payload carries flow and seq. The IPv4 header
// checksum is set; the UDP checksum is 0 ("not computed", RFC 768).
func BuildInnerUDP(dst []byte, src, dstIP net.IP, sport, dport uint16, size int, flow uint16, seq uint64) []byte {
	if size < 20+8+PayloadMin {
		size = 20 + 8 + PayloadMin
	}
	if cap(dst) < size {
		dst = make([]byte, size)
	}
	p := dst[:size]
	for i := range p {
		p[i] = 0
	}
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	p[8], p[9] = 64, 17
	copy(p[12:16], src.To4())
	copy(p[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(p[10:12], ipChecksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	binary.BigEndian.PutUint16(p[24:26], uint16(size-20))
	PutPayload(p[28:], flow, seq)
	return p
}

// PutPayload writes the bench payload header at the start of b (len(b) >= PayloadMin).
func PutPayload(b []byte, flow uint16, seq uint64) {
	binary.BigEndian.PutUint32(b[0:4], magic)
	binary.BigEndian.PutUint16(b[4:6], flow)
	binary.BigEndian.PutUint64(b[8:16], seq)
}

// GetPayload decodes the bench payload header; ok is false if b is not one.
func GetPayload(b []byte) (flow uint16, seq uint64, ok bool) {
	if len(b) < PayloadMin || binary.BigEndian.Uint32(b[0:4]) != magic {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(b[4:6]), binary.BigEndian.Uint64(b[8:16]), true
}

// UDPPayload returns the UDP payload of an inner IPv4/UDP packet, or nil.
func UDPPayload(inner []byte) []byte {
	if len(inner) < 28 || inner[0]>>4 != 4 || inner[9] != 17 {
		return nil
	}
	ihl := int(inner[0]&0x0F) * 4
	if ihl < 20 || len(inner) < ihl+8 {
		return nil
	}
	return inner[ihl+8:]
}

func ipChecksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for s>>16 != 0 {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return ^uint16(s)
}
