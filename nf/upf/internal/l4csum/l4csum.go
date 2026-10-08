// Package l4csum verifies and repairs the TCP/UDP checksum of a single IP
// packet in place. It exists for the UPF N6 downlink path: on hosts where the
// the host network path is a userspace proxy (Docker Desktop for macOS),
// TCP segments read from the TUN can carry a complete but incorrect L4
// checksum (not a CHECKSUM_PARTIAL/offload artefact) that a UE rejects once
// the packet is carried unmodified inside GTP-U (TS 29.281 §5, G-PDU = T-PDU).
//
// The function is pure, allocation-free and safe for concurrent use.
//
// Refs: RFC 1071 (Internet checksum), RFC 793 §3.1 (TCP), RFC 768 (UDP),
// RFC 8200 §8.1 (IPv6 upper-layer checksums, UDP zero checksum illegal).
package l4csum

import "encoding/binary"

// Protocol / IP-version labels reported in Result.
const (
	// ProtoTCP labels a repaired TCP segment.
	ProtoTCP = "tcp"
	// ProtoUDP labels a repaired UDP datagram.
	ProtoUDP = "udp"
	// IPv4 labels an IPv4 packet.
	IPv4 = "v4"
	// IPv6 labels an IPv6 packet.
	IPv6 = "v6"
)

// Result describes a repaired packet.
type Result struct {
	Proto string // ProtoTCP or ProtoUDP
	IP    string // IPv4 or IPv6
	Old   uint16 // checksum found in the packet before the repair
	New   uint16 // checksum written by the repair
}

const (
	ipProtoTCP = 6  // IANA protocol number, RFC 793
	ipProtoUDP = 17 // IANA protocol number, RFC 768

	ipv4MinHdr      = 20     // RFC 791 §3.1 minimum header length
	ipv4OffTotalLen = 2      // Total Length field
	ipv4OffFrag     = 6      // Flags + Fragment Offset field
	ipv4OffProto    = 9      // Protocol field
	ipv4OffSrc      = 12     // Source address (4 octets), dst follows
	ipv4AddrLen     = 4      // IPv4 address length
	ipv4FragMask    = 0x3fff // MF flag (0x2000) | fragment offset (0x1fff)

	ipv6Hdr        = 40 // RFC 8200 §3 fixed header length
	ipv6OffPayload = 4  // Payload Length field
	ipv6OffNext    = 6  // Next Header field
	ipv6OffSrc     = 8  // Source address (16 octets), dst follows
	ipv6AddrLen    = 16 // IPv6 address length

	tcpMinHdr      = 20 // RFC 793 §3.1 minimum header length
	tcpOffChecksum = 16 // TCP checksum field offset
	udpHdr         = 8  // RFC 768 header length
	udpOffLength   = 4  // UDP length field offset
	udpOffChecksum = 6  // UDP checksum field offset

	csumValid = 0xFFFF // folded sum over data incl. checksum of a valid segment
)

// Repair verifies the TCP/UDP checksum of the IP packet pkt (IPv4 or IPv6,
// starting at the IP header) and rewrites it in place when it is wrong.
// It reports whether the packet was modified. Ineligible packets (fragments,
// IPv6 extension headers, truncated or inconsistent lengths, other protocols,
// IPv4 UDP with checksum 0 meaning "none") are left untouched. IPv6 UDP with
// checksum 0 is computed and filled in (RFC 8200 §8.1). Bytes beyond the IP
// total/payload length (link padding) are ignored.
func Repair(pkt []byte) (Result, bool) {
	if len(pkt) < 1 {
		return Result{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		return repairV4(pkt)
	case 6:
		return repairV6(pkt)
	}
	return Result{}, false
}

func repairV4(pkt []byte) (Result, bool) {
	if len(pkt) < ipv4MinHdr {
		return Result{}, false
	}
	hl := int(pkt[0]&0x0F) * 4
	total := int(binary.BigEndian.Uint16(pkt[ipv4OffTotalLen:]))
	if hl < ipv4MinHdr || total > len(pkt) || hl > total {
		return Result{}, false
	}
	if binary.BigEndian.Uint16(pkt[ipv4OffFrag:])&ipv4FragMask != 0 {
		return Result{}, false
	}
	proto := pkt[ipv4OffProto]
	seg := pkt[hl:total]
	var acc uint64
	acc = sum(pkt[ipv4OffSrc:ipv4OffSrc+2*ipv4AddrLen], acc)
	acc += uint64(proto) + uint64(len(seg))
	return finish(seg, proto, IPv4, acc, false)
}

func repairV6(pkt []byte) (Result, bool) {
	if len(pkt) < ipv6Hdr {
		return Result{}, false
	}
	plen := int(binary.BigEndian.Uint16(pkt[ipv6OffPayload:]))
	if ipv6Hdr+plen > len(pkt) {
		return Result{}, false
	}
	proto := pkt[ipv6OffNext]
	seg := pkt[ipv6Hdr : ipv6Hdr+plen]
	var acc uint64
	acc = sum(pkt[ipv6OffSrc:ipv6OffSrc+2*ipv6AddrLen], acc)
	acc += uint64(proto) + uint64(len(seg))
	return finish(seg, proto, IPv6, acc, true)
}

// finish validates the L4 header, then verifies/repairs the checksum.
// acc already holds the pseudo-header sum.
func finish(seg []byte, proto byte, ip string, acc uint64, v6 bool) (Result, bool) {
	var off int
	var name string
	switch proto {
	case ipProtoTCP:
		if len(seg) < tcpMinHdr {
			return Result{}, false
		}
		off, name = tcpOffChecksum, ProtoTCP
	case ipProtoUDP:
		if len(seg) < udpHdr || int(binary.BigEndian.Uint16(seg[udpOffLength:])) != len(seg) {
			return Result{}, false
		}
		off, name = udpOffChecksum, ProtoUDP
	default:
		return Result{}, false
	}
	stored := binary.BigEndian.Uint16(seg[off:])
	if proto == ipProtoUDP && stored == 0 && !v6 {
		return Result{}, false // IPv4: 0 = sender computed no checksum (RFC 768)
	}
	// off is even, so the checksum field splits the sum on a 16-bit boundary.
	acc = sum(seg[:off], acc)
	acc = sum(seg[off+2:], acc)
	computed := ^fold(acc)
	if !(proto == ipProtoUDP && v6 && stored == 0) && fold(acc+uint64(stored)) == csumValid {
		return Result{}, false
	}
	if proto == ipProtoUDP && computed == 0 {
		computed = 0xFFFF // RFC 768 / RFC 8200 §8.1
	}
	binary.BigEndian.PutUint16(seg[off:], computed)
	return Result{Proto: name, IP: ip, Old: stored, New: computed}, true
}

// sum adds b, taken as big-endian 16-bit words (a trailing odd octet is padded
// with zero), to acc without folding. b must start on a 16-bit boundary of the
// logical stream. Eight octets are accumulated per step as two 32-bit halves so
// the uint64 accumulator cannot overflow for any IP packet (RFC 1071 §2(C)).
func sum(b []byte, acc uint64) uint64 {
	for len(b) >= 8 {
		v := binary.BigEndian.Uint64(b)
		acc += v>>32 + v&0xFFFFFFFF
		b = b[8:]
	}
	for len(b) >= 2 {
		acc += uint64(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint64(b[0]) << 8
	}
	return acc
}

// fold reduces a wide one's-complement accumulator to 16 bits.
func fold(acc uint64) uint16 {
	for acc>>16 != 0 {
		acc = acc&0xFFFF + acc>>16
	}
	return uint16(acc)
}
