// Package ra builds and parses RFC 4861 ICMPv6 Neighbor Discovery messages
// needed for IPv6 stateless address autoconfiguration (SLAAC, RFC 4862) of a
// delegated /64 PDU session prefix: the Router Advertisement (RA) the UPF
// sends downlink to the UE, and the Router Solicitation (RS) it may receive
// uplink from the UE. This is a standard IETF wire format (not a 3GPP
// protocol), hand-built here with named constants and RFC section
// references — no bespoke framing is introduced.
//
// Ref: RFC 4861 §4.1 (Router Solicitation), §4.2 (Router Advertisement),
// §4.6.2 (Prefix Information option); RFC 4443 §2.3 (ICMPv6 checksum);
// RFC 4862 (SLAAC); TS 23.501 §5.8.2.2.2 (5GC use of RA for PDU session
// prefix delegation).
package ra

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// ICMPv6 message types (RFC 4861 §4.1, §4.2).
const (
	ICMPv6TypeRouterSolicitation  uint8 = 133
	ICMPv6TypeRouterAdvertisement uint8 = 134
	icmpv6Code                    uint8 = 0
)

// IPv6 fixed header field values (RFC 8200 §3).
const (
	ipv6Version                = 6
	ipv6HeaderLen              = 40
	NextHeaderICMPv6     uint8 = 58  // RFC 4443 §2.1
	hopLimitNeighborDisc uint8 = 255 // RFC 4861 §4.2/§4.1 mandate Hop Limit 255 for ND messages
)

// Router Advertisement flags octet (RFC 4861 §4.2): M (Managed) and O
// (Other config) bits. SLAAC-only prefix delegation keeps both clear.
const (
	raFlagManaged     uint8 = 0x80
	raFlagOtherConfig uint8 = 0x40
)

// Prefix Information option (RFC 4861 §4.6.2).
const (
	optTypePrefixInformation       uint8 = 3
	optLenPrefixInformation8Octets uint8 = 4    // option length in 8-octet units (32 bytes)
	prefixInfoFlagOnLink           uint8 = 0x80 // L bit
	prefixInfoFlagAutonomous       uint8 = 0x40 // A bit
	prefixInfoOptionLen                  = 32   // bytes: 1+1+1+1+4+4+4+16
)

// Defaults applied by BuildRouterAdvertisement when the caller leaves the
// corresponding Options field at zero. RFC 4861 §6.2.1 gives these as the
// recommended default values for AdvCurHopLimit / AdvDefaultLifetime /
// AdvValidLifetime / AdvPreferredLifetime; MaxRtrAdvInterval bounds the
// periodic advertising cadence this UPF uses (well inside the RFC's
// [4s, 1800s] legal range).
const (
	// DefaultCurHopLimit is advertised to UEs as the IPv6 Hop Limit to use
	// for outgoing packets. Ref: RFC 4861 §6.2.1.
	DefaultCurHopLimit uint8 = 64
	// DefaultRouterLifetimeSeconds bounds how long the UE may use the UPF as
	// its default router. Ref: RFC 4861 §6.2.1.
	DefaultRouterLifetimeSeconds uint16 = 1800
	// DefaultValidLifetimeSeconds / DefaultPreferredLifetimeSeconds mirror the
	// RFC 4861 §6.2.1 recommended defaults (30 days / 7 days) for the
	// delegated /64 Prefix Information option.
	DefaultValidLifetimeSeconds     uint32 = 2592000
	DefaultPreferredLifetimeSeconds uint32 = 604800
	// MaxRtrAdvInterval bounds the UPF's periodic (unsolicited) RA cadence
	// per session. Ref: RFC 4861 §6.2.1 (legal range [4s, 1800s]).
	MaxRtrAdvInterval = 30 * time.Second
)

// LinkLocalRouterAddr / AllNodesMulticastAddr are the default IPv6 header
// source/destination for a periodic (unsolicited) Router Advertisement.
// Ref: RFC 4861 §4.2, §6.2.3.
var (
	LinkLocalRouterAddr   = net.ParseIP("fe80::1")
	AllNodesMulticastAddr = net.ParseIP("ff02::1")
)

// Options customises a built Router Advertisement. Zero-valued fields fall
// back to the RFC 4861 §6.2.1 defaults above.
type Options struct {
	// CurHopLimit is advertised in the RA; 0 uses DefaultCurHopLimit.
	CurHopLimit uint8
	// RouterLifetimeSeconds; 0 uses DefaultRouterLifetimeSeconds.
	RouterLifetimeSeconds uint16
	// ValidLifetimeSeconds / PreferredLifetimeSeconds for the Prefix
	// Information option; 0 uses the Default* constants above.
	ValidLifetimeSeconds     uint32
	PreferredLifetimeSeconds uint32
	// Src is the IPv6 header source address; nil uses LinkLocalRouterAddr.
	Src net.IP
	// Dst is the IPv6 header destination address; nil uses
	// AllNodesMulticastAddr (periodic RA). Set to the UE's solicitation
	// source address for a unicast solicited RA (RFC 4861 §6.2.6).
	Dst net.IP
}

// BuildRouterAdvertisement returns a complete IPv6 packet carrying an ICMPv6
// Router Advertisement (RFC 4861 §4.2) with a single Prefix Information
// option (§4.6.2) advertising prefix (a /64) for SLAAC (L=1 on-link, A=1
// autonomous). Ref: TS 23.501 §5.8.2.2.2.
func BuildRouterAdvertisement(prefix *net.IPNet, opts Options) ([]byte, error) {
	if prefix == nil {
		return nil, fmt.Errorf("upf: build router advertisement: nil prefix")
	}
	ones, bits := prefix.Mask.Size()
	if bits != 128 || ones != 64 {
		return nil, fmt.Errorf("upf: build router advertisement: prefix %s is not a /64", prefix)
	}
	prefixBytes := prefix.IP.To16()
	if prefixBytes == nil {
		return nil, fmt.Errorf("upf: build router advertisement: prefix %s is not IPv6", prefix)
	}

	curHopLimit := opts.CurHopLimit
	if curHopLimit == 0 {
		curHopLimit = DefaultCurHopLimit
	}
	routerLifetime := opts.RouterLifetimeSeconds
	if routerLifetime == 0 {
		routerLifetime = DefaultRouterLifetimeSeconds
	}
	validLifetime := opts.ValidLifetimeSeconds
	if validLifetime == 0 {
		validLifetime = DefaultValidLifetimeSeconds
	}
	preferredLifetime := opts.PreferredLifetimeSeconds
	if preferredLifetime == 0 {
		preferredLifetime = DefaultPreferredLifetimeSeconds
	}
	src := opts.Src
	if src == nil {
		src = LinkLocalRouterAddr
	}
	dst := opts.Dst
	if dst == nil {
		dst = AllNodesMulticastAddr
	}

	// ICMPv6 Router Advertisement message (RFC 4861 §4.2): 16-byte fixed
	// header + one Prefix Information option (32 bytes).
	msg := make([]byte, 16+prefixInfoOptionLen)
	msg[0] = ICMPv6TypeRouterAdvertisement
	msg[1] = icmpv6Code
	// msg[2:4] checksum computed below, left zero for now.
	msg[4] = curHopLimit
	msg[5] = 0 // M=0, O=0 (SLAAC only, TS 23.501 §5.8.2.2.2)
	binary.BigEndian.PutUint16(msg[6:8], routerLifetime)
	binary.BigEndian.PutUint32(msg[8:12], 0)  // Reachable Time = 0 (unspecified)
	binary.BigEndian.PutUint32(msg[12:16], 0) // Retrans Timer = 0 (unspecified)

	opt := msg[16:]
	opt[0] = optTypePrefixInformation
	opt[1] = optLenPrefixInformation8Octets
	opt[2] = 64 // Prefix Length
	opt[3] = prefixInfoFlagOnLink | prefixInfoFlagAutonomous
	binary.BigEndian.PutUint32(opt[4:8], validLifetime)
	binary.BigEndian.PutUint32(opt[8:12], preferredLifetime)
	binary.BigEndian.PutUint32(opt[12:16], 0) // Reserved2
	copy(opt[16:32], prefixBytes)

	binary.BigEndian.PutUint16(msg[2:4], ICMPv6Checksum(src, dst, msg))

	return BuildIPv6Packet(src, dst, NextHeaderICMPv6, hopLimitNeighborDisc, msg), nil
}

// ParseRouterSolicitation inspects a decapsulated inner IP packet (as
// received uplink from the UE) and reports whether it is an ICMPv6 Router
// Solicitation (RFC 4861 §4.1), returning the packet's IPv6 source address
// (used as the unicast destination for a solicited RA, §6.2.6). Returns
// false for anything else (including truncated/non-IPv6 input).
func ParseRouterSolicitation(pkt []byte) (bool, net.IP) {
	if len(pkt) < ipv6HeaderLen {
		return false, nil
	}
	if pkt[0]>>4 != ipv6Version {
		return false, nil
	}
	if pkt[6] != NextHeaderICMPv6 {
		return false, nil
	}
	icmp := pkt[ipv6HeaderLen:]
	if len(icmp) < 8 {
		return false, nil
	}
	if icmp[0] != ICMPv6TypeRouterSolicitation {
		return false, nil
	}
	src := make(net.IP, net.IPv6len)
	copy(src, pkt[8:24])
	return true, src
}

// BuildIPv6Packet assembles a fixed IPv6 header (RFC 8200 §3, 40 bytes) in
// front of payload. Traffic class and flow label are zero.
func BuildIPv6Packet(src, dst net.IP, nextHeader, hopLimit uint8, payload []byte) []byte {
	pkt := make([]byte, ipv6HeaderLen+len(payload))
	pkt[0] = ipv6Version << 4
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	pkt[6] = nextHeader
	pkt[7] = hopLimit
	copy(pkt[8:24], src.To16())
	copy(pkt[24:40], dst.To16())
	copy(pkt[40:], payload)
	return pkt
}

// ICMPv6Checksum computes the ICMPv6 checksum (RFC 4443 §2.3) over the IPv6
// pseudo-header (RFC 8200 §8.1: source, destination, upper-layer packet
// length, zero-padded next header) followed by msg (with the checksum field
// itself treated as zero, per RFC 1071).
func ICMPv6Checksum(src, dst net.IP, msg []byte) uint16 {
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(msg)))
	pseudo[39] = NextHeaderICMPv6

	sum := sum16(pseudo)
	sum += sum16WithChecksumZeroed(msg)
	return foldChecksum(sum)
}

// sum16WithChecksumZeroed sums msg as 16-bit big-endian words, treating
// bytes [2:4] (the ICMPv6 checksum field) as zero regardless of their
// current content — used both when computing and verifying the checksum.
func sum16WithChecksumZeroed(msg []byte) uint32 {
	if len(msg) < 4 {
		return sum16(msg)
	}
	tmp := make([]byte, len(msg))
	copy(tmp, msg)
	tmp[2], tmp[3] = 0, 0
	return sum16(tmp)
}

func sum16(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
