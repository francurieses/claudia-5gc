package ra

import (
	"encoding/binary"
	"net"
	"testing"
)

func mustPrefix(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return n
}

func TestBuildRouterAdvertisement_IPv6Header(t *testing.T) {
	prefix := mustPrefix(t, "2001:db8:61::/64")
	pkt, err := BuildRouterAdvertisement(prefix, Options{})
	if err != nil {
		t.Fatalf("BuildRouterAdvertisement: %v", err)
	}
	if len(pkt) < ipv6HeaderLen {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}

	if version := pkt[0] >> 4; version != 6 {
		t.Errorf("IP version = %d, want 6", version)
	}
	// Traffic class + flow label must be zero.
	if pkt[0]&0x0F != 0 || pkt[1] != 0 || pkt[2] != 0 || pkt[3] != 0 {
		t.Errorf("traffic class/flow label not zero: % x", pkt[0:4])
	}
	payloadLen := binary.BigEndian.Uint16(pkt[4:6])
	wantPayloadLen := uint16(16 + prefixInfoOptionLen) // ICMPv6 RA fixed hdr + PIO
	if payloadLen != wantPayloadLen {
		t.Errorf("payload length = %d, want %d", payloadLen, wantPayloadLen)
	}
	if pkt[6] != NextHeaderICMPv6 {
		t.Errorf("next header = %d, want %d (ICMPv6)", pkt[6], NextHeaderICMPv6)
	}
	if pkt[7] != 255 {
		t.Errorf("hop limit = %d, want 255 (RFC 4861 §4.2)", pkt[7])
	}
	src := net.IP(pkt[8:24])
	if !src.Equal(LinkLocalRouterAddr) {
		t.Errorf("default src = %s, want %s", src, LinkLocalRouterAddr)
	}
	dst := net.IP(pkt[24:40])
	if !dst.Equal(AllNodesMulticastAddr) {
		t.Errorf("default dst = %s, want %s (periodic RA)", dst, AllNodesMulticastAddr)
	}
	if len(pkt) != ipv6HeaderLen+int(payloadLen) {
		t.Errorf("total packet length = %d, want %d", len(pkt), ipv6HeaderLen+int(payloadLen))
	}
}

func TestBuildRouterAdvertisement_ICMPv6Fields(t *testing.T) {
	prefix := mustPrefix(t, "2001:db8:61::/64")
	pkt, err := BuildRouterAdvertisement(prefix, Options{
		CurHopLimit:           42,
		RouterLifetimeSeconds: 900,
	})
	if err != nil {
		t.Fatalf("BuildRouterAdvertisement: %v", err)
	}
	icmp := pkt[ipv6HeaderLen:]

	if icmp[0] != ICMPv6TypeRouterAdvertisement {
		t.Errorf("ICMPv6 type = %d, want %d", icmp[0], ICMPv6TypeRouterAdvertisement)
	}
	if icmp[1] != 0 {
		t.Errorf("ICMPv6 code = %d, want 0", icmp[1])
	}
	if icmp[4] != 42 {
		t.Errorf("Cur Hop Limit = %d, want 42", icmp[4])
	}
	if flags := icmp[5]; flags&0xC0 != 0 {
		t.Errorf("M/O flags = 0x%02x, want 0 (SLAAC only)", flags)
	}
	if lifetime := binary.BigEndian.Uint16(icmp[6:8]); lifetime != 900 {
		t.Errorf("Router Lifetime = %d, want 900", lifetime)
	}
	if rt := binary.BigEndian.Uint32(icmp[8:12]); rt != 0 {
		t.Errorf("Reachable Time = %d, want 0", rt)
	}
	if rt := binary.BigEndian.Uint32(icmp[12:16]); rt != 0 {
		t.Errorf("Retrans Timer = %d, want 0", rt)
	}
}

func TestBuildRouterAdvertisement_PrefixInformationOption(t *testing.T) {
	prefix := mustPrefix(t, "2001:db8:61::/64")
	pkt, err := BuildRouterAdvertisement(prefix, Options{
		ValidLifetimeSeconds:     3600,
		PreferredLifetimeSeconds: 1800,
	})
	if err != nil {
		t.Fatalf("BuildRouterAdvertisement: %v", err)
	}
	opt := pkt[ipv6HeaderLen+16:] // skip IPv6 header + ICMPv6 RA fixed header

	if opt[0] != optTypePrefixInformation {
		t.Errorf("option type = %d, want 3 (Prefix Information)", opt[0])
	}
	if opt[1] != optLenPrefixInformation8Octets {
		t.Errorf("option length = %d (8-octet units), want 4 (32 bytes)", opt[1])
	}
	if opt[2] != 64 {
		t.Errorf("Prefix Length = %d, want 64", opt[2])
	}
	// L=1 (on-link, 0x80) | A=1 (autonomous, 0x40) => 0xC0.
	if opt[3] != 0xC0 {
		t.Errorf("L+A flags = 0x%02x, want 0xC0", opt[3])
	}
	if v := binary.BigEndian.Uint32(opt[4:8]); v != 3600 {
		t.Errorf("Valid Lifetime = %d, want 3600", v)
	}
	if v := binary.BigEndian.Uint32(opt[8:12]); v != 1800 {
		t.Errorf("Preferred Lifetime = %d, want 1800", v)
	}
	if v := binary.BigEndian.Uint32(opt[12:16]); v != 0 {
		t.Errorf("Reserved2 = %d, want 0", v)
	}
	gotPrefix := net.IP(opt[16:32])
	wantPrefix := prefix.IP.To16()
	if !gotPrefix.Equal(wantPrefix) {
		t.Errorf("prefix bytes = %s, want %s", gotPrefix, net.IP(wantPrefix))
	}
}

func TestBuildRouterAdvertisement_Defaults(t *testing.T) {
	prefix := mustPrefix(t, "2001:db8:61::/64")
	pkt, err := BuildRouterAdvertisement(prefix, Options{})
	if err != nil {
		t.Fatalf("BuildRouterAdvertisement: %v", err)
	}
	icmp := pkt[ipv6HeaderLen:]
	if icmp[4] != DefaultCurHopLimit {
		t.Errorf("default Cur Hop Limit = %d, want %d", icmp[4], DefaultCurHopLimit)
	}
	if lifetime := binary.BigEndian.Uint16(icmp[6:8]); lifetime != DefaultRouterLifetimeSeconds {
		t.Errorf("default Router Lifetime = %d, want %d", lifetime, DefaultRouterLifetimeSeconds)
	}
	opt := icmp[16:]
	if v := binary.BigEndian.Uint32(opt[4:8]); v != DefaultValidLifetimeSeconds {
		t.Errorf("default Valid Lifetime = %d, want %d", v, DefaultValidLifetimeSeconds)
	}
	if v := binary.BigEndian.Uint32(opt[8:12]); v != DefaultPreferredLifetimeSeconds {
		t.Errorf("default Preferred Lifetime = %d, want %d", v, DefaultPreferredLifetimeSeconds)
	}
}

func TestBuildRouterAdvertisement_UnicastDst(t *testing.T) {
	prefix := mustPrefix(t, "2001:db8:61::/64")
	ueSrc := net.ParseIP("fe80::200:ff:fe00:1")
	pkt, err := BuildRouterAdvertisement(prefix, Options{Dst: ueSrc})
	if err != nil {
		t.Fatalf("BuildRouterAdvertisement: %v", err)
	}
	dst := net.IP(pkt[24:40])
	if !dst.Equal(ueSrc) {
		t.Errorf("unicast dst = %s, want %s", dst, ueSrc)
	}
}

func TestBuildRouterAdvertisement_RejectsNon64Prefix(t *testing.T) {
	prefix := mustPrefix(t, "2001:db8:61::/56")
	if _, err := BuildRouterAdvertisement(prefix, Options{}); err == nil {
		t.Error("expected error for non-/64 prefix")
	}
}

func TestBuildRouterAdvertisement_RejectsNilPrefix(t *testing.T) {
	if _, err := BuildRouterAdvertisement(nil, Options{}); err == nil {
		t.Error("expected error for nil prefix")
	}
}

// TestBuildRouterAdvertisement_ChecksumValid verifies the ICMPv6 checksum
// (RFC 4443 §2.3): summing the IPv6 pseudo-header + the full ICMPv6 message
// (checksum field included, as transmitted) in ones-complement arithmetic
// must fold to 0xFFFF (i.e. ones-complement zero).
func TestBuildRouterAdvertisement_ChecksumValid(t *testing.T) {
	prefix := mustPrefix(t, "2001:db8:61::/64")
	pkt, err := BuildRouterAdvertisement(prefix, Options{})
	if err != nil {
		t.Fatalf("BuildRouterAdvertisement: %v", err)
	}
	src := net.IP(pkt[8:24])
	dst := net.IP(pkt[24:40])
	msg := pkt[ipv6HeaderLen:]

	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(msg)))
	pseudo[39] = NextHeaderICMPv6

	sum := sum16(pseudo) + sum16(msg) // msg here includes the real checksum bytes
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if sum != 0xFFFF {
		t.Errorf("checksum verification sum = 0x%04x, want 0xFFFF (valid checksum)", sum)
	}
}

func TestParseRouterSolicitation_Positive(t *testing.T) {
	srcAddr := net.ParseIP("fe80::200:ff:fe00:2")
	pkt := make([]byte, ipv6HeaderLen+8)
	pkt[0] = 6 << 4
	pkt[6] = NextHeaderICMPv6
	pkt[7] = 255
	copy(pkt[8:24], srcAddr.To16())
	copy(pkt[24:40], net.ParseIP("ff02::2").To16())
	pkt[ipv6HeaderLen] = ICMPv6TypeRouterSolicitation

	ok, src := ParseRouterSolicitation(pkt)
	if !ok {
		t.Fatal("expected Router Solicitation to be detected")
	}
	if !src.Equal(srcAddr) {
		t.Errorf("solicitation src = %s, want %s", src, srcAddr)
	}
}

func TestParseRouterSolicitation_NegativeWrongType(t *testing.T) {
	pkt := make([]byte, ipv6HeaderLen+8)
	pkt[0] = 6 << 4
	pkt[6] = NextHeaderICMPv6
	pkt[ipv6HeaderLen] = ICMPv6TypeRouterAdvertisement // not a solicitation

	ok, _ := ParseRouterSolicitation(pkt)
	if ok {
		t.Error("Router Advertisement misdetected as solicitation")
	}
}

func TestParseRouterSolicitation_NegativeNotIPv6(t *testing.T) {
	pkt := make([]byte, ipv6HeaderLen+8)
	pkt[0] = 4 << 4 // IPv4 version nibble
	pkt[6] = NextHeaderICMPv6
	pkt[ipv6HeaderLen] = ICMPv6TypeRouterSolicitation

	ok, _ := ParseRouterSolicitation(pkt)
	if ok {
		t.Error("IPv4 packet misdetected as IPv6 Router Solicitation")
	}
}

func TestParseRouterSolicitation_NegativeTruncated(t *testing.T) {
	ok, _ := ParseRouterSolicitation(make([]byte, 10))
	if ok {
		t.Error("truncated packet misdetected as Router Solicitation")
	}
}

func TestParseRouterSolicitation_NegativeNotICMPv6(t *testing.T) {
	pkt := make([]byte, ipv6HeaderLen+8)
	pkt[0] = 6 << 4
	pkt[6] = 17 // UDP, not ICMPv6
	pkt[ipv6HeaderLen] = ICMPv6TypeRouterSolicitation

	ok, _ := ParseRouterSolicitation(pkt)
	if ok {
		t.Error("non-ICMPv6 next-header packet misdetected as Router Solicitation")
	}
}
