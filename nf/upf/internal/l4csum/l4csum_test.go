package l4csum

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// refChecksum is an independent naive RFC 1071 reference: 16-bit words, 32-bit
// accumulator, with the checksum field zeroed by the caller.
func refChecksum(pseudo, seg []byte) uint16 {
	var s uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			s += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			s += uint32(b[len(b)-1]) << 8
		}
	}
	add(pseudo)
	add(seg)
	for s>>16 != 0 {
		s = s&0xFFFF + s>>16
	}
	return ^uint16(s)
}

var (
	src4 = []byte{1, 1, 1, 1}
	dst4 = []byte{10, 60, 0, 3}
	src6 = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst6 = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0x60, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}
)

// l4 builds a TCP or UDP segment with a payload and the checksum field zeroed.
func l4(proto byte, payload []byte) []byte {
	if proto == ipProtoTCP {
		seg := make([]byte, tcpMinHdr+len(payload))
		binary.BigEndian.PutUint16(seg[0:], 80)
		binary.BigEndian.PutUint16(seg[2:], 58924)
		seg[12] = 5 << 4
		seg[13] = 0x12
		copy(seg[tcpMinHdr:], payload)
		return seg
	}
	seg := make([]byte, udpHdr+len(payload))
	binary.BigEndian.PutUint16(seg[0:], 5000)
	binary.BigEndian.PutUint16(seg[2:], 6000)
	binary.BigEndian.PutUint16(seg[udpOffLength:], uint16(len(seg)))
	copy(seg[udpHdr:], payload)
	return seg
}

func csOff(proto byte) int {
	if proto == ipProtoTCP {
		return tcpOffChecksum
	}
	return udpOffChecksum
}

func pseudo4(proto byte, n int) []byte {
	p := append(append([]byte{}, src4...), dst4...)
	return append(p, 0, proto, byte(n>>8), byte(n))
}

func pseudo6(proto byte, n int) []byte {
	p := append(append([]byte{}, src6...), dst6...)
	return append(p, 0, 0, byte(n>>8), byte(n), 0, 0, 0, proto)
}

// mk4 builds an IPv4 packet; the L4 checksum is set to want (or the correct
// one when want < 0).
func mk4(proto byte, seg []byte, want int) []byte {
	cs := csOff(proto)
	if want < 0 {
		binary.BigEndian.PutUint16(seg[cs:], 0)
		want = int(refChecksum(pseudo4(proto, len(seg)), seg))
		if proto == ipProtoUDP && want == 0 {
			want = 0xFFFF
		}
	}
	binary.BigEndian.PutUint16(seg[cs:], uint16(want))
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(seg)))
	h[8], h[9] = 64, proto
	copy(h[12:], src4)
	copy(h[16:], dst4)
	return append(h, seg...)
}

func mk6(proto byte, seg []byte, want int) []byte {
	cs := csOff(proto)
	if want < 0 {
		binary.BigEndian.PutUint16(seg[cs:], 0)
		want = int(refChecksum(pseudo6(proto, len(seg)), seg))
		if proto == ipProtoUDP && want == 0 {
			want = 0xFFFF
		}
	}
	binary.BigEndian.PutUint16(seg[cs:], uint16(want))
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(seg)))
	h[6], h[7] = proto, 64
	copy(h[8:], src6)
	copy(h[24:], dst6)
	return append(h, seg...)
}

func payload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*7 + 3)
	}
	return p
}

func TestRepairRepaired(t *testing.T) {
	tests := []struct {
		name  string
		build func() []byte
		off   int // checksum offset within packet
		res   Result
	}{
		{"tcp v4 wrong", func() []byte { return mk4(6, l4(6, payload(100)), 0xf76c) }, 20 + 16, Result{Proto: "tcp", IP: "v4"}},
		{"tcp v4 zero not verifying", func() []byte { return mk4(6, l4(6, payload(100)), 0) }, 20 + 16, Result{Proto: "tcp", IP: "v4"}},
		{"tcp v4 odd length", func() []byte { return mk4(6, l4(6, payload(101)), 0x1234) }, 20 + 16, Result{Proto: "tcp", IP: "v4"}},
		{"tcp v4 no payload", func() []byte { return mk4(6, l4(6, nil), 0x1234) }, 20 + 16, Result{Proto: "tcp", IP: "v4"}},
		{"tcp v4 1400", func() []byte { return mk4(6, l4(6, payload(1400)), 0x4321) }, 20 + 16, Result{Proto: "tcp", IP: "v4"}},
		{"udp v4 wrong", func() []byte { return mk4(17, l4(17, payload(64)), 0xabcd) }, 20 + 6, Result{Proto: "udp", IP: "v4"}},
		{"udp v4 odd", func() []byte { return mk4(17, l4(17, payload(63)), 0xabcd) }, 20 + 6, Result{Proto: "udp", IP: "v4"}},
		{"tcp v6 wrong", func() []byte { return mk6(6, l4(6, payload(77)), 0x1111) }, 40 + 16, Result{Proto: "tcp", IP: "v6"}},
		{"udp v6 wrong", func() []byte { return mk6(17, l4(17, payload(50)), 0x2222) }, 40 + 6, Result{Proto: "udp", IP: "v6"}},
		{"udp v6 zero filled", func() []byte { return mk6(17, l4(17, payload(50)), 0) }, 40 + 6, Result{Proto: "udp", IP: "v6"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := tc.build()
			hl := 20
			proto := pkt[9]
			var pseudo []byte
			if pkt[0]>>4 == 6 {
				hl, proto = 40, pkt[6]
				pseudo = pseudo6(proto, len(pkt)-hl)
			} else {
				pseudo = pseudo4(proto, len(pkt)-hl)
			}
			seg := append([]byte{}, pkt[hl:]...)
			cs := csOff(proto)
			seg[cs], seg[cs+1] = 0, 0
			want := refChecksum(pseudo, seg)
			if proto == ipProtoUDP && want == 0 {
				want = 0xFFFF
			}
			old := binary.BigEndian.Uint16(pkt[tc.off:])
			res, ok := Repair(pkt)
			if !ok || res.Proto != tc.res.Proto || res.IP != tc.res.IP {
				t.Fatalf("Repair = %+v,%v want %+v,true", res, ok, tc.res)
			}
			if res.Old != old || res.New != want {
				t.Fatalf("Old/New = 0x%04x/0x%04x want 0x%04x/0x%04x", res.Old, res.New, old, want)
			}
			if got := binary.BigEndian.Uint16(pkt[tc.off:]); got != want {
				t.Fatalf("checksum = 0x%04x want 0x%04x", got, want)
			}
			// Idempotent: a second pass finds it valid.
			if _, ok := Repair(pkt); ok {
				t.Fatal("second Repair reported a change")
			}
		})
	}
}

func TestRepairUntouched(t *testing.T) {
	trunc := func(b []byte, n int) []byte { return b[:n] }
	frag := func(flags uint16) []byte {
		p := mk4(6, l4(6, payload(20)), 0x1234)
		binary.BigEndian.PutUint16(p[6:], flags)
		return p
	}
	udpLen := mk4(17, l4(17, payload(20)), 0x1234)
	binary.BigEndian.PutUint16(udpLen[20+4:], 99)
	udp6Len := mk6(17, l4(17, payload(20)), 0x1234)
	binary.BigEndian.PutUint16(udp6Len[40+4:], 99)
	ihl4 := mk4(6, l4(6, payload(20)), 0x1234)
	ihl4[0] = 0x44 // IHL < 5
	ihlBig2 := mk4(6, l4(6, nil), 0x1234)
	ihlBig2[0] = 0x4F // IHL*4 = 60 > TotalLength 40
	hbh := mk6(6, l4(6, payload(20)), 0x1234)
	hbh[6] = 0 // Hop-by-Hop
	fragExt := mk6(6, l4(6, payload(20)), 0x1234)
	fragExt[6] = 44 // Fragment header
	icmp4 := mk4(6, l4(6, payload(20)), 0x1234)
	icmp4[9] = 1
	icmp6 := mk6(6, l4(6, payload(20)), 0x1234)
	icmp6[6] = 58
	v4TotalBig := mk4(6, l4(6, payload(20)), 0x1234)
	binary.BigEndian.PutUint16(v4TotalBig[2:], 500)
	v6PayBig := mk6(6, l4(6, payload(20)), 0x1234)
	binary.BigEndian.PutUint16(v6PayBig[4:], 500)

	tests := []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"version 5", []byte{0x50, 0, 0, 0}},
		{"short v4", []byte{0x45, 0, 0, 20}},
		{"short v6", []byte{0x60, 0, 0, 0}},
		{"MF set", frag(0x2000)},
		{"frag offset", frag(0x0010)},
		{"IHL<5", ihl4},
		{"IHL*4 > TotalLength", ihlBig2},
		{"TotalLength > len", v4TotalBig},
		{"v6 payload > len", v6PayBig},
		{"truncated tcp v4", func() []byte {
			p := mk4(6, l4(6, nil), 0x1234)
			p = trunc(p, 20+19)
			binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
			return p
		}()},
		{"truncated udp v4", func() []byte {
			p := mk4(17, l4(17, nil), 0x1234)
			p = trunc(p, 20+7)
			binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
			return p
		}()},
		{"truncated tcp v6", func() []byte {
			p := mk6(6, l4(6, nil), 0x1234)
			p = trunc(p, 40+19)
			binary.BigEndian.PutUint16(p[4:], 19)
			return p
		}()},
		{"udp length mismatch v4", udpLen},
		{"udp length mismatch v6", udp6Len},
		{"udp v4 zero = none", mk4(17, l4(17, payload(30)), 0)},
		{"v6 hop-by-hop", hbh},
		{"v6 fragment", fragExt},
		{"icmp v4", icmp4},
		{"icmpv6", icmp6},
		{"valid tcp v4", mk4(6, l4(6, payload(333)), -1)},
		{"valid udp v4", mk4(17, l4(17, payload(333)), -1)},
		{"valid tcp v6", mk6(6, l4(6, payload(333)), -1)},
		{"valid udp v6", mk6(17, l4(17, payload(333)), -1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]byte(nil), tc.pkt...)
			if res, ok := Repair(tc.pkt); ok {
				t.Fatalf("Repair modified packet: %+v", res)
			}
			if !bytes.Equal(before, tc.pkt) {
				t.Fatal("packet bytes changed")
			}
		})
	}
}

// TestRepairZeroEquivalence: a stored 0xFFFF where the computed value is
// 0x0000 (and vice versa for TCP) is valid and must not be "repaired".
func TestRepairZeroEquivalence(t *testing.T) {
	// Find a UDP v4 payload whose checksum computes to 0x0000.
	for i := 0; i < 70000; i++ {
		seg := l4(17, []byte{byte(i >> 8), byte(i), 0, 0})
		pkt := mk4(17, seg, 0)
		binary.BigEndian.PutUint16(pkt[26:], 0xFFFF) // stored FFFF
		p := append([]byte(nil), pkt...)
		binary.BigEndian.PutUint16(p[26:], 0)
		if refChecksum(pseudo4(17, len(seg)), p[20:]) != 0 {
			continue
		}
		if _, ok := Repair(pkt); ok {
			t.Fatal("0xFFFF for computed 0x0000 was repaired")
		}
		// Wrong checksum on a packet whose true value is 0 -> written as 0xFFFF.
		binary.BigEndian.PutUint16(pkt[26:], 0x1234)
		if _, ok := Repair(pkt); !ok {
			t.Fatal("wrong checksum not repaired")
		}
		if got := binary.BigEndian.Uint16(pkt[26:]); got != 0xFFFF {
			t.Fatalf("computed 0 written as 0x%04x, want 0xFFFF", got)
		}
		return
	}
	t.Fatal("no zero-checksum vector found")
}

func TestRepairTrailingPaddingIgnored(t *testing.T) {
	pkt := mk4(6, l4(6, payload(31)), -1)
	pkt = append(pkt, 0xde, 0xad, 0xbe, 0xef, 0x01)
	before := append([]byte(nil), pkt...)
	if _, ok := Repair(pkt); ok {
		t.Fatal("valid packet with trailing padding repaired")
	}
	// Corrupt, then repair: padding must stay intact and not affect the sum.
	binary.BigEndian.PutUint16(pkt[36:], 0x9999)
	if _, ok := Repair(pkt); !ok {
		t.Fatal("not repaired")
	}
	if !bytes.Equal(pkt, before) {
		t.Fatal("repair result differs from the valid original (padding leaked into sum or was modified)")
	}
}

func TestRepairZeroAllocs(t *testing.T) {
	pkt := mk4(6, l4(6, payload(1400)), 0x1111)
	if n := testing.AllocsPerRun(100, func() {
		pkt[36], pkt[37] = 0x11, 0x11
		Repair(pkt)
	}); n != 0 {
		t.Fatalf("allocs/op = %v, want 0", n)
	}
}

func BenchmarkRepair1400(b *testing.B) {
	pkt := mk4(6, l4(6, payload(1400)), 0x1111)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pkt[36], pkt[37] = 0x11, 0x11
		Repair(pkt)
	}
}
