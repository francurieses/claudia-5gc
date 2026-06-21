package server

import (
	"fmt"
	"net"
	"sync"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// IPv6Pool delegates per-session /64 prefixes out of a configured shorter base
// prefix (e.g. a /56 yields 256 /64s) for IPv6 / IPv4v6 PDU sessions. Each
// session gets a dedicated /64; the UE configures its address by SLAAC from the
// Router Advertisement of that /64 on the UPF TUN (the RA itself is the
// escalated UPF-001 data-plane work). Ref: TS 23.501 §5.8.2.2.
//
// The base prefix length must be a multiple of 8 and in [8, 64] so the /64
// subnet id occupies whole octets; this covers the operator-realistic /48–/64
// allocations without bit-level packing.
type IPv6Pool struct {
	base      net.IP // 16-octet network address of the base prefix
	baseOnes  int    // base prefix length in bits (multiple of 8)
	startByte int    // first octet of the /64 subnet id (baseOnes/8)
	max       uint64 // number of /64s available (1 << (64-baseOnes))

	mu        sync.Mutex
	allocated map[uint64]bool
}

// NewIPv6Pool parses a base IPv6 prefix (CIDR) and returns a /64-delegating pool.
func NewIPv6Pool(cidr string) (*IPv6Pool, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("%q is not an IPv6 prefix", cidr)
	}
	ones, _ := ipnet.Mask.Size()
	if ones < 8 || ones > 64 || ones%8 != 0 {
		return nil, fmt.Errorf("IPv6 base prefix length /%d must be a multiple of 8 in [8,64]", ones)
	}
	base := make(net.IP, net.IPv6len)
	copy(base, ipnet.IP.To16())
	return &IPv6Pool{
		base:      base,
		baseOnes:  ones,
		startByte: ones / 8,
		max:       uint64(1) << (64 - ones),
		allocated: make(map[uint64]bool),
	}, nil
}

// Allocate reserves the lowest-free /64 and returns it together with the 8-octet
// interface identifier assigned to the UE for the PDU Address IE
// (TS 24.501 §9.11.4.10). Returns an error when the pool is exhausted.
func (p *IPv6Pool) Allocate() (prefix *net.IPNet, iid []byte, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for idx := uint64(0); idx < p.max; idx++ {
		if p.allocated[idx] {
			continue
		}
		p.allocated[idx] = true
		return p.prefixForIndex(idx), defaultIID(), nil
	}
	return nil, nil, fmt.Errorf("IPv6 /64 pool exhausted")
}

// Release returns a previously allocated /64 to the pool. Unknown prefixes are
// ignored so deletion is idempotent.
func (p *IPv6Pool) Release(prefix *net.IPNet) {
	if prefix == nil {
		return
	}
	idx, ok := p.indexForPrefix(prefix.IP)
	if !ok {
		return
	}
	p.mu.Lock()
	delete(p.allocated, idx)
	p.mu.Unlock()
}

func (p *IPv6Pool) prefixForIndex(idx uint64) *net.IPNet {
	ip := make(net.IP, net.IPv6len)
	copy(ip, p.base)
	v := idx
	for b := 7; b >= p.startByte; b-- {
		ip[b] = byte(v & 0xFF)
		v >>= 8
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}
}

func (p *IPv6Pool) indexForPrefix(ip net.IP) (uint64, bool) {
	ip16 := ip.To16()
	if ip16 == nil {
		return 0, false
	}
	var idx uint64
	for b := p.startByte; b <= 7; b++ {
		idx = (idx << 8) | uint64(ip16[b])
	}
	if idx >= p.max {
		return 0, false
	}
	return idx, true
}

// defaultIID is the interface identifier the SMF assigns within each delegated
// /64. Each session owns a distinct /64, so a fixed ::1 IID is unambiguous and
// the UE forms its own address by SLAAC regardless. Ref: TS 23.501 §5.8.2.2.2.
func defaultIID() []byte {
	return []byte{0, 0, 0, 0, 0, 0, 0, 1}
}

// selectPDUSessionType resolves the granted PDU session type from the type the
// UE requested and whether the target DNN can delegate IPv6 prefixes. A v6
// request on an IPv4-only DNN is downgraded to IPv4 (operators may instead
// reject with 5GSM cause #50; this slice downgrades and logs the granted type).
// Unsupported types (Ethernet/Unstructured) also fall back to IPv4.
// Ref: TS 23.501 §5.8.2.2, TS 24.501 §9.11.4.11.
func selectPDUSessionType(requested *uint8, dnnSupportsV6 bool) uint8 {
	if requested == nil {
		return nas.PDUSessionTypeIPv4
	}
	switch *requested {
	case nas.PDUSessionTypeIPv6:
		if dnnSupportsV6 {
			return nas.PDUSessionTypeIPv6
		}
	case nas.PDUSessionTypeIPv4v6:
		if dnnSupportsV6 {
			return nas.PDUSessionTypeIPv4v6
		}
	}
	return nas.PDUSessionTypeIPv4
}

// pduTypeNeedsIPv4 / pduTypeNeedsIPv6 report which address families a granted
// type requires.
func pduTypeNeedsIPv4(t uint8) bool {
	return t == nas.PDUSessionTypeIPv4 || t == nas.PDUSessionTypeIPv4v6
}

func pduTypeNeedsIPv6(t uint8) bool {
	return t == nas.PDUSessionTypeIPv6 || t == nas.PDUSessionTypeIPv4v6
}
