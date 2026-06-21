package server

import (
	"net"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestSelectPDUSessionType(t *testing.T) {
	v4 := nas.PDUSessionTypeIPv4
	v6 := nas.PDUSessionTypeIPv6
	v4v6 := nas.PDUSessionTypeIPv4v6
	eth := nas.PDUSessionTypeEthernet

	tests := []struct {
		name      string
		requested *uint8
		supportV6 bool
		want      uint8
	}{
		{"absent request defaults to IPv4", nil, true, nas.PDUSessionTypeIPv4},
		{"IPv4 stays IPv4", &v4, true, nas.PDUSessionTypeIPv4},
		{"IPv6 on v6 DNN granted", &v6, true, nas.PDUSessionTypeIPv6},
		{"IPv6 on v4-only DNN downgrades", &v6, false, nas.PDUSessionTypeIPv4},
		{"IPv4v6 on v6 DNN granted", &v4v6, true, nas.PDUSessionTypeIPv4v6},
		{"IPv4v6 on v4-only DNN downgrades", &v4v6, false, nas.PDUSessionTypeIPv4},
		{"Ethernet falls back to IPv4", &eth, true, nas.PDUSessionTypeIPv4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectPDUSessionType(tc.requested, tc.supportV6); got != tc.want {
				t.Errorf("selectPDUSessionType = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestNewIPv6PoolValidation(t *testing.T) {
	if _, err := NewIPv6Pool("2001:db8:61::/56"); err != nil {
		t.Errorf("valid /56 rejected: %v", err)
	}
	if _, err := NewIPv6Pool("10.60.0.0/24"); err == nil {
		t.Error("IPv4 prefix accepted as IPv6 pool")
	}
	if _, err := NewIPv6Pool("2001:db8::/60"); err == nil {
		t.Error("non-octet-aligned /60 prefix accepted")
	}
	if _, err := NewIPv6Pool("not-a-prefix"); err == nil {
		t.Error("garbage CIDR accepted")
	}
}

func TestIPv6PoolAllocateDistinctAndInside(t *testing.T) {
	p, err := NewIPv6Pool("2001:db8:61::/56")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	_, base, _ := net.ParseCIDR("2001:db8:61::/56")

	p1, iid, err := p.Allocate()
	if err != nil {
		t.Fatalf("allocate 1: %v", err)
	}
	if len(iid) != 8 {
		t.Errorf("IID length = %d, want 8", len(iid))
	}
	p2, _, err := p.Allocate()
	if err != nil {
		t.Fatalf("allocate 2: %v", err)
	}
	if p1.String() == p2.String() {
		t.Errorf("two allocations returned the same /64: %s", p1)
	}
	for _, pf := range []*net.IPNet{p1, p2} {
		if ones, _ := pf.Mask.Size(); ones != 64 {
			t.Errorf("prefix %s is not a /64", pf)
		}
		if !base.Contains(pf.IP) {
			t.Errorf("prefix %s is outside the base pool %s", pf, base)
		}
	}
}

func TestIPv6PoolReleaseReuse(t *testing.T) {
	p, err := NewIPv6Pool("2001:db8:61::/56")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	first, _, _ := p.Allocate() // index 0
	second, _, _ := p.Allocate()
	_ = second

	p.Release(first)
	third, _, err := p.Allocate()
	if err != nil {
		t.Fatalf("allocate after release: %v", err)
	}
	if third.String() != first.String() {
		t.Errorf("expected released /64 %s to be reused, got %s", first, third)
	}
}

func TestIPv6PoolExhaustion(t *testing.T) {
	// A /64 base pool has exactly one /64 (itself).
	p, err := NewIPv6Pool("2001:db8:61::/64")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if _, _, err := p.Allocate(); err != nil {
		t.Fatalf("first allocate should succeed: %v", err)
	}
	if _, _, err := p.Allocate(); err == nil {
		t.Error("expected exhaustion error on the second allocation")
	}
}
