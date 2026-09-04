package server

import "testing"

// TestIPPoolReservesNetworkAndGateway covers the live-OTA bug found
// 2026-09-03: the very first UE (a Pixel 6a) was handed 10.60.0.1 — the
// conventional gateway/TUN address — with the allocator only excluding the
// bare network address (10.60.0.0). Ref: TS 23.501 §5.6.5 leaves the first
// usable address unspecified, but handing out ".1" collides with what most
// UE/OS stacks and every other UPF in this repo's config
// (nf/upf/config/dev.yaml: tun_addr .254, but .1 is still the address every
// textbook example reserves) assume is the router.
func TestIPPoolReservesNetworkAndGateway(t *testing.T) {
	p, err := NewIPPool("10.60.0.0/30") // usable pool: .0(net) .1(gw) .2 .3(bcast-ish, /30 has no real bcast rule here)
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	first, err := p.Allocate()
	if err != nil {
		t.Fatalf("first Allocate: %v", err)
	}
	if got, want := first.String(), "10.60.0.2"; got != want {
		t.Errorf("first allocated UE IP = %s, want %s (network .0 and gateway .1 must be skipped)", got, want)
	}

	second, err := p.Allocate()
	if err != nil {
		t.Fatalf("second Allocate: %v", err)
	}
	if got, want := second.String(), "10.60.0.3"; got != want {
		t.Errorf("second allocated UE IP = %s, want %s", got, want)
	}

	if _, err := p.Allocate(); err == nil {
		t.Error("expected pool exhaustion after both non-reserved addresses are allocated")
	}
}

// TestIPPoolNeverAllocatesGatewayEvenAfterRelease guards against a
// regression where releasing an address could re-admit the reserved gateway
// into the free set.
func TestIPPoolNeverAllocatesGatewayEvenAfterRelease(t *testing.T) {
	p, err := NewIPPool("10.61.0.0/29")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	for i := 0; i < 6; i++ { // .2 through .7 = 6 usable addresses in a /29 once .0/.1 are reserved
		ip, err := p.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		if ip.String() == "10.61.0.0" || ip.String() == "10.61.0.1" {
			t.Fatalf("Allocate #%d returned reserved address %s", i, ip)
		}
		p.Release(ip)
	}
}
