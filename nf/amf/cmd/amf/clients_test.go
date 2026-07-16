package main

// clients_test.go — regression test for the 3GPP conformance audit fix
// (Jul 2026): subscribed UE-AMBR (TS 29.571 BitRate strings) parsed from the
// UDM am-data response instead of being dropped. Ref: TS 38.413 §9.3.1.58

import "testing"

func TestParseBitRateKbps(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"1 Gbps", 1_000_000},
		{"500 Mbps", 500_000},
		{"1.5 Mbps", 1_500},
		{"200 Kbps", 200},
		{"4000 bps", 4},
		{"", 0},
		{"garbage", 0},
		{"-1 Mbps", 0},
		{"10 Xbps", 0},
	}
	for _, c := range cases {
		if got := parseBitRateKbps(c.in); got != c.want {
			t.Errorf("parseBitRateKbps(%q): got %d, want %d", c.in, got, c.want)
		}
	}
}
