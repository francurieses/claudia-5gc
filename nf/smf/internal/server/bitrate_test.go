package server

import "testing"

func TestParseBitRateKbps(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"100 Mbps", 100_000, true},
		{"1 Gbps", 1_000_000, true},
		{"1.5 Gbps", 1_500_000, true},
		{"2 Tbps", 2_000_000_000, true},
		{"64 Kbps", 64, true},
		{"1500 bps", 2, true},   // rounded up
		{"1000 bps", 1, true},   // exact
		{"1 bps", 1, true},      // rounded up
		{"0.1 Mbps", 100, true}, // float snap, no 101
		{"0.0001 Kbps", 1, true},
		{"1.0005 Mbps", 1001, true},
		{"0 Mbps", 0, false},
		{"", 0, false},
		{"100", 0, false},
		{"Mbps", 0, false},
		{"100Mbps", 0, false},
		{"100 mbps", 0, false},
		{"-5 Mbps", 0, false},
		{"1e3 Kbps", 0, false},
		{"100 Mbps extra", 0, false},
		{"99999999999999999999 Tbps", 0, false}, // overflow guard
		{"2000000 Tbps", 0, false},
	}
	for _, tc := range tests {
		got, ok := parseBitRateKbps(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseBitRateKbps(%q) = %d,%v want %d,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseAMBR(t *testing.T) {
	if k, m := parseAMBR("1 Gbps", 5, 5); k != 1_000_000 || m != 1000 {
		t.Errorf("1 Gbps: got %d,%d", k, m)
	}
	if k, m := parseAMBR("1500 bps", 5, 5); k != 2 || m != 1 {
		t.Errorf("1500 bps: got %d,%d (Mbps must round up to 1)", k, m)
	}
	if k, m := parseAMBR("1.5 Mbps", 5, 5); k != 1500 || m != 2 {
		t.Errorf("1.5 Mbps: got %d,%d", k, m)
	}
	if k, m := parseAMBR("garbage", 7000, 7); k != 7000 || m != 7 {
		t.Errorf("fallback: got %d,%d", k, m)
	}
}

func TestKbpsOrMbps(t *testing.T) {
	if got := kbpsOrMbps(1500, 2); got != 1500 {
		t.Errorf("consistent: %d", got)
	}
	if got := kbpsOrMbps(1500, 50); got != 50000 {
		t.Errorf("overridden Mbps must win: %d", got)
	}
	if got := kbpsOrMbps(0, 50); got != 50000 {
		t.Errorf("no kbps: %d", got)
	}
	if got := kbpsOrMbps(100, 0); got != 0 {
		t.Errorf("zero mbps: %d", got)
	}
}
