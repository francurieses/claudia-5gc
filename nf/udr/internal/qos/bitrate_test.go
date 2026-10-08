package qos

import (
	"errors"
	"testing"
)

func TestValidateBitRate(t *testing.T) {
	ok := []struct {
		in   string
		kbps uint64
	}{
		{"100 Mbps", 100_000}, {"20 Mbps", 20_000}, {"0.125 Gbps", 125_000}, {"125000 Kbps", 125_000},
		{"1 bps", 1}, {"1500 bps", 2}, {"1.1 Mbps", 1100}, {"1 Tbps", 1_000_000_000},
		{"1000 Tbps", MaxBitRateKbps}, {"  5 Mbps ", 5000}, {"0.0001 Kbps", 1},
	}
	for _, c := range ok {
		canon, k, err := ValidateBitRate(c.in)
		if err != nil || k != c.kbps {
			t.Errorf("%q: got (%q,%d,%v), want kbps %d", c.in, canon, k, err, c.kbps)
		}
	}
	bad := []struct {
		in   string
		want error
	}{
		{"20Mbps", ErrBitRateFormat}, {"20 mbps", ErrBitRateFormat}, {"20 MB", ErrBitRateFormat},
		{"-5 Mbps", ErrBitRateFormat}, {"", ErrBitRateFormat}, {"20  Mbps", ErrBitRateFormat},
		{"1e3 Mbps", ErrBitRateFormat}, {".5 Mbps", ErrBitRateFormat},
		{"0 Mbps", ErrBitRateRange}, {"0 Kbps", ErrBitRateRange}, {"0.0 bps", ErrBitRateRange},
		{"1001 Tbps", ErrBitRateRange}, {"99999999999999999999999 Tbps", ErrBitRateRange},
	}
	for _, c := range bad {
		if _, _, err := ValidateBitRate(c.in); !errors.Is(err, c.want) {
			t.Errorf("%q: got %v, want %v", c.in, err, c.want)
		}
	}
}
