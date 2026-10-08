package server

import (
	"fmt"
	"regexp"
	"testing"
)

func TestBitRateFormatConformant(t *testing.T) {
	re := regexp.MustCompile(bitRateKbpsPattern)
	for _, v := range []uint64{0, 1, 100000, 1000000} {
		s := fmt.Sprintf("%d Kbps", v)
		if !re.MatchString(s) {
			t.Errorf("%q does not match TS 29.571 §5.5.2", s)
		}
	}
	if re.MatchString("100000Kbps") {
		t.Error("unspaced form must not match")
	}
}

// TestBitRatePatternRejects pins the TS 29.571 §5.5.2 reject list shared with
// the slice-dnn-qos endpoint (UDR-003).
func TestBitRatePatternRejects(t *testing.T) {
	re := regexp.MustCompile(bitRateKbpsPattern)
	for _, v := range []string{"20Mbps", "20 mbps", "20 MB", "-5 Mbps", "", " 20 Mbps", "20 Mbps ", "20  Mbps", "1e3 Mbps", ".5 Mbps", "20 Pbps"} {
		if re.MatchString(v) {
			t.Errorf("%q must not match TS 29.571 §5.5.2", v)
		}
	}
	for _, v := range []string{"20 Mbps", "0.125 Gbps", "125000 Kbps", "1 bps", "3 Tbps"} {
		if !re.MatchString(v) {
			t.Errorf("%q must match", v)
		}
	}
}
