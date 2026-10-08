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
