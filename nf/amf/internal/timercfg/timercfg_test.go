package timercfg

import (
	"testing"
	"time"
)

// TestNASTimerDefaults: an unset T3550/T3560/T3570 falls back to the TS 24.501
// §10.2 Table 10.2.2 default of 6 s; a configured value wins.
func TestNASTimerDefaults(t *testing.T) {
	var zero Values
	if zero.T3550() != 6*time.Second || zero.T3560() != 6*time.Second || zero.T3570() != 6*time.Second {
		t.Fatalf("defaults = %v %v %v, want 6 s", zero.T3550(), zero.T3560(), zero.T3570())
	}
	v := Values{T3550Secs: 12, T3560Secs: 3, T3570Secs: 9}
	if v.T3550() != 12*time.Second || v.T3560() != 3*time.Second || v.T3570() != 9*time.Second {
		t.Fatalf("configured = %v %v %v", v.T3550(), v.T3560(), v.T3570())
	}
}
