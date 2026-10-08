package pace

import (
	"math"
	"testing"
	"time"
)

// TestPacerAccuracy checks the released count tracks rate*elapsed within 5 %.
func TestPacerAccuracy(t *testing.T) {
	start := time.Unix(1000, 0)
	p := New(100000, start)
	var total uint64
	for ms := 1; ms <= 2000; ms++ {
		total += p.Due(start.Add(time.Duration(ms)*time.Millisecond), 1<<20)
	}
	want := 200000.0
	if math.Abs(float64(total)-want)/want > 0.05 {
		t.Fatalf("released %d, want %.0f ±5%%", total, want)
	}
}

func TestPacerBurstCap(t *testing.T) {
	start := time.Unix(0, 0)
	p := New(1000, start)
	if n := p.Due(start.Add(10*time.Second), 64); n != 64 {
		t.Fatalf("burst = %d, want 64", n)
	}
}

func TestPacerZeroRate(t *testing.T) {
	if n := New(0, time.Now()).Due(time.Now().Add(time.Hour), 10); n != 0 {
		t.Fatalf("zero rate released %d", n)
	}
}
