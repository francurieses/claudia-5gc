package qos

import (
	"sync"
	"testing"
)

const ms = int64(1_000_000) // nanoseconds

func TestDepthAndFloor(t *testing.T) {
	tests := []struct {
		name      string
		kbps      uint64
		burstMs   int
		wantBytes int64
	}{
		{"8000kbps 10ms", 8000, 10, 10000},
		{"4000kbps 10ms", 4000, 10, 5000},
		{"2000kbps 10ms hits floor", 2000, 10, FloorBytes},
		{"1kbps floor", 1, 100, FloorBytes},
		{"100Mbps default burst", 100_000, DefaultBurstMs, 1_250_000},
		{"burst 0 means default", 8000, 0, 100000},
		{"burst clamped high", 8000, 5000, 1_000_000},
		{"max finite rate", UnlimitedKbps - 1, MaxBurstMs, (UnlimitedKbps - 1) * 1000 / 8},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBucket(tc.kbps, tc.burstMs, 0)
			if got := b.DepthBytes(); got != tc.wantBytes {
				t.Fatalf("depth = %d B, want %d B", got, tc.wantBytes)
			}
			if got := b.TokensBytes(0); got != tc.wantBytes {
				t.Fatalf("starts full: tokens = %d B, want %d B", got, tc.wantBytes)
			}
		})
	}
}

func TestAdmitBurstThenRefill(t *testing.T) {
	b := NewBucket(8000, 10, 0) // 1000 B/ms, depth 10000 B
	pass := 0
	for i := 0; i < 15; i++ {
		if b.Admit(1000, 0) {
			pass++
		}
	}
	if pass != 10 {
		t.Fatalf("burst admitted %d, want 10", pass)
	}
	pass = 0
	for i := 0; i < 5; i++ {
		if b.Admit(1000, 3*ms) {
			pass++
		}
	}
	if pass != 3 {
		t.Fatalf("after 3 ms admitted %d, want 3", pass)
	}
}

func TestIdleClamp(t *testing.T) {
	b := NewBucket(8000, 10, 0)
	for b.Admit(1000, 0) {
	}
	const tenSeconds = 10_000 * 1_000_000
	if got := b.TokensBytes(tenSeconds); got != 10000 {
		t.Fatalf("idle tokens = %d, want clamp to depth 10000", got)
	}
	// Huge idle gap must not overflow.
	if got := b.TokensBytes(1 << 62); got != 10000 {
		t.Fatalf("huge idle tokens = %d, want 10000", got)
	}
}

func TestSteadyStateRateAccuracy(t *testing.T) {
	for _, kbps := range []uint64{1000, 100_000, 1_000_000} {
		b := NewBucket(kbps, DefaultBurstMs, 0)
		for b.Admit(1500, 0) { // drain the initial burst
		}
		const pkt = 1500
		var now, admitted int64
		step := int64(10_000) // 10 us offered-load tick
		for now = 0; now < 1000*ms; now += step {
			// offer far more than the rate: a packet every tick
			if b.Admit(pkt, now) {
				admitted += pkt
			}
		}
		wantBytes := int64(kbps) * 1000 / 8 // one second
		lo, hi := wantBytes*98/100, wantBytes*102/100
		// at 1 Gb/s a 1500 B packet per 10us caps offered load at 1.2 Gb/s, still > rate
		if admitted < lo || admitted > hi {
			t.Errorf("%d kbps: admitted %d B in 1 s, want %d +/-2%%", kbps, admitted, wantBytes)
		}
	}
}

func TestRefund(t *testing.T) {
	b := NewBucket(8000, 10, 0)
	if !b.Admit(4000, 0) {
		t.Fatal("admit")
	}
	b.Refund(4000)
	if got := b.TokensBytes(0); got != 10000 {
		t.Fatalf("after refund tokens = %d, want 10000", got)
	}
	b.Refund(5000) // never above depth
	if got := b.TokensBytes(0); got != 10000 {
		t.Fatalf("refund overflow: tokens = %d, want clamp 10000", got)
	}
}

func TestSetRate(t *testing.T) {
	t.Run("lower clamps tokens to new depth", func(t *testing.T) {
		b := NewBucket(8000, 10, 0)
		b.SetRate(4000, 0)
		if got := b.TokensBytes(0); got != 5000 {
			t.Fatalf("tokens = %d, want 5000", got)
		}
		if b.Rate() != 4000 {
			t.Fatalf("rate = %d", b.Rate())
		}
	})
	t.Run("raise keeps tokens, does not top up", func(t *testing.T) {
		b := NewBucket(4000, 10, 0)
		for b.Admit(1000, 0) {
		}
		b.SetRate(16000, 0)
		if got := b.TokensBytes(0); got != 0 {
			t.Fatalf("tokens = %d, want 0", got)
		}
		if got := b.TokensBytes(5 * ms); got != 10000 { // 2000 B/ms * 5 ms
			t.Fatalf("after 5ms at new rate tokens = %d, want 10000", got)
		}
	})
	t.Run("settles credit at the old rate first", func(t *testing.T) {
		b := NewBucket(8000, 10, 0)
		for b.Admit(1000, 0) {
		}
		b.SetRate(4000, 2*ms) // 2 ms at 1000 B/ms accrued, then clamp to 5000
		if got := b.TokensBytes(2 * ms); got != 2000 {
			t.Fatalf("tokens = %d, want 2000", got)
		}
	})
}

func TestBackwardsClockIgnored(t *testing.T) {
	b := NewBucket(8000, 10, 100*ms)
	for b.Admit(1000, 100*ms) {
	}
	if b.Admit(1000, 50*ms) {
		t.Fatal("a clock going backwards must not credit tokens")
	}
}

func TestConcurrentAdmitConserves(t *testing.T) {
	b := NewBucket(8000, 10, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := 0
			for i := 0; i < 100; i++ {
				if b.Admit(1000, 0) {
					n++
				}
			}
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	}
	wg.Wait()
	if total != 10 {
		t.Fatalf("concurrent admitted %d, want exactly 10", total)
	}
}

func TestClampBurstMs(t *testing.T) {
	for in, want := range map[int]int{0: DefaultBurstMs, -5: MinBurstMs, 1: 1, 10: 10, 1000: 1000, 1001: MaxBurstMs} {
		if got := ClampBurstMs(in); got != want {
			t.Errorf("ClampBurstMs(%d) = %d, want %d", in, got, want)
		}
	}
}

func BenchmarkBucketAdmit(b *testing.B) {
	bk := NewBucket(1_000_000, DefaultBurstMs, 0)
	b.ReportAllocs()
	var now int64
	for i := 0; i < b.N; i++ {
		now += 12_000
		bk.Admit(1400, now)
	}
}
