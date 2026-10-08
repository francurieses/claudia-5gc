// Package qos implements the UPF's rate policer: a zero-allocation,
// integer-only token bucket used to enforce the MBR of a QoS Enforcement Rule
// and the Session-AMBR (one bucket per QER per direction).
//
// Ref: TS 23.501 §5.7.1.8 (the UPF enforces the UL and DL Session-AMBR),
// §5.7.2.6 (Aggregate Bit Rates), §5.7.2.5 (excess traffic may be discarded by
// a policing function); TS 29.244 §5.4.4 (QoS control), §8.2.8 (MBR, kbps).
package qos

import (
	"sync"
	"time"
)

// Clock returns a monotonic time in nanoseconds. It is injected so tests drive
// the policer deterministically; production uses MonotonicClock.
type Clock func() int64

// MonotonicClock returns a Clock backed by the runtime's monotonic reading.
func MonotonicClock() Clock {
	start := time.Now()
	return func() int64 { return int64(time.Since(start)) }
}

const (
	// MinBurstMs and MaxBurstMs bound the configurable bucket depth in
	// milliseconds of traffic at the MBR (config qos.burst_ms). MaxBurstMs also
	// keeps depth*1e6 inside int64 for every MBR below UnlimitedKbps:
	// 0xFFFFFFFF kbps * 1000 ms * 1e6 = 4.29e18 < 9.22e18.
	MinBurstMs = 1
	MaxBurstMs = 1000

	// DefaultBurstMs is the default bucket depth in milliseconds (design choice
	// of docs/procedures/AmbrEnforcement.md, tuned with scripts/perf).
	DefaultBurstMs = 100

	// FloorBytes is the minimum bucket depth: 3 x 1500 octets, so one
	// MTU-sized burst is never starved at low rates.
	FloorBytes = 3 * 1500

	// UnlimitedKbps is the MBR value (2^32-1 kbps) at and above which a
	// direction is treated as not limited (local policy; keeps tools/gtpu-bench
	// sessions, which send 0xFFFFFFFF, at zero per-packet cost).
	UnlimitedKbps = 0xFFFFFFFF

	// ubitPerBit is the fixed-point scale of the token counter. One kbps for
	// one nanosecond is exactly 1 micro-bit, so refill is exact integer math.
	ubitPerBit = 1_000_000
)

// ClampBurstMs normalises a configured burst: 0 (unset) gives DefaultBurstMs,
// other values are clamped to [MinBurstMs, MaxBurstMs].
func ClampBurstMs(ms int) int {
	switch {
	case ms == 0:
		return DefaultBurstMs
	case ms < MinBurstMs:
		return MinBurstMs
	case ms > MaxBurstMs:
		return MaxBurstMs
	}
	return ms
}

// Bucket is a token-bucket policer for one direction of one QER. All methods
// are safe for concurrent use; none allocates.
type Bucket struct {
	mu      sync.Mutex
	burstMs int
	rate    uint64 // kbps
	depth   int64  // micro-bits
	fillNs  int64  // time to fill an empty bucket from zero
	tokens  int64  // micro-bits
	last    int64  // clock reading of the last refill
}

// NewBucket returns a full bucket for rateKbps (1 <= rateKbps < UnlimitedKbps)
// whose depth is max(rateKbps*burstMs bits, FloorBytes*8 bits).
func NewBucket(rateKbps uint64, burstMs int, now int64) *Bucket {
	b := &Bucket{burstMs: ClampBurstMs(burstMs), last: now}
	b.setRate(rateKbps)
	b.tokens = b.depth
	return b
}

func (b *Bucket) setRate(rateKbps uint64) {
	if rateKbps == 0 {
		rateKbps = 1 // callers pass nil instead of a zero-rate bucket; stay div-safe
	}
	if rateKbps >= UnlimitedKbps {
		rateKbps = UnlimitedKbps - 1
	}
	bits := int64(rateKbps) * int64(b.burstMs) // kbps * ms = bits
	if floor := int64(FloorBytes) * 8; bits < floor {
		bits = floor
	}
	b.rate = rateKbps
	b.depth = bits * ubitPerBit
	r := int64(rateKbps)
	b.fillNs = (b.depth + r - 1) / r
}

// Rate returns the configured rate in kbps.
func (b *Bucket) Rate() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rate
}

// SetRate changes the rate in place. Credit accrued up to now at the old rate
// is settled first; the tokens are then clamped to the new depth (never topped
// up), so the shared bucket keeps its state across an Update QER.
func (b *Bucket) SetRate(rateKbps uint64, now int64) {
	b.mu.Lock()
	b.refill(now)
	b.setRate(rateKbps)
	if b.tokens > b.depth {
		b.tokens = b.depth
	}
	b.mu.Unlock()
}

// refill credits the time elapsed since the last refill. Elapsed time at or
// beyond fillNs is clamped to "full" before multiplying, which rules out int64
// overflow for idle buckets. Caller holds b.mu.
func (b *Bucket) refill(now int64) {
	el := now - b.last
	if el <= 0 {
		return
	}
	b.last = now
	if el >= b.fillNs {
		b.tokens = b.depth
		return
	}
	b.tokens += el * int64(b.rate)
	if b.tokens > b.depth {
		b.tokens = b.depth
	}
}

// Admit debits an n-octet packet and reports whether it conforms. A
// non-conforming packet debits nothing.
func (b *Bucket) Admit(n int, now int64) bool {
	cost := int64(n) * 8 * ubitPerBit
	b.mu.Lock()
	b.refill(now)
	ok := b.tokens >= cost
	if ok {
		b.tokens -= cost
	}
	b.mu.Unlock()
	return ok
}

// Refund returns the tokens of an n-octet packet that Admit accepted but a
// later bucket rejected, so a policed packet consumes no earlier budget.
func (b *Bucket) Refund(n int) {
	cost := int64(n) * 8 * ubitPerBit
	b.mu.Lock()
	b.tokens += cost
	if b.tokens > b.depth {
		b.tokens = b.depth
	}
	b.mu.Unlock()
}

// TokensBytes returns the credit available at now, in whole octets.
func (b *Bucket) TokensBytes(now int64) int64 {
	b.mu.Lock()
	b.refill(now)
	t := b.tokens
	b.mu.Unlock()
	return t / (8 * ubitPerBit)
}

// DepthBytes returns the bucket depth in octets.
func (b *Bucket) DepthBytes() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.depth / (8 * ubitPerBit)
}
