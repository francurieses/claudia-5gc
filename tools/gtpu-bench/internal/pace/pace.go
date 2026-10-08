// Package pace provides a rate pacer that releases packets at a target packets-per-second
// without per-packet timers: the caller asks how many packets are due now.
package pace

import "time"

// Pacer tracks how many packets should have been sent by now at Rate pkts/s.
type Pacer struct {
	rate  float64
	start time.Time
	sent  uint64
}

// New returns a pacer starting at start. A non-positive rate paces nothing (Due returns 0).
func New(rate float64, start time.Time) *Pacer { return &Pacer{rate: rate, start: start} }

// Due returns how many packets may be sent at time now to stay on schedule, and records them
// as sent. It caps one call at maxBurst so a stalled sender does not flood the receiver.
func (p *Pacer) Due(now time.Time, maxBurst uint64) uint64 {
	if p.rate <= 0 || now.Before(p.start) {
		return 0
	}
	want := uint64(now.Sub(p.start).Seconds() * p.rate)
	if want <= p.sent {
		return 0
	}
	n := want - p.sent
	if n > maxBurst {
		// Skip the backlog rather than burst it: the shortfall shows up as offered < target.
		p.sent = want - maxBurst
		n = maxBurst
	}
	p.sent += n
	return n
}

// Sent returns the number of packets released so far.
func (p *Pacer) Sent() uint64 { return p.sent }
