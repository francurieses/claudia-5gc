package guard

import (
	"sync"
	"time"
)

// Entry is one audited call: a state-changing attempt, its outcome and who made it.
// Inputs are recorded as a hash only, so SUPIs and keys never reach the log.
type Entry struct {
	Time    time.Time `json:"time"`
	Tool    string    `json:"tool"`
	Risk    string    `json:"risk"`
	Role    string    `json:"role"`
	Session string    `json:"session"`
	// RemoteAddr is the caller's IP for HTTP transports, when known.
	RemoteAddr string `json:"remote_addr,omitempty"`
	Outcome    string `json:"outcome"` // executed | failed | dry_run | refused
	InputHash  string `json:"input_hash"`
	Error      string `json:"error,omitempty"`
}

// Audit is a bounded, concurrency-safe ring of Entry values. The oldest entry is
// dropped when the ring is full.
type Audit struct {
	mu   sync.Mutex
	buf  []Entry
	next int
	full bool
}

// NewAudit returns a ring holding up to size entries.
func NewAudit(size int) *Audit {
	return &Audit{buf: make([]Entry, size)}
}

// Add appends an entry, overwriting the oldest when full.
func (a *Audit) Add(e Entry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.buf[a.next] = e
	a.next = (a.next + 1) % len(a.buf)
	if a.next == 0 {
		a.full = true
	}
}

// Recent returns up to n of the newest entries, oldest first.
func (a *Audit) Recent(n int) []Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	count := a.next
	if a.full {
		count = len(a.buf)
	}
	if n <= 0 || n > count {
		n = count
	}
	out := make([]Entry, 0, n)
	start := a.next - n
	for i := 0; i < n; i++ {
		idx := (start + i + len(a.buf)) % len(a.buf)
		out = append(out, a.buf[idx])
	}
	return out
}
