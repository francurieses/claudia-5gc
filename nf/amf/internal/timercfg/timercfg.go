// Package timercfg holds the AMF UE-lifecycle timer values that can change at
// runtime through the O&M API: T3512 (sent to the UE in REGISTRATION ACCEPT),
// the mobile reachable guard and the implicit de-registration timer.
//
// The values live in one immutable snapshot swapped atomically, so a reader
// (Registration Accept builder, Mobile Reachable arming) always sees a
// consistent T3512 + guard pair and no write-ordering between separate
// atomics is needed. Mobile reachable is always derived as T3512 + guard.
//
// Refs: TS 24.501 §5.3.7, §10.2 Table 10.2.1; TS 23.501 §5.4.1.1.
package timercfg

import (
	"sync/atomic"
	"time"
)

// Values is one consistent set of timer durations in seconds.
type Values struct {
	// T3512Secs is the periodic registration update timer sent in IEI 0x5E.
	// Ref: TS 24.501 §10.2 Table 10.2.1.
	T3512Secs int
	// GuardSecs is added to T3512 to obtain the mobile reachable timer.
	// Ref: TS 24.501 §5.3.7 (mobile reachable timer longer than T3512).
	GuardSecs int
	// ImplicitDetachSecs is the implicit de-registration timer.
	// Ref: TS 24.501 §5.3.7; TS 23.501 §5.4.1.1.
	ImplicitDetachSecs int
}

// MobileReachableSecs is the derived mobile reachable timer, T3512 + guard.
// Ref: TS 24.501 §5.3.7.
func (v Values) MobileReachableSecs() int { return v.T3512Secs + v.GuardSecs }

// MobileReachable returns MobileReachableSecs as a duration.
func (v Values) MobileReachable() time.Duration {
	return time.Duration(v.MobileReachableSecs()) * time.Second
}

// ImplicitDetach returns ImplicitDetachSecs as a duration.
func (v Values) ImplicitDetach() time.Duration {
	return time.Duration(v.ImplicitDetachSecs) * time.Second
}

// Store is the runtime timer store. The zero value is not usable; use New.
type Store struct {
	base Values
	cur  atomic.Pointer[Values]
}

// New returns a Store whose effective values start equal to base.
func New(base Values) *Store {
	s := &Store{base: base}
	v := base
	s.cur.Store(&v)
	return s
}

// Base returns the immutable startup (YAML) values.
func (s *Store) Base() Values { return s.base }

// Effective returns the current values.
func (s *Store) Effective() Values { return *s.cur.Load() }

// Set replaces the effective values atomically (caller validates).
func (s *Store) Set(v Values) { s.cur.Store(&v) }

// Reset restores the effective values to base.
func (s *Store) Reset() { s.Set(s.base) }

// T3512Secs returns the effective T3512 in seconds.
func (s *Store) T3512Secs() int { return s.cur.Load().T3512Secs }
