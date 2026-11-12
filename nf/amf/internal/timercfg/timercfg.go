// Package timercfg holds the AMF UE-lifecycle timer values that can change at
// runtime through the O&M API: T3512 (sent to the UE in REGISTRATION ACCEPT),
// the mobile reachable guard and the implicit de-registration timer.
//
// The values live in one immutable snapshot swapped atomically, so a reader
// (Registration Accept builder, Mobile Reachable arming) always sees a
// consistent T3512 + guard pair and no write-ordering between separate
// atomics is needed. Mobile reachable is always derived as T3512 + guard.
//
// It also carries the network-side NAS common-procedure supervision timers
// T3550 (REGISTRATION ACCEPT), T3560 (AUTHENTICATION REQUEST / SECURITY MODE
// COMMAND) and T3570 (IDENTITY REQUEST), whose TS 24.501 §10.2 defaults apply
// whenever a value is unset (zero).
//
// Refs: TS 24.501 §5.3.7, §10.2 Table 10.2.1, Table 10.2.2; TS 23.501 §5.4.1.1.
package timercfg

import (
	"sync/atomic"
	"time"
)

// Default values of the NAS common-procedure supervision timers.
// Ref: TS 24.501 §10.2 Table 10.2.2 (T3550, T3560, T3570: 6 s each).
const (
	// DefaultT3550Secs is the default T3550 (REGISTRATION ACCEPT supervision).
	DefaultT3550Secs = 6
	// DefaultT3560Secs is the default T3560 (AUTHENTICATION REQUEST and SECURITY
	// MODE COMMAND supervision).
	DefaultT3560Secs = 6
	// DefaultT3570Secs is the default T3570 (IDENTITY REQUEST supervision).
	DefaultT3570Secs = 6
)

// Bounds of the runtime-changeable NAS common-procedure timers (lab limits; the
// network chooses these values, TS 24.501 §10.2 only gives the defaults).
const (
	// MinNASTimerSecs is the lowest T3550/T3560/T3570 accepted.
	MinNASTimerSecs = 1
	// MaxNASTimerSecs is the highest T3550/T3560/T3570 accepted.
	MaxNASTimerSecs = 60
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
	// T3550Secs supervises the REGISTRATION ACCEPT carrying a new 5G-GUTI;
	// 0 means DefaultT3550Secs. Ref: TS 24.501 §5.5.1.2.8 c), §10.2 Table 10.2.2.
	T3550Secs int
	// T3560Secs supervises AUTHENTICATION REQUEST and SECURITY MODE COMMAND;
	// 0 means DefaultT3560Secs. Ref: TS 24.501 §5.4.1.3.7, §5.4.2.7, §10.2.
	T3560Secs int
	// T3570Secs supervises IDENTITY REQUEST; 0 means DefaultT3570Secs.
	// Ref: TS 24.501 §5.4.3.6, §10.2 Table 10.2.2.
	T3570Secs int
}

func secsOrDefault(v, def int) time.Duration {
	if v <= 0 {
		v = def
	}
	return time.Duration(v) * time.Second
}

// T3550 returns the T3550 duration (TS default when unset).
func (v Values) T3550() time.Duration { return secsOrDefault(v.T3550Secs, DefaultT3550Secs) }

// T3560 returns the T3560 duration (TS default when unset).
func (v Values) T3560() time.Duration { return secsOrDefault(v.T3560Secs, DefaultT3560Secs) }

// T3570 returns the T3570 duration (TS default when unset).
func (v Values) T3570() time.Duration { return secsOrDefault(v.T3570Secs, DefaultT3570Secs) }

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
