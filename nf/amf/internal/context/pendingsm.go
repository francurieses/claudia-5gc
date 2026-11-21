package context

import (
	"sort"
	"time"
)

// PendingSMRelease is one PDU session whose network-initiated release (5GSM
// cause Cause) is waiting for a CM-IDLE UE to answer paging, so the PDU SESSION
// RELEASE COMMAND can be delivered after the Service Accept.
// Ref: TS 23.502 §4.3.4.2 step 4; TS 24.501 §6.3.3.2.
type PendingSMRelease struct {
	PSI   uint8
	Cause uint8
}

type pendingSMEntry struct {
	cause uint8
	guard *time.Timer
}

// AddPendingSMRelease records a pending release for psi. It returns false (and
// changes nothing) when one is already recorded, which makes the mgmt DELETE
// idempotent. In-memory only; takes u.mu.
func (u *UEContext) AddPendingSMRelease(psi, cause uint8) bool {
	added, _ := u.AddPendingSMReleaseFirst(psi, cause)
	return added
}

// AddPendingSMReleaseFirst is AddPendingSMRelease that also reports whether the
// entry is the only pending one (first of the paging cycle), so the caller
// pages the UE once per cycle, not once per PSI. Takes u.mu.
func (u *UEContext) AddPendingSMReleaseFirst(psi, cause uint8) (added, first bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, dup := u.pendingSMRelease[psi]; dup {
		return false, false
	}
	first = len(u.pendingSMRelease) == 0
	if u.pendingSMRelease == nil {
		u.pendingSMRelease = make(map[uint8]*pendingSMEntry)
	}
	u.pendingSMRelease[psi] = &pendingSMEntry{cause: cause}
	return true, first
}

// SetPendingSMReleaseGuard attaches the paging guard timer to the pending
// release of psi. When no release is pending (cleared meanwhile) the timer is
// stopped. Takes u.mu.
func (u *UEContext) SetPendingSMReleaseGuard(psi uint8, t *time.Timer) {
	u.mu.Lock()
	defer u.mu.Unlock()
	e, ok := u.pendingSMRelease[psi]
	if !ok {
		t.Stop()
		return
	}
	if e.guard != nil {
		e.guard.Stop()
	}
	e.guard = t
}

// PendingSMReleaseCause returns the 5GSM cause of the pending release of psi.
func (u *UEContext) PendingSMReleaseCause(psi uint8) (uint8, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	e, ok := u.pendingSMRelease[psi]
	if !ok {
		return 0, false
	}
	return e.cause, true
}

// PendingSMReleases returns the pending releases in ascending PSI order without
// clearing them. Takes u.mu.
func (u *UEContext) PendingSMReleases() []PendingSMRelease {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.pendingSMRelease) == 0 {
		return nil
	}
	out := make([]PendingSMRelease, 0, len(u.pendingSMRelease))
	for psi, e := range u.pendingSMRelease {
		out = append(out, PendingSMRelease{PSI: psi, Cause: e.cause})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PSI < out[j].PSI })
	return out
}

// StopPendingSMReleaseGuards stops every paging guard timer (the UE answered the
// paging) but keeps the entries until the release is armed or cleared.
func (u *UEContext) StopPendingSMReleaseGuards() {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, e := range u.pendingSMRelease {
		if e.guard != nil {
			e.guard.Stop()
			e.guard = nil
		}
	}
}

// ClearPendingSMRelease drops the pending release of psi and stops its guard.
// It reports whether one was pending (a guard expiry uses this as its claim).
func (u *UEContext) ClearPendingSMRelease(psi uint8) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	e, ok := u.pendingSMRelease[psi]
	if !ok {
		return false
	}
	if e.guard != nil {
		e.guard.Stop()
	}
	delete(u.pendingSMRelease, psi)
	return true
}

// ClearAllPendingSMReleases drops every pending release (de-registration,
// context removal).
func (u *UEContext) ClearAllPendingSMReleases() {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, e := range u.pendingSMRelease {
		if e.guard != nil {
			e.guard.Stop()
		}
	}
	u.pendingSMRelease = nil
}
