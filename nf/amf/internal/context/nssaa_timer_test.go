package context

import (
	"sync"
	"testing"
)

type stubTimer struct {
	mu      sync.Mutex
	stopped int
}

func (s *stubTimer) Stop() bool { s.mu.Lock(); s.stopped++; s.mu.Unlock(); return true }

// The T3575 supervision state lives on the UE: re-arming invalidates the old
// generation, Stop and Manager.Remove stop the timer, and a stopped generation
// is never "current" again. Ref: TS 24.501 §5.4.7.2.3 a)
func TestNSSAATimerLifecycle(t *testing.T) {
	ue := &UEContext{SUPI: "imsi-1"}
	first, second := &stubTimer{}, &stubTimer{}
	var g1, g2 uint64
	ue.ArmNSSAATimer("cmd1", 0, func(g uint64) NSSAATimerStopper { g1 = g; return first })
	if cmd, n, ok := ue.NSSAATimerCurrent(g1); !ok || cmd != "cmd1" || n != 0 {
		t.Fatalf("current = %v %d %v", cmd, n, ok)
	}
	ue.ArmNSSAATimer("cmd2", 3, func(g uint64) NSSAATimerStopper { g2 = g; return second })
	if first.stopped != 1 {
		t.Fatal("re-arm must stop the previous timer")
	}
	if _, _, ok := ue.NSSAATimerCurrent(g1); ok {
		t.Fatal("old generation must be stale")
	}
	if cmd, n, ok := ue.NSSAATimerCurrent(g2); !ok || cmd != "cmd2" || n != 3 || !ue.NSSAATimerRunning() {
		t.Fatalf("current = %v %d %v", cmd, n, ok)
	}

	m := NewManager(AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	m.Remove(t.Context(), ue)
	if second.stopped != 1 || ue.NSSAATimerRunning() {
		t.Fatal("Manager.Remove must stop T3575")
	}
	if _, _, ok := ue.NSSAATimerCurrent(g2); ok {
		t.Fatal("a stopped generation must not be current")
	}
	ue.StopNSSAATimer() // idempotent
}

// StopAllTimers (run on a UE's reconnection) must not touch T3575.
func TestStopAllTimersKeepsNSSAATimer(t *testing.T) {
	ue := &UEContext{}
	st := &stubTimer{}
	ue.ArmNSSAATimer("c", 0, func(uint64) NSSAATimerStopper { return st })
	ue.StopAllTimers()
	if st.stopped != 0 || !ue.NSSAATimerRunning() {
		t.Fatal("StopAllTimers must not stop the NSSAA supervision")
	}
}
