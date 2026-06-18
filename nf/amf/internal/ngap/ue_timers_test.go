package ngap

// ue_timers_test.go — unit tests for the UE lifecycle timers (Mobile Reachable
// Timer + Implicit Detach Timer). The Mobile Reachable Timer must only lead to
// implicit detach while the UE is CM-IDLE: a CM-CONNECTED UE has a NAS
// signalling connection and is reachable by definition.
// Ref: 3GPP TS 23.501 §5.3.2, TS 24.501 §5.3.7

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// newTimerTestServer builds a Server with short timers and a detach counter.
func newTimerTestServer(t *testing.T, detached *atomic.Int32) *Server {
	t.Helper()
	s := NewServer("", amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil), nil, AMFConfig{}, slog.Default())
	s.WithTimerConfig(TimerConfig{
		MobileReachable: 30 * time.Millisecond,
		ImplicitDetach:  30 * time.Millisecond,
	})
	s.SetImplicitDetachHandler(func(_ context.Context, _ *amfctx.UEContext) {
		detached.Add(1)
	})
	return s
}

// TestMobileReachable_IdleUEIsDetached verifies the normal CM-IDLE path:
// MRT fires → Implicit Detach Timer fires → onImplicitDetach is called.
func TestMobileReachable_IdleUEIsDetached(t *testing.T) {
	var detached atomic.Int32
	s := newTimerTestServer(t, &detached)

	ue := &amfctx.UEContext{SUPI: "imsi-001010000000099", CMState: amfctx.CMIdle}
	s.StartMobileReachableTimer(ue)

	deadline := time.After(2 * time.Second)
	for detached.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("implicit detach never fired for CM-IDLE UE")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestMobileReachable_ConnectedUEIsNotDetached verifies that a UE in
// CM-CONNECTED state is never implicitly detached even if the timer was
// (wrongly) armed or the stop raced the firing.
func TestMobileReachable_ConnectedUEIsNotDetached(t *testing.T) {
	var detached atomic.Int32
	s := newTimerTestServer(t, &detached)

	ue := &amfctx.UEContext{SUPI: "imsi-001010000000099", CMState: amfctx.CMConnected}
	s.StartMobileReachableTimer(ue)

	time.Sleep(200 * time.Millisecond) // well past MRT + implicit detach
	if n := detached.Load(); n != 0 {
		t.Fatalf("CM-CONNECTED UE was implicitly detached %d time(s)", n)
	}
}

// TestStopUETimers_CancelsWatchdogs verifies that StopUETimers (wired to the
// NAS layer's onUEReachable callback) cancels a pending implicit detach when
// the UE re-enters CM-CONNECTED.
func TestStopUETimers_CancelsWatchdogs(t *testing.T) {
	var detached atomic.Int32
	s := newTimerTestServer(t, &detached)

	ue := &amfctx.UEContext{SUPI: "imsi-001010000000099", CMState: amfctx.CMIdle}
	s.StartMobileReachableTimer(ue)

	// UE comes back before the MRT expires.
	ue.Lock()
	ue.CMState = amfctx.CMConnected
	ue.Unlock()
	s.StopUETimers(ue)

	time.Sleep(200 * time.Millisecond)
	if n := detached.Load(); n != 0 {
		t.Fatalf("UE was implicitly detached %d time(s) after StopUETimers", n)
	}
}
