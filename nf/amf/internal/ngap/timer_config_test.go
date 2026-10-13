package ngap

// Tests for runtime-changeable lifecycle timers: values are read from the
// shared timercfg store when a timer is armed; armed timers keep their
// duration. Ref: TS 24.501 §5.3.7; TS 23.501 §5.4.1.1.

import (
	"log/slog"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/timercfg"
)

func newStoreServer() (*Server, *timercfg.Store) {
	s := NewServer("", amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil), nil, AMFConfig{}, slog.Default())
	st := timercfg.New(timercfg.Values{T3512Secs: 60, GuardSecs: 120, ImplicitDetachSecs: 60})
	s.WithTimerStore(st)
	return s, st
}

func TestTimerConfigSnapshotFollowsStore(t *testing.T) {
	s, st := newStoreServer()
	if got := s.TimerConfigSnapshot(); got.MobileReachable != 180*time.Second || got.ImplicitDetach != 60*time.Second {
		t.Fatalf("base snapshot = %+v", got)
	}
	st.Set(timercfg.Values{T3512Secs: 120, GuardSecs: 120, ImplicitDetachSecs: 300})
	if got := s.TimerConfigSnapshot(); got.MobileReachable != 240*time.Second || got.ImplicitDetach != 300*time.Second {
		t.Fatalf("changed snapshot = %+v", got)
	}
}

func TestTimerConfigArmedAfterChangeUsesNewDuration(t *testing.T) {
	s, st := newStoreServer()
	st.Set(timercfg.Values{T3512Secs: 120, GuardSecs: 120, ImplicitDetachSecs: 300})
	ue := &amfctx.UEContext{SUPI: "imsi-001010000000001", CMState: amfctx.CMIdle}
	t.Cleanup(func() { s.StopUETimers(ue) })

	s.StartMobileReachableTimer(ue)
	s.startImplicitDetachTimer(ue)
	mr, id := ue.ArmedDurations()
	if mr != 240*time.Second || id != 300*time.Second {
		t.Fatalf("armed durations = %v / %v, want 240s / 300s", mr, id)
	}
}

func TestTimerConfigArmedTimerKeepsOldDuration(t *testing.T) {
	s, st := newStoreServer()
	ue := &amfctx.UEContext{SUPI: "imsi-001010000000001", CMState: amfctx.CMIdle}
	t.Cleanup(func() { s.StopUETimers(ue) })

	s.StartMobileReachableTimer(ue)
	st.Set(timercfg.Values{T3512Secs: 600, GuardSecs: 120, ImplicitDetachSecs: 60})
	if mr, _ := ue.ArmedDurations(); mr != 180*time.Second {
		t.Fatalf("armed Mobile Reachable changed to %v after a later change, want 180s", mr)
	}
}

func TestT3512RuntimeMobileReachableUsesSentWhenLowered(t *testing.T) {
	s, st := newStoreServer()
	st.Set(timercfg.Values{T3512Secs: 60, GuardSecs: 120, ImplicitDetachSecs: 60})
	ue := &amfctx.UEContext{SUPI: "imsi-001010000000001", CMState: amfctx.CMIdle, T3512SentSecs: 600}
	t.Cleanup(func() { s.StopUETimers(ue) })

	s.StartMobileReachableTimer(ue)
	if mr, _ := ue.ArmedDurations(); mr != 720*time.Second {
		t.Fatalf("armed Mobile Reachable = %v, want max(600,60)+120 = 720s", mr)
	}
}

func TestT3512RuntimeMobileReachableRaisedUsesEffective(t *testing.T) {
	s, st := newStoreServer()
	st.Set(timercfg.Values{T3512Secs: 600, GuardSecs: 120, ImplicitDetachSecs: 60})
	ue := &amfctx.UEContext{SUPI: "imsi-001010000000001", CMState: amfctx.CMIdle, T3512SentSecs: 60}
	t.Cleanup(func() { s.StopUETimers(ue) })

	s.StartMobileReachableTimer(ue)
	if mr, _ := ue.ArmedDurations(); mr != 720*time.Second {
		t.Fatalf("armed Mobile Reachable = %v, want 720s", mr)
	}
}
