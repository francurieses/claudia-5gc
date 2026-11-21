package context

import (
	"testing"
	"time"
)

func TestPendingSMRelease(t *testing.T) {
	ue := &UEContext{}
	if !ue.AddPendingSMRelease(2, 39) || ue.AddPendingSMRelease(2, 39) {
		t.Fatal("Add must succeed once and be idempotent")
	}
	ue.AddPendingSMRelease(1, 39)
	got := ue.PendingSMReleases()
	if len(got) != 2 || got[0].PSI != 1 || got[1].PSI != 2 {
		t.Fatalf("PendingSMReleases=%v; want PSI order 1,2", got)
	}
	fired := make(chan struct{}, 1)
	ue.SetPendingSMReleaseGuard(1, time.AfterFunc(20*time.Millisecond, func() { fired <- struct{}{} }))
	if !ue.ClearPendingSMRelease(1) || ue.ClearPendingSMRelease(1) {
		t.Fatal("Clear must report once")
	}
	select {
	case <-fired:
		t.Fatal("guard fired after Clear")
	case <-time.After(60 * time.Millisecond):
	}
	ue.ClearAllPendingSMReleases()
	if len(ue.PendingSMReleases()) != 0 {
		t.Fatal("ClearAll left entries")
	}
}
