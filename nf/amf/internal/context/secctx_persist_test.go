package context

import (
	"bytes"
	"testing"
)

// TestSecurityCtxPendingKeepsConfirmedAsPrevious: a second Begin while a change is
// pending keeps the originally confirmed context as previous (TS 24.501 §5.4.2.5),
// rollback restores it, and the persisted record carries the confirmed context
// while the new one is unconfirmed.
func TestSecurityCtxPendingKeepsConfirmedAsPrevious(t *testing.T) {
	ue := &UEContext{}
	confirmed := SecurityContext{Active: true, KAMF: bytes.Repeat([]byte{1}, 32), UplinkCount: 7}
	ue.SecurityCtx = confirmed
	ue.BeginSecurityCtxChange()
	ue.SecurityCtx = SecurityContext{Active: true, KAMF: bytes.Repeat([]byte{2}, 32)} // first new
	ue.BeginSecurityCtxChange()                                                       // second auth
	ue.SecurityCtx = SecurityContext{Active: true, KAMF: bytes.Repeat([]byte{3}, 32)} // second new

	if got := ue.PreviousSecurityCtx(); got == nil || got.KAMF[0] != 1 {
		t.Fatalf("previous = %+v, want the originally confirmed context", got)
	}
	if rec := ueContextToRecord(ue); rec.SecurityCtx.KAMF[0] != 1 || rec.SecurityCtx.UplinkCount != 7 {
		t.Fatalf("persisted kamf[0]=%d, want the confirmed context", rec.SecurityCtx.KAMF[0])
	}
	if pending, restored := ue.RollbackSecurityCtxChange(); !pending || !restored || ue.SecurityCtx.KAMF[0] != 1 {
		t.Fatalf("rollback pending=%v restored=%v kamf[0]=%d", pending, restored, ue.SecurityCtx.KAMF[0])
	}
	if rec := ueContextToRecord(ue); rec.SecurityCtx.KAMF[0] != 1 {
		t.Fatal("persisted context changed after rollback")
	}
}

// TestSecurityCtxPendingNoPreviousPersistsNothing: with no confirmed context an
// unconfirmed new one is not persisted.
func TestSecurityCtxPendingNoPreviousPersistsNothing(t *testing.T) {
	ue := &UEContext{}
	ue.BeginSecurityCtxChange()
	ue.SecurityCtx = SecurityContext{Active: true, KAMF: bytes.Repeat([]byte{9}, 32)}
	if rec := ueContextToRecord(ue); rec.SecurityCtx.Active || len(rec.SecurityCtx.KAMF) != 0 {
		t.Fatalf("persisted unconfirmed context: %+v", rec.SecurityCtx)
	}
}
