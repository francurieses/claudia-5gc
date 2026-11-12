package context

import "testing"

// TestClearRegProcClearsPriorReg: ending the pending registration procedure also
// drops the prior-registration marker. Ref: TS 24.501 §5.5.1.2.8 c)
func TestClearRegProcClearsPriorReg(t *testing.T) {
	ue := &UEContext{}
	ue.SetPendingAccept([]byte{0x7e, 0x00, 0x42}, true)
	if _, prior, ok := ue.PendingAccept(); !ok || !prior {
		t.Fatalf("pending Accept prior=%v ok=%v", prior, ok)
	}
	ue.ClearRegProc()
	ue.Lock()
	ue.State = GMMCommonProcedureInitiated
	ue.Unlock()
	if ue.RegistrationNeverCompleted() == false {
		t.Fatal("priorReg survived ClearRegProc: update treated as already registered")
	}
}

// TestAbortRegAcceptAlwaysRegistered: aborting a pending Accept leaves the UE
// 5GMM-REGISTERED, initial or update. Ref: TS 24.501 §5.5.1.2.8 c), §5.5.1.3.8 c)
func TestAbortRegAcceptAlwaysRegistered(t *testing.T) {
	for _, prior := range []bool{false, true} {
		ue := &UEContext{State: GMMCommonProcedureInitiated}
		ue.SetPendingAccept([]byte{1}, prior)
		if got, was := ue.AbortRegAccept(); got != prior || !was {
			t.Fatalf("AbortRegAccept = %v,%v", got, was)
		}
		if ue.State != GMMRegistered {
			t.Fatalf("prior=%v: state %s, want 5GMM-REGISTERED", prior, ue.State)
		}
	}
}
