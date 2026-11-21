package context

// aud_registration_test.go — regression tests for the registration spec audit
// (dev/campaigns/results/audit-registration.md). All findings are fixed
// (registration audit W1-W4 tasks), so every reproduction runs as a normal regression test:
//
//	GOWORK=off go test ./nf/amf/internal/context/ -run TestAUDRegistration -v
//
// Ref: TS 24.501 §5.5.1.2.4, §5.5.1.3.8 a)

import (
	"context"
	"testing"
)

// TestAUDRegistration15_ReallocatedGUTIReleasesOldTMSI: AssignGUTI adds a
// 5G-TMSI index entry on every (re)allocation and never drops the previous one,
// and Remove deletes only the current one. Every periodic/mobility update leaks
// an index entry, and an old 5G-TMSI keeps resolving to the context even after
// it was removed. TS 24.501 §5.5.1.3.8 a) 1) i): once the new 5G-GUTI is used,
// the AMF shall consider the old 5G-GUTI as invalid.
func TestAUDRegistration15_ReallocatedGUTIReleasesOldTMSI(t *testing.T) {
	ctx := context.Background()
	m := NewManager(AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	ue := m.AllocateUEContext(1)
	old := m.AssignGUTI(ctx, ue).TMSI
	_ = m.AssignGUTI(ctx, ue) // periodic/mobility registration update reallocates the 5G-GUTI

	m.Remove(ctx, ue)
	if got, ok := m.GetByTMSI(old); ok {
		t.Fatalf("old 5G-TMSI %08x still resolves to a removed context (%p): index entry leaked", old, got)
	}
}

// TestAUDRegistration21_CorrelationIDNoPanic: CorrelationID slices the last 8
// characters of the SUCI. extractIdentity stores "unknown" (7 characters) for a
// REGISTRATION REQUEST carrying an IMEI or no identity, so the first caller
// panics (index -1). No caller exists today; nothing recovers if one is added.
func TestAUDRegistration21_CorrelationIDNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CorrelationID panicked: %v", r)
		}
	}()
	u := &UEContext{SUCI: "unknown"}
	_ = u.CorrelationID()
}

// TestAUDRegistration24_TransitionAndCMStateRaceSnapshot: TransitionTo /
// SetCMState take the UE lock, so concurrent writers and Snapshot readers do
// not race (run under -race). TransitionToLocked is for callers holding u.mu.
func TestAUDRegistration24_TransitionAndCMStateRaceSnapshot(t *testing.T) {
	m := NewManager(AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	ue := m.AllocateUEContext(1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			ue.TransitionTo(GMMRegistered)
			ue.SetCMState(CMConnected)
			ue.Lock()
			ue.TransitionToLocked(GMMDeregistered)
			ue.Unlock()
			ue.SetCMState(CMIdle)
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
			_ = ue.Snapshot()
		}
	}
}

// TestAUDRegistration22_NGRANRCUDeletesStoredRadioCapability: the NG-RAN-RCU bit
// (octet 3 bit 2) of the 5GS update type IE deletes the stored UE radio
// capability; other bits (SMS requested) or an absent IE keep it.
// Ref: TS 24.501 §5.5.1.3.4, §9.11.3.9A.
func TestAUDRegistration22_NGRANRCUDeletesStoredRadioCapability(t *testing.T) {
	for _, tc := range []struct {
		name string
		ie   []byte
		kept bool
	}{
		{"absent", nil, true},
		{"sms requested only", []byte{0x01}, true},
		{"ng-ran-rcu", []byte{0x02}, false},
		{"ng-ran-rcu + sms", []byte{0x03}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
			ue := m.AllocateUEContext(1)
			ue.UERadioCapability = []byte{1, 2, 3}
			if got := ue.ApplyNGRANRCU(tc.ie); got == tc.kept {
				t.Fatalf("ApplyNGRANRCU = %v", got)
			}
			if kept := len(ue.UERadioCapability) > 0; kept != tc.kept {
				t.Fatalf("capability kept=%v, want %v", kept, tc.kept)
			}
		})
	}
}
