package context

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestTMSIIndexLifecycle: the 5G-TMSI index keeps at most the current and one
// previous 5G-TMSI per UE; ConfirmGUTI drops the previous one and Remove drops
// both. Ref: TS 24.501 §5.5.1.2.4, §5.5.1.3.8 a) 1) i)
func TestTMSIIndexLifecycle(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name        string
		reallocs    int  // AssignGUTI calls after the first one
		confirm     bool // ConfirmGUTI after the last allocation
		remove      bool
		wantEntries int
		wantPrevOK  bool // previous 5G-TMSI still resolves
	}{
		{name: "first allocation", reallocs: 0, wantEntries: 1},
		{name: "reallocation keeps previous until confirmed", reallocs: 1, wantEntries: 2, wantPrevOK: true},
		{name: "confirmation drops previous", reallocs: 1, confirm: true, wantEntries: 1},
		{name: "repeated reallocation is bounded", reallocs: 10, wantEntries: 2, wantPrevOK: true},
		{name: "remove drops current and previous", reallocs: 1, remove: true, wantEntries: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
			ue := m.AllocateUEContext(1)
			prev := m.AssignGUTI(ctx, ue).TMSI
			cur := prev
			for i := 0; i < tc.reallocs; i++ {
				prev = cur
				cur = m.AssignGUTI(ctx, ue).TMSI
			}
			if tc.confirm {
				m.ConfirmGUTI(ue)
			}
			if tc.remove {
				m.Remove(ctx, ue)
			}
			m.mu.RLock()
			n := len(m.uesByTMSI)
			m.mu.RUnlock()
			if n != tc.wantEntries {
				t.Fatalf("5G-TMSI index has %d entries, want %d", n, tc.wantEntries)
			}
			if tc.reallocs > 0 {
				if _, ok := m.GetByTMSI(prev); ok != tc.wantPrevOK {
					t.Fatalf("previous 5G-TMSI %08x resolves=%v, want %v", prev, ok, tc.wantPrevOK)
				}
			}
			if _, ok := m.GetByTMSI(cur); ok == tc.remove {
				t.Fatalf("current 5G-TMSI %08x resolves=%v after remove=%v", cur, ok, tc.remove)
			}
		})
	}
}

// TestSerialQueuePanicContained: a panicking serial task is recovered, the
// next task of the same UE still runs, and the releaser is called with
// remove=true for a non-registered UE and remove=false for a registered one.
func TestSerialQueuePanicContained(t *testing.T) {
	tests := []struct {
		name       string
		state      GMM5State
		sent       bool
		wantRemove bool
		wantGone   bool // context removed locally from the manager
	}{
		{name: "registered UE keeps registration", state: GMMRegistered, sent: true, wantRemove: false},
		{name: "unregistered UE released over N2", state: GMMDeregistered, sent: true, wantRemove: true},
		{name: "unregistered UE without N2 removed locally", state: GMMDeregistered, sent: false, wantRemove: true, wantGone: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
			ue := m.AllocateUEContext(1)
			ue.State = tc.state
			var mu sync.Mutex
			calls, gotRemove := 0, false
			m.SetPanicReleaser(func(_ context.Context, _ *UEContext, remove bool) bool {
				mu.Lock()
				calls++
				gotRemove = remove
				mu.Unlock()
				return tc.sent
			})
			done := make(chan struct{})
			ue.EnqueueSerial(func() { panic("injected") })
			ue.EnqueueSerial(func() { close(done) })
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("task after the panicking one never ran: drain goroutine died")
			}
			mu.Lock()
			defer mu.Unlock()
			if calls != 1 || gotRemove != tc.wantRemove {
				t.Fatalf("releaser calls=%d remove=%v, want 1 / %v", calls, gotRemove, tc.wantRemove)
			}
			if _, ok := m.GetByNGAPId(ue.AMFUENGAPId); ok == tc.wantGone {
				t.Fatalf("context present=%v, want removed=%v", ok, tc.wantGone)
			}
		})
	}
}

// TestRecoverPanicContains: a deferred RecoverPanic stops the panic at the
// goroutine boundary (NGAP dispatch call site).
func TestRecoverPanicContains(t *testing.T) {
	func() {
		defer RecoverPanic(context.Background(), nil, "N2", nil)
		panic("injected")
	}()
}
