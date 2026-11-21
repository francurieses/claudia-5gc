package nasmsg

// sm_release_order_test.go - SMF-012 rework: concurrent network-initiated
// releases keep NAS COUNT order on the wire, and one paging per cycle.
// Ref: TS 24.501 §4.4.3.1; TS 23.502 §4.3.4.2.

import (
	"context"
	"sync"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// orderSender records the NAS SQN of each NGAP release command in wire order.
// The command carrying the lowest COUNT (SQN == first) is held on a gate until
// another command has been sent or the wait bound passes: without LockDLNAS a
// later COUNT overtakes it (guaranteed out-of-order); with the lock nobody can
// overtake and the bound only ends the wait.
type orderSender struct {
	releaseSender
	first byte // SQN of the lowest DL NAS COUNT of the run
	omu   sync.Mutex
	sqns  []byte
	gate  chan struct{}
	once  sync.Once
}

func (o *orderSender) SendPDUSessionResourceReleaseCommand(_ *amfctx.UEContext, _ uint8, pdu []byte) error {
	sqn := pdu[6]
	if sqn == o.first {
		select {
		case <-o.gate:
		case <-time.After(300 * time.Millisecond):
		}
	}
	o.omu.Lock()
	o.sqns = append(o.sqns, sqn)
	o.omu.Unlock()
	if sqn != o.first {
		o.once.Do(func() { close(o.gate) })
	}
	return nil
}

func TestConcurrentNetworkReleasesKeepNASCountOrder(t *testing.T) {
	s := &orderSender{gate: make(chan struct{})}
	h, ue := newReleaseTestHandler(t, &s.releaseSender)
	h.sender = s
	ue.Lock()
	start := ue.SecurityCtx.DownlinkCount
	ue.Unlock()
	s.first = byte(start) // SQN is the low byte of the COUNT (TS 33.501 §6.4.3.1)
	for _, psi := range []uint8{4, 5, 6, 7} {
		ue.PDUSessions[psi] = &amfctx.PDUSession{PDUSessionID: psi, SMFInstanceID: "r"}
	}
	var wg sync.WaitGroup
	for _, psi := range []uint8{3, 4, 5, 6, 7} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, psi, 39); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	s.omu.Lock()
	defer s.omu.Unlock()
	if len(s.sqns) != 5 {
		t.Fatalf("got %d commands", len(s.sqns))
	}
	// Reconstruct the full COUNT from the SQN (5 commands: no ambiguity).
	for i, sqn := range s.sqns {
		want := byte(start) + byte(i)
		if sqn != want {
			t.Fatalf("NAS COUNT %d out of order on the wire at %d (SQN %d, want %d): %v",
				start+uint32(i), i, sqn, want, s.sqns)
		}
	}
}

type pagerCount struct {
	mu sync.Mutex
	n  int
}

func (p *pagerCount) SendPaging(*amfctx.UEContext) error {
	p.mu.Lock()
	p.n++
	p.mu.Unlock()
	return nil
}

func TestIdleUEWithTwoPendingPSIsPagedOnce(t *testing.T) {
	s := newReleaseSender()
	h, ue := newReleaseTestHandler(t, s)
	ue.PDUSessions[4] = &amfctx.PDUSession{PDUSessionID: 4, SMFInstanceID: "r4"}
	ue.CMState = amfctx.CMIdle
	pg := &pagerCount{}
	h.SetPager(pg)
	for _, psi := range []uint8{3, 4} {
		if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, psi, 39); err != nil {
			t.Fatal(err)
		}
	}
	if pg.n != 1 {
		t.Fatalf("SendPaging called %d times, want 1", pg.n)
	}
	if got := len(ue.PendingSMReleases()); got != 2 {
		t.Fatalf("pending = %d, want 2", got)
	}
	ue.StopPendingSMReleaseGuards()
}
