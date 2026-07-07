package ngap

// dispatch_concurrency_test.go — regression tests for the per-UE serial NGAP
// dispatch. One UE's slow SBI call (e.g. Nsmf_PDUSession_CreateSMContext)
// must not delay NGAP/NAS processing for other UEs, while messages for the
// same UE must keep strict arrival order (SecurityCtx.UplinkCount depends on it).
// Ref: TS 38.412 §7 (SCTP ordered delivery), TS 24.501 §4.4.3 (NAS COUNT)

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// blockingNASHandler blocks HandleNASMessage for the UE whose AMF UE NGAP ID
// is blockID until release is closed; all calls are recorded per UE.
type blockingNASHandler struct {
	mu      sync.Mutex
	calls   map[int64][][]byte // AMF UE NGAP ID → NAS PDUs in handled order
	blockID int64
	release chan struct{}
	started chan struct{} // signalled once the blocked UE's handler has begun
}

func (h *blockingNASHandler) HandleNASMessage(_ context.Context, ue *amfctx.UEContext, pdu []byte) error {
	if ue.AMFUENGAPId == h.blockID {
		h.started <- struct{}{}
		<-h.release
	}
	h.mu.Lock()
	h.calls[ue.AMFUENGAPId] = append(h.calls[ue.AMFUENGAPId], pdu)
	h.mu.Unlock()
	return nil
}

func (h *blockingNASHandler) handled(id int64) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.calls[id])
}

// TestUplinkNASTransport_SlowUEDoesNotBlockOthers verifies that a NAS handler
// blocked on UE A (simulating a slow CreateSMContext) does not prevent UE B's
// Uplink NAS Transport from being processed.
func TestUplinkNASTransport_SlowUEDoesNotBlockOthers(t *testing.T) {
	mgr := amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	ueA := mgr.AllocateUEContext(1)
	ueB := mgr.AllocateUEContext(2)

	h := &blockingNASHandler{
		calls:   make(map[int64][][]byte),
		blockID: ueA.AMFUENGAPId,
		release: make(chan struct{}),
		started: make(chan struct{}, 1),
	}
	s := NewServer("", mgr, h, AMFConfig{}, slog.Default())
	gnb := &GNBContext{UEs: map[int64]*amfctx.UEContext{}, IdleUEs: map[int64]*amfctx.UEContext{}}

	// UE A's message: handler blocks. The dispatch call itself must return
	// promptly — the blocking work runs on UE A's serial queue.
	done := make(chan struct{})
	go func() {
		s.handleUplinkNASTransport(context.Background(), gnb, &Message{
			Value: &UplinkNASTransport{AMFUENGAPId: ueA.AMFUENGAPId, NASPdu: []byte{0x01}},
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUplinkNASTransport blocked the dispatch goroutine while the NAS handler was slow")
	}
	<-h.started // UE A's handler is now inside the blocking SBI call

	// UE B's message must complete while UE A is still blocked.
	s.handleUplinkNASTransport(context.Background(), gnb, &Message{
		Value: &UplinkNASTransport{AMFUENGAPId: ueB.AMFUENGAPId, NASPdu: []byte{0x02}},
	})
	deadline := time.Now().Add(2 * time.Second)
	for h.handled(ueB.AMFUENGAPId) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("UE B's NAS message was not processed while UE A's SBI call was in flight")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if h.handled(ueA.AMFUENGAPId) != 0 {
		t.Fatal("UE A's handler completed unexpectedly — test setup broken")
	}

	close(h.release)
	deadline = time.Now().Add(2 * time.Second)
	for h.handled(ueA.AMFUENGAPId) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("UE A's NAS message never completed after unblocking")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestEnqueueSerial_PerUEOrdering verifies strict FIFO execution of queued
// tasks for a single UE — the guarantee that keeps SecurityCtx.UplinkCount
// consistent for back-to-back messages (RegistrationComplete + UL NAS Transport).
func TestEnqueueSerial_PerUEOrdering(t *testing.T) {
	ue := &amfctx.UEContext{}
	const n = 200
	var mu sync.Mutex
	var order []int
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		ue.EnqueueSerial(func() {
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
			wg.Done()
		})
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if order[i] != i {
			t.Fatalf("task order violated at index %d: got %d", i, order[i])
		}
	}
}
