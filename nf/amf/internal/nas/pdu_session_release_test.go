package nasmsg

// pdu_session_release_test.go — unit tests for the NW-initiated PDU Session
// Release ordering (TS 23.502 §4.3.4.3):
//   - The SM context is NOT deleted when the Release Command goes out; it is
//     deleted only once the UE confirms with a PDU Session Release Complete
//     (steps 5-8). Deleting it up-front inverts the spec ordering.
//   - The SM context deletion survives cancellation of the triggering context.
//     The NW-initiated release is driven by an HTTP mgmt request whose context
//     is cancelled the instant the handler returns 202; a delete bound to it
//     dies in flight with "context canceled".
//   - The T3592 guard releases the SM context if the UE never answers, so a
//     silent UE cannot leak a session in the SMF/UPF.
//   - Completion is idempotent and a no-op for sessions never NW-released.
//
// Ref: TS 23.502 §4.3.4.3; TS 24.501 §8.3.9, §10.3; TS 29.502 §5.2.2.3.3.

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// releaseSender is a fakeSender that also implements the optional
// DeleteSMContext interface the release path type-asserts for, recording each
// call and the liveness of the context it was handed.
type releaseSender struct {
	fakeSender

	mu       sync.Mutex
	refs     []string
	ctxErrs  []error
	deleteCh chan struct{}
}

func newReleaseSender() *releaseSender {
	return &releaseSender{deleteCh: make(chan struct{}, 4)}
}

func (r *releaseSender) DeleteSMContext(ctx context.Context, smContextRef string) error {
	r.mu.Lock()
	r.refs = append(r.refs, smContextRef)
	r.ctxErrs = append(r.ctxErrs, ctx.Err())
	r.mu.Unlock()
	select {
	case r.deleteCh <- struct{}{}:
	default:
	}
	return nil
}

func (r *releaseSender) calls() ([]string, []error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.refs...), append([]error(nil), r.ctxErrs...)
}

// newReleaseTestHandler builds a Handler with a real RegistrationHandler — the
// release path persists the UE context, so h.reg must be usable.
func newReleaseTestHandler(t *testing.T, sender *releaseSender) (*Handler, *amfctx.UEContext) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	reg := procedures.NewRegistrationHandler(mgr, nil, nil, nil, "test-amf", "001", "01", logger)

	ue := newTestUE(t)
	ue.PDUSessions[3] = &amfctx.PDUSession{
		PDUSessionID:  3,
		DNN:           "internet",
		SMFInstanceID: "sm-ctx-ref-3",
	}
	return NewHandler(sender, reg, logger), ue
}

// TestNetworkPDUSessionRelease_DefersSMContextDeleteUntilComplete asserts the
// TS 23.502 §4.3.4.3 ordering: the Release Command (steps 3-4) must not carry
// the SM context deletion with it — that belongs to steps 7-8, after the UE's
// Release Complete.
func TestNetworkPDUSessionRelease_DefersSMContextDeleteUntilComplete(t *testing.T) {
	sender := newReleaseSender()
	h, ue := newReleaseTestHandler(t, sender)

	if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 3); err != nil {
		t.Fatalf("InitiateNetworkPDUSessionRelease: %v", err)
	}

	if refs, _ := sender.calls(); len(refs) != 0 {
		t.Fatalf("SM context deleted before the UE confirmed the release: %v", refs)
	}
	ue.Lock()
	_, stillThere := ue.PDUSessions[3]
	ue.Unlock()
	if !stillThere {
		t.Error("PDU session dropped from UE context before Release Complete")
	}

	// UE confirms (step 5) → SM context must now be released (steps 7-8).
	h.completeNetworkPDUSessionRelease(context.Background(), ue, 3, "RELEASE_COMPLETE")

	refs, _ := sender.calls()
	if len(refs) != 1 || refs[0] != "sm-ctx-ref-3" {
		t.Fatalf("want one DeleteSMContext for sm-ctx-ref-3 after Release Complete, got %v", refs)
	}
	ue.Lock()
	_, stillThere = ue.PDUSessions[3]
	ue.Unlock()
	if stillThere {
		t.Error("PDU session still in UE context after release completed")
	}
}

// TestNetworkPDUSessionRelease_SurvivesTriggerContextCancel is the regression
// test for the live failure "smf: delete sm context: context canceled": the
// mgmt HTTP handler returns 202 and its request context is cancelled while the
// release is still in flight. The SM context deletion must not be bound to it.
func TestNetworkPDUSessionRelease_SurvivesTriggerContextCancel(t *testing.T) {
	sender := newReleaseSender()
	h, ue := newReleaseTestHandler(t, sender)

	// Mirror the mgmt API: the trigger's context dies as soon as it responds.
	trigger, cancel := context.WithCancel(context.Background())
	if err := h.InitiateNetworkPDUSessionRelease(trigger, ue, 3); err != nil {
		t.Fatalf("InitiateNetworkPDUSessionRelease: %v", err)
	}
	cancel()

	h.completeNetworkPDUSessionRelease(trigger, ue, 3, "RELEASE_COMPLETE")

	refs, ctxErrs := sender.calls()
	if len(refs) != 1 {
		t.Fatalf("want one DeleteSMContext, got %v", refs)
	}
	if ctxErrs[0] != nil {
		t.Errorf("DeleteSMContext ran on a cancelled context (%v) — the SBI DELETE would abort in flight", ctxErrs[0])
	}
}

// TestNetworkPDUSessionRelease_GuardReleasesWhenUESilent asserts a UE that
// never sends Release Complete cannot leak the session: the T3592 guard
// releases the SM context anyway. Ref: TS 24.501 §10.3.
func TestNetworkPDUSessionRelease_GuardReleasesWhenUESilent(t *testing.T) {
	sender := newReleaseSender()
	h, ue := newReleaseTestHandler(t, sender)

	if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 3); err != nil {
		t.Fatalf("InitiateNetworkPDUSessionRelease: %v", err)
	}

	// Fire the guard now rather than sleeping out T3592.
	v, ok := h.pendingRelease.Load(pendingReleaseKey(ue.AMFUENGAPId, 3))
	if !ok {
		t.Fatal("no pending release registered after Release Command")
	}
	st := v.(*pendingReleaseState)
	if !st.guard.Reset(time.Millisecond) {
		t.Fatal("guard timer was not armed")
	}

	select {
	case <-sender.deleteCh:
	case <-time.After(2 * time.Second):
		t.Fatal("T3592 guard did not release the SM context for a silent UE")
	}

	refs, ctxErrs := sender.calls()
	if len(refs) != 1 || refs[0] != "sm-ctx-ref-3" {
		t.Fatalf("want one DeleteSMContext for sm-ctx-ref-3, got %v", refs)
	}
	if ctxErrs[0] != nil {
		t.Errorf("guard-path DeleteSMContext ran on a cancelled context: %v", ctxErrs[0])
	}
}

// TestNetworkPDUSessionRelease_CompleteIsIdempotent covers the race between the
// UE's Release Complete and the T3592 guard (both may run), plus a Release
// Complete for a UE-initiated release, which the NW path never registered.
func TestNetworkPDUSessionRelease_CompleteIsIdempotent(t *testing.T) {
	sender := newReleaseSender()
	h, ue := newReleaseTestHandler(t, sender)

	// Unknown session: must be a silent no-op, not a spurious delete or panic.
	h.completeNetworkPDUSessionRelease(context.Background(), ue, 9, "RELEASE_COMPLETE")
	if refs, _ := sender.calls(); len(refs) != 0 {
		t.Fatalf("deleted an SM context for a session never NW-released: %v", refs)
	}

	if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 3); err != nil {
		t.Fatalf("InitiateNetworkPDUSessionRelease: %v", err)
	}
	h.completeNetworkPDUSessionRelease(context.Background(), ue, 3, "RELEASE_COMPLETE")
	h.completeNetworkPDUSessionRelease(context.Background(), ue, 3, "T3592_EXPIRY")

	if refs, _ := sender.calls(); len(refs) != 1 {
		t.Fatalf("want exactly one DeleteSMContext across duplicate completions, got %v", refs)
	}
}

// TestPDUSessionReleaseComplete_DrivesCompletion asserts the wiring: a 5GSM PDU
// Session Release Complete (0xD4) arriving in a UL NAS Transport is what
// completes the release. Ref: TS 24.501 §8.3.10.
func TestPDUSessionReleaseComplete_DrivesCompletion(t *testing.T) {
	sender := newReleaseSender()
	h, ue := newReleaseTestHandler(t, sender)

	if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 3); err != nil {
		t.Fatalf("InitiateNetworkPDUSessionRelease: %v", err)
	}

	// 5GSM header: EPD | PSI | PTI | msgType, carried in a UL NAS Transport.
	psi := uint8(3)
	container := []byte{nas.PDGroupSessionManagement, psi, 0x00, byte(nas.MsgTypePDUSessionReleaseComplete)}
	msg := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			MessageType:                   nas.MsgTypeULNASTransport,
		},
		Body: &nas.ULNASTransport{
			PayloadContainerType: nas.PayloadContainerTypeN1SM,
			PayloadContainer:     container,
			PDUSessionID:         &psi,
		},
	}
	if err := h.handleULNASTransport(context.Background(), ue, msg); err != nil {
		t.Fatalf("handleULNASTransport: %v", err)
	}

	refs, _ := sender.calls()
	if len(refs) != 1 || refs[0] != "sm-ctx-ref-3" {
		t.Fatalf("Release Complete did not release the SM context, got %v", refs)
	}
}
