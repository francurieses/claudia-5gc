package ngap

// n2_targetfailed_test.go — SMF-005 companion changes C1 (UP deactivation of target-failed PSIs
// after HANDOVER NOTIFY) and C2 (403 + HANDOVER_PREP_FAIL on the HANDOVER_RES_ALLOC_FAIL leg is
// the expected outcome). Ref: TS 23.502 §4.3.7 step 1, §4.9.1.3.3; TS 29.502 §5.2.2.3.4;
// docs/procedures/N2Handover.md §7.6.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/free5gc/ngap/ngapType"
)

// failedAck admits PSI 1 and reports PSIs 2 (known), 11 (unknown to the AMF) as target-failed.
func (h *n2Harness) failedAck(t *testing.T) *HandoverRequestAckMsg {
	t.Helper()
	failT := resAllocFailTransfer(t, ngapType.CauseRadioNetworkPresentNoRadioResourcesAvailableInTargetCell)
	h.run(t, h.required(1, 2))
	h.smf.answer("hoack:"+ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoHandoverCmd, N2SmInfo: hoCmdTransfer(t, 1)}))
	ack := h.admit(1)
	ack.FailedSessions = []PDUSessionHOFailedItem{
		{PDUSessionID: 2, HandoverResourceAllocationUnsuccessfulTransfer: failT},
		{PDUSessionID: 2, HandoverResourceAllocationUnsuccessfulTransfer: failT}, // duplicate
		{PDUSessionID: 11, HandoverResourceAllocationUnsuccessfulTransfer: failT},
	}
	return ack
}

// ackFailed delivers the ack of failedAck and clears the HANDOVER COMMAND from the source link.
func (h *n2Harness) ackFailed(t *testing.T) {
	t.Helper()
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.failedAck(t))
	h.srcLn.mu.Lock()
	h.srcLn.sent = nil
	h.srcLn.mu.Unlock()
}

func noDeactivateWithin(t *testing.T, h *n2Harness) {
	t.Helper()
	h.srv.hoCompleteWG.Wait()
	if c := h.smf.callsOf("deactivate"); len(c) != 0 {
		t.Fatalf("unexpected deactivate calls: %+v", c)
	}
}

func TestN2TargetFailed_C1_DeactivatedAfterNotifyOnly(t *testing.T) {
	h := newN2Harness(t)
	h.ackFailed(t)

	st := h.srv.pendingN2HO[h.amfID]
	if st == nil || len(st.targetFailed) != 1 || st.targetFailed[0] != 2 {
		t.Fatalf("targetFailed = %+v, want [2] (unknown PSI 11 and duplicates excluded)", st)
	}
	// Preparation done, handover not executed: nothing is deactivated.
	noDeactivateWithin(t, h)

	before := procCount(t, procN2SMFDeactivate, smfResultOK)
	h.srv.HandleHandoverNotifyForTest(context.Background(), h.tgt, &HandoverNotifyMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8})
	h.srv.hoCompleteWG.Wait()

	calls := h.smf.callsOf("deactivate")
	if len(calls) != 1 || calls[0].ref != ref(2) {
		t.Fatalf("deactivate calls = %+v, want exactly one for PSI 2", calls)
	}
	if got := procCount(t, procN2SMFDeactivate, smfResultOK); got != before+1 {
		t.Fatalf("N2HandoverSMFDeactivate OK = %v, want %v", got, before+1)
	}
	if n := len(h.srcLn.pdus()); n != 1 {
		t.Fatalf("UEContextReleaseCommand to source: %d PDUs", n)
	}
	r, ok := h.sink.find("UpdateSMContext upCnxState DEACTIVATED for target-failed")
	if !ok || r.attrs["spec_ref"] != refN2TargetFailedDeact || r.attrs["direction"] != "OUT" ||
		r.attrs["interface"] != "Nsmf" || fmt.Sprint(r.attrs["pdu_session_id"]) != "2" || r.attrs["supi"] == nil {
		t.Fatalf("request log wrong: %+v", r)
	}
}

func TestN2TargetFailed_C1_FailureCountedAndDoesNotDelayRelease(t *testing.T) {
	h := newN2Harness(t)
	block := make(chan struct{})
	h.smf.deact = func(string) error { <-block; return errors.New("boom") }
	h.ackFailed(t)
	before := procCount(t, procN2SMFDeactivate, smfResultFailure)

	h.srv.handleHandoverNotify(context.Background(), h.tgt, &Message{Value: &HandoverNotifyMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8}})
	if n := len(h.srcLn.pdus()); n != 1 {
		t.Fatalf("UEContextReleaseCommand delayed by the deactivation (%d PDUs)", n)
	}
	close(block)
	h.srv.hoCompleteWG.Wait()
	if got := procCount(t, procN2SMFDeactivate, smfResultFailure); got != before+1 {
		t.Fatalf("FAILURE metric = %v, want %v", got, before+1)
	}
}

func TestN2TargetFailed_C1_BoundedByTimeout(t *testing.T) {
	h := newN2Harness(t)
	h.srv.onUPDeactivate = func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() }
	h.srv.SetSMFHOUpdateTimeoutForTest(50 * time.Millisecond)
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.failedAck(t))
	before := procCount(t, procN2SMFDeactivate, smfResultFailure)
	h.srv.HandleHandoverNotifyForTest(context.Background(), h.tgt, &HandoverNotifyMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8})
	h.srv.hoCompleteWG.Wait()
	if got := procCount(t, procN2SMFDeactivate, smfResultFailure); got != before+1 {
		t.Fatalf("timeout not counted: %v", got)
	}
}

func TestN2TargetFailed_C1_NoDeactivationWhenAllFailedOrNilHook(t *testing.T) {
	// All PSIs target-failed: preparation failure, pending state dropped, a late NOTIFY is a no-op.
	h := newN2Harness(t)
	h.run(t, h.required(1))
	ack := &HandoverRequestAckMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8, TargetToSourceTransparentContainer: []byte{7},
		FailedSessions: []PDUSessionHOFailedItem{{PDUSessionID: 1,
			HandoverResourceAllocationUnsuccessfulTransfer: resAllocFailTransfer(t, ngapType.CauseRadioNetworkPresentUnspecified)}}}
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, ack)
	h.srv.HandleHandoverNotifyForTest(context.Background(), h.tgt, &HandoverNotifyMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8})
	noDeactivateWithin(t, h)

	// Nil hook: no panic, no call, release still sent.
	h2 := newN2Harness(t)
	h2.srv.onUPDeactivate = nil
	h2.ackFailed(t)
	h2.srv.HandleHandoverNotifyForTest(context.Background(), h2.tgt, &HandoverNotifyMsg{AMFUENGAPId: h2.amfID, RANUENGAPId: 8})
	noDeactivateWithin(t, h2)
	if n := len(h2.srcLn.pdus()); n != 1 {
		t.Fatalf("release not sent with nil hook: %d", n)
	}
}

func TestN2TargetFailed_C1_NoFailedPSIs_NoDeactivation(t *testing.T) {
	h := newN2Harness(t)
	h.toNotify(t)
	h.srv.HandleHandoverNotifyForTest(context.Background(), h.tgt, &HandoverNotifyMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8})
	noDeactivateWithin(t, h)
}

func TestN2ResAllocFail_C2_403PrepFailCountedOK(t *testing.T) {
	h := newN2Harness(t)
	h.run(t, h.required(1, 2))
	prep := prepUnsuccessfulTransfer(t, int64(ngapType.CauseRadioNetworkPresentUnspecified))
	h.smf.answer("resallocfail:"+ref(2), fixed(SMFUpdateResult{HTTPStatus: 403, N2SmInfoType: n2InfoHandoverPrepFail,
		N2SmInfo: prep, Cause: "HANDOVER_RESOURCE_ALLOCATION_FAILURE"}))
	okBefore := procCount(t, procN2SMFResAllocFail, smfResultOK)
	rejBefore := procCount(t, procN2SMFResAllocFail, smfResultReject)

	ack := h.admit(1)
	ack.FailedSessions = []PDUSessionHOFailedItem{{PDUSessionID: 2,
		HandoverResourceAllocationUnsuccessfulTransfer: resAllocFailTransfer(t, ngapType.CauseRadioNetworkPresentUnspecified)}}
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, ack)

	if got := procCount(t, procN2SMFResAllocFail, smfResultOK); got != okBefore+1 {
		t.Fatalf("OK = %v, want %v", got, okBefore+1)
	}
	if got := procCount(t, procN2SMFResAllocFail, smfResultReject); got != rejBefore {
		t.Fatalf("REJECT moved: %v", got)
	}
	if r, ok := h.sink.find("SMF accepted HANDOVER_RES_ALLOC_FAIL"); !ok || r.attrs["result"] != smfResultOK {
		t.Fatalf("accepted log missing: %+v", r)
	}
	cmd := decodeHandoverCommand(t, h.srcLn.pdus()[0].raw)
	if string(cmd.release[2]) != string(prep) {
		t.Fatalf("SMF IE bytes not used verbatim")
	}
}

func TestN2ResAllocFail_C2_Other4xxStillRejected(t *testing.T) {
	h := newN2Harness(t)
	h.run(t, h.required(1, 2))
	h.smf.answer("resallocfail:"+ref(2), fixed(SMFUpdateResult{HTTPStatus: 403, N2SmInfoType: "OTHER"}))
	before := procCount(t, procN2SMFResAllocFail, smfResultReject)
	ack := h.admit(1)
	ack.FailedSessions = []PDUSessionHOFailedItem{{PDUSessionID: 2,
		HandoverResourceAllocationUnsuccessfulTransfer: resAllocFailTransfer(t, ngapType.CauseRadioNetworkPresentUnspecified)}}
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, ack)
	if got := procCount(t, procN2SMFResAllocFail, smfResultReject); got != before+1 {
		t.Fatalf("REJECT = %v, want %v", got, before+1)
	}
}
