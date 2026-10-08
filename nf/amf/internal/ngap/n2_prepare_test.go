package ngap

// n2_prepare_test.go — AMF-012 follow-up: N2 handover PREPARING leg at HANDOVER REQUIRED,
// target-failed PDU sessions of HANDOVER REQUEST ACKNOWLEDGE (HANDOVER_RES_ALLOC_FAIL, IE 78)
// and the COMPLETED leg after HANDOVER NOTIFY. SMF hooks are deterministic fakes; waiting is
// done on channels with timeouts (never select/default polling).
// Ref: TS 23.502 §4.9.1.3.2 steps 1-12, §4.9.1.3.3; TS 29.502 §5.2.2.3.4; TS 38.413 §8.4.1-§8.4.3

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/francurieses/claudia-5gc/shared/logging"
)

// ---- recording logger that keeps With() attributes ----------------------------------

type flatRec struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

type recSink struct {
	mu   sync.Mutex
	recs []flatRec
}

type attrRecorder struct {
	sink *recSink
	pre  []slog.Attr
}

func (a *attrRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (a *attrRecorder) Handle(_ context.Context, r slog.Record) error {
	m := map[string]any{}
	for _, p := range a.pre {
		m[p.Key] = p.Value.Any()
	}
	r.Attrs(func(at slog.Attr) bool { m[at.Key] = at.Value.Any(); return true })
	a.sink.mu.Lock()
	a.sink.recs = append(a.sink.recs, flatRec{r.Level, r.Message, m})
	a.sink.mu.Unlock()
	return nil
}
func (a *attrRecorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &attrRecorder{sink: a.sink, pre: append(append([]slog.Attr(nil), a.pre...), attrs...)}
}
func (a *attrRecorder) WithGroup(string) slog.Handler { return a }

func (s *recSink) snapshot() []flatRec {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]flatRec(nil), s.recs...)
}

func (s *recSink) find(msgSub string) (flatRec, bool) {
	for _, r := range s.snapshot() {
		if containsFold(r.msg, msgSub) {
			return r, true
		}
	}
	return flatRec{}, false
}

// procCount reads fivegc_procedure_total{nf="AMF",procedure,result}.
func procCount(t *testing.T, proc, result string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "fivegc_procedure_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			l := map[string]string{}
			for _, lp := range m.GetLabel() {
				l[lp.GetName()] = lp.GetValue()
			}
			if l["nf"] == "AMF" && l["procedure"] == proc && l["result"] == result {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// ---- fixtures -----------------------------------------------------------------------

// setupReqTransfer is a valid PDUSessionResourceSetupRequestTransfer distinguishable by teid.
func setupReqTransfer(t *testing.T, teid byte) []byte {
	return mustMarshal(t, ngapType.PDUSessionResourceSetupRequestTransfer{
		ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceSetupRequestTransferIEs{
			List: []ngapType.PDUSessionResourceSetupRequestTransferIEs{{
				Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDULNGUUPTNLInformation},
				Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
				Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
					Present:               ngapType.PDUSessionResourceSetupRequestTransferIEsPresentULNGUUPTNLInformation,
					ULNGUUPTNLInformation: gtpTunnel(teid),
				},
			}},
		},
	})
}

func resAllocFailTransfer(t *testing.T, cause aper.Enumerated) []byte {
	return mustMarshal(t, ngapType.HandoverResourceAllocationUnsuccessfulTransfer{
		Cause: buildCause(ngapType.CausePresentRadioNetwork, int64(cause)),
	})
}

var cachedTransfer = []byte{1, 2, 3} // N2SmTransfer of every harness session

type n2Harness struct {
	*smfHarness
	sink    *recSink
	targets chan HOTargetID
}

// newN2Harness wires the three new hooks to the fake SMF (kinds "required", "resallocfail",
// "complete") and replaces the logger with an attribute-keeping recorder.
func newN2Harness(t *testing.T) *n2Harness {
	t.Helper()
	h := &n2Harness{smfHarness: newSMFHarness(t), sink: &recSink{}, targets: make(chan HOTargetID, 16)}
	h.srv.logger = slog.New(&attrRecorder{sink: h.sink})
	req := h.smf.hook("required")
	h.srv.onHandoverRequired = func(ctx context.Context, ref string, tr []byte, tgt HOTargetID) SMFUpdateResult {
		h.targets <- tgt
		return req(ctx, ref, tr)
	}
	h.srv.onHandoverResAllocFail = h.smf.hook("resallocfail")
	comp := h.smf.hook("complete")
	h.srv.onHandoverComplete = func(ctx context.Context, ref string) SMFUpdateResult { return comp(ctx, ref, nil) }
	return h
}

func (h *n2Harness) required(psis ...uint8) *HandoverRequiredMsg {
	r := &HandoverRequiredMsg{
		AMFUENGAPId: h.amfID, RANUENGAPId: 1, TargetGlobalRANNodeID: h.tgt.GlobalGNBID,
		SourceToTargetTransparentContainer: []byte{9},
		Target: HOTargetID{
			Node: GlobalRANNode{Type: RANNodeTypeGNB, MCC: "001", MNC: "01", GNBID: 0x123456, GNBIDBitLen: 24},
			TAI:  &HOTargetTAI{MCC: "001", MNC: "01", TAC: "000001"},
		},
	}
	for _, p := range psis {
		r.PDUSessions = append(r.PDUSessions, PDUSessionHORqdItem{PDUSessionID: p, HandoverRequiredTransfer: []byte{0xA0 + p}})
	}
	return r
}

// run sends the HANDOVER REQUIRED, waits for the serial task and returns the HANDOVER
// REQUEST written to the target (nil when none); the fake links are cleared.
func (h *n2Harness) run(t *testing.T, req *HandoverRequiredMsg) []byte {
	t.Helper()
	h.srv.HandleHandoverRequiredForTest(context.Background(), h.src, req)
	var hr []byte
	if p := h.tgtLn.pdus(); len(p) > 0 {
		if len(p) != 1 || p[0].ppid != 60 {
			t.Fatalf("target got %d PDUs", len(p))
		}
		hr = p[0].raw
	}
	h.tgtLn.mu.Lock()
	h.tgtLn.sent = nil
	h.tgtLn.mu.Unlock()
	return hr
}

// hrTransfers maps PSI -> HandoverRequestTransfer of a HANDOVER REQUEST.
func hrTransfers(t *testing.T, raw []byte) (map[int64][]byte, []int64) {
	t.Helper()
	_, ies := handoverRequestIEs(t, raw)
	out := map[int64][]byte{}
	var order []int64
	ie, ok := ies[ngapType.ProtocolIEIDPDUSessionResourceSetupListHOReq]
	if !ok || ie.Value.PDUSessionResourceSetupListHOReq == nil {
		t.Fatalf("no PDUSessionResourceSetupListHOReq")
	}
	for _, it := range ie.Value.PDUSessionResourceSetupListHOReq.List {
		out[it.PDUSessionID.Value] = []byte(it.HandoverRequestTransfer)
		order = append(order, it.PDUSessionID.Value)
	}
	return out, order
}

func (h *n2Harness) preparationFailureCause(t *testing.T, raw []byte) ngapType.Cause {
	t.Helper()
	pdu, err := libngap.Decoder(raw)
	if err != nil || pdu.UnsuccessfulOutcome == nil || pdu.UnsuccessfulOutcome.Value.HandoverPreparationFailure == nil {
		t.Fatalf("not a HandoverPreparationFailure (err=%v)", err)
	}
	for _, ie := range pdu.UnsuccessfulOutcome.Value.HandoverPreparationFailure.ProtocolIEs.List {
		if ie.Value.Cause != nil {
			return *ie.Value.Cause
		}
	}
	t.Fatalf("no Cause IE")
	return ngapType.Cause{}
}

// ---- PREPARING leg ---------------------------------------------------------------------

func TestN2Preparing_SMFTransferInHandoverRequest(t *testing.T) {
	h := newN2Harness(t)
	s1, s2 := setupReqTransfer(t, 1), setupReqTransfer(t, 2)
	h.smf.answer("required:"+ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, HoState: hoStatePreparing, N2SmInfoType: n2InfoPDUResSetupReq, N2SmInfo: s1}))
	h.smf.answer("required:"+ref(2), fixed(SMFUpdateResult{HTTPStatus: 200, HoState: hoStatePreparing, N2SmInfoType: n2InfoPDUResSetupReq, N2SmInfo: s2}))
	nccBefore, _ := h.nccNow()
	before := procCount(t, procN2SMFPreparing, smfResultOK)

	hr := h.run(t, h.required(1, 2))
	if hr == nil {
		t.Fatalf("HANDOVER REQUEST not sent")
	}
	tr, order := hrTransfers(t, hr)
	if len(tr) != 2 || !bytes.Equal(tr[1], s1) || !bytes.Equal(tr[2], s2) || !equalIDs(order, []int64{1, 2}) {
		t.Fatalf("HANDOVER REQUEST transfers = %v (order %v), want the SMF PDU_RES_SETUP_REQ bytes", tr, order)
	}
	calls := h.smf.callsOf("required")
	if len(calls) != 2 {
		t.Fatalf("PREPARING calls = %d, want 2 (PSI 3 not listed by the source)", len(calls))
	}
	for _, c := range calls {
		want := []byte{0xA1}
		if c.ref == ref(2) {
			want = []byte{0xA2}
		}
		if !bytes.Equal(c.transfer, want) {
			t.Fatalf("HandoverRequiredTransfer for %s = %x, want %x", c.ref, c.transfer, want)
		}
	}
	tgt := <-h.targets
	if tgt.Node.GNBID != 0x123456 || tgt.TAI == nil || tgt.TAI.TAC != "000001" {
		t.Fatalf("target ID not passed to the SMF hook: %+v", tgt)
	}
	if nccAfter, _ := h.nccNow(); nccAfter == nccBefore {
		t.Fatalf("NCC not advanced after a successful PREPARING leg")
	}
	st := h.srv.pendingN2HO[h.amfID]
	if st == nil || len(st.prepReleased) != 0 {
		t.Fatalf("pending state wrong: %+v", st)
	}
	if got := procCount(t, procN2SMFPreparing, smfResultOK); got != before+2 {
		t.Fatalf("N2HandoverSMFPreparing OK = %v, want %v", got, before+2)
	}
	r, ok := h.sink.find("UpdateSMContext for N2 handover preparation (PREPARING)")
	if !ok || r.attrs["ho_state"] != hoStatePreparing || r.attrs["n2_sm_info_type"] != n2InfoHandoverRequired ||
		r.attrs["spec_ref"] != refN2PreparingReq || r.attrs["direction"] != "OUT" || r.attrs["interface"] != "Nsmf" {
		t.Fatalf("request log wrong: %+v", r)
	}
}

func TestN2Preparing_FallbackToCachedTransfer(t *testing.T) {
	tests := []struct {
		name  string
		res   SMFUpdateResult
		level slog.Level
	}{
		{"no n2SmInfo", SMFUpdateResult{HTTPStatus: 200, HoState: hoStatePreparing}, slog.LevelWarn},
		{"undecodable", SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPDUResSetupReq, N2SmInfo: garbage}, slog.LevelError},
		{"wrong type", SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoHandoverCmd, N2SmInfo: hoCmdTransfer(t, 1)}, slog.LevelError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newN2Harness(t)
			h.smf.answer("required:"+ref(1), fixed(tc.res))
			hr := h.run(t, h.required(1))
			tr, _ := hrTransfers(t, hr)
			if !bytes.Equal(tr[1], cachedTransfer) {
				t.Fatalf("transfer = %x, want cached %x", tr[1], cachedTransfer)
			}
			if bytes.Contains(hr, garbage) {
				t.Fatalf("undecodable bytes forwarded")
			}
			found := false
			for _, r := range h.sink.snapshot() {
				if r.level == tc.level && containsFold(r.msg, "cached N2SmTransfer") {
					found = true
				}
			}
			if !found {
				t.Fatalf("fallback not logged at %v", tc.level)
			}
		})
	}
}

func TestN2Preparing_NoUsableTransferAndNoCache_IsFailure(t *testing.T) {
	h := newN2Harness(t)
	h.ue.Lock()
	h.ue.PDUSessions[2].N2SmTransfer = nil
	h.ue.Unlock()
	h.smf.answer("required:"+ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPDUResSetupReq, N2SmInfo: setupReqTransfer(t, 1)}))
	h.smf.answer("required:"+ref(2), fixed(SMFUpdateResult{HTTPStatus: 200}))
	hr := h.run(t, h.required(1, 2))
	tr, _ := hrTransfers(t, hr)
	if len(tr) != 1 || tr[1] == nil {
		t.Fatalf("PSI 2 (no usable transfer at all) must be excluded: %v", tr)
	}
	if st := h.srv.pendingN2HO[h.amfID]; st == nil || len(st.prepReleased) != 1 || st.prepReleased[0].PDUSessionID != 2 {
		t.Fatalf("PSI 2 not remembered as released")
	}
}

func TestN2Preparing_RejectedPSIsAreExcludedAndEndInIE78(t *testing.T) {
	prep := prepUnsuccessfulTransfer(t, int64(ngapType.CauseRadioNetworkPresentUnspecified))
	tests := []struct {
		name      string
		answer    func(context.Context, []byte) SMFUpdateResult
		result    string
		wantCause aper.Enumerated
		verbatim  []byte
	}{
		{"404", fixed(SMFUpdateResult{HTTPStatus: 404}), smfResultReject, ngapType.CauseRadioNetworkPresentUnknownPDUSessionID, nil},
		{"500", fixed(SMFUpdateResult{HTTPStatus: 500}), smfResultReject, ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"timeout", func(ctx context.Context, _ []byte) SMFUpdateResult {
			<-ctx.Done()
			return SMFUpdateResult{Err: ctx.Err()}
		}, smfResultFailure, ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"2xx CANCELLED", fixed(SMFUpdateResult{HTTPStatus: 200, HoState: hoStateCancelled}), smfResultReject,
			ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"2xx HANDOVER_PREP_FAIL verbatim", fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoHandoverPrepFail, N2SmInfo: prep}),
			smfResultReject, ngapType.CauseRadioNetworkPresentUnspecified, prep},
		{"500 HANDOVER_PREP_FAIL verbatim", fixed(SMFUpdateResult{HTTPStatus: 500, N2SmInfoType: n2InfoHandoverPrepFail, N2SmInfo: prep}),
			smfResultReject, ngapType.CauseRadioNetworkPresentUnspecified, prep},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newN2Harness(t)
			h.smf.answer("required:"+ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPDUResSetupReq, N2SmInfo: setupReqTransfer(t, 1)}))
			h.smf.answer("required:"+ref(2), tc.answer)
			before := procCount(t, procN2SMFPreparing, tc.result)
			hr := h.run(t, h.required(1, 2))
			tr, _ := hrTransfers(t, hr)
			if len(tr) != 1 || tr[1] == nil {
				t.Fatalf("rejected PSI 2 must not be in the HANDOVER REQUEST: %v", tr)
			}
			if got := procCount(t, procN2SMFPreparing, tc.result); got != before+1 {
				t.Fatalf("N2HandoverSMFPreparing %s = %v, want %v", tc.result, got, before+1)
			}
			// Continue with the Ack: PSI 2 must end in HANDOVER COMMAND IE 78.
			h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1))
			cmd := decodeHandoverCommand(t, h.srcLn.pdus()[0].raw)
			if !equalIDs(cmd.ids, []int64{10, 85, 29, 59, 78, 106}) || len(cmd.handover) != 1 || len(cmd.release) != 1 {
				t.Fatalf("IE order = %v handover=%d release=%d", cmd.ids, len(cmd.handover), len(cmd.release))
			}
			wantRadioCause(t, prepCause(t, cmd.release[2]), tc.wantCause)
			if tc.verbatim != nil && !bytes.Equal(cmd.release[2], tc.verbatim) {
				t.Fatalf("not the SMF bytes verbatim")
			}
		})
	}
}

func TestN2Preparing_AllRejected_PreparationFailure_NoNCC_NoPending(t *testing.T) {
	h := newN2Harness(t)
	h.smf.answer("required:"+ref(1), fixed(SMFUpdateResult{HTTPStatus: 500}))
	h.smf.answer("required:"+ref(2), fixed(SMFUpdateResult{HTTPStatus: 404}))
	nccBefore, _ := h.nccNow()
	nhBefore, _, _ := h.ue.NHState()
	hr := h.run(t, h.required(1, 2))
	if hr != nil {
		t.Fatalf("HANDOVER REQUEST sent although every PSI was rejected")
	}
	srcSent := h.srcLn.pdus()
	if len(srcSent) != 1 || srcSent[0].ppid != 60 {
		t.Fatalf("source got %d PDUs", len(srcSent))
	}
	wantRadioCause(t, h.preparationFailureCause(t, srcSent[0].raw),
		ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)
	nhAfter, nccAfter, _ := h.ue.NHState()
	if nccAfter != nccBefore || nhAfter != nhBefore {
		t.Fatalf("NCC/NH consumed by a preparation that failed at the SMF (ncc %d -> %d)", nccBefore, nccAfter)
	}
	if h.srv.HasPendingN2HandoverForTest(h.amfID) {
		t.Fatalf("pending state created")
	}
	r, ok := h.sink.find("HandoverPreparationFailure")
	if !ok || r.attrs["cause"] != causeSMFRejectedAll || r.attrs["result"] != smfResultReject ||
		r.attrs["interface"] != "N2" || r.attrs["direction"] != "OUT" {
		t.Fatalf("failure log wrong: %+v", r)
	}
}

func TestN2Preparing_UnknownSourcePSI(t *testing.T) {
	t.Run("skipped, no SMF call, listed in IE 78 when another PSI succeeds", func(t *testing.T) {
		h := newN2Harness(t)
		h.run(t, h.required(1, 11))
		for _, c := range h.smf.callsOf("required") {
			if c.ref != ref(1) {
				t.Fatalf("SMF called for the unknown PSI: %+v", c)
			}
		}
		st := h.srv.pendingN2HO[h.amfID]
		if st == nil || len(st.prepReleased) != 1 || st.prepReleased[0].PDUSessionID != 11 {
			t.Fatalf("unknown PSI not remembered: %+v", st)
		}
		w, ok := h.sink.find("PDU session from gNB not found")
		if !ok || w.level != slog.LevelWarn || w.attrs["direction"] != "IN" {
			t.Fatalf("WARN missing / without direction: %+v", w)
		}
		h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1))
		cmd := decodeHandoverCommand(t, h.srcLn.pdus()[0].raw)
		wantRadioCause(t, prepCause(t, cmd.release[11]), ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)
	})
	t.Run("only unknown PSIs: missing-IE reject, NCC untouched", func(t *testing.T) {
		h := newN2Harness(t)
		nccBefore, _ := h.nccNow()
		if hr := h.run(t, h.required(11)); hr != nil {
			t.Fatalf("HANDOVER REQUEST sent without any candidate")
		}
		if len(h.smf.callsOf("required")) != 0 {
			t.Fatalf("SMF called without candidates")
		}
		if nccAfter, _ := h.nccNow(); nccAfter != nccBefore {
			t.Fatalf("NCC consumed")
		}
		if r, ok := h.sink.find("HandoverPreparationFailure"); !ok || r.attrs["cause"] != "missing-ie-PDUSessionResourceSetupListHOReq" {
			t.Fatalf("reject cause wrong: %+v", r)
		}
	})
}

func TestN2Preparing_SourceListedNone_FallsBackToAllSessionsWithoutRequiredTransfer(t *testing.T) {
	h := newN2Harness(t)
	hr := h.run(t, h.required())
	tr, order := hrTransfers(t, hr)
	if !equalIDs(order, []int64{1, 2, 3}) || !bytes.Equal(tr[1], cachedTransfer) {
		t.Fatalf("order=%v tr=%v", order, tr)
	}
	calls := h.smf.callsOf("required")
	if len(calls) != 3 {
		t.Fatalf("PREPARING calls = %d, want 3", len(calls))
	}
	for _, c := range calls {
		if len(c.transfer) != 0 {
			t.Fatalf("HandoverRequiredTransfer sent for the fallback set: %x", c.transfer)
		}
	}
}

func TestN2Preparing_NilHook_CachedTransferNoSMFCall(t *testing.T) {
	h := newN2Harness(t)
	h.srv.onHandoverRequired = nil
	hr := h.run(t, h.required(1, 2))
	tr, _ := hrTransfers(t, hr)
	if !bytes.Equal(tr[1], cachedTransfer) || !bytes.Equal(tr[2], cachedTransfer) {
		t.Fatalf("cached transfers not used")
	}
	if len(h.smf.callsOf("required")) != 0 {
		t.Fatalf("SMF called without a hook")
	}
	if r, ok := h.sink.find("no SMF hook configured"); !ok || r.level != slog.LevelWarn || r.attrs["direction"] != "OUT" {
		t.Fatalf("WARN missing or without direction: %+v", r)
	}
}

func TestN2Preparing_DoesNotBlockSCTPLoopOrOtherUEs(t *testing.T) {
	h := newN2Harness(t)
	block := make(chan struct{})
	h.smf.answer("required:"+ref(1), func(context.Context, []byte) SMFUpdateResult { <-block; return SMFUpdateResult{HTTPStatus: 200} })
	h.srv.SetSMFHOUpdateTimeoutForTest(smfTestWait * 2)
	done := make(chan struct{})
	go func() {
		h.srv.StartHandoverRequiredForTest(context.Background(), h.src, h.required(1))
		close(done)
	}()
	select {
	case <-done: // the inline part returned while the SMF call is pending
	case <-time.After(smfTestWait):
		t.Fatalf("handleHandoverRequired blocked on the SMF call (SCTP loop would stall)")
	}
	h.smf.expect(t, 1)
	other := h.srv.mgr.AllocateUEContext(2)
	ran := make(chan struct{})
	other.EnqueueSerial(func() { close(ran) })
	select {
	case <-ran:
	case <-time.After(smfTestWait):
		t.Fatalf("another UE blocked behind the pending SMF call")
	}
	if len(h.tgtLn.pdus()) != 0 {
		t.Fatalf("HANDOVER REQUEST written while the SMF call is pending")
	}
	close(block)
	h.srv.WaitUESerialForTest(h.amfID)
	if len(h.tgtLn.pdus()) != 1 {
		t.Fatalf("HANDOVER REQUEST not sent after the SMF answered")
	}
}

// ---- target-failed PSIs of HANDOVER REQUEST ACKNOWLEDGE ---------------------------------

func TestN2Ack_TargetFailedPSIs_ForwardedAndInIE78_NoDuplicates(t *testing.T) {
	h := newN2Harness(t)
	// PREPARING: PSI 3 rejected by the SMF; PSIs 1, 2 go to the target.
	h.smf.answer("required:"+ref(3), fixed(SMFUpdateResult{HTTPStatus: 500}))
	h.run(t, h.required(1, 2, 3))
	h.smf.answer("hoack:"+ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, HoState: hoStatePrepared, N2SmInfoType: n2InfoHandoverCmd, N2SmInfo: hoCmdTransfer(t, 1)}))
	h.smf.answer("resallocfail:"+ref(2), fixed(SMFUpdateResult{HTTPStatus: 200, HoState: hoStateCancelled}))
	failT := resAllocFailTransfer(t, ngapType.CauseRadioNetworkPresentNoRadioResourcesAvailableInTargetCell)
	before := procCount(t, procN2SMFResAllocFail, smfResultOK)

	ack := h.admit(1)
	ack.FailedSessions = []PDUSessionHOFailedItem{
		{PDUSessionID: 2, HandoverResourceAllocationUnsuccessfulTransfer: failT},
		{PDUSessionID: 11, HandoverResourceAllocationUnsuccessfulTransfer: failT}, // unknown to the AMF
		{PDUSessionID: 3, HandoverResourceAllocationUnsuccessfulTransfer: failT},  // also a PREPARING reject: no duplicate
	}
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, ack)

	calls := h.smf.callsOf("resallocfail")
	got := map[string][]byte{}
	for _, c := range calls {
		got[c.ref] = c.transfer
	}
	if len(calls) != 2 || !bytes.Equal(got[ref(2)], failT) || !bytes.Equal(got[ref(3)], failT) {
		t.Fatalf("HANDOVER_RES_ALLOC_FAIL calls = %+v (unknown PSI 11 must not reach the SMF)", calls)
	}
	// 2xx hoState CANCELLED on this leg is OK, not a rejection.
	if got := procCount(t, procN2SMFResAllocFail, smfResultOK); got != before+2 {
		t.Fatalf("N2HandoverSMFResAllocFail OK = %v, want %v", got, before+2)
	}
	if r, ok := h.sink.find("HandoverRequestAcknowledge: failed-to-setup PDU session not found"); !ok || r.level != slog.LevelWarn || r.attrs["direction"] != "IN" {
		t.Fatalf("unknown failed PSI not WARNed with direction: %+v", r)
	}
	cmd := decodeHandoverCommand(t, h.srcLn.pdus()[0].raw)
	if !equalIDs(cmd.ids, []int64{10, 85, 29, 59, 78, 106}) {
		t.Fatalf("IE order = %v", cmd.ids)
	}
	if len(cmd.handover) != 1 || len(cmd.release) != 3 {
		t.Fatalf("handover=%v release=%v, want PSI 1 in IE 59 and PSIs 2, 11, 3 once each in IE 78", cmd.handover, cmd.release)
	}
	for _, psi := range []int64{2, 11, 3} {
		if _, ok := cmd.release[psi]; !ok {
			t.Fatalf("PSI %d missing in IE 78", psi)
		}
	}
	// PSI 2 / 11: cause decoded from the target's transfer; PSI 3 (duplicate): first occurrence wins.
	wantRadioCause(t, prepCause(t, cmd.release[2]), ngapType.CauseRadioNetworkPresentNoRadioResourcesAvailableInTargetCell)
	wantRadioCause(t, prepCause(t, cmd.release[11]), ngapType.CauseRadioNetworkPresentNoRadioResourcesAvailableInTargetCell)
	st := h.srv.pendingN2HO[h.amfID]
	if st == nil || len(st.admittedSessions) != 1 || st.admittedSessions[0].PDUSessionID != 1 {
		t.Fatalf("accepted set wrong")
	}
}

func TestN2Ack_TargetFailed_UndecodableTransferFallsBackToCause7_SMFPrepFailVerbatim(t *testing.T) {
	h := newN2Harness(t)
	h.run(t, h.required(1, 2, 3))
	prep := prepUnsuccessfulTransfer(t, int64(ngapType.CauseRadioNetworkPresentUnspecified))
	h.smf.answer("resallocfail:"+ref(3), fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoHandoverPrepFail, N2SmInfo: prep}))
	ack := h.admit(1)
	ack.FailedSessions = []PDUSessionHOFailedItem{
		{PDUSessionID: 2, HandoverResourceAllocationUnsuccessfulTransfer: garbage},
		{PDUSessionID: 3, HandoverResourceAllocationUnsuccessfulTransfer: resAllocFailTransfer(t, ngapType.CauseRadioNetworkPresentUnspecified)},
	}
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, ack)
	cmd := decodeHandoverCommand(t, h.srcLn.pdus()[0].raw)
	wantRadioCause(t, prepCause(t, cmd.release[2]), ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)
	if !bytes.Equal(cmd.release[3], prep) {
		t.Fatalf("SMF HANDOVER_PREP_FAIL bytes not used verbatim for PSI 3")
	}
}

func TestN2Ack_AllTargetFailed_PreparationFailure_StillForwardedToSMF(t *testing.T) {
	h := newN2Harness(t)
	h.run(t, h.required(1))
	ack := &HandoverRequestAckMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8, TargetToSourceTransparentContainer: []byte{7},
		FailedSessions: []PDUSessionHOFailedItem{{PDUSessionID: 1,
			HandoverResourceAllocationUnsuccessfulTransfer: resAllocFailTransfer(t, ngapType.CauseRadioNetworkPresentUnspecified)}}}
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, ack)
	if len(h.smf.callsOf("resallocfail")) != 1 {
		t.Fatalf("failed PSI not forwarded to the SMF")
	}
	srcSent := h.srcLn.pdus()
	if len(srcSent) != 1 {
		t.Fatalf("source got %d PDUs", len(srcSent))
	}
	h.preparationFailureCause(t, srcSent[0].raw)
	if h.srv.HasPendingN2HandoverForTest(h.amfID) {
		t.Fatalf("pending state not dropped")
	}
}

func TestN2Ack_ResAllocFail_RejectAndFailureAreOnlyLogged(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(context.Context, []byte) SMFUpdateResult
		result string
	}{
		{"404", fixed(SMFUpdateResult{HTTPStatus: 404}), smfResultReject},
		{"timeout", func(ctx context.Context, _ []byte) SMFUpdateResult {
			<-ctx.Done()
			return SMFUpdateResult{Err: ctx.Err()}
		}, smfResultFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newN2Harness(t)
			h.run(t, h.required(1, 2))
			h.smf.answer("resallocfail:"+ref(2), tc.answer)
			before := procCount(t, procN2SMFResAllocFail, tc.result)
			ack := h.admit(1)
			ack.FailedSessions = []PDUSessionHOFailedItem{{PDUSessionID: 2,
				HandoverResourceAllocationUnsuccessfulTransfer: resAllocFailTransfer(t, ngapType.CauseRadioNetworkPresentUnspecified)}}
			h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, ack)
			cmd := decodeHandoverCommand(t, h.srcLn.pdus()[0].raw)
			if len(cmd.handover) != 1 || len(cmd.release) != 1 {
				t.Fatalf("an SMF problem on the RES_ALLOC_FAIL leg must not change the HANDOVER COMMAND")
			}
			if got := procCount(t, procN2SMFResAllocFail, tc.result); got != before+1 {
				t.Fatalf("metric %s = %v, want %v", tc.result, got, before+1)
			}
		})
	}
}

// ---- COMPLETED leg after HANDOVER NOTIFY ----------------------------------------------------

func (h *n2Harness) toNotify(t *testing.T) {
	t.Helper()
	h.run(t, h.required(1, 2))
	h.smf.answer("hoack:"+ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoHandoverCmd, N2SmInfo: hoCmdTransfer(t, 1)}))
	h.smf.answer("hoack:"+ref(2), fixed(SMFUpdateResult{HTTPStatus: 500}))
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1, 2))
	h.srcLn.mu.Lock()
	h.srcLn.sent = nil
	h.srcLn.mu.Unlock()
}

func TestN2Notify_CompletedOnlyForAcceptedPSIs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer SMFUpdateResult
		result string
	}{
		{"COMPLETED", SMFUpdateResult{HTTPStatus: 200, HoState: hoStateCompleted}, smfResultOK},
		{"CANCELLED is still OK on this leg", SMFUpdateResult{HTTPStatus: 200, HoState: hoStateCancelled}, smfResultOK},
		{"404", SMFUpdateResult{HTTPStatus: 404}, smfResultReject},
		{"transport error", SMFUpdateResult{Err: context.DeadlineExceeded}, smfResultFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newN2Harness(t)
			h.toNotify(t)
			h.smf.answer("complete:"+ref(1), fixed(tc.answer))
			before := procCount(t, procN2SMFComplete, tc.result)
			h.srv.HandleHandoverNotifyForTest(context.Background(), h.tgt, &HandoverNotifyMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8})

			calls := h.smf.callsOf("complete")
			if len(calls) != 1 || calls[0].ref != ref(1) || len(calls[0].transfer) != 0 {
				t.Fatalf("COMPLETED calls = %+v, want exactly one for the SMF-accepted PSI 1", calls)
			}
			if got := procCount(t, procN2SMFComplete, tc.result); got != before+1 {
				t.Fatalf("N2HandoverSMFComplete %s = %v, want %v", tc.result, got, before+1)
			}
			if h.ue.RANUENGAPId != 8 {
				t.Fatalf("UE context not migrated")
			}
			if n := len(h.srcLn.pdus()); n != 1 {
				t.Fatalf("UEContextReleaseCommand to the source: %d PDUs", n)
			}
			if h.srv.HasPendingN2HandoverForTest(h.amfID) {
				t.Fatalf("pending state not consumed")
			}
			r, ok := h.sink.find("UpdateSMContext Handover Complete")
			if !ok || r.attrs["ho_state"] != hoStateCompleted || r.attrs["spec_ref"] != refN2Complete ||
				r.attrs["correlation_id"] == "" || r.attrs["correlation_id"] == nil {
				t.Fatalf("request log wrong: %+v", r)
			}
		})
	}
}

func TestN2Notify_ReleaseToSourceNotDelayedBySMF(t *testing.T) {
	h := newN2Harness(t)
	h.toNotify(t)
	block := make(chan struct{})
	h.smf.answer("complete:"+ref(1), func(context.Context, []byte) SMFUpdateResult { <-block; return SMFUpdateResult{HTTPStatus: 200} })
	h.srv.SetSMFHOUpdateTimeoutForTest(smfTestWait * 2)
	h.srv.handleHandoverNotify(context.Background(), h.tgt, &Message{Value: &HandoverNotifyMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8}})
	h.smf.expect(t, 1)
	if n := len(h.srcLn.pdus()); n != 1 {
		t.Fatalf("UEContextReleaseCommand delayed behind the pending COMPLETED call (%d PDUs)", n)
	}
	close(block)
	h.srv.hoCompleteWG.Wait()
}

func TestN2Notify_NilHook_NoCall(t *testing.T) {
	h := newN2Harness(t)
	h.toNotify(t)
	h.srv.onHandoverComplete = nil
	h.srv.HandleHandoverNotifyForTest(context.Background(), h.tgt, &HandoverNotifyMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8})
	if len(h.smf.callsOf("complete")) != 0 || len(h.srcLn.pdus()) != 1 {
		t.Fatalf("nil hook: calls=%d release=%d", len(h.smf.callsOf("complete")), len(h.srcLn.pdus()))
	}
}

func TestN2Notify_NoPending_WarnWithInterfaceAndDirection(t *testing.T) {
	h := newN2Harness(t)
	h.srv.HandleHandoverNotifyForTest(context.Background(), h.tgt, &HandoverNotifyMsg{AMFUENGAPId: 4242, RANUENGAPId: 8})
	r, ok := h.sink.find("no pending N2 handover")
	if !ok || r.level != slog.LevelWarn || r.attrs["interface"] != "N2" || r.attrs["direction"] != "IN" {
		t.Fatalf("WARN wrong: %+v", r)
	}
}

// ---- log completeness ------------------------------------------------------------------------

func TestN2Handover_EveryLogLineHasMandatoryFields(t *testing.T) {
	h := newN2Harness(t)
	h.smf.answer("required:"+ref(2), fixed(SMFUpdateResult{HTTPStatus: 404}))
	h.run(t, h.required(1, 2, 11))
	h.smf.answer("hoack:"+ref(1), fixed(SMFUpdateResult{HTTPStatus: 200}))
	ack := h.admit(1)
	ack.FailedSessions = []PDUSessionHOFailedItem{{PDUSessionID: 3,
		HandoverResourceAllocationUnsuccessfulTransfer: resAllocFailTransfer(t, ngapType.CauseRadioNetworkPresentUnspecified)},
		{PDUSessionID: 12}}
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, ack)
	h.srv.HandleHandoverNotifyForTest(context.Background(), h.tgt, &HandoverNotifyMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8})
	// And a UE-not-found reject.
	h.srv.HandleHandoverRequiredForTest(context.Background(), h.src, &HandoverRequiredMsg{AMFUENGAPId: 999, RANUENGAPId: 1})

	recs := h.sink.snapshot()
	if len(recs) < 20 {
		t.Fatalf("only %d log lines — flow not exercised", len(recs))
	}
	for _, r := range recs {
		if r.attrs["procedure"] == "ANRelease" {
			continue // generic SendUEContextReleaseCommand line (ngap.go), not part of the handover handlers
		}
		for _, k := range []string{"nf", "procedure", "interface", "direction", "spec_ref"} {
			if v, ok := r.attrs[k]; !ok || v == "" {
				t.Errorf("log line %q lacks %q (attrs %v)", r.msg, k, r.attrs)
			}
		}
		if r.attrs["correlation_id"] == nil && r.attrs["amf_ue_ngap_id"] != int64(999) {
			t.Errorf("log line %q lacks correlation_id", r.msg)
		}
	}
}

// ---- codec ----------------------------------------------------------------------------------

func TestExtractHOTargetID(t *testing.T) {
	plmn := aper.OctetString{0x00, 0xF1, 0x10} // MCC 001, MNC 01
	gnb := ngapType.TargetID{
		Present: ngapType.TargetIDPresentTargetRANNodeID,
		TargetRANNodeID: &ngapType.TargetRANNodeID{
			GlobalRANNodeID: ngapType.GlobalRANNodeID{
				Present: ngapType.GlobalRANNodeIDPresentGlobalGNBID,
				GlobalGNBID: &ngapType.GlobalGNBID{
					PLMNIdentity: ngapType.PLMNIdentity{Value: plmn},
					GNBID: ngapType.GNBID{Present: ngapType.GNBIDPresentGNBID,
						GNBID: &aper.BitString{Bytes: []byte{0x12, 0x34, 0x56, 0x00}, BitLength: 24}},
				},
			},
			SelectedTAI: ngapType.TAI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmn}, TAC: ngapType.TAC{Value: aper.OctetString{0, 0, 7}}},
		},
	}
	got := extractHOTargetID(&gnb)
	if got.Node.Type != RANNodeTypeGNB || got.Node.GNBIDBitLen != 24 || got.Node.GNBID != 0x123456 || got.Node.MCC != "001" || got.Node.MNC != "01" {
		t.Fatalf("node = %+v", got.Node)
	}
	if got.TAI == nil || got.TAI.TAC != "000007" || got.TAI.MCC != "001" || got.TAI.MNC != "01" {
		t.Fatalf("tai = %+v", got.TAI)
	}
	if z := extractHOTargetID(nil); z.TAI != nil || z.Node.Type != "" {
		t.Fatalf("nil TargetID must decode to the zero value")
	}
	if z := extractHOTargetID(&ngapType.TargetID{Present: ngapType.TargetIDPresentTargeteNBID}); z.TAI != nil {
		t.Fatalf("non-gNB target must decode to the zero value")
	}
}

func TestExtractHandoverRequestAcknowledge_FailedToSetupList(t *testing.T) {
	ack := &ngapType.HandoverRequestAcknowledge{}
	ack.ProtocolIEs.List = []ngapType.HandoverRequestAcknowledgeIEs{{
		Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListHOAck},
		Value: ngapType.HandoverRequestAcknowledgeIEsValue{
			Present: ngapType.HandoverRequestAcknowledgeIEsPresentPDUSessionResourceFailedToSetupListHOAck,
			PDUSessionResourceFailedToSetupListHOAck: &ngapType.PDUSessionResourceFailedToSetupListHOAck{
				List: []ngapType.PDUSessionResourceFailedToSetupItemHOAck{
					{PDUSessionID: ngapType.PDUSessionID{Value: 4}, HandoverResourceAllocationUnsuccessfulTransfer: aper.OctetString{9, 8}},
				}},
		},
	}}
	got := extractHandoverRequestAcknowledge(ack)
	if len(got.FailedSessions) != 1 || got.FailedSessions[0].PDUSessionID != 4 ||
		!bytes.Equal(got.FailedSessions[0].HandoverResourceAllocationUnsuccessfulTransfer, []byte{9, 8}) {
		t.Fatalf("FailedSessions = %+v", got.FailedSessions)
	}
}

func TestCauseFromNGAPRoundTrip(t *testing.T) {
	for _, p := range []int{ngapType.CausePresentRadioNetwork, ngapType.CausePresentTransport, ngapType.CausePresentNas,
		ngapType.CausePresentProtocol, ngapType.CausePresentMisc} {
		gp, gv, ok := causeFromNGAP(buildCause(p, 3))
		if !ok || gp != p || gv != 3 {
			t.Fatalf("present %d -> (%d,%d,%v)", p, gp, gv, ok)
		}
	}
	if _, _, ok := causeFromNGAP(ngapType.Cause{}); ok {
		t.Fatalf("empty cause decoded")
	}
}

// One correlation ID per N2 handover: the PREPARING, HANDOVER_REQ_ACK and COMPLETED SMF
// legs (and their log lines) share the ID generated at HANDOVER REQUIRED.
// Ref: root CLAUDE.md "Logging — Required Format" (correlation_id)
func TestN2Handover_OneCorrelationIDAcrossLegs(t *testing.T) {
	h := newN2Harness(t)
	var mu sync.Mutex
	seen := map[string][]string{}
	note := func(leg string, ctx context.Context) {
		mu.Lock()
		seen[leg] = append(seen[leg], logging.CorrelationID(ctx))
		mu.Unlock()
	}
	prep, ack, comp := h.srv.onHandoverRequired, h.srv.onHandoverReqAck, h.srv.onHandoverComplete
	h.srv.onHandoverRequired = func(ctx context.Context, ref string, tr []byte, tgt HOTargetID) SMFUpdateResult {
		note("preparing", ctx)
		return prep(ctx, ref, tr, tgt)
	}
	h.srv.onHandoverReqAck = func(ctx context.Context, ref string, tr []byte) SMFUpdateResult {
		note("reqack", ctx)
		return ack(ctx, ref, tr)
	}
	h.srv.onHandoverComplete = func(ctx context.Context, ref string) SMFUpdateResult {
		note("completed", ctx)
		return comp(ctx, ref)
	}

	h.run(t, h.required(1))
	h.smf.answer("hoack:"+ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoHandoverCmd, N2SmInfo: hoCmdTransfer(t, 1)}))
	// Each later leg arrives on a fresh ctx with no correlation ID, as on the SCTP read loop.
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1))
	h.srv.HandleHandoverNotifyForTest(context.Background(), h.tgt, &HandoverNotifyMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8})

	mu.Lock()
	defer mu.Unlock()
	id := ""
	for _, leg := range []string{"preparing", "reqack", "completed"} {
		ids := seen[leg]
		if len(ids) == 0 {
			t.Fatalf("%s hook not called", leg)
		}
		for _, got := range ids {
			if got == "" {
				t.Fatalf("%s leg has no correlation ID", leg)
			}
			if id == "" {
				id = got
			}
			if got != id {
				t.Fatalf("%s leg correlation_id = %q, want %q (shared)", leg, got, id)
			}
		}
	}
	for _, r := range h.sink.snapshot() {
		if cid, ok := r.attrs["correlation_id"]; ok && cid != id {
			t.Fatalf("log %q correlation_id = %v, want %q", r.msg, cid, id)
		}
	}
}
