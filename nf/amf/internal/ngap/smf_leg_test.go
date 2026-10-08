package ngap

// smf_leg_test.go — AMF-012: synchronous SMF leg of the Xn Path Switch and of the N2
// Handover Request Acknowledge. SMF hooks are deterministic fakes; waiting is done on
// channels with timeouts (never select/default polling).
// Ref: TS 23.502 §4.9.1.2.2 steps 2-7, §4.9.1.3.2 steps 9-12; TS 38.413 §8.4.4.2, §9.3.4

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

const smfTestWait = 3 * time.Second

// ---- transfers ---------------------------------------------------------------------

func gtpTunnel(teid byte) *ngapType.UPTransportLayerInformation {
	return &ngapType.UPTransportLayerInformation{
		Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
		GTPTunnel: &ngapType.GTPTunnel{
			TransportLayerAddress: ngapType.TransportLayerAddress{Value: aper.BitString{Bytes: []byte{10, 0, 0, teid}, BitLength: 32}},
			GTPTEID:               ngapType.GTPTEID{Value: aper.OctetString{0, 0, 0, teid}},
		},
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := aper.MarshalWithParams(v, "valueExt")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func ackTransfer(t *testing.T, teid byte) []byte {
	return mustMarshal(t, ngapType.PathSwitchRequestAcknowledgeTransfer{ULNGUUPTNLInformation: gtpTunnel(teid)})
}

func hoCmdTransfer(t *testing.T, teid byte) []byte {
	return mustMarshal(t, ngapType.HandoverCommandTransfer{DLForwardingUPTNLInformation: gtpTunnel(teid)})
}

func unsuccessfulTransfer(t *testing.T, cause int64) []byte {
	b, err := buildUnsuccessfulTransfer(ngapType.CausePresentRadioNetwork, cause)
	if err != nil {
		t.Fatalf("build unsuccessful transfer: %v", err)
	}
	return b
}

func prepUnsuccessfulTransfer(t *testing.T, cause int64) []byte {
	return mustMarshal(t, ngapType.HandoverPreparationUnsuccessfulTransfer{Cause: buildCause(ngapType.CausePresentRadioNetwork, cause)})
}

var garbage = []byte{0xff, 0xff, 0xff, 0xff}

func TestSMFTransferValidators(t *testing.T) {
	if !validPathSwitchAckTransfer(ackTransfer(t, 1)) || !validHandoverCommandTransfer(hoCmdTransfer(t, 1)) {
		t.Fatalf("valid transfers rejected")
	}
	if validPathSwitchAckTransfer(nil) || validHandoverCommandTransfer(nil) {
		t.Fatalf("empty bytes accepted")
	}
	if validPathSwitchAckTransfer(garbage) || validPathSwitchUnsuccessfulTransfer(garbage) ||
		validHandoverCommandTransfer(garbage) || validHandoverPrepUnsuccessfulTransfer(garbage) {
		t.Fatalf("garbage accepted as a valid transfer")
	}
}

// ---- fake SMF ----------------------------------------------------------------------

type smfCall struct {
	kind     string // "switch" | "setupfail" | "deactivate" | "hoack"
	ref      string
	transfer []byte
}

type fakeSMF struct {
	mu    sync.Mutex
	calls []smfCall
	got   chan smfCall // every call, buffered
	// per-PSI answers keyed by SM context ref ("smctx-N"), per kind.
	answers map[string]func(ctx context.Context, transfer []byte) SMFUpdateResult
	deact   func(ref string) error
}

func newFakeSMF() *fakeSMF {
	return &fakeSMF{got: make(chan smfCall, 64), answers: map[string]func(context.Context, []byte) SMFUpdateResult{}}
}

func (f *fakeSMF) record(c smfCall) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	f.got <- c
}

func (f *fakeSMF) callsOf(kind string) []smfCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []smfCall
	for _, c := range f.calls {
		if c.kind == kind {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeSMF) hook(kind string) SMFTransferHook {
	return func(ctx context.Context, ref string, tr []byte) SMFUpdateResult {
		f.record(smfCall{kind, ref, append([]byte(nil), tr...)})
		key := kind + ":" + ref
		f.mu.Lock()
		fn, ok := f.answers[key]
		if !ok {
			fn, ok = f.answers[ref]
		}
		f.mu.Unlock()
		if !ok {
			return SMFUpdateResult{HTTPStatus: 200}
		}
		return fn(ctx, tr)
	}
}

func (f *fakeSMF) answer(ref string, fn func(ctx context.Context, tr []byte) SMFUpdateResult) {
	f.mu.Lock()
	f.answers[ref] = fn
	f.mu.Unlock()
}

func fixed(r SMFUpdateResult) func(context.Context, []byte) SMFUpdateResult {
	return func(context.Context, []byte) SMFUpdateResult { return r }
}

// expect waits for n calls on the recording channel.
func (f *fakeSMF) expect(t *testing.T, n int) []smfCall {
	t.Helper()
	var out []smfCall
	for i := 0; i < n; i++ {
		select {
		case c := <-f.got:
			out = append(out, c)
		case <-time.After(smfTestWait):
			t.Fatalf("timed out waiting for SMF call %d/%d", i+1, n)
		}
	}
	return out
}

type smfHarness struct {
	*xnHarness
	smf *fakeSMF
}

// newSMFHarness: UE with PDU sessions 1, 2, 3 (refs "smctx-N"), all hooks wired to a fake SMF.
func newSMFHarness(t *testing.T) *smfHarness {
	t.Helper()
	h := &smfHarness{xnHarness: newXnHarness(t), smf: newFakeSMF()}
	h.ue.PDUSessions = map[uint8]*amfctx.PDUSession{}
	for _, id := range []uint8{1, 2, 3} {
		h.ue.PDUSessions[id] = &amfctx.PDUSession{PDUSessionID: id, SMFInstanceID: "smctx-" + string(rune('0'+id)),
			SNSSAI: amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}, N2SmTransfer: []byte{1, 2, 3}}
	}
	h.srv.onPathSwitchPDUSession = h.smf.hook("switch")
	h.srv.onPathSwitchSetupFail = h.smf.hook("setupfail")
	h.srv.onHandoverReqAck = h.smf.hook("hoack")
	h.srv.onUPDeactivate = func(_ context.Context, ref string) error {
		h.smf.record(smfCall{kind: "deactivate", ref: ref})
		if h.smf.deact != nil {
			return h.smf.deact(ref)
		}
		return nil
	}
	h.srv.SetSMFHOUpdateTimeoutForTest(300 * time.Millisecond)
	return h
}

func ref(psi uint8) string { return "smctx-" + string(rune('0'+psi)) }

func (h *smfHarness) ackItems(t *testing.T, raw []byte) (switched, released map[int64][]byte, ids []int64) {
	t.Helper()
	ack, ies := ackIEs(t, raw)
	switched, released = map[int64][]byte{}, map[int64][]byte{}
	for _, ie := range ack.ProtocolIEs.List {
		if ie.Value.PDUSessionResourceSwitchedList != nil {
			for _, it := range ie.Value.PDUSessionResourceSwitchedList.List {
				switched[it.PDUSessionID.Value] = []byte(it.PathSwitchRequestAcknowledgeTransfer)
			}
		}
		if ie.Value.PDUSessionResourceReleasedListPSAck != nil {
			for _, it := range ie.Value.PDUSessionResourceReleasedListPSAck.List {
				released[it.PDUSessionID.Value] = []byte(it.PathSwitchRequestUnsuccessfulTransfer)
			}
		}
	}
	return switched, released, idsOf(ies)
}

func causeOf(t *testing.T, b []byte) ngapType.Cause {
	t.Helper()
	var tr ngapType.PathSwitchRequestUnsuccessfulTransfer
	if err := aper.UnmarshalWithParams(b, &tr, "valueExt"); err != nil {
		t.Fatalf("decode unsuccessful transfer: %v", err)
	}
	return tr.Cause
}

func wantRadioCause(t *testing.T, c ngapType.Cause, want aper.Enumerated) {
	t.Helper()
	if c.Present != ngapType.CausePresentRadioNetwork || c.RadioNetwork.Value != want {
		t.Fatalf("cause = %+v, want radioNetwork %d", c, want)
	}
}

var emptyAckTransfer = func() []byte {
	b, _ := aper.MarshalWithParams(ngapType.PathSwitchRequestAcknowledgeTransfer{}, "valueExt")
	return b
}()

// ---- Xn: AC1 -----------------------------------------------------------------------

func TestXnSMFLeg_AckCarriesSMFTransfers_AndWaitsForEveryAnswer(t *testing.T) {
	h := newSMFHarness(t)
	t1, t2 := ackTransfer(t, 1), ackTransfer(t, 2)
	h.smf.answer(ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPathSwitchReqAck, N2SmInfo: t1}))
	release := make(chan struct{})
	h.smf.answer(ref(2), func(context.Context, []byte) SMFUpdateResult {
		<-release
		return SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPathSwitchReqAck, N2SmInfo: t2}
	})
	h.srv.SetSMFHOUpdateTimeoutForTest(smfTestWait * 2)

	// The handler call itself returns without waiting for the SMF.
	h.srv.StartPathSwitchRequestForTest(context.Background(), h.tgt, h.pathSwitch(7, 1, 2))
	calls := h.smf.expect(t, 2) // both requests in flight, PSI 2 still unanswered
	if n := len(h.tgtLn.pdus()); n != 0 {
		t.Fatalf("%d NGAP PDUs written to the target before the SMF answered", n)
	}
	for _, c := range calls {
		if !bytes.Equal(c.transfer, []byte{0xAB}) {
			t.Fatalf("PATH_SWITCH_REQ n2SmInfo = %x, want the relayed PathSwitchRequestTransfer", c.transfer)
		}
	}
	close(release)
	if !h.srv.WaitUESerialForTest(h.amfID) {
		t.Fatalf("serial queue did not drain")
	}
	sent := h.tgtLn.pdus()
	if len(sent) != 1 || sent[0].ppid != 60 {
		t.Fatalf("target got %d PDUs", len(sent))
	}
	sw, rel, ids := h.ackItems(t, sent[0].raw)
	if want := []int64{10, 85, 93, 77, 0}; !equalIDs(ids, want) {
		t.Fatalf("IE order = %v, want %v", ids, want)
	}
	if !bytes.Equal(sw[1], t1) || !bytes.Equal(sw[2], t2) || len(rel) != 0 {
		t.Fatalf("Switched transfers are not the SMF bytes")
	}
	if ncc, _ := h.nccNow(); ncc != 2 {
		t.Fatalf("ncc = %d, want 2", ncc)
	}
	if h.ue.RANUENGAPId != 7 {
		t.Fatalf("UE not re-bound")
	}
}

func (h *smfHarness) nccNow() (uint8, bool) {
	_, ncc, valid := h.ue.NHState()
	return ncc, valid
}

func TestXnSMFLeg_RejectedPSIsGoToReleasedListPSAck(t *testing.T) {
	failBytes := unsuccessfulTransfer(t, int64(ngapType.CauseRadioNetworkPresentUnspecified))
	tests := []struct {
		name      string
		answer    func(context.Context, []byte) SMFUpdateResult
		wantCause aper.Enumerated
		wantBytes []byte // verbatim SMF bytes expected
	}{
		{"404", fixed(SMFUpdateResult{HTTPStatus: 404, Cause: "CONTEXT_NOT_FOUND"}), ngapType.CauseRadioNetworkPresentUnknownPDUSessionID, nil},
		{"500", fixed(SMFUpdateResult{HTTPStatus: 500}), ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"transport error", fixed(SMFUpdateResult{Err: errors.New("connection refused")}), ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"never answers (timeout)", func(ctx context.Context, _ []byte) SMFUpdateResult {
			<-ctx.Done()
			return SMFUpdateResult{Err: ctx.Err()}
		},
			ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"REQ_FAIL bytes verbatim", fixed(SMFUpdateResult{HTTPStatus: 500, N2SmInfoType: n2InfoPathSwitchReqFail, N2SmInfo: failBytes}),
			ngapType.CauseRadioNetworkPresentUnspecified, failBytes},
		{"2xx REQ_FAIL bytes verbatim", fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPathSwitchReqFail, N2SmInfo: failBytes}),
			ngapType.CauseRadioNetworkPresentUnspecified, failBytes},
		{"2xx REQ_FAIL undecodable -> AMF cause", fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPathSwitchReqFail, N2SmInfo: garbage}),
			ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"2xx REQ_FAIL no bytes -> AMF cause", fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPathSwitchReqFail}),
			ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"REQ_FAIL undecodable ignored", fixed(SMFUpdateResult{HTTPStatus: 500, N2SmInfoType: n2InfoPathSwitchReqFail, N2SmInfo: garbage}),
			ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newSMFHarness(t)
			good := ackTransfer(t, 1)
			h.smf.answer(ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPathSwitchReqAck, N2SmInfo: good}))
			h.smf.answer(ref(2), tc.answer)
			h.run(h.pathSwitch(7, 1, 2))
			sent := h.tgtLn.pdus()
			if len(sent) != 1 {
				t.Fatalf("target got %d PDUs", len(sent))
			}
			sw, rel, ids := h.ackItems(t, sent[0].raw)
			if want := []int64{10, 85, 93, 77, 68, 0}; !equalIDs(ids, want) {
				t.Fatalf("IE order = %v, want %v", ids, want)
			}
			if len(sw) != 1 || !bytes.Equal(sw[1], good) {
				t.Fatalf("switched = %v", sw)
			}
			wantRadioCause(t, causeOf(t, rel[2]), tc.wantCause)
			if tc.wantBytes != nil && !bytes.Equal(rel[2], tc.wantBytes) {
				t.Fatalf("released transfer not the SMF bytes verbatim")
			}
			if bytes.Contains(sent[0].raw, garbage) {
				t.Fatalf("undecodable bytes forwarded")
			}
			if h.ue.RANUENGAPId != 7 {
				t.Fatalf("UE not re-bound after a partial success")
			}
		})
	}
}

func TestXnSMFLeg_AllRejected_FailureNoRebindNoNCCNoDeactivate(t *testing.T) {
	h := newSMFHarness(t)
	h.smf.answer(ref(1), fixed(SMFUpdateResult{HTTPStatus: 404}))
	h.smf.answer(ref(2), fixed(SMFUpdateResult{HTTPStatus: 500}))
	nccBefore, _ := h.nccNow()
	h.run(h.pathSwitch(7, 1, 2, 11)) // 11 unknown to the AMF
	sent := h.tgtLn.pdus()
	if len(sent) != 1 {
		t.Fatalf("target got %d PDUs", len(sent))
	}
	_, _, items := failureItems(t, sent[0].raw)
	wantRadioCause(t, items[1], ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)
	wantRadioCause(t, items[2], ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)
	wantRadioCause(t, items[11], ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)
	if ncc, _ := h.nccNow(); ncc != nccBefore {
		t.Fatalf("NCC advanced on FAILURE (%d -> %d)", nccBefore, ncc)
	}
	if h.ue.RANUENGAPId != 1 || h.tgt.UEs[7] != nil {
		t.Fatalf("UE re-bound on FAILURE")
	}
	if len(h.smf.callsOf("deactivate")) != 0 {
		t.Fatalf("DEACTIVATED sent on FAILURE")
	}
	r, ok := h.logs.find("PathSwitchRequestFailure")
	if !ok {
		t.Fatalf("failure not logged")
	}
	if v, _ := recAttr(r, "cause"); v != "smf-rejected-all" {
		t.Fatalf("cause = %v", v)
	}
	if v, _ := recAttr(r, "result"); v != "REJECT" {
		t.Fatalf("result = %v", v)
	}
}

func TestXnSMFLeg_TimeoutLogged(t *testing.T) {
	h := newSMFHarness(t)
	h.srv.SetSMFHOUpdateTimeoutForTest(50 * time.Millisecond)
	h.smf.answer(ref(1), func(ctx context.Context, _ []byte) SMFUpdateResult {
		<-ctx.Done()
		return SMFUpdateResult{Err: ctx.Err()}
	})
	h.run(h.pathSwitch(7, 1))
	if _, _, items := failureItems(t, h.tgtLn.pdus()[0].raw); len(items) != 1 {
		t.Fatalf("items = %v", items)
	}
	found := false
	h.logs.mu.Lock()
	for _, r := range h.logs.recs {
		if v, _ := recAttr(r, "cause"); v == "smf-timeout" && r.Level == slog.LevelError {
			found = true
		}
	}
	h.logs.mu.Unlock()
	if !found {
		t.Fatalf("no ERROR log with cause smf-timeout")
	}
}

// A hook that ignores ctx must not hold the handover beyond the bound.
func TestXnSMFLeg_HookIgnoringContextIsBounded(t *testing.T) {
	h := newSMFHarness(t)
	h.srv.SetSMFHOUpdateTimeoutForTest(50 * time.Millisecond)
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	h.smf.answer(ref(1), func(context.Context, []byte) SMFUpdateResult { <-block; return SMFUpdateResult{HTTPStatus: 200} })
	h.run(h.pathSwitch(7, 1))
	failureItems(t, h.tgtLn.pdus()[0].raw)
}

// ---- Xn: AC2 failed-to-setup + not listed ------------------------------------------

func (h *smfHarness) withFailed(req *PathSwitchRequestMsg, psi uint8, tr []byte) *PathSwitchRequestMsg {
	req.FailedToSetup = append(req.FailedToSetup, PDUSessionFailedSetupItem{PDUSessionID: psi, PathSwitchRequestSetupFailedTransfer: tr})
	return req
}

func TestXnSMFLeg_FailedToSetupForwarded_AckUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		ans  func(context.Context, []byte) SMFUpdateResult
	}{
		{"200", fixed(SMFUpdateResult{HTTPStatus: 200})},
		{"422", fixed(SMFUpdateResult{HTTPStatus: 422})},
		{"500", fixed(SMFUpdateResult{HTTPStatus: 500})},
		{"timeout", func(ctx context.Context, _ []byte) SMFUpdateResult {
			<-ctx.Done()
			return SMFUpdateResult{Err: ctx.Err()}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSMFHarness(t)
			h.smf.answer("setupfail:"+ref(2), tc.ans)
			h.run(h.withFailed(h.pathSwitch(7, 1), 2, []byte{0xCD}))
			fc := h.smf.callsOf("setupfail")
			if len(fc) != 1 || fc[0].ref != ref(2) || !bytes.Equal(fc[0].transfer, []byte{0xCD}) {
				t.Fatalf("setupfail calls = %+v", fc)
			}
			sw, rel, ids := h.ackItems(t, h.tgtLn.pdus()[0].raw)
			if want := []int64{10, 85, 93, 77, 0}; !equalIDs(ids, want) {
				t.Fatalf("IE order = %v", ids)
			}
			if _, in := sw[2]; in || len(sw) != 1 || len(rel) != 0 {
				t.Fatalf("failed PSI leaked into the Ack: sw=%v rel=%v", sw, rel)
			}
			if tc.name != "200" {
				found := false
				h.logs.mu.Lock()
				for _, r := range h.logs.recs {
					if r.Level == slog.LevelWarn && r.Message != "" && containsFold(r.Message, "PATH_SWITCH_SETUP_FAIL") {
						found = true
					}
				}
				h.logs.mu.Unlock()
				if !found {
					t.Fatalf("setup-fail failure not logged at WARN")
				}
			}
		})
	}
}

func containsFold(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

func TestXnSMFLeg_FailedToSetup_UnknownAndDuplicate(t *testing.T) {
	t.Run("unknown PSI: no SMF call, WARN", func(t *testing.T) {
		h := newSMFHarness(t)
		h.run(h.withFailed(h.pathSwitch(7, 1), 11, []byte{1}))
		if n := len(h.smf.callsOf("setupfail")); n != 0 {
			t.Fatalf("setupfail calls = %d", n)
		}
		r, ok := h.logs.find("Failed-to-Setup PDU session not found")
		if !ok || r.Level != slog.LevelWarn {
			t.Fatalf("WARN missing")
		}
		if v, _ := recAttr(r, "pdu_session_id"); fmt.Sprint(v) != "11" {
			t.Fatalf("pdu_session_id = %v", v)
		}
		ackIEs(t, h.tgtLn.pdus()[0].raw)
	})
	t.Run("PSI in both lists: FAILURE multiple-PDU-session-ID-instances, no SMF call", func(t *testing.T) {
		h := newSMFHarness(t)
		h.run(h.withFailed(h.pathSwitch(7, 1, 2), 2, []byte{1}))
		_, _, items := failureItems(t, h.tgtLn.pdus()[0].raw)
		wantRadioCause(t, items[2], ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)
		if c := items[1]; c.Present != ngapType.CausePresentMisc || c.Misc.Value != ngapType.CauseMiscPresentUnspecified {
			t.Fatalf("PSI 1 cause = %+v", c)
		}
		h.smf.mu.Lock()
		n := len(h.smf.calls)
		h.smf.mu.Unlock()
		if n != 0 || h.ue.RANUENGAPId != 1 {
			t.Fatalf("SMF calls=%d rebound=%v", n, h.ue.RANUENGAPId != 1)
		}
	})
}

func TestXnSMFLeg_NotListedSessionsDeactivatedAfterAck(t *testing.T) {
	h := newSMFHarness(t)
	h.run(h.withFailed(h.pathSwitch(7, 1), 2, []byte{1})) // PSI 3 is in neither list
	got := h.smf.callsOf("deactivate")
	deadline := time.After(smfTestWait)
	for len(got) < 1 {
		select {
		case <-h.smf.got:
		case <-deadline:
			t.Fatalf("no DEACTIVATED call")
		}
		got = h.smf.callsOf("deactivate")
	}
	if len(got) != 1 || got[0].ref != ref(3) || got[0].transfer != nil {
		t.Fatalf("deactivate calls = %+v", got)
	}
	// Never deleted: all three sessions stay in the UE context.
	h.ue.Lock()
	n := len(h.ue.PDUSessions)
	h.ue.Unlock()
	if n != 3 {
		t.Fatalf("UE holds %d PDU sessions, want 3", n)
	}
	// The DEACTIVATED request left only after the Ack was written.
	if len(h.tgtLn.pdus()) != 1 {
		t.Fatalf("ack missing")
	}
}

func TestXnSMFLeg_DeactivateFailureDoesNotAffectAck(t *testing.T) {
	h := newSMFHarness(t)
	h.smf.deact = func(string) error { return errors.New("status 500") }
	h.run(h.pathSwitch(7, 1))
	h.smf.expect(t, 1+2) // switch + two DEACTIVATED (PSI 2, 3)
	ackIEs(t, h.tgtLn.pdus()[0].raw)
	if h.ue.RANUENGAPId != 7 || len(h.ue.PDUSessions) != 3 {
		t.Fatalf("UE state affected by the DEACTIVATED failure")
	}
	deadline := time.After(smfTestWait)
	for {
		if r, ok := h.logs.find("UP deactivation of PDU session failed"); ok {
			if r.Level != slog.LevelWarn {
				t.Fatalf("level = %v", r.Level)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatalf("DEACTIVATED failure not logged")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// ---- Xn: compatibility fallbacks ---------------------------------------------------

func TestXnSMFLeg_FallbackEmptyTransfer(t *testing.T) {
	tests := []struct {
		name  string
		res   SMFUpdateResult
		level slog.Level
	}{
		{"200 empty body", SMFUpdateResult{HTTPStatus: 200}, slog.LevelWarn},
		{"204", SMFUpdateResult{HTTPStatus: 204}, slog.LevelWarn},
		{"undecodable bytes", SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPathSwitchReqAck, N2SmInfo: garbage}, slog.LevelError},
		{"wrong type", SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoHandoverCmd, N2SmInfo: hoCmdTransfer(t, 1)}, slog.LevelError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newSMFHarness(t)
			h.smf.answer(ref(1), fixed(tc.res))
			h.run(h.pathSwitch(7, 1))
			sent := h.tgtLn.pdus()
			sw, _, _ := h.ackItems(t, sent[0].raw)
			if !bytes.Equal(sw[1], emptyAckTransfer) {
				t.Fatalf("transfer = %x, want the empty encoded transfer", sw[1])
			}
			if bytes.Contains(sent[0].raw, garbage) {
				t.Fatalf("undecodable bytes forwarded")
			}
			if h.ue.RANUENGAPId != 7 {
				t.Fatalf("UE not re-bound")
			}
			found := false
			h.logs.mu.Lock()
			for _, r := range h.logs.recs {
				if r.Level == tc.level && containsFold(r.Message, "empty PathSwitchRequestAcknowledgeTransfer") {
					found = true
				}
			}
			h.logs.mu.Unlock()
			if !found {
				t.Fatalf("fallback not logged at %v", tc.level)
			}
		})
	}
}

func TestXnSMFLeg_NilHooks_TodaysBehaviour(t *testing.T) {
	h := newSMFHarness(t)
	h.srv.onPathSwitchPDUSession, h.srv.onPathSwitchSetupFail, h.srv.onUPDeactivate = nil, nil, nil
	h.run(h.withFailed(h.pathSwitch(7, 1), 2, []byte{1}))
	sw, _, _ := h.ackItems(t, h.tgtLn.pdus()[0].raw)
	if !bytes.Equal(sw[1], emptyAckTransfer) {
		t.Fatalf("not the empty transfer")
	}
	r, ok := h.logs.find("no SMF hook configured")
	if !ok || r.Level != slog.LevelWarn {
		t.Fatalf("WARN about missing SMF hook not logged")
	}
}

// While UE A's SMF call is pending, the handler call returned and another UE's serial
// queue still runs (the SCTP read loop is not blocked).
func TestXnSMFLeg_PendingSMFCallDoesNotBlockOtherUEs(t *testing.T) {
	h := newSMFHarness(t)
	block := make(chan struct{})
	h.smf.answer(ref(1), func(context.Context, []byte) SMFUpdateResult { <-block; return SMFUpdateResult{HTTPStatus: 200} })
	h.srv.SetSMFHOUpdateTimeoutForTest(smfTestWait * 2)
	h.srv.StartPathSwitchRequestForTest(context.Background(), h.tgt, h.pathSwitch(7, 1))
	h.smf.expect(t, 1)

	other := h.srv.mgr.AllocateUEContext(2)
	ran := make(chan struct{})
	other.EnqueueSerial(func() { close(ran) })
	select {
	case <-ran:
	case <-time.After(smfTestWait):
		t.Fatalf("another UE's serial task blocked behind the pending SMF call")
	}
	if n := len(h.tgtLn.pdus()); n != 0 {
		t.Fatalf("ack written while the SMF call is pending")
	}
	close(block)
	h.srv.WaitUESerialForTest(h.amfID)
	ackIEs(t, h.tgtLn.pdus()[0].raw)
}

func TestXnSMFLeg_PreCheckRejectsBeforeAnySMFCall(t *testing.T) {
	h := newSMFHarness(t)
	h.ue.Lock()
	h.ue.NHValid = false
	h.ue.Unlock()
	h.run(h.pathSwitch(7, 1))
	_, _, items := failureItems(t, h.tgtLn.pdus()[0].raw)
	if c := items[1]; c.Present != ngapType.CausePresentMisc || c.Misc.Value != ngapType.CauseMiscPresentUnspecified {
		t.Fatalf("cause = %+v", c)
	}
	h.smf.mu.Lock()
	n := len(h.smf.calls)
	h.smf.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d SMF calls before the pre-check rejected the request", n)
	}
}

// ---- N2 handover: AC3 --------------------------------------------------------------

func (h *smfHarness) startN2(t *testing.T) {
	t.Helper()
	h.srv.HandleHandoverRequiredForTest(context.Background(), h.src, &HandoverRequiredMsg{
		AMFUENGAPId: h.amfID, RANUENGAPId: 1, TargetGlobalRANNodeID: h.tgt.GlobalGNBID,
		SourceToTargetTransparentContainer: []byte{9},
	})
	if len(h.tgtLn.pdus()) != 1 {
		t.Fatalf("HandoverRequest not sent")
	}
	h.tgtLn.mu.Lock()
	h.tgtLn.sent = nil
	h.tgtLn.mu.Unlock()
}

func (h *smfHarness) admit(psis ...uint8) *HandoverRequestAckMsg {
	a := &HandoverRequestAckMsg{AMFUENGAPId: h.amfID, RANUENGAPId: 8, TargetToSourceTransparentContainer: []byte{7}}
	for _, p := range psis {
		a.AdmittedSessions = append(a.AdmittedSessions, PDUSessionHOAdmittedItem{PDUSessionID: p, HandoverRequestAcknowledgeTransfer: []byte{0xE0 + p}})
	}
	return a
}

type hoCmd struct {
	ids      []int64
	handover map[int64][]byte
	release  map[int64][]byte
}

func decodeHandoverCommand(t *testing.T, raw []byte) hoCmd {
	t.Helper()
	pdu, err := libngap.Decoder(raw)
	if err != nil || pdu.SuccessfulOutcome == nil || pdu.SuccessfulOutcome.Value.HandoverCommand == nil {
		t.Fatalf("not a HandoverCommand (err=%v)", err)
	}
	out := hoCmd{handover: map[int64][]byte{}, release: map[int64][]byte{}}
	for _, ie := range pdu.SuccessfulOutcome.Value.HandoverCommand.ProtocolIEs.List {
		out.ids = append(out.ids, ie.Id.Value)
		if l := ie.Value.PDUSessionResourceHandoverList; l != nil {
			for _, it := range l.List {
				out.handover[it.PDUSessionID.Value] = []byte(it.HandoverCommandTransfer)
			}
		}
		if l := ie.Value.PDUSessionResourceToReleaseListHOCmd; l != nil {
			for _, it := range l.List {
				out.release[it.PDUSessionID.Value] = []byte(it.HandoverPreparationUnsuccessfulTransfer)
			}
		}
	}
	return out
}

func prepCause(t *testing.T, b []byte) ngapType.Cause {
	t.Helper()
	var tr ngapType.HandoverPreparationUnsuccessfulTransfer
	if err := aper.UnmarshalWithParams(b, &tr, "valueExt"); err != nil {
		t.Fatalf("decode HandoverPreparationUnsuccessfulTransfer: %v", err)
	}
	return tr.Cause
}

var emptyHOCmdTransfer = func() []byte {
	b, _ := aper.MarshalWithParams(ngapType.HandoverCommandTransfer{}, "valueExt")
	return b
}()

func TestN2SMFLeg_HandoverCommandCarriesSMFTransfers(t *testing.T) {
	h := newSMFHarness(t)
	h.startN2(t)
	c1, c2 := hoCmdTransfer(t, 1), hoCmdTransfer(t, 2)
	h.smf.answer(ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, HoState: "PREPARED", N2SmInfoType: n2InfoHandoverCmd, N2SmInfo: c1}))
	h.smf.answer(ref(2), fixed(SMFUpdateResult{HTTPStatus: 200, HoState: "PREPARED", N2SmInfoType: n2InfoHandoverCmd, N2SmInfo: c2}))
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1, 2))

	calls := h.smf.callsOf("hoack")
	if len(calls) != 2 {
		t.Fatalf("hoack calls = %d", len(calls))
	}
	for _, c := range calls {
		want := []byte{0xE1}
		if c.ref == ref(2) {
			want = []byte{0xE2}
		}
		if !bytes.Equal(c.transfer, want) {
			t.Fatalf("HANDOVER_REQ_ACK n2SmInfo for %s = %x, want the target's transfer %x", c.ref, c.transfer, want)
		}
	}
	srcSent := h.srcLn.pdus()
	if len(srcSent) != 1 || srcSent[0].ppid != 60 {
		t.Fatalf("source got %d PDUs", len(srcSent))
	}
	cmd := decodeHandoverCommand(t, srcSent[0].raw)
	if !equalIDs(cmd.ids, []int64{10, 85, 29, 59, 106}) {
		t.Fatalf("IE order = %v", cmd.ids)
	}
	if !bytes.Equal(cmd.handover[1], c1) || !bytes.Equal(cmd.handover[2], c2) {
		t.Fatalf("IE 59 items are not the SMF HandoverCommandTransfer bytes")
	}
	if h.tgt.UEs[8] != h.ue {
		t.Fatalf("UE not registered on the target gNB")
	}
	st := h.srv.pendingN2HO[h.amfID]
	if st == nil || len(st.admittedSessions) != 2 {
		t.Fatalf("accepted set not stored")
	}
}

func TestN2SMFLeg_FallbackEmptyHandoverCommandTransfer(t *testing.T) {
	tests := []struct {
		name  string
		res   SMFUpdateResult
		level slog.Level
	}{
		{"no n2SmInfo", SMFUpdateResult{HTTPStatus: 200, HoState: "PREPARED"}, slog.LevelWarn},
		{"undecodable", SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoHandoverCmd, N2SmInfo: garbage}, slog.LevelError},
		{"wrong type", SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoPathSwitchReqAck, N2SmInfo: ackTransfer(t, 1)}, slog.LevelError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newSMFHarness(t)
			h.startN2(t)
			h.smf.answer(ref(1), fixed(tc.res))
			h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1))
			raw := h.srcLn.pdus()[0].raw
			cmd := decodeHandoverCommand(t, raw)
			if !bytes.Equal(cmd.handover[1], emptyHOCmdTransfer) {
				t.Fatalf("transfer = %x, want the empty HandoverCommandTransfer", cmd.handover[1])
			}
			if bytes.Contains(raw, garbage) {
				t.Fatalf("undecodable bytes forwarded")
			}
			found := false
			h.logs.mu.Lock()
			for _, r := range h.logs.recs {
				if r.Level == tc.level && containsFold(r.Message, "empty HandoverCommandTransfer") {
					found = true
				}
			}
			h.logs.mu.Unlock()
			if !found {
				t.Fatalf("fallback not logged at %v", tc.level)
			}
		})
	}
}

func TestN2SMFLeg_PartialFailure_ToReleaseListHOCmd(t *testing.T) {
	prep := prepUnsuccessfulTransfer(t, int64(ngapType.CauseRadioNetworkPresentUnspecified))
	tests := []struct {
		name      string
		answer    func(context.Context, []byte) SMFUpdateResult
		wantCause aper.Enumerated
		verbatim  []byte
	}{
		{"404", fixed(SMFUpdateResult{HTTPStatus: 404}), ngapType.CauseRadioNetworkPresentUnknownPDUSessionID, nil},
		{"500", fixed(SMFUpdateResult{HTTPStatus: 500}), ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"timeout", func(ctx context.Context, _ []byte) SMFUpdateResult {
			<-ctx.Done()
			return SMFUpdateResult{Err: ctx.Err()}
		},
			ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"2xx HANDOVER_PREP_FAIL verbatim", fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoHandoverPrepFail, N2SmInfo: prep}),
			ngapType.CauseRadioNetworkPresentUnspecified, prep},
		{"2xx hoState CANCELLED -> AMF cause", fixed(SMFUpdateResult{HTTPStatus: 200, HoState: hoStateCancelled}),
			ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem, nil},
		{"HANDOVER_PREP_FAIL verbatim", fixed(SMFUpdateResult{HTTPStatus: 500, N2SmInfoType: n2InfoHandoverPrepFail, N2SmInfo: prep}),
			ngapType.CauseRadioNetworkPresentUnspecified, prep},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newSMFHarness(t)
			h.startN2(t)
			h.smf.answer(ref(1), fixed(SMFUpdateResult{HTTPStatus: 200, N2SmInfoType: n2InfoHandoverCmd, N2SmInfo: hoCmdTransfer(t, 1)}))
			h.smf.answer(ref(2), tc.answer)
			h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1, 2))
			cmd := decodeHandoverCommand(t, h.srcLn.pdus()[0].raw)
			if !equalIDs(cmd.ids, []int64{10, 85, 29, 59, 78, 106}) {
				t.Fatalf("IE order = %v", cmd.ids)
			}
			if len(cmd.handover) != 1 || len(cmd.release) != 1 {
				t.Fatalf("handover=%d release=%d", len(cmd.handover), len(cmd.release))
			}
			wantRadioCause(t, prepCause(t, cmd.release[2]), tc.wantCause)
			if tc.verbatim != nil && !bytes.Equal(cmd.release[2], tc.verbatim) {
				t.Fatalf("not the SMF bytes verbatim")
			}
			st := h.srv.pendingN2HO[h.amfID]
			if st == nil || len(st.admittedSessions) != 1 || st.admittedSessions[0].PDUSessionID != 1 {
				t.Fatalf("stored accepted set wrong")
			}
		})
	}
}

func TestN2SMFLeg_UnknownAdmittedPSI_NoSMFCall(t *testing.T) {
	h := newSMFHarness(t)
	h.startN2(t)
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1, 11))
	cmd := decodeHandoverCommand(t, h.srcLn.pdus()[0].raw)
	wantRadioCause(t, prepCause(t, cmd.release[11]), ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)
	for _, c := range h.smf.callsOf("hoack") {
		if c.ref != ref(1) {
			t.Fatalf("SMF called for the unknown PSI: %+v", c)
		}
	}
}

func TestN2SMFLeg_AllFail_PreparationFailure(t *testing.T) {
	for _, name := range []string{"500", "timeout"} {
		t.Run(name, func(t *testing.T) {
			h := newSMFHarness(t)
			h.startN2(t)
			for _, p := range []uint8{1, 2} {
				if name == "500" {
					h.smf.answer(ref(p), fixed(SMFUpdateResult{HTTPStatus: 500}))
				} else {
					h.smf.answer(ref(p), func(ctx context.Context, _ []byte) SMFUpdateResult {
						<-ctx.Done()
						return SMFUpdateResult{Err: ctx.Err()}
					})
				}
			}
			h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1, 2))
			srcSent := h.srcLn.pdus()
			if len(srcSent) != 1 || srcSent[0].ppid != 60 {
				t.Fatalf("source got %d PDUs", len(srcSent))
			}
			pdu, err := libngap.Decoder(srcSent[0].raw)
			if err != nil || pdu.UnsuccessfulOutcome == nil || pdu.UnsuccessfulOutcome.Value.HandoverPreparationFailure == nil {
				t.Fatalf("not a HandoverPreparationFailure (err=%v)", err)
			}
			var cause *ngapType.Cause
			for _, ie := range pdu.UnsuccessfulOutcome.Value.HandoverPreparationFailure.ProtocolIEs.List {
				if ie.Value.Cause != nil {
					cause = ie.Value.Cause
				}
			}
			if cause == nil {
				t.Fatalf("no Cause IE")
			}
			wantRadioCause(t, *cause, ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)
			if h.srv.HasPendingN2HandoverForTest(h.amfID) {
				t.Fatalf("pending N2 handover not dropped")
			}
			if h.tgt.UEs[8] != nil {
				t.Fatalf("UE registered on the target gNB")
			}
			r, ok := h.logs.find("HandoverPreparationFailure")
			if !ok {
				t.Fatalf("failure not logged")
			}
			if v, _ := recAttr(r, "result"); v != "REJECT" {
				t.Fatalf("result = %v", v)
			}
		})
	}
}

func TestN2SMFLeg_NilHook_TodaysBehaviour(t *testing.T) {
	h := newSMFHarness(t)
	h.srv.onHandoverReqAck = nil
	h.startN2(t)
	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1, 2))
	cmd := decodeHandoverCommand(t, h.srcLn.pdus()[0].raw)
	if !equalIDs(cmd.ids, []int64{10, 85, 29, 59, 106}) || !bytes.Equal(cmd.handover[1], emptyHOCmdTransfer) {
		t.Fatalf("nil hook: ids=%v", cmd.ids)
	}
	if r, ok := h.logs.find("no SMF hook configured"); !ok || r.Level != slog.LevelWarn {
		t.Fatalf("WARN missing")
	}
}

func TestN2SMFLeg_PendingSMFCallDoesNotBlockOtherUEs(t *testing.T) {
	h := newSMFHarness(t)
	h.startN2(t)
	block := make(chan struct{})
	h.smf.answer(ref(1), func(context.Context, []byte) SMFUpdateResult { <-block; return SMFUpdateResult{HTTPStatus: 200} })
	h.srv.SetSMFHOUpdateTimeoutForTest(smfTestWait * 2)
	h.srv.StartHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, h.admit(1))
	h.smf.expect(t, 1)
	other := h.srv.mgr.AllocateUEContext(2)
	ran := make(chan struct{})
	other.EnqueueSerial(func() { close(ran) })
	select {
	case <-ran:
	case <-time.After(smfTestWait):
		t.Fatalf("another UE blocked behind the pending SMF call")
	}
	if len(h.srcLn.pdus()) != 0 {
		t.Fatalf("HANDOVER COMMAND written while the SMF call is pending")
	}
	close(block)
	h.srv.WaitUESerialForTest(h.amfID)
	decodeHandoverCommand(t, h.srcLn.pdus()[0].raw)
}

func TestBuildHandoverCommand_ToReleaseListOrderAndBytes(t *testing.T) {
	raw := BuildHandoverCommand(1, 2, 0,
		[]PDUSessionHOCmdItem{{PDUSessionID: 1}},
		[]PDUSessionHOReleaseItem{{PDUSessionID: 2, CausePresent: ngapType.CausePresentRadioNetwork,
			CauseValue: int64(ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)}},
		[]byte{7})
	cmd := decodeHandoverCommand(t, raw)
	if !equalIDs(cmd.ids, []int64{10, 85, 29, 59, 78, 106}) {
		t.Fatalf("IE order = %v", cmd.ids)
	}
	if !bytes.Equal(cmd.handover[1], emptyHOCmdTransfer) {
		t.Fatalf("empty transfer not encoded")
	}
	wantRadioCause(t, prepCause(t, cmd.release[2]), ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)
}
