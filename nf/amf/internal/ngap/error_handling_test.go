package ngap

// error_handling_test.go — NGAP error handling (TS 38.413 §10.2, §10.3.4.2, §10.3.5, §10.5,
// §10.6, §8.7.5). Design: docs/procedures/ngap-error-handling.md.

import (
	"context"
	"encoding/hex"
	"log/slog"
	"math/rand"
	"reflect"
	"sync"
	"testing"

	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
	"github.com/free5gc/aper"
)

// ehHarness is a Server with one fake-SCTP gNB, one UE (AMF UE NGAP ID 1 / RAN 101) and a
// recording NAS handler.
type ehHarness struct {
	srv  *Server
	gnb  *GNBContext
	mu   sync.Mutex
	out  [][]byte
	ppid []uint32
	nas  [][]byte
	gate chan struct{} // when non-nil the NAS handler blocks until it is closed
}

func (h *ehHarness) HandleNASMessage(_ context.Context, _ *amfctx.UEContext, pdu []byte) error {
	if h.gate != nil {
		<-h.gate
	}
	h.mu.Lock()
	h.nas = append(h.nas, pdu)
	h.mu.Unlock()
	return nil
}

func newEHHarness(t *testing.T) *ehHarness {
	t.Helper()
	h := &ehHarness{}
	mgr := amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	ue := mgr.AllocateUEContext(101)
	if ue.AMFUENGAPId != 1 {
		t.Fatalf("test assumes first AMF UE NGAP ID 1, got %d", ue.AMFUENGAPId)
	}
	h.srv = NewServer("", mgr, h, AMFConfig{}, slog.Default())
	h.gnb = &GNBContext{UEs: map[int64]*amfctx.UEContext{}, IdleUEs: map[int64]*amfctx.UEContext{}}
	h.gnb.SetTransportForTest("10.0.0.1:38412", func(pdu []byte, info *sctp.SndRcvInfo) (int, error) {
		h.mu.Lock()
		h.out = append(h.out, append([]byte{}, pdu...))
		h.ppid = append(h.ppid, info.PPID)
		h.mu.Unlock()
		return len(pdu), nil
	})
	return h
}

func (h *ehHarness) dispatch(pdu []byte) {
	h.srv.DispatchNGAPForTest(context.Background(), h.gnb, pdu)
	h.srv.WaitUESerialForTest(1)
}

func (h *ehHarness) delivered() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.nas) }

func (h *ehHarness) errorIndications(t *testing.T) []ErrorIndicationView {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	var evs []ErrorIndicationView
	for i, b := range h.out {
		if h.ppid[i] != 60 {
			t.Errorf("outbound PDU %d sent with PPID %d, want 60", i, h.ppid[i])
		}
		v, ok, err := DecodeOutboundErrorIndicationForTest(b)
		if err != nil {
			t.Fatalf("decode outbound: %v", err)
		}
		if ok {
			evs = append(evs, v)
		}
	}
	return evs
}

func mustInject(t *testing.T, pdu []byte, id uint16, crit aper.Enumerated) []byte {
	t.Helper()
	out, err := InjectProtocolIEForTest(pdu, id, crit, []byte{0xAA, 0xBB})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestUnknownIEDecoderKeepsIDAndCriticality pins the decoder behaviour the scan relies on:
// an unknown IE id is decoded with Present == 0 and its Id and Criticality kept.
func TestUnknownIEDecoderKeepsIDAndCriticality(t *testing.T) {
	pdu := mustInject(t, buildULNAS(t, 1, 101, []byte{1}), 65000, ngapType.CriticalityPresentNotify)
	p, err := libngap.Decoder(pdu)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	ies, err := walkProtocolIEs(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ies) != 4 {
		t.Fatalf("want 4 IEs, got %d", len(ies))
	}
	last := ies[3]
	if last.id != 65000 || last.present != 0 || last.crit != ngapType.CriticalityPresentNotify {
		t.Fatalf("unknown IE = %+v", last)
	}
}

func TestUnknownIEReject(t *testing.T) {
	t.Run("class 2 initiating: ERROR INDICATION, message not processed", func(t *testing.T) {
		h := newEHHarness(t)
		h.dispatch(mustInject(t, buildULNAS(t, 1, 101, []byte{1}), 65000, ngapType.CriticalityPresentReject))
		evs := h.errorIndications(t)
		if len(evs) != 1 || len(h.out) != 1 {
			t.Fatalf("want exactly 1 ERROR INDICATION, got %d (%d PDUs)", len(evs), len(h.out))
		}
		ev := evs[0]
		if !ev.HasAMFUENGAPID || ev.AMFUENGAPID != 1 || !ev.HasRANUENGAPID || ev.RANUENGAPID != 101 {
			t.Errorf("IDs = %+v", ev)
		}
		if ev.CausePresent != ngapType.CausePresentProtocol || ev.CauseValue != int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorReject) {
			t.Errorf("cause = %d/%d", ev.CausePresent, ev.CauseValue)
		}
		if ev.CDProcedureCode != int64(ProcUplinkNASTransport) || ev.CDTriggeringMessage != 0 || ev.CDProcedureCriticality != int64(ngapType.CriticalityPresentIgnore) {
			t.Errorf("CD header = %+v", ev)
		}
		if len(ev.CDIEs) != 1 || ev.CDIEs[0] != (CDIEView{IECriticality: 0, IEID: 65000, TypeOfError: 0}) {
			t.Errorf("CD IEs = %+v", ev.CDIEs)
		}
		if h.delivered() != 0 {
			t.Error("NAS PDU delivered despite reject")
		}
	})
	t.Run("HANDOVER REQUIRED: HANDOVER PREPARATION FAILURE with CD, no EI", func(t *testing.T) {
		h := newEHHarness(t)
		h.dispatch(mustInject(t, buildHandoverRequiredPDU(t, 1, 101, true), 65000, ngapType.CriticalityPresentReject))
		if len(h.out) != 1 {
			t.Fatalf("want 1 outbound PDU, got %d", len(h.out))
		}
		p, err := libngap.Decoder(h.out[0])
		if err != nil {
			t.Fatal(err)
		}
		if p.Present != ngapType.NGAPPDUPresentUnsuccessfulOutcome ||
			p.UnsuccessfulOutcome.ProcedureCode.Value != ngapType.ProcedureCodeHandoverPreparation {
			t.Fatalf("not a HANDOVER PREPARATION FAILURE: %+v", p)
		}
		var cd *ngapType.CriticalityDiagnostics
		for _, ie := range p.UnsuccessfulOutcome.Value.HandoverPreparationFailure.ProtocolIEs.List {
			if ie.Value.CriticalityDiagnostics != nil {
				cd = ie.Value.CriticalityDiagnostics
			}
		}
		if cd == nil || cd.IEsCriticalityDiagnostics == nil || len(cd.IEsCriticalityDiagnostics.List) != 1 {
			t.Fatalf("missing CD: %+v", cd)
		}
		it := cd.IEsCriticalityDiagnostics.List[0]
		if it.IEID.Value != 65000 || it.IECriticality.Value != ngapType.CriticalityPresentReject || it.TypeOfError.Value != ngapType.TypeOfErrorPresentNotUnderstood {
			t.Errorf("CD item = %+v", it)
		}
		if cd.ProcedureCode != nil || cd.TriggeringMessage != nil {
			t.Error("Procedure Code / Triggering Message must not be in a failure message CD")
		}
	})
	t.Run("PATH SWITCH REQUEST: PATH SWITCH REQUEST FAILURE with CD", func(t *testing.T) {
		h := newEHHarness(t)
		h.dispatch(mustInject(t, buildPathSwitchRequestPDU(t, 1, 202, 5), 65000, ngapType.CriticalityPresentReject))
		if len(h.out) != 1 {
			t.Fatalf("want 1 outbound PDU, got %d", len(h.out))
		}
		p, err := libngap.Decoder(h.out[0])
		if err != nil {
			t.Fatal(err)
		}
		if p.Present != ngapType.NGAPPDUPresentUnsuccessfulOutcome ||
			p.UnsuccessfulOutcome.ProcedureCode.Value != ngapType.ProcedureCodePathSwitchRequest {
			t.Fatalf("not a PATH SWITCH REQUEST FAILURE: %+v", p)
		}
		found := false
		for _, ie := range p.UnsuccessfulOutcome.Value.PathSwitchRequestFailure.ProtocolIEs.List {
			if cd := ie.Value.CriticalityDiagnostics; cd != nil && len(cd.IEsCriticalityDiagnostics.List) == 1 &&
				cd.IEsCriticalityDiagnostics.List[0].IEID.Value == 65000 {
				found = true
			}
		}
		if !found {
			t.Error("Criticality Diagnostics with IE 65000 not found")
		}
	})
	t.Run("NG SETUP REQUEST: NG SETUP FAILURE with CD, gNB not NG_READY", func(t *testing.T) {
		h := newEHHarness(t)
		pdu := buildNGSetupRequestPDU(t, []byte{0x00, 0x00, 0x01, 0x00}, 32, "gnb")
		h.dispatch(mustInject(t, pdu, 65000, ngapType.CriticalityPresentReject))
		if len(h.out) != 1 || h.ppid[0] != 60 {
			t.Fatalf("want 1 PDU with PPID 60, got %d", len(h.out))
		}
		p, err := libngap.Decoder(h.out[0])
		if err != nil || p.Present != ngapType.NGAPPDUPresentUnsuccessfulOutcome ||
			p.UnsuccessfulOutcome.ProcedureCode.Value != ngapType.ProcedureCodeNGSetup {
			t.Fatalf("not an NG SETUP FAILURE: %v %+v", err, p)
		}
		l := p.UnsuccessfulOutcome.Value.NGSetupFailure.ProtocolIEs.List
		if len(l) != 2 || l[0].Id.Value != ngapType.ProtocolIEIDCause || l[1].Id.Value != ngapType.ProtocolIEIDCriticalityDiagnostics {
			t.Fatalf("IE order wrong: %+v", l)
		}
		_, c, _ := causeFromNGAP(*l[0].Value.Cause)
		if c != int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorReject) {
			t.Errorf("cause = %d", c)
		}
		cd := l[1].Value.CriticalityDiagnostics
		if cd.ProcedureCode != nil || cd.TriggeringMessage != nil || len(cd.IEsCriticalityDiagnostics.List) != 1 ||
			cd.IEsCriticalityDiagnostics.List[0].IEID.Value != 65000 {
			t.Errorf("CD = %+v", cd)
		}
		if h.gnb.State == GNBStateNGReady {
			t.Error("gNB must not be NG_READY")
		}
	})
	t.Run("response message: local handling only", func(t *testing.T) {
		h := newEHHarness(t)
		h.dispatch(mustInject(t, buildSyntheticPDUSessionReleaseResponse(t, 1, 101), 65000, ngapType.CriticalityPresentReject))
		if len(h.out) != 0 {
			t.Fatalf("unexpected outbound PDUs: %d", len(h.out))
		}
	})
	t.Run("missing mandatory NAS-PDU", func(t *testing.T) {
		h := newEHHarness(t)
		h.dispatch(buildULNAS(t, 1, 101, nil))
		evs := h.errorIndications(t)
		if len(evs) != 1 || len(evs[0].CDIEs) != 1 ||
			evs[0].CDIEs[0] != (CDIEView{IECriticality: 0, IEID: ngapType.ProtocolIEIDNASPDU, TypeOfError: 1}) {
			t.Fatalf("EI = %+v", evs)
		}
		if h.delivered() != 0 {
			t.Error("NAS delivered")
		}
	})
	t.Run("HANDOVER REQUIRED missing Target ID", func(t *testing.T) {
		h := newEHHarness(t)
		h.dispatch(buildHandoverRequiredPDU(t, 1, 101, false))
		if len(h.out) != 1 {
			t.Fatalf("want 1 PDU, got %d", len(h.out))
		}
		p, err := libngap.Decoder(h.out[0])
		if err != nil || p.Present != ngapType.NGAPPDUPresentUnsuccessfulOutcome {
			t.Fatalf("not a failure message: %v", err)
		}
		cd := p.UnsuccessfulOutcome.Value.HandoverPreparationFailure.ProtocolIEs.List[3].Value.CriticalityDiagnostics
		if cd == nil || cd.IEsCriticalityDiagnostics.List[0].IEID.Value != ngapType.ProtocolIEIDTargetID ||
			cd.IEsCriticalityDiagnostics.List[0].TypeOfError.Value != ngapType.TypeOfErrorPresentMissing {
			t.Errorf("CD = %+v", cd)
		}
	})
}

func TestUnknownIENotify(t *testing.T) {
	h := newEHHarness(t)
	h.dispatch(mustInject(t, buildULNAS(t, 1, 101, []byte{1}), 65000, ngapType.CriticalityPresentNotify))
	if h.delivered() != 1 {
		t.Error("message must be processed with its understood IEs")
	}
	evs := h.errorIndications(t)
	if len(evs) != 1 {
		t.Fatalf("want 1 EI, got %d", len(evs))
	}
	ev := evs[0]
	if ev.CauseValue != int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorIgnoreAndNotify) ||
		len(ev.CDIEs) != 1 || ev.CDIEs[0].IECriticality != int64(ngapType.CriticalityPresentNotify) ||
		!ev.HasAMFUENGAPID || ev.CDProcedureCriticality != int64(ngapType.CriticalityPresentIgnore) {
		t.Errorf("EI = %+v", ev)
	}
}

func TestUnknownIEIgnore(t *testing.T) {
	h := newEHHarness(t)
	h.dispatch(mustInject(t, buildULNAS(t, 1, 101, []byte{1}), 65000, ngapType.CriticalityPresentIgnore))
	if h.delivered() != 1 || len(h.out) != 0 {
		t.Errorf("delivered=%d out=%d, want 1/0", h.delivered(), len(h.out))
	}
	// Well-formed: no EI either.
	h2 := newEHHarness(t)
	h2.dispatch(buildULNAS(t, 1, 101, []byte{1}))
	if h2.delivered() != 1 || len(h2.out) != 0 {
		t.Errorf("well-formed: delivered=%d out=%d", h2.delivered(), len(h2.out))
	}
}

func TestUnknownIEReceivedErrorIndicationNeverAnswered(t *testing.T) {
	h := newEHHarness(t)
	ei, err := BuildErrorIndication(ErrorIndicationParams{CausePresent: ngapType.CausePresentProtocol, CauseValue: 0})
	if err != nil {
		t.Fatal(err)
	}
	h.dispatch(mustInject(t, ei, 65000, ngapType.CriticalityPresentReject))
	if len(h.out) != 0 {
		t.Fatalf("ERROR INDICATION answered: %d PDUs", len(h.out))
	}
}

func TestUnknownIEUnknownLocalUENGAPID(t *testing.T) {
	h := newEHHarness(t)
	h.dispatch(buildULNAS(t, 999, 555, []byte{1}))
	evs := h.errorIndications(t)
	if len(evs) != 1 || evs[0].AMFUENGAPID != 999 || evs[0].RANUENGAPID != 555 ||
		evs[0].CausePresent != ngapType.CausePresentRadioNetwork ||
		evs[0].CauseValue != int64(ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID) {
		t.Fatalf("EI = %+v", evs)
	}
	if _, ok := h.srv.mgr.GetByNGAPId(1); !ok {
		t.Error("UE 1 must stay registered")
	}
}

func TestTransferSyntaxError(t *testing.T) {
	t.Run("undecodable PDU: non-UE-associated EI", func(t *testing.T) {
		h := newEHHarness(t)
		h.dispatch([]byte{0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
		evs := h.errorIndications(t)
		if len(evs) != 1 || len(h.out) != 1 {
			t.Fatalf("want 1 EI, got %d", len(evs))
		}
		if evs[0].HasAMFUENGAPID || evs[0].HasRANUENGAPID ||
			evs[0].CausePresent != ngapType.CausePresentProtocol ||
			evs[0].CauseValue != int64(ngapType.CauseProtocolPresentTransferSyntaxError) {
			t.Errorf("EI = %+v", evs[0])
		}
	})
	t.Run("undecodable PDU identifiable as ERROR INDICATION: not answered", func(t *testing.T) {
		h := newEHHarness(t)
		ei, err := BuildErrorIndication(ErrorIndicationParams{CausePresent: ngapType.CausePresentProtocol, CauseValue: 0})
		if err != nil {
			t.Fatal(err)
		}
		trunc := ei[:len(ei)-2]
		if _, err := libngap.Decoder(trunc); err == nil {
			t.Skip("truncated PDU still decodes")
		}
		h.dispatch(trunc)
		if len(h.out) != 0 {
			t.Fatalf("answered an ERROR INDICATION: %d", len(h.out))
		}
	})
	t.Run("peek", func(t *testing.T) {
		ei, _ := BuildErrorIndication(ErrorIndicationParams{CausePresent: ngapType.CausePresentProtocol, CauseValue: 0})
		if !peekErrorIndication(ei) || peekErrorIndication(buildULNAS(t, 1, 1, []byte{1})) || peekErrorIndication([]byte{0}) {
			t.Error("peekErrorIndication wrong")
		}
	})
}

func TestBuildErrorIndication(t *testing.T) {
	amf, ran := int64(7), int64(9)
	pc := int64(46)
	tm := ngapType.TriggeringMessagePresentInitiatingMessage
	crit := ngapType.CriticalityPresentIgnore
	cd := BuildCriticalityDiagnostics(CriticalityDiagnosticsParams{ProcedureCode: &pc, TriggeringMessage: &tm, ProcedureCriticality: &crit,
		IEs: []CDIEItem{{IECriticality: ngapType.CriticalityPresentReject, IEID: 65535, TypeOfError: ngapType.TypeOfErrorPresentMissing}}})
	b, err := BuildErrorIndication(ErrorIndicationParams{AMFUENGAPID: &amf, RANUENGAPID: &ran,
		CausePresent: ngapType.CausePresentRadioNetwork, CauseValue: int64(ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID), CD: &cd})
	if err != nil {
		t.Fatal(err)
	}
	v, ok, err := DecodeOutboundErrorIndicationForTest(b)
	if err != nil || !ok {
		t.Fatalf("decode: ok=%v err=%v", ok, err)
	}
	if v.AMFUENGAPID != 7 || v.RANUENGAPID != 9 || v.CDProcedureCode != 46 || len(v.CDIEs) != 1 || v.CDIEs[0].IEID != 65535 {
		t.Errorf("view = %+v", v)
	}
	// Spec order §9.2.6.13: AMF UE NGAP ID, RAN UE NGAP ID, Cause, Criticality Diagnostics.
	p, _ := libngap.Decoder(b)
	var ids []int64
	for _, ie := range p.InitiatingMessage.Value.ErrorIndication.ProtocolIEs.List {
		ids = append(ids, ie.Id.Value)
	}
	want := []int64{ngapType.ProtocolIEIDAMFUENGAPID, ngapType.ProtocolIEIDRANUENGAPID, ngapType.ProtocolIEIDCause, ngapType.ProtocolIEIDCriticalityDiagnostics}
	if len(ids) != 4 || ids[0] != want[0] || ids[1] != want[1] || ids[2] != want[2] || ids[3] != want[3] {
		t.Errorf("IE order = %v, want %v", ids, want)
	}
	if p.InitiatingMessage.ProcedureCode.Value != 9 || p.InitiatingMessage.Criticality.Value != ngapType.CriticalityPresentIgnore {
		t.Error("procedure code / criticality wrong")
	}

	for name, params := range map[string]ErrorIndicationParams{
		"neither cause nor CD": {},
		"only AMF id":          {AMFUENGAPID: &amf, CausePresent: ngapType.CausePresentProtocol},
		"only RAN id":          {RANUENGAPID: &ran, CausePresent: ngapType.CausePresentProtocol},
	} {
		if _, err := BuildErrorIndication(params); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestBuildCriticalityDiagnosticsCapsAt256(t *testing.T) {
	var items []CDIEItem
	for i := 0; i < 300; i++ {
		items = append(items, CDIEItem{IECriticality: ngapType.CriticalityPresentReject, IEID: int64(i)})
	}
	cd := BuildCriticalityDiagnostics(CriticalityDiagnosticsParams{IEs: items})
	if n := len(cd.IEsCriticalityDiagnostics.List); n != 256 {
		t.Fatalf("list len = %d, want 256", n)
	}
}

// TestFailureBuildersUnchangedWithoutDiagnostics compares with hex captured from the HEAD
// builders (before the *WithDiagnostics variants existed): a nil CD must stay byte-identical.
func TestFailureBuildersUnchangedWithoutDiagnostics(t *testing.T) {
	var nh [32]byte
	snssai := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	rel := []PDUSessionReleasedItem{{PDUSessionID: 5, CausePresent: ngapType.CausePresentRadioNetwork, CauseValue: 1}}
	for name, tc := range map[string]struct {
		got  [2][]byte
		want string
	}{
		"HandoverPreparationFailure": {[2][]byte{
			BuildHandoverPreparationFailure(1, 2, ngapType.CausePresentRadioNetwork, 3),
			BuildHandoverPreparationFailureWithDiagnostics(1, 2, ngapType.CausePresentRadioNetwork, 3, nil)},
			"400c0015000003000a40020001005540020002000f400200c0"},
		"PathSwitchRequestFailure": {[2][]byte{
			BuildPathSwitchRequestFailure(1, 2, rel),
			BuildPathSwitchRequestFailureWithDiagnostics(1, 2, rel, nil)},
			"40190019000003000a4002000100554002000200454006000005020010"},
		"NGSetupResponse": {[2][]byte{
			BuildNGSetupResponse("amf", "001", "01", 2, 1, 3, snssai),
			BuildNGSetupResponseWithDiagnostics("amf", "001", "01", 2, 1, 3, snssai, nil)},
			"2015002c000004000100050100616d6600600008000000f11002004300564001640050000b0000f11000001008000001"},
		"HandoverCommand": {[2][]byte{
			BuildHandoverCommand(1, 2, 0, []PDUSessionHOCmdItem{{PDUSessionID: 5}}, nil, []byte{1, 2, 3}),
			BuildHandoverCommandWithDiagnostics(1, 2, 0, []PDUSessionHOCmdItem{{PDUSessionID: 5}}, nil, []byte{1, 2, 3}, nil)},
			"200c0025000005000a00020001005500020002001d000100003b40050000050100006a000403010203"},
		"PathSwitchRequestAcknowledge": {[2][]byte{
			BuildPathSwitchRequestAcknowledge(PathSwitchAckParams{AMFUENGAPId: 1, RANUENGAPId: 2, NCC: 1, NH: nh,
				Switched: []PDUSessionSwitchItem{{PDUSessionID: 5}}, AllowedNSSAI: snssai}),
			BuildPathSwitchRequestAcknowledge(PathSwitchAckParams{AMFUENGAPId: 1, RANUENGAPId: 2, NCC: 1, NH: nh,
				Switched: []PDUSessionSwitchItem{{PDUSessionID: 5}}, AllowedNSSAI: snssai, CD: nil})},
			"20190046000005000a40020001005540020002005d0021080000000000000000000000000000000000000000000000000000000000000000004d40050000050100000000050201000001"},
	} {
		for i, got := range tc.got {
			if hx := hex.EncodeToString(got); hx != tc.want {
				t.Errorf("%s variant %d: got %s, want HEAD golden %s", name, i, hx, tc.want)
			}
		}
	}
}

// TestWithDiagnosticsBuilders: a CD adds exactly one IE 19 (ignore) in spec position.
func TestWithDiagnosticsBuilders(t *testing.T) {
	cd := BuildCriticalityDiagnostics(CriticalityDiagnosticsParams{IEs: []CDIEItem{{IECriticality: ngapType.CriticalityPresentNotify, IEID: 65000, TypeOfError: ngapType.TypeOfErrorPresentNotUnderstood}}})
	var nh [32]byte
	snssai := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	nsr, _ := libngap.Decoder(BuildNGSetupResponseWithDiagnostics("amf", "001", "01", 2, 1, 3, snssai, &cd))
	l := nsr.SuccessfulOutcome.Value.NGSetupResponse.ProtocolIEs.List
	if last := l[len(l)-1]; last.Id.Value != ngapType.ProtocolIEIDCriticalityDiagnostics || last.Criticality.Value != ngapType.CriticalityPresentIgnore || last.Value.CriticalityDiagnostics == nil {
		t.Errorf("NG SETUP RESPONSE CD not last/ignore: %+v", last)
	}
	hoc, _ := libngap.Decoder(BuildHandoverCommandWithDiagnostics(1, 2, 0, nil, nil, []byte{1}, &cd))
	hl := hoc.SuccessfulOutcome.Value.HandoverCommand.ProtocolIEs.List
	if last := hl[len(hl)-1]; last.Id.Value != ngapType.ProtocolIEIDCriticalityDiagnostics || last.Value.CriticalityDiagnostics == nil {
		t.Errorf("HANDOVER COMMAND CD not last: %+v", last)
	}
	psa, _ := libngap.Decoder(BuildPathSwitchRequestAcknowledge(PathSwitchAckParams{AMFUENGAPId: 1, RANUENGAPId: 2, NCC: 1, NH: nh,
		Switched: []PDUSessionSwitchItem{{PDUSessionID: 5}}, AllowedNSSAI: snssai, CD: &cd}))
	pl := psa.SuccessfulOutcome.Value.PathSwitchRequestAcknowledge.ProtocolIEs.List
	if last := pl[len(pl)-1]; last.Id.Value != ngapType.ProtocolIEIDCriticalityDiagnostics || last.Value.CriticalityDiagnostics == nil {
		t.Errorf("PATH SWITCH ACK CD not last: %+v", last)
	}
}

// ---- PDU builders ------------------------------------------------------------

func buildHandoverRequiredPDU(t *testing.T, amf, ran int64, withTargetID bool) []byte {
	t.Helper()
	msg := &ngapType.HandoverRequired{}
	add := func(id int64, crit aper.Enumerated, v ngapType.HandoverRequiredIEsValue) {
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ngapType.HandoverRequiredIEs{
			Id: ngapType.ProtocolIEID{Value: id}, Criticality: ngapType.Criticality{Value: crit}, Value: v})
	}
	rej, ign := ngapType.CriticalityPresentReject, ngapType.CriticalityPresentIgnore
	add(ngapType.ProtocolIEIDAMFUENGAPID, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentAMFUENGAPID, AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amf}})
	add(ngapType.ProtocolIEIDRANUENGAPID, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentRANUENGAPID, RANUENGAPID: &ngapType.RANUENGAPID{Value: ran}})
	add(ngapType.ProtocolIEIDHandoverType, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentHandoverType, HandoverType: &ngapType.HandoverType{Value: ngapType.HandoverTypePresentIntra5gs}})
	cause := buildCause(ngapType.CausePresentRadioNetwork, 0)
	add(ngapType.ProtocolIEIDCause, ign, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentCause, Cause: &cause})
	if withTargetID {
		gid := aper.BitString{Bytes: []byte{0x00, 0x00, 0x01, 0x00}, BitLength: 32}
		add(ngapType.ProtocolIEIDTargetID, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentTargetID,
			TargetID: &ngapType.TargetID{Present: ngapType.TargetIDPresentTargetRANNodeID, TargetRANNodeID: &ngapType.TargetRANNodeID{
				GlobalRANNodeID: ngapType.GlobalRANNodeID{Present: ngapType.GlobalRANNodeIDPresentGlobalGNBID, GlobalGNBID: &ngapType.GlobalGNBID{
					PLMNIdentity: ngapType.PLMNIdentity{Value: aper.OctetString{0x00, 0xF1, 0x10}},
					GNBID:        ngapType.GNBID{Present: ngapType.GNBIDPresentGNBID, GNBID: &gid}}},
				SelectedTAI: ngapType.TAI{PLMNIdentity: ngapType.PLMNIdentity{Value: aper.OctetString{0x00, 0xF1, 0x10}}, TAC: ngapType.TAC{Value: aper.OctetString{0, 0, 1}}}}}})
	}
	add(ngapType.ProtocolIEIDPDUSessionResourceListHORqd, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentPDUSessionResourceListHORqd,
		PDUSessionResourceListHORqd: &ngapType.PDUSessionResourceListHORqd{List: []ngapType.PDUSessionResourceItemHORqd{
			{PDUSessionID: ngapType.PDUSessionID{Value: 5}, HandoverRequiredTransfer: aper.OctetString{0x01}}}}})
	add(ngapType.ProtocolIEIDSourceToTargetTransparentContainer, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentSourceToTargetTransparentContainer,
		SourceToTargetTransparentContainer: &ngapType.SourceToTargetTransparentContainer{Value: aper.OctetString{0x02}}})
	b, err := libngap.Encoder(ngapType.NGAPPDU{Present: ngapType.NGAPPDUPresentInitiatingMessage, InitiatingMessage: &ngapType.InitiatingMessage{
		ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeHandoverPreparation},
		Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value:         ngapType.InitiatingMessageValue{Present: ngapType.InitiatingMessagePresentHandoverRequired, HandoverRequired: msg}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func buildPathSwitchRequestPDU(t *testing.T, sourceAMF, ran int64, psi int64) []byte {
	t.Helper()
	msg := &ngapType.PathSwitchRequest{}
	add := func(id int64, v ngapType.PathSwitchRequestIEsValue) {
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ngapType.PathSwitchRequestIEs{
			Id: ngapType.ProtocolIEID{Value: id}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject}, Value: v})
	}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.PathSwitchRequestIEsValue{Present: ngapType.PathSwitchRequestIEsPresentRANUENGAPID, RANUENGAPID: &ngapType.RANUENGAPID{Value: ran}})
	add(ngapType.ProtocolIEIDSourceAMFUENGAPID, ngapType.PathSwitchRequestIEsValue{Present: ngapType.PathSwitchRequestIEsPresentSourceAMFUENGAPID, SourceAMFUENGAPID: &ngapType.AMFUENGAPID{Value: sourceAMF}})
	add(ngapType.ProtocolIEIDPDUSessionResourceToBeSwitchedDLList, ngapType.PathSwitchRequestIEsValue{Present: ngapType.PathSwitchRequestIEsPresentPDUSessionResourceToBeSwitchedDLList,
		PDUSessionResourceToBeSwitchedDLList: &ngapType.PDUSessionResourceToBeSwitchedDLList{List: []ngapType.PDUSessionResourceToBeSwitchedDLItem{
			{PDUSessionID: ngapType.PDUSessionID{Value: psi}, PathSwitchRequestTransfer: aper.OctetString{0x01}}}}})
	b, err := libngap.Encoder(ngapType.NGAPPDU{Present: ngapType.NGAPPDUPresentInitiatingMessage, InitiatingMessage: &ngapType.InitiatingMessage{
		ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePathSwitchRequest},
		Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value:         ngapType.InitiatingMessageValue{Present: ngapType.InitiatingMessagePresentPathSwitchRequest, PathSwitchRequest: msg}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---- finding 1: notify IE on a message with a response -> CD in the response ----------

func TestUnknownIENotifyWithResponseMessage(t *testing.T) {
	cases := []struct {
		name string
		pdu  func(t *testing.T) []byte
		cd   func(msg *Message) *ngapType.CriticalityDiagnostics
	}{
		{"NG SETUP REQUEST", func(t *testing.T) []byte {
			return buildNGSetupRequestPDU(t, []byte{0x00, 0x00, 0x01, 0x00}, 32, "gnb")
		}, func(m *Message) *ngapType.CriticalityDiagnostics { return m.Value.(*NGSetupRequest).NotifyCD }},
		{"HANDOVER REQUIRED", func(t *testing.T) []byte { return buildHandoverRequiredPDU(t, 1, 101, true) },
			func(m *Message) *ngapType.CriticalityDiagnostics { return m.Value.(*HandoverRequiredMsg).NotifyCD }},
		{"PATH SWITCH REQUEST", func(t *testing.T) []byte { return buildPathSwitchRequestPDU(t, 1, 202, 5) },
			func(m *Message) *ngapType.CriticalityDiagnostics { return m.Value.(*PathSwitchRequestMsg).NotifyCD }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newEHHarness(t)
			msg, pdu, err := decodeNGAPPDUWithRaw(mustInject(t, tc.pdu(t), 65000, ngapType.CriticalityPresentNotify))
			if err != nil {
				t.Fatal(err)
			}
			process, post := h.srv.checkAbstractSyntax(context.Background(), h.gnb, msg, pdu)
			if !process || post != nil {
				t.Fatalf("process=%v post=%v: want processed with no ERROR INDICATION action", process, post)
			}
			if len(h.out) != 0 {
				t.Fatalf("ERROR INDICATION sent: %d PDUs", len(h.out))
			}
			cd := tc.cd(msg)
			if cd == nil || cd.ProcedureCode != nil || cd.TriggeringMessage != nil || cd.ProcedureCriticality != nil ||
				len(cd.IEsCriticalityDiagnostics.List) != 1 || cd.IEsCriticalityDiagnostics.List[0].IEID.Value != 65000 ||
				cd.IEsCriticalityDiagnostics.List[0].IECriticality.Value != ngapType.CriticalityPresentNotify {
				t.Fatalf("NotifyCD = %+v", cd)
			}
		})
	}
	t.Run("NG RESET keeps the ERROR INDICATION", func(t *testing.T) {
		msg := &Message{Type: 0, ProcedureCode: ProcNGReset}
		if hasResponseMessage(msg.ProcedureCode) {
			t.Error("NG RESET has no AMF-built response")
		}
	})
}

// ---- finding 2: unknown Procedure Code (§10.3.4.1) ------------------------------------

func TestUnknownProcedureCode(t *testing.T) {
	unknown := func(t *testing.T, code byte, crit aper.Enumerated) []byte {
		pdu := append([]byte{}, buildULNAS(t, 1, 101, []byte{1})...)
		pdu[1] = code
		pdu[2] = byte(crit) << 6
		p, err := libngap.Decoder(pdu)
		if err != nil || p.InitiatingMessage.Value.Present != 0 {
			t.Skipf("decoder does not leave unknown procedure unpopulated: err=%v", err)
		}
		return pdu
	}
	t.Run("reject: ERROR INDICATION abstract-syntax-error-reject + CD", func(t *testing.T) {
		h := newEHHarness(t)
		h.dispatch(unknown(t, 200, ngapType.CriticalityPresentReject))
		evs := h.errorIndications(t)
		if len(evs) != 1 {
			t.Fatalf("want 1 EI, got %d", len(evs))
		}
		ev := evs[0]
		if ev.CauseValue != int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorReject) || ev.CDProcedureCode != 200 ||
			ev.CDTriggeringMessage != 0 || ev.CDProcedureCriticality != int64(ngapType.CriticalityPresentReject) || len(ev.CDIEs) != 0 {
			t.Errorf("EI = %+v", ev)
		}
		if h.delivered() != 0 {
			t.Error("message processed")
		}
	})
	t.Run("notify: abstract-syntax-error-ignore-and-notify, procedure ignored", func(t *testing.T) {
		h := newEHHarness(t)
		h.dispatch(unknown(t, 200, ngapType.CriticalityPresentNotify))
		evs := h.errorIndications(t)
		if len(evs) != 1 || evs[0].CauseValue != int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorIgnoreAndNotify) ||
			evs[0].CDProcedureCriticality != int64(ngapType.CriticalityPresentNotify) {
			t.Fatalf("EI = %+v", evs)
		}
	})
	t.Run("ignore: silently dropped", func(t *testing.T) {
		h := newEHHarness(t)
		h.dispatch(unknown(t, 200, ngapType.CriticalityPresentIgnore))
		if len(h.out) != 0 || h.delivered() != 0 {
			t.Errorf("out=%d delivered=%d, want 0/0", len(h.out), h.delivered())
		}
	})
	t.Run("never for ERROR INDICATION (procedure code 9)", func(t *testing.T) {
		h := newEHHarness(t)
		ei, _ := BuildErrorIndication(ErrorIndicationParams{CausePresent: ngapType.CausePresentProtocol, CauseValue: 0})
		h.dispatch(ei)
		if len(h.out) != 0 {
			t.Fatalf("ERROR INDICATION answered: %d", len(h.out))
		}
	})
}

// ---- finding 4: robustness of the scan -------------------------------------------------

func TestAbstractSyntaxScanMalformedInput(t *testing.T) {
	bad := map[string]*ngapType.NGAPPDU{
		"nil pdu":                 nil,
		"nil InitiatingMessage":   {Present: ngapType.NGAPPDUPresentInitiatingMessage},
		"nil SuccessfulOutcome":   {Present: ngapType.NGAPPDUPresentSuccessfulOutcome},
		"nil UnsuccessfulOutcome": {Present: ngapType.NGAPPDUPresentUnsuccessfulOutcome},
		"unknown choice":          {Present: 99},
		"no message populated":    {Present: ngapType.NGAPPDUPresentInitiatingMessage, InitiatingMessage: &ngapType.InitiatingMessage{}},
	}
	for name, pdu := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := walkProtocolIEs(pdu); err == nil {
				t.Error("want error, got nil")
			}
			if _, _, _, err := scanAbstractSyntax(&Message{}, pdu); err == nil {
				t.Error("scan: want error, got nil")
			}
		})
	}
	t.Run("reflection helpers on non-struct", func(t *testing.T) {
		if _, err := structField(reflect.ValueOf(3), "X"); err == nil {
			t.Error("structField on int: want error")
		}
		if _, err := structField(reflect.Value{}, "X"); err == nil {
			t.Error("structField on invalid: want error")
		}
		if _, err := reflectInt(reflect.ValueOf("s")); err == nil {
			t.Error("reflectInt on string: want error")
		}
		if _, err := reflectInt(reflect.Value{}); err == nil {
			t.Error("reflectInt on invalid: want error")
		}
	})
	t.Run("dispatch of a scan error drops the PDU", func(t *testing.T) {
		h := newEHHarness(t)
		process, post := h.srv.checkAbstractSyntax(context.Background(), h.gnb, &Message{ProcedureCode: ProcUplinkNASTransport},
			&ngapType.NGAPPDU{Present: ngapType.NGAPPDUPresentInitiatingMessage})
		if process || post != nil {
			t.Errorf("process=%v post=%v, want dropped", process, post)
		}
	})
}

// TestDispatchRandomMutationsNeverPanic flips bytes of valid PDUs and feeds truncations.
func TestDispatchRandomMutationsNeverPanic(t *testing.T) {
	seeds := [][]byte{
		buildULNAS(t, 1, 101, []byte{1, 2, 3}),
		buildHandoverRequiredPDU(t, 1, 101, true),
		buildPathSwitchRequestPDU(t, 1, 202, 5),
		buildNGSetupRequestPDU(t, []byte{0x00, 0x00, 0x01, 0x00}, 32, "gnb"),
	}
	rng := rand.New(rand.NewSource(1))
	h := newEHHarness(t)
	for _, seed := range seeds {
		for i := 0; i < 300; i++ {
			m := append([]byte{}, seed...)
			for k := 0; k <= rng.Intn(3); k++ {
				m[rng.Intn(len(m))] = byte(rng.Intn(256))
			}
			if i%5 == 0 {
				m = m[:rng.Intn(len(m)+1)]
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("dispatch panicked on %x: %v", m, r)
					}
				}()
				// handlers other than the scan are exercised too; only the scan/decoder path
				// is under test, so stop at checkAbstractSyntax.
				msg, pdu, err := decodeNGAPPDUWithRaw(m)
				if err != nil {
					return
				}
				h.srv.checkAbstractSyntax(context.Background(), h.gnb, msg, pdu)
			}()
		}
	}
}

// ---- finding 5: notify EI follows the UE's queued work ---------------------------------

func TestUnknownIENotifyFollowsQueuedUEWork(t *testing.T) {
	h := newEHHarness(t)
	h.gate = make(chan struct{})
	h.srv.DispatchNGAPForTest(context.Background(), h.gnb, mustInject(t, buildULNAS(t, 1, 101, []byte{1}), 65000, ngapType.CriticalityPresentNotify))
	h.mu.Lock()
	early := len(h.out)
	h.mu.Unlock()
	if early != 0 {
		t.Fatalf("notify ERROR INDICATION sent before the UE's NAS work ran (%d PDUs)", early)
	}
	close(h.gate)
	h.srv.WaitUESerialForTest(1)
	if h.delivered() != 1 {
		t.Error("NAS not delivered")
	}
	if evs := h.errorIndications(t); len(evs) != 1 {
		t.Fatalf("want 1 EI after the work, got %d", len(evs))
	}
}

// ---- finding 6: §10.6 local release ------------------------------------------------------

func TestUnknownAMFUENGAPIDLocallyReleasesMatchingRANUENGAPID(t *testing.T) {
	h := newEHHarness(t)
	ue, _ := h.srv.mgr.GetByNGAPId(1)
	h.gnb.UEs[101] = ue
	var released []*amfctx.UEContext
	h.srv.SetGNBDisconnectHandler(func(_ context.Context, u *amfctx.UEContext) { released = append(released, u) })
	h.dispatch(buildULNAS(t, 999, 101, []byte{1})) // unknown AMF id, RAN id 101 matches UE 1
	if len(released) != 1 || released[0] != ue {
		t.Fatalf("released = %v, want the UE with RAN id 101", released)
	}
	if _, ok := h.gnb.UEs[101]; ok {
		t.Error("UE still in gnb.UEs")
	}
	if evs := h.errorIndications(t); len(evs) != 1 {
		t.Errorf("want the unknown-local-UE-NGAP-ID EI, got %d", len(evs))
	}
}
