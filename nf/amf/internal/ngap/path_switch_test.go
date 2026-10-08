package ngap

// path_switch_test.go — Xn handover (Path Switch Request) and the N2 handover
// legs touched by AMF-011: Ack IE order, NH/NCC chain, no source release, PPID 60,
// Failure causes, UE-AMBR in HANDOVER REQUEST.
// Ref: TS 38.413 §8.4.4, §9.2.3.8-§9.2.3.10, §9.3.1.18; TS 33.501 §6.9.2.3.2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
)

// ---- harness -----------------------------------------------------------------

type sentPDU struct {
	raw  []byte
	ppid uint32
}

type fakeLink struct {
	mu   sync.Mutex
	sent []sentPDU
}

func (f *fakeLink) write(pdu []byte, info *sctp.SndRcvInfo) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentPDU{append([]byte(nil), pdu...), info.PPID})
	return len(pdu), nil
}

func (f *fakeLink) pdus() []sentPDU {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentPDU(nil), f.sent...)
}

type logRecorder struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (l *logRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (l *logRecorder) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = append(l.recs, r.Clone())
	return nil
}
func (l *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logRecorder) WithGroup(string) slog.Handler      { return l }

// attrs flattens all records; logs created with logger.With(...) lose their With
// attrs here (WithAttrs is a no-op) — tests only look at per-call attrs and levels.
func (l *logRecorder) find(msg string) (slog.Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.recs {
		if strings.Contains(r.Message, msg) {
			return r, true
		}
	}
	return slog.Record{}, false
}

func recAttr(r slog.Record, key string) (any, bool) {
	var v any
	var ok bool
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			v, ok = a.Value.Any(), true
			return false
		}
		return true
	})
	return v, ok
}

type xnHarness struct {
	srv           *Server
	ue            *amfctx.UEContext
	src, tgt      *GNBContext
	srcLn, tgtLn  *fakeLink
	kamf          []byte
	kgnb          [32]byte
	logs          *logRecorder
	smfCalls      chan string
	amfID, ranOld int64
}

func newXnHarness(t *testing.T) *xnHarness {
	t.Helper()
	logs := &logRecorder{}
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := &xnHarness{logs: logs, smfCalls: make(chan string, 8), srcLn: &fakeLink{}, tgtLn: &fakeLink{}}
	h.srv = &Server{
		cfg:         AMFConfig{MCC: "001", MNC: "01"},
		mgr:         mgr,
		logger:      slog.New(logs),
		gnbs:        map[string]*GNBContext{},
		pendingN2HO: map[int64]*n2HandoverState{},
	}
	h.srv.onPathSwitchPDUSession = func(_ context.Context, ref string, _ []byte) SMFUpdateResult {
		h.smfCalls <- ref
		return SMFUpdateResult{HTTPStatus: 200}
	}

	h.ranOld = 1
	h.ue = mgr.AllocateUEContext(h.ranOld)
	h.amfID = h.ue.AMFUENGAPId
	h.kamf = bytes.Repeat([]byte{0x11}, 32)
	for i := range h.kgnb {
		h.kgnb[i] = byte(0xA0 + i)
	}
	h.ue.SUPI = "imsi-001010000000001"
	h.ue.SecurityCtx.KAMF = h.kamf
	h.ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	h.ue.PDUSessions[5] = &amfctx.PDUSession{PDUSessionID: 5, SMFInstanceID: "smctx-5",
		SNSSAI: amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}, N2SmTransfer: []byte{1, 2, 3}}
	h.ue.UESecCapEA[1], h.ue.UESecCapEA[2] = true, true
	h.ue.UESecCapIA[1], h.ue.UESecCapIA[2] = true, true
	h.ue.CMState = amfctx.CMConnected
	h.ue.SetKgNB(h.kgnb)

	mk := func(name string, id uint32, ln *fakeLink, addr string) *GNBContext {
		g := &GNBContext{
			Name:        name,
			GlobalGNBID: []byte{0, 0, byte(id)},
			UEs:         map[int64]*amfctx.UEContext{},
			IdleUEs:     map[int64]*amfctx.UEContext{},
		}
		g.SetTransportForTest(addr, ln.write)
		h.srv.AddGNBForTest(addr, g)
		return g
	}
	h.src = mk("gnb-source", 1, h.srcLn, "10.0.0.1:1")
	h.tgt = mk("gnb-target", 2, h.tgtLn, "10.0.0.2:1")
	h.src.UEs[h.ranOld] = h.ue
	h.ue.GNBAddr = "10.0.0.1:1"
	return h
}

func (h *xnHarness) pathSwitch(ranID int64, psis ...uint8) *PathSwitchRequestMsg {
	return h.pathSwitchFor(h.amfID, ranID, psis...)
}

func (h *xnHarness) pathSwitchFor(amfID, ranID int64, psis ...uint8) *PathSwitchRequestMsg {
	req := &PathSwitchRequestMsg{SourceAMFUENGAPId: amfID, RANUENGAPId: ranID}
	for _, p := range psis {
		req.PDUSessions = append(req.PDUSessions, PDUSessionSwitchItem{PDUSessionID: p, PathSwitchRequestTransfer: []byte{0xAB}})
	}
	return req
}

func (h *xnHarness) run(req *PathSwitchRequestMsg) {
	h.srv.HandlePathSwitchRequestForTest(context.Background(), h.tgt, req)
}

// ---- decode helpers ------------------------------------------------------------

type ieInfo struct {
	id   int64
	crit aper.Enumerated
}

func ackIEs(t *testing.T, raw []byte) (*ngapType.PathSwitchRequestAcknowledge, []ieInfo) {
	t.Helper()
	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if pdu.SuccessfulOutcome == nil || pdu.SuccessfulOutcome.ProcedureCode.Value != ngapType.ProcedureCodePathSwitchRequest ||
		pdu.SuccessfulOutcome.Value.PathSwitchRequestAcknowledge == nil {
		t.Fatalf("not a PathSwitchRequestAcknowledge")
	}
	ack := pdu.SuccessfulOutcome.Value.PathSwitchRequestAcknowledge
	var ies []ieInfo
	for _, ie := range ack.ProtocolIEs.List {
		ies = append(ies, ieInfo{ie.Id.Value, ie.Criticality.Value})
	}
	return ack, ies
}

func ackSecurityContext(ack *ngapType.PathSwitchRequestAcknowledge) (ncc int64, nh []byte, bits uint64) {
	for _, ie := range ack.ProtocolIEs.List {
		if ie.Value.SecurityContext != nil {
			sc := ie.Value.SecurityContext
			return sc.NextHopChainingCount.Value, sc.NextHopNH.Value.Bytes, sc.NextHopNH.Value.BitLength
		}
	}
	return -1, nil, 0
}

func failureItems(t *testing.T, raw []byte) (amfID, ranID int64, items map[int64]ngapType.Cause) {
	t.Helper()
	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("decode failure: %v", err)
	}
	if pdu.UnsuccessfulOutcome == nil || pdu.UnsuccessfulOutcome.ProcedureCode.Value != ngapType.ProcedureCodePathSwitchRequest ||
		pdu.UnsuccessfulOutcome.Value.PathSwitchRequestFailure == nil {
		t.Fatalf("not a PathSwitchRequestFailure")
	}
	items = map[int64]ngapType.Cause{}
	var order []int64
	for _, ie := range pdu.UnsuccessfulOutcome.Value.PathSwitchRequestFailure.ProtocolIEs.List {
		order = append(order, ie.Id.Value)
		switch {
		case ie.Value.AMFUENGAPID != nil:
			amfID = ie.Value.AMFUENGAPID.Value
		case ie.Value.RANUENGAPID != nil:
			ranID = ie.Value.RANUENGAPID.Value
		case ie.Value.PDUSessionResourceReleasedListPSFail != nil:
			for _, it := range ie.Value.PDUSessionResourceReleasedListPSFail.List {
				var tr ngapType.PathSwitchRequestUnsuccessfulTransfer
				if err := aper.UnmarshalWithParams(it.PathSwitchRequestUnsuccessfulTransfer, &tr, "valueExt"); err != nil {
					t.Fatalf("decode unsuccessful transfer: %v", err)
				}
				items[it.PDUSessionID.Value] = tr.Cause
			}
		}
	}
	if len(order) != 3 || order[0] != 10 || order[1] != 85 || order[2] != 69 {
		t.Fatalf("failure IE order = %v, want [10 85 69]", order)
	}
	return
}

func idsOf(ies []ieInfo) []int64 {
	out := make([]int64, len(ies))
	for i, ie := range ies {
		out[i] = ie.id
	}
	return out
}

func equalIDs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nhN(kamf, kgnb []byte, n int) []byte {
	nh := kdf.KNH(kamf, kgnb)
	for i := 1; i < n; i++ {
		nh = kdf.KNH(kamf, nh)
	}
	return nh
}

// ---- Ack: handler tests ---------------------------------------------------------

func TestPathSwitch_AckHappyPath(t *testing.T) {
	h := newXnHarness(t)
	h.run(h.pathSwitch(7, 5))

	sent := h.tgtLn.pdus()
	if len(sent) != 1 {
		t.Fatalf("target gNB got %d PDUs, want 1", len(sent))
	}
	if sent[0].ppid != 60 {
		t.Fatalf("ack PPID = %d, want 60", sent[0].ppid)
	}
	ack, ies := ackIEs(t, sent[0].raw)
	if want := []int64{10, 85, 93, 77, 0}; !equalIDs(idsOf(ies), want) {
		t.Fatalf("IE order = %v, want %v", idsOf(ies), want)
	}
	crit := map[int64]aper.Enumerated{10: ngapType.CriticalityPresentIgnore, 85: ngapType.CriticalityPresentIgnore,
		93: ngapType.CriticalityPresentReject, 77: ngapType.CriticalityPresentIgnore, 0: ngapType.CriticalityPresentReject}
	for _, ie := range ies {
		if crit[ie.id] != ie.crit {
			t.Errorf("IE %d criticality = %d, want %d", ie.id, ie.crit, crit[ie.id])
		}
	}
	ncc, nh, bits := ackSecurityContext(ack)
	if ncc != 2 || bits != 256 {
		t.Fatalf("ncc=%d bits=%d, want 2/256", ncc, bits)
	}
	if want := nhN(h.kamf, h.kgnb[:], 2); !bytes.Equal(nh, want) {
		t.Fatalf("NH != KNH(KAMF, KNH(KAMF, KgNB))")
	}
	if got := ack.ProtocolIEs.List[0].Value.AMFUENGAPID.Value; got != h.amfID {
		t.Errorf("AMF UE NGAP ID = %d, want %d", got, h.amfID)
	}
	if got := ack.ProtocolIEs.List[1].Value.RANUENGAPID.Value; got != 7 {
		t.Errorf("RAN UE NGAP ID = %d, want 7", got)
	}
	nssai := ack.ProtocolIEs.List[4].Value.AllowedNSSAI
	if len(nssai.List) != 1 || nssai.List[0].SNSSAI.SST.Value[0] != 1 || !bytes.Equal(nssai.List[0].SNSSAI.SD.Value, []byte{0, 0, 1}) {
		t.Fatalf("allowed NSSAI wrong: %+v", nssai.List)
	}
	switched := ack.ProtocolIEs.List[3].Value.PDUSessionResourceSwitchedList
	if len(switched.List) != 1 || switched.List[0].PDUSessionID.Value != 5 {
		t.Fatalf("switched list wrong")
	}
	select {
	case ref := <-h.smfCalls:
		if ref != "smctx-5" {
			t.Fatalf("SMF ref %q", ref)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("SMF not notified")
	}
}

func TestPathSwitch_NoSourceSignalling_AndRebind(t *testing.T) {
	h := newXnHarness(t)
	h.run(h.pathSwitch(7, 5))

	if n := len(h.srcLn.pdus()); n != 0 {
		t.Fatalf("source gNB received %d PDUs, want 0", n)
	}
	for _, p := range h.tgtLn.pdus() {
		pdu, _ := libngap.Decoder(p.raw)
		if pdu.InitiatingMessage != nil && pdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeUEContextRelease {
			t.Fatalf("UE Context Release Command sent")
		}
	}
	if h.ue.PendingRemoval {
		t.Fatalf("UE flagged for removal")
	}
	if h.ue.RANUENGAPId != 7 || h.ue.GNBAddr != "10.0.0.2:1" || h.ue.AMFUENGAPId != h.amfID {
		t.Fatalf("rebind wrong: ran=%d addr=%s", h.ue.RANUENGAPId, h.ue.GNBAddr)
	}
	if h.tgt.UEs[7] != h.ue {
		t.Fatalf("target map missing UE")
	}
	if _, ok := h.src.UEs[1]; ok {
		t.Fatalf("source map still holds UE")
	}
	if h.ue.CMState != amfctx.CMConnected {
		t.Fatalf("CM state changed")
	}
}

func TestPathSwitch_NHChainAcrossHops(t *testing.T) {
	h := newXnHarness(t)
	for hop, wantNCC := range []int64{2, 3, 4} {
		h.run(h.pathSwitch(int64(10+hop), 5))
		sent := h.tgtLn.pdus()
		ack, _ := ackIEs(t, sent[len(sent)-1].raw)
		ncc, nh, _ := ackSecurityContext(ack)
		if ncc != wantNCC {
			t.Fatalf("hop %d ncc=%d want %d", hop+1, ncc, wantNCC)
		}
		if want := nhN(h.kamf, h.kgnb[:], hop+2); !bytes.Equal(nh, want) {
			t.Fatalf("hop %d NH mismatch", hop+1)
		}
	}
}

func TestPathSwitch_NCCWrap(t *testing.T) {
	tests := []struct{ before, after uint8 }{{1, 2}, {6, 7}, {7, 0}, {0, 1}}
	for _, tc := range tests {
		h := newXnHarness(t)
		prev := [32]byte{0x77}
		h.ue.SetNHState(prev, tc.before)
		h.run(h.pathSwitch(7, 5))
		ack, _ := ackIEs(t, h.tgtLn.pdus()[0].raw)
		ncc, nh, _ := ackSecurityContext(ack)
		if ncc != int64(tc.after) || !bytes.Equal(nh, kdf.KNH(h.kamf, prev[:])) {
			t.Fatalf("before=%d: ncc=%d, NH chain wrong", tc.before, ncc)
		}
	}
}

func TestPathSwitch_AllowedNSSAI(t *testing.T) {
	type nssai = amfctx.SNSSAISubscribed
	tests := []struct {
		name     string
		allowed  []nssai
		sessions map[uint8]nssai
		want     [][2]string // SST, SD hex
		wantFail bool
		warn     bool
	}{
		{"dedupe by SST/SD", []nssai{{SST: 1, SD: "000001", DNN: "a"}, {SST: 1, SD: "000001", DNN: "b"}},
			map[uint8]nssai{5: {SST: 1, SD: "000001"}}, [][2]string{{"01", "000001"}}, false, false},
		{"empty falls back to sessions", nil,
			map[uint8]nssai{5: {SST: 1, SD: "000001"}, 6: {SST: 2, SD: "000002"}},
			[][2]string{{"01", "000001"}, {"02", "000002"}}, false, true},
		{"empty and no session S-NSSAI fails", nil, map[uint8]nssai{5: {}}, nil, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newXnHarness(t)
			h.ue.AllowedNSSAI = tc.allowed
			h.ue.PDUSessions = map[uint8]*amfctx.PDUSession{}
			var psis []uint8
			for id, sn := range tc.sessions {
				h.ue.PDUSessions[id] = &amfctx.PDUSession{PDUSessionID: id, SMFInstanceID: "x", SNSSAI: sn}
				psis = append(psis, id)
			}
			h.run(h.pathSwitch(7, psis...))
			sent := h.tgtLn.pdus()
			if len(sent) != 1 {
				t.Fatalf("PDUs = %d", len(sent))
			}
			if tc.wantFail {
				_, _, items := failureItems(t, sent[0].raw)
				c := items[5]
				if c.Present != ngapType.CausePresentMisc || c.Misc.Value != ngapType.CauseMiscPresentUnspecified {
					t.Fatalf("cause = %+v", c)
				}
				if h.ue.RANUENGAPId != 1 || h.tgt.UEs[7] != nil {
					t.Fatalf("UE rebound on failure")
				}
				return
			}
			ack, _ := ackIEs(t, sent[0].raw)
			var got [][2]string
			for _, ie := range ack.ProtocolIEs.List {
				if ie.Value.AllowedNSSAI != nil {
					for _, it := range ie.Value.AllowedNSSAI.List {
						got = append(got, [2]string{hexs(it.SNSSAI.SST.Value), hexs(it.SNSSAI.SD.Value)})
					}
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("nssai = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("nssai = %v, want %v", got, tc.want)
				}
			}
			r, ok := h.logs.find("Allowed NSSAI empty")
			if ok != tc.warn {
				t.Fatalf("fallback warn logged=%v want %v", ok, tc.warn)
			}
			if ok {
				if v, _ := recAttr(r, "allowed_nssai_fallback"); v != "pdu_sessions" || r.Level != slog.LevelWarn {
					t.Fatalf("fallback log wrong: %v %v", v, r.Level)
				}
			}
		})
	}
}

func hexs(b []byte) string {
	const d = "0123456789abcdef"
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte(d[x>>4])
		sb.WriteByte(d[x&15])
	}
	return sb.String()
}

func TestPathSwitch_PartialSuccess_UnknownPSIInReleasedList(t *testing.T) {
	h := newXnHarness(t)
	h.run(h.pathSwitch(7, 5, 11))
	ack, ies := ackIEs(t, h.tgtLn.pdus()[0].raw)
	if want := []int64{10, 85, 93, 77, 68, 0}; !equalIDs(idsOf(ies), want) {
		t.Fatalf("IE order = %v want %v", idsOf(ies), want)
	}
	sw := ack.ProtocolIEs.List[3].Value.PDUSessionResourceSwitchedList
	if len(sw.List) != 1 || sw.List[0].PDUSessionID.Value != 5 {
		t.Fatalf("switched list wrong")
	}
	rel := ack.ProtocolIEs.List[4].Value.PDUSessionResourceReleasedListPSAck
	if len(rel.List) != 1 || rel.List[0].PDUSessionID.Value != 11 {
		t.Fatalf("released list wrong")
	}
	var tr ngapType.PathSwitchRequestUnsuccessfulTransfer
	if err := aper.UnmarshalWithParams(rel.List[0].PathSwitchRequestUnsuccessfulTransfer, &tr, "valueExt"); err != nil {
		t.Fatal(err)
	}
	if tr.Cause.Present != ngapType.CausePresentRadioNetwork || tr.Cause.RadioNetwork.Value != ngapType.CauseRadioNetworkPresentUnknownPDUSessionID {
		t.Fatalf("cause = %+v", tr.Cause)
	}
}

func TestPathSwitch_UESecurityCapabilities(t *testing.T) {
	stored := UESecCapBitmaps{Enc: 0xC000, Int: 0xC000}
	tests := []struct {
		name    string
		req     *UESecCapBitmaps
		wantIE  bool
		wantWrn bool
	}{
		{"equal", &stored, false, false},
		{"equal ignoring bits beyond NEA3", &UESecCapBitmaps{Enc: 0xC00F, Int: 0xC000}, false, false},
		{"differ", &UESecCapBitmaps{Enc: 0xE000, Int: 0xC000}, true, true},
		{"absent", nil, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newXnHarness(t)
			req := h.pathSwitch(7, 5)
			req.UESecCap = tc.req
			h.run(req)
			ack, ies := ackIEs(t, h.tgtLn.pdus()[0].raw)
			want := []int64{10, 85, 93, 77, 0}
			if tc.wantIE {
				want = []int64{10, 85, 119, 93, 77, 0}
			}
			if !equalIDs(idsOf(ies), want) {
				t.Fatalf("IE order = %v want %v", idsOf(ies), want)
			}
			if tc.wantIE {
				c := ack.ProtocolIEs.List[2].Value.UESecurityCapabilities
				if bitmap16(c.NRencryptionAlgorithms.Value.Bytes) != stored.Enc || bitmap16(c.NRintegrityProtectionAlgorithms.Value.Bytes) != stored.Int {
					t.Fatalf("echoed capabilities != stored")
				}
				if ies[2].crit != ngapType.CriticalityPresentReject {
					t.Fatalf("IE 119 criticality")
				}
			}
			if r, ok := h.logs.find("differ from stored"); ok != tc.wantWrn || (ok && r.Level != slog.LevelWarn) {
				t.Fatalf("mismatch warn logged=%v", ok)
			}
		})
	}
}

func TestPathSwitch_Failures(t *testing.T) {
	radio := func(v aper.Enumerated) func(ngapType.Cause) bool {
		return func(c ngapType.Cause) bool {
			return c.Present == ngapType.CausePresentRadioNetwork && c.RadioNetwork.Value == v
		}
	}
	misc := func(c ngapType.Cause) bool {
		return c.Present == ngapType.CausePresentMisc && c.Misc.Value == ngapType.CauseMiscPresentUnspecified
	}
	tests := []struct {
		name      string
		setup     func(h *xnHarness)
		amfID     func(h *xnHarness) int64
		psis      []uint8
		want      map[int64]func(ngapType.Cause) bool
		wantLevel slog.Level
	}{
		{"unknown UE", nil, func(*xnHarness) int64 { return 4242 }, []uint8{5},
			map[int64]func(ngapType.Cause) bool{5: radio(ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID)}, slog.LevelWarn},
		{"unknown PSI only", nil, nil, []uint8{11},
			map[int64]func(ngapType.Cause) bool{11: radio(ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)}, slog.LevelWarn},
		{"duplicate PSI", nil, nil, []uint8{5, 5},
			map[int64]func(ngapType.Cause) bool{5: radio(ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)}, slog.LevelWarn},
		{"no KgNB", func(h *xnHarness) {
			h.ue.Lock()
			h.ue.NHValid = false
			h.ue.Unlock()
		}, nil, []uint8{5}, map[int64]func(ngapType.Cause) bool{5: misc}, slog.LevelError},
		{"zero KAMF", func(h *xnHarness) {
			h.ue.Lock()
			h.ue.SecurityCtx.KAMF = make([]byte, 32)
			h.ue.Unlock()
		}, nil, []uint8{5}, map[int64]func(ngapType.Cause) bool{5: misc}, slog.LevelError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newXnHarness(t)
			if tc.setup != nil {
				tc.setup(h)
			}
			amfID := h.amfID
			if tc.amfID != nil {
				amfID = tc.amfID(h)
			}
			_, nccBefore, _ := h.ue.NHState()
			h.run(h.pathSwitchFor(amfID, 7, tc.psis...))
			sent := h.tgtLn.pdus()
			if len(sent) != 1 || sent[0].ppid != 60 {
				t.Fatalf("sent=%d (want 1 failure, PPID 60)", len(sent))
			}
			gotAMF, gotRAN, items := failureItems(t, sent[0].raw)
			if gotAMF != amfID || gotRAN != 7 {
				t.Fatalf("echoed ids %d/%d", gotAMF, gotRAN)
			}
			for psi, ok := range tc.want {
				c, present := items[psi]
				if !present || !ok(c) {
					t.Fatalf("PSI %d cause = %+v", psi, c)
				}
			}
			if h.ue.RANUENGAPId != 1 || h.tgt.UEs[7] != nil || h.src.UEs[1] != h.ue {
				t.Fatalf("UE rebound on failure")
			}
			if n := len(h.srcLn.pdus()); n != 0 {
				t.Fatalf("source received %d PDUs", n)
			}
			if tc.name == "unknown PSI only" || tc.name == "duplicate PSI" {
				if _, ncc, _ := h.ue.NHState(); ncc != nccBefore {
					t.Fatalf("NH chain advanced on early reject")
				}
			}
			r, ok := h.logs.find("PathSwitchRequestFailure")
			if !ok || r.Level != tc.wantLevel {
				t.Fatalf("failure log missing/level %v", r.Level)
			}
			if v, _ := recAttr(r, "result"); v != "REJECT" {
				t.Fatalf("result = %v", v)
			}
			if v, _ := recAttr(r, "spec_ref"); v != "TS 38.413 §8.4.4.3" {
				t.Fatalf("spec_ref = %v", v)
			}
		})
	}
}

func TestPathSwitch_NeverLogsKeys(t *testing.T) {
	h := newXnHarness(t)
	h.run(h.pathSwitch(7, 5))
	nh := nhN(h.kamf, h.kgnb[:], 2)
	needles := []string{hexs(nh), hexs(h.kgnb[:])}
	h.logs.mu.Lock()
	defer h.logs.mu.Unlock()
	sawNCC := false
	for _, r := range h.logs.recs {
		r.Attrs(func(a slog.Attr) bool {
			s := a.Value.String()
			for _, n := range needles {
				if strings.Contains(strings.ToLower(s), n) {
					t.Errorf("key material in log attr %s", a.Key)
				}
			}
			if a.Key == "ncc" {
				sawNCC = true
			}
			return true
		})
	}
	if !sawNCC {
		t.Errorf("ncc not logged")
	}
}

// ---- builders ---------------------------------------------------------------------

func TestBuildPathSwitchAck_RequiresMandatoryIEs(t *testing.T) {
	sw := []PDUSessionSwitchItem{{PDUSessionID: 5}}
	nssai := []amfctx.SNSSAISubscribed{{SST: 1}}
	if BuildPathSwitchRequestAcknowledge(PathSwitchAckParams{Switched: sw}) != nil {
		t.Errorf("built without Allowed NSSAI")
	}
	if BuildPathSwitchRequestAcknowledge(PathSwitchAckParams{AllowedNSSAI: nssai}) != nil {
		t.Errorf("built without switched sessions")
	}
	if BuildPathSwitchRequestAcknowledge(PathSwitchAckParams{Switched: sw, AllowedNSSAI: nssai, NCC: 3}) == nil {
		t.Errorf("did not build a complete ack")
	}
}

func TestBuildPathSwitchFailure_EmptyList(t *testing.T) {
	if BuildPathSwitchRequestFailure(1, 2, nil) != nil {
		t.Fatalf("built with empty released list (IE 69 is SIZE 1..)")
	}
}

func TestExtractPathSwitchRequest_Decodes(t *testing.T) {
	plmn := plmnFromMCCMNC("001", "01")
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePathSwitchRequest},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentPathSwitchRequest,
				PathSwitchRequest: &ngapType.PathSwitchRequest{ProtocolIEs: ngapType.ProtocolIEContainerPathSwitchRequestIEs{List: []ngapType.PathSwitchRequestIEs{
					{Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
						Value: ngapType.PathSwitchRequestIEsValue{Present: ngapType.PathSwitchRequestIEsPresentRANUENGAPID, RANUENGAPID: &ngapType.RANUENGAPID{Value: 7}}},
					{Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDSourceAMFUENGAPID}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
						Value: ngapType.PathSwitchRequestIEsValue{Present: ngapType.PathSwitchRequestIEsPresentSourceAMFUENGAPID, SourceAMFUENGAPID: &ngapType.AMFUENGAPID{Value: 3}}},
					{Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUserLocationInformation}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
						Value: ngapType.PathSwitchRequestIEsValue{Present: ngapType.PathSwitchRequestIEsPresentUserLocationInformation,
							UserLocationInformation: &ngapType.UserLocationInformation{
								Present: ngapType.UserLocationInformationPresentUserLocationInformationNR,
								UserLocationInformationNR: &ngapType.UserLocationInformationNR{
									NRCGI: ngapType.NRCGI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmn},
										NRCellIdentity: ngapType.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0, 0, 0, 1, 0}, BitLength: 36}}},
									TAI: ngapType.TAI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmn}, TAC: ngapType.TAC{Value: aper.OctetString{0, 0, 9}}},
								}}}},
					{Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUESecurityCapabilities}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
						Value: ngapType.PathSwitchRequestIEsValue{Present: ngapType.PathSwitchRequestIEsPresentUESecurityCapabilities,
							UESecurityCapabilities: buildUESecurityCapabilities(0xE000, 0xC000)}},
					{Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceToBeSwitchedDLList}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
						Value: ngapType.PathSwitchRequestIEsValue{Present: ngapType.PathSwitchRequestIEsPresentPDUSessionResourceToBeSwitchedDLList,
							PDUSessionResourceToBeSwitchedDLList: &ngapType.PDUSessionResourceToBeSwitchedDLList{List: []ngapType.PDUSessionResourceToBeSwitchedDLItem{
								{PDUSessionID: ngapType.PDUSessionID{Value: 5}, PathSwitchRequestTransfer: aper.OctetString{1}}}}}},
					{Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListPSReq}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
						Value: ngapType.PathSwitchRequestIEsValue{Present: ngapType.PathSwitchRequestIEsPresentPDUSessionResourceFailedToSetupListPSReq,
							PDUSessionResourceFailedToSetupListPSReq: &ngapType.PDUSessionResourceFailedToSetupListPSReq{List: []ngapType.PDUSessionResourceFailedToSetupItemPSReq{
								{PDUSessionID: ngapType.PDUSessionID{Value: 6}, PathSwitchRequestSetupFailedTransfer: aper.OctetString{2}}}}}},
				}}},
			},
		},
	}
	raw, err := libngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := buildMessage(dec).Value.(*PathSwitchRequestMsg)
	if m.RANUENGAPId != 7 || m.SourceAMFUENGAPId != 3 || len(m.PDUSessions) != 1 || m.PDUSessions[0].PDUSessionID != 5 {
		t.Fatalf("basic fields wrong: %+v", m)
	}
	if m.TAI == nil || m.TAI.TAC != 9 || m.TAI.MCC != "001" {
		t.Fatalf("TAI = %+v", m.TAI)
	}
	if m.UESecCap == nil || m.UESecCap.Enc != 0xE000 || m.UESecCap.Int != 0xC000 {
		t.Fatalf("UESecCap = %+v", m.UESecCap)
	}
	if len(m.FailedToSetup) != 1 || m.FailedToSetup[0].PDUSessionID != 6 {
		t.Fatalf("failed list = %+v", m.FailedToSetup)
	}
}

// ---- N2 handover legs ----------------------------------------------------------------

func handoverRequestIEs(t *testing.T, raw []byte) (*ngapType.HandoverRequest, map[int64]ngapType.HandoverRequestIEs) {
	t.Helper()
	pdu, err := libngap.Decoder(raw)
	if err != nil || pdu.InitiatingMessage == nil || pdu.InitiatingMessage.Value.HandoverRequest == nil {
		t.Fatalf("not a HandoverRequest (err=%v)", err)
	}
	hr := pdu.InitiatingMessage.Value.HandoverRequest
	m := map[int64]ngapType.HandoverRequestIEs{}
	for _, ie := range hr.ProtocolIEs.List {
		m[ie.Id.Value] = ie
	}
	return hr, m
}

func hoSessions() []PDUSessionHOReqItem {
	return []PDUSessionHOReqItem{{PDUSessionID: 5, SNSSAI: amfctx.SNSSAISubscribed{SST: 1}, HandoverRequestTransfer: []byte{0xAA}}}
}

func buildHR(ambr *UEAMBR) []byte {
	return BuildHandoverRequest(1, 0, ngapType.CausePresentRadioNetwork, 0, ambr, 2, [32]byte{1},
		0xE000, 0xE000, hoSessions(), []amfctx.SNSSAISubscribed{{SST: 1}, {SST: 1}}, []byte{1}, "001", "01", 1, 1, 1)
}

func TestBuildHandoverRequest_UEAMBR(t *testing.T) {
	tests := []struct {
		name     string
		ambr     *UEAMBR
		ul, dl   int64
		critical bool
	}{
		{"subscribed", NewUEAMBRFromKbps(200000, 500000), 200_000_000, 500_000_000, true},
		{"large subscribed", NewUEAMBRFromKbps(2_000_000, 4_000_000), 2_000_000_000, 4_000_000_000, true},
		{"zero falls back to default", NewUEAMBRFromKbps(0, 0), DefaultUEAMBRBps, DefaultUEAMBRBps, true},
		{"nil falls back to default", nil, DefaultUEAMBRBps, DefaultUEAMBRBps, true},
		{"one direction unknown", NewUEAMBRFromKbps(0, 500000), DefaultUEAMBRBps, 500_000_000, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ies := handoverRequestIEs(t, buildHR(tc.ambr))
			ie, ok := ies[110]
			if !ok || ie.Criticality.Value != ngapType.CriticalityPresentReject {
				t.Fatalf("IE 110 missing / criticality")
			}
			a := ie.Value.UEAggregateMaximumBitRate
			if a.UEAggregateMaximumBitRateUL.Value != tc.ul || a.UEAggregateMaximumBitRateDL.Value != tc.dl {
				t.Fatalf("ambr = %d/%d, want %d/%d", a.UEAggregateMaximumBitRateUL.Value, a.UEAggregateMaximumBitRateDL.Value, tc.ul, tc.dl)
			}
		})
	}
}

func TestBuildHandoverRequest_SecurityContextAndNSSAIDedupe(t *testing.T) {
	_, ies := handoverRequestIEs(t, buildHR(nil))
	sc := ies[93].Value.SecurityContext
	if sc.NextHopChainingCount.Value != 2 || sc.NextHopNH.Value.BitLength != 256 {
		t.Fatalf("security context wrong")
	}
	if n := len(ies[0].Value.AllowedNSSAI.List); n != 1 {
		t.Fatalf("allowed NSSAI items = %d, want 1 (deduped)", n)
	}
}

func TestN2Handover_ChainPPIDAndAMBR(t *testing.T) {
	h := newXnHarness(t)
	// An Xn hop first: the N2 HANDOVER REQUEST must continue the chain at NCC 3.
	h.run(h.pathSwitch(7, 5))
	h.srv.gnbs["10.0.0.2:1"].UEs = map[int64]*amfctx.UEContext{}
	h.ue.Lock()
	h.ue.SubscribedAMBR.UL, h.ue.SubscribedAMBR.DL = 200000, 500000
	h.ue.Unlock()
	h.tgtLn.sent = nil

	h.srv.HandleHandoverRequiredForTest(context.Background(), h.src, &HandoverRequiredMsg{
		AMFUENGAPId: h.amfID, RANUENGAPId: 7, TargetGlobalRANNodeID: h.tgt.GlobalGNBID,
		SourceToTargetTransparentContainer: []byte{9},
	})
	sent := h.tgtLn.pdus()
	if len(sent) != 1 || sent[0].ppid != 60 {
		t.Fatalf("HandoverRequest sent=%d", len(sent))
	}
	_, ies := handoverRequestIEs(t, sent[0].raw)
	sc := ies[93].Value.SecurityContext
	if sc.NextHopChainingCount.Value != 3 || !bytes.Equal(sc.NextHopNH.Value.Bytes, nhN(h.kamf, h.kgnb[:], 3)) {
		t.Fatalf("HO request does not continue the NH chain (ncc=%d)", sc.NextHopChainingCount.Value)
	}
	if a := ies[110].Value.UEAggregateMaximumBitRate; a.UEAggregateMaximumBitRateUL.Value != 200_000_000 || a.UEAggregateMaximumBitRateDL.Value != 500_000_000 {
		t.Fatalf("UE-AMBR not the subscribed value")
	}

	h.srv.HandleHandoverRequestAcknowledgeForTest(context.Background(), h.tgt, &HandoverRequestAckMsg{
		AMFUENGAPId: h.amfID, RANUENGAPId: 8, TargetToSourceTransparentContainer: []byte{7},
	})
	srcSent := h.srcLn.pdus()
	if len(srcSent) != 1 || srcSent[0].ppid != 60 {
		t.Fatalf("HandoverCommand sent=%d", len(srcSent))
	}
}

func TestN2Handover_NoSecurityContext_NoRequest(t *testing.T) {
	h := newXnHarness(t)
	h.ue.Lock()
	h.ue.NHValid = false
	h.ue.Unlock()
	h.srv.HandleHandoverRequiredForTest(context.Background(), h.src, &HandoverRequiredMsg{
		AMFUENGAPId: h.amfID, RANUENGAPId: 1, TargetGlobalRANNodeID: h.tgt.GlobalGNBID,
	})
	if n := len(h.tgtLn.pdus()); n != 0 {
		t.Fatalf("HandoverRequest sent without a usable security context")
	}
	if n := len(h.srcLn.pdus()); n != 1 {
		t.Fatalf("HandoverPreparationFailure not sent to source gNB (n=%d)", n)
	}
}

// TestBuildHandoverRequest_IEOrder asserts the decoded IE ids follow the ASN.1
// HandoverRequestIEs order (TS 38.413 Table 9.2.3.4-1).
func TestBuildHandoverRequest_IEOrder(t *testing.T) {
	hr, _ := handoverRequestIEs(t, buildHR(nil))
	want := []int64{10, 29, 15, 110, 119, 93, 73, 0, 101, 28}
	var got []int64
	for _, ie := range hr.ProtocolIEs.List {
		got = append(got, ie.Id.Value)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("IE order = %v, want %v", got, want)
	}
}

func TestBuildHandoverRequest_MissingMandatoryIE(t *testing.T) {
	nssai := []amfctx.SNSSAISubscribed{{SST: 1}}
	tests := []struct {
		name string
		ses  []PDUSessionHOReqItem
		n    []amfctx.SNSSAISubscribed
		c    []byte
	}{
		{"no sessions", nil, nssai, []byte{1}},
		{"no allowed nssai", hoSessions(), nil, []byte{1}},
		{"no container", hoSessions(), nssai, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if b := BuildHandoverRequest(1, 0, ngapType.CausePresentRadioNetwork, 0, nil, 1, [32]byte{},
				0, 0, tc.ses, tc.n, tc.c, "001", "01", 1, 1, 1); b != nil {
				t.Fatalf("expected nil for missing mandatory IE")
			}
		})
	}
}

// TestBuildHandoverCommand_IEOrder asserts TS 38.413 Table 9.2.3.2-1 order.
func TestBuildHandoverCommand_IEOrder(t *testing.T) {
	raw := BuildHandoverCommand(1, 2, 0, []PDUSessionHOCmdItem{{PDUSessionID: 5}}, nil, []byte{7})
	pdu, err := libngap.Decoder(raw)
	if err != nil || pdu.SuccessfulOutcome == nil || pdu.SuccessfulOutcome.Value.HandoverCommand == nil {
		t.Fatalf("not a HandoverCommand (err=%v)", err)
	}
	var got []int64
	for _, ie := range pdu.SuccessfulOutcome.Value.HandoverCommand.ProtocolIEs.List {
		got = append(got, ie.Id.Value)
	}
	want := []int64{10, 85, 29, 59, 106}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("IE order = %v, want %v", got, want)
	}
}

func TestBuildHandoverPreparationFailure(t *testing.T) {
	raw := BuildHandoverPreparationFailure(1, 2, ngapType.CausePresentMisc, int64(ngapType.CauseMiscPresentUnspecified))
	pdu, err := libngap.Decoder(raw)
	if err != nil || pdu.UnsuccessfulOutcome == nil || pdu.UnsuccessfulOutcome.Value.HandoverPreparationFailure == nil {
		t.Fatalf("not a HandoverPreparationFailure (err=%v)", err)
	}
	var got []int64
	for _, ie := range pdu.UnsuccessfulOutcome.Value.HandoverPreparationFailure.ProtocolIEs.List {
		got = append(got, ie.Id.Value)
	}
	if fmt.Sprint(got) != "[10 85 15]" {
		t.Fatalf("IEs = %v", got)
	}
}
