package ngap

// ng_reset_test.go — NG Reset (NG-RAN initiated): ACK codec and UE-associated release.
// Ref: TS 38.413 §8.7.4.2.2, §9.2.6.11, §9.2.6.12

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

func i64(v int64) *int64 { return &v }

// TestNGResetAcknowledgeRoundTrip covers both ACK variants (reset-all: no list; partial:
// echoed list incl. partially-present and omitted-empty items) plus the diagnostics order.
func TestNGResetAcknowledgeRoundTrip(t *testing.T) {
	cd := BuildCriticalityDiagnostics(CriticalityDiagnosticsParams{})
	tests := []struct {
		name     string
		items    []ResetItem
		cd       bool
		wantIDs  []int64
		wantList []ResetItem
	}{
		{"reset-all no list", nil, false, nil, nil},
		{"partial echoes order and presence",
			[]ResetItem{{i64(1), i64(10)}, {AMF: i64(999)}, {RAN: i64(888)}}, false,
			[]int64{ngapType.ProtocolIEIDUEAssociatedLogicalNGConnectionList},
			[]ResetItem{{i64(1), i64(10)}, {AMF: i64(999)}, {RAN: i64(888)}}},
		{"empty item omitted, list absent when nothing remains", []ResetItem{{}}, false, nil, nil},
		{"list then diagnostics",
			[]ResetItem{{AMF: i64(5)}}, true,
			[]int64{ngapType.ProtocolIEIDUEAssociatedLogicalNGConnectionList, ngapType.ProtocolIEIDCriticalityDiagnostics},
			[]ResetItem{{AMF: i64(5)}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c *ngapType.CriticalityDiagnostics
			if tc.cd {
				c = &cd
			}
			b, err := BuildNGResetAcknowledge(tc.items, c)
			if err != nil {
				t.Fatal(err)
			}
			v, ok, err := DecodeNGResetAckForTest(b)
			if err != nil || !ok {
				t.Fatalf("decode ok=%v err=%v", ok, err)
			}
			if v.ProcedureCode != ngapType.ProcedureCodeNGReset {
				t.Errorf("procedure code %d", v.ProcedureCode)
			}
			if len(v.IEIDs) != len(tc.wantIDs) {
				t.Fatalf("IE ids %v, want %v", v.IEIDs, tc.wantIDs)
			}
			for i := range tc.wantIDs {
				if v.IEIDs[i] != tc.wantIDs[i] {
					t.Fatalf("IE order %v, want %v", v.IEIDs, tc.wantIDs)
				}
			}
			if !itemsEqual(v.Items, tc.wantList) {
				t.Errorf("items mismatch: got %+v want %+v", v.Items, tc.wantList)
			}
		})
	}
}

func itemsEqual(a, b []ResetItem) bool {
	if len(a) != len(b) {
		return false
	}
	eq := func(x, y *int64) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	for i := range a {
		if !eq(a[i].AMF, b[i].AMF) || !eq(a[i].RAN, b[i].RAN) {
			return false
		}
	}
	return true
}

type resetHarness struct {
	srv      *Server
	gnbA     *GNBContext
	gnbB     *GNBContext
	mu       sync.Mutex
	outA     [][]byte
	ppids    []uint32
	anCalled map[string]int
}

func newResetHarness(t *testing.T) *resetHarness {
	t.Helper()
	h := &resetHarness{anCalled: map[string]int{}}
	mgr := amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	h.srv = NewServer("", mgr, nil, AMFConfig{}, slog.Default())
	h.srv.SetANReleaseHandler(func(_ context.Context, ue *amfctx.UEContext) {
		h.mu.Lock()
		h.anCalled[ue.SUPI]++
		h.mu.Unlock()
	})
	mk := func(name string, out *[][]byte) *GNBContext {
		g := &GNBContext{Name: name, UEs: map[int64]*amfctx.UEContext{}, IdleUEs: map[int64]*amfctx.UEContext{}, State: GNBStateNGReady}
		g.SetTransportForTest(name+":38412", func(pdu []byte, info *sctp.SndRcvInfo) (int, error) {
			h.mu.Lock()
			if out != nil {
				*out = append(*out, append([]byte{}, pdu...))
				h.ppids = append(h.ppids, info.PPID)
			}
			h.mu.Unlock()
			return len(pdu), nil
		})
		return g
	}
	h.gnbA = mk("gnb-a", &h.outA)
	h.gnbB = mk("gnb-b", nil)
	return h
}

func (h *resetHarness) addUE(g *GNBContext, ran int64, supi string) *amfctx.UEContext {
	ue := h.srv.mgr.AllocateUEContext(ran)
	ue.SUPI = supi
	ue.State = amfctx.GMMRegistered
	ue.CMState = amfctx.CMConnected
	ue.GNBAddr = g.remoteAddrString()
	ue.PDUSessions = map[uint8]*amfctx.PDUSession{1: {}}
	g.UEs[ran] = ue
	return ue
}

func (h *resetHarness) reset(t *testing.T, p NGResetParams) {
	t.Helper()
	pdu, err := BuildNGResetForTest(p)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.DispatchNGAPForTest(context.Background(), h.gnbA, pdu)
	h.srv.mgr.ListContexts() // no-op barrier
}

func (h *resetHarness) waitSMF(t *testing.T, ues ...*amfctx.UEContext) {
	for _, ue := range ues {
		h.srv.WaitUESerialForTest(ue.AMFUENGAPId)
	}
}

// waitQueue blocks until everything queued on the UE's serial queue so far has run (also for
// a UE already removed from the manager, which WaitUESerialForTest cannot resolve).
func (h *resetHarness) waitQueue(ue *amfctx.UEContext) {
	done := make(chan struct{})
	ue.EnqueueSerial(func() { close(done) })
	<-done
}

func (h *resetHarness) ack(t *testing.T) NGResetAckView {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.outA) != 1 {
		t.Fatalf("expected exactly 1 outbound PDU, got %d", len(h.outA))
	}
	if h.ppids[0] != 60 {
		t.Errorf("PPID %d, want 60", h.ppids[0])
	}
	v, ok, err := DecodeNGResetAckForTest(h.outA[0])
	if err != nil || !ok {
		t.Fatalf("not an NG RESET ACKNOWLEDGE: ok=%v err=%v", ok, err)
	}
	return v
}

func cm(ue *amfctx.UEContext) amfctx.CMState {
	ue.Lock()
	defer ue.Unlock()
	return ue.CMState
}

func TestNGResetAllReleasesOnlyThisGNB(t *testing.T) {
	h := newResetHarness(t)
	u1 := h.addUE(h.gnbA, 10, "imsi-1")
	u2 := h.addUE(h.gnbA, 11, "imsi-2")
	u3 := h.addUE(h.gnbB, 12, "imsi-3")
	h.reset(t, NGResetParams{ResetAll: true})
	h.waitSMF(t, u1, u2)

	v := h.ack(t)
	if v.HasList {
		t.Error("reset-all ACK must not carry the UE list")
	}
	if cm(u1) != amfctx.CMIdle || cm(u2) != amfctx.CMIdle {
		t.Error("UEs of the gNB must be CM-IDLE")
	}
	if cm(u3) != amfctx.CMConnected {
		t.Error("UE of the other gNB must stay CM-CONNECTED")
	}
	if len(h.gnbA.UEs) != 0 || len(h.gnbA.IdleUEs) != 2 || len(h.gnbB.UEs) != 1 {
		t.Errorf("registry A.UEs=%d A.Idle=%d B.UEs=%d", len(h.gnbA.UEs), len(h.gnbA.IdleUEs), len(h.gnbB.UEs))
	}
	if h.anCalled["imsi-1"] != 1 || h.anCalled["imsi-2"] != 1 || h.anCalled["imsi-3"] != 0 {
		t.Errorf("onANRelease calls: %v", h.anCalled)
	}
	if h.gnbA.NGResetCount != 1 || h.gnbA.State != GNBStateNGReady {
		t.Errorf("registry count=%d state=%v", h.gnbA.NGResetCount, h.gnbA.State)
	}
	if _, ok := h.srv.mgr.GetByNGAPId(u1.AMFUENGAPId); !ok {
		t.Error("UE context must remain")
	}
}

func TestNGResetPartialReleasesOnlyListedAndEchoes(t *testing.T) {
	h := newResetHarness(t)
	u1 := h.addUE(h.gnbA, 10, "imsi-1")
	u2 := h.addUE(h.gnbA, 11, "imsi-2")
	u3 := h.addUE(h.gnbA, 12, "imsi-3")
	other := h.addUE(h.gnbB, 13, "imsi-4")
	items := []ResetItem{
		{AMF: i64(u1.AMFUENGAPId), RAN: i64(10)},
		{AMF: i64(999999)},
		{RAN: i64(11)},
		{AMF: i64(other.AMFUENGAPId)}, // served by another gNB: unknown here
	}
	h.reset(t, NGResetParams{Items: items})
	h.waitSMF(t, u1, u2)

	v := h.ack(t)
	if !itemsEqual(v.Items, items) {
		t.Errorf("echoed items %+v, want %+v", v.Items, items)
	}
	if cm(u1) != amfctx.CMIdle || cm(u2) != amfctx.CMIdle {
		t.Error("listed UEs must be CM-IDLE")
	}
	if cm(u3) != amfctx.CMConnected || cm(other) != amfctx.CMConnected {
		t.Error("unlisted / other-gNB UEs must stay CM-CONNECTED")
	}
	if h.anCalled["imsi-3"] != 0 || h.anCalled["imsi-4"] != 0 {
		t.Errorf("SMF notified for unlisted UE: %v", h.anCalled)
	}
}

func TestNGResetIdempotentAndEmptyItem(t *testing.T) {
	h := newResetHarness(t)
	u1 := h.addUE(h.gnbA, 10, "imsi-1")
	h.reset(t, NGResetParams{Items: []ResetItem{{}}})
	if v := h.ack(t); v.HasList {
		t.Error("empty item must be omitted from the ACK")
	}
	if cm(u1) != amfctx.CMConnected {
		t.Error("nothing must be released for an empty item")
	}
	h.mu.Lock()
	h.outA, h.ppids = nil, nil
	h.mu.Unlock()
	items := []ResetItem{{AMF: i64(u1.AMFUENGAPId), RAN: i64(10)}}
	h.reset(t, NGResetParams{Items: items})
	h.reset(t, NGResetParams{Items: items}) // retry: IDs now unknown, still acknowledged
	h.mu.Lock()
	n := len(h.outA)
	h.mu.Unlock()
	if n != 2 {
		t.Fatalf("want 2 ACKs, got %d", n)
	}
	h.waitSMF(t, u1)
	if h.anCalled["imsi-1"] != 1 {
		t.Errorf("SMF notified %d times, want once", h.anCalled["imsi-1"])
	}
}

func TestNGResetPendingRemovalAndMissingResetType(t *testing.T) {
	h := newResetHarness(t)
	u1 := h.addUE(h.gnbA, 10, "imsi-1")
	u1.PendingRemoval = true
	h.reset(t, NGResetParams{ResetAll: true})
	h.ack(t)
	h.waitQueue(u1) // deterministic: nothing may have been queued toward the SMF
	if _, ok := h.srv.mgr.GetByNGAPId(u1.AMFUENGAPId); ok {
		t.Error("pending-removal UE must be removed")
	}
	if h.anCalled["imsi-1"] != 0 {
		t.Error("no SMF deactivation for a pending deregistration")
	}

	h2 := newResetHarness(t)
	u2 := h2.addUE(h2.gnbA, 10, "imsi-2")
	h2.reset(t, NGResetParams{OmitResetType: true})
	h2.mu.Lock()
	defer h2.mu.Unlock()
	if len(h2.outA) != 1 {
		t.Fatalf("want 1 PDU (ERROR INDICATION), got %d", len(h2.outA))
	}
	if _, isAck, _ := DecodeNGResetAckForTest(h2.outA[0]); isAck {
		t.Error("missing Reset Type must not be acknowledged")
	}
	if cm(u2) != amfctx.CMConnected || h2.gnbA.NGResetCount != 0 {
		t.Error("nothing released and counter unchanged on missing IE 88")
	}
}

// TestNGResetStaleSourceAfterN2Handover: after a completed N2 HO the source gNB still lists
// the UE (until its release complete). A reset from the source must only drop that stale
// entry: the UE stays CM-CONNECTED on the target, no SMF deactivation, no idle registration.
func TestNGResetStaleSourceAfterN2Handover(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(ue *amfctx.UEContext, target *GNBContext)
	}{
		{"UE moved to another gNB", func(ue *amfctx.UEContext, target *GNBContext) {
			ue.GNBAddr = target.remoteAddrString()
			ue.RANUENGAPId = 55
		}},
		{"same address, other RAN UE NGAP ID", func(ue *amfctx.UEContext, _ *GNBContext) {
			ue.RANUENGAPId = 56
		}},
	}
	for _, tc := range tests {
		for _, resetAll := range []bool{true, false} {
			t.Run(tc.name, func(t *testing.T) {
				h := newResetHarness(t)
				ue := h.addUE(h.gnbA, 10, "imsi-1") // stale entry on the source gNB (A)
				ue.Lock()
				tc.mutate(ue, h.gnbB)
				ue.Unlock()
				p := NGResetParams{ResetAll: resetAll}
				if !resetAll {
					p.Items = []ResetItem{{AMF: i64(ue.AMFUENGAPId), RAN: i64(10)}}
				}
				h.reset(t, p)
				h.ack(t)
				h.waitQueue(ue)
				if cm(ue) != amfctx.CMConnected {
					t.Error("UE served elsewhere must stay CM-CONNECTED")
				}
				if h.anCalled["imsi-1"] != 0 {
					t.Error("no SMF deactivation for a stale source entry")
				}
				if len(h.gnbA.UEs) != 0 || len(h.gnbA.IdleUEs) != 0 {
					t.Errorf("stale entry must be dropped without idle registration: UEs=%d Idle=%d",
						len(h.gnbA.UEs), len(h.gnbA.IdleUEs))
				}
				ue.Lock()
				timer := ue.MobileReachableTimer
				ue.Unlock()
				if timer != nil {
					t.Error("mobile reachable timer must not start")
				}
			})
		}
	}
}

// TestNGResetAbortsHandoverOfTargetByBothIDs: a partial reset of the target gNB aborts the
// prepared N2 HO only when the item matches the target RAN UE NGAP ID too.
func TestNGResetAbortsHandoverOfTargetByBothIDs(t *testing.T) {
	tests := []struct {
		name      string
		item      func(amf int64) ResetItem
		wantAbort bool
	}{
		{"AMF and target RAN match", func(a int64) ResetItem { return ResetItem{AMF: i64(a), RAN: i64(77)} }, true},
		{"AMF matches, other RAN ID", func(a int64) ResetItem { return ResetItem{AMF: i64(a), RAN: i64(99)} }, false},
		{"RAN only, matching", func(int64) ResetItem { return ResetItem{RAN: i64(77)} }, true},
		{"RAN only, other", func(int64) ResetItem { return ResetItem{RAN: i64(78)} }, false},
		{"AMF only, matching", func(a int64) ResetItem { return ResetItem{AMF: i64(a)} }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newResetHarness(t)
			ue := h.addUE(h.gnbB, 10, "imsi-1") // source gNB B, target is gNB A
			h.srv.pendingN2HOMu.Lock()
			h.srv.pendingN2HO[ue.AMFUENGAPId] = &n2HandoverState{
				sourceGNB: h.gnbB, sourceRANUENGAPId: 10, targetGNB: h.gnbA, targetRANUENGAPId: 77}
			h.srv.pendingN2HOMu.Unlock()
			h.reset(t, NGResetParams{Items: []ResetItem{tc.item(ue.AMFUENGAPId)}})
			h.srv.pendingN2HOMu.Lock()
			_, still := h.srv.pendingN2HO[ue.AMFUENGAPId]
			h.srv.pendingN2HOMu.Unlock()
			if still == tc.wantAbort {
				t.Errorf("pending HO present=%v, wantAbort=%v", still, tc.wantAbort)
			}
		})
	}
}

// TestNGResetUnknownResetTypeErrorIndication: a Reset Type choice-Extensions alternative is
// answered with ERROR INDICATION abstract-syntax-error-reject plus Criticality Diagnostics
// (procedure code 20, initiating message, procedure criticality reject, IE 88).
func TestNGResetUnknownResetTypeErrorIndication(t *testing.T) {
	h := newResetHarness(t)
	u := h.addUE(h.gnbA, 10, "imsi-1")
	pdu := []byte{0x00, 0x14, 0x00, 0x0c, 0x00, 0x00, 0x01,
		0x00, 0x58, 0x00, 0x05, 0x80, 0x00, 0x01, 0x40, 0x00}
	h.srv.DispatchNGAPForTest(context.Background(), h.gnbA, pdu)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.outA) != 1 {
		t.Fatalf("want 1 PDU, got %d", len(h.outA))
	}
	p, err := libngap.Decoder(h.outA[0])
	if err != nil || p.InitiatingMessage == nil || p.InitiatingMessage.Value.ErrorIndication == nil {
		t.Fatalf("not an ERROR INDICATION: %v", err)
	}
	var cause *ngapType.Cause
	var cd *ngapType.CriticalityDiagnostics
	for _, ie := range p.InitiatingMessage.Value.ErrorIndication.ProtocolIEs.List {
		cause, cd = pick(cause, ie.Value.Cause), pickCD(cd, ie.Value.CriticalityDiagnostics)
	}
	if cause == nil || cause.Protocol == nil ||
		cause.Protocol.Value != ngapType.CauseProtocolPresentAbstractSyntaxErrorReject {
		t.Errorf("cause %+v, want protocol abstract-syntax-error-reject", cause)
	}
	if cd == nil || cd.ProcedureCode == nil || cd.ProcedureCode.Value != ngapType.ProcedureCodeNGReset ||
		cd.TriggeringMessage == nil || cd.TriggeringMessage.Value != ngapType.TriggeringMessagePresentInitiatingMessage ||
		cd.ProcedureCriticality == nil || cd.ProcedureCriticality.Value != ngapType.CriticalityPresentReject ||
		cd.IEsCriticalityDiagnostics == nil || len(cd.IEsCriticalityDiagnostics.List) != 1 ||
		cd.IEsCriticalityDiagnostics.List[0].IEID.Value != ngapType.ProtocolIEIDResetType {
		t.Errorf("criticality diagnostics %+v", cd)
	}
	if cm(u) != amfctx.CMConnected {
		t.Error("nothing may be released")
	}
}

func pick(old, v *ngapType.Cause) *ngapType.Cause {
	if v != nil {
		return v
	}
	return old
}

func pickCD(old, v *ngapType.CriticalityDiagnostics) *ngapType.CriticalityDiagnostics {
	if v != nil {
		return v
	}
	return old
}

// TestNGResetReleasedPairRejectsUplinkNAS: after an NG RESET the old (AMF, RAN) UE NGAP ID
// pair is not a live association; an UPLINK NAS TRANSPORT on it gets an ERROR INDICATION
// (unknown-local-UE-NGAP-ID, TS 38.413 §10.6), no NAS is processed, no DL message is sent
// and the registered UE stays CM-IDLE with its PDU sessions.
func TestNGResetReleasedPairRejectsUplinkNAS(t *testing.T) {
	h := newResetHarness(t)
	ue := h.addUE(h.gnbA, 10, "imsi-1")
	amfID := ue.AMFUENGAPId
	h.reset(t, NGResetParams{ResetAll: true})
	h.ack(t)
	h.waitQueue(ue)
	if cm(ue) != amfctx.CMIdle {
		t.Fatal("UE must be CM-IDLE after reset")
	}
	h.srv.HandleUplinkNASTransportForTest(context.Background(), h.gnbA,
		&UplinkNASTransport{AMFUENGAPId: amfID, RANUENGAPId: 10, NASPdu: []byte{0x7e, 0x00, 0x41}})
	h.waitQueue(ue)

	h.mu.Lock()
	if len(h.outA) != 2 {
		t.Fatalf("want ACK + 1 ERROR INDICATION, got %d PDUs", len(h.outA))
	}
	ei, ok, err := DecodeOutboundErrorIndicationForTest(h.outA[1])
	h.mu.Unlock()
	if err != nil || !ok {
		t.Fatalf("second PDU is not an ERROR INDICATION: ok=%v err=%v", ok, err)
	}
	if ei.CausePresent != ngapType.CausePresentRadioNetwork ||
		ei.CauseValue != int64(ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID) {
		t.Errorf("cause %d/%d, want radioNetwork unknown-local-UE-NGAP-ID", ei.CausePresent, ei.CauseValue)
	}
	ue.Lock()
	state, npdu := ue.State, len(ue.PDUSessions)
	ue.Unlock()
	if cm(ue) != amfctx.CMIdle || state != amfctx.GMMRegistered || npdu != 1 {
		t.Errorf("UE must stay CM-IDLE/REGISTERED with sessions: cm=%v state=%v pdu=%d", cm(ue), state, npdu)
	}
	if _, still := h.srv.mgr.GetByNGAPId(amfID); !still {
		t.Error("registered UE must not be released locally")
	}
	if !h.gnbA.isReleasedAssociation(10, ue) {
		t.Error("reset pair must be reported as released")
	}
	// A fresh INITIAL UE MESSAGE / ICS re-registers the pair (ngap.go: gnb.UEs[ran] = ue).
	h.gnbA.mu.Lock()
	h.gnbA.UEs[11] = ue
	delete(h.gnbA.IdleUEs, 10) // promotion done by handleInitialUEMessage (ngap.go:~1805)
	h.gnbA.mu.Unlock()
	if h.gnbA.isReleasedAssociation(11, ue) || h.gnbA.isReleasedAssociation(10, ue) {
		t.Error("re-associated UE must not be treated as released")
	}
}
