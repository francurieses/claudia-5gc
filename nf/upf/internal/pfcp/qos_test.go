package pfcp

// qos_test.go — AmbrEnforcement (UPF-005): multi-QER provisioning over real
// PFCP/UDP, validation (cause 66/73/65, no partial application), the enforcement
// snapshot and the admission hooks, with a controllable enforcement clock.
// Ref: TS 29.244 §5.2.5, §5.4.3, §5.4.4, §7.5.2.2, §7.5.2.5, §7.5.4.2,
// §7.5.4.5, §7.5.4.9, §8.2.1, §8.2.80; TS 23.501 §5.7.1.8.

import (
	"net"
	"sync/atomic"
	"testing"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

const msNs = int64(1_000_000)

// fakeClock is the injected enforcement clock.
type fakeClock struct{ ns atomic.Int64 }

func (c *fakeClock) Now() int64         { return c.ns.Load() }
func (c *fakeClock) AdvanceMs(ms int64) { c.ns.Add(ms * msNs) }

type qosHarness struct {
	t     *testing.T
	srv   *Server
	table *SessionTable
	addr  *net.UDPAddr
	clk   *fakeClock
	seq   uint32
}

func newQoSHarness(t *testing.T, cfg QoSConfig) *qosHarness {
	t.Helper()
	clk := &fakeClock{}
	cfg.Clock = clk.Now
	if cfg.BurstMs == 0 {
		cfg.BurstMs = 10
	}
	srv, table, addr, stop := startTestUPFWith(t, Config{QoS: cfg})
	t.Cleanup(stop)
	return &qosHarness{t: t, srv: srv, table: table, addr: addr, clk: clk}
}

func (h *qosHarness) nextSeq() uint32 { h.seq++; return h.seq }

func pdrIE(id uint16, ulTEID uint32, ueIP string, qerIDs ...uint32) *pfcpie.IE {
	ies := []*pfcpie.IE{
		pfcpie.NewPDRID(id),
		pfcpie.NewPrecedence(100),
		pfcpie.NewPDI(
			pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
			pfcpie.NewFTEID(0x01, ulTEID, net.ParseIP("127.0.0.1"), nil, 0),
			pfcpie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
		),
		pfcpie.NewFARID(1),
	}
	for _, q := range qerIDs {
		ies = append(ies, pfcpie.NewQERID(q))
	}
	return pfcpie.NewCreatePDR(ies...)
}

func qerIE(id uint32, gate *[2]uint8, mbr *[2]uint64, qfi int) *pfcpie.IE {
	ies := []*pfcpie.IE{pfcpie.NewQERID(id)}
	if gate != nil {
		ies = append(ies, pfcpie.NewGateStatus(gate[0], gate[1]))
	}
	if mbr != nil {
		ies = append(ies, pfcpie.NewMBR(mbr[0], mbr[1]))
	}
	if qfi >= 0 {
		ies = append(ies, pfcpie.NewQFI(uint8(qfi)))
	}
	return pfcpie.NewCreateQER(ies...)
}

var open2 = &[2]uint8{0, 0}

func mbrPair(ul, dl uint64) *[2]uint64 { return &[2]uint64{ul, dl} }

func (h *qosHarness) establish(seid uint64, ulTEID uint32, ies ...*pfcpie.IE) pfcpmsg.Message {
	h.t.Helper()
	all := append([]*pfcpie.IE{
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(seid, net.ParseIP("127.0.0.1"), nil),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02)),
	}, ies...)
	return sendAndRecv(h.t, h.addr, pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, h.nextSeq(), 0, all...))
}

func (h *qosHarness) modify(seid uint64, ies ...*pfcpie.IE) pfcpmsg.Message {
	h.t.Helper()
	return sendAndRecv(h.t, h.addr, pfcpmsg.NewSessionModificationRequest(0, 0, seid, h.nextSeq(), 0, ies...))
}

func causeOf(t *testing.T, m pfcpmsg.Message) uint8 {
	t.Helper()
	var ie *pfcpie.IE
	switch r := m.(type) {
	case *pfcpmsg.SessionEstablishmentResponse:
		ie = r.Cause
	case *pfcpmsg.SessionModificationResponse:
		ie = r.Cause
	case *pfcpmsg.SessionDeletionResponse:
		ie = r.Cause
	default:
		t.Fatalf("unexpected response %T", m)
	}
	c, err := ie.Cause()
	if err != nil {
		t.Fatalf("cause: %v", err)
	}
	return c
}

func failedRule(t *testing.T, m pfcpmsg.Message) (typ uint8, id uint32) {
	t.Helper()
	var ie *pfcpie.IE
	switch r := m.(type) {
	case *pfcpmsg.SessionEstablishmentResponse:
		ie = r.FailedRuleID
	case *pfcpmsg.SessionModificationResponse:
		ie = r.FailedRuleID
	}
	if ie == nil {
		t.Fatalf("response carries no Failed Rule ID")
	}
	typ, _ = ie.RuleIDType()
	id, _ = ie.FailedRuleID()
	return typ, id
}

func offending(t *testing.T, m pfcpmsg.Message) uint16 {
	t.Helper()
	r, ok := m.(*pfcpmsg.SessionEstablishmentResponse)
	if !ok || r.OffendingIE == nil {
		t.Fatalf("response carries no Offending IE")
	}
	v, _ := r.OffendingIE.OffendingIE()
	return v
}

// standardSession installs the SMF's new layout: QER 1 = Session-AMBR (no
// QFI), QER 2 = QoS flow (QFI 1, no MBR), PDR 1 -> {1, 2}.
func (h *qosHarness) standardSession(seid uint64, ulTEID uint32, ulKbps, dlKbps uint64) *Session {
	h.t.Helper()
	resp := h.establish(seid, ulTEID,
		pdrIE(1, ulTEID, "10.60.0.5", 1, 2),
		qerIE(1, open2, mbrPair(ulKbps, dlKbps), -1),
		qerIE(2, open2, nil, 1),
	)
	if c := causeOf(h.t, resp); c != pfcpie.CauseRequestAccepted {
		h.t.Fatalf("establishment cause = %d, want 1", c)
	}
	sess := h.table.GetByULTEID(ulTEID)
	if sess == nil {
		h.t.Fatal("session not stored")
	}
	return sess
}

func offerUL(sess *Session, count, size int) (pass int, drops [NumDropReasons]int) {
	for i := 0; i < count; i++ {
		if ok, r := sess.AdmitUL(size); ok {
			pass++
		} else {
			drops[r]++
		}
	}
	return
}

func offerDL(sess *Session, count, size int) (pass int, drops [NumDropReasons]int) {
	for i := 0; i < count; i++ {
		if ok, r := sess.AdmitDL(size); ok {
			pass++
		} else {
			drops[r]++
		}
	}
	return
}

func TestEstablishmentStoresMultipleQERsAndPDRList(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	const seid, teid = uint64(100), uint32(0x100)
	sess := h.standardSession(seid, teid, 8000, 8000)

	info, ok := h.srv.SessionQoS(seid)
	if !ok {
		t.Fatal("SessionQoS: unknown session")
	}
	q1, q2 := info.QERs[1], info.QERs[2]
	if !q1.HasMBR || q1.MBRULKbps != 8000 || q1.MBRDLKbps != 8000 || q1.HasQFI {
		t.Errorf("QER 1 = %+v, want MBR 8000/8000 and no QFI", q1)
	}
	if q2.HasMBR || !q2.HasQFI || q2.QFI != 1 {
		t.Errorf("QER 2 = %+v, want QFI 1 and no MBR", q2)
	}
	if got := info.PDRs[1].QERIDs; len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("PDR 1 QER IDs = %v, want [1 2] in order", got)
	}
	if info.DLQFI != 1 || sess.DLQFI() != 1 {
		t.Errorf("DL QFI = %d/%d, want 1 (taken from QER 2, not QER 1)", info.DLQFI, sess.DLQFI())
	}
	if info.QERs[1].ulBucket != nil {
		t.Error("QoSInfo must not leak live buckets")
	}
}

func TestEnforcementUplinkDownlink(t *testing.T) {
	tests := []struct {
		name         string
		ul, dl       uint64
		count, size  int
		wantUL       int // forwarded
		wantDL       int
		wantULBucket int64 // expected depth sanity (bytes) is implied by want*
	}{
		{"within AMBR", 8000, 8000, 10, 1000, 10, 10, 0},
		{"above AMBR", 8000, 8000, 15, 1000, 10, 10, 0},
		{"asymmetric", 8000, 4000, 10, 1000, 10, 5, 0},
		{"floor depth", 2000, 2000, 5, 1500, 3, 3, 0},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newQoSHarness(t, QoSConfig{})
			sess := h.standardSession(uint64(200+i), uint32(0x200+i), tc.ul, tc.dl)
			pass, drops := offerUL(sess, tc.count, tc.size)
			if pass != tc.wantUL || drops[DropMBRExceeded] != tc.count-tc.wantUL {
				t.Errorf("UL: pass=%d drops=%v, want pass=%d", pass, drops, tc.wantUL)
			}
			pass, drops = offerDL(sess, tc.count, tc.size)
			if pass != tc.wantDL || drops[DropMBRExceeded] != tc.count-tc.wantDL {
				t.Errorf("DL: pass=%d drops=%v, want pass=%d", pass, drops, tc.wantDL)
			}
		})
	}
}

func TestRefillAndIdleClamp(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	sess := h.standardSession(300, 0x300, 8000, 8000)
	offerUL(sess, 10, 1000)
	h.clk.AdvanceMs(3)
	if pass, _ := offerUL(sess, 5, 1000); pass != 3 {
		t.Errorf("after 3 ms forwarded %d, want 3", pass)
	}
	h.clk.AdvanceMs(10_000)
	if pass, _ := offerUL(sess, 15, 1000); pass != 10 {
		t.Errorf("after 10 s idle forwarded %d, want 10 (depth clamp)", pass)
	}
}

func TestMostRestrictiveQERWinsAndRefund(t *testing.T) {
	t.Run("flow QER stricter", func(t *testing.T) {
		h := newQoSHarness(t, QoSConfig{})
		resp := h.establish(400, 0x400, pdrIE(1, 0x400, "10.60.0.5", 1, 2),
			qerIE(1, open2, mbrPair(8000, 8000), -1), qerIE(2, open2, mbrPair(4000, 4000), 1))
		if causeOf(t, resp) != 1 {
			t.Fatal("rejected")
		}
		sess := h.table.GetByULTEID(0x400)
		if pass, _ := offerUL(sess, 10, 1000); pass != 5 {
			t.Errorf("forwarded %d, want 5", pass)
		}
	})
	t.Run("AMBR stricter and refund of the flow bucket", func(t *testing.T) {
		h := newQoSHarness(t, QoSConfig{})
		resp := h.establish(401, 0x401, pdrIE(1, 0x401, "10.60.0.5", 1, 2),
			qerIE(1, open2, mbrPair(4000, 4000), -1), qerIE(2, open2, mbrPair(8000, 8000), 1))
		if causeOf(t, resp) != 1 {
			t.Fatal("rejected")
		}
		sess := h.table.GetByULTEID(0x401)
		if pass, _ := offerUL(sess, 10, 1000); pass != 5 {
			t.Fatalf("forwarded %d, want 5", pass)
		}
		// Packets 6-10 passed QER 2 first, were rejected by QER 1 and refunded:
		// QER 2 still holds 10000-5000 B.
		if got, ok := h.srv.QERBucketBytes(401, 2, true); !ok || got != 5000 {
			t.Errorf("QER 2 UL tokens = %d (ok=%v), want 5000", got, ok)
		}
		// Remove QER 1: QER 2 alone admits its remaining 5000 B.
		m := h.modify(401, pfcpie.NewRemoveQER(pfcpie.NewQERID(1)),
			pfcpie.NewUpdatePDR(pfcpie.NewPDRID(1), pfcpie.NewQERID(2)))
		if c := causeOf(t, m); c != 1 {
			t.Fatalf("modification cause = %d", c)
		}
		if pass, _ := offerUL(sess, 6, 1000); pass != 5 {
			t.Errorf("after Remove QER 1 forwarded %d, want 5", pass)
		}
	})
}

func TestSessionAMBRSharedAcrossPDRs(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	resp := h.establish(500, 0x500,
		pdrIE(1, 0x500, "10.60.0.5", 1, 2),
		pdrIE(2, 0x500, "10.60.0.5", 1, 3),
		qerIE(1, open2, mbrPair(8000, 8000), -1),
		qerIE(2, open2, nil, 1),
		qerIE(3, open2, nil, 5))
	if causeOf(t, resp) != 1 {
		t.Fatal("rejected")
	}
	sess := h.table.GetByULTEID(0x500)
	pass := 0
	for i := 0; i < 6; i++ {
		if ok, _ := sess.AdmitULForPDR(1, 1000); ok {
			pass++
		}
	}
	for i := 0; i < 6; i++ {
		if ok, _ := sess.AdmitULForPDR(2, 1000); ok {
			pass++
		}
	}
	if pass != 10 {
		t.Errorf("forwarded %d across both PDRs, want 10 (shared Session-AMBR bucket)", pass)
	}
	if ok, _ := sess.AdmitULForPDR(99, 1000); !ok {
		t.Error("unknown PDR must admit")
	}
}

func TestUpdateQER(t *testing.T) {
	upd := func(ies ...*pfcpie.IE) *pfcpie.IE { return pfcpie.NewUpdateQER(ies...) }
	t.Run("lowering clamps tokens to the new depth", func(t *testing.T) {
		h := newQoSHarness(t, QoSConfig{})
		sess := h.standardSession(600, 0x600, 8000, 8000)
		m := h.modify(600, upd(pfcpie.NewQERID(1), pfcpie.NewMBR(4000, 4000)))
		if causeOf(t, m) != 1 {
			t.Fatal("rejected")
		}
		if pass, _ := offerUL(sess, 10, 1000); pass != 5 {
			t.Errorf("forwarded %d, want 5", pass)
		}
		info, _ := h.srv.SessionQoS(600)
		if q := info.QERs[2]; !q.HasQFI || q.QFI != 1 || q.HasMBR {
			t.Errorf("QER 2 changed by Update QER 1: %+v", q)
		}
		if q := info.QERs[1]; q.MBRULKbps != 4000 || q.HasQFI {
			t.Errorf("QER 1 = %+v, want MBR 4000 and no QFI", q)
		}
	})
	t.Run("raising admits more once tokens refill", func(t *testing.T) {
		h := newQoSHarness(t, QoSConfig{})
		sess := h.standardSession(601, 0x601, 4000, 4000)
		offerUL(sess, 10, 1000)
		if causeOf(t, h.modify(601, upd(pfcpie.NewQERID(1), pfcpie.NewMBR(16000, 16000)))) != 1 {
			t.Fatal("rejected")
		}
		h.clk.AdvanceMs(5)
		if pass, _ := offerUL(sess, 10, 1000); pass != 10 {
			t.Errorf("forwarded %d, want 10", pass)
		}
	})
	t.Run("absent MBR keeps the stored MBR", func(t *testing.T) {
		h := newQoSHarness(t, QoSConfig{})
		sess := h.standardSession(602, 0x602, 8000, 8000)
		if causeOf(t, h.modify(602, upd(pfcpie.NewQERID(1), pfcpie.NewGateStatus(0, 0)))) != 1 {
			t.Fatal("rejected")
		}
		if pass, _ := offerUL(sess, 15, 1000); pass != 10 {
			t.Errorf("forwarded %d, want 10", pass)
		}
	})
	t.Run("MBR to 0 makes the direction unlimited, back to a value limits again", func(t *testing.T) {
		h := newQoSHarness(t, QoSConfig{})
		sess := h.standardSession(603, 0x603, 8000, 8000)
		h.modify(603, upd(pfcpie.NewQERID(1), pfcpie.NewMBR(0, 8000)))
		if pass, _ := offerUL(sess, 100, 1000); pass != 100 {
			t.Errorf("UL forwarded %d, want 100 (unlimited)", pass)
		}
		if pass, _ := offerDL(sess, 15, 1000); pass != 10 {
			t.Errorf("DL forwarded %d, want 10", pass)
		}
		h.modify(603, upd(pfcpie.NewQERID(1), pfcpie.NewMBR(8000, 8000)))
		if pass, _ := offerUL(sess, 15, 1000); pass != 10 {
			t.Errorf("UL after re-limit forwarded %d, want 10 (fresh full bucket)", pass)
		}
	})
}

func TestGating(t *testing.T) {
	upd := func(id uint32, ul, dl uint8) *pfcpie.IE {
		return pfcpie.NewUpdateQER(pfcpie.NewQERID(id), pfcpie.NewGateStatus(ul, dl))
	}
	t.Run("UL closed drops UL only and consumes no tokens", func(t *testing.T) {
		h := newQoSHarness(t, QoSConfig{})
		sess := h.standardSession(700, 0x700, 8000, 8000)
		h.modify(700, upd(2, 1, 0))
		pass, drops := offerUL(sess, 4, 1000)
		if pass != 0 || drops[DropGateClosed] != 4 || drops[DropMBRExceeded] != 0 {
			t.Errorf("UL pass=%d drops=%v", pass, drops)
		}
		if got, _ := h.srv.QERBucketBytes(700, 1, true); got != 10000 {
			t.Errorf("QER 1 UL tokens = %d, want 10000", got)
		}
		if pass, _ := offerDL(sess, 4, 1000); pass != 4 {
			t.Errorf("DL forwarded %d, want 4", pass)
		}
	})
	t.Run("DL closed then reopened", func(t *testing.T) {
		h := newQoSHarness(t, QoSConfig{})
		sess := h.standardSession(701, 0x701, 8000, 8000)
		h.modify(701, upd(1, 0, 1))
		if pass, drops := offerDL(sess, 4, 1000); pass != 0 || drops[DropGateClosed] != 4 {
			t.Errorf("DL closed: pass=%d drops=%v", pass, drops)
		}
		h.modify(701, upd(1, 0, 0))
		if pass, _ := offerDL(sess, 3, 1000); pass != 3 {
			t.Errorf("DL reopened forwarded %d, want 3", pass)
		}
	})
	t.Run("spare value interpreted as CLOSED", func(t *testing.T) {
		// TS 29.244 §8.2.7: values 2 and 3 are read as 1 (CLOSED).
		for _, spare := range []uint8{2, 3} {
			h := newQoSHarness(t, QoSConfig{})
			sess := h.standardSession(702, 0x702, 8000, 8000)
			if c := causeOf(t, h.modify(702, upd(2, spare, 0))); c != 1 {
				t.Fatalf("cause = %d", c)
			}
			if pass, drops := offerUL(sess, 3, 1000); pass != 0 || drops[DropGateClosed] != 3 {
				t.Errorf("spare %d: forwarded %d drops %v, want all gate-closed", spare, pass, drops)
			}
			if info, _ := h.srv.SessionQoS(702); info.QERs[2].GateUL != gateClosed || info.QERs[2].GateDL != gateOpen {
				t.Errorf("spare %d stored as UL=%d DL=%d, want CLOSED/OPEN", spare, info.QERs[2].GateUL, info.QERs[2].GateDL)
			}
		}
	})
}

func TestUnlimitedMBR(t *testing.T) {
	tests := []struct {
		name string
		mbr  *[2]uint64
	}{
		{"absent", nil},
		{"zero", mbrPair(0, 0)},
		{"0xFFFFFFFF", mbrPair(0xFFFFFFFF, 0xFFFFFFFF)},
		{"5-octet max", mbrPair(0xFFFFFFFFFF, 0xFFFFFFFFFF)},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newQoSHarness(t, QoSConfig{})
			seid, teid := uint64(800+i), uint32(0x800+i)
			resp := h.establish(seid, teid, pdrIE(1, teid, "10.60.0.5", 1), qerIE(1, open2, tc.mbr, 1))
			if causeOf(t, resp) != 1 {
				t.Fatal("rejected")
			}
			sess := h.table.GetByULTEID(teid)
			if pass, _ := offerUL(sess, 100, 1500); pass != 100 {
				t.Errorf("UL forwarded %d, want 100", pass)
			}
			if pass, _ := offerDL(sess, 100, 1500); pass != 100 {
				t.Errorf("DL forwarded %d, want 100", pass)
			}
			if sess.DLQFI() != 1 {
				t.Errorf("DL QFI = %d, want 1", sess.DLQFI())
			}
		})
	}
	t.Run("zero in one direction only", func(t *testing.T) {
		h := newQoSHarness(t, QoSConfig{})
		h.establish(810, 0x810, pdrIE(1, 0x810, "10.60.0.5", 1), qerIE(1, open2, mbrPair(8000, 0), 1))
		sess := h.table.GetByULTEID(0x810)
		if pass, _ := offerUL(sess, 15, 1000); pass != 10 {
			t.Errorf("UL forwarded %d, want 10", pass)
		}
		if pass, _ := offerDL(sess, 15, 1000); pass != 15 {
			t.Errorf("DL forwarded %d, want 15", pass)
		}
	})
}

func TestKnobMBREnforcementOff(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{MBRDisabled: true})
	sess := h.standardSession(900, 0x900, 8000, 8000)
	if pass, _ := offerUL(sess, 100, 1000); pass != 100 {
		t.Errorf("forwarded %d, want 100 (line rate)", pass)
	}
	h.modify(900, pfcpie.NewUpdateQER(pfcpie.NewQERID(2), pfcpie.NewGateStatus(1, 0)))
	if pass, drops := offerUL(sess, 4, 1000); pass != 0 || drops[DropGateClosed] != 4 {
		t.Errorf("gate must still be enforced: pass=%d drops=%v", pass, drops)
	}
}

func TestCreateQERInModification(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	resp := h.establish(1000, 0x1000, pdrIE(1, 0x1000, "10.60.0.5", 1), qerIE(1, open2, nil, 1))
	if causeOf(t, resp) != 1 {
		t.Fatal("rejected")
	}
	sess := h.table.GetByULTEID(0x1000)
	m := h.modify(1000, qerIE(3, open2, mbrPair(4000, 4000), -1),
		pfcpie.NewUpdatePDR(pfcpie.NewPDRID(1), pfcpie.NewQERID(1), pfcpie.NewQERID(3)))
	if c := causeOf(t, m); c != 1 {
		t.Fatalf("cause = %d", c)
	}
	// CreateQER inside a modification is a Create QER IE of the request.
	if pass, _ := offerUL(sess, 10, 1000); pass != 5 {
		t.Errorf("forwarded %d, want 5", pass)
	}
}

func TestEstablishmentRejections(t *testing.T) {
	noID := pfcpie.NewCreateQER(pfcpie.NewGateStatus(0, 0), pfcpie.NewMBR(8000, 8000))
	tests := []struct {
		name      string
		ies       []*pfcpie.IE
		wantCause uint8
		ruleType  uint8
		ruleID    uint32
		offending uint16
	}{
		{"create QER without QER ID", []*pfcpie.IE{pdrIE(1, 0x1100, "10.60.0.5"), noID}, 66, 0, 0, pfcpie.QERID},
		{"duplicate QER ID", []*pfcpie.IE{pdrIE(1, 0x1100, "10.60.0.5", 1),
			qerIE(1, open2, mbrPair(8000, 8000), -1), qerIE(1, open2, mbrPair(4000, 4000), 1)},
			73, pfcpie.RuleIDTypeQER, 1, 0},
		{"PDR references missing QER", []*pfcpie.IE{pdrIE(1, 0x1100, "10.60.0.5", 1, 2),
			qerIE(1, open2, mbrPair(8000, 8000), -1)},
			73, pfcpie.RuleIDTypePDR, 1, 0},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newQoSHarness(t, QoSConfig{})
			seid := uint64(1100 + i)
			resp := h.establish(seid, 0x1100, tc.ies...)
			if c := causeOf(t, resp); c != tc.wantCause {
				t.Fatalf("cause = %d, want %d", c, tc.wantCause)
			}
			if tc.wantCause == 66 {
				if got := offending(t, resp); got != tc.offending {
					t.Errorf("offending IE = %d, want %d", got, tc.offending)
				}
			} else if typ, id := failedRule(t, resp); typ != tc.ruleType || id != tc.ruleID {
				t.Errorf("failed rule = {%d,%d}, want {%d,%d}", typ, id, tc.ruleType, tc.ruleID)
			}
			if _, ok := h.srv.SessionQoS(seid); ok || h.table.GetByULTEID(0x1100) != nil {
				t.Error("a rejected establishment must store no session")
			}
		})
	}
}

func TestEstablishmentGateAbsentIsLenient(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	resp := h.establish(1200, 0x1200, pdrIE(1, 0x1200, "10.60.0.5", 1), qerIE(1, nil, mbrPair(8000, 8000), 1))
	if causeOf(t, resp) != 1 {
		t.Fatal("rejected")
	}
	sess := h.table.GetByULTEID(0x1200)
	if pass, _ := offerUL(sess, 3, 1000); pass != 3 {
		t.Errorf("forwarded %d, want 3 (gates default to OPEN)", pass)
	}
}

func TestModificationRejectionsApplyNothing(t *testing.T) {
	upd := func(id uint32, ul, dl uint64) *pfcpie.IE {
		return pfcpie.NewUpdateQER(pfcpie.NewQERID(id), pfcpie.NewMBR(ul, dl))
	}
	tests := []struct {
		name     string
		ies      []*pfcpie.IE
		ruleType uint8
		ruleID   uint32
	}{
		{"update unknown QER", []*pfcpie.IE{upd(99, 1000, 1000)}, pfcpie.RuleIDTypeQER, 99},
		{"valid + invalid update applies nothing", []*pfcpie.IE{upd(1, 4000, 4000), upd(99, 1000, 1000)}, pfcpie.RuleIDTypeQER, 99},
		{"remove unknown QER", []*pfcpie.IE{pfcpie.NewRemoveQER(pfcpie.NewQERID(99))}, pfcpie.RuleIDTypeQER, 99},
		{"remove still-referenced QER", []*pfcpie.IE{pfcpie.NewRemoveQER(pfcpie.NewQERID(1))}, pfcpie.RuleIDTypeQER, 1},
		{"create existing QER ID", []*pfcpie.IE{qerIE(2, open2, nil, 1)}, pfcpie.RuleIDTypeQER, 2},
		{"update PDR to unknown QER", []*pfcpie.IE{pfcpie.NewUpdatePDR(pfcpie.NewPDRID(1), pfcpie.NewQERID(77))}, pfcpie.RuleIDTypePDR, 1},
		{"update unknown PDR", []*pfcpie.IE{pfcpie.NewUpdatePDR(pfcpie.NewPDRID(9), pfcpie.NewQERID(1))}, pfcpie.RuleIDTypePDR, 9},
		{"update + remove same QER", []*pfcpie.IE{upd(1, 4000, 4000), pfcpie.NewRemoveQER(pfcpie.NewQERID(1)),
			pfcpie.NewUpdatePDR(pfcpie.NewPDRID(1), pfcpie.NewQERID(2))}, pfcpie.RuleIDTypeQER, 1},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newQoSHarness(t, QoSConfig{})
			seid := uint64(1300 + i)
			sess := h.standardSession(seid, uint32(0x1300+i), 8000, 8000)
			resp := h.modify(seid, tc.ies...)
			if c := causeOf(t, resp); c != pfcpie.CauseRuleCreationModificationFailure {
				t.Fatalf("cause = %d, want 73", c)
			}
			if typ, id := failedRule(t, resp); typ != tc.ruleType || id != tc.ruleID {
				t.Errorf("failed rule = {%d,%d}, want {%d,%d}", typ, id, tc.ruleType, tc.ruleID)
			}
			info, _ := h.srv.SessionQoS(seid)
			if q := info.QERs[1]; q.MBRULKbps != 8000 || q.MBRDLKbps != 8000 || len(info.QERs) != 2 {
				t.Errorf("session mutated by rejected request: %+v", info.QERs)
			}
			if got := info.PDRs[1].QERIDs; len(got) != 2 {
				t.Errorf("PDR list mutated: %v", got)
			}
			if pass, _ := offerUL(sess, 15, 1000); pass != 10 {
				t.Errorf("forwarded %d, want 10 (old rate still enforced)", pass)
			}
		})
	}
}

func TestModificationUnknownSEID(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	m := h.modify(424242, pfcpie.NewUpdateQER(pfcpie.NewQERID(1), pfcpie.NewMBR(1000, 1000)))
	if c := causeOf(t, m); c != pfcpie.CauseSessionContextNotFound {
		t.Errorf("cause = %d, want 65", c)
	}
}

func TestModificationQERWithoutID(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	h.standardSession(1400, 0x1400, 8000, 8000)
	m := h.modify(1400, pfcpie.NewUpdateQER(pfcpie.NewMBR(1000, 1000)))
	if c := causeOf(t, m); c != pfcpie.CauseMandatoryIEMissing {
		t.Errorf("cause = %d, want 66", c)
	}
}

func TestDeletionDropsQoSState(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	sess := h.standardSession(1500, 0x1500, 8000, 8000)
	del := pfcpmsg.NewSessionDeletionRequest(0, 0, 1500, h.nextSeq(), 0)
	if c := causeOf(t, sendAndRecv(t, h.addr, del)); c != 1 {
		t.Fatalf("cause = %d", c)
	}
	if h.table.GetByULTEID(0x1500) != nil {
		t.Error("session still present")
	}
	if ok, _ := sess.AdmitUL(1000); !ok || sess.DLQFI() != 0 {
		t.Error("a stale session pointer must enforce and mark nothing after deletion")
	}
}

func TestLegacySingleQERStillWorks(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	resp := h.establish(1600, 0x1600, pdrIE(1, 0x1600, "10.60.0.5", 1),
		qerIE(1, open2, mbrPair(0xFFFFFFFF, 0xFFFFFFFF), 1))
	if causeOf(t, resp) != 1 {
		t.Fatal("rejected")
	}
	sess := h.table.GetByULTEID(0x1600)
	if pass, _ := offerDL(sess, 200, 1500); pass != 200 {
		t.Errorf("forwarded %d, want 200", pass)
	}
	if sess.DLQFI() != 1 {
		t.Errorf("DL QFI = %d, want 1", sess.DLQFI())
	}
	// Old SMF QoS modification: Update QER {1, gate, MBR, QFI 1}.
	m := h.modify(1600, pfcpie.NewUpdateQER(pfcpie.NewQERID(1), pfcpie.NewGateStatus(0, 0),
		pfcpie.NewMBR(8000, 8000), pfcpie.NewQFI(1)))
	if causeOf(t, m) != 1 {
		t.Fatal("update rejected")
	}
	if pass, _ := offerUL(sess, 15, 1000); pass != 10 {
		t.Errorf("forwarded %d, want 10", pass)
	}
}

func TestBuildQoSViewSelection(t *testing.T) {
	clk := &fakeClock{}
	cfg := QoSConfig{BurstMs: 10, Clock: clk.Now}
	mk := func() *Session {
		return &Session{
			QERs: map[uint32]*QERState{
				1: {QERID: 1, HasMBR: true, MBRULKbps: 8000, MBRDLKbps: 8000},
				2: {QERID: 2, HasQFI: true, QFI: 7},
				3: {QERID: 3, HasMBR: true, MBRULKbps: 4000, MBRDLKbps: 4000, HasQFI: true, QFI: 9},
			},
		}
	}
	t.Run("no QFI anywhere gives 0", func(t *testing.T) {
		s := &Session{QERs: map[uint32]*QERState{1: {QERID: 1}}, PDRs: map[uint16]*PDRState{1: {PDRID: 1, QERIDs: []uint32{1}}}}
		s.RebuildQoS(cfg)
		if s.DLQFI() != 0 {
			t.Errorf("DLQFI = %d", s.DLQFI())
		}
	})
	t.Run("lowest-precedence access PDR governs, first QFI in order", func(t *testing.T) {
		s := mk()
		s.PDRs = map[uint16]*PDRState{
			1: {PDRID: 1, Precedence: 200, QERIDs: []uint32{1, 3}},
			2: {PDRID: 2, Precedence: 100, QERIDs: []uint32{1, 2}},
		}
		s.RebuildQoS(cfg)
		if s.DLQFI() != 7 {
			t.Errorf("DLQFI = %d, want 7 (PDR 2 has the lower precedence value)", s.DLQFI())
		}
	})
	t.Run("a Core PDR governs downlink", func(t *testing.T) {
		s := mk()
		s.PDRs = map[uint16]*PDRState{
			1: {PDRID: 1, Precedence: 100, QERIDs: []uint32{1, 2}},
			2: {PDRID: 2, Precedence: 100, SourceInterface: srcInterfaceCore, QERIDs: []uint32{3}},
		}
		s.RebuildQoS(cfg)
		if pass, _ := offerDL(s, 10, 1000); pass != 5 {
			t.Errorf("DL forwarded %d, want 5 (QER 3 4000 kbps)", pass)
		}
		if pass, _ := offerUL(s, 15, 1000); pass != 10 {
			t.Errorf("UL forwarded %d, want 10 (QER 1 8000 kbps)", pass)
		}
		if s.DLQFI() != 9 {
			t.Errorf("DLQFI = %d, want 9", s.DLQFI())
		}
	})
	t.Run("rebuild keeps bucket identity and tokens", func(t *testing.T) {
		s := mk()
		s.PDRs = map[uint16]*PDRState{1: {PDRID: 1, QERIDs: []uint32{1, 2}}}
		s.RebuildQoS(cfg)
		offerUL(s, 6, 1000)
		before := s.QERs[1].ulBucket
		s.RebuildQoS(cfg)
		if s.QERs[1].ulBucket != before {
			t.Error("bucket replaced on rebuild")
		}
		if pass, _ := offerUL(s, 10, 1000); pass != 4 {
			t.Errorf("forwarded %d, want 4 (tokens preserved)", pass)
		}
	})
	t.Run("nothing installed gives nil view", func(t *testing.T) {
		s := &Session{}
		s.RebuildQoS(cfg)
		if s.qos.Load() != nil {
			t.Error("view should be nil")
		}
		if ok, r := s.AdmitUL(1500); !ok || r != DropNone {
			t.Error("must admit")
		}
	})
}

func TestDropReasonLabels(t *testing.T) {
	if DropMBRExceeded.String() != "qer_mbr_exceeded" || DropGateClosed.String() != "qer_gate_closed" || DropNone.String() != "" {
		t.Fatal("reason labels changed")
	}
}

func TestAdmitConcurrentWithRebuild(t *testing.T) {
	clk := &fakeClock{}
	cfg := QoSConfig{BurstMs: 10, Clock: clk.Now}
	s := &Session{
		QERs: map[uint32]*QERState{
			1: {QERID: 1, HasMBR: true, MBRULKbps: 8000, MBRDLKbps: 8000},
			2: {QERID: 2, HasQFI: true, QFI: 1},
		},
		PDRs: map[uint16]*PDRState{1: {PDRID: 1, QERIDs: []uint32{1, 2}}},
	}
	s.RebuildQoS(cfg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			s.AdmitUL(1000)
			s.AdmitDL(1000)
			_ = s.DLQFI()
		}
	}()
	for i := 0; i < 200; i++ {
		clk.AdvanceMs(1)
		s.QERs[1].MBRULKbps = uint64(4000 + i)
		s.RebuildQoS(cfg)
	}
	<-done
}

func BenchmarkAdmit(b *testing.B) {
	// Each case owns its clock so one case's advance never refills another.
	type benchCase struct {
		name   string
		qers   func() map[uint32]*QERState
		advNs  int64
		wantOK bool
		drain  bool
	}
	cases := []benchCase{
		{"unlimited", func() map[uint32]*QERState {
			return map[uint32]*QERState{
				1: {QERID: 1, HasMBR: true, MBRULKbps: 0xFFFFFFFF, MBRDLKbps: 0xFFFFFFFF},
				2: {QERID: 2, HasQFI: true, QFI: 1}}
		}, 0, true, false},
		// 100 Gb/s on both QERs: always passes, but pays the two-bucket path.
		{"limited-pass", func() map[uint32]*QERState {
			return map[uint32]*QERState{
				1: {QERID: 1, HasMBR: true, MBRULKbps: 100_000_000, MBRDLKbps: 100_000_000},
				2: {QERID: 2, HasQFI: true, QFI: 1, HasMBR: true, MBRULKbps: 100_000_000, MBRDLKbps: 100_000_000}}
		}, 1000, true, false},
		// 1 kbps with a frozen clock: drains after the 4500 B floor, then drops
		// (and refunds the flow bucket every time).
		{"limited-drop", func() map[uint32]*QERState {
			return map[uint32]*QERState{
				1: {QERID: 1, HasMBR: true, MBRULKbps: 1, MBRDLKbps: 1},
				2: {QERID: 2, HasQFI: true, QFI: 1, HasMBR: true, MBRULKbps: 100_000_000, MBRDLKbps: 100_000_000}}
		}, 0, false, true},
		{"gate-closed", func() map[uint32]*QERState {
			return map[uint32]*QERState{
				1: {QERID: 1, GateUL: gateClosed}, 2: {QERID: 2, HasQFI: true, QFI: 1}}
		}, 0, false, false},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			clk := &fakeClock{}
			s := &Session{QERs: c.qers(), PDRs: map[uint16]*PDRState{1: {PDRID: 1, QERIDs: []uint32{1, 2}}}}
			s.RebuildQoS(QoSConfig{BurstMs: 100, Clock: clk.Now})
			if c.drain {
				for i := 0; i < 10; i++ {
					s.AdmitUL(1500)
				}
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				clk.ns.Add(c.advNs)
				if ok, _ := s.AdmitUL(1400); ok != c.wantOK {
					b.Fatalf("admit = %v, want %v", ok, c.wantOK)
				}
			}
		})
	}
	b.Run("nil-view", func(b *testing.B) {
		s := &Session{}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.AdmitUL(1400)
		}
	})
	b.Run("real-clock-limited-pass", func(b *testing.B) {
		s := &Session{QERs: map[uint32]*QERState{
			1: {QERID: 1, HasMBR: true, MBRULKbps: 100_000_000, MBRDLKbps: 100_000_000},
			2: {QERID: 2, HasQFI: true, QFI: 1, HasMBR: true, MBRULKbps: 100_000_000, MBRDLKbps: 100_000_000}},
			PDRs: map[uint16]*PDRState{1: {PDRID: 1, QERIDs: []uint32{1, 2}}}}
		s.RebuildQoS(QoSConfig{})
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.AdmitUL(1400)
		}
	})
}

func TestNormGate(t *testing.T) {
	tests := []struct {
		in    uint8
		want  uint8
		spare bool
	}{{0, gateOpen, false}, {1, gateClosed, false}, {2, gateClosed, true}, {3, gateClosed, true}}
	for _, tc := range tests {
		if g, sp := normGate(tc.in); g != tc.want || sp != tc.spare {
			t.Errorf("normGate(%d) = %d,%v want %d,%v", tc.in, g, sp, tc.want, tc.spare)
		}
	}
}

// warnRec records lenient-parse warnings.
type warnRec struct{ msgs []string }

func (w *warnRec) fn(msg, spec string, qerID uint32) { w.msgs = append(w.msgs, msg+"|"+spec) }

func TestWarnGateCreateVsUpdate(t *testing.T) {
	var w warnRec
	warnGate(qerParams{id: 1}, true, w.fn)  // Create, absent -> warn
	warnGate(qerParams{id: 1}, false, w.fn) // Update, absent -> unchanged, no warn
	if len(w.msgs) != 1 {
		t.Fatalf("absent gate warnings = %v, want 1 (Create only)", w.msgs)
	}
	warnGate(qerParams{id: 1, hasGate: true, spareGate: true}, false, w.fn) // Update, spare -> warn
	if len(w.msgs) != 2 {
		t.Errorf("spare gate in Update QER not warned: %v", w.msgs)
	}
}

func TestModificationSpareGateWarnsOnUpdate(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	h.standardSession(1500, 0x1500, 8000, 8000)
	sess := h.table.GetByULTEID(0x1500)
	var w warnRec
	req := pfcpmsg.NewSessionModificationRequest(0, 0, 1500, 1, 0,
		pfcpie.NewUpdateQER(pfcpie.NewQERID(2), pfcpie.NewGateStatus(2, 0)))
	if _, rej := planModificationQoS(sess, req, w.fn); rej != nil {
		t.Fatalf("rejected: %+v", rej)
	}
	if len(w.msgs) != 1 {
		t.Errorf("warnings = %v, want 1 spare-gate warning", w.msgs)
	}
	req = pfcpmsg.NewSessionModificationRequest(0, 0, 1500, 2, 0,
		pfcpie.NewUpdateQER(pfcpie.NewQERID(2), pfcpie.NewMBR(1, 1)))
	w = warnRec{}
	if _, rej := planModificationQoS(sess, req, w.fn); rej != nil || len(w.msgs) != 0 {
		t.Errorf("Update QER without Gate Status must not warn: rej=%v warns=%v", rej, w.msgs)
	}
}

func TestDuplicateQERIDInPDRIsDeduplicated(t *testing.T) {
	// Create PDR path.
	var w warnRec
	ps, rej := parsePDRQoS([]*pfcpie.IE{pfcpie.NewPDRID(1), pfcpie.NewQERID(1), pfcpie.NewQERID(2), pfcpie.NewQERID(1)}, w.fn)
	if rej != nil || len(ps.QERIDs) != 2 || ps.QERIDs[0] != 1 || ps.QERIDs[1] != 2 || len(w.msgs) != 1 {
		t.Errorf("Create PDR: ids=%v rej=%v warns=%v, want [1 2] and one warning", ps.QERIDs, rej, w.msgs)
	}
	// Update PDR path, end to end: the duplicate must not debit twice.
	h := newQoSHarness(t, QoSConfig{})
	sess := h.standardSession(1600, 0x1600, 8000, 8000)
	if c := causeOf(t, h.modify(1600, pfcpie.NewUpdatePDR(pfcpie.NewPDRID(1),
		pfcpie.NewQERID(1), pfcpie.NewQERID(1), pfcpie.NewQERID(2)))); c != 1 {
		t.Fatalf("cause = %d", c)
	}
	info, _ := h.srv.SessionQoS(1600)
	if got := info.PDRs[1].QERIDs; len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("PDR QER list = %v, want [1 2]", got)
	}
	if pass, _ := offerUL(sess, 15, 1000); pass != 10 {
		t.Errorf("forwarded %d, want 10 (packet debited once)", pass)
	}
}

func TestEstablishmentResponseCarriesNodeID(t *testing.T) {
	h := newQoSHarness(t, QoSConfig{})
	accept := h.establish(1700, 0x1700, pdrIE(1, 0x1700, "10.60.0.5", 1), qerIE(1, open2, nil, 1))
	reject := h.establish(1701, 0x1701, pdrIE(1, 0x1701, "10.60.0.6", 9))
	for name, m := range map[string]pfcpmsg.Message{"accept": accept, "reject": reject} {
		r, ok := m.(*pfcpmsg.SessionEstablishmentResponse)
		if !ok {
			t.Fatalf("%s: %T", name, m)
		}
		if r.NodeID == nil {
			t.Errorf("%s: Session Establishment Response lacks the mandatory Node ID (TS 29.244 §7.5.3.1)", name)
		}
	}
	if causeOf(t, reject) != pfcpie.CauseRuleCreationModificationFailure {
		t.Error("second establishment should have been rejected")
	}
}

func TestRejectCarriesIESpecRef(t *testing.T) {
	tests := []struct {
		rej  *pfcpReject
		want string
	}{
		{rejectMissing(pfcpie.QERID, specCreateQER, "x"), "TS 29.244 §7.5.2.5"},
		{rejectIncorrect(pfcpie.UpdateQER, specUpdateQER, "x"), "TS 29.244 §7.5.4.5"},
		{rejectRule(pfcpie.RuleIDTypeQER, 1, specRemoveQER, "x"), "TS 29.244 §7.5.4.9"},
		{rejectRule(pfcpie.RuleIDTypePDR, 1, specCreatePDR, "x"), "TS 29.244 §7.5.2.2"},
		{rejectRule(pfcpie.RuleIDTypePDR, 1, specUpdatePDR, "x"), "TS 29.244 §7.5.4.2"},
	}
	for _, tc := range tests {
		if tc.rej.spec != tc.want {
			t.Errorf("spec = %q, want %q", tc.rej.spec, tc.want)
		}
	}
}
