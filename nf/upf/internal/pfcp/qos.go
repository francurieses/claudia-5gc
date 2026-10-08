// QoS enforcement state for a PFCP session: QERs keyed by QER ID, the QER ID
// list of each PDR, and the immutable snapshot (qosView) the GTP-U datapath
// reads with a single atomic load. The token buckets themselves live in
// package qos.
//
// Ref: TS 29.244 §5.2.5 (QER handling), §5.4.3 (gating control), §5.4.4 (QoS
// control: MBR), §7.5.2.2 (QER ID list of a PDR), §7.5.2.5 (Create QER);
// TS 23.501 §5.7.1.8 (UPF enforces UL and DL Session-AMBR), §5.7.2.6.
package pfcp

import (
	"math"
	"sort"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/qos"
)

// PFCP Gate Status values (TS 29.244 §8.2.7). Other values are spare.
const (
	gateOpen   uint8 = 0
	gateClosed uint8 = 1
)

// DropReason says why the QoS enforcement refused a packet.
type DropReason uint8

// Drop reasons, indexing the datapath's pre-resolved drop counters
// (fivegc_upf_packet_drops_total{reason}).
const (
	// DropNone means the packet was admitted.
	DropNone DropReason = iota
	// DropGateClosed: a QER of the PDR has its Gate Status CLOSED for this
	// direction (TS 29.244 §5.4.3, §8.2.7). Reason label "qer_gate_closed".
	DropGateClosed
	// DropMBRExceeded: the packet exceeded the MBR of a QER or the
	// Session-AMBR (TS 29.244 §5.4.4). Reason label "qer_mbr_exceeded".
	DropMBRExceeded

	// NumDropReasons is the size of a table indexed by DropReason.
	NumDropReasons
)

// String returns the fivegc_upf_packet_drops_total reason label.
func (r DropReason) String() string {
	switch r {
	case DropGateClosed:
		return "qer_gate_closed"
	case DropMBRExceeded:
		return "qer_mbr_exceeded"
	default:
		return ""
	}
}

// QoSConfig configures MBR enforcement (config block `qos:`).
type QoSConfig struct {
	// MBRDisabled switches MBR/Session-AMBR policing off (config
	// qos.mbr_enforcement=false). Gate Status CLOSED is still enforced:
	// gating is a different function (TS 29.244 §5.4.3).
	MBRDisabled bool
	// BurstMs is the bucket depth in ms of traffic at the MBR; 0 = default
	// (qos.DefaultBurstMs), clamped to [qos.MinBurstMs, qos.MaxBurstMs].
	BurstMs int
	// Clock is the monotonic enforcement clock (ns); nil = qos.MonotonicClock().
	// Tests inject a controllable clock.
	Clock qos.Clock
}

func (c QoSConfig) normalized() QoSConfig {
	c.BurstMs = qos.ClampBurstMs(c.BurstMs)
	if c.Clock == nil {
		c.Clock = qos.MonotonicClock()
	}
	return c
}

// QERState mirrors one QoS Enforcement Rule installed by the SMF.
// MBR values are in kbps per TS 29.244 §8.2.8.
type QERState struct {
	QERID  uint32
	QFI    uint8
	HasQFI bool  // QFI IE present (TS 29.244 §8.2.89)
	GateUL uint8 // 0 = OPEN, 1 = CLOSED (TS 29.244 §8.2.7); spare values are stored as OPEN
	GateDL uint8
	// HasMBR is true when an MBR IE was received. An absent IE, a zero value or
	// a value >= qos.UnlimitedKbps means "not limited" in that direction.
	HasMBR    bool
	MBRULKbps uint64
	MBRDLKbps uint64

	// ulBucket/dlBucket are long-lived: a rebuild reuses them so a bucket
	// shared by several PDRs stays shared and keeps its tokens across an
	// Update QER. Nil = unlimited. Guarded by SessionTable.mu.
	ulBucket, dlBucket *qos.Bucket
}

// PDRState holds what the UPF keeps of a Packet Detection Rule for QoS.
type PDRState struct {
	PDRID uint16
	// SourceInterface is the PDI Source Interface (TS 29.244 §8.2.2): 0 Access
	// (uplink), 1 Core (downlink). Absent is stored as Access.
	SourceInterface uint8
	// Precedence (TS 29.244 §8.2.11); absent = math.MaxUint32 (lowest).
	Precedence uint32
	// QERIDs is the QER ID list in received order (TS 29.244 §7.5.2.2).
	QERIDs []uint32
}

const (
	srcInterfaceAccess uint8 = 0
	srcInterfaceCore   uint8 = 1
)

// dirView is the resolved enforcement of one direction for one PDR.
type dirView struct {
	// gateClosed: some referenced QER has this direction's gate CLOSED.
	gateClosed bool
	// buckets are the limited QERs' buckets in evaluation order: QoS-flow QERs
	// (carrying a QFI) first, session-level (Session-AMBR) QERs last.
	buckets []*qos.Bucket
}

// pdrView is both directions of one PDR.
type pdrView struct{ ul, dl dirView }

// qosView is the immutable enforcement snapshot of a session, rebuilt on
// every PFCP change and published through Session.qos. The datapath does one
// atomic load per packet and never takes the session-table lock.
type qosView struct {
	clock  qos.Clock
	ul, dl dirView // default PDR selection (see PDR -> QER resolution)
	byPDR  map[uint16]*pdrView
	// dlQFI is the QFI placed in the DL PDU Session Container (TS 38.415
	// §5.5.2.1, TS 29.244 §8.2.89); hasQFI is false when no QER carries one.
	dlQFI  uint8
	hasQFI bool
}

// admit applies the gate then the buckets. now is read once and shared by all
// buckets. A packet rejected by a later bucket is refunded on the earlier ones.
func (d *dirView) admit(clock qos.Clock, n int) (bool, DropReason) {
	if d.gateClosed {
		return false, DropGateClosed
	}
	switch len(d.buckets) {
	case 0:
		return true, DropNone
	case 1:
		if d.buckets[0].Admit(n, clock()) {
			return true, DropNone
		}
		return false, DropMBRExceeded
	}
	now := clock()
	for i, b := range d.buckets {
		if !b.Admit(n, now) {
			for _, prev := range d.buckets[:i] {
				prev.Refund(n)
			}
			return false, DropMBRExceeded
		}
	}
	return true, DropNone
}

// AdmitUL polices an n-octet uplink packet (inner IP packet length) against
// the QERs of the session's uplink PDR. Zero allocations; no lock.
// Ref: TS 23.501 §5.7.1.8, TS 29.244 §5.4.3, §5.4.4.
func (s *Session) AdmitUL(n int) (bool, DropReason) {
	v := s.qos.Load()
	if v == nil {
		return true, DropNone
	}
	return v.ul.admit(v.clock, n)
}

// AdmitDL polices an n-octet downlink packet against the QERs of the session
// (the uplink PDR's QER list unless a Core-side PDR exists), using the DL gate
// and DL buckets. Zero allocations; no lock.
func (s *Session) AdmitDL(n int) (bool, DropReason) {
	v := s.qos.Load()
	if v == nil {
		return true, DropNone
	}
	return v.dl.admit(v.clock, n)
}

// AdmitULForPDR is AdmitUL for the QER list of one specific PDR; an unknown
// PDR ID admits the packet. Used when several PDRs share the Session-AMBR QER.
func (s *Session) AdmitULForPDR(pdrID uint16, n int) (bool, DropReason) {
	v := s.qos.Load()
	if v == nil {
		return true, DropNone
	}
	p := v.byPDR[pdrID]
	if p == nil {
		return true, DropNone
	}
	return p.ul.admit(v.clock, n)
}

// AdmitDLForPDR is AdmitDL for the QER list of one specific PDR.
func (s *Session) AdmitDLForPDR(pdrID uint16, n int) (bool, DropReason) {
	v := s.qos.Load()
	if v == nil {
		return true, DropNone
	}
	p := v.byPDR[pdrID]
	if p == nil {
		return true, DropNone
	}
	return p.dl.admit(v.clock, n)
}

// DLQFI returns the QFI for the DL PDU Session Container from the published
// snapshot (0 when none). Lock-free; replaces the former unsynchronised read of
// a PFCP-mutated field. Ref: TS 38.415 §5.5.2.1.
func (s *Session) DLQFI() uint8 {
	if v := s.qos.Load(); v != nil {
		return v.dlQFI
	}
	return 0
}

// RebuildQoS rebuilds the enforcement snapshot from s.QERs and s.PDRs and
// publishes it. The caller must hold exclusive access to those maps
// (SessionTable.mu write lock, or the session is not yet published). Buckets
// are reused across rebuilds so token state survives an Update QER.
// Ref: TS 29.244 §5.2.5.
func (s *Session) RebuildQoS(cfg QoSConfig) {
	cfg = cfg.normalized()
	s.qos.Store(buildQoSView(s, cfg))
}

// effectiveKbps returns the rate to police, 0 meaning unlimited.
func (q *QERState) effectiveKbps(ul bool, cfg QoSConfig) uint64 {
	if cfg.MBRDisabled || !q.HasMBR {
		return 0
	}
	k := q.MBRDLKbps
	if ul {
		k = q.MBRULKbps
	}
	if k == 0 || k >= qos.UnlimitedKbps {
		return 0
	}
	return k
}

func reconcileBucket(b *qos.Bucket, want uint64, cfg QoSConfig, now int64) *qos.Bucket {
	switch {
	case want == 0:
		return nil
	case b == nil:
		return qos.NewBucket(want, cfg.BurstMs, now)
	case b.Rate() != want:
		b.SetRate(want, now)
	}
	return b
}

func buildQoSView(s *Session, cfg QoSConfig) *qosView {
	if len(s.QERs) == 0 && len(s.PDRs) == 0 {
		return nil
	}
	now := cfg.Clock()
	for _, q := range s.QERs {
		q.ulBucket = reconcileBucket(q.ulBucket, q.effectiveKbps(true, cfg), cfg, now)
		q.dlBucket = reconcileBucket(q.dlBucket, q.effectiveKbps(false, cfg), cfg, now)
	}

	v := &qosView{clock: cfg.Clock, byPDR: make(map[uint16]*pdrView, len(s.PDRs))}
	var accessPDR, corePDR *PDRState
	for _, p := range s.PDRs {
		v.byPDR[p.PDRID] = buildPDRView(s, p)
		switch {
		case p.SourceInterface == srcInterfaceCore:
			corePDR = lowerPrecedence(corePDR, p)
		default:
			accessPDR = lowerPrecedence(accessPDR, p)
		}
	}
	if accessPDR != nil {
		pv := v.byPDR[accessPDR.PDRID]
		v.ul, v.dl = pv.ul, pv.dl
		v.dlQFI, v.hasQFI = firstQFI(s, accessPDR)
	}
	if corePDR != nil {
		// Spec-complete form: a Core-side PDR governs downlink.
		v.dl = v.byPDR[corePDR.PDRID].dl
		if q, ok := firstQFI(s, corePDR); ok {
			v.dlQFI, v.hasQFI = q, true
		}
	}
	return v
}

// lowerPrecedence returns the PDR with the lowest precedence VALUE (highest
// priority); ties break on PDR ID for determinism.
func lowerPrecedence(cur, p *PDRState) *PDRState {
	if cur == nil || p.Precedence < cur.Precedence ||
		(p.Precedence == cur.Precedence && p.PDRID < cur.PDRID) {
		return p
	}
	return cur
}

// orderedQERs resolves a PDR's QER ID list to QERs in evaluation order:
// QoS-flow QERs (carrying a QFI) first, session-level QERs after, each group
// in received order. Unknown IDs cannot occur (validated) and are skipped.
func orderedQERs(s *Session, p *PDRState) []*QERState {
	out := make([]*QERState, 0, len(p.QERIDs))
	for _, id := range p.QERIDs {
		if q := s.QERs[id]; q != nil && q.HasQFI {
			out = append(out, q)
		}
	}
	for _, id := range p.QERIDs {
		if q := s.QERs[id]; q != nil && !q.HasQFI {
			out = append(out, q)
		}
	}
	return out
}

func firstQFI(s *Session, p *PDRState) (uint8, bool) {
	for _, q := range orderedQERs(s, p) {
		if q.HasQFI {
			return q.QFI, true
		}
	}
	return 0, false
}

func buildPDRView(s *Session, p *PDRState) *pdrView {
	pv := &pdrView{}
	for _, q := range orderedQERs(s, p) {
		if q.GateUL == gateClosed {
			pv.ul.gateClosed = true
		}
		if q.GateDL == gateClosed {
			pv.dl.gateClosed = true
		}
		if q.ulBucket != nil {
			pv.ul.buckets = append(pv.ul.buckets, q.ulBucket)
		}
		if q.dlBucket != nil {
			pv.dl.buckets = append(pv.dl.buckets, q.dlBucket)
		}
	}
	return pv
}

// QoSInfo is a deep copy of a session's QoS state for inspection (tests,
// diagnostics). It shares nothing with the live session.
type QoSInfo struct {
	QERs map[uint32]QERState
	PDRs map[uint16]PDRState
	// DLQFI is the QFI the datapath currently puts in DL PDU Session Containers.
	DLQFI uint8
}

// qosInfoLocked copies the QoS state; the caller holds SessionTable.mu.
func qosInfoLocked(s *Session) QoSInfo {
	info := QoSInfo{
		QERs:  make(map[uint32]QERState, len(s.QERs)),
		PDRs:  make(map[uint16]PDRState, len(s.PDRs)),
		DLQFI: s.DLQFI(),
	}
	for id, q := range s.QERs {
		c := *q
		c.ulBucket, c.dlBucket = nil, nil
		info.QERs[id] = c
	}
	for id, p := range s.PDRs {
		c := *p
		c.QERIDs = append([]uint32(nil), p.QERIDs...)
		info.PDRs[id] = c
	}
	return info
}

func sortedQERIDs(m map[uint32]*QERState) []uint32 {
	ids := make([]uint32, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// noPrecedence is the precedence assumed for a PDR without a Precedence IE.
const noPrecedence uint32 = math.MaxUint32
