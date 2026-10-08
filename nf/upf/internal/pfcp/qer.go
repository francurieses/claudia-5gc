package pfcp

// qer.go — parsing, validation and application of the QoS rules carried by
// PFCP Session Establishment and Modification: Create/Update/Remove QER and
// the QER ID list of Create/Update PDR. Validation always completes before
// anything is applied, so a rejected request leaves the session untouched
// (no partial application).
//
// Ref: TS 29.244 §7.5.2.2 (Create PDR), §7.5.2.5 (Create QER), §7.5.4.2
// (Update PDR), §7.5.4.5 (Update QER), §7.5.4.9 (Remove QER), §8.2.1 (Cause),
// §8.2.7 (Gate Status), §8.2.8 (MBR), §8.2.80 (Failed Rule ID).

import (
	"context"
	"log/slog"
	"sort"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// procAmbrEnforcement is the canonical procedure name of these log lines.
const procAmbrEnforcement = "AmbrEnforcement"

// Pre-resolved fivegc_procedure_total children. Counting unit: one increment
// per QER create/update/remove applied (OK) and one per rejected PFCP message
// carrying QoS rules (REJECT). Control plane only, never per packet.
var (
	ambrOK     = metrics.ProcedureTotal.WithLabelValues("UPF", procAmbrEnforcement, "OK")
	ambrReject = metrics.ProcedureTotal.WithLabelValues("UPF", procAmbrEnforcement, "REJECT")
)

// Spec references used in AmbrEnforcement log lines.
const (
	specCreateQER = "TS 29.244 §7.5.2.5"
	specUpdateQER = "TS 29.244 §7.5.4.5"
	specRemoveQER = "TS 29.244 §7.5.4.9"
	specCreatePDR = "TS 29.244 §7.5.2.2"
	specUpdatePDR = "TS 29.244 §7.5.4.2"
	specGate      = "TS 29.244 §8.2.7"
)

// warnFunc reports a lenient-parse fix-up (spec_ref spec, QER ID qerID).
type warnFunc func(msg, spec string, qerID uint32)

// pfcpReject is a rejection decided during validation: the Cause plus the
// IE that identifies the culprit (Offending IE for 66/69, Failed Rule ID for 73).
type pfcpReject struct {
	cause  uint8
	ies    []*pfcpie.IE
	reason string
	// spec is the clause of the IE that failed (log spec_ref).
	spec string
	// ruleType/ruleID/offending are kept for logging.
	offending uint16
	ruleType  uint8
	ruleID    uint32
	isRule    bool
}

func rejectMissing(offending uint16, spec, reason string) *pfcpReject {
	return &pfcpReject{cause: pfcpie.CauseMandatoryIEMissing, ies: []*pfcpie.IE{pfcpie.NewOffendingIE(offending)},
		reason: reason, spec: spec, offending: offending}
}

func rejectIncorrect(offending uint16, spec, reason string) *pfcpReject {
	return &pfcpReject{cause: pfcpie.CauseMandatoryIEIncorrect, ies: []*pfcpie.IE{pfcpie.NewOffendingIE(offending)},
		reason: reason, spec: spec, offending: offending}
}

func rejectRule(ruleType uint8, id uint32, spec, reason string) *pfcpReject {
	return &pfcpReject{cause: pfcpie.CauseRuleCreationModificationFailure,
		ies: []*pfcpie.IE{pfcpie.NewFailedRuleID(ruleType, id)}, reason: reason, spec: spec,
		ruleType: ruleType, ruleID: id, isRule: true}
}

// qerParams is the decoded content of a Create QER or Update QER IE.
type qerParams struct {
	id    uint32
	hasID bool
	hasGate,
	spareGate bool
	gateUL, gateDL uint8 // normalised: 0 OPEN / 1 CLOSED
	hasMBR         bool
	mbrUL, mbrDL   uint64
	hasQFI         bool
	qfi            uint8
}

// normGate maps a Gate Status field to OPEN/CLOSED; the spare values 2 and 3
// are "shall not be sent; if received, interpreted as 1 (CLOSED)" (TS 29.244
// §8.2.7, Table 8.2.7-2) and are reported through spare.
func normGate(v uint8) (g uint8, spare bool) {
	switch v {
	case gateOpen, gateClosed:
		return v, false
	default:
		return gateClosed, true
	}
}

// parseQERParams decodes the children of a Create/Update QER. Only scalars are
// retained (no aliasing of the PFCP receive buffer). ieType is the parent IE
// type, used as Offending IE when the grouped IE itself is malformed.
func parseQERParams(children []*pfcpie.IE, spec string) (qerParams, *pfcpReject) {
	var p qerParams
	for _, c := range children {
		switch c.Type {
		case pfcpie.QERID:
			v, err := c.QERID()
			if err != nil {
				return p, rejectIncorrect(pfcpie.QERID, spec, "QER ID malformed")
			}
			p.id, p.hasID = v, true
		case pfcpie.QFI:
			v, err := c.QFI()
			if err != nil {
				return p, rejectIncorrect(pfcpie.QFI, spec, "QFI malformed")
			}
			p.qfi, p.hasQFI = v, true
		case pfcpie.GateStatus:
			ul, err1 := c.GateStatusUL()
			dl, err2 := c.GateStatusDL()
			if err1 != nil || err2 != nil {
				return p, rejectIncorrect(pfcpie.GateStatus, spec, "Gate Status malformed")
			}
			var s1, s2 bool
			p.gateUL, s1 = normGate(ul)
			p.gateDL, s2 = normGate(dl)
			p.hasGate, p.spareGate = true, s1 || s2
		case pfcpie.MBR:
			ul, err1 := c.MBRUL()
			dl, err2 := c.MBRDL()
			if err1 != nil || err2 != nil {
				return p, rejectIncorrect(pfcpie.MBR, spec, "MBR malformed")
			}
			p.mbrUL, p.mbrDL, p.hasMBR = ul, dl, true
		}
	}
	return p, nil
}

func (p qerParams) newState() *QERState {
	q := &QERState{QERID: p.id, QFI: p.qfi, HasQFI: p.hasQFI,
		HasMBR: p.hasMBR, MBRULKbps: p.mbrUL, MBRDLKbps: p.mbrDL}
	if p.hasGate {
		q.GateUL, q.GateDL = p.gateUL, p.gateDL
	}
	return q
}

// appendQERID appends id to list unless already present (a QER ID listed twice
// in one PDR must not debit the packet twice, TS 29.244 §7.5.2.2); dup reports
// whether it was a duplicate.
func appendQERID(list []uint32, id uint32) (out []uint32, dup bool) {
	for _, v := range list {
		if v == id {
			return list, true
		}
	}
	return append(list, id), false
}

// parsePDRQoS is what the QoS path takes from a Create PDR.
func parsePDRQoS(children []*pfcpie.IE, warn warnFunc) (*PDRState, *pfcpReject) {
	p := &PDRState{SourceInterface: srcInterfaceAccess, Precedence: noPrecedence}
	for _, c := range children {
		switch c.Type {
		case pfcpie.PDRID:
			if v, err := c.PDRID(); err == nil {
				p.PDRID = v
			}
		case pfcpie.Precedence:
			if v, err := c.Precedence(); err == nil {
				p.Precedence = v
			}
		case pfcpie.QERID:
			v, err := c.QERID()
			if err != nil {
				return nil, rejectIncorrect(pfcpie.QERID, specCreatePDR, "PDR QER ID malformed")
			}
			var dup bool
			if p.QERIDs, dup = appendQERID(p.QERIDs, v); dup && warn != nil {
				warn("PDR lists a QER ID more than once, duplicate ignored", specCreatePDR, v)
			}
		case pfcpie.PDI:
			pdi, err := c.PDI()
			if err != nil {
				continue
			}
			for _, pc := range pdi {
				if pc.Type == pfcpie.SourceInterface {
					if v, err := pc.SourceInterface(); err == nil {
						p.SourceInterface = v
					}
				}
			}
		}
	}
	return p, nil
}

// establishmentQoS validates and builds the QoS state of a Session
// Establishment: Create QERs keyed by QER ID plus the PDR list. warn is called
// for lenient fix-ups (absent/spare Gate Status).
func establishmentQoS(createQER []*pfcpie.IE, pdrs []*PDRState, warn warnFunc) (map[uint32]*QERState, map[uint16]*PDRState, *pfcpReject) {
	qers := make(map[uint32]*QERState, len(createQER))
	for _, ie := range createQER {
		children, err := ie.CreateQER()
		if err != nil {
			return nil, nil, rejectIncorrect(pfcpie.CreateQER, specCreateQER, "Create QER malformed")
		}
		p, rej := parseQERParams(children, specCreateQER)
		if rej != nil {
			return nil, nil, rej
		}
		if !p.hasID {
			return nil, nil, rejectMissing(pfcpie.QERID, specCreateQER, "Create QER without QER ID")
		}
		if _, dup := qers[p.id]; dup {
			return nil, nil, rejectRule(pfcpie.RuleIDTypeQER, p.id, specCreateQER, "duplicate QER ID")
		}
		warnGate(p, true, warn)
		qers[p.id] = p.newState()
	}
	pdrMap := make(map[uint16]*PDRState, len(pdrs))
	for _, p := range pdrs {
		pdrMap[p.PDRID] = p
	}
	for _, p := range pdrs {
		for _, id := range p.QERIDs {
			if _, ok := qers[id]; !ok {
				return nil, nil, rejectRule(pfcpie.RuleIDTypePDR, uint32(p.PDRID), specCreatePDR, "PDR references a QER that was not created")
			}
		}
	}
	return qers, pdrMap, nil
}

// warnGate reports lenient Gate Status handling. An absent Gate Status is only
// worth a warning in a Create QER (defaults to OPEN); in an Update QER absent
// means "unchanged" (create=false).
func warnGate(p qerParams, create bool, warn warnFunc) {
	if warn == nil {
		return
	}
	if !p.hasGate {
		if create {
			warn("QER Gate Status absent, defaulting to OPEN", specGate, p.id)
		}
	} else if p.spareGate {
		warn("QER Gate Status spare value 2/3 received, interpreted as CLOSED", specGate, p.id)
	}
}

// pdrListUpdate is a parsed Update PDR carrying a QER ID list.
type pdrListUpdate struct {
	pdrID uint16
	qers  []uint32
}

// modPlan is a validated QoS change set of a Session Modification Request.
type modPlan struct {
	creates []qerParams
	updates []qerParams
	removes []uint32
	pdrs    []pdrListUpdate
}

func (m *modPlan) empty() bool {
	return len(m.creates)+len(m.updates)+len(m.removes)+len(m.pdrs) == 0
}

// planModificationQoS parses the QER/PDR-list IEs of req and validates them
// against sess (callers hold at least the table read lock). Nothing is applied.
func planModificationQoS(sess *Session, req *pfcpmsg.SessionModificationRequest, warn warnFunc) (*modPlan, *pfcpReject) {
	plan := &modPlan{}

	for _, ie := range req.CreateQER {
		children, err := ie.CreateQER()
		if err != nil {
			return nil, rejectIncorrect(pfcpie.CreateQER, specCreateQER, "Create QER malformed")
		}
		p, rej := parseQERParams(children, specCreateQER)
		if rej != nil {
			return nil, rej
		}
		if !p.hasID {
			return nil, rejectMissing(pfcpie.QERID, specCreateQER, "Create QER without QER ID")
		}
		plan.creates = append(plan.creates, p)
	}
	for _, ie := range req.UpdateQER {
		children, err := ie.UpdateQER()
		if err != nil {
			return nil, rejectIncorrect(pfcpie.UpdateQER, specUpdateQER, "Update QER malformed")
		}
		p, rej := parseQERParams(children, specUpdateQER)
		if rej != nil {
			return nil, rej
		}
		if !p.hasID {
			return nil, rejectMissing(pfcpie.QERID, specUpdateQER, "Update QER without QER ID")
		}
		plan.updates = append(plan.updates, p)
	}
	for _, ie := range req.RemoveQER {
		children, err := ie.RemoveQER()
		if err != nil {
			return nil, rejectIncorrect(pfcpie.RemoveQER, specRemoveQER, "Remove QER malformed")
		}
		var id uint32
		found := false
		for _, c := range children {
			if c.Type == pfcpie.QERID {
				v, err := c.QERID()
				if err != nil {
					return nil, rejectIncorrect(pfcpie.QERID, specRemoveQER, "Remove QER QER ID malformed")
				}
				id, found = v, true
			}
		}
		if !found {
			return nil, rejectMissing(pfcpie.QERID, specRemoveQER, "Remove QER without QER ID")
		}
		plan.removes = append(plan.removes, id)
	}
	// Minimal Update PDR: only the QER ID list (TS 29.244 §7.5.4.2). When the
	// list is present it replaces the PDR's list; other children are ignored.
	for _, ie := range req.UpdatePDR {
		children, err := ie.UpdatePDR()
		if err != nil {
			return nil, rejectIncorrect(pfcpie.UpdatePDR, specUpdatePDR, "Update PDR malformed")
		}
		var u pdrListUpdate
		hasID := false
		for _, c := range children {
			switch c.Type {
			case pfcpie.PDRID:
				v, err := c.PDRID()
				if err != nil {
					return nil, rejectIncorrect(pfcpie.PDRID, specUpdatePDR, "Update PDR PDR ID malformed")
				}
				u.pdrID, hasID = v, true
			case pfcpie.QERID:
				v, err := c.QERID()
				if err != nil {
					return nil, rejectIncorrect(pfcpie.QERID, specUpdatePDR, "Update PDR QER ID malformed")
				}
				var dup bool
				if u.qers, dup = appendQERID(u.qers, v); dup && warn != nil {
					warn("Update PDR lists a QER ID more than once, duplicate ignored", specUpdatePDR, v)
				}
			}
		}
		if !hasID {
			return nil, rejectMissing(pfcpie.PDRID, specUpdatePDR, "Update PDR without PDR ID")
		}
		if len(u.qers) > 0 {
			plan.pdrs = append(plan.pdrs, u)
		}
	}
	if plan.empty() {
		return plan, nil
	}

	// Validation against the session as it will look after the message.
	exists := func(id uint32) bool { _, ok := sess.QERs[id]; return ok }
	removed := make(map[uint32]bool, len(plan.removes))
	for _, id := range plan.removes {
		if !exists(id) {
			return nil, rejectRule(pfcpie.RuleIDTypeQER, id, specRemoveQER, "Remove QER for unknown QER ID")
		}
		removed[id] = true
	}
	after := make(map[uint32]bool, len(sess.QERs)+len(plan.creates))
	for id := range sess.QERs {
		if !removed[id] {
			after[id] = true
		}
	}
	for _, p := range plan.creates {
		if exists(p.id) || after[p.id] {
			return nil, rejectRule(pfcpie.RuleIDTypeQER, p.id, specCreateQER, "Create QER with an existing QER ID")
		}
		after[p.id] = true
	}
	for _, p := range plan.updates {
		if !exists(p.id) || removed[p.id] {
			return nil, rejectRule(pfcpie.RuleIDTypeQER, p.id, specUpdateQER, "Update QER for unknown QER ID")
		}
	}
	updatedPDR := make(map[uint16]bool, len(plan.pdrs))
	for _, u := range plan.pdrs {
		if _, ok := sess.PDRs[u.pdrID]; !ok {
			return nil, rejectRule(pfcpie.RuleIDTypePDR, uint32(u.pdrID), specUpdatePDR, "Update PDR for unknown PDR ID")
		}
		updatedPDR[u.pdrID] = true
		for _, id := range u.qers {
			if !after[id] {
				return nil, rejectRule(pfcpie.RuleIDTypePDR, uint32(u.pdrID), specUpdatePDR, "Update PDR references an unknown QER")
			}
		}
	}
	pdrIDs := make([]int, 0, len(sess.PDRs))
	for id := range sess.PDRs {
		pdrIDs = append(pdrIDs, int(id))
	}
	sort.Ints(pdrIDs)
	for _, pid := range pdrIDs {
		if updatedPDR[uint16(pid)] {
			continue
		}
		for _, id := range sess.PDRs[uint16(pid)].QERIDs {
			if !after[id] {
				return nil, rejectRule(pfcpie.RuleIDTypeQER, id, specRemoveQER, "Remove QER still referenced by a PDR")
			}
		}
	}
	for _, p := range plan.creates {
		warnGate(p, true, warn)
	}
	for _, p := range plan.updates {
		warnGate(p, false, warn)
	}
	return plan, nil
}

// applyQoS applies a validated plan and republishes the snapshot. The caller
// holds the table write lock. It returns the QERs that changed, for logging.
func (s *Server) applyQoS(sess *Session, plan *modPlan) (changed []qerChange) {
	for _, id := range plan.removes {
		delete(sess.QERs, id)
		changed = append(changed, qerChange{op: "remove", spec: specRemoveQER, id: id})
	}
	for _, p := range plan.creates {
		q := p.newState()
		sess.QERs[p.id] = q
		changed = append(changed, qerChange{op: "create", spec: specCreateQER, id: p.id, q: *q})
	}
	for _, p := range plan.updates {
		q := sess.QERs[p.id]
		if p.hasGate {
			q.GateUL, q.GateDL = p.gateUL, p.gateDL
		}
		if p.hasMBR {
			q.HasMBR, q.MBRULKbps, q.MBRDLKbps = true, p.mbrUL, p.mbrDL
		}
		if p.hasQFI {
			q.QFI, q.HasQFI = p.qfi, true
		}
		changed = append(changed, qerChange{op: "update", spec: specUpdateQER, id: p.id, q: *q})
	}
	for _, u := range plan.pdrs {
		sess.PDRs[u.pdrID].QERIDs = append([]uint32(nil), u.qers...)
	}
	sess.RebuildQoS(s.qosCfg)
	return changed
}

// logUpdatePDR emits the AmbrEnforcement INFO line for an Update PDR that
// replaced a PDR's QER ID list. Ref: TS 29.244 §7.5.4.2.
func (s *Server) logUpdatePDR(ctx context.Context, seid uint64, u pdrListUpdate) {
	logging.NewProcedureLogger(ctx, s.logger, procAmbrEnforcement).Info("PDR QER list updated",
		"interface", "N4", "direction", "IN", "spec_ref", specUpdatePDR,
		"seid", seid, "pdr_id", u.pdrID, "qer_ids", u.qers, "result", "OK")
}

// qerChange describes one applied QER operation for the log.
type qerChange struct {
	op, spec string
	id       uint32
	q        QERState
}

// logQER emits the canonical AmbrEnforcement INFO line for one QER operation.
func (s *Server) logQER(ctx context.Context, op, spec string, seid uint64, id uint32, q *QERState) {
	ambrOK.Inc()
	logger := logging.NewProcedureLogger(ctx, s.logger, procAmbrEnforcement)
	attrs := []any{
		"interface", "N4", "direction", "IN",
		"spec_ref", spec, "seid", seid, "qer_id", id, "operation", op, "result", "OK",
	}
	if q != nil {
		attrs = append(attrs,
			"qfi", q.QFI, "has_qfi", q.HasQFI, "has_mbr", q.HasMBR,
			"mbr_ul_kbps", q.MBRULKbps, "mbr_dl_kbps", q.MBRDLKbps,
			"gate_ul", q.GateUL, "gate_dl", q.GateDL)
	}
	logger.Info("QER installed", attrs...)
}

// logReject emits the AmbrEnforcement WARN line for a rejected request.
func (s *Server) logReject(ctx context.Context, seid uint64, rej *pfcpReject) {
	ambrReject.Inc()
	logger := logging.NewProcedureLogger(ctx, s.logger, procAmbrEnforcement)
	attrs := []any{
		"interface", "N4", "direction", "IN",
		"spec_ref", rej.spec, "seid", seid, "result", "REJECT", "cause", rej.cause, "reason", rej.reason,
	}
	if rej.isRule {
		attrs = append(attrs, "failed_rule_type", rej.ruleType, "failed_rule_id", rej.ruleID)
	} else {
		attrs = append(attrs, "offending_ie", rej.offending)
	}
	logger.Warn("QoS rules rejected", attrs...)
}

// warnFn returns the lenient-parse warning callback bound to a session.
func (s *Server) warnFn(ctx context.Context, seid uint64) warnFunc {
	return func(msg, spec string, qerID uint32) {
		logging.NewProcedureLogger(ctx, s.logger, procAmbrEnforcement).LogAttrs(ctx, slog.LevelWarn, msg,
			slog.String("interface", "N4"), slog.String("direction", "IN"),
			slog.String("spec_ref", spec), slog.Uint64("seid", seid), slog.Uint64("qer_id", uint64(qerID)))
	}
}

// SessionQoS returns a deep copy of the QoS state (QERs by ID, PDR QER lists,
// current DL QFI) of the session with the given UP SEID, or false if unknown.
func (s *Server) SessionQoS(upSEID uint64) (QoSInfo, bool) {
	s.sessions.mu.RLock()
	defer s.sessions.mu.RUnlock()
	sess := s.sessions.bySEID[upSEID]
	if sess == nil {
		return QoSInfo{}, false
	}
	return qosInfoLocked(sess), true
}

// QERBucketBytes returns the tokens (octets) currently held by the uplink or
// downlink bucket of a QER, evaluated at the enforcement clock. ok is false
// when the session or QER is unknown or the direction is unlimited (no bucket).
func (s *Server) QERBucketBytes(upSEID uint64, qerID uint32, uplink bool) (tokens int64, ok bool) {
	s.sessions.mu.RLock()
	defer s.sessions.mu.RUnlock()
	sess := s.sessions.bySEID[upSEID]
	if sess == nil {
		return 0, false
	}
	q := sess.QERs[qerID]
	if q == nil {
		return 0, false
	}
	b := q.dlBucket
	if uplink {
		b = q.ulBucket
	}
	if b == nil {
		return 0, false
	}
	return b.TokensBytes(s.qosCfg.Clock()), true
}

// QoSConfig returns the effective (normalised) QoS enforcement configuration.
func (s *Server) QoSConfig() QoSConfig { return s.qosCfg }
