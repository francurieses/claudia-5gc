package ngap

// handover.go — Xn and N2 Handover handlers.
// Xn Handover: PathSwitchRequest — TS 23.502 §4.9.1.2.2, TS 38.413 §8.4.4
// N2 Handover: HandoverRequired / HandoverRequest / HandoverRequestAck /
//              HandoverCommand / HandoverNotify — TS 23.502 §4.9.1.3

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/free5gc/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// n2HandoverState holds in-progress N2 handover state between HANDOVER REQUIRED and
// HANDOVER NOTIFY. Created when the HANDOVER REQUEST is sent (after the PREPARING SMF leg);
// consumed when HandoverNotify arrives (or dropped on preparation failure).
type n2HandoverState struct {
	sourceGNB         *GNBContext
	sourceRANUENGAPId int64
	targetGNB         *GNBContext // set after HandoverRequest is sent
	handoverType      int
	causePresent      int
	causeValue        int64
	admittedSessions  []PDUSessionHOAdmittedItem // SMF-accepted subset, populated from HandoverRequestAck
	tgtToSrcContainer []byte                     // populated from HandoverRequestAck
	// prepReleased are the PDU sessions rejected by the SMF in the PREPARING leg (plus the
	// ones the source listed but the AMF does not know); they end in HANDOVER COMMAND IE 78.
	prepReleased []PDUSessionHOReleaseItem
	// correlationID is generated at HANDOVER REQUIRED and reused (context, log field,
	// X-Correlation-Id on the SMF calls) by the HANDOVER REQUEST ACKNOWLEDGE and HANDOVER
	// NOTIFY legs so every leg of one N2 handover shares it.
	correlationID string
	// targetFailed are the PSIs of the HANDOVER REQUEST ACKNOWLEDGE Failed to Setup List that
	// the AMF knows (have an SM context). After HANDOVER NOTIFY the AMF indicates them to the
	// SMF with upCnxState=DEACTIVATED (TS 23.502 §4.3.7 step 1). Never acted on if the
	// handover is not executed. Guarded by Server.pendingN2HOMu.
	targetFailed []uint8
}

// Spec references used by the Xn handover logs (TS 23.502 / TS 38.413 / TS 33.501).
const (
	refXnPathSwitch    = "TS 23.502 §4.9.1.2.2 step 1"
	refXnSMF           = "TS 23.502 §4.9.1.2.2 step 2"
	refXnNHChain       = "TS 33.501 §6.9.2.3.2"
	refXnAck           = "TS 38.413 §8.4.4.2"
	refXnFailure       = "TS 38.413 §8.4.4.3"
	refXnRebind        = "TS 23.502 §4.9.1.2.2 step 7"
	refXnSecCapCheck   = "TS 33.501 §6.7.3.1"
	allowedNSSAIPDUSrc = "pdu_sessions"
)

// secCapCompareMask limits the UE Security Capabilities comparison to NEA1-3 /
// NIA1-3: those are the only algorithms the AMF stores (UESecCapEA/IA[1..3]).
const secCapCompareMask uint16 = 0xE000

// pathSwitchPlan is what the inline part of handlePathSwitchRequest hands to the
// per-UE serial task that runs the synchronous SMF leg.
type pathSwitchPlan struct {
	// requested are the distinct PSIs of the To Be Switched list, in request order.
	requested []uint8
	// transfers maps a requested PSI to its PathSwitchRequestTransfer.
	transfers map[uint8][]byte
	// smRefs maps the UE's known PSIs to their SM context reference.
	smRefs map[uint8]string
	// failed are the Failed to Setup List PSReq items (distinct PSIs).
	failed []PDUSessionFailedSetupItem
}

// xnOutcome is the per-PSI result of the Xn SMF leg.
type xnOutcome struct {
	switched bool
	ack      []byte                 // SMF PathSwitchRequestAcknowledgeTransfer (nil = empty)
	rel      PDUSessionReleasedItem // set when !switched
}

// handlePathSwitchRequest processes an NGAP PathSwitchRequest from the target gNB.
//
// Flow per TS 23.502 §4.9.1.2.2 / TS 38.413 §8.4.4 (docs/procedures/XnHandover.md §7.1, §7.4):
//  1. Inline on the SCTP read loop: identify the UE by Source AMF UE NGAP ID, reject
//     duplicate PSIs (also across the Failed to Setup list), split known / unknown PSIs,
//     pre-check the security context and the Allowed NSSAI (else PATH SWITCH REQUEST
//     FAILURE). The NH chain is NOT advanced yet.
//  2. On the UE's serial queue (completePathSwitch): wait for the SMF leg of every PSI
//     (concurrent, bounded), forward Failed-to-Setup PSIs, classify the outcomes.
//  3. At least one PSI switched: advance NH/NCC (TS 33.501 §6.9.2.3.2) and send PATH SWITCH
//     REQUEST ACKNOWLEDGE (PPID 60) carrying the SMF transfers; none switched: send PATH
//     SWITCH REQUEST FAILURE, no re-bind, no NCC consumed.
//  4. Only after a successful Ack re-bind the UE-associated NG connection to the target
//     gNB and deactivate the UP of UE PDU sessions that are in neither list. The AMF
//     sends NOTHING to the source gNB: the target releases it over XnAP
//     (TS 23.502 §4.9.1.2.2 step 8).
//
// Ref: TS 38.413 §8.4.4
func (s *Server) handlePathSwitchRequest(ctx context.Context, targetGNB *GNBContext, msg *Message) {
	req, ok := msg.Value.(*PathSwitchRequestMsg)
	if !ok {
		s.logger.Error("PathSwitchRequest body decode failed",
			"nf", "AMF", "procedure", procXnHandover, "interface", "N2", "direction", "IN",
			"message_type", "PathSwitchRequest", "result", "FAILURE", "spec_ref", "TS 38.413 §9.2.3.8")
		return
	}
	ctx = withCorrelation(ctx)

	// base carries the procedure-wide fields; each log line adds its own
	// interface / direction / message_type / spec_ref (no duplicate keys).
	base := s.logger.With(
		"nf", "AMF",
		"procedure", procXnHandover,
		"correlation_id", logging.CorrelationID(ctx),
		"amf_ue_ngap_id", req.SourceAMFUENGAPId,
		"ran_ue_ngap_id", req.RANUENGAPId,
	)
	base.Info("PathSwitchRequest received from target gNB",
		"interface", "N2", "direction", "IN", "message_type", "PathSwitchRequest",
		"spec_ref", refXnPathSwitch)

	// Distinct requested PSIs in request order; PSIs duplicated within the To Be Switched
	// list, within the Failed to Setup list, or present in both lists.
	var requested []uint8
	duplicated := map[uint8]bool{}
	seen := map[uint8]bool{}
	transfers := make(map[uint8][]byte, len(req.PDUSessions))
	for _, it := range req.PDUSessions {
		if seen[it.PDUSessionID] {
			duplicated[it.PDUSessionID] = true
			continue
		}
		seen[it.PDUSessionID] = true
		requested = append(requested, it.PDUSessionID)
		transfers[it.PDUSessionID] = it.PathSwitchRequestTransfer
	}
	var failedOnly []uint8 // PSIs of the Failed to Setup list only (request order)
	var failedItems []PDUSessionFailedSetupItem
	failedSeen := map[uint8]bool{}
	for _, f := range req.FailedToSetup {
		if seen[f.PDUSessionID] || failedSeen[f.PDUSessionID] {
			duplicated[f.PDUSessionID] = true
			if failedSeen[f.PDUSessionID] {
				continue
			}
		}
		if !seen[f.PDUSessionID] {
			failedOnly = append(failedOnly, f.PDUSessionID)
		}
		failedSeen[f.PDUSessionID] = true
		failedItems = append(failedItems, f)
	}
	allWith := func(present int, value int64) []PDUSessionReleasedItem {
		out := make([]PDUSessionReleasedItem, 0, len(requested))
		for _, id := range requested {
			out = append(out, PDUSessionReleasedItem{PDUSessionID: id, CausePresent: present, CauseValue: value})
		}
		return out
	}
	radioNet := ngapCausePresentRadioNetwork
	miscUnspecified := int64(ngapType.CauseMiscPresentUnspecified)

	// Step 1: Find UE context by the AMF UE NGAP ID used with the source gNB.
	ue, found := s.mgr.GetByNGAPId(req.SourceAMFUENGAPId)
	if !found {
		s.rejectPathSwitch(base, targetGNB, req, "unknown-local-UE-NGAP-ID", false,
			allWith(radioNet, int64(ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID)))
		return
	}
	base = base.With("supi", ue.SUPI)

	// Step 2a: duplicated PSI (E12: also across the two lists).
	if len(duplicated) > 0 {
		ids := append([]uint8(nil), requested...)
		for _, id := range failedOnly {
			if duplicated[id] {
				ids = append(ids, id)
			}
		}
		items := make([]PDUSessionReleasedItem, 0, len(ids))
		for _, id := range ids {
			it := PDUSessionReleasedItem{PDUSessionID: id, CausePresent: ngapType.CausePresentMisc, CauseValue: miscUnspecified}
			if duplicated[id] {
				it = PDUSessionReleasedItem{PDUSessionID: id, CausePresent: radioNet,
					CauseValue: int64(ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)}
			}
			items = append(items, it)
		}
		s.rejectPathSwitch(base, targetGNB, req, "multiple-PDU-session-ID-instances", false, items)
		return
	}

	// Step 2b: known / unknown PSIs.
	ue.Lock()
	smRefs := make(map[uint8]string, len(ue.PDUSessions))
	for id, sess := range ue.PDUSessions {
		smRefs[id] = sess.SMFInstanceID
	}
	ue.Unlock()
	var unknown []PDUSessionReleasedItem
	known := 0
	for _, id := range requested {
		if _, ok := smRefs[id]; ok {
			known++
			continue
		}
		base.Warn("path switch: PDU session not found in UE context",
			"interface", "N2", "direction", "IN", "pdu_session_id", id, "spec_ref", refXnPathSwitch)
		unknown = append(unknown, PDUSessionReleasedItem{PDUSessionID: id,
			CausePresent: radioNet, CauseValue: int64(ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)})
	}
	if known == 0 {
		s.rejectPathSwitch(base, targetGNB, req, "unknown-PDU-session-ID", false, unknown)
		return
	}

	// Step 3 (pre-check only, nothing advanced): a request that would be rejected for lack
	// of security context / Allowed NSSAI must be rejected BEFORE the SMF switches the UPF
	// to the target gNB (docs/procedures/XnHandover.md §7.4.2).
	ue.Lock()
	allowed, _ := resolveAllowedNSSAI(ue.AllowedNSSAI, ue.PDUSessions)
	chainOK := ue.NHChainUsableLocked()
	ue.Unlock()
	if !chainOK {
		s.rejectPathSwitch(base, targetGNB, req, "no-security-context", true,
			allWith(ngapType.CausePresentMisc, miscUnspecified))
		return
	}
	if len(allowed) == 0 {
		s.rejectPathSwitch(base, targetGNB, req, "no-allowed-nssai", true,
			allWith(ngapType.CausePresentMisc, miscUnspecified))
		return
	}

	// The SMF leg blocks: run it on the UE's serial queue so the target gNB association's
	// read loop keeps serving other UEs (nf/amf/CLAUDE.md §6, doc §7.4.1).
	plan := pathSwitchPlan{requested: requested, transfers: transfers, smRefs: smRefs, failed: failedItems}
	ue.EnqueueSerial(func() {
		s.completePathSwitch(ctx, base, ue, targetGNB, req, plan)
	})
}

// completePathSwitch runs the synchronous SMF leg, builds and sends the Ack / Failure and
// re-binds the UE. It runs on the UE's serial queue. Ref: docs/procedures/XnHandover.md §7.4.2-7.4.4.
func (s *Server) completePathSwitch(ctx context.Context, base *slog.Logger, ue *amfctx.UEContext,
	targetGNB *GNBContext, req *PathSwitchRequestMsg, plan pathSwitchPlan) {
	timeout := s.smfUpdateTimeout()
	pathHook, failHook, deactHook := s.onPathSwitchPDUSession, s.onPathSwitchSetupFail, s.onUPDeactivate

	if pathHook == nil {
		base.Warn("no SMF hook configured — path switch sessions counted as switched with an empty transfer",
			"interface", "Nsmf", "direction", "OUT", "result", smfResultOK, "spec_ref", refXnSMF)
	}

	// Concurrent per-PSI calls; results land in a slice indexed by request position.
	outs := make([]xnOutcome, len(plan.requested))
	var wg sync.WaitGroup
	for i, psi := range plan.requested {
		ref, known := plan.smRefs[psi]
		switch {
		case !known:
			outs[i] = xnOutcome{rel: PDUSessionReleasedItem{PDUSessionID: psi, CausePresent: ngapCausePresentRadioNetwork,
				CauseValue: int64(ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)}}
		case pathHook == nil:
			outs[i] = xnOutcome{switched: true}
		default:
			wg.Add(1)
			go func() {
				defer wg.Done()
				outs[i] = s.xnSwitchPSI(ctx, base, pathHook, timeout, psi, ref, plan.transfers[psi])
			}()
		}
	}
	// Failed to Setup List PSReq: forward each known PSI; outcome is only logged.
	listed := make(map[uint8]bool, len(plan.requested)+len(plan.failed))
	for _, psi := range plan.requested {
		listed[psi] = true
	}
	for _, f := range plan.failed {
		listed[f.PDUSessionID] = true
		ref, known := plan.smRefs[f.PDUSessionID]
		if !known {
			base.Warn("path switch: Failed-to-Setup PDU session not found in UE context",
				"interface", "N2", "direction", "IN", "pdu_session_id", f.PDUSessionID, "spec_ref", refXnPathSwitch)
			continue
		}
		if failHook == nil {
			base.Debug("no SMF hook configured — Failed-to-Setup PDU session not forwarded",
				"interface", "Nsmf", "direction", "IN", "pdu_session_id", f.PDUSessionID, "spec_ref", refXnSMF)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.xnForwardSetupFail(ctx, base, failHook, timeout, f.PDUSessionID, ref, f.PathSwitchRequestSetupFailedTransfer)
		}()
	}
	wg.Wait()

	var switched []PDUSessionSwitchItem
	var released []PDUSessionReleasedItem
	for i, psi := range plan.requested {
		if outs[i].switched {
			switched = append(switched, PDUSessionSwitchItem{PDUSessionID: psi,
				PathSwitchRequestTransfer: plan.transfers[psi], AckTransfer: outs[i].ack})
		} else {
			released = append(released, outs[i].rel)
		}
	}
	// No PSI switched: PATH SWITCH REQUEST FAILURE (TS 23.502 §4.9.1.2.2 step 7).
	if len(switched) == 0 {
		s.rejectPathSwitch(base, targetGNB, req, causeSMFRejectedAll, false, released)
		return
	}

	// Security context: advance the chain only now that an Ack will be built, in one
	// critical section so two hops in flight cannot reuse an NCC (doc §7.2).
	encBm, intBm := s.ueSecCapBitmaps(ue) // takes ue.mu: call before Lock
	ue.Lock()
	allowed, fallback := resolveAllowedNSSAI(ue.AllowedNSSAI, ue.PDUSessions)
	nh, ncc, chainOK := ue.NextNHLocked()
	oldRANUENGAPId := ue.RANUENGAPId
	ue.Unlock()
	if !chainOK || len(allowed) == 0 {
		// E9: chain lost between the pre-check and now (the SMF already switched the UP).
		all := make([]PDUSessionReleasedItem, 0, len(plan.requested))
		for _, psi := range plan.requested {
			all = append(all, PDUSessionReleasedItem{PDUSessionID: psi,
				CausePresent: ngapType.CausePresentMisc, CauseValue: int64(ngapType.CauseMiscPresentUnspecified)})
		}
		s.rejectPathSwitch(base, targetGNB, req, "no-security-context", true, all)
		return
	}
	base.Info("NH chain advanced for path switch",
		"interface", "N2", "direction", "IN", "ncc", ncc, "spec_ref", refXnNHChain)
	if fallback {
		base.Warn("Allowed NSSAI empty — using S-NSSAIs of established PDU sessions",
			"interface", "N2", "direction", "IN", "allowed_nssai_fallback", allowedNSSAIPDUSrc, "spec_ref", "TS 23.501 §5.15.5.3")
	}

	// UE Security Capabilities: echo the stored ones only when the target's differ.
	var secCap *UESecCapBitmaps
	if req.UESecCap != nil &&
		(req.UESecCap.Enc&secCapCompareMask != encBm&secCapCompareMask ||
			req.UESecCap.Int&secCapCompareMask != intBm&secCapCompareMask) {
		secCap = &UESecCapBitmaps{Enc: encBm, Int: intBm}
		base.Warn("UE Security Capabilities in PathSwitchRequest differ from stored ones",
			"interface", "N2", "direction", "IN", "result", "MISMATCH", "spec_ref", refXnSecCapCheck)
	}

	// PATH SWITCH REQUEST ACKNOWLEDGE (TS 38.413 Table 9.2.3.9-1 order), PPID 60.
	ack := BuildPathSwitchRequestAcknowledge(PathSwitchAckParams{
		AMFUENGAPId:  req.SourceAMFUENGAPId,
		RANUENGAPId:  req.RANUENGAPId,
		UESecCap:     secCap,
		NCC:          ncc,
		NH:           nh,
		Switched:     switched,
		Released:     released,
		AllowedNSSAI: allowed,
	})
	if ack == nil {
		base.Error("failed to build PathSwitchRequestAcknowledge",
			"interface", "N2", "direction", "OUT", "result", "FAILURE", "spec_ref", refXnAck)
		metrics.HandoverTotal.WithLabelValues("AMF", "xn", "FAILURE").Inc()
		metrics.ProcedureTotal.WithLabelValues("AMF", "XnHandover", "FAILURE").Inc()
		return
	}
	if _, err := targetGNB.writeNGAP(ack); err != nil {
		base.Error("send PathSwitchRequestAcknowledge failed",
			"interface", "N2", "direction", "OUT", "result", "FAILURE", "error", err, "spec_ref", refXnAck)
		metrics.HandoverTotal.WithLabelValues("AMF", "xn", "FAILURE").Inc()
		metrics.ProcedureTotal.WithLabelValues("AMF", "XnHandover", "FAILURE").Inc()
		return
	}
	base.Info("PathSwitchRequestAcknowledge sent",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "PathSwitchRequestAcknowledge",
		"ncc", ncc,
		"switched_sessions", len(switched),
		"released_sessions", len(released),
		"result", "OK",
		"spec_ref", refXnAck,
	)

	// Re-bind the UE-associated logical NG connection to the target gNB.
	// No NGAP is sent to the source gNB (it is released over XnAP by the target).
	sourceGNB := s.findSourceGNB(ue)
	if sourceGNB != nil {
		sourceGNB.mu.Lock()
		delete(sourceGNB.UEs, oldRANUENGAPId)
		sourceGNB.mu.Unlock()
	}
	targetGNB.mu.Lock()
	targetGNB.UEs[req.RANUENGAPId] = ue
	targetGNB.mu.Unlock()

	addr := targetGNB.remoteAddrString()
	ue.Lock()
	ue.RANUENGAPId = req.RANUENGAPId
	ue.GNBAddr = addr
	if req.TAI != nil {
		ue.TAI = amfctx.TAI{MCC: req.TAI.MCC, MNC: req.TAI.MNC, TAC: req.TAI.TAC}
	}
	ue.Unlock()

	base.Info("Xn Handover complete — UE context moved to target gNB",
		"interface", "N2",
		"direction", "IN",
		"old_ran_ue_ngap_id", oldRANUENGAPId,
		"new_ran_ue_ngap_id", req.RANUENGAPId,
		"result", "OK",
		"spec_ref", refXnRebind,
	)
	metrics.HandoverTotal.WithLabelValues("AMF", "xn", "OK").Inc()
	metrics.ProcedureTotal.WithLabelValues("AMF", "XnHandover", "OK").Inc()

	// UE PDU sessions in neither request list: deactivate their UP connection at the SMF
	// (never ReleaseSMContext, sessions stay in the UE context). Async, errors only logged.
	s.deactivateUnlistedSessions(ctx, base, ue, listed, deactHook, timeout)
}

// xnSwitchPSI performs the PATH_SWITCH_REQ UpdateSMContext of one PDU session and
// classifies the answer (docs/procedures/XnHandover.md §7.4.2, §5.1 E1-E7).
func (s *Server) xnSwitchPSI(ctx context.Context, base *slog.Logger, hook SMFTransferHook, timeout time.Duration,
	psi uint8, ref string, transfer []byte) xnOutcome {
	base.Info("UpdateSMContext for path switch",
		"interface", "Nsmf", "direction", "OUT", "message_type", "UpdateSMContext",
		"n2_sm_info_type", n2InfoPathSwitchReq, "pdu_session_id", psi, "spec_ref", refXnSMF)
	res, dur, timedOut := callSMF(ctx, timeout, hook, ref, transfer)
	log := base.With("interface", "Nsmf", "direction", "IN", "message_type", "UpdateSMContextResponse",
		"pdu_session_id", psi, "n2_sm_info_type", res.N2SmInfoType, "http_status", res.HTTPStatus,
		"duration_ms", dur.Milliseconds(), "spec_ref", refXnSMFResp)

	// A 2xx answer carrying PATH_SWITCH_REQ_FAIL is a failure of that PDU session
	// (TS 23.502 §4.9.1.2.2 step 6; TS 38.413 §9.3.4 (Path Switch Request Unsuccessful Transfer)).
	if res.OK() && res.N2SmInfoType != n2InfoPathSwitchReqFail {
		out := xnOutcome{switched: true}
		legResult := smfResultOK
		switch {
		case len(res.N2SmInfo) == 0:
			log.Warn("SMF returned no n2SmInfo — empty PathSwitchRequestAcknowledgeTransfer used",
				"smf_n2sminfo", "absent", "result", smfResultOK)
		case res.N2SmInfoType != n2InfoPathSwitchReqAck:
			log.Error("SMF returned n2SmInfo of an unexpected type — empty PathSwitchRequestAcknowledgeTransfer used",
				"cause", causeInvalidN2SmInfo, "expected_n2_sm_info_type", n2InfoPathSwitchReqAck, "result", smfResultFailure)
			legResult = smfResultFailure
		case !validPathSwitchAckTransfer(res.N2SmInfo):
			log.Error("SMF returned undecodable n2SmInfo — empty PathSwitchRequestAcknowledgeTransfer used",
				"cause", causeInvalidN2SmInfo, "result", smfResultFailure)
			legResult = smfResultFailure
		default:
			out.ack = res.N2SmInfo
			log.Info("SMF switched PDU session", "result", smfResultOK)
		}
		recordSMFLeg(procXnSMFUpdate, legResult)
		return out
	}

	present, value := failCause(res, timedOut)
	rel := PDUSessionReleasedItem{PDUSessionID: psi, CausePresent: present, CauseValue: value}
	cause := failCauseLabel(res, timedOut)
	if res.Err != nil {
		log.Error("SMF path switch update failed", "cause", cause, "error", res.Err, "result", smfResultFailure)
		recordSMFLeg(procXnSMFUpdate, smfResultFailure)
		return xnOutcome{rel: rel}
	}
	if res.N2SmInfoType == n2InfoPathSwitchReqFail && validPathSwitchUnsuccessfulTransfer(res.N2SmInfo) {
		rel.Transfer = res.N2SmInfo
	} else if len(res.N2SmInfo) > 0 {
		log.Error("SMF returned unusable PathSwitchRequestUnsuccessfulTransfer — AMF-built cause used",
			"cause", causeInvalidN2SmInfo, "result", smfResultFailure)
	}
	log.Warn("SMF rejected path switch of PDU session", "cause", cause, "result", smfResultReject)
	recordSMFLeg(procXnSMFUpdate, smfResultReject)
	return xnOutcome{rel: rel}
}

// xnForwardSetupFail forwards one Failed to Setup List PSReq PDU session to the SMF
// (PATH_SWITCH_SETUP_FAIL, failedToBeSwitched=true). The outcome is only logged
// (doc §5.1 E10).
func (s *Server) xnForwardSetupFail(ctx context.Context, base *slog.Logger, hook SMFTransferHook, timeout time.Duration,
	psi uint8, ref string, transfer []byte) {
	base.Info("UpdateSMContext for path switch setup failure",
		"interface", "Nsmf", "direction", "OUT", "message_type", "UpdateSMContext",
		"n2_sm_info_type", n2InfoPathSwitchSetupFl, "failed_to_be_switched", true,
		"pdu_session_id", psi, "spec_ref", refXnSMF)
	res, dur, timedOut := callSMF(ctx, timeout, hook, ref, transfer)
	log := base.With("interface", "Nsmf", "direction", "IN", "message_type", "UpdateSMContextResponse",
		"pdu_session_id", psi, "n2_sm_info_type", n2InfoPathSwitchSetupFl, "http_status", res.HTTPStatus,
		"duration_ms", dur.Milliseconds(), "spec_ref", refXnSMFResp)
	switch {
	case res.OK():
		log.Info("SMF accepted PATH_SWITCH_SETUP_FAIL", "result", smfResultOK)
		recordSMFLeg(procXnSMFSetupFail, smfResultOK)
	case res.Err != nil:
		log.Warn("SMF PATH_SWITCH_SETUP_FAIL update failed", "cause", failCauseLabel(res, timedOut),
			"error", res.Err, "result", smfResultFailure)
		recordSMFLeg(procXnSMFSetupFail, smfResultFailure)
	default:
		log.Warn("SMF rejected PATH_SWITCH_SETUP_FAIL", "cause", failCauseLabel(res, timedOut), "result", smfResultReject)
		recordSMFLeg(procXnSMFSetupFail, smfResultReject)
	}
}

// deactivateUnlistedSessions sends Nsmf_PDUSession_UpdateSMContext upCnxState=DEACTIVATED
// for every UE PDU session whose PSI is in neither list of the Path Switch Request
// (asynchronously, one call each, bounded by timeout). Failures are only logged
// (doc §5.1 E13). Ref: docs/procedures/XnHandover.md §7.4.4.
func (s *Server) deactivateUnlistedSessions(ctx context.Context, base *slog.Logger, ue *amfctx.UEContext,
	listed map[uint8]bool, hook UPDeactivateHook, timeout time.Duration) {
	ue.Lock()
	type sessRef struct {
		psi uint8
		ref string
	}
	var todo []sessRef
	for id, sess := range ue.PDUSessions {
		if !listed[id] {
			todo = append(todo, sessRef{id, sess.SMFInstanceID})
		}
	}
	ue.Unlock()
	if len(todo) == 0 {
		return
	}
	sort.Slice(todo, func(i, j int) bool { return todo[i].psi < todo[j].psi })
	if hook == nil {
		base.Warn("no SMF hook configured — UP of PDU sessions not in the Path Switch Request not deactivated",
			"interface", "Nsmf", "direction", "IN", "sessions", len(todo), "spec_ref", refXnSMFDeact)
		return
	}
	for _, t := range todo {
		base.Info("UpdateSMContext upCnxState DEACTIVATED for PDU session not in the Path Switch Request",
			"interface", "Nsmf", "direction", "OUT", "message_type", "UpdateSMContext",
			"up_cnx_state", "DEACTIVATED", "pdu_session_id", t.psi, "spec_ref", refXnSMFDeact)
		go func() {
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			start := time.Now()
			err := hook(cctx, t.ref)
			log := base.With("interface", "Nsmf", "direction", "IN", "message_type", "UpdateSMContextResponse",
				"up_cnx_state", "DEACTIVATED", "pdu_session_id", t.psi,
				"duration_ms", time.Since(start).Milliseconds(), "spec_ref", refXnSMFDeact)
			if err != nil {
				log.Warn("UP deactivation of PDU session failed", "result", smfResultFailure, "error", err)
				recordSMFLeg(procXnSMFDeactivate, smfResultFailure)
				return
			}
			log.Info("UP deactivated at SMF", "result", smfResultOK)
			recordSMFLeg(procXnSMFDeactivate, smfResultOK)
		}()
	}
}

// rejectPathSwitch sends a PATH SWITCH REQUEST FAILURE (PPID 60) with the given
// per-session causes and logs it (WARN, or ERROR when isError). The UE is never
// re-bound. log carries the procedure fields only. Ref: TS 38.413 §8.4.4.3, §9.2.3.10.
func (s *Server) rejectPathSwitch(log *slog.Logger, targetGNB *GNBContext, req *PathSwitchRequestMsg,
	reason string, isError bool, items []PDUSessionReleasedItem) {
	logf := log.Warn
	if isError {
		logf = log.Error
	}
	logf("PathSwitchRequestFailure",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "PathSwitchRequestFailure",
		"result", "REJECT",
		"cause", reason,
		"spec_ref", refXnFailure,
	)
	metrics.HandoverTotal.WithLabelValues("AMF", "xn", "REJECT").Inc()
	metrics.ProcedureTotal.WithLabelValues("AMF", "XnHandover", "REJECT").Inc()
	pdu := BuildPathSwitchRequestFailure(req.SourceAMFUENGAPId, req.RANUENGAPId, items)
	if pdu == nil {
		log.Error("failed to build PathSwitchRequestFailure",
			"interface", "N2", "direction", "OUT", "result", "FAILURE", "cause", reason, "spec_ref", refXnFailure)
		return
	}
	if _, err := targetGNB.writeNGAP(pdu); err != nil {
		log.Error("send PathSwitchRequestFailure failed",
			"interface", "N2", "direction", "OUT", "result", "FAILURE", "error", err, "spec_ref", refXnFailure)
	}
}

// resolveAllowedNSSAI returns the Allowed NSSAI to advertise: the UE's Allowed NSSAI,
// de-duplicated on (SST, SD); when empty, the de-duplicated S-NSSAIs of the UE's
// established PDU sessions (fallback=true). A PDU session can only exist on an
// allowed slice, so the fallback never grants a new slice. Empty result: nothing to
// advertise. Caller holds ue.mu. Ref: docs/procedures/XnHandover.md §7.3.
func resolveAllowedNSSAI(allowed []amfctx.SNSSAISubscribed, sessions map[uint8]*amfctx.PDUSession) (out []amfctx.SNSSAISubscribed, fallback bool) {
	dedupe := func(in []amfctx.SNSSAISubscribed) []amfctx.SNSSAISubscribed {
		type key struct {
			sst uint8
			sd  string
		}
		seen := map[key]bool{}
		var res []amfctx.SNSSAISubscribed
		for _, n := range in {
			if k := (key{n.SST, n.SD}); !seen[k] {
				seen[k] = true
				res = append(res, n)
			}
		}
		return res
	}
	if out = dedupe(allowed); len(out) > 0 {
		return out, false
	}
	ids := make([]int, 0, len(sessions))
	for id := range sessions {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	var fromSessions []amfctx.SNSSAISubscribed
	for _, id := range ids {
		sn := sessions[uint8(id)].SNSSAI
		if sn.SST == 0 { // S-NSSAI absent (SST 0 is not a valid value)
			continue
		}
		fromSessions = append(fromSessions, sn)
	}
	out = dedupe(fromSessions)
	return out, len(out) > 0
}

// findSourceGNB returns the GNBContext that currently holds the UE in its UEs map,
// or nil if not found (UE may already be in idle).
func (s *Server) findSourceGNB(ue *amfctx.UEContext) *GNBContext {
	amfID := ue.AMFUENGAPId
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, gnb := range s.gnbs {
		gnb.mu.Lock()
		for _, candidate := range gnb.UEs {
			if candidate.AMFUENGAPId == amfID {
				gnb.mu.Unlock()
				return gnb
			}
		}
		gnb.mu.Unlock()
	}
	return nil
}

const (
	ngapCausePresentRadioNetwork = ngapType.CausePresentRadioNetwork
	// ngapCauseSuccessfulHandover is radioNetwork "successful-handover" (2).
	ngapCauseSuccessfulHandover = int64(ngapType.CauseRadioNetworkPresentSuccessfulHandover)
)

// ---- N2 Handover (TS 23.502 §4.9.1.3 / TS 38.413 §8.4) --------------------

// n2HandoverContext returns ctx carrying the correlation ID of the pending N2 handover
// (generated at HANDOVER REQUIRED); when there is no pending state (or it predates the ID)
// a fresh one is generated when ctx has none.
func n2HandoverContext(ctx context.Context, state *n2HandoverState) context.Context {
	if state != nil && state.correlationID != "" {
		return logging.WithCorrelationID(ctx, state.correlationID)
	}
	return withCorrelation(ctx)
}

// n2Base returns the logger carrying the procedure-wide fields of one N2 handover; every
// line adds its own interface / direction / message_type / spec_ref (no duplicate keys).
func (s *Server) n2Base(ctx context.Context, amfUENGAPId int64) *slog.Logger {
	return s.logger.With(
		"nf", "AMF",
		"procedure", procN2Handover,
		"correlation_id", logging.CorrelationID(ctx),
		"amf_ue_ngap_id", amfUENGAPId,
	)
}

// hoCandidate is one PDU session considered for an N2 handover.
type hoCandidate struct {
	psi      uint8
	ref      string // SM context reference
	snssai   amfctx.SNSSAISubscribed
	cached   []byte // N2SmTransfer cached at PDU session establishment (may be empty)
	required []byte // source gNB's HandoverRequiredTransfer (nil when none)
}

// hoPrepOutcome is the per-PSI result of the PREPARING leg.
type hoPrepOutcome struct {
	accepted bool
	transfer []byte                  // PDUSessionResourceSetupRequestTransfer for the HANDOVER REQUEST
	rel      PDUSessionHOReleaseItem // set when !accepted
}

// handleHandoverRequired processes NGAP HandoverRequired from the source gNB.
//
// Flow (TS 23.502 §4.9.1.3.2 steps 1-8; TS 38.413 §8.4.1, §8.4.2):
//  1. Inline on the SCTP read loop: decode, UE lookup, target gNB resolution,
//     source != target, side-effect-free security pre-check (NH chain NOT advanced).
//  2. On the UE's serial queue (continueHandoverPreparation): PREPARING
//     Nsmf_PDUSession_UpdateSMContext per candidate PDU session (steps 3-6), advance NH/NCC
//     only when >= 1 PDU session is left, send HANDOVER REQUEST (step 8) and store the
//     pending state so HANDOVER REQUEST ACKNOWLEDGE can continue.
//
// Ref: TS 38.413 §8.4.1.2, §9.2.3.1; TS 23.502 §4.9.1.3.2
func (s *Server) handleHandoverRequired(ctx context.Context, sourceGNB *GNBContext, msg *Message) {
	req, ok := msg.Value.(*HandoverRequiredMsg)
	if !ok {
		s.logger.Error("HandoverRequired body decode failed",
			"nf", "AMF", "procedure", procN2Handover, "interface", "N2", "direction", "IN",
			"message_type", "HandoverRequired", "result", "FAILURE", "spec_ref", "TS 38.413 §9.2.3.1")
		return
	}
	ctx = withCorrelation(ctx)

	log := s.n2Base(ctx, req.AMFUENGAPId).With("ran_ue_ngap_id", req.RANUENGAPId)
	log.Info("HandoverRequired received from source gNB",
		"interface", "N2", "direction", "IN", "message_type", "HandoverRequired",
		"connected_gnbs", strings.Join(s.connectedGNBIDs(), ","),
		"target_id_hex", hex.EncodeToString(req.TargetGlobalRANNodeID),
		"spec_ref", refN2Required)

	ue, found := s.mgr.GetByNGAPId(req.AMFUENGAPId)
	if !found {
		log.Warn("HandoverRequired: UE not found by AMFUENGAPId",
			"interface", "N2", "direction", "IN", "spec_ref", refN2Required)
		s.rejectHandoverPreparation(log, sourceGNB, req, "unknown-local-ue-ngap-id",
			ngapCausePresentRadioNetwork, int64(ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID))
		return
	}
	log = log.With("supi", ue.SUPI)

	// Resolve target gNB by matching GlobalRANNodeID bytes.
	targetGNB := s.findGNBByGlobalID(req.TargetGlobalRANNodeID)
	if targetGNB == nil {
		log.Warn("HandoverRequired: target gNB not found — is it connected and NG Setup complete?",
			"interface", "N2", "direction", "IN", "spec_ref", refN2Required,
			"target_id_hex", hex.EncodeToString(req.TargetGlobalRANNodeID),
			"connected_gnb_ids", strings.Join(s.connectedGNBIDs(), ","),
		)
		s.rejectHandoverPreparation(log, sourceGNB, req, "unknown-target-id",
			ngapCausePresentRadioNetwork, int64(ngapType.CauseRadioNetworkPresentUnknownTargetID))
		return
	}
	if targetGNB == sourceGNB {
		log.Warn("HandoverRequired: source and target gNB resolved to the same connection",
			"interface", "N2", "direction", "IN", "spec_ref", refN2Required,
			"target_id_hex", hex.EncodeToString(req.TargetGlobalRANNodeID),
		)
		s.rejectHandoverPreparation(log, sourceGNB, req, "unknown-target-id",
			ngapCausePresentRadioNetwork, int64(ngapType.CauseRadioNetworkPresentUnknownTargetID))
		return
	}
	log.Info("HandoverRequired: target gNB resolved",
		"interface", "N2", "direction", "IN", "spec_ref", refN2Required,
		"target_gnb_addr", targetGNB.remoteAddrString(),
		"target_gnb_name", targetGNB.Name,
	)

	// Side-effect-free pre-check: the NH chain is advanced only once the SMF leg left at least
	// one PDU session, so a preparation that fails at the SMF consumes no NCC (same rule as
	// the Xn path). Ref: TS 33.501 §6.9.2.3.3.
	ue.Lock()
	chainOK := ue.NHChainUsableLocked()
	ue.Unlock()
	if !chainOK {
		log.Error("HandoverRequired: no usable security context — NH chain not initialised",
			"interface", "N2", "direction", "IN", "result", smfResultFailure, "spec_ref", "TS 33.501 §6.9.2.3.3")
		s.rejectHandoverPreparation(log, sourceGNB, req, "no-nh-chain",
			ngapType.CausePresentMisc, int64(ngapType.CauseMiscPresentUnspecified))
		return
	}

	// The SMF leg blocks: run it on the UE's serial queue so the source gNB association's
	// read loop keeps serving other UEs (nf/amf/CLAUDE.md §6).
	ue.EnqueueSerial(func() {
		s.continueHandoverPreparation(ctx, log, ue, sourceGNB, targetGNB, req)
	})
}

// continueHandoverPreparation runs the PREPARING SMF leg, advances NH/NCC and sends the
// HANDOVER REQUEST. It runs on the UE's serial queue.
// Ref: TS 23.502 §4.9.1.3.2 steps 3-8; docs/procedures/XnHandover.md §4.6.
func (s *Server) continueHandoverPreparation(ctx context.Context, log *slog.Logger, ue *amfctx.UEContext,
	sourceGNB, targetGNB *GNBContext, req *HandoverRequiredMsg) {
	timeout := s.smfUpdateTimeout()
	hook := s.onHandoverRequired

	// ueSecCapBitmaps must be called OUTSIDE the lock — it acquires ue.Lock() internally and
	// Go's sync.Mutex is not reentrant.
	encAlgsBitmap, intAlgsBitmap := s.ueSecCapBitmaps(ue)
	ue.Lock()
	allowedNSSAI := ue.AllowedNSSAI
	ueAMBR := NewUEAMBRFromKbps(ue.SubscribedAMBR.UL, ue.SubscribedAMBR.DL)
	uePDUSessions := make(map[uint8]hoCandidate, len(ue.PDUSessions))
	for id, sess := range ue.PDUSessions {
		uePDUSessions[id] = hoCandidate{psi: id, ref: sess.SMFInstanceID, snssai: sess.SNSSAI, cached: sess.N2SmTransfer}
	}
	ue.Unlock()

	log.Info("HandoverRequired: PDU session state",
		"interface", "N2", "direction", "IN", "spec_ref", refN2Required,
		"req_sessions_from_gnb", len(req.PDUSessions),
		"ue_sessions_in_amf", len(uePDUSessions),
	)

	// Candidate PDU sessions: the PSIs the source listed that the AMF knows (with their
	// HandoverRequiredTransfer); PSIs unknown to the AMF are WARNed and later listed in
	// HANDOVER COMMAND IE 78 (unknown-PDU-session-ID). Source listed none: every UE session.
	var cands []hoCandidate
	var unknown []PDUSessionHOReleaseItem
	if len(req.PDUSessions) > 0 {
		seen := map[uint8]bool{}
		for _, item := range req.PDUSessions {
			if seen[item.PDUSessionID] {
				continue
			}
			seen[item.PDUSessionID] = true
			c, known := uePDUSessions[item.PDUSessionID]
			if !known {
				log.Warn("HandoverRequired: PDU session from gNB not found in UE context",
					"interface", "N2", "direction", "IN", "spec_ref", refN2Required, "pdu_session_id", item.PDUSessionID)
				if hook != nil {
					unknown = append(unknown, PDUSessionHOReleaseItem{PDUSessionID: item.PDUSessionID,
						CausePresent: ngapCausePresentRadioNetwork,
						CauseValue:   int64(ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)})
				}
				continue
			}
			c.required = item.HandoverRequiredTransfer
			if hook == nil && len(c.cached) == 0 {
				log.Warn("HandoverRequired: session from gNB has no cached N2SmTransfer",
					"interface", "N2", "direction", "IN", "spec_ref", refN2Required, "pdu_session_id", item.PDUSessionID)
				continue
			}
			cands = append(cands, c)
		}
	} else if len(uePDUSessions) > 0 {
		// Fallback: source gNB omitted PDU sessions from HandoverRequired but the AMF has them
		// in the UE context (e.g. the gNB did not complete PDUSessionResourceSetup before the
		// handover timer fired — common in PacketRusher). No HandoverRequiredTransfer.
		// Ref: TS 38.413 §9.2.3.4 (PDUSessionResourceSetupListHOReq)
		log.Info("HandoverRequired: source gNB listed no PDU sessions — falling back to AMF UE context",
			"interface", "N2", "direction", "IN", "ue_sessions_in_amf", len(uePDUSessions),
			"spec_ref", "TS 38.413 §9.2.3.4")
		ids := make([]int, 0, len(uePDUSessions))
		for id := range uePDUSessions {
			ids = append(ids, int(id))
		}
		sort.Ints(ids)
		for _, id := range ids {
			c := uePDUSessions[uint8(id)]
			if hook == nil && len(c.cached) == 0 {
				continue
			}
			cands = append(cands, c)
		}
	}

	// Mandatory HANDOVER REQUEST IEs are checked BEFORE the SMF is consulted so a doomed
	// preparation leaves no SMF session in hoState PREPARING.
	if missing := HandoverRequestMissingIE(len(cands), len(allowedNSSAI), len(req.SourceToTargetTransparentContainer)); missing != "" {
		log.Error("HandoverRequired: mandatory HandoverRequest IE unavailable — preparation aborted",
			"interface", "N2", "direction", "OUT", "result", smfResultFailure, "missing_ie", missing,
			"spec_ref", "TS 38.413 §9.2.3.4 Table 9.2.3.4-1")
		s.rejectHandoverPreparation(log, sourceGNB, req, "missing-ie-"+missing,
			ngapType.CausePresentMisc, int64(ngapType.CauseMiscPresentUnspecified))
		return
	}

	// PREPARING leg (steps 3-6), concurrent per PDU session.
	outs := make([]hoPrepOutcome, len(cands))
	if hook == nil {
		log.Warn("no SMF hook configured — cached N2SmTransfer used for HANDOVER REQUEST, no PREPARING call",
			"interface", "Nsmf", "direction", "OUT", "spec_ref", refN2PreparingReq)
		for i, c := range cands {
			outs[i] = hoPrepOutcome{accepted: true, transfer: c.cached}
		}
	} else {
		var wg sync.WaitGroup
		for i, c := range cands {
			wg.Add(1)
			go func() {
				defer wg.Done()
				outs[i] = s.n2PreparingSMF(ctx, log, hook, timeout, c, req.Target)
			}()
		}
		wg.Wait()
	}
	var sessions []PDUSessionHOReqItem
	var prepReleased []PDUSessionHOReleaseItem
	for i, c := range cands {
		if outs[i].accepted {
			sessions = append(sessions, PDUSessionHOReqItem{PDUSessionID: c.psi, SNSSAI: c.snssai,
				HandoverRequestTransfer: outs[i].transfer})
		} else {
			prepReleased = append(prepReleased, outs[i].rel)
		}
	}
	if len(sessions) == 0 {
		// Every candidate was rejected by the SMF: no NCC consumed, no pending state.
		s.rejectHandoverPreparation(log, sourceGNB, req, causeSMFRejectedAll, ngapCausePresentRadioNetwork,
			int64(ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem))
		return
	}
	prepReleased = append(prepReleased, unknown...)

	// Advance the per-UE NH chain: NCC := (NCC+1) mod 8, NH := KNH(KAMF, NH_prev).
	// Ref: TS 33.501 §6.9.2.3.3, Annex A.10
	ue.Lock()
	nh, nhNCC, nhOK := ue.NextNHLocked()
	ue.Unlock()
	if !nhOK {
		log.Error("HandoverRequired: no usable security context — NH chain not initialised",
			"interface", "N2", "direction", "IN", "result", smfResultFailure, "spec_ref", "TS 33.501 §6.9.2.3.3")
		s.rejectHandoverPreparation(log, sourceGNB, req, "no-nh-chain",
			ngapType.CausePresentMisc, int64(ngapType.CauseMiscPresentUnspecified))
		return
	}
	log.Info("HandoverRequired: NH chain advanced",
		"interface", "N2", "direction", "IN", "ncc", nhNCC, "spec_ref", "TS 33.501 §6.9.2.3.3")

	pdu := BuildHandoverRequest(
		req.AMFUENGAPId,
		req.HandoverType,
		req.CausePresent, req.CauseValue,
		ueAMBR,
		nhNCC, nh,
		encAlgsBitmap, intAlgsBitmap,
		sessions,
		allowedNSSAI,
		req.SourceToTargetTransparentContainer,
		s.cfg.MCC, s.cfg.MNC,
		s.cfg.RegionID, s.cfg.SetID, s.cfg.AMFID,
	)
	if pdu == nil {
		log.Error("BuildHandoverRequest failed",
			"interface", "N2", "direction", "OUT", "result", smfResultFailure, "spec_ref", "TS 38.413 §9.2.3.4")
		s.rejectHandoverPreparation(log, sourceGNB, req, "encode-failure",
			ngapType.CausePresentMisc, int64(ngapType.CauseMiscPresentUnspecified))
		return
	}

	// Pending state is stored BEFORE the HANDOVER REQUEST is written so a fast target
	// HANDOVER REQUEST ACKNOWLEDGE always finds it; consumed by
	// handleHandoverRequestAcknowledge / HandoverNotify.
	state := &n2HandoverState{
		sourceGNB:         sourceGNB,
		sourceRANUENGAPId: req.RANUENGAPId,
		targetGNB:         targetGNB,
		handoverType:      req.HandoverType,
		causePresent:      req.CausePresent,
		causeValue:        req.CauseValue,
		prepReleased:      prepReleased,
		correlationID:     logging.CorrelationID(ctx),
	}
	s.pendingN2HOMu.Lock()
	s.pendingN2HO[req.AMFUENGAPId] = state
	s.pendingN2HOMu.Unlock()

	if _, err := targetGNB.writeNGAP(pdu); err != nil {
		log.Error("HandoverRequest send failed",
			"interface", "N2", "direction", "OUT", "result", smfResultFailure, "error", err, "spec_ref", "TS 38.413 §8.4.2.2")
		s.pendingN2HOMu.Lock()
		if s.pendingN2HO[req.AMFUENGAPId] == state {
			delete(s.pendingN2HO, req.AMFUENGAPId)
		}
		s.pendingN2HOMu.Unlock()
		s.rejectHandoverPreparation(log, sourceGNB, req, "target-send-failure",
			ngapType.CausePresentMisc, int64(ngapType.CauseMiscPresentUnspecified))
		return
	}
	log.Info("HandoverRequest sent to target gNB",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "HandoverRequest",
		"handover_sessions", len(sessions),
		"rejected_sessions", len(prepReleased),
		"result", smfResultOK,
		"spec_ref", refN2HOReq+"; TS 38.413 §8.4.2.2",
	)
}

// n2PreparingSMF performs the PREPARING UpdateSMContext (hoState=PREPARING,
// HANDOVER_REQUIRED) of one candidate PDU session and classifies the answer.
// Ref: TS 23.502 §4.9.1.3.2 steps 3-6; TS 29.502 §5.2.2.3.4.
func (s *Server) n2PreparingSMF(ctx context.Context, base *slog.Logger, hook HandoverRequiredHook, timeout time.Duration,
	c hoCandidate, target HOTargetID) hoPrepOutcome {
	base.Info("UpdateSMContext for N2 handover preparation (PREPARING)",
		"interface", "Nsmf", "direction", "OUT", "message_type", "UpdateSMContext",
		"n2_sm_info_type", n2InfoHandoverRequired, "ho_state", hoStatePreparing,
		"pdu_session_id", c.psi, "spec_ref", refN2PreparingReq)
	res, dur, timedOut := callSMFBounded(ctx, timeout, func(cctx context.Context) SMFUpdateResult {
		return hook(cctx, c.ref, c.required, target)
	})
	log := base.With("interface", "Nsmf", "direction", "IN", "message_type", "UpdateSMContextResponse",
		"pdu_session_id", c.psi, "n2_sm_info_type", res.N2SmInfoType, "ho_state", res.HoState,
		"http_status", res.HTTPStatus, "duration_ms", dur.Milliseconds(), "spec_ref", refN2PreparingResp)

	// 2xx with hoState CANCELLED or HANDOVER_PREP_FAIL is a rejection of that PDU session.
	if res.OK() && res.N2SmInfoType != n2InfoHandoverPrepFail && res.HoState != hoStateCancelled {
		out := hoPrepOutcome{accepted: true}
		legResult := smfResultOK
		switch {
		case res.N2SmInfoType == n2InfoPDUResSetupReq && validPDUResSetupRequestTransfer(res.N2SmInfo):
			out.transfer = res.N2SmInfo
			log.Info("SMF prepared PDU session for handover", "result", smfResultOK)
		case len(c.cached) == 0:
			log.Error("SMF returned no usable PDU_RES_SETUP_REQ n2SmInfo and no cached N2SmTransfer — PDU session excluded",
				"cause", causeInvalidN2SmInfo, "result", smfResultFailure)
			recordSMFLeg(procN2SMFPreparing, smfResultFailure)
			present, value := failCause(SMFUpdateResult{}, false)
			return hoPrepOutcome{rel: PDUSessionHOReleaseItem{PDUSessionID: c.psi, CausePresent: present, CauseValue: value}}
		case len(res.N2SmInfo) == 0:
			out.transfer = c.cached
			log.Warn("SMF returned no n2SmInfo — cached N2SmTransfer used for the HANDOVER REQUEST",
				"smf_n2sminfo", "absent", "fallback", "cached-n2smtransfer", "result", smfResultOK)
		default:
			out.transfer = c.cached
			log.Error("SMF returned n2SmInfo of an unexpected type or undecodable — cached N2SmTransfer used for the HANDOVER REQUEST",
				"cause", causeInvalidN2SmInfo, "expected_n2_sm_info_type", n2InfoPDUResSetupReq,
				"fallback", "cached-n2smtransfer", "result", smfResultFailure)
			legResult = smfResultFailure
		}
		recordSMFLeg(procN2SMFPreparing, legResult)
		return out
	}
	rel := n2RejectedRelease(log, res, timedOut, c.psi, procN2SMFPreparing,
		"SMF handover preparation (PREPARING) failed", "SMF rejected handover preparation (PREPARING) of PDU session")
	return hoPrepOutcome{rel: rel}
}

// n2RejectedRelease turns a failed / rejected SMF answer of one PDU session into its
// HANDOVER COMMAND IE 78 item (SMF HandoverPreparationUnsuccessfulTransfer when valid, else
// an AMF-built {Cause}), logs the outcome and counts it under proc. log carries the response
// fields. Ref: docs/procedures/XnHandover.md §5.1 E5-E7; TS 38.413 §9.3.4
// (Handover Preparation Unsuccessful Transfer).
func n2RejectedRelease(log *slog.Logger, res SMFUpdateResult, timedOut bool, psi uint8, proc, failMsg, rejectMsg string) PDUSessionHOReleaseItem {
	present, value := failCause(res, timedOut)
	rel := PDUSessionHOReleaseItem{PDUSessionID: psi, CausePresent: present, CauseValue: value}
	cause := failCauseLabel(res, timedOut)
	if res.Err != nil {
		log.Error(failMsg, "cause", cause, "error", res.Err, "result", smfResultFailure)
		recordSMFLeg(proc, smfResultFailure)
		return rel
	}
	if res.N2SmInfoType == n2InfoHandoverPrepFail && validHandoverPrepUnsuccessfulTransfer(res.N2SmInfo) {
		rel.HandoverPreparationUnsuccessfulTransfer = res.N2SmInfo
	} else if len(res.N2SmInfo) > 0 {
		log.Error("SMF returned unusable HandoverPreparationUnsuccessfulTransfer — AMF-built cause used",
			"cause", causeInvalidN2SmInfo, "result", smfResultFailure)
	}
	log.Warn(rejectMsg, "cause", cause, "result", smfResultReject)
	recordSMFLeg(proc, smfResultReject)
	return rel
}

// rejectHandoverPreparation sends a HANDOVER PREPARATION FAILURE to the source
// gNB (PPID 60 via writeNGAP). log carries the procedure fields only.
// Ref: TS 38.413 §8.4.1.3, §9.2.3.3.
func (s *Server) rejectHandoverPreparation(log *slog.Logger, sourceGNB *GNBContext, req *HandoverRequiredMsg,
	reason string, causePresent int, causeValue int64) {
	log.Warn("HandoverPreparationFailure",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "HandoverPreparationFailure",
		"result", smfResultReject,
		"cause", reason,
		"spec_ref", refN2PrepFailure,
	)
	metrics.HandoverTotal.WithLabelValues("AMF", "n2", "REJECT").Inc()
	metrics.ProcedureTotal.WithLabelValues("AMF", procN2Handover, "REJECT").Inc()
	pdu := BuildHandoverPreparationFailure(req.AMFUENGAPId, req.RANUENGAPId, causePresent, causeValue)
	if pdu == nil {
		log.Error("failed to build HandoverPreparationFailure",
			"interface", "N2", "direction", "OUT", "result", smfResultFailure, "cause", reason, "spec_ref", "TS 38.413 §9.2.3.3")
		return
	}
	if _, err := sourceGNB.writeNGAP(pdu); err != nil {
		log.Error("send HandoverPreparationFailure failed",
			"interface", "N2", "direction", "OUT", "result", smfResultFailure, "error", err, "spec_ref", refN2PrepFailure)
	}
}

// n2Outcome is the per-PSI result of the N2 handover SMF leg.
type n2Outcome struct {
	handled   bool
	cmd       []byte // SMF HandoverCommandTransfer (nil = AMF encodes an empty one)
	toRelease PDUSessionHOReleaseItem
}

// handleHandoverRequestAcknowledge processes NGAP HandoverRequestAcknowledge from the
// target gNB: consults the SMF per admitted PDU session (hoState=PREPARED,
// HANDOVER_REQ_ACK), forwards the target-failed PDU sessions (HANDOVER_RES_ALLOC_FAIL) and
// sends HandoverCommand — whose per-PSI HandoverCommandTransfer comes from the SMF — to the
// source gNB, or HandoverPreparationFailure when the SMF accepted none. The blocking SMF
// leg runs on the UE's serial queue.
//
// Ref: TS 38.413 §8.4.2.2, §9.2.3.5; TS 23.502 §4.9.1.3.2 steps 9-12; docs/procedures/XnHandover.md §7.4.5
func (s *Server) handleHandoverRequestAcknowledge(ctx context.Context, targetGNB *GNBContext, msg *Message) {
	ack, ok := msg.Value.(*HandoverRequestAckMsg)
	if !ok {
		s.logger.Error("HandoverRequestAcknowledge body decode failed",
			"nf", "AMF", "procedure", procN2Handover, "interface", "N2", "direction", "IN",
			"message_type", "HandoverRequestAcknowledge", "result", "FAILURE", "spec_ref", "TS 38.413 §9.2.3.5")
		return
	}

	s.pendingN2HOMu.Lock()
	state, ok2 := s.pendingN2HO[ack.AMFUENGAPId]
	if ok2 {
		state.tgtToSrcContainer = ack.TargetToSourceTransparentContainer
	}
	s.pendingN2HOMu.Unlock()
	ctx = n2HandoverContext(ctx, state)

	base := s.n2Base(ctx, ack.AMFUENGAPId).With("new_ran_ue_ngap_id", ack.RANUENGAPId)
	base.Info("HandoverRequestAcknowledge received from target gNB",
		"interface", "N2", "direction", "IN", "message_type", "HandoverRequestAcknowledge",
		"admitted_sessions", len(ack.AdmittedSessions), "failed_sessions", len(ack.FailedSessions),
		"spec_ref", refN2Ack)

	if !ok2 {
		base.Warn("HandoverRequestAcknowledge: no pending N2 handover for UE",
			"interface", "N2", "direction", "IN", "spec_ref", refN2Ack)
		return
	}

	ue, found := s.mgr.GetByNGAPId(ack.AMFUENGAPId)
	if !found {
		base.Warn("HandoverRequestAcknowledge: UE not found", "interface", "N2", "direction", "IN", "spec_ref", refN2Ack)
		return
	}
	base = base.With("supi", ue.SUPI)

	ue.EnqueueSerial(func() {
		s.completeHandoverPreparation(ctx, base, ue, targetGNB, ack, state)
	})
}

// completeHandoverPreparation runs the SMF leg of an N2 handover and answers the source
// gNB. It runs on the UE's serial queue. Ref: docs/procedures/XnHandover.md §7.4.5, §5.1 E14-E19.
func (s *Server) completeHandoverPreparation(ctx context.Context, base *slog.Logger, ue *amfctx.UEContext,
	targetGNB *GNBContext, ack *HandoverRequestAckMsg, state *n2HandoverState) {
	timeout := s.smfUpdateTimeout()
	hook := s.onHandoverReqAck
	failHook := s.onHandoverResAllocFail

	ue.Lock()
	smRefs := make(map[uint8]string, len(ue.PDUSessions))
	for id, sess := range ue.PDUSessions {
		smRefs[id] = sess.SMFInstanceID
	}
	ue.Unlock()

	outs := make([]n2Outcome, len(ack.AdmittedSessions))
	failOuts := make([][]byte, len(ack.FailedSessions)) // SMF HANDOVER_PREP_FAIL bytes (verbatim) per failed PSI
	var wg sync.WaitGroup
	if hook == nil {
		base.Warn("no SMF hook configured — admitted PDU sessions placed in the HANDOVER COMMAND with an empty HandoverCommandTransfer",
			"interface", "Nsmf", "direction", "OUT", "spec_ref", refN2SMFReq)
		for i := range outs {
			outs[i] = n2Outcome{handled: true}
		}
	} else {
		for i, adm := range ack.AdmittedSessions {
			ref, known := smRefs[adm.PDUSessionID]
			if !known {
				base.Warn("HandoverRequestAcknowledge: admitted PDU session not found in UE context",
					"interface", "N2", "direction", "IN", "pdu_session_id", adm.PDUSessionID, "spec_ref", refN2Ack)
				outs[i] = n2Outcome{toRelease: PDUSessionHOReleaseItem{PDUSessionID: adm.PDUSessionID,
					CausePresent: ngapCausePresentRadioNetwork,
					CauseValue:   int64(ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)}}
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				outs[i] = s.n2PrepareSMF(ctx, base, hook, timeout, adm.PDUSessionID, ref, adm.HandoverRequestAcknowledgeTransfer)
			}()
		}
	}
	// Target-failed PDU sessions (Failed to Setup List HOAck): forward each known PSI to the
	// SMF as HANDOVER_RES_ALLOC_FAIL; the outcome is only logged.
	for i, f := range ack.FailedSessions {
		ref, known := smRefs[f.PDUSessionID]
		if !known {
			base.Warn("HandoverRequestAcknowledge: failed-to-setup PDU session not found in UE context",
				"interface", "N2", "direction", "IN", "pdu_session_id", f.PDUSessionID, "spec_ref", refN2Ack)
			continue
		}
		if failHook == nil {
			base.Debug("no SMF hook configured — failed-to-setup PDU session not forwarded",
				"interface", "Nsmf", "direction", "OUT", "pdu_session_id", f.PDUSessionID, "spec_ref", refN2ResAllocFail)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			failOuts[i] = s.n2ForwardResAllocFail(ctx, base, failHook, timeout, f.PDUSessionID, ref,
				f.HandoverResourceAllocationUnsuccessfulTransfer)
		}()
	}
	wg.Wait()

	var handled []PDUSessionHOCmdItem
	var accepted []PDUSessionHOAdmittedItem
	var targetFailed []uint8
	for _, f := range ack.FailedSessions {
		if _, known := smRefs[f.PDUSessionID]; known && !slices.Contains(targetFailed, f.PDUSessionID) {
			targetFailed = append(targetFailed, f.PDUSessionID)
		}
	}
	var toRelease []PDUSessionHOReleaseItem
	inCmd := map[uint8]bool{}
	for i, adm := range ack.AdmittedSessions {
		if outs[i].handled {
			handled = append(handled, PDUSessionHOCmdItem{PDUSessionID: adm.PDUSessionID, HandoverCommandTransfer: outs[i].cmd})
			accepted = append(accepted, adm)
			inCmd[adm.PDUSessionID] = true
		}
	}
	// IE 78: SMF-rejected admitted PSIs, target-failed PSIs, PREPARING-leg rejects; no PSI twice
	// and none that is also in IE 59.
	inRelease := map[uint8]bool{}
	addRelease := func(r PDUSessionHOReleaseItem) {
		if inCmd[r.PDUSessionID] || inRelease[r.PDUSessionID] {
			return
		}
		inRelease[r.PDUSessionID] = true
		toRelease = append(toRelease, r)
	}
	for i := range ack.AdmittedSessions {
		if !outs[i].handled {
			addRelease(outs[i].toRelease)
		}
	}
	for i, f := range ack.FailedSessions {
		rel := PDUSessionHOReleaseItem{PDUSessionID: f.PDUSessionID,
			CausePresent: ngapCausePresentRadioNetwork,
			CauseValue:   int64(ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)}
		if len(failOuts[i]) > 0 {
			rel.HandoverPreparationUnsuccessfulTransfer = failOuts[i]
		} else if p, v, ok := hoResAllocFailCause(f.HandoverResourceAllocationUnsuccessfulTransfer); ok {
			rel.CausePresent, rel.CauseValue = p, v
		}
		addRelease(rel)
	}
	for _, r := range state.prepReleased {
		addRelease(r)
	}

	if (hook != nil || len(ack.FailedSessions) > 0) && len(handled) == 0 {
		// E19: no PDU session left for IE 59 (all admitted PSIs failed at the SMF / the target
		// admitted none).
		s.pendingN2HOMu.Lock()
		if s.pendingN2HO[ack.AMFUENGAPId] == state {
			delete(s.pendingN2HO, ack.AMFUENGAPId)
		}
		s.pendingN2HOMu.Unlock()
		s.rejectHandoverPreparation(base, state.sourceGNB,
			&HandoverRequiredMsg{AMFUENGAPId: ack.AMFUENGAPId, RANUENGAPId: state.sourceRANUENGAPId},
			causeSMFRejectedAll, ngapCausePresentRadioNetwork,
			int64(ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem))
		return
	}

	// Remember only the SMF-accepted set (HandoverNotify / a later step 12 touch only these).
	s.pendingN2HOMu.Lock()
	state.admittedSessions = accepted
	state.targetFailed = targetFailed
	s.pendingN2HOMu.Unlock()

	cmdPDU := BuildHandoverCommand(
		ack.AMFUENGAPId,
		state.sourceRANUENGAPId,
		state.handoverType,
		handled,
		toRelease,
		ack.TargetToSourceTransparentContainer,
	)
	if cmdPDU == nil {
		base.Error("BuildHandoverCommand failed",
			"interface", "N2", "direction", "OUT", "result", smfResultFailure, "spec_ref", refN2Command)
		return
	}

	if _, err := state.sourceGNB.writeNGAP(cmdPDU); err != nil {
		base.Error("HandoverCommand send to source gNB failed",
			"interface", "N2", "direction", "OUT", "result", smfResultFailure, "error", err, "spec_ref", refN2Command)
		return
	}
	base.Info("HandoverCommand sent to source gNB",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "HandoverCommand",
		"handover_sessions", len(handled),
		"to_release_sessions", len(toRelease),
		"result", smfResultOK,
		"spec_ref", refN2Command,
	)

	// Register UE in target gNB's UEs map so that HandoverNotify can find the
	// gNB entry and update the UE context after the handover completes.
	targetGNB.mu.Lock()
	targetGNB.UEs[ack.RANUENGAPId] = ue
	targetGNB.mu.Unlock()
}

// hoResAllocFailCause decodes the Cause of a target's HandoverResourceAllocationUnsuccessfulTransfer
// (TS 38.413 §9.3.4, Handover Resource Allocation Unsuccessful Transfer).
func hoResAllocFailCause(b []byte) (present int, value int64, ok bool) {
	var tr ngapType.HandoverResourceAllocationUnsuccessfulTransfer
	if !decodesAs(b, &tr) {
		return 0, 0, false
	}
	return causeFromNGAP(tr.Cause)
}

// n2ForwardResAllocFail forwards one target-failed PDU session to the SMF
// (hoState=PREPARED, HANDOVER_RES_ALLOC_FAIL). The SMF answers 403
// HANDOVER_RESOURCE_ALLOCATION_FAILURE with a HANDOVER_PREP_FAIL transfer (TS 29.502
// §5.2.2.3.4.2), which the AMF counts as OK on this leg (C2); the outcome is only logged; it returns the SMF's HandoverPreparationUnsuccessfulTransfer
// when one came back and is valid, else nil.
// Ref: TS 23.502 §4.9.1.3.2 steps 10-12; TS 29.502 §5.2.2.3.4.
func (s *Server) n2ForwardResAllocFail(ctx context.Context, base *slog.Logger, hook SMFTransferHook, timeout time.Duration,
	psi uint8, ref string, transfer []byte) []byte {
	base.Info("UpdateSMContext for N2 handover resource allocation failure",
		"interface", "Nsmf", "direction", "OUT", "message_type", "UpdateSMContext",
		"n2_sm_info_type", n2InfoHandoverResAllocFl, "ho_state", hoStatePrepared,
		"pdu_session_id", psi, "spec_ref", refN2ResAllocFail)
	res, dur, timedOut := callSMF(ctx, timeout, hook, ref, transfer)
	log := base.With("interface", "Nsmf", "direction", "IN", "message_type", "UpdateSMContextResponse",
		"pdu_session_id", psi, "n2_sm_info_type", res.N2SmInfoType, "ho_state", res.HoState,
		"http_status", res.HTTPStatus, "duration_ms", dur.Milliseconds(), "spec_ref", refN2ResAllocFailResp)
	switch {
	case res.OK():
		log.Info("SMF accepted HANDOVER_RES_ALLOC_FAIL", "result", smfResultOK)
		recordSMFLeg(procN2SMFResAllocFail, smfResultOK)
	case res.Err != nil:
		log.Warn("SMF HANDOVER_RES_ALLOC_FAIL update failed", "cause", failCauseLabel(res, timedOut),
			"error", res.Err, "result", smfResultFailure)
		recordSMFLeg(procN2SMFResAllocFail, smfResultFailure)
	case res.N2SmInfoType == n2InfoHandoverPrepFail:
		// TS 29.502 §5.2.2.3.4: the SMF answers a target resource allocation failure with a
		// SmContextUpdateError (403) carrying HANDOVER_PREP_FAIL — the expected outcome.
		log.Info("SMF accepted HANDOVER_RES_ALLOC_FAIL", "cause", failCauseLabel(res, timedOut), "result", smfResultOK)
		recordSMFLeg(procN2SMFResAllocFail, smfResultOK)
	default:
		log.Warn("SMF rejected HANDOVER_RES_ALLOC_FAIL", "cause", failCauseLabel(res, timedOut), "result", smfResultReject)
		recordSMFLeg(procN2SMFResAllocFail, smfResultReject)
	}
	if res.N2SmInfoType == n2InfoHandoverPrepFail && validHandoverPrepUnsuccessfulTransfer(res.N2SmInfo) {
		return res.N2SmInfo
	}
	return nil
}

// n2PrepareSMF performs the HANDOVER_REQ_ACK UpdateSMContext (hoState=PREPARED) of one
// admitted PDU session and classifies the answer (doc §5.1 E14-E17).
func (s *Server) n2PrepareSMF(ctx context.Context, base *slog.Logger, hook SMFTransferHook, timeout time.Duration,
	psi uint8, ref string, transfer []byte) n2Outcome {
	base.Info("UpdateSMContext for N2 handover preparation",
		"interface", "Nsmf", "direction", "OUT", "message_type", "UpdateSMContext",
		"n2_sm_info_type", n2InfoHandoverReqAck, "ho_state", hoStatePrepared,
		"pdu_session_id", psi, "spec_ref", refN2SMFReq)
	res, dur, timedOut := callSMF(ctx, timeout, hook, ref, transfer)
	log := base.With("interface", "Nsmf", "direction", "IN", "message_type", "UpdateSMContextResponse",
		"pdu_session_id", psi, "n2_sm_info_type", res.N2SmInfoType, "http_status", res.HTTPStatus,
		"duration_ms", dur.Milliseconds(), "spec_ref", refN2SMFResp)

	// A 2xx answer carrying HANDOVER_PREP_FAIL or hoState=CANCELLED is a failure of that
	// PDU session (TS 23.502 §4.9.1.3.2 step 12; TS 38.413 §9.3.4, Handover Preparation
	// Unsuccessful Transfer).
	if res.OK() && res.N2SmInfoType != n2InfoHandoverPrepFail && res.HoState != hoStateCancelled {
		out := n2Outcome{handled: true}
		legResult := smfResultOK
		switch {
		case len(res.N2SmInfo) == 0:
			log.Warn("SMF returned no n2SmInfo — empty HandoverCommandTransfer used",
				"smf_n2sminfo", "absent", "fallback", "empty-handover-command-transfer", "result", smfResultOK)
		case res.N2SmInfoType != n2InfoHandoverCmd:
			log.Error("SMF returned n2SmInfo of an unexpected type — empty HandoverCommandTransfer used",
				"cause", causeInvalidN2SmInfo, "expected_n2_sm_info_type", n2InfoHandoverCmd,
				"fallback", "empty-handover-command-transfer", "result", smfResultFailure)
			legResult = smfResultFailure
		case !validHandoverCommandTransfer(res.N2SmInfo):
			log.Error("SMF returned undecodable n2SmInfo — empty HandoverCommandTransfer used",
				"cause", causeInvalidN2SmInfo, "fallback", "empty-handover-command-transfer", "result", smfResultFailure)
			legResult = smfResultFailure
		default:
			out.cmd = res.N2SmInfo
			log.Info("SMF prepared PDU session for handover", "result", smfResultOK)
		}
		recordSMFLeg(procN2SMFPrepare, legResult)
		return out
	}

	rel := n2RejectedRelease(log, res, timedOut, psi, procN2SMFPrepare,
		"SMF handover preparation failed", "SMF rejected handover preparation of PDU session")
	return n2Outcome{toRelease: PDUSessionHOReleaseItem{PDUSessionID: rel.PDUSessionID,
		HandoverPreparationUnsuccessfulTransfer: rel.HandoverPreparationUnsuccessfulTransfer,
		CausePresent:                            rel.CausePresent, CauseValue: rel.CauseValue}}
}

// handleHandoverNotify processes NGAP HandoverNotify from the target gNB,
// signaling that the UE has successfully connected to the target cell.
// Migrates the UE context, releases the source gNB's UE context and notifies the SMF of the
// completion (hoState COMPLETED) per SMF-accepted PDU session.
//
// Ref: TS 38.413 §8.4.3, §9.2.3.7; TS 23.502 §4.9.1.3.3
func (s *Server) handleHandoverNotify(ctx context.Context, targetGNB *GNBContext, msg *Message) {
	notify, ok := msg.Value.(*HandoverNotifyMsg)
	if !ok {
		s.logger.Error("HandoverNotify body decode failed",
			"nf", "AMF", "procedure", procN2Handover, "interface", "N2", "direction", "IN",
			"message_type", "HandoverNotify", "result", "FAILURE", "spec_ref", "TS 38.413 §9.2.3.7")
		return
	}

	s.pendingN2HOMu.Lock()
	state, ok2 := s.pendingN2HO[notify.AMFUENGAPId]
	delete(s.pendingN2HO, notify.AMFUENGAPId)
	s.pendingN2HOMu.Unlock()
	ctx = n2HandoverContext(ctx, state)

	log := s.n2Base(ctx, notify.AMFUENGAPId).With("ran_ue_ngap_id", notify.RANUENGAPId)
	log.Info("HandoverNotify received from target gNB — handover complete",
		"interface", "N2", "direction", "IN", "message_type", "HandoverNotify", "spec_ref", refN2Notify)

	if !ok2 {
		log.Warn("HandoverNotify: no pending N2 handover for UE",
			"interface", "N2", "direction", "IN", "spec_ref", refN2Notify)
		return
	}

	ue, found := s.mgr.GetByNGAPId(notify.AMFUENGAPId)
	if !found {
		log.Warn("HandoverNotify: UE not found", "interface", "N2", "direction", "IN", "spec_ref", refN2Notify)
		return
	}
	log = log.With("supi", ue.SUPI)

	oldRANUENGAPId := ue.RANUENGAPId

	// Step 1: Move UE from source gNB to target gNB in gNB maps.
	state.sourceGNB.mu.Lock()
	delete(state.sourceGNB.UEs, state.sourceRANUENGAPId)
	state.sourceGNB.mu.Unlock()

	// Target gNB entry was pre-populated in completeHandoverPreparation.
	// Update UE context to point to new RAN UE NGAP ID and gNB.
	ue.Lock()
	ue.RANUENGAPId = notify.RANUENGAPId
	ue.GNBAddr = targetGNB.remoteAddrString()
	// The Handover Request (mandatory UE-AMBR) already delivered UE-AMBR to the
	// target gNB. Ref: TS 38.413 §8.4.2, §9.2.3.4
	ue.UEAMBRSentToRAN = true
	if notify.UserLocationInformation != nil {
		if tai := extractTAIFromULI(notify.UserLocationInformation); tai != nil {
			ue.TAI = amfctx.TAI{MCC: tai.MCC, MNC: tai.MNC, TAC: tai.TAC}
		}
	}
	smRefs := make(map[uint8]string, len(ue.PDUSessions))
	for id, sess := range ue.PDUSessions {
		smRefs[id] = sess.SMFInstanceID
	}
	ue.Unlock()

	log.Info("UE context migrated to target gNB",
		"interface", "N2", "direction", "IN", "spec_ref", refN2Notify,
		"old_ran_ue_ngap_id", oldRANUENGAPId,
		"new_ran_ue_ngap_id", notify.RANUENGAPId,
	)

	// Step 2: Handover Complete towards the SMF for every SMF-accepted PDU session
	// (concurrent, bounded, off the SCTP read loop; outcome only logged).
	// Ref: TS 23.502 §4.9.1.3.3; TS 29.502 §5.2.2.3.4
	s.notifyHandoverComplete(ctx, log, smRefs, state.admittedSessions)
	// Target-failed PSIs: the handover was executed, so the AMF now indicates them to the SMF
	// (UP deactivation). Ref: TS 23.502 §4.3.7 step 1; §4.9.1.3.3.
	s.notifyTargetFailedDeactivate(ctx, log, smRefs, state.targetFailed)

	// Step 3: Send UEContextReleaseCommand to the source gNB (not delayed by the SMF leg).
	// Ref: TS 23.502 §4.9.1.3.3 (UE Context Release in the source NG-RAN), TS 38.413 §8.3.3
	if err := s.SendUEContextReleaseCommand(
		state.sourceGNB,
		notify.AMFUENGAPId,
		state.sourceRANUENGAPId,
		ngapCausePresentRadioNetwork, ngapCauseSuccessfulHandover,
	); err != nil {
		log.Warn("UEContextReleaseCommand to source gNB failed",
			"interface", "N2", "direction", "OUT", "result", smfResultFailure, "error", err, "spec_ref", refN2UECtxRelease)
	} else {
		log.Info("UEContextReleaseCommand sent to source gNB",
			"interface", "N2",
			"direction", "OUT",
			"message_type", "UEContextReleaseCommand",
			"spec_ref", refN2UECtxRelease,
		)
	}

	log.Info("N2 Handover complete",
		"interface", "N2", "direction", "IN",
		"result", smfResultOK,
		"spec_ref", "TS 23.502 §4.9.1.3.3",
	)
	metrics.HandoverTotal.WithLabelValues("AMF", "n2", "OK").Inc()
	metrics.ProcedureTotal.WithLabelValues("AMF", procN2Handover, "OK").Inc()
}

// notifyHandoverComplete starts the COMPLETED UpdateSMContext of every accepted PDU session
// in its own goroutine (tracked by s.hoCompleteWG) so the SCTP read loop never blocks.
func (s *Server) notifyHandoverComplete(ctx context.Context, log *slog.Logger, smRefs map[uint8]string,
	accepted []PDUSessionHOAdmittedItem) {
	hook := s.onHandoverComplete
	if hook == nil {
		if len(accepted) > 0 {
			log.Debug("no SMF hook configured — Handover Complete not sent to the SMF",
				"interface", "Nsmf", "direction", "OUT", "spec_ref", refN2Complete)
		}
		return
	}
	timeout := s.smfUpdateTimeout()
	// The request context is detached from cancellation of the read loop but keeps the
	// correlation ID.
	cctx := context.WithoutCancel(ctx)
	for _, adm := range accepted {
		ref := smRefs[adm.PDUSessionID]
		if ref == "" {
			log.Warn("N2 handover notify: PDU session not in UE context",
				"interface", "Nsmf", "direction", "OUT", "pdu_session_id", adm.PDUSessionID, "spec_ref", refN2Complete)
			continue
		}
		psi := adm.PDUSessionID
		s.hoCompleteWG.Add(1)
		go func() {
			defer s.hoCompleteWG.Done()
			s.n2CompleteSMF(cctx, log, hook, timeout, psi, ref)
		}()
	}
}

// notifyTargetFailedDeactivate sends UpdateSMContext upCnxState=DEACTIVATED for every target-failed
// PSI, one detached goroutine each (tracked by s.hoCompleteWG), bounded by smfUpdateTimeout().
// Called only after HANDOVER NOTIFY, i.e. when the handover was executed.
// Ref: TS 23.502 §4.3.7 step 1, §4.9.1.3.3 step 7; docs/procedures/N2Handover.md §7.6 (C1).
func (s *Server) notifyTargetFailedDeactivate(ctx context.Context, log *slog.Logger, smRefs map[uint8]string, psis []uint8) {
	if len(psis) == 0 {
		return
	}
	hook := s.onUPDeactivate
	if hook == nil {
		log.Warn("no SMF hook configured — target-failed PDU sessions not deactivated at the SMF",
			"interface", "Nsmf", "direction", "OUT", "sessions", len(psis), "spec_ref", refN2TargetFailedDeact)
		return
	}
	timeout := s.smfUpdateTimeout()
	cctx := context.WithoutCancel(ctx) // keeps the correlation ID, survives the read-loop context
	for _, psi := range psis {
		ref := smRefs[psi]
		if ref == "" {
			log.Warn("N2 handover notify: target-failed PDU session not in UE context",
				"interface", "Nsmf", "direction", "OUT", "pdu_session_id", psi, "spec_ref", refN2TargetFailedDeact)
			continue
		}
		log.Info("UpdateSMContext upCnxState DEACTIVATED for target-failed PDU session",
			"interface", "Nsmf", "direction", "OUT", "message_type", "UpdateSMContext",
			"up_cnx_state", "DEACTIVATED", "pdu_session_id", psi, "spec_ref", refN2TargetFailedDeact)
		s.hoCompleteWG.Add(1)
		go func() {
			defer s.hoCompleteWG.Done()
			tctx, cancel := context.WithTimeout(cctx, timeout)
			defer cancel()
			start := time.Now()
			err := hook(tctx, ref)
			l := log.With("interface", "Nsmf", "direction", "IN", "message_type", "UpdateSMContextResponse",
				"up_cnx_state", "DEACTIVATED", "pdu_session_id", psi,
				"duration_ms", time.Since(start).Milliseconds(), "spec_ref", refN2TargetFailedDeact)
			if err != nil {
				l.Warn("UP deactivation of target-failed PDU session failed", "result", smfResultFailure, "error", err)
				recordSMFLeg(procN2SMFDeactivate, smfResultFailure)
				return
			}
			l.Info("target-failed PDU session deactivated at SMF", "result", smfResultOK)
			recordSMFLeg(procN2SMFDeactivate, smfResultOK)
		}()
	}
}

// n2CompleteSMF performs the Handover Complete UpdateSMContext (hoState=COMPLETED) of one PDU
// session. The outcome is only logged and counted. Ref: TS 23.502 §4.9.1.3.3; TS 29.502 §5.2.2.3.4.
func (s *Server) n2CompleteSMF(ctx context.Context, base *slog.Logger, hook HandoverCompleteHook, timeout time.Duration,
	psi uint8, ref string) {
	base.Info("UpdateSMContext Handover Complete",
		"interface", "Nsmf", "direction", "OUT", "message_type", "UpdateSMContext",
		"ho_state", hoStateCompleted, "pdu_session_id", psi, "spec_ref", refN2Complete)
	res, dur, timedOut := callSMFBounded(ctx, timeout, func(cctx context.Context) SMFUpdateResult {
		return hook(cctx, ref)
	})
	// hoState COMPLETED / CANCELLED in a 2xx answer is a normal acknowledgement on this leg.
	log := base.With("interface", "Nsmf", "direction", "IN", "message_type", "UpdateSMContextResponse",
		"pdu_session_id", psi, "ho_state", res.HoState, "http_status", res.HTTPStatus,
		"duration_ms", dur.Milliseconds(), "spec_ref", refN2Complete)
	switch {
	case res.OK():
		log.Info("SMF acknowledged Handover Complete", "result", smfResultOK)
		recordSMFLeg(procN2SMFComplete, smfResultOK)
	case res.Err != nil:
		log.Warn("SMF Handover Complete update failed", "cause", failCauseLabel(res, timedOut),
			"error", res.Err, "result", smfResultFailure)
		recordSMFLeg(procN2SMFComplete, smfResultFailure)
	default:
		log.Warn("SMF rejected Handover Complete", "cause", failCauseLabel(res, timedOut), "result", smfResultReject)
		recordSMFLeg(procN2SMFComplete, smfResultReject)
	}
}

// connectedGNBIDs returns a hex string for each connected gNB's GlobalGNBID.
// Used for diagnostic logging — cheap snapshot under read lock.
func (s *Server) connectedGNBIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.gnbs))
	for addr, gnb := range s.gnbs {
		gnb.mu.Lock()
		id := hex.EncodeToString(gnb.GlobalGNBID)
		name := gnb.Name
		gnb.mu.Unlock()
		ids = append(ids, addr+"(id="+id+",name="+name+")")
	}
	return ids
}

// findGNBByGlobalID looks up a connected gNB by its GlobalRANNodeID bytes.
// Returns nil if no matching gNB is found.
func (s *Server) findGNBByGlobalID(globalID []byte) *GNBContext {
	if len(globalID) == 0 {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, gnb := range s.gnbs {
		gnb.mu.Lock()
		match := bytes.Equal(gnb.GlobalGNBID, globalID)
		gnb.mu.Unlock()
		if match {
			return gnb
		}
	}
	return nil
}

// ueSecCapBitmaps returns the UE security capability bitmaps for NGAP
// from the stored UESecCapEA/IA fields. Caller must NOT hold ue.mu.
func (s *Server) ueSecCapBitmaps(ue *amfctx.UEContext) (enc, integ uint16) {
	ue.Lock()
	defer ue.Unlock()
	if ue.UESecCapEA[1] {
		enc |= 1 << 15
	}
	if ue.UESecCapEA[2] {
		enc |= 1 << 14
	}
	if ue.UESecCapEA[3] {
		enc |= 1 << 13
	}
	if ue.UESecCapIA[1] {
		integ |= 1 << 15
	}
	if ue.UESecCapIA[2] {
		integ |= 1 << 14
	}
	if ue.UESecCapIA[3] {
		integ |= 1 << 13
	}
	return
}
