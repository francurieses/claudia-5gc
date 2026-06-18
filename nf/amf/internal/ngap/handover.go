package ngap

// handover.go — Xn and N2 Handover handlers.
// Xn Handover: PathSwitchRequest — TS 23.502 §4.9.1.2
// N2 Handover: HandoverRequired / HandoverRequest / HandoverRequestAck /
//              HandoverCommand / HandoverNotify — TS 23.502 §4.9.1.3

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// n2HandoverState holds in-progress N2 handover state between steps 1 and 5.
// Created when HandoverRequired arrives; consumed when HandoverNotify arrives.
type n2HandoverState struct {
	sourceGNB               *GNBContext
	sourceRANUENGAPId       int64
	targetGNB               *GNBContext // set after HandoverRequest is sent
	handoverType            int
	causePresent            int
	causeValue              int64
	admittedSessions        []PDUSessionHOAdmittedItem // populated from HandoverRequestAck
	tgtToSrcContainer       []byte                     // populated from HandoverRequestAck
}

// handlePathSwitchRequest processes an NGAP PathSwitchRequest from the target gNB.
//
// Flow per TS 23.502 §4.9.1.2:
//  1. Identify UE by SourceAMFUENGAPId.
//  2. For each switched PDU session: notify SMF to update PFCP with new DL endpoint.
//  3. Send PathSwitchRequestAcknowledge to target gNB.
//  4. Send UEContextReleaseCommand to source gNB.
//  5. Update UE context: new RANUENGAPId, new gNB association.
//
// Ref: TS 38.413 §8.9.4 (NGAP Path Switch Request)
func (s *Server) handlePathSwitchRequest(ctx context.Context, targetGNB *GNBContext, msg *Message) {
	req, ok := msg.Value.(*PathSwitchRequestMsg)
	if !ok {
		s.logger.Error("PathSwitchRequest body decode failed")
		return
	}

	log := s.logger.With(
		"procedure", "XnHandover",
		"interface", "N2",
		"direction", "IN",
		"message_type", "PathSwitchRequest",
		"source_amf_ue_ngap_id", req.SourceAMFUENGAPId,
		"new_ran_ue_ngap_id", req.RANUENGAPId,
		"spec_ref", "TS 23.502 §4.9.1.2",
	)
	log.Info("PathSwitchRequest received from target gNB")

	// Step 1: Find UE context by the AMF UE NGAP ID used with the source gNB.
	ue, found := s.mgr.GetByNGAPId(req.SourceAMFUENGAPId)
	if !found {
		log.Warn("PathSwitchRequest: UE not found by SourceAMFUENGAPId",
			"source_amf_ue_ngap_id", req.SourceAMFUENGAPId)
		return
	}

	log = log.With("supi", ue.SUPI)

	// Step 2: Notify SMF for each switched PDU session so PFCP is updated.
	if s.onPathSwitchPDUSession != nil {
		ue.Lock()
		sessions := make(map[uint8]string, len(ue.PDUSessions))
		for id, sess := range ue.PDUSessions {
			sessions[id] = sess.SMFInstanceID
		}
		ue.Unlock()

		for _, switched := range req.PDUSessions {
			smContextRef := sessions[switched.PDUSessionID]
			if smContextRef == "" {
				log.Warn("path switch: PDU session not found in UE context",
					"pdu_session_id", switched.PDUSessionID)
				continue
			}
			go s.onPathSwitchPDUSession(ctx, smContextRef, switched.PathSwitchRequestTransfer)
		}
	}

	// Step 3: Send PathSwitchRequestAcknowledge to target gNB.
	ack := BuildPathSwitchRequestAcknowledge(req.SourceAMFUENGAPId, req.RANUENGAPId, req.PDUSessions)
	if ack == nil {
		log.Error("failed to build PathSwitchRequestAcknowledge")
		return
	}
	if _, err := targetGNB.Conn.Write(ack); err != nil {
		log.Error("send PathSwitchRequestAcknowledge failed", "error", err)
		return
	}
	log.Info("PathSwitchRequestAcknowledge sent",
		"direction", "OUT",
		"message_type", "PathSwitchRequestAcknowledge",
		"spec_ref", "TS 38.413 §8.9.4",
	)

	// Step 4: Send UEContextReleaseCommand to source gNB so it can free resources.
	// Find the source gNB (old gNB the UE was on) by scanning gnbs for the old RANID.
	oldRANUENGAPId := ue.RANUENGAPId
	sourceGNB := s.findSourceGNB(ue)
	if sourceGNB != nil && sourceGNB != targetGNB {
		if err := s.SendUEContextReleaseCommand(
			sourceGNB, req.SourceAMFUENGAPId, oldRANUENGAPId,
			ngapCausePresentRadioNetwork, ngapCauseSuccessfulHandover,
		); err != nil {
			log.Warn("UEContextReleaseCommand to source gNB failed", "error", err)
		} else {
			log.Info("UEContextReleaseCommand sent to source gNB",
				"direction", "OUT",
				"spec_ref", "TS 38.413 §8.9.4 step 9",
			)
		}
	}

	// Step 5: Update UE context to new gNB association.
	// Remove from source gNB UEs, add to target gNB UEs with new RAN ID.
	if sourceGNB != nil && sourceGNB != targetGNB {
		sourceGNB.mu.Lock()
		delete(sourceGNB.UEs, oldRANUENGAPId)
		sourceGNB.mu.Unlock()
	}

	targetGNB.mu.Lock()
	targetGNB.UEs[req.RANUENGAPId] = ue
	targetGNB.mu.Unlock()

	ue.Lock()
	ue.RANUENGAPId = req.RANUENGAPId
	ue.GNBAddr = targetGNB.Conn.RemoteAddr().String()
	ue.Unlock()

	log.Info("Xn Handover complete — UE context moved to target gNB",
		"new_ran_ue_ngap_id", req.RANUENGAPId,
		"result", "OK",
		"spec_ref", "TS 23.502 §4.9.1.2",
	)
	metrics.HandoverTotal.WithLabelValues("AMF", "xn", "OK").Inc()
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
	ngapCausePresentRadioNetwork     = 1 // ngapType.CausePresentRadioNetwork
	ngapCauseSuccessfulHandover int64 = 0 // ngapType.CauseRadioNetworkPresentSuccessfulHandover
)

// ---- N2 Handover (TS 23.502 §4.9.1.3 / TS 38.413 §8.4) --------------------

// handleHandoverRequired processes NGAP HandoverRequired from the source gNB.
//
// Flow:
//  1. Decode HandoverRequired.
//  2. Resolve target gNB by GlobalRANNodeID.
//  3. Derive NH/NCC for target gNB AS security.
//  4. Send HandoverRequest to target gNB.
//  5. Save pending state so HandoverRequestAcknowledge can continue.
//
// Ref: TS 38.413 §8.4.1.2, TS 23.502 §4.9.1.3
func (s *Server) handleHandoverRequired(ctx context.Context, sourceGNB *GNBContext, msg *Message) {
	req, ok := msg.Value.(*HandoverRequiredMsg)
	if !ok {
		s.logger.Error("HandoverRequired body decode failed")
		return
	}

	log := s.logger.With(
		"procedure", "N2Handover",
		"interface", "N2",
		"direction", "IN",
		"message_type", "HandoverRequired",
		"amf_ue_ngap_id", req.AMFUENGAPId,
		"spec_ref", "TS 23.502 §4.9.1.3",
	)
	log.Info("HandoverRequired received from source gNB")

	// Checkpoint A — fires immediately after the first Info, before any lock.
	// If this does NOT appear in logs, the running binary is the old one (deadlock not fixed).
	log.Info("HandoverRequired: checkpoint A — UE lookup",
		"connected_gnbs", strings.Join(s.connectedGNBIDs(), ","),
		"target_id_hex", hex.EncodeToString(req.TargetGlobalRANNodeID),
	)

	ue, found := s.mgr.GetByNGAPId(req.AMFUENGAPId)
	if !found {
		log.Warn("HandoverRequired: UE not found by AMFUENGAPId")
		return
	}
	log = log.With("supi", ue.SUPI)

	// Resolve target gNB by matching GlobalRANNodeID bytes.
	// Checkpoint B — confirms target gNB resolution.
	targetGNB := s.findGNBByGlobalID(req.TargetGlobalRANNodeID)
	if targetGNB == nil {
		log.Warn("HandoverRequired: target gNB not found — is it connected and NG Setup complete?",
			"target_id_hex", hex.EncodeToString(req.TargetGlobalRANNodeID),
			"connected_gnb_ids", strings.Join(s.connectedGNBIDs(), ","),
		)
		return
	}
	if targetGNB == sourceGNB {
		log.Warn("HandoverRequired: source and target gNB resolved to the same connection",
			"target_id_hex", hex.EncodeToString(req.TargetGlobalRANNodeID),
		)
		return
	}
	log.Info("HandoverRequired: checkpoint B — target gNB resolved",
		"target_gnb_addr", targetGNB.Conn.RemoteAddr().String(),
		"target_gnb_name", targetGNB.Name,
	)

	// Derive NH for target gNB (NCC=1, NH = KDF(KAMF, KgNB_source)).
	// Ref: TS 33.501 §A.11, §6.9.2.1.2
	// Note: ueSecCapBitmaps must be called OUTSIDE the lock — it acquires ue.Lock()
	// internally and Go's sync.Mutex is not reentrant.
	encAlgsBitmap, intAlgsBitmap := s.ueSecCapBitmaps(ue)
	ue.Lock()
	kamf := ue.SecurityCtx.KAMF
	kgnbSrc := ue.KgNB
	allowedNSSAI := ue.AllowedNSSAI
	ue.Unlock()

	nhBytes := kdf.KNH(kamf, kgnbSrc[:])
	var nh [32]byte
	copy(nh[:], nhBytes)

	// Build PDU session list for HandoverRequest.
	// HandoverRequestTransfer (TS 38.413 §9.3.4.2) must contain the UPF's
	// GTP-U UL endpoint (uL-NGU-UP-TNL-Information) so the target gNB can send
	// uplink user-plane traffic to the UPF. This has the same APER structure as
	// PDUSessionResourceSetupRequestTransfer (§9.3.4.1), which the AMF cached
	// at session establishment in PDUSession.N2SmTransfer.
	// Do NOT forward HandoverRequiredTransfer from the source gNB here — that
	// is a different IE type (§9.3.4.4) containing only directForwardingPathAvailability.
	var sessions []PDUSessionHOReqItem
	ue.Lock()
	uePDUSessions := make(map[uint8]*amfctx.PDUSession, len(ue.PDUSessions))
	for id, sess := range ue.PDUSessions {
		uePDUSessions[id] = sess
	}
	ue.Unlock()

	log.Info("HandoverRequired: PDU session state",
		"req_sessions_from_gnb", len(req.PDUSessions),
		"ue_sessions_in_amf", len(uePDUSessions),
	)

	if len(req.PDUSessions) > 0 {
		// Normal path: source gNB listed sessions to hand over.
		for _, pduss := range req.PDUSessions {
			if sess, ok := uePDUSessions[pduss.PDUSessionID]; ok && len(sess.N2SmTransfer) > 0 {
				sessions = append(sessions, PDUSessionHOReqItem{
					PDUSessionID:            pduss.PDUSessionID,
					SNSSAI:                  sess.SNSSAI,
					HandoverRequestTransfer: sess.N2SmTransfer,
				})
			} else {
				log.Warn("HandoverRequired: session from gNB not found or missing N2SmTransfer",
					"pdu_session_id", pduss.PDUSessionID,
					"in_ue_ctx", sess != nil,
					"has_n2sm_transfer", sess != nil && len(sess.N2SmTransfer) > 0,
				)
			}
		}
	} else if len(uePDUSessions) > 0 {
		// Fallback: source gNB omitted PDU sessions from HandoverRequired but AMF
		// has them in UE context (e.g. gNB didn't complete PDUSessionResourceSetup
		// before firing the handover timer — common in PacketRusher simulation).
		// Use N2SmTransfer cached at PDU session establishment so the target gNB
		// can set up the GTP-U tunnel to the UPF.
		// Ref: TS 38.413 §9.2.2.1 (PDUSessionResourceSetupListHOReq is optional)
		log.Info("HandoverRequired: source gNB listed no PDU sessions — falling back to AMF UE context",
			"ue_sessions_in_amf", len(uePDUSessions),
			"spec_ref", "TS 38.413 §9.2.2.1",
		)
		for id, sess := range uePDUSessions {
			if len(sess.N2SmTransfer) > 0 {
				sessions = append(sessions, PDUSessionHOReqItem{
					PDUSessionID:            id,
					SNSSAI:                  sess.SNSSAI,
					HandoverRequestTransfer: sess.N2SmTransfer,
				})
			}
		}
	}

	pdu := BuildHandoverRequest(
		req.AMFUENGAPId,
		req.HandoverType,
		req.CausePresent, req.CauseValue,
		1, nh, // NCC=1, first hop refresh
		encAlgsBitmap, intAlgsBitmap,
		sessions,
		allowedNSSAI,
		req.SourceToTargetTransparentContainer,
		s.cfg.MCC, s.cfg.MNC,
		s.cfg.RegionID, s.cfg.SetID, s.cfg.AMFID,
	)
	if pdu == nil {
		log.Error("BuildHandoverRequest failed")
		return
	}

	if _, err := targetGNB.Conn.Write(pdu); err != nil {
		log.Error("HandoverRequest send failed", "error", err)
		return
	}
	log.Info("HandoverRequest sent to target gNB",
		"direction", "OUT",
		"message_type", "HandoverRequest",
		"spec_ref", "TS 38.413 §8.4.2",
	)

	// Save pending state — consumed by handleHandoverRequestAcknowledge.
	s.pendingN2HOMu.Lock()
	s.pendingN2HO[req.AMFUENGAPId] = &n2HandoverState{
		sourceGNB:         sourceGNB,
		sourceRANUENGAPId: req.RANUENGAPId,
		targetGNB:         targetGNB,
		handoverType:      req.HandoverType,
		causePresent:      req.CausePresent,
		causeValue:        req.CauseValue,
	}
	s.pendingN2HOMu.Unlock()
}

// handleHandoverRequestAcknowledge processes NGAP HandoverRequestAcknowledge
// from the target gNB. Sends HandoverCommand back to the source gNB.
//
// Ref: TS 38.413 §8.4.2.2, TS 23.502 §4.9.1.3 step 7
func (s *Server) handleHandoverRequestAcknowledge(ctx context.Context, targetGNB *GNBContext, msg *Message) {
	ack, ok := msg.Value.(*HandoverRequestAckMsg)
	if !ok {
		s.logger.Error("HandoverRequestAcknowledge body decode failed")
		return
	}

	log := s.logger.With(
		"procedure", "N2Handover",
		"interface", "N2",
		"direction", "IN",
		"message_type", "HandoverRequestAcknowledge",
		"amf_ue_ngap_id", ack.AMFUENGAPId,
		"new_ran_ue_ngap_id", ack.RANUENGAPId,
		"spec_ref", "TS 23.502 §4.9.1.3",
	)
	log.Info("HandoverRequestAcknowledge received from target gNB")

	s.pendingN2HOMu.Lock()
	state, ok2 := s.pendingN2HO[ack.AMFUENGAPId]
	if ok2 {
		state.admittedSessions = ack.AdmittedSessions
		state.tgtToSrcContainer = ack.TargetToSourceTransparentContainer
	}
	s.pendingN2HOMu.Unlock()

	if !ok2 {
		log.Warn("HandoverRequestAcknowledge: no pending N2 handover for UE")
		return
	}

	ue, found := s.mgr.GetByNGAPId(ack.AMFUENGAPId)
	if !found {
		log.Warn("HandoverRequestAcknowledge: UE not found")
		return
	}
	log = log.With("supi", ue.SUPI)

	// Build HandoverCommand and send to source gNB.
	cmdPDU := BuildHandoverCommand(
		ack.AMFUENGAPId,
		state.sourceRANUENGAPId,
		state.handoverType,
		ack.AdmittedSessions,
		ack.TargetToSourceTransparentContainer,
	)
	if cmdPDU == nil {
		log.Error("BuildHandoverCommand failed")
		return
	}

	if _, err := state.sourceGNB.Conn.Write(cmdPDU); err != nil {
		log.Error("HandoverCommand send to source gNB failed", "error", err)
		return
	}
	log.Info("HandoverCommand sent to source gNB",
		"direction", "OUT",
		"message_type", "HandoverCommand",
		"spec_ref", "TS 38.413 §8.4.1 (SuccessfulOutcome)",
	)

	// Register UE in target gNB's UEs map so that HandoverNotify can find the
	// gNB entry and update the UE context after the handover completes.
	targetGNB.mu.Lock()
	targetGNB.UEs[ack.RANUENGAPId] = ue
	targetGNB.mu.Unlock()
}

// handleHandoverNotify processes NGAP HandoverNotify from the target gNB,
// signaling that the UE has successfully connected to the target cell.
// Migrates the UE context, releases source gNB resources, and notifies SMF.
//
// Ref: TS 38.413 §8.4.3, TS 23.502 §4.9.1.3 step 11-13
func (s *Server) handleHandoverNotify(ctx context.Context, targetGNB *GNBContext, msg *Message) {
	notify, ok := msg.Value.(*HandoverNotifyMsg)
	if !ok {
		s.logger.Error("HandoverNotify body decode failed")
		return
	}

	log := s.logger.With(
		"procedure", "N2Handover",
		"interface", "N2",
		"direction", "IN",
		"message_type", "HandoverNotify",
		"amf_ue_ngap_id", notify.AMFUENGAPId,
		"spec_ref", "TS 23.502 §4.9.1.3",
	)
	log.Info("HandoverNotify received from target gNB — handover complete")

	s.pendingN2HOMu.Lock()
	state, ok2 := s.pendingN2HO[notify.AMFUENGAPId]
	delete(s.pendingN2HO, notify.AMFUENGAPId)
	s.pendingN2HOMu.Unlock()

	if !ok2 {
		log.Warn("HandoverNotify: no pending N2 handover for UE")
		return
	}

	ue, found := s.mgr.GetByNGAPId(notify.AMFUENGAPId)
	if !found {
		log.Warn("HandoverNotify: UE not found")
		return
	}
	log = log.With("supi", ue.SUPI)

	oldRANUENGAPId := ue.RANUENGAPId

	// Step 1: Move UE from source gNB to target gNB in gNB maps.
	state.sourceGNB.mu.Lock()
	delete(state.sourceGNB.UEs, state.sourceRANUENGAPId)
	state.sourceGNB.mu.Unlock()

	// Target gNB entry was pre-populated in handleHandoverRequestAcknowledge.
	// Update UE context to point to new RAN UE NGAP ID and gNB.
	ue.Lock()
	ue.RANUENGAPId = notify.RANUENGAPId
	ue.GNBAddr = targetGNB.Conn.RemoteAddr().String()
	if notify.UserLocationInformation != nil {
		if tai := extractTAIFromULI(notify.UserLocationInformation); tai != nil {
			ue.TAI = amfctx.TAI{MCC: tai.MCC, MNC: tai.MNC, TAC: tai.TAC}
		}
	}
	ue.Unlock()

	log.Info("UE context migrated to target gNB",
		"old_ran_ue_ngap_id", oldRANUENGAPId,
		"new_ran_ue_ngap_id", notify.RANUENGAPId,
	)

	// Step 2: Notify SMF for each admitted PDU session (PFCP path update).
	// Ref: TS 23.502 §4.9.1.3 step 12
	if s.onN2HandoverComplete != nil {
		ue.Lock()
		sessions := make(map[uint8]string, len(ue.PDUSessions))
		for id, sess := range ue.PDUSessions {
			sessions[id] = sess.SMFInstanceID
		}
		ue.Unlock()

		for _, admitted := range state.admittedSessions {
			smContextRef := sessions[admitted.PDUSessionID]
			if smContextRef == "" {
				log.Warn("N2 handover notify: PDU session not in UE context",
					"pdu_session_id", admitted.PDUSessionID)
				continue
			}
			go s.onN2HandoverComplete(ctx, smContextRef, admitted.HandoverRequestAcknowledgeTransfer)
		}
	}

	// Step 3: Send UEContextReleaseCommand to source gNB.
	// Ref: TS 23.502 §4.9.1.3 step 13, TS 38.413 §8.3.5
	if err := s.SendUEContextReleaseCommand(
		state.sourceGNB,
		notify.AMFUENGAPId,
		state.sourceRANUENGAPId,
		ngapCausePresentRadioNetwork, ngapCauseSuccessfulHandover,
	); err != nil {
		log.Warn("UEContextReleaseCommand to source gNB failed", "error", err)
	} else {
		log.Info("UEContextReleaseCommand sent to source gNB",
			"direction", "OUT",
			"spec_ref", "TS 38.413 §8.4.3 step 3",
		)
	}

	log.Info("N2 Handover complete",
		"result", "OK",
		"spec_ref", "TS 23.502 §4.9.1.3",
	)
	metrics.HandoverTotal.WithLabelValues("AMF", "n2", "OK").Inc()
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

