package server

// handover_n2.go — SMF answers for the N2 handover UpdateSMContext requests of the AMF
// (hoState PREPARING / COMPLETED, n2SmInfoType HANDOVER_RES_ALLOC_FAIL) and of the Xn path
// switch legs (PATH_SWITCH_REQ, PATH_SWITCH_SETUP_FAIL). PREPARING and HANDOVER_RES_ALLOC_FAIL
// are SBI response + in-memory state only; COMPLETED and PATH_SWITCH_REQ switch the UPF DL FAR
// synchronously (pfcp_ho.go) and answer after the PFCP response; PATH_SWITCH_SETUP_FAIL
// answers 204 and then deactivates or releases the PDU session (detached). SMF-005, human
// approval for the PFCP path recorded; design docs/procedures/N2Handover.md.
// Ref: TS 23.502 §4.9.1.3.2, §4.9.1.3.3, §4.9.1.2.2; TS 29.502 §5.2.2.3.3, §5.2.2.3.4.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// errUnexpectedN2SmInfoType: PREPARING carries only HANDOVER_REQUIRED N2 SM info.
var errUnexpectedN2SmInfoType = errors.New("smf: unexpected n2SmInfoType for hoState PREPARING")

// handleHandoverPreparing serves hoState PREPARING (n2SmInfoType HANDOVER_REQUIRED or none):
// decodes the HandoverRequiredTransfer, records HOState/HODirectForwarding and answers 200
// {"hoState":"PREPARING","n2SmInfoType":"PDU_RES_SETUP_REQ","n2SmInfo":<transfer>} where the
// transfer is the PDUSessionResourceSetupRequestTransfer for the target (UPF tunnel unchanged),
// with DataForwardingNotPossible when no direct forwarding path exists. Errors answer
// SmContextUpdateError with a HANDOVER_PREP_FAIL transfer.
// Ref: TS 23.502 §4.9.1.3.2 steps 3-6; TS 29.502 §5.2.2.3.4; TS 38.413 §9.3.4.1, §9.3.4.14.
func (s *Server) handleHandoverPreparing(w http.ResponseWriter, log *slog.Logger, smContextRef, n2SmInfoType string, body map[string]interface{}) {
	log = log.With("procedure", "N2Handover", "interface", "Nsmf", "ho_state", hoStatePreparing,
		"n2_sm_info_type", n2SmInfoType)

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()
	if sess == nil {
		log.Warn("N2 HO preparing: session not found", "direction", "IN", "result", "REJECT",
			"cause", "CONTEXT_NOT_FOUND", "spec_ref", "TS 23.502 §4.9.1.3.2 step 3")
		smContextUpdateError(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found",
			handoverPrepFailTransfer(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownPDUSessionID),
			n2SmInfoTypeHandoverPrepFail)
		return
	}

	direct := false
	if b64, _ := body["n2SmInfo"].(string); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		var req ngapType.HandoverRequiredTransfer
		if err == nil && n2SmInfoType != "" && n2SmInfoType != n2SmInfoTypeHandoverRequired {
			err = errUnexpectedN2SmInfoType
		}
		if err == nil {
			err = aper.UnmarshalWithParams(raw, &req, "valueExt")
		}
		if err != nil {
			log.Error("N2 HO preparing: decode HandoverRequiredTransfer failed", "direction", "IN",
				"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "result", "REJECT", "error", err,
				"spec_ref", "TS 23.502 §4.9.1.3.2 step 3")
			smContextUpdateError(w, http.StatusUnprocessableEntity, "SYSTEM_FAILURE", err.Error(),
				handoverPrepFailTransfer(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError),
				n2SmInfoTypeHandoverPrepFail)
			return
		}
		direct = req.DirectForwardingPathAvailability != nil
	}
	log.Info("N2 HO preparing: request received", "direction", "IN", "supi", sess.SUPI,
		"pdu_session_id", sess.PDUSessionID, "target_id", body["targetId"], "direct_forwarding", direct,
		"spec_ref", "TS 23.502 §4.9.1.3.2 step 3")

	transfer, err := buildPDUSessionResourceSetupRequestTransferOpts(
		net.ParseIP(s.cfg.UPFN3Addr), sess.ULTEID, 1 /* QFI */, int64(sess.FiveQI),
		int64(sess.AMBRULMbps)*1_000_000, int64(sess.AMBRDLMbps)*1_000_000,
		ngapPDUSessionType(sess.PDUSessionType), !direct,
	)
	if err != nil {
		log.Error("N2 HO preparing: encode PDUSessionResourceSetupRequestTransfer failed", "direction", "OUT",
			"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "result", "FAILURE", "error", err,
			"spec_ref", "TS 23.502 §4.9.1.3.2 step 6")
		smContextUpdateError(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error(),
			handoverPrepFailTransfer(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem),
			n2SmInfoTypeHandoverPrepFail)
		return
	}

	s.sessionMu.Lock()
	sess.HOState = hoStatePreparing
	sess.HODirectForwarding = direct
	sess.HOTargetFailed, sess.HOReleaseOnDeactivate = false, false // a newer HO supersedes
	s.sessionMu.Unlock()

	forwarding := dataForwardingDirect
	if !direct {
		forwarding = dataForwardingNotPossible
	}
	log.Info("N2 HO preparing: PDU_RES_SETUP_REQ transfer returned (no PFCP)", "direction", "OUT",
		"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "ulTEID", sess.ULTEID,
		"data_forwarding", forwarding, "result", "OK", "spec_ref", "TS 23.502 §4.9.1.3.2 step 6")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"hoState":      hoStatePreparing,
		"n2SmInfo":     base64.StdEncoding.EncodeToString(transfer),
		"n2SmInfoType": n2SmInfoTypePduResSetupReq,
	})
}

// handleHandoverResAllocFail serves n2SmInfoType HANDOVER_RES_ALLOC_FAIL: the target NG-RAN
// could not allocate resources for this PDU session. The target tunnel is cleared, HOState set
// to NONE, the session flagged target-failed with the release-or-deactivate decision of rule R1
// (executed when the AMF later sends upCnxState DEACTIVATED), and the SMF answers 403
// SmContextUpdateError HANDOVER_RESOURCE_ALLOCATION_FAILURE with a HANDOVER_PREP_FAIL transfer
// carrying the relayed target Cause. No PFCP: the UE is still served by the source.
// Unknown context -> 404 SmContextUpdateError.
// Ref: TS 23.502 §4.9.1.3.2 step 10, §4.3.7; TS 29.502 §5.2.2.3.4; TS 38.413 §9.3.4.
func (s *Server) handleHandoverResAllocFail(w http.ResponseWriter, log *slog.Logger, smContextRef string, body map[string]interface{}) {
	log = log.With("procedure", "N2Handover", "interface", "Nsmf",
		"n2_sm_info_type", n2SmInfoTypeHandoverResAllocFail)

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()
	if sess == nil {
		log.Warn("N2 HO resource allocation failure: session not found", "direction", "IN", "result", "REJECT",
			"cause", "CONTEXT_NOT_FOUND", "spec_ref", "TS 23.502 §4.9.1.3.2 step 10")
		smContextUpdateError(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found", nil, "")
		return
	}

	// Relayed Cause; default (undecodable / absent transfer) is
	// ho-failure-in-target-5GC-ngran-node-or-target-system (7).
	relayed := ngapCause(ngapType.CausePresentRadioNetwork,
		ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)
	decoded := false
	if b64, _ := body["n2SmInfo"].(string); b64 != "" {
		var tr ngapType.HandoverResourceAllocationUnsuccessfulTransfer
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err == nil {
			err = aper.UnmarshalWithParams(raw, &tr, "valueExt")
		}
		if err != nil {
			log.Warn("N2 HO resource allocation failure: transfer undecodable (accepted)", "direction", "IN",
				"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "error", err,
				"spec_ref", "TS 23.502 §4.9.1.3.2 step 10")
		} else {
			relayed, decoded = tr.Cause, true
		}
	}

	s.sessionMu.Lock()
	releasing := sess.State == sessionStateReleasing
	release := decoded && releaseOnTargetFailure(relayed, sess.UPSecurityRequired)
	sess.HOTargetGNBIP = nil
	sess.HOTargetDLTEID = 0
	sess.HOState = hoStateNone
	sess.HODirectForwarding = false
	if !releasing { // the node recovery releases a RELEASING session anyway
		sess.HOTargetFailed = true
		sess.HOReleaseOnDeactivate = release
	}
	s.sessionMu.Unlock()

	action := targetFailedDeactivate
	if release {
		action = targetFailedRelease
	}
	log.Info("N2 HO resource allocation failure: target tunnel cleared, HOState NONE, "+
		"deactivate/release decision waits for the AMF indication (no PFCP)",
		"direction", "IN", "supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "ho_state", hoStateNone,
		"ngap_cause_group", relayed.Present, "ngap_cause", ngapCauseValue(relayed),
		"target_failed_action", action, "followup", "await-amf-deactivation", "http_status", http.StatusForbidden,
		"result", "OK", "spec_ref", "TS 23.502 §4.9.1.3.2 step 10; TS 29.502 §5.2.2.3.4")
	smContextUpdateError(w, http.StatusForbidden, causeHOResAllocFailure,
		"target NG-RAN could not allocate resources for the PDU session",
		handoverPrepFailTransferCause(relayed), n2SmInfoTypeHandoverPrepFail)
}

// handleHandoverComplete serves hoState COMPLETED (Handover Complete after HANDOVER NOTIFY):
// switches the UPF DL FAR to the stored target tunnel (PFCP Session Modification, Update FAR 1
// FORW + Outer Header Creation) and answers 200 {"hoState":"COMPLETED"} only after the
// Session Modification Response with Cause 1. Errors are SmContextUpdateError without n2SmInfo:
// 404 unknown context, 409 RELEASING, 500 SYSTEM_FAILURE (no stored target tunnel, or UPF Cause
// != 1 / missing), 504 UPF_NOT_RESPONDING (no response within hoN4Timeout); on N4 failure
// HOState and the target tunnel are kept. A repeated COMPLETED is idempotent (no second PFCP).
// Ref: TS 23.502 §4.9.1.3.3 (Handover Complete, N4 Session Modification); TS 29.502 §5.2.2.3.4;
// TS 29.244 §7.5.4.
func (s *Server) handleHandoverComplete(ctx context.Context, w http.ResponseWriter, base *slog.Logger, smContextRef string) {
	const specIn = "TS 23.502 §4.9.1.3.3 (Handover Complete)"
	const specOut = "TS 23.502 §4.9.1.3.3; TS 29.502 §5.2.2.3.4"
	log := base.With("procedure", "N2Handover", "interface", "Nsmf", "ho_state", hoStateCompleted)

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()
	if sess == nil {
		log.Warn("N2 HO complete: session not found", "direction", "IN", "result", "REJECT",
			"cause", "CONTEXT_NOT_FOUND", "spec_ref", specIn)
		smContextUpdateError(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found", nil, "")
		return
	}

	s.sessionMu.Lock()
	releasing := sess.State == sessionStateReleasing
	prev := sess.HOState
	prevState := sess.State
	tgtIP, tgtTEID := sess.HOTargetGNBIP, sess.HOTargetDLTEID
	s.sessionMu.Unlock()

	if releasing {
		log.Warn("N2 HO complete rejected — session RELEASING after UPF restart/failure",
			"direction", "OUT", "result", "REJECT", "cause", causeSessionReleasing, "supi", sess.SUPI,
			"pdu_session_id", sess.PDUSessionID, "spec_ref", "TS 29.502 §5.2.2.3; TS 23.527 §4.3")
		smContextUpdateError(w, http.StatusConflict, causeSessionReleasing,
			"PDU session is being released after a UPF restart/failure", nil, "")
		return
	}
	log.Info("N2 HO complete: Handover Complete received", "direction", "IN", "supi", sess.SUPI,
		"pdu_session_id", sess.PDUSessionID, "previous_ho_state", prev, "spec_ref", specIn)
	if prev == hoStateCompleted {
		log.Debug("N2 HO complete: already switched, idempotent answer (no PFCP)", "direction", "OUT",
			"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "result", "OK", "spec_ref", specIn)
		writeHOState(w, hoStateCompleted)
		return
	}
	if len(tgtIP) == 0 || tgtTEID == 0 {
		log.Warn("N2 HO complete: no stored target tunnel", "direction", "IN", "supi", sess.SUPI,
			"pdu_session_id", sess.PDUSessionID, "detail", "no target tunnel", "previous_ho_state", prev,
			"result", "REJECT", "spec_ref", specIn)
		metrics.ProcedureTotal.WithLabelValues("SMF", "N2HandoverDLSwitch", "REJECT").Inc()
		smContextUpdateError(w, http.StatusInternalServerError, causeSystemFailure, "no target tunnel", nil, "")
		return
	}
	if prev != hoStatePrepared {
		log.Warn("N2 HO complete: HOState was not PREPARED", "direction", "IN", "supi", sess.SUPI,
			"pdu_session_id", sess.PDUSessionID, "previous_ho_state", prev, "spec_ref", specIn)
	}
	if !s.markSessionActive(sess) { // RELEASING race: no N4
		smContextUpdateError(w, http.StatusConflict, causeSessionReleasing,
			"PDU session is being released after a UPF restart/failure", nil, "")
		return
	}

	cause, err := s.pfcpSwitchDL(ctx, base, "N2Handover", specN2Switch, sess, tgtTEID, tgtIP)
	if err != nil {
		s.sessionMu.Lock()
		if sess.State != sessionStateReleasing {
			sess.State = prevState // restore the pre-switch state; HOState and tunnel are kept
		}
		s.sessionMu.Unlock()
		status, pcause := hoN4Failure(err)
		metrics.ProcedureTotal.WithLabelValues("SMF", "N2HandoverDLSwitch", hoN4Result(err)).Inc()
		logCause := pcause
		if errors.Is(err, errPFCPTimeout) {
			logCause = "pfcp-timeout"
		}
		log.Error("N2 HO complete: DL switch failed", "direction", "OUT", "supi", sess.SUPI,
			"pdu_session_id", sess.PDUSessionID, "seid", sess.SEID, "dl_switch", "failed",
			"http_status", status, "cause", logCause, "problem_cause", pcause,
			"pfcp_cause", pfcpCauseLabel(cause, err), "result", "FAILURE", "error", err, "spec_ref", specOut)
		smContextUpdateError(w, status, pcause, "PFCP Session Modification failed", nil, "")
		return
	}

	s.sessionMu.Lock()
	sess.HOState = hoStateCompleted
	sess.HOTargetGNBIP = nil
	sess.HOTargetDLTEID = 0
	sess.HODirectForwarding = false
	sess.HOTargetFailed, sess.HOReleaseOnDeactivate = false, false
	s.sessionMu.Unlock()
	metrics.ProcedureTotal.WithLabelValues("SMF", "N2HandoverDLSwitch", "OK").Inc()
	log.Info("N2 HO complete: DL path switched to target tunnel, acknowledged", "direction", "OUT",
		"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "seid", sess.SEID, "dl_switch", "done",
		"target_gnb_ip", tgtIP.String(), "target_dl_teid", tgtTEID, "http_status", http.StatusOK,
		"result", "OK", "spec_ref", specOut)
	writeHOState(w, hoStateCompleted)
}

// writeHOState answers 200 {"hoState": state}.
func writeHOState(w http.ResponseWriter, state string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"hoState": state})
}

// handlePathSwitchReq serves n2SmInfoType PATH_SWITCH_REQ (Xn handover): decodes the
// PathSwitchRequestTransfer, encodes the PathSwitchRequestAcknowledgeTransfer first, switches
// the UPF DL FAR synchronously (same Update FAR as the N2 switch) and answers 200
// PATH_SWITCH_REQ_ACK only after the Session Modification Response with Cause 1. Failures are
// SmContextUpdateError + PATH_SWITCH_REQ_FAIL (PathSwitchRequestUnsuccessfulTransfer): 422
// undecodable transfer (no PFCP), 404 unknown context, 409 RELEASING, 500 SYSTEM_FAILURE (UPF
// Cause != 1 / missing, or ack encode failure), 504 UPF_NOT_RESPONDING (timeout). On N4 failure
// the session State is restored.
// Ref: TS 23.502 §4.9.1.2.2 steps 2-6; TS 29.502 §5.2.2.3.3; TS 29.244 §7.5.4; TS 38.413 §9.3.4.8-9.3.4.9.
func (s *Server) handlePathSwitchReq(ctx context.Context, w http.ResponseWriter, base *slog.Logger, smContextRef string, n2SmInfo []byte) {
	log := base.With("procedure", "XnHandover", "n2_sm_info_type", "PATH_SWITCH_REQ")

	gnbIP, dlTEID, err := extractPathSwitchTunnelInfo(n2SmInfo)
	if err != nil {
		log.Error("extractPathSwitchTunnelInfo failed", "interface", "Nsmf", "direction", "IN",
			"result", "REJECT", "error", err, "spec_ref", "TS 23.502 §4.9.1.2.2 step 2")
		smContextUpdateError(w, http.StatusUnprocessableEntity, causeSystemFailure, err.Error(),
			pathSwitchUnsuccessfulTransfer(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError),
			n2SmInfoTypePathSwitchReqFail)
		return
	}
	log.Info("Xn Handover: target gNB DL tunnel info", "interface", "Nsmf", "direction", "IN",
		"gnbIP", gnbIP, "dlTEID", dlTEID, "spec_ref", "TS 23.502 §4.9.1.2.2 step 2")

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()
	if sess == nil {
		log.Warn("session not found", "interface", "Nsmf", "direction", "OUT", "result", "REJECT",
			"cause", "CONTEXT_NOT_FOUND", "spec_ref", "TS 29.502 §6.1.7.3")
		smContextUpdateError(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found",
			pathSwitchUnsuccessfulTransfer(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownPDUSessionID),
			n2SmInfoTypePathSwitchReqFail)
		return
	}
	if s.rejectIfReleasing(w, log, sess, "N2 SM info update", true) {
		return
	}

	// Encode the acknowledge BEFORE touching the UPF: a PSI the AMF will report as released
	// must never be switched (N2Handover.md E-T9).
	ack, merr := aper.MarshalWithParams(ngapType.PathSwitchRequestAcknowledgeTransfer{}, "valueExt")
	if merr != nil {
		log.Error("encode PathSwitchRequestAcknowledgeTransfer failed", "error", merr,
			"interface", "Nsmf", "direction", "OUT", "result", "FAILURE",
			"spec_ref", "TS 23.502 §4.9.1.2.2 step 6; TS 29.502 §5.2.2.3.3")
		pathSwitchAckEncodeFailure(w, merr)
		return
	}

	s.sessionMu.Lock()
	prevState := sess.State
	s.sessionMu.Unlock()
	if !s.markSessionActive(sess) { // RELEASING race: no N4
		smContextUpdateError(w, http.StatusConflict, causeSessionReleasing,
			"PDU session is being released after a UPF restart/failure",
			pathSwitchUnsuccessfulTransfer(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnspecified),
			n2SmInfoTypePathSwitchReqFail)
		return
	}

	cause, err := s.pfcpSwitchDL(ctx, base, "XnHandover", specXnSwitch, sess, dlTEID, gnbIP)
	if err != nil {
		s.sessionMu.Lock()
		if sess.State != sessionStateReleasing {
			sess.State = prevState
		}
		s.sessionMu.Unlock()
		status, pcause := hoN4Failure(err)
		metrics.ProcedureTotal.WithLabelValues("SMF", "XnHandoverDLSwitch", hoN4Result(err)).Inc()
		log.Error("Xn path switch: DL switch failed", "interface", "Nsmf", "direction", "OUT",
			"n2_sm_info_type", n2SmInfoTypePathSwitchReqFail, "supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID,
			"seid", sess.SEID, "dl_switch", "failed", "http_status", status, "cause", pcause,
			"pfcp_cause", pfcpCauseLabel(cause, err), "result", "FAILURE", "error", err,
			"spec_ref", "TS 23.502 §4.9.1.2.2 step 6; TS 29.502 §5.2.2.3.3")
		smContextUpdateError(w, status, pcause, "PFCP Session Modification failed",
			pathSwitchUnsuccessfulTransfer(ngapType.CausePresentRadioNetwork,
				ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem),
			n2SmInfoTypePathSwitchReqFail)
		return
	}

	metrics.ProcedureTotal.WithLabelValues("SMF", "XnHandoverDLSwitch", "OK").Inc()
	log.Info("Xn path switch: PathSwitchRequestAcknowledgeTransfer returned",
		"interface", "Nsmf", "direction", "OUT", "n2_sm_info_type", n2SmInfoTypePathSwitchReqAck,
		"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "seid", sess.SEID, "dl_switch", "done",
		"http_status", http.StatusOK, "result", "OK", "spec_ref", "TS 23.502 §4.9.1.2.2 step 6")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"n2SmInfo":     base64.StdEncoding.EncodeToString(ack),
		"n2SmInfoType": n2SmInfoTypePathSwitchReqAck,
	})
}

// handlePathSwitchSetupFail serves n2SmInfoType PATH_SWITCH_SETUP_FAIL (PSI in the Failed to
// Setup List of the PATH SWITCH REQUEST): decodes the relayed Cause, answers 204 No Content and
// then, detached from the request, deactivates the UP connection (Update FAR DROP, State IDLE)
// or releases the PDU session per rule R1. A RELEASING session takes no action. Unknown
// context -> 404 SmContextUpdateError.
// Ref: TS 23.502 §4.9.1.2.2 step 2, §4.3.7, §4.3.4.2; TS 29.502 §5.2.2.3.3.
func (s *Server) handlePathSwitchSetupFail(ctx context.Context, w http.ResponseWriter, base *slog.Logger, smContextRef string, n2SmInfo []byte) {
	log := base.With("procedure", "XnHandover", "interface", "Nsmf",
		"n2_sm_info_type", n2SmInfoTypePathSwitchSetupFail)

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()
	if sess == nil {
		log.Warn("Xn path switch: session not found", "direction", "IN", "result", "REJECT",
			"cause", "CONTEXT_NOT_FOUND", "spec_ref", "TS 29.502 §5.2.2.3.3; TS 23.502 §4.9.1.2.2 step 2")
		smContextUpdateError(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found", nil, "")
		return
	}

	var tr ngapType.PathSwitchRequestSetupFailedTransfer
	release := false
	if err := aper.UnmarshalWithParams(n2SmInfo, &tr, "valueExt"); err != nil {
		log.Warn("Xn path switch: PathSwitchRequestSetupFailedTransfer undecodable (deactivating)",
			"direction", "IN", "supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID,
			"result", "OK", "error", err, "spec_ref", "TS 23.502 §4.9.1.2.2 step 2")
	} else {
		s.sessionMu.Lock()
		release = releaseOnTargetFailure(tr.Cause, sess.UPSecurityRequired)
		s.sessionMu.Unlock()
		log.Info("Xn path switch: failed-to-setup PSI relayed by AMF",
			"direction", "IN", "supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID,
			"ngap_cause_group", tr.Cause.Present, "ngap_cause", ngapCauseValue(tr.Cause), "result", "OK",
			"spec_ref", "TS 23.502 §4.9.1.2.2 step 2")
	}

	s.sessionMu.Lock()
	releasing := sess.State == sessionStateReleasing
	s.sessionMu.Unlock()
	action := targetFailedDeactivate
	if release {
		action = targetFailedRelease
	}
	log.Info("Xn path switch: PATH_SWITCH_SETUP_FAIL answered 204", "direction", "OUT",
		"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "http_status", http.StatusNoContent,
		"target_failed_action", action, "session_releasing", releasing, "result", "OK",
		"spec_ref", "TS 29.502 §5.2.2.3.3; TS 23.502 §4.9.1.2.2 step 2")
	w.WriteHeader(http.StatusNoContent)
	if releasing {
		return // the PFCP node recovery releases the session; no deactivation / release here
	}
	dctx := context.WithoutCancel(ctx)
	s.goHO(func() { s.runTargetFailedAction(dctx, base, "XnHandover", sess, release) })
}
