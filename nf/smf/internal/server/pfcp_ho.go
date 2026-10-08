package server

// pfcp_ho.go — synchronous N4 helpers used by the handover legs of Nsmf_PDUSession_UpdateSMContext
// (SMF-005, docs/procedures/N2Handover.md §7.1): the DL path switch at Handover Complete / Xn
// path switch (Update FAR 1: FORW + Outer Header Creation of the target gNB) and the UP
// deactivation of a target-failed PDU session (Update FAR 1: DROP). Both go through
// pfcpTransact, check the Cause of the Session Modification Response and return it to the
// caller, which answers the AMF only afterwards.
// Ref: TS 23.502 §4.9.1.3.3, §4.9.1.2.2 steps 3-4, §4.3.7; TS 29.244 §7.5.4, §7.5.5.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/free5gc/ngap/ngapType"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// hoN4Timeout bounds the SMF's wait for the PFCP Session Modification Response inside a
// handover UpdateSMContext (N2 Handover Complete, Xn PATH_SWITCH_REQ, detached deactivation).
// It is an implementation guard, not a 3GPP timer: it must stay below the AMF's
// smfHOUpdateTimeout (2 s, nf/amf/internal/ngap/smf_leg.go) so the AMF receives an explicit
// SmContextUpdateError instead of timing out itself. With the default T1 (3 s) only the first
// transmission fits in the budget (TS 29.244 §6.4 retransmission is still used when T1 is shorter).
const hoN4Timeout = 1500 * time.Millisecond

// Problem causes used by the handover legs.
// Ref: TS 29.502 §6.1.7.3 (application errors), TS 29.500 §5.2.7.2.
const (
	causeSystemFailure = "SYSTEM_FAILURE"
	// causeUPFNotResponding: the UPF did not answer the PFCP request within hoN4Timeout.
	causeUPFNotResponding = "UPF_NOT_RESPONDING"
	// causeHOResAllocFailure: the target NG-RAN could not allocate resources for the PDU session.
	causeHOResAllocFailure = "HANDOVER_RESOURCE_ALLOCATION_FAILURE"
)

// Log values of the target_failed_action field.
const (
	targetFailedDeactivate = "deactivate"
	targetFailedRelease    = "release"
)

var (
	// errSessionReleasing: the session is RELEASING (PFCP node recovery); no N4 is sent.
	errSessionReleasing = errors.New("smf: session releasing, N4 skipped")
	// errPFCPRejected: the UPF answered with a Cause other than Request accepted.
	errPFCPRejected = errors.New("smf: pfcp: request rejected by UPF")
	// errPFCPCauseMissing: the Session Modification Response carries no Cause IE.
	errPFCPCauseMissing = errors.New("smf: pfcp: response without Cause")
)

// hoN4Spec names the spec clauses logged for one N4 exchange.
type hoN4Spec struct{ out, in string }

var (
	specN2Switch = hoN4Spec{
		out: "TS 23.502 §4.9.1.3.3 (N4 Session Modification); TS 29.244 §7.5.4",
		in:  "TS 29.244 §7.5.5",
	}
	specXnSwitch = hoN4Spec{
		out: "TS 23.502 §4.9.1.2.2 step 3; TS 29.244 §7.5.4",
		in:  "TS 23.502 §4.9.1.2.2 step 4; TS 29.244 §7.5.5",
	}
	specDeactivate = hoN4Spec{
		out: "TS 23.502 §4.3.7 step 3; TS 29.244 §7.5.4.3",
		in:  "TS 29.244 §7.5.5",
	}
)

// buildDLSwitchFAR builds the Update FAR of the DL path switch: FAR 1, Apply Action FORW,
// Update Forwarding Parameters with Outer Header Creation GTP-U/UDP/IPv4 (target TEID + IP).
// Shared with sendPFCPSessionModification so both stay byte-identical.
// Ref: TS 29.244 §7.5.4.3, §8.2.26, §8.2.56.
func buildDLSwitchFAR(dlTEID uint32, gnbIP net.IP) *pfcpie.IE {
	return pfcpie.NewUpdateFAR(
		pfcpie.NewFARID(1),
		pfcpie.NewApplyAction(0x02), // FORW
		pfcpie.NewUpdateForwardingParameters(
			// Outer header: GTP-U/UDP/IPv4 (desc=0x0100), DL TEID, gNB N3 IP
			pfcpie.NewOuterHeaderCreation(0x0100, dlTEID, gnbIP.String(), "", 0, 0, 0),
		),
	)
}

// buildDLDropFAR builds the Update FAR of a UP deactivation: FAR 1, Apply Action DROP
// (0x01, TS 29.244 §8.2.26), no forwarding parameters. Shared with sendPFCPSessionDeactivation.
// Ref: TS 29.244 §7.5.4.3.
func buildDLDropFAR() *pfcpie.IE {
	return pfcpie.NewUpdateFAR(
		pfcpie.NewFARID(1),
		pfcpie.NewApplyAction(0x01), // DROP — UPF discards DL packets
	)
}

// pfcpSwitchDL sends the DL path switch (Update FAR 1 FORW + OHC) and waits for the response.
// It returns the PFCP Cause (0 when none was received) and an error: errSessionReleasing,
// errPFCPTimeout, errPFCPRejected (cause != 1), errPFCPCauseMissing or a transport error.
// base must not carry procedure/interface attributes.
// Ref: TS 23.502 §4.9.1.3.3, §4.9.1.2.2 steps 3-4; TS 29.244 §7.5.4, §7.5.5.
func (s *Server) pfcpSwitchDL(ctx context.Context, base *slog.Logger, procedure string, spec hoN4Spec,
	sess *Session, dlTEID uint32, gnbIP net.IP) (uint8, error) {
	return s.pfcpModifyFAR(ctx, base, procedure, spec, sess, buildDLSwitchFAR(dlTEID, gnbIP), "FORW",
		"dl_teid", dlTEID, "gnb_ip", gnbIP.String())
}

// pfcpDeactivateDL sends Update FAR 1 with Apply Action DROP (UP deactivation) and waits for
// the response. Same return contract as pfcpSwitchDL.
// Ref: TS 23.502 §4.3.7 step 3; TS 29.244 §7.5.4.3.
func (s *Server) pfcpDeactivateDL(ctx context.Context, base *slog.Logger, procedure string, sess *Session) (uint8, error) {
	return s.pfcpModifyFAR(ctx, base, procedure, specDeactivate, sess, buildDLDropFAR(), "DROP")
}

// pfcpModifyFAR is the shared synchronous Session Modification transaction (bounded by
// hoN4Timeout) with the canonical N4 OUT/IN log lines.
func (s *Server) pfcpModifyFAR(ctx context.Context, base *slog.Logger, procedure string, spec hoN4Spec,
	sess *Session, far *pfcpie.IE, applyAction string, extra ...any) (uint8, error) {
	if s.skipN4ForReleasing(sess, "HandoverModification") {
		return 0, errSessionReleasing
	}
	ctx, cancel := context.WithTimeout(ctx, hoN4Timeout)
	defer cancel()

	log := base.With("procedure", procedure, "interface", "N4", "supi", sess.SUPI,
		"pdu_session_id", sess.PDUSessionID, "seid", sess.SEID)
	req := pfcpmsg.NewSessionModificationRequest(0, 0, sess.SEID, s.nextPFCPSeq(), 0, far)
	log.InfoContext(ctx, "PFCP Session Modification Request sent", append([]any{
		"direction", "OUT", "message_type", "PFCPSessionModificationRequest",
		"far_id", 1, "apply_action", applyAction, "seq", req.Sequence(), "spec_ref", spec.out}, extra...)...)

	start := time.Now()
	msg, err := s.pfcpTransact(ctx, base, req, pfcpmsg.MsgTypeSessionModificationResponse)
	if err != nil {
		if errors.Is(err, errPFCPTimeout) || errors.Is(err, context.DeadlineExceeded) {
			err = errPFCPTimeout
		}
		log.WarnContext(ctx, "PFCP Session Modification Response not received",
			"direction", "IN", "message_type", "PFCPSessionModificationResponse", "result", "FAILURE",
			"cause", "pfcp-timeout", "error", err, "duration_ms", time.Since(start).Milliseconds(),
			"spec_ref", spec.in)
		return 0, err
	}
	rsp, ok := msg.(*pfcpmsg.SessionModificationResponse)
	if !ok || rsp.Cause == nil {
		log.WarnContext(ctx, "PFCP Session Modification Response without Cause",
			"direction", "IN", "message_type", "PFCPSessionModificationResponse", "result", "FAILURE",
			"pfcp_cause", "missing", "duration_ms", time.Since(start).Milliseconds(), "spec_ref", spec.in)
		return 0, errPFCPCauseMissing
	}
	cause, _ := rsp.Cause.Cause()
	fields := []any{"direction", "IN", "message_type", "PFCPSessionModificationResponse",
		"pfcp_cause", cause, "duration_ms", time.Since(start).Milliseconds(), "spec_ref", spec.in}
	if rsp.OffendingIE != nil {
		if t, oerr := rsp.OffendingIE.OffendingIE(); oerr == nil {
			fields = append(fields, "offending_ie", t)
		}
	}
	if cause != pfcpie.CauseRequestAccepted {
		log.WarnContext(ctx, "PFCP Session Modification rejected by UPF", append(fields, "result", "REJECT")...)
		return cause, fmt.Errorf("%w: cause %d", errPFCPRejected, cause)
	}
	log.InfoContext(ctx, "PFCP Session Modification Response received", append(fields, "result", "OK")...)
	return cause, nil
}

// hoN4Failure maps a pfcpSwitchDL / pfcpDeactivateDL error to the HTTP status and problem cause
// of the SmContextUpdateError (N2Handover.md §4.4): 409 releasing, 504 UPF_NOT_RESPONDING on
// timeout, 500 SYSTEM_FAILURE otherwise.
func hoN4Failure(err error) (int, string) {
	switch {
	case errors.Is(err, errSessionReleasing):
		return http.StatusConflict, causeSessionReleasing
	case errors.Is(err, errPFCPTimeout):
		return http.StatusGatewayTimeout, causeUPFNotResponding
	default:
		return http.StatusInternalServerError, causeSystemFailure
	}
}

// hoN4Result is the metric/log result label of a failed N4 exchange: REJECT for a UPF
// answer with a non-accepted Cause, FAILURE otherwise.
func hoN4Result(err error) string {
	if errors.Is(err, errPFCPRejected) {
		return "REJECT"
	}
	return "FAILURE"
}

// pfcpCauseLabel is the pfcp_cause log value of a failed exchange: the numeric Cause, or
// "missing" when the response had none, or "" when no response arrived.
func pfcpCauseLabel(cause uint8, err error) any {
	switch {
	case errors.Is(err, errPFCPCauseMissing):
		return "missing"
	case errors.Is(err, errPFCPRejected):
		return cause
	}
	return ""
}

// releaseOnTargetFailure is rule R1 (N2Handover.md §5.2): a target-failed PDU session is
// released when the NGAP Cause says user-plane integrity/confidentiality protection is not
// possible AND the session's UP security enforcement policy is Required; every other case
// deactivates the UP connection instead.
// Ref: TS 23.502 §4.9.1.2.2 step 2, §4.3.7, §4.3.4.2; TS 23.501 §5.10.3; TS 38.413 §9.3.1.2.
func releaseOnTargetFailure(c ngapType.Cause, upSecRequired bool) bool {
	if !upSecRequired || c.Present != ngapType.CausePresentRadioNetwork || c.RadioNetwork == nil {
		return false
	}
	switch c.RadioNetwork.Value {
	case ngapType.CauseRadioNetworkPresentUpIntegrityProtectionNotPossible,
		ngapType.CauseRadioNetworkPresentUpConfidentialityProtectionNotPossible:
		return true
	}
	return false
}

// goHO runs fn on a tracked goroutine (WaitHandoverTasks waits for it); used for the
// detached release/deactivation of target-failed PDU sessions.
func (s *Server) goHO(fn func()) {
	s.hoWG.Add(1)
	go func() {
		defer s.hoWG.Done()
		fn()
	}()
}

// WaitHandoverTasks blocks until every detached target-failed release/deactivation goroutine
// has finished; used by tests.
func (s *Server) WaitHandoverTasks() { s.hoWG.Wait() }

// runTargetFailedAction executes the release-or-deactivate decision for a target-failed PDU
// session (runs detached from the AMF request). release=true asks the AMF to release the PDU
// session (SMF-initiated release, TS 23.502 §4.3.4.2); on failure it falls back to the UP
// deactivation (Update FAR DROP, State=IDLE on Cause 1).
// Ref: TS 23.502 §4.9.1.2.2 step 2, §4.3.7, §4.3.4.2.
func (s *Server) runTargetFailedAction(ctx context.Context, base *slog.Logger, procedure string, sess *Session, release bool) {
	log := base.With("procedure", procedure, "supi", sess.SUPI,
		"pdu_session_id", sess.PDUSessionID, "seid", sess.SEID)
	if release {
		err := s.requestAMFRelease(ctx, sess.SUPI, sess.PDUSessionID)
		if err == nil {
			metrics.ProcedureTotal.WithLabelValues("SMF", "HandoverTargetFailedRelease", "OK").Inc()
			log.InfoContext(ctx, "target-failed PDU session release requested from AMF",
				"interface", "Namf-mgmt", "direction", "OUT", "target_failed_action", targetFailedRelease,
				"result", "OK", "spec_ref", "TS 23.502 §4.3.4.2")
			return
		}
		metrics.ProcedureTotal.WithLabelValues("SMF", "HandoverTargetFailedRelease", "FAILURE").Inc()
		log.WarnContext(ctx, "target-failed PDU session release failed — falling back to UP deactivation",
			"interface", "Namf-mgmt", "direction", "OUT", "target_failed_action", targetFailedRelease,
			"result", "FAILURE", "error", err, "spec_ref", "TS 23.502 §4.3.4.2")
	}
	cause, err := s.pfcpDeactivateDL(ctx, base, procedure, sess)
	if err != nil {
		metrics.ProcedureTotal.WithLabelValues("SMF", "HandoverTargetFailedDeactivate", hoN4Result(err)).Inc()
		log.WarnContext(ctx, "target-failed PDU session UP deactivation failed",
			"interface", "N4", "direction", "OUT", "target_failed_action", targetFailedDeactivate,
			"up_deactivation", "failed", "pfcp_cause", pfcpCauseLabel(cause, err), "result", hoN4Result(err),
			"error", err, "spec_ref", "TS 23.502 §4.3.7")
		return
	}
	s.sessionMu.Lock()
	if sess.State != sessionStateReleasing {
		sess.State = "IDLE"
	}
	s.sessionMu.Unlock()
	metrics.ProcedureTotal.WithLabelValues("SMF", "HandoverTargetFailedDeactivate", "OK").Inc()
	log.InfoContext(ctx, "target-failed PDU session UP connection deactivated",
		"interface", "N4", "direction", "OUT", "target_failed_action", targetFailedDeactivate,
		"up_deactivation", "done", "result", "OK", "spec_ref", "TS 23.502 §4.3.7")
}
