package server

// pfcp_dldr.go — SMF side of the network-triggered Service Request N4 trigger (SMF-011):
// the UPF buffers DL data of a CM-IDLE session (Update FAR 1 BUFF+NOCP) and sends a PFCP
// Session Report Request with Report Type DLDR + Downlink Data Report. The SMF answers the
// report first, then asks the AMF to page the UE with Namf_Communication_N1N2MessageTransfer;
// on AMF failure it tells the UPF to discard the buffer (Update FAR 1 DROP).
// Design: docs/procedures/network-triggered-service-request.md ("N4 trigger (SMF-011)").
// Ref: TS 23.502 §4.2.3.3 steps 2a-3c; TS 29.244 §5.2.3, §7.5.8.2, §7.5.9, §8.2.21.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	// procDLDR is the procedure label of the DLDR metric (result OK/REJECT/FAILURE).
	procDLDR = "DownlinkDataReport"
	// procNTSR is the procedure of the DLDR-triggered paging logs and metric.
	procNTSR = "NetworkTriggeredServiceRequest"

	// dlPagingGuardTimeout bounds how long the "paging pending" flag suppresses a further
	// N1N2MessageTransfer for the same session: if the UE does not answer the page (no UP
	// activation) the flag is cleared and the DL FAR re-armed with BUFF+NOCP so a new DLDR
	// can page again. Implementation guard, not a 3GPP timer.
	// Ref: TS 23.502 §4.2.3.3 step 3a (SMF decides whether to contact the AMF).
	dlPagingGuardTimeout = 20 * time.Second

	// dlPagingDropTimeout bounds the Update FAR 1 DROP sent after an AMF failure; it runs on a
	// context detached from the (possibly expired) N1N2 deadline. Implementation guard.
	// Ref: TS 23.502 §4.2.3.3 step 3c.
	dlPagingDropTimeout = 3 * time.Second

	// dlPagingN1N2Timeout bounds the detached N1N2MessageTransfer call (implementation guard).
	dlPagingN1N2Timeout = 5 * time.Second

	// n1n2TempRejectRetry is the wait before the single retry after the AMF answered 409
	// TEMPORARY_REJECT_* (handover / registration ongoing). Implementation guard.
	// Ref: TS 23.502 §4.2.3.3 step 3b; TS 29.518 §6.1.3.5.3.
	n1n2TempRejectRetry = 2 * time.Second

	// causeAMFUnreachable is logged when the AMF gave no HTTP answer (transport error/timeout).
	causeAMFUnreachable = "AMF_UNREACHABLE"

	// dlServiceInfoFlagQFI / dlServiceInfoFlagPPI are the flag bits of octet 5 of the
	// Downlink Data Service Information IE. Ref: TS 29.244 §8.2.27 Figure 8.2.27-1.
	dlServiceInfoFlagPPI = 0x01
	dlServiceInfoFlagQFI = 0x02
	// qfiMask extracts the 6-bit QFI. Ref: TS 29.244 §8.2.27.
	qfiMask = 0x3f
)

// Spec labels of the DLDR flow log lines.
const (
	specDLDRIn     = "TS 23.502 §4.2.3.3 step 2a"
	specDLDRNamf   = "TS 23.502 §4.2.3.3 step 3a"
	specDLDRDrop   = "TS 23.502 §4.2.3.3 step 3c; TS 29.244 §7.5.4.3"
	specDLDRReArm  = "TS 23.502 §4.2.3.3 step 3a; TS 29.244 §5.2.3.1"
	specDLDRIEs    = "TS 29.244 §7.5.8.2"
	specDLDRReport = "TS 29.244 §7.5.9"
)

// isDLDR reports whether the Session Report Request carries the DLDR bit in Report Type.
// Ref: TS 29.244 §8.2.21.
func isDLDR(req *pfcpmsg.SessionReportRequest) bool {
	return req.ReportType != nil && req.ReportType.HasDLDR()
}

// downlinkDataReport is the parsed Downlink Data Report IE (TS 29.244 §7.5.8.2).
type downlinkDataReport struct {
	PDRID  uint16
	QFI    uint8
	HasQFI bool
}

// parseDownlinkDataReport decodes PDR ID (M) and the optional Downlink Data Service
// Information QFI. ok is false when the mandatory PDR ID is absent.
func parseDownlinkDataReport(dldr *pfcpie.IE) (rep downlinkDataReport, ok bool) {
	children, err := dldr.DownlinkDataReport()
	if err != nil {
		return rep, false
	}
	for _, c := range children {
		switch c.Type {
		case pfcpie.PDRID:
			if v, err := c.PDRID(); err == nil {
				rep.PDRID, ok = v, true
			}
		case pfcpie.DownlinkDataServiceInformation:
			p := c.Payload
			if len(p) == 0 || p[0]&dlServiceInfoFlagQFI == 0 {
				continue
			}
			i := 1
			if p[0]&dlServiceInfoFlagPPI != 0 {
				i++
			}
			if len(p) > i {
				rep.QFI, rep.HasQFI = p[i]&qfiMask, true
			}
		}
	}
	return rep, ok
}

// consumeDownlinkDataReport handles a Session Report Request with Report Type DLDR and
// returns the PFCP Cause, the Offending IE type (Cause 67 only, else 0) and, when paging must
// start, the function that performs it. The caller sends the Session Report Response first and
// then runs post (TS 23.502 §4.2.3.3 step 2b before 3a). No I/O happens here.
// Cause 65: unknown SEID (response header SEID 0, TS 29.244 §7.2.2.4.2); Cause 67 "Conditional
// IE missing" (TS 29.244 §7.6.6, §7.2.3.2, Table 7.5.8.1-1): Downlink Data Report absent
// (Offending IE 83) or without PDR ID (Offending IE 56).
func (s *Server) consumeDownlinkDataReport(ctx context.Context, req *pfcpmsg.SessionReportRequest) (cause uint8, offending uint16, post func()) {
	seid := req.SEID()
	log := logging.NewProcedureLogger(ctx, s.logger, procNTSR)

	sess := s.sessionBySEID(seid)
	if sess == nil {
		log.Warn("PFCP Downlink Data Report: session not found",
			"interface", "N4", "direction", "IN", "spec_ref", specDLDRIn+"; "+specDLDRReport,
			"seid", seid, "result", "REJECT", "cause", "SessionContextNotFound")
		metrics.ProcedureTotal.WithLabelValues("SMF", procDLDR, "REJECT").Inc()
		return pfcpie.CauseSessionContextNotFound, 0, nil
	}

	if req.DownlinkDataReport == nil {
		log.Warn("PFCP Downlink Data Report: IE missing",
			"interface", "N4", "direction", "IN", "spec_ref", specDLDRIn+"; "+specDLDRIEs,
			"seid", seid, "supi", sess.SUPI, "result", "REJECT", "cause", "ConditionalIEMissing")
		metrics.ProcedureTotal.WithLabelValues("SMF", procDLDR, "REJECT").Inc()
		return pfcpie.CauseConditionalIEMissing, pfcpie.DownlinkDataReport, nil
	}
	rep, ok := parseDownlinkDataReport(req.DownlinkDataReport)
	if !ok {
		log.Warn("PFCP Downlink Data Report: PDR ID missing",
			"interface", "N4", "direction", "IN", "spec_ref", specDLDRIn+"; "+specDLDRIEs,
			"seid", seid, "supi", sess.SUPI, "result", "REJECT", "cause", "ConditionalIEMissing")
		metrics.ProcedureTotal.WithLabelValues("SMF", procDLDR, "REJECT").Inc()
		return pfcpie.CauseConditionalIEMissing, pfcpie.PDRID, nil
	}

	// Check and set "paging pending" atomically under the session lock so two concurrent
	// DLDRs trigger exactly one N1N2MessageTransfer.
	s.sessionMu.Lock()
	supi, psi, state, stale := sess.SUPI, sess.PDUSessionID, sess.State, sess.N4Stale
	pending := sess.DLPagingPending
	start := !stale && state != sessionStateReleasing && state != "ACTIVE" && !pending
	if start {
		s.setDLPagingPendingLocked(sess)
	}
	s.sessionMu.Unlock()

	fields := []any{"interface", "N4", "direction", "IN", "spec_ref", specDLDRIn,
		"seid", seid, "supi", supi, "pdu_session_id", psi, "pdr_id", rep.PDRID,
		"session_state", state, "spec_ref_pfcp", specDLDRIEs}
	if rep.HasQFI {
		fields = append(fields, "qfi", rep.QFI)
	}
	switch {
	case stale || state == sessionStateReleasing || state == "ACTIVE":
		log.Info("PFCP Downlink Data Report: no paging needed", append(fields, "result", "OK", "reason", "session_"+state)...)
		metrics.ProcedureTotal.WithLabelValues("SMF", procDLDR, "OK").Inc()
		return pfcpie.CauseRequestAccepted, 0, nil
	case pending:
		log.Info("PFCP Downlink Data Report: paging already pending, no second N1N2MessageTransfer",
			append(fields, "result", "OK", "reason", "paging_pending")...)
		metrics.ProcedureTotal.WithLabelValues("SMF", procDLDR, "OK").Inc()
		return pfcpie.CauseRequestAccepted, 0, nil
	}
	if rep.PDRID != dlPDRID {
		log.Warn("PFCP Downlink Data Report: unexpected PDR ID", append(fields, "expected_pdr_id", dlPDRID)...)
	}
	log.Info("PFCP Downlink Data Report consumed", append(fields, "result", "OK")...)
	metrics.ProcedureTotal.WithLabelValues("SMF", procDLDR, "OK").Inc()

	// Detached from the PFCP receive loop; carries a correlation ID for the Namf leg.
	dctx := logging.WithCorrelationID(context.WithoutCancel(ctx), ulid.Make().String())
	return pfcpie.CauseRequestAccepted, 0, func() {
		s.goHO(func() { s.runDLPaging(dctx, sess, supi, psi) })
	}
}

// setDLPagingPendingLocked marks paging pending and arms the guard timer (dlPagingGuardTimeout).
// The caller holds s.sessionMu.
func (s *Server) setDLPagingPendingLocked(sess *Session) {
	if sess.dlPagingTimer != nil {
		sess.dlPagingTimer.Stop()
	}
	sess.DLPagingPending = true
	sess.dlPagingGen++
	gen := sess.dlPagingGen
	sess.dlPagingTimer = time.AfterFunc(dlPagingGuardTimeout, func() { s.expireDLPaging(sess, gen) })
}

// clearDLPagingPending clears the pending flag and stops the guard timer; it reports whether
// the flag was set. Called on UP re-activation, AMF failure and guard expiry.
func (s *Server) clearDLPagingPending(sess *Session) bool {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	return s.clearDLPagingLocked(sess)
}

func (s *Server) clearDLPagingLocked(sess *Session) bool {
	was := sess.DLPagingPending
	sess.DLPagingPending = false
	sess.dlPagingGen++
	if sess.dlPagingTimer != nil {
		sess.dlPagingTimer.Stop()
		sess.dlPagingTimer = nil
	}
	return was
}

// dlPagingPending reports whether a paging N1N2MessageTransfer is pending for sess.
func (s *Server) dlPagingPending(sess *Session) bool {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	return sess.DLPagingPending
}

// expireDLPaging runs at dlPagingGuardTimeout: the UE did not answer the page. It clears the
// flag and re-arms the DL FAR with BUFF+NOCP so the next DL packet can page again.
func (s *Server) expireDLPaging(sess *Session, gen uint64) {
	s.sessionMu.Lock()
	if !sess.DLPagingPending || sess.dlPagingGen != gen {
		s.sessionMu.Unlock()
		return
	}
	s.clearDLPagingLocked(sess)
	idle := sess.State == "IDLE"
	s.sessionMu.Unlock()

	ctx := logging.WithCorrelationID(context.Background(), ulid.Make().String())
	log := logging.NewProcedureLogger(ctx, s.logger, procNTSR)
	log.Warn("paging guard timer expired, UE did not answer the page",
		"interface", "N4", "direction", "OUT", "spec_ref", specDLDRReArm,
		"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "seid", sess.SEID,
		"guard_s", dlPagingGuardTimeout.Seconds(), "result", "FAILURE", "cause", "PAGING_GUARD_EXPIRED")
	if !idle {
		return
	}
	s.goHO(func() {
		if _, err := s.pfcpModifyFAR(ctx, s.logger, procNTSR,
			hoN4Spec{out: specDLDRReArm, in: "TS 29.244 §7.5.5"}, sess, buildDLBuffNocpFAR(), applyActionBuffNocpLabel); err != nil {
			log.Warn("re-arm Update FAR 1 BUFF+NOCP after paging guard expiry failed",
				"interface", "N4", "direction", "OUT", "spec_ref", specDLDRReArm,
				"seid", sess.SEID, "error", err, "result", "FAILURE")
		}
	})
}

// n1n2CauseAccepted reports whether the 2xx N1N2MessageTransfer cause means the transfer was
// initiated or the UE is being reached (an empty cause is tolerated).
// Ref: TS 29.518 §6.1.6.3.7 N1N2MessageTransferCause.
func n1n2CauseAccepted(c string) bool {
	switch c {
	case "", "N1_N2_TRANSFER_INITIATED", "ATTEMPTING_TO_REACH_UE", "WAIT_FOR_ASYNCHRONOUS_TRANSFER":
		return true
	}
	return false
}

// runDLPaging performs step 3a: Namf_Communication_N1N2MessageTransfer towards the AMF, one
// retry after 409 TEMPORARY_REJECT, and the failure handling (clear pending + Update FAR 1
// DROP so the UPF discards the buffer, TS 23.502 §4.2.3.3 step 3c).
func (s *Server) runDLPaging(ctx context.Context, sess *Session, supi string, psi uint8) {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, dlPagingN1N2Timeout)
	defer cancel()
	log := logging.NewProcedureLogger(ctx, s.logger, procNTSR)
	base := []any{"interface", "Namf", "direction", "OUT", "spec_ref", specDLDRNamf,
		"supi", supi, "pdu_session_id", psi, "seid", sess.SEID}

	start := time.Now()
	log.Info("N1N2MessageTransfer to AMF (DLDR trigger)", append(base, "message_type", "N1N2MessageTransfer")...)
	amfCause, err := s.triggerN1N2MessageTransfer(ctx, supi, psi)
	var ne *n1n2Error
	unexpected := false
	if errors.As(err, &ne) && ne.Status == 409 {
		log.Warn("AMF temporary reject, retrying once", append(base, "cause", ne.Cause, "result", "RETRY")...)
		select {
		case <-time.After(n1n2TempRejectRetry):
		case <-ctx.Done():
		}
		amfCause, err = s.triggerN1N2MessageTransfer(ctx, supi, psi)
		ne = nil // do not label a later transport error with the stale 409
	}
	if err == nil && !n1n2CauseAccepted(amfCause) {
		err = fmt.Errorf("smf: N1N2MessageTransfer: unexpected cause %q", amfCause)
		amfCause = ""
		unexpected = true
	}
	if err == nil {
		log.Info("N1N2MessageTransfer accepted by AMF, UE is being paged",
			append(base, "result", "OK", "amf_cause", amfCause, "duration_ms", time.Since(start).Milliseconds())...)
		metrics.ProcedureTotal.WithLabelValues("SMF", procNTSR, "OK").Inc()
		return
	}

	cause := causeAMFUnreachable
	if unexpected {
		cause = "AMF_UNEXPECTED_CAUSE"
	} else if errors.As(err, &ne) && ne.Cause != "" {
		cause = ne.Cause
	} else if ne != nil {
		cause = "AMF_STATUS_" + itoa(ne.Status)
	}
	log.Error("N1N2MessageTransfer to AMF failed",
		append(base, "result", "FAILURE", "cause", cause, "error", err, "duration_ms", time.Since(start).Milliseconds())...)
	metrics.ProcedureTotal.WithLabelValues("SMF", procNTSR, "FAILURE").Inc()

	s.clearDLPagingPending(sess)
	// The N1N2 deadline may be spent: send the DROP on a detached context with its own timeout.
	dctx, dcancel := context.WithTimeout(context.WithoutCancel(parent), dlPagingDropTimeout)
	defer dcancel()
	if _, derr := s.pfcpModifyFAR(dctx, s.logger, procNTSR,
		hoN4Spec{out: specDLDRDrop, in: "TS 29.244 §7.5.5"}, sess, buildDLDropFAR(), "DROP"); derr != nil {
		log.Warn("Update FAR 1 DROP after AMF failure not confirmed", "interface", "N4", "direction", "OUT",
			"spec_ref", specDLDRDrop, "seid", sess.SEID, "error", derr, "result", "FAILURE")
	}
}
