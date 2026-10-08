package ngap

// smf_leg.go — synchronous Nsmf_PDUSession_UpdateSMContext leg of the Xn (Path Switch)
// and N2 (Handover Request Acknowledge) handovers (AMF-012).
//
// The AMF waits for each per-PDU-session SMF response and relays the SMF-returned
// N2 SM information into the NGAP response instead of building empty transfers
// itself. Design: docs/procedures/XnHandover.md §7.4.
//
// N2 handover legs (all per admitted/candidate PDU session, TS 29.502 §5.2.2.3.4):
//   - PREPARING at HANDOVER REQUIRED (TS 23.502 §4.9.1.3.2 steps 3-6);
//   - PREPARED, HANDOVER_REQ_ACK / HANDOVER_RES_ALLOC_FAIL at HANDOVER REQUEST
//     ACKNOWLEDGE (steps 9-12);
//   - COMPLETED after HANDOVER NOTIFY (TS 23.502 §4.9.1.3.3, Handover Complete).
//
// Ref: TS 23.502 §4.9.1.2.2 steps 2-7, §4.9.1.3.2 steps 3-12; TS 38.413 §8.4.4.2, §9.3.4.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// smfHOUpdateTimeout bounds the AMF's wait for one Nsmf_PDUSession_UpdateSMContext
// response during a handover. It is an implementation guard, NOT a 3GPP timer: it
// must stay below the target gNB's path-switch supervision (implementation specific;
// TS 38.413 defines no AMF-side timer for the Path Switch Request procedure) and below
// the source gNB's TNGRELOCprep for N2 handover. All PDU sessions run concurrently so
// the total wait is about one timeout. Tests shorten it with SetSMFHOUpdateTimeoutForTest.
const smfHOUpdateTimeout = 2 * time.Second

// N2SmInfoType values of Nsmf_PDUSession (TS 29.502 §6.1.6.3 (N2SmInfoType / HoState), same strings as the SMF).
const (
	n2InfoPathSwitchReq      = "PATH_SWITCH_REQ"
	n2InfoPathSwitchSetupFl  = "PATH_SWITCH_SETUP_FAIL"
	n2InfoPathSwitchReqAck   = "PATH_SWITCH_REQ_ACK"
	n2InfoPathSwitchReqFail  = "PATH_SWITCH_REQ_FAIL"
	n2InfoHandoverReqAck     = "HANDOVER_REQ_ACK"
	n2InfoHandoverCmd        = "HANDOVER_CMD"
	n2InfoHandoverPrepFail   = "HANDOVER_PREP_FAIL"
	n2InfoHandoverRequired   = "HANDOVER_REQUIRED"
	n2InfoPDUResSetupReq     = "PDU_RES_SETUP_REQ"
	n2InfoHandoverResAllocFl = "HANDOVER_RES_ALLOC_FAIL"
	hoStatePreparing         = "PREPARING"
	hoStatePrepared          = "PREPARED"
	hoStateCancelled         = "CANCELLED"
	hoStateCompleted         = "COMPLETED"
	causeSMFTimeout          = "smf-timeout"
	causeSMFUnreachable      = "smf-unreachable"
	causeInvalidN2SmInfo     = "invalid-n2sminfo"
	causeSMFRejectedAll      = "smf-rejected-all"
	smfResultOK              = "OK"
	smfResultReject          = "REJECT"
	smfResultFailure         = "FAILURE"
	procXnHandover           = "XnHandover"
	procN2Handover           = "N2Handover"
	procXnSMFUpdate          = "XnHandoverSMFUpdate"
	procXnSMFSetupFail       = "XnHandoverSMFSetupFail"
	procXnSMFDeactivate      = "XnHandoverSMFDeactivate"
	procN2SMFPrepare         = "N2HandoverSMFPrepare"
	procN2SMFPreparing       = "N2HandoverSMFPreparing"
	procN2SMFResAllocFail    = "N2HandoverSMFResAllocFail"
	procN2SMFComplete        = "N2HandoverSMFComplete"
	procN2SMFDeactivate      = "N2HandoverSMFDeactivate"
	refN2TargetFailedDeact   = "TS 23.502 §4.3.7 step 1; §4.9.1.3.3"
	refXnSMFResp             = "TS 23.502 §4.9.1.2.2 step 6"
	refXnSMFDeact            = "TS 23.502 §4.9.1.2.2 (UP deactivation of sessions not listed)"
	refN2SMFReq              = "TS 23.502 §4.9.1.3.2 steps 10-12 (request, step 10)"
	refN2SMFResp             = "TS 23.502 §4.9.1.3.2 steps 10-12 (response, step 12)"
	refN2Command             = "TS 38.413 §8.4.1.2"
	refN2PrepFailure         = "TS 38.413 §8.4.1.3"
	refN2Ack                 = "TS 23.502 §4.9.1.3.2 step 9"
	refN2Required            = "TS 23.502 §4.9.1.3.2 step 1"
	refN2PreparingReq        = "TS 23.502 §4.9.1.3.2 step 3"
	refN2PreparingResp       = "TS 23.502 §4.9.1.3.2 step 6"
	refN2HOReq               = "TS 23.502 §4.9.1.3.2 step 8"
	refN2ResAllocFail        = "TS 23.502 §4.9.1.3.2 step 10"
	refN2ResAllocFailResp    = "TS 23.502 §4.9.1.3.2 step 12"
	refN2Complete            = "TS 23.502 §4.9.1.3.3 (Handover Complete indication)"
	refN2Notify              = "TS 38.413 §8.4.3"
	refN2UECtxRelease        = "TS 23.502 §4.9.1.3.3 (UE Context Release in the source NG-RAN); TS 38.413 §8.3.3"
	refUnsuccessfulTransfers = "TS 38.413 §9.3.4"
)

// SMFUpdateResult is the decoded outcome of one Nsmf_PDUSession_UpdateSMContext call
// (SmContextUpdatedData for 2xx, SmContextUpdateError otherwise — TS 29.502 §6.1.6.2 (SmContextUpdatedData / SmContextUpdateError)).
// A call counts as successful only when Err is nil and HTTPStatus is 2xx; a zero
// HTTPStatus without Err is treated as a failure.
type SMFUpdateResult struct {
	// HTTPStatus is the SMF HTTP status code (0 when no response was received).
	HTTPStatus int
	// N2SmInfo is the decoded (base64-decoded) APER n2SmInfo, nil when absent.
	N2SmInfo []byte
	// N2SmInfoType is the n2SmInfoType string accompanying N2SmInfo ("" when absent).
	N2SmInfoType string
	// HoState is the hoState of SmContextUpdatedData ("" when absent).
	HoState string
	// Cause is the ProblemDetails cause of an error response ("" when absent).
	Cause string
	// Err is a transport-level error (no HTTP response); context.DeadlineExceeded
	// when the AMF-side wait timed out.
	Err error
}

// OK reports whether the SMF answered with a 2xx status.
func (r SMFUpdateResult) OK() bool {
	return r.Err == nil && r.HTTPStatus >= http.StatusOK && r.HTTPStatus < http.StatusMultipleChoices
}

// SMFTransferHook performs one Nsmf_PDUSession_UpdateSMContext call for the SM context
// smContextRef carrying the given raw N2 SM information (the NGAP transfer relayed
// unchanged) and returns the decoded response. It must honour ctx cancellation.
type SMFTransferHook func(ctx context.Context, smContextRef string, n2SmInfo []byte) SMFUpdateResult

// UPDeactivateHook performs Nsmf_PDUSession_UpdateSMContext with upCnxState=DEACTIVATED
// (no N2 SM information) for smContextRef. Ref: TS 29.502 §5.2.2.3.2 (UP activation/deactivation).
type UPDeactivateHook func(ctx context.Context, smContextRef string) error

// HandoverRequiredHook performs the PREPARING Nsmf_PDUSession_UpdateSMContext (hoState
// PREPARING, n2SmInfoType HANDOVER_REQUIRED) for smContextRef carrying the source gNB's
// HandoverRequiredTransfer (nil when it sent none) and the decoded Target ID, and returns
// the decoded response (PDU_RES_SETUP_REQ on success). It must honour ctx cancellation.
// Ref: TS 23.502 §4.9.1.3.2 steps 3-6; TS 29.502 §5.2.2.3.4.
type HandoverRequiredHook func(ctx context.Context, smContextRef string, hoRequiredTransfer []byte, target HOTargetID) SMFUpdateResult

// HandoverCompleteHook performs the Handover Complete UpdateSMContext (hoState COMPLETED,
// no N2 SM information) for smContextRef. It must honour ctx cancellation.
// Ref: TS 23.502 §4.9.1.3.3; TS 29.502 §5.2.2.3.4.
type HandoverCompleteHook func(ctx context.Context, smContextRef string) SMFUpdateResult

// smfUpdateTimeout returns the per-PSI SMF wait bound (test override or the default).
func (s *Server) smfUpdateTimeout() time.Duration {
	if s.smfHOTimeout > 0 {
		return s.smfHOTimeout
	}
	return smfHOUpdateTimeout
}

// callSMF runs hook bounded by timeout. It returns as soon as the hook answers or the
// bound expires, whichever is first, so a hook that ignores ctx cannot hold the
// handover beyond the bound (its goroutine ends when the hook eventually returns).
func callSMF(ctx context.Context, timeout time.Duration, hook SMFTransferHook, ref string, transfer []byte) (res SMFUpdateResult, dur time.Duration, timedOut bool) {
	return callSMFBounded(ctx, timeout, func(cctx context.Context) SMFUpdateResult { return hook(cctx, ref, transfer) })
}

// callSMFBounded is callSMF for an arbitrary call (the hooks of the PREPARING and
// COMPLETED legs have other signatures than SMFTransferHook).
func callSMFBounded(ctx context.Context, timeout time.Duration, call func(ctx context.Context) SMFUpdateResult) (res SMFUpdateResult, dur time.Duration, timedOut bool) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	ch := make(chan SMFUpdateResult, 1)
	go func() { ch <- call(cctx) }()
	select {
	case res = <-ch:
		return res, time.Since(start), errors.Is(res.Err, context.DeadlineExceeded)
	case <-cctx.Done():
		return SMFUpdateResult{Err: cctx.Err()}, time.Since(start), errors.Is(cctx.Err(), context.DeadlineExceeded)
	}
}

// withCorrelation returns ctx carrying a correlation ID (generated when absent) so
// the SBI legs of one handover share the X-Correlation-Id.
func withCorrelation(ctx context.Context) context.Context {
	if logging.CorrelationID(ctx) != "" {
		return ctx
	}
	return logging.WithCorrelationID(ctx, "")
}

// ---- decode checks of SMF-supplied transfers (never forward undecodable bytes) ----

func decodesAs(b []byte, v any) bool {
	return len(b) > 0 && aper.UnmarshalWithParams(b, v, "valueExt") == nil
}

func validPathSwitchAckTransfer(b []byte) bool {
	return decodesAs(b, &ngapType.PathSwitchRequestAcknowledgeTransfer{})
}

func validPathSwitchUnsuccessfulTransfer(b []byte) bool {
	return decodesAs(b, &ngapType.PathSwitchRequestUnsuccessfulTransfer{})
}

func validHandoverCommandTransfer(b []byte) bool {
	return decodesAs(b, &ngapType.HandoverCommandTransfer{})
}

// validPDUResSetupRequestTransfer reports whether b decodes as a PDUSessionResourceSetupRequestTransfer
// (also used as the Handover Request Transfer, TS 38.413 §9.3.4.1) that carries the
// UL-NGU-UP-TNLInformation the target gNB needs. The APER decoder accepts arbitrary garbage as
// an empty IE list, so an empty / tunnel-less result is rejected too.
func validPDUResSetupRequestTransfer(b []byte) bool {
	var tr ngapType.PDUSessionResourceSetupRequestTransfer
	if !decodesAs(b, &tr) {
		return false
	}
	for _, ie := range tr.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDULNGUUPTNLInformation && ie.Value.ULNGUUPTNLInformation != nil {
			return true
		}
	}
	return false
}

func validHandoverPrepUnsuccessfulTransfer(b []byte) bool {
	return decodesAs(b, &ngapType.HandoverPreparationUnsuccessfulTransfer{})
}

// failCause maps a failed SMF call to the NGAP radioNetwork cause the AMF builds when
// the SMF supplied no usable transfer: 404 -> unknown-PDU-session-ID (26), everything
// else -> ho-failure-in-target-5GC-ngran-node-or-target-system (7).
// Ref: docs/procedures/XnHandover.md §5.1 E5-E7, E17.
func failCause(res SMFUpdateResult, timedOut bool) (present int, value int64) {
	if !timedOut && res.Err == nil && res.HTTPStatus == http.StatusNotFound {
		return ngapType.CausePresentRadioNetwork, int64(ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)
	}
	return ngapType.CausePresentRadioNetwork, int64(ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)
}

// failCauseLabel is the `cause` log value of a failed SMF call.
func failCauseLabel(res SMFUpdateResult, timedOut bool) string {
	switch {
	case timedOut:
		return causeSMFTimeout
	case res.Err != nil:
		return causeSMFUnreachable
	case res.Cause != "":
		return res.Cause
	default:
		return "smf-rejected"
	}
}

// recordSMFLeg counts the outcome of one per-PDU-session Nsmf_PDUSession_UpdateSMContext
// handover leg in fivegc_procedure_total{nf="AMF",procedure=proc,result}. proc is one of
// procXnSMFUpdate, procXnSMFSetupFail, procXnSMFDeactivate, procN2SMFPrepare,
// procN2SMFPreparing, procN2SMFResAllocFail, procN2SMFComplete; result is
// smfResultOK|smfResultReject|smfResultFailure (same value as the leg's `result` log field).
func recordSMFLeg(proc, result string) {
	metrics.ProcedureTotal.WithLabelValues("AMF", proc, result).Inc()
}
