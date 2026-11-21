package nasmsg

// udm_dereg.go - UDM-triggered network-initiated de-registration (AMF-037 slice A).
//
// Nudm_UECM_DeregistrationNotification dispatch by deregReason and CM state:
//
//	SUBSCRIPTION_WITHDRAWN / REREGISTRATION_REQUIRED, CM-CONNECTED
//	    -> DEREGISTRATION REQUEST (no 5GMM cause), SM + PCF + SDM released right
//	       after the send, N2 release on ACCEPT / T3522 abort, no UECM DELETE
//	same, CM-IDLE
//	    -> implicit de-registration (no NAS, no paging)
//	5GS_TO_EPS_MOBILITY[_UE_INITIAL_REGISTRATION]
//	    -> silent: SM contexts kept, PCF + SDM released, context removed
//	accessType NON_3GPP_ACCESS -> no-op (3GPP-only AMF)
//	any other reason -> not handled here (caller keeps its legacy local removal)
//
// Design: docs/procedures/network-deregistration.md.
// Ref: TS 23.502 §4.2.2.3.3, §4.11.1.3.2 step 15, §4.11.1.5.3 step 13;
// TS 24.501 §5.5.2.3.1; TS 29.503 §5.3.2.3

import (
	"context"
	"log/slog"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// DeregistrationReason values (TS 29.503 §6.2.6.3.3) and AccessType values
// (TS 29.571 §5.4.3.2) the AMF acts on.
const (
	DeregReasonSubscriptionWithdrawn  = "SUBSCRIPTION_WITHDRAWN"
	DeregReasonReregistrationRequired = "REREGISTRATION_REQUIRED"
	DeregReasonEPSMobility            = "5GS_TO_EPS_MOBILITY"
	DeregReasonEPSMobilityUEInitReg   = "5GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION"
	accessTypeNon3GPP                 = "NON_3GPP_ACCESS"
)

// UDMDeregTimeout bounds the SBI work of one UDM-triggered de-registration (own
// bound, not a 3GPP value).
const UDMDeregTimeout = 30 * time.Second

// UDMDeregAction is the class of a DeregistrationNotification reason.
type UDMDeregAction int

const (
	// UDMDeregOther: reason not covered by AMF-037 (legacy local removal).
	UDMDeregOther UDMDeregAction = iota
	// UDMDeregExplicit: explicit (CM-CONNECTED) / implicit (CM-IDLE) de-registration.
	UDMDeregExplicit
	// UDMDeregEPS: 5GS to EPS mobility, SM contexts stay.
	UDMDeregEPS
)

// ClassifyUDMDereg maps a deregReason to its action class (docs §1.1).
func ClassifyUDMDereg(reason string) UDMDeregAction {
	switch reason {
	case DeregReasonSubscriptionWithdrawn, DeregReasonReregistrationRequired:
		return UDMDeregExplicit
	case DeregReasonEPSMobility, DeregReasonEPSMobilityUEInitReg:
		return UDMDeregEPS
	}
	return UDMDeregOther
}

// HandleUDMDeregistration serves a DeregistrationNotification for ue. It returns
// handled=false for reasons outside AMF-037 (the caller then runs its legacy
// removal); otherwise the work is enqueued on the UE's serial queue, detached
// from ctx (the HTTP request returns 204 right after), and handled=true.
// accessType empty = 3GPP access. Ref: TS 23.502 §4.2.2.3.3 steps 1-3
func (h *Handler) HandleUDMDeregistration(ctx context.Context, ue *amfctx.UEContext, reason, accessType string) (handled bool) {
	log := h.udmDeregLogger(ue, reason, accessType)
	if accessType == accessTypeNon3GPP {
		log.Info("UDM deregistration for non-3GPP access ignored - 3GPP-only AMF",
			"interface", "Nudm", "direction", "IN", "result", "OK", "spec_ref", "TS 23.502 §4.2.2.3.3 step 2")
		return true
	}
	action := ClassifyUDMDereg(reason)
	if action == UDMDeregOther {
		return false
	}
	dctx := context.WithoutCancel(ctx)
	ue.EnqueueSerial(func() {
		rctx, cancel := context.WithTimeout(dctx, UDMDeregTimeout)
		defer cancel()
		h.runUDMDeregistration(rctx, ue, reason, action, accessType)
	})
	return true
}

func (h *Handler) udmDeregLogger(ue *amfctx.UEContext, reason, accessType string) *slog.Logger {
	if accessType == "" {
		accessType = "3GPP_ACCESS"
	}
	return h.logger.With("nf", "AMF", "procedure", "NetworkDeregistration",
		"supi", ue.SUPI, "amf_ue_ngap_id", ue.AMFUENGAPId,
		"dereg_reason", reason, "access_type", accessType)
}

// runUDMDeregistration is the dispatch; it runs on the UE's serial queue.
func (h *Handler) runUDMDeregistration(ctx context.Context, ue *amfctx.UEContext, reason string, action UDMDeregAction, accessType string) {
	ue.Lock()
	connected := ue.CMState == amfctx.CMConnected
	state := ue.State
	removing := ue.PendingRemoval
	ue.Unlock()
	cm := "CM-IDLE"
	if connected {
		cm = "CM-CONNECTED"
	}
	log := h.udmDeregLogger(ue, reason, accessType).With("cm_state", cm)

	if removing || state == amfctx.GMMDeregistered {
		log.Info("UDM deregistration ignored - UE already being de-registered",
			"interface", "Nudm", "direction", "IN", "result", "OK",
			"spec_ref", "TS 23.502 §4.2.2.3.3 step 1")
		return
	}

	switch {
	case action == UDMDeregEPS:
		// §4.11.1.3.2 step 15 / §4.11.1.5.3 step 13: PCF terminated, SM contexts kept.
		h.implicitUDMTeardown(ctx, ue, log, false, "TS 23.502 §4.11.1.5.3 step 13")
	case !connected:
		h.implicitUDMTeardown(ctx, ue, log, true, "TS 23.502 §4.2.2.3.3 step 2 (implicit)")
	case state == amfctx.GMMDeregisteredInitiated:
		// A network-initiated de-registration is already in flight (e.g. NSSAA #62):
		// let it finish, but without the UECM DELETE; release the sessions now.
		ue.MarkDeregByUDM()
		// rel17: the in-flight request has no T3522 - arm the local-abort guard so the
		// teardown still completes (TS 24.501 §5.5.2.3.5 a)).
		if !h.reg.NSSAASpecLiteral() && !ue.DeregTimerRunning() {
			h.armUDMDeregGuard(ue, &nas.DeregistrationRequestNW{AccessType: procedures.AccessType3GPP})
		}
		h.releaseUDMResources(ctx, ue, log, true)
		log.Info("UDM deregistration joined the de-registration already in progress",
			"interface", "Nudm", "direction", "IN", "result", "OK",
			"spec_ref", "TS 23.502 §4.2.2.3.3 step 2")
	default:
		h.explicitUDMDeregistration(ctx, ue, reason, log)
	}
}

// explicitUDMDeregistration sends the DEREGISTRATION REQUEST to a CM-CONNECTED UE.
// On a send failure it falls back to the implicit teardown plus an N2 release
// attempt (TS 24.501 §5.5.2.3.5 b)). Ref: TS 23.502 §4.2.2.3.3 steps 2-5a
func (h *Handler) explicitUDMDeregistration(ctx context.Context, ue *amfctx.UEContext, reason string, log *slog.Logger) {
	ue.MarkDeregByUDM()
	req := &nas.DeregistrationRequestNW{
		AccessType:             procedures.AccessType3GPP,
		ReregistrationRequired: reason == DeregReasonReregistrationRequired,
	}
	if err := h.sendNetworkDeregistrationReq(ctx, ue, req, "NetworkDeregistration",
		"TS 23.502 §4.2.2.3.3 step 2"); err != nil {
		ue.ClearDeregByUDM()
		log.Warn("DEREGISTRATION REQUEST send failed - implicit de-registration",
			"interface", "N1", "direction", "OUT", "result", "FAILURE", "error", err,
			"spec_ref", "TS 24.501 §5.5.2.3.5 b)")
		metrics.ProcedureTotal.WithLabelValues("AMF", "NetworkDeregistration", "FAILURE").Inc()
		h.implicitUDMTeardown(ctx, ue, log, true, "TS 24.501 §5.5.2.3.5 b)")
		return
	}
	if !h.reg.NSSAASpecLiteral() {
		h.armUDMDeregGuard(ue, req)
	}
	// §5.5.2.3.1: SM release + PCF termination precede the ACCEPT (steps 4, 5, 5a).
	h.releaseUDMResources(ctx, ue, log, true)
	metrics.ProcedureTotal.WithLabelValues("AMF", "NetworkDeregistration", "OK").Inc()
	log.Info("UDM-triggered DEREGISTRATION REQUEST sent - awaiting UE accept",
		"interface", "N1", "direction", "OUT", "result", "OK", "rereg_required", req.ReregistrationRequired,
		"spec_ref", "TS 23.502 §4.2.2.3.3 step 2")
}

// armUDMDeregGuard arms, under the rel17 profile only (no T3522, no
// retransmission: wire identity), one local-abort guard of
// (NWDeregT3522MaxRetransmissions+1) x T3522 for a UDM-triggered de-registration:
// preloading the expiry count makes the single expiry the "fifth" one, i.e. the
// local abort (onDeregT3522Expiry). Ref: TS 24.501 §5.5.2.3.5 a)
func (h *Handler) armUDMDeregGuard(ue *amfctx.UEContext, req *nas.DeregistrationRequestNW) {
	guard := time.Duration(NWDeregT3522MaxRetransmissions+1) * NWDeregT3522Duration
	ue.ArmDeregTimer(req, NWDeregT3522MaxRetransmissions, func(gen uint64) amfctx.TimerStopper {
		return h.scheduleTimer(guard, func() {
			ue.EnqueueSerial(func() { h.onDeregT3522Expiry(ue, gen) })
		})
	})
}

// releaseUDMResources runs steps 3-5a: SDM unsubscribe, SM contexts (releaseSM),
// PCF AM + UE policy. Each is best-effort and idempotent.
func (h *Handler) releaseUDMResources(ctx context.Context, ue *amfctx.UEContext, log *slog.Logger, releaseSM bool) {
	h.reg.UnsubscribeSDMOf(ctx, ue)
	if releaseSM {
		h.releaseSMContexts(ctx, ue, log, "UDM deregistration")
	}
	h.releasePCFAssociations(ctx, ue, log)
}

// implicitUDMTeardown de-registers the UE without NAS: resources released, the
// UE moves to 5GMM-DEREGISTERED and the context is removed. When the UE is
// CM-CONNECTED (any releaseSM value, incl. 5GS to EPS mobility) the N2 release is
// sent so the gNB UE context is not orphaned. No UECM DELETE. Ref: TS 23.502 §4.2.2.3.3 step 2
// ("explicit or implicit"), §4.11.1.5.3 step 13
func (h *Handler) implicitUDMTeardown(ctx context.Context, ue *amfctx.UEContext, log *slog.Logger, releaseSM bool, specRef string) {
	h.releaseUDMResources(ctx, ue, log, releaseSM)
	ue.Lock()
	ue.TransitionToLocked(amfctx.GMMDeregistered)
	connected := ue.CMState == amfctx.CMConnected
	if connected {
		ue.PendingRemoval = true // BEFORE the release command (watchdog), docs CLAUDE.md §9
	}
	ue.Unlock()
	if connected {
		if err := h.sender.SendUEContextReleaseCommandForUE(ue, ngapCausePresentNas, ngapCauseNasDeregister); err != nil {
			log.Warn("UE context release failed on implicit de-registration", "interface", "N2",
				"direction", "OUT", "error", err, "spec_ref", "TS 23.502 §4.2.2.3.3 step 7")
		}
	}
	h.reg.RemoveUEContext(ctx, ue)
	metrics.ProcedureTotal.WithLabelValues("AMF", "NetworkDeregistration", "OK").Inc()
	log.Info("UE de-registered implicitly on UDM request - context removed",
		"interface", "Nudm", "direction", "IN", "result", "OK", "spec_ref", specRef)
}

// releaseSMContexts releases every PDU session's SM context at the SMF (when the
// sender can) and empties the session map. Idempotent.
func (h *Handler) releaseSMContexts(ctx context.Context, ue *amfctx.UEContext, log *slog.Logger, what string) {
	smfDel, canDel := h.sender.(interface {
		DeleteSMContext(ctx context.Context, smContextRef string) error
	})
	ue.Lock()
	sessions := make(map[uint8]*amfctx.PDUSession, len(ue.PDUSessions))
	for k, v := range ue.PDUSessions {
		sessions[k] = v
	}
	ue.Unlock()

	for _, sess := range sessions {
		if sess.SMFInstanceID != "" && canDel {
			if err := smfDel.DeleteSMContext(ctx, sess.SMFInstanceID); err != nil {
				log.Warn("SMF DeleteSMContext failed during "+what,
					"interface", "Nsmf", "direction", "OUT", "spec_ref", "TS 23.502 §4.2.2.3.3 step 4",
					"smContextRef", sess.SMFInstanceID, "error", err)
			}
		}
		ue.Lock()
		delete(ue.PDUSessions, sess.PDUSessionID)
		ue.Unlock()
	}
}

// releasePCFAssociations terminates the AM and UE policy associations at the PCF
// and clears their ids (non-fatal, idempotent). Ref: TS 23.502 §4.2.2.3.2
// steps 6, 6a (reused by §4.2.2.3.3 steps 5, 5a)
func (h *Handler) releasePCFAssociations(ctx context.Context, ue *amfctx.UEContext, log *slog.Logger) {
	ue.Lock()
	amID, polID := ue.AMPolicyAssocID, ue.PolicyAssociationID
	ue.Unlock()
	if amID != "" {
		if err := h.reg.ReleaseAMPolicy(ctx, amID); err != nil {
			log.Warn("PCF AM policy release failed (non-fatal)", "error", err,
				"interface", "Npcf", "direction", "OUT",
				"am_pol_asso_id", amID, "spec_ref", "TS 23.502 §4.2.2.3.3 step 5")
		}
		ue.Lock()
		ue.AMPolicyAssocID = ""
		ue.Unlock()
	}
	if polID != "" {
		if err := h.reg.ReleasePCFPolicy(ctx, polID); err != nil {
			log.Warn("PCF UE policy release failed (non-fatal)", "error", err,
				"interface", "Npcf", "direction", "OUT",
				"pol_asso_id", polID, "spec_ref", "TS 23.502 §4.2.2.3.3 step 5a")
		}
		ue.Lock()
		ue.PolicyAssociationID = ""
		ue.Unlock()
	}
}
