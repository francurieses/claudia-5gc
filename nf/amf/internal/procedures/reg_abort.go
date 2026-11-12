package procedures

import (
	"context"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

// regAbortCleanupTimeout bounds the best-effort PCF / UDM cleanup of an aborted
// registration (AMF-034). It is an implementation bound, not a 3GPP timer.
const regAbortCleanupTimeout = 10 * time.Second

// ReleaseUERegistration releases the UDM registration (Nudm_UECM deregistration;
// DeregisterUECM also deletes the SDM subscription while the UE is still in the
// manager, so call it before the context is removed) and the PCF AM / UE policy
// associations of a UE whose context is removed without a UE-initiated
// de-registration (initial registration rolled back after an Initial Context Setup
// failure). The same steps, in the same order, as the UE-initiated
// de-registration; every failure is logged and does not stop the cleanup.
// Detached from ctx cancellation and bounded by regAbortCleanupTimeout. The
// lifecycle / registration timers are stopped by Manager.Remove, not here.
// procedure is the log procedure name of the caller.
// Ref: TS 23.502 §4.2.2.3.2 step 3, TS 29.503 §5.3.2.4, TS 29.507 §4.2.5
func (h *RegistrationHandler) ReleaseUERegistration(ctx context.Context, ue *amfctx.UEContext, procedure string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), regAbortCleanupTimeout)
	defer cancel()
	log := h.logger.With(
		"nf", "AMF",
		"procedure", procedure,
		"correlation_id", logging.CorrelationID(ctx),
		"supi", ue.SUPI,
		"spec_ref", "TS 23.502 §4.2.2.3.2 step 3",
	)
	ue.Lock()
	supi, amPol, uePol := ue.SUPI, ue.AMPolicyAssocID, ue.PolicyAssociationID
	ue.AMPolicyAssocID, ue.PolicyAssociationID = "", ""
	ue.Unlock()

	if supi != "" {
		if err := h.DeregisterUECM(rctx, supi); err != nil {
			log.Warn("UDM UECM deregistration failed (non-fatal)", "interface", "Nudm", "direction", "OUT", "result", "FAILURE", "error", err)
		}
	}
	if amPol != "" {
		if err := h.ReleaseAMPolicy(rctx, amPol); err != nil {
			log.Warn("PCF AM policy release failed (non-fatal)", "interface", "Npcf", "direction", "OUT", "result", "FAILURE", "error", err, "am_pol_asso_id", amPol)
		}
	}
	if uePol != "" {
		if err := h.ReleasePCFPolicy(rctx, uePol); err != nil {
			log.Warn("PCF UE policy release failed (non-fatal)", "interface", "Npcf", "direction", "OUT", "result", "FAILURE", "error", err, "pol_asso_id", uePol)
		}
	}
}
