package procedures

// reg_update.go - re-evaluation of the Allowed NSSAI for a registration update
// (AUD-registration-12).

import (
	"context"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// ReevaluateAllowedNSSAI recomputes the Allowed NSSAI of a registered UE from the
// Requested NSSAI of a mobility / periodic REGISTRATION REQUEST (ue.RequestedNSSAI)
// and the subscribed S-NSSAIs kept from the last registration. With no known
// subscription the Allowed NSSAI is left unchanged; an empty intersection falls
// back to the default S-NSSAIs, else it is left unchanged (a registration update
// must not drop all slices of an established UE).
// Ref: TS 24.501 §5.5.1.3.2, §5.5.1.3.4; TS 23.502 §4.2.2.2.3
func (h *RegistrationHandler) ReevaluateAllowedNSSAI(ctx context.Context, ue *amfctx.UEContext) {
	if len(ue.RequestedNSSAI) == 0 || len(ue.SubscribedNSSAI) == 0 {
		return
	}
	allowed := h.withoutUnauthorizedNSSAA(ctx, ue, filterAllowedNSSAI(ue.RequestedNSSAI, ue.SubscribedNSSAI))
	// The rejected requested S-NSSAIs of an earlier registration must not leak
	// into this Accept: recompute them for this Requested NSSAI only.
	ue.NotAvailableNSSAI = nil
	if len(allowed) == 0 {
		// None permitted: the default S-NSSAIs (TS 24.501 §5.5.1.3.4, TS 23.501
		// §5.15.5.2.1); without defaults the Allowed NSSAI stays unchanged.
		allowed = h.withoutUnauthorizedNSSAA(ctx, ue, ue.DefaultNSSAI)
		if len(allowed) == 0 {
			return
		}
		ue.NotAvailableNSSAI = notAvailableRequested(ue.RequestedNSSAI, ue.SubscribedNSSAI)
		h.logger.InfoContext(ctx, "default S-NSSAI fallback applied",
			"procedure", "MobilityRegistrationUpdate", "supi", ue.SUPI,
			"interface", "N1", "direction", "OUT", "default_count", len(allowed),
			"spec_ref", SpecRefDefaultNSSAIFallback)
	}
	ue.AllowedNSSAI = h.limitAllowedNSSAI(ctx, ue, allowed)
}

// withoutUnauthorizedNSSAA drops from list the S-NSSAIs that a registration
// update may not allow: those whose NSSAA failed or was revoked
// (ue.RejectedNSSAI) and, when NSSAA is configured, those subject to NSSAA that
// are not already in the current Allowed NSSAI (not yet authorized). No NSSAA
// is started from the update path; the dropped slices are logged.
// Ref: TS 24.501 §5.5.1.3.4; TS 23.502 §4.2.9.2
func (h *RegistrationHandler) withoutUnauthorizedNSSAA(ctx context.Context, ue *amfctx.UEContext, list []amfctx.SNSSAISubscribed) []amfctx.SNSSAISubscribed {
	var out []amfctx.SNSSAISubscribed
	for _, s := range list {
		switch {
		case hasSubscribed(ue.RejectedNSSAI, s):
			h.logger.InfoContext(ctx, "S-NSSAI left out of the Allowed NSSAI: NSSAA failed or revoked",
				"procedure", "MobilityRegistrationUpdate", "supi", ue.SUPI,
				"sst", s.SST, "sd", s.SD, "spec_ref", "TS 24.501 §5.5.1.3.4")
		case h.nssaa != nil && s.SubjectToNSSAA && !hasSubscribed(ue.AllowedNSSAI, s):
			h.logger.InfoContext(ctx, "S-NSSAI left out of the Allowed NSSAI: NSSAA not yet successful",
				"procedure", "MobilityRegistrationUpdate", "supi", ue.SUPI,
				"sst", s.SST, "sd", s.SD, "spec_ref", "TS 24.501 §5.5.1.3.4")
		default:
			out = append(out, s)
		}
	}
	return out
}
