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
// subscription, or an empty intersection, the Allowed NSSAI is left unchanged (a
// registration update must not drop all slices of an established UE).
// Ref: TS 24.501 §5.5.1.3.2, §5.5.1.3.4; TS 23.502 §4.2.2.2.3
func (h *RegistrationHandler) ReevaluateAllowedNSSAI(ctx context.Context, ue *amfctx.UEContext) {
	if len(ue.RequestedNSSAI) == 0 || len(ue.SubscribedNSSAI) == 0 {
		return
	}
	allowed := filterAllowedNSSAI(ue.RequestedNSSAI, ue.SubscribedNSSAI)
	if len(allowed) == 0 {
		return
	}
	ue.AllowedNSSAI = h.limitAllowedNSSAI(ctx, ue, allowed)
}
