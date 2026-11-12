package procedures

// budget.go - network-side latency budget of the registration procedure
// (AUD-registration-20). The UE runs T3510 from the REGISTRATION REQUEST until
// the REGISTRATION ACCEPT/REJECT (TS 24.501 §10.2 Table 10.2.1, 15 s); the AMF
// must answer before it expires or the UE aborts and retries. Every SBI call of
// the procedure therefore runs under its own context.WithTimeout derived from the
// caller context, and the sum of the sequential steps stays below
// RegistrationNetworkBudget. Table: docs/procedures/initial-registration.md.
//
// The values are project choices (the TS fixes only T3510), not 3GPP timers.

import (
	"context"
	"time"
)

const (
	// T3510 is the UE-side registration supervision timer, 15 s
	// (TS 24.501 §10.2 Table 10.2.1). The AMF never waits that long.
	T3510 = 15 * time.Second

	// RegistrationNetworkBudget is the cap on the sum of the sequential SBI steps
	// of one registration (Phase1 AUSF init + Phase2 AUSF confirm + Phase3), leaving
	// 5 s of T3510 for the radio, the UE and the N1 round trips.
	RegistrationNetworkBudget = 10 * time.Second

	// BudgetAUSFInit bounds Nausf_UEAuthentication_Authenticate (mandatory).
	// Expiry: REGISTRATION REJECT #22 (NFUnavailableRejectCause).
	BudgetAUSFInit = 2 * time.Second
	// BudgetAUSFConfirm bounds the RES* confirmation / AUTS resync (mandatory).
	// Expiry: REGISTRATION REJECT #22.
	BudgetAUSFConfirm = 2 * time.Second
	// BudgetUDMUECM bounds Nudm_UECM_Registration (mandatory, non-emergency).
	// Expiry: REGISTRATION REJECT #22. Emergency: ignored.
	BudgetUDMUECM = 1500 * time.Millisecond
	// BudgetUDMSDMGet bounds Nudm_SDM_Get am-data (mandatory).
	// Expiry: REGISTRATION REJECT #22.
	BudgetUDMSDMGet = 1500 * time.Millisecond
	// BudgetOptionalPeers bounds each of NSSF slice selection, PCF AM policy and
	// PCF UE policy (optional, run in parallel, so the group costs one budget).
	// Expiry: non-fatal, the local fallback / operator default is used.
	BudgetOptionalPeers = 1500 * time.Millisecond
	// BudgetUDMSDMSubscribe bounds Nudm_SDM_Subscribe (optional, non-fatal).
	BudgetUDMSDMSubscribe = 1 * time.Second

	// Phase3Budget caps the whole of Phase3: UECM + SDM get + parallel optional
	// peers + SDM subscribe (1.5 + 1.5 + 1.5 + 1 = 5.5 s worst case, capped).
	Phase3Budget = 5 * time.Second
)

// Budgets holds the per-step timeouts; the zero value of a field means the
// package default. Injectable for tests via WithBudgets.
type Budgets struct {
	AUSFInit, AUSFConfirm, UECM, SDMGet, Optional, SDMSubscribe, Phase3 time.Duration
}

// DefaultBudgets returns the documented budget table.
func DefaultBudgets() Budgets {
	return Budgets{
		AUSFInit: BudgetAUSFInit, AUSFConfirm: BudgetAUSFConfirm, UECM: BudgetUDMUECM,
		SDMGet: BudgetUDMSDMGet, Optional: BudgetOptionalPeers,
		SDMSubscribe: BudgetUDMSDMSubscribe, Phase3: Phase3Budget,
	}
}

// WithBudgets overrides the step budgets (non-zero fields only). Call before serving.
func (h *RegistrationHandler) WithBudgets(b Budgets) {
	d := DefaultBudgets()
	pick := func(v *time.Duration, o time.Duration) {
		if o > 0 {
			*v = o
		}
	}
	pick(&d.AUSFInit, b.AUSFInit)
	pick(&d.AUSFConfirm, b.AUSFConfirm)
	pick(&d.UECM, b.UECM)
	pick(&d.SDMGet, b.SDMGet)
	pick(&d.Optional, b.Optional)
	pick(&d.SDMSubscribe, b.SDMSubscribe)
	pick(&d.Phase3, b.Phase3)
	h.budgets = d
}

// budget returns the effective budgets (defaults when none were set).
func (h *RegistrationHandler) budget() Budgets {
	if h.budgets == (Budgets{}) {
		return DefaultBudgets()
	}
	return h.budgets
}

// stepCtx derives the per-step context from the caller context.
func stepCtx(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}
