package procedures

// nssai_fallback.go - Allowed NSSAI selection with the default S-NSSAI
// fallback and the rejected NSSAI of a REGISTRATION ACCEPT / REJECT
// (AMF-036).

import (
	"context"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// SpecRefDefaultNSSAIFallback is the clause behind the default S-NSSAI fallback.
const SpecRefDefaultNSSAIFallback = "TS 23.501 §5.15.5.2.1; TS 24.501 §5.5.1.2.4"

// MergeSubscribedNSSAI returns defaults followed by the other single S-NSSAIs,
// de-duplicated on SST+SD (the first entry wins, so a default keeps its flags).
// Ref: TS 29.503 Nssai (defaultSingleNssais M, singleNssais O)
func MergeSubscribedNSSAI(defaults, singles []amfctx.SNSSAISubscribed) []amfctx.SNSSAISubscribed {
	var out []amfctx.SNSSAISubscribed
	for _, l := range [][]amfctx.SNSSAISubscribed{defaults, singles} {
		for _, s := range l {
			if !hasSubscribed(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// selectAllowedNSSAI implements TS 23.501 §5.15.5.2.1 step (A): the requested
// (or NSSF-selected) S-NSSAIs permitted by the subscription; when none was
// requested or none is permitted, the default S-NSSAIs. The bool reports that
// the default fallback was applied. The result is not capped.
func selectAllowedNSSAI(requested, subscribed, defaults []amfctx.SNSSAISubscribed) (allowed []amfctx.SNSSAISubscribed, fallback bool) {
	if len(requested) > 0 {
		allowed = filterAllowedNSSAI(requested, subscribed)
	}
	if len(allowed) == 0 && len(defaults) > 0 {
		return append([]amfctx.SNSSAISubscribed(nil), defaults...), true
	}
	return allowed, false
}

// notAvailableRequested returns the requested S-NSSAIs that are not permitted
// by the subscription (rejected, cause "not available in the current PLMN").
func notAvailableRequested(requested, subscribed []amfctx.SNSSAISubscribed) []amfctx.SNSSAISubscribed {
	var out []amfctx.SNSSAISubscribed
	for _, r := range requested {
		if len(filterAllowedNSSAI([]amfctx.SNSSAISubscribed{r}, subscribed)) == 0 {
			out = append(out, r)
		}
	}
	return out
}

// applyAllowedNSSAISelection sets ue.AllowedNSSAI (default fallback included,
// capped by limitAllowedNSSAI) and ue.NotAvailableNSSAI, and logs the fallback.
func (h *RegistrationHandler) applyAllowedNSSAISelection(ctx context.Context, ue *amfctx.UEContext, base, subscribed, defaults []amfctx.SNSSAISubscribed) {
	allowed, fallback := selectAllowedNSSAI(base, subscribed, defaults)
	ue.NotAvailableNSSAI = nil
	if fallback {
		if len(ue.RequestedNSSAI) > 0 {
			ue.NotAvailableNSSAI = notAvailableRequested(ue.RequestedNSSAI, subscribed)
		}
		h.logger.InfoContext(ctx, "default S-NSSAI fallback applied",
			"procedure", "InitialRegistration", "supi", ue.SUPI,
			"interface", "N1", "direction", "OUT",
			"requested_count", len(ue.RequestedNSSAI), "default_count", len(allowed),
			"rejected_count", len(ue.NotAvailableNSSAI),
			"spec_ref", SpecRefDefaultNSSAIFallback)
	}
	ue.AllowedNSSAI = h.limitAllowedNSSAI(ctx, ue, allowed)
}

// ExtendedRejectedNSSAIForUE builds the Extended rejected NSSAI value of list
// (one type-000 partial list, at most 8 entries): an entry whose requested
// S-NSSAI carried a mapped HPLMN S-NSSAI echoes it, except for the NSSAA
// failed/revoked cause (Table 9.11.3.75.1 NOTE 5/6).
// Ref: TS 24.501 §9.11.3.75, §4.6.1, §5.5.1.2.4
func ExtendedRejectedNSSAIForUE(ue *amfctx.UEContext, list []nas.RejectedSNSSAI) *nas.ExtendedRejectedNSSAI {
	e := nas.ExtendedRejectedNSSAIFromList(list)
	if e == nil {
		return nil
	}
	els := e.Lists[0].Elements
	for i := range els {
		if els[i].Cause == nas.RejectedCauseNSSAAFailedOrRevoked {
			continue
		}
		for _, r := range ue.RequestedNSSAI {
			if r.HasMapped && sameSlice(toNASSNSSAI(r), els[i].SNSSAI) {
				m := nas.SNSSAI{SST: r.MappedSST, SD: nas.SDFromString(r.MappedSD)}
				els[i].Mapped = &m
				break
			}
		}
	}
	return e
}

// setAcceptRejectedNSSAI puts the rejected NSSAI of a REGISTRATION ACCEPT: the
// NSSAA failed/revoked slices (when withNSSAA, cause 2) followed by the
// requested S-NSSAIs rejected as not available (default fallback, cause 0), at
// most nas.MaxRejectedSNSSAIs. With the UE's ER-NSSAI capability under rel19 it
// goes into the Extended rejected NSSAI IE (0x68), else the Rejected NSSAI IE.
// Reports whether an IE was set. Ref: TS 24.501 §5.5.1.2.4, §9.11.3.46, §9.11.3.75
func (h *RegistrationHandler) setAcceptRejectedNSSAI(ra *nas.RegistrationAccept, ue *amfctx.UEContext, withNSSAA bool) bool {
	var list []nas.RejectedSNSSAI
	complete := true
	if withNSSAA {
		list, complete = NASRejectedNSSAI(ue.RejectedNSSAI)
	}
	for _, s := range ue.NotAvailableNSSAI {
		if hasSubscribed(ue.RejectedNSSAI, s) {
			continue
		}
		if len(list) == nas.MaxRejectedSNSSAIs {
			complete = false
			break
		}
		list = append(list, nas.RejectedSNSSAI{Cause: nas.RejectedCauseNotAvailableInPLMN, SNSSAI: toNASSNSSAI(s)})
	}
	if len(list) == 0 {
		return false
	}
	set := false
	if h.UseExtendedRejectedNSSAI(ue) {
		ra.ExtendedRejectedNSSAI = ExtendedRejectedNSSAIForUE(ue, list)
		set = true
	} else if v, err := nas.RejectedNSSAIValue(list); err == nil {
		ra.RejectedNSSAI = v
		set = true
	}
	if !complete {
		h.logger.Warn("Rejected NSSAI truncated to the IE maximum",
			"procedure", "InitialRegistration", "supi", ue.SUPI, "max", nas.MaxRejectedSNSSAIs,
			"spec_ref", "TS 24.501 §9.11.3.46")
	}
	return set
}

// applyDefaultNSSAISelection is the NSSF branch for a UE that sent no Requested
// NSSAI: the Allowed NSSAI is the default S-NSSAIs, restricted to the NSSF result
// when that intersection is not empty, else the plain defaults. It is always the
// default-fallback case (logged). Ref: TS 23.501 §5.15.5.2.1 (B)
func (h *RegistrationHandler) applyDefaultNSSAISelection(ctx context.Context, ue *amfctx.UEContext, nssfAllowed, defaults []amfctx.SNSSAISubscribed) {
	allowed := filterAllowedNSSAI(nssfAllowed, defaults)
	if len(allowed) == 0 {
		allowed = append([]amfctx.SNSSAISubscribed(nil), defaults...)
	}
	ue.NotAvailableNSSAI = nil
	if len(allowed) > 0 {
		h.logger.InfoContext(ctx, "default S-NSSAI fallback applied",
			"procedure", "InitialRegistration", "supi", ue.SUPI,
			"interface", "N1", "direction", "OUT",
			"requested_count", 0, "default_count", len(allowed),
			"rejected_count", 0, "spec_ref", SpecRefDefaultNSSAIFallback)
	}
	ue.AllowedNSSAI = h.limitAllowedNSSAI(ctx, ue, allowed)
}

// ueSupportsNSSAA reports the UE's NSSAA capability (5GMM capability octet 4
// bit 5); an absent capability IE means not supported. Ref: TS 24.501 §9.11.3.1
func ueSupportsNSSAA(ue *amfctx.UEContext) bool {
	return ue.Capability5GMM != nil && ue.Capability5GMM.NSSAA
}

// restrictNSSAAForUnsupportedUE handles a UE that did not indicate NSSAA
// support (only when NSSAA is configured): S-NSSAIs subject to NSSAA are removed
// from the Allowed NSSAI (the requested ones become rejected "not available in
// the current PLMN"), NSSAA is not triggered, and if the Allowed NSSAI is then
// empty the default S-NSSAIs not subject to NSSAA apply (fallback). An empty
// result leads to REGISTRATION REJECT #62 in the caller. Reports whether the
// UE is such a UE. Ref: TS 23.501 §5.15.10; TS 24.501 §5.5.1.2.4, §5.5.1.2.5 b) 2)
func (h *RegistrationHandler) restrictNSSAAForUnsupportedUE(ctx context.Context, ue *amfctx.UEContext) bool {
	if h.nssaa == nil || ueSupportsNSSAA(ue) {
		return false
	}
	ue.PendingNSSAA = nil
	var kept []amfctx.SNSSAISubscribed
	removed := false
	for _, s := range ue.AllowedNSSAI {
		if s.SubjectToNSSAA {
			removed = true
			continue
		}
		kept = append(kept, s)
	}
	for _, r := range ue.RequestedNSSAI {
		for _, sub := range ue.SubscribedNSSAI {
			if sub.SubjectToNSSAA && sameSlice(toNASSNSSAI(sub), toNASSNSSAI(r)) &&
				!hasSubscribed(ue.NotAvailableNSSAI, r) {
				ue.NotAvailableNSSAI = append(ue.NotAvailableNSSAI, r)
			}
		}
	}
	if len(kept) == 0 {
		for _, d := range ue.DefaultNSSAI {
			if !d.SubjectToNSSAA {
				kept = append(kept, d)
			}
		}
		if len(kept) > 0 {
			h.logger.InfoContext(ctx, "default S-NSSAI fallback applied",
				"procedure", "InitialRegistration", "supi", ue.SUPI,
				"interface", "N1", "direction", "OUT",
				"requested_count", len(ue.RequestedNSSAI), "default_count", len(kept),
				"rejected_count", len(ue.NotAvailableNSSAI),
				"spec_ref", SpecRefDefaultNSSAIFallback)
		}
	}
	if removed || len(kept) == 0 {
		h.logger.InfoContext(ctx, "UE does not support NSSAA: NSSAA-subject S-NSSAIs not allowed",
			"procedure", "InitialRegistration", "interface", "N1", "direction", "OUT",
			"supi", ue.SUPI, "allowed_count", len(kept),
			"spec_ref", "TS 23.501 §5.15.10; TS 24.501 §5.5.1.2.5 b) 2)")
	}
	ue.AllowedNSSAI = h.limitAllowedNSSAI(ctx, ue, kept)
	return true
}
