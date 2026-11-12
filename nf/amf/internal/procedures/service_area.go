package procedures

import (
	"strconv"
	"strings"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// maxServiceAreaTAs is the maximum number of TAs conveyed in the Service area
// list IE. Ref: TS 24.501 §5.3.5, §9.11.3.49 (up to 16 TAIs).
const maxServiceAreaTAs = 16

// buildServiceAreaList builds the Service area list IE of REGISTRATION ACCEPT
// from the UE's PCF service area restriction. It returns nil (IE absent, legacy
// bytes) when the UE has no restriction.
//
// The network conveys either an allowed area or a non-allowed area, never both
// (TS 24.501 §5.3.5):
//   - NOT_ALLOWED_AREAS with TACs: non-allowed type, type-00 list of those TACs
//     of the serving PLMN;
//   - ALLOWED_AREAS with TACs: allowed type, type-00 list of those TACs;
//   - ALLOWED_AREAS with an EMPTY list (TS 29.571 §5.4.4.18: "allowed nowhere"):
//     an allowed list with zero TAs is not encodable (§9.11.3.49 needs at least
//     one element), so the equivalent non-allowed area is sent: every TA of the
//     registration area (served TACs + the current TA, TAI list of the accept);
//   - absent area list or no TACs: no IE.
//
// More than 16 TAs are truncated (warn). Ref: TS 24.501 §5.3.5, §9.11.3.49;
// TS 23.501 §5.3.4.1
func (h *RegistrationHandler) buildServiceAreaList(ue *amfctx.UEContext) *nas.ServiceAreaList {
	sar, curTAC := ue.ServiceAreaSnapshot()
	if sar == nil {
		return nil
	}
	var (
		tacs       []uint32
		nonAllowed bool
	)
	switch sar.RestrictionType {
	case "NOT_ALLOWED_AREAS":
		tacs, nonAllowed = h.parseTACs(ue, sar.NotAllowedTACs), true
	case "ALLOWED_AREAS":
		switch {
		case sar.AllowedTACs == nil:
			return nil // no area list: unrestricted
		case len(sar.AllowedTACs) == 0:
			tacs, nonAllowed = h.registrationAreaTACs(curTAC), true // allowed nowhere
		default:
			tacs = h.parseTACs(ue, sar.AllowedTACs)
			if len(tacs) == 0 {
				// Every entry malformed: fail restrictive, never open. With some
				// valid entries the IE keeps only those (a subset of what the PCF
				// granted; AllowsTAC compares the same hex strings, so enforcement
				// and IE agree). Warned per entry by parseTACs.
				tacs, nonAllowed = h.registrationAreaTACs(curTAC), true
			}
		}
	default:
		return nil
	}
	if len(tacs) == 0 {
		return nil
	}
	if len(tacs) > maxServiceAreaTAs {
		h.logger.Warn("service area list truncated to 16 TAs",
			"nf", "AMF", "procedure", "InitialRegistration", "interface", "N1", "direction", "OUT",
			"supi", ue.SUPI, "tas", len(tacs), "spec_ref", "TS 24.501 §5.3.5, §9.11.3.49")
		tacs = tacs[:maxServiceAreaTAs]
	}
	return &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{{
		NonAllowed: nonAllowed,
		TypeOfList: nas.ServiceAreaTypeNonConsecutiveTACs,
		MCC:        h.plmnMCC,
		MNC:        h.plmnMNC,
		TACs:       tacs,
	}}}
}

// registrationAreaTACs returns the TACs of the registration area sent in the
// TAI list IE: configured served TACs plus the UE's current TAC (buildTAIList).
func (h *RegistrationHandler) registrationAreaTACs(current uint32) []uint32 {
	tacs := append([]uint32(nil), h.servedTACs...)
	for _, t := range tacs {
		if t == current {
			return tacs
		}
	}
	return append(tacs, current)
}

// parseTACs converts PCF TAC hex strings (6 hex digits, TS 29.571 Tac) to
// 24-bit values. Malformed entries are skipped with a warning; the caller
// decides how to stay restrictive (see buildServiceAreaList).
func (h *RegistrationHandler) parseTACs(ue *amfctx.UEContext, in []string) []uint32 {
	out := make([]uint32, 0, len(in))
	for _, s := range in {
		v, err := strconv.ParseUint(strings.TrimSpace(s), 16, 32)
		if err != nil || v > 0xFFFFFF {
			h.logger.Warn("malformed TAC in PCF service area restriction skipped",
				"nf", "AMF", "procedure", "InitialRegistration", "interface", "N15", "direction", "IN",
				"supi", ue.SUPI, "tac", s, "result", "FAILURE", "spec_ref", "TS 29.571 §5.4.4.18")
			continue
		}
		out = append(out, uint32(v))
	}
	return out
}
