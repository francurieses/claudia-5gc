package procedures

import (
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// TestIsAllowedTAUnknownRestrictionType checks an unknown
// ServiceAreaRestriction.restrictionType value is ignored (treated as absent,
// i.e. unrestricted) rather than rejecting the UE (TS 29.500 §6.6.2,
// TS 29.571 §5.3.12 style anyOf[enum,string]).
func TestIsAllowedTAUnknownRestrictionType(t *testing.T) {
	h := &RegistrationHandler{}
	tests := []struct {
		name string
		sar  amfctx.ServiceAreaRestriction
		tac  uint32
		want bool
	}{
		{"unknown type, allowed list ignored", amfctx.ServiceAreaRestriction{RestrictionType: "FUTURE_AREAS", AllowedTACs: []string{"000002"}}, 1, true},
		{"unknown type, not-allowed list ignored", amfctx.ServiceAreaRestriction{RestrictionType: "FUTURE_AREAS", NotAllowedTACs: []string{"000001"}}, 1, true},
		{"known ALLOWED_AREAS unchanged", amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS", AllowedTACs: []string{"000002"}}, 1, false},
		{"known NOT_ALLOWED_AREAS unchanged", amfctx.ServiceAreaRestriction{RestrictionType: "NOT_ALLOWED_AREAS", NotAllowedTACs: []string{"000001"}}, 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.isAllowedTA(tc.tac, &tc.sar); got != tc.want {
				t.Fatalf("isAllowedTA = %v, want %v", got, tc.want)
			}
		})
	}
}
