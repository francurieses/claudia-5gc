package procedures

import (
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func sarHandler() *RegistrationHandler {
	return &RegistrationHandler{plmnMCC: "001", plmnMNC: "01", servedTACs: []uint32{1, 2}, logger: slog.Default()}
}

func TestBuildServiceAreaList(t *testing.T) {
	h := sarHandler()
	many := make([]string, 20)
	for i := range many {
		many[i] = "0000" + string(rune('a'+i%6)) + "0"
	}
	for _, tc := range []struct {
		name       string
		sar        *amfctx.ServiceAreaRestriction
		wantNil    bool
		nonAllowed bool
		tacs       []uint32
	}{
		{"no SAR", nil, true, false, nil},
		{"allowed", &amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS", AllowedTACs: []string{"000001", "00000A"}}, false, false, []uint32{1, 10}},
		{"non-allowed", &amfctx.ServiceAreaRestriction{RestrictionType: "NOT_ALLOWED_AREAS", NotAllowedTACs: []string{"000005"}}, false, true, []uint32{5}},
		{"allowed absent list", &amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS"}, true, false, nil},
		{"allowed nowhere -> registration area non-allowed", &amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS", AllowedTACs: []string{}}, false, true, []uint32{1, 2, 7}},
		{"allowed all malformed -> restrictive", &amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS", AllowedTACs: []string{"zzzzzz", "1000000"}}, false, true, []uint32{1, 2, 7}},
		{"allowed some malformed -> valid entries only", &amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS", AllowedTACs: []string{"nothex", "000003"}}, false, false, []uint32{3}},
		{"truncated to 16", &amfctx.ServiceAreaRestriction{RestrictionType: "NOT_ALLOWED_AREAS", NotAllowedTACs: many}, false, true, nil},
	} {
		ue := &amfctx.UEContext{ServAreaRes: tc.sar}
		ue.TAI.TAC = 7
		got := h.buildServiceAreaList(ue)
		if tc.wantNil {
			if got != nil {
				t.Errorf("%s: got %+v want nil", tc.name, got)
			}
			continue
		}
		if got == nil || len(got.Partial) != 1 {
			t.Fatalf("%s: got %+v", tc.name, got)
		}
		p := got.Partial[0]
		if p.NonAllowed != tc.nonAllowed || p.MCC != "001" || p.MNC != "01" || p.TypeOfList != nas.ServiceAreaTypeNonConsecutiveTACs {
			t.Errorf("%s: partial %+v", tc.name, p)
		}
		if tc.tacs != nil && !equalU32(p.TACs, tc.tacs) {
			t.Errorf("%s: TACs %v want %v", tc.name, p.TACs, tc.tacs)
		}
		if tc.name == "truncated to 16" && len(p.TACs) != 16 {
			t.Errorf("%s: %d TACs, want 16", tc.name, len(p.TACs))
		}
		if _, err := nas.EncodeServiceAreaListValue(got); err != nil {
			t.Errorf("%s: not encodable: %v", tc.name, err)
		}
	}
}

// TestRegistrationAcceptWithoutSARHasNoServiceAreaList guards the legacy bytes:
// without a service area restriction the IE (0x27) is absent.
func TestRegistrationAcceptWithoutSARHasNoServiceAreaList(t *testing.T) {
	ra := &nas.RegistrationAccept{RegistrationResult: 1, ServiceAreaList: sarHandler().buildServiceAreaList(&amfctx.UEContext{})}
	if ra.ServiceAreaList != nil {
		t.Fatal("ServiceAreaList must stay nil without SAR")
	}
	b, err := nas.EncodeRegistrationAccept(ra)
	if err != nil {
		t.Fatal(err)
	}
	with := &nas.RegistrationAccept{RegistrationResult: 1, ServiceAreaList: &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{{
		TypeOfList: nas.ServiceAreaTypeNonConsecutiveTACs, MCC: "001", MNC: "01", TACs: []uint32{1}}}}}
	b2, err := nas.EncodeRegistrationAccept(with)
	if err != nil {
		t.Fatal(err)
	}
	if len(b2) <= len(b) {
		t.Fatal("IE not added when present")
	}
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
