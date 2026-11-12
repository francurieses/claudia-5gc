package sbi

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func profileNamed(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCatalogsOfferNothing: the PCF implements no optional feature of its
// producer APIs, so it offers "0" under both profiles, except
// Npcf_PolicyAuthorization feature 17 AuthorizationWithRequiredQoS (bit 16,
// 0x10000; TS 29.514 §5.8).
func TestCatalogsOfferNothing(t *testing.T) {
	tests := []struct {
		name  string
		cat   *features.Catalog
		count int
	}{
		{"Npcf_SMPolicyControl", NpcfSMPolicyControlCatalog(), 119},
		{"Npcf_AMPolicyControl", NpcfAMPolicyControlCatalog(), 24},
		{"Npcf_UEPolicyControl", NpcfUEPolicyControlCatalog(), 28},
		{"Npcf_PolicyAuthorization", NpcfPolicyAuthorizationCatalog(), 83},
	}
	for _, tc := range tests {
		for _, prof := range []string{"rel17", "rel19"} {
			want := ""
			if tc.name == "Npcf_PolicyAuthorization" {
				want = "10000"
			}
			got := tc.cat.Supported(profileNamed(t, prof))
			if (want == "" && !got.IsEmpty()) || (want != "" && got.String() != want) {
				t.Errorf("%s/%s: offers %q, want %q", tc.name, prof, got, want)
			}
		}
		if n := len(tc.cat.Entries()); n != tc.count {
			t.Errorf("%s: %d entries, want %d", tc.name, n, tc.count)
		}
		for _, e := range tc.cat.Entries() {
			if e.Implemented && (tc.name != "Npcf_PolicyAuthorization" || e.Number != 17) {
				t.Errorf("%s: feature %d %s implemented", tc.name, e.Number, e.Name)
			}
		}
	}
}

// TestGolden_NFProfile pins the rel17 / nil-profile NFRegister body bytes
// (captured from the inline literal of cmd/pcf/main.go at the pre-REL19-2.7
// HEAD) and checks that only rel19 adds the per-service supportedFeatures.
func TestGolden_NFProfile(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	want, err := os.ReadFile("testdata/golden_nf_profile.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*capability.Profile{nil, profileNamed(t, "rel17")} {
		got, err := json.Marshal(BuildNFProfile(id, p, NpcfSMPolicyControlCatalog(), NpcfUEPolicyControlCatalog(), NpcfAMPolicyControlCatalog(), NpcfPolicyAuthorizationCatalog()))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("rel17 NF profile changed\n got: %s\nwant: %s", got, want)
		}
	}
	got, _ := json.Marshal(BuildNFProfile(id, profileNamed(t, "rel19"), NpcfSMPolicyControlCatalog(), NpcfUEPolicyControlCatalog(), NpcfAMPolicyControlCatalog(), NpcfPolicyAuthorizationCatalog()))
	if n := strings.Count(string(got), `"supportedFeatures":"0"`); n != 3 {
		t.Errorf("rel19 profile: %d per-service supportedFeatures \"0\", want 3: %s", n, got)
	}
	if !strings.Contains(string(got), `"supportedFeatures":"10000"`) {
		t.Errorf("rel19 profile: npcf-policyauthorization must offer 10000: %s", got)
	}
}

// TestNFProfile_AllFourServices asserts the four Npcf services are registered
// under both release profiles. Ref: TS 29.510 §6.1.6.2.3.
func TestNFProfile_AllFourServices(t *testing.T) {
	want := []string{"npcf-smpolicycontrol", "npcf-ue-policy-control", "npcf-am-policy-control", "npcf-policyauthorization"}
	for _, name := range []string{"rel17", "rel19"} {
		prof := BuildNFProfile("id", profileNamed(t, name), NpcfSMPolicyControlCatalog(), NpcfUEPolicyControlCatalog(), NpcfAMPolicyControlCatalog(), NpcfPolicyAuthorizationCatalog())
		got := map[string]bool{}
		for _, svc := range prof.NFServices {
			got[svc.ServiceName] = true
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("%s: service %s missing from NF profile", name, w)
			}
		}
		if len(prof.NFServices) != len(want) {
			t.Errorf("%s: %d services, want %d", name, len(prof.NFServices), len(want))
		}
	}
}
