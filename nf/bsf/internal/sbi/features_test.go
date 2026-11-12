package sbi

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func profileNamed(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCatalogOffersNothing: the BSF implements no optional Nbsf_Management
// feature, so it offers "0" under both profiles.
func TestCatalogOffersNothing(t *testing.T) {
	for _, name := range []string{"rel17", "rel19"} {
		if got := NbsfManagementCatalog().Supported(profileNamed(t, name)); !got.IsEmpty() {
			t.Errorf("%s: offers %q", name, got)
		}
	}
	if n := len(NbsfManagementCatalog().Entries()); n != 8 {
		t.Errorf("catalog has %d entries, want 8", n)
	}
	if e, ok := NbsfManagementCatalog().Lookup(8); !ok || e.Name != "ExpTime" || e.Implemented {
		t.Errorf("entry 8 = %+v", e)
	}
}

// TestGolden_NFProfile pins the rel17 / nil-profile NFRegister body bytes
// (captured from the pre-REL19-2.7 code) and checks that only rel19 adds the
// per-service supportedFeatures.
func TestGolden_NFProfile(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	want, err := os.ReadFile("testdata/golden_nf_profile.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*capability.Profile{nil, profileNamed(t, "rel17")} {
		got, err := json.Marshal(BuildNFProfile(id, p, NbsfManagementCatalog()))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("rel17 NF profile changed\n got: %s\nwant: %s", got, want)
		}
	}
	got, _ := json.Marshal(BuildNFProfile(id, profileNamed(t, "rel19"), NbsfManagementCatalog()))
	if !strings.Contains(string(got), `"supportedFeatures":"0"`) {
		t.Errorf("rel19 profile lacks per-service supportedFeatures: %s", got)
	}
}
