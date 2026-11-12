package sbi

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

const testID = "00000000-0000-4008-8000-000000000001"

func profileNamed(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCatalogOffersNothing: the UDR claims no optional Nudr_DataRepository
// feature, so it offers "0" under both profiles.
func TestCatalogOffersNothing(t *testing.T) {
	for _, name := range []string{"rel17", "rel19"} {
		if got := NudrDataRepositoryCatalog().Supported(profileNamed(t, name)); !got.IsEmpty() {
			t.Errorf("%s: offers %q", name, got)
		}
	}
	if n := len(NudrDataRepositoryCatalog().Entries()); n != 78 {
		t.Errorf("catalog has %d entries, want 78", n)
	}
	if e, ok := NudrDataRepositoryCatalog().Lookup(9); !ok || e.Name != "SessionManagementPolicyDataPatch" || e.Implemented {
		t.Errorf("entry 9 = %+v", e)
	}
}

// TestGolden_NFProfile pins the rel17 / nil-profile NFRegister body bytes
// (captured from the pre-REL19-2.7 inline literal of cmd/udr/main.go) and
// checks that only rel19 adds the per-service supportedFeatures.
func TestGolden_NFProfile(t *testing.T) {
	want, err := os.ReadFile("testdata/golden_nf_profile.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*capability.Profile{nil, profileNamed(t, "rel17")} {
		got, err := json.Marshal(BuildNFProfile(testID, p, NudrDataRepositoryCatalog()))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("rel17 NF profile changed\n got: %s\nwant: %s", got, want)
		}
	}
	got, _ := json.Marshal(BuildNFProfile(testID, profileNamed(t, "rel19"), NudrDataRepositoryCatalog()))
	if !strings.Contains(string(got), `"supportedFeatures":"0"`) {
		t.Errorf("rel19 profile lacks per-service supportedFeatures: %s", got)
	}
}
