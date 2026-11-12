package sbi

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
)

// testSNSSAIs are the S-NSSAIs of the pre-change registration golden.
var testSNSSAIs = []nrf.SNSSAIEntry{{SST: 1, SD: "000001"}, {SST: 2, SD: "000002"}}

func profileNamed(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCatalogOffersNothing: the NSSF implements no optional Nnssf_NSSelection
// feature, so it offers "0" under both profiles.
func TestCatalogOffersNothing(t *testing.T) {
	for _, name := range []string{"rel17", "rel19"} {
		if got := NnssfNSSelectionCatalog().Supported(profileNamed(t, name)); !got.IsEmpty() {
			t.Errorf("%s: offers %q", name, got)
		}
	}
	if n := len(NnssfNSSelectionCatalog().Entries()); n != 4 {
		t.Errorf("catalog has %d entries, want 4", n)
	}
	if e, ok := NnssfNSSelectionCatalog().Lookup(4); !ok || e.Name != "SIOP" || e.Implemented {
		t.Errorf("entry 4 = %+v", e)
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
		got, err := json.Marshal(BuildNFProfile(id, testSNSSAIs, p, NnssfNSSelectionCatalog()))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("rel17 NF profile changed\n got: %s\nwant: %s", got, want)
		}
	}
	got, _ := json.Marshal(BuildNFProfile(id, testSNSSAIs, profileNamed(t, "rel19"), NnssfNSSelectionCatalog()))
	if !strings.Contains(string(got), `"supportedFeatures":"0"`) {
		t.Errorf("rel19 profile lacks per-service supportedFeatures: %s", got)
	}
}
