package sbi

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// testFQDN is the FQDN of the pre-change registration golden.
const testFQDN = "lmf.5gc.mnc001.mcc001.3gppnetwork.org"

func profileNamed(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCatalogOffersNothing: the LMF implements no optional Nlmf_Location
// feature, so it offers "0" under both profiles.
func TestCatalogOffersNothing(t *testing.T) {
	for _, name := range []string{"rel17", "rel19"} {
		if got := NlmfLocationCatalog().Supported(profileNamed(t, name)); !got.IsEmpty() {
			t.Errorf("%s: offers %q", name, got)
		}
	}
	if n := len(NlmfLocationCatalog().Entries()); n != 9 {
		t.Errorf("catalog has %d entries, want 9", n)
	}
	if e, ok := NlmfLocationCatalog().Lookup(9); !ok || e.Name != "MWAB" || e.Implemented {
		t.Errorf("entry 9 = %+v", e)
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
		got, err := json.Marshal(BuildNFProfile(id, testFQDN, p, NlmfLocationCatalog()))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("rel17 NF profile changed\n got: %s\nwant: %s", got, want)
		}
	}
	got, _ := json.Marshal(BuildNFProfile(id, testFQDN, profileNamed(t, "rel19"), NlmfLocationCatalog()))
	if !strings.Contains(string(got), `"supportedFeatures":"0"`) {
		t.Errorf("rel19 profile lacks per-service supportedFeatures: %s", got)
	}
}
