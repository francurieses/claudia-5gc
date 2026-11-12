package sbi

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
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

// TestCatalogOffersNothing: the NEF implements no optional AsSessionWithQoS
// feature, so it offers "0" under both profiles.
func TestCatalogOffersNothing(t *testing.T) {
	for _, name := range []string{"rel17", "rel19"} {
		if got := AsSessionWithQoSCatalog().Supported(profileNamed(t, name)); !got.IsEmpty() {
			t.Errorf("%s: offers %q", name, got)
		}
	}
	if n := len(AsSessionWithQoSCatalog().Entries()); n != 38 {
		t.Errorf("entries=%d want 38", n)
	}
}

// TestGolden_NFProfile pins the rel17 / nil-profile NFRegister body bytes
// (captured from the pre-REL19-2.7 code) and checks that rel19 is identical
// (the NEF never registers per-service supportedFeatures).
func TestGolden_NFProfile(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	const fqdn = "nef.5gc.test"
	want, err := os.ReadFile("testdata/golden_nf_profile.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*capability.Profile{nil, profileNamed(t, "rel17")} {
		got, err := json.Marshal(BuildNFProfile(id, fqdn, p, AsSessionWithQoSCatalog()))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("rel17 NF profile changed\n got: %s\nwant: %s", got, want)
		}
	}
	// TS 29.122 §5.2.7 / TS 29.522 §5.2: no features registered for northbound
	// APIs; rel19 differs from rel17 only in apiFullVersion (NRF-VER-001).
	want19 := strings.Replace(string(want), `"apiFullVersion":"1.2.3"`, `"apiFullVersion":"`+apiversion.Of(profileNamed(t, "rel19"), apiversion.AsSessionWithQoS).Full+`"`, 1)
	got, _ := json.Marshal(BuildNFProfile(id, fqdn, profileNamed(t, "rel19"), AsSessionWithQoSCatalog()))
	if string(got) != want19 || want19 == string(want) || strings.Contains(string(got), "supportedFeatures") {
		t.Errorf("rel19 NF profile must equal the rel17 bytes except apiFullVersion: %s", got)
	}
}

// TestConsumerCatalogsMarkOnlyES3XX: the Npcf_PolicyAuthorization consumer
// catalog implements ES3XX (26, bit 25) and AuthorizationWithRequiredQoS (17,
// bit 16) = 0x2010000; Nbsf_Management (4) implements exactly ES3XX.
func TestConsumerCatalogsMarkOnlyES3XX(t *testing.T) {
	for _, tc := range []struct {
		name string
		cat  *features.Catalog
		want string
	}{
		{"Npcf_PolicyAuthorization", NpcfPolicyAuthorizationCatalog(), "2010000"},
		{"Nbsf_Management", NbsfManagementCatalog(), "8"},
	} {
		p, err := capability.NewProfile(capability.ReleaseConfig{Profile: "rel19"}, func(string) string { return "" })
		if err != nil {
			t.Fatal(err)
		}
		if got := tc.cat.Supported(p).String(); got != tc.want {
			t.Errorf("%s rel19 = %q, want %q", tc.name, got, tc.want)
		}
	}
}
