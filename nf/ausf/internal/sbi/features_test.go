package sbi

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
)

func profileNamed(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCatalogsOfferNothing: the AUSF implements no optional Nausf/Nudm_UEAU
// feature (ES3XX is a consumer obligation, SUBDMIG is not implemented).
func TestCatalogsOfferNothing(t *testing.T) {
	for _, name := range []string{"rel17", "rel19"} {
		p := profileNamed(t, name)
		if got := NausfUEAuthenticationCatalog().Supported(p); !got.IsEmpty() {
			t.Errorf("%s: Nausf offers %q", name, got)
		}
		if got := NudmUEAUCatalog().Supported(p); !got.IsEmpty() {
			t.Errorf("%s: Nudm_UEAU offers %q", name, got)
		}
	}
	if e, ok := NausfUEAuthenticationCatalog().Lookup(1); !ok || e.Name != "ES3XX" || !e.Mandatory {
		t.Errorf("Nausf entry 1 = %+v", e)
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
		got, err := json.Marshal(BuildNFProfile(id, p, NausfUEAuthenticationCatalog()))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("rel17 NF profile changed\n got: %s\nwant: %s", got, want)
		}
	}
	got, _ := json.Marshal(BuildNFProfile(id, profileNamed(t, "rel19"), NausfUEAuthenticationCatalog()))
	if !strings.Contains(string(got), `"supportedFeatures":"0"`) {
		t.Errorf("rel19 profile lacks per-service supportedFeatures: %s", got)
	}
}

// TestNFProfileFQDNIdentity: fqdn unset leaves the profile byte-identical;
// set adds fqdn, ipEndPoints port and plmnList.
func TestNFProfileFQDNIdentity(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	p := profileNamed(t, "rel19")
	base, _ := json.Marshal(BuildNFProfile(id, p, NausfUEAuthenticationCatalog()))
	unset := BuildNFProfile(id, p, NausfUEAuthenticationCatalog())
	if err := nrf.ApplyFQDNIdentity(unset, "", "0.0.0.0:8002", "001", "02"); err != nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(unset); string(got) != string(base) {
		t.Fatalf("unset fqdn changed profile: %s", got)
	}
	set := BuildNFProfile(id, p, NausfUEAuthenticationCatalog())
	if err := nrf.ApplyFQDNIdentity(set, "ausf.5gc.mnc002.mcc001.3gppnetwork.org", "0.0.0.0:8002", "001", "02"); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(set)
	for _, w := range []string{`"fqdn":"ausf.5gc.mnc002.mcc001.3gppnetwork.org"`, `"port":8002`, `"plmnList":[{"mcc":"001","mnc":"02"}]`} {
		if !strings.Contains(string(got), w) {
			t.Errorf("profile lacks %s: %s", w, got)
		}
	}
}
