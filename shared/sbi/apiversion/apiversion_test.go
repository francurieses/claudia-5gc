package apiversion

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

var semver = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

var allConstants = []Service{
	NamfComm, NausfAuth, NbsfManagement, NlmfLoc, AsSessionWithQoS, NnssfNSSelection,
	NpcfAMPolicyControl, NpcfSMPolicyControl, NpcfUEPolicyControl, NpcfPolicyAuth,
	NsmfPDUSession, NsmsfSMS, NudmUEAU, NudmSDM, NudmUECM, NudrDR,
	NnrfNFManagement, NnrfNFDiscovery, N32cHandshake,
}

func profile(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("NewProfile(%q): %v", name, err)
	}
	return p
}

func cmp(t *testing.T, a, b string) int {
	t.Helper()
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range pa {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x - y
		}
	}
	return 0
}

func TestEveryConstantInTable(t *testing.T) {
	if len(All()) != len(allConstants) {
		t.Fatalf("table has %d rows, %d constants", len(All()), len(allConstants))
	}
	for _, s := range allConstants {
		for _, p := range []*capability.Profile{nil, profile(t, "rel19")} {
			v, ok := Lookup(p, s)
			if !ok || v.InURI == "" || v.Full == "" {
				t.Errorf("%s: missing or empty (%+v, %v)", s, v, ok)
			}
		}
	}
}

func TestEntryFormat(t *testing.T) {
	seen := map[Service]bool{}
	for _, e := range All() {
		if seen[e.Service] {
			t.Errorf("duplicate %s", e.Service)
		}
		seen[e.Service] = true
		if e.Spec == "" || e.YAML == "" {
			t.Errorf("%s: missing Spec/YAML", e.Service)
		}
		for _, f := range []string{e.Rel17, e.Rel19} {
			if !semver.MatchString(f) {
				t.Errorf("%s: %q not semver", e.Service, f)
				continue
			}
			if e.InURI != "v"+strings.SplitN(f, ".", 2)[0] {
				t.Errorf("%s: InURI %q vs full %q", e.Service, e.InURI, f)
			}
		}
		if cmp(t, e.Rel19, e.Rel17) < 0 {
			t.Errorf("%s: rel19 %s < rel17 %s", e.Service, e.Rel19, e.Rel17)
		}
	}
}

func TestProfileSelection(t *testing.T) {
	if v := Of(nil, NamfComm); v != (Version{"v1", "1.2.8"}) {
		t.Errorf("nil profile: %+v", v)
	}
	if v := Of(profile(t, "rel17"), NamfComm); v.Full != "1.2.8" {
		t.Errorf("rel17: %+v", v)
	}
	if v := Of(profile(t, "rel19"), NamfComm); v != (Version{"v1", "1.4.3"}) {
		t.Errorf("rel19: %+v", v)
	}
	if v := Of(nil, NudrDR); v.InURI != "v2" {
		t.Errorf("udr: %+v", v)
	}
}

func TestUnknownService(t *testing.T) {
	if v, ok := Lookup(nil, "nope"); ok || v != (Version{}) {
		t.Errorf("got %+v, %v", v, ok)
	}
}
