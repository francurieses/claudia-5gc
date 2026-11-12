package sbi

// nrf_version_test.go - the PCF NFProfile advertises the apiFullVersion of its
// release profile for every service. Ref: TS 29.510 §6.1.6.2.3; TS 29.501 §4.3.1.

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
)

func TestBuildNFProfile_APIFullVersion(t *testing.T) {
	build := func(name string) []string {
		p := profileNamed(t, name)
		prof := BuildNFProfile("id", p, NpcfSMPolicyControlCatalog(), NpcfUEPolicyControlCatalog(), NpcfAMPolicyControlCatalog(), NpcfPolicyAuthorizationCatalog())
		var out []string
		for _, s := range prof.NFServices {
			out = append(out, s.Versions[0].APIFullVersion)
		}
		return out
	}
	svcs := []apiversion.Service{apiversion.NpcfSMPolicyControl, apiversion.NpcfUEPolicyControl, apiversion.NpcfAMPolicyControl, apiversion.NpcfPolicyAuth}
	for _, name := range []string{"rel17", "rel19"} {
		got := build(name)
		p := profileNamed(t, name)
		for i, svc := range svcs {
			if want := apiversion.Of(p, svc).Full; got[i] != want {
				t.Errorf("%s %s: apiFullVersion = %q, want %q", name, svc, got[i], want)
			}
		}
	}
	if got := build("rel19")[0]; got != "1.4.2" {
		t.Errorf("rel19 npcf-smpolicycontrol = %q, want 1.4.2", got)
	}
}
