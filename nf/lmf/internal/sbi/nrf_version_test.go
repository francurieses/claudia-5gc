package sbi

// nrf_version_test.go - the LMF NFProfile advertises the apiFullVersion of its
// release profile. Ref: TS 29.510 §6.1.6.2.3; TS 29.501 §4.3.1.

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
)

func TestBuildNFProfile_APIFullVersion(t *testing.T) {
	build := func(p *capability.Profile) string {
		prof := BuildNFProfile("id", "lmf.test", p, NlmfLocationCatalog())
		return prof.NFServices[0].Versions[0].APIFullVersion
	}
	legacy := apiversion.Of(nil, apiversion.NlmfLoc).Full
	if got := build(nil); got != legacy {
		t.Errorf("nil profile = %q, want legacy %q", got, legacy)
	}
	if got := build(profileNamed(t, "rel17")); got != legacy {
		t.Errorf("rel17 = %q, want legacy %q", got, legacy)
	}
	p19 := profileNamed(t, "rel19")
	if got, want := build(p19), apiversion.Of(p19, apiversion.NlmfLoc).Full; got != want {
		t.Errorf("rel19 = %q, want %q", got, want)
	}
}
