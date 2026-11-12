package server

// nrf_version_test.go - the SMF NFProfile advertises the apiFullVersion of its
// release profile. Ref: TS 29.510 §6.1.6.2.3; TS 29.501 §4.3.1.

import (
	"testing"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
)

func TestBuildNFProfile_APIFullVersion(t *testing.T) {
	build := func(p *capability.Profile) string {
		prof := BuildNFProfile(&config.Config{NFInstanceID: "id"}, p)
		return prof.NFServices[0].Versions[0].APIFullVersion
	}
	legacy := apiversion.Of(nil, apiversion.NsmfPDUSession).Full
	if got := build(nil); got != legacy {
		t.Errorf("nil profile = %q, want legacy %q", got, legacy)
	}
	if got := build(profileFor(t, "rel17")); got != legacy {
		t.Errorf("rel17 = %q, want legacy %q", got, legacy)
	}
	p19 := profileFor(t, "rel19")
	if got, want := build(p19), apiversion.Of(p19, apiversion.NsmfPDUSession).Full; got != want || got == legacy {
		t.Errorf("rel19 = %q, want %q (!= %q)", got, want, legacy)
	}
}
