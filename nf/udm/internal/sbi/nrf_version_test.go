package sbi

// nrf_version_test.go - the UDM NFProfile advertises the apiFullVersion of its
// release profile. Ref: TS 29.510 §6.1.6.2.3; TS 29.501 §4.3.1.

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
)

func TestBuildNFProfile_APIFullVersion(t *testing.T) {
	build := func(p *capability.Profile) string {
		prof := BuildNFProfile("id", p, NudmUEAUCatalog())
		return prof.NFServices[0].Versions[0].APIFullVersion
	}
	legacy := apiversion.Of(nil, apiversion.NudmUEAU).Full
	if got := build(nil); got != legacy {
		t.Errorf("nil profile = %q, want legacy %q", got, legacy)
	}
	if got := build(profileNamed(t, "rel17")); got != legacy {
		t.Errorf("rel17 = %q, want legacy %q", got, legacy)
	}
	p19 := profileNamed(t, "rel19")
	if got, want := build(p19), apiversion.Of(p19, apiversion.NudmUEAU).Full; got != want {
		t.Errorf("rel19 = %q, want %q", got, want)
	}
}

// TestBuildNFProfile_ServicesByProfile: rel17 / nil keep the legacy single
// nudm-ueau service; rel19 also registers nudm-sdm (v2) and nudm-uecm (v1) so
// NRF discovery by service-names finds the UDM (ROAM-001: the hSEPP resolves
// the home UDM by service name). Ref: TS 29.510 §6.1.6.2.3; TS 29.503.
func TestBuildNFProfile_ServicesByProfile(t *testing.T) {
	for _, p := range []*capability.Profile{nil, profileNamed(t, "rel17")} {
		prof := BuildNFProfile("id", p, NudmUEAUCatalog())
		if len(prof.NFServices) != 1 || prof.NFServices[0].ServiceName != "nudm-ueau" {
			t.Fatalf("legacy profile services = %+v, want only nudm-ueau", prof.NFServices)
		}
	}
	p19 := profileNamed(t, "rel19")
	prof := BuildNFProfile("id", p19, NudmUEAUCatalog())
	want := []struct {
		name, inURI string
		svc         apiversion.Service
	}{
		{"nudm-ueau", "v1", apiversion.NudmUEAU},
		{"nudm-sdm", "v2", apiversion.NudmSDM},
		{"nudm-uecm", "v1", apiversion.NudmUECM},
	}
	if len(prof.NFServices) != len(want) {
		t.Fatalf("rel19 services = %d, want %d: %+v", len(prof.NFServices), len(want), prof.NFServices)
	}
	for i, w := range want {
		s := prof.NFServices[i]
		if s.ServiceName != w.name || s.ServiceInstanceID != "id-"+w.name {
			t.Errorf("service %d = %q/%q, want %q", i, s.ServiceName, s.ServiceInstanceID, w.name)
		}
		if len(s.Versions) != 1 || s.Versions[0].APIVersionInURI != w.inURI ||
			s.Versions[0].APIFullVersion != apiversion.Of(p19, w.svc).Full {
			t.Errorf("service %s versions = %+v, want %s / %s", w.name, s.Versions, w.inURI, apiversion.Of(p19, w.svc).Full)
		}
		if s.SupportedFeatures != "0" || s.Scheme != "https" || s.NFServiceStatus != "REGISTERED" {
			t.Errorf("service %s = %+v", w.name, s)
		}
	}
}
