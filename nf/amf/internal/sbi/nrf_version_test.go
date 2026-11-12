package sbi

// nrf_version_test.go - the AMF NFProfile advertises the apiFullVersion of its
// release profile. Ref: TS 29.510 §6.1.6.2.3; TS 29.501 §4.3.1.

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
)

func TestBuildNFProfile_APIFullVersion(t *testing.T) {
	cases := []struct {
		name string
		p    *capability.Profile
		want string
	}{
		{"nil", nil, apiversion.Of(nil, apiversion.NamfComm).Full},
		{"rel17", profileNamed(t, "rel17"), "1.2.8"},
		{"rel19", profileNamed(t, "rel19"), "1.4.3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := BuildNFProfile("id", c.p, NamfCommunicationCatalog()).NFServices[0].Versions[0].APIFullVersion
			if got != c.want {
				t.Fatalf("apiFullVersion = %q, want %q", got, c.want)
			}
		})
	}
}
