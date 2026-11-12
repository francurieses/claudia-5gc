package sbi

import (
	"encoding/json"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

func profileFor(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildNFProfile(t *testing.T) {
	p := BuildNFProfile("id-1", nil, nil)
	if p.NFType != "SEPP" || p.NFInstanceID != "id-1" || p.NFStatus != "REGISTERED" {
		t.Fatalf("bad profile: %+v", p)
	}
	if len(p.NFServices) != 1 || p.NFServices[0].ServiceName != "n32c-handshake" {
		t.Fatalf("bad services: %+v", p.NFServices)
	}
	if v := p.NFServices[0].Versions[0]; v.APIVersionInURI != "v1" || v.APIFullVersion != "1.2.1" {
		t.Fatalf("bad rel17 version: %+v", v)
	}
}

// The registered apiName is the TS 29.573 Table 6-1 value (not a Rel-17 enum member).
func TestRegisteredServiceName(t *testing.T) {
	if ServiceN32cHandshake != "n32c-handshake" {
		t.Fatalf("constant = %q", ServiceN32cHandshake)
	}
	for _, name := range []string{capability.ProfileRel17, capability.ProfileRel19} {
		p := BuildNFProfile("id", profileFor(t, name), nil)
		if got := p.NFServices[0].ServiceName; got != "n32c-handshake" {
			t.Fatalf("%s: serviceName %q", name, got)
		}
	}
}

func TestSeppInfoRemotePlmnList(t *testing.T) {
	partners := []config.PLMN{{MCC: "001", MNC: "02"}, {MCC: "310", MNC: "260"}}
	for _, name := range []string{capability.ProfileRel17, capability.ProfileRel19} {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(BuildNFProfile("id", profileFor(t, name), partners))
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(b, &raw); err != nil {
				t.Fatal(err)
			}
			var info struct {
				RemotePlmnList []map[string]string `json:"remotePlmnList"`
			}
			if err := json.Unmarshal(raw["seppInfo"], &info); err != nil {
				t.Fatalf("seppInfo missing/invalid: %v (%s)", err, b)
			}
			l := info.RemotePlmnList
			if len(l) != 2 || l[0]["mcc"] != "001" || l[0]["mnc"] != "02" || l[1]["mcc"] != "310" || l[1]["mnc"] != "260" {
				t.Fatalf("seppInfo = %s", b)
			}
		})
	}
}

func TestSeppInfoOmittedWithoutPartners(t *testing.T) {
	for _, name := range []string{capability.ProfileRel17, capability.ProfileRel19} {
		b, err := json.Marshal(BuildNFProfile("id", profileFor(t, name), nil))
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(b, &raw)
		if _, ok := raw["seppInfo"]; ok { // remotePlmnList has minItems 1
			t.Fatalf("%s: seppInfo emitted without partners: %s", name, b)
		}
	}
}
