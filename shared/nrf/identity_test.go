package nrf

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApplyFQDNIdentity(t *testing.T) {
	mk := func() *NFProfile {
		return &NFProfile{NFInstanceID: "id", NFType: "UDM", NFStatus: "REGISTERED",
			NFServices: []NFService{{ServiceInstanceID: "s", ServiceName: "nudm-ueau", Scheme: "https", NFServiceStatus: "REGISTERED"}}}
	}
	base, _ := json.Marshal(mk())

	p := mk()
	if err := ApplyFQDNIdentity(p, "", "0.0.0.0:8003", "", ""); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(p)
	if string(got) != string(base) {
		t.Fatalf("empty fqdn changed profile:\n%s\n%s", got, base)
	}
	if strings.Contains(string(base), "fqdn") || strings.Contains(string(base), "plmnList") {
		t.Fatalf("baseline unexpectedly carries identity: %s", base)
	}

	p = mk()
	if err := ApplyFQDNIdentity(p, "udm.5gc.mnc002.mcc001.3gppnetwork.org", "0.0.0.0:8003", "001", "02"); err != nil {
		t.Fatal(err)
	}
	got, _ = json.Marshal(p)
	for _, want := range []string{
		`"fqdn":"udm.5gc.mnc002.mcc001.3gppnetwork.org"`,
		`"ipEndPoints":[{"port":8003}]`,
		`"plmnList":[{"mcc":"001","mnc":"02"}]`,
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}

func TestApplyFQDNIdentityErrors(t *testing.T) {
	const ok = "udm.5gc.mnc002.mcc001.3gppnetwork.org"
	long := strings.Repeat("a", 64) + ".org"
	cases := []struct{ name, fqdn, addr, mcc, mnc string }{
		{"scheme", "https://" + ok, "0.0.0.0:8003", "001", "02"},
		{"port in fqdn", ok + ":8003", "0.0.0.0:8003", "001", "02"},
		{"empty label", "udm..org", "0.0.0.0:8003", "001", "02"},
		{"trailing dot", ok + ".", "0.0.0.0:8003", "001", "02"},
		{"hyphen edge", "-udm.org", "0.0.0.0:8003", "001", "02"},
		{"long label", long, "0.0.0.0:8003", "001", "02"},
		{"addr no port", ok, "0.0.0.0", "001", "02"},
		{"port non numeric", ok, "0.0.0.0:http", "001", "02"},
		{"port zero", ok, "0.0.0.0:0", "001", "02"},
		{"port too big", ok, "0.0.0.0:65536", "001", "02"},
		{"empty plmn", ok, "0.0.0.0:8003", "", ""},
		{"short mcc", ok, "0.0.0.0:8003", "01", "02"},
		{"long mnc", ok, "0.0.0.0:8003", "001", "0123"},
		{"short mnc", ok, "0.0.0.0:8003", "001", "2"},
		{"non digit mnc", ok, "0.0.0.0:8003", "001", "0a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &NFProfile{NFServices: []NFService{{ServiceName: "s"}}}
			before, _ := json.Marshal(p)
			if err := ApplyFQDNIdentity(p, c.fqdn, c.addr, c.mcc, c.mnc); err == nil {
				t.Fatal("expected error")
			}
			if after, _ := json.Marshal(p); string(after) != string(before) {
				t.Fatalf("profile mutated on error: %s", after)
			}
		})
	}
	if err := ApplyFQDNIdentity(&NFProfile{}, "nf1", "[::]:8003", "310", "260"); err != nil {
		t.Fatalf("valid single-label/3-digit mnc rejected: %v", err)
	}
}
