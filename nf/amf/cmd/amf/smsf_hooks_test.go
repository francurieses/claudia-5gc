package main

// smsf_hooks_test.go - construction hooks for the SMSF uplink goldens.

import (
	"net/http"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func smsfProfile(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newSMSFClientForTest(addr string, c *http.Client, p *capability.Profile) *HTTPSMSFClient {
	return &HTTPSMSFClient{address: addr, client: c, profile: p, boundary: "GOLDENBOUNDARY"}
}
