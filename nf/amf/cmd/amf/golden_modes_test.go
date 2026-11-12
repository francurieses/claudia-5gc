package main

// golden_modes_test.go - profile settings the rel17 goldens run under: no
// profile loaded and the explicit rel17 profile must both leave the legacy
// bytes unchanged (decision D2).

import (
	"net/http"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// goldenMode is one profile setting that must leave the legacy bytes unchanged.
type goldenMode struct {
	name    string
	profile *capability.Profile
}

func goldenModes(t *testing.T) []goldenMode {
	t.Helper()
	return []goldenMode{{"no-profile", nil}, {"explicit-rel17", testProfile(t, "rel17")}}
}

func newAUSFClient(addr string, hc *http.Client, m goldenMode) *HTTPAUSFClient {
	return &HTTPAUSFClient{address: addr, client: hc, profile: m.profile}
}

func newUDMClient(addr string, hc *http.Client, m goldenMode) *HTTPUDMClient {
	return &HTTPUDMClient{address: addr, client: hc, profile: m.profile}
}
