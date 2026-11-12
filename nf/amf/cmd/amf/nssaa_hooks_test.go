package main

// nssaa_hooks_test.go - construction hook for the NSSAA client goldens
// (REL19-3.5 slice E).

import (
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func newNSSAAClientForTest(addr string, c *http.Client, p *capability.Profile) *HTTPNSSAAClient {
	return &HTTPNSSAAClient{address: addr, client: c, profile: p}
}
