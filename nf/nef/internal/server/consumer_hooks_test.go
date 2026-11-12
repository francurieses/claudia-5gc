package server

// consumer_hooks_test.go - construction hooks for the consumer-side goldens
// (REL19-2.7 slice 7). The golden test file only uses these helpers so that it
// compiles unchanged against the pre-change HEAD tree, where a shim with the
// same names (ignoring the profile) is used to capture the golden files.

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func hookBSF(base string, c *http.Client, p *capability.Profile) *HTTPBSFClient {
	return (&HTTPBSFClient{BaseURL: base, Client: c, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}).WithFeatures(p, nil)
}

func hookPCF(c *http.Client, p *capability.Profile) *HTTPPolicyAuthClient {
	return (&HTTPPolicyAuthClient{Client: c}).WithFeatures(p, nil)
}

func hookCreate(ctx context.Context, c *HTTPPolicyAuthClient, uri string, req *AppSessionContextReqData) (string, error) {
	id, _, err := c.CreateAppSession(ctx, uri, req)
	return id, err
}
