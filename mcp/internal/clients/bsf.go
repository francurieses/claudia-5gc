package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// BSF wraps the Nbsf_Management service (TS 29.521 §5.2.2.4, PcfBinding discovery).
// The BSF SBI enforces mTLS: use the SBI client.
type BSF struct {
	baseURL string
	http    *http.Client
}

// NewBSF builds a BSF client. baseURL is e.g. https://bsf:8010.
func NewBSF(baseURL string, httpClient *http.Client) *BSF {
	return &BSF{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// Discover calls GET /nbsf-management/v1/pcfBindings with the given query
// (supi, ipv4Addr, dnn, ...). The BSF answers one PcfBinding JSON, or 204 No Content
// (TS 29.521 GetPCFBindings) / 404 when none matches; both return (nil, nil).
func (c *BSF) Discover(ctx context.Context, q url.Values) (json.RawMessage, error) {
	u := c.baseURL + "/nbsf-management/v1/pcfBindings"
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("bsf: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bsf: discover pcf binding: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bsf: discover pcf binding: status %d: %s", resp.StatusCode, truncate(body))
	}
	return body, nil
}
