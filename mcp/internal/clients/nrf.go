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

// NRF wraps the NRF SBI for the Group B tools. Reference: 3GPP TS 29.510.
type NRF struct {
	baseURL string
	http    *http.Client
}

// NewNRF builds an NRF client. baseURL is e.g. https://nrf:8000.
func NewNRF(baseURL string, httpClient *http.Client) *NRF {
	return &NRF{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// Discover performs Nnrf_NFDiscovery (TS 29.510 §5.3.2.2). query carries the
// discovery filters (target-nf-type, requester-nf-type, service-names, dnn,
// snssais). Returns the raw NRF JSON response.
func (c *NRF) Discover(ctx context.Context, query url.Values) (json.RawMessage, error) {
	u := c.baseURL + "/nnrf-disc/v1/nf-instances?" + query.Encode()
	return c.getJSON(ctx, u)
}

// List retrieves all registered NF profiles via NFListRetrieval
// (TS 29.510 §5.2.2.6). detail=true asks the NRF to inline full profiles.
func (c *NRF) List(ctx context.Context, detail bool) (json.RawMessage, error) {
	u := c.baseURL + "/nnrf-nfm/v1/nf-instances"
	if detail {
		u += "?detail=true"
	}
	return c.getJSON(ctx, u)
}

// GetByID retrieves a single NF profile via NFProfileRetrieve
// (TS 29.510 §5.2.2.5). Returns (nil, nil) when the NF is not found.
func (c *NRF) GetByID(ctx context.Context, id string) (json.RawMessage, error) {
	u := c.baseURL + "/nnrf-nfm/v1/nf-instances/" + url.PathEscape(id)
	body, status, err := c.do(ctx, u)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("nrf: profile retrieve %s: status %d", id, status)
	}
	return body, nil
}

func (c *NRF) getJSON(ctx context.Context, u string) (json.RawMessage, error) {
	body, status, err := c.do(ctx, u)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("nrf: GET %s: status %d", u, status)
	}
	return body, nil
}

func (c *NRF) do(ctx context.Context, u string) (json.RawMessage, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("nrf: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("nrf: request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("nrf: read body: %w", err)
	}
	return body, resp.StatusCode, nil
}
