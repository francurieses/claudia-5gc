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

// UDM wraps the Nudm_SDM service for subscription QoS lookups. The UDM SBI
// enforces mTLS — use the SBI client. Ref: TS 29.503 §5.2.2.2 (GET sm-data).
type UDM struct {
	baseURL string
	http    *http.Client
}

// NewUDM builds a UDM SDM client. baseURL is e.g. https://udm:8003.
func NewUDM(baseURL string, httpClient *http.Client) *UDM {
	return &UDM{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// GetSMData returns the SessionManagementSubscriptionData array for a SUPI.
// Returns (nil, nil) when the subscriber has no SM subscription.
func (c *UDM) GetSMData(ctx context.Context, supi string) (json.RawMessage, error) {
	u := c.baseURL + "/nudm-sdm/v2/" + url.PathEscape(supi) + "/sm-data"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("udm: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("udm: get sm-data: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("udm: get sm-data: status %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
