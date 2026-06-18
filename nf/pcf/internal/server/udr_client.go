package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/types"
)

// UDRClient is the PCF's interface to the UDR for policy data retrieval.
// Ref: TS 29.504 §5.2.4 (Nudr_DataRepository, policy-data resource)
type UDRClient interface {
	// GetPolicySubscription returns URSP rules for a SUPI.
	// Returns nil, nil when no per-subscriber override exists.
	GetPolicySubscription(ctx context.Context, supi string) (*types.PolicySubscription, error)
}

// HTTPUDRClient calls the UDR over mTLS HTTP/2.
type HTTPUDRClient struct {
	baseURL string
	client  *http.Client
}

// NewHTTPUDRClient constructs a client pointing at the given UDR base URL.
// client must be an HTTP/2-enabled TLS client (e.g. from shared/sbi).
func NewHTTPUDRClient(baseURL string, client *http.Client) *HTTPUDRClient {
	return &HTTPUDRClient{baseURL: baseURL, client: client}
}

func (c *HTTPUDRClient) GetPolicySubscription(ctx context.Context, supi string) (*types.PolicySubscription, error) {
	url := c.baseURL + "/nudr-dr/v2/policy-data/" + supi + "/ue-policy-set"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("pcf: udr client: new request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pcf: udr client: GET policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pcf: udr client: unexpected status %d", resp.StatusCode)
	}

	var sub types.PolicySubscription
	if err := json.NewDecoder(resp.Body).Decode(&sub); err != nil {
		return nil, fmt.Errorf("pcf: udr client: decode policy: %w", err)
	}
	return &sub, nil
}
