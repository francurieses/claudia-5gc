package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/types"
)

// UDRClient is the PCF's interface to the UDR for policy data retrieval.
// Ref: TS 29.504 §5.2.13 (Nudr_DataRepository, policy-data resource)
type UDRClient interface {
	// GetPolicySubscription returns URSP rules for a SUPI.
	// Returns nil, nil when no per-subscriber override exists.
	GetPolicySubscription(ctx context.Context, supi string) (*types.PolicySubscription, error)

	// GetSmPolicyData returns the subscriber's SM policy data (per-S-NSSAI/DNN
	// authorized QoS). Returns nil, nil when none is provisioned. TS 29.519 §5.6.2.4.
	GetSmPolicyData(ctx context.Context, supi string) (*types.SmPolicyData, error)
	// PutSmPolicyData persists the subscriber's SM policy data through Nudr_DR.
	PutSmPolicyData(ctx context.Context, data *types.SmPolicyData) error
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

func (c *HTTPUDRClient) GetSmPolicyData(ctx context.Context, supi string) (*types.SmPolicyData, error) {
	url := c.baseURL + "/nudr-dr/v2/policy-data/" + supi + "/sm-data"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("pcf: udr client: new request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pcf: udr client: GET sm-data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pcf: udr client: unexpected status %d", resp.StatusCode)
	}

	var data types.SmPolicyData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("pcf: udr client: decode sm-data: %w", err)
	}
	return &data, nil
}

func (c *HTTPUDRClient) PutSmPolicyData(ctx context.Context, data *types.SmPolicyData) error {
	url := c.baseURL + "/nudr-dr/v2/policy-data/" + data.SUPI + "/sm-data"
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("pcf: udr client: marshal sm-data: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pcf: udr client: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("pcf: udr client: PUT sm-data: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pcf: udr client: PUT sm-data unexpected status %d", resp.StatusCode)
	}
	return nil
}
