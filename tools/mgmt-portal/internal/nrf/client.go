// Package nrf queries the NRF for registered NF instances.
package nrf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// NFProfile is a partial view of a 3GPP NF profile.
type NFProfile struct {
	NfInstanceID string   `json:"nfInstanceId"`
	NfType       string   `json:"nfType"`
	NfStatus     string   `json:"nfStatus"`
	HeartBeatTimer int    `json:"heartBeatTimer"`
	IPv4Addresses []string `json:"ipv4Addresses"`
	SNSSAIs      []SNSSAI `json:"sNssais,omitempty"`
}

// SNSSAI is an S-NSSAI as returned by NRF.
type SNSSAI struct {
	SST int    `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

// DiscoveryResponse is the NRF discovery response body.
type DiscoveryResponse struct {
	NFInstances []NFProfile `json:"nfInstances"`
}

// Client queries the NRF SBI endpoint.
type Client struct {
	baseURL string
	http    *http.Client
}

// New returns a Client for the given NRF URL using the provided HTTP client.
// Pass an mTLS-capable client (with portal cert) so NRF mutual-auth succeeds.
func New(baseURL string, httpClient *http.Client) *Client {
	return &Client{
		baseURL: baseURL,
		http:    httpClient,
	}
}

// ListNFInstances returns all registered NF profiles from the NRF.
// detail=true is required: without it the NRF returns instance ids only
// (TS 29.510 §5.2.2.6 NFListRetrieval), not the full profiles we decode.
func (c *Client) ListNFInstances(ctx context.Context) ([]NFProfile, error) {
	url := c.baseURL + "/nnrf-nfm/v1/nf-instances?detail=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nrf: ListNFInstances: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nrf: ListNFInstances: status %d", resp.StatusCode)
	}

	var result DiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("nrf: decode: %w", err)
	}
	return result.NFInstances, nil
}

// HealthCheck checks the NRF /healthz endpoint.
func (c *Client) HealthCheck(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
