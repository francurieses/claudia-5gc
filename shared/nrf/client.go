// Package nrf provides an NRF SBI client for NF registration and heartbeats.
//
// Ref: 3GPP TS 29.510 v17 — Nnrf_NFManagement
package nrf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Client is an NRF SBI client.
type Client struct {
	http    *http.Client
	baseURL string
	logger  *slog.Logger
}

// New builds an NRF client.
// baseURL is the NRF address, e.g. "https://nrf.5gc.local:8000".
func New(baseURL string, httpClient *http.Client, logger *slog.Logger) *Client {
	return &Client{
		http:    httpClient,
		baseURL: baseURL,
		logger:  logger.With("component", "nrf-client"),
	}
}

// NFProfile is the minimal profile sent on registration.
// Mirrors the NRF registry.NFProfile (subset).
type NFProfile struct {
	NFInstanceID   string      `json:"nfInstanceId"`
	NFType         string      `json:"nfType"`
	NFStatus       string      `json:"nfStatus"`
	HeartBeatTimer int         `json:"heartBeatTimer,omitempty"`
	FQDN           string      `json:"fqdn,omitempty"`
	IPv4Addresses  []string    `json:"ipv4Addresses,omitempty"`
	NFServices     []NFService `json:"nfServices,omitempty"`
	// SNSSAIs is the list of slices this NF instance supports.
	// Ref: TS 29.510 §5.2.2.2.2 (nfProfile sNssais)
	SNSSAIs []SNSSAIEntry `json:"sNssais,omitempty"`
	// DNNList is the list of Data Network Names served by this NF (SMF/UPF).
	// Ref: TS 29.510 §6.1.6.2.28 (SmfInfo)
	DNNList []string `json:"dnnList,omitempty"`
}

// SNSSAIEntry is a single S-NSSAI in an NF profile.
type SNSSAIEntry struct {
	SST int    `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

// NFService mirrors registry.NFService.
type NFService struct {
	ServiceInstanceID string             `json:"serviceInstanceId"`
	ServiceName       string             `json:"serviceName"`
	Versions          []NFServiceVersion `json:"versions"`
	Scheme            string             `json:"scheme"`
	NFServiceStatus   string             `json:"nfServiceStatus"`
	IPEndpoints       []IPEndpoint       `json:"ipEndPoints,omitempty"`
}

// NFServiceVersion mirrors registry.NFServiceVersion.
type NFServiceVersion struct {
	APIVersionInURI string `json:"apiVersionInUri"`
	APIFullVersion  string `json:"apiFullVersion"`
}

// IPEndpoint mirrors registry.IPEndpoint.
type IPEndpoint struct {
	IPv4Address string `json:"ipv4Address,omitempty"`
	Port        int    `json:"port,omitempty"`
}

// Register sends PUT /nnrf-nfm/v1/nf-instances/{id} and returns the
// heartBeatTimer instructed by the NRF (0 if not provided).
// Ref: TS 29.510 §5.2.2.2.2
func (c *Client) Register(ctx context.Context, profile *NFProfile) (heartbeatTimer int, err error) {
	body, err := json.Marshal(profile)
	if err != nil {
		return 0, fmt.Errorf("nrf: marshal profile: %w", err)
	}
	url := fmt.Sprintf("%s/nnrf-nfm/v1/nf-instances/%s", c.baseURL, profile.NFInstanceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("nrf: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("nrf: register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("nrf: register: unexpected status %d", resp.StatusCode)
	}
	var registered NFProfile
	if err := json.NewDecoder(resp.Body).Decode(&registered); err == nil {
		heartbeatTimer = registered.HeartBeatTimer
	}
	c.logger.Info("registered with NRF",
		"nf_instance_id", profile.NFInstanceID,
		"nf_type", profile.NFType,
		"heartbeat_timer", heartbeatTimer,
		"spec_ref", "TS 29.510 §5.2.2.2.2",
	)
	return heartbeatTimer, nil
}

// Heartbeat sends a JSON Patch heartbeat PATCH per TS 29.510 §5.2.2.3.4.
func (c *Client) Heartbeat(ctx context.Context, nfInstanceID string) error {
	patch := `[{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]`
	url := fmt.Sprintf("%s/nnrf-nfm/v1/nf-instances/%s", c.baseURL, nfInstanceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewBufferString(patch))
	if err != nil {
		return fmt.Errorf("nrf: heartbeat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json-patch+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("nrf: heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("nrf: heartbeat: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// StartHeartbeat runs a goroutine that sends periodic heartbeats until ctx
// is cancelled. On heartbeat failure it re-registers the NF so that an NRF
// restart (which loses in-memory state) is recovered automatically.
// Per TS 29.510 §5.2.2.3.4, a 404 from the NRF means the registration was
// lost and must be retried as a full PUT.
func (c *Client) StartHeartbeat(ctx context.Context, profile *NFProfile, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.Heartbeat(ctx, profile.NFInstanceID); err != nil {
					c.logger.Warn("heartbeat failed — re-registering",
						"nf_instance_id", profile.NFInstanceID,
						"error", err,
						"spec_ref", "TS 29.510 §5.2.2.3.4",
					)
					if _, rerr := c.Register(ctx, profile); rerr != nil {
						c.logger.Warn("re-registration failed",
							"nf_instance_id", profile.NFInstanceID,
							"error", rerr,
						)
					}
				}
			}
		}
	}()
}

// RegisterAndStartHeartbeat registers the NF and starts periodic heartbeats.
// interval is clamped to 80% of the NRF-instructed heartBeatTimer if > 0.
func (c *Client) RegisterAndStartHeartbeat(ctx context.Context, profile *NFProfile, defaultInterval time.Duration) error {
	timer, err := c.Register(ctx, profile)
	if err != nil {
		return err
	}
	interval := defaultInterval
	if timer > 0 {
		advised := time.Duration(float64(timer)*0.8) * time.Second
		if advised < interval {
			interval = advised
		}
	}
	c.StartHeartbeat(ctx, profile, interval)
	return nil
}
