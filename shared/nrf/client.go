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
	"sync"
	"time"
)

// RegisterRetryInitialBackoff is the delay before the first background retry
// of NFRegister after the initial registration attempt failed. The NF must
// register with the NRF before it is discoverable by other NFs, so a failed
// attempt is retried until it succeeds.
// Ref: TS 29.510 §5.2.2.2.2 (NFRegister).
const RegisterRetryInitialBackoff = 1 * time.Second

// RegisterRetryMaxBackoff caps the exponential backoff between background
// NFRegister retries so that an NF recovers within this bound once the NRF
// becomes reachable again.
// Ref: TS 29.510 §5.2.2.2.2 (NFRegister).
const RegisterRetryMaxBackoff = 30 * time.Second

// MinHeartbeatInterval is the lower bound applied to the NF heartbeat
// period derived from the NRF-advised heartBeatTimer (an integer number of
// seconds) and to any non-positive interval. Without it a heartBeatTimer of
// 1 s yields 0.8 s truncated to zero, and time.NewTicker panics on a
// non-positive duration.
// Ref: TS 29.510 §5.2.2.3.4 (NF Heartbeat), §6.1.6.2.2 (NFProfile
// heartBeatTimer).
const MinHeartbeatInterval = 1 * time.Second

// Client is an NRF SBI client.
type Client struct {
	http    *http.Client
	baseURL string
	logger  *slog.Logger

	// retryInitial / retryMax override the register retry backoff (tests
	// only); zero means RegisterRetryInitialBackoff / RegisterRetryMaxBackoff.
	retryInitial time.Duration
	retryMax     time.Duration
	// wg tracks background goroutines (register retry, heartbeat loop).
	wg sync.WaitGroup
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
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.heartbeatLoop(ctx, profile, interval)
	}()
}

// heartbeatLoop blocks sending heartbeats every interval until ctx is done.
// A non-positive interval is clamped to MinHeartbeatInterval because
// time.NewTicker panics on it.
func (c *Client) heartbeatLoop(ctx context.Context, profile *NFProfile, interval time.Duration) {
	if interval <= 0 {
		interval = MinHeartbeatInterval
	}
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
}

// heartbeatInterval returns min(defaultInterval, 80% of the NRF-instructed
// heartBeatTimer) when the NRF provided one (timer > 0, in seconds).
// The NRF-advised value is floored at MinHeartbeatInterval so that a 1 s
// heartBeatTimer cannot truncate to a zero interval, and a non-positive
// defaultInterval is replaced by MinHeartbeatInterval. A positive
// caller-chosen defaultInterval below the floor is kept as is.
// Ref: TS 29.510 §5.2.2.2.2 (heartBeatTimer in the NFRegister response),
// §5.2.2.3.4, §6.1.6.2.2.
func heartbeatInterval(timer int, defaultInterval time.Duration) time.Duration {
	interval := defaultInterval
	if interval <= 0 {
		interval = MinHeartbeatInterval
	}
	if timer > 0 {
		advised := max(time.Duration(timer)*time.Second*4/5, MinHeartbeatInterval)
		if advised < interval {
			interval = advised
		}
	}
	return interval
}

// RegisterAndStartHeartbeat registers the NF and starts periodic heartbeats.
// interval is clamped to 80% of the NRF-instructed heartBeatTimer if > 0.
//
// If the initial NFRegister fails (e.g. the NRF is restarting or not yet
// resolvable), a background goroutine keeps retrying it with bounded
// exponential backoff until it succeeds or ctx is cancelled, then continues
// with the normal heartbeat loop. The initial error is still returned so the
// caller can log it; registration is nevertheless eventually guaranteed.
// Ref: TS 29.510 §5.2.2.2.2, §5.2.2.3.2.
func (c *Client) RegisterAndStartHeartbeat(ctx context.Context, profile *NFProfile, defaultInterval time.Duration) error {
	timer, err := c.Register(ctx, profile)
	if err != nil {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			timer, ok := c.registerWithRetry(ctx, profile)
			if !ok {
				return
			}
			c.heartbeatLoop(ctx, profile, heartbeatInterval(timer, defaultInterval))
		}()
		return fmt.Errorf("nrf: initial register failed, retrying in background: %w", err)
	}
	c.StartHeartbeat(ctx, profile, heartbeatInterval(timer, defaultInterval))
	return nil
}

// registerWithRetry retries NFRegister with bounded exponential backoff until
// it succeeds (returning the NRF heartBeatTimer and true) or ctx is cancelled
// (returning false). Ref: TS 29.510 §5.2.2.2.2.
func (c *Client) registerWithRetry(ctx context.Context, profile *NFProfile) (int, bool) {
	backoff, maxBackoff := c.retryInitial, c.retryMax
	if backoff <= 0 {
		backoff = RegisterRetryInitialBackoff
	}
	if maxBackoff <= 0 {
		maxBackoff = RegisterRetryMaxBackoff
	}
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	for attempt := 1; ; attempt++ {
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return 0, false
		case <-t.C:
		}
		timer, err := c.Register(ctx, profile)
		if err == nil {
			return timer, true
		}
		if ctx.Err() != nil {
			return 0, false
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		c.logger.Warn("NRF registration retry failed",
			"nf_instance_id", profile.NFInstanceID,
			"attempt", attempt,
			"next_backoff", backoff.String(),
			"error", err,
			"spec_ref", "TS 29.510 §5.2.2.2.2",
		)
	}
}
