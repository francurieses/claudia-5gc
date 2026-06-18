package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// PCFQoSPolicy holds per-subscriber QoS parameters stored in the PCF.
// Ref: TS 29.512 §5.2.2.2 — qosDecs and sessRules returned by PCF.
type PCFQoSPolicy struct {
	FiveQI           int    `json:"5qi"`
	ARPPriorityLevel int    `json:"arp_priority_level,omitempty"`
	AMBRUplink       string `json:"ambr_uplink,omitempty"`
	AMBRDownlink     string `json:"ambr_downlink,omitempty"`
}

// PCF wraps the PCF internal management API for Group H tools.
// The management endpoints share the SBI port but are not 3GPP-defined —
// they expose per-subscriber SM policy overrides for operator use.
type PCF struct {
	baseURL string
	http    *http.Client
}

// NewPCF builds a PCF management client. baseURL is e.g. https://pcf:8006.
// httpClient should be the SBI mTLS client since PCF listens on the SBI port.
func NewPCF(baseURL string, httpClient *http.Client) *PCF {
	return &PCF{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// SetQoSPolicy stores a per-subscriber SM policy override in the PCF.
// The override is applied on the next PDU session establishment for this SUPI.
func (c *PCF) SetQoSPolicy(ctx context.Context, supi string, p PCFQoSPolicy) error {
	body, _ := json.Marshal(p)
	u := c.baseURL + "/pcf-internal/v1/subscribers/" + url.PathEscape(supi) + "/sm-policy-override"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pcf: set qos policy: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("pcf: set qos policy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return fmt.Errorf("pcf: set qos policy: status %d: %s", resp.StatusCode, detail)
	}
	return nil
}

// GetQoSPolicy retrieves the active per-subscriber override, or (nil, nil) if none is set.
func (c *PCF) GetQoSPolicy(ctx context.Context, supi string) (*PCFQoSPolicy, error) {
	u := c.baseURL + "/pcf-internal/v1/subscribers/" + url.PathEscape(supi) + "/sm-policy-override"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("pcf: get qos policy: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pcf: get qos policy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pcf: get qos policy: status %d", resp.StatusCode)
	}
	var p PCFQoSPolicy
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("pcf: get qos policy: decode: %w", err)
	}
	return &p, nil
}

// DeleteQoSPolicy removes the per-subscriber override; subsequent sessions revert to defaults.
// Returns nil if the override did not exist (idempotent).
func (c *PCF) DeleteQoSPolicy(ctx context.Context, supi string) error {
	u := c.baseURL + "/pcf-internal/v1/subscribers/" + url.PathEscape(supi) + "/sm-policy-override"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return fmt.Errorf("pcf: delete qos policy: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("pcf: delete qos policy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("pcf: delete qos policy: status %d", resp.StatusCode)
}
