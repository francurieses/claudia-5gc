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

// AMF wraps the AMF management API for the Group C tools. The management API is
// plain HTTP (default :9002). Reference: 3GPP TS 23.502 (UE context handling).
type AMF struct {
	baseURL string
	http    *http.Client
}

// NewAMF builds an AMF management client. baseURL is e.g. http://amf:9002.
func NewAMF(baseURL string, httpClient *http.Client) *AMF {
	return &AMF{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// ListContexts retrieves all active UE context snapshots.
func (c *AMF) ListContexts(ctx context.Context) (json.RawMessage, error) {
	body, status, err := c.do(ctx, c.baseURL+"/amf/v1/ue-contexts")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("amf: list ue-contexts: status %d", status)
	}
	return body, nil
}

// ListGNBs retrieves the AMF gNB registry (connected + recently disconnected
// gNBs). Calls GET /amf/v1/ran/gnbs. Ref: TS 38.413 §8.7.1 (NG Setup).
func (c *AMF) ListGNBs(ctx context.Context) (json.RawMessage, error) {
	body, status, err := c.do(ctx, c.baseURL+"/amf/v1/ran/gnbs")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("amf: list ran gnbs: status %d", status)
	}
	return body, nil
}

// GetContext retrieves a single UE context snapshot by SUPI. Returns (nil, nil)
// when the UE is not found.
func (c *AMF) GetContext(ctx context.Context, supi string) (json.RawMessage, error) {
	u := c.baseURL + "/amf/v1/ue-contexts/" + url.PathEscape(supi)
	body, status, err := c.do(ctx, u)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("amf: get ue-context %s: status %d", supi, status)
	}
	return body, nil
}

func (c *AMF) do(ctx context.Context, u string) (json.RawMessage, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("amf: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("amf: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("amf: read body: %w", err)
	}
	return body, resp.StatusCode, nil
}

// sendAMF performs a management-API call that changes state and returns the
// status code and the (capped) body. Non-2xx codes are returned, not errors, so
// each control tool maps the codes it expects (for example 409 CM-IDLE).
func (c *AMF) sendAMF(ctx context.Context, method, u string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("amf: encode body: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return 0, nil, fmt.Errorf("amf: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("amf: %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("amf: read body: %w", err)
	}
	return resp.StatusCode, raw, nil
}

// DeregisterUE triggers a network-initiated deregistration with re-registration
// required. Calls DELETE /amf/v1/ue-contexts/{supi}. Ref: TS 23.502 §4.2.2.3.3.
func (c *AMF) DeregisterUE(ctx context.Context, supi string) (int, []byte, error) {
	return c.sendAMF(ctx, http.MethodDelete, c.baseURL+"/amf/v1/ue-contexts/"+url.PathEscape(supi), nil)
}

// ReleasePDUSession triggers a network-initiated PDU session release. Calls
// DELETE /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}. Ref: TS 23.502 §4.3.4.3.
func (c *AMF) ReleasePDUSession(ctx context.Context, supi string, psi int) (int, []byte, error) {
	u := fmt.Sprintf("%s/amf/v1/ue-contexts/%s/pdu-sessions/%d", c.baseURL, url.PathEscape(supi), psi)
	return c.sendAMF(ctx, http.MethodDelete, u, nil)
}

// PushPolicies asks the AMF to send the current URSP (UE policy) to a registered
// UE. Calls POST /amf/v1/ue-contexts/{supi}/push-policies. 409 means CM-IDLE:
// delivery is deferred. Ref: TS 23.502 §4.2.4.3.
func (c *AMF) PushPolicies(ctx context.Context, supi string) (int, []byte, error) {
	return c.sendAMF(ctx, http.MethodPost, c.baseURL+"/amf/v1/ue-contexts/"+url.PathEscape(supi)+"/push-policies", nil)
}

// NSSAA runs an AAA-initiated slice re-authentication or revocation. Calls
// POST /amf/v1/ue-contexts/{supi}/nssaa/{action} with {sst, sd}. action is
// "reauth" or "revoke". Ref: TS 23.502 §4.2.9.3 (re-auth), §4.2.9.4 (revoke).
func (c *AMF) NSSAA(ctx context.Context, supi, action string, sst int, sd string) (int, []byte, error) {
	u := c.baseURL + "/amf/v1/ue-contexts/" + url.PathEscape(supi) + "/nssaa/" + action
	return c.sendAMF(ctx, http.MethodPost, u, map[string]any{"sst": sst, "sd": sd})
}

// ANRelease asks the AMF to release the AN connection of a CM-CONNECTED UE (UE
// Context Release Command, cause O&M intervention). Calls
// POST /amf/v1/ue-contexts/{supi}/an-release. Ref: TS 23.502 §4.2.6, TS 38.413 §8.3.3.
func (c *AMF) ANRelease(ctx context.Context, supi string) (int, []byte, error) {
	return c.sendAMF(ctx, http.MethodPost, c.baseURL+"/amf/v1/ue-contexts/"+url.PathEscape(supi)+"/an-release", nil)
}

// TimerConfigPath is the AMF management path for the runtime NAS timers.
const TimerConfigPath = "/amf/v1/config/timers"

// GetTimerConfig reads the effective and base AMF timers. Calls
// GET /amf/v1/config/timers. Ref: TS 24.501 §5.3.7, §10.2 Table 10.2.1.
func (c *AMF) GetTimerConfig(ctx context.Context) (int, []byte, error) {
	return c.sendAMF(ctx, http.MethodGet, c.baseURL+TimerConfigPath, nil)
}

// PutTimerConfig changes (or with reset:true restores) the AMF timers at runtime.
// Calls PUT /amf/v1/config/timers. Non-2xx codes are returned, not errors.
func (c *AMF) PutTimerConfig(ctx context.Context, body map[string]any) (int, []byte, error) {
	return c.sendAMF(ctx, http.MethodPut, c.baseURL+TimerConfigPath, body)
}
