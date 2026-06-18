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

// SMF wraps the SMF internal management API (/nsmf-management/v1), which shares
// the SBI listener — use the mTLS SBI client. The endpoints are not 3GPP-defined;
// they expose the SMF session store and the NW-initiated QoS modification
// trigger (TS 23.502 §4.3.3.2).
type SMF struct {
	baseURL string
	http    *http.Client
}

// NewSMF builds an SMF management client. baseURL is e.g. https://smf:8004.
func NewSMF(baseURL string, httpClient *http.Client) *SMF {
	return &SMF{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// ListSessions returns the raw session list from the SMF session store.
func (c *SMF) ListSessions(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, c.baseURL+"/nsmf-management/v1/sessions")
}

// GetSession returns one session with its QoS flow and PFCP QER view.
// supi is optional and disambiguates when multiple UEs share the PSI.
// Returns (nil, nil) when no session matches.
func (c *SMF) GetSession(ctx context.Context, pduSessionID int, supi string) (json.RawMessage, error) {
	u := fmt.Sprintf("%s/nsmf-management/v1/sessions/%d", c.baseURL, pduSessionID)
	if supi != "" {
		u += "?supi=" + url.QueryEscape(supi)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("smf: build request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("smf: get session: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("smf: get session: status %d: %s", resp.StatusCode, body)
	}
	return body, nil
}

// SetSessionQoS triggers the NW-initiated PDU Session Modification for one
// session via POST /nsmf-management/v1/sessions/{psi}/qos.
func (c *SMF) SetSessionQoS(ctx context.Context, pduSessionID, fiveQI int, reason, supi string, ambrDLMbps, ambrULMbps int) (json.RawMessage, error) {
	payload := map[string]any{"5qi": fiveQI, "reason": reason}
	if supi != "" {
		payload["supi"] = supi
	}
	if ambrDLMbps > 0 {
		payload["ambr_dl_mbps"] = ambrDLMbps
	}
	if ambrULMbps > 0 {
		payload["ambr_ul_mbps"] = ambrULMbps
	}
	body, _ := json.Marshal(payload)
	u := fmt.Sprintf("%s/nsmf-management/v1/sessions/%d/qos", c.baseURL, pduSessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("smf: build qos request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("smf: set session qos: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("smf: set session qos: status %d: %s", resp.StatusCode, respBody)
	}
	return respBody, nil
}

func (c *SMF) get(ctx context.Context, u string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("smf: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("smf: request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("smf: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("smf: status %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
