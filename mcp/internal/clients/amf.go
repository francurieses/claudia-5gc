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

// ModifyPDUSessionQoS triggers a NW-initiated QoS modification on an active PDU session.
// Calls PATCH /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}/qos.
// Ref: TS 23.502 §4.3.3.2
func (c *AMF) ModifyPDUSessionQoS(ctx context.Context, supi string, pduSessionID int, fiveQI, ambrDLMbps, ambrULMbps int) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{
		"5qi":         fiveQI,
		"ambr_dl_mbps": ambrDLMbps,
		"ambr_ul_mbps": ambrULMbps,
	})
	u := fmt.Sprintf("%s/amf/v1/ue-contexts/%s/pdu-sessions/%d/qos",
		c.baseURL, url.PathEscape(supi), pduSessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("amf: build qos modify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("amf: qos modify: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("amf: qos modify: status %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
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
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("amf: read body: %w", err)
	}
	return body, resp.StatusCode, nil
}
