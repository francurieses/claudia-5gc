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

// SMSF wraps the SMSF internal MT-SMS trigger (/nsmsf-sms-internal/v1), which
// shares the SBI listener, so it needs the mTLS SBI client. The endpoint is an
// operator convenience, not 3GPP-defined (TS 23.502 §4.13.3 flow).
type SMSF struct {
	baseURL string
	http    *http.Client
}

// NewSMSF builds an SMSF client. baseURL is e.g. https://smsf:8009.
func NewSMSF(baseURL string, httpClient *http.Client) *SMSF {
	return &SMSF{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// SendMT calls POST /nsmsf-sms-internal/v1/ue-contexts/{supi}/mt-sms with
// {"smsPayload": <base64>}. Non-2xx codes are returned, not errors.
func (c *SMSF) SendMT(ctx context.Context, supi, payloadB64 string) (int, []byte, error) {
	b, err := json.Marshal(map[string]string{"smsPayload": payloadB64})
	if err != nil {
		return 0, nil, fmt.Errorf("smsf: encode body: %w", err)
	}
	u := c.baseURL + "/nsmsf-sms-internal/v1/ue-contexts/" + url.PathEscape(supi) + "/mt-sms"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return 0, nil, fmt.Errorf("smsf: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("smsf: mt-sms: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("smsf: read body: %w", err)
	}
	return resp.StatusCode, raw, nil
}
