package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// TokenSource yields an OAuth2 access token for a service. *oauth2.TokenCache
// (shared/oauth2) satisfies it.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// NEF wraps the Nnef_AFsessionWithQoS service (TS 29.522 §4.4.13, §5.14). The NEF
// SBI enforces mTLS and an OAuth2 bearer token (scope nnef-afsessionwithqos).
type NEF struct {
	baseURL string
	http    *http.Client
	tokens  TokenSource
}

// NewNEF builds a NEF client. baseURL is e.g. https://nef:8011. tokens may be nil
// (no Authorization header is sent).
func NewNEF(baseURL string, httpClient *http.Client, tokens TokenSource) *NEF {
	return &NEF{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient, tokens: tokens}
}

func (c *NEF) subsPath(scsAsID string) string {
	return c.baseURL + "/3gpp-as-session-with-qos/v1/" + url.PathEscape(scsAsID) + "/subscriptions"
}

// CreateSubscription calls POST /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions
// (TS 29.522 §4.4.13.2.5). It returns the status, the body and the Location header.
func (c *NEF) CreateSubscription(ctx context.Context, scsAsID string, body any) (int, []byte, string, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, "", fmt.Errorf("nef: encode body: %w", err)
	}
	status, raw, hdr, err := c.do(ctx, http.MethodPost, c.subsPath(scsAsID), b)
	return status, raw, hdr.Get("Location"), err
}

// GetSubscription calls GET .../subscriptions/{subscriptionId}.
func (c *NEF) GetSubscription(ctx context.Context, scsAsID, subID string) (int, []byte, error) {
	status, raw, _, err := c.do(ctx, http.MethodGet, c.subsPath(scsAsID)+"/"+url.PathEscape(subID), nil)
	return status, raw, err
}

// DeleteSubscription calls DELETE .../subscriptions/{subscriptionId}.
func (c *NEF) DeleteSubscription(ctx context.Context, scsAsID, subID string) (int, []byte, error) {
	status, raw, _, err := c.do(ctx, http.MethodDelete, c.subsPath(scsAsID)+"/"+url.PathEscape(subID), nil)
	return status, raw, err
}

// do sends one request with the bearer token. A token failure is logged and the
// request still goes out, so the NEF answers 401 and the caller sees the status
// (same posture as shared/oauth2.BearerTransport).
func (c *NEF) do(ctx context.Context, method, u string, body []byte) (int, []byte, http.Header, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("nef: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.tokens != nil {
		tok, terr := c.tokens.Token(ctx)
		if terr != nil {
			slog.WarnContext(ctx, "nef: access token unavailable, sending without bearer",
				"nf", "MCP", "interface", "Nnrf", "direction", "OUT", "error", terr,
				"spec_ref", "TS 33.501 §13.4.1")
		} else if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("nef: %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, resp.Header, fmt.Errorf("nef: read body: %w", err)
	}
	return resp.StatusCode, raw, resp.Header, nil
}
