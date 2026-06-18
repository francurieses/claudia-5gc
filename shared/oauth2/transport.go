package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// TokenResponse is the NRF /oauth2/v1/token response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// TokenCache fetches and caches OAuth2 access tokens from the NRF.
// It automatically refreshes before expiry.
type TokenCache struct {
	mu          sync.Mutex
	http        *http.Client
	tokenURL    string
	nfInstanceID string
	scope       string
	secret      []byte // used for local validation only
	token       string
	expiresAt   time.Time
}

// NewTokenCache creates a token cache for the given NRF token endpoint.
func NewTokenCache(httpClient *http.Client, tokenURL, nfInstanceID, scope string) *TokenCache {
	return &TokenCache{
		http:         httpClient,
		tokenURL:     tokenURL,
		nfInstanceID: nfInstanceID,
		scope:        scope,
	}
}

// Token returns a valid access token, refreshing if necessary.
func (c *TokenCache) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiresAt.Add(-30*time.Second)) {
		return c.token, nil
	}
	return c.refresh(ctx)
}

func (c *TokenCache) refresh(ctx context.Context) (string, error) {
	form := url.Values{
		"grant_type":   {"client_credentials"},
		"nfInstanceId": {c.nfInstanceID},
		"scope":        {c.scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL,
		bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("oauth2: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth2: token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oauth2: token endpoint status %d", resp.StatusCode)
	}
	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("oauth2: decode token response: %w", err)
	}
	c.token = tr.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.token, nil
}

// BearerTransport is an http.RoundTripper that attaches an OAuth2 Bearer token
// to every outgoing request, fetching/refreshing via TokenCache.
type BearerTransport struct {
	Base  http.RoundTripper
	Cache *TokenCache
}

func (t *BearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.Cache.Token(req.Context())
	if err != nil {
		// Proceed without token if NRF is temporarily unavailable.
		// The producer will reject with 401 if OAuth2 is enforced.
		_ = err
	}
	if token != "" {
		// Clone the request to avoid mutating the caller's copy.
		cloned := req.Clone(req.Context())
		cloned.Header.Set("Authorization", "Bearer "+token)
		return t.Base.RoundTrip(cloned)
	}
	return t.Base.RoundTrip(req)
}

// NewBearerClient wraps an http.Client with OAuth2 Bearer token injection.
func NewBearerClient(base *http.Client, cache *TokenCache) *http.Client {
	return &http.Client{
		Transport: &BearerTransport{
			Base:  base.Transport,
			Cache: cache,
		},
		Timeout: base.Timeout,
	}
}
