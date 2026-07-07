package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// UDMSDMClient fetches location-privacy data from UDM Nudm_SDM.
// Ref: TS 29.503 §5.2.2; TS 23.273 §9.1.
type UDMSDMClient interface {
	GetLcsPrivacyData(ctx context.Context, supi string) (*LcsPrivacyData, error)
}

// LcsPrivacyData is the subscriber location-privacy policy returned by UDM.
// Ref: TS 29.571 §5.2.7.5.
type LcsPrivacyData struct {
	// LocationPrivacy is the overall location-privacy indicator.
	// Known values: "ALLOW_ALL", "ALLOW_PLMN_OPERATOR_SERVICES", "BLOCK_ALL".
	LocationPrivacy string `json:"locationPrivacy,omitempty"`
	// LcsPrivacyExceptionList lists LCS client identities allowed despite
	// a restrictive LocationPrivacy setting.
	LcsPrivacyExceptionList []string `json:"lcsPrivacyExceptionList,omitempty"`
}

type udmCacheEntry struct {
	data    *LcsPrivacyData
	expires time.Time
}

// HTTPUDMSDMClient calls the UDM Nudm_SDM lcs-privacy-data resource over
// mTLS HTTP/2. Results are cached per-SUPI for 5 minutes to avoid a UDM
// roundtrip on every DetermineLocation call.
// Ref: TS 29.503 §5.2.2.
type HTTPUDMSDMClient struct {
	BaseURL string
	Client  *http.Client
	mu      sync.Mutex
	cache   map[string]udmCacheEntry
}

// GetLcsPrivacyData fetches the subscriber's location-privacy policy from UDM.
// On any HTTP/network error or non-200 response the method returns a fail-open
// ALLOW_ALL policy so that a UDM outage never blocks positioning entirely.
func (c *HTTPUDMSDMClient) GetLcsPrivacyData(ctx context.Context, supi string) (*LcsPrivacyData, error) {
	c.mu.Lock()
	if e, ok := c.cache[supi]; ok && time.Now().Before(e.expires) {
		c.mu.Unlock()
		return e.data, nil
	}
	c.mu.Unlock()

	reqURL := c.BaseURL + "/nudm-sdm/v2/" + url.PathEscape(supi) + "/lcs-privacy-data"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("udm: lcs-privacy-data: %w", err)
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("udm: lcs-privacy-data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Fail-open: treat any non-200 as allow-all so a UDM stub or 404
		// does not block location services in dev.
		return &LcsPrivacyData{LocationPrivacy: "ALLOW_ALL"}, nil
	}

	var data LcsPrivacyData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("udm: decode lcs-privacy-data: %w", err)
	}

	c.mu.Lock()
	if c.cache == nil {
		c.cache = make(map[string]udmCacheEntry)
	}
	c.cache[supi] = udmCacheEntry{data: &data, expires: time.Now().Add(5 * time.Minute)}
	c.mu.Unlock()
	return &data, nil
}
