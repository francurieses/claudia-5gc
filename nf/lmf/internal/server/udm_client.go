package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// UDMSDMClient fetches location-privacy data from UDM Nudm_SDM.
// Ref: TS 29.503 §5.2.2; TS 23.273 §9.1.
type UDMSDMClient interface {
	GetLcsPrivacyData(ctx context.Context, supi string) (*LcsPrivacyData, error)
}

// LcsPrivacyData is the LMF's internal location-privacy policy record, filled
// from the Nudm_SDM lcs-privacy-data answer by lcsPrivacyWire /
// legacyLcsPrivacyWire (never serialised on a 3GPP wire).
//
// oapi: none internal LMF policy record; wire shapes are lcsPrivacyWire (TS 29.503 LcsPrivacyData) and legacyLcsPrivacyWire
type LcsPrivacyData struct {
	// LocationPrivacy is the overall location-privacy indicator.
	// Known values: "ALLOW_ALL", "ALLOW_PLMN_OPERATOR_SERVICES", "BLOCK_ALL".
	LocationPrivacy string
	// LcsPrivacyExceptionList lists LCS client identities allowed despite
	// a restrictive LocationPrivacy setting.
	LcsPrivacyExceptionList []string
}

// lcsPrivacyWire is the consumer view of the TS 29.503 LcsPrivacyData answer.
// Only lpi.locationPrivacyInd is consumed: LOCATION_DISALLOWED maps to
// BLOCK_ALL and LOCATION_ALLOWED to ALLOW_ALL; unknown values (the enumeration
// is anyOf[enum, string], TS 29.501 §5.3.12) are ignored.
//
// oapi: TS29503_Nudm_SDM.yaml#/components/schemas/LcsPrivacyData
type lcsPrivacyWire struct {
	Lpi *lpiWire `json:"lpi,omitempty"`
}

// lpiWire is the Lpi data type. Ref: TS 29.503 (Lpi).
//
// oapi: TS29503_Nudm_SDM.yaml#/components/schemas/Lpi
type lpiWire struct {
	LocationPrivacyInd string `json:"locationPrivacyInd"`
}

// legacyLcsPrivacyWire is the answer shape of this project's UDM stub
// (Rel-17 baseline), decoded in every profile next to the spec shape.
//
// oapi: none legacy project UDM stub answer shape of LcsPrivacyData, see lcsPrivacyWire
type legacyLcsPrivacyWire struct {
	LocationPrivacy         string   `json:"locationPrivacy,omitempty"`
	LcsPrivacyExceptionList []string `json:"lcsPrivacyExceptionList,omitempty"`
}

// decodeLcsPrivacy decodes a lcs-privacy-data body in either shape (TS 29.500
// §6.6.2 tolerant reader): the spec attribute wins when present and known, the
// legacy attributes fill the rest. Each view is decoded independently so a type
// clash in one cannot fail the other; an undecodable object in both is an error.
func decodeLcsPrivacy(body []byte) (*LcsPrivacyData, error) {
	// {} and null carry no member at all: not a usable answer (unknown members
	// and unknown enum values alone stay tolerated, TS 29.500 §6.6.2).
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err == nil && len(members) == 0 {
		return nil, errors.New("lmf: decode lcs-privacy-data: empty body")
	}
	var spec lcsPrivacyWire
	specErr := json.Unmarshal(body, &spec)
	if specErr != nil {
		spec = lcsPrivacyWire{}
	}
	var legacy legacyLcsPrivacyWire
	legacyErr := json.Unmarshal(body, &legacy)
	if legacyErr != nil {
		legacy = legacyLcsPrivacyWire{}
	}
	if (specErr != nil && legacyErr != nil) || (legacyErr != nil && spec.Lpi == nil) {
		return nil, fmt.Errorf("lmf: decode lcs-privacy-data: %w", errors.Join(specErr, legacyErr))
	}
	out := &LcsPrivacyData{LocationPrivacy: legacy.LocationPrivacy, LcsPrivacyExceptionList: legacy.LcsPrivacyExceptionList}
	if spec.Lpi != nil {
		switch spec.Lpi.LocationPrivacyInd {
		case "LOCATION_DISALLOWED":
			out.LocationPrivacy = "BLOCK_ALL"
		case "LOCATION_ALLOWED":
			out.LocationPrivacy = "ALLOW_ALL"
		}
	}
	return out, nil
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

	raw, err := io.ReadAll(io.LimitReader(resp.Body, features.MaxRequestBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("udm: read lcs-privacy-data: %w", err)
	}
	if int64(len(raw)) > features.MaxRequestBodyBytes {
		return nil, fmt.Errorf("udm: read lcs-privacy-data: body exceeds %d bytes", features.MaxRequestBodyBytes)
	}
	dp, err := decodeLcsPrivacy(raw)
	if err != nil {
		return nil, fmt.Errorf("udm: decode lcs-privacy-data: %w", err)
	}
	data := *dp

	c.mu.Lock()
	if c.cache == nil {
		c.cache = make(map[string]udmCacheEntry)
	}
	c.cache[supi] = udmCacheEntry{data: &data, expires: time.Now().Add(5 * time.Minute)}
	c.mu.Unlock()
	return &data, nil
}
