package nrf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// DiscoveryPath is the Nnrf_NFDiscovery NFDiscover resource.
// Ref: TS 29.510 §5.3.2.2 (NFDiscover), §6.2.3.2.1.
const DiscoveryPath = "/nnrf-disc/v1/nf-instances"

// Query parameter names of the NFDiscover request.
// Ref: TS 29.510 §6.2.3.2.3.1 (Table 6.2.3.2.3.1-1).
const (
	// QueryTargetNFType is the mandatory target-nf-type parameter.
	QueryTargetNFType = "target-nf-type"
	// QueryRequesterNFType is the mandatory requester-nf-type parameter.
	QueryRequesterNFType = "requester-nf-type"
	// QueryServiceNames is the service-names parameter (comma-separated).
	QueryServiceNames = "service-names"
	// QuerySupportedFeatures: features required to be supported by the
	// target NF. Meaningful only with exactly one service name.
	QuerySupportedFeatures = "supported-features"
	// QueryRequesterFeatures: Nnrf_NFDiscovery API features supported by the
	// requester (not the target service's features). Conditionally present;
	// in Rel-19 it shall be included when the requester supports e.g.
	// Service-Map or Enh-NF-Discovery. The NRF answers in
	// SearchResult.nrfSupportedFeatures. Ref: TS 29.510 §6.2.3.2.3.1.
	QueryRequesterFeatures = "requester-features"
	// QueryRequesterNFInstanceID is the requester-nf-instance-id parameter.
	QueryRequesterNFInstanceID = "requester-nf-instance-id"
	// QuerySNSSAIs is the snssais parameter (JSON array of Snssai).
	QuerySNSSAIs = "snssais"
	// QueryDNN is the dnn parameter.
	QueryDNN = "dnn"
)

// maxDiscoverBody bounds the SearchResult body read from the NRF.
const maxDiscoverBody = 16 << 20

// DiscoveryQuery holds the NFDiscover query parameters.
// Ref: TS 29.510 §6.2.3.2.3.1.
type DiscoveryQuery struct {
	// TargetNFType and RequesterNFType are mandatory.
	TargetNFType    string
	RequesterNFType string
	// ServiceNames is sent comma-joined (style form, explode false).
	ServiceNames []string
	// SupportedFeatures: features the target NF service must support.
	// TS 29.510 §6.2.3.2.3.1 (Table 6.2.3.2.3.1-1, V17.16.0 and V19.8.0): "may be present only if the
	// service-names attribute is present and if it contains a single
	// service-name. It shall be ignored by the NRF otherwise." Discover
	// therefore rejects it unless len(ServiceNames) == 1.
	SupportedFeatures string
	// RequesterFeatures: Nnrf_NFDiscovery API features supported by this
	// requester (not the features of the target service). Presence is
	// conditional; in Rel-19 it shall be included when the requester supports
	// e.g. Service-Map or Enh-NF-Discovery. The NRF answers in
	// SearchResult.NRFSupportedFeatures. Ref: TS 29.510 §6.2.3.2.3.1.
	RequesterFeatures     string
	RequesterNFInstanceID string
	// SNSSAIs is sent JSON-encoded in the snssais parameter.
	SNSSAIs []SNSSAIEntry
	DNN     string
	// Extra carries other §6.2.3.2.3.1 parameters verbatim. Typed fields
	// take precedence over a same-named key in Extra.
	Extra url.Values
}

// values validates q and renders its query string parameters.
func (q DiscoveryQuery) values() (url.Values, error) {
	if q.TargetNFType == "" {
		return nil, errors.New("nrf: discover: target-nf-type is required")
	}
	if q.RequesterNFType == "" {
		return nil, errors.New("nrf: discover: requester-nf-type is required")
	}
	if err := features.Validate(q.SupportedFeatures); q.SupportedFeatures != "" && err != nil {
		return nil, fmt.Errorf("nrf: discover: supported-features: %w", err)
	}
	if err := features.Validate(q.RequesterFeatures); q.RequesterFeatures != "" && err != nil {
		return nil, fmt.Errorf("nrf: discover: requester-features: %w", err)
	}
	if q.SupportedFeatures != "" && len(q.ServiceNames) != 1 {
		return nil, errors.New("nrf: discover: supported-features requires exactly one service name")
	}
	v := url.Values{}
	v.Set(QueryTargetNFType, q.TargetNFType)
	v.Set(QueryRequesterNFType, q.RequesterNFType)
	if len(q.ServiceNames) > 0 {
		v.Set(QueryServiceNames, strings.Join(q.ServiceNames, ","))
	}
	if q.SupportedFeatures != "" {
		v.Set(QuerySupportedFeatures, q.SupportedFeatures)
	}
	if q.RequesterFeatures != "" {
		v.Set(QueryRequesterFeatures, q.RequesterFeatures)
	}
	if q.RequesterNFInstanceID != "" {
		v.Set(QueryRequesterNFInstanceID, q.RequesterNFInstanceID)
	}
	if len(q.SNSSAIs) > 0 {
		b, err := json.Marshal(q.SNSSAIs)
		if err != nil {
			return nil, fmt.Errorf("nrf: discover: encode snssais: %w", err)
		}
		v.Set(QuerySNSSAIs, string(b))
	}
	if q.DNN != "" {
		v.Set(QueryDNN, q.DNN)
	}
	for k, vals := range q.Extra {
		if _, taken := v[k]; taken {
			continue
		}
		v[k] = append([]string(nil), vals...)
	}
	return v, nil
}

// SearchResult is the NFDiscover response body.
// Ref: TS 29.510 §6.2.6.2.2 (SearchResult).
type SearchResult struct {
	// ValidityPeriod is the validity of the result in seconds (optional in
	// Rel-17, required in Rel-19); 0 when absent.
	ValidityPeriod int `json:"validityPeriod,omitempty"`
	// NFInstances are the matching NF profiles.
	NFInstances []NFProfile `json:"nfInstances"`
	// NRFSupportedFeatures is the NRF's own Nnrf_NFDiscovery supported-feature
	// bitmask, negotiated against the requester-features sent in the query
	// (TS 29.510 §6.2.6.2.2, SearchResult).
	NRFSupportedFeatures string `json:"nrfSupportedFeatures,omitempty"`

	// Negotiated is the Nnrf_NFDiscovery feature set negotiated for this
	// result: the requester-features offered in the query intersected with
	// NRFSupportedFeatures (TS 29.500 §6.6.2). Filled by Client.Discover, never
	// (un)marshalled; empty when nothing was offered or the NRF answered
	// nothing or a malformed value.
	Negotiated features.Set `json:"-"`

	// nrfSFRaw is the nrfSupportedFeatures value as received (any JSON type),
	// kept so a non-string answer can be logged instead of failing the decode.
	nrfSFRaw json.RawMessage

	// Extra holds unmodelled SearchResult attributes (searchId,
	// numNfInstComplete, preferredSearch, ...).
	Extra map[string]json.RawMessage `json:"-"`
}

// Discover performs NFDiscover: GET /nnrf-disc/v1/nf-instances.
// No request is sent if q is invalid. A non-200 status is an error.
// Ref: TS 29.510 §5.3.2.2, §6.2.3.2.3.1.
//
// Profile awareness (decision D2): when q.RequesterFeatures is empty it is
// filled with features.Request(discovery catalog, profile), so a nil or Rel-17
// profile sends no requester-features (byte-identical legacy query) and a
// Rel-19 profile sends its offered set ("0" when nothing is implemented). The
// NRF's nrfSupportedFeatures answer is negotiated with that offer
// (SearchResult.Negotiated) and logged as FeatureNegotiation; a malformed
// answer is logged result=FAILURE and does not fail the discovery.
func (c *Client) Discover(ctx context.Context, q DiscoveryQuery) (*SearchResult, error) {
	if q.RequesterFeatures == "" {
		q.RequesterFeatures = features.Request(c.discovery(), c.profile)
	}
	vals, err := q.values()
	if err != nil {
		return nil, err
	}
	u := c.baseURL + DiscoveryPath + "?" + vals.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("nrf: discover: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nrf: discover: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nrf: discover: unexpected status %d", resp.StatusCode)
	}
	var res SearchResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiscoverBody)).Decode(&res); err != nil {
		return nil, fmt.Errorf("nrf: discover: decode SearchResult: %w", err)
	}
	res.Negotiated = c.logDiscoveryNegotiation(ctx, q.RequesterNFType, q.RequesterFeatures, res.nrfSFRaw)
	c.logger.Info("NF discovery",
		"interface", "Nnrf", "direction", "OUT",
		"target_nf_type", q.TargetNFType,
		"service_names", strings.Join(q.ServiceNames, ","),
		"supported_features", q.SupportedFeatures,
		"requester_features", q.RequesterFeatures,
		"instances", len(res.NFInstances),
		"validity_period", res.ValidityPeriod,
		"result", "OK",
		"spec_ref", "TS 29.510 §5.3.2.2; query parameters §6.2.3.2.3.1",
	)
	return &res, nil
}
