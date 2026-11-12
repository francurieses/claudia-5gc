package nrf

import (
	"encoding/json"
	"fmt"

	"github.com/francurieses/claudia-5gc/shared/jsoncompat"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// Method-less aliases break the recursion of the custom (Un)MarshalJSON.
type (
	nfProfileAlias    NFProfile
	nfServiceAlias    NFService
	searchResultAlias SearchResult
)

// UnmarshalJSON decodes the profile and keeps unknown top-level attributes in
// Extra. Ref: TS 29.500 §6.6.2.
func (p *NFProfile) UnmarshalJSON(b []byte) error {
	if err := jsoncompat.Unmarshal(b, (*nfProfileAlias)(p), &p.Extra); err != nil {
		return fmt.Errorf("nrf: decode NFProfile: %w", err)
	}
	return nil
}

// MarshalJSON encodes the profile followed by Extra (known fields win). With
// no Extra the output is identical to the pre-Extra encoding.
func (p NFProfile) MarshalJSON() ([]byte, error) {
	return jsoncompat.Marshal(nfProfileAlias(p), p.Extra)
}

// UnmarshalJSON decodes the service and keeps unknown attributes in Extra.
func (s *NFService) UnmarshalJSON(b []byte) error {
	if err := jsoncompat.Unmarshal(b, (*nfServiceAlias)(s), &s.Extra); err != nil {
		return fmt.Errorf("nrf: decode NFService: %w", err)
	}
	return nil
}

// MarshalJSON encodes the service followed by Extra (known fields win).
func (s NFService) MarshalJSON() ([]byte, error) {
	return jsoncompat.Marshal(nfServiceAlias(s), s.Extra)
}

// UnmarshalJSON decodes the search result and keeps unknown attributes in Extra.
//
// nrfSupportedFeatures is read as raw JSON (R13): a value of the wrong JSON
// type must not fail the whole discovery. A string lands in
// NRFSupportedFeatures; the raw value is kept for the negotiation, which logs
// a non-string as result=FAILURE.
func (r *SearchResult) UnmarshalJSON(b []byte) error {
	var w searchResultWire
	var extra map[string]json.RawMessage
	if err := jsoncompat.Unmarshal(b, &w, &extra); err != nil {
		return fmt.Errorf("nrf: decode SearchResult: %w", err)
	}
	*r = SearchResult(w.searchResultAlias)
	r.Extra = extra
	r.nrfSFRaw = w.NRFSF
	if s, err := features.RawString(w.NRFSF); err == nil {
		r.NRFSupportedFeatures = s
	}
	return nil
}

// searchResultWire shadows nrfSupportedFeatures with a raw value (the outer
// field wins over the promoted one in encoding/json).
type searchResultWire struct {
	searchResultAlias
	NRFSF json.RawMessage `json:"nrfSupportedFeatures,omitempty"`
}

// MarshalJSON encodes the search result followed by Extra.
func (r SearchResult) MarshalJSON() ([]byte, error) {
	return jsoncompat.Marshal(searchResultAlias(r), r.Extra)
}

var (
	_ json.Marshaler   = NFProfile{}
	_ json.Unmarshaler = (*NFProfile)(nil)
)
