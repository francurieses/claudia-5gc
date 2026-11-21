package server

// shape.go - rel19 wire-shape helpers of the NRF (NRF-003): Service-Map
// conversion between "nfServices" and "nfServiceList", Inter-Plmn-Fqdn
// stripping, SubscriptionData validityTime and the 400 ProblemDetails switch.
// Everything here works on raw JSON (json.RawMessage per attribute) so that
// attributes this NRF does not model survive. Ref: TS 29.510 §6.1.6.2.2
// NOTE 15, §6.2.6.2.3 NOTE 10, §6.1.6.2.16, §6.1.9 Table 6.1.9-1.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/francurieses/claudia-5gc/nf/nrf/internal/registry"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

const (
	// featureNFMServiceMap is Nnrf_NFManagement feature 1, Service-Map
	// (TS 29.510 Table 6.1.9-1).
	featureNFMServiceMap = 1
	// featureNFMInterPlmnFqdn is Nnrf_NFManagement feature 3, Inter-Plmn-Fqdn
	// (TS 29.510 Table 6.1.9-1).
	featureNFMInterPlmnFqdn = 3
	// featureDiscServiceMap is Nnrf_NFDiscovery feature 6, Service-Map
	// (TS 29.510 Table 6.2.9-1).
	featureDiscServiceMap = 6

	// DefaultSubscriptionValidity is the validityTime the NRF assigns to an
	// NFStatusSubscribe that carries none (or a time not in the future).
	// TS 29.510 §6.1.6.2.16 requires validityTime "always" to be sent back
	// but leaves the value to the NRF; 24 h is this NRF's local policy.
	DefaultSubscriptionValidity = 24 * time.Hour

	keyNFServices     = "nfServices"
	keyNFServiceList  = "nfServiceList"
	keyInterPlmnFqdn  = "interPlmnFqdn"
	keyReqPlmnList    = "reqPlmnList"
	keyValidityTime   = "validityTime"
	keySubscriptionID = "subscriptionId"
	keyNrfSupported   = "nrfSupportedFeatures"
)

// specLiteral reports whether the rel19 wire-shape fixes apply.
func (s *Server) specLiteral() bool { return features.SpecLiteral(s.profile) }

// shapeOpts selects the transformations applied to an NFProfile JSON object.
type shapeOpts struct {
	// serviceMap: emit "nfServiceList" (true) or "nfServices" (false).
	serviceMap bool
	// stripInterPlmnFqdn removes "interPlmnFqdn" at profile and service level.
	stripInterPlmnFqdn bool
}

// shapeProfile applies opts to one NFProfile JSON object. It returns the new
// JSON and the number of array services skipped because they carry no
// serviceInstanceId and so cannot be keyed.
func shapeProfile(in []byte, o shapeOpts) (out []byte, skipped int, err error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(in, &obj); err != nil {
		return nil, 0, fmt.Errorf("nrf: shape profile: %w", err)
	}
	if obj == nil {
		return nil, 0, fmt.Errorf("nrf: shape profile: not an object")
	}
	if skipped, err = convertServices(obj, o.serviceMap); err != nil {
		return nil, 0, err
	}
	if o.stripInterPlmnFqdn {
		unparsed, err := stripFqdn(obj)
		if err != nil {
			return nil, 0, err
		}
		skipped += unparsed
	}
	out, err = json.Marshal(obj)
	if err != nil {
		return nil, 0, fmt.Errorf("nrf: shape profile: %w", err)
	}
	return out, skipped, nil
}

// isEmptyJSON reports an absent / null / empty-container attribute.
func isEmptyJSON(v json.RawMessage) bool {
	switch string(v) {
	case "", "null", "[]", "{}":
		return true
	}
	return false
}

// convertServices makes obj carry exactly one of nfServiceList (wantMap) or
// nfServices, never both (TS 29.510 §6.1.6.2.2 NOTE 15). When both were
// registered the attribute of the target shape wins.
func convertServices(obj map[string]json.RawMessage, wantMap bool) (skipped int, err error) {
	arr, hasArr := obj[keyNFServices]
	lst, hasLst := obj[keyNFServiceList]
	hasArr = hasArr && !isEmptyJSON(arr)
	hasLst = hasLst && !isEmptyJSON(lst)
	if wantMap {
		delete(obj, keyNFServices)
		if hasLst || !hasArr {
			if !hasLst {
				delete(obj, keyNFServiceList)
			}
			return 0, nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(arr, &items); err != nil {
			return 0, fmt.Errorf("nrf: shape profile: nfServices: %w", err)
		}
		m := make(map[string]json.RawMessage, len(items))
		for _, it := range items {
			var id struct {
				ID string `json:"serviceInstanceId"`
			}
			if err := json.Unmarshal(it, &id); err != nil || id.ID == "" {
				skipped++
				continue
			}
			m[id.ID] = it
		}
		b, err := json.Marshal(m)
		if err != nil {
			return 0, fmt.Errorf("nrf: shape profile: %w", err)
		}
		obj[keyNFServiceList] = b
		return skipped, nil
	}
	delete(obj, keyNFServiceList)
	if hasArr || !hasLst {
		if !hasArr {
			delete(obj, keyNFServices)
		}
		return 0, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(lst, &m); err != nil {
		return 0, fmt.Errorf("nrf: shape profile: nfServiceList: %w", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	items := make([]json.RawMessage, 0, len(keys))
	for _, k := range keys {
		items = append(items, m[k])
	}
	b, err := json.Marshal(items)
	if err != nil {
		return 0, fmt.Errorf("nrf: shape profile: %w", err)
	}
	obj[keyNFServices] = b
	return 0, nil
}

// stripFqdn deletes interPlmnFqdn from the profile and from every NFService
// of both service attributes (TS 29.510 §6.1.6.2.2 / §6.1.6.2.3).
//
// It returns the number of services that were not JSON objects and so were
// left untouched (reported by the caller as dropped/unparseable).
func stripFqdn(obj map[string]json.RawMessage) (unparsed int, err error) {
	delete(obj, keyInterPlmnFqdn)
	strip := func(svc json.RawMessage) (json.RawMessage, error) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(svc, &m); err != nil || m == nil {
			unparsed++
			return svc, nil // not an object: leave untouched
		}
		if _, ok := m[keyInterPlmnFqdn]; !ok {
			return svc, nil
		}
		delete(m, keyInterPlmnFqdn)
		return json.Marshal(m)
	}
	if v, ok := obj[keyNFServices]; ok && !isEmptyJSON(v) {
		var items []json.RawMessage
		if err := json.Unmarshal(v, &items); err != nil {
			return 0, fmt.Errorf("nrf: strip interPlmnFqdn: nfServices: %w", err)
		}
		for i := range items {
			n, err := strip(items[i])
			if err != nil {
				return 0, fmt.Errorf("nrf: strip interPlmnFqdn: %w", err)
			}
			items[i] = n
		}
		b, err := json.Marshal(items)
		if err != nil {
			return 0, fmt.Errorf("nrf: strip interPlmnFqdn: %w", err)
		}
		obj[keyNFServices] = b
	}
	if v, ok := obj[keyNFServiceList]; ok && !isEmptyJSON(v) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(v, &m); err != nil {
			return 0, fmt.Errorf("nrf: strip interPlmnFqdn: nfServiceList: %w", err)
		}
		for k := range m {
			n, err := strip(m[k])
			if err != nil {
				return 0, fmt.Errorf("nrf: strip interPlmnFqdn: %w", err)
			}
			m[k] = n
		}
		b, err := json.Marshal(m)
		if err != nil {
			return 0, fmt.Errorf("nrf: strip interPlmnFqdn: %w", err)
		}
		obj[keyNFServiceList] = b
	}
	return unparsed, nil
}

// shapedProfile marshals p (merged raw JSON) and applies o.
func shapedProfile(p *registry.NFProfile, o shapeOpts) (json.RawMessage, int, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, 0, fmt.Errorf("nrf: marshal profile: %w", err)
	}
	out, skipped, err := shapeProfile(b, o)
	return out, skipped, err
}

// subscriptionValidity returns the validityTime to answer and store: the
// requested value when it is a valid DateTime in the future, else now plus
// DefaultSubscriptionValidity (TS 29.510 §6.1.6.2.16: always sent back).
func subscriptionValidity(requested string, now time.Time) (wire string, t time.Time) {
	if requested != "" {
		if rt, err := time.Parse(time.RFC3339, requested); err == nil && rt.After(now) {
			return requested, rt
		}
	}
	t = now.Add(DefaultSubscriptionValidity).UTC()
	return t.Format(time.RFC3339), t
}

// validDateTime reports whether v parses as an RFC 3339 DateTime
// (TS 29.571 §5.2.2).
func validDateTime(v string) bool {
	_, err := time.Parse(time.RFC3339, v)
	return err == nil
}

// intraPLMN reports whether a subscriber is intra-PLMN: reqPlmnList absent /
// empty, or at least one entry equal to the NRF's PLMN. TS 29.510 §6.1.6.2.16
// ("reqPlmnList shall be included when subscribing to NF services in a
// different PLMN"). Design rule: docs/procedures/NrfNegotiatedFeatures.md §7.2.
// A malformed list returns an error (the caller rejects; never fails open).
func intraPLMN(reqPlmnList json.RawMessage, mcc, mnc string) (bool, error) {
	if isEmptyJSON(reqPlmnList) {
		return true, nil
	}
	var l []registry.PLMN
	if err := json.Unmarshal(reqPlmnList, &l); err != nil {
		return true, err
	}
	if len(l) == 0 {
		return true, nil
	}
	for _, p := range l {
		if p.MCC == mcc && p.MNC == mnc {
			return true, nil
		}
	}
	return false, nil
}

// badRequest answers 400. Under the rel19 profile it is an
// application/problem+json ProblemDetails (TS 29.500 §5.2.7.2, cause from
// Table 5.2.7.2-1, optional InvalidParam per TS 29.571 §5.2.4.6); under rel17
// it is the frozen text/plain legacy body.
func (s *Server) badRequest(w http.ResponseWriter, cause, legacyText, detail, param string) {
	if !s.specLiteral() {
		http.Error(w, legacyText, http.StatusBadRequest)
		return
	}
	if param == "" {
		problem(w, http.StatusBadRequest, cause, detail)
		return
	}
	problemParam(w, http.StatusBadRequest, cause, detail, param, detail)
}
