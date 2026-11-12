package server

// features.go - producer-side supportedFeatures negotiation of the NRF
// (REL19-2.7 slice 5). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2;
// TS 29.510 §6.1.9 (Nnrf_NFManagement), §6.2.9 (Nnrf_NFDiscovery).
//
// Where the NRF negotiates (attribute names as in the Rel-17 OpenAPI):
//
//   - NFStatusSubscribe, POST /subscriptions: SubscriptionData.requesterFeatures
//     (request, writeOnly) -> SubscriptionData.nrfSupportedFeatures (response,
//     readOnly). The negotiated set is kept on the Subscription.
//   - NFDiscover, GET /nf-instances: query "requester-features" ->
//     SearchResult.nrfSupportedFeatures.
//   - NFProfileRetrieve, GET /nf-instances/{id}: query "requester-features";
//     the NFProfile response schema has no supportedFeatures attribute at the
//     top level, so there is nothing to answer: the value is validated and the
//     negotiation logged.
//   - NFRegister / NFUpdate: NFProfile has no top-level supportedFeatures
//     (only NFService.supportedFeatures, the registrant's own advertised set,
//     stored verbatim), so no negotiation takes place.
//   - Nnrf_AccessToken: no supportedFeatures attribute in the request or the
//     response.
//
// The "supported-features" discovery query parameter is a FILTER on the target
// service's features (see registry.matchSupportedFeatures), not a negotiation.

import (
	"context"
	"encoding/json"
	"net/http"

	nrfsbi "github.com/francurieses/claudia-5gc/nf/nrf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

const (
	// queryRequesterFeatures is the optional query parameter in which the
	// consumer indicates its features (TS 29.510 Table 6.1.3.3.3.1-1 for the
	// NF instance retrieval, Table 6.2.3.2.3.1-1 for discovery).
	queryRequesterFeatures = "requester-features"
	// paramQueryRequesterFeatures is the invalidParams "param" of a bad
	// requester-features query parameter (TS 29.571 §5.2.4.6).
	paramQueryRequesterFeatures = "query " + queryRequesterFeatures
	// bodyRequesterFeatures is the SubscriptionData attribute carrying the
	// consumer's Nnrf_NFManagement features (TS 29.510 §6.1.6.2.16).
	bodyRequesterFeatures = "requesterFeatures"
	// paramRequesterFeatures is its JSON Pointer for invalidParams
	// (TS 29.571 §5.2.4.6).
	paramRequesterFeatures = "/" + bodyRequesterFeatures
)

// SetProfile wires the release profile used for supportedFeatures
// negotiation. Must be called before Start(). Ref: TS 29.500 §6.6.2.
func (s *Server) SetProfile(p *capability.Profile) { s.profile = p }

// SetCatalogs replaces the Nnrf_NFManagement and Nnrf_NFDiscovery catalogs
// (tests inject catalogs with Implemented entries); nil restores the default.
// Must be called before Start().
func (s *Server) SetCatalogs(mgmt, disc *features.Catalog) { s.mgmtCat, s.discCat = mgmt, disc }

func (s *Server) mgmtCatalog() *features.Catalog {
	if s.mgmtCat == nil {
		return nrfsbi.NnrfNFManagementCatalog()
	}
	return s.mgmtCat
}

func (s *Server) discCatalog() *features.Catalog {
	if s.discCat == nil {
		return nrfsbi.NnrfNFDiscoveryCatalog()
	}
	return s.discCat
}

// featureCtx returns the request context carrying the correlation id.
func featureCtx(r *http.Request) context.Context {
	return logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
}

// peerNFType returns the consumer NF type from the User-Agent header
// (TS 29.500 §5.2.2.2), else hint when it is a valid NFType token, else
// "UNKNOWN".
func peerNFType(r *http.Request, hint string) string {
	if !features.ValidNFType(hint) {
		hint = "UNKNOWN"
	}
	return features.PeerNFTypeFromUserAgent(r.UserAgent(), hint)
}

// negotiation is the outcome of an accepted request's feature negotiation.
type negotiation struct {
	peer    string       // value as received
	present bool         // false -> logged as "absent"
	answer  string       // nrfSupportedFeatures value; "" = omit (D1, rel17)
	set     features.Set // negotiated set (intersection)
	local   features.Set
}

// negotiate runs the producer side for peer (decision D1): the attribute is
// absent under rel17 when the request carried no value and present under
// rel19 (and whenever the request carried a value, under both profiles).
//
// The NRF-specific twist: SubscriptionData.nrfSupportedFeatures
// (TS 29.510 §6.1.6.2.16, Table 6.1.6.2.16-1) and
// SearchResult.nrfSupportedFeatures (§6.2.6.2.2, Table 6.2.6.2.2-1) are
// defined as the "Features supported by the NRF", separate from the
// requester's requesterFeatures / requester-features. That API-specific
// definition overrides the generic intersection of TS 29.500 §6.6.2, so the
// attribute carries the NRF's own set, while the intersection stays in
// negotiation.set (Subscription.Features and the log's features_negotiated).
// The caller has already validated peer.
func (s *Server) negotiate(cat *features.Catalog, peer string) negotiation {
	ans, set := features.Answer(cat, s.profile, peer)
	local := cat.Supported(s.profile)
	if ans != "" {
		ans = local.String()
	}
	return negotiation{peer: peer, present: peer != "", answer: ans, set: set, local: local}
}

// logOK emits the FeatureNegotiation OK record; call it only once the request
// has been accepted.
func (s *Server) logOK(r *http.Request, iface, peerNF string, n negotiation) {
	features.LogNegotiation(featureCtx(r), s.logger, features.Negotiation{
		NF:        "NRF",
		Interface: iface, Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: n.local, Peer: n.peer, PeerPresent: n.present, Negotiated: n.set,
	})
}

// rejectBadFeatures logs the REJECT record and answers 400 for a malformed
// supportedFeatures value: OPTIONAL_QUERY_PARAM_INCORRECT for a query
// parameter, INVALID_MSG_FORMAT for a body attribute (TS 29.500 §5.2.7.2,
// Table 5.2.7.2-1).
func (s *Server) rejectBadFeatures(w http.ResponseWriter, r *http.Request, iface, peerNF string,
	cat *features.Catalog, peer, cause, param string, err error) {
	features.LogNegotiation(featureCtx(r), s.logger, features.Negotiation{
		NF:        "NRF",
		Interface: iface, Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: cause,
		Local: cat.Supported(s.profile), Peer: peer, PeerPresent: true,
	}, "error", err)
	problemParam(w, http.StatusBadRequest, cause,
		param+" is not a valid SupportedFeatures hex string", param, err.Error())
}

// payloadTooLarge answers a body over features.MaxRequestBodyBytes with 413
// and a ProblemDetails without a cause (the spec defines no 413 cause), after
// logging one WARN record. Ref: TS 29.500 §5.2.7.1; TS 29.571 §5.2.4.1.
func (s *Server) payloadTooLarge(w http.ResponseWriter, r *http.Request, procedure string) {
	s.logger.WarnContext(featureCtx(r), "request body too large",
		"procedure", procedure, "correlation_id", r.Header.Get("X-Correlation-Id"),
		"interface", "Nnrf", "direction", "IN", "result", "REJECT", "cause", "PAYLOAD_TOO_LARGE",
		"spec_ref", "TS 29.500 §5.2.7.1")
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusRequestEntityTooLarge,
		"detail": "request body too large",
	}); err != nil {
		s.logger.Debug("write 413 problem details", "error", err)
	}
}
