package server

// features.go - producer-side supportedFeatures negotiation of
// Nudr_DataRepository (REL19-2.7 slice 5). Ref: TS 29.500 §6.6.2, §5.2.7.2;
// TS 29.571 §5.2.2; TS 29.504 §6.1.8 (the one feature table of the API; the
// subscription-data and policy-data resources of TS 29.505 / TS 29.519 refer
// to it).
//
// Where the UDR negotiates (attribute names as in the Rel-17 OpenAPI):
//
//	GET  .../authentication-subscription  query supported-features; the
//	                                      AuthenticationSubscription response
//	                                      has no supportedFeatures attribute.
//	PATCH .../authentication-subscription query supported-features; 204.
//	GET  .../provisioned-data/am-data     query supported-features ->
//	                                      AccessAndMobilitySubscriptionData.
//	                                      supportedFeatures.
//	GET  .../provisioned-data/sm-data     query supported-features; the
//	                                      SmSubsData response has no top-level
//	                                      attribute.
//	PUT  .../context-data/amf-3gpp-access body Amf3GppAccessRegistration.
//	                                      supportedFeatures; the UDR answers
//	                                      201 with no body, so nothing is sent
//	                                      back.
//	GET  policy-data/.../ue-policy-set    query supp-feat -> UePolicySet.suppFeat.
//	PUT  policy-data/.../ue-policy-set    body UePolicySet.suppFeat; 204.
//	GET  policy-data/.../sm-data          query supp-feat -> SmPolicyData.suppFeat.
//
// Not negotiated: PATCH of ue-policy-set and sm-data (UePolicySetPatch and
// SmPolicyDataPatch have no suppFeat attribute and the PATCH operations no
// supp-feat parameter in the Rel-17 YAML), DELETE, and the resources that are
// not in the TS 29.504 / 29.505 / 29.519 YAML at all (PUT sm-data of both
// data sets, default-policies, /nudr-internal/*).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	udrsbi "github.com/francurieses/claudia-5gc/nf/udr/internal/sbi"
	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

const (
	// querySupportedFeatures is the optional query parameter of the TS 29.505
	// subscription-data resources (TS29505_Subscription_Data.yaml).
	querySupportedFeatures = "supported-features"
	// querySuppFeat is the optional query parameter of the TS 29.519
	// policy-data resources (TS29519_Policy_Data.yaml).
	querySuppFeat = "supp-feat"

	// peerUDM / peerPCF are the peer_nf_type fallbacks when the User-Agent
	// carries no valid NF type: the TS 29.504 consumers of the data sets.
	peerUDM = "UDM"
	peerPCF = "PCF"

	// attrSupportedFeatures / attrSuppFeat are the body attribute names.
	attrSupportedFeatures = "supportedFeatures"
	attrSuppFeat          = "suppFeat"
)

// SetProfile wires the release profile used for supportedFeatures
// negotiation. Must be called before Start(). Ref: TS 29.500 §6.6.2.
func (s *Server) SetProfile(p *capability.Profile) { s.profile = p }

// SetCatalog replaces the Nudr_DataRepository catalog (tests inject catalogs
// with Implemented entries); nil restores the default. Must be called before
// Start().
func (s *Server) SetCatalog(c *features.Catalog) { s.cat = c }

// catalog returns the catalog in use (the default when none was injected, so
// a Server built as a struct literal in tests behaves like New).
func (s *Server) catalog() *features.Catalog {
	if s.cat == nil {
		return udrsbi.NudrDataRepositoryCatalog()
	}
	return s.cat
}

// negotiation is the outcome of an accepted request's feature negotiation.
type negotiation struct {
	peer    string       // value as received
	present bool         // false -> logged as "absent"
	answer  string       // response attribute value; "" = omit (D1, rel17)
	set     features.Set // negotiated set
	peerNF  string
	// unparsed marks a body that could not be examined for the attribute (not
	// a JSON object): no negotiation took place, so logOK stays silent rather
	// than record features_peer=absent for it.
	unparsed bool
}

// featureCtx returns the context carrying the correlation id (request header,
// else the one the middleware put on the response).
func featureCtx(w http.ResponseWriter, r *http.Request) context.Context {
	corr := r.Header.Get("X-Correlation-Id")
	if corr == "" {
		corr = w.Header().Get("X-Correlation-Id")
	}
	return logging.WithCorrelationID(r.Context(), corr)
}

func (s *Server) negotiate(r *http.Request, peer, fallbackPeerNF string) negotiation {
	ans, set := features.Answer(s.catalog(), s.profile, peer)
	return negotiation{
		peer: peer, present: peer != "", answer: ans, set: set,
		peerNF: features.PeerNFTypeFromUserAgent(r.UserAgent(), fallbackPeerNF),
	}
}

// logOK emits the FeatureNegotiation OK record; call it only once the request
// has been accepted.
func (s *Server) logOK(w http.ResponseWriter, r *http.Request, n negotiation) {
	if n.unparsed {
		return
	}
	features.LogNegotiation(featureCtx(w, r), s.logger, features.Negotiation{
		NF:        "UDR",
		Interface: "Nudr", Direction: "IN", PeerNF: n.peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.catalog().Supported(s.profile), Peer: n.peer, PeerPresent: n.present, Negotiated: n.set,
	})
}

// reject logs the REJECT record and answers the 400 ProblemDetails with the
// invalid parameter: OPTIONAL_QUERY_PARAM_INCORRECT for a query parameter,
// INVALID_MSG_FORMAT for a body attribute (TS 29.500 Table 5.2.7.2-1).
func (s *Server) reject(w http.ResponseWriter, r *http.Request, fallbackPeerNF, peer, cause, param string, err error) {
	features.LogNegotiation(featureCtx(w, r), s.logger, features.Negotiation{
		NF:        "UDR",
		Interface: "Nudr", Direction: "IN",
		PeerNF:  features.PeerNFTypeFromUserAgent(r.UserAgent(), fallbackPeerNF),
		SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: cause,
		Local: s.catalog().Supported(s.profile), Peer: peer, PeerPresent: true,
	}, "error", err)
	s.problemParams(w, http.StatusBadRequest, cause, param+" is not a valid SupportedFeatures hex string",
		[]invalidParam{{Param: param}})
}

// queryFeatures validates the optional features query parameter and runs the
// producer side of the negotiation. It writes the 400 itself and returns
// ok=false on a non-hex value. An empty value counts as absent.
func (s *Server) queryFeatures(w http.ResponseWriter, r *http.Request, name, fallbackPeerNF string) (negotiation, bool) {
	peer := r.URL.Query().Get(name)
	if err := features.Validate(peer); err != nil {
		s.reject(w, r, fallbackPeerNF, peer, features.CauseOptionalQueryParamIncorrect, "query "+name, err)
		return negotiation{}, false
	}
	return s.negotiate(r, peer, fallbackPeerNF), true
}

// bodyFeatures extracts the optional top-level features attribute (name) from
// a JSON request body, validates it and runs the producer side. An empty body
// carries no attribute. A body that is not a JSON object is left to the legacy
// handlers (status codes unchanged) but is NOT recorded as "absent": the
// decode error is logged and no negotiation line is emitted. A non-string or
// non-hex attribute is a 400 INVALID_MSG_FORMAT with the JSON Pointer in
// invalidParams (TS 29.571 §5.2.4.6). It writes the 400 itself and returns
// ok=false in that case.
func (s *Server) bodyFeatures(w http.ResponseWriter, r *http.Request, body []byte, name, fallbackPeerNF string) (negotiation, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return s.negotiate(r, "", fallbackPeerNF), true
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		s.logger.WarnContext(featureCtx(w, r), "request body is not a JSON object: "+name+" not negotiated",
			"procedure", "FeatureNegotiationSkipped", "interface", "Nudr", "direction", "IN",
			"peer_nf_type", features.PeerNFTypeFromUserAgent(r.UserAgent(), fallbackPeerNF),
			"cause", features.CauseInvalidMsgFormat, "error", err, "spec_ref", features.SpecRefInvalid)
		n := s.negotiate(r, "", fallbackPeerNF)
		n.unparsed = true
		return n, true
	}
	raw, present := probe[name]
	if !present {
		return s.negotiate(r, "", fallbackPeerNF), true
	}
	var peer string
	if err := json.Unmarshal(raw, &peer); err != nil {
		s.reject(w, r, fallbackPeerNF, "", features.CauseInvalidMsgFormat, "/"+name, err)
		return negotiation{}, false
	}
	if err := features.Validate(peer); err != nil {
		s.reject(w, r, fallbackPeerNF, peer, features.CauseInvalidMsgFormat, "/"+name, err)
		return negotiation{}, false
	}
	return s.negotiate(r, peer, fallbackPeerNF), true
}

// readBody reads the request body bounded by features.MaxRequestBodyBytes.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes))
}

// bodyReadFailed answers a request body that could not be read: 413 for a body
// over features.MaxRequestBodyBytes (ProblemDetails without a cause, the spec
// defines none; TS 29.500 §5.2.7.1, TS 29.571 §5.2.4.1), else 400 with
// otherCause. It logs the failure.
func (s *Server) bodyReadFailed(w http.ResponseWriter, r *http.Request, procedure, otherCause string, err error) {
	var mbe *http.MaxBytesError
	status := http.StatusBadRequest
	if errors.As(err, &mbe) {
		status = http.StatusRequestEntityTooLarge
	}
	s.logger.WarnContext(featureCtx(w, r), "request body not read",
		"procedure", procedure, "interface", "Nudr", "direction", "IN", "result", "REJECT",
		"http_status", status, "error", err, "spec_ref", "TS 29.500 §5.2.7.1")
	if status == http.StatusRequestEntityTooLarge {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "detail": "request body too large"})
		return
	}
	s.problem(w, status, otherCause, err.Error())
}

// uePolicySetResponse is the GET ue-policy-set body: the stored policy
// subscription plus UePolicySet.suppFeat (TS 29.519 §5.4.2.4), omitted when
// empty so the legacy bytes are unchanged. The stored struct never holds the
// attribute, so a client value is not echoed.
//
// oapi: TS29519_Policy_Data.yaml#/components/schemas/UePolicySet
type uePolicySetResponse struct {
	*store.PolicySubscription
	SuppFeat string `json:"suppFeat,omitempty"`
}

// smPolicyDataResponse is the GET sm-data (policy) body: the stored SM policy
// data plus SmPolicyData.suppFeat (TS 29.519 §5.4.2.5).
//
// oapi: TS29519_Policy_Data.yaml#/components/schemas/SmPolicyData
type smPolicyDataResponse struct {
	*store.SmPolicyData
	SuppFeat string `json:"suppFeat,omitempty"`
}
