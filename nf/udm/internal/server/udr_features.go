package server

// udr_features.go - consumer-side supportedFeatures negotiation of the UDM's
// Nudr_DataRepository client (REL19-2.7 slice 6b-2). Ref: TS 29.500 §6.6.2;
// TS 29.504 §6.1.8; TS 29.505 (TS29505_Subscription_Data.yaml, Rel-17);
// decision D2 of dev/REL19_PROGRAM.md §2.
//
// Where the UDM negotiates with the UDR (names as in the OpenAPI):
//
//	GET   .../authentication-subscription query supported-features; the
//	      AuthenticationSubscription schema has no supportedFeatures attribute,
//	      so there is no answer (rule R12).
//	PATCH .../authentication-subscription query supported-features; the body is
//	      a patch document and the 204 has no body: the parameter is sent, no
//	      answer exists and nothing is negotiated or logged.
//	GET   .../provisioned-data/am-data    query supported-features ->
//	      AccessAndMobilitySubscriptionData.supportedFeatures.
//	GET   .../provisioned-data/sm-data    query supported-features; the 200 body
//	      has no top-level supportedFeatures attribute (rule R12).
//
// The query parameter is optional in the YAML for every operation, so it is
// sent under the Rel-19 profile only (rel17 keeps the legacy request bytes).
// This set is the Nudr_DataRepository set of the UDM-UDR association; it is
// independent of the Nudm_SDM set negotiated with the AMF for the same UE.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/url"

	udmsbi "github.com/francurieses/claudia-5gc/nf/udm/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

const (
	// udrQuerySupportedFeatures is the optional supported-features query
	// parameter of the Nudr_DataRepository operations used by the UDM.
	// Ref: TS29505_Subscription_Data.yaml (Rel-17 lines 37, 71, 737, 887).
	udrQuerySupportedFeatures = "supported-features"
	// udrPeerNF is the peer_nf_type of the Nudr negotiation record.
	udrPeerNF = "UDR"
)

// WithFeatures wires the release profile and the base logger used for the
// Nudr_DataRepository supportedFeatures negotiation. A nil profile is Rel-17
// (no supported-features sent). Must be called before the client is shared.
func (c *HTTPUDRClient) WithFeatures(p *capability.Profile, logger *slog.Logger) *HTTPUDRClient {
	c.profile = p
	c.logger = logger
	return c
}

// SetCatalog replaces the Nudr_DataRepository consumer catalog (tests inject
// catalogs with implemented bits); nil restores the default.
func (c *HTTPUDRClient) SetCatalog(cat *features.Catalog) { c.cat = cat }

func (c *HTTPUDRClient) catalog() *features.Catalog {
	if c.cat == nil {
		return udmsbi.NudrDataRepositoryCatalog()
	}
	return c.cat
}

// offer is the supported-features value to send: "" under rel17 or no profile
// (the parameter is omitted), the implemented set ("0" when empty) under rel19.
func (c *HTTPUDRClient) offer() string { return features.Request(c.catalog(), c.profile) }

// withOffer appends the supported-features query parameter to rawURL when the
// profile offers one, and returns the offer.
func (c *HTTPUDRClient) withOffer(rawURL string) (string, string) {
	offer := c.offer()
	if offer == "" {
		return rawURL, ""
	}
	return rawURL + "?" + url.Values{udrQuerySupportedFeatures: {offer}}.Encode(), offer
}

// negotiate computes the features negotiated with the UDR from the offer and
// the answer attribute (raw JSON, so a value of the wrong type is a negotiation
// failure and not a decode failure of the UDR response) and logs the consumer
// FeatureNegotiation record (interface Nudr, direction OUT, peer UDR). A
// malformed answer negotiates nothing and is logged result=FAILURE; the
// procedure is never failed (R13). features.AcceptAnswer validates the answer
// even when the offer is empty (R14).
func (c *HTTPUDRClient) negotiate(ctx context.Context, supi, offer string, raw json.RawMessage) features.Set {
	answer, rawErr := features.RawString(raw)
	var negotiated features.Set
	err := rawErr
	if err == nil {
		negotiated, err = features.AcceptAnswer(offer, answer)
	}
	n := features.Negotiation{
		NF:        "UDM",
		Interface: "Nudr", Direction: "OUT", PeerNF: udrPeerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: c.catalog().Supported(c.profile), Peer: answer, PeerPresent: answer != "", Negotiated: negotiated,
	}
	var extra []any
	if err != nil {
		n.Result = "FAILURE"
		negotiated = features.Set{}
		n.Negotiated = negotiated
		if rawErr != nil {
			n.Peer, n.PeerPresent = string(raw), len(raw) > 0
		}
		extra = append(extra, "error", err)
	}
	features.LogNegotiation(logging.WithSUPI(ctx, supi), c.logger, n, extra...)
	return negotiated
}
