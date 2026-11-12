package server

// udr_features.go - consumer-side supportedFeatures negotiation of the PCF's
// Nudr_DataRepository client (REL19-2.7 slice 6b-1). Ref: TS 29.500 §6.6.2;
// TS 29.504 §6.1.8; TS 29.519 (TS29519_Policy_Data.yaml, Rel-17 and Rel-19);
// decision D2 of dev/REL19_PROGRAM.md §2.
//
// Where the PCF negotiates with the UDR (attribute names as in the OpenAPI):
//
//	GET policy-data/{ueId}/ue-policy-set  query supp-feat -> UePolicySet.suppFeat
//	GET policy-data/{ueId}/sm-data        query supp-feat -> SmPolicyData.suppFeat
//
// Both query parameters are optional in the YAML, so they are sent under the
// Rel-19 profile only (rel17 keeps the legacy request bytes). PUT sm-data is
// not negotiated: it is not an operation of the TS 29.519 YAML (only
// sm-data/{usageMonId} has a PUT), SmPolicyData.suppFeat is therefore not
// offered in the body, and types.SmPolicyData has no suppFeat field.

import (
	"context"
	"encoding/json"
	"log/slog"

	pcfsbi "github.com/francurieses/claudia-5gc/nf/pcf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

const (
	// udrQuerySuppFeat is the optional supp-feat query parameter of the
	// ReadUEPolicySet and ReadSessionManagementPolicyData operations.
	// Ref: TS29519_Policy_Data.yaml (Rel-17 lines 159 and 355).
	udrQuerySuppFeat = "supp-feat"
	// udrPeerNF is the peer_nf_type of the Nudr negotiation record.
	udrPeerNF = "UDR"
)

// WithFeatures wires the release profile and the base logger used for the
// Nudr_DataRepository supportedFeatures negotiation. A nil profile is Rel-17
// (no supp-feat sent). Must be called before the client is shared.
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
		return pcfsbi.NudrDataRepositoryCatalog()
	}
	return c.cat
}

// offer is the supp-feat value to send: "" under rel17 or no profile (the
// parameter is omitted), the implemented set ("0" when empty) under rel19.
func (c *HTTPUDRClient) offer() string { return features.Request(c.catalog(), c.profile) }

// suppFeatString extracts the string value of a suppFeat attribute received
// as raw JSON: absent -> "", a non-string value is an error (schema
// violation, TS 29.571 §5.2.2).
func suppFeatString(raw json.RawMessage) (string, error) { return features.RawString(raw) }

// negotiate computes the features negotiated with the UDR from the offer and
// the response's suppFeat and logs the consumer FeatureNegotiation record
// (interface Nudr, direction OUT, peer UDR). A malformed answer negotiates
// nothing and is logged result=FAILURE; the procedure is never failed (R13).
// features.AcceptAnswer validates the answer even when the offer is empty (R14).
func (c *HTTPUDRClient) negotiate(ctx context.Context, supi, offer string, raw json.RawMessage) features.Set {
	answer, err := suppFeatString(raw)
	var negotiated features.Set
	if err == nil {
		negotiated, err = features.AcceptAnswer(offer, answer)
	}
	n := features.Negotiation{
		NF:        "PCF",
		Interface: "Nudr", Direction: "OUT", PeerNF: udrPeerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: c.catalog().Supported(c.profile), Peer: answer, PeerPresent: answer != "", Negotiated: negotiated,
	}
	if err != nil {
		n.Result = "FAILURE"
		n.Peer, n.PeerPresent = string(raw), len(raw) > 0
		features.LogNegotiation(logging.WithSUPI(ctx, supi), c.logger, n, "error", err)
		return features.Set{}
	}
	features.LogNegotiation(logging.WithSUPI(ctx, supi), c.logger, n)
	return negotiated
}
