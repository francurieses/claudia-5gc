package nrf

// negotiate.go - consumer-side supportedFeatures negotiation of the
// Nnrf_NFDiscovery client (REL19-2.7 slice 6b-1). Ref: TS 29.500 §6.6.2;
// TS 29.510 §6.2.3.2.3.1 (requester-features), §6.2.6.2.2 (SearchResult.
// nrfSupportedFeatures), §6.2.9 (Table 6.2.9-1); decisions D2 (consumer) of
// dev/REL19_PROGRAM.md §2.
//
// Nnrf_NFManagement (Client.Register): the Rel-17 and Rel-19 NFProfile schemas
// (TS29510_Nnrf_NFManagement.yaml) carry no attribute for the consumer's
// NFManagement feature set. "requester-features" exists only on the GET of an
// NF instance (and on the SubscriptionData body, which this client does not
// send), and NFRegister is a PUT of the profile whose only supportedFeatures
// is the per-NFService one already sent by NFService.SupportedFeatures. Hence
// Register negotiates nothing and sends nothing new.

import (
	"context"
	"encoding/json"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// peerNRF is the peer_nf_type of the Nnrf negotiation log record.
const peerNRF = "NRF"

// discoveryCatalog is the Nnrf_NFDiscovery consumer catalog (TS 29.510
// §6.2.9). The client post-processes no discovery feature (it forwards the
// query parameters and returns the profiles), so no bit is implemented and a
// rel19 requester offers "0".
var discoveryCatalog = features.MustCatalog(features.NnrfNFDiscoveryEntries()...)

// SetProfile wires the release profile that gates the supportedFeatures wire
// behaviour (decision D2): nil or Rel-17 sends no requester-features unless the
// caller sets DiscoveryQuery.RequesterFeatures itself; Rel-19 sends the offered
// set ("0" when empty). Must be called before the client is shared.
func (c *Client) SetProfile(p *capability.Profile) { c.profile = p }

// SetDiscoveryCatalog replaces the Nnrf_NFDiscovery consumer catalog (tests
// inject catalogs with implemented bits); nil restores the default.
func (c *Client) SetDiscoveryCatalog(cat *features.Catalog) { c.discCat = cat }

// discovery returns the catalog in use.
func (c *Client) discovery() *features.Catalog {
	if c.discCat == nil {
		return discoveryCatalog
	}
	return c.discCat
}

// logDiscoveryNegotiation computes the negotiated set from what was offered in
// requester-features and the NRF's nrfSupportedFeatures, and logs the consumer
// FeatureNegotiation record (nf = the requester NF type of the query, which is
// also the fivegc_procedure_total nf label; interface Nnrf, direction OUT, peer
// NRF). A malformed answer negotiates nothing and is logged result=FAILURE; the
// discovery itself is never failed (R13).
func (c *Client) logDiscoveryNegotiation(ctx context.Context, nf, offer string, raw json.RawMessage) features.Set {
	answer, err := features.RawString(raw)
	rawErr := err
	var negotiated features.Set
	if err == nil {
		negotiated, err = features.AcceptAnswer(offer, answer)
	}
	n := features.Negotiation{
		NF: nf, Interface: "Nnrf", Direction: "OUT", PeerNF: peerNRF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: c.discovery().Supported(c.profile), Peer: answer, PeerPresent: answer != "", Negotiated: negotiated,
	}
	var extra []any
	if err != nil {
		n.Result = "FAILURE"
		if rawErr != nil {
			n.Peer, n.PeerPresent = string(raw), len(raw) > 0
		}
		extra = append(extra, "error", err)
	}
	features.LogNegotiation(ctx, c.logger, n, extra...)
	return negotiated
}
