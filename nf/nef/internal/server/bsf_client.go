// Package server implements the NEF Nnef SBI server and its outbound client stubs.
// This file provides the BSF client used by the NEF to discover the serving PCF
// for a given UE IP address over Nbsf_Management_Discovery.
//
// Ref: TS 29.521 §5.2.2.4 (Nbsf_Management_Discovery)
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	nefsbi "github.com/francurieses/claudia-5gc/nf/nef/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// maxBSFBodyBytes bounds the PcfBinding response decode.
const maxBSFBodyBytes = 1 << 20

// ErrPcfBindingNotFound is returned when the BSF has no binding for the queried UE IP.
// The NEF maps this sentinel to a northbound 404 PCF_BINDING_NOT_FOUND.
//
// Ref: TS 29.521 §5.2.2.4.4 (discovery miss)
var ErrPcfBindingNotFound = errors.New("nef: bsf: no PCF binding for the UE IP")

// PcfBinding holds the fields of a TS 29.521 §6.2.6 PcfBinding that the NEF
// consumes from the BSF Discovery response. Only the routing + scoping subset
// is used; the full BSF store record has additional fields.
//
// oapi: TS29521_Nbsf_Management.yaml#/components/schemas/PcfBinding
type PcfBinding struct {
	// BindingID is the BSF-assigned identifier (for logging only in NEF).
	// oapi-ext: PcfBinding has no id attribute (the bindingId is the last segment of the Location URI returned by Register, TS 29.521 §4.2.2.2); this project's BSF echoes it in the discovery answer, the NEF only logs it and tolerates its absence.
	BindingID string `json:"bindingId,omitempty"`
	// PcfFqdn is the primary PCF SBI FQDN. Preferred over pcfIpEndPoints.
	// Ref: TS 29.521 §6.2.6
	PcfFqdn string `json:"pcfFqdn,omitempty"`
	// PcfIpEndPoints are fallback PCF endpoints when PcfFqdn is absent.
	PcfIpEndPoints []PcfIpEndPoint `json:"pcfIpEndPoints,omitempty"`
	// PcfId is the NF instance ID of the serving PCF for NRF correlation / logging.
	PcfId string `json:"pcfId,omitempty"`
	// Dnn is the PDU session Data Network Name; passed through to the PCF app-session.
	Dnn string `json:"dnn,omitempty"`
	// Snssai is the PDU session S-NSSAI; passed through to the PCF app-session.
	Snssai *BindingSnssai `json:"snssai,omitempty"`
	// SuppFeat is the BSF's answer to the supp-feat query (raw JSON so a
	// non-string value is detected instead of failing the whole decode).
	// Ref: TS 29.521 §5.6.2.2, §5.8
	SuppFeat json.RawMessage `json:"suppFeat,omitempty"`
}

// PcfIpEndPoint is an IP endpoint entry in a PcfBinding.
// Ref: TS 29.510 §6.1.6.2.27
//
// oapi: TS29510_Nnrf_NFManagement.yaml#/components/schemas/IpEndPoint
type PcfIpEndPoint struct {
	Ipv4Address string `json:"ipv4Address,omitempty"`
	Port        int    `json:"port,omitempty"`
	Transport   string `json:"transport,omitempty"`
}

// BindingSnssai is the S-NSSAI from a PcfBinding.
// Ref: TS 29.571 §5.4.4
//
// oapi: TS29571_CommonData.yaml#/components/schemas/Snssai
type BindingSnssai struct {
	Sst int    `json:"sst"`
	Sd  string `json:"sd,omitempty"`
}

// BSFClient is the NEF's interface to the BSF for PCF binding discovery.
//
// Ref: TS 29.521 §5.2.2.4
type BSFClient interface {
	// Discover queries the BSF for the serving PCF binding for the given UE
	// IPv4 address. On success (HTTP 200) it returns the PcfBinding. On HTTP 204 (or 404)
	// it returns ErrPcfBindingNotFound. Any network or other error is wrapped
	// and returned as-is so the caller can log-and-fail.
	//
	// Ref: TS 29.521 §5.2.2.4
	Discover(ctx context.Context, ipv4Addr string) (*PcfBinding, error)
}

// HTTPBSFClient is the concrete BSFClient implementation that sends requests
// over mTLS HTTP/2 to the BSF.
type HTTPBSFClient struct {
	// BaseURL is the BSF API root, e.g. "https://bsf:8010".
	BaseURL string
	// Client is an HTTP/2-capable (mTLS) http.Client.
	Client *http.Client
	// Logger is the NEF structured logger for Nbsf-direction log lines.
	Logger *slog.Logger

	profile *capability.Profile
	flog    *slog.Logger // base logger for FeatureNegotiation records
	cat     *features.Catalog
}

// WithFeatures wires the release profile and the base process logger used for
// the Nbsf_Management supportedFeatures negotiation. A nil profile is Rel-17
// (no supp-feat sent). Call before the client is shared.
func (c *HTTPBSFClient) WithFeatures(p *capability.Profile, logger *slog.Logger) *HTTPBSFClient {
	c.profile = p
	c.flog = logger
	return c
}

// SetCatalog replaces the consumer catalog (tests); nil restores the default.
func (c *HTTPBSFClient) SetCatalog(cat *features.Catalog) { c.cat = cat }

// logger returns the configured logger or slog.Default().
func (c *HTTPBSFClient) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c *HTTPBSFClient) catalog() *features.Catalog {
	if c.cat == nil {
		return nefsbi.NbsfManagementCatalog()
	}
	return c.cat
}

// negotiate computes the features negotiated with the BSF and logs the
// consumer FeatureNegotiation record. A malformed answer negotiates nothing,
// is logged result=FAILURE and never fails the discovery. Only called on a
// 200 answer: 204/404 carry no PcfBinding, hence no answer to negotiate.
func (c *HTTPBSFClient) negotiate(ctx context.Context, offer string, raw json.RawMessage) features.Set {
	return negotiateConsumer(ctx, c.flog, "Nbsf", "BSF", c.catalog(), c.profile, offer, raw)
}

// negotiateConsumer is the shared consumer-side negotiation + logging of the
// NEF clients: RawString + AcceptAnswer (a non-string answer or a malformed
// one negotiates nothing; AcceptAnswer validates it even for an empty offer).
func negotiateConsumer(ctx context.Context, base *slog.Logger, iface, peerNF string, cat *features.Catalog, p *capability.Profile, offer string, raw json.RawMessage) features.Set {
	answer, err := features.RawString(raw)
	var negotiated features.Set
	if err == nil {
		negotiated, err = features.AcceptAnswer(offer, answer)
	}
	n := features.Negotiation{
		NF:        "NEF",
		Interface: iface, Direction: "OUT", PeerNF: peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: cat.Supported(p), Peer: answer, PeerPresent: answer != "", Negotiated: negotiated,
	}
	if err != nil {
		n.Result = "FAILURE"
		n.Peer, n.PeerPresent = string(raw), len(raw) > 0
		features.LogNegotiation(ctx, base, n, "error", err)
		return features.Set{}
	}
	features.LogNegotiation(ctx, base, n)
	return negotiated
}

// Discover implements BSFClient.
// Sends GET /nbsf-management/v1/pcfBindings?ipv4Addr={addr}.
// Returns ErrPcfBindingNotFound on HTTP 204/404; wraps other errors.
//
// Ref: TS 29.521 §5.2.2.4
func (c *HTTPBSFClient) Discover(ctx context.Context, ipv4Addr string) (*PcfBinding, error) {
	url := c.BaseURL + "/nbsf-management/v1/pcfBindings?ipv4Addr=" + ipv4Addr
	// supp-feat is optional in the YAML: sent under rel19 only so the rel17
	// request bytes stay identical (decision D2). The offer is lowercase hex.
	offer := features.Request(c.catalog(), c.profile)
	if offer != "" {
		url += "&supp-feat=" + offer
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("nef: bsf discover: new request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nef: bsf discover: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var binding PcfBinding
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxBSFBodyBytes)).Decode(&binding); err != nil {
			return nil, fmt.Errorf("nef: bsf discover: decode response: %w", err)
		}
		c.negotiate(ctx, offer, binding.SuppFeat)
		c.logger().Debug("BSF discovery: binding found",
			"ipv4_addr", ipv4Addr,
			"binding_id", binding.BindingID,
			"pcf_fqdn", binding.PcfFqdn,
			"pcf_id", binding.PcfId,
		)
		return &binding, nil

	case http.StatusNoContent, http.StatusNotFound:
		// No PCF binding registered for this UE IP: 204 per TS 29.521 §4.2.4.2
		// (404 tolerated for older BSF implementations).
		return nil, ErrPcfBindingNotFound

	default:
		return nil, fmt.Errorf("nef: bsf discover: unexpected status %d", resp.StatusCode)
	}
}

// pcfBaseURI builds the PCF SBI base URI from a PcfBinding.
// Prefers pcfFqdn; falls back to the first pcfIpEndPoint.
// Returns "" when neither is available (caller must handle).
//
// Ref: TS 29.521 §6.2.6 — at least one of pcfFqdn / pcfIpEndPoints is present.
func pcfBaseURI(b *PcfBinding) string {
	if b.PcfFqdn != "" {
		return "https://" + b.PcfFqdn
	}
	if len(b.PcfIpEndPoints) > 0 {
		ep := b.PcfIpEndPoints[0]
		if ep.Port > 0 {
			return fmt.Sprintf("https://%s:%d", ep.Ipv4Address, ep.Port)
		}
		return "https://" + ep.Ipv4Address
	}
	return ""
}
