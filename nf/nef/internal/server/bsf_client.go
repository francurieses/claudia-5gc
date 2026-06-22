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
	"log/slog"
	"net/http"
)

// ErrPcfBindingNotFound is returned when the BSF has no binding for the queried UE IP.
// The NEF maps this sentinel to a northbound 404 PCF_BINDING_NOT_FOUND.
//
// Ref: TS 29.521 §5.2.2.4.4 (discovery miss)
var ErrPcfBindingNotFound = errors.New("nef: bsf: no PCF binding for the UE IP")

// PcfBinding holds the fields of a TS 29.521 §6.2.6 PcfBinding that the NEF
// consumes from the BSF Discovery response. Only the routing + scoping subset
// is used; the full BSF store record has additional fields.
type PcfBinding struct {
	// BindingID is the BSF-assigned identifier (for logging only in NEF).
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
}

// PcfIpEndPoint is an IP endpoint entry in a PcfBinding.
// Ref: TS 29.510 §6.1.6.2.27
type PcfIpEndPoint struct {
	Ipv4Address string `json:"ipv4Address,omitempty"`
	Port        int    `json:"port,omitempty"`
	Transport   string `json:"transport,omitempty"`
}

// BindingSnssai is the S-NSSAI from a PcfBinding.
// Ref: TS 29.571 §5.4.4
type BindingSnssai struct {
	Sst int    `json:"sst"`
	Sd  string `json:"sd,omitempty"`
}

// BSFClient is the NEF's interface to the BSF for PCF binding discovery.
//
// Ref: TS 29.521 §5.2.2.4
type BSFClient interface {
	// Discover queries the BSF for the serving PCF binding for the given UE
	// IPv4 address. On success (HTTP 200) it returns the PcfBinding. On HTTP 404
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
}

// Discover implements BSFClient.
// Sends GET /nbsf-management/v1/pcfBindings?ipv4Addr={addr}.
// Returns ErrPcfBindingNotFound on HTTP 404; wraps other errors.
//
// Ref: TS 29.521 §5.2.2.4
func (c *HTTPBSFClient) Discover(ctx context.Context, ipv4Addr string) (*PcfBinding, error) {
	url := c.BaseURL + "/nbsf-management/v1/pcfBindings?ipv4Addr=" + ipv4Addr
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
		if err := json.NewDecoder(resp.Body).Decode(&binding); err != nil {
			return nil, fmt.Errorf("nef: bsf discover: decode response: %w", err)
		}
		c.Logger.Debug("BSF discovery: binding found",
			"ipv4_addr", ipv4Addr,
			"binding_id", binding.BindingID,
			"pcf_fqdn", binding.PcfFqdn,
			"pcf_id", binding.PcfId,
		)
		return &binding, nil

	case http.StatusNotFound:
		// No PCF binding registered for this UE IP.
		// Ref: TS 29.521 §5.2.2.4.4
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
