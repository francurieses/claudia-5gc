// Package server implements the PCF SBI server and its SBI client stubs.
// This file provides the BSF client used by the PCF to register and deregister
// PCF bindings with the Binding Support Function over Nbsf_Management.
//
// Ref: TS 29.521 §5, TS 23.501 §6.2.16
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// BSFClient is the PCF's interface to the BSF for PCF binding management.
// All methods are fail-open: callers (handleCreateSmPolicy / handleDeleteSmPolicy)
// MUST NOT fail the SM policy operation when the BSF returns an error.
//
// Ref: TS 29.521 §5.2.2.2 (Register), §5.2.2.3 (Deregister)
type BSFClient interface {
	// RegisterBinding sends POST /nbsf-management/v1/pcfBindings with the given
	// PcfBindingRequest body. On success (201) it returns the bindingId parsed from
	// the Location header tail. On 403 EXISTING_BINDING_INFO_FOUND the existing
	// binding is treated as idempotent and a best-effort extraction of the bindingId
	// from the response body is attempted. Any other failure returns an error.
	//
	// Ref: TS 29.521 §5.2.2.2
	RegisterBinding(ctx context.Context, binding *PcfBindingRequest) (bindingID string, err error)

	// DeregisterBinding sends DELETE /nbsf-management/v1/pcfBindings/{bindingId}.
	// 204 No Content is success; 404 is treated as already-gone (no error).
	//
	// Ref: TS 29.521 §5.2.2.3
	DeregisterBinding(ctx context.Context, bindingID string) error
}

// PcfBindingRequest is the subset of TS 29.521 §6.2.6 PcfBinding sent by the PCF
// when registering a new binding. BindingID is not set by the requester; it is
// assigned and returned by the BSF.
type PcfBindingRequest struct {
	// Supi is the UE Subscription Permanent Identifier. Optional.
	Supi string `json:"supi,omitempty"`
	// Gpsi is the Generic Public Subscription Identifier. Optional.
	Gpsi string `json:"gpsi,omitempty"`
	// Ipv4Addr is the UE IPv4 address. Conditional.
	// Ref: TS 29.521 §6.2.6
	Ipv4Addr string `json:"ipv4Addr,omitempty"`
	// Ipv6Prefix is the UE IPv6 prefix. Conditional.
	Ipv6Prefix string `json:"ipv6Prefix,omitempty"`
	// Dnn is the Data Network Name of the PDU session. Mandatory.
	Dnn string `json:"dnn"`
	// Snssai is the S-NSSAI of the PDU session. Mandatory.
	Snssai PcfBindingSnssai `json:"snssai"`
	// PcfFqdn is the FQDN of this PCF. Conditional (pcfFqdn or pcfIpEndPoints).
	// Ref: TS 29.521 §6.2.6
	PcfFqdn string `json:"pcfFqdn,omitempty"`
	// PcfId is the NF instance ID of this PCF. Optional.
	PcfId string `json:"pcfId,omitempty"`
}

// PcfBindingSnssai is the S-NSSAI (Slice/Service Type + optional Slice Differentiator)
// used within a PcfBindingRequest. Mirrors store.Snssai but lives in the server package
// to avoid an import cycle.
// Ref: TS 29.571 §5.4.4
type PcfBindingSnssai struct {
	Sst int    `json:"sst"`
	Sd  string `json:"sd,omitempty"`
}

// HTTPBSFClient is the concrete implementation of BSFClient that sends requests
// over mTLS HTTP/2 to the BSF.
type HTTPBSFClient struct {
	// BaseURL is the BSF API root, e.g. "https://bsf:8010".
	BaseURL string
	// Client is an HTTP/2-capable (mTLS) http.Client shared with other SBI calls.
	Client *http.Client
	// Logger is the PCF's structured logger for Nbsf-direction log lines.
	Logger *slog.Logger
	// PcfFqdn is the PCF's own SBI FQDN, injected into every registered binding
	// so that consumers can discover and reach this PCF. Ref: TS 29.521 §6.2.6.
	PcfFqdn string
	// PcfId is the NF instance ID of this PCF for NRF correlation.
	PcfId string
}

// RegisterBinding implements BSFClient. Sends POST /nbsf-management/v1/pcfBindings.
// Returns the bindingId on success. Fail-open: 403 EXISTING_BINDING_INFO_FOUND is
// treated as a successful idempotent register; any network / parse error is returned
// so the caller can log-and-continue.
//
// Ref: TS 29.521 §5.2.2.2
func (c *HTTPBSFClient) RegisterBinding(ctx context.Context, binding *PcfBindingRequest) (string, error) {
	body, err := json.Marshal(binding)
	if err != nil {
		return "", fmt.Errorf("pcf: bsf register: marshal binding: %w", err)
	}

	url := c.BaseURL + "/nbsf-management/v1/pcfBindings"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("pcf: bsf register: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("pcf: bsf register: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated:
		// Prefer the Location header tail as the bindingId.
		if loc := resp.Header.Get("Location"); loc != "" {
			parts := strings.Split(strings.TrimRight(loc, "/"), "/")
			if id := parts[len(parts)-1]; id != "" {
				return id, nil
			}
		}
		// Fallback: parse bindingId from the response body.
		var respBody struct {
			BindingID string `json:"bindingId"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&respBody); err == nil && respBody.BindingID != "" {
			return respBody.BindingID, nil
		}
		return "", fmt.Errorf("pcf: bsf register: 201 but no bindingId in Location or body")

	case http.StatusForbidden:
		// 403 EXISTING_BINDING_INFO_FOUND — a stale binding from a prior unclean session
		// release still exists. The BSF response body MAY contain the existing PcfBinding
		// including its bindingId. Attempt a best-effort extract; if unavailable, return
		// a sentinel empty string so the caller can log the duplicate and continue.
		//
		// Ref: TS 29.521 §5.2.2.2.4
		var respBody struct {
			BindingID string `json:"bindingId"`
			Cause     string `json:"cause"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&respBody)
		cause := respBody.Cause
		if cause == "" {
			cause = "EXISTING_BINDING_INFO_FOUND"
		}
		// Idempotent: not a hard error. Return the existing bindingId if available.
		return respBody.BindingID, fmt.Errorf("pcf: bsf register: 403 %s (existing binding, reusing)", cause)

	default:
		return "", fmt.Errorf("pcf: bsf register: unexpected status %d", resp.StatusCode)
	}
}

// DeregisterBinding implements BSFClient. Sends DELETE /nbsf-management/v1/pcfBindings/{bindingId}.
// 204 No Content is success; 404 is treated as already-gone (benign). Any other
// error is returned so the caller can log-and-continue.
//
// Ref: TS 29.521 §5.2.2.3
func (c *HTTPBSFClient) DeregisterBinding(ctx context.Context, bindingID string) error {
	url := c.BaseURL + "/nbsf-management/v1/pcfBindings/" + bindingID
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("pcf: bsf deregister: new request: %w", err)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("pcf: bsf deregister: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		// Binding already gone — treat as success (idempotent deregister).
		// Ref: TS 29.521 §5.2.2.3.4
		return nil
	default:
		return fmt.Errorf("pcf: bsf deregister: unexpected status %d", resp.StatusCode)
	}
}
