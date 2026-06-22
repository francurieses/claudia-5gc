// Package server — PCF policy-authorization client (Npcf_PolicyAuthorization).
//
// The NEF maps an AF AsSessionWithQoS Create/Delete onto the PCF's
// Npcf_PolicyAuthorization service. The PCF SBI URI comes from the PcfBinding
// returned by the BSF, NOT from NRF discovery — the BSF already identified the
// specific serving PCF instance for the UE's PDU session.
//
// Ref: TS 29.514 §5.2.2.2 (Create), §5.2.2.4 (Delete)
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

// AppSessionContextReqData is the request body for Npcf_PolicyAuthorization_Create.
// Only the fields used by the NEF in the baseline are included.
// Ref: TS 29.514 §5.6.2.3
type AppSessionContextReqData struct {
	// AspId is the Application Service Provider identifier (AF / scsAsId).
	// Ref: TS 29.514 §5.6.2.3
	AspId string `json:"aspId,omitempty"`
	// AfAppId is the application identifier as known to the AF.
	AfAppId string `json:"afAppId,omitempty"`
	// UeIpv4 is the UE IPv4 address to which the QoS applies.
	UeIpv4 string `json:"ueIpv4,omitempty"`
	// UeIpv6 is the UE IPv6 address (alternative to UeIpv4).
	UeIpv6 string `json:"ueIpv6,omitempty"`
	// QosReference is the pre-provisioned QoS profile reference authorized by the PCF.
	// Ref: TS 29.514 §5.6.2.3
	QosReference string `json:"qosReference,omitempty"`
	// Dnn is the Data Network Name scoping the authorization.
	Dnn string `json:"dnn,omitempty"`
	// SliceInfo is the S-NSSAI scoping the authorization.
	SliceInfo *BindingSnssai `json:"sliceInfo,omitempty"`
	// MedComponents is a map of media components describing the IP flows.
	// The baseline sends a single "DATA" component when flowInfo is present.
	MedComponents map[string]MediaComponent `json:"medComponents,omitempty"`
	// SuppFeat is the negotiated supported features bitmask.
	SuppFeat string `json:"suppFeat,omitempty"`
}

// MediaComponent describes an IP media flow component within an app-session.
// Ref: TS 29.514 §5.6.2.10
type MediaComponent struct {
	// MedCompN is the media component number key (map key, not a field).
	MedType     string   `json:"medType,omitempty"`
	FDescs      []string `json:"fDescs,omitempty"`
	AfAppId     string   `json:"afAppId,omitempty"`
	MedSubComps []string `json:"medSubComps,omitempty"`
}

// AppSessionContext is the PCF's response to a successful Npcf_PolicyAuthorization_Create.
// Ref: TS 29.514 §5.6.2.2
type AppSessionContext struct {
	// AscRespData contains the PCF's authorization response data.
	AscRespData *AppSessionContextRespData `json:"ascRespData,omitempty"`
}

// AppSessionContextRespData is the response part of an AppSessionContext.
// Ref: TS 29.514 §5.6.2.4
type AppSessionContextRespData struct {
	// SuppFeat is the negotiated supported features.
	SuppFeat string `json:"suppFeat,omitempty"`
}

// PolicyAuthorizationClient is the NEF's interface to the PCF for
// Npcf_PolicyAuthorization_Create and _Delete operations.
//
// Ref: TS 29.514 §5.2.2.2 (Create), §5.2.2.4 (Delete)
type PolicyAuthorizationClient interface {
	// CreateAppSession sends POST /npcf-policyauthorization/v1/app-sessions
	// to the PCF at pcfBaseURI. Returns the appSessionId parsed from the
	// Location header on 201 Created. Returns an error whose message starts
	// with "403" when the PCF rejects the authorization.
	//
	// Ref: TS 29.514 §5.2.2.2
	CreateAppSession(ctx context.Context, pcfBaseURI string, req *AppSessionContextReqData) (appSessionID string, err error)

	// DeleteAppSession sends DELETE /npcf-policyauthorization/v1/app-sessions/{id}
	// to the PCF at pcfBaseURI. 204 No Content is success; 404 is treated as
	// already-gone (idempotent). Any other status is returned as an error.
	//
	// Ref: TS 29.514 §5.2.2.4
	DeleteAppSession(ctx context.Context, pcfBaseURI, appSessionID string) error
}

// HTTPPolicyAuthClient is the concrete PolicyAuthorizationClient that sends
// requests over mTLS HTTP/2 to the PCF.
type HTTPPolicyAuthClient struct {
	// Client is the mTLS HTTP/2 http.Client.
	Client *http.Client
	// Logger is the NEF structured logger for Npcf-direction log lines.
	Logger *slog.Logger
}

// CreateAppSession implements PolicyAuthorizationClient.
// Sends POST /npcf-policyauthorization/v1/app-sessions to pcfBaseURI.
//
// Ref: TS 29.514 §5.2.2.2
func (c *HTTPPolicyAuthClient) CreateAppSession(ctx context.Context, pcfBaseURI string, req *AppSessionContextReqData) (string, error) {
	body, err := json.Marshal(map[string]any{"ascReqData": req})
	if err != nil {
		return "", fmt.Errorf("nef: pcf create app-session: marshal: %w", err)
	}

	url := pcfBaseURI + "/npcf-policyauthorization/v1/app-sessions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("nef: pcf create app-session: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.Client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("nef: pcf create app-session: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated:
		// Extract appSessionId from Location header tail.
		loc := resp.Header.Get("Location")
		if loc != "" {
			parts := strings.Split(strings.TrimRight(loc, "/"), "/")
			if id := parts[len(parts)-1]; id != "" {
				return id, nil
			}
		}
		// Fallback: try to parse from body.
		var respBody struct {
			AppSessionID string `json:"appSessionId"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&respBody); err == nil && respBody.AppSessionID != "" {
			return respBody.AppSessionID, nil
		}
		return "", fmt.Errorf("nef: pcf create app-session: 201 but no appSessionId in Location or body")

	case http.StatusForbidden:
		// PCF rejected the authorization — propagate as a 403 to the AF.
		// Ref: TS 29.514 §5.2.2.2.4
		return "", fmt.Errorf("403: pcf rejected policy authorization")

	default:
		return "", fmt.Errorf("nef: pcf create app-session: unexpected status %d", resp.StatusCode)
	}
}

// DeleteAppSession implements PolicyAuthorizationClient.
// Sends DELETE /npcf-policyauthorization/v1/app-sessions/{appSessionID} to pcfBaseURI.
//
// Ref: TS 29.514 §5.2.2.4
func (c *HTTPPolicyAuthClient) DeleteAppSession(ctx context.Context, pcfBaseURI, appSessionID string) error {
	url := pcfBaseURI + "/npcf-policyauthorization/v1/app-sessions/" + appSessionID
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("nef: pcf delete app-session: new request: %w", err)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("nef: pcf delete app-session: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		// App-session already gone — treat as success (idempotent).
		// Ref: TS 29.514 §5.2.2.4
		return nil
	default:
		return fmt.Errorf("nef: pcf delete app-session: unexpected status %d", resp.StatusCode)
	}
}
