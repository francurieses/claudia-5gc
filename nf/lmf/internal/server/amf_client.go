// Package server implements the LMF Nlmf_Location SBI server and its outbound clients.
// This file provides the AMF client used by the LMF to consume the Namf_Location
// ProvideLocationInfo service from the AMF.
//
// Ref: TS 29.518 §5.2.2.6 (Namf_Location_ProvideLocationInfo consumer side)
// Ref: TS 23.273 §7.2 (UE positioning procedure — Cell-ID method)
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/logging"
)

// Sentinel errors returned by AMFLocationClient. The server maps them to the
// correct HTTP status codes and ProblemDetails cause strings for the LCS client.

// ErrUEContextNotFound is returned when the AMF responds with 404 CONTEXT_NOT_FOUND.
// The LMF propagates this as a 404 CONTEXT_NOT_FOUND to the LCS consumer.
//
// Ref: TS 29.572 §5.2.2.2; error table: {ueContextId} has no UE context in AMF.
var ErrUEContextNotFound = errors.New("lmf: amf client: UE context not found")

// ErrLocationFailure is returned when the AMF responds with a 5xx status or any
// other non-200/404 status, signalling a positioning failure (e.g. NGAP timeout,
// CM-IDLE UE, gNB error).
//
// Ref: TS 29.572 §5.2.2.2; error table: LOCATION_FAILURE / UE_NOT_REACHABLE.
var ErrLocationFailure = errors.New("lmf: amf client: location failure")

// RequestLocInfo is the Namf_Location request body sent by the LMF to the AMF.
// Field names and json tags MUST match nf/amf/internal/sbi/types.go RequestLocInfo.
//
// Ref: TS 29.518 §5.2.2.6; TS 23.273 §7.2.
type RequestLocInfo struct {
	// Req5gsLoc requests the current 5GS location (TAI + NRCGI of serving cell).
	// Set to true for the Cell-ID positioning MVP.
	Req5gsLoc bool `json:"req5gsLoc"`
	// ReqCurrentLoc requests a fresh measurement (triggers NGAP LocationReportingControl).
	ReqCurrentLoc bool `json:"reqCurrentLoc,omitempty"`
	// SupportedGADShapes is the list of GAD shapes the consumer can decode.
	SupportedGADShapes []string `json:"supportedGADShapes,omitempty"`
}

// LocationData is the Namf_Location response body returned by the AMF to the LMF.
// Field names and json tags MUST match nf/amf/internal/sbi/types.go LocationData.
//
// Ref: TS 29.518 §5.2.2.6; TS 29.572 §6.1.6.2.2.
type LocationData struct {
	// LocationEstimate holds the GAD POINT shape (lat/lon). Placeholder 0,0 when absent.
	LocationEstimate *GeographicArea `json:"locationEstimate,omitempty"`
	// NRCellId is the serving NR cell rendered as a hex string (36-bit cell id).
	NRCellId string `json:"nrCellId,omitempty"`
	// Tai is the Tracking Area Identity of the serving cell.
	Tai *TaiLoc `json:"tai,omitempty"`
	// AgeOfLocationEstimate is minutes since the estimate (0 = fresh report).
	AgeOfLocationEstimate int `json:"ageOfLocationEstimate"`
}

// GeographicArea holds a minimal GAD POINT shape.
// Ref: TS 29.572 §6.1.6.2.x; TS 29.571 §5.4.4.x.
type GeographicArea struct {
	// Shape is the GAD shape identifier, e.g. "POINT".
	Shape string `json:"shape"`
	// Point holds the WGS84 lat/lon when Shape is "POINT".
	Point *LatLon `json:"point,omitempty"`
}

// LatLon is a WGS84 coordinate pair.
type LatLon struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// TaiLoc is the Tracking Area Identity carried in LocationData.
// Ref: TS 29.571 §5.4.4.3; TS 38.413 §9.3.1.x.
type TaiLoc struct {
	PlmnId PlmnID `json:"plmnId"`
	// Tac is a 3-byte hex string, e.g. "000001".
	Tac string `json:"tac"`
}

// PlmnID identifies a PLMN.
// Ref: TS 29.571 §5.4.4.3.
type PlmnID struct {
	MCC string `json:"mcc"`
	MNC string `json:"mnc"`
}

// amfProblem is the ProblemDetails body returned by the AMF on 4xx/5xx errors.
// Used to extract the cause string for propagation to the LCS client.
// Ref: TS 29.571 §5.2.4.1.
type amfProblem struct {
	Cause  string `json:"cause"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

// AMFLocationClient is the LMF's interface to the AMF for Namf_Location calls.
//
// Ref: TS 29.518 §5.2.2.6 (Namf_Location_ProvideLocationInfo consumer)
type AMFLocationClient interface {
	// ProvideLocationInfo calls POST /namf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info
	// on the AMF. Returns (LocationData, "", nil) on success. Returns
	// (nil, "CONTEXT_NOT_FOUND", ErrUEContextNotFound) on AMF 404. Returns
	// (nil, cause, ErrLocationFailure) on any other error (5xx, network, timeout).
	//
	// Ref: TS 29.518 §5.2.2.6
	ProvideLocationInfo(ctx context.Context, ueContextID string) (*LocationData, string, error)
}

// HTTPAMFLocationClient is the concrete AMFLocationClient implementation that
// sends requests over mTLS HTTP/2 to the AMF SBI server.
type HTTPAMFLocationClient struct {
	// BaseURL is the AMF SBI root, e.g. "https://amf:8001".
	BaseURL string
	// Client is an HTTP/2-capable (mTLS) http.Client.
	Client *http.Client
	// Logger is the LMF structured logger for Namf-direction log lines.
	Logger *slog.Logger
}

// ProvideLocationInfo implements AMFLocationClient.
// Sends POST /namf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info to the AMF.
//
// HTTP status mapping:
//   - 200 → (LocationData, "", nil)
//   - 404 → (nil, "CONTEXT_NOT_FOUND", ErrUEContextNotFound)
//   - other → (nil, cause-from-body-or-"LOCATION_FAILURE", ErrLocationFailure)
//
// Ref: TS 29.518 §5.2.2.6; TS 23.273 §7.2.
func (c *HTTPAMFLocationClient) ProvideLocationInfo(ctx context.Context, ueContextID string) (*LocationData, string, error) {
	url := c.BaseURL + "/namf-loc/v1/ue-contexts/" + ueContextID + "/provide-loc-info"

	reqBody := RequestLocInfo{
		Req5gsLoc:          true,
		ReqCurrentLoc:      true,
		SupportedGADShapes: []string{"POINT"},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: amf client: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: amf client: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Propagate correlation ID for traceability across the Namf interface.
	if corrID := logging.CorrelationID(ctx); corrID != "" {
		req.Header.Set("X-Correlation-Id", corrID)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: amf client: do request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var loc LocationData
		if err := json.NewDecoder(resp.Body).Decode(&loc); err != nil {
			return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: amf client: decode response: %w", err)
		}
		return &loc, "", nil

	case http.StatusNotFound:
		// AMF has no UE context for this identifier.
		// Ref: TS 29.572 error table — CONTEXT_NOT_FOUND.
		cause := extractCause(resp)
		if cause == "" {
			cause = "CONTEXT_NOT_FOUND"
		}
		return nil, cause, ErrUEContextNotFound

	default:
		// Any other status (409, 504, etc.) — positioning failure.
		// Extract the cause from the AMF ProblemDetails if present.
		cause := extractCause(resp)
		if cause == "" {
			cause = "LOCATION_FAILURE"
		}
		return nil, cause, fmt.Errorf("%w: amf returned status %d cause %s", ErrLocationFailure, resp.StatusCode, cause)
	}
}

// extractCause attempts to decode a ProblemDetails body and return the cause string.
// Returns "" when the body cannot be decoded or is empty.
func extractCause(resp *http.Response) string {
	var pd amfProblem
	if err := json.NewDecoder(resp.Body).Decode(&pd); err != nil {
		return ""
	}
	return pd.Cause
}
