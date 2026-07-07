// Package server implements the LMF Nlmf_Location SBI server and its outbound clients.
// This file provides the AMF client used by the LMF to consume the Namf_Location
// ProvideLocationInfo service from the AMF, and adds the DL NRPPa relay client
// for E-CID NRPPa positioning (LMF-004, TS 29.518 §5.2.2.6).
//
// Ref: TS 29.518 §5.2.2.6 (Namf_Location_ProvideLocationInfo + dl-nrppa-info consumer side)
// Ref: TS 23.273 §7.2 (UE positioning procedure — Cell-ID method)
// Ref: TS 38.413 §8.17.3 (NGAP UE-Associated NRPPa Transport — AMF relay)
package server

import (
	"bytes"
	"context"
	"encoding/base64"
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

// LocationData is the Namf_Location response body returned by the AMF to the LMF,
// and also the Nlmf_Location response body returned by the LMF to the LCS consumer.
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
	// PositioningDataList records which positioning method(s) contributed to the estimate.
	// "eCID" indicates an E-CID (RSRP-weighted centroid) fix via NRPPa relay (LMF-004).
	// Absent or empty indicates Cell-ID positioning (LMF-001).
	// Ref: TS 29.572 §6.1.6.2.2 (positioningDataList).
	PositioningDataList []string `json:"positioningDataList,omitempty"`
}

// GeographicArea holds a minimal GAD POINT shape.
// Ref: TS 29.572 §6.1.6.2.x; TS 29.571 §5.4.4.x.
type GeographicArea struct {
	// Shape is the GAD shape identifier, e.g. "POINT".
	Shape string `json:"shape"`
	// Point holds the WGS84 lat/lon when Shape is "POINT".
	Point *LatLon `json:"point,omitempty"`
	// Uncertainty is the horizontal accuracy radius in metres (LMF-synthesized).
	// Carried for the consumer/portal; the GAD POINT shape itself has no uncertainty.
	Uncertainty float64 `json:"uncertainty,omitempty"`
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

// ---- DL NRPPa relay client (LMF-004) -----------------------------------------
//
// dlNRPPaReqBody is the JSON request body for POST .../dl-nrppa-info.
// Field names MUST match nf/amf/internal/sbi/types.go DLNRPPaInfoReq.
// Ref: TS 29.518 §5.2.2.6 (Namf_Location NRPPa relay extension).
type dlNRPPaReqBody struct {
	// NrppaPdu is the base64-encoded opaque NRPPa PDU to relay to the gNB.
	NrppaPdu string `json:"nrppaPdu"`
	// RoutingId is the optional LMF routing identity (base64-encoded).
	RoutingId string `json:"routingId,omitempty"`
}

// dlNRPPaRspBody is the JSON response body for a successful POST .../dl-nrppa-info.
// Field names MUST match nf/amf/internal/sbi/types.go DLNRPPaInfoRsp.
type dlNRPPaRspBody struct {
	// NrppaPdu is the base64-encoded UL NRPPa PDU received from the gNB.
	NrppaPdu string `json:"nrppaPdu"`
}

// SendDLNRPPa sends an opaque NRPPa PDU to the gNB serving the UE by POSTing to
// POST /namf-loc/v1/ue-contexts/{ueContextId}/dl-nrppa-info on the AMF.
//
// The AMF wraps the PDU in an NGAP DownlinkUEAssociatedNRPPaTransport (ProcCode=8)
// and waits for the gNB's UplinkUEAssociatedNRPPaTransport (ProcCode=50) response,
// then returns the UL NRPPa PDU bytes in the synchronous HTTP response body.
//
// Returns (respPDU, "", nil) on success (HTTP 200).
// Returns (nil, "CONTEXT_NOT_FOUND", ErrUEContextNotFound) on AMF 404.
// Returns (nil, cause, ErrLocationFailure) on 504 (guard-timer / CM-IDLE) or other errors.
//
// The LMF treats any error as a signal to fall back to Cell-ID positioning transparently.
// Ref: TS 29.518 §5.2.2.6; TS 38.413 §8.17.3 (NGAP UE-Associated NRPPa Transport);
// TS 23.273 §7.2 step C; NRPPaRelay.md §Endpoints.
func (c *HTTPAMFLocationClient) SendDLNRPPa(ctx context.Context, ueContextID string, nrppaPDU []byte) ([]byte, string, error) {
	url := c.BaseURL + "/namf-loc/v1/ue-contexts/" + ueContextID + "/dl-nrppa-info"

	reqBody := dlNRPPaReqBody{NrppaPdu: base64.StdEncoding.EncodeToString(nrppaPDU)}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: dl-nrppa-info: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: dl-nrppa-info: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if corrID := logging.CorrelationID(ctx); corrID != "" {
		req.Header.Set("X-Correlation-Id", corrID)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: dl-nrppa-info: do request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var rsp dlNRPPaRspBody
		if err := json.NewDecoder(resp.Body).Decode(&rsp); err != nil {
			return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: dl-nrppa-info: decode response: %w", err)
		}
		pdu, err := base64.StdEncoding.DecodeString(rsp.NrppaPdu)
		if err != nil {
			// Try URL-safe encoding fallback (AMF may use either variant).
			pdu, err = base64.URLEncoding.DecodeString(rsp.NrppaPdu)
			if err != nil {
				return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: dl-nrppa-info: decode base64 response: %w", err)
			}
		}
		return pdu, "", nil

	case http.StatusNotFound:
		// AMF has no UE context — cannot relay NRPPa.
		cause := extractCause(resp)
		if cause == "" {
			cause = "CONTEXT_NOT_FOUND"
		}
		return nil, cause, ErrUEContextNotFound

	case http.StatusGatewayTimeout:
		// AMF guard timer expired — no UL NRPPa received from gNB in time.
		// LMF falls back to Cell-ID; this is NOT a hard error surfaced to the LCS client.
		// Ref: NRPPaRelay.md §Error table; TS 23.273 §6.2.9 (graceful downgrade on timeout).
		cause := extractCause(resp)
		if cause == "" {
			cause = "UE_NOT_REACHABLE"
		}
		return nil, cause, fmt.Errorf("%w: dl-nrppa-info guard timer: %s", ErrLocationFailure, cause)

	default:
		cause := extractCause(resp)
		if cause == "" {
			cause = "LOCATION_FAILURE"
		}
		return nil, cause, fmt.Errorf("%w: dl-nrppa-info status %d: %s", ErrLocationFailure, resp.StatusCode, cause)
	}
}

// ---- DL LPP relay client (LMF-005) -------------------------------------------
//
// dlLPPReqBody is the JSON request body for POST .../dl-lpp-info.
// Field names MUST match nf/amf/internal/sbi/types.go DLLPPInfoReq.
// Ref: TS 29.518 §5.2.2.6 (Namf_Location LPP relay extension); TS 24.501 §8.7.4.
type dlLPPReqBody struct {
	// LppPdu is the base64-encoded opaque LPP PDU to relay to the UE.
	LppPdu string `json:"lppPdu"`
	// ExpectUlResponse (ADDITIVE, LMF-009; default true when absent) tells
	// the AMF whether a matching UL NAS Transport (PCT=0x03) is expected.
	// false = DL-only leg (ProvideAssistanceData — TS 37.355 assistance
	// delivery is unsolicited, no response message): the AMF sends the DL
	// NAS Transport and returns 204 No Content without registering a
	// pendingLPP waiter. Ref: docs/procedures/LPPRelay.md §Endpoints.
	ExpectUlResponse bool `json:"expectUlResponse"`
}

// dlLPPRspBody is the JSON response body for a successful POST .../dl-lpp-info.
// Field names MUST match nf/amf/internal/sbi/types.go DLLPPInfoRsp.
type dlLPPRspBody struct {
	// LppPdu is the base64-encoded UL LPP PDU received from the UE.
	LppPdu string `json:"lppPdu"`
}

// SendDLLPP sends an opaque LPP PDU to the UE serving the given ueContextID by
// POSTing to POST /namf-loc/v1/ue-contexts/{ueContextId}/dl-lpp-info on the AMF.
//
// The AMF wraps the PDU in a DL NAS Transport (payload container type 0x03).
// With expectUlResponse=true it waits for the UE's matching UL NAS Transport
// (payload container type 0x03) and returns the UL LPP PDU bytes in the
// synchronous HTTP response body; with expectUlResponse=false (leg 2,
// ProvideAssistanceData — DL-only) it returns immediately after the DL send
// and the AMF answers 204 No Content.
//
// Returns (respPDU, "", nil) on HTTP 200; (nil, "", nil) on HTTP 204.
// Returns (nil, "CONTEXT_NOT_FOUND", ErrUEContextNotFound) on AMF 404.
// Returns (nil, cause, ErrLocationFailure) on 504 (guard-timer / CM-IDLE) or
// other errors.
//
// The LMF treats any error as a signal to fall back to E-CID/Cell-ID
// positioning transparently.
// Ref: TS 29.518 §5.2.2.6; TS 24.501 §8.7.4; TS 23.273 §6.2.10;
// docs/procedures/LPPRelay.md §Endpoints.
func (c *HTTPAMFLocationClient) SendDLLPP(ctx context.Context, ueContextID string, lppPDU []byte, expectUlResponse bool) ([]byte, string, error) {
	url := c.BaseURL + "/namf-loc/v1/ue-contexts/" + ueContextID + "/dl-lpp-info"

	reqBody := dlLPPReqBody{
		LppPdu:           base64.StdEncoding.EncodeToString(lppPDU),
		ExpectUlResponse: expectUlResponse,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: dl-lpp-info: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: dl-lpp-info: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if corrID := logging.CorrelationID(ctx); corrID != "" {
		req.Header.Set("X-Correlation-Id", corrID)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: dl-lpp-info: do request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		// DL-only leg (expectUlResponse=false): the AMF sent the DL NAS
		// Transport; no UL LPP PDU exists by design. Ref: LPPRelay.md leg 2.
		return nil, "", nil

	case http.StatusOK:
		var rsp dlLPPRspBody
		if err := json.NewDecoder(resp.Body).Decode(&rsp); err != nil {
			return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: dl-lpp-info: decode response: %w", err)
		}
		pdu, err := base64.StdEncoding.DecodeString(rsp.LppPdu)
		if err != nil {
			// Try URL-safe encoding fallback (AMF may use either variant).
			pdu, err = base64.URLEncoding.DecodeString(rsp.LppPdu)
			if err != nil {
				return nil, "LOCATION_FAILURE", fmt.Errorf("lmf: dl-lpp-info: decode base64 response: %w", err)
			}
		}
		return pdu, "", nil

	case http.StatusNotFound:
		// AMF has no UE context — cannot relay LPP.
		cause := extractCause(resp)
		if cause == "" {
			cause = "CONTEXT_NOT_FOUND"
		}
		return nil, cause, ErrUEContextNotFound

	case http.StatusGatewayTimeout:
		// AMF guard timer expired — no UL LPP received from the UE in time.
		// LMF falls back to E-CID; this is NOT a hard error surfaced to the LCS client.
		// Ref: docs/procedures/LPPRelay.md §Error table; TS 23.273 §6.2.10.
		cause := extractCause(resp)
		if cause == "" {
			cause = "UE_NOT_REACHABLE"
		}
		return nil, cause, fmt.Errorf("%w: dl-lpp-info guard timer: %s", ErrLocationFailure, cause)

	default:
		cause := extractCause(resp)
		if cause == "" {
			cause = "LOCATION_FAILURE"
		}
		return nil, cause, fmt.Errorf("%w: dl-lpp-info status %d: %s", ErrLocationFailure, resp.StatusCode, cause)
	}
}
