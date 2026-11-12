// Package server — PCF policy-authorization client (Npcf_PolicyAuthorization).
//
// The NEF maps an AF AsSessionWithQoS Create/Delete onto the PCF's
// Npcf_PolicyAuthorization service. The PCF SBI URI comes from the PcfBinding
// returned by the BSF, NOT from NRF discovery — the BSF already identified the
// specific serving PCF instance for the UE's PDU session.
//
// Ref: TS 29.514 §5.2.2.2 (Create), §4.2.4.2 (Delete)
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	nefsbi "github.com/francurieses/claudia-5gc/nf/nef/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// maxPCFCreateBodyBytes bounds the AppSessionContext response read.
const maxPCFCreateBodyBytes = 1 << 20

// AppSessionContextReqData is the request body for Npcf_PolicyAuthorization_Create.
// Only the fields used by the NEF in the baseline are included.
// Ref: TS 29.514 §5.6.2.3
//
// oapi: TS29514_Npcf_PolicyAuthorization.yaml#/components/schemas/AppSessionContextReqData
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
	// Set under rel17 / no profile only, where it is sent as the project member
	// "ascReqData.qosReference" (see MarshalJSON). AppSessionContextReqData has no
	// such attribute: under rel19 the reference travels in
	// medComponents[].qosReference (MediaComponent, TS 29.514 §5.6.2.10).
	QosReference string `json:"-"`
	// qosTopLevel selects the wire shape explicitly: true = frozen legacy shape
	// (top-level qosReference), false = spec shape. Set by the caller under
	// rel17 / no profile and by UnmarshalJSON when the member was present, so
	// decode then marshal never flips the shape.
	qosTopLevel bool
	// Dnn is the Data Network Name scoping the authorization.
	Dnn string `json:"dnn,omitempty"`
	// SliceInfo is the S-NSSAI scoping the authorization.
	SliceInfo *BindingSnssai `json:"sliceInfo,omitempty"`
	// MedComponents is a map of media components describing the IP flows.
	// The baseline sends a single "DATA" component when flowInfo is present.
	// Values are MediaComponent (rel19, spec-literal) or LegacyMediaComponent
	// (rel17 baseline); see buildMedComponents.
	MedComponents map[string]any `json:"medComponents,omitempty"`
	// NotifUri is the NEF notification URI for PCF callbacks, built from the NEF
	// apiRoot. Required by the schema; set under the rel19 (spec-literal)
	// profile only, omitted under rel17 / no profile so the legacy request
	// stays byte-identical. Note: the "{notifUri}/notify" callback form of
	// §5.5.2.2 is defined for evSubsc.notifUri; the NEF uses one base for both.
	// Ref: TS 29.514 §5.6.2.3, §5.5.2.2
	NotifUri string `json:"notifUri,omitempty"`
	// SuppFeat is the features the NEF offers (ascReqData.suppFeat). Set by the
	// client under the rel19 profile only; omitted under rel17 (decision D2).
	// Ref: TS 29.514 §5.6.2.3, §5.8
	SuppFeat string `json:"suppFeat,omitempty"`
}

// legacyAscReqData is the Rel-17-profile (frozen) wire shape of
// AppSessionContextReqData: qosReference at the top level, between ueIpv6 and
// dnn, exactly as before REL19-3.5.
//
// oapi: none legacy Rel-17-profile wire shape of AppSessionContextReqData (top-level qosReference), see AppSessionContextReqData
type legacyAscReqData struct {
	AspId         string         `json:"aspId,omitempty"`
	AfAppId       string         `json:"afAppId,omitempty"`
	UeIpv4        string         `json:"ueIpv4,omitempty"`
	UeIpv6        string         `json:"ueIpv6,omitempty"`
	QosReference  string         `json:"qosReference,omitempty"`
	Dnn           string         `json:"dnn,omitempty"`
	SliceInfo     *BindingSnssai `json:"sliceInfo,omitempty"`
	MedComponents map[string]any `json:"medComponents,omitempty"`
	NotifUri      string         `json:"notifUri,omitempty"`
	SuppFeat      string         `json:"suppFeat,omitempty"`
}

// MarshalJSON emits the frozen legacy shape when qosTopLevel is set (rel17 /
// no profile) and the spec shape otherwise.
func (a AppSessionContextReqData) MarshalJSON() ([]byte, error) {
	if a.qosTopLevel {
		b, err := json.Marshal(legacyAscReqData{
			AspId: a.AspId, AfAppId: a.AfAppId, UeIpv4: a.UeIpv4, UeIpv6: a.UeIpv6,
			QosReference: a.QosReference, Dnn: a.Dnn, SliceInfo: a.SliceInfo,
			MedComponents: a.MedComponents, NotifUri: a.NotifUri, SuppFeat: a.SuppFeat,
		})
		if err != nil {
			return nil, fmt.Errorf("nef: marshal AppSessionContextReqData: %w", err)
		}
		return b, nil
	}
	type plain AppSessionContextReqData
	b, err := json.Marshal(plain(a))
	if err != nil {
		return nil, fmt.Errorf("nef: marshal AppSessionContextReqData: %w", err)
	}
	return b, nil
}

// UnmarshalJSON accepts both shapes: the legacy top-level qosReference, or the
// spec medComponents[].qosReference (the first component in key order).
func (a *AppSessionContextReqData) UnmarshalJSON(b []byte) error {
	type plain AppSessionContextReqData
	aux := struct {
		*plain
		QosReference string `json:"qosReference"`
	}{plain: (*plain)(a)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return fmt.Errorf("nef: decode AppSessionContextReqData: %w", err)
	}
	a.QosReference = aux.QosReference
	a.qosTopLevel = aux.QosReference != ""
	if a.QosReference == "" {
		keys := make([]string, 0, len(a.MedComponents))
		for k := range a.MedComponents {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if m, ok := a.MedComponents[k].(map[string]any); ok {
				if q, ok := m["qosReference"].(string); ok && q != "" {
					a.QosReference = q
					break
				}
			}
		}
	}
	return nil
}

// MediaComponent describes an IP media flow component within an app-session
// (spec-literal shape, sent under the rel19 profile).
// Ref: TS 29.514 §5.6.2.10
//
// oapi: TS29514_Npcf_PolicyAuthorization.yaml#/components/schemas/MediaComponent
type MediaComponent struct {
	// MedCompN is the media component number (required).
	MedCompN int `json:"medCompN"`
	// MedSubComps maps the fNum (as string key) to its media sub-component.
	MedSubComps map[string]MediaSubComponent `json:"medSubComps,omitempty"`
	MedType     string                       `json:"medType,omitempty"`
	AfAppId     string                       `json:"afAppId,omitempty"`
	// QosReference is the pre-defined QoS the PCF authorizes for the flows
	// (the AF's AsSessionWithQoS qosReference). Ref: TS 29.514 §5.6.2.10
	QosReference string `json:"qosReference,omitempty"`
}

// MediaSubComponent identifies a media sub-component carrying the flow
// descriptions. Ref: TS 29.514 §5.6.2.11
//
// oapi: TS29514_Npcf_PolicyAuthorization.yaml#/components/schemas/MediaSubComponent
type MediaSubComponent struct {
	// FNum is the flow number (required).
	FNum   int      `json:"fNum"`
	FDescs []string `json:"fDescs,omitempty"`
}

// LegacyMediaComponent is the frozen Rel-17-profile wire shape (fDescs at the
// media-component level, no medCompN); it is not schema-conformant and is sent
// under rel17 / no profile only, byte-identical to the pre-REL19-3.5 NEF.
//
// oapi: none legacy Rel-17-profile wire shape of MediaComponent, see MediaComponent
type LegacyMediaComponent struct {
	MedType     string   `json:"medType,omitempty"`
	FDescs      []string `json:"fDescs,omitempty"`
	AfAppId     string   `json:"afAppId,omitempty"`
	MedSubComps []string `json:"medSubComps,omitempty"`
}

// maxFlowDescriptions is the maxItems of FlowInfo.flowDescriptions.
// Ref: TS 29.122 FlowInfo (TS29122_CommonData.yaml#/components/schemas/FlowInfo, maxItems 2)
const maxFlowDescriptions = 2

// flowInfoError describes a rejected flowInfo entry (rel19 validation).
type flowInfoError struct {
	param  string // JSON pointer into the AF request
	detail string
}

func (e *flowInfoError) Error() string { return e.detail }

// validateFlowInfo checks the AF flowInfo under the spec-literal profile:
// flowId values (non-zero) must be unique, and flowDescriptions holds at most
// maxFlowDescriptions entries (FlowInfo.flowDescriptions minItems 1 maxItems 2;
// an absent list is accepted, an empty one cannot be told apart from absent).
// Ref: TS 29.122 FlowInfo
func validateFlowInfo(fi []FlowInfo) *flowInfoError {
	seen := make(map[int]bool, len(fi))
	for i, f := range fi {
		if len(f.FlowDescriptions) > maxFlowDescriptions {
			return &flowInfoError{
				param:  fmt.Sprintf("/flowInfo/%d/flowDescriptions", i),
				detail: fmt.Sprintf("flowDescriptions must hold 1..%d entries, got %d", maxFlowDescriptions, len(f.FlowDescriptions)),
			}
		}
		if f.FlowID == 0 {
			continue
		}
		if seen[f.FlowID] {
			return &flowInfoError{
				param:  fmt.Sprintf("/flowInfo/%d/flowId", i),
				detail: fmt.Sprintf("duplicate flowId %d", f.FlowID),
			}
		}
		seen[f.FlowID] = true
	}
	return nil
}

// flowIDFallback reports whether any flowInfo entry lacks a flowId (0/absent,
// rel17-era AF), so the NEF numbers it by position under rel19.
func flowIDFallback(fi []FlowInfo) bool {
	for _, f := range fi {
		if f.FlowID == 0 {
			return true
		}
	}
	return false
}

// buildMedComponents maps the AF flowInfo onto ascReqData.medComponents.
// Under the spec-literal profile (rel19) it returns one MediaComponent
// (medCompN 1) with one MediaSubComponent per flowInfo entry, fNum = the AF's
// flowId; an entry without flowId (0/absent) gets the first unused number
// starting at its position (i+1). Otherwise it returns the frozen legacy shape
// (single component "1", the last flowInfo entry's descriptions win, as
// before). Under rel19 qosRef (the AF qosReference) is carried as
// MediaComponent.qosReference; without flowInfo a component holding only that
// reference is built. Duplicate flowIds must be rejected beforehand (validateFlowInfo).
// Ref: TS 29.514 §5.6.2.10/.11, TS 29.122 FlowInfo
func buildMedComponents(fi []FlowInfo, specLiteral bool, qosRef string) map[string]any {
	if len(fi) == 0 {
		if specLiteral && qosRef != "" {
			// The qosReference needs a MediaComponent to travel in (rel19).
			return map[string]any{"1": MediaComponent{MedCompN: 1, MedType: "DATA", QosReference: qosRef}}
		}
		return nil
	}
	if !specLiteral {
		return map[string]any{"1": LegacyMediaComponent{MedType: "DATA", FDescs: fi[len(fi)-1].FlowDescriptions}}
	}
	used := make(map[int]bool, len(fi))
	for _, f := range fi {
		if f.FlowID != 0 {
			used[f.FlowID] = true
		}
	}
	subs := make(map[string]MediaSubComponent, len(fi))
	for i, f := range fi {
		n := f.FlowID
		if n == 0 {
			n = i + 1
			for used[n] {
				n++
			}
			used[n] = true
		}
		subs[strconv.Itoa(n)] = MediaSubComponent{FNum: n, FDescs: f.FlowDescriptions}
	}
	return map[string]any{"1": MediaComponent{MedCompN: 1, MedType: "DATA", MedSubComps: subs, QosReference: qosRef}}
}

// AppSessionContext is the PCF's response to a successful Npcf_PolicyAuthorization_Create.
// Ref: TS 29.514 §5.6.2.2
//
// oapi: TS29514_Npcf_PolicyAuthorization.yaml#/components/schemas/AppSessionContext
type AppSessionContext struct {
	// AscRespData contains the PCF's authorization response data.
	AscRespData *AppSessionContextRespData `json:"ascRespData,omitempty"`
}

// AppSessionContextRespData is the response part of an AppSessionContext.
// Ref: TS 29.514 §5.6.2.4
//
// oapi: TS29514_Npcf_PolicyAuthorization.yaml#/components/schemas/AppSessionContextRespData
type AppSessionContextRespData struct {
	// SuppFeat is the PCF's answer (raw JSON so a non-string value is detected
	// instead of failing the decode). Ref: TS 29.514 §5.6.2.4, §5.8
	SuppFeat json.RawMessage `json:"suppFeat,omitempty"`
}

// PolicyAuthorizationClient is the NEF's interface to the PCF for
// Npcf_PolicyAuthorization_Create and _Delete operations.
//
// Ref: TS 29.514 §5.2.2.2 (Create), §4.2.4.2 (Delete)
type PolicyAuthorizationClient interface {
	// CreateAppSession sends POST /npcf-policyauthorization/v1/app-sessions
	// to the PCF at pcfBaseURI. Returns the appSessionId parsed from the
	// Location header on 201 Created and the supportedFeatures set negotiated
	// with the PCF (empty when no answer or a malformed one). Returns an error
	// whose message starts with "403" when the PCF rejects the authorization.
	//
	// Ref: TS 29.514 §5.2.2.2, §5.8
	CreateAppSession(ctx context.Context, pcfBaseURI string, req *AppSessionContextReqData) (appSessionID string, negotiated features.Set, err error)

	// DeleteAppSession sends the custom delete operation
	// POST /npcf-policyauthorization/v1/app-sessions/{id}/delete to the PCF at
	// pcfBaseURI. 200 (AppSessionContext) or 204 No Content is success; 404 is
	// treated as already-gone (idempotent). Any other status is returned as an error.
	//
	// Ref: TS 29.514 §4.2.4.2, §5.3.3.4.2
	DeleteAppSession(ctx context.Context, pcfBaseURI, appSessionID string) error
}

// appSessionsPath is the Npcf_PolicyAuthorization app-sessions collection
// (TS 29.514 §5.1 / OpenAPI servers path).
const appSessionsPath = "/npcf-policyauthorization/v1/app-sessions"

// HTTPPolicyAuthClient is the concrete PolicyAuthorizationClient that sends
// requests over mTLS HTTP/2 to the PCF.
type HTTPPolicyAuthClient struct {
	// Client is the mTLS HTTP/2 http.Client.
	Client *http.Client
	// Logger is the NEF structured logger for Npcf-direction log lines.
	Logger *slog.Logger

	profile *capability.Profile
	flog    *slog.Logger // base logger for FeatureNegotiation records
	cat     *features.Catalog
}

// WithFeatures wires the release profile and the base process logger used for
// the Npcf_PolicyAuthorization supportedFeatures negotiation. A nil profile is
// Rel-17 (no suppFeat sent). Call before the client is shared.
func (c *HTTPPolicyAuthClient) WithFeatures(p *capability.Profile, logger *slog.Logger) *HTTPPolicyAuthClient {
	c.profile = p
	c.flog = logger
	return c
}

// SetCatalog replaces the consumer catalog (tests); nil restores the default.
func (c *HTTPPolicyAuthClient) SetCatalog(cat *features.Catalog) { c.cat = cat }

func (c *HTTPPolicyAuthClient) catalog() *features.Catalog {
	if c.cat == nil {
		return nefsbi.NpcfPolicyAuthorizationCatalog()
	}
	return c.cat
}

// logger returns the configured logger or slog.Default().
func (c *HTTPPolicyAuthClient) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// CreateAppSession implements PolicyAuthorizationClient.
// Sends POST /npcf-policyauthorization/v1/app-sessions to pcfBaseURI.
//
// Ref: TS 29.514 §5.2.2.2
func (c *HTTPPolicyAuthClient) CreateAppSession(ctx context.Context, pcfBaseURI string, req *AppSessionContextReqData) (string, features.Set, error) {
	// Offer the implemented set under rel19 only (rel17 omits ascReqData.suppFeat,
	// byte-identical legacy request; the YAML marks it required: INFO, decision D1/D2).
	offer := features.Request(c.catalog(), c.profile)
	// Copy so the caller's request is not mutated; only assign a non-empty
	// offer (rel17: SuppFeat stays "" and is omitted, byte-identical request).
	out := *req
	if offer != "" {
		out.SuppFeat = offer
	}
	body, err := json.Marshal(map[string]any{"ascReqData": &out})
	if err != nil {
		return "", features.Set{}, fmt.Errorf("nef: pcf create app-session: marshal: %w", err)
	}

	url := pcfBaseURI + appSessionsPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", features.Set{}, fmt.Errorf("nef: pcf create app-session: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.Client.Do(httpReq)
	if err != nil {
		return "", features.Set{}, fmt.Errorf("nef: pcf create app-session: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated:
		// Read the body once, bounded to maxPCFCreateBodyBytes (1 MiB): it
		// carries ascRespData.suppFeat and, for a legacy PCF without
		// Location, the non-schema appSessionId. HEAD decoded the body
		// unbounded in that fallback; the bound is a deliberate hardening.
		// Both the negotiation and the id fallback use the FIRST JSON value
		// of the body (streaming decode, trailing bytes tolerated as HEAD).
		// An empty body is "no answer" (OK); a read error or a non-empty
		// body that is not decodable (also: truncated at the bound) yields
		// exactly one FeatureNegotiation FAILURE record carrying the error,
		// nothing negotiated, and never fails the create.
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxPCFCreateBodyBytes))
		var ctxResp struct {
			AscRespData  *AppSessionContextRespData `json:"ascRespData"`
			AppSessionID string                     `json:"appSessionId"`
		}
		var negotiated features.Set
		switch {
		case rerr != nil:
			negotiated = c.failNegotiation(ctx, nil, "BODY_READ_ERROR", rerr)
		case len(bytes.TrimSpace(raw)) == 0:
			negotiated = negotiateConsumer(ctx, c.flog, "Npcf", "PCF", c.catalog(), c.profile, offer, nil)
		default:
			if uerr := json.NewDecoder(bytes.NewReader(raw)).Decode(&ctxResp); uerr != nil {
				ctxResp.AscRespData, ctxResp.AppSessionID = nil, ""
				negotiated = c.failNegotiation(ctx, raw, "BODY_DECODE_ERROR", uerr)
			} else {
				var answer json.RawMessage
				if ctxResp.AscRespData != nil {
					answer = ctxResp.AscRespData.SuppFeat
				}
				negotiated = negotiateConsumer(ctx, c.flog, "Npcf", "PCF", c.catalog(), c.profile, offer, answer)
			}
		}

		// Extract appSessionId from the Location header (absolute {apiRoot}/...
		// per TS 29.501 §4.4.1; relative form still accepted). The path must be
		// exactly the app-sessions collection plus one id.
		loc := resp.Header.Get("Location")
		if strings.TrimSpace(loc) != "" {
			id := sbi.ResourceIDFromLocationUnder(loc, appSessionsPath)
			if id == "" {
				return "", features.Set{}, fmt.Errorf("nef: pcf create app-session: Location %q is not under %s", loc, appSessionsPath)
			}
			return id, negotiated, nil
		}
		// Legacy fallback for a PCF that predates the Rel-17 alignment and
		// returned the id only in the (non-schema) body, with no Location.
		if ctxResp.AppSessionID != "" {
			c.logger().Warn("PCF app-session 201 without Location: using legacy body appSessionId",
				"procedure", "AppSessionCreate", "interface", "Npcf", "direction", "IN",
				"result", "OK", "cause", "MISSING_LOCATION",
				"app_session_id", ctxResp.AppSessionID,
				"spec_ref", "TS 29.514 §4.2.2 / TS 29.501 §4.4.1")
			return ctxResp.AppSessionID, negotiated, nil
		}
		return "", features.Set{}, fmt.Errorf("nef: pcf create app-session: 201 but no appSessionId in Location or body")

	case http.StatusForbidden:
		// PCF rejected the authorization — propagate as a 403 to the AF.
		// Ref: TS 29.514 §5.2.2.2.4
		return "", features.Set{}, fmt.Errorf("403: pcf rejected policy authorization")

	default:
		return "", features.Set{}, fmt.Errorf("nef: pcf create app-session: unexpected status %d", resp.StatusCode)
	}
}

// failNegotiation logs exactly one consumer FeatureNegotiation record with
// result=FAILURE, the cause and the error (raw is the unusable body, may be
// nil), and returns the empty set.
func (c *HTTPPolicyAuthClient) failNegotiation(ctx context.Context, raw []byte, cause string, cerr error) features.Set {
	features.LogNegotiation(ctx, c.flog, features.Negotiation{
		NF:        "NEF",
		Interface: "Npcf", Direction: "OUT", PeerNF: "PCF",
		SpecRef: features.SpecRef, Result: "FAILURE", Cause: cause,
		Local: c.catalog().Supported(c.profile),
		Peer:  string(raw), PeerPresent: len(raw) > 0, Negotiated: features.Set{},
	}, "error", cerr)
	return features.Set{}
}

// DeleteAppSession implements PolicyAuthorizationClient.
// Sends POST /npcf-policyauthorization/v1/app-sessions/{appSessionID}/delete
// to pcfBaseURI with NO request body and no Content-Type: the
// EventsSubscReqData body is optional (requestBody required: false) and its
// schema requires "events", so an empty object would be invalid.
//
// Ref: TS 29.514 §4.2.4.2, §5.3.3.4.2
func (c *HTTPPolicyAuthClient) DeleteAppSession(ctx context.Context, pcfBaseURI, appSessionID string) error {
	url := pcfBaseURI + "/npcf-policyauthorization/v1/app-sessions/" + appSessionID + "/delete"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("nef: pcf delete app-session: new request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("nef: pcf delete app-session: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		// App-session already gone — treat as success (idempotent).
		// Ref: TS 29.514 §4.2.4.2
		if c.Logger != nil {
			c.Logger.InfoContext(ctx, "pcf app-session already gone (treated as deleted)",
				"procedure", "AppSessionDelete", "interface", "Npcf",
				"direction", "IN", "spec_ref", "TS 29.514 §4.2.4.2",
				"app_session_id", appSessionID, "result", "OK")
		}
		return nil
	default:
		detail := readProblemCause(resp.Body)
		return fmt.Errorf("nef: pcf delete app-session: unexpected status %d%s", resp.StatusCode, detail)
	}
}

// maxProblemBodyBytes bounds how much of a PCF error body is read/echoed.
const maxProblemBodyBytes = 512

// readProblemCause extracts the ProblemDetails "cause" (or a truncated body)
// from an error response, formatted as a suffix for an error message.
func readProblemCause(r io.Reader) string {
	raw, _ := io.ReadAll(io.LimitReader(r, maxProblemBodyBytes))
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	var pd struct {
		Cause string `json:"cause"`
	}
	if err := json.Unmarshal(raw, &pd); err == nil && pd.Cause != "" {
		return " (cause " + pd.Cause + ")"
	}
	return " (body " + string(raw) + ")"
}
