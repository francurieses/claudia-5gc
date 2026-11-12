// Package server — Npcf_PolicyAuthorization handlers (TS 29.514).
//
// This file implements the thin Create + Delete endpoints for app-sessions used
// by the NEF to map an AF AsSessionWithQoS request onto a PCF policy operation.
// The full TS 29.514 lifecycle (Update / Subscribe / Notify / Patch) is out of
// scope for the baseline increment.
//
// Ref: TS 29.514 §5.2.2.2 (Create), §4.2.4.2 (Delete), §5.6.2.3 (data types)
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/google/uuid"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// AppSessionContext is the top-level resource for a Npcf_PolicyAuthorization
// app-session. On Create the NEF sends ascReqData; the PCF echoes the
// context in the 201 response body. The minted appSessionId is not a schema
// attribute: it is only conveyed by the Location header (TS 29.501 §4.4.1).
//
// Ref: TS 29.514 §5.6.2.2
//
// oapi: TS29514_Npcf_PolicyAuthorization.yaml#/components/schemas/AppSessionContext
type AppSessionContext struct {
	// AscReqData holds the request data sent by the NEF on app-session creation.
	// Ref: TS 29.514 §5.6.2.3
	AscReqData *AppSessionContextReqData `json:"ascReqData,omitempty"`
	// AscRespData carries the PCF's answer: the negotiated supported features.
	// Omitted when there is nothing to answer (rel17 profile, request without
	// suppFeat). Ref: TS 29.514 §5.6.2.2, §5.6.2.4
	AscRespData *AppSessionContextRespData `json:"ascRespData,omitempty"`
	// Features is the set negotiated at creation (TS 29.500 §6.6.2); not part
	// of the resource representation.
	Features features.Set `json:"-"`
}

// AppSessionContextRespData is the response part of an AppSessionContext: the
// PCF's answer to the AF's ascReqData. Only suppFeat is modelled.
// Ref: TS 29.514 §5.6.2.4
//
// oapi: TS29514_Npcf_PolicyAuthorization.yaml#/components/schemas/AppSessionContextRespData
type AppSessionContextRespData struct {
	// SuppFeat is the features negotiated for the app-session (the
	// intersection of the AF's ascReqData.suppFeat with the PCF's offer).
	// Ref: TS 29.514 §5.8; TS 29.500 §6.6.2.
	SuppFeat string `json:"suppFeat,omitempty"`
}

// AppSessionContextReqData carries the AF-supplied parameters mapped by the NEF
// from an AsSessionWithQoS request (TS 29.522 §5.14.2.1.2) onto the PCF
// policy-authorization Create operation.
//
// Ref: TS 29.514 §5.6.2.3
//
// oapi: TS29514_Npcf_PolicyAuthorization.yaml#/components/schemas/AppSessionContextReqData
type AppSessionContextReqData struct {
	// AspId is the Application Service Provider identifier (AF / scsAsId).
	// Ref: TS 29.514 §5.6.2.3
	AspId string `json:"aspId,omitempty"`
	// AfAppId is the application identifier as known to the AF.
	AfAppId string `json:"afAppId,omitempty"`
	// UeIpv4 is the UE IPv4 address to which the QoS applies. At least one of
	// UeIpv4 / UeIpv6 MUST be present. Ref: TS 29.514 §5.6.2.3
	UeIpv4 string `json:"ueIpv4,omitempty"`
	// UeIpv6 is the UE IPv6 address (alternative to UeIpv4).
	UeIpv6 string `json:"ueIpv6,omitempty"`
	// QosReference is the pre-provisioned QoS profile reference (5QI-equivalent /
	// operator-named QoS) authorized by the PCF. Filled by captureQosReference
	// from the spec home medComponents[].qosReference (MediaComponent,
	// TS 29.514 §5.6.2.10) or, for a rel17-profile NEF, from the project member
	// ascReqData.qosReference; never decoded by encoding/json directly, so a
	// type error keeps its "ascReqData.suppFeat" field path.
	QosReference string `json:"-"`
	// qosTopLevel records that the reference arrived as the top-level project
	// member, which the 201 echo then reproduces byte for byte.
	qosTopLevel bool
	// Dnn is the Data Network Name scoping the authorization.
	Dnn string `json:"dnn,omitempty"`
	// SliceInfo is the S-NSSAI scoping the authorization.
	// Reuses PcfBindingSnssai (sst + optional sd) which is already defined in this
	// package; a separate AppSnssai type is not needed.
	SliceInfo *PcfBindingSnssai `json:"sliceInfo,omitempty"`
	// MedComponents is a map of media components describing the IP flows.
	// The baseline accepts the map as generic JSON so no MediaComponent struct is
	// needed here (the PCF stores the app-session as-is without interpreting media).
	MedComponents map[string]any `json:"medComponents,omitempty"`
	// NotifUri is the AF notification URI. Required by the schema but accepted
	// when absent in every profile (mixed-release AFs); stored with the
	// app-session as received. (The "{notifUri}/notify" callback form of
	// §5.5.2.2 is defined for evSubsc.notifUri, not this field.)
	// Ref: TS 29.514 §5.6.2.3, §5.5.2.2
	NotifUri string `json:"notifUri,omitempty"`
	// SuppFeat is the AF's offered supported features as received (echoed
	// with the rest of ascReqData); the negotiated value is answered in
	// AscRespData.SuppFeat. Ref: TS 29.514 §5.6.2.3, §5.8.
	SuppFeat string `json:"suppFeat,omitempty"`
}

// legacyAscReqData is the Rel-17-profile (frozen) shape of ascReqData as echoed
// to a NEF that sent the top-level qosReference.
//
// oapi: none legacy Rel-17-profile wire shape of AppSessionContextReqData (top-level qosReference), see AppSessionContextReqData
type legacyAscReqData struct {
	AspId         string            `json:"aspId,omitempty"`
	AfAppId       string            `json:"afAppId,omitempty"`
	UeIpv4        string            `json:"ueIpv4,omitempty"`
	UeIpv6        string            `json:"ueIpv6,omitempty"`
	QosReference  string            `json:"qosReference,omitempty"`
	Dnn           string            `json:"dnn,omitempty"`
	SliceInfo     *PcfBindingSnssai `json:"sliceInfo,omitempty"`
	MedComponents map[string]any    `json:"medComponents,omitempty"`
	NotifUri      string            `json:"notifUri,omitempty"`
	SuppFeat      string            `json:"suppFeat,omitempty"`
}

// MarshalJSON echoes the top-level qosReference only when the request carried
// it (rel17-profile NEF); otherwise the spec shape.
func (a AppSessionContextReqData) MarshalJSON() ([]byte, error) {
	if a.qosTopLevel && a.QosReference != "" {
		b, err := json.Marshal(legacyAscReqData{
			AspId: a.AspId, AfAppId: a.AfAppId, UeIpv4: a.UeIpv4, UeIpv6: a.UeIpv6,
			QosReference: a.QosReference, Dnn: a.Dnn, SliceInfo: a.SliceInfo,
			MedComponents: a.MedComponents, NotifUri: a.NotifUri, SuppFeat: a.SuppFeat,
		})
		if err != nil {
			return nil, fmt.Errorf("pcf: marshal AppSessionContextReqData: %w", err)
		}
		return b, nil
	}
	type plain AppSessionContextReqData
	b, err := json.Marshal(plain(a))
	if err != nil {
		return nil, fmt.Errorf("pcf: marshal AppSessionContextReqData: %w", err)
	}
	return b, nil
}

// captureQosReference fills a.QosReference from either wire shape of the
// request body raw: the project member ascReqData.qosReference wins when
// present (rel17-profile NEF), else the first (in key order) non-empty
// medComponents[].qosReference. TS 29.500 §6.6.2: tolerant reader. A
// qosReference that is not a string violates the schema and returns an error
// (the handler answers 400, TS 29.500 §5.2.7.2).
func (a *AppSessionContextReqData) captureQosReference(raw []byte) error {
	var probe struct {
		AscReqData struct {
			QosReference string `json:"qosReference"`
		} `json:"ascReqData"`
	}
	// Same first-value decode as the main decoder, so trailing bytes are
	// handled identically.
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&probe); err != nil {
		return fmt.Errorf("pcf: decode ascReqData.qosReference: %w", err)
	}
	if probe.AscReqData.QosReference != "" {
		a.QosReference, a.qosTopLevel = probe.AscReqData.QosReference, true
		return nil
	}
	keys := make([]string, 0, len(a.MedComponents))
	for k := range a.MedComponents {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		m, ok := a.MedComponents[k].(map[string]any)
		if !ok {
			continue
		}
		q, present := m["qosReference"]
		if !present {
			continue
		}
		qs, isStr := q.(string)
		if !isStr {
			return fmt.Errorf("pcf: medComponents[%s].qosReference: not a string", k)
		}
		if qs != "" {
			a.QosReference = qs
			return nil
		}
	}
	return nil
}

// decodeBodyCapturing is decodeBody that also returns the body bytes, read
// once under features.MaxRequestBodyBytes and decoded exactly once into v
// (first JSON value, trailing bytes tolerated as decodeBody does), for
// captureQosReference.
func decodeBodyCapturing(w http.ResponseWriter, r *http.Request, v any) (raw []byte, tooLarge bool, err error) {
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	raw, err = io.ReadAll(r.Body)
	if err == nil {
		err = json.NewDecoder(bytes.NewReader(raw)).Decode(v)
	}
	var mbe *http.MaxBytesError
	return raw, errors.As(err, &mbe), err
}

// Policy authorization procedure names and clauses (logs and metrics).
const (
	procPolicyAuthCreate    = "PolicyAuthorizationCreate"
	procPolicyAuthDelete    = "PolicyAuthorizationDelete"
	policyAuthCreateSpecRef = "TS 29.514 §4.2.2"
	policyAuthDeleteSpecRef = "TS 29.514 §4.2.4.2"
)

// handleCreateAppSession processes POST /npcf-policyauthorization/v1/app-sessions.
// The NEF calls this to map an AF AsSessionWithQoS Create onto the PCF.
// On success the PCF mints an appSessionId, stores the AppSessionContext in-memory,
// logs the authorized qosReference, and returns 201 Created.
//
// QoS binding note: the PCF here receives only the UE IP, not the SUPI, so a
// precise SUPI→SM-policy binding is not possible in this thin baseline. The
// app-session is stored and the authorized qosReference is logged. A full
// UE-IP→SUPI resolution and DNN-scoped override binding is deferred to a future
// increment (requires the PCF to query the BSF or UDR for the SUPI).
//
// Ref: TS 29.514 §5.2.2.2
func (s *Server) handleCreateAppSession(w http.ResponseWriter, r *http.Request) {
	corrID := r.Header.Get("X-Correlation-Id")
	base := s.procLog(r, procPolicyAuthCreate)
	log := dirLog(base, ifaceNpcf, dirIn, policyAuthCreateSpecRef)
	out := dirLog(base, ifaceNpcf, dirOut, policyAuthCreateSpecRef)

	reqCtx := logging.WithCorrelationID(r.Context(), corrID)
	peerNF := peerNFType(r, apiPolicyAuth)

	var ctx AppSessionContext
	rawBody, tooLarge, err := decodeBodyCapturing(w, r, &ctx)
	if err != nil {
		if tooLarge {
			s.payloadTooLarge(reqCtx, w, apiPolicyAuth, procPolicyAuthCreate)
			return
		}
		if features.IsTypeErrorOn(err, apiInfos[apiPolicyAuth].field) {
			s.rejectSuppFeat(reqCtx, w, apiPolicyAuth, peerNF, "<non-string>", err, detailNotString)
			return
		}
		log.Warn("app-session create: malformed JSON body", "error", err,
			"result", "REJECT", "cause", "MANDATORY_IE_INCORRECT")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT",
			"request body: "+err.Error())
		return
	}

	// ascRespData is PCF-generated: never accept or echo a client-supplied one.
	ctx.AscRespData = nil

	if ctx.AscReqData != nil {
		if err := ctx.AscReqData.captureQosReference(rawBody); err != nil {
			log.Warn("app-session create: qosReference has the wrong type", "error", err,
				"result", "REJECT", "cause", "MANDATORY_IE_INCORRECT",
				"spec_ref", "TS 29.500 §5.2.7.2")
			problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT",
				"qosReference must be a string")
			return
		}
	}

	// ascReqData.suppFeat must be schema-valid before any state is touched.
	// Ref: TS 29.500 §5.2.7.2, §6.6.2.
	var peerSuppFeat string
	if ctx.AscReqData != nil {
		peerSuppFeat = ctx.AscReqData.SuppFeat
		if err := features.Validate(peerSuppFeat); err != nil {
			s.rejectSuppFeat(reqCtx, w, apiPolicyAuth, peerNF, peerSuppFeat, err, detailNotHex)
			return
		}
	}

	if ctx.AscReqData == nil {
		log.Warn("app-session create: ascReqData missing",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"ascReqData is mandatory")
		return
	}
	if ctx.AscReqData.UeIpv4 == "" && ctx.AscReqData.UeIpv6 == "" {
		log.Warn("app-session create: no UE address in ascReqData",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"ascReqData.ueIpv4 or ascReqData.ueIpv6 is required")
		return
	}

	// Producer side (decision D1): the intersection, answered in
	// ascRespData.suppFeat; absent under rel17 when the request had none.
	// Ref: TS 29.514 §5.8.
	suppAnswer, suppSet := s.answer(apiPolicyAuth, peerSuppFeat)

	appSessionID := uuid.NewString()

	// Best-effort QoS binding note: the PCF here knows the UE IP but not the SUPI,
	// so it cannot directly key into smPolicyOverrides (which is SUPI-keyed).
	// The authorized qosReference is logged for traceability. A precise binding
	// (UE-IP → SUPI lookup → DNN-scoped override) is deferred.
	// Ref: docs/procedures/network-exposure.md "PCF leg (new thin endpoint)"
	log.Info("authorized QoS recorded (DNN-scoped override binding deferred — UE-IP→SUPI resolution out of baseline scope)",
		"app_session_id", appSessionID,
		"ue_ipv4", ctx.AscReqData.UeIpv4,
		"ue_ipv6", ctx.AscReqData.UeIpv6,
		"qos_reference", ctx.AscReqData.QosReference,
		"dnn", ctx.AscReqData.Dnn,
		"asp_id", ctx.AscReqData.AspId,
	)

	ctx.Features = suppSet
	if suppAnswer != "" {
		ctx.AscRespData = &AppSessionContextRespData{SuppFeat: suppAnswer}
	}

	s.appSessionsMu.Lock()
	s.appSessions[appSessionID] = ctx
	s.appSessionsMu.Unlock()

	// Request accepted: record the negotiation (TS 29.500 §6.6.2).
	s.logAccepted(reqCtx, apiPolicyAuth, peerNF, peerSuppFeat, suppSet)

	out.Info("app-session created",
		"app_session_id", appSessionID,
		"ue_ipv4", ctx.AscReqData.UeIpv4,
		"qos_reference", ctx.AscReqData.QosReference,
		"result", "OK",
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", s.apiRoot(r)+"/npcf-policyauthorization/v1/app-sessions/"+appSessionID)
	w.WriteHeader(http.StatusCreated)
	encodeBody(out, w, ctx)
}

// handleDeleteAppSession processes POST /npcf-policyauthorization/v1/app-sessions/{appSessionId}/delete
// (optional EventsSubscReqData body, size-bounded and syntax-checked, content
// ignored). The NEF calls this when the AF deletes its AsSessionWithQoS
// subscription. 204 No Content on success; 404
// when the app-session is not found (the NEF treats both as success).
//
// Ref: TS 29.514 §4.2.4.2, §5.3.3.4.2
func (s *Server) handleDeleteAppSession(w http.ResponseWriter, r *http.Request) {
	appSessionID := r.PathValue("appSessionId")
	base := s.procLog(r, procPolicyAuthDelete).With("app_session_id", appSessionID)
	out := dirLog(base, ifaceNpcf, dirOut, policyAuthDeleteSpecRef)

	// Optional EventsSubscReqData body: bounded and syntax-checked, content
	// ignored (no event reporting yet -> 204, TS 29.514 §4.2.4.2 b). Validated
	// before any state is deleted.
	if _, ok := s.readOptionalJSONBody(w, r, apiPolicyAuth, procPolicyAuthDelete, base); !ok {
		return
	}

	s.appSessionsMu.Lock()
	_, exists := s.appSessions[appSessionID]
	if exists {
		delete(s.appSessions, appSessionID)
	}
	s.appSessionsMu.Unlock()

	if !exists {
		out.Warn("app-session not found", "result", "REJECT", "cause", "APPLICATION_SESSION_CONTEXT_NOT_FOUND")
		problem(w, http.StatusNotFound, "APPLICATION_SESSION_CONTEXT_NOT_FOUND",
			"app-session "+appSessionID+" not found")
		return
	}

	out.Info("app-session deleted", "result", "OK")
	w.WriteHeader(http.StatusNoContent)
}
