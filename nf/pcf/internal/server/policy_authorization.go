// Package server — Npcf_PolicyAuthorization handlers (TS 29.514).
//
// This file implements the thin Create + Delete endpoints for app-sessions used
// by the NEF to map an AF AsSessionWithQoS request onto a PCF policy operation.
// The full TS 29.514 lifecycle (Update / Subscribe / Notify / Patch) is out of
// scope for the baseline increment.
//
// Ref: TS 29.514 §5.2.2.2 (Create), §5.2.2.4 (Delete), §5.6.2.3 (data types)
package server

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

// AppSessionContext is the top-level resource for a Npcf_PolicyAuthorization
// app-session. On Create the NEF sends ascReqData; the PCF echoes the full
// context (including the minted appSessionId) in the 201 response body.
//
// Ref: TS 29.514 §5.6.2.2
type AppSessionContext struct {
	// AscReqData holds the request data sent by the NEF on app-session creation.
	// Ref: TS 29.514 §5.6.2.3
	AscReqData *AppSessionContextReqData `json:"ascReqData,omitempty"`
	// AppSessionID is the PCF-assigned identifier for this app-session.
	// Returned in the 201 response body so the NEF can parse it as a fallback
	// when the Location header is unavailable.
	// Ref: TS 29.514 §5.6.2.2
	AppSessionID string `json:"appSessionId,omitempty"`
}

// AppSessionContextReqData carries the AF-supplied parameters mapped by the NEF
// from an AsSessionWithQoS request (TS 29.522 §5.14.2.1.2) onto the PCF
// policy-authorization Create operation.
//
// Ref: TS 29.514 §5.6.2.3
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
	// operator-named QoS) authorized by the PCF. Ref: TS 29.514 §5.6.2.3
	QosReference string `json:"qosReference,omitempty"`
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
	// SuppFeat is the negotiated supported features bitmask.
	SuppFeat string `json:"suppFeat,omitempty"`
}

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
	log := s.logger.With(
		"procedure", "PolicyAuthorizationCreate",
		"interface", "Npcf",
		"direction", "IN",
		"correlation_id", corrID,
		"spec_ref", "TS 29.514 §5.2.2.2",
	)

	var ctx AppSessionContext
	if err := json.NewDecoder(r.Body).Decode(&ctx); err != nil {
		log.Warn("app-session create: malformed JSON body", "error", err)
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT",
			"request body: "+err.Error())
		return
	}

	if ctx.AscReqData == nil {
		log.Warn("app-session create: ascReqData missing")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"ascReqData is mandatory")
		return
	}
	if ctx.AscReqData.UeIpv4 == "" && ctx.AscReqData.UeIpv6 == "" {
		log.Warn("app-session create: no UE address in ascReqData")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"ascReqData.ueIpv4 or ascReqData.ueIpv6 is required")
		return
	}

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

	ctx.AppSessionID = appSessionID

	s.appSessionsMu.Lock()
	s.appSessions[appSessionID] = ctx
	s.appSessionsMu.Unlock()

	log.Info("app-session created",
		"app_session_id", appSessionID,
		"ue_ipv4", ctx.AscReqData.UeIpv4,
		"qos_reference", ctx.AscReqData.QosReference,
		"direction", "OUT",
		"result", "OK",
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/npcf-policyauthorization/v1/app-sessions/"+appSessionID)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ctx)
}

// handleDeleteAppSession processes DELETE /npcf-policyauthorization/v1/app-sessions/{appSessionId}.
// The NEF calls this when the AF deletes its AsSessionWithQoS subscription.
// 204 No Content on success; 404 when the app-session is not found (the NEF
// treats both as success — idempotent delete).
//
// Ref: TS 29.514 §5.2.2.4
func (s *Server) handleDeleteAppSession(w http.ResponseWriter, r *http.Request) {
	appSessionID := r.PathValue("appSessionId")
	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With(
		"procedure", "PolicyAuthorizationDelete",
		"interface", "Npcf",
		"direction", "IN",
		"correlation_id", corrID,
		"spec_ref", "TS 29.514 §5.2.2.4",
		"app_session_id", appSessionID,
	)

	s.appSessionsMu.Lock()
	_, exists := s.appSessions[appSessionID]
	if exists {
		delete(s.appSessions, appSessionID)
	}
	s.appSessionsMu.Unlock()

	if !exists {
		log.Warn("app-session not found", "result", "NOT_FOUND")
		problem(w, http.StatusNotFound, "APP_SESSION_NOT_FOUND",
			"app-session "+appSessionID+" not found")
		return
	}

	log.Info("app-session deleted", "result", "OK")
	w.WriteHeader(http.StatusNoContent)
}
