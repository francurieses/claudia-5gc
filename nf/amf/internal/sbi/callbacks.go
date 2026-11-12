package sbi

// callbacks.go - consumer-side callback endpoints the AMF hands to the UDM:
// the Nudm_UECM DeregistrationNotification (deregCallbackUri of the
// Amf3GppAccessRegistration) and the Nudm_SDM ModificationNotification
// (callbackReference of the SdmSubscription). AUD-registration-17.
//
// Both validate the body, log with the canonical fields and answer 204. The
// DeregistrationNotification resolves the UE by the SUPI path suffix of the
// deregCallbackUri and runs the local deregistration (404 if unknown).

import (
	"encoding/json"
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/logging"
)

const (
	// UDMDeregCallbackPath receives Nudm_UECM DeregistrationNotification.
	// Ref: TS 29.503 §5.3.2.3 (DeregistrationNotification; URI from §5.3.2.2 deregCallbackUri), §6.2.5.2 (DeregistrationData).
	UDMDeregCallbackPath = "/namf-callback/v1/udm-uecm/dereg-notify"
	// UDMSDMCallbackPath receives Nudm_SDM ModificationNotification.
	// Ref: TS 29.503 §5.2.2.5 (ModificationNotification; URI from §5.2.2.3 callbackReference), §6.1.6.2.21.
	UDMSDMCallbackPath = "/namf-callback/v1/udm-sdm/modification-notify"
)

// maxCallbackBodyBytes bounds a callback request body (own bound, not a spec value).
const maxCallbackBodyBytes = 1 << 20

// handleUDMDeregNotify serves the DeregistrationNotification. deregReason is
// mandatory (DeregistrationData, TS 29.503 Table 6.2.6.2.5-1).
func (s *Server) handleUDMDeregNotify(w http.ResponseWriter, r *http.Request) {
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "UDMDeregistrationNotification").With(
		"nf", "AMF", "interface", "Nudm", "direction", "IN",
		"spec_ref", "TS 29.503 §5.3.2.3, §6.2.6.2.5")
	var body struct {
		DeregReason string `json:"deregReason"`
		AccessType  string `json:"accessType"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCallbackBodyBytes)).Decode(&body); err != nil || body.DeregReason == "" {
		log.Warn("UDM deregistration notification rejected: invalid body",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", errString(err))
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "deregReason is mandatory")
		return
	}
	supi := r.PathValue("supi")
	ue, ok := s.mgr.GetBySUPI(supi)
	if !ok {
		log.Warn("UDM deregistration notification: UE unknown",
			"result", "REJECT", "cause", "CONTEXT_NOT_FOUND", "supi", supi, "dereg_reason", body.DeregReason)
		s.problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no UE context for the SUPI")
		return
	}
	if s.onUDMDereg == nil {
		log.Error("UDM deregistration notification: no local deregistration handler wired",
			"result", "FAILURE", "cause", "NOT_WIRED", "supi", supi)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", "deregistration not available")
		return
	}
	if err := s.onUDMDereg(r.Context(), ue, body.DeregReason); err != nil {
		log.Error("UDM deregistration notification: local deregistration failed",
			"result", "FAILURE", "cause", "DEREGISTRATION_FAILED", "supi", supi, "error", err.Error())
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", "local deregistration failed")
		return
	}
	log.Info("UDM deregistration notification: UE deregistered locally",
		"result", "OK", "supi", supi, "dereg_reason", body.DeregReason, "access_type", body.AccessType)
	w.WriteHeader(http.StatusNoContent)
}

// handleUDMSDMNotify serves the SDM ModificationNotification: notifyItems
// (rel19 shape) or resourceChanges (frozen rel17 shape) must be present.
func (s *Server) handleUDMSDMNotify(w http.ResponseWriter, r *http.Request) {
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "UDMSDMNotification").With(
		"nf", "AMF", "interface", "Nudm", "direction", "IN",
		"spec_ref", "TS 29.503 §5.2.2.5, §6.1.6.2.21")
	var body struct {
		NotifyItems     []json.RawMessage `json:"notifyItems"`
		ResourceChanges []json.RawMessage `json:"resourceChanges"`
		SubscriptionID  string            `json:"subscriptionId"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCallbackBodyBytes)).Decode(&body); err != nil ||
		len(body.NotifyItems)+len(body.ResourceChanges) == 0 {
		log.Warn("UDM SDM notification rejected: invalid body",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", errString(err))
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "notifyItems is mandatory")
		return
	}
	log.Info("UDM SDM modification notification received",
		"result", "OK", "subscription_id", body.SubscriptionID,
		"items", len(body.NotifyItems)+len(body.ResourceChanges))
	w.WriteHeader(http.StatusNoContent)
}

// errString renders a possibly-nil error for logging (nil = missing-field reject).
func errString(err error) string {
	if err == nil {
		return "mandatory attribute missing"
	}
	return err.Error()
}
