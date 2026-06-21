package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// handleDLDataNotification simulates a UPF Downlink Data Report for a PDU session
// whose user plane is deactivated (UE in CM-IDLE) and asks the AMF to page the UE
// via Namf_Communication_N1N2MessageTransfer.
//
// The genuine trigger is an N4 PFCP Session Report from the UPF (UPF-001, which is
// on the hard-stop PFCP session-management path); this endpoint is the control-plane
// stand-in so the paging → Service Request → user-plane-reactivation chain works.
// Ref: TS 23.502 §4.2.3.3.
func (s *Server) handleDLDataNotification(w http.ResponseWriter, r *http.Request) {
	psi64, err := strconv.ParseUint(r.PathValue("pduSessionId"), 10, 8)
	if err != nil {
		problem(w, http.StatusBadRequest, "INVALID_PARAM", "pduSessionId must be 0-255")
		return
	}
	psi := uint8(psi64)

	// SUPI may come from the query string or the JSON body; it disambiguates when
	// several UEs share the same PDU session id.
	supi := r.URL.Query().Get("supi")
	if supi == "" {
		var body struct {
			SUPI string `json:"supi"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		supi = body.SUPI
	}

	log := s.logger.With("procedure", "NetworkTriggeredServiceRequest",
		"interface", "Nsmf", "direction", "IN", "pdu_session_id", psi)

	_, sessions := s.findSessionsByPSI(psi, supi)
	if len(sessions) == 0 {
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no session with that pduSessionId")
		return
	}
	if len(sessions) > 1 {
		supis := make([]string, len(sessions))
		for i, sess := range sessions {
			supis[i] = sess.SUPI
		}
		problem(w, http.StatusConflict, "AMBIGUOUS_SESSION",
			"multiple sessions match pduSessionId; disambiguate with supi — candidates: "+strings.Join(supis, ", "))
		return
	}
	sess := sessions[0]

	s.sessionMu.Lock()
	sessSUPI := sess.SUPI
	state := sess.State
	s.sessionMu.Unlock()

	cause, err := s.triggerN1N2MessageTransfer(r.Context(), sessSUPI, psi)
	if err != nil {
		log.Error("N1N2MessageTransfer to AMF failed", "supi", sessSUPI, "error", err, "result", "FAILURE")
		metrics.ProcedureTotal.WithLabelValues("SMF", "NetworkTriggeredServiceRequest", "FAILURE").Inc()
		problem(w, http.StatusBadGateway, "AMF_TRANSFER_FAILED", err.Error())
		return
	}

	log.Info("DL data notification handled — AMF asked to reach the UE",
		"supi", sessSUPI, "session_state", state, "amf_cause", cause,
		"result", "OK", "spec_ref", "TS 23.502 §4.2.3.3")
	metrics.ProcedureTotal.WithLabelValues("SMF", "NetworkTriggeredServiceRequest", "OK").Inc()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"supi":         sessSUPI,
		"pduSessionId": psi,
		"amfCause":     cause,
		"notifiedAt":   time.Now().UTC().Format(time.RFC3339),
	})
}

// triggerN1N2MessageTransfer POSTs Namf_Communication_N1N2MessageTransfer to the
// AMF (namf-comm, mTLS HTTP/2). Returns the AMF's N1N2 transfer cause.
// Ref: TS 29.518 §5.2.2.3.
func (s *Server) triggerN1N2MessageTransfer(ctx context.Context, supi string, psi uint8) (string, error) {
	if s.cfg.Peers.AMF == "" {
		return "", fmt.Errorf("smf: amf SBI peer not configured")
	}
	payload, _ := json.Marshal(map[string]any{"pduSessionId": psi})
	u := fmt.Sprintf("https://%s/namf-comm/v1/ue-contexts/%s/n1-n2-messages",
		s.cfg.Peers.AMF, url.PathEscape(supi))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(payload)))
	if err != nil {
		return "", fmt.Errorf("smf: build N1N2 request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("smf: N1N2MessageTransfer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("smf: N1N2MessageTransfer: status %d", resp.StatusCode)
	}
	var rsp struct {
		Cause string `json:"cause"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&rsp)
	return rsp.Cause, nil
}
