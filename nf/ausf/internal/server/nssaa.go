package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
)

// NSSAA EAP relay — POST /nausf-nssaa/v1/{supi}/authenticate
//
// The AMF (EAP pass-through authenticator) relays the UE's slice-auth EAP packets
// to the AAA-S through the AUSF. There is no separate NSSAAF NF nor a real external
// AAA-S in this deployment; the AUSF fronts a *simulated* AAA-S that runs a single
// EAP round (Identity → Success/Failure). The decision is deterministic: the AAA-S
// rejects when the EAP-Response/Identity NAI contains the substring "reject"
// (case-insensitive), and authorizes otherwise. This proves the EAP round-trip path
// AMF → AUSF → AAA-S without binding to a specific EAP method.
//
// Ref: TS 23.502 §4.2.9.2, TS 33.501 §16, TS 29.526 (Nnssaaf_NSSAA, mapped here).

type nssaaRequest struct {
	SUPI       string `json:"supi"`
	GPSI       string `json:"gpsi,omitempty"`
	SNSSAI     snssai `json:"snssai"`
	EAPPayload string `json:"eapPayload"` // base64 EAP packet (EAP-Response from the UE)
}

type snssai struct {
	SST uint8  `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

// EAP authentication results (TS 29.509 §6.1.6.3.6 AuthResult, reused for NSSAA).
const (
	authResultSuccess = "EAP_SUCCESS"
	authResultFailure = "EAP_FAILURE"
)

type nssaaResponse struct {
	AuthResult string `json:"authResult"`
	EAPPayload string `json:"eapPayload"` // base64 terminal EAP packet (Success/Failure)
}

// handleNSSAAAuthenticate relays the UE's EAP-Response to the simulated AAA-S and
// returns the terminal EAP result.
func (s *Server) handleNSSAAAuthenticate(w http.ResponseWriter, r *http.Request) {
	spanCtx, span := tracing.Tracer("AUSF", "procedures").Start(r.Context(), "Nausf_NSSAA_Authenticate")
	defer span.End()
	r = r.WithContext(spanCtx)

	supi := r.PathValue("supi")
	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With(
		"procedure", "NSSAA",
		"interface", "Nausf",
		"direction", "IN",
		"correlation_id", corrID,
		"spec_ref", "TS 23.502 §4.2.9.2",
		"supi", supi,
	)

	var req nssaaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}
	if req.SUPI == "" {
		req.SUPI = supi
	}

	eapResp, err := base64.StdEncoding.DecodeString(req.EAPPayload)
	if err != nil || len(eapResp) == 0 {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "eapPayload missing or not base64")
		return
	}
	if err := eap.Validate(eapResp); err != nil {
		problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", err.Error())
		return
	}

	identifier, _ := eap.Identifier(eapResp)
	identity, idErr := eap.Identity(eapResp)

	// Simulated AAA-S decision.
	authorized := idErr == nil && !strings.Contains(strings.ToLower(identity), "reject")

	var resp nssaaResponse
	if authorized {
		resp = nssaaResponse{
			AuthResult: authResultSuccess,
			EAPPayload: base64.StdEncoding.EncodeToString(eap.BuildSuccess(identifier)),
		}
	} else {
		resp = nssaaResponse{
			AuthResult: authResultFailure,
			EAPPayload: base64.StdEncoding.EncodeToString(eap.BuildFailure(identifier)),
		}
	}

	log.Info("NSSAA EAP relayed to AAA-S",
		"direction", "OUT",
		"sst", req.SNSSAI.SST,
		"sd", req.SNSSAI.SD,
		"identity", identity,
		"result", resp.AuthResult,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
