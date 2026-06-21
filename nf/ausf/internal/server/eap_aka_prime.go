package server

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/francurieses/claudia-5gc/shared/aka"
	"github.com/francurieses/claudia-5gc/shared/crypto/eapaka"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// eapIdentifier is the EAP Identifier used for the single-round AKA'-Challenge.
const eapIdentifier byte = 1

// initEAPAKAPrime handles the EAP-AKA' branch of Nausf_UEAuthentication_Authenticate.
//
// The UDM returned the transformed AV (RAND, AUTN, XRES, CK', IK'). The AUSF
// derives the EAP-AKA' key hierarchy, builds the EAP-Request/AKA'-Challenge and
// returns it to the AMF together with the eap-session link.
// Ref: TS 33.501 §6.1.3.1, RFC 5448 §3.
func (s *Server) initEAPAKAPrime(w http.ResponseWriter, r *http.Request, log *slog.Logger, snName string, udm *UDMAuthDataResponse) {
	if snName == "" {
		snName = s.cfg.ServingNetworkName
	}

	randBytes, err1 := hex.DecodeString(udm.Rand)
	autnBytes, err2 := hex.DecodeString(udm.Autn)
	ckPrime, err3 := hex.DecodeString(udm.CkPrime)
	ikPrime, err4 := hex.DecodeString(udm.IkPrime)
	xres, err5 := hex.DecodeString(udm.Xres)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil ||
		len(randBytes) != 16 || len(autnBytes) != 16 || len(ckPrime) != 16 || len(ikPrime) != 16 || len(xres) == 0 {
		log.Error("invalid EAP-AKA' AV from UDM")
		problem(w, http.StatusInternalServerError, "NF_FAILURE", "invalid EAP-AKA' AV from UDM")
		return
	}

	// Derive the EAP-AKA' key hierarchy: MK = PRF'(IK'|CK', "EAP-AKA'"|Identity).
	// The Identity is the SUPI; the UE derives the same keys from the same inputs.
	keys := eapaka.DeriveKeys([16]byte(ckPrime), [16]byte(ikPrime), udm.Supi)
	kausf := eapaka.KAUSFFromEMSK(keys.EMSK)

	// Build EAP-Request/AKA'-Challenge (AT_RAND, AT_AUTN, AT_KDF, AT_KDF_INPUT, AT_MAC).
	challenge := eapaka.BuildChallenge(eapIdentifier, [16]byte(randBytes), [16]byte(autnBytes), snName, keys.KAut)

	authCtxID := uuid.NewString()
	ctx := &aka.AuthContext{
		SUPI:           udm.Supi,
		ServingNetName: snName,
		RAND:           [16]byte(randBytes),
		AUTN:           [16]byte(autnBytes),
		XRES:           [8]byte(xres[:8]),
		KAUSF:          kausf,
		AuthType:       "EAP_AKA_PRIME",
		EAPKAut:        keys.KAut,
		EAPIdentifier:  eapIdentifier,
		CreatedAt:      time.Now(),
	}
	s.authStore.Put(authCtxID, ctx)

	locationURL := fmt.Sprintf("/nausf-auth/v1/ue-authentications/%s", authCtxID)
	log.Info("EAP-AKA' challenge generated, returning to AMF",
		"direction", "OUT",
		"auth_ctx_id", authCtxID,
		"supi", udm.Supi,
		"auth_type", "EAP_AKA_PRIME",
		"spec_ref", "TS 33.501 §6.1.3.1",
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", locationURL)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authType": "EAP_AKA_PRIME",
		"5gAuthData": map[string]any{
			"eapPayload": base64.StdEncoding.EncodeToString(challenge),
		},
		"_links": map[string]any{
			"eap-session": map[string]string{
				"href": locationURL + "/eap-session",
			},
		},
		"servingNetworkName": snName,
	})
}

// handleEAPSession — PUT /nausf-auth/v1/ue-authentications/{authCtxId}/eap-session
//
// Receives the EAP-Response/AKA'-Challenge from the UE (relayed by the AMF),
// verifies AT_MAC and AT_RES, and on success returns EAP-Success + K_SEAF.
// Ref: TS 29.509 §5.7, §6.1.6.2.4; RFC 5448 §3.
func (s *Server) handleEAPSession(w http.ResponseWriter, r *http.Request) {
	authCtxID := r.PathValue("authCtxId")
	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With(
		"procedure", "EapAkaPrime",
		"interface", "Nausf",
		"direction", "IN",
		"correlation_id", corrID,
		"auth_ctx_id", authCtxID,
		"spec_ref", "TS 33.501 §6.1.3.1",
	)

	var body struct {
		EapPayload string `json:"eapPayload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}

	ctx, ok := s.authStore.Get(authCtxID)
	if !ok {
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "unknown authCtxId")
		return
	}
	if ctx.AuthType != "EAP_AKA_PRIME" {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "auth context is not EAP-AKA'")
		return
	}
	if time.Since(ctx.CreatedAt) > 5*time.Minute {
		s.authStore.Delete(authCtxID)
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "auth context expired")
		return
	}
	log = log.With("supi", ctx.SUPI)

	pkt, err := base64.StdEncoding.DecodeString(body.EapPayload)
	if err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "eapPayload: invalid base64")
		return
	}
	if err := eapaka.Validate(pkt); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}

	// Verify AT_MAC with K_aut, then compare AT_RES against the stored XRES.
	macOK := eapaka.VerifyMAC(pkt, ctx.EAPKAut)
	res, resErr := eapaka.ExtractRES(pkt)
	resOK := resErr == nil && hmac.Equal(res, ctx.XRES[:])

	if !macOK || !resOK {
		s.authStore.Delete(authCtxID)
		log.Warn("EAP-AKA' authentication failed",
			"result", "REJECT",
			"mac_ok", macOK,
			"res_ok", resOK,
			"spec_ref", "TS 33.501 §6.1.3.1",
		)
		metrics.AuthenticationTotal.WithLabelValues("AUSF", "FAILURE").Inc()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authResult": "AUTHENTICATION_FAILURE",
			"eapPayload": base64.StdEncoding.EncodeToString(eapaka.BuildFailure(ctx.EAPIdentifier)),
		})
		return
	}

	// Success: K_SEAF = KDF(K_AUSF, SN name).
	kseaf := kdf.KSEAF(ctx.KAUSF, ctx.ServingNetName)
	s.authStore.Delete(authCtxID)
	log.Info("EAP-AKA' authentication succeeded",
		"result", "OK",
		"direction", "OUT",
		"spec_ref", "TS 33.501 §6.1.3.1",
	)
	metrics.AuthenticationTotal.WithLabelValues("AUSF", "OK").Inc()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authResult": "AUTHENTICATION_SUCCESS",
		"eapPayload": base64.StdEncoding.EncodeToString(eapaka.BuildSuccess(ctx.EAPIdentifier)),
		"kSeaf":      hex.EncodeToString(kseaf),
		"supi":       ctx.SUPI,
	})
}
