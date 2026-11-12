package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
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

// nssaaRequest is the request body of the AUSF-hosted simulated NSSAA relay.
//
// oapi: none legacy Rel-17-profile wire shape (AUSF-hosted relay), see SliceAuthInfo
type nssaaRequest struct {
	SUPI       string `json:"supi"`
	GPSI       string `json:"gpsi,omitempty"`
	SNSSAI     snssai `json:"snssai"`
	EAPPayload string `json:"eapPayload"` // base64 EAP packet (EAP-Response from the UE)
}

// snssai is the S-NSSAI carried in NSSAA relay bodies.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/Snssai
type snssai struct {
	SST uint8  `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

// EAP authentication results (TS 29.509 §6.1.6.3.6 AuthResult, reused for NSSAA).
const (
	authResultSuccess = "EAP_SUCCESS"
	authResultFailure = "EAP_FAILURE"
)

// nssaaResponse is the response body of the AUSF-hosted simulated NSSAA relay.
//
// oapi: none legacy Rel-17-profile wire shape (AUSF-hosted relay), see SliceAuthInfo
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

// ---- TS 29.526 Nnssaaf_NSSAA resource (REL19-3.5 slice E) -----------------

const (
	// nssaaBasePath is the TS 29.526 §6.1.1 apiRoot-relative base of the
	// Nnssaaf_NSSAA API, "/nnssaaf-nssaa/v1".
	nssaaBasePath = "/nnssaaf-nssaa/v1"
	// nssaaCtxPath is the slice-authentications collection of TS 29.526 §6.1.3.
	nssaaCtxPath = nssaaBasePath + "/slice-authentications"
	// nssaaCtxTTL bounds how long a non-terminal slice authentication context
	// waits for the confirmation (own bound, not a spec timer).
	nssaaCtxTTL = 5 * time.Minute
	// nssaaMaxContexts bounds the context map (own bound); on overflow the
	// oldest entries are evicted.
	nssaaMaxContexts = 4096
	// nssaaChallengeMarker in the EAP-Response/Identity NAI makes the simulated
	// AAA-S run a second round (EAP-Request, then a terminal result on PUT).
	nssaaChallengeMarker = "challenge"
	// eapTypeMD5Challenge is the EAP method type used for the simulated
	// second-round EAP-Request. Ref: RFC 3748 §5.4
	eapTypeMD5Challenge byte = 4
	// causeSliceAuthRejected is the application error of a slice that is not
	// authorized. Ref: TS 29.526 §5.2.2.2.1 step 3b, Table 6.1.7.3-1
	causeSliceAuthRejected = "SLICE_AUTH_REJECTED"
	// nssaaIdentityLogLen bounds the hex digest of the NAI written to logs.
	nssaaIdentityLogLen = 8
	// nssaaBadBodyDetail is the fixed detail of a malformed request body, so no
	// decoder text (which may echo input) reaches the peer.
	nssaaBadBodyDetail = "malformed JSON request body"
)

// identityLogID returns a short digest of an EAP identity (NAI), so the log
// correlates requests without carrying the subscriber's identifier.
func identityLogID(identity string) string {
	if identity == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])[:nssaaIdentityLogLen]
}

// validAuthority reports whether h is a plain host[:port] authority.
func validAuthority(h string) bool {
	if h == "" || strings.ContainsAny(h, "/?#@ \t\r\n\\") {
		return false
	}
	u, err := url.Parse("//" + h)
	return err == nil && u.Host == h && u.Hostname() != ""
}

// locationAuthority returns the authority of the Location header: the
// configured SBI authority first, then a routable SBIAddress, and the request
// Host only as a validated last resort ("" = emit a relative reference).
func (s *Server) locationAuthority(r *http.Request) string {
	if a := s.cfg.SBIAuthority; validAuthority(a) {
		return a
	}
	if host, _, err := net.SplitHostPort(s.cfg.SBIAddress); err == nil && validAuthority(s.cfg.SBIAddress) {
		if ip := net.ParseIP(host); host != "" && (ip == nil || !ip.IsUnspecified()) {
			return s.cfg.SBIAddress
		}
	}
	if validAuthority(r.Host) {
		return r.Host
	}
	return ""
}

// sliceAuthInfo is the body of POST /slice-authentications.
//
// oapi: TS29526_Nnssaaf_NSSAA.yaml#/components/schemas/SliceAuthInfo
type sliceAuthInfo struct {
	GPSI           string          `json:"gpsi"`
	SNSSAI         *snssai         `json:"snssai"`
	EAPIDRsp       json.RawMessage `json:"eapIdRsp"` // base64 string, JSON null (EapMessage is nullable) or absent
	AMFInstanceID  string          `json:"amfInstanceId,omitempty"`
	ReauthNotifURI string          `json:"reauthNotifUri,omitempty"`
	RevocNotifURI  string          `json:"revocNotifUri,omitempty"`
}

// sliceAuthContext is the 201 body of POST /slice-authentications.
//
// oapi: TS29526_Nnssaaf_NSSAA.yaml#/components/schemas/SliceAuthContext
type sliceAuthContext struct {
	GPSI       string `json:"gpsi"`
	SNSSAI     snssai `json:"snssai"`
	AuthCtxID  string `json:"authCtxId"`
	EAPMessage string `json:"eapMessage"`
}

// sliceAuthConfirmationData is the body of PUT /slice-authentications/{authCtxId}.
//
// oapi: TS29526_Nnssaaf_NSSAA.yaml#/components/schemas/SliceAuthConfirmationData
type sliceAuthConfirmationData struct {
	GPSI       string  `json:"gpsi"`
	SNSSAI     *snssai `json:"snssai"`
	EAPMessage string  `json:"eapMessage"`
}

// sliceAuthConfirmationResponse is the 200 body of PUT /slice-authentications/{authCtxId}.
//
// oapi: TS29526_Nnssaaf_NSSAA.yaml#/components/schemas/SliceAuthConfirmationResponse
type sliceAuthConfirmationResponse struct {
	GPSI       string `json:"gpsi"`
	SNSSAI     snssai `json:"snssai"`
	EAPMessage string `json:"eapMessage"`
	AuthResult string `json:"authResult,omitempty"`
}

// nssaaCtx is one non-terminal slice authentication context.
type nssaaCtx struct {
	gpsi    string
	snssai  snssai
	eapID   byte
	expires time.Time
	created time.Time
}

// nssaaStore is a bounded, TTL-limited map of slice authentication contexts.
type nssaaStore struct {
	mu  sync.Mutex
	m   map[string]*nssaaCtx
	now func() time.Time
}

func newNSSAAStore() *nssaaStore {
	return &nssaaStore{m: make(map[string]*nssaaCtx), now: time.Now}
}

// put stores c under a fresh id, dropping expired entries and, when still full,
// the oldest one.
func (st *nssaaStore) put(c *nssaaCtx) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	for id, e := range st.m {
		if now.After(e.expires) {
			delete(st.m, id)
		}
	}
	for len(st.m) >= nssaaMaxContexts {
		var oldest string
		for id, e := range st.m {
			if oldest == "" || e.created.Before(st.m[oldest].created) {
				oldest = id
			}
		}
		delete(st.m, oldest)
	}
	id := uuid.NewString()
	c.created, c.expires = now, now.Add(nssaaCtxTTL)
	st.m[id] = c
	return id
}

// take removes and returns the live context id (nil when unknown or expired).
func (st *nssaaStore) take(id string) *nssaaCtx {
	st.mu.Lock()
	defer st.mu.Unlock()
	c := st.m[id]
	delete(st.m, id)
	if c == nil || st.now().After(c.expires) {
		return nil
	}
	return c
}

// takeIfMatch atomically looks the context up and consumes it only when match
// accepts it. found is false for an unknown or expired id; a mismatch leaves
// the context stored (a wrong request must not destroy the exchange).
func (st *nssaaStore) takeIfMatch(id string, match func(*nssaaCtx) bool) (c *nssaaCtx, found, matched bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	e := st.m[id]
	if e == nil {
		return nil, false, false
	}
	if st.now().After(e.expires) {
		delete(st.m, id)
		return nil, false, false
	}
	if !match(e) {
		return nil, true, false
	}
	delete(st.m, id)
	return e, true, true
}

// buildChallenge builds the simulated second-round EAP-Request (RFC 3748 §4.1).
func buildChallenge(identifier byte) []byte {
	const data = 0x01 // one octet of MD5-Challenge Value-Size, simulated
	return []byte{eap.CodeRequest, identifier, 0, 6, eapTypeMD5Challenge, data}
}

// decodeSliceBody decodes a bounded JSON body (unknown members tolerated) and
// answers 413 / 400 itself; it reports whether the caller may continue.
func decodeSliceBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			payloadTooLarge(w)
			return false
		}
		problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", nssaaBadBodyDetail)
		return false
	}
	return true
}

// sliceAuthParams collects the InvalidParam JSON pointers of the mandatory
// attributes (TS 29.526 §6.1.6.2.2 / §6.1.6.2.4).
func sliceAuthParams(gpsi string, sn *snssai, eapField, eapValue string) []map[string]string {
	var ps []map[string]string
	if gpsi == "" {
		ps = append(ps, map[string]string{"param": "/gpsi", "reason": "mandatory attribute missing"})
	}
	if sn == nil {
		ps = append(ps, map[string]string{"param": "/snssai", "reason": "mandatory attribute missing"})
	}
	if eapValue == "" {
		ps = append(ps, map[string]string{"param": "/" + eapField, "reason": "mandatory attribute missing"})
	}
	return ps
}

// decodeEAPField decodes a base64 EapMessage and validates the EAP framing.
func decodeEAPField(field, v string) ([]byte, []map[string]string) {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) == 0 {
		return nil, []map[string]string{{"param": "/" + field, "reason": "not a base64 EAP packet"}}
	}
	if err := eap.Validate(b); err != nil {
		return nil, []map[string]string{{"param": "/" + field, "reason": err.Error()}}
	}
	return b, nil
}

func (s *Server) nssaaStoreOrNew() *nssaaStore {
	s.nssaaOnce.Do(func() { s.nssaaCtxs = newNSSAAStore() })
	return s.nssaaCtxs
}

// nssaaDone increments fivegc_procedure_total for a terminal Nnssaaf_NSSAA
// outcome (OK = EAP-Success, REJECT = EAP-Failure / 4xx). A create that opens a
// multi-round exchange (201 with EAP-Request, PENDING) is not terminal and is
// counted when the PUT completes it.
func nssaaDone(result string) {
	metrics.ProcedureTotal.WithLabelValues("AUSF", "NSSAA", result).Inc()
}

// handleSliceAuthCreate serves POST /nnssaaf-nssaa/v1/slice-authentications:
// the AMF relays the UE's EAP-Response/Identity, the simulated AAA-S answers
// with the next EAP message. A one-round AAA-S answers the terminal
// EAP-Success/Failure; an identity containing "challenge" yields an
// EAP-Request and a stored context completed by the PUT.
// Ref: TS 29.526 §5.2.2.2; TS 23.502 §4.2.9.2
func (s *Server) handleSliceAuthCreate(w http.ResponseWriter, r *http.Request) {
	spanCtx, span := tracing.Tracer("AUSF", "procedures").Start(r.Context(), "Nnssaaf_NSSAA_Authenticate")
	defer span.End()
	r = r.WithContext(spanCtx)
	log := s.logger.With(
		"procedure", "NSSAA", "interface", "Nnssaaf", "direction", "IN",
		"correlation_id", r.Header.Get("X-Correlation-Id"),
		"spec_ref", "TS 29.526 §5.2.2.2",
	)

	var in sliceAuthInfo
	if !decodeSliceBody(w, r, &in) {
		nssaaDone("REJECT")
		return
	}
	// eapIdRsp: absent is a missing mandatory attribute; JSON null is the
	// "EAP ID Response with Null value" of TS 29.526 §5.2.2.2.1 step 1 (EapMessage
	// is nullable), accepted and not forwarded to the AAA-S.
	idRspNull := bytes.Equal(bytes.TrimSpace(in.EAPIDRsp), []byte("null"))
	var idRsp string
	if len(in.EAPIDRsp) > 0 && !idRspNull {
		if err := json.Unmarshal(in.EAPIDRsp, &idRsp); err != nil {
			log.Warn("slice authentication rejected", "result", "REJECT", "cause", "MANDATORY_IE_INCORRECT")
			nssaaDone("REJECT")
			problemParams(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid or missing SliceAuthInfo attribute",
				[]map[string]string{{"param": "/eapIdRsp", "reason": "not a string"}})
			return
		}
	}
	eapField := idRsp
	if idRspNull {
		eapField = "null" // present: only used for the mandatory-presence check
	}
	params := sliceAuthParams(in.GPSI, in.SNSSAI, "eapIdRsp", eapField)
	var eapResp []byte
	if idRsp != "" {
		var bad []map[string]string
		if eapResp, bad = decodeEAPField("eapIdRsp", idRsp); bad != nil {
			params = append(params, bad...)
		} else if t, terr := eap.Type(eapResp); terr != nil || eapResp[0] != eap.CodeResponse || t != eap.TypeIdentity {
			// A create carries the UE's EAP-Response/Identity (or nothing).
			params = append(params, map[string]string{"param": "/eapIdRsp", "reason": "not an EAP-Response/Identity"})
		}
	}
	if len(params) > 0 {
		log.Warn("slice authentication rejected", "result", "REJECT", "cause", "MANDATORY_IE_INCORRECT")
		nssaaDone("REJECT")
		problemParams(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid or missing SliceAuthInfo attribute", params)
		return
	}

	out := sliceAuthContext{GPSI: in.GPSI, SNSSAI: *in.SNSSAI}
	var identity, result string
	switch eapResp {
	case nil:
		// No identity received: the simulated AAA-S starts the EAP exchange itself
		// with an EAP-Request/Identity and waits for the UE's answer (PUT).
		const firstID byte = 1
		out.EAPMessage = base64.StdEncoding.EncodeToString(eap.BuildIdentityRequest(firstID))
		out.AuthCtxID = s.nssaaStoreOrNew().put(&nssaaCtx{gpsi: in.GPSI, snssai: *in.SNSSAI, eapID: firstID})
		result = "PENDING"
	default:
		identifier, _ := eap.Identifier(eapResp)
		identity, _ = eap.Identity(eapResp)
		lower := strings.ToLower(identity)
		switch {
		case strings.Contains(lower, "reject"):
			// The AAA-S refuses the slice: 403 SLICE_AUTH_REJECTED, no context kept.
			// Ref: TS 29.526 §5.2.2.2.1 step 3b, Table 6.1.7.3-1
			log.Warn("NSSAA rejected by AAA-S", "direction", "OUT", "sst", in.SNSSAI.SST, "sd", in.SNSSAI.SD,
				"identity_id", identityLogID(identity), "result", "REJECT", "cause", causeSliceAuthRejected)
			nssaaDone("REJECT")
			problem(w, http.StatusForbidden, causeSliceAuthRejected, "slice-specific authentication rejected by the AAA-S")
			return
		case strings.Contains(lower, nssaaChallengeMarker):
			next := identifier + 1
			out.EAPMessage = base64.StdEncoding.EncodeToString(buildChallenge(next))
			out.AuthCtxID = s.nssaaStoreOrNew().put(&nssaaCtx{gpsi: in.GPSI, snssai: *in.SNSSAI, eapID: next})
			result = "PENDING"
		default:
			// One-round AAA-S: the terminal EAP-Success rides in the 201 (RFC 3748
			// §4.2 permits an authenticator to finish after the Identity round). No
			// authResult exists in SliceAuthContext, so the consumer infers success
			// from the EAP code; the context is not stored (nothing left to confirm).
			out.EAPMessage = base64.StdEncoding.EncodeToString(eap.BuildSuccess(identifier))
			out.AuthCtxID = uuid.NewString()
			result = authResultSuccess
			nssaaDone("OK")
		}
	}

	log.Info("NSSAA EAP relayed to AAA-S",
		"direction", "OUT", "sst", in.SNSSAI.SST, "sd", in.SNSSAI.SD,
		"identity_id", identityLogID(identity), "result", result, "auth_ctx_id", out.AuthCtxID)

	// Location is an absolute URI (TS 29.501 §4.4.1) built on the configured
	// SBI authority; without a usable authority a relative reference is sent.
	loc := nssaaCtxPath + "/" + out.AuthCtxID
	if auth := s.locationAuthority(r); auth != "" {
		scheme := "https"
		if r.TLS == nil && s.cfg.TLS.CertFile == "" {
			scheme = "http"
		}
		loc = scheme + "://" + auth + loc
	}
	w.Header().Set("Location", loc)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(out)
}

// handleSliceAuthConfirm serves PUT /nnssaaf-nssaa/v1/slice-authentications/{authCtxId}:
// the UE's next EAP-Response completes a multi-round exchange; the terminal
// result deletes the context. Ref: TS 29.526 §5.2.2.3
func (s *Server) handleSliceAuthConfirm(w http.ResponseWriter, r *http.Request) {
	spanCtx, span := tracing.Tracer("AUSF", "procedures").Start(r.Context(), "Nnssaaf_NSSAA_Confirm")
	defer span.End()
	r = r.WithContext(spanCtx)
	id := r.PathValue("authCtxId")
	log := s.logger.With(
		"procedure", "NSSAA", "interface", "Nnssaaf", "direction", "IN",
		"correlation_id", r.Header.Get("X-Correlation-Id"),
		"spec_ref", "TS 29.526 §5.2.2.3", "auth_ctx_id", id,
	)

	var in sliceAuthConfirmationData
	if !decodeSliceBody(w, r, &in) {
		nssaaDone("REJECT")
		return
	}
	params := sliceAuthParams(in.GPSI, in.SNSSAI, "eapMessage", in.EAPMessage)
	if in.EAPMessage != "" {
		if _, bad := decodeEAPField("eapMessage", in.EAPMessage); bad != nil {
			params = append(params, bad...)
		}
	}
	if len(params) > 0 {
		log.Warn("slice authentication confirmation rejected", "result", "REJECT", "cause", "MANDATORY_IE_INCORRECT")
		nssaaDone("REJECT")
		problemParams(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid or missing SliceAuthConfirmationData attribute", params)
		return
	}
	// Compare gpsi/snssai with the stored context BEFORE consuming it: a request
	// for another UE or slice must not destroy the exchange.
	c, found, matched := s.nssaaStoreOrNew().takeIfMatch(id, func(c *nssaaCtx) bool {
		return c.gpsi == in.GPSI && c.snssai == *in.SNSSAI
	})
	if !found {
		log.Warn("slice authentication context not found", "result", "REJECT", "cause", "CONTEXT_NOT_FOUND")
		nssaaDone("REJECT")
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "slice authentication context not found or expired")
		return
	}
	if !matched {
		log.Warn("slice authentication confirmation does not match the context", "result", "REJECT", "cause", "MANDATORY_IE_INCORRECT")
		nssaaDone("REJECT")
		problemParams(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "gpsi or snssai does not match the slice authentication context",
			[]map[string]string{{"param": "/gpsi", "reason": "or /snssai: differs from the context"}})
		return
	}
	eapResp, _ := base64.StdEncoding.DecodeString(in.EAPMessage)
	rid, _ := eap.Identifier(eapResp)
	out := sliceAuthConfirmationResponse{GPSI: c.gpsi, SNSSAI: c.snssai}
	// The second round succeeds when the EAP-Response echoes the Request
	// identifier; anything else fails the authentication.
	if code, _ := eap.Code(eapResp); code == eap.CodeResponse && rid == c.eapID {
		out.EAPMessage = base64.StdEncoding.EncodeToString(eap.BuildSuccess(rid))
		out.AuthResult = authResultSuccess
	} else {
		out.EAPMessage = base64.StdEncoding.EncodeToString(eap.BuildFailure(c.eapID))
		out.AuthResult = authResultFailure
	}
	if out.AuthResult == authResultSuccess {
		nssaaDone("OK")
	} else {
		nssaaDone("REJECT")
	}
	log.Info("NSSAA confirmation processed", "direction", "OUT", "result", out.AuthResult)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}
