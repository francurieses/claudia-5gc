package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	amfsbi "github.com/francurieses/claudia-5gc/nf/amf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// ---- AUSF Client (Nausf_UEAuthentication) --------------------------------

// HTTPAUSFClient calls the AUSF over HTTP/2.
// Ref: TS 29.509
type HTTPAUSFClient struct {
	address string
	client  *http.Client
	// profile gates supportedFeatures on the wire (decision D2): nil or rel17
	// sends none (byte-identical to the pre-negotiation request).
	profile *capability.Profile
	// catalog is the Nausf_UEAuthentication consumer catalog; nil = the
	// default amfsbi.NausfUEAuthenticationCatalog().
	catalog *features.Catalog
	// logger is the base logger for the FeatureNegotiation record; nil =
	// slog.Default().
	logger *slog.Logger
}

func (c *HTTPAUSFClient) cat() *features.Catalog {
	if c.catalog != nil {
		return c.catalog
	}
	return amfsbi.NausfUEAuthenticationCatalog()
}

// logConsumerNegotiation computes the negotiated set (features.AcceptAnswer)
// and logs the consumer FeatureNegotiation record for an outbound SBI call. A
// malformed answer (R13) negotiates nothing and is logged result=FAILURE; it
// never fails the procedure. Ref: TS 29.500 §6.6.2.
func logConsumerNegotiation(ctx context.Context, base *slog.Logger, cat *features.Catalog, p *capability.Profile,
	iface, peerNF, offer, answer string, extra ...any) features.Set {
	var raw json.RawMessage
	if answer != "" {
		raw, _ = json.Marshal(answer)
	}
	return logConsumerNegotiationRaw(ctx, base, cat, p, iface, peerNF, offer, raw, extra...)
}

// logConsumerNegotiationRaw is logConsumerNegotiation for an answer attribute
// received as raw JSON: a value of the wrong JSON type is a negotiation failure
// (R13) and not a decode failure of the whole response.
func logConsumerNegotiationRaw(ctx context.Context, base *slog.Logger, cat *features.Catalog, p *capability.Profile,
	iface, peerNF, offer string, raw json.RawMessage, extra ...any) features.Set {
	answer, rawErr := features.RawString(raw)
	err := rawErr
	var negotiated features.Set
	if err == nil {
		negotiated, err = features.AcceptAnswer(offer, answer)
	}
	n := amfsbi.Negotiation{
		Interface: iface, Direction: "OUT", PeerNF: peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: cat.Supported(p), Peer: answer, PeerPresent: answer != "", Negotiated: negotiated,
	}
	if err != nil {
		n.Result = "FAILURE"
		n.Negotiated = features.Set{}
		negotiated = features.Set{}
		if rawErr != nil {
			n.Peer, n.PeerPresent = string(raw), len(raw) > 0
		}
		extra = append(extra, "error", err)
	}
	amfsbi.LogNegotiation(ctx, base, n, extra...)
	return negotiated
}

// initAuthBody builds the AuthenticationInfo request body. Under the rel19
// profile it carries supportedFeatures (TS 29.509 §6.1.6.2.2; TS 29.500
// §6.6.2: the client shall include it when creating a resource); under rel17
// the body is unchanged.
func (c *HTTPAUSFClient) initAuthBody(fields map[string]any) (body []byte, offer string) {
	offer = features.Request(c.cat(), c.profile)
	if offer != "" {
		fields["supportedFeatures"] = offer
	}
	body, _ = json.Marshal(fields)
	return body, offer
}

// logInitAuthNegotiation records the Nausf negotiation. The 201 body
// (UEAuthenticationCtx, TS 29.509 §6.1.6.2.3) has no supportedFeatures
// attribute in the Rel-17 and Rel-19 OpenAPI, so there is no answer to read:
// rule R12 negotiates nothing.
func (c *HTTPAUSFClient) logInitAuthNegotiation(ctx context.Context, supiOrSuci, offer string) {
	logConsumerNegotiation(ctx, c.logger, c.cat(), c.profile, "Nausf", "AUSF", offer, "",
		"supi_or_suci", supiOrSuci)
}

// av5gAkaOctets is the length of RAND, AUTN and HXRES* in octets: their
// schema patterns are 32 hexadecimal characters each (HxresStar in TS 29.509,
// Rand and Autn referenced from TS29503_Nudm_UEAU.yaml).
// Ref: TS 29.509 §6.1.6.2.5 (Av5gAka), §6.1.6.3.2 (HxresStar)
const av5gAkaOctets = 16

// nausfAuthCtx is the 201 answer of Nausf_UEAuthentication UEAuthenticationPost.
// The 5G SE AV travels in 5gAuthData (Av5gAka); the project AUSF still answers
// with the legacy flat members, so both shapes are read (5gAuthData first).
// Unknown members are ignored (TS 29.500 §6.6.2).
// Ref: TS 29.509 §6.1.6.2.3 (UEAuthenticationCtx), §6.1.6.2.4 (5gAuthData)
//
// oapi: TS29509_Nausf_UEAuthentication.yaml#/components/schemas/UEAuthenticationCtx
type nausfAuthCtx struct {
	AuthType string `json:"authType"`
	// FiveGAuthData is an Av5gAka object (5G_AKA) or an EapPayload string
	// (EAP-AKA'), mutually exclusive alternatives; kept raw so either decodes.
	FiveGAuthData json.RawMessage `json:"5gAuthData"`
	Links         struct {
		AKA struct {
			Href string `json:"href"`
		} `json:"5g-aka"`
	} `json:"_links"`
	// oapi-ext: legacy flat 5G AV member of the project AUSF (rel17 baseline); TS 29.509 carries it in 5gAuthData
	RAND string `json:"rand"`
	// oapi-ext: legacy flat 5G AV member of the project AUSF (rel17 baseline); TS 29.509 carries it in 5gAuthData
	HXRESStar string `json:"hxresStar"`
	// oapi-ext: legacy flat 5G AV member of the project AUSF (rel17 baseline); TS 29.509 carries it in 5gAuthData
	AUTN string `json:"autn"`
	// oapi-ext: legacy project member; TS 29.509 returns the SUPI only in ConfirmationDataResponse
	SUPI string `json:"supi"`
}

// av5gAka is the 5G AKA authentication vector of a UEAuthenticationCtx.
//
// oapi: TS29509_Nausf_UEAuthentication.yaml#/components/schemas/Av5gAka
type av5gAka struct {
	RAND      string `json:"rand"`
	HXRESStar string `json:"hxresStar"`
	AUTN      string `json:"autn"`
}

// vector returns RAND, AUTN and HXRES* of the answer: from 5gAuthData when it
// is an Av5gAka object carrying a vector, else from the legacy flat members.
// A missing, non-hex or wrong-length value is an error: the [16]byte
// conversions below must never see a short slice (that is a runtime panic).
func (a *nausfAuthCtx) vector() (rnd, autn [av5gAkaOctets]byte, hxresStar []byte, err error) {
	v := av5gAka{RAND: a.RAND, HXRESStar: a.HXRESStar, AUTN: a.AUTN}
	if d := bytes.TrimSpace(a.FiveGAuthData); len(d) > 0 && d[0] == '{' {
		var spec av5gAka
		if err := json.Unmarshal(d, &spec); err != nil {
			return rnd, autn, nil, fmt.Errorf("ausf: decode 5gAuthData: %w", err)
		}
		if spec != (av5gAka{}) {
			v = spec
		}
	}
	r, err := av5gAkaValue("rand", v.RAND)
	if err != nil {
		return rnd, autn, nil, err
	}
	n, err := av5gAkaValue("autn", v.AUTN)
	if err != nil {
		return rnd, autn, nil, err
	}
	hx, err := av5gAkaValue("hxresStar", v.HXRESStar)
	if err != nil {
		return rnd, autn, nil, err
	}
	return [av5gAkaOctets]byte(r), [av5gAkaOctets]byte(n), hx, nil
}

// av5gAkaValue decodes one hex member of the 5G AV and checks its length. The
// value itself is not echoed into the error (authentication material).
func av5gAkaValue(name, s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != av5gAkaOctets {
		return nil, fmt.Errorf("ausf: invalid 5G AV %s: %d characters, want %d hexadecimal", name, len(s), 2*av5gAkaOctets)
	}
	return b, nil
}

func (c *HTTPAUSFClient) InitiateAuth(ctx context.Context, supiOrSuci, servingNetName string) (*procedures.AUSFInitResponse, error) {
	body, offer := c.initAuthBody(map[string]any{
		"supiOrSuci":         supiOrSuci,
		"servingNetworkName": servingNetName,
	})
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://"+c.address+"/nausf-auth/v1/ue-authentications",
		bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("amf: build ausf authentication request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ausf: initiate auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var prob map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		return nil, fmt.Errorf("ausf: initiate auth: status %d cause=%v", resp.StatusCode, prob["cause"])
	}

	var result nausfAuthCtx
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ausf: decode response: %w", err)
	}
	c.logInitAuthNegotiation(ctx, supiOrSuci, offer)

	rnd, autn, hxres, err := result.vector()
	if err != nil {
		return nil, fmt.Errorf("ausf: initiate auth: %w", err)
	}

	// Extract authCtxID from Location header
	loc := resp.Header.Get("Location")
	authCtxID := extractAuthCtxID(loc)

	return &procedures.AUSFInitResponse{
		AuthCtxID: authCtxID,
		RAND:      rnd,
		AUTN:      autn,
		HXRESStar: hxres,
		SUPI:      result.SUPI,
	}, nil
}

func (c *HTTPAUSFClient) ResyncAuth(ctx context.Context, supiOrSuci, servingNetName string, rand [16]byte, auts []byte) (*procedures.AUSFInitResponse, error) {
	body, offer := c.initAuthBody(map[string]any{
		"supiOrSuci":         supiOrSuci,
		"servingNetworkName": servingNetName,
		"resynchronizationInfo": map[string]string{
			"rand": hex.EncodeToString(rand[:]),
			"auts": hex.EncodeToString(auts),
		},
	})
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://"+c.address+"/nausf-auth/v1/ue-authentications",
		bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("amf: build ausf authentication request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ausf: resync auth: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		var prob map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		return nil, fmt.Errorf("ausf: resync auth: status %d cause=%v", resp.StatusCode, prob["cause"])
	}

	var result nausfAuthCtx
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ausf: resync decode: %w", err)
	}
	c.logInitAuthNegotiation(ctx, supiOrSuci, offer)

	rnd, autn, hxres, err := result.vector()
	if err != nil {
		return nil, fmt.Errorf("ausf: resync auth: %w", err)
	}
	loc := resp.Header.Get("Location")
	authCtxID := extractAuthCtxID(loc)

	return &procedures.AUSFInitResponse{
		AuthCtxID: authCtxID,
		RAND:      rnd,
		AUTN:      autn,
		HXRESStar: hxres,
		SUPI:      result.SUPI,
	}, nil
}

func (c *HTTPAUSFClient) ConfirmAuth(ctx context.Context, authCtxID, resStar string) (*procedures.AUSFConfirmResponse, error) {
	// ConfirmationData.supportedFeatures (TS 29.509 §6.1.6.2.6) is C: "shall be
	// present if at least one optional feature defined in clause 6.1.9 is
	// supported". Offered under rel19 only (decision D2); rel17 bytes unchanged.
	fields := map[string]string{"resStar": resStar}
	offer := features.Request(c.cat(), c.profile)
	if offer != "" {
		fields["supportedFeatures"] = offer
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("amf: encode ausf confirmation: %w", err)
	}
	url := "https://" + c.address + "/nausf-auth/v1/ue-authentications/" + authCtxID + "/5g-aka-confirmation"
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("amf: build ausf confirmation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ausf: confirm auth: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AuthResult string `json:"authResult"`
		KAUSF      string `json:"kausf"`
		SUPI       string `json:"supi"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ausf: confirm decode: %w", err)
	}
	// ConfirmationDataResponse has no supportedFeatures attribute in the Rel-17
	// and Rel-19 OpenAPI: nothing to read (rule R12); the offer is logged.
	logConsumerNegotiation(ctx, c.logger, c.cat(), c.profile, "Nausf", "AUSF", offer, "",
		"auth_ctx_id", authCtxID)
	if result.AuthResult != "AUTHENTICATION_SUCCESS" {
		return nil, fmt.Errorf("ausf: authentication rejected: %s: %w", result.AuthResult, procedures.ErrAuthenticationRejected)
	}

	kausf, err := hex.DecodeString(result.KAUSF)
	if err != nil {
		return nil, fmt.Errorf("amf: decode ausf kausf: %w", err)
	}
	return &procedures.AUSFConfirmResponse{SUPI: result.SUPI, KAUSF: kausf}, nil
}

// ---- NSSAA Client (Nausf_NSSAA EAP relay) --------------------------------

// HTTPNSSAAClient relays the UE's slice-auth EAP packets to the AAA-S via the AUSF.
// Ref: TS 23.502 §4.2.9.2, TS 29.526 (mapped onto the AUSF here).
type HTTPNSSAAClient struct {
	address string // AUSF SBI address
	client  *http.Client
	// profile gates the wire shape (REL19-3.5 slice E): nil or rel17 sends the
	// frozen legacy relay body; rel19 uses the TS 29.526 slice-authentications
	// resource (SliceAuthInfo).
	profile *capability.Profile
}

// nssaaLegacyResult is the legacy relay answer.
//
// oapi: none legacy Rel-17-profile wire shape (AUSF-hosted relay), see SliceAuthContext
type nssaaLegacyResult struct {
	AuthResult string `json:"authResult"`
	EAPPayload string `json:"eapPayload"`
}

// nssaaSNSSAI is the Snssai carried in the TS 29.526 bodies.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/Snssai
type nssaaSNSSAI struct {
	SST uint8  `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

// nssaaSliceAuthInfo is the Nnssaaf_NSSAA create request.
//
// oapi: TS29526_Nnssaaf_NSSAA.yaml#/components/schemas/SliceAuthInfo
type nssaaSliceAuthInfo struct {
	GPSI     string      `json:"gpsi"`
	SNSSAI   nssaaSNSSAI `json:"snssai"`
	EAPIDRsp string      `json:"eapIdRsp"`
}

// nssaaSliceAuthContext is the Nnssaaf_NSSAA 201 answer.
//
// oapi: TS29526_Nnssaaf_NSSAA.yaml#/components/schemas/SliceAuthContext
type nssaaSliceAuthContext struct {
	GPSI       string      `json:"gpsi"`
	SNSSAI     nssaaSNSSAI `json:"snssai"`
	AuthCtxID  string      `json:"authCtxId"`
	EAPMessage string      `json:"eapMessage"`
}

// nssaaMaxResponseBytes bounds the AUSF answer read by the client (own bound).
const nssaaMaxResponseBytes = 1 << 20

// nssaaCreatePath is the TS 29.526 §6.1.3 slice-authentications collection.
const nssaaCreatePath = "/nnssaaf-nssaa/v1/slice-authentications"

// nssaaProblem is the subset of ProblemDetails the NSSAA client inspects.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/ProblemDetails
type nssaaProblem struct {
	Cause string `json:"cause"`
}

// nssaaCauseSliceAuthRejected is the application error of an unauthorized
// slice. Ref: TS 29.526 §5.2.2.2.1 step 3b, Table 6.1.7.3-1
const nssaaCauseSliceAuthRejected = "SLICE_AUTH_REJECTED"

// drainBody discards (a bounded part of) a response body so the HTTP/2 stream
// and connection can be reused.
func drainBody(r io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r, nssaaMaxResponseBytes))
}

// Authenticate relays the UE's EAP-Response/Identity and returns the EAP
// result: terminal Success/Failure, or (rel19) a non-terminal EAP-Request with
// the authCtxId of the open slice authentication context, to be continued with
// Confirm.
func (c *HTTPNSSAAClient) Authenticate(
	ctx context.Context, supi, gpsi string, sst uint8, sd string, eapPayload []byte,
) (*procedures.NSSAAAuthResult, error) {
	if features.SpecLiteral(c.profile) {
		return c.authenticateSpec(ctx, supi, gpsi, sst, sd, eapPayload)
	}
	body, err := json.Marshal(map[string]any{
		"supi":       supi,
		"gpsi":       gpsi,
		"snssai":     map[string]any{"sst": sst, "sd": sd},
		"eapPayload": base64.StdEncoding.EncodeToString(eapPayload),
	})
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa encode request: %w", err)
	}
	url := fmt.Sprintf("https://%s/nausf-nssaa/v1/%s/authenticate", c.address, supi)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa authenticate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		drainBody(resp.Body)
		return nil, fmt.Errorf("amf: nssaa authenticate: status %d", resp.StatusCode)
	}

	var result nssaaLegacyResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, nssaaMaxResponseBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("amf: nssaa decode: %w", err)
	}
	// Frozen rel17 behaviour (HEAD bf9dd80): a malformed base64 eapPayload is
	// not an error, the bytes decoded so far (possibly none) are forwarded.
	eapBytes, _ := base64.StdEncoding.DecodeString(result.EAPPayload)
	return &procedures.NSSAAAuthResult{AuthResult: result.AuthResult, EAPPayload: eapBytes}, nil
}

// authenticateSpec performs POST /nnssaaf-nssaa/v1/slice-authentications.
//
// Result mapping (SliceAuthContext has no authResult attribute):
//   - 201 with a terminal EAP-Success/EAP-Failure in eapMessage: the AMF infers
//     the result from the EAP code (RFC 3748 §4.2), as the AAA-S finished in
//     one round;
//   - 403 SLICE_AUTH_REJECTED: the slice is not authorized (TS 29.526
//     §5.2.2.2.1 step 3b); the AMF builds the EAP-Failure for the UE itself,
//     using the identifier of the UE's EAP-Response;
//   - anything else is an error (the slice authentication could not be completed).
//
// Ref: TS 29.526 §5.2.2.2
func (c *HTTPNSSAAClient) authenticateSpec(
	ctx context.Context, supi, gpsi string, sst uint8, sd string, eapPayload []byte,
) (*procedures.NSSAAAuthResult, error) {
	log := slog.With("nf", "AMF", "procedure", "NSSAA", "interface", "Nnssaaf", "direction", "OUT",
		"correlation_id", logging.CorrelationID(ctx), "supi", supi,
		"spec_ref", "TS 29.526 §5.2.2.2")
	// gpsi is mandatory in SliceAuthInfo: never substitute the SUPI for it.
	if gpsi == "" || gpsi == supi || strings.HasPrefix(gpsi, "imsi-") || strings.HasPrefix(gpsi, "nai-") {
		log.Warn("NSSAA not possible: no GPSI for the UE", "result", "FAILURE", "cause", "GPSI_UNAVAILABLE")
		return nil, errors.New("amf: nssaa: no GPSI available (mandatory in SliceAuthInfo, TS 29.526 §6.1.6.2.2)")
	}
	body, err := json.Marshal(nssaaSliceAuthInfo{
		GPSI:     gpsi,
		SNSSAI:   nssaaSNSSAI{SST: sst, SD: sd},
		EAPIDRsp: base64.StdEncoding.EncodeToString(eapPayload),
	})
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+c.address+nssaaCreatePath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if id := logging.CorrelationID(ctx); id != "" {
		req.Header.Set("X-Correlation-Id", id)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa create: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		var prob nssaaProblem
		derr := json.NewDecoder(io.LimitReader(resp.Body, nssaaMaxResponseBytes)).Decode(&prob)
		drainBody(resp.Body)
		if derr == nil && prob.Cause == nssaaCauseSliceAuthRejected {
			id, ierr := eap.Identifier(eapPayload)
			if ierr != nil {
				return nil, fmt.Errorf("amf: nssaa reject: UE EAP packet: %w", ierr)
			}
			log.Info("NSSAA slice not authorized by the AAA-S", "result", "REJECT", "cause", prob.Cause)
			return &procedures.NSSAAAuthResult{
				AuthResult: procedures.NSSAAResultFailure,
				EAPPayload: eap.BuildFailure(id),
			}, nil
		}
	}
	if resp.StatusCode != http.StatusCreated {
		drainBody(resp.Body)
		log.Warn("NSSAA create rejected", "result", "FAILURE", "cause", resp.StatusCode)
		return nil, fmt.Errorf("amf: nssaa create: status %d", resp.StatusCode)
	}
	var out nssaaSliceAuthContext
	if err := json.NewDecoder(io.LimitReader(resp.Body, nssaaMaxResponseBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("amf: nssaa decode: %w", err)
	}
	eapBytes, err := base64.StdEncoding.DecodeString(out.EAPMessage)
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa decode eapMessage: %w", err)
	}
	if err := eap.Validate(eapBytes); err != nil {
		return nil, fmt.Errorf("amf: nssaa decode eapMessage: %w", err)
	}
	switch eapBytes[0] {
	case eap.CodeSuccess: // RFC 3748 §4.2
		return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eapBytes}, nil
	case eap.CodeFailure:
		return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultFailure, EAPPayload: eapBytes}, nil
	case eap.CodeRequest:
		// Multi-round exchange: the context stays open at the NSSAAF; the id comes
		// from the body, else from the Location header (TS 29.501 §4.4.1).
		id := out.AuthCtxID
		if id == "" {
			id = authCtxIDFromLocation(resp.Header.Get("Location"))
		}
		if !validAuthCtxID(id) {
			log.Warn("NSSAA EAP-Request without a usable authCtxId", "result", "FAILURE")
			return nil, errors.New("amf: nssaa: EAP-Request without a usable authCtxId")
		}
		return &procedures.NSSAAAuthResult{EAPRequest: eapBytes, AuthCtxID: id}, nil
	default:
		log.Warn("NSSAA unexpected EAP code", "result", "FAILURE", "auth_ctx_id", out.AuthCtxID)
		return nil, fmt.Errorf("amf: nssaa: unexpected EAP code %d in eapMessage", eapBytes[0])
	}
}

// nssaaSliceAuthConfirmationData is the PUT body of the Nnssaaf_NSSAA confirm.
//
// oapi: TS29526_Nnssaaf_NSSAA.yaml#/components/schemas/SliceAuthConfirmationData
type nssaaSliceAuthConfirmationData struct {
	GPSI       string      `json:"gpsi"`
	SNSSAI     nssaaSNSSAI `json:"snssai"`
	EAPMessage string      `json:"eapMessage"`
}

// nssaaSliceAuthConfirmationResponse is the 200 answer of the confirm.
//
// oapi: TS29526_Nnssaaf_NSSAA.yaml#/components/schemas/SliceAuthConfirmationResponse
type nssaaSliceAuthConfirmationResponse struct {
	GPSI       string      `json:"gpsi"`
	SNSSAI     nssaaSNSSAI `json:"snssai"`
	EAPMessage string      `json:"eapMessage"`
	AuthResult string      `json:"authResult,omitempty"`
}

// nssaaConfirmSpecRef is the spec reference of the Nnssaaf confirm (PUT of the
// UE's following EAP-Response).
const nssaaConfirmSpecRef = "TS 29.526 §5.2.2.2.1 steps 4-9, §6.1.3.3.3.1"

// nssaaAuthCtxIDPattern bounds an authCtxId before it becomes a URL path
// segment: unreserved characters only (RFC 3986 §2.3), 1..128 of them. The
// AMF does not guess the NSSAAF's id format, only keeps it from altering the
// request path.
var nssaaAuthCtxIDPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

// validAuthCtxID reports whether id is usable as the last path segment of the
// slice-authentications resource: it matches nssaaAuthCtxIDPattern and is not a
// dot segment ("." / ".." would climb out of the collection).
func validAuthCtxID(id string) bool {
	return id != "." && id != ".." && nssaaAuthCtxIDPattern.MatchString(id)
}

// authCtxIDFromLocation extracts the authCtxId from the Location header of a
// 201 (TS 29.501 §4.4.1), accepting it only when the header addresses the
// slice-authentications collection: its path must end with
// nssaaCreatePath + "/" + id. Anything else yields "".
func authCtxIDFromLocation(loc string) string {
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	prefix := nssaaCreatePath + "/"
	i := strings.LastIndex(u.Path, prefix)
	if i < 0 { // collection path (which starts with "/") is the segment boundary
		return ""
	}
	id := u.Path[i+len(prefix):]
	if strings.Contains(id, "/") {
		return ""
	}
	return id
}

// Confirm performs PUT /nnssaaf-nssaa/v1/slice-authentications/{authCtxId} with
// the UE's next EAP-Response. A 200 carries either the terminal result
// (authResult EAP_SUCCESS / EAP_FAILURE, or an EAP-Success/Failure in eapMessage)
// or the next EAP-Request, which the AMF relays to the UE. Rel19 only: the
// legacy relay has no multi-round exchange.
// Ref: TS 29.526 §5.2.2.2.1 steps 4-9, §6.1.3.3.3.1
func (c *HTTPNSSAAClient) Confirm(
	ctx context.Context, supi, gpsi string, sst uint8, sd, authCtxID string, eapPayload []byte,
) (*procedures.NSSAAAuthResult, error) {
	log := slog.With("nf", "AMF", "procedure", "NSSAA", "interface", "Nnssaaf", "direction", "OUT",
		"correlation_id", logging.CorrelationID(ctx), "supi", supi,
		"auth_ctx_id", authCtxID, "spec_ref", nssaaConfirmSpecRef)
	if !features.SpecLiteral(c.profile) {
		return nil, errors.New("amf: nssaa confirm: not available under the rel17 profile")
	}
	if !validAuthCtxID(authCtxID) {
		return nil, errors.New("amf: nssaa confirm: invalid authCtxId")
	}
	if gpsi == "" || gpsi == supi || strings.HasPrefix(gpsi, "imsi-") || strings.HasPrefix(gpsi, "nai-") {
		return nil, errors.New("amf: nssaa: no GPSI available (mandatory in SliceAuthConfirmationData, TS 29.526 §6.1.6.2.4)")
	}
	body, err := json.Marshal(nssaaSliceAuthConfirmationData{
		GPSI:       gpsi,
		SNSSAI:     nssaaSNSSAI{SST: sst, SD: sd},
		EAPMessage: base64.StdEncoding.EncodeToString(eapPayload),
	})
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		"https://"+c.address+nssaaCreatePath+"/"+authCtxID, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if id := logging.CorrelationID(ctx); id != "" {
		req.Header.Set("X-Correlation-Id", id)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa confirm: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		var prob nssaaProblem
		derr := json.NewDecoder(io.LimitReader(resp.Body, nssaaMaxResponseBytes)).Decode(&prob)
		drainBody(resp.Body)
		if derr == nil && prob.Cause == nssaaCauseSliceAuthRejected {
			id, ierr := eap.Identifier(eapPayload)
			if ierr != nil {
				return nil, fmt.Errorf("amf: nssaa reject: UE EAP packet: %w", ierr)
			}
			log.Info("NSSAA slice not authorized by the AAA-S", "result", "REJECT", "cause", prob.Cause)
			return &procedures.NSSAAAuthResult{
				AuthResult: procedures.NSSAAResultFailure,
				EAPPayload: eap.BuildFailure(id),
			}, nil
		}
	}
	if resp.StatusCode == http.StatusNotFound {
		// The NSSAAF no longer knows the context (expired / restarted): the AMF
		// may restart the exchange once. Ref: TS 29.526 §6.1.3.3.3.1 (404)
		drainBody(resp.Body)
		log.Warn("NSSAA confirm: authentication context not found", "result", "FAILURE", "cause", resp.StatusCode)
		return nil, fmt.Errorf("amf: nssaa confirm: status 404: %w", procedures.ErrNSSAAContextLost)
	}
	if resp.StatusCode != http.StatusOK {
		drainBody(resp.Body)
		log.Warn("NSSAA confirm rejected", "result", "FAILURE", "cause", resp.StatusCode)
		return nil, fmt.Errorf("amf: nssaa confirm: status %d", resp.StatusCode)
	}
	var out nssaaSliceAuthConfirmationResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, nssaaMaxResponseBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("amf: nssaa decode: %w", err)
	}
	// The answer must belong to the request (gpsi and snssai are mandatory in
	// SliceAuthConfirmationResponse, TS 29.526 §6.1.6.2.5).
	if out.GPSI != gpsi || out.SNSSAI.SST != sst || !strings.EqualFold(out.SNSSAI.SD, sd) {
		log.Warn("NSSAA confirm answer does not match the request", "result", "FAILURE",
			"answer_gpsi", out.GPSI, "answer_sst", out.SNSSAI.SST, "answer_sd", out.SNSSAI.SD)
		return nil, errors.New("amf: nssaa confirm: gpsi/snssai of the answer do not match the request")
	}
	eapBytes, err := base64.StdEncoding.DecodeString(out.EAPMessage)
	if err != nil {
		return nil, fmt.Errorf("amf: nssaa decode eapMessage: %w", err)
	}
	if err := eap.Validate(eapBytes); err != nil {
		return nil, fmt.Errorf("amf: nssaa decode eapMessage: %w", err)
	}
	switch {
	case out.AuthResult == procedures.NSSAAResultSuccess && eapBytes[0] == eap.CodeSuccess:
		return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eapBytes}, nil
	case out.AuthResult == procedures.NSSAAResultFailure && eapBytes[0] == eap.CodeFailure:
		return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultFailure, EAPPayload: eapBytes}, nil
	case out.AuthResult == "" && eapBytes[0] == eap.CodeRequest:
		return &procedures.NSSAAAuthResult{EAPRequest: eapBytes, AuthCtxID: authCtxID}, nil
	// An EAP-Success never grants the slice without authResult EAP_SUCCESS
	// (TS 29.526 §5.2.2.2.1 step 6a: the NSSAAF sets it); it falls to the error
	// below. A bare EAP-Failure is still a failure (fail closed).
	case out.AuthResult == "" && eapBytes[0] == eap.CodeFailure:
		return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultFailure, EAPPayload: eapBytes}, nil
	default:
		log.Warn("NSSAA inconsistent confirm answer", "result", "FAILURE",
			"auth_result", out.AuthResult, "eap_code", eapBytes[0])
		return nil, fmt.Errorf("amf: nssaa confirm: authResult %q inconsistent with EAP code %d", out.AuthResult, eapBytes[0])
	}
}

func extractAuthCtxID(location string) string {
	// Location: /nausf-auth/v1/ue-authentications/<authCtxId>
	for i := len(location) - 1; i >= 0; i-- {
		if location[i] == '/' {
			return location[i+1:]
		}
	}
	return location
}

// ---- UDM Client (Nudm_SDM + Nudm_UECM) ----------------------------------

// HTTPUDMClient calls the UDM over HTTP/2.
// Ref: TS 29.503
type HTTPUDMClient struct {
	address string
	client  *http.Client
	// profile gates supportedFeatures on the wire (decision D2): nil or rel17
	// sends none (byte-identical to the pre-negotiation request).
	profile *capability.Profile
	// sdmCatalog / uecmCatalog are the Nudm_SDM and Nudm_UECM consumer
	// catalogs; nil = the amfsbi defaults.
	sdmCatalog  *features.Catalog
	uecmCatalog *features.Catalog
	// logger is the base logger for the FeatureNegotiation record; nil =
	// slog.Default().
	logger *slog.Logger
	// self carries the AMF identity the Nudm_UECM registration (guami,
	// deregCallbackUri) and Nudm_SDM subscription (callbackReference) bodies
	// need; nil = legacy registration body, no SDM subscription.
	self *udmSelf
}

// udmSelf is the AMF's own identity towards the UDM. Ref: TS 29.503 §6.2.6.2.2,
// §6.1.6.2.3.
type udmSelf struct {
	nfInstanceID string
	// apiRoot is the AMF's own SBI apiRoot, e.g. https://amf.local:8001.
	apiRoot  string
	mcc, mnc string
	amfID    string // 6 hex digits: AMF Region ID (8b) | Set ID (10b) | Pointer (6b), TS 23.003 §2.10.1
}

// SetSelf configures the AMF identity used in UDM request bodies: apiRoot is the
// AMF's own SBI apiRoot (scheme://host:port) the callback URIs are built on;
// amfRegionID/amfSetID/amfPointer form the GUAMI AMF ID (TS 23.003 §2.10.1).
func (c *HTTPUDMClient) SetSelf(nfInstanceID, apiRoot, mcc, mnc string, amfRegionID uint8, amfSetID uint16, amfPointer uint8) {
	amfID := uint32(amfRegionID)<<16 | uint32(amfSetID&0x3FF)<<6 | uint32(amfPointer&0x3F)
	c.self = &udmSelf{nfInstanceID: nfInstanceID, apiRoot: strings.TrimRight(apiRoot, "/"),
		mcc: mcc, mnc: mnc, amfID: fmt.Sprintf("%06X", amfID)}
}

// udmProblem builds a *procedures.UDMError from a non-2xx answer, reading the
// ProblemDetails cause/detail (TS 29.500 §5.2.7) from the bounded body.
func udmProblem(op string, resp *http.Response) *procedures.UDMError {
	e := &procedures.UDMError{Op: op, Status: resp.StatusCode}
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxNegotiationBodyBytes))
	if rerr != nil {
		e.Detail = fmt.Sprintf("amf: read problem details: %v", rerr)
		return e
	}
	var pd struct {
		Cause  string `json:"cause"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(raw, &pd) == nil {
		e.Cause, e.Detail = pd.Cause, pd.Detail
	}
	return e
}

func (c *HTTPUDMClient) sdmCat() *features.Catalog {
	if c.sdmCatalog != nil {
		return c.sdmCatalog
	}
	return amfsbi.NudmSDMCatalog()
}

func (c *HTTPUDMClient) uecmCat() *features.Catalog {
	if c.uecmCatalog != nil {
		return c.uecmCatalog
	}
	return amfsbi.NudmUECMCatalog()
}

// RegisterAMF implements Nudm_UECM_Registration (consumer side). Under the
// rel19 profile the Amf3GppAccessRegistration carries supportedFeatures (TS
// 29.500 §6.6.2: the client shall include it when creating a resource) and the
// answer in the 2xx body is intersected with the offer (features.Accept, rules
// R11-R14); under rel17 the request is unchanged and the response body is not
// read. A negotiation problem never fails the registration.
// Ref: TS 29.503 §5.3.2.2, §6.2.6.2.2, §6.2.8.
func (c *HTTPUDMClient) RegisterAMF(ctx context.Context, supi, amfInstanceID, servingNetName string) error {
	offer := features.Request(c.uecmCat(), c.profile)
	fields := map[string]string{
		"amfInstanceId":      amfInstanceID,
		"servingNetworkName": servingNetName,
	}
	if offer != "" {
		fields["supportedFeatures"] = offer
	}
	var payload any = fields
	if c.self != nil {
		// Amf3GppAccessRegistration mandatory attributes deregCallbackUri, guami
		// and ratType (TS 29.503 §6.2.6.2.2 Table 6.2.6.2.2-1; mandatory in the
		// Rel-17 YAML too, specs/3gpp-openapi/Rel-17/TS29503_Nudm_UECM.yaml) are
		// sent under BOTH release profiles: a Rel-17 conformance fix, not gated
		// Rel-19 behaviour. servingNetworkName is not an attribute of the
		// resource and is dropped (the in-repo UDM does not read it either). The
		// callback URI carries the SUPI so the notification resolves the UE.
		full := map[string]any{
			"amfInstanceId":    amfInstanceID,
			"deregCallbackUri": c.self.apiRoot + amfsbi.UDMDeregCallbackPath + "/" + url.PathEscape(supi),
			"guami": map[string]any{
				"plmnId": map[string]string{"mcc": c.self.mcc, "mnc": c.self.mnc},
				"amfId":  c.self.amfID,
			},
			"ratType": "NR",
		}
		if offer != "" {
			full["supportedFeatures"] = offer
		}
		payload = full
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("amf: encode uecm registration: %w", err)
	}
	target := fmt.Sprintf("https://%s/nudm-uecm/v1/%s/registrations/amf-3gpp-access", c.address, supi)
	req, err := http.NewRequestWithContext(ctx, "PUT", target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("amf: build uecm registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return &procedures.UDMError{Op: "uecm register", Err: fmt.Errorf("amf: uecm register: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// A refused registration fails the procedure (the caller maps the cause,
		// procedures.RejectCauseForUDMError). Ref: TS 23.502 §4.2.2.2.2 step 14a
		perr := udmProblem("uecm register", resp)
		base := c.logger
		if base == nil {
			base = slog.Default()
		}
		logging.NewProcedureLogger(ctx, base, "UECMRegistration").Warn("UDM refused AMF registration",
			"interface", "Nudm", "direction", "IN",
			"supi", supi, "result", "FAILURE", "cause", fmt.Sprintf("HTTP %d %s", resp.StatusCode, perr.Cause),
			"status", resp.StatusCode, "spec_ref", "TS 29.503 §5.3.2.2")
		return perr
	}
	if offer == "" {
		// rel17: nothing was offered, so nothing can be negotiated (rule
		// R14) and the response body is not read.
		logConsumerNegotiation(ctx, c.logger, c.uecmCat(), c.profile, "Nudm", "UDM", "", "", "supi", supi)
		return nil
	}
	answer, derr := registrationAnswer(resp.Body)
	if derr != nil {
		// Unreadable answer: negotiate nothing, log FAILURE, carry on.
		amfsbi.LogNegotiation(ctx, c.logger, amfsbi.Negotiation{
			Interface: "Nudm", Direction: "OUT", PeerNF: "UDM",
			SpecRef: features.SpecRef, Result: "FAILURE",
			Local: c.uecmCat().Supported(c.profile),
		}, "supi", supi, "error", derr)
		return nil
	}
	logConsumerNegotiation(ctx, c.logger, c.uecmCat(), c.profile, "Nudm", "UDM", offer, answer, "supi", supi)
	return nil
}

// maxNegotiationBodyBytes bounds the response body read for an answer (own
// bound, not a spec value).
const maxNegotiationBodyBytes = 1 << 20

// registrationAnswer extracts Amf3GppAccessRegistration.supportedFeatures from
// a 2xx body. An empty body or an absent attribute is the empty answer (rule
// R12). Ref: TS 29.503 §6.2.6.2.2.
func registrationAnswer(r io.Reader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxNegotiationBodyBytes))
	if err != nil {
		return "", fmt.Errorf("udm: read registration answer: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", nil
	}
	var rsp struct {
		SupportedFeatures string `json:"supportedFeatures"`
	}
	if err := json.Unmarshal(raw, &rsp); err != nil {
		return "", fmt.Errorf("udm: decode registration answer: %w", err)
	}
	return rsp.SupportedFeatures, nil
}

// DeregisterUECM deregisters the AMF from the UDM for this SUPI.
// Called after deregistration to clean up UDM state.
// Ref: TS 29.503 §5.3.2.4 (Nudm_UECM_Deregistration)
func (c *HTTPUDMClient) DeregisterUECM(ctx context.Context, supi string) error {
	url := fmt.Sprintf("https://%s/nudm-uecm/v1/%s/registrations/amf-3gpp-access", c.address, supi)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("amf: build uecm deregistration request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("amf: deregister UE: %w", err)
	}
	resp.Body.Close()
	// 204 No Content = success; 404 = already deregistered (tolerate both)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("udm: deregister UE: status %d", resp.StatusCode)
	}
	return nil
}

// SubscribeAMData implements Nudm_SDM_Subscribe for the SUPI's am-data
// (SdmSubscription: nfInstanceId, callbackReference, monitoredResourceUris) and
// returns the subscription id taken from the Location header. Without SetSelf
// no subscription is made and "" is returned.
// Ref: TS 29.503 §5.2.2.3, §6.1.6.2.3
func (c *HTTPUDMClient) SubscribeAMData(ctx context.Context, supi string) (string, error) {
	if c.self == nil {
		return "", nil
	}
	// monitoredResourceUris are resource paths below the Nudm_SDM root
	// (TS 29.503 Table 6.1.6.2.3-1 / §6.1.3.x: "/nudm-sdm/v2/{supi}/am-data").
	body, err := json.Marshal(map[string]any{
		"nfInstanceId":          c.self.nfInstanceID,
		"callbackReference":     c.self.apiRoot + amfsbi.UDMSDMCallbackPath,
		"monitoredResourceUris": []string{"/nudm-sdm/v2/" + supi + "/am-data"},
	})
	if err != nil {
		return "", fmt.Errorf("amf: encode sdm subscription: %w", err)
	}
	u := fmt.Sprintf("https://%s/nudm-sdm/v2/%s/sdm-subscriptions", c.address, supi)
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("amf: build sdm subscribe request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", &procedures.UDMError{Op: "sdm subscribe", Err: fmt.Errorf("amf: sdm subscribe: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", udmProblem("sdm subscribe", resp)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxNegotiationBodyBytes))
	loc := resp.Header.Get("Location")
	id := loc[strings.LastIndex(loc, "/")+1:]
	if id == "" {
		return "", &procedures.UDMError{Op: "sdm subscribe", Err: errors.New("201 without Location subscription id")}
	}
	return id, nil
}

// UnsubscribeSDM implements Nudm_SDM_Unsubscribe (DELETE); 404 = already gone.
// Ref: TS 29.503 §5.2.2.4
func (c *HTTPUDMClient) UnsubscribeSDM(ctx context.Context, supi, subscriptionID string) error {
	u := fmt.Sprintf("https://%s/nudm-sdm/v2/%s/sdm-subscriptions/%s", c.address, supi, url.PathEscape(subscriptionID))
	req, err := http.NewRequestWithContext(ctx, "DELETE", u, nil)
	if err != nil {
		return fmt.Errorf("amf: build sdm unsubscribe request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return &procedures.UDMError{Op: "sdm unsubscribe", Err: fmt.Errorf("amf: sdm unsubscribe: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return udmProblem("sdm unsubscribe", resp)
	}
	return nil
}

func (c *HTTPUDMClient) GetAMSubscriptionData(ctx context.Context, supi string) (*procedures.UDMAMSubscription, error) {
	reqURL := fmt.Sprintf("https://%s/nudm-sdm/v2/%s/am-data", c.address, supi)
	// The supported-features query parameter is optional for a GET ("may
	// include", TS 29.500 §6.6.2): sent under rel19 only (decision D2).
	offer := features.Request(c.sdmCat(), c.profile)
	if offer != "" {
		reqURL += "?" + url.Values{"supported-features": {offer}}.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("amf: build udm am-data request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("amf: get AM data: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		NSSAI struct {
			DefaultSingleNssais []struct {
				SST            int    `json:"sst"`
				SD             string `json:"sd,omitempty"`
				DNN            string `json:"dnn,omitempty"` // portal-assigned preferred DNN
				SubjectToNSSAA bool   `json:"subjectToNetworkSliceSpecificAuthenticationAndAuthorization,omitempty"`
			} `json:"defaultSingleNssais"`
		} `json:"nssai"`
		SubscribedUEAMBR struct {
			Uplink   string `json:"uplink"`
			Downlink string `json:"downlink"`
		} `json:"subscribedUeAmbr"`
		// GPSIs: AccessAndMobilitySubscriptionData.gpsis (TS 29.503 §6.1.6.2.4),
		// "msisdn-<digits>" or "extid-<id>"; the NSSAA GPSI source.
		GPSIs []string `json:"gpsis"`
		// SupportedFeatures: AccessAndMobilitySubscriptionData.supportedFeatures
		// (TS 29.503 §6.1.6.2.4), the UDM's Nudm_SDM answer.
		// Raw JSON: a non-string answer is a negotiation failure (R13), not a
		// decode failure of the whole response.
		SupportedFeatures json.RawMessage `json:"supportedFeatures"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxNegotiationBodyBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("udm: decode AM data: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logConsumerNegotiationRaw(ctx, c.logger, c.sdmCat(), c.profile, "Nudm", "UDM", offer, result.SupportedFeatures, "supi", supi)
	}

	sub := &procedures.UDMAMSubscription{
		// Subscribed UE-AMBR (TS 29.571 BitRate strings, e.g. "1 Gbps") → kbit/s.
		// Forwarded to the gNB in the InitialContextSetupRequest UE-AMBR IE.
		// Ref: TS 38.413 §9.3.1.58, TS 23.501 §5.7.2.6
		AMBRUplink:   parseBitRateKbps(result.SubscribedUEAMBR.Uplink),
		AMBRDownlink: parseBitRateKbps(result.SubscribedUEAMBR.Downlink),
		GPSI:         pickGPSI(result.GPSIs),
	}
	for _, s := range result.NSSAI.DefaultSingleNssais {
		sub.AllowedNSSAI = append(sub.AllowedNSSAI, amfctx.SNSSAISubscribed{
			SST:            uint8(s.SST),
			SD:             s.SD,
			DNN:            s.DNN,
			SubjectToNSSAA: s.SubjectToNSSAA,
		})
	}
	return sub, nil
}

// pickGPSI selects the GPSI the AMF uses towards the NSSAAF from the subscribed
// list: the first "msisdn-" entry, else the first well-formed entry, else "".
// Ref: TS 29.526 §5.2.2.2.1 step 1 ("any one of the GPSIs"), TS 29.571 §5.3.2 (Gpsi pattern)
func pickGPSI(gpsis []string) string {
	first := ""
	for _, g := range gpsis {
		switch {
		case strings.HasPrefix(g, "msisdn-") && len(g) > len("msisdn-"):
			return g
		case first == "" && strings.HasPrefix(g, "extid-") && len(g) > len("extid-"):
			first = g
		}
	}
	return first
}

// parseBitRateKbps converts a TS 29.571 BitRate string ("200 Kbps", "1 Gbps",
// "1.5 Mbps") to kbit/s. Returns 0 for an empty or unparseable value so the
// caller falls back to the operator default.
func parseBitRateKbps(s string) uint64 {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return 0
	}
	val, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || val < 0 {
		return 0
	}
	switch fields[1] {
	case "bps":
		return uint64(val / 1000)
	case "Kbps":
		return uint64(val)
	case "Mbps":
		return uint64(val * 1000)
	case "Gbps":
		return uint64(val * 1000 * 1000)
	case "Tbps":
		return uint64(val * 1000 * 1000 * 1000)
	}
	return 0
}

// ---- SMF Client (Nsmf_PDUSession) ----------------------------------------

// SMFClient interface for PDU session management
type SMFClient interface {
	// CreateSMContext also returns the Nsmf_PDUSession supportedFeatures set
	// negotiated with the SMF (empty under the rel17 profile). Negotiation
	// problems never fail the call. Ref: TS 29.500 §6.6.2.
	CreateSMContext(ctx context.Context, supi, dnn string, pduSessionID uint8, n1SmMsg []byte, snssai amfctx.SNSSAISubscribed) (smContextRef string, n1SmResp []byte, n2SmInfo []byte, negotiated features.Set, err error)
	UpdateSMContext(ctx context.Context, smContextRef string, n2SmInfo []byte) error
	DeleteSMContext(ctx context.Context, smContextRef string) error
	// NotifyANRelease sends Nsmf_PDUSession_UpdateSMContext with upCnxState=DEACTIVATED
	// so the SMF can instruct the UPF to suspend DL forwarding.
	// Ref: TS 29.502 §5.2.2.3.2, TS 23.502 §4.2.6 step 5
	NotifyANRelease(ctx context.Context, smContextRef string) error
	// ModifySMContext sends Nsmf_PDUSession_UpdateSMContext with the 5GSM Modification
	// Request, triggering QoS recalculation at SMF+PCF and returning the Modification
	// Command + N2SM Modify Request Transfer. Ref: TS 23.502 §4.3.3.1
	ModifySMContext(ctx context.Context, smContextRef string, n1SmMsg []byte, pduSessionID uint8) (n1SmResp []byte, n2SmInfo []byte, err error)
	// ModifyQoSSMContext sends a NW-initiated policy-update trigger to the SMF with
	// new 5QI and AMBR parameters. The SMF responds with a 5GSM Modification Command
	// + N2SM Modify Request Transfer ready to forward to the gNB.
	// Ref: TS 23.502 §4.3.3.2, TS 29.512 §5.2.2.3 (PolicyUpdateNotification)
	ModifyQoSSMContext(ctx context.Context, smContextRef string, pduSessionID uint8, fiveQI, ambrDLMbps, ambrULMbps int) (n1SmResp []byte, n2SmInfo []byte, err error)
}

// HTTPSMFClient calls the SMF over HTTP/2
// Ref: TS 29.502
type HTTPSMFClient struct {
	address string
	client  *http.Client
	// profile gates supportedFeatures on the wire (decision D2): nil or rel17
	// sends none (byte-identical to the pre-negotiation request).
	profile *capability.Profile
	// catalog is the Nsmf_PDUSession consumer catalog; nil = the default
	// amfsbi.NsmfPDUSessionCatalog().
	catalog *features.Catalog
	// logger is the base logger for the FeatureNegotiation record; nil =
	// slog.Default().
	logger *slog.Logger
}

// withAddress returns a copy of c targeting another SMF address (per-slice
// NRF discovery), keeping the transport and the negotiation configuration.
func (c *HTTPSMFClient) withAddress(addr string) *HTTPSMFClient {
	cp := *c
	cp.address = addr
	return &cp
}

func (c *HTTPSMFClient) cat() *features.Catalog {
	if c.catalog != nil {
		return c.catalog
	}
	return amfsbi.NsmfPDUSessionCatalog()
}

// CreateSMContext implements Nsmf_PDUSession_CreateSMContext (consumer side).
// Under the rel19 profile the request carries supportedFeatures (TS 29.500
// §6.6.2: the client shall include it when creating a resource) and the
// answer is intersected with the offer (features.Accept, rules R11-R14); under
// rel17 the body is unchanged.
// Ref: TS 29.502 §5.2.2.2, §6.1.8; TS 29.500 §6.6.2.
func (c *HTTPSMFClient) CreateSMContext(ctx context.Context, supi, dnn string, pduSessionID uint8, n1SmMsg []byte, snssai amfctx.SNSSAISubscribed) (string, []byte, []byte, features.Set, error) {
	offer := features.Request(c.cat(), c.profile)
	fields := map[string]any{
		"supi":         supi,
		"dnn":          dnn,
		"pduSessionId": pduSessionID,
		"anType":       "3GPP_ACCESS",
		"requestType":  "INITIAL_REQUEST",
		"servingNfId":  "amf-001",
		"n1SmMsg":      base64.StdEncoding.EncodeToString(n1SmMsg),
		"snssai":       map[string]any{"sst": int(snssai.SST), "sd": snssai.SD},
	}
	if offer != "" {
		fields["supportedFeatures"] = offer
	}
	body, _ := json.Marshal(fields)
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://"+c.address+"/nsmf-pdusession/v1/sm-contexts",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", nil, nil, features.Set{}, fmt.Errorf("smf: create sm context: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", nil, nil, features.Set{}, fmt.Errorf("smf: status %d", resp.StatusCode)
	}

	// Unknown attributes are ignored (TS 29.500 §6.6.2): only the ones named
	// here are decoded.
	var result struct {
		SMContextRef      string `json:"smContextRef"`
		N1SmMsg           string `json:"n1SmMsg"`
		N2SmInfo          string `json:"n2SmInfo"`
		SupportedFeatures string `json:"supportedFeatures"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, nil, features.Set{}, fmt.Errorf("smf: decode response: %w", err)
	}

	n1Resp, _ := base64.StdEncoding.DecodeString(result.N1SmMsg)
	n2Info, _ := base64.StdEncoding.DecodeString(result.N2SmInfo)

	negotiated := c.logNegotiation(ctx, supi, pduSessionID, offer, result.SupportedFeatures)
	return result.SMContextRef, n1Resp, n2Info, negotiated, nil
}

// logNegotiation computes the negotiated set (features.AcceptAnswer) and logs the
// consumer FeatureNegotiation record. A malformed answer (R13) negotiates
// nothing and is logged result=FAILURE; it never fails the procedure.
func (c *HTTPSMFClient) logNegotiation(ctx context.Context, supi string, psi uint8, offer, answer string) features.Set {
	negotiated, err := features.AcceptAnswer(offer, answer)
	n := amfsbi.Negotiation{
		Interface: "Nsmf", Direction: "OUT", PeerNF: "SMF",
		SpecRef: features.SpecRef, Result: "OK",
		Local: c.cat().Supported(c.profile), Peer: answer, PeerPresent: answer != "", Negotiated: negotiated,
	}
	extra := []any{"supi", supi, "pdu_session_id", int(psi)}
	if err != nil {
		n.Result = "FAILURE"
		extra = append(extra, "error", err)
	}
	amfsbi.LogNegotiation(ctx, c.logger, n, extra...)
	return negotiated
}

func (c *HTTPSMFClient) UpdateSMContext(ctx context.Context, smContextRef string, n2SmInfo []byte) error {
	body, _ := json.Marshal(map[string]any{"n2SmInfo": base64.StdEncoding.EncodeToString(n2SmInfo)})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("smf: update sm context: %w", err)
	}
	resp.Body.Close()
	return nil
}

// maxSMFUpdateBody bounds the SMF UpdateSMContext response body read by the AMF.
const maxSMFUpdateBody = 1 << 20

// postUpdateSMContext POSTs an Nsmf_PDUSession_UpdateSMContext request (JSON, n2SmInfo as
// base64 — this repo's AMF-SMF binding) and decodes the response into an SMFUpdateResult.
// Transport errors are returned in Err, never as a Go error, so the handover logic can
// classify them. Ref: TS 29.502 §5.2.2.3, §6.1.6.2 (SmContextUpdatedData / SmContextUpdateError).
func (c *HTTPSMFClient) postUpdateSMContext(ctx context.Context, smContextRef string, fields map[string]any) ngap.SMFUpdateResult {
	body, err := json.Marshal(fields)
	if err != nil {
		return ngap.SMFUpdateResult{Err: fmt.Errorf("smf: encode update sm context: %w", err)}
	}
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return ngap.SMFUpdateResult{Err: fmt.Errorf("smf: build update sm context request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	if id := logging.CorrelationID(ctx); id != "" {
		req.Header.Set("X-Correlation-Id", id)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return ngap.SMFUpdateResult{Err: fmt.Errorf("smf: update sm context: %w", err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSMFUpdateBody))
	if err != nil {
		return ngap.SMFUpdateResult{HTTPStatus: resp.StatusCode, Err: fmt.Errorf("smf: read update sm context response: %w", err)}
	}
	return decodeSMFUpdateResponse(resp.StatusCode, raw)
}

// decodeSMFUpdateResponse decodes SmContextUpdatedData (2xx) or SmContextUpdateError
// (other statuses; a plain ProblemDetails body is tolerated) into an SMFUpdateResult.
// An empty or non-JSON body leaves the N2/problem fields empty. An n2SmInfo that is not
// valid base64 is returned as its raw bytes so the AMF's APER decode check rejects it
// (it is never forwarded). Ref: TS 29.502 §6.1.6.2 (SmContextUpdatedData / SmContextUpdateError).
func decodeSMFUpdateResponse(status int, body []byte) ngap.SMFUpdateResult {
	res := ngap.SMFUpdateResult{HTTPStatus: status}
	var parsed struct {
		N2SmInfo     string `json:"n2SmInfo"`
		N2SmInfoType string `json:"n2SmInfoType"`
		HoState      string `json:"hoState"`
		Cause        string `json:"cause"` // plain ProblemDetails
		Error        *struct {
			Cause string `json:"cause"`
		} `json:"error"` // SmContextUpdateError.error
	}
	if len(bytes.TrimSpace(body)) == 0 || json.Unmarshal(body, &parsed) != nil {
		return res
	}
	res.N2SmInfoType = parsed.N2SmInfoType
	res.HoState = parsed.HoState
	if parsed.N2SmInfo != "" {
		if dec, err := base64.StdEncoding.DecodeString(parsed.N2SmInfo); err == nil {
			res.N2SmInfo = dec
		} else {
			res.N2SmInfo = []byte(parsed.N2SmInfo)
		}
	}
	res.Cause = parsed.Cause
	if parsed.Error != nil && parsed.Error.Cause != "" {
		res.Cause = parsed.Error.Cause
	}
	return res
}

// UpdatePathSwitch calls Nsmf_PDUSession_UpdateSMContext with the PathSwitchRequestTransfer
// (n2SmInfoType PATH_SWITCH_REQ, toBeSwitched=true) and returns the decoded SMF response:
// the PathSwitchRequestAcknowledgeTransfer (PATH_SWITCH_REQ_ACK) on success or the
// SmContextUpdateError on failure. The SMF updates the PFCP session with the target gNB's
// DL GTP-U endpoint.
// Ref: TS 29.502 §5.2.2.3.3, TS 23.502 §4.9.1.2.2 steps 2-6
func (c *HTTPSMFClient) UpdatePathSwitch(ctx context.Context, smContextRef string, pathSwitchTransfer []byte) ngap.SMFUpdateResult {
	return c.postUpdateSMContext(ctx, smContextRef, map[string]any{
		"n2SmInfo":     base64.StdEncoding.EncodeToString(pathSwitchTransfer),
		"n2SmInfoType": "PATH_SWITCH_REQ",
		"toBeSwitched": true,
	})
}

// UpdatePDUSessionSetupFail relays a PDU Session Resource Setup Unsuccessful
// Transfer from an Initial Context Setup Response / Failure to the SMF
// (Nsmf_PDUSession_UpdateSMContext, n2SmInfoType PDU_RES_SETUP_FAIL, the transfer
// as N2 SM info); the SMF decides the session's fate.
// Ref: TS 38.413 §8.3.1.2-3, TS 23.502 §4.2.3.2 steps 12-15, TS 29.502 §6.1.6.3
func (c *HTTPSMFClient) UpdatePDUSessionSetupFail(ctx context.Context, smContextRef string, unsuccessfulTransfer []byte) {
	res := c.postUpdateSMContext(ctx, smContextRef, map[string]any{
		"n2SmInfo":     base64.StdEncoding.EncodeToString(unsuccessfulTransfer),
		"n2SmInfoType": "PDU_RES_SETUP_FAIL",
	})
	log := c.logger.With("nf", "AMF", "procedure", "InitialContextSetup", "interface", "Nsmf",
		"direction", "OUT", "correlation_id", logging.CorrelationID(ctx), "smContextRef", smContextRef,
		"n2_sm_info_type", "PDU_RES_SETUP_FAIL", "spec_ref", "TS 23.502 §4.2.3.2 steps 12-15")
	switch {
	case res.Err != nil:
		log.Warn("SMF UpdateSMContext PDU_RES_SETUP_FAIL failed", "result", "FAILURE", "error", res.Err)
	case res.HTTPStatus >= 300:
		log.Warn("SMF UpdateSMContext PDU_RES_SETUP_FAIL rejected", "result", "FAILURE",
			"http_status", res.HTTPStatus, "cause", res.Cause)
	default:
		log.Info("SMF UpdateSMContext PDU_RES_SETUP_FAIL accepted", "result", "OK", "http_status", res.HTTPStatus)
	}
}

// UpdatePathSwitchSetupFail forwards a PDU session of the Path Switch Request's Failed to
// Setup List PSReq (PathSwitchRequestSetupFailedTransfer, PATH_SWITCH_SETUP_FAIL,
// failedToBeSwitched=true). Ref: TS 29.502 §5.2.2.3.3, TS 23.502 §4.9.1.2.2 step 2
func (c *HTTPSMFClient) UpdatePathSwitchSetupFail(ctx context.Context, smContextRef string, setupFailedTransfer []byte) ngap.SMFUpdateResult {
	return c.postUpdateSMContext(ctx, smContextRef, map[string]any{
		"n2SmInfo":           base64.StdEncoding.EncodeToString(setupFailedTransfer),
		"n2SmInfoType":       "PATH_SWITCH_SETUP_FAIL",
		"failedToBeSwitched": true,
	})
}

// PrepareHandover calls Nsmf_PDUSession_UpdateSMContext for one admitted PDU session of an
// N2 handover (hoState=PREPARED, n2SmInfoType HANDOVER_REQ_ACK, n2SmInfo =
// HandoverRequestAcknowledgeTransfer). The SMF answers with the HandoverCommandTransfer
// (HANDOVER_CMD). Ref: TS 29.502 §5.2.2.3.4, TS 23.502 §4.9.1.3.2 steps 10-12
func (c *HTTPSMFClient) PrepareHandover(ctx context.Context, smContextRef string, hoAckTransfer []byte) ngap.SMFUpdateResult {
	return c.postUpdateSMContext(ctx, smContextRef, map[string]any{
		"n2SmInfo":     base64.StdEncoding.EncodeToString(hoAckTransfer),
		"n2SmInfoType": "HANDOVER_REQ_ACK",
		"hoState":      "PREPARED",
	})
}

// PrepareHandoverRequired calls Nsmf_PDUSession_UpdateSMContext for one candidate PDU session
// of a HANDOVER REQUIRED (hoState=PREPARING, n2SmInfoType HANDOVER_REQUIRED, n2SmInfo =
// HandoverRequiredTransfer, omitted when the source sent none, targetId = NgRanTargetId).
// The SMF answers with the PDUSessionResourceSetupRequestTransfer (PDU_RES_SETUP_REQ).
// Ref: TS 29.502 §5.2.2.3.4, TS 23.502 §4.9.1.3.2 steps 3-6
func (c *HTTPSMFClient) PrepareHandoverRequired(ctx context.Context, smContextRef string, hoRequiredTransfer []byte, target ngap.HOTargetID) ngap.SMFUpdateResult {
	fields := map[string]any{
		"hoState":      "PREPARING",
		"n2SmInfoType": "HANDOVER_REQUIRED",
	}
	if len(hoRequiredTransfer) > 0 {
		fields["n2SmInfo"] = base64.StdEncoding.EncodeToString(hoRequiredTransfer)
	}
	if t := ngRanTargetID(target); len(t) > 0 {
		fields["targetId"] = t
	}
	return c.postUpdateSMContext(ctx, smContextRef, fields)
}

// HandoverResourceAllocationFailed forwards one PDU session of the Failed to Setup List HOAck
// of a HANDOVER REQUEST ACKNOWLEDGE (hoState=PREPARED, n2SmInfoType HANDOVER_RES_ALLOC_FAIL,
// n2SmInfo = HandoverResourceAllocationUnsuccessfulTransfer). The SMF answers 403
// HANDOVER_RESOURCE_ALLOCATION_FAILURE with a HANDOVER_PREP_FAIL transfer (TS 29.502
// §5.2.2.3.4.2), counted OK by the AMF (C2). Ref: TS 29.502 §5.2.2.3.4, TS 23.502 §4.9.1.3.2 steps 10-12
func (c *HTTPSMFClient) HandoverResourceAllocationFailed(ctx context.Context, smContextRef string, unsuccessfulTransfer []byte) ngap.SMFUpdateResult {
	return c.postUpdateSMContext(ctx, smContextRef, map[string]any{
		"n2SmInfo":     base64.StdEncoding.EncodeToString(unsuccessfulTransfer),
		"n2SmInfoType": "HANDOVER_RES_ALLOC_FAIL",
		"hoState":      "PREPARED",
	})
}

// CompleteHandover sends the Handover Complete UpdateSMContext (hoState=COMPLETED, no
// n2SmInfo) after a HANDOVER NOTIFY. Ref: TS 29.502 §5.2.2.3.4, TS 23.502 §4.9.1.3.3
func (c *HTTPSMFClient) CompleteHandover(ctx context.Context, smContextRef string) ngap.SMFUpdateResult {
	return c.postUpdateSMContext(ctx, smContextRef, map[string]any{"hoState": "COMPLETED"})
}

// gNBValueMinDigits is the minimum number of hex digits of NgRanTargetId gNbId.gNBValue
// (pattern ^[A-Fa-f0-9]{6,8}$, TS 29.571 GNbId).
const gNBValueMinDigits = 6

// ngRanTargetID renders the Target ID of a HANDOVER REQUIRED as the TS 29.571 NgRanTargetId
// JSON object ({ranNodeId:{plmnId,gNbId:{bitLength,gNBValue}}, tai:{plmnId,tac}}); parts that
// are absent are omitted and an empty map is returned when nothing is known. gNBValue is the
// right-aligned gNB ID value as hex (ceil(bitLength/4) digits, at least 6).
func ngRanTargetID(t ngap.HOTargetID) map[string]any {
	out := map[string]any{}
	if n := t.Node; n.Type == ngap.RANNodeTypeGNB && n.GNBIDBitLen > 0 {
		digits := (int(n.GNBIDBitLen) + 3) / 4
		if digits < gNBValueMinDigits {
			digits = gNBValueMinDigits
		}
		out["ranNodeId"] = map[string]any{
			"plmnId": map[string]string{"mcc": n.MCC, "mnc": n.MNC},
			"gNbId": map[string]any{
				"bitLength": n.GNBIDBitLen,
				"gNBValue":  fmt.Sprintf("%0*x", digits, n.GNBID),
			},
		}
	}
	if t.TAI != nil {
		out["tai"] = map[string]any{
			"plmnId": map[string]string{"mcc": t.TAI.MCC, "mnc": t.TAI.MNC},
			"tac":    t.TAI.TAC,
		}
	}
	return out
}

// NotifyANRelease calls Nsmf_PDUSession_UpdateSMContext with upCnxState=DEACTIVATED.
// This signals the SMF that the UE has gone CM-IDLE so DL traffic should be buffered/dropped.
// Ref: TS 29.502 §5.2.2.3.2 (UP activation/deactivation)
func (c *HTTPSMFClient) NotifyANRelease(ctx context.Context, smContextRef string) error {
	body, _ := json.Marshal(map[string]string{"upCnxState": "DEACTIVATED"})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if id := logging.CorrelationID(ctx); id != "" {
		req.Header.Set("X-Correlation-Id", id)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("smf: notify AN release: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("smf: notify AN release: status %d", resp.StatusCode)
	}
	return nil
}

// ActivateSMContext calls Nsmf_PDUSession_UpdateSMContext with upCnxState=ACTIVATING.
// The SMF rebuilds the PDUSessionResourceSetupRequestTransfer (UL TEID + QoS) for the
// session so the AMF can carry it as N2SM info in InitialContextSetupRequest during
// Service Request UP re-activation.
// Ref: TS 29.502 §5.2.2.3.2.2, TS 23.502 §4.2.3.2 step 12
func (c *HTTPSMFClient) ActivateSMContext(ctx context.Context, smContextRef string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"upCnxState": "ACTIVATING"})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("smf: activate sm context: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("smf: activate sm context: status %d", resp.StatusCode)
	}

	var result struct {
		N2SmInfo string `json:"n2SmInfo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("smf: activate sm context: decode response: %w", err)
	}
	n2SmInfo, err := base64.StdEncoding.DecodeString(result.N2SmInfo)
	if err != nil || len(n2SmInfo) == 0 {
		return nil, fmt.Errorf("smf: activate sm context: empty or invalid n2SmInfo")
	}
	return n2SmInfo, nil
}

// ModifySMContext sends Nsmf_PDUSession_UpdateSMContext with the 5GSM Modification Request.
// Returns the body of the 5GSM Modification Command and the N2SM Modify Request Transfer.
// Ref: TS 29.502 §5.2.2.3.2, TS 23.502 §4.3.3.1
func (c *HTTPSMFClient) ModifySMContext(ctx context.Context, smContextRef string, n1SmMsg []byte, pduSessionID uint8) ([]byte, []byte, error) {
	body, _ := json.Marshal(map[string]any{
		"n1SmMsg":      base64.StdEncoding.EncodeToString(n1SmMsg),
		"pduSessionId": pduSessionID,
	})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("smf: modify sm context: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("smf: modify sm context: status %d", resp.StatusCode)
	}

	var result struct {
		N1SmMsg  string `json:"n1SmMsg"`
		N2SmInfo string `json:"n2SmInfo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("smf: modify sm context: decode response: %w", err)
	}
	n1SmResp, _ := base64.StdEncoding.DecodeString(result.N1SmMsg)
	n2SmInfo, _ := base64.StdEncoding.DecodeString(result.N2SmInfo)
	return n1SmResp, n2SmInfo, nil
}

// ModifyQoSSMContext sends a NW-initiated policy-update trigger to the SMF.
// The body carries policyUpdate=true plus the new 5QI and AMBR values.
// Ref: TS 23.502 §4.3.3.2
func (c *HTTPSMFClient) ModifyQoSSMContext(ctx context.Context, smContextRef string, pduSessionID uint8, fiveQI, ambrDLMbps, ambrULMbps int) ([]byte, []byte, error) {
	body, _ := json.Marshal(map[string]any{
		"policyUpdate": true,
		"pduSessionId": pduSessionID,
		"fiveQI":       fiveQI,
		"ambrDLMbps":   ambrDLMbps,
		"ambrULMbps":   ambrULMbps,
	})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("smf: qos modify sm context: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("smf: qos modify sm context: status %d", resp.StatusCode)
	}

	var result struct {
		N1SmMsg  string `json:"n1SmMsg"`
		N2SmInfo string `json:"n2SmInfo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("smf: qos modify sm context: decode response: %w", err)
	}
	n1SmResp, _ := base64.StdEncoding.DecodeString(result.N1SmMsg)
	n2SmInfo, _ := base64.StdEncoding.DecodeString(result.N2SmInfo)
	return n1SmResp, n2SmInfo, nil
}

func (c *HTTPSMFClient) DeleteSMContext(ctx context.Context, smContextRef string) error {
	u := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef
	req, _ := http.NewRequestWithContext(ctx, "DELETE", u, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("smf: delete sm context: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("smf: delete sm context: status %d", resp.StatusCode)
	}
	return nil
}

// ---- NRF Client (Nnrf_NFDiscovery) ----------------------------------------

// HTTPNRFClient calls the NRF discovery API for slice-aware SMF selection.
// Ref: TS 29.510 §5.3.2.2.2
type HTTPNRFClient struct {
	address string
	client  *http.Client
	// cache maps "SST:SD" → SMF address to avoid repeated discovery calls
	mu    sync.Mutex
	cache map[string]string

	// profile gates requester-features on the wire (decision D2): nil or rel17
	// sends none (byte-identical discovery URL); rel19 sends the offered set
	// ("0" when nothing is implemented). TS 29.510 §6.2.3.2.3.1 Table
	// 6.2.3.2.3.1-1: the parameter "may be included" when none of the listed
	// features is supported.
	profile *capability.Profile
	// catalog is the Nnrf_NFDiscovery consumer catalog; nil = the default
	// amfsbi.NnrfNFDiscoveryCatalog().
	catalog *features.Catalog
	// logger is the base logger (the process logger, which carries nf) for the
	// FeatureNegotiation record and for the SMF-discovery fallback record
	// (logSMFDiscoveryFallback). nil: the FeatureNegotiation record uses
	// slog.Default(), the fallback record is skipped (nothing is logged).
	logger *slog.Logger
}

// WithFeatures wires the release profile and the base logger used for the
// Nnrf_NFDiscovery supportedFeatures negotiation. Must be called before the
// client is shared.
func (c *HTTPNRFClient) WithFeatures(p *capability.Profile, logger *slog.Logger) *HTTPNRFClient {
	c.profile = p
	c.logger = logger
	return c
}

func (c *HTTPNRFClient) cat() *features.Catalog {
	if c.catalog != nil {
		return c.catalog
	}
	return amfsbi.NnrfNFDiscoveryCatalog()
}

// NewHTTPNRFClient creates a new NRF discovery client. address is host:port; a
// base URL is accepted and normalised (see normalizeHostPort), because Discover
// prepends "https://" itself and a doubled scheme turns "https" into the host.
func NewHTTPNRFClient(address string, httpClient *http.Client) *HTTPNRFClient {
	return &HTTPNRFClient{
		address: normalizeHostPort(address),
		client:  httpClient,
		cache:   make(map[string]string),
	}
}

// normalizeHostPort reduces a peer address to the host:port form the SBI
// clients in this file expect: one leading "https://" or "http://" scheme
// (case-insensitive, RFC 3986 §3.1) and any trailing "/" are removed. SBA is
// always TLS, so an "http://" input does not select plain HTTP; the client
// still dials https.
func normalizeHostPort(address string) string {
	for _, scheme := range []string{"https://", "http://"} {
		if len(address) >= len(scheme) && strings.EqualFold(address[:len(scheme)], scheme) {
			address = address[len(scheme):]
			break
		}
	}
	return strings.TrimRight(address, "/")
}

// Discover queries NRF for NF instances of the given type, filtered by SNSSAIs.
// Returns the first (highest-priority) result.
func (c *HTTPNRFClient) Discover(ctx context.Context, targetNFType, requesterNFType string, snssais []amfctx.SNSSAISubscribed) ([]procedures.NFEndpoint, error) {
	params := url.Values{
		"target-nf-type":    {targetNFType},
		"requester-nf-type": {requesterNFType},
	}
	if len(snssais) > 0 {
		type snssaiQ struct {
			SST int    `json:"sst"`
			SD  string `json:"sd,omitempty"`
		}
		list := make([]snssaiQ, 0, len(snssais))
		for _, s := range snssais {
			list = append(list, snssaiQ{SST: int(s.SST), SD: s.SD})
		}
		b, _ := json.Marshal(list)
		params.Set("snssais", string(b))
	}
	// requester-features (TS 29.510 §6.2.3.2.3.1): rel19 only (decision D2).
	offer := features.Request(c.cat(), c.profile)
	if offer != "" {
		params.Set("requester-features", offer)
	}
	reqURL := "https://" + c.address + "/nnrf-disc/v1/nf-instances?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("nrf: discover: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nrf: discover: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nrf: discover: status %d", resp.StatusCode)
	}
	var result struct {
		// NRFSupportedFeatures is the NRF's own Nnrf_NFDiscovery feature set
		// (TS 29.510 §6.2.6.2.2, SearchResult.nrfSupportedFeatures).
		// Raw JSON: a non-string answer is a negotiation failure (R13).
		NRFSupportedFeatures json.RawMessage `json:"nrfSupportedFeatures"`
		NFInstances          []struct {
			NFInstanceID  string   `json:"nfInstanceId"`
			IPv4Addresses []string `json:"ipv4Addresses"`
			NFServices    []struct {
				IPEndpoints []struct {
					IPv4Address string `json:"ipv4Address"`
					Port        int    `json:"port"`
				} `json:"ipEndPoints"`
			} `json:"nfServices"`
		} `json:"nfInstances"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxNegotiationBodyBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("nrf: discover: decode: %w", err)
	}
	logConsumerNegotiationRaw(ctx, c.logger, c.cat(), c.profile, "Nnrf", "NRF", offer, result.NRFSupportedFeatures,
		"target_nf_type", targetNFType)
	var endpoints []procedures.NFEndpoint
	for _, inst := range result.NFInstances {
		addr := ""
		if len(inst.NFServices) > 0 && len(inst.NFServices[0].IPEndpoints) > 0 {
			ep := inst.NFServices[0].IPEndpoints[0]
			addr = fmt.Sprintf("%s:%d", ep.IPv4Address, ep.Port)
		} else if len(inst.IPv4Addresses) > 0 {
			addr = inst.IPv4Addresses[0]
		}
		if addr != "" {
			endpoints = append(endpoints, procedures.NFEndpoint{
				InstanceID: inst.NFInstanceID,
				Address:    addr,
			})
		}
	}
	return endpoints, nil
}

// errNoSMFEndpoint is the cause DiscoverSMFAddress reports when the NRF
// answered 200 but no returned NF instance carries an address.
var errNoSMFEndpoint = errors.New("discovery result has no NF instance with an address")

// DiscoverSMFAddress returns the address of an SMF serving the given slice.
// Uses a simple in-memory cache keyed by "SST:SD"; failures are never cached.
// Any failure (NRF unreachable, non-200, or no instance with an address)
// returns an error, on which CallSMF falls back to the statically configured
// SMF peer; the cause is logged by logSMFDiscoveryFallback, at a level that
// depends on it.
func (c *HTTPNRFClient) DiscoverSMFAddress(ctx context.Context, snssai amfctx.SNSSAISubscribed) (string, error) {
	key := fmt.Sprintf("%d:%s", snssai.SST, snssai.SD)
	c.mu.Lock()
	if addr, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return addr, nil
	}
	c.mu.Unlock()

	endpoints, err := c.Discover(ctx, "SMF", "AMF", []amfctx.SNSSAISubscribed{snssai})
	if err == nil && len(endpoints) == 0 {
		err = errNoSMFEndpoint
	}
	if err != nil {
		err = fmt.Errorf("nrf: no SMF found for slice SST=%d SD=%s: %w", snssai.SST, snssai.SD, err)
		c.logSMFDiscoveryFallback(ctx, snssai, err)
		return "", err
	}
	addr := endpoints[0].Address
	c.mu.Lock()
	c.cache[key] = addr
	c.mu.Unlock()
	return addr, nil
}

// logSMFDiscoveryFallback records why SMF selection through the NRF produced no
// address. CallSMF swallows that error and uses the static SMF peer, so without
// this record the fallback is invisible (it once hid a malformed NRF URL).
// The level follows the cause. errNoSMFEndpoint (the NRF answered 200 but no
// instance carries an address) is Debug: no NF registers an ipEndPoints /
// ipv4Addresses entry with the NRF today, so every PDU Session Establishment
// takes this path and a higher level would be noise. Every other cause
// (transport or DNS error, non-200 status, undecodable body) is a real NRF
// problem and is Warn, so it is not hidden. A nil logger (client built without
// WithFeatures) logs nothing. nf comes from the process logger; correlation_id
// and the UE identifiers come from ctx. Ref: TS 23.501 §6.3.2.
func (c *HTTPNRFClient) logSMFDiscoveryFallback(ctx context.Context, snssai amfctx.SNSSAISubscribed, err error) {
	if c.logger == nil {
		return
	}
	level := slog.LevelWarn
	if errors.Is(err, errNoSMFEndpoint) {
		level = slog.LevelDebug
	}
	// Skip building the procedure logger (several With calls) when the level is
	// off, which is the Debug case under the default Info level.
	if !c.logger.Enabled(ctx, level) {
		return
	}
	logging.NewProcedureLogger(ctx, c.logger, "NFDiscover").Log(ctx, level, "NRF SMF discovery yielded no usable address",
		"interface", "Nnrf",
		"direction", "OUT",
		"snssai_sst", snssai.SST,
		"snssai_sd", snssai.SD,
		"error", err,
		"spec_ref", "TS 23.501 §6.3.2",
	)
}

// ---- NSSF Client (Nnssf_NSSelection) ----------------------------------------

// HTTPNSSFClient calls the NSSF NSSelection API for slice-aware registration.
// Ref: TS 29.531 §5.2.2.2
type HTTPNSSFClient struct {
	address string
	client  *http.Client
}

// NSSelection calls NSSF to get the authorised NSSAI for a UE.
// Returns the intersection of requested slices and the NSSF-configured allowed list.
// Ref: TS 29.531 §5.2.2.2.3.1
func (c *HTTPNSSFClient) NSSelection(ctx context.Context, nfType, nfID string, requested []amfctx.SNSSAISubscribed) ([]amfctx.SNSSAISubscribed, error) {
	params := url.Values{
		"nf-type": {nfType},
		"nf-id":   {nfID},
	}
	if len(requested) > 0 {
		type snssaiQ struct {
			SST int    `json:"sst"`
			SD  string `json:"sd,omitempty"`
		}
		list := make([]snssaiQ, 0, len(requested))
		for _, s := range requested {
			list = append(list, snssaiQ{SST: int(s.SST), SD: s.SD})
		}
		b, _ := json.Marshal(list)
		params.Set("slice-info-request-for-registration.requestedNssai", string(b))
	}
	reqURL := "https://" + c.address + "/nnssf-nsselection/v2/network-slice-information?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("nssf: NSSelection: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nssf: NSSelection: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nssf: NSSelection: status %d", resp.StatusCode)
	}

	var result struct {
		AllowedNssaiList []struct {
			AllowedSnssaiList []struct {
				SST int    `json:"sst"`
				SD  string `json:"sd,omitempty"`
			} `json:"allowedSnssaiList"`
		} `json:"allowedNssaiList"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("nssf: NSSelection decode: %w", err)
	}

	var allowed []amfctx.SNSSAISubscribed
	for _, entry := range result.AllowedNssaiList {
		for _, s := range entry.AllowedSnssaiList {
			allowed = append(allowed, amfctx.SNSSAISubscribed{
				SST: uint8(s.SST),
				SD:  s.SD,
			})
		}
	}
	return allowed, nil
}

// ---- PCF Client (Npcf_UEPolicyControl / N15) ----------------------------

// HTTPPCFClient calls the PCF over HTTP/2 for UE policy association.
// Ref: TS 29.525 §4.2.2
type HTTPPCFClient struct {
	address string
	client  *http.Client
}

func (c *HTTPPCFClient) CreateUEPolicyAssociation(ctx context.Context, supi, servingPlmn string) (string, []byte, error) {
	body, err := json.Marshal(map[string]any{
		"supi":        supi,
		"servingPlmn": servingPlmn,
	})
	if err != nil {
		return "", nil, fmt.Errorf("pcf: CreateUEPolicyAssociation: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+c.address+uePolicyCollection,
		bytes.NewReader(body))
	if err != nil {
		return "", nil, fmt.Errorf("pcf: CreateUEPolicyAssociation: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("pcf: CreateUEPolicyAssociation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var prob map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		return "", nil, fmt.Errorf("pcf: CreateUEPolicyAssociation: status %d cause=%v",
			resp.StatusCode, prob["cause"])
	}

	// TS 29.525 §5.6.2.2 PolicyAssociation: the container is the base64 (TS 29.571
	// Bytes) "uePolicy" attribute. The legacy "uePolicySections" map and body
	// "polAssoId" are read only as a fallback for a PCF that predates the
	// Rel-17 OpenAPI alignment.
	var result struct {
		PolAssoID        string `json:"polAssoId"`
		UEPolicy         string `json:"uePolicy"`
		UEPolicySections map[string]struct {
			Content string `json:"uePolicySectionContent"`
		} `json:"uePolicySections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("pcf: CreateUEPolicyAssociation: decode: %w", err)
	}

	polAssoID, err := policyAssociationID(resp.Header.Get("Location"), uePolicyCollection, result.PolAssoID)
	if err != nil {
		return "", nil, fmt.Errorf("pcf: CreateUEPolicyAssociation: %w", err)
	}

	encoded := result.UEPolicy
	if encoded == "" {
		for _, section := range result.UEPolicySections {
			if section.Content != "" {
				encoded = section.Content
				break
			}
		}
	}
	var container []byte
	if encoded != "" {
		container, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return polAssoID, nil, fmt.Errorf("pcf: decode policy container: %w", err)
		}
	}
	return polAssoID, container, nil
}

// Npcf policy association collections (TS 29.525 §5.1 / TS 29.507 §5.1).
const (
	uePolicyCollection = "/npcf-ue-policy-control/v1/policies"
	amPolicyCollection = "/npcf-am-policy-control/v1/policies"
)

// policyAssociationID derives the policy association id of a 201 response.
// The id is the single path segment after collection in the Location header
// (TS 29.507 §5.6.2.2 / TS 29.525 §5.6.2.2: the PolicyAssociation body carries
// no id); legacyBodyID (the pre-alignment non-schema "polAssoId") is used only
// when Location is absent. A Location outside the collection is an error. An
// error is also returned when neither yields an id.
func policyAssociationID(location, collection, legacyBodyID string) (string, error) {
	if id := sbi.ResourceIDFromLocationUnder(location, collection); id != "" {
		return id, nil
	}
	if strings.TrimSpace(location) == "" && legacyBodyID != "" {
		return legacyBodyID, nil
	}
	return "", fmt.Errorf("no policy association id (Location %q not under %s, no usable body polAssoId)", location, collection)
}

// deletePolicyAssociation issues DELETE <collection>/{polAssoID} against the
// PCF and maps the result (TS 29.525 §4.2.5 / TS 29.507 §4.2.5): any 2xx is
// success; 404 is "already gone" ONLY when the body is a ProblemDetails
// (application/problem+json) - a bare 404 (mux text, proxy) is an error. An
// empty polAssoID is rejected without sending a request.
func deletePolicyAssociation(ctx context.Context, hc *http.Client, op, address, collection, polAssoID string) error {
	if polAssoID == "" {
		return fmt.Errorf("pcf: %s: empty policy association id", op)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		"https://"+address+collection+"/"+url.PathEscape(polAssoID), nil)
	if err != nil {
		return fmt.Errorf("pcf: %s: new request: %w", op, err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("pcf: %s: %w", op, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	return policyDeleteResult(ctx, op, polAssoID, resp)
}

// policyDeleteResult maps the status of a policy association DELETE (see
// deletePolicyAssociation).
func policyDeleteResult(ctx context.Context, op, polAssoID string, resp *http.Response) error {
	if resp.StatusCode/100 == 2 {
		return nil
	}
	var prob struct {
		Cause string `json:"cause"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&prob)
	if resp.StatusCode == http.StatusNotFound && isProblemJSON(resp.Header.Get("Content-Type")) {
		slog.InfoContext(ctx, "PCF policy association already released",
			"procedure", op, "interface", "N15", "direction", "IN",
			"result", "OK", "cause", prob.Cause, "pol_asso_id", polAssoID,
			"http_status", resp.StatusCode,
			"spec_ref", "TS 29.525 §4.2.5 / TS 29.507 §4.2.5")
		return nil
	}
	return fmt.Errorf("pcf: %s: status %d cause=%q", op, resp.StatusCode, prob.Cause)
}

// isProblemJSON reports whether a Content-Type header is application/problem+json
// (TS 29.500 §5.2.7.2), ignoring parameters and case.
func isProblemJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "application/problem+json"
}

func (c *HTTPPCFClient) DeleteUEPolicyAssociation(ctx context.Context, polAssoID string) error {
	return deletePolicyAssociation(ctx, c.client, "DeleteUEPolicyAssociation", c.address, uePolicyCollection, polAssoID)
}

// ---- PCF AM Policy Client (Npcf_AMPolicyControl / N15) ----------------------

// HTTPAMPolicyClient calls the PCF over HTTP/2 for AM Policy Association.
// Ref: TS 29.507 §4.2.2
type HTTPAMPolicyClient struct {
	address string
	client  *http.Client
}

// CreateAMPolicyAssociation creates an AM Policy Association at registration.
// Returns the polAssoId, RFSP index, and optional service area restriction (nil = unrestricted).
// Non-fatal — caller should log and continue if it fails. Ref: TS 29.507 §4.2.2
func (c *HTTPAMPolicyClient) CreateAMPolicyAssociation(ctx context.Context, supi, accessType, mcc, mnc string) (
	polAssoID string, rfsp int, servAreaRes *amfctx.ServiceAreaRestriction, err error) {
	body, err := json.Marshal(map[string]any{
		"supi":       supi,
		"accessType": accessType,
		"plmnId":     map[string]string{"mcc": mcc, "mnc": mnc},
	})
	if err != nil {
		return "", 0, nil, fmt.Errorf("pcf: CreateAMPolicyAssociation: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+c.address+amPolicyCollection,
		bytes.NewReader(body))
	if err != nil {
		return "", 0, nil, fmt.Errorf("pcf: CreateAMPolicyAssociation: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", 0, nil, fmt.Errorf("pcf: CreateAMPolicyAssociation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var prob map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		return "", 0, nil, fmt.Errorf("pcf: CreateAMPolicyAssociation: status %d cause=%v",
			resp.StatusCode, prob["cause"])
	}

	// TS 29.507 §5.6.2.2 PolicyAssociation carries no id: it comes from Location.
	// Body "polAssoId" is a legacy fallback only (see policyAssociationID).
	var result struct {
		PolAssoID   string  `json:"polAssoId"`
		RFSP        float64 `json:"rfsp"`
		ServAreaRes *struct {
			RestrictionType string `json:"restrictionType"`
			Areas           []struct {
				TACs []string `json:"tacs"`
			} `json:"areas"`
		} `json:"servAreaRes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, nil, fmt.Errorf("pcf: CreateAMPolicyAssociation: decode: %w", err)
	}
	polAssoID, err = policyAssociationID(resp.Header.Get("Location"), amPolicyCollection, result.PolAssoID)
	if err != nil {
		return "", 0, nil, fmt.Errorf("pcf: CreateAMPolicyAssociation: %w", err)
	}

	var sar *amfctx.ServiceAreaRestriction
	if result.ServAreaRes != nil && result.ServAreaRes.RestrictionType != "" {
		sar = &amfctx.ServiceAreaRestriction{
			RestrictionType: result.ServAreaRes.RestrictionType,
		}
		// A present-but-empty ALLOWED_AREAS array means "allowed nowhere" and must
		// stay distinguishable (non-nil empty) from an absent array.
		// Ref: TS 29.571 §5.4.4.18
		if result.ServAreaRes.RestrictionType == "ALLOWED_AREAS" && result.ServAreaRes.Areas != nil {
			sar.AllowedTACs = []string{}
		}
		for _, area := range result.ServAreaRes.Areas {
			if result.ServAreaRes.RestrictionType == "ALLOWED_AREAS" {
				sar.AllowedTACs = append(sar.AllowedTACs, area.TACs...)
			} else {
				sar.NotAllowedTACs = append(sar.NotAllowedTACs, area.TACs...)
			}
		}
	}
	return polAssoID, int(result.RFSP), sar, nil
}

// DeleteAMPolicyAssociation releases the AM policy association at deregistration.
// Ref: TS 29.507 §4.2.5
func (c *HTTPAMPolicyClient) DeleteAMPolicyAssociation(ctx context.Context, polAssoID string) error {
	return deletePolicyAssociation(ctx, c.client, "DeleteAMPolicyAssociation", c.address, amPolicyCollection, polAssoID)
}

// ---- SMSF Client (Nsmsf_SMService) ---------------------------------------

// HTTPSMSFClient calls the SMSF over mTLS HTTP/2 to relay MO SMS.
// Implements nasmsg.SMSFClient.
// Ref: TS 29.540 §5.2.4 (Nsmsf_SMService_UplinkSMS)
type HTTPSMSFClient struct {
	address string
	client  *http.Client
	// profile gates the request encoding (REL19-3.5): nil or rel17 sends the
	// frozen JSON body; rel19 sends the spec-literal multipart/related.
	profile *capability.Profile
	// boundary fixes the multipart boundary (tests only); empty = random.
	boundary string
}

// smsPayloadContentID is the Content-Id of the SMS binary body part, referenced
// by SmsRecordData.smsPayload.contentId. Ref: TS 29.540 §6.1.6.2.3
const smsPayloadContentID = "smsPayload"

// smsfErrBodyMaxBytes bounds the ProblemDetails read from a non-2xx SMSF answer.
const smsfErrBodyMaxBytes = 64 << 10

// smsPayloadContentType is the media type of the SMS binary part.
// Ref: TS 29.540 §6.1.3.3
const smsPayloadContentType = "application/vnd.3gpp.sms"

// uplinkSMSRequestBody builds the UplinkSMS request body and Content-Type.
// Rel-17 profile (or none): the legacy JSON {"smsPayload":"<b64>","smsRecordId"}.
// Rel-19: multipart/related with the SmsRecordData JSON root part (smsPayload =
// RefToBinaryData) and the binary SMS part. The binary part carries the bare
// Content-Id "smsPayload" (3GPP practice; the SMSF decoder also accepts <id>).
// Ref: TS 29.540 §5.2.4, TS 29.500 §5.4 (multipart/related)
func (c *HTTPSMSFClient) uplinkSMSRequestBody(smsRecordID, smsPayloadBase64 string) (contentType string, body []byte, err error) {
	if !features.SpecLiteral(c.profile) {
		body, err = json.Marshal(map[string]string{
			"smsRecordId": smsRecordID,
			"smsPayload":  smsPayloadBase64,
		})
		if err != nil {
			return "", nil, fmt.Errorf("smsf: uplink sms: marshal: %w", err)
		}
		return "application/json", body, nil
	}
	bin, err := base64.StdEncoding.DecodeString(smsPayloadBase64)
	if err != nil {
		return "", nil, fmt.Errorf("smsf: uplink sms: smsPayload is not base64: %w", err)
	}
	rec, err := json.Marshal(map[string]any{
		"smsRecordId": smsRecordID,
		"smsPayload":  map[string]string{"contentId": smsPayloadContentID},
	})
	if err != nil {
		return "", nil, fmt.Errorf("smsf: uplink sms: marshal: %w", err)
	}
	ct, body, err := sbi.EncodeRelated(c.boundary, []sbi.RelatedPart{
		{ContentType: "application/json", Body: rec},
		{ContentType: smsPayloadContentType, ContentID: smsPayloadContentID, Body: bin},
	})
	if err != nil {
		return "", nil, fmt.Errorf("smsf: uplink sms: %w", err)
	}
	return ct, body, nil
}

// UplinkSMS forwards an MO SMS payload (base64 SM-CP/RP container from the NAS
// Payload Container, PCT=0x02) to the SMSF. The AMF is a transparent relay and
// does not parse the container. A 404 means the SMSF has no active SMS context.
// Ref: TS 29.540 §5.2.4
func (c *HTTPSMSFClient) UplinkSMS(ctx context.Context, supi, smsRecordID, smsPayloadBase64 string) error {
	contentType, body, err := c.uplinkSMSRequestBody(smsRecordID, smsPayloadBase64)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://"+c.address+"/nsmsf-sms/v2/ue-contexts/"+url.PathEscape(supi)+"/sendsms",
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("smsf: uplink sms: build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("smsf: uplink sms: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		var prob map[string]any
		if derr := json.NewDecoder(io.LimitReader(resp.Body, smsfErrBodyMaxBytes)).Decode(&prob); derr != nil {
			return fmt.Errorf("smsf: uplink sms: status %d (problem body undecodable: %w)", resp.StatusCode, derr)
		}
		return fmt.Errorf("smsf: uplink sms: status %d cause=%v", resp.StatusCode, prob["cause"])
	}
	return nil
}
