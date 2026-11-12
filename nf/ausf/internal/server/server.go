// Package server implements the AUSF HTTP/2 SBI server.
//
// Service: Nausf_UEAuthentication (TS 29.509)
//
// Endpoints:
//
//	POST /nausf-auth/v1/ue-authentications              — initiate auth (step 2/3)
//	PUT  /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation — confirm (step 8)
//	DELETE /nausf-auth/v1/ue-authentications/{authCtxId} — cancel
//
// Ref: TS 29.509 v17.x §5.7 + §5.8 (5G-AKA flow)
package server

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	ausfsbi "github.com/francurieses/claudia-5gc/nf/ausf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/aka"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
	"github.com/francurieses/claudia-5gc/shared/types"
)

// UDMClient is the interface used to call UDM from AUSF.
// In production this is an SBI HTTP/2 client; in tests it's a mock.
type UDMClient interface {
	GenerateAuthData(ctx context.Context, supi string, req *UDMAuthDataRequest) (*UDMAuthDataResponse, error)
}

// CauseMandatoryIEIncorrect is the ProblemDetails cause for a malformed
// mandatory IE. Ref: TS 29.500 §5.2.7.2, Table 5.2.7.2-1.
const CauseMandatoryIEIncorrect = "MANDATORY_IE_INCORRECT"

// UDMError is a non-2xx Nudm_UEAU answer carrying the UDM ProblemDetails.
// Ref: TS 29.503 §6.3.7.3.
type UDMError struct {
	Status int
	Cause  string
	Detail string
	// InvalidParams is the UDM's invalidParams list, relayed unchanged on a
	// 400 (TS 29.500 Table 5.2.7.2-1 NOTE 1).
	InvalidParams []map[string]string
}

// Error implements error.
func (e *UDMError) Error() string {
	return fmt.Sprintf("udm: status %d cause %s", e.Status, e.Cause)
}

// udmPropagated reports whether the UDM status is relayed to the AMF as is
// (400/403/404/501); everything else stays NF_FAILURE 500.
// Ref: TS 29.509 §6.1.7.3.
func udmPropagated(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusNotImplemented:
		return true
	}
	return false
}

// ResyncInfo carries RAND + AUTS for a re-synchronisation request.
// Ref: TS 29.503 §6.1.6.2.2, TS 33.501 §6.1.3.2 step 11
type ResyncInfo struct {
	RAND string // hex (16 bytes)
	AUTS string // hex (14 bytes)
}

// UDMAuthDataRequest mirrors Nudm_UEAuthentication_Get request body.
// Ref: TS 29.503 §5.2.2.2.2
type UDMAuthDataRequest struct {
	ServingNetworkName string
	AUSFInstanceID     string
	// SupportedFeatures is the Nudm_UEAU offer (features.Request): empty under
	// rel17 / no profile, so the client omits the attribute; "0" or hex under
	// rel19. Ref: TS 29.503 §6.1.6.2.2, TS 29.500 §6.6.2.
	SupportedFeatures     string
	ResynchronizationInfo *ResyncInfo // present on SQN re-sync (TS 33.501 §C.2)
}

// 5G-AKA authentication vector element lengths in bytes.
// Ref: TS 33.501 §6.1.3.2 (RAND 128 bit, AUTN 128 bit, XRES* 128 bit,
// HXRES* 128 bit per Annex A.5, KAUSF 256 bit per Annex A.2).
const (
	avRandLen      = 16
	avAutnLen      = 16
	avXresStarLen  = 16
	avHxresStarLen = 16
	avKausfLen     = 32
)

// AuthType / AvType wire values. Ref: TS 29.503 §6.3.6.3.3 (Enumeration: AuthType),
// §6.3.6.3.4 (Enumeration: AvType).
const (
	authType5GAKA       = "5G_AKA"
	authTypeEAPAKAPrime = "EAP_AKA_PRIME"
	avType5GHEAKA       = "5G_HE_AKA"
	avTypeEAPAKAPrime   = "EAP_AKA_PRIME"
)

// AuthenticationInfoResult is the spec-literal Nudm_UEAuthentication_Get
// answer (nested authenticationVector). Ref: TS 29.503 §6.3.6.2.3 (Type: AuthenticationInfoResult)
//
// oapi: TS29503_Nudm_UEAU.yaml#/components/schemas/AuthenticationInfoResult
type AuthenticationInfoResult struct {
	AuthType             string                `json:"authType"`
	SupportedFeatures    string                `json:"supportedFeatures,omitempty"`
	AuthenticationVector *AuthenticationVector `json:"authenticationVector,omitempty"`
	Supi                 string                `json:"supi,omitempty"`
}

// AuthenticationVector is the union Av5GHeAka (avType 5G_HE_AKA) /
// AvEapAkaPrime (avType EAP_AKA_PRIME). Ref: TS 29.503 §6.3.6.2.4 (AvEapAkaPrime), §6.3.6.2.5 (Av5GHeAka)
//
// oapi: TS29503_Nudm_UEAU.yaml#/components/schemas/AuthenticationVector
type AuthenticationVector struct {
	AvType   string `json:"avType"`
	Rand     string `json:"rand"`
	Autn     string `json:"autn"`
	XresStar string `json:"xresStar,omitempty"` // 5G_HE_AKA
	Kausf    string `json:"kausf,omitempty"`    // 5G_HE_AKA
	Xres     string `json:"xres,omitempty"`     // EAP_AKA_PRIME
	CkPrime  string `json:"ckPrime,omitempty"`  // EAP_AKA_PRIME
	IkPrime  string `json:"ikPrime,omitempty"`  // EAP_AKA_PRIME
}

// udmAuthDataWire decodes both UDM answer shapes: the spec shape (embedded
// AuthenticationInfoResult) and the flat Rel-17-profile shape. The consumer
// accepts both whatever its own release profile (mixed-release deployments).
//
// oapi: none decode-only superset of AuthenticationInfoResult that also accepts the legacy flat Rel-17-profile attributes
type udmAuthDataWire struct {
	AuthenticationInfoResult
	Rand      string `json:"rand"`
	Autn      string `json:"autn"`
	XresStar  string `json:"xresStar"`
	HxresStar string `json:"hxresStar"`
	Kausf     string `json:"kausf"`
	CkPrime   string `json:"ckPrime"`
	IkPrime   string `json:"ikPrime"`
	Xres      string `json:"xres"`
}

// UDMAuthDataResponse is the AUSF's normalised view of the Nudm_UEAuthentication_Get
// answer, filled by UnmarshalJSON from either wire shape.
//
// For 5G-AKA: XresStar/HxresStar/Kausf are populated. HxresStar is taken from
// a legacy flat answer when present, otherwise derived here from RAND and
// XRES* (TS 33.501 Annex A.5), as the spec UDM does not send it.
// For EAP-AKA' (TS 33.501 §6.1.3.1): CkPrime/IkPrime/Xres are populated instead
// and the AUSF derives the EAP-AKA' key hierarchy itself.
//
// oapi: none internal normalised view of AuthenticationInfoResult, decoded by UnmarshalJSON and never serialised, see AuthenticationInfoResult
type UDMAuthDataResponse struct {
	AuthType  string
	Rand      string
	Autn      string
	XresStar  string
	HxresStar string
	Kausf     string
	Supi      string
	// EAP-AKA' transformed AV (TS 33.402 Annex A.2).
	CkPrime string
	IkPrime string
	Xres    string
	// SupportedFeatures is the UDM's Nudm_UEAU answer (AuthenticationInfoResult).
	// Ref: TS 29.503 §6.3.6.2.3, TS 29.500 §6.6.2.
	SupportedFeatures string
}

// UnmarshalJSON decodes the nested spec shape (preferred) or the flat legacy
// shape into the normalised view and derives a missing HXRES*.
func (r *UDMAuthDataResponse) UnmarshalJSON(b []byte) error {
	var w udmAuthDataWire
	if err := json.Unmarshal(b, &w); err != nil {
		return fmt.Errorf("ausf: decode udm auth data: %w", err)
	}
	*r = UDMAuthDataResponse{
		AuthType: w.AuthType, Supi: w.Supi, SupportedFeatures: w.SupportedFeatures,
		Rand: w.Rand, Autn: w.Autn, XresStar: w.XresStar, HxresStar: w.HxresStar,
		Kausf: w.Kausf, CkPrime: w.CkPrime, IkPrime: w.IkPrime, Xres: w.Xres,
	}
	if v := w.AuthenticationVector; v != nil {
		r.Rand, r.Autn = v.Rand, v.Autn
		r.XresStar, r.Kausf = v.XresStar, v.Kausf
		r.Xres, r.CkPrime, r.IkPrime = v.Xres, v.CkPrime, v.IkPrime
		// The spec vector never carries HXRES*: ignore any flat leftover.
		r.HxresStar = ""
		if r.AuthType == "" {
			switch v.AvType {
			case avType5GHEAKA:
				r.AuthType = authType5GAKA
			case avTypeEAPAKAPrime:
				r.AuthType = authTypeEAPAKAPrime
			}
		}
	}
	if r.AuthType != authTypeEAPAKAPrime && r.HxresStar == "" {
		r.HxresStar = deriveHXRESStar(r.Rand, r.XresStar)
	}
	return nil
}

// deriveHXRESStar computes HXRES* = lower 128 bits of SHA-256(RAND || XRES*)
// (TS 33.501 Annex A.5) with the shared kdf helper. It returns "" when RAND or
// XRES* is not valid hex or RAND is not 16 bytes; the caller then fails the
// AV validation as before.
func deriveHXRESStar(randHex, xresStarHex string) string {
	rb, err := hex.DecodeString(randHex)
	if err != nil || len(rb) != 16 {
		return ""
	}
	xb, err := hex.DecodeString(xresStarHex)
	if err != nil || len(xb) == 0 {
		return ""
	}
	return hex.EncodeToString(kdf.HRESStar([16]byte(rb), xb))
}

// Server is the AUSF SBI server.
type Server struct {
	cfg       Config
	authStore aka.AuthStore
	udm       UDMClient
	logger    *slog.Logger
	httpSrv   *http.Server
	// profile gates the supportedFeatures wire behaviour (decisions D1/D2,
	// dev/REL19_PROGRAM.md §2); nil behaves as rel17.
	profile *capability.Profile
	// nausfCat is the Nausf_UEAuthentication producer catalog, nudmCat the
	// Nudm_UEAU consumer catalog.
	nausfCat *features.Catalog
	nudmCat  *features.Catalog
	// nssaaCtxs holds the non-terminal Nnssaaf_NSSAA slice authentication
	// contexts (TS 29.526), created on first use.
	nssaaOnce sync.Once
	nssaaCtxs *nssaaStore
}

// SetProfile wires the release profile used for supportedFeatures negotiation.
// Must be called before Start(). Ref: TS 29.500 §6.6.2.
func (s *Server) SetProfile(p *capability.Profile) { s.profile = p }

// SetCatalogs replaces the Nausf_UEAuthentication (producer) and Nudm_UEAU
// (consumer) catalogs; a nil argument keeps the current one. Tests use it to
// negotiate non-empty sets. Must be called before Start().
func (s *Server) SetCatalogs(nausf, nudm *features.Catalog) {
	if nausf != nil {
		s.nausfCat = nausf
	}
	if nudm != nil {
		s.nudmCat = nudm
	}
}

// Config holds AUSF runtime configuration.
type Config struct {
	NFInstanceID string
	SBIAddress   string
	// SBIAuthority is the host[:port] the AUSF is reached at by SBI peers; it
	// builds absolute Location URIs. Empty = derive from SBIAddress / request.
	SBIAuthority       string
	MetricsAddr        string
	ServingNetworkName string // e.g. "5G:mnc093.mcc208.3gppnetwork.org"
	TLS                struct {
		CertFile string
		KeyFile  string
		CAFile   string
	}
}

func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("cert/key not configured")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
		KeyLogWriter: sbi.OpenKeyLogWriter(),
	}, nil
}

func New(cfg Config, udm UDMClient, authStore aka.AuthStore, logger *slog.Logger) (*Server, error) {
	if authStore == nil {
		authStore = aka.NewStore()
	}
	s := &Server{
		cfg:       cfg,
		authStore: authStore,
		udm:       udm,
		logger:    logger.With("nf", "AUSF", "nf_instance_id", cfg.NFInstanceID),
		nausfCat:  ausfsbi.NausfUEAuthenticationCatalog(),
		nudmCat:   ausfsbi.NudmUEAUCatalog(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /nausf-auth/v1/ue-authentications", s.handleInitAuth)
	mux.HandleFunc("PUT /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation", s.handleConfirm)
	mux.HandleFunc("PUT /nausf-auth/v1/ue-authentications/{authCtxId}/eap-session", s.handleEAPSession)
	mux.HandleFunc("DELETE /nausf-auth/v1/ue-authentications/{authCtxId}", s.handleDelete)
	mux.HandleFunc("POST /nausf-nssaa/v1/{supi}/authenticate", s.handleNSSAAAuthenticate)
	// TS 29.526 Nnssaaf_NSSAA resource, served in every release profile.
	mux.HandleFunc("POST "+nssaaCtxPath, s.handleSliceAuthCreate)
	mux.HandleFunc("PUT "+nssaaCtxPath+"/{authCtxId}", s.handleSliceAuthConfirm)
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Load TLS config
	var tlsCfg *tls.Config
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		var err error
		tlsCfg, err = loadTLSConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS config: %w", err)
		}
	} else {
		s.logger.Warn("TLS not configured, using H2C (DEV ONLY)", "cert_file", cfg.TLS.CertFile)
	}

	s.httpSrv = &http.Server{
		Addr:              cfg.SBIAddress,
		Handler:           otelhttp.NewHandler(s.middleware(mux), "AUSF"),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// Handler returns the server's HTTP handler for in-process testing.
func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }

func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("AUSF SBI server listening", "addr", s.cfg.SBIAddress, "tls", s.httpSrv.TLSConfig != nil)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutCtx)
	}()
	var err error
	if s.httpSrv.TLSConfig != nil {
		_ = http2.ConfigureServer(s.httpSrv, &http2.Server{})
		err = s.httpSrv.ListenAndServeTLS("", "")
	} else {
		s.httpSrv.Handler = h2c.NewHandler(s.httpSrv.Handler, &http2.Server{})
		err = s.httpSrv.ListenAndServe()
	}
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ---- Handlers -----------------------------------------------------------

// handleInitAuth — POST /nausf-auth/v1/ue-authentications
// Ref: TS 29.509 §5.7.2.2 (UeAuthentication_Authenticate request)
func (s *Server) handleInitAuth(w http.ResponseWriter, r *http.Request) {
	spanCtx, span := tracing.Tracer("AUSF", "procedures").Start(r.Context(), "Nausf_UEAuthentication_Authenticate")
	defer span.End()
	r = r.WithContext(spanCtx)

	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With(
		"procedure", "UEAuthentication",
		"interface", "Nausf",
		"direction", "IN",
		"correlation_id", corrID,
		"spec_ref", "TS 29.509 §5.7.2.2",
	)

	// Parse request body (AuthenticationInfo — TS 29.509 §6.1.6.2.2)
	var authInfo struct {
		SUPIUSUCI             string `json:"supiOrSuci"`
		ServingNetworkName    string `json:"servingNetworkName"`
		AUSFInstanceID        string `json:"ausfInstanceId,omitempty"`
		ResynchronizationInfo *struct {
			RAND string `json:"rand"`
			AUTS string `json:"auts"`
		} `json:"resynchronizationInfo,omitempty"`
		// SupportedFeatures: TS 29.509 §6.1.6.2.2 (AuthenticationInfo).
		SupportedFeatures string `json:"supportedFeatures,omitempty"`
	}
	fctx := logging.WithCorrelationID(r.Context(), corrID)
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&authInfo); err != nil {
		if features.IsTypeError(err) {
			s.rejectSupportedFeatures(fctx, w, "<non-string>", err)
			return
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			payloadTooLarge(w)
			return
		}
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}
	// supportedFeatures must be schema-valid before any state is touched.
	// Ref: TS 29.500 §5.2.7.2, §6.6.2.
	if err := features.Validate(authInfo.SupportedFeatures); err != nil {
		s.rejectSupportedFeatures(fctx, w, authInfo.SupportedFeatures, err)
		return
	}
	// Producer side of the negotiation. UEAuthenticationCtx carries no
	// supportedFeatures attribute (TS 29.509 §6.1.6.2.3), so the answer is
	// computed and logged but there is no field to return it in.
	_, negotiated := features.Answer(s.nausfCat, s.profile, authInfo.SupportedFeatures)
	features.LogNegotiation(fctx, s.logger, features.Negotiation{
		NF:        "AUSF",
		Interface: "Nausf", Direction: "IN", PeerNF: "AMF",
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.nausfCat.Supported(s.profile), Peer: authInfo.SupportedFeatures,
		PeerPresent: authInfo.SupportedFeatures != "", Negotiated: negotiated,
	})
	// SUCI form check before any state is touched or the UDM is called.
	// Ref: TS 29.509 §6.1.6.2.2 (AuthenticationInfo.supiOrSuci), TS 29.571 §5.3.2.
	shownID := authInfo.SUPIUSUCI
	if types.IsSUCI(authInfo.SUPIUSUCI) {
		suci, perr := types.ParseSUCI(authInfo.SUPIUSUCI)
		if perr != nil {
			log.Warn("malformed SUCI rejected",
				"result", "REJECT", "cause", CauseMandatoryIEIncorrect,
				"error", perr, "spec_ref", "TS 29.509 §6.1.6.2.2; TS 29.571 §5.3.2")
			problemParams(w, http.StatusBadRequest, CauseMandatoryIEIncorrect,
				"supiOrSuci is not a valid SUCI",
				[]map[string]string{{"param": "/supiOrSuci"}})
			return
		}
		if suci.ProtectionScheme != types.SUCISchemeNull {
			// Never log the concealed scheme output.
			shownID = fmt.Sprintf("suci-%d-%s-%s-%s-%d-%d-<concealed>", suci.SUPIType,
				suci.MCC, suci.MNC, suci.RoutingIndicator, suci.ProtectionScheme, suci.HNPublicKeyID)
		}
		log = log.With("suci_scheme", suci.ProtectionScheme,
			"hn_public_key_id", suci.HNPublicKeyID,
			"routing_indicator", suci.RoutingIndicator)
	}
	log = log.With("supi_or_suci", shownID)
	span.SetAttributes(
		attribute.String("supi_or_suci", shownID),
		attribute.String("serving_net", authInfo.ServingNetworkName),
	)
	log.Info("authentication initiation received",
		"direction", "IN", "message_type", "AuthenticationInfo")

	// Call UDM to get the 5G HE AV (Nudm_UEAuthentication_Get).
	// If resynchronizationInfo is present (SQN sync failure), forward it so UDM
	// can recover SQN_MS and generate a fresh AV.
	// Ref: TS 29.503 §5.2.2.2.2, TS 33.501 §6.1.3.2 step 11
	udmReq := &UDMAuthDataRequest{
		ServingNetworkName: authInfo.ServingNetworkName,
		AUSFInstanceID:     s.cfg.NFInstanceID,
		// Decision D2: empty (attribute omitted) under rel17, the offered set
		// under rel19. Ref: TS 29.500 §6.6.2.
		SupportedFeatures: features.Request(s.nudmCat, s.profile),
	}
	if authInfo.ResynchronizationInfo != nil {
		udmReq.ResynchronizationInfo = &ResyncInfo{
			RAND: authInfo.ResynchronizationInfo.RAND,
			AUTS: authInfo.ResynchronizationInfo.AUTS,
		}
		log.Info("re-sync authentication request received",
			"spec_ref", "TS 33.501 §6.1.3.2 step 11",
		)
	}
	udmResp, err := s.udm.GenerateAuthData(r.Context(), authInfo.SUPIUSUCI, udmReq)
	if err != nil {
		var ue *UDMError
		if errors.As(err, &ue) && udmPropagated(ue.Status) {
			// Propagate the UDM's 4xx/501 answer. Ref: TS 29.509 §6.1.7.3 (Nausf_UEAuthentication_Authenticate errors).
			log.Warn("UDM rejected auth data request", "result", "REJECT",
				"status", ue.Status, "cause", ue.Cause, "error", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, "UDM rejected")
			params := ue.InvalidParams
			if ue.Status == http.StatusBadRequest && len(params) == 0 {
				// MANDATORY_IE_INCORRECT always carries invalidParams
				// (TS 29.500 Table 5.2.7.2-1 NOTE 1); the SUCI is the UDM
				// path variable supiOrSuci.
				params = []map[string]string{{"param": "supiOrSuci"}}
			}
			problemParams(w, ue.Status, ue.Cause, ue.Detail, params)
			return
		}
		log.Error("UDM auth data request failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "UDM call failed")
		problem(w, http.StatusInternalServerError, "NF_FAILURE",
			fmt.Sprintf("UDM error: %v", err))
		return
	}

	s.acceptUDMFeatures(fctx, udmReq.SupportedFeatures, udmResp.SupportedFeatures)

	// EAP-AKA' branch (TS 33.501 §6.1.3.1): UDM/ARPF selected EAP-AKA' for this
	// subscriber and returned the transformed AV (CK'/IK'). The AUSF runs the EAP
	// method itself rather than the RES* verification flow below.
	if udmResp.AuthType == "EAP_AKA_PRIME" {
		s.initEAPAKAPrime(w, r, log, authInfo.ServingNetworkName, udmResp)
		return
	}

	// Parse and validate RAND, AUTN, XRES*, HXRES*, KAUSF from the UDM answer.
	// A missing or non-hex element must never yield a stored context with
	// empty values. Ref: TS 33.501 §6.1.3.2 (5G HE AV), Annex A.5, A.2.
	if udmResp.HxresStar == "" {
		udmResp.HxresStar = deriveHXRESStar(udmResp.Rand, udmResp.XresStar)
	}
	randBytes, err1 := hex.DecodeString(udmResp.Rand)
	autnBytes, err2 := hex.DecodeString(udmResp.Autn)
	xresStar, err3 := hex.DecodeString(udmResp.XresStar)
	hresStar, err4 := hex.DecodeString(udmResp.HxresStar)
	kausf, err5 := hex.DecodeString(udmResp.Kausf)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil ||
		len(randBytes) != avRandLen || len(autnBytes) != avAutnLen ||
		len(xresStar) != avXresStarLen || len(hresStar) != avHxresStarLen || len(kausf) != avKausfLen {
		log.Error("invalid 5G HE AV from UDM",
			"result", "FAILURE",
			"cause", "invalid or missing rand/autn/xresStar/hxresStar/kausf",
			"spec_ref", "TS 33.501 §6.1.3.2")
		problem(w, http.StatusInternalServerError, "NF_FAILURE", "invalid AV from UDM")
		return
	}

	// Store auth context
	authCtxID := uuid.NewString()
	authCtx := &aka.AuthContext{
		SUPI:           udmResp.Supi,
		SUCI:           authInfo.SUPIUSUCI,
		ServingNetName: authInfo.ServingNetworkName,
		RAND:           [16]byte(randBytes),
		AUTN:           [16]byte(autnBytes),
		XRESStar:       xresStar,
		HRESStar:       hresStar,
		KAUSF:          kausf,
		CreatedAt:      time.Now(),
	}
	s.authStore.Put(authCtxID, authCtx)

	span.SetAttributes(
		attribute.String("auth_ctx_id", authCtxID),
		attribute.String("supi", udmResp.Supi),
	)
	span.SetStatus(codes.Ok, "")
	log.Info("5G AV generated, returning SE AV to AMF",
		"direction", "OUT",
		"auth_ctx_id", authCtxID,
		"supi", udmResp.Supi,
		"spec_ref", "TS 33.501 §6.1.3.2 step 4",
	)

	// Build 5G SE AV (RAND, HXRES*, AUTN) — ref TS 29.509 §6.1.6.2.3
	locationURL := fmt.Sprintf("/nausf-auth/v1/ue-authentications/%s", authCtxID)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", locationURL)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"_links": map[string]any{
			"5g-aka": map[string]string{
				"href": locationURL + "/5g-aka-confirmation",
			},
		},
		"rand":      udmResp.Rand,
		"hxresStar": hex.EncodeToString(hresStar),
		"autn":      udmResp.Autn,
		"supi":      udmResp.Supi,
		"authType":  "5G_AKA",
	})
}

// handleConfirm — PUT /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation
// Ref: TS 29.509 §5.7.2.4 (step 8 — verify RES*)
func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	authCtxID := r.PathValue("authCtxId")

	spanCtx, span := tracing.Tracer("AUSF", "procedures").Start(r.Context(), "Nausf_UEAuthentication_5gAkaConfirmation")
	span.SetAttributes(attribute.String("auth_ctx_id", authCtxID))
	defer span.End()
	r = r.WithContext(spanCtx)

	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With(
		"procedure", "UEAuthentication",
		"interface", "Nausf",
		"direction", "IN",
		"correlation_id", corrID,
		"auth_ctx_id", authCtxID,
		"spec_ref", "TS 29.509 §5.7.2.4",
	)

	var confirmReq struct {
		ResStar string `json:"resStar"`
	}
	if err := json.NewDecoder(r.Body).Decode(&confirmReq); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}

	resStar, err := hex.DecodeString(confirmReq.ResStar)
	if err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "resStar: invalid hex")
		return
	}

	ctx, ok := s.authStore.Get(authCtxID)
	if !ok {
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "unknown authCtxId")
		return
	}
	log = log.With("supi", ctx.SUPI)

	kausf, err := aka.VerifyRES(ctx, resStar)
	if err != nil {
		span.SetStatus(codes.Error, "RES* verification failed")
		log.Warn("RES* verification failed",
			"result", "REJECT",
			"spec_ref", "TS 33.501 §6.1.3.2 step 8",
		)
		metrics.AuthenticationTotal.WithLabelValues("AUSF", "FAILURE").Inc()
		problem(w, http.StatusOK, "AUTHENTICATION_REJECTED", "RES* mismatch")
		return
	}

	s.authStore.Delete(authCtxID)
	span.SetAttributes(attribute.String("supi", ctx.SUPI))
	span.SetStatus(codes.Ok, "")
	log.Info("5G-AKA authentication confirmed",
		"result", "OK",
		"direction", "OUT",
		"spec_ref", "TS 33.501 §6.1.3.2 step 9",
	)
	metrics.AuthenticationTotal.WithLabelValues("AUSF", "OK").Inc()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authResult": "AUTHENTICATION_SUCCESS",
		"kausf":      hex.EncodeToString(kausf),
		"supi":       ctx.SUPI,
	})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	authCtxID := r.PathValue("authCtxId")
	s.authStore.Delete(authCtxID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corr := r.Header.Get("X-Correlation-Id")
		if corr == "" {
			corr = ulid.Make().String()
			r.Header.Set("X-Correlation-Id", corr)
		}
		w.Header().Set("X-Correlation-Id", corr)
		next.ServeHTTP(w, r)
	})
}

// rejectSupportedFeatures answers a schema-invalid supportedFeatures with 400
// INVALID_MSG_FORMAT and invalidParams[{param: /supportedFeatures}] and logs
// the REJECT negotiation record. Ref: TS 29.500 §5.2.7.2; TS 29.571 §5.2.4.6.
func (s *Server) rejectSupportedFeatures(ctx context.Context, w http.ResponseWriter, shown string, cause error) {
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "AUSF",
		Interface: "Nausf", Direction: "IN", PeerNF: "AMF",
		SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: features.CauseInvalidMsgFormat,
		Local: s.nausfCat.Supported(s.profile), Peer: shown, PeerPresent: true,
	}, "error", cause)
	problemParams(w, http.StatusBadRequest, features.CauseInvalidMsgFormat,
		"supportedFeatures is not a valid hexadecimal string",
		[]map[string]string{{"param": features.ParamSupportedFeatures}})
}

// acceptUDMFeatures processes the supportedFeatures of the UDM's Nudm_UEAU
// answer (consumer side, TS 29.500 §6.6.2) and logs the FeatureNegotiation
// record. There is no resource to store the result on. A non-hex answer
// negotiates nothing and is logged result=FAILURE; the procedure is never
// failed (R13).
func (s *Server) acceptUDMFeatures(ctx context.Context, offer, answer string) features.Set {
	// Validate the answer before Accept: Accept returns early on an empty offer
	// (R14) without looking at the answer, so a malformed answer would log OK.
	negotiated, err := features.Accept(offer, answer)
	if err == nil {
		if verr := features.Validate(answer); verr != nil {
			negotiated, err = features.Set{}, fmt.Errorf("features: accept: answer: %w", verr)
		}
	}
	n := features.Negotiation{
		NF:        "AUSF",
		Interface: "Nudm", Direction: "OUT", PeerNF: "UDM",
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.nudmCat.Supported(s.profile), Peer: answer, PeerPresent: answer != "", Negotiated: negotiated,
	}
	var extra []any
	if err != nil {
		n.Result = "FAILURE"
		extra = append(extra, "error", err)
	}
	features.LogNegotiation(ctx, s.logger, n, extra...)
	return negotiated
}

// problemParams writes a ProblemDetails response with invalidParams.
// Ref: TS 29.571 §5.2.4.1 (ProblemDetails), §5.2.4.6 (InvalidParam).
func problemParams(w http.ResponseWriter, status int, cause, detail string, params []map[string]string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{"status": status, "cause": cause, "detail": detail}
	if len(params) > 0 {
		body["invalidParams"] = params
	}
	_ = json.NewEncoder(w).Encode(body)
}

func problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"cause":  cause,
		"detail": detail,
	})
}

// payloadTooLarge answers a body over features.MaxRequestBodyBytes with 413 and
// a ProblemDetails without a cause (no 413 cause is defined).
// Ref: TS 29.500 §5.2.7.1; TS 29.571 §5.2.4.1.
func payloadTooLarge(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusRequestEntityTooLarge,
		"detail": "request body too large",
	})
}
