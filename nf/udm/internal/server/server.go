// Package server implements the UDM HTTP/2 SBI server.
//
// Services implemented:
//
//	Nudm_UEAuthentication — GetAuthData (POST): generates 5G HE AV for AUSF
//	Nudm_SDM              — Get (GET): returns AM data to AMF
//	Nudm_UECM             — Registration (PUT): AMF registers serving network
//
// Ref: 3GPP TS 29.503 v17.x
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/shared/aka"
	suciPkg "github.com/francurieses/claudia-5gc/shared/crypto/suci"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// UDRClient calls the UDR for subscription data.
type UDRClient interface {
	GetAuthSubscription(ctx context.Context, supi string) (*UDRAuthSub, error)
	UpdateSQN(ctx context.Context, supi, newSQN string) error
	GetAMData(ctx context.Context, supi string) (*UDRAMData, error)
	// GetSMData returns the raw SessionManagementSubscriptionData array
	// (TS 29.503 §6.1.6.2.7). Returns nil, nil when not provisioned.
	GetSMData(ctx context.Context, supi string) (json.RawMessage, error)
}

// UDRAuthSub mirrors the UDR authentication subscription structure.
type UDRAuthSub struct {
	AuthMethod string
	K          string // hex
	OPc        string // hex
	AMF        string // hex (2 bytes)
	SQN        string // hex (6 bytes)
	AlgID      string // "milenage"
}

// UDRAMData holds AM subscription data from the UDR.
type UDRAMData struct {
	SNSSAIs                  []SNSSAIEntry
	AMBRUplink, AMBRDownlink uint64
}

type SNSSAIEntry struct {
	SST int
	SD  string
	DNN string // portal-assigned preferred DNN (empty = no preference)
}

// TLSConfig holds TLS configuration for the server.
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// Server is the UDM SBI server.
type Server struct {
	udr     UDRClient
	logger  *slog.Logger
	httpSrv *http.Server
	addr    string
	// Serving network name (for KAUSF derivation)
	snName string
	// homeNetPrivKeyA is the Home Network X25519 private key for SUCI Profile A.
	// Zero value = Profile A not enabled; SUCI with protectionScheme=1 will be rejected.
	// Ref: TS 33.501 §6.12, Annex C.3
	homeNetPrivKeyA    [32]byte
	homeNetPrivKeyASet bool
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

// New builds the UDM server.
func New(addr, snName string, tlsCfg TLSConfig, udr UDRClient, logger *slog.Logger) (*Server, error) {
	s := &Server{
		udr:    udr,
		logger: logger.With("nf", "UDM"),
		addr:   addr,
		snName: snName,
	}
	return newWithServer(s, tlsCfg)
}

// WithHomeNetPrivKeyA loads the Home Network X25519 private key (hex-encoded) for
// SUCI Profile A deconcealment. If not set, Profile A SUCI deconcealment returns 501.
// Ref: TS 33.501 §6.12, Annex C.3
func (s *Server) WithHomeNetPrivKeyA(hexKey string) error {
	if hexKey == "" {
		return nil
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("udm: invalid hn_private_key_x25519: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("udm: hn_private_key_x25519 must be 32 bytes, got %d", len(b))
	}
	copy(s.homeNetPrivKeyA[:], b)
	s.homeNetPrivKeyASet = true
	s.logger.Info("UDM: SUCI Profile A (X25519) enabled",
		"spec_ref", "TS 33.501 §6.12 Annex C.3")
	return nil
}

func newWithServer(s *Server, tlsCfg TLSConfig) (*Server, error) {
	mux := http.NewServeMux()

	// Nudm_UEAuthentication
	mux.HandleFunc("POST /nudm-ueau/v1/{supi}/security-information/generate-auth-data",
		s.handleGenerateAuthData)

	// Nudm_SDM: AM data
	mux.HandleFunc("GET /nudm-sdm/v2/{supi}/am-data",
		s.handleGetAMData)

	// Nudm_SDM: SM data — session management subscription with subscribed
	// default QoS, consumed by the SMF over N10 (TS 29.503 §6.1.6.2.7)
	mux.HandleFunc("GET /nudm-sdm/v2/{supi}/sm-data",
		s.handleGetSMData)

	// Nudm_UECM: AMF registration / deregistration
	mux.HandleFunc("PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access",
		s.handleAMFRegistration)
	mux.HandleFunc("DELETE /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access",
		s.handleAMFDeregistration)

	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Load TLS config
	var tlsConfig *tls.Config
	if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		var err error
		tlsConfig, err = loadTLSConfig(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS config: %w", err)
		}
	} else {
		s.logger.Warn("TLS not configured, using H2C (DEV ONLY)", "cert_file", tlsCfg.CertFile)
	}

	s.httpSrv = &http.Server{
		Addr:              s.addr,
		Handler:           otelhttp.NewHandler(s.middleware(mux), "UDM"),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// Start runs the server.
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("UDM SBI server listening", "addr", s.addr, "tls", s.httpSrv.TLSConfig != nil)
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

// ---- Nudm_UEAuthentication (TS 29.503 §5.2.2.2) -------------------------
// POST /nudm-ueau/v1/{supiOrSuci}/security-information/generate-auth-data
func (s *Server) handleGenerateAuthData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi") // may be SUPI or SUCI (UDM resolves)

	spanCtx, span := tracing.Tracer("UDM", "procedures").Start(r.Context(), "Nudm_UEAuthentication_Get")
	span.SetAttributes(attribute.String("supi_or_suci", supi))
	defer span.End()
	r = r.WithContext(spanCtx)

	log := s.logger.With(
		"procedure", "GenerateAuthData",
		"interface", "Nudm",
		"direction", "IN",
		"supi_or_suci", supi,
		"correlation_id", r.Header.Get("X-Correlation-Id"),
		"spec_ref", "TS 29.503 §5.2.2.2",
	)

	var req struct {
		ServingNetworkName    string `json:"servingNetworkName"`
		AUSFInstanceID        string `json:"ausfInstanceId,omitempty"`
		ResynchronizationInfo *struct {
			RAND string `json:"rand"`
			AUTS string `json:"auts"`
		} `json:"resynchronizationInfo,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}
	log = log.With("serving_net", req.ServingNetworkName)
	if req.ResynchronizationInfo != nil {
		log.Info("GenerateAuthData re-sync request received",
			"spec_ref", "TS 33.501 §6.1.3.2 step 11")
	} else {
		log.Info("GenerateAuthData request received")
	}

	// SUCI deconcealment — TS 33.501 §6.12
	// The AMF passes the SUCI as received from the UE. UDM resolves it to a SUPI.
	actualSUPI := supi
	if strings.HasPrefix(supi, "suci-") {
		parsed, err := suciPkg.ParseSUCIString(supi)
		if err != nil {
			log.Error("SUCI parse failed", "error", err)
			s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT",
				fmt.Sprintf("invalid SUCI: %v", err))
			return
		}
		switch parsed.ProtectionScheme {
		case suciPkg.ProfileNull:
			result, err := suciPkg.DeconceaNull(parsed)
			if err != nil {
				log.Error("null-scheme SUCI deconcealment failed", "error", err)
				s.problem(w, http.StatusInternalServerError, "NF_FAILURE", err.Error())
				return
			}
			actualSUPI = result.SUPI
			log.Info("SUCI deconcealed (null scheme)",
				"suci", supi, "supi", actualSUPI,
				"spec_ref", "TS 33.501 §6.12")
		case suciPkg.ProfileA:
			// Profile A: X25519 ECIES — requires home-network private key
			// Ref: TS 33.501 §6.12, Annex C.3
			if !s.homeNetPrivKeyASet {
				log.Error("SUCI Profile A received but hn_private_key_x25519 not configured")
				s.problem(w, http.StatusNotImplemented, "NF_FAILURE",
					"SUCI Profile A not configured: set hn_private_key_x25519 in UDM config")
				return
			}
			result, err := suciPkg.DeconceaProfileA(parsed, s.homeNetPrivKeyA)
			if err != nil {
				log.Error("SUCI Profile A deconcealment failed", "error", err)
				s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT",
					fmt.Sprintf("SUCI Profile A deconcealment: %v", err))
				return
			}
			actualSUPI = result.SUPI
			log.Info("SUCI deconcealed (Profile A / X25519)",
				"suci", supi, "supi", actualSUPI,
				"spec_ref", "TS 33.501 §6.12 Annex C.3")
		default:
			// Profile B requires secp256r1 key — not yet configured
			log.Error("SUCI protection scheme not implemented",
				"scheme", parsed.ProtectionScheme)
			s.problem(w, http.StatusNotImplemented, "NF_FAILURE",
				fmt.Sprintf("SUCI protection scheme %d not yet supported", parsed.ProtectionScheme))
			return
		}
	}

	span.SetAttributes(attribute.String("supi", actualSUPI))

	// Fetch authentication subscription from UDR
	authSub, err := s.udr.GetAuthSubscription(r.Context(), actualSUPI)
	if err != nil {
		log.Error("UDR auth subscription fetch failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "UDR fetch failed")
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND",
			fmt.Sprintf("subscriber not found: %v", err))
		return
	}

	// Parse credentials
	k, err := aka.ParseHexKey(authSub.K)
	if err != nil {
		log.Error("invalid K", "error", err)
		s.problem(w, http.StatusInternalServerError, "NF_FAILURE", "invalid K")
		return
	}
	opc, err := aka.ParseHexKey(authSub.OPc)
	if err != nil {
		log.Error("invalid OPc", "error", err)
		s.problem(w, http.StatusInternalServerError, "NF_FAILURE", "invalid OPc")
		return
	}
	sqn, err := aka.ParseHexSQN(authSub.SQN)
	if err != nil {
		log.Error("invalid SQN", "error", err)
		sqn = [6]byte{0, 0, 0, 0, 0, 1} // default
	}
	amf, err := aka.ParseHexAMF(authSub.AMF)
	if err != nil {
		log.Error("invalid AMF", "error", err)
		amf = [2]byte{0x80, 0x00}
	}

	// If resynchronizationInfo is present, recover SQN_MS from AUTS and use
	// SQN_MS+1 as the starting SQN for the new AV.
	// Ref: TS 33.501 §C.2, TS 33.501 §6.1.3.2 step 11
	if ri := req.ResynchronizationInfo; ri != nil {
		randHex, err := hex.DecodeString(ri.RAND)
		if err != nil || len(randHex) != 16 {
			s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid resync RAND")
			return
		}
		autsHex, err := hex.DecodeString(ri.AUTS)
		if err != nil || len(autsHex) != 14 {
			s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid AUTS length")
			return
		}
		sqnMS, err := aka.ResyncFromAUTS(k, opc, [16]byte(randHex), [14]byte(autsHex))
		if err != nil {
			log.Warn("AUTS verification failed", "error", err,
				"spec_ref", "TS 33.501 §C.2")
			s.problem(w, http.StatusForbidden, "AUTHENTICATION_REJECTED", err.Error())
			return
		}
		sqn = aka.IncrementSQN(sqnMS)
		log.Info("SQN recovered from AUTS and incremented",
			"sqn_ms", hex.EncodeToString(sqnMS[:]),
			"new_sqn", hex.EncodeToString(sqn[:]),
			"spec_ref", "TS 33.501 §C.2",
		)
	}

	// Generate 5G HE AV via Milenage + KDF
	snName := req.ServingNetworkName
	if snName == "" {
		snName = s.snName
	}
	heav, err := aka.GenerateFull(aka.HEAVInput{
		SUPI: actualSUPI,
		K:    k,
		OPc:  opc,
		AMF:  amf,
		SQN:  sqn,
	}, snName)
	if err != nil {
		log.Error("GenerateFull failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "NF_FAILURE", err.Error())
		return
	}

	// Increment SQN and store (non-time-based scheme)
	newSQN := aka.IncrementSQN(sqn)
	newSQNHex := hex.EncodeToString(newSQN[:])
	if err := s.udr.UpdateSQN(r.Context(), actualSUPI, newSQNHex); err != nil {
		log.Warn("SQN update failed (non-fatal)", "error", err)
	}

	span.SetStatus(codes.Ok, "")
	log.Info("5G HE AV generated, returning to AUSF",
		"direction", "OUT",
		"supi", actualSUPI,
		"spec_ref", "TS 33.501 §6.1.3.2 step 3",
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authType":  "5G_AKA",
		"rand":      hex.EncodeToString(heav.RAND[:]),
		"autn":      hex.EncodeToString(heav.AUTN[:]),
		"xresStar":  hex.EncodeToString(heav.XRESStar),
		"hxresStar": hex.EncodeToString(heav.HRESStar),
		"kausf":     hex.EncodeToString(heav.KAUSF),
		"supi":      actualSUPI,
	})
}

// ---- Nudm_SDM Get (TS 29.503 §5.2.2.2) ----------------------------------
func (s *Server) handleGetAMData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.logger.With("procedure", "GetAMData", "supi", supi)
	log.Info("GetAMData request", "direction", "IN")

	amData, err := s.udr.GetAMData(r.Context(), supi)
	if err != nil {
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
		return
	}

	snssais := make([]map[string]any, 0)
	for _, s := range amData.SNSSAIs {
		entry := map[string]any{"sst": s.SST}
		if s.SD != "" {
			entry["sd"] = s.SD
		}
		if s.DNN != "" {
			entry["dnn"] = s.DNN
		}
		snssais = append(snssais, entry)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"nssai": map[string]any{
			"defaultSingleNssais": snssais,
		},
		"subscribedUeAmbr": map[string]any{
			"uplink":   fmt.Sprintf("%dKbps", amData.AMBRUplink),
			"downlink": fmt.Sprintf("%dKbps", amData.AMBRDownlink),
		},
	})
}

// handleGetSMData serves Nudm_SDM Get for sm-data: the per-slice session
// management subscription including the subscribed default QoS profile.
// Optional query parameters filter the result:
//
//	dnn           — keep only entries whose dnnConfigurations contain this DNN
//	single-nssai  — JSON {"sst":1,"sd":"000001"}; keep only the matching slice
//
// Ref: TS 29.503 §5.2.2.2 (GET sm-data), §6.1.6.2.7
func (s *Server) handleGetSMData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.logger.With("procedure", "GetSMData", "supi", supi, "interface", "Nudm")
	log.Info("GetSMData request", "direction", "IN")

	raw, err := s.udr.GetSMData(r.Context(), supi)
	if err != nil {
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	if raw == nil {
		s.problem(w, http.StatusNotFound, "DATA_NOT_FOUND", "no SM subscription for "+supi)
		return
	}

	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", "malformed sm-data from UDR: "+err.Error())
		return
	}

	dnnFilter := r.URL.Query().Get("dnn")
	snssaiFilter := r.URL.Query().Get("single-nssai")
	var wantSNSSAI *struct {
		SST int    `json:"sst"`
		SD  string `json:"sd"`
	}
	if snssaiFilter != "" {
		wantSNSSAI = &struct {
			SST int    `json:"sst"`
			SD  string `json:"sd"`
		}{}
		if err := json.Unmarshal([]byte(snssaiFilter), wantSNSSAI); err != nil {
			s.problem(w, http.StatusBadRequest, "INVALID_QUERY_PARAM", "single-nssai: "+err.Error())
			return
		}
	}

	filtered := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		if wantSNSSAI != nil {
			sn, _ := e["singleNssai"].(map[string]any)
			sst, _ := sn["sst"].(float64)
			sd, _ := sn["sd"].(string)
			if int(sst) != wantSNSSAI.SST || (wantSNSSAI.SD != "" && sd != wantSNSSAI.SD) {
				continue
			}
		}
		if dnnFilter != "" {
			cfgs, _ := e["dnnConfigurations"].(map[string]any)
			if _, ok := cfgs[dnnFilter]; !ok {
				continue
			}
		}
		filtered = append(filtered, e)
	}

	log.Info("SM subscription returned",
		"direction", "OUT",
		"slice_count", len(filtered),
		"spec_ref", "TS 29.503 §6.1.6.2.7",
	)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(filtered)
}

// ---- Nudm_UECM AMF Registration / Deregistration --------------------------

func (s *Server) handleAMFRegistration(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	s.logger.Info("AMF registered at UDM",
		"procedure", "UECMRegistration",
		"direction", "IN",
		"supi", supi,
		"spec_ref", "TS 29.503 §5.3.2.2",
	)
	w.WriteHeader(http.StatusCreated)
}

// handleAMFDeregistration handles Nudm_UECM_Deregistration from the AMF.
// The AMF calls this after UE deregistration to clear its serving record.
// Ref: TS 29.503 §5.3.2.4
func (s *Server) handleAMFDeregistration(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	s.logger.Info("AMF deregistered at UDM",
		"procedure", "UECMDeregistration",
		"direction", "IN",
		"supi", supi,
		"spec_ref", "TS 29.503 §5.3.2.4",
	)
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
		}
		w.Header().Set("X-Correlation-Id", corr)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "cause": cause, "detail": detail})
}

// ---- HTTP UDR client ----------------------------------------------------

// HTTPUDRClient calls the UDR over HTTP.
type HTTPUDRClient struct {
	address string
	client  *http.Client
}

func NewHTTPUDRClient(address string, client *http.Client) *HTTPUDRClient {
	return &HTTPUDRClient{address: address, client: client}
}

func (c *HTTPUDRClient) GetAuthSubscription(ctx context.Context, supi string) (*UDRAuthSub, error) {
	url := fmt.Sprintf("https://%s/nudr-dr/v2/subscription-data/%s/authentication-data/authentication-subscription", c.address, supi)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("udr: get auth sub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("udr: subscriber not found: %s", supi)
	}
	var result struct {
		AuthMethod string `json:"authenticationMethod"`
		EncK       string `json:"encPermanentKey"`
		EncOPc     string `json:"encOpcKey"`
		AMF        string `json:"authenticationManagementField"`
		AlgID      string `json:"algorithmId"`
		SQN        struct {
			SQN string `json:"sqn"`
		} `json:"sequenceNumber"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("udr: decode auth sub: %w", err)
	}
	return &UDRAuthSub{
		AuthMethod: result.AuthMethod,
		K:          result.EncK,
		OPc:        result.EncOPc,
		AMF:        result.AMF,
		SQN:        result.SQN.SQN,
		AlgID:      result.AlgID,
	}, nil
}

func (c *HTTPUDRClient) UpdateSQN(ctx context.Context, supi, newSQN string) error {
	body, _ := json.Marshal(map[string]any{
		"sequenceNumber": map[string]string{"sqn": newSQN},
	})
	url := fmt.Sprintf("https://%s/nudr-dr/v2/subscription-data/%s/authentication-data/authentication-subscription", c.address, supi)
	req, _ := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/merge-patch+json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *HTTPUDRClient) GetSMData(ctx context.Context, supi string) (json.RawMessage, error) {
	url := fmt.Sprintf("https://%s/nudr-dr/v2/subscription-data/%s/001/provisioned-data/sm-data", c.address, supi)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("udr: get sm data: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("udr: get sm data: status %d", resp.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("udr: decode sm data: %w", err)
	}
	return raw, nil
}

func (c *HTTPUDRClient) GetAMData(ctx context.Context, supi string) (*UDRAMData, error) {
	url := fmt.Sprintf("https://%s/nudr-dr/v2/subscription-data/%s/001/provisioned-data/am-data", c.address, supi)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		NSSAI struct {
			DefaultSingleNssais []struct {
				SST int    `json:"sst"`
				SD  string `json:"sd,omitempty"`
				DNN string `json:"dnn,omitempty"` // portal-assigned preferred DNN
			} `json:"defaultSingleNssais"`
		} `json:"nssai"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	amData := &UDRAMData{AMBRUplink: 100000, AMBRDownlink: 100000}
	for _, s := range result.NSSAI.DefaultSingleNssais {
		amData.SNSSAIs = append(amData.SNSSAIs, SNSSAIEntry{SST: s.SST, SD: s.SD, DNN: s.DNN})
	}
	return amData, nil
}
