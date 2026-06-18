// Package server implements the AUSF HTTP/2 SBI server.
//
// Service: Nausf_UEAuthentication (TS 29.509)
//
// Endpoints:
//   POST /nausf-auth/v1/ue-authentications              — initiate auth (step 2/3)
//   PUT  /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation — confirm (step 8)
//   DELETE /nausf-auth/v1/ue-authentications/{authCtxId} — cancel
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
	"time"

	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/shared/aka"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// UDMClient is the interface used to call UDM from AUSF.
// In production this is an SBI HTTP/2 client; in tests it's a mock.
type UDMClient interface {
	GenerateAuthData(ctx context.Context, supi string, req *UDMAuthDataRequest) (*UDMAuthDataResponse, error)
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
	ServingNetworkName    string
	AUSFInstanceID        string
	SupportedFeatures     string
	ResynchronizationInfo *ResyncInfo // present on SQN re-sync (TS 33.501 §C.2)
}

// UDMAuthDataResponse mirrors the Nudm_UEAuthentication_Get response.
type UDMAuthDataResponse struct {
	AuthType  string `json:"authType"`
	Rand      string `json:"rand"`
	Autn      string `json:"autn"`
	XresStar  string `json:"xresStar"`
	HxresStar string `json:"hxresStar"`
	Kausf     string `json:"kausf"`
	Supi      string `json:"supi"`
}

// Server is the AUSF SBI server.
type Server struct {
	cfg       Config
	authStore aka.AuthStore
	udm       UDMClient
	logger    *slog.Logger
	httpSrv   *http.Server
}

// Config holds AUSF runtime configuration.
type Config struct {
	NFInstanceID string
	SBIAddress   string
	MetricsAddr  string
	ServingNetworkName string // e.g. "5G:mnc093.mcc208.3gppnetwork.org"
	TLS struct {
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
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /nausf-auth/v1/ue-authentications", s.handleInitAuth)
	mux.HandleFunc("PUT /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation", s.handleConfirm)
	mux.HandleFunc("DELETE /nausf-auth/v1/ue-authentications/{authCtxId}", s.handleDelete)
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
		SUPIUSUCI          string `json:"supiOrSuci"`
		ServingNetworkName string `json:"servingNetworkName"`
		AUSFInstanceID     string `json:"ausfInstanceId,omitempty"`
		ResynchronizationInfo *struct {
			RAND string `json:"rand"`
			AUTS string `json:"auts"`
		} `json:"resynchronizationInfo,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&authInfo); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}
	log = log.With("supi_or_suci", authInfo.SUPIUSUCI)
	span.SetAttributes(
		attribute.String("supi_or_suci", authInfo.SUPIUSUCI),
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
		log.Error("UDM auth data request failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "UDM call failed")
		problem(w, http.StatusInternalServerError, "NF_FAILURE",
			fmt.Sprintf("UDM error: %v", err))
		return
	}

	// Parse RAND, AUTN, XRES* from UDM response
	randBytes, _ := hex.DecodeString(udmResp.Rand)
	autnBytes, _ := hex.DecodeString(udmResp.Autn)
	xresStar, _ := hex.DecodeString(udmResp.XresStar)
	hresStar, _ := hex.DecodeString(udmResp.HxresStar)
	kausf, _ := hex.DecodeString(udmResp.Kausf)

	if len(randBytes) != 16 || len(autnBytes) != 16 {
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
		"rand":       udmResp.Rand,
		"hxresStar":  hex.EncodeToString(hresStar),
		"autn":       udmResp.Autn,
		"supi":       udmResp.Supi,
		"authType":   "5G_AKA",
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

func problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"cause":  cause,
		"detail": detail,
	})
}
