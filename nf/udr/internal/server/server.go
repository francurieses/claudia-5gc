// Package server implements the UDR HTTP/2 SBI server.
//
// Service: Nudr_DataRepository (TS 29.504)
//
// Endpoints implemented (auth + AM subscription subset):
//
//	GET    /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription
//	PATCH  /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription
//	GET    /nudr-dr/v2/subscription-data/{supi}/{servingPlmnId}/provisioned-data/am-data
//	PUT    /nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access
//
// Ref: TS 29.504 v17.x + TS 29.505 §5
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// TLSConfig holds TLS configuration for the server.
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// Server is the UDR SBI server.
type Server struct {
	store   store.Store
	logger  *slog.Logger
	httpSrv *http.Server
	addr    string
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

// New builds the UDR server.
func New(addr string, tlsCfg TLSConfig, st store.Store, logger *slog.Logger) (*Server, error) {
	s := &Server{
		store:  st,
		logger: logger.With("nf", "UDR"),
		addr:   addr,
	}
	mux := http.NewServeMux()

	// Authentication subscription
	mux.HandleFunc("GET /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription",
		s.handleGetAuthSub)
	mux.HandleFunc("PATCH /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription",
		s.handlePatchAuthSub)

	// AM subscription data (serving PLMN aware, simplified — no PLMN filter)
	mux.HandleFunc("GET /nudr-dr/v2/subscription-data/{supi}/{servingPlmnId}/provisioned-data/am-data",
		s.handleGetAMData)

	// SM subscription data — per-slice session management subscription with the
	// subscribed default 5G QoS profile (TS 29.503 §6.1.6.2.7, TS 29.505)
	mux.HandleFunc("GET /nudr-dr/v2/subscription-data/{supi}/{servingPlmnId}/provisioned-data/sm-data",
		s.handleGetSMData)
	mux.HandleFunc("PUT /nudr-dr/v2/subscription-data/{supi}/{servingPlmnId}/provisioned-data/sm-data",
		s.handlePutSMData)

	// UECM context data (AMF registration)
	mux.HandleFunc("PUT /nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access",
		s.handlePutAMFContext)

	// Policy subscription data — URSP rules (TS 29.525 / TS 24.526)
	// Ref: TS 29.504 §5.2.4 (policy data)
	mux.HandleFunc("GET /nudr-dr/v2/policy-data/{supi}/ue-policy-set",
		s.handleGetUEPolicySet)
	mux.HandleFunc("PUT /nudr-dr/v2/policy-data/{supi}/ue-policy-set",
		s.handlePutUEPolicySet)
	mux.HandleFunc("DELETE /nudr-dr/v2/policy-data/{supi}/ue-policy-set",
		s.handleDeleteUEPolicySet)
	mux.HandleFunc("GET /nudr-dr/v2/policy-data/default-policies",
		s.handleListDefaultPolicies)

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
		Addr:              addr,
		Handler:           s.middleware(mux),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// Start runs the server until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("UDR SBI server listening", "addr", s.addr, "tls", s.httpSrv.TLSConfig != nil)
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

// GET authentication-subscription (Nudr_DataRepository_Query)
// Ref: TS 29.504 §5.2.2.2, TS 29.505 §5.2.2
func (s *Server) handleGetAuthSub(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "GetAuthSubscription", supi)

	sub, err := s.store.GetAuthSubscription(supi)
	if err != nil {
		log.Warn("not found", "error", err)
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
		return
	}
	log.Info("auth subscription returned", "direction", "OUT")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(authSubToJSON(sub))
}

// PATCH authentication-subscription — update SQN after auth
// Ref: TS 29.504 §5.2.2.3 (PatchUpdate)
func (s *Server) handlePatchAuthSub(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "PatchAuthSubscription", supi)

	var patch struct {
		SequenceNumber *struct {
			SQN string `json:"sqn"`
		} `json:"sequenceNumber"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	if patch.SequenceNumber != nil {
		if err := s.store.UpdateSQN(supi, patch.SequenceNumber.SQN); err != nil {
			log.Error("UpdateSQN failed", "error", err)
			s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
			return
		}
		log.Info("SQN updated", "direction", "IN")
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET am-data — access and mobility subscription data
// Ref: TS 29.504 §5.2.2.2, TS 29.505 §5.2.2 (AMData)
func (s *Server) handleGetAMData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "GetAMData", supi)

	sub, err := s.store.GetAMSubscription(supi)
	if err != nil {
		log.Warn("AM subscription not found", "error", err)
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
		return
	}
	log.Info("AM subscription returned", "direction", "OUT")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(amSubToJSON(sub))
}

// GET sm-data — session management subscription data with subscribed default QoS
// Ref: TS 29.504 §5.2.2.2, TS 29.503 §6.1.6.2.7 (SessionManagementSubscriptionData)
func (s *Server) handleGetSMData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "GetSMData", supi)

	subs, err := s.store.GetSMSubscriptions(supi)
	if err != nil {
		log.Error("GetSMSubscriptions failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	if subs == nil {
		log.Warn("SM subscription not found")
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND",
			"no SM subscription for "+supi)
		return
	}
	log.Info("SM subscription returned", "direction", "OUT", "slice_count", len(subs))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(subs)
}

// PUT sm-data — provision session management subscription data
func (s *Server) handlePutSMData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "PutSMData", supi)

	var subs []store.SessionManagementSubscriptionData
	if err := json.NewDecoder(r.Body).Decode(&subs); err != nil {
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	if err := s.store.PutSMSubscriptions(supi, subs); err != nil {
		log.Error("PutSMSubscriptions failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	log.Info("SM subscription stored", "direction", "IN", "slice_count", len(subs))
	w.WriteHeader(http.StatusNoContent)
}

// PUT amf-3gpp-access — UDM UECM AMF registration context
func (s *Server) handlePutAMFContext(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	s.procedureLog(r, "PutAMFContext", supi).Info("AMF context registered", "direction", "IN")
	w.WriteHeader(http.StatusCreated)
}

// ---- Policy data handlers (TS 29.504 §5.2.4) ----------------------------

// GET /nudr-dr/v2/policy-data/{supi}/ue-policy-set
func (s *Server) handleGetUEPolicySet(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "GetUEPolicySet", supi)

	sub, err := s.store.GetPolicySubscription(supi)
	if err != nil {
		log.Error("GetPolicySubscription failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	if sub == nil {
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND",
			"no policy subscription for "+supi)
		return
	}
	log.Info("UE policy set returned", "direction", "OUT", "rule_count", len(sub.Rules))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sub)
}

// PUT /nudr-dr/v2/policy-data/{supi}/ue-policy-set
func (s *Server) handlePutUEPolicySet(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "PutUEPolicySet", supi)

	var sub store.PolicySubscription
	if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	sub.SUPI = supi
	if err := s.store.PutPolicySubscription(&sub); err != nil {
		log.Error("PutPolicySubscription failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	log.Info("UE policy set stored", "direction", "IN", "rule_count", len(sub.Rules))
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /nudr-dr/v2/policy-data/{supi}/ue-policy-set
func (s *Server) handleDeleteUEPolicySet(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "DeleteUEPolicySet", supi)

	if err := s.store.DeletePolicySubscription(supi); err != nil {
		log.Error("DeletePolicySubscription failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	log.Info("UE policy set deleted", "direction", "IN")
	w.WriteHeader(http.StatusNoContent)
}

// GET /nudr-dr/v2/policy-data/default-policies
func (s *Server) handleListDefaultPolicies(w http.ResponseWriter, r *http.Request) {
	subs, err := s.store.ListPolicySubscriptions()
	if err != nil {
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(subs)
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

func (s *Server) procedureLog(r *http.Request, procedure, supi string) *slog.Logger {
	return s.logger.With(
		"procedure", procedure,
		"interface", "Nudr",
		"direction", "IN",
		"supi", supi,
		"correlation_id", r.Header.Get("X-Correlation-Id"),
	)
}

func (s *Server) problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "cause": cause, "detail": detail})
}

// ---- JSON converters ----------------------------------------------------

func authSubToJSON(s *store.AuthenticationSubscription) map[string]any {
	return map[string]any{
		"authenticationMethod":          s.AuthenticationMethod,
		"encPermanentKey":               s.EncPermanentKey,
		"encOpcKey":                     s.EncOpcKey,
		"authenticationManagementField": s.AuthenticationManagementField,
		"algorithmId":                   s.AlgorithmID,
		"sequenceNumber": map[string]any{
			"sqn":       s.SequenceNumber.SQN,
			"sqnScheme": s.SequenceNumber.SQNScheme,
		},
	}
}

func amSubToJSON(s *store.AccessAndMobilitySubscriptionData) map[string]any {
	snssais := make([]map[string]any, 0)
	for _, n := range s.NSSAI.SNSSAIs {
		entry := map[string]any{"sst": n.SST}
		if n.SD != "" {
			entry["sd"] = n.SD
		}
		if n.DNN != "" {
			entry["dnn"] = n.DNN
		}
		snssais = append(snssais, entry)
	}
	return map[string]any{
		"nssai": map[string]any{
			"defaultSingleNssais": snssais,
		},
		"subscribedUeAmbr": map[string]any{
			"uplink":   fmt.Sprintf("%dKbps", s.SubscribedUEAMBRUplink),
			"downlink": fmt.Sprintf("%dKbps", s.SubscribedUEAMBRDownlink),
		},
	}
}

// supiPath extracts the SUPI from a path like /.../{supi}/...
func supiPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 4 {
		return parts[4]
	}
	return ""
}
