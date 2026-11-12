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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/oklog/ulid/v2"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/udr/internal/qos"
	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
	"github.com/francurieses/claudia-5gc/shared/types"
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

	// operatorSeed / knownDNNs configure the slice-dnn-qos endpoints (see
	// SetSliceQoSSeed, SetKnownDNNs); both are optional.
	operatorSeed map[store.SliceKey]store.AMBR
	knownDNNs    map[string]struct{}

	// profile gates the supportedFeatures wire behaviour (decisions D1/D2,
	// dev/REL19_PROGRAM.md §2); nil behaves as rel17. cat is the
	// Nudr_DataRepository producer catalog; nil = the default.
	profile *capability.Profile
	cat     *features.Catalog
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

// New builds the UDR server. logger must already carry the "nf" attribute (as
// the process logger of cmd/udr does): slog's JSON handler does not
// de-duplicate keys, so New does not add it a second time.
func New(addr string, tlsCfg TLSConfig, st store.Store, logger *slog.Logger) (*Server, error) {
	s := &Server{
		store:  st,
		logger: logger,
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
	// subscribed default 5G QoS profile (TS 29.503 §6.1.6.2.8, TS 29.505)
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
	mux.HandleFunc("PATCH /nudr-dr/v2/policy-data/{supi}/ue-policy-set",
		s.handlePatchUEPolicySet)
	mux.HandleFunc("DELETE /nudr-dr/v2/policy-data/{supi}/ue-policy-set",
		s.handleDeleteUEPolicySet)
	mux.HandleFunc("GET /nudr-dr/v2/policy-data/default-policies",
		s.handleListDefaultPolicies)

	// SM policy data — per-S-NSSAI/per-DNN authorized QoS (TS 29.519 §5.6.2.4)
	mux.HandleFunc("GET /nudr-dr/v2/policy-data/{supi}/sm-data",
		s.handleGetSmPolicyData)
	mux.HandleFunc("PUT /nudr-dr/v2/policy-data/{supi}/sm-data",
		s.handlePutSmPolicyData)
	mux.HandleFunc("PATCH /nudr-dr/v2/policy-data/{supi}/sm-data",
		s.handlePatchSmPolicyData)

	// Internal provisioning API (not 3GPP). The management portal provisions
	// slices by writing subscription_am directly; this lets it ask the UDR to
	// re-derive the matching sm-data, so the slice→QoS mapping stays owned by
	// the UDR instead of being duplicated in the portal.
	mux.HandleFunc("POST /nudr-internal/v1/subscribers/{supi}/sync-sm-data",
		s.handleSyncSMData)

	s.registerSliceQoS(mux)

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

	neg, ok := s.queryFeatures(w, r, querySupportedFeatures, peerUDM)
	if !ok {
		return
	}
	sub, err := s.store.GetAuthSubscription(supi)
	if err != nil {
		log.Warn("not found", "error", err)
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
		return
	}
	// AuthenticationSubscription has no supportedFeatures attribute (TS 29.505
	// Rel-17 YAML): the value is validated and logged, nothing is answered.
	s.logOK(w, r, neg)
	log.Info("auth subscription returned", "direction", "OUT")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(authSubToJSON(sub))
}

// PATCH authentication-subscription — update SQN after auth
// Ref: TS 29.504 §5.2.2.3 (PatchUpdate)
func (s *Server) handlePatchAuthSub(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "PatchAuthSubscription", supi)

	neg, ok := s.queryFeatures(w, r, querySupportedFeatures, peerUDM)
	if !ok {
		return
	}
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
	s.logOK(w, r, neg)
	w.WriteHeader(http.StatusNoContent)
}

// GET am-data — access and mobility subscription data
// Ref: TS 29.504 §5.2.2.2, TS 29.505 §5.2.2 (AMData)
func (s *Server) handleGetAMData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "GetAMData", supi)

	neg, ok := s.queryFeatures(w, r, querySupportedFeatures, peerUDM)
	if !ok {
		return
	}
	sub, err := s.store.GetAMSubscription(supi)
	if err != nil {
		log.Warn("AM subscription not found", "error", err)
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
		return
	}
	s.logOK(w, r, neg)
	log.Info("AM subscription returned", "direction", "OUT")
	resp := amSubToJSON(sub)
	// AccessAndMobilitySubscriptionData.gpsis (TS 29.503 §6.1.6.2.4, schema
	// served by TS 29.505): spec-literal Rel-19 profile only (AMF-020); the
	// legacy profile keeps the pre-existing bytes even when GPSIs are stored.
	if features.SpecLiteral(s.profile) {
		if gpsis := s.validGPSIs(log, supi, sub.GPSIS); len(gpsis) > 0 {
			resp["gpsis"] = gpsis
		}
	}
	// AccessAndMobilitySubscriptionData.supportedFeatures (TS 29.503 §6.1.6.2.4,
	// served by TS 29.505): the negotiated set, absent under rel17 when the
	// request had none (decision D1). The data type points at the Nudm_SDM
	// table (TS 29.503 §6.1.8) while the query parameter negotiates the
	// Nudr_DataRepository table (TS 29.504 §6.1.8); the UDR implements no bit
	// of either, so the value is the empty intersection ("0") in practice.
	if neg.answer != "" {
		resp[attrSupportedFeatures] = neg.answer
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// GET sm-data — session management subscription data with subscribed default QoS
// Ref: TS 29.504 §5.2.2.2, TS 29.503 §6.1.6.2.8 (SessionManagementSubscriptionData)
func (s *Server) handleGetSMData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "GetSMData", supi)

	neg, ok := s.queryFeatures(w, r, querySupportedFeatures, peerUDM)
	if !ok {
		return
	}
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
	// SmSubsData has no top-level supportedFeatures attribute (TS 29.505
	// Rel-17 YAML): validated and logged, nothing is answered.
	s.logOK(w, r, neg)
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
	// The registration body is not stored (pre-existing); it is only read for
	// Amf3GppAccessRegistration.supportedFeatures. An empty body carries no
	// attribute and is accepted as before; an unreadable or oversize one is
	// refused (400 / 413) rather than silently skipping the validation.
	body, err := readBody(w, r)
	if err != nil {
		s.bodyReadFailed(w, r, "PutAMFContext", features.CauseInvalidMsgFormat, err)
		return
	}
	neg, ok := s.bodyFeatures(w, r, body, attrSupportedFeatures, peerUDM)
	if !ok {
		return
	}
	s.logOK(w, r, neg)
	s.procedureLog(r, "PutAMFContext", supi).Info("AMF context registered", "direction", "IN")
	// The 201 has no body here, so there is nothing to answer in (the spec 201
	// carries the registration); the negotiation is validated and logged.
	w.WriteHeader(http.StatusCreated)
}

// ---- Policy data handlers (TS 29.504 §5.2.4) ----------------------------

// GET /nudr-dr/v2/policy-data/{supi}/ue-policy-set
func (s *Server) handleGetUEPolicySet(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "GetUEPolicySet", supi)

	neg, ok := s.queryFeatures(w, r, querySuppFeat, peerPCF)
	if !ok {
		return
	}
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
	s.logOK(w, r, neg)
	log.Info("UE policy set returned", "direction", "OUT", "rule_count", len(sub.Rules))
	w.Header().Set("Content-Type", "application/json")
	// UePolicySet.suppFeat (TS 29.519 §5.4.2.4): the negotiated set, absent
	// under rel17 when the request had none (decision D1).
	_ = json.NewEncoder(w).Encode(uePolicySetResponse{PolicySubscription: sub, SuppFeat: neg.answer})
}

// PUT /nudr-dr/v2/policy-data/{supi}/ue-policy-set
func (s *Server) handlePutUEPolicySet(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "PutUEPolicySet", supi)

	body, err := readBody(w, r)
	if err != nil {
		s.bodyReadFailed(w, r, "PutUEPolicySet", "MANDATORY_IE_INCORRECT", err)
		return
	}
	var sub store.PolicySubscription
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&sub); err != nil {
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	neg, ok := s.bodyFeatures(w, r, body, attrSuppFeat, peerPCF)
	if !ok {
		return
	}
	sub.SUPI = supi
	if err := s.store.PutPolicySubscription(&sub); err != nil {
		log.Error("PutPolicySubscription failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	// UePolicySet.suppFeat is the consumer's set here; the 204 has no body to
	// answer in, so the negotiation is validated and logged only.
	s.logOK(w, r, neg)
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

// PATCH /nudr-dr/v2/policy-data/{supi}/ue-policy-set — partial update of the
// UE policy set (e.g. precedence or rules). Ref: TS 29.504 §5.2.13.
func (s *Server) handlePatchUEPolicySet(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "PatchUEPolicySet", supi)

	cur, err := s.store.GetPolicySubscription(supi)
	if err != nil {
		log.Error("GetPolicySubscription failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	if cur == nil {
		s.problem(w, http.StatusNotFound, "DATA_NOT_FOUND", "no policy subscription for "+supi)
		return
	}

	// Decode into a sparse view so absent fields leave the current value intact.
	var patch struct {
		Precedence *int              `json:"precedence"`
		Rules      *[]store.URSPRule `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	if patch.Precedence != nil {
		cur.Precedence = *patch.Precedence
	}
	if patch.Rules != nil {
		cur.Rules = *patch.Rules
	}
	cur.SUPI = supi
	if err := s.store.PutPolicySubscription(cur); err != nil {
		log.Error("PutPolicySubscription failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	log.Info("UE policy set patched", "direction", "IN", "precedence", cur.Precedence, "rule_count", len(cur.Rules))
	w.WriteHeader(http.StatusNoContent)
}

// GET /nudr-dr/v2/policy-data/{supi}/sm-data — SM policy data (TS 29.519 §5.6.2.4)
func (s *Server) handleGetSmPolicyData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "GetSmPolicyData", supi)

	neg, ok := s.queryFeatures(w, r, querySuppFeat, peerPCF)
	if !ok {
		return
	}
	data, err := s.store.GetSmPolicyData(supi)
	if err != nil {
		log.Error("GetSmPolicyData failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	if data == nil {
		s.problem(w, http.StatusNotFound, "DATA_NOT_FOUND", "no SM policy data for "+supi)
		return
	}
	s.logOK(w, r, neg)
	log.Info("SM policy data returned", "direction", "OUT", "slice_count", len(data.SmPolicySnssaiData))
	w.Header().Set("Content-Type", "application/json")
	// SmPolicyData.suppFeat (TS 29.519 §5.4.2.5): the negotiated set, absent
	// under rel17 when the request had none (decision D1).
	_ = json.NewEncoder(w).Encode(smPolicyDataResponse{SmPolicyData: data, SuppFeat: neg.answer})
}

// PUT /nudr-dr/v2/policy-data/{supi}/sm-data — replace SM policy data
func (s *Server) handlePutSmPolicyData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "PutSmPolicyData", supi)

	var data store.SmPolicyData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	data.SUPI = supi
	if err := s.store.PutSmPolicyData(&data); err != nil {
		log.Error("PutSmPolicyData failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	log.Info("SM policy data stored", "direction", "IN", "slice_count", len(data.SmPolicySnssaiData))
	w.WriteHeader(http.StatusNoContent)
}

// PATCH /nudr-dr/v2/policy-data/{supi}/sm-data — merge SM policy data per S-NSSAI key
func (s *Server) handlePatchSmPolicyData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "PatchSmPolicyData", supi)

	var patch store.SmPolicyData
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", err.Error())
		return
	}
	if err := s.store.PatchSmPolicyData(supi, &patch); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.problem(w, http.StatusNotFound, "DATA_NOT_FOUND", "no SM policy data for "+supi)
			return
		}
		log.Error("PatchSmPolicyData failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	log.Info("SM policy data patched", "direction", "IN", "slice_count", len(patch.SmPolicySnssaiData))
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

// Handler returns the server's root HTTP handler (middleware + routes) for
// in-process testing over HTTP/1.1 (httptest). Not used in production.
func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }

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

// handleSyncSMData re-derives a subscriber's session management subscription
// data from the slices in its AM subscription. Internal provisioning API — not
// a 3GPP operation.
//
// The management portal writes subscription_am directly when it provisions a
// slice; without this, sm-data kept the slice set it was seeded with, so a
// portal-added slice had no DNNConfiguration and the SMF fell back to
// OPERATOR_DEFAULT QoS. Ref: TS 29.503 §6.1.6.2.8.
func (s *Server) handleSyncSMData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.procedureLog(r, "SyncSMData", supi)

	slices, err := store.SyncSMDataFromAM(s.store, supi)
	if err != nil {
		log.Error("sync sm-data failed", "error", err)
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
		return
	}

	log.Info("sm-data resynced from am-data", "direction", "OUT",
		"slice_count", slices, "spec_ref", "TS 29.503 §6.1.6.2.8")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"supi": supi, "slices": slices})
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

// validGPSIs keeps the stored GPSIs that match the Gpsi schema pattern
// (TS 29.571 §5.3.2); each rejected entry is logged and skipped.
func (s *Server) validGPSIs(log *slog.Logger, supi string, stored []string) []string {
	valid, rejected := types.FilterGpsis(stored)
	for _, g := range rejected {
		log.Warn("stored GPSI does not match the Gpsi pattern, skipped",
			"result", "REJECT", "cause", "INVALID_GPSI", "gpsi", g, "spec_ref", "TS 29.571 §5.3.2")
	}
	return valid
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
			"uplink":   fmt.Sprintf("%d Kbps", s.SubscribedUEAMBRUplink),
			"downlink": fmt.Sprintf("%d Kbps", s.SubscribedUEAMBRDownlink),
		},
	}
}

// bitRateKbpsPattern is the TS 29.571 §5.5.2 BitRate regex (space mandatory).
const bitRateKbpsPattern = qos.BitRatePattern
