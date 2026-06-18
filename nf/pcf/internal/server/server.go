package server

import (
	"context"
	"crypto/tls"
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
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// SMPolicyOverride holds per-subscriber QoS parameters that override the default SM policy.
// DNN scopes the override to one Data Network Name (empty = all DNNs of the SUPI); a
// DNN-scoped override is used by the NW-triggered additional PDU session flow so the new
// session gets dedicated QoS without disturbing the subscriber's other sessions.
// Ref: TS 29.512 §5.2.2.2 — PCF may return per-UE qosDecs and sessRules.
type SMPolicyOverride struct {
	FiveQI           int    `json:"5qi"`
	DNN              string `json:"dnn,omitempty"`
	ARPPriorityLevel int    `json:"arp_priority_level,omitempty"`
	AMBRUplink       string `json:"ambr_uplink,omitempty"`
	AMBRDownlink     string `json:"ambr_downlink,omitempty"`
}

// overrideKey builds the smPolicyOverrides map key: "supi" for subscriber-wide
// overrides, "supi|dnn" for DNN-scoped ones.
func overrideKey(supi, dnn string) string {
	if dnn == "" {
		return supi
	}
	return supi + "|" + dnn
}

type Server struct {
	cfg               *config.Config
	logger            *slog.Logger
	httpSrv           *http.Server
	policies          map[string]map[string]interface{}
	policiesMu        sync.Mutex
	smPolicyOverrides map[string]SMPolicyOverride // key: overrideKey(supi, dnn)
	udrClient         UDRClient                   // optional; nil disables UDR lookup (config defaults used)
}

// WithUDRClient attaches a UDR client for per-subscriber URSP rule lookup (N36 interface).
func (s *Server) WithUDRClient(c UDRClient) {
	s.udrClient = c
}

func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	s := &Server{
		cfg:               cfg,
		logger:            logger.With("nf", "PCF"),
		policies:          make(map[string]map[string]interface{}),
		smPolicyOverrides: make(map[string]SMPolicyOverride),
	}

	mux := http.NewServeMux()
	// N7 — Npcf_SMPolicyControl
	mux.HandleFunc("POST /npcf-smpolicycontrol/v1/sm-policies", s.handleCreateSmPolicy)
	mux.HandleFunc("DELETE /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}", s.handleDeleteSmPolicy)
	// N15 — Npcf_UEPolicyControl
	mux.HandleFunc("POST /npcf-ue-policy-control/v1/ue-policies", s.handleCreateUEPolicy)
	mux.HandleFunc("DELETE /npcf-ue-policy-control/v1/ue-policies/{polAssoId}", s.handleDeleteUEPolicy)
	// Internal management — per-subscriber SM policy QoS overrides (not a 3GPP SBI)
	mux.HandleFunc("PUT /pcf-internal/v1/subscribers/{supi}/sm-policy-override", s.handleSetQoSOverride)
	mux.HandleFunc("GET /pcf-internal/v1/subscribers/{supi}/sm-policy-override", s.handleGetQoSOverride)
	mux.HandleFunc("DELETE /pcf-internal/v1/subscribers/{supi}/sm-policy-override", s.handleDeleteQoSOverride)
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	var tlsCfg *tls.Config
	if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" {
		var err error
		tlsCfg, err = loadTLSConfig(cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS config: %w", err)
		}
	} else {
		s.logger.Warn("TLS not configured, using H2C (DEV ONLY)")
	}

	s.httpSrv = &http.Server{
		Addr:              cfg.SBI.Address,
		Handler:           otelhttp.NewHandler(s.middleware(mux), "PCF"),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("PCF SBI server listening", "addr", s.cfg.SBI.Address)
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

func (s *Server) handleCreateSmPolicy(w http.ResponseWriter, r *http.Request) {
	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With("procedure", "SmPolicyCreate", "interface", "Npcf", "direction", "IN", "correlation_id", corrID)

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}

	log.Info("SmPolicyControl_Create received")

	// Generate policy ID
	smPolicyId := uuid.NewString()

	// Store policy
	s.policiesMu.Lock()
	s.policies[smPolicyId] = req
	s.policiesMu.Unlock()

	// QoS decision precedence (highest first):
	//  1. DNN-scoped per-subscriber override (NW-triggered session flow)
	//  2. Subscriber-wide override stored in the PCF (operator/MCP action)
	//  3. Subscribed default QoS reported by the SMF (subsDefQos/subsSessAmbr
	//     from UDM sm-data — TS 29.512 §5.6.2.3 SmPolicyContextData)
	//  4. Operator defaults from config
	// Ref: TS 29.512 §5.2.2.2 — PCF may return per-UE qosDecs and sessRules.
	supi, _ := req["supi"].(string)
	dnn, _ := req["dnn"].(string)
	fiveQI := s.cfg.DefaultSMPolicy.FiveQI
	arpPriority := s.cfg.DefaultSMPolicy.ARPPriorityLevel
	ambrUL := s.cfg.DefaultSMPolicy.SessionAMBRUplink
	ambrDL := s.cfg.DefaultSMPolicy.SessionAMBRDownlink
	qosSource := "OPERATOR_DEFAULT"

	if subsDef, ok := req["subsDefQos"].(map[string]interface{}); ok {
		if v, ok := subsDef["5qi"].(float64); ok && v > 0 {
			fiveQI = int(v)
			qosSource = "UDM_SUBSCRIPTION"
		}
		if arp, ok := subsDef["arp"].(map[string]interface{}); ok {
			if v, ok := arp["priorityLevel"].(float64); ok && v > 0 {
				arpPriority = int(v)
			}
		}
	}
	if subsAmbr, ok := req["subsSessAmbr"].(map[string]interface{}); ok {
		if v, ok := subsAmbr["uplink"].(string); ok && v != "" {
			ambrUL = v
		}
		if v, ok := subsAmbr["downlink"].(string); ok && v != "" {
			ambrDL = v
		}
	}

	s.policiesMu.Lock()
	ov, ok := s.smPolicyOverrides[overrideKey(supi, dnn)] // DNN-scoped first
	if !ok {
		ov, ok = s.smPolicyOverrides[supi] // then subscriber-wide
	}
	if ok {
		fiveQI = ov.FiveQI
		qosSource = "PCF_OVERRIDE"
		if ov.ARPPriorityLevel != 0 {
			arpPriority = ov.ARPPriorityLevel
		}
		if ov.AMBRUplink != "" {
			ambrUL = ov.AMBRUplink
		}
		if ov.AMBRDownlink != "" {
			ambrDL = ov.AMBRDownlink
		}
		log.Info("SmPolicyCreate: applying per-subscriber override",
			"supi", supi, "dnn", dnn, "override_dnn", ov.DNN, "5qi", fiveQI)
	}
	s.policiesMu.Unlock()

	p := s.cfg.DefaultSMPolicy
	response := map[string]interface{}{
		"smPolicyId": smPolicyId,
		// x5gcQosSource is a non-3GPP additive field reporting which input the
		// PCF used for the QoS decision (consumed by SMF/MCP/portal).
		"x5gcQosSource": qosSource,
		"sessRules": map[string]interface{}{
			"sr-1": map[string]interface{}{
				"sessAmbr": map[string]string{
					"uplink":   ambrUL,
					"downlink": ambrDL,
				},
			},
		},
		"pccRules": map[string]interface{}{
			"pr-1": map[string]interface{}{
				"pccRuleId":  "pr-1",
				"flowInfos":  []map[string]string{{"flowDesc": p.FlowDescription}},
				"precedence": p.FlowPrecedence,
			},
		},
		"qosDecs": map[string]interface{}{
			"qd-1": map[string]interface{}{
				"5qi": fiveQI,
				"arp": map[string]interface{}{
					"priorityLevel": arpPriority,
					"preemptCap":    p.ARPPreemptCap,
					"preemptVuln":   p.ARPPreemptVuln,
				},
			},
		},
	}

	log.Info("SmPolicyControl_Create responded",
		"smPolicyId", smPolicyId,
		"5qi", fiveQI,
		"qos_source", qosSource,
		"direction", "OUT",
		"result", "OK",
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/npcf-smpolicycontrol/v1/sm-policies/"+smPolicyId)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleDeleteSmPolicy(w http.ResponseWriter, r *http.Request) {
	smPolicyId := r.PathValue("smPolicyId")
	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With("procedure", "SmPolicyDelete", "interface", "Npcf", "direction", "IN", "correlation_id", corrID, "smPolicyId", smPolicyId)

	s.policiesMu.Lock()
	delete(s.policies, smPolicyId)
	s.policiesMu.Unlock()

	log.Info("SmPolicyControl_Delete", "result", "OK")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

// handleSetQoSOverride stores a per-subscriber SM policy override.
// PUT /pcf-internal/v1/subscribers/{supi}/sm-policy-override
// Body: SMPolicyOverride JSON; optional "dnn" scopes the override to one DNN.
// Used by MCP and portal to configure per-UE QoS before session establishment.
func (s *Server) handleSetQoSOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	var ov SMPolicyOverride
	if err := json.NewDecoder(r.Body).Decode(&ov); err != nil {
		problem(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if ov.FiveQI == 0 {
		problem(w, http.StatusBadRequest, "MISSING_FIELD", "5qi is required and must be non-zero")
		return
	}
	s.policiesMu.Lock()
	s.smPolicyOverrides[overrideKey(supi, ov.DNN)] = ov
	s.policiesMu.Unlock()
	s.logger.Info("QoS override set", "supi", supi, "dnn", ov.DNN, "5qi", ov.FiveQI,
		"ambr_uplink", ov.AMBRUplink, "ambr_downlink", ov.AMBRDownlink)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ov)
}

// handleGetQoSOverride returns the active per-subscriber override, or 404 if none is set.
// GET /pcf-internal/v1/subscribers/{supi}/sm-policy-override[?dnn=<dnn>]
func (s *Server) handleGetQoSOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	dnn := r.URL.Query().Get("dnn")
	s.policiesMu.Lock()
	ov, ok := s.smPolicyOverrides[overrideKey(supi, dnn)]
	s.policiesMu.Unlock()
	if !ok {
		problem(w, http.StatusNotFound, "NOT_FOUND", "no override for "+supi)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ov)
}

// handleDeleteQoSOverride removes a per-subscriber override; subsequent sessions revert to defaults.
// DELETE /pcf-internal/v1/subscribers/{supi}/sm-policy-override[?dnn=<dnn>]
func (s *Server) handleDeleteQoSOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	key := overrideKey(supi, r.URL.Query().Get("dnn"))
	s.policiesMu.Lock()
	_, existed := s.smPolicyOverrides[key]
	delete(s.smPolicyOverrides, key)
	s.policiesMu.Unlock()
	if !existed {
		problem(w, http.StatusNotFound, "NOT_FOUND", "no override for "+supi)
		return
	}
	s.logger.Info("QoS override deleted", "key", key)
	w.WriteHeader(http.StatusNoContent)
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

func problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"cause":  cause,
		"detail": detail,
	})
}
