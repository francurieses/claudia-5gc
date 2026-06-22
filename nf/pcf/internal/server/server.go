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
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/types"
)

// udrSmPolicyBucketKey is the S-NSSAI map key the PCF uses when persisting its
// (DNN-scoped) SM policy overrides as UDR SmPolicyData. The overrides are not
// slice-scoped, so they live in a single "unspecified slice" bucket; the read
// path (resolveSmPolicyDnnData) resolves by DNN regardless of the slice key.
const udrSmPolicyBucketKey = "0"

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

// resolveSmPolicyDnnData finds the authorized QoS for a DNN in UDR SM policy
// data. An exact DNN match (across any S-NSSAI bucket) wins; otherwise a
// subscriber-wide entry (DNN "") is used. The S-NSSAI key is not matched —
// the PCF stores its overrides under a single bucket and resolves by DNN.
func resolveSmPolicyDnnData(data *types.SmPolicyData, dnn string) (types.SmPolicyDnnData, bool) {
	if data == nil {
		return types.SmPolicyDnnData{}, false
	}
	var wide types.SmPolicyDnnData
	var haveWide bool
	for _, e := range data.SmPolicySnssaiData {
		if dnn != "" {
			if d, ok := e.SmPolicyDnnData[dnn]; ok {
				return d, true
			}
		}
		if d, ok := e.SmPolicyDnnData[""]; ok {
			wide, haveWide = d, true
		}
	}
	return wide, haveWide
}

// buildOverrideDnnData assembles the per-DNN policy data for a subscriber from
// all of its in-memory SM policy overrides. The caller must hold policiesMu.
func (s *Server) buildOverrideDnnData(supi string) map[string]types.SmPolicyDnnData {
	dnnData := make(map[string]types.SmPolicyDnnData)
	prefix := supi + "|"
	for key, ov := range s.smPolicyOverrides {
		if key != supi && !strings.HasPrefix(key, prefix) {
			continue
		}
		dnnData[ov.DNN] = types.SmPolicyDnnData{
			DNN:          ov.DNN,
			FiveQI:       ov.FiveQI,
			ARPPriority:  ov.ARPPriorityLevel,
			AMBRUplink:   ov.AMBRUplink,
			AMBRDownlink: ov.AMBRDownlink,
		}
	}
	return dnnData
}

// persistSmPolicyToUDR write-throughs the subscriber's current overrides to the
// UDR over Nudr_DR (best-effort, non-fatal). No-op when no UDR client is wired.
//
// It is read-modify-write: the PCF reads the current SmPolicyData, replaces only
// its own bucket (udrSmPolicyBucketKey) with the rebuilt overrides — or removes
// that bucket when no overrides remain — and writes the result back. This keeps
// directly-provisioned per-S-NSSAI slices intact (the PCF only manages its own
// bucket, it does not own the whole document).
func (s *Server) persistSmPolicyToUDR(ctx context.Context, supi string) {
	if s.udrClient == nil {
		return
	}
	s.policiesMu.Lock()
	dnnData := s.buildOverrideDnnData(supi)
	s.policiesMu.Unlock()

	cur, err := s.udrClient.GetSmPolicyData(ctx, supi)
	if err != nil {
		s.logger.Warn("UDR read before write-through failed (override applied in-memory only)",
			"supi", supi, "error", err)
		return
	}
	if cur == nil {
		cur = &types.SmPolicyData{}
	}
	cur.SUPI = supi
	if cur.SmPolicySnssaiData == nil {
		cur.SmPolicySnssaiData = map[string]types.SmPolicySnssaiData{}
	}
	if len(dnnData) == 0 {
		delete(cur.SmPolicySnssaiData, udrSmPolicyBucketKey)
	} else {
		cur.SmPolicySnssaiData[udrSmPolicyBucketKey] = types.SmPolicySnssaiData{SmPolicyDnnData: dnnData}
	}
	if err := s.udrClient.PutSmPolicyData(ctx, cur); err != nil {
		s.logger.Warn("UDR PutSmPolicyData failed (override applied in-memory only)",
			"supi", supi, "error", err)
	}
}

type Server struct {
	cfg               *config.Config
	logger            *slog.Logger
	httpSrv           *http.Server
	policies          map[string]map[string]interface{}
	policiesMu        sync.Mutex
	smPolicyOverrides map[string]SMPolicyOverride // key: overrideKey(supi, dnn)
	udrClient         UDRClient                   // optional; nil disables UDR lookup (config defaults used)
	bsfClient         BSFClient                   // optional; nil when BSF not configured (fail-open)

	// bsfBindingIDs maps smPolicyId → BSF bindingId so handleDeleteSmPolicy can
	// issue the correct Nbsf_Management_DeRegister call.
	// Protected by policiesMu (same lock as policies for simplicity).
	// Ref: TS 29.521 §5.2.2.3
	bsfBindingIDs map[string]string

	// AM policy associations (Npcf_AMPolicyControl, TS 29.507).
	// key: polAssoId → AMPolicyAssociation
	amPolicies   map[string]AMPolicyAssociation
	amPoliciesMu sync.Mutex

	// rfspOverrides holds per-subscriber RFSP overrides (key: supi → rfsp 1-256).
	// Set via the internal management API; consulted in handleCreateAMPolicy so the
	// AMF receives a subscriber-specific RFSP instead of the operator default.
	// In-memory only (reset on PCF restart) — mirrors smPolicyOverrides.
	rfspOverrides map[string]int

	// appSessions holds Npcf_PolicyAuthorization app-session contexts indexed by
	// appSessionId (UUID minted by the PCF on Create). Used by the NEF to map an
	// AF AsSessionWithQoS request onto a PCF policy-authorization operation.
	// In-memory only (reset on PCF restart).
	// Ref: TS 29.514 §5.2.2.2 (Create), §5.2.2.4 (Delete)
	appSessions   map[string]AppSessionContext
	appSessionsMu sync.Mutex
}

// AMPolicyAssociation holds an AMF AM policy association record.
// Ref: TS 29.507 §6.1.1.2.4
type AMPolicyAssociation struct {
	PolAssoID  string `json:"polAssoId"`
	SUPI       string `json:"supi,omitempty"`
	RFSP       int    `json:"rfsp,omitempty"` // 1-256; 0 = not set
	AccessType string `json:"accessType,omitempty"`
}

// WithUDRClient attaches a UDR client for per-subscriber URSP rule lookup (N36 interface).
func (s *Server) WithUDRClient(c UDRClient) {
	s.udrClient = c
}

// WithBSFClient attaches a BSF client for PCF binding registration/deregistration
// (Nbsf_Management interface). When nil, BSF integration is disabled (fail-open).
// Ref: TS 29.521 §5, TS 23.501 §6.2.16
func (s *Server) WithBSFClient(c BSFClient) {
	s.bsfClient = c
}

func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	s := &Server{
		cfg:               cfg,
		logger:            logger.With("nf", "PCF"),
		policies:          make(map[string]map[string]interface{}),
		smPolicyOverrides: make(map[string]SMPolicyOverride),
		bsfBindingIDs:     make(map[string]string),
		amPolicies:        make(map[string]AMPolicyAssociation),
		rfspOverrides:     make(map[string]int),
		appSessions:       make(map[string]AppSessionContext),
	}

	mux := http.NewServeMux()
	// N7 — Npcf_SMPolicyControl
	mux.HandleFunc("POST /npcf-smpolicycontrol/v1/sm-policies", s.handleCreateSmPolicy)
	// SM Policy Association Update — custom "update" operation (TS 29.512 §5.2.2.3).
	mux.HandleFunc("POST /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}/update", s.handleUpdateSmPolicy)
	mux.HandleFunc("DELETE /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}", s.handleDeleteSmPolicy)
	// N15 — Npcf_UEPolicyControl (URSP)
	mux.HandleFunc("POST /npcf-ue-policy-control/v1/ue-policies", s.handleCreateUEPolicy)
	mux.HandleFunc("DELETE /npcf-ue-policy-control/v1/ue-policies/{polAssoId}", s.handleDeleteUEPolicy)
	// N15 — Npcf_AMPolicyControl (AM policy: RFSP + service area restrictions)
	// Ref: TS 29.507 §4.2.2
	mux.HandleFunc("POST /npcf-ampolicycontrol/v1/policies", s.handleCreateAMPolicy)
	mux.HandleFunc("DELETE /npcf-ampolicycontrol/v1/policies/{polAssoId}", s.handleDeleteAMPolicy)
	// Npcf_PolicyAuthorization (TS 29.514) — consumed by the NEF to map AF
	// AsSessionWithQoS requests onto PCF policy operations.
	// Ref: TS 29.514 §5.2.2.2 (Create), §5.2.2.4 (Delete)
	mux.HandleFunc("POST /npcf-policyauthorization/v1/app-sessions", s.handleCreateAppSession)
	mux.HandleFunc("DELETE /npcf-policyauthorization/v1/app-sessions/{appSessionId}", s.handleDeleteAppSession)
	// Internal management — per-subscriber SM policy QoS overrides (not a 3GPP SBI)
	mux.HandleFunc("PUT /pcf-internal/v1/subscribers/{supi}/sm-policy-override", s.handleSetQoSOverride)
	mux.HandleFunc("GET /pcf-internal/v1/subscribers/{supi}/sm-policy-override", s.handleGetQoSOverride)
	mux.HandleFunc("DELETE /pcf-internal/v1/subscribers/{supi}/sm-policy-override", s.handleDeleteQoSOverride)
	// Internal management — per-subscriber AM policy (RFSP) overrides (not a 3GPP SBI)
	mux.HandleFunc("PUT /pcf-internal/v1/subscribers/{supi}/am-policy-override", s.handleSetRFSPOverride)
	mux.HandleFunc("GET /pcf-internal/v1/subscribers/{supi}/am-policy-override", s.handleGetRFSPOverride)
	mux.HandleFunc("DELETE /pcf-internal/v1/subscribers/{supi}/am-policy-override", s.handleDeleteRFSPOverride)
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
	s.policiesMu.Unlock()

	// Tier 3 — SM Policy Data from the UDR (N36, TS 29.519 §5.6.2.4). Consulted
	// only when no in-memory override matches; it is authoritative repository
	// policy and beats the UDM subscription default. Fail-open on any error so
	// the decision is unchanged when the UDR is absent/unreachable.
	if !ok && s.udrClient != nil {
		if data, err := s.udrClient.GetSmPolicyData(r.Context(), supi); err != nil {
			log.Warn("UDR GetSmPolicyData failed (using subscription/defaults)", "error", err)
		} else if d, found := resolveSmPolicyDnnData(data, dnn); found {
			if d.FiveQI != 0 {
				fiveQI = d.FiveQI
			}
			if d.ARPPriority != 0 {
				arpPriority = d.ARPPriority
			}
			if d.AMBRUplink != "" {
				ambrUL = d.AMBRUplink
			}
			if d.AMBRDownlink != "" {
				ambrDL = d.AMBRDownlink
			}
			qosSource = "UDR_POLICY_DATA"
			log.Info("SmPolicyCreate: applying UDR SM policy data",
				"supi", supi, "dnn", dnn, "5qi", fiveQI)
		}
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

	// ---- BSF binding registration (Nbsf_Management_Register) -------------------
	// Best-effort, fail-open: register the PCF binding with the BSF so that NEF/AF
	// consumers can discover the serving PCF by UE IP. Run in a detached goroutine
	// so that a slow or absent BSF never delays the SM policy create response.
	// Ref: TS 29.521 §5.2.2.2, TS 23.501 §6.2.16
	if s.bsfClient != nil {
		// Extract the UE IPv4 address from the SM policy context data.
		// The SMF sends it as "ipv4Address" (TS 29.512 §5.6.2.3).
		ueIPv4, _ := req["ipv4Address"].(string)
		if ueIPv4 == "" {
			// Tolerate alternative field name used by some consumers.
			ueIPv4, _ = req["ipv4Addr"].(string)
		}
		if ueIPv4 != "" {
			// Extract S-NSSAI from the request body.
			var snssai PcfBindingSnssai
			if snssaiRaw, ok := req["snssai"].(map[string]interface{}); ok {
				if sst, ok := snssaiRaw["sst"].(float64); ok {
					snssai.Sst = int(sst)
				}
				if sd, ok := snssaiRaw["sd"].(string); ok {
					snssai.Sd = sd
				}
			}
			bindingReq := &PcfBindingRequest{
				Supi:     supi,
				Ipv4Addr: ueIPv4,
				Dnn:      dnn,
				Snssai:   snssai,
				PcfFqdn:  s.cfg.SBI.FQDN,
				PcfId:    s.cfg.NFInstanceID,
			}
			bsfLog := log.With(
				"interface", "Nbsf",
				"direction", "OUT",
				"spec_ref", "TS 29.521 §5.2.2.2",
				"supi", supi,
				"dnn", dnn,
				"ipv4_addr", ueIPv4,
			)
			policyIDCopy := smPolicyId
			go func() {
				bsfCtx := context.Background()
				bindingID, err := s.bsfClient.RegisterBinding(bsfCtx, bindingReq)
				if err != nil {
					// 403 EXISTING_BINDING_INFO_FOUND is idempotent — log at Info.
					if strings.Contains(err.Error(), "403") {
						bsfLog.Info("BSF binding already exists (idempotent)",
							"binding_id", bindingID, "result", "OK", "cause", "EXISTING_BINDING_INFO_FOUND")
					} else {
						bsfLog.Warn("BSF RegisterBinding failed (fail-open)",
							"error", err, "result", "FAILURE")
					}
					// Store whatever bindingId was extracted from the 403 body (may be "").
					if bindingID != "" {
						s.policiesMu.Lock()
						s.bsfBindingIDs[policyIDCopy] = bindingID
						s.policiesMu.Unlock()
					}
					return
				}
				bsfLog.Info("BSF binding registered",
					"binding_id", bindingID, "result", "OK")
				s.policiesMu.Lock()
				s.bsfBindingIDs[policyIDCopy] = bindingID
				s.policiesMu.Unlock()
			}()
		}
	}
}

func (s *Server) handleDeleteSmPolicy(w http.ResponseWriter, r *http.Request) {
	smPolicyId := r.PathValue("smPolicyId")
	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With("procedure", "SmPolicyDelete", "interface", "Npcf", "direction", "IN", "correlation_id", corrID, "smPolicyId", smPolicyId)

	// Retrieve and remove the associated BSF bindingId before deleting the policy record.
	s.policiesMu.Lock()
	bindingID := s.bsfBindingIDs[smPolicyId]
	delete(s.bsfBindingIDs, smPolicyId)
	delete(s.policies, smPolicyId)
	s.policiesMu.Unlock()

	// ---- BSF binding deregistration (Nbsf_Management_DeRegister) ---------------
	// Best-effort, fail-open: deregister the PCF binding so the BSF's registry stays
	// accurate. A missing or unreachable BSF must not block the SM policy delete.
	// Ref: TS 29.521 §5.2.2.3, TS 23.501 §6.2.16
	if s.bsfClient != nil && bindingID != "" {
		bsfLog := log.With(
			"interface", "Nbsf",
			"direction", "OUT",
			"spec_ref", "TS 29.521 §5.2.2.3",
			"binding_id", bindingID,
		)
		if err := s.bsfClient.DeregisterBinding(r.Context(), bindingID); err != nil {
			bsfLog.Warn("BSF DeregisterBinding failed (fail-open)", "error", err, "result", "FAILURE")
		} else {
			bsfLog.Info("BSF binding deregistered", "result", "OK")
		}
	}

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
	// Write-through to the UDR (N36) so the policy is repository-backed.
	s.persistSmPolicyToUDR(r.Context(), supi)
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
	// Reflect the removal in the UDR (N36).
	s.persistSmPolicyToUDR(r.Context(), supi)
	s.logger.Info("QoS override deleted", "key", key)
	w.WriteHeader(http.StatusNoContent)
}

// handleSetRFSPOverride stores a per-subscriber RFSP override consulted at AM policy
// creation. PUT /pcf-internal/v1/subscribers/{supi}/am-policy-override
// Body: {"rfsp": <1-256>}. The new value takes effect on the UE's next registration.
// Ref: TS 38.413 §9.3.1.27 (IndexToRFSP), TS 23.501 §5.3.4.2.
func (s *Server) handleSetRFSPOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	var body struct {
		RFSP int `json:"rfsp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if body.RFSP < 1 || body.RFSP > 256 {
		problem(w, http.StatusBadRequest, "INVALID_VALUE", "rfsp must be in range 1-256")
		return
	}
	s.amPoliciesMu.Lock()
	s.rfspOverrides[supi] = body.RFSP
	s.amPoliciesMu.Unlock()
	s.logger.Info("RFSP override set",
		"procedure", "AMPolicyOverride", "supi", supi, "rfsp", body.RFSP,
		"spec_ref", "TS 38.413 §9.3.1.27")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"supi": supi, "rfsp": body.RFSP})
}

// handleGetRFSPOverride returns the active per-subscriber RFSP override, or 404 if none.
// GET /pcf-internal/v1/subscribers/{supi}/am-policy-override
func (s *Server) handleGetRFSPOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	s.amPoliciesMu.Lock()
	rfsp, ok := s.rfspOverrides[supi]
	s.amPoliciesMu.Unlock()
	if !ok {
		problem(w, http.StatusNotFound, "NOT_FOUND", "no RFSP override for "+supi)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"supi": supi, "rfsp": rfsp})
}

// handleDeleteRFSPOverride removes a per-subscriber RFSP override; the subscriber reverts
// to the operator default on its next registration.
// DELETE /pcf-internal/v1/subscribers/{supi}/am-policy-override
func (s *Server) handleDeleteRFSPOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	s.amPoliciesMu.Lock()
	_, existed := s.rfspOverrides[supi]
	delete(s.rfspOverrides, supi)
	s.amPoliciesMu.Unlock()
	if !existed {
		problem(w, http.StatusNotFound, "NOT_FOUND", "no RFSP override for "+supi)
		return
	}
	s.logger.Info("RFSP override deleted", "procedure", "AMPolicyOverride", "supi", supi)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Npcf_AMPolicyControl (TS 29.507) ---------------------------------------

// handleCreateAMPolicy processes POST /npcf-ampolicycontrol/v1/policies.
// AMF calls this at Initial Registration (TS 23.502 §4.2.2.2.2 step 14c).
// Ref: TS 29.507 §4.2.2.2
func (s *Server) handleCreateAMPolicy(w http.ResponseWriter, r *http.Request) {
	log := s.logger.With(
		"procedure", "AMPolicyCreate",
		"interface", "Npcf",
		"direction", "IN",
		"correlation_id", r.Header.Get("X-Correlation-Id"),
		"spec_ref", "TS 29.507 §4.2.2.2",
	)

	var req struct {
		SUPI       string `json:"supi"`
		AccessType string `json:"accessType"`
		PEI        string `json:"pei,omitempty"`
		GPSI       string `json:"gpsi,omitempty"`
		PLMNId     any    `json:"plmnId,omitempty"`
		NotifURI   string `json:"notificationUri,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "request body: "+err.Error())
		return
	}
	if req.SUPI == "" {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "supi is mandatory")
		return
	}
	if req.AccessType == "" {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "accessType is mandatory")
		return
	}

	// RFSP resolution: per-subscriber override (set via the internal management API,
	// e.g. by the mgmt portal) takes precedence over the operator default of 1.
	// Ref: TS 29.507 §4.2.2.2, TS 23.501 §5.3.4.2
	rfsp := 1
	s.amPoliciesMu.Lock()
	if ov, ok := s.rfspOverrides[req.SUPI]; ok && ov > 0 {
		rfsp = ov
	}
	s.amPoliciesMu.Unlock()

	polAssoID := ulid.Make().String()
	assoc := AMPolicyAssociation{
		PolAssoID:  polAssoID,
		SUPI:       req.SUPI,
		RFSP:       rfsp,
		AccessType: req.AccessType,
	}

	s.amPoliciesMu.Lock()
	s.amPolicies[polAssoID] = assoc
	s.amPoliciesMu.Unlock()

	log.Info("AM policy association created",
		"pol_asso_id", polAssoID,
		"supi", req.SUPI,
		"access_type", req.AccessType,
		"rfsp", assoc.RFSP,
		"direction", "OUT",
		"result", "OK",
	)

	location := "/npcf-ampolicycontrol/v1/policies/" + polAssoID
	w.Header().Set("Location", location)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"polAssoId": polAssoID,
		"rfsp":      assoc.RFSP,
		"triggers":  []string{},
	})
}

// handleDeleteAMPolicy processes DELETE /npcf-ampolicycontrol/v1/policies/{polAssoId}.
// AMF calls this at UE Deregistration. Ref: TS 29.507 §4.2.2.4
func (s *Server) handleDeleteAMPolicy(w http.ResponseWriter, r *http.Request) {
	polAssoID := r.PathValue("polAssoId")
	log := s.logger.With(
		"procedure", "AMPolicyDelete",
		"pol_asso_id", polAssoID,
		"spec_ref", "TS 29.507 §4.2.2.4",
	)

	s.amPoliciesMu.Lock()
	_, ok := s.amPolicies[polAssoID]
	delete(s.amPolicies, polAssoID)
	s.amPoliciesMu.Unlock()

	if !ok {
		problem(w, http.StatusNotFound, "POLICY_ASSOCIATION_NOT_FOUND",
			"AM policy association "+polAssoID+" not found")
		return
	}
	log.Info("AM policy association deleted")
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
