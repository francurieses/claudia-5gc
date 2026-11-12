package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
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
//
// oapi: none PCF internal management API (/pcf-internal), not a 3GPP SBI body
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
func (s *Server) persistSmPolicyToUDR(ctx context.Context, base *slog.Logger, supi string) {
	if s.udrClient == nil {
		return
	}
	s.policiesMu.Lock()
	dnnData := s.buildOverrideDnnData(supi)
	s.policiesMu.Unlock()

	udrLog := dirLog(base, "N36", dirOut, udrQuerySpecRef)
	cur, err := s.udrClient.GetSmPolicyData(ctx, supi)
	if err != nil {
		udrLog.Warn("UDR read before write-through failed (override applied in-memory only)",
			"supi", supi, "error", err, "result", "FAILURE")
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
		udrLog.Warn("UDR PutSmPolicyData failed (override applied in-memory only)",
			"supi", supi, "error", err, "result", "FAILURE")
	}
}

type Server struct {
	cfg    *config.Config
	logger *slog.Logger
	// baseLogger is the process logger as passed to New (it already carries
	// nf / nf_instance_id in cmd/pcf); FeatureNegotiation records are built
	// from it so no key is duplicated. Ref: TS 29.500 §6.6.2.
	baseLogger        *slog.Logger
	httpSrv           *http.Server
	policies          map[string]map[string]interface{}
	policiesMu        sync.RWMutex
	smPolicyOverrides map[string]SMPolicyOverride // key: overrideKey(supi, dnn)
	udrClient         UDRClient                   // optional; nil disables UDR lookup (config defaults used)
	bsfClient         BSFClient                   // optional; nil when BSF not configured (fail-open)

	// bsfBindingIDs maps smPolicyId → BSF bindingId so handleDeleteSmPolicy can
	// issue the correct Nbsf_Management_DeRegister call.
	// Protected by policiesMu (same lock as policies for simplicity).
	// Ref: TS 29.521 §5.2.2.3
	bsfBindingIDs map[string]string

	// profile gates the supportedFeatures wire behaviour (decisions D1/D2,
	// dev/REL19_PROGRAM.md §2); nil behaves as rel17. cats holds the producer
	// catalog of each Npcf API, indexed by apiKind.
	profile *capability.Profile
	cats    [apiCount]*features.Catalog

	// smFeatures / ueFeatures hold the features negotiated at creation for each
	// SM policy (smPolicyId) and UE policy association (polAssoId), kept for
	// later update/notify operations (which gate on the negotiated set). Those
	// operations do not exist yet, so the maps are write-only today (set on
	// create, dropped on delete). Protected by policiesMu. Ref: TS 29.500 §6.6.2.
	smFeatures map[string]features.Set
	ueFeatures map[string]features.Set

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
	// Ref: TS 29.514 §5.2.2.2 (Create), §4.2.4.2 (Delete)
	appSessions   map[string]AppSessionContext
	appSessionsMu sync.Mutex
}

// AMPolicyAssociation holds an AMF AM policy association record.
// Ref: TS 29.507 §6.1.1.2.4
//
// oapi: none in-memory PCF AM policy association record, never serialised (the PolicyAssociation 201 body is built as a map in handleCreateAMPolicy)
type AMPolicyAssociation struct {
	PolAssoID  string `json:"polAssoId"`
	SUPI       string `json:"supi,omitempty"`
	RFSP       int    `json:"rfsp,omitempty"` // 1-256; 0 = not set
	AccessType string `json:"accessType,omitempty"`
	// Features is the set negotiated at creation (TS 29.500 §6.6.2); not part
	// of the resource representation.
	Features features.Set `json:"-"`
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

// New builds the PCF SBI server. The logger MUST already carry the "nf" key
// (cmd/pcf adds nf and nf_instance_id once); New does not add it again so that
// every log line carries exactly one "nf" key.
func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	s := &Server{
		cfg:               cfg,
		logger:            logger,
		baseLogger:        logger,
		smFeatures:        make(map[string]features.Set),
		ueFeatures:        make(map[string]features.Set),
		policies:          make(map[string]map[string]interface{}),
		smPolicyOverrides: make(map[string]SMPolicyOverride),
		bsfBindingIDs:     make(map[string]string),
		amPolicies:        make(map[string]AMPolicyAssociation),
		rfspOverrides:     make(map[string]int),
		appSessions:       make(map[string]AppSessionContext),
	}
	s.SetCatalogs(Catalogs{})
	if cfg.SBI.FQDN == "" {
		s.logger.Warn("sbi.fqdn not set: Location authority taken from the request Host",
			"spec_ref", "TS 29.501 §4.4.1")
	}

	mux := http.NewServeMux()
	// N7 — Npcf_SMPolicyControl (TS 29.512; YAML server url {apiRoot}/npcf-smpolicycontrol/v1)
	mux.HandleFunc("POST /npcf-smpolicycontrol/v1/sm-policies", s.handleCreateSmPolicy)
	// SM Policy Association Update — custom "update" operation (TS 29.512 §5.2.2.3).
	mux.HandleFunc("POST /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}/update", s.handleUpdateSmPolicy)
	// SM Policy Association Delete — custom "delete" operation, POST with
	// SmPolicyDeleteData. Ref: TS 29.512 §4.2.5.2, §5.3.3.4.2 (YAML POST .../delete).
	mux.HandleFunc("POST /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}/delete", s.handleDeleteSmPolicyPost)
	// N15 — Npcf_UEPolicyControl (URSP). Ref: TS 29.525 §5.2; YAML paths
	// {apiRoot}/npcf-ue-policy-control/v1/policies[/{polAssoId}].
	mux.HandleFunc("POST /npcf-ue-policy-control/v1/policies", s.handleCreateUEPolicy)
	mux.HandleFunc("DELETE /npcf-ue-policy-control/v1/policies/{polAssoId}", s.handleDeleteUEPolicy)
	// N15 — Npcf_AMPolicyControl (AM policy: RFSP + service area restrictions)
	// Ref: TS 29.507 §4.2.2; YAML server url {apiRoot}/npcf-am-policy-control/v1
	mux.HandleFunc("POST /npcf-am-policy-control/v1/policies", s.handleCreateAMPolicy)
	mux.HandleFunc("DELETE /npcf-am-policy-control/v1/policies/{polAssoId}", s.handleDeleteAMPolicy)
	// Npcf_PolicyAuthorization (TS 29.514) — consumed by the NEF to map AF
	// AsSessionWithQoS requests onto PCF policy operations.
	// Ref: TS 29.514 §5.2.2.2 (Create), §4.2.4.2 / §5.3.3.4.2 (Delete: POST .../delete)
	mux.HandleFunc("POST /npcf-policyauthorization/v1/app-sessions", s.handleCreateAppSession)
	mux.HandleFunc("POST /npcf-policyauthorization/v1/app-sessions/{appSessionId}/delete", s.handleDeleteAppSession)
	// Internal management — per-subscriber SM policy QoS overrides (not a 3GPP SBI)
	mux.HandleFunc("GET /pcf-internal/v1/sm-policy-overrides", s.handleListQoSOverrides)
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
		tlsCfg, err = loadTLSConfig(cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile, cfg.SBI.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("pcf: server: load TLS config: %w", err)
		}
	} else {
		s.logger.Warn("TLS not configured, using H2C (DEV ONLY)", "spec_ref", "TS 33.501 §13.1")
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
	base := s.procLog(r, "SmPolicyCreate")
	log := dirLog(base, ifaceNpcf, dirIn, smPolicyCreateSpecRef)
	out := dirLog(base, ifaceNpcf, dirOut, smPolicyCreateSpecRef)

	ctx := logging.WithCorrelationID(r.Context(), corrID)
	peerNF := peerNFType(r, apiSMPolicy)

	var req map[string]interface{}
	if tooLarge, err := decodeBody(w, r, &req); err != nil {
		if tooLarge {
			s.payloadTooLarge(ctx, w, apiSMPolicy, "SmPolicyCreate")
			return
		}
		log.Warn("SmPolicyControl_Create: request body rejected", "error", err,
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}

	// suppFeat must be schema-valid before any state is touched.
	// Ref: TS 29.500 §5.2.7.2, §6.6.2.
	peerSuppFeat, isStr := suppFeatFromMap(req)
	if !isStr {
		s.rejectSuppFeat(ctx, w, apiSMPolicy, peerNF, "<non-string>", errors.New("suppFeat is not a JSON string"), detailNotString)
		return
	}
	if err := features.Validate(peerSuppFeat); err != nil {
		s.rejectSuppFeat(ctx, w, apiSMPolicy, peerNF, peerSuppFeat, err, detailNotHex)
		return
	}
	// Producer side (decision D1): the intersection, absent under rel17 when
	// the request had none, "0" under rel19. Ref: TS 29.512 §5.8.
	suppAnswer, suppSet := s.answer(apiSMPolicy, peerSuppFeat)

	log.Info("SmPolicyControl_Create received")

	// Generate policy ID
	smPolicyId := uuid.NewString()

	// Store policy. The policies map is shared with UE policy associations, so
	// the record carries a type marker (kind) that releaseSmPolicy and
	// handleUpdateSmPolicy check. The stored copy leaves req untouched.
	stored := maps.Clone(req)
	stored[recordTypeKey] = recordTypeSMPolicy
	s.policiesMu.Lock()
	s.policies[smPolicyId] = stored
	s.smFeatures[smPolicyId] = suppSet
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
		udrLog := dirLog(base, "N36", dirOut, udrQuerySpecRef)
		if data, err := s.udrClient.GetSmPolicyData(r.Context(), supi); err != nil {
			udrLog.Warn("UDR GetSmPolicyData failed (using subscription/defaults)", "error", err, "result", "FAILURE")
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
			udrLog.Info("SmPolicyCreate: applying UDR SM policy data",
				"supi", supi, "dnn", dnn, "5qi", fiveQI, "result", "OK")
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
			"supi", supi, "dnn", dnn, "override_dnn", ov.DNN, "5qi", fiveQI, "result", "OK")
	}

	p := s.cfg.DefaultSMPolicy
	response := map[string]interface{}{
		// SmPolicyDecision (TS 29.512 §5.6.2.4) has no identifier attribute: the
		// smPolicyId is conveyed only by the Location header (TS 29.501 §4.4.1).
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

	if suppAnswer != "" {
		response["suppFeat"] = suppAnswer
	}

	// Request accepted: record the negotiation (TS 29.500 §6.6.2).
	s.logAccepted(ctx, apiSMPolicy, peerNF, peerSuppFeat, suppSet)

	out.Info("SmPolicyControl_Create responded",
		"smPolicyId", smPolicyId,
		"5qi", fiveQI,
		"qos_source", qosSource,
		"result", "OK",
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", s.apiRoot(r)+"/npcf-smpolicycontrol/v1/sm-policies/"+smPolicyId)
	w.WriteHeader(http.StatusCreated)
	encodeBody(out, w, response)

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
			bsfLog := dirLog(base, "Nbsf", dirOut, "TS 29.521 §5.2.2.2").With(
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

// smPolicyDeleteSpecRef is the step-level clause for the Delete service
// operation: the PCF removes the SM policy association (TS 29.512 §4.2.5.2).
const smPolicyDeleteSpecRef = "TS 29.512 §4.2.5.2"

// procSmPolicyDelete is the procedure name of the SM policy delete operation
// (logs and fivegc_procedure_total).
const procSmPolicyDelete = "SmPolicyDelete"

// specRefInvalidMsgFormat is the clause for the 400 INVALID_MSG_FORMAT answered
// to a syntactically invalid request body.
const specRefInvalidMsgFormat = "TS 29.500 §5.2.7.2"

// readOptionalJSONBody reads the optional request body of a custom delete
// operation, bounded by features.MaxRequestBodyBytes, and validates that a
// non-empty body is JSON. It writes the error response itself (413 for an
// over-cap body, 400 for a read error, 400 INVALID_MSG_FORMAT for non-JSON,
// TS 29.500 §5.2.7.2) and returns ok=false; the caller must not change any
// state in that case. empty reports a zero-length (or whitespace-only) body.
// base is the procedure-level logger (procedure, correlation_id, ids); the 413
// is logged and counted under procedure.
func (s *Server) readOptionalJSONBody(w http.ResponseWriter, r *http.Request, k apiKind, procedure string, base *slog.Logger) (empty, ok bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
			s.payloadTooLarge(ctx, w, k, procedure)
			return false, false
		}
		dirLog(base, ifaceNpcf, dirIn, specRefInvalidMsgFormat).Warn("request body read failed",
			"error", err, "result", "REJECT", "cause", "INVALID_MSG_FORMAT")
		problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", "request body could not be read")
		return false, false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return true, true
	}
	if !json.Valid(raw) {
		dirLog(base, ifaceNpcf, dirIn, specRefInvalidMsgFormat).Warn("request body is not valid JSON",
			"result", "REJECT", "cause", "INVALID_MSG_FORMAT")
		problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", "request body is not valid JSON")
		return false, false
	}
	return false, true
}

// handleDeleteSmPolicyPost implements POST .../sm-policies/{smPolicyId}/delete
// with an SmPolicyDeleteData body (required: true in the YAML, but an empty
// body is accepted leniently and logged; a non-JSON body is rejected with 400
// INVALID_MSG_FORMAT before any state changes). 204 on success, 404
// ProblemDetails POLICY_ASSOCIATION_NOT_FOUND when the SM policy is unknown.
// Ref: TS 29.512 §4.2.5.2, §5.3.3.4.2, §5.7.3.
func (s *Server) handleDeleteSmPolicyPost(w http.ResponseWriter, r *http.Request) {
	smPolicyId := r.PathValue("smPolicyId")
	base := s.procLog(r, procSmPolicyDelete).With("smPolicyId", smPolicyId)
	in := dirLog(base, ifaceNpcf, dirIn, smPolicyDeleteSpecRef)
	out := dirLog(base, ifaceNpcf, dirOut, smPolicyDeleteSpecRef)

	empty, ok := s.readOptionalJSONBody(w, r, apiSMPolicy, procSmPolicyDelete, base)
	if !ok {
		return
	}
	if empty {
		in.Info("SmPolicyDeleteData body empty (accepted leniently)")
	}

	if !s.releaseSmPolicy(r.Context(), base, smPolicyId) {
		out.Warn("SmPolicyControl_Delete: SM policy not found", "result", "REJECT",
			"cause", "POLICY_ASSOCIATION_NOT_FOUND")
		problem(w, http.StatusNotFound, "POLICY_ASSOCIATION_NOT_FOUND", "SM policy "+smPolicyId+" not found")
		return
	}
	out.Info("SmPolicyControl_Delete", "result", "OK", "known", true)
	w.WriteHeader(http.StatusNoContent)
}

// releaseSmPolicy removes the SM policy record and its negotiated features and
// deregisters the BSF binding, if any. It reports whether an SM policy with that
// id was known; a record of any other type is left untouched and reported
// unknown. A BSF binding ID is never dropped without a deregistration attempt,
// even when the policy map no longer holds the policy. base is the procedure-level logger.
func (s *Server) releaseSmPolicy(ctx context.Context, base *slog.Logger, smPolicyId string) (known bool) {
	s.policiesMu.Lock()
	rec, found := s.policies[smPolicyId]
	if found && !isRecordType(rec, recordTypeSMPolicy) {
		// The id belongs to another resource type (e.g. a UE policy
		// association): it must not be deleted through the SM policy API.
		s.policiesMu.Unlock()
		return false
	}
	known = found
	bindingID := s.bsfBindingIDs[smPolicyId]
	delete(s.bsfBindingIDs, smPolicyId)
	delete(s.policies, smPolicyId)
	delete(s.smFeatures, smPolicyId)
	s.policiesMu.Unlock()

	// ---- BSF binding deregistration (Nbsf_Management_DeRegister) ---------------
	// Best-effort, fail-open: deregister the PCF binding so the BSF's registry stays
	// accurate. A missing or unreachable BSF must not block the SM policy delete.
	// Ref: TS 29.521 §5.2.2.3, TS 23.501 §6.2.16
	if bindingID != "" {
		bsfLog := dirLog(base, "Nbsf", dirOut, "TS 29.521 §5.2.2.3").With("binding_id", bindingID)
		if s.bsfClient == nil {
			bsfLog.Warn("BSF binding dropped without deregistration (no BSF client)", "result", "FAILURE")
			return known
		}
		if err := s.bsfClient.DeregisterBinding(ctx, bindingID); err != nil {
			bsfLog.Warn("BSF DeregisterBinding failed (fail-open)", "error", err, "result", "FAILURE")
		} else {
			bsfLog.Info("BSF binding deregistered", "result", "OK")
		}
	}
	return known
}

// Log field values shared by the Npcf handlers.
const (
	// ifaceNpcf is the interface label of the Npcf service-based interface
	// (N7/N15/N5 consumers all reach the PCF through it).
	ifaceNpcf = "Npcf"
	dirIn     = "IN"
	dirOut    = "OUT"
)

// Internal management API (not a 3GPP SBI): log labels of the per-subscriber
// QoS / RFSP override endpoints under /pcf-internal/v1.
const (
	ifaceInternal   = "Npcf-internal"
	specRefInternal = "n/a (internal management API)"

	procSmPolicyOverride     = "SmPolicyOverride"
	procSmPolicyOverrideList = "SmPolicyOverrideList"
	procAMPolicyOverride     = "AMPolicyOverride"
)

// internalLogs returns the IN and OUT loggers of an internal management
// request (procedure, correlation_id, interface Npcf-internal, spec_ref).
func (s *Server) internalLogs(r *http.Request, procedure string, attrs ...any) (base, in, out *slog.Logger) {
	base = s.procLog(r, procedure)
	if len(attrs) > 0 {
		base = base.With(attrs...)
	}
	return base, dirLog(base, ifaceInternal, dirIn, specRefInternal),
		dirLog(base, ifaceInternal, dirOut, specRefInternal)
}

// procLog returns the procedure-level logger of a request: s.baseLogger (which
// carries "nf" exactly once, see New) plus procedure and correlation_id.
// Callers add interface / direction / spec_ref per line with dirLog so no key
// is ever emitted twice. Ref: root CLAUDE.md "Logging - Required Format".
func (s *Server) procLog(r *http.Request, procedure string) *slog.Logger {
	return logging.NewProcedureLogger(
		logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id")),
		s.baseLogger, procedure)
}

// dirLog derives a logger carrying the mandatory interface, direction and
// spec_ref fields from a procedure-level logger.
func dirLog(base *slog.Logger, iface, direction, specRef string) *slog.Logger {
	return base.With("interface", iface, "direction", direction, "spec_ref", specRef)
}

// apiRoot returns the {apiRoot} of this PCF's SBI for absolute Location
// headers: "https://" + authority (SBA is always https). It never emits an
// unspecified host (0.0.0.0, ::, empty). The authority is, in order:
//
//  1. the configured sbi.fqdn, with the port of sbi.address when it has one;
//  2. the request Host (the peer is mTLS-authenticated, so it is the name the
//     peer itself used to reach this PCF);
//  3. the TLS SNI server name of the request, with the port of sbi.address;
//  4. the host of sbi.address, only when it is a specified address;
//  5. otherwise "" - the Location is then the bare path (relative reference).
//
// Ref: TS 29.501 §4.4.1.
func (s *Server) apiRoot(r *http.Request) string {
	host, port, err := net.SplitHostPort(s.cfg.SBI.Address)
	if err != nil {
		host, port = s.cfg.SBI.Address, ""
	}
	authority := func(h string) string {
		if port == "" {
			return h
		}
		return net.JoinHostPort(h, port)
	}
	if fqdn := s.cfg.SBI.FQDN; fqdn != "" {
		return "https://" + authority(fqdn)
	}
	if r.Host != "" {
		return "https://" + r.Host
	}
	if r.TLS != nil && r.TLS.ServerName != "" {
		return "https://" + authority(r.TLS.ServerName)
	}
	if host != "" {
		if ip := net.ParseIP(host); ip == nil || !ip.IsUnspecified() {
			return "https://" + authority(host)
		}
	}
	return ""
}

// udrQuerySpecRef is the clause of the Nudr_DataRepository Query service
// operation the PCF consumes on N36 (policy data lookup).
const udrQuerySpecRef = "TS 29.504 §5.2.2"

// Record kinds stored under recordTypeKey in the shared policies map, so a
// delete/update only acts on a record of the right resource type.
const (
	recordTypeKey      = "type"
	recordTypeSMPolicy = "sm-policy"
	recordTypeUEPolicy = "ue-policy"
)

// isRecordType reports whether rec is a policies-map record of the given kind.
func isRecordType(rec map[string]interface{}, kind string) bool {
	t, _ := rec[recordTypeKey].(string)
	return t == kind
}

// encodeBody writes v as the JSON response body. A failure after the status
// line was sent cannot change the answer, so it is logged (out carries
// procedure, correlation_id, interface, direction and spec_ref).
func encodeBody(out *slog.Logger, w io.Writer, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		out.Warn("response body encode failed", "error", err, "result", "FAILURE")
	}
}

// smPolicyCreateSpecRef is the clause of the SM Policy Association creation.
const smPolicyCreateSpecRef = "TS 29.512 §4.2.2"

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
	base, in, out := s.internalLogs(r, procSmPolicyOverride, "supi", supi)
	in.Info("QoS override set received")
	var ov SMPolicyOverride
	if err := json.NewDecoder(r.Body).Decode(&ov); err != nil {
		out.Warn("QoS override set: invalid body", "error", err, "result", "REJECT", "cause", "INVALID_BODY")
		problem(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if ov.FiveQI == 0 {
		out.Warn("QoS override set: 5qi missing", "result", "REJECT", "cause", "MISSING_FIELD")
		problem(w, http.StatusBadRequest, "MISSING_FIELD", "5qi is required and must be non-zero")
		return
	}
	s.policiesMu.Lock()
	s.smPolicyOverrides[overrideKey(supi, ov.DNN)] = ov
	s.policiesMu.Unlock()
	// Write-through to the UDR (N36) so the policy is repository-backed.
	s.persistSmPolicyToUDR(r.Context(), base, supi)
	out.Info("QoS override set", "dnn", ov.DNN, "5qi", ov.FiveQI,
		"ambr_uplink", ov.AMBRUplink, "ambr_downlink", ov.AMBRDownlink, "result", "OK")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encodeBody(out, w, ov)
}

// handleGetQoSOverride returns the active per-subscriber override, or 404 if none is set.
// GET /pcf-internal/v1/subscribers/{supi}/sm-policy-override[?dnn=<dnn>]
func (s *Server) handleGetQoSOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	dnn := r.URL.Query().Get("dnn")
	_, in, out := s.internalLogs(r, procSmPolicyOverride, "supi", supi)
	in.Info("QoS override get received", "dnn", dnn)
	s.policiesMu.Lock()
	ov, ok := s.smPolicyOverrides[overrideKey(supi, dnn)]
	s.policiesMu.Unlock()
	if !ok {
		out.Warn("QoS override get: none set", "dnn", dnn, "result", "REJECT", "cause", "NOT_FOUND")
		problem(w, http.StatusNotFound, "NOT_FOUND", "no override for "+supi)
		return
	}
	out.Info("QoS override returned", "dnn", dnn, "5qi", ov.FiveQI, "result", "OK")
	w.Header().Set("Content-Type", "application/json")
	encodeBody(out, w, ov)
}

// SMPolicyOverrideEntry is one element of the override list: the override's own
// JSON fields (5qi, dnn, ...) plus the owning SUPI.
//
// oapi: none PCF internal management API (/pcf-internal), not a 3GPP SBI body
type SMPolicyOverrideEntry struct {
	SUPI string `json:"supi"`
	SMPolicyOverride
}

// handleListQoSOverrides returns every in-memory SM policy override as a JSON array
// (never null), sorted by (supi, dnn); optional ?supi= filter.
// GET /pcf-internal/v1/sm-policy-overrides — internal management API, not a 3GPP SBI.
// Context: TS 29.512 §5.2.2.2 (SM policy association).
func (s *Server) handleListQoSOverrides(w http.ResponseWriter, r *http.Request) {
	supiFilter := r.URL.Query().Get("supi")
	_, in, out := s.internalLogs(r, procSmPolicyOverrideList)
	in.Info("SM policy override list received", "supi_filter", supiFilter)
	entries := make([]SMPolicyOverrideEntry, 0)
	s.policiesMu.RLock()
	for key, ov := range s.smPolicyOverrides {
		supi, _, _ := strings.Cut(key, "|")
		if supiFilter != "" && supi != supiFilter {
			continue
		}
		entries = append(entries, SMPolicyOverrideEntry{SUPI: supi, SMPolicyOverride: ov})
	}
	s.policiesMu.RUnlock()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].SUPI != entries[j].SUPI {
			return entries[i].SUPI < entries[j].SUPI
		}
		return entries[i].DNN < entries[j].DNN
	})
	body, err := json.Marshal(entries)
	if err != nil {
		metrics.ProcedureTotal.WithLabelValues("PCF", procSmPolicyOverrideList, "FAILURE").Inc()
		out.Error("SM policy override list encode failed", "error", err, "result", "FAILURE", "cause", "ENCODE_ERROR")
		problem(w, http.StatusInternalServerError, "ENCODE_ERROR", err.Error())
		return
	}
	metrics.ProcedureTotal.WithLabelValues("PCF", procSmPolicyOverrideList, "OK").Inc()
	out.Info("SM policy override list", "result", "OK", "count", len(entries))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleDeleteQoSOverride removes a per-subscriber override; subsequent sessions revert to defaults.
// DELETE /pcf-internal/v1/subscribers/{supi}/sm-policy-override[?dnn=<dnn>]
func (s *Server) handleDeleteQoSOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	key := overrideKey(supi, r.URL.Query().Get("dnn"))
	base, in, out := s.internalLogs(r, procSmPolicyOverride, "supi", supi)
	in.Info("QoS override delete received", "key", key)
	s.policiesMu.Lock()
	_, existed := s.smPolicyOverrides[key]
	delete(s.smPolicyOverrides, key)
	s.policiesMu.Unlock()
	if !existed {
		out.Warn("QoS override delete: none set", "key", key, "result", "REJECT", "cause", "NOT_FOUND")
		problem(w, http.StatusNotFound, "NOT_FOUND", "no override for "+supi)
		return
	}
	// Reflect the removal in the UDR (N36).
	s.persistSmPolicyToUDR(r.Context(), base, supi)
	out.Info("QoS override deleted", "key", key, "result", "OK")
	w.WriteHeader(http.StatusNoContent)
}

// handleSetRFSPOverride stores a per-subscriber RFSP override consulted at AM policy
// creation. PUT /pcf-internal/v1/subscribers/{supi}/am-policy-override
// Body: {"rfsp": <1-256>}. The new value takes effect on the UE's next registration.
// Ref: TS 38.413 §9.3.1.27 (IndexToRFSP), TS 23.501 §5.3.4.2.
func (s *Server) handleSetRFSPOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	_, in, out := s.internalLogs(r, procAMPolicyOverride, "supi", supi)
	in.Info("RFSP override set received")
	var body struct {
		RFSP int `json:"rfsp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		out.Warn("RFSP override set: invalid body", "error", err, "result", "REJECT", "cause", "INVALID_BODY")
		problem(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if body.RFSP < 1 || body.RFSP > 256 {
		out.Warn("RFSP override set: rfsp out of range", "rfsp", body.RFSP,
			"result", "REJECT", "cause", "INVALID_VALUE")
		problem(w, http.StatusBadRequest, "INVALID_VALUE", "rfsp must be in range 1-256")
		return
	}
	s.amPoliciesMu.Lock()
	s.rfspOverrides[supi] = body.RFSP
	s.amPoliciesMu.Unlock()
	out.Info("RFSP override set", "rfsp", body.RFSP, "result", "OK")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encodeBody(out, w, map[string]any{"supi": supi, "rfsp": body.RFSP})
}

// handleGetRFSPOverride returns the active per-subscriber RFSP override, or 404 if none.
// GET /pcf-internal/v1/subscribers/{supi}/am-policy-override
func (s *Server) handleGetRFSPOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	_, in, out := s.internalLogs(r, procAMPolicyOverride, "supi", supi)
	in.Info("RFSP override get received")
	s.amPoliciesMu.Lock()
	rfsp, ok := s.rfspOverrides[supi]
	s.amPoliciesMu.Unlock()
	if !ok {
		out.Warn("RFSP override get: none set", "result", "REJECT", "cause", "NOT_FOUND")
		problem(w, http.StatusNotFound, "NOT_FOUND", "no RFSP override for "+supi)
		return
	}
	out.Info("RFSP override returned", "rfsp", rfsp, "result", "OK")
	w.Header().Set("Content-Type", "application/json")
	encodeBody(out, w, map[string]any{"supi": supi, "rfsp": rfsp})
}

// handleDeleteRFSPOverride removes a per-subscriber RFSP override; the subscriber reverts
// to the operator default on its next registration.
// DELETE /pcf-internal/v1/subscribers/{supi}/am-policy-override
func (s *Server) handleDeleteRFSPOverride(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	_, in, out := s.internalLogs(r, procAMPolicyOverride, "supi", supi)
	in.Info("RFSP override delete received")
	s.amPoliciesMu.Lock()
	_, existed := s.rfspOverrides[supi]
	delete(s.rfspOverrides, supi)
	s.amPoliciesMu.Unlock()
	if !existed {
		out.Warn("RFSP override delete: none set", "result", "REJECT", "cause", "NOT_FOUND")
		problem(w, http.StatusNotFound, "NOT_FOUND", "no RFSP override for "+supi)
		return
	}
	out.Info("RFSP override deleted", "result", "OK")
	w.WriteHeader(http.StatusNoContent)
}

// ---- Npcf_AMPolicyControl (TS 29.507) ---------------------------------------

// AM policy association procedure names and clauses (logs and metrics).
const (
	procAMPolicyCreate    = "AMPolicyCreate"
	procAMPolicyDelete    = "AMPolicyDelete"
	amPolicyCreateSpecRef = "TS 29.507 §4.2.2"
	amPolicyDeleteSpecRef = "TS 29.507 §4.2.5"
)

// handleCreateAMPolicy processes POST /npcf-am-policy-control/v1/policies.
// AMF calls this at Initial Registration (TS 23.502 §4.2.2.2.2 step 14c).
// Ref: TS 29.507 §4.2.2
func (s *Server) handleCreateAMPolicy(w http.ResponseWriter, r *http.Request) {
	base := s.procLog(r, procAMPolicyCreate)
	log := dirLog(base, ifaceNpcf, dirIn, amPolicyCreateSpecRef)
	out := dirLog(base, ifaceNpcf, dirOut, amPolicyCreateSpecRef)

	var req struct {
		SUPI       string `json:"supi"`
		AccessType string `json:"accessType"`
		PEI        string `json:"pei,omitempty"`
		GPSI       string `json:"gpsi,omitempty"`
		PLMNId     any    `json:"plmnId,omitempty"`
		NotifURI   string `json:"notificationUri,omitempty"`
		SuppFeat   string `json:"suppFeat,omitempty"`
	}
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	peerNF := peerNFType(r, apiAMPolicy)
	if tooLarge, err := decodeBody(w, r, &req); err != nil {
		if tooLarge {
			s.payloadTooLarge(ctx, w, apiAMPolicy, procAMPolicyCreate)
			return
		}
		if features.IsTypeErrorOn(err, apiInfos[apiAMPolicy].field) {
			s.rejectSuppFeat(ctx, w, apiAMPolicy, peerNF, "<non-string>", err, detailNotString)
			return
		}
		log.Warn("AM policy create: request body rejected", "error", err,
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "request body: "+err.Error())
		return
	}
	// suppFeat must be schema-valid before any state is touched.
	// Ref: TS 29.500 §5.2.7.2, §6.6.2.
	if err := features.Validate(req.SuppFeat); err != nil {
		s.rejectSuppFeat(ctx, w, apiAMPolicy, peerNF, req.SuppFeat, err, detailNotHex)
		return
	}
	// Producer side (decision D1). Ref: TS 29.507 §5.8.
	suppAnswer, suppSet := s.answer(apiAMPolicy, req.SuppFeat)
	if req.SUPI == "" {
		log.Warn("AM policy create: supi missing", "result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "supi is mandatory")
		return
	}
	if req.AccessType == "" {
		log.Warn("AM policy create: accessType missing", "supi", req.SUPI,
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "accessType is mandatory")
		return
	}

	// RFSP resolution: per-subscriber override (set via the internal management API,
	// e.g. by the mgmt portal) takes precedence over the operator default of 1.
	// Ref: TS 29.507 §4.2.2, TS 23.501 §5.3.4.2
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
		Features:   suppSet,
	}

	s.amPoliciesMu.Lock()
	s.amPolicies[polAssoID] = assoc
	s.amPoliciesMu.Unlock()

	out.Info("AM policy association created",
		"pol_asso_id", polAssoID,
		"supi", req.SUPI,
		"access_type", req.AccessType,
		"rfsp", assoc.RFSP,
		"result", "OK",
	)

	// PolicyAssociation (TS 29.507 §5.6.2.2) has no polAssoId attribute: the
	// identifier is conveyed only by the Location header (TS 29.501 §4.4.1).
	resp := map[string]any{
		"rfsp": assoc.RFSP,
	}
	// triggers is optional with minItems 1 (TS 29.507 PolicyAssociation): no
	// trigger is requested, so the attribute is omitted rather than sent empty.
	if suppAnswer != "" {
		resp["suppFeat"] = suppAnswer
	}
	// Request accepted: record the negotiation (TS 29.500 §6.6.2).
	s.logAccepted(ctx, apiAMPolicy, peerNF, req.SuppFeat, suppSet)

	location := s.apiRoot(r) + "/npcf-am-policy-control/v1/policies/" + polAssoID
	w.Header().Set("Location", location)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	encodeBody(out, w, resp)
}

// handleDeleteAMPolicy processes DELETE /npcf-am-policy-control/v1/policies/{polAssoId}.
// AMF calls this at UE Deregistration. 204 on success, 404 ProblemDetails
// POLICY_ASSOCIATION_NOT_FOUND when unknown. Ref: TS 29.507 §4.2.5
func (s *Server) handleDeleteAMPolicy(w http.ResponseWriter, r *http.Request) {
	polAssoID := r.PathValue("polAssoId")
	base := s.procLog(r, procAMPolicyDelete).With("pol_asso_id", polAssoID)
	dirLog(base, ifaceNpcf, dirIn, amPolicyDeleteSpecRef).Info("AM policy association delete received")
	out := dirLog(base, ifaceNpcf, dirOut, amPolicyDeleteSpecRef)

	s.amPoliciesMu.Lock()
	_, ok := s.amPolicies[polAssoID]
	delete(s.amPolicies, polAssoID)
	s.amPoliciesMu.Unlock()

	if !ok {
		out.Warn("AM policy association not found", "result", "REJECT", "cause", "POLICY_ASSOCIATION_NOT_FOUND")
		problem(w, http.StatusNotFound, "POLICY_ASSOCIATION_NOT_FOUND",
			"AM policy association "+polAssoID+" not found")
		return
	}
	out.Info("AM policy association deleted", "result", "OK")
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

// loadTLSConfig builds the SBI server TLS configuration: mutual TLS (SBA is
// always mTLS) - every client must present a certificate signed by caFile
// (sbi.tls.ca_file). NextProtos is set here, before http2.ConfigureServer runs
// in Start (ALPN invariant). Ref: TS 33.501 §13.1, TS 29.500 §4.4.2.
func loadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("cert/key not configured")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("pcf: server: load CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("pcf: server: load CA: no PEM certificate in %q", caFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
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
