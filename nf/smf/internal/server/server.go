package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/smf/internal/store"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// SliceID identifies a network slice by SST and SD.
type SliceID struct {
	SST uint8
	SD  string
}

// Session holds state for one PDU session.
type Session struct {
	SUPI         string
	PDUSessionID uint8 // PSI as signalled by the UE (TS 24.501 §9.4)
	DNN          string
	UEIP         net.IP
	ULTEID       uint32  // UPF's UL GTP-U TEID (gNB sends GTP packets here)
	SEID         uint64  // CP F-SEID used to identify this session in PFCP
	SliceID      SliceID // S-NSSAI associated with this session
	SmPolicyID   string  // PCF SM Policy ID (Npcf_SMPolicyControl, TS 29.512 §5.2.2.2)
	FiveQI       uint8   // authorized 5QI (TS 23.501 §5.7)
	ARPPriority  int     // ARP priority level 1-15 (TS 29.571 §5.5.2)
	AMBRULMbps   int     // Session AMBR uplink in Mbps
	AMBRDLMbps   int     // Session AMBR downlink in Mbps
	QoSSource    string  // where the 5QI came from (see QoSSource* constants in qos.go)
	State        string  // ACTIVE | IDLE (user plane deactivated)
	CreatedAt    time.Time
}

// smPolicyQoS carries the QoS parameters extracted from the PCF SM Policy response.
// Ref: TS 29.512 §5.2.2.2 — qosDecs + sessRules.
type smPolicyQoS struct {
	FiveQI      uint8
	ARPPriority int
	AMBRULMbps  int
	AMBRDLMbps  int
	Source      string // QoSSource* constant
}

type Server struct {
	cfg        *config.Config
	logger     *slog.Logger
	httpSrv    *http.Server
	httpClient *http.Client // SBI client for peer NF calls (PCF, UDM)
	mgmtHTTP   *http.Client // plain HTTP client for the AMF management API
	sessions   map[string]*Session
	sessionMu  sync.Mutex
	// ipPools holds one IP pool per DNN; keyed by DNN name.
	// Ref: TS 23.501 §5.6.5 — each DNN has an isolated UE address space.
	ipPools    map[string]*IPPool
	nextSEID   atomic.Uint64 // monotonic counter for PFCP CP-SEID
	nextTEID   atomic.Uint32 // monotonic counter for UL GTP-U TEIDs
	pfcpSeq    atomic.Uint32 // PFCP sequence number
	// db is optional; nil = in-memory only (dev without Docker / unit tests).
	db store.Store
}

type IPPool struct {
	subnet    *net.IPNet
	allocated map[string]bool
	mu        sync.Mutex
}

func NewIPPool(cidr string) (*IPPool, error) {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return &IPPool{
		subnet:    subnet,
		allocated: make(map[string]bool),
	}, nil
}

func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for ip := p.subnet.IP.Mask(p.subnet.Mask); p.subnet.Contains(ip); incIP(ip) {
		if !p.allocated[ip.String()] && !ip.Equal(p.subnet.IP) {
			p.allocated[ip.String()] = true
			return ip, nil
		}
	}
	return nil, errors.New("IP pool exhausted")
}

func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.allocated, ip.String())
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// New creates the SMF server. db may be nil for in-memory-only operation.
func New(cfg *config.Config, logger *slog.Logger, db store.Store) (*Server, error) {
	ipPools := make(map[string]*IPPool, len(cfg.DNNs))
	for _, dnn := range cfg.DNNs {
		pool, err := NewIPPool(dnn.UEIPPool)
		if err != nil {
			return nil, fmt.Errorf("smf: DNN %q IP pool (%s): %w", dnn.Name, dnn.UEIPPool, err)
		}
		ipPools[dnn.Name] = pool
		logger.Info("SMF: DNN IP pool initialised", "dnn", dnn.Name, "pool", dnn.UEIPPool)
	}
	// Safety net: always have an "internet" pool even if config omits it.
	if _, ok := ipPools["internet"]; !ok {
		pool, err := NewIPPool(cfg.UEIPPool)
		if err != nil {
			return nil, fmt.Errorf("smf: fallback internet pool (%s): %w", cfg.UEIPPool, err)
		}
		ipPools["internet"] = pool
	}

	httpClient, err := sbi.NewHTTP2Client(cfg.SBI.TLS.CAFile)
	if err != nil {
		logger.Warn("SMF: could not build SBI HTTP/2 client, using H2C fallback", "error", err)
		httpClient = sbi.NewH2CClient()
	}

	s := &Server{
		cfg:        cfg,
		logger:     logger.With("nf", "SMF"),
		httpClient: httpClient,
		mgmtHTTP:   &http.Client{Timeout: 15 * time.Second},
		sessions:   make(map[string]*Session),
		ipPools:    ipPools,
		db:         db,
	}
	if db != nil {
		if err := s.loadFromStore(context.Background()); err != nil {
			logger.Warn("SMF: failed to load sessions from store — starting empty", "error", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /nsmf-pdusession/v1/sm-contexts", s.handleCreateSMContext)
	mux.HandleFunc("POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify", s.handleUpdateSMContext)
	mux.HandleFunc("DELETE /nsmf-pdusession/v1/sm-contexts/{smContextRef}", s.handleDeleteSMContext)
	// Internal management API — session inspection + NW-initiated QoS
	// modification trigger (not a 3GPP SBI; consumed by MCP + portal).
	mux.HandleFunc("GET /nsmf-management/v1/sessions", s.handleMgmtListSessions)
	mux.HandleFunc("GET /nsmf-management/v1/sessions/{pduSessionId}", s.handleMgmtGetSession)
	mux.HandleFunc("POST /nsmf-management/v1/sessions/{pduSessionId}/qos", s.handleMgmtSetQoS)
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	var tlsCfg *tls.Config
	if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" {
		var err error
		tlsCfg, err = loadTLSConfig(cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS config: %w", err)
		}
	} else {
		s.logger.Warn("TLS not configured (DEV ONLY)")
	}

	s.httpSrv = &http.Server{
		Addr:              cfg.SBI.Address,
		Handler:           otelhttp.NewHandler(s.middleware(mux), "SMF"),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// loadFromStore purges sessions that belong to a previous SMF run.
//
// The UPF is purely in-memory: every time it restarts its PFCP session table
// is empty. Loading stale sessions would mark their IPs as occupied and push
// the SEID/TEID counters forward unnecessarily. Instead, we treat all
// persisted sessions as stale and delete them, so each run starts with a
// clean IP pool and counters starting at 1.
//
// Ref: TS 29.244 §8.2 (PFCP Association Establishment — peer state is reset
// on re-association, so CP-side sessions must be re-established from scratch).
func (s *Server) loadFromStore(ctx context.Context) error {
	sessions, err := s.db.ListSessions(ctx)
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		s.logger.Info("SMF: no stale sessions in store — starting fresh")
		return nil
	}
	for ref := range sessions {
		if delErr := s.db.DeleteSession(ctx, ref); delErr != nil {
			s.logger.Warn("SMF: failed to purge stale session from store",
				"smContextRef", ref, "error", delErr)
		}
	}
	s.logger.Info("SMF: purged stale sessions from previous run — starting fresh",
		"count", len(sessions),
	)
	return nil
}

// cleanupAllSessions releases all currently active sessions: deletes them from
// PostgreSQL and sends best-effort PFCP Session Deletion to the UPF. Called on
// graceful shutdown so the next run starts with a clean store.
func (s *Server) cleanupAllSessions(ctx context.Context) {
	s.sessionMu.Lock()
	sessions := make(map[string]*Session, len(s.sessions))
	for ref, sess := range s.sessions {
		sessions[ref] = sess
	}
	s.sessionMu.Unlock()

	if len(sessions) == 0 {
		return
	}

	for ref, sess := range sessions {
		s.deleteSession(ctx, ref)
		s.deleteSMPolicy(ctx, sess.SmPolicyID)
		go s.sendPFCPSessionDeletion(context.Background(), sess)
	}
	s.logger.Info("SMF: released all sessions on shutdown", "count", len(sessions))
}

// persistSession writes a session to PostgreSQL. No-op when db is nil.
func (s *Server) persistSession(ctx context.Context, ref string, sess *Session) {
	if s.db == nil {
		return
	}
	rec := &store.SessionRecord{
		SUPI:   sess.SUPI,
		DNN:    sess.DNN,
		UEIP:   sess.UEIP.String(),
		ULTEID: sess.ULTEID,
		SEID:   sess.SEID,
		SST:    sess.SliceID.SST,
		SD:     sess.SliceID.SD,
	}
	if err := s.db.UpsertSession(ctx, ref, rec); err != nil {
		s.logger.Error("SMF: persistSession failed", "smContextRef", ref, "error", err)
	}
}

// deleteSession removes a session from PostgreSQL. No-op when db is nil.
func (s *Server) deleteSession(ctx context.Context, ref string) {
	if s.db == nil {
		return
	}
	if err := s.db.DeleteSession(ctx, ref); err != nil {
		s.logger.Error("SMF: deleteSession failed", "smContextRef", ref, "error", err)
	}
}

func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("SMF SBI server listening", "addr", s.cfg.SBI.Address)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.cleanupAllSessions(shutCtx)
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

// handleCreateSMContext creates a new SM context (PDU session)
// Ref: TS 29.502 §5.2.2.3.1
func (s *Server) handleCreateSMContext(w http.ResponseWriter, r *http.Request) {
	spanCtx, span := tracing.Tracer("SMF", "procedures").Start(r.Context(), "Nsmf_PDUSession_CreateSMContext")
	defer span.End()
	r = r.WithContext(spanCtx)

	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With("procedure", "SmContextCreate", "interface", "Nsmf", "direction", "IN", "correlation_id", corrID)

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}

	log.Info("Nsmf_PDUSession_CreateSMContext received")

	// Extract request fields
	supi, _ := req["supi"].(string)
	dnn, _ := req["dnn"].(string)
	pduSessionID, _ := req["pduSessionId"].(float64)
	n1SmMsgB64, _ := req["n1SmMsg"].(string)

	n1SmMsg, _ := base64.StdEncoding.DecodeString(n1SmMsgB64)
	// n1SmMsg is the full 5GSM message (EPD|PSI|PTI|MT|body); the decoder
	// expects the body only. Decoded fields are informational for now.
	if len(n1SmMsg) > 4 {
		pduReq, _ := nas.DecodePDUSessionEstablishmentRequest(n1SmMsg[4:])
		_ = pduReq
	}

	// Extract S-NSSAI if provided (passed by AMF per TS 29.502 §6.1.6.2.2)
	var slice SliceID
	if snssaiRaw, ok := req["snssai"].(map[string]interface{}); ok {
		if sst, ok := snssaiRaw["sst"].(float64); ok {
			slice.SST = uint8(sst)
		}
		if sd, ok := snssaiRaw["sd"].(string); ok {
			slice.SD = sd
		}
	}

	span.SetAttributes(
		attribute.String("supi", supi),
		attribute.String("dnn", dnn),
		attribute.Int("snssai_sst", int(slice.SST)),
		attribute.String("snssai_sd", slice.SD),
	)

	// Allocate UE IP from the DNN-specific pool (TS 23.501 §5.6.5).
	// Fall back to "internet" pool when the requested DNN is not explicitly configured.
	dnnPool := s.ipPools[dnn]
	if dnnPool == nil {
		dnnPool = s.ipPools["internet"]
	}
	if dnnPool == nil {
		log.Error("no IP pool for DNN", "dnn", dnn)
		problem(w, http.StatusUnprocessableEntity, "DNN_NOT_SERVED",
			fmt.Sprintf("DNN %q not served by this SMF", dnn))
		return
	}
	ip, err := dnnPool.Allocate()
	if err != nil {
		log.Error("IP allocation failed", "error", err, "dnn", dnn)
		span.RecordError(err)
		span.SetStatus(codes.Error, "IP pool exhausted")
		metrics.PDUSessionTotal.WithLabelValues("SMF", dnn, "FAILURE").Inc()
		problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}

	smContextRef := uuid.NewString()

	// Per-session identifiers (unique across all sessions)
	ulTEID := s.nextTEID.Add(1)
	seid := s.nextSEID.Add(1)

	// Fetch the subscribed default QoS from UDM over N10 first; it is reported
	// to the PCF as subsDefQos/subsSessAmbr, and used directly when the PCF is
	// unavailable. Ref: TS 23.502 §4.3.2.2.1 step 4 (SM subscription retrieval).
	subQoS := s.fetchSubscribedQoS(r.Context(), supi, dnn, slice)

	// Create SM Policy association with PCF — QoS parameters must be known
	// before encoding N1SM/N2SM. The PCF-authorized values take precedence over
	// the UDM subscription. Ref: TS 23.502 §4.3.2.2.1 step 6, TS 29.512 §5.2.2.2.
	smPolicyID, policyQoS := s.createSMPolicy(r.Context(), supi, dnn, slice, subQoS)

	// N1SM: PDU Session Establishment Accept body (AMF wraps in DL NAS Transport).
	// Carries the QoS rules (QFI=1 default flow) and the QoS flow descriptions
	// with the authorized 5QI (TS 24.501 §9.11.4.12/§9.11.4.13).
	n1SmResp, _ := nas.EncodePDUSessionEstablishmentAcceptBodyWithQoS(
		nas.PDUSessionTypeIPv4, nas.SSCMode1, ip, dnn,
		1 /* QFI=1 for default flow */, policyQoS.FiveQI,
		policyQoS.AMBRDLMbps, policyQoS.AMBRULMbps,
		nas.SNSSAI{SST: slice.SST, SD: nas.SDFromString(slice.SD)},
	)
	n1SmRespB64 := base64.StdEncoding.EncodeToString(n1SmResp)

	// N2SM: Resource Setup Request Transfer — tells gNB the 5QI for the QoS flow.
	n2SmInfo, err := buildPDUSessionResourceSetupRequestTransfer(
		net.ParseIP(s.cfg.UPFN3Addr), ulTEID, 1 /* QFI */, int64(policyQoS.FiveQI),
		int64(policyQoS.AMBRULMbps)*1_000_000, int64(policyQoS.AMBRDLMbps)*1_000_000,
	)
	if err != nil {
		log.Error("N2SM Transfer encoding failed", "error", err)
		metrics.PDUSessionTotal.WithLabelValues("SMF", dnn, "FAILURE").Inc()
		problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	log.Info("N2SM Transfer built",
		"size", len(n2SmInfo), "ulTEID", ulTEID, "upfN3", s.cfg.UPFN3Addr,
		"5qi", policyQoS.FiveQI)
	n2SmInfoB64 := base64.StdEncoding.EncodeToString(n2SmInfo)

	// Store typed session
	sess := &Session{
		SUPI:         supi,
		PDUSessionID: uint8(pduSessionID),
		DNN:          dnn,
		UEIP:         ip,
		ULTEID:       ulTEID,
		SEID:         seid,
		SliceID:      slice,
		SmPolicyID:   smPolicyID,
		FiveQI:       policyQoS.FiveQI,
		ARPPriority:  policyQoS.ARPPriority,
		AMBRULMbps:   policyQoS.AMBRULMbps,
		AMBRDLMbps:   policyQoS.AMBRDLMbps,
		QoSSource:    policyQoS.Source,
		State:        "ACTIVE",
		CreatedAt:    time.Now(),
	}
	s.sessionMu.Lock()
	s.sessions[smContextRef] = sess
	s.sessionMu.Unlock()
	s.persistSession(r.Context(), smContextRef, sess)
	metrics.PDUSessionTotal.WithLabelValues("SMF", dnn, "OK").Inc()
	metrics.PDUSessionsActive.WithLabelValues("SMF", dnn).Inc()

	// Establish PFCP session with UPF asynchronously
	go s.sendPFCPSessionEstablishment(context.Background(), sess)

	span.SetAttributes(
		attribute.String("sm_context_ref", smContextRef),
		attribute.String("allocated_ip", ip.String()),
		attribute.Int("5qi", int(policyQoS.FiveQI)),
	)
	span.SetStatus(codes.Ok, "")
	log.Info("Nsmf_PDUSession_CreateSMContext responded",
		"smContextRef", smContextRef,
		"allocatedIP", ip.String(),
		"snssai_sst", slice.SST,
		"snssai_sd", slice.SD,
		"5qi", policyQoS.FiveQI,
		"direction", "OUT",
		"result", "OK",
	)

	response := map[string]interface{}{
		"smContextRef": smContextRef,
		"n1SmMsg":      n1SmRespB64,
		"n2SmInfo":     n2SmInfoB64,
		"n2SmInfoType": "PDU_RES_SETUP_REQ",
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/nsmf-pdusession/v1/sm-contexts/"+smContextRef)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// handleUpdateSMContext handles three cases:
//  1. N2SM response from gNB (PDU session resource setup): activates DL GTP-U forwarding in UPF.
//  2. AN release notification (upCnxState=DEACTIVATED): deactivates DL forwarding in UPF.
//  3. Xn path switch (n2SmInfoType=PATH_SWITCH_REQ): updates DL GTP-U to target gNB endpoint.
//
// Ref: TS 29.502 §5.2.2.3.2, TS 23.502 §4.3.2.2.1 step 9, TS 23.502 §4.2.6, TS 23.502 §4.9.1.2
func (s *Server) handleUpdateSMContext(w http.ResponseWriter, r *http.Request) {
	smContextRef := r.PathValue("smContextRef")

	spanCtx, span := tracing.Tracer("SMF", "procedures").Start(r.Context(), "Nsmf_PDUSession_UpdateSMContext")
	span.SetAttributes(attribute.String("sm_context_ref", smContextRef))
	defer span.End()
	r = r.WithContext(spanCtx)

	log := s.logger.With("procedure", "SmContextUpdate", "smContextRef", smContextRef)

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}

	// AN Release: upCnxState=DEACTIVATED — suspend UPF DL path.
	// Ref: TS 23.502 §4.2.6 step 5, TS 29.502 §5.2.2.3.2
	if upCnxState, _ := body["upCnxState"].(string); upCnxState == "DEACTIVATED" {
		s.sessionMu.Lock()
		sess := s.sessions[smContextRef]
		s.sessionMu.Unlock()

		if sess == nil {
			log.Warn("AN release: session not found")
			problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found")
			return
		}

		log.Info("AN Release — deactivating UPF DL forwarding",
			"interface", "N4",
			"direction", "OUT",
			"supi", sess.SUPI,
			"seid", sess.SEID,
			"spec_ref", "TS 23.502 §4.2.6",
		)
		s.sessionMu.Lock()
		sess.State = "IDLE"
		s.sessionMu.Unlock()
		go s.sendPFCPSessionDeactivation(context.Background(), sess)
		w.WriteHeader(http.StatusOK)
		return
	}

	// NW-initiated QoS modification: policyUpdate flag set by AMF management API.
	// The SMF builds a PDU Session Modification Command with new QoS rules and AMBR.
	// Ref: TS 23.502 §4.3.3.2, TS 29.512 §5.2.2.3 (PolicyUpdateNotification)
	if policyUpdate, _ := body["policyUpdate"].(bool); policyUpdate {
		s.sessionMu.Lock()
		sess := s.sessions[smContextRef]
		s.sessionMu.Unlock()
		if sess == nil {
			problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found")
			return
		}

		fiveQI := sess.FiveQI
		ambrDL := sess.AMBRDLMbps
		ambrUL := sess.AMBRULMbps

		// Override with values from request body if present.
		if v, ok := body["fiveQI"].(float64); ok && v > 0 {
			fiveQI = uint8(v)
		}
		if v, ok := body["ambrDLMbps"].(float64); ok && v > 0 {
			ambrDL = int(v)
		}
		if v, ok := body["ambrULMbps"].(float64); ok && v > 0 {
			ambrUL = int(v)
		}

		// Update session QoS state.
		s.sessionMu.Lock()
		sess.FiveQI = fiveQI
		sess.AMBRDLMbps = ambrDL
		sess.AMBRULMbps = ambrUL
		if sess.QoSSource != QoSSourceManualOverride {
			sess.QoSSource = QoSSourceNWModification
		}
		s.sessionMu.Unlock()

		// N4: push the updated QER (new MBR for the modified flow) to the UPF
		// and wait for its ack before signalling the UE/gNB.
		// Ref: TS 23.502 §4.3.3.2 step 2 (N4 Session Modification), TS 29.244 §7.5.4
		if upfAck := s.sendPFCPQoSModification(r.Context(), sess); !upfAck {
			log.Warn("PFCP QER modification not acknowledged by UPF — continuing N1/N2 signalling",
				"seid", sess.SEID, "spec_ref", "TS 29.244 §7.5.4")
		}

		pduSessionID, _ := body["pduSessionId"].(float64)
		const nwPTI uint8 = 0 // PTI=0 for NW-initiated (TS 24.501 §9.4)

		cmdBody := nas.EncodePDUSessionModificationCommandBodyWithQoS(1 /* QFI=1 */, fiveQI, ambrDL, ambrUL)
		n1SmCmd := nas.WrapPDUSessionModificationCommandBody(uint8(pduSessionID), nwPTI, cmdBody)

		n2SmInfo, err := buildPDUSessionResourceModifyRequestTransfer()
		if err != nil {
			log.Error("N2SM Modify Transfer encoding failed for policy update", "error", err)
			problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
			return
		}
		log.Info("NW-initiated QoS modification",
			"smContextRef", smContextRef, "pduSessionID", pduSessionID,
			"5qi", fiveQI, "ambr_dl_mbps", ambrDL, "ambr_ul_mbps", ambrUL,
			"qos_source", sess.QoSSource,
			"interface", "Nsmf", "direction", "OUT",
			"spec_ref", "TS 23.502 §4.3.3.2",
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"n1SmMsg":  base64.StdEncoding.EncodeToString(n1SmCmd),
			"n2SmInfo": base64.StdEncoding.EncodeToString(n2SmInfo),
		})
		return
	}

	// PDU Session Modification: n1SmMsg present with 5GSM ModificationRequest (0xC9).
	// The SMF accepts the modification as-is and returns a Modification Command.
	// Ref: TS 23.502 §4.3.3.1, TS 29.502 §5.2.2.3.2
	if n1SmMsgB64, _ := body["n1SmMsg"].(string); n1SmMsgB64 != "" {
		n1SmMsgBytes, err := base64.StdEncoding.DecodeString(n1SmMsgB64)
		if err == nil && len(n1SmMsgBytes) >= 4 && nas.MessageType(n1SmMsgBytes[3]) == nas.MsgTypePDUSessionModificationRequest {
			pduSessionID := n1SmMsgBytes[1]
			pti := n1SmMsgBytes[2]

			cmdBody := nas.EncodePDUSessionModificationCommandBody()
			n1SmCmd := nas.WrapPDUSessionModificationCommandBody(pduSessionID, pti, cmdBody)

			n2SmInfo, err := buildPDUSessionResourceModifyRequestTransfer()
			if err != nil {
				log.Error("N2SM Modify Transfer encoding failed", "error", err)
				problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
				return
			}
			log.Info("Nsmf_PDUSession_ModifySMContext: accepting modification",
				"smContextRef", smContextRef, "pduSessionID", pduSessionID,
				"interface", "Nsmf", "direction", "OUT",
				"spec_ref", "TS 23.502 §4.3.3.1",
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"n1SmMsg":  base64.StdEncoding.EncodeToString(n1SmCmd),
				"n2SmInfo": base64.StdEncoding.EncodeToString(n2SmInfo),
			})
			return
		}
	}

	n2SmInfoB64, _ := body["n2SmInfo"].(string)
	n2SmInfoBytes, err := base64.StdEncoding.DecodeString(n2SmInfoB64)
	if err != nil || len(n2SmInfoBytes) == 0 {
		log.Warn("UpdateSMContext: no N2SM info and no upCnxState, ignoring")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Choose decoder based on n2SmInfoType: PATH_SWITCH_REQ uses PathSwitchRequestTransfer.
	n2SmInfoType, _ := body["n2SmInfoType"].(string)
	var (
		gnbIP  net.IP
		dlTEID uint32
	)
	if n2SmInfoType == "PATH_SWITCH_REQ" {
		gnbIP, dlTEID, err = extractPathSwitchTunnelInfo(n2SmInfoBytes)
		if err != nil {
			log.Error("extractPathSwitchTunnelInfo failed", "error", err)
			problem(w, http.StatusUnprocessableEntity, "SYSTEM_FAILURE", err.Error())
			return
		}
		log.Info("Xn Handover: target gNB DL tunnel info", "gnbIP", gnbIP, "dlTEID", dlTEID,
			"spec_ref", "TS 23.502 §4.9.1.2")
	} else {
		gnbIP, dlTEID, err = extractGNBTunnelInfo(n2SmInfoBytes)
		if err != nil {
			log.Error("extractGNBTunnelInfo failed", "error", err)
			problem(w, http.StatusUnprocessableEntity, "SYSTEM_FAILURE", err.Error())
			return
		}
		log.Info("gNB DL tunnel info", "gnbIP", gnbIP, "dlTEID", dlTEID)
	}

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()

	if sess == nil {
		log.Warn("session not found")
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found")
		return
	}

	s.sessionMu.Lock()
	sess.State = "ACTIVE"
	s.sessionMu.Unlock()
	go s.sendPFCPSessionModification(context.Background(), sess, dlTEID, gnbIP)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteSMContext(w http.ResponseWriter, r *http.Request) {
	smContextRef := r.PathValue("smContextRef")
	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With("procedure", "SmContextDelete", "smContextRef", smContextRef, "correlation_id", corrID)

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	if sess != nil {
		pool := s.ipPools[sess.DNN]
		if pool == nil {
			pool = s.ipPools["internet"]
		}
		if pool != nil {
			pool.Release(sess.UEIP)
		}
	}
	delete(s.sessions, smContextRef)
	s.sessionMu.Unlock()
	s.deleteSession(r.Context(), smContextRef)

	if sess != nil {
		metrics.PDUSessionsActive.WithLabelValues("SMF", sess.DNN).Dec()
		log.Info("Nsmf_PDUSession_DeleteSMContext — releasing session",
			"supi", sess.SUPI, "ueIP", sess.UEIP, "seid", sess.SEID,
			"spec_ref", "TS 29.502 §5.2.2.3.3",
		)
		// Delete SM Policy association with PCF (TS 29.512 §5.2.2.4; TS 23.502 §4.3.4.2 step 3b)
		s.deleteSMPolicy(r.Context(), sess.SmPolicyID)
		go s.sendPFCPSessionDeletion(context.Background(), sess)
	} else {
		log.Warn("Nsmf_PDUSession_DeleteSMContext — session not found")
	}

	w.WriteHeader(http.StatusNoContent)
}

// sendPFCPSessionDeletion sends a PFCP Session Deletion Request to the UPF.
// Ref: TS 29.244 §7.5.6
func (s *Server) sendPFCPSessionDeletion(ctx context.Context, sess *Session) {
	upfAddr, err := net.ResolveUDPAddr("udp", s.cfg.Peers.UPF)
	if err != nil {
		s.logger.Error("PFCP: resolve UPF address", "error", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, upfAddr)
	if err != nil {
		s.logger.Error("PFCP: dial UPF", "error", err)
		return
	}
	defer conn.Close()

	seq := s.pfcpSeq.Add(1)
	req := pfcpmsg.NewSessionDeletionRequest(0, 0, sess.SEID, seq, 0)

	b, err := req.Marshal()
	if err != nil {
		s.logger.Error("PFCP: marshal deletion request", "error", err)
		return
	}
	if _, err := conn.Write(b); err != nil {
		s.logger.Error("PFCP: send deletion request", "error", err)
		return
	}

	s.logger.Info("PFCP SessionDeletion sent", "seid", sess.SEID, "ueIP", sess.UEIP)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		s.logger.Warn("PFCP: no deletion response", "error", err)
		return
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		s.logger.Warn("PFCP: parse deletion response", "error", err)
		return
	}
	s.logger.Info("PFCP SessionDeletion response", "type", msg.MessageTypeName(), "seid", sess.SEID)
}

// sendPFCPSessionDeactivation sends a PFCP Session Modification to the UPF instructing
// it to DROP DL packets (no outer header creation) for this session. Called when the UE
// goes CM-IDLE (AN release). When the UE reconnects via Service Request, a subsequent
// sendPFCPSessionModification re-enables DL forwarding with the new gNB tunnel.
// Ref: TS 29.244 §6.3.3, TS 23.502 §4.2.6
func (s *Server) sendPFCPSessionDeactivation(ctx context.Context, sess *Session) {
	upfAddr, err := net.ResolveUDPAddr("udp", s.cfg.Peers.UPF)
	if err != nil {
		s.logger.Error("PFCP: resolve UPF address", "error", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, upfAddr)
	if err != nil {
		s.logger.Error("PFCP: dial UPF", "error", err)
		return
	}
	defer conn.Close()

	seq := s.pfcpSeq.Add(1)
	// Update the DL FAR: remove outer header creation (DROP action = no forwarding).
	// ApplyAction 0x01 = DROP per TS 29.244 Table 7.5.2.3-1.
	req := pfcpmsg.NewSessionModificationRequest(
		0, 0, sess.SEID, seq, 0,
		pfcpie.NewUpdateFAR(
			pfcpie.NewFARID(1),
			pfcpie.NewApplyAction(0x01), // DROP — UPF discards DL packets
		),
	)

	b, err := req.Marshal()
	if err != nil {
		s.logger.Error("PFCP: marshal deactivation request", "error", err)
		return
	}
	if _, err := conn.Write(b); err != nil {
		s.logger.Error("PFCP: send deactivation request", "error", err)
		return
	}

	s.logger.Info("PFCP SessionDeactivation sent (AN release)",
		"seid", sess.SEID, "supi", sess.SUPI)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		s.logger.Warn("PFCP: no deactivation response", "error", err)
		return
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		s.logger.Warn("PFCP: parse deactivation response", "error", err)
		return
	}
	s.logger.Info("PFCP SessionDeactivation response", "type", msg.MessageTypeName(), "seid", sess.SEID)
}

// createSMPolicy calls PCF to create an SM Policy association.
// Returns the smPolicyId and QoS parameters assigned by PCF.
//
// The subscribed default QoS fetched from UDM (subQoS, may be nil) is reported
// to the PCF as subsDefQos/subsSessAmbr (TS 29.512 §5.6.2.3 SmPolicyContextData);
// the PCF-authorized decision takes precedence over the subscription. When the
// PCF is unreachable, the UDM subscription applies; failing that, operator
// defaults (non-fatal; session proceeds).
// Ref: TS 29.512 §5.2.2.2 (Npcf_SMPolicyControl_Create)
func (s *Server) createSMPolicy(ctx context.Context, supi, dnn string, slice SliceID, subQoS *subscribedQoS) (string, smPolicyQoS) {
	fallback := smPolicyQoS{FiveQI: 9, ARPPriority: 8, AMBRULMbps: 100, AMBRDLMbps: 100, Source: QoSSourceOperatorDefault}
	if subQoS != nil {
		fallback = smPolicyQoS{
			FiveQI:      uint8(subQoS.FiveQI),
			ARPPriority: subQoS.ARPPriority,
			AMBRULMbps:  subQoS.AMBRULMbps,
			AMBRDLMbps:  subQoS.AMBRDLMbps,
			Source:      QoSSourceUDMSubscription,
		}
	}
	if s.cfg.Peers.PCF == "" {
		return "", fallback
	}
	reqBody := map[string]interface{}{
		"supi":           supi,
		"dnn":            dnn,
		"pduSessionType": "IPV4",
		"snssai": map[string]interface{}{
			"sst": int(slice.SST),
			"sd":  slice.SD,
		},
	}
	if subQoS != nil {
		reqBody["subsDefQos"] = map[string]interface{}{
			"5qi": subQoS.FiveQI,
			"arp": map[string]interface{}{
				"priorityLevel": subQoS.ARPPriority,
				"preemptCap":    subQoS.ARPPreemptCap,
				"preemptVuln":   subQoS.ARPPreemptVuln,
			},
		}
		reqBody["subsSessAmbr"] = map[string]interface{}{
			"uplink":   fmt.Sprintf("%d Mbps", subQoS.AMBRULMbps),
			"downlink": fmt.Sprintf("%d Mbps", subQoS.AMBRDLMbps),
		}
	}
	body, _ := json.Marshal(reqBody)
	pcfURL := "https://" + s.cfg.Peers.PCF + "/npcf-smpolicycontrol/v1/sm-policies"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pcfURL, bytes.NewReader(body))
	if err != nil {
		s.logger.Warn("PCF: create SM policy request build failed", "error", err)
		return "", fallback
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Warn("PCF: create SM policy call failed — falling back", "error", err,
			"fallback_source", fallback.Source,
			"spec_ref", "TS 29.512 §5.2.2.2")
		return "", fallback
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		s.logger.Warn("PCF: unexpected status on SM policy create — falling back",
			"status", resp.StatusCode, "fallback_source", fallback.Source)
		return "", fallback
	}

	// Extract smPolicyId from Location header (e.g. /npcf-smpolicycontrol/v1/sm-policies/<id>)
	smPolicyID := ""
	if loc := resp.Header.Get("Location"); loc != "" {
		parts := strings.Split(loc, "/")
		smPolicyID = parts[len(parts)-1]
	}

	// Parse QoS parameters from response body (TS 29.512 §5.2.2.2).
	// The PCF decision wins over the UDM subscription; x5gcQosSource is a
	// non-3GPP additive field reporting which input the PCF actually used.
	qos := smPolicyQoS{
		FiveQI:      fallback.FiveQI,
		ARPPriority: fallback.ARPPriority,
		AMBRULMbps:  fallback.AMBRULMbps,
		AMBRDLMbps:  fallback.AMBRDLMbps,
		Source:      QoSSourceOperatorDefault,
	}
	var respBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err == nil {
		if src, ok := respBody["x5gcQosSource"].(string); ok && src != "" {
			qos.Source = src
		}
		if qosDecs, ok := respBody["qosDecs"].(map[string]interface{}); ok {
			for _, v := range qosDecs {
				if dec, ok := v.(map[string]interface{}); ok {
					if fiveQI, ok := dec["5qi"].(float64); ok && fiveQI > 0 {
						qos.FiveQI = uint8(fiveQI)
					}
					if arp, ok := dec["arp"].(map[string]interface{}); ok {
						if pl, ok := arp["priorityLevel"].(float64); ok && pl > 0 {
							qos.ARPPriority = int(pl)
						}
					}
					break // only the first qosDec entry is used
				}
			}
		}
		if sessRules, ok := respBody["sessRules"].(map[string]interface{}); ok {
			for _, v := range sessRules {
				if rule, ok := v.(map[string]interface{}); ok {
					if ambr, ok := rule["sessAmbr"].(map[string]interface{}); ok {
						if ul, ok := ambr["uplink"].(string); ok {
							qos.AMBRULMbps = parseMbps(ul, fallback.AMBRULMbps)
						}
						if dl, ok := ambr["downlink"].(string); ok {
							qos.AMBRDLMbps = parseMbps(dl, fallback.AMBRDLMbps)
						}
					}
					break
				}
			}
		}
	}

	s.logger.Info("PCF: SM Policy created",
		"smPolicyId", smPolicyID, "supi", supi,
		"5qi", qos.FiveQI, "ambr_ul_mbps", qos.AMBRULMbps, "ambr_dl_mbps", qos.AMBRDLMbps,
		"qos_source", qos.Source,
		"spec_ref", "TS 29.512 §5.2.2.2",
	)
	return smPolicyID, qos
}

// parseMbps extracts the integer Mbps value from a string like "100 Mbps".
// Returns fallback if parsing fails.
func parseMbps(s string, fallback int) int {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return fallback
	}
	var v int
	if _, err := fmt.Sscanf(fields[0], "%d", &v); err != nil || v <= 0 {
		return fallback
	}
	return v
}

// deleteSMPolicy calls PCF to delete an SM Policy association.
// Best-effort: logs on failure but does not block session cleanup.
// Ref: TS 29.512 §5.2.2.4 (Npcf_SMPolicyControl_Delete)
func (s *Server) deleteSMPolicy(ctx context.Context, smPolicyID string) {
	if smPolicyID == "" || s.cfg.Peers.PCF == "" {
		return
	}
	pcfURL := "https://" + s.cfg.Peers.PCF + "/npcf-smpolicycontrol/v1/sm-policies/" + smPolicyID
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, pcfURL, nil)
	if err != nil {
		s.logger.Warn("PCF: delete SM policy request build failed", "error", err)
		return
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Warn("PCF: delete SM policy call failed",
			"smPolicyId", smPolicyID, "error", err,
			"spec_ref", "TS 29.512 §5.2.2.4")
		return
	}
	resp.Body.Close()
	s.logger.Info("PCF: SM Policy deleted",
		"smPolicyId", smPolicyID,
		"spec_ref", "TS 29.512 §5.2.2.4",
	)
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

// buildPDUSessionResourceSetupRequestTransfer encodes N2SM transfer info
// Ref: TS 38.413 §9.3.4.5 - PDU Session Resource Setup Request Transfer
//
// Transfer includes (orden idéntico al de free5GC):
// - IE 130: PDUSessionAggregateMaximumBitRate (AMBR)
// - IE 139: ULNGUUPTNLInformation (GTPTunnel con IP de UPF + TEID)
// - IE 134: PDUSessionType (IPv4)
// - IE 136: QosFlowSetupRequestList (al menos un QoS flow)
//
// PDUSessionResourceSetupRequestTransfer es un SEQUENCE extensible en el ASN.1
// de NGAP, por lo que DEBE codificarse con el parámetro "valueExt" para emitir
// el bit de prefijo de extensión. Sin él, el bitstream queda desplazado y el
// gNB (UERANSIM) y Wireshark no pueden decodificarlo. free5GC usa exactamente
// aper.MarshalWithParams(transfer, "valueExt").
// buildPDUSessionResourceSetupRequestTransfer encodes N2SM transfer info.
// ambrULBps and ambrDLBps are bit rates in bits per second.
// fiveQI is the 5QI value to include in the QoS Flow Setup Request List.
// Ref: TS 38.413 §9.3.4.5 — PDU Session Resource Setup Request Transfer
func buildPDUSessionResourceSetupRequestTransfer(upfIP net.IP, dlTEID uint32, qfi uint8, fiveQI, ambrULBps, ambrDLBps int64) ([]byte, error) {
	transfer := ngapType.PDUSessionResourceSetupRequestTransfer{
		ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceSetupRequestTransferIEs{
			List: []ngapType.PDUSessionResourceSetupRequestTransferIEs{
				// IE: PDUSessionAggregateMaximumBitRate (ID 130)
				{
					Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionAggregateMaximumBitRate},
					Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
					Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
						Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentPDUSessionAggregateMaximumBitRate,
						PDUSessionAggregateMaximumBitRate: &ngapType.PDUSessionAggregateMaximumBitRate{
							PDUSessionAggregateMaximumBitRateUL: ngapType.BitRate{Value: ambrULBps},
							PDUSessionAggregateMaximumBitRateDL: ngapType.BitRate{Value: ambrDLBps},
						},
					},
				},
				// IE: ULNGUUPTNLInformation (ID 139) - GTP-U tunnel to UPF
				{
					Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDULNGUUPTNLInformation},
					Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
					Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
						Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentULNGUUPTNLInformation,
						ULNGUUPTNLInformation: &ngapType.UPTransportLayerInformation{
							Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
							GTPTunnel: &ngapType.GTPTunnel{
								TransportLayerAddress: buildTransportLayerAddress(upfIP),
								GTPTEID: ngapType.GTPTEID{
									Value: aper.OctetString(encodeGTPTEID(dlTEID)),
								},
							},
						},
					},
				},
				// IE: PDUSessionType (ID 134)
				{
					Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionType},
					Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
					Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
						Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentPDUSessionType,
						PDUSessionType: &ngapType.PDUSessionType{
							Value: ngapType.PDUSessionTypePresentIpv4,
						},
					},
				},
				// IE: QosFlowSetupRequestList (ID 136)
				{
					Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDQosFlowSetupRequestList},
					Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
					Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
						Present:                 ngapType.PDUSessionResourceSetupRequestTransferIEsPresentQosFlowSetupRequestList,
						QosFlowSetupRequestList: buildQosFlowSetupRequestList(qfi, fiveQI),
					},
				},
			},
		},
	}

	encoded, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("smf: encode PDUSessionResourceSetupRequestTransfer: %w", err)
	}
	return encoded, nil
}

// buildPDUSessionResourceModifyRequestTransfer builds an empty N2SM Modify Request Transfer.
// All IEs in PDUSessionResourceModifyRequestTransfer are optional; an empty list signals
// no radio resource changes are needed (QoS unchanged).
// Ref: TS 38.413 §9.3.4.7 (PDU Session Resource Modify Request Transfer)
func buildPDUSessionResourceModifyRequestTransfer() ([]byte, error) {
	transfer := ngapType.PDUSessionResourceModifyRequestTransfer{
		ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceModifyRequestTransferIEs{
			List: []ngapType.PDUSessionResourceModifyRequestTransferIEs{},
		},
	}
	encoded, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("smf: encode PDUSessionResourceModifyRequestTransfer: %w", err)
	}
	return encoded, nil
}

// buildTransportLayerAddress encodes UPF IP as APER BitString with length (32 for IPv4)
// Ref: TS 38.413 §9.3.4.5, Annex B — TransportLayerAddress is BIT STRING
func buildTransportLayerAddress(ip net.IP) ngapType.TransportLayerAddress {
	ipv4 := ip.To4()
	if ipv4 == nil {
		ipv4 = net.ParseIP("0.0.0.0").To4()
	}
	return ngapType.TransportLayerAddress{
		Value: aper.BitString{
			Bytes:     ipv4,
			BitLength: 32,
		},
	}
}

// encodeGTPTEID encodes 32-bit TEID as 4-byte big-endian
func encodeGTPTEID(teid uint32) []byte {
	return []byte{
		byte(teid >> 24),
		byte(teid >> 16),
		byte(teid >> 8),
		byte(teid),
	}
}

// buildQosFlowSetupRequestList creates a list with one QoS flow using the given 5QI.
// Ref: TS 38.413 §9.3.4.5, TS 23.501 §5.7.2
func buildQosFlowSetupRequestList(qfi uint8, fiveQI int64) *ngapType.QosFlowSetupRequestList {
	return &ngapType.QosFlowSetupRequestList{
		List: []ngapType.QosFlowSetupRequestItem{
			{
				QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: int64(qfi)},
				QosFlowLevelQosParameters: ngapType.QosFlowLevelQosParameters{
					QosCharacteristics: ngapType.QosCharacteristics{
						Present: ngapType.QosCharacteristicsPresentNonDynamic5QI,
						NonDynamic5QI: &ngapType.NonDynamic5QIDescriptor{
							FiveQI: ngapType.FiveQI{Value: fiveQI},
						},
					},
					AllocationAndRetentionPriority: ngapType.AllocationAndRetentionPriority{
						PriorityLevelARP:        ngapType.PriorityLevelARP{Value: 9},
						PreEmptionCapability:    ngapType.PreEmptionCapability{Value: ngapType.PreEmptionCapabilityPresentShallNotTriggerPreEmption},
						PreEmptionVulnerability: ngapType.PreEmptionVulnerability{Value: ngapType.PreEmptionVulnerabilityPresentNotPreEmptable},
					},
				},
			},
		},
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

func problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"cause":  cause,
		"detail": detail,
	})
}

// sendPFCPSessionEstablishment sends a PFCP Session Establishment Request to UPF.
// Tells UPF: packets arriving on N3 with TEID=sess.ULTEID belong to UE sess.UEIP.
// Ref: TS 29.244 §6.3.2
func (s *Server) sendPFCPSessionEstablishment(ctx context.Context, sess *Session) {
	upfAddr, err := net.ResolveUDPAddr("udp", s.cfg.Peers.UPF)
	if err != nil {
		s.logger.Error("PFCP: resolve UPF address", "error", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, upfAddr)
	if err != nil {
		s.logger.Error("PFCP: dial UPF", "error", err)
		return
	}
	defer conn.Close()

	seq := s.pfcpSeq.Add(1)
	req := pfcpmsg.NewSessionEstablishmentRequest(
		0, 0, 0, seq, 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(sess.SEID, net.ParseIP("0.0.0.0"), nil),
		pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(1),
			pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(
				pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				// F-TEID: UPF listens for GTP-U on N3 IP with UL TEID
				pfcpie.NewFTEID(0x01, sess.ULTEID, net.ParseIP(s.cfg.UPFN3Addr), nil, 0),
				pfcpie.NewUEIPAddress(0x02, sess.UEIP.String(), "", 0, 0),
				// Network Instance carries the DNN so the UPF can select the
				// correct N6 interface for this session's traffic.
				// Ref: TS 29.244 §6.3.3.14, TS 23.501 §5.6.5
				pfcpie.NewNetworkInstance(sess.DNN),
			),
			pfcpie.NewOuterHeaderRemoval(0, 0),
			pfcpie.NewFARID(1),
			pfcpie.NewQERID(1),
		),
		pfcpie.NewCreateFAR(
			pfcpie.NewFARID(1),
			pfcpie.NewApplyAction(0x02), // FORWARD (DL header added via Modification later)
		),
		// QoS Enforcement Rule for the default flow (QFI=1): gates open, MBR set
		// to the session AMBR. The MBR values are in kbps per TS 29.244 §8.2.8.
		// Ref: TS 29.244 §7.5.2.5 (Create QER), §8.2.27 (QER correlation/contents)
		pfcpie.NewCreateQER(
			pfcpie.NewQERID(1),
			pfcpie.NewGateStatus(0, 0), // UL/DL OPEN
			pfcpie.NewMBR(uint64(sess.AMBRULMbps)*1000, uint64(sess.AMBRDLMbps)*1000),
			pfcpie.NewQFI(1),
		),
	)

	b, err := req.Marshal()
	if err != nil {
		s.logger.Error("PFCP: marshal establishment request", "error", err)
		return
	}

	if _, err := conn.Write(b); err != nil {
		s.logger.Error("PFCP: send establishment request", "error", err)
		return
	}

	s.logger.Info("PFCP SessionEstablishment sent",
		"seid", sess.SEID, "ulTEID", sess.ULTEID, "ueIP", sess.UEIP,
		"qer_qfi", 1, "qer_mbr_ul_kbps", sess.AMBRULMbps*1000, "qer_mbr_dl_kbps", sess.AMBRDLMbps*1000,
		"spec_ref", "TS 29.244 §7.5.2.5")

	// Read response (best-effort, no retransmission for now)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		s.logger.Warn("PFCP: no establishment response", "error", err)
		return
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		s.logger.Warn("PFCP: parse establishment response", "error", err)
		return
	}
	s.logger.Info("PFCP SessionEstablishment response", "type", msg.MessageTypeName())
}

// sendPFCPQoSModification sends a PFCP Session Modification Request updating the
// QER for the default flow (QFI=1) with the session's current AMBR as MBR.
// Returns true when the UPF acknowledged the modification.
// Ref: TS 29.244 §7.5.4 (Session Modification), §7.5.2.5 (Update QER)
func (s *Server) sendPFCPQoSModification(ctx context.Context, sess *Session) bool {
	upfAddr, err := net.ResolveUDPAddr("udp", s.cfg.Peers.UPF)
	if err != nil {
		s.logger.Error("PFCP: resolve UPF address", "error", err)
		return false
	}
	conn, err := net.DialUDP("udp", nil, upfAddr)
	if err != nil {
		s.logger.Error("PFCP: dial UPF", "error", err)
		return false
	}
	defer conn.Close()

	s.sessionMu.Lock()
	seid := sess.SEID
	mbrUL := uint64(sess.AMBRULMbps) * 1000
	mbrDL := uint64(sess.AMBRDLMbps) * 1000
	fiveQI := sess.FiveQI
	s.sessionMu.Unlock()

	seq := s.pfcpSeq.Add(1)
	req := pfcpmsg.NewSessionModificationRequest(
		0, 0, seid, seq, 0,
		pfcpie.NewUpdateQER(
			pfcpie.NewQERID(1),
			pfcpie.NewGateStatus(0, 0), // UL/DL OPEN
			pfcpie.NewMBR(mbrUL, mbrDL),
			pfcpie.NewQFI(1),
		),
	)
	b, err := req.Marshal()
	if err != nil {
		s.logger.Error("PFCP: marshal QER modification", "error", err)
		return false
	}
	if _, err := conn.Write(b); err != nil {
		s.logger.Error("PFCP: send QER modification", "error", err)
		return false
	}
	s.logger.Info("PFCP QER modification sent",
		"interface", "N4", "direction", "OUT",
		"seid", seid, "5qi", fiveQI,
		"mbr_ul_kbps", mbrUL, "mbr_dl_kbps", mbrDL,
		"spec_ref", "TS 29.244 §7.5.4",
	)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		s.logger.Warn("PFCP: no QER modification response", "error", err)
		return false
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		s.logger.Warn("PFCP: parse QER modification response", "error", err)
		return false
	}
	s.logger.Info("PFCP QER modification acknowledged",
		"interface", "N4", "direction", "IN",
		"type", msg.MessageTypeName(), "seid", seid, "result", "OK",
	)
	return true
}

// sendPFCPSessionModification sends a PFCP Session Modification Request with the DL tunnel.
// After this, UPF knows to encapsulate downlink packets in GTP-U with dlTEID towards gnbIP.
// Ref: TS 29.244 §6.3.3
func (s *Server) sendPFCPSessionModification(ctx context.Context, sess *Session, dlTEID uint32, gnbIP net.IP) {
	upfAddr, err := net.ResolveUDPAddr("udp", s.cfg.Peers.UPF)
	if err != nil {
		s.logger.Error("PFCP: resolve UPF address", "error", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, upfAddr)
	if err != nil {
		s.logger.Error("PFCP: dial UPF", "error", err)
		return
	}
	defer conn.Close()

	seq := s.pfcpSeq.Add(1)
	// SEID in header = UP SEID assigned by UPF during establishment.
	// Our UPF assigns UP SEID = CP SEID for simplicity.
	req := pfcpmsg.NewSessionModificationRequest(
		0, 0, sess.SEID, seq, 0,
		pfcpie.NewUpdateFAR(
			pfcpie.NewFARID(1),
			pfcpie.NewApplyAction(0x02), // FORWARD
			pfcpie.NewUpdateForwardingParameters(
				// Outer header: GTP-U/UDP/IPv4 (desc=0x0100), DL TEID, gNB N3 IP
				pfcpie.NewOuterHeaderCreation(0x0100, dlTEID, gnbIP.String(), "", 0, 0, 0),
			),
		),
	)

	b, err := req.Marshal()
	if err != nil {
		s.logger.Error("PFCP: marshal modification request", "error", err)
		return
	}

	if _, err := conn.Write(b); err != nil {
		s.logger.Error("PFCP: send modification request", "error", err)
		return
	}

	s.logger.Info("PFCP SessionModification sent",
		"seid", sess.SEID, "dlTEID", dlTEID, "gnbIP", gnbIP)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		s.logger.Warn("PFCP: no modification response", "error", err)
		return
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		s.logger.Warn("PFCP: parse modification response", "error", err)
		return
	}
	s.logger.Info("PFCP SessionModification response", "type", msg.MessageTypeName())
}

// extractPathSwitchTunnelInfo decodes the APER-encoded PathSwitchRequestTransfer
// (from Xn handover) and returns the target gNB's DL GTP-U IP and TEID.
// Ref: TS 38.413 §9.3.4.9
func extractPathSwitchTunnelInfo(n2SmInfo []byte) (net.IP, uint32, error) {
	var transfer ngapType.PathSwitchRequestTransfer
	if err := aper.UnmarshalWithParams(n2SmInfo, &transfer, "valueExt"); err != nil {
		return nil, 0, fmt.Errorf("smf: decode PathSwitchRequestTransfer: %w", err)
	}

	gtpTunnel := transfer.DLNGUUPTNLInformation.GTPTunnel
	if gtpTunnel == nil {
		return nil, 0, fmt.Errorf("smf: GTPTunnel is nil in PathSwitchRequestTransfer")
	}

	teidBytes := []byte(gtpTunnel.GTPTEID.Value)
	if len(teidBytes) != 4 {
		return nil, 0, fmt.Errorf("smf: unexpected TEID length %d in path switch", len(teidBytes))
	}
	dlTEID := binary.BigEndian.Uint32(teidBytes)

	ipBytes := gtpTunnel.TransportLayerAddress.Value.Bytes
	if len(ipBytes) < 4 {
		return nil, 0, fmt.Errorf("smf: unexpected IP length %d in path switch", len(ipBytes))
	}
	gnbIP := make(net.IP, 4)
	copy(gnbIP, ipBytes[:4])

	return gnbIP, dlTEID, nil
}

// extractGNBTunnelInfo decodes the APER-encoded PDUSessionResourceSetupResponseTransfer
// and returns the gNB's DL GTP-U IP and TEID for this PDU session.
// Ref: TS 38.413 §9.3.4.6
func extractGNBTunnelInfo(n2SmInfo []byte) (net.IP, uint32, error) {
	var transfer ngapType.PDUSessionResourceSetupResponseTransfer
	if err := aper.UnmarshalWithParams(n2SmInfo, &transfer, "valueExt"); err != nil {
		return nil, 0, fmt.Errorf("smf: decode PDUSessionResourceSetupResponseTransfer: %w", err)
	}

	gtpTunnel := transfer.DLQosFlowPerTNLInformation.UPTransportLayerInformation.GTPTunnel
	if gtpTunnel == nil {
		return nil, 0, fmt.Errorf("smf: GTPTunnel is nil in response transfer")
	}

	teidBytes := []byte(gtpTunnel.GTPTEID.Value)
	if len(teidBytes) != 4 {
		return nil, 0, fmt.Errorf("smf: unexpected TEID length %d", len(teidBytes))
	}
	dlTEID := binary.BigEndian.Uint32(teidBytes)

	ipBytes := gtpTunnel.TransportLayerAddress.Value.Bytes
	if len(ipBytes) < 4 {
		return nil, 0, fmt.Errorf("smf: unexpected IP length %d", len(ipBytes))
	}
	gnbIP := make(net.IP, 4)
	copy(gnbIP, ipBytes[:4])

	return gnbIP, dlTEID, nil
}
