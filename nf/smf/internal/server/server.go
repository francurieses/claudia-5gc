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
	"github.com/francurieses/claudia-5gc/shared/logging"
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
	AMBRULKbps   uint64  // exact Session AMBR uplink in kbps (PFCP MBR)
	AMBRDLKbps   uint64  // exact Session AMBR downlink in kbps (PFCP MBR)
	QoSSource    string  // where the 5QI came from (see QoSSource* constants in qos.go)
	State        string  // ACTIVE | IDLE (user plane deactivated) | RELEASING (PFCP node recovery in progress)
	CreatedAt    time.Time
	// N4EstablishedAt is when the UPF accepted the PFCP Session Establishment
	// (zero until then; CreatedAt is the fallback). Compared with the UPF
	// Recovery Time Stamp to find sessions lost in a UPF restart.
	// Ref: TS 23.007 §19A, TS 23.527 §4.3.
	N4EstablishedAt time.Time
	// N4Stale is set when the UPF restarted: its PFCP session table is empty, so
	// no N4 signalling (Deletion/Modification) must be sent for this session.
	N4Stale bool
	// PDUSessionType is the granted type (PDUSessionTypeIPv4|IPv6|IPv4v6).
	// Ref: TS 24.501 §9.11.4.11.
	PDUSessionType uint8
	// UEIPv6Prefix is the delegated /64 (CIDR string) for IPv6/IPv4v6 sessions;
	// the prefix is advertised to the UE via RA on the UPF TUN (escalated,
	// UPF-001). Empty for IPv4-only sessions. Ref: TS 23.501 §5.8.2.2.
	UEIPv6Prefix string

	// HOTargetGNBIP / HOTargetDLTEID hold the target gNB DL NG-U GTP tunnel
	// received in the HandoverRequestAcknowledgeTransfer (n2SmInfoType
	// HANDOVER_REQ_ACK). Stored for N2 HO step 12 (DL switch at HANDOVER
	// NOTIFY, TS 23.502 §4.9.1.3.3); used by handleHandoverComplete for the
	// DL path switch and cleared after it. In-memory only — not persisted.
	HOTargetGNBIP  net.IP
	HOTargetDLTEID uint32
	// HOState is the N2 handover state tracked from the AMF's UpdateSMContext
	// hoState values (hoState* constants). In-memory only.
	// Ref: TS 29.502 §6.1.6.3 (HoState), §5.2.2.3.4.
	HOState string
	// HODirectForwarding is true when the source NG-RAN signalled a direct
	// data forwarding path (HandoverRequiredTransfer.DirectForwardingPathAvailability).
	// Ref: TS 38.413 §9.3.4.14; TS 23.502 §4.9.1.3.2 step 3.
	HODirectForwarding bool
	// HOTargetFailed is set by HANDOVER_RES_ALLOC_FAIL (the target could not set the
	// PDU session up); the release-or-deactivate decision (HOReleaseOnDeactivate, rule R1)
	// is executed when the AMF later signals upCnxState DEACTIVATED. Cleared by
	// DEACTIVATED, PREPARING, ACTIVATING and a successful COMPLETED.
	// Ref: TS 23.502 §4.3.7 step 1, §4.9.1.3.2 step 10; docs/procedures/N2Handover.md §7.8.
	HOTargetFailed bool
	// HOReleaseOnDeactivate is the rule R1 result: true = release the PDU session,
	// false = deactivate the UP connection.
	HOReleaseOnDeactivate bool
	// UPSecurityRequired is true when the session's UP security enforcement policy is
	// "Required" (TS 23.501 §5.10.3). This SMF never signals Required (the Security
	// Indication IE is omitted), so it is false today; rule R1 reads it.
	UPSecurityRequired bool
}

// smPolicyQoS carries the QoS parameters extracted from the PCF SM Policy response.
// Ref: TS 29.512 §5.2.2.2 — qosDecs + sessRules.
type smPolicyQoS struct {
	FiveQI      uint8
	ARPPriority int
	AMBRULMbps  int
	AMBRDLMbps  int
	AMBRULKbps  uint64 // exact Session-AMBR UL in kbps (PFCP MBR, TS 29.244 §8.2.8)
	AMBRDLKbps  uint64 // exact Session-AMBR DL in kbps
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
	ipPools map[string]*IPPool
	// ipv6Pools holds one /64-delegating IPv6 pool per IPv6-capable DNN, keyed
	// by DNN name. A DNN absent here is IPv4-only. Ref: TS 23.501 §5.8.2.2.
	ipv6Pools map[string]*IPv6Pool
	nextSEID  atomic.Uint64 // monotonic counter for PFCP CP-SEID
	nextTEID  atomic.Uint32 // monotonic counter for UL GTP-U TEIDs
	pfcpSeq   atomic.Uint32 // PFCP sequence number
	// db is optional; nil = in-memory only (dev without Docker / unit tests).
	db store.Store
	// secondaryAuthDNNs marks which DNNs require DN-AAA secondary
	// authentication/authorization at PDU Session Establishment. A DNN
	// absent here establishes without any EAP round (TS 23.501 §5.6.6).
	secondaryAuthDNNs map[string]bool
	// dnAAA is the SMF's seam onto the Data Network AAA server (N6). Default
	// is the in-core simulated implementation; tests may substitute their own.
	dnAAA DNAAAClient
	// pendingAuth holds in-flight secondary-authentication state, keyed by
	// smContextRef. Ref: TS 23.502 §4.3.2.3.
	pendingAuth   map[string]*pendingSecondaryAuth
	pendingAuthMu sync.Mutex
	// n1n2Push defaults to s.pushN1N2Message; overridable in tests to capture
	// the NAS bytes pushed towards the UE without needing a live mTLS AMF peer.
	n1n2Push func(ctx context.Context, supi string, psi uint8, n1SmMsg, n2SmInfo []byte, n2SmInfoType string) (string, error)

	// PFCP node-level supervision (SMF-004), see pfcp_node.go.
	recoveryTS time.Time      // SMF local Recovery Time Stamp (TS 29.244 §8.2.65), seconds resolution
	pfcpTimers pfcpNodeTimers // T1/N1/heartbeat/retry timers; tests may override
	assoc      pfcpAssociation
	assocKick  chan struct{} // nudges an immediate Association Setup attempt
	recoverCh  chan struct{} // supervisor wake-up after a detection event
	releaseWG  sync.WaitGroup
	guardWG    sync.WaitGroup // RELEASING guard timers (pfcp_node.go)
	hoWG       sync.WaitGroup // detached target-failed release/deactivation tasks (pfcp_ho.go)
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

	network := p.subnet.IP.Mask(p.subnet.Mask)
	// Conventional gateway/TUN address: network + 1 (".1"). Never hand this
	// out to a UE — some UPF deployments bind their DN-side TUN interface
	// there, and even when they don't (this one uses .254, see
	// nf/upf/config/dev.yaml), .1 is the address most UE/OS stacks and
	// documentation assume is the router, so reserving it is cheap insurance.
	// Live OTA session 2026-09-03: the allocator handed the very first UE
	// (Pixel 6a) address .1 with zero exclusions besides the network address
	// itself — found while debugging "no internet" after PDU session setup.
	gateway := make(net.IP, len(network))
	copy(gateway, network)
	incIP(gateway)

	for ip := p.subnet.IP.Mask(p.subnet.Mask); p.subnet.Contains(ip); incIP(ip) {
		if !p.allocated[ip.String()] && !ip.Equal(p.subnet.IP) && !ip.Equal(gateway) {
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

// dnsServersFor returns the configured IPv4 DNS resolvers for the given DNN,
// parsed from config.Config.DNNs[i].DNS. Returns nil (no EPCO DNS IE emitted)
// if the DNN is unknown or has no valid IPv4 entries — Config.Load already
// defaults every DNN's DNS list, so this is normally non-empty.
func (s *Server) dnsServersFor(dnn string) []net.IP {
	for _, d := range s.cfg.DNNs {
		if d.Name != dnn {
			continue
		}
		var out []net.IP
		for _, a := range d.DNS {
			if ip := net.ParseIP(a).To4(); ip != nil {
				out = append(out, ip)
			}
		}
		return out
	}
	return nil
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

	// IPv6 /64-delegating pools for DNNs that configure an IPv6 prefix. A DNN
	// without ue_ipv6_prefix is IPv4-only. Ref: TS 23.501 §5.8.2.2.
	ipv6Pools := make(map[string]*IPv6Pool)
	for _, dnn := range cfg.DNNs {
		if dnn.UEIPv6Prefix == "" {
			continue
		}
		pool, err := NewIPv6Pool(dnn.UEIPv6Prefix)
		if err != nil {
			return nil, fmt.Errorf("smf: DNN %q IPv6 prefix (%s): %w", dnn.Name, dnn.UEIPv6Prefix, err)
		}
		ipv6Pools[dnn.Name] = pool
		logger.Info("SMF: DNN IPv6 prefix pool initialised", "dnn", dnn.Name, "prefix", dnn.UEIPv6Prefix)
	}

	// Use an mTLS client when cert/key are configured so the SMF can call peer NF
	// SBI servers that require client certificates (e.g. the AMF namf-comm server
	// for N1N2MessageTransfer). Falls back to TLS-only, then H2C. Presenting a
	// client cert to a peer that does not request one is harmless.
	// Ref: TS 29.500 §4.4.1, TS 33.501 §13.
	var httpClient *http.Client
	var err error
	if cfg.SBI.TLS.CertFile != "" && cfg.SBI.TLS.KeyFile != "" && cfg.SBI.TLS.CAFile != "" {
		httpClient, err = sbi.NewMTLSClient(cfg.SBI.TLS.CAFile, cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
	} else {
		httpClient, err = sbi.NewHTTP2Client(cfg.SBI.TLS.CAFile)
	}
	if err != nil {
		logger.Warn("SMF: could not build SBI HTTP/2 client, using H2C fallback", "error", err)
		httpClient = sbi.NewH2CClient()
	}

	// Secondary authentication (TS 23.501 §5.6.6): per-DNN gate + the
	// simulated DN-AAA's dev/test "unreachable" knob.
	secondaryAuthDNNs := make(map[string]bool)
	dnAAAUnreachableDNNs := make(map[string]bool)
	for _, dnn := range cfg.DNNs {
		if dnn.SecondaryAuth {
			secondaryAuthDNNs[dnn.Name] = true
			logger.Info("SMF: DNN requires secondary DN-AAA authentication",
				"dnn", dnn.Name, "spec_ref", "TS 23.501 §5.6.6")
		}
		if dnn.DNAAAUnreachable {
			dnAAAUnreachableDNNs[dnn.Name] = true
		}
	}

	s := &Server{
		cfg:               cfg,
		logger:            logger.With("nf", "SMF"),
		httpClient:        httpClient,
		mgmtHTTP:          &http.Client{Timeout: 15 * time.Second},
		sessions:          make(map[string]*Session),
		ipPools:           ipPools,
		ipv6Pools:         ipv6Pools,
		db:                db,
		secondaryAuthDNNs: secondaryAuthDNNs,
		dnAAA:             newSimulatedDNAAAClient(dnAAAUnreachableDNNs),
		pendingAuth:       make(map[string]*pendingSecondaryAuth),
		recoveryTS:        time.Now().UTC().Truncate(time.Second),
		pfcpTimers:        pfcpTimersFromConfig(cfg.N4),
		assocKick:         make(chan struct{}, 1),
		recoverCh:         make(chan struct{}, 1),
	}
	s.assoc.state = assocSetupPending
	s.n1n2Push = s.pushN1N2Message
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
	// DL-data notification — simulates the UPF Downlink Data Report (PFCP Session
	// Report) for a session whose user plane is deactivated, driving CN paging via
	// Namf_Communication_N1N2MessageTransfer. The real N4 PFCP DDN is UPF-001
	// (PFCP session-management path). Ref: TS 23.502 §4.2.3.3.
	mux.HandleFunc("POST /nsmf-management/v1/sessions/{pduSessionId}/dl-data-notification", s.handleDLDataNotification)
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
		// A session N4Stale (UPF restarted, SEID unknown to the new UPF) gets no
		// PFCP deletion. Ref: TS 23.527 §4.3, TS 29.244 §7.5.6.
		s.sessionMu.Lock()
		n4Stale := sess.N4Stale
		s.sessionMu.Unlock()
		if n4Stale {
			continue
		}
		go s.sendPFCPSessionDeletion(context.Background(), sess)
	}
	s.logger.Info("SMF: released all sessions on shutdown", "count", len(sessions))
}

// persistSession writes a session to PostgreSQL. No-op when db is nil.
func (s *Server) persistSession(ctx context.Context, ref string, sess *Session) {
	if s.db == nil {
		return
	}
	// net.IP.String() returns the literal text "<nil>" for a nil/zero-length
	// IP (a well-known Go stdlib gotcha) — that must never reach the store.
	// A pure IPv6/IPv6-only session has no sess.UEIP (IPv4) at all, so fall
	// back to the derived full IPv6 address (delegated /64 + IID) instead of
	// leaving the column blank, which would also drop the session from the
	// portal's `WHERE ue_ip != ''` session list.
	ueIPStr := ""
	if sess.UEIP != nil {
		ueIPStr = sess.UEIP.String()
	} else if v6, err := ueIPv6Address(sess.UEIPv6Prefix); err == nil {
		ueIPStr = v6.String()
	}
	rec := &store.SessionRecord{
		SUPI:   sess.SUPI,
		DNN:    sess.DNN,
		UEIP:   ueIPStr,
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
	s.warnIfNotAssociated(r.Context(), corrID)

	// Extract request fields
	supi, _ := req["supi"].(string)
	dnn, _ := req["dnn"].(string)
	pduSessionID, _ := req["pduSessionId"].(float64)
	n1SmMsgB64, _ := req["n1SmMsg"].(string)

	n1SmMsg, _ := base64.StdEncoding.DecodeString(n1SmMsgB64)
	// n1SmMsg is the full 5GSM message (EPD|PSI|PTI|MT|body); the decoder
	// expects the body only. We extract the requested PDU session type to drive
	// IPv6/IPv4v6 prefix delegation (TS 23.501 §5.8.2.2, TS 24.501 §9.11.4.11).
	// The PTI (octet 3) is echoed on every 5GSM response for this session,
	// including the secondary-authentication AUTH COMMAND/RESULT/ACCEPT/REJECT
	// messages below (TS 24.501 §9.6).
	var pti uint8
	if len(n1SmMsg) > 2 {
		pti = n1SmMsg[2]
	}
	var requestedType *uint8
	// Keep the whole decoded request: the Accept's ePCO must answer the UE's
	// own container list IN THE UE'S OWN ORDER (nas.BuildEPCOReply, mirroring
	// Open5GS smf_pco_build) — a Pixel 6a / Shannon modem that puts IPCP
	// (0x8021) first got dnses=[] when we answered it last. The decoded request
	// also carries the requested PDU session type, which drives both IPv6
	// prefix delegation and the 5GSM cause #50/#51 on a downgrade.
	// See docs/ACCEPT-DIFF-open5gs-vs-claudia-2026-09-04.md.
	var pduReq *nas.PDUSessionEstablishmentRequest
	if len(n1SmMsg) > 4 {
		if decoded, err := nas.DecodePDUSessionEstablishmentRequest(n1SmMsg[4:]); err == nil {
			pduReq = decoded
			requestedType = decoded.PDUSessionType
		}
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

	// Resolve the granted PDU session type from the UE request + the DNN's IPv6
	// capability, then allocate the required address family/families.
	// Ref: TS 23.501 §5.8.2.2, TS 24.501 §9.11.4.11.
	v6Pool := s.ipv6Pools[dnn]
	grantedType := selectPDUSessionType(requestedType, v6Pool != nil)

	var ip net.IP // IPv4 (nil for an IPv6-only session)
	var err error
	if pduTypeNeedsIPv4(grantedType) {
		ip, err = dnnPool.Allocate()
		if err != nil {
			log.Error("IP allocation failed", "error", err, "dnn", dnn)
			span.RecordError(err)
			span.SetStatus(codes.Error, "IP pool exhausted")
			metrics.PDUSessionTotal.WithLabelValues("SMF", dnn, "FAILURE").Inc()
			problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
			return
		}
	}

	var v6Prefix *net.IPNet
	var v6IID []byte
	if pduTypeNeedsIPv6(grantedType) {
		v6Prefix, v6IID, err = v6Pool.Allocate()
		if err != nil {
			if ip != nil {
				dnnPool.Release(ip)
			}
			log.Error("IPv6 prefix allocation failed", "error", err, "dnn", dnn)
			span.RecordError(err)
			span.SetStatus(codes.Error, "IPv6 pool exhausted")
			metrics.PDUSessionTotal.WithLabelValues("SMF", dnn, "FAILURE").Inc()
			problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
			return
		}
	}

	smContextRef := uuid.NewString()

	// Per-session identifiers (unique across all sessions)
	ulTEID := s.nextTEID.Add(1)
	seid := s.nextSEID.Add(1)

	// Secondary authentication gate (TS 23.501 §5.6.6, TS 23.502 §4.3.2.3): if
	// the DNN requires DN-AAA authorization, hold the session in
	// PENDING_SECONDARY_AUTH instead of proceeding straight to PCF/N4/Accept.
	// The address material already allocated above is reserved for this
	// session and released on rejection. A DNN without secondary_auth falls
	// straight through to the unchanged flow below (no regression).
	if s.secondaryAuthRequired(dnn) {
		pending := &pendingSecondaryAuth{
			SmContextRef: smContextRef,
			SUPI:         supi,
			DNN:          dnn,
			PDUSessionID: uint8(pduSessionID),
			PTI:          pti,
			Slice:        slice,
			GrantedType:  grantedType,
			IPv4:         ip,
			V6Prefix:     v6Prefix,
			V6IID:        v6IID,
			PCORequest:   pduReq,
			ULTEID:       ulTEID,
			SEID:         seid,
		}
		s.startSecondaryAuth(r.Context(), pending)

		span.SetAttributes(
			attribute.String("sm_context_ref", smContextRef),
			attribute.Bool("secondary_auth_pending", true),
		)
		span.SetStatus(codes.Ok, "")
		log.Info("Nsmf_PDUSession_CreateSMContext: secondary auth pending, deferring Accept",
			"smContextRef", smContextRef, "dnn", dnn, "supi", supi,
			"direction", "OUT", "spec_ref", "TS 23.502 §4.3.2.3",
		)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "/nsmf-pdusession/v1/sm-contexts/"+smContextRef)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"smContextRef": smContextRef,
		})
		return
	}

	// Fetch the subscribed default QoS from UDM over N10 first; it is reported
	// to the PCF as subsDefQos/subsSessAmbr, and used directly when the PCF is
	// unavailable. Ref: TS 23.502 §4.3.2.2.1 step 4 (SM subscription retrieval).
	subQoS := s.fetchSubscribedQoS(r.Context(), supi, dnn, slice)

	// Create SM Policy association with PCF — QoS parameters must be known
	// before encoding N1SM/N2SM. The PCF-authorized values take precedence over
	// the UDM subscription. Ref: TS 23.502 §4.3.2.2.1 step 6, TS 29.512 §5.2.2.2.
	// Pass the allocated UE IPv4 address (nil-safe: "" for IPv6-only sessions) so
	// the PCF can register a PCF binding with the BSF. Ref: TS 29.512 §5.6.2.3.
	ueIPv4Str := ""
	if ip != nil {
		ueIPv4Str = ip.String()
	}
	smPolicyID, policyQoS := s.createSMPolicy(r.Context(), supi, dnn, ueIPv4Str, slice, subQoS)

	// N1SM: PDU Session Establishment Accept body (AMF wraps in DL NAS Transport).
	// Carries the QoS rules (QFI=1 default flow), the QoS flow descriptions
	// with the authorized 5QI (TS 24.501 §9.11.4.12/§9.11.4.13), and the DNN's
	// DNS resolvers in the EPCO so the UE doesn't sit at "no internet" purely
	// for lack of a resolver (Config.Load defaults this per DNN when unset).
	n1SmResp, _ := nas.EncodeEstablishmentAcceptBody(nas.EstablishmentAcceptParams{
		Addr:    nas.PDUAddressInfo{SessionType: grantedType, IPv4: ip, IPv6IID: v6IID},
		SSCMode: nas.SSCMode1,
		DNN:     dnn,
		QFI:     1, // QFI=1 for the default flow
		FiveQI:  policyQoS.FiveQI,
		DLMbps:  policyQoS.AMBRDLMbps,
		ULMbps:  policyQoS.AMBRULMbps,
		DNSv4:   s.dnsServersFor(dnn),
		MTU:     nas.DefaultIPv4LinkMTU,
		SNSSAI:  []nas.SNSSAI{{SST: slice.SST, SD: nas.SDFromString(slice.SD)}},
		Request: pduReq,
	})
	n1SmRespB64 := base64.StdEncoding.EncodeToString(n1SmResp)

	// N2SM: Resource Setup Request Transfer — tells gNB the 5QI for the QoS flow.
	n2SmInfo, err := buildPDUSessionResourceSetupRequestTransfer(
		net.ParseIP(s.cfg.UPFN3Addr), ulTEID, 1 /* QFI */, int64(policyQoS.FiveQI),
		int64(policyQoS.AMBRULMbps)*1_000_000, int64(policyQoS.AMBRDLMbps)*1_000_000,
		ngapPDUSessionType(grantedType),
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

	var v6PrefixStr string
	if v6Prefix != nil {
		v6PrefixStr = v6Prefix.String()
	}

	// Store typed session
	sess := &Session{
		SUPI:           supi,
		PDUSessionID:   uint8(pduSessionID),
		DNN:            dnn,
		UEIP:           ip,
		ULTEID:         ulTEID,
		SEID:           seid,
		SliceID:        slice,
		SmPolicyID:     smPolicyID,
		FiveQI:         policyQoS.FiveQI,
		ARPPriority:    policyQoS.ARPPriority,
		AMBRULMbps:     policyQoS.AMBRULMbps,
		AMBRDLMbps:     policyQoS.AMBRDLMbps,
		AMBRULKbps:     policyQoS.AMBRULKbps,
		AMBRDLKbps:     policyQoS.AMBRDLKbps,
		QoSSource:      policyQoS.Source,
		State:          "ACTIVE",
		CreatedAt:      time.Now(),
		PDUSessionType: grantedType,
		UEIPv6Prefix:   v6PrefixStr,
	}
	s.sessionMu.Lock()
	s.sessions[smContextRef] = sess
	s.sessionMu.Unlock()
	s.persistSession(r.Context(), smContextRef, sess)
	metrics.PDUSessionTotal.WithLabelValues("SMF", dnn, "OK").Inc()
	metrics.PDUSessionsActive.WithLabelValues("SMF", dnn).Inc()

	if pduTypeNeedsIPv6(grantedType) {
		// The IPv6 UE-IP is installed in the PFCP PDR (UE IP Address IE, V6 flag)
		// and the UPF starts a per-session Router Advertisement advertiser for the
		// delegated /64 on the DNN's user plane (human sign-off 2026-07-22, same
		// PFCP-path exception precedent as UPF-001). Ref: TS 23.501 §5.8.2.2.
		log.Info("IPv6 user plane installed at UPF",
			"pdu_session_type", grantedType, "ipv6_prefix", v6PrefixStr,
			"spec_ref", "TS 23.501 §5.8.2.2.2")
	}

	// Establish the PFCP session with the UPF whenever the session carries any
	// UE address (IPv4, IPv6-only or IPv4v6) — the granted-type-aware UE IP
	// Address IE built in sendPFCPSessionEstablishment covers all three cases.
	if ip != nil || pduTypeNeedsIPv6(grantedType) {
		go s.sendPFCPSessionEstablishment(context.Background(), sess)
	}

	allocatedIP := "" // IPv4 address, or the delegated /64 for IPv6-only sessions
	switch {
	case ip != nil:
		allocatedIP = ip.String()
	case v6PrefixStr != "":
		allocatedIP = v6PrefixStr
	}

	span.SetAttributes(
		attribute.String("sm_context_ref", smContextRef),
		attribute.String("allocated_ip", allocatedIP),
		attribute.String("ipv6_prefix", v6PrefixStr),
		attribute.Int("pdu_session_type", int(grantedType)),
		attribute.Int("5qi", int(policyQoS.FiveQI)),
	)
	span.SetStatus(codes.Ok, "")
	log.Info("Nsmf_PDUSession_CreateSMContext responded",
		"smContextRef", smContextRef,
		"allocatedIP", allocatedIP,
		"ipv6Prefix", v6PrefixStr,
		"pduSessionType", grantedType,
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

// handleUpdateSMContext handles these cases:
//  1. N2SM response from gNB (PDU session resource setup): activates DL GTP-U forwarding in UPF.
//  2. AN release notification (upCnxState=DEACTIVATED): deactivates DL forwarding in UPF.
//  3. Xn path switch (n2SmInfoType=PATH_SWITCH_REQ): updates DL GTP-U to target gNB endpoint.
//  4. N2 handover (hoState PREPARING / COMPLETED, n2SmInfoType HANDOVER_REQ_ACK /
//     HANDOVER_RES_ALLOC_FAIL): PREPARING / REQ_ACK / RES_ALLOC_FAIL are SBI + in-memory only;
//     COMPLETED switches the UPF DL FAR synchronously (pfcp_ho.go) before answering.
//
// Ref: TS 29.502 §5.2.2.3.2 (UP activation), §5.2.2.3.3 (Xn handover), §5.2.2.3.4 (N2 handover),
// TS 23.502 §4.3.2.2.1 step 9, §4.2.6, §4.9.1.2.2, §4.9.1.3.2
func (s *Server) handleUpdateSMContext(w http.ResponseWriter, r *http.Request) {
	smContextRef := r.PathValue("smContextRef")

	spanCtx, span := tracing.Tracer("SMF", "procedures").Start(r.Context(), "Nsmf_PDUSession_UpdateSMContext")
	span.SetAttributes(attribute.String("sm_context_ref", smContextRef))
	defer span.End()
	if corrID := r.Header.Get("X-Correlation-Id"); corrID != "" {
		spanCtx = logging.WithCorrelationID(spanCtx, corrID)
	}
	r = r.WithContext(spanCtx)

	// hoLog carries no `procedure` key: the handover branches add their own
	// (XnHandover / N2Handover) so every line has exactly one.
	hoLog := s.logger.With("smContextRef", smContextRef,
		"correlation_id", r.Header.Get("X-Correlation-Id"))
	log := s.logger.With("procedure", "SmContextUpdate", "smContextRef", smContextRef)

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}

	// N2 handover branches keyed on hoState / n2SmInfoType. They are dispatched before
	// the "no N2SM info" fallback because PREPARING (without n2SmInfo) and COMPLETED
	// carry none. Only COMPLETED sends PFCP (synchronous DL switch).
	// Ref: TS 29.502 §5.2.2.3.4; TS 23.502 §4.9.1.3.2, §4.9.1.3.3
	n2SmInfoType, _ := body["n2SmInfoType"].(string)
	hoState, _ := body["hoState"].(string)
	switch {
	case hoState == hoStatePreparing:
		s.handleHandoverPreparing(w, hoLog, smContextRef, n2SmInfoType, body)
		return
	case hoState == hoStateCompleted:
		s.handleHandoverComplete(r.Context(), w, hoLog, smContextRef)
		return
	case n2SmInfoType == n2SmInfoTypeHandoverResAllocFail:
		s.handleHandoverResAllocFail(w, hoLog, smContextRef, body)
		return
	}

	// UP re-activation (Service Request): upCnxState=ACTIVATING — re-emit the
	// PDUSessionResourceSetupRequestTransfer (UL TEID + QoS) so the AMF can
	// carry N2SM info in InitialContextSetupRequest (TS 23.502 §4.2.3 step 6).
	// DL forwarding is re-activated when the AMF forwards the gNB's response
	// transfer back here (default N2SM-response branch below).
	// Ref: TS 29.502 §5.2.2.3.2.2, TS 23.502 §4.2.3.2 step 12
	if upCnxState, _ := body["upCnxState"].(string); upCnxState == "ACTIVATING" {
		s.sessionMu.Lock()
		sess := s.sessions[smContextRef]
		s.sessionMu.Unlock()
		if sess == nil {
			log.Warn("UP activation: session not found")
			problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found")
			return
		}
		if s.rejectIfReleasing(w, log, sess, "UP activation", false) {
			return
		}
		s.sessionMu.Lock()
		sess.HOTargetFailed, sess.HOReleaseOnDeactivate = false, false
		s.sessionMu.Unlock()

		n2SmInfo, err := buildPDUSessionResourceSetupRequestTransfer(
			net.ParseIP(s.cfg.UPFN3Addr), sess.ULTEID, 1 /* QFI */, int64(sess.FiveQI),
			int64(sess.AMBRULMbps)*1_000_000, int64(sess.AMBRDLMbps)*1_000_000,
			ngapPDUSessionType(sess.PDUSessionType),
		)
		if err != nil {
			log.Error("N2SM Transfer encoding failed for UP activation", "error", err)
			problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
			return
		}

		log.Info("UP re-activation — N2SM Setup Request Transfer rebuilt",
			"interface", "Nsmf",
			"direction", "OUT",
			"supi", sess.SUPI,
			"pdu_session_id", sess.PDUSessionID,
			"ulTEID", sess.ULTEID,
			"5qi", sess.FiveQI,
			"spec_ref", "TS 23.502 §4.2.3.2 step 12",
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"n2SmInfo":     base64.StdEncoding.EncodeToString(n2SmInfo),
			"n2SmInfoType": "PDU_RES_SETUP_REQ",
			"upCnxState":   "ACTIVATING",
		})
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

		// Target-failed PDU session (HANDOVER_RES_ALLOC_FAIL earlier): the AMF indicates the
		// executed handover with DEACTIVATED, which triggers the stored release-or-deactivate
		// decision (rule R1). Ref: TS 23.502 §4.3.7 step 1, §4.9.1.3.3.
		s.sessionMu.Lock()
		failed, release := sess.HOTargetFailed, sess.HOReleaseOnDeactivate
		sess.HOTargetFailed, sess.HOReleaseOnDeactivate = false, false
		releasing := sess.State == sessionStateReleasing
		s.sessionMu.Unlock()
		if failed && !releasing {
			action := targetFailedDeactivate
			if release {
				action = targetFailedRelease
			}
			hoLog.Info("target-failed PDU session: AMF indicated handover executed (DEACTIVATED)",
				"procedure", "N2Handover", "interface", "Nsmf", "direction", "IN",
				"up_cnx_state", "DEACTIVATED", "target_failed_action", action,
				"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "seid", sess.SEID,
				"result", "OK", "spec_ref", "TS 23.502 §4.3.7 step 1; §4.9.1.3.3")
			w.WriteHeader(http.StatusOK)
			dctx := context.WithoutCancel(r.Context())
			s.goHO(func() { s.runTargetFailedAction(dctx, hoLog, "N2Handover", sess, release) })
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
		if sess.State != sessionStateReleasing {
			sess.State = "IDLE"
		}
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

		// Consult PCF to authorize the requested QoS change before applying it
		// (SM Policy Association Update). On rejection no N4/N1/N2 change is made.
		// Ref: TS 29.512 §5.2.2.3, TS 23.502 §4.3.3.2 step 1b.
		granted, authorized := s.updateSMPolicy(r.Context(), sess, fiveQI, ambrUL, ambrDL)
		if !authorized {
			log.Info("NW-initiated QoS modification rejected by PCF",
				"smContextRef", smContextRef, "requested_5qi", fiveQI,
				"interface", "Nsmf", "direction", "OUT", "result", "REJECT",
				"spec_ref", "TS 29.512 §5.2.2.3")
			problem(w, http.StatusForbidden, "REQUESTED_QOS_NOT_AUTHORIZED",
				"PCF rejected the requested QoS change")
			return
		}
		fiveQI = granted.FiveQI
		ambrDL = granted.AMBRDLMbps
		ambrUL = granted.AMBRULMbps

		// Update session QoS state.
		s.sessionMu.Lock()
		sess.FiveQI = fiveQI
		sess.AMBRDLMbps = ambrDL
		sess.AMBRULMbps = ambrUL
		sess.AMBRDLKbps = granted.AMBRDLKbps
		sess.AMBRULKbps = granted.AMBRULKbps
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

	// PDU SESSION AUTHENTICATION COMPLETE (0xC6): the UE's EAP-Response relayed
	// by the AMF during secondary authentication. Dispatched before the
	// general n1SmMsg branches below since it answers via the pushed-message
	// path (N1N2MessageTransfer), not a same-call response.
	// Ref: TS 23.502 §4.3.2.3, TS 24.501 §8.3.6.
	if n1SmMsgB64, _ := body["n1SmMsg"].(string); n1SmMsgB64 != "" {
		if n1SmMsgBytes, err := base64.StdEncoding.DecodeString(n1SmMsgB64); err == nil &&
			len(n1SmMsgBytes) >= 4 && nas.MessageType(n1SmMsgBytes[3]) == nas.MsgTypePDUSessionAuthenticationComplete {
			s.handleSecondaryAuthComplete(w, r, smContextRef, n1SmMsgBytes)
			return
		}
	}

	// PDU Session Modification: n1SmMsg present with 5GSM ModificationRequest (0xC9).
	// The SMF accepts the modification as-is and returns a Modification Command.
	// Ref: TS 23.502 §4.3.3.1, TS 29.502 §5.2.2.3.2
	if n1SmMsgB64, _ := body["n1SmMsg"].(string); n1SmMsgB64 != "" {
		n1SmMsgBytes, err := base64.StdEncoding.DecodeString(n1SmMsgB64)
		if err == nil && len(n1SmMsgBytes) >= 4 && nas.MessageType(n1SmMsgBytes[3]) == nas.MsgTypePDUSessionModificationRequest {
			pduSessionID := n1SmMsgBytes[1]
			pti := n1SmMsgBytes[2]

			// Consult PCF to authorize the UE-requested modification (SM Policy
			// Association Update). With no per-subscriber override the PCF echoes
			// the current QoS (no change → byte-identical empty command body); an
			// override is applied as a real QoS modification (N4 QER + QoS IEs).
			// Ref: TS 29.512 §5.2.2.3, TS 23.502 §4.3.3.1 step 1b.
			cmdBody := nas.EncodePDUSessionModificationCommandBody()
			s.sessionMu.Lock()
			sess := s.sessions[smContextRef]
			s.sessionMu.Unlock()
			if sess != nil {
				curFiveQI, curUL, curDL := sess.FiveQI, sess.AMBRULMbps, sess.AMBRDLMbps
				granted, authorized := s.updateSMPolicy(r.Context(), sess, curFiveQI, curUL, curDL)
				if authorized && (granted.FiveQI != curFiveQI || granted.AMBRULMbps != curUL || granted.AMBRDLMbps != curDL) {
					s.sessionMu.Lock()
					sess.FiveQI = granted.FiveQI
					sess.AMBRULMbps = granted.AMBRULMbps
					sess.AMBRDLMbps = granted.AMBRDLMbps
					sess.AMBRULKbps = granted.AMBRULKbps
					sess.AMBRDLKbps = granted.AMBRDLKbps
					sess.QoSSource = granted.Source
					s.sessionMu.Unlock()
					if upfAck := s.sendPFCPQoSModification(r.Context(), sess); !upfAck {
						log.Warn("PFCP QER modification not acknowledged by UPF (UE-requested)",
							"seid", sess.SEID, "spec_ref", "TS 29.244 §7.5.4")
					}
					cmdBody = nas.EncodePDUSessionModificationCommandBodyWithQoS(
						1 /* QFI=1 */, granted.FiveQI, granted.AMBRDLMbps, granted.AMBRULMbps)
					log.Info("UE-requested modification: PCF applied policy decision",
						"5qi", granted.FiveQI, "qos_source", granted.Source,
						"spec_ref", "TS 29.512 §5.2.2.3")
				}
			}
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

	// N2 HO steps 10-12: HANDOVER_REQ_ACK -> HANDOVER_CMD, SBI response only (no PFCP, indirect forwarding out of scope).
	// Ref: TS 23.502 §4.9.1.3.2 steps 10-12, TS 29.502 §5.2.2.3.4
	if n2SmInfoType == n2SmInfoTypeHandoverReqAck {
		s.handleHandoverReqAck(w, hoLog, smContextRef, n2SmInfoBytes)
		return
	}
	// Xn path switch failed-to-setup PSI: 204, then detached deactivate/release (rule R1).
	// Ref: TS 23.502 §4.9.1.2.2 step 2 (PathSwitchRequestSetupFailedTransfer relayed by the AMF)
	if n2SmInfoType == n2SmInfoTypePathSwitchSetupFail {
		s.handlePathSwitchSetupFail(r.Context(), w, hoLog, smContextRef, n2SmInfoBytes)
		return
	}

	// Xn path switch: synchronous DL switch, answered after the PFCP response.
	// Ref: TS 23.502 §4.9.1.2.2 steps 2-6, TS 29.502 §5.2.2.3.3.
	if n2SmInfoType == "PATH_SWITCH_REQ" {
		s.handlePathSwitchReq(r.Context(), w, hoLog, smContextRef, n2SmInfoBytes)
		return
	}

	gnbIP, dlTEID, err := extractGNBTunnelInfo(n2SmInfoBytes)
	if err != nil {
		log.Error("extractGNBTunnelInfo failed", "error", err)
		problem(w, http.StatusUnprocessableEntity, "SYSTEM_FAILURE", err.Error())
		return
	}
	log.Info("gNB DL tunnel info", "gnbIP", gnbIP, "dlTEID", dlTEID)

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()

	if sess == nil {
		log.Warn("session not found")
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found")
		return
	}

	if s.rejectIfReleasing(w, log, sess, "N2 SM info update", false) {
		return
	}
	if s.markSessionActive(sess) {
		go s.sendPFCPSessionModification(context.Background(), sess, dlTEID, gnbIP)
	}

	w.WriteHeader(http.StatusOK)
}

// pathSwitchAckEncodeFailure answers a PATH_SWITCH_REQ whose
// PathSwitchRequestAcknowledgeTransfer could not be encoded: SmContextUpdateError
// (500 SYSTEM_FAILURE) carrying a PathSwitchRequestUnsuccessfulTransfer with radioNetwork
// cause ho-failure-in-target-5GC-ngran-node-or-target-system (7), n2SmInfoType
// PATH_SWITCH_REQ_FAIL, so the AMF can send PATH SWITCH REQUEST FAILURE.
// Ref: TS 29.502 §5.2.2.3.3, §6.1.6.2; TS 23.502 §4.9.1.2.2 step 6; TS 38.413 §9.3.1.2.
func pathSwitchAckEncodeFailure(w http.ResponseWriter, encErr error) {
	smContextUpdateError(w, http.StatusInternalServerError, "SYSTEM_FAILURE", encErr.Error(),
		pathSwitchUnsuccessfulTransfer(ngapType.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem),
		n2SmInfoTypePathSwitchReqFail)
}

// n2SmInfoType values exchanged with the AMF during handover.
// Ref: TS 29.502 §6.1.6.3 (N2SmInfoType), docs/procedures/XnHandover.md §4.6.
const (
	n2SmInfoTypeHandoverReqAck      = "HANDOVER_REQ_ACK"
	n2SmInfoTypeHandoverCmd         = "HANDOVER_CMD"
	n2SmInfoTypeHandoverRequired    = "HANDOVER_REQUIRED"
	n2SmInfoTypeHandoverPrepFail    = "HANDOVER_PREP_FAIL"
	n2SmInfoTypePduResSetupReq      = "PDU_RES_SETUP_REQ"
	n2SmInfoTypePathSwitchReqAck    = "PATH_SWITCH_REQ_ACK"
	n2SmInfoTypePathSwitchReqFail   = "PATH_SWITCH_REQ_FAIL"
	n2SmInfoTypePathSwitchSetupFail = "PATH_SWITCH_SETUP_FAIL"
	// n2SmInfoTypeHandoverResAllocFail carries the target's
	// HandoverResourceAllocationUnsuccessfulTransfer (TS 23.502 §4.9.1.3.2 step 10).
	n2SmInfoTypeHandoverResAllocFail = "HANDOVER_RES_ALLOC_FAIL"
)

// HoState values (SmContextUpdateData / SmContextUpdatedData.hoState).
// Ref: TS 29.502 §6.1.6.3 (HoState), §5.2.2.3.4.
const (
	hoStatePreparing = "PREPARING"
	hoStatePrepared  = "PREPARED"
	hoStateCompleted = "COMPLETED"
	// hoStateNone: no handover in progress / handover preparation failed or was cancelled
	// (the SMF-side value after HANDOVER_RES_ALLOC_FAIL, TS 29.502 §5.2.2.3.4).
	hoStateNone = "NONE"
)

// causeSessionReleasing is the problem cause returned for an UpdateSMContext that
// would (re)activate the user plane of a session being released after a UPF
// restart/failure. DEVIATION: TS 29.502 §5.2.2.3 defines no dedicated cause for
// an SM context in release; 409 Conflict with this cause is used (pattern of the
// AMBIGUOUS_SESSION 409 in this NF) so the AMF rejects the update and the
// session release proceeds. Ref: TS 23.527 §4.3, TS 23.502 §4.3.4.2.
const causeSessionReleasing = "PDU_SESSION_RELEASING"

// markSessionActive sets State=ACTIVE unless the session turned RELEASING after
// the rejectIfReleasing check (check-and-set in one critical section, so a
// concurrent recovery marking is never overwritten). It returns false when the
// session is RELEASING, in which case no N4 Session Modification must follow.
// Ref: TS 23.527 §4.3.2.
func (s *Server) markSessionActive(sess *Session) bool {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if sess.State == sessionStateReleasing {
		return false
	}
	sess.State = "ACTIVE"
	return true
}

// rejectIfReleasing answers 409 and returns true when sess is RELEASING; no N4
// signalling and no N2 SM info are produced. For Xn path switch the error is an
// SmContextUpdateError carrying PATH_SWITCH_REQ_FAIL (TS 29.502 §5.2.2.3.3).
func (s *Server) rejectIfReleasing(w http.ResponseWriter, log *slog.Logger, sess *Session, op string, pathSwitch bool) bool {
	s.sessionMu.Lock()
	releasing := sess.State == sessionStateReleasing
	s.sessionMu.Unlock()
	if !releasing {
		return false
	}
	log.Warn("UpdateSMContext rejected — session RELEASING after UPF restart/failure",
		"interface", "Nsmf", "direction", "OUT", "result", "REJECT", "cause", causeSessionReleasing,
		"operation", op, "supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID,
		"spec_ref", "TS 29.502 §5.2.2.3; TS 23.527 §4.3")
	detail := "PDU session is being released after a UPF restart/failure"
	if pathSwitch {
		smContextUpdateError(w, http.StatusConflict, causeSessionReleasing, detail,
			pathSwitchUnsuccessfulTransfer(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnspecified),
			n2SmInfoTypePathSwitchReqFail)
		return true
	}
	problem(w, http.StatusConflict, causeSessionReleasing, detail)
	return true
}

// smContextUpdateError writes an SmContextUpdateError (TS 29.502 §6.1.6.2): the nested
// ProblemDetails in "error" plus, when n2SmInfo is non-empty, the N2 SM transfer and its
// n2SmInfoType the AMF can relay (PATH_SWITCH_REQ_FAIL, HANDOVER_PREP_FAIL, ...).
// Content-Type is application/json (the body is not a bare ProblemDetails).
// Ref: TS 29.502 §5.2.2.3.3 / §5.2.2.3.4, §6.1.6.2; TS 23.502 §4.9.1.2.2 step 6, §4.9.1.3.2 step 12.
func smContextUpdateError(w http.ResponseWriter, status int, cause, detail string, n2SmInfo []byte, n2SmInfoType string) {
	out := map[string]interface{}{
		"error": map[string]interface{}{"status": status, "cause": cause, "detail": detail},
	}
	if len(n2SmInfo) > 0 {
		out["n2SmInfo"] = base64.StdEncoding.EncodeToString(n2SmInfo)
		out["n2SmInfoType"] = n2SmInfoType
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(out)
}

// ngapCause builds an NGAP Cause CHOICE for the radioNetwork / protocol groups.
// Ref: TS 38.413 §9.3.1.2.
func ngapCause(present int, value aper.Enumerated) ngapType.Cause {
	c := ngapType.Cause{Present: present}
	switch present {
	case ngapType.CausePresentRadioNetwork:
		c.RadioNetwork = &ngapType.CauseRadioNetwork{Value: value}
	case ngapType.CausePresentProtocol:
		c.Protocol = &ngapType.CauseProtocol{Value: value}
	}
	return c
}

// pathSwitchUnsuccessfulTransfer encodes PathSwitchRequestUnsuccessfulTransfer{Cause}
// (nil on encode failure). Ref: TS 38.413 §9.3.4 (Path Switch Request Unsuccessful Transfer).
func pathSwitchUnsuccessfulTransfer(causePresent int, causeValue aper.Enumerated) []byte {
	b, err := aper.MarshalWithParams(ngapType.PathSwitchRequestUnsuccessfulTransfer{
		Cause: ngapCause(causePresent, causeValue)}, "valueExt")
	if err != nil {
		return nil
	}
	return b
}

// handoverPrepFailTransfer encodes HandoverPreparationUnsuccessfulTransfer{Cause}
// (nil on encode failure). Ref: TS 38.413 §9.3.4 (Handover Preparation Unsuccessful Transfer).
func handoverPrepFailTransfer(causePresent int, causeValue aper.Enumerated) []byte {
	b, err := aper.MarshalWithParams(ngapType.HandoverPreparationUnsuccessfulTransfer{
		Cause: ngapCause(causePresent, causeValue)}, "valueExt")
	if err != nil {
		return nil
	}
	return b
}

// handoverPrepFailTransferCause encodes HandoverPreparationUnsuccessfulTransfer{Cause} with an
// already-built NGAP Cause (relayed unchanged, any group). nil on encode failure.
// Ref: TS 38.413 §9.3.4 (Handover Preparation Unsuccessful Transfer).
func handoverPrepFailTransferCause(c ngapType.Cause) []byte {
	b, err := aper.MarshalWithParams(ngapType.HandoverPreparationUnsuccessfulTransfer{Cause: c}, "valueExt")
	if err != nil {
		return nil
	}
	return b
}

// handleHandoverReqAck serves n2SmInfoType HANDOVER_REQ_ACK: decodes the
// HandoverRequestAcknowledgeTransfer, stores the target DL NG-U tunnel on the
// session, sets HOState PREPARED and answers with a HandoverCommandTransfer. When the
// source signalled a direct forwarding path and the target returned a DL forwarding
// tunnel, the command carries that tunnel and the forwarded QoS flows (direct data
// forwarding); otherwise it is empty (indirect forwarding would need UPF forwarding
// tunnels = PFCP, not done). No PFCP is sent and the session State is unchanged (the DL
// switch happens at HANDOVER NOTIFY). Errors answer SmContextUpdateError with a
// HANDOVER_PREP_FAIL transfer.
// Ref: TS 23.502 §4.9.1.3.2 steps 10-12; TS 29.502 §5.2.2.3.4; TS 38.413 §9.3.4.10, §9.3.4.11.
func (s *Server) handleHandoverReqAck(w http.ResponseWriter, log *slog.Logger, smContextRef string, n2SmInfo []byte) {
	log = log.With("procedure", "N2Handover", "interface", "Nsmf",
		"n2_sm_info_type", n2SmInfoTypeHandoverReqAck)

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()
	if sess == nil {
		log.Warn("N2 HO: session not found", "direction", "IN", "result", "REJECT", "cause", "CONTEXT_NOT_FOUND",
			"spec_ref", "TS 29.502 §5.2.2.3.4; TS 23.502 §4.9.1.3.2 step 10")
		smContextUpdateError(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found",
			handoverPrepFailTransfer(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownPDUSessionID),
			n2SmInfoTypeHandoverPrepFail)
		return
	}

	ack, gnbIP, dlTEID, err := decodeHandoverAck(n2SmInfo)
	if err != nil {
		log.Error("N2 HO: decode HandoverRequestAcknowledgeTransfer failed", "direction", "IN",
			"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "result", "REJECT", "error", err,
			"spec_ref", "TS 23.502 §4.9.1.3.2 step 10")
		smContextUpdateError(w, http.StatusUnprocessableEntity, "SYSTEM_FAILURE", err.Error(),
			handoverPrepFailTransfer(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError),
			n2SmInfoTypeHandoverPrepFail)
		return
	}

	s.sessionMu.Lock()
	direct := sess.HODirectForwarding
	s.sessionMu.Unlock()

	cmdTransfer, forwarding, fwdReason := buildHandoverCommandTransfer(direct, ack)
	cmd, err := aper.MarshalWithParams(cmdTransfer, "valueExt")
	if err != nil {
		log.Error("N2 HO: encode HandoverCommandTransfer failed", "direction", "OUT", "result", "FAILURE",
			"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "error", err,
			"spec_ref", "TS 23.502 §4.9.1.3.2 step 12")
		smContextUpdateError(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error(),
			handoverPrepFailTransfer(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem),
			n2SmInfoTypeHandoverPrepFail)
		return
	}

	s.sessionMu.Lock()
	sess.HOTargetGNBIP = gnbIP
	sess.HOTargetDLTEID = dlTEID
	sess.HOState = hoStatePrepared
	s.sessionMu.Unlock()

	log.Info("N2 HO: target DL tunnel stored, HandoverCommandTransfer returned (no PFCP)",
		"direction", "OUT", "supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID,
		"gnbIP", gnbIP, "dlTEID", dlTEID, "ho_state", hoStatePrepared, "data_forwarding", forwarding,
		"data_forwarding_reason", fwdReason,
		"result", "OK", "spec_ref", "TS 23.502 §4.9.1.3.2 step 12")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"hoState":      hoStatePrepared,
		"n2SmInfo":     base64.StdEncoding.EncodeToString(cmd),
		"n2SmInfoType": n2SmInfoTypeHandoverCmd,
	})
}

// Values of the data_forwarding log field.
const (
	dataForwardingDirect      = "direct"
	dataForwardingNotPossible = "not-possible"
	// dataForwardingNone: no forwarding tunnel returned (indirect forwarding would need PFCP).
	dataForwardingNone = "none"
)

// Values of the data_forwarding_reason log field (set when data_forwarding is "none").
const (
	// forwardingReasonNoDirectPath: no direct forwarding path (or no PREPARING); indirect
	// forwarding would need UPF forwarding tunnels via PFCP, not implemented.
	forwardingReasonNoDirectPath = "no-direct-forwarding-path"
	// forwardingReasonNoTunnel: direct path, but the ack transfer has no DLForwardingUPTNLInformation.
	forwardingReasonNoTunnel = "target-provided-no-forwarding-tunnel"
	// forwardingReasonNoFlow: no QoS flow with DataForwardingAccepted.
	forwardingReasonNoFlow = "no-flow-accepted-for-forwarding"
)

// buildHandoverCommandTransfer builds the HandoverCommandTransfer for HANDOVER_CMD. With a
// direct forwarding path (source signalled DirectForwardingPathAvailability) and a target
// DLForwardingUPTNLInformation it carries that tunnel and the QoS flows whose
// DataForwardingAccepted is present (omitted if none). It returns the data_forwarding value and, for "none", the reason.
// Ref: TS 38.413 §9.3.4.10 (Handover Command Transfer), §9.3.4.11; TS 23.502 §4.9.1.3.2 step 12.
func buildHandoverCommandTransfer(direct bool, ack *ngapType.HandoverRequestAcknowledgeTransfer) (ngapType.HandoverCommandTransfer, string, string) {
	var cmd ngapType.HandoverCommandTransfer
	if !direct {
		return cmd, dataForwardingNone, forwardingReasonNoDirectPath
	}
	if ack.DLForwardingUPTNLInformation == nil {
		return cmd, dataForwardingNone, forwardingReasonNoTunnel
	}
	var list []ngapType.QosFlowToBeForwardedItem
	for _, f := range ack.QosFlowSetupResponseList.List {
		if f.DataForwardingAccepted != nil {
			list = append(list, ngapType.QosFlowToBeForwardedItem{QosFlowIdentifier: f.QosFlowIdentifier})
		}
	}
	if len(list) == 0 {
		return cmd, dataForwardingNone, forwardingReasonNoFlow
	}
	cmd.DLForwardingUPTNLInformation = ack.DLForwardingUPTNLInformation
	cmd.QosFlowToBeForwardedList = &ngapType.QosFlowToBeForwardedList{List: list}
	return cmd, dataForwardingDirect, ""
}

// ngapCauseValue returns the numeric value of the selected NGAP Cause choice.
func ngapCauseValue(c ngapType.Cause) int64 {
	switch c.Present {
	case ngapType.CausePresentRadioNetwork:
		if c.RadioNetwork != nil {
			return int64(c.RadioNetwork.Value)
		}
	case ngapType.CausePresentTransport:
		if c.Transport != nil {
			return int64(c.Transport.Value)
		}
	case ngapType.CausePresentNas:
		if c.Nas != nil {
			return int64(c.Nas.Value)
		}
	case ngapType.CausePresentProtocol:
		if c.Protocol != nil {
			return int64(c.Protocol.Value)
		}
	case ngapType.CausePresentMisc:
		if c.Misc != nil {
			return int64(c.Misc.Value)
		}
	}
	return -1
}

// extractHandoverAckTunnelInfo decodes the APER-encoded HandoverRequestAcknowledgeTransfer
// and returns the target gNB DL NG-U GTP tunnel (IP, TEID).
// Ref: TS 38.413 §9.3.4.11
func extractHandoverAckTunnelInfo(n2SmInfo []byte) (net.IP, uint32, error) {
	_, ip, teid, err := decodeHandoverAck(n2SmInfo)
	return ip, teid, err
}

// decodeHandoverAck decodes the HandoverRequestAcknowledgeTransfer and returns it with the
// target gNB DL NG-U GTP tunnel (IP, TEID). Ref: TS 38.413 §9.3.4.11
func decodeHandoverAck(n2SmInfo []byte) (*ngapType.HandoverRequestAcknowledgeTransfer, net.IP, uint32, error) {
	var transfer ngapType.HandoverRequestAcknowledgeTransfer
	if err := aper.UnmarshalWithParams(n2SmInfo, &transfer, "valueExt"); err != nil {
		return nil, nil, 0, fmt.Errorf("smf: decode HandoverRequestAcknowledgeTransfer: %w", err)
	}
	gtpTunnel := transfer.DLNGUUPTNLInformation.GTPTunnel
	if gtpTunnel == nil {
		return nil, nil, 0, fmt.Errorf("smf: GTPTunnel is nil in HandoverRequestAcknowledgeTransfer")
	}
	teidBytes := []byte(gtpTunnel.GTPTEID.Value)
	if len(teidBytes) != 4 {
		return nil, nil, 0, fmt.Errorf("smf: unexpected TEID length %d in handover ack", len(teidBytes))
	}
	ipBytes := gtpTunnel.TransportLayerAddress.Value.Bytes
	if len(ipBytes) < 4 {
		return nil, nil, 0, fmt.Errorf("smf: unexpected IP length %d in handover ack", len(ipBytes))
	}
	gnbIP := make(net.IP, 4)
	copy(gnbIP, ipBytes[:4])
	return &transfer, gnbIP, binary.BigEndian.Uint32(teidBytes), nil
}

func (s *Server) handleDeleteSMContext(w http.ResponseWriter, r *http.Request) {
	smContextRef := r.PathValue("smContextRef")
	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With("procedure", "SmContextDelete", "smContextRef", smContextRef, "correlation_id", corrID)

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()

	if sess != nil {
		// Idempotent: a concurrent local release (PFCP node recovery fallback)
		// may have removed the session already; releaseSessionLocal then no-ops.
		if s.releaseSessionLocal(r.Context(), smContextRef, sess, true) {
			log.Info("Nsmf_PDUSession_DeleteSMContext — releasing session",
				"supi", sess.SUPI, "ueIP", sess.UEIP, "seid", sess.SEID,
				"spec_ref", "TS 29.502 §5.2.2.4",
			)
		}
	} else {
		s.deleteSession(r.Context(), smContextRef)
		log.Warn("Nsmf_PDUSession_DeleteSMContext — session not found")
	}

	w.WriteHeader(http.StatusNoContent)
}

// releaseSessionLocal frees every SMF-side resource of a PDU session: UE IPv4
// address and IPv6 prefix, the session table and store entries, the active-session
// gauge and the SM policy association. When sendN4 is true and the session is not
// N4Stale (UPF restarted, its session table is empty) a best-effort PFCP Session
// Deletion is sent. It is shared by the Nsmf release handler and the PFCP
// node-recovery local-release fallback, and is idempotent: it returns false and
// does nothing when ref no longer maps to sess (never double-frees an address).
// Ref: TS 29.502 §5.2.2.4, TS 23.502 §4.3.4.2, TS 29.244 §7.5.6.
func (s *Server) releaseSessionLocal(ctx context.Context, ref string, sess *Session, sendN4 bool) bool {
	s.sessionMu.Lock()
	if s.sessions[ref] != sess {
		s.sessionMu.Unlock()
		return false
	}
	pool := s.ipPools[sess.DNN]
	if pool == nil {
		pool = s.ipPools["internet"]
	}
	if pool != nil && sess.UEIP != nil {
		pool.Release(sess.UEIP)
	}
	if v6pool := s.ipv6Pools[sess.DNN]; v6pool != nil && sess.UEIPv6Prefix != "" {
		if _, prefix, perr := net.ParseCIDR(sess.UEIPv6Prefix); perr == nil {
			v6pool.Release(prefix)
		}
	}
	delete(s.sessions, ref)
	n4Stale := sess.N4Stale
	s.sessionMu.Unlock()
	s.deleteSession(ctx, ref)

	metrics.PDUSessionsActive.WithLabelValues("SMF", sess.DNN).Dec()
	// Delete SM Policy association with PCF (TS 29.512 §5.2.2.4; TS 23.502 §4.3.4.2 step 3b)
	s.deleteSMPolicy(ctx, sess.SmPolicyID)
	if sendN4 && !n4Stale {
		go s.sendPFCPSessionDeletion(context.Background(), sess)
	}
	return true
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

	seq := s.nextPFCPSeq()
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
	if s.skipN4ForReleasing(sess, "SessionDeactivation") {
		return
	}
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

	seq := s.nextPFCPSeq()
	// Update the DL FAR: remove outer header creation (DROP action = no forwarding).
	// ApplyAction 0x01 = DROP per TS 29.244 Table 7.5.2.3-1.
	req := pfcpmsg.NewSessionModificationRequest(
		0, 0, sess.SEID, seq, 0,
		buildDLDropFAR(),
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
// ueIPv4 is the allocated UE IPv4 address (e.g. "10.60.0.1"). When non-empty it is
// sent to the PCF as SmPolicyContextData.ipv4Address (TS 29.512 §5.6.2.3) so the PCF
// can register a PCF binding with the BSF (TS 29.521 §5.2.2.2). Pass "" for IPv6-only
// sessions or when the address is not yet known; the field is omitted from the body.
//
// The subscribed default QoS fetched from UDM (subQoS, may be nil) is reported
// to the PCF as subsDefQos/subsSessAmbr (TS 29.512 §5.6.2.3 SmPolicyContextData);
// the PCF-authorized decision takes precedence over the subscription. When the
// PCF is unreachable, the UDM subscription applies; failing that, operator
// defaults (non-fatal; session proceeds).
// Ref: TS 29.512 §5.2.2.2 (Npcf_SMPolicyControl_Create), §5.6.2.3 (SmPolicyContextData)
func (s *Server) createSMPolicy(ctx context.Context, supi, dnn, ueIPv4 string, slice SliceID, subQoS *subscribedQoS) (string, smPolicyQoS) {
	fallback := smPolicyQoS{FiveQI: 9, ARPPriority: 8, AMBRULMbps: 100, AMBRDLMbps: 100, AMBRULKbps: 100_000, AMBRDLKbps: 100_000, Source: QoSSourceOperatorDefault}
	if subQoS != nil {
		fallback = smPolicyQoS{
			FiveQI:      uint8(subQoS.FiveQI),
			ARPPriority: subQoS.ARPPriority,
			AMBRULMbps:  subQoS.AMBRULMbps,
			AMBRDLMbps:  subQoS.AMBRDLMbps,
			AMBRULKbps:  kbpsOrMbps(subQoS.AMBRULKbps, subQoS.AMBRULMbps),
			AMBRDLKbps:  kbpsOrMbps(subQoS.AMBRDLKbps, subQoS.AMBRDLMbps),
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
	// Include the UE IPv4 address so the PCF can register a PCF binding with the BSF.
	// Field name: SmPolicyContextData.ipv4Address (TS 29.512 §5.6.2.3).
	// Omitted when empty to preserve byte-identical behaviour for IPv6-only sessions.
	if ueIPv4 != "" {
		reqBody["ipv4Address"] = ueIPv4
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
		AMBRULKbps:  fallback.AMBRULKbps,
		AMBRDLKbps:  fallback.AMBRDLKbps,
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
							qos.AMBRULKbps, qos.AMBRULMbps = parseAMBR(ul, fallback.AMBRULKbps, fallback.AMBRULMbps)
						}
						if dl, ok := ambr["downlink"].(string); ok {
							qos.AMBRDLKbps, qos.AMBRDLMbps = parseAMBR(dl, fallback.AMBRDLKbps, fallback.AMBRDLMbps)
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

// updateSMPolicy consults PCF to authorize a QoS modification on an existing SM
// Policy Association (TS 29.512 §5.2.2.3). reqFiveQI / reqAMBR*Mbps are the
// requested values. Returns the granted QoS and whether the PCF authorized the
// change (false ⇒ the SMF must not apply it).
//
// Fail-open: when the PCF peer is not configured, the session has no SmPolicyId,
// or the PCF is unreachable, it returns the requested values with authorized=true
// — consistent with createSMPolicy's establishment-time fallback (no regression
// when the PCF is absent). Ref: TS 29.512 §5.2.2.3 (Npcf_SMPolicyControl_Update).
func (s *Server) updateSMPolicy(ctx context.Context, sess *Session, reqFiveQI uint8, reqAMBRULMbps, reqAMBRDLMbps int) (smPolicyQoS, bool) {
	requested := smPolicyQoS{
		FiveQI:      reqFiveQI,
		ARPPriority: sess.ARPPriority,
		AMBRULMbps:  reqAMBRULMbps,
		AMBRDLMbps:  reqAMBRDLMbps,
		AMBRULKbps:  kbpsOrMbps(sess.AMBRULKbps, reqAMBRULMbps),
		AMBRDLKbps:  kbpsOrMbps(sess.AMBRDLKbps, reqAMBRDLMbps),
		Source:      QoSSourceNWModification,
	}
	if s.cfg.Peers.PCF == "" || sess.SmPolicyID == "" {
		return requested, true // fail-open: nothing to consult
	}

	reqBody := map[string]interface{}{
		"repPolicyCtrlReqTriggers": []string{"RES_MO_RE"},
		"reqQos": map[string]interface{}{
			"5qi": int(reqFiveQI),
			"ambr": map[string]string{
				"uplink":   fmt.Sprintf("%d Mbps", reqAMBRULMbps),
				"downlink": fmt.Sprintf("%d Mbps", reqAMBRDLMbps),
			},
		},
		"supi": sess.SUPI,
		"dnn":  sess.DNN,
	}
	body, _ := json.Marshal(reqBody)
	pcfURL := "https://" + s.cfg.Peers.PCF + "/npcf-smpolicycontrol/v1/sm-policies/" + sess.SmPolicyID + "/update"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pcfURL, bytes.NewReader(body))
	if err != nil {
		s.logger.Warn("PCF: update SM policy request build failed — failing open", "error", err)
		return requested, true
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Warn("PCF: update SM policy call failed — failing open", "error", err,
			"spec_ref", "TS 29.512 §5.2.2.3")
		return requested, true
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		s.logger.Info("PCF: SM Policy update rejected",
			"smPolicyId", sess.SmPolicyID, "requested_5qi", reqFiveQI,
			"result", "REJECT", "spec_ref", "TS 29.512 §5.2.2.3")
		return requested, false
	}
	if resp.StatusCode != http.StatusOK {
		s.logger.Warn("PCF: unexpected status on SM policy update — failing open",
			"status", resp.StatusCode)
		return requested, true
	}

	granted := requested
	var respBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err == nil {
		if src, ok := respBody["x5gcQosSource"].(string); ok && src != "" {
			granted.Source = src
		}
		if qosDecs, ok := respBody["qosDecs"].(map[string]interface{}); ok {
			for _, v := range qosDecs {
				if dec, ok := v.(map[string]interface{}); ok {
					if fiveQI, ok := dec["5qi"].(float64); ok && fiveQI > 0 {
						granted.FiveQI = uint8(fiveQI)
					}
					if arp, ok := dec["arp"].(map[string]interface{}); ok {
						if pl, ok := arp["priorityLevel"].(float64); ok && pl > 0 {
							granted.ARPPriority = int(pl)
						}
					}
					break
				}
			}
		}
		if sessRules, ok := respBody["sessRules"].(map[string]interface{}); ok {
			for _, v := range sessRules {
				if rule, ok := v.(map[string]interface{}); ok {
					if ambr, ok := rule["sessAmbr"].(map[string]interface{}); ok {
						if ul, ok := ambr["uplink"].(string); ok {
							granted.AMBRULKbps, granted.AMBRULMbps = parseAMBR(ul, requested.AMBRULKbps, reqAMBRULMbps)
						}
						if dl, ok := ambr["downlink"].(string); ok {
							granted.AMBRDLKbps, granted.AMBRDLMbps = parseAMBR(dl, requested.AMBRDLKbps, reqAMBRDLMbps)
						}
					}
					break
				}
			}
		}
	}
	s.logger.Info("PCF: SM Policy update authorised",
		"smPolicyId", sess.SmPolicyID,
		"5qi", granted.FiveQI, "ambr_ul_mbps", granted.AMBRULMbps, "ambr_dl_mbps", granted.AMBRDLMbps,
		"qos_source", granted.Source, "spec_ref", "TS 29.512 §5.2.2.3")
	return granted, true
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
// Ref: TS 38.413 §9.3.4.1 - PDU Session Resource Setup Request Transfer
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
// Ref: TS 38.413 §9.3.4.1 — PDU Session Resource Setup Request Transfer
// ngapPDUSessionType maps a 5GSM PDU session type value (TS 24.501 §9.11.4.11)
// to the NGAP PDUSessionType enumeration (TS 38.413 §9.3.1.51).
func ngapPDUSessionType(t uint8) aper.Enumerated {
	switch t {
	case nas.PDUSessionTypeIPv6:
		return ngapType.PDUSessionTypePresentIpv6
	case nas.PDUSessionTypeIPv4v6:
		return ngapType.PDUSessionTypePresentIpv4v6
	default:
		return ngapType.PDUSessionTypePresentIpv4
	}
}

func buildPDUSessionResourceSetupRequestTransfer(upfIP net.IP, dlTEID uint32, qfi uint8, fiveQI, ambrULBps, ambrDLBps int64, pduType aper.Enumerated) ([]byte, error) {
	return buildPDUSessionResourceSetupRequestTransferOpts(upfIP, dlTEID, qfi, fiveQI, ambrULBps, ambrDLBps, pduType, false)
}

// buildPDUSessionResourceSetupRequestTransferOpts is the variant used by the N2 handover
// PREPARING answer: with dataFwdNotPossible it adds the optional IE DataForwardingNotPossible
// (id 127, criticality reject) between ULNGUUPTNLInformation and PDUSessionType, which is the
// ASN.1 IE-set order (130, 139, [AdditionalUL..], 127, 134, ..., 136). With false the output is
// byte-identical to buildPDUSessionResourceSetupRequestTransfer.
// Ref: TS 38.413 §9.3.4.1 (PDU Session Resource Setup Request Transfer), §9.3.1.43 (Data Forwarding Not Possible).
func buildPDUSessionResourceSetupRequestTransferOpts(upfIP net.IP, dlTEID uint32, qfi uint8, fiveQI, ambrULBps, ambrDLBps int64, pduType aper.Enumerated, dataFwdNotPossible bool) ([]byte, error) {
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
							Value: pduType,
						},
					},
				},
				// IE: QosFlowSetupRequestList (ID 136)
				{
					Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDQosFlowSetupRequestList},
					Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
					Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
						Present:                 ngapType.PDUSessionResourceSetupRequestTransferIEsPresentQosFlowSetupRequestList,
						QosFlowSetupRequestList: buildQosFlowSetupRequestList(qfi, fiveQI, ambrULBps, ambrDLBps),
					},
				},
			},
		},
	}

	if dataFwdNotPossible {
		// Insert IE 127 after the UL NG-U UP TNL Information (index 1) to keep ASN.1 order.
		ie := ngapType.PDUSessionResourceSetupRequestTransferIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDDataForwardingNotPossible},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
				Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentDataForwardingNotPossible,
				DataForwardingNotPossible: &ngapType.DataForwardingNotPossible{
					Value: ngapType.DataForwardingNotPossiblePresentDataForwardingNotPossible},
			},
		}
		l := transfer.ProtocolIEs.List
		l = append(l[:2], append([]ngapType.PDUSessionResourceSetupRequestTransferIEs{ie}, l[2:]...)...)
		transfer.ProtocolIEs.List = l
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
// For GBR 5QIs the GBR QoS Flow Information IE is mandatory (TS 38.413 §9.3.1.12:
// "shall be present for GBR QoS flows") — a real gNB rejects a GBR flow without
// it. GFBR/MFBR are set to the session AMBR since our flows carry the whole
// session. Ref: TS 38.413 §9.3.4.1, §9.3.1.12; TS 23.501 §5.7.2
func buildQosFlowSetupRequestList(qfi uint8, fiveQI, ambrULBps, ambrDLBps int64) *ngapType.QosFlowSetupRequestList {
	params := ngapType.QosFlowLevelQosParameters{
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
	}
	if nas.Is5QIGBR(uint8(fiveQI)) {
		params.GBRQosInformation = &ngapType.GBRQosInformation{
			MaximumFlowBitRateDL:    ngapType.BitRate{Value: ambrDLBps},
			MaximumFlowBitRateUL:    ngapType.BitRate{Value: ambrULBps},
			GuaranteedFlowBitRateDL: ngapType.BitRate{Value: ambrDLBps},
			GuaranteedFlowBitRateUL: ngapType.BitRate{Value: ambrULBps},
		}
	}
	return &ngapType.QosFlowSetupRequestList{
		List: []ngapType.QosFlowSetupRequestItem{
			{
				QosFlowIdentifier:         ngapType.QosFlowIdentifier{Value: int64(qfi)},
				QosFlowLevelQosParameters: params,
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

// usageReportingURRID is the single Usage Reporting Rule ID installed per PDU
// session for active usage reporting (volume-threshold + periodic). The SMF
// installs exactly one URR per session for the MVP. Ref: TS 29.244 §7.5.2.4.
const usageReportingURRID uint32 = 1

// reportingTriggersPerioVolth is the Reporting Triggers IE bitmask enabling
// both the periodic (PERIO) and volume-threshold (VOLTH) triggers. TS 29.244
// §8.2.41 Figure 8.2.41-1 places PERIO at bit 1 (0x01) and VOLTH at bit 2
// (0x02) of octet 1. go-pfcp's NewReportingTriggers(uint16) constructor
// stores the argument big-endian, so octet 1 lands in the HIGH byte of the
// uint16 — verified by round-trip against ie.HasPERIO()/ie.HasVOLTH() in
// TestSendPFCPSessionEstablishmentInstallsURR.
const reportingTriggersPerioVolth uint16 = 0x0300

// volumeThresholdFlagTOVOL selects the Total Volume field in the Volume
// Threshold IE (as opposed to separate uplink/downlink thresholds).
// Ref: TS 29.244 §8.2.13.
const volumeThresholdFlagTOVOL uint8 = 0x01

// sessionAMBRQERID is the Session-AMBR QER, referenced by the PDRs of all
// non-GBR QoS flows of the PDU session. Ref: TS 29.244 §7.5.2.5, TS 23.501 §5.7.2.6.
const sessionAMBRQERID uint32 = 1

// defaultFlowQERID is the QoS-flow QER of the default (non-GBR) QoS flow.
// Ref: TS 29.244 §7.5.2.5, §8.2.89.
const defaultFlowQERID uint32 = 2

// defaultQFI is the QFI of the default QoS flow of a PDU session.
// Ref: TS 29.244 §8.2.89, TS 23.501 §5.7.1.1.
const defaultQFI uint8 = 1

// sessionAMBRKbps returns the exact Session-AMBR (UL, DL) in kbps for the
// PFCP MBR IE (TS 29.244 §8.2.8), falling back to the Mbps fields for sessions
// created without the exact value.
func sessionAMBRKbps(sess *Session) (ul, dl uint64) {
	return kbpsOrMbps(sess.AMBRULKbps, sess.AMBRULMbps), kbpsOrMbps(sess.AMBRDLKbps, sess.AMBRDLMbps)
}

// buildSessionAMBRCreateQER builds Create QER 1: gates open, MBR = Session-AMBR
// (kbps, TS 29.244 §8.2.8), no QFI. The MBR IE is omitted when either AMBR is
// 0/unknown (MBR=0 is not defined as "unlimited"); the caller logs a WARN for
// that misconfiguration. Ref: TS 29.244 §7.5.2.5, TS 23.501 §5.7.2.6.
func buildSessionAMBRCreateQER(ulKbps, dlKbps uint64) *pfcpie.IE {
	ies := []*pfcpie.IE{pfcpie.NewQERID(sessionAMBRQERID), pfcpie.NewGateStatus(0, 0)}
	if ulKbps > 0 && dlKbps > 0 {
		ies = append(ies, pfcpie.NewMBR(ulKbps, dlKbps))
	}
	return pfcpie.NewCreateQER(ies...)
}

// buildDefaultFlowCreateQER builds Create QER 2 for the default non-GBR flow:
// gates open, QFI 1, no MBR (MFBR applies to GBR flows only, TS 23.501 §5.7.2.5).
// Ref: TS 29.244 §7.5.2.5.
func buildDefaultFlowCreateQER() *pfcpie.IE {
	return pfcpie.NewCreateQER(
		pfcpie.NewQERID(defaultFlowQERID),
		pfcpie.NewGateStatus(0, 0),
		pfcpie.NewQFI(defaultQFI),
	)
}

// buildSessionAMBRUpdateQER builds Update QER 1 carrying the new Session-AMBR
// (kbps; no QFI). When either rate is 0/unknown the MBR IE is omitted, which per
// TS 29.244 §7.5.4.5 means "unchanged": the UPF keeps the previous limit. MBR=0
// is deliberately never sent (it is not "unlimited"); sendPFCPQoSModification
// logs a WARN in that case. Ref: TS 29.244 §7.5.4.5.
func buildSessionAMBRUpdateQER(ulKbps, dlKbps uint64) *pfcpie.IE {
	ies := []*pfcpie.IE{pfcpie.NewQERID(sessionAMBRQERID), pfcpie.NewGateStatus(0, 0)}
	if ulKbps > 0 && dlKbps > 0 {
		ies = append(ies, pfcpie.NewMBR(ulKbps, dlKbps))
	}
	return pfcpie.NewUpdateQER(ies...)
}

// sendPFCPSessionEstablishment sends a PFCP Session Establishment Request to UPF.
// Tells UPF: packets arriving on N3 with TEID=sess.ULTEID belong to UE sess.UEIP.
// Also installs a Usage Reporting Rule (Create URR, TS 29.244 §7.5.2.4) so the
// UPF measures and actively reports volume/duration usage (TS 29.244 §5.2.2.4)
// back to the SMF's persistent PFCP receiver — see pfcp_report.go.
// Ref: TS 29.244 §6.3.2
func (s *Server) sendPFCPSessionEstablishment(ctx context.Context, sess *Session) {
	ambrULKbps, ambrDLKbps := sessionAMBRKbps(sess)
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

	// UE IP Address IE (TS 29.244 §8.2.62), granted-type aware: bit1=V6
	// (0x01), bit2=V4 (0x02). IPv4 default path is byte-identical to before
	// (flags 0x02, empty v6 field). Ref: TS 23.501 §5.8.2.2.
	ueIPIE, ueIPv6, err := buildUEIPAddressIE(sess)
	if err != nil {
		s.logger.Error("PFCP: build UE IP Address IE", "error", err, "seid", sess.SEID)
		return
	}

	seq := s.nextPFCPSeq()
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
				ueIPIE,
				// Network Instance carries the DNN so the UPF can select the
				// correct N6 interface for this session's traffic.
				// Ref: TS 29.244 §6.3.3.14, TS 23.501 §5.6.5
				pfcpie.NewNetworkInstance(sess.DNN),
			),
			pfcpie.NewOuterHeaderRemoval(0, 0),
			pfcpie.NewFARID(1),
			// QER ID list: Session-AMBR QER + QoS-flow QER (TS 29.244 §7.5.2.2).
			pfcpie.NewQERID(sessionAMBRQERID),
			pfcpie.NewQERID(defaultFlowQERID),
			// URR ID list within the PDR — links this PDR to the Usage
			// Reporting Rule below so the UPF measures traffic it forwards.
			// Ref: TS 29.244 §7.5.2.2.
			pfcpie.NewURRID(usageReportingURRID),
		),
		pfcpie.NewCreateFAR(
			pfcpie.NewFARID(1),
			pfcpie.NewApplyAction(0x02), // FORWARD (DL header added via Modification later)
		),
		// Session-AMBR QER (shared by all non-GBR PDRs) and QoS-flow QER of the
		// default flow. Ref: TS 29.244 §7.5.2.5, TS 23.501 §5.7.2.6.
		buildSessionAMBRCreateQER(ambrULKbps, ambrDLKbps),
		buildDefaultFlowCreateQER(),
		// Usage Reporting Rule — active usage reporting (volume-threshold +
		// periodic), consumed by the SMF's persistent PFCP receiver
		// (pfcp_report.go). Ref: TS 29.244 §7.5.2.4, §5.2.2.4.
		pfcpie.NewCreateURR(
			pfcpie.NewURRID(usageReportingURRID),
			pfcpie.NewMeasurementMethod(0, 1, 1), // event=0, volum=1, durat=1
			pfcpie.NewReportingTriggers(reportingTriggersPerioVolth),
			pfcpie.NewVolumeThreshold(volumeThresholdFlagTOVOL, s.cfg.N4.VolumeThresholdBytes, 0, 0),
			pfcpie.NewMeasurementPeriod(time.Duration(s.cfg.N4.MeasurementPeriodSeconds)*time.Second),
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

	if (ambrULKbps == 0) != (ambrDLKbps == 0) {
		s.logger.Warn("Session-AMBR set in one direction only: QER MBR IE omitted (no rate limiting)",
			"interface", "N4", "direction", "OUT", "seid", sess.SEID,
			"ambr_ul_kbps", ambrULKbps, "ambr_dl_kbps", ambrDLKbps,
			"spec_ref", "TS 29.244 §7.5.2.5")
	}

	s.logger.Info("PFCP SessionEstablishment sent",
		"seid", sess.SEID, "ulTEID", sess.ULTEID, "ueIP", sess.UEIP, "ueIPv6", ueIPv6,
		"interface", "N4", "direction", "OUT",
		"ambr_qer_id", sessionAMBRQERID, "ambr_qer_mbr_ul_kbps", ambrULKbps,
		"ambr_qer_mbr_dl_kbps", ambrDLKbps,
		"flow_qer_id", defaultFlowQERID, "flow_qer_qfi", defaultQFI,
		"urr_id", usageReportingURRID, "vol_threshold_bytes", s.cfg.N4.VolumeThresholdBytes,
		"meas_period_s", s.cfg.N4.MeasurementPeriodSeconds,
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
	if rsp, ok := msg.(*pfcpmsg.SessionEstablishmentResponse); ok && rsp.Cause != nil {
		if c, cerr := rsp.Cause.Cause(); cerr == nil && c == pfcpie.CauseRequestAccepted {
			s.sessionMu.Lock()
			sess.N4EstablishedAt = time.Now()
			s.sessionMu.Unlock()
		}
	}
}

// sendPFCPQoSModification sends a PFCP Session Modification Request updating the
// QER for the default flow (QFI=1) with the session's current AMBR as MBR.
// Returns true when the UPF acknowledged the modification.
// Ref: TS 29.244 §7.5.4 (Session Modification), §7.5.2.5 (Update QER)
func (s *Server) sendPFCPQoSModification(ctx context.Context, sess *Session) bool {
	if s.skipN4ForReleasing(sess, "QoSModification") {
		return false
	}
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
	mbrUL, mbrDL := sessionAMBRKbps(sess)
	fiveQI := sess.FiveQI
	s.sessionMu.Unlock()

	if mbrUL == 0 || mbrDL == 0 {
		// TS 29.244 §7.5.4.5: an Update QER without MBR leaves the previous limit
		// in force at the UPF. We do not send MBR=0, so the old AMBR persists.
		s.logger.Warn("Session-AMBR 0/unknown in QoS modification: MBR omitted, UPF keeps previous limit",
			"interface", "N4", "direction", "OUT", "procedure", "AmbrEnforcement",
			"seid", seid, "mbr_ul_kbps", mbrUL, "mbr_dl_kbps", mbrDL,
			"spec_ref", "TS 29.244 §7.5.4.5")
	}

	seq := s.nextPFCPSeq()
	req := pfcpmsg.NewSessionModificationRequest(
		0, 0, seid, seq, 0,
		buildSessionAMBRUpdateQER(mbrUL, mbrDL),
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
		"interface", "N4", "direction", "OUT", "procedure", "AmbrEnforcement",
		"seid", seid, "5qi", fiveQI, "qer_id", sessionAMBRQERID,
		"mbr_ul_kbps", mbrUL, "mbr_dl_kbps", mbrDL,
		"spec_ref", "TS 29.244 §7.5.4.5",
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
	if s.skipN4ForReleasing(sess, "SessionModification") {
		return
	}
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

	seq := s.nextPFCPSeq()
	// SEID in header = UP SEID assigned by UPF during establishment.
	// Our UPF assigns UP SEID = CP SEID for simplicity.
	req := pfcpmsg.NewSessionModificationRequest(
		0, 0, sess.SEID, seq, 0,
		buildDLSwitchFAR(dlTEID, gnbIP),
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
