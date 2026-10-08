// Package pfcp implements the PFCP server (N4 interface) for UPF.
// Ref: 3GPP TS 29.244
package pfcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/ra"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// smfPFCPPort is the well-known UDP port on which every SMF is expected to
// run a persistent PFCP receiver (bound to 0.0.0.0:8805) for node-initiated
// messages such as the Session Report Request. Ref: TS 29.244 §6.2.1.
const smfPFCPPort = 8805

// usageReportTickInterval is the UPF's internal sweep cadence for evaluating
// VOLTH/PERIO Usage Reporting Rule triggers across all sessions. TS 29.244
// §5.2.2.4 defines the triggers but leaves the sweep cadence implementation
// -defined; 2s bounds VOLTH detection latency while keeping CPU cost
// negligible for the expected session counts.
// Ref: TS 29.244 §5.2.2.4
const usageReportTickInterval = 2 * time.Second

// Usage Report Trigger octet-1 bit values (TS 29.244 §8.2.44 Figure
// 8.2.44-1): PERIO = bit 1 (0x01), VOLTH = bit 2 (0x02). Verified against
// go-pfcp's ie.HasPERIO()/ie.HasVOLTH(), which read the same bit positions
// from the Reporting Triggers / Usage Report Trigger octet.
const (
	usageReportTriggerPERIO uint8 = 0x01
	usageReportTriggerVOLTH uint8 = 0x02
)

// volumeMeasurementFlags selects TOVOL|ULVOL|DLVOL and their packet-count
// counterparts (TONOP|ULNOP|DLNOP) in the Volume Measurement IE.
// Ref: TS 29.244 §8.2.5.
const volumeMeasurementFlags uint8 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20

// Session holds per-PDU-session state shared between PFCP and GTP-U.
type Session struct {
	CPSEID uint64 // CP F-SEID (assigned by SMF)
	UPSEID uint64 // UP F-SEID (assigned by UPF — equals CP SEID for simplicity)
	ULTEID uint32 // UL TEID: gNB sends GTP-U packets here
	UEIP   net.IP // UE IPv4 address
	GNBIP  net.IP // gNB N3 IP: UPF sends DL GTP-U here
	DLTEID uint32 // DL TEID: used in GTP-U header when sending to gNB

	// UEIPv6 is the UE's full 128-bit IPv6 address (delegated /64 + IID),
	// parsed from the PFCP UE IP Address IE V6 field (TS 29.244 §8.2.62).
	// Nil for IPv4-only sessions. Ref: TS 23.501 §5.8.2.2.
	UEIPv6 net.IP
	// DNN is the Data Network Name from the PDI's Network Instance IE
	// (TS 29.244 §6.3.3.14) — identifies which per-DNN user plane this
	// session's Router Advertisement belongs to.
	DNN string

	// SMFAddr is the SMF's persistent PFCP receiver address, learned from the
	// source address of the Session Establishment Request. Session Report
	// Requests (node-initiated) are sent here. Ref: TS 29.244 §7.5.5.
	SMFAddr *net.UDPAddr

	// QoS enforcement state (TS 29.244 §5.2.5, §7.5.2.5): QERs keyed by QER ID
	// and the QER ID list of each PDR. Mutated only by the PFCP goroutine under
	// SessionTable.mu; the datapath never reads them — it reads the immutable
	// snapshot published in qos by RebuildQoS.
	QERs map[uint32]*QERState
	PDRs map[uint16]*PDRState
	qos  atomic.Pointer[qosView]

	// Usage Reporting Rule state (TS 29.244 §5.2.2.4 / §7.5.2.4).
	URRState URRState

	// raCancel stops this session's per-session Router Advertisement
	// advertiser goroutine (started when UEIPv6 != nil, TS 23.501
	// §5.8.2.2.2). Guarded by SessionTable.mu (same lock used elsewhere for
	// mutable Session fields). Nil when no advertiser is running.
	raCancel context.CancelFunc
}

// URRState mirrors the Usage Reporting Rule installed by the SMF for active
// usage reporting: volume-threshold (VOLTH) and periodic (PERIO) triggers.
// Ref: TS 29.244 §5.2.2.4 (URR handling), §7.5.2.4 (Create URR).
type URRState struct {
	URRID           uint32
	MeasureVolume   bool // Measurement Method VOLUM bit, TS 29.244 §8.2.40
	MeasureDuration bool // Measurement Method DURAT bit
	TriggerVOLTH    bool // Reporting Triggers VOLTH bit, TS 29.244 §8.2.41
	TriggerPERIO    bool // Reporting Triggers PERIO bit

	VolumeThreshold   uint64        // bytes, TS 29.244 §8.2.13
	MeasurementPeriod time.Duration // periodic cadence, TS 29.244 §8.2.42

	// Runtime counters incremented from the GTP-U datapath (hot path — kept
	// lock-free with per-field atomics rather than the session table mutex).
	ULVolume  atomic.Uint64
	DLVolume  atomic.Uint64
	ULPackets atomic.Uint64
	DLPackets atomic.Uint64
	URSeqn    atomic.Uint32 // UR-SEQN, monotonically increasing per URR (§8.2.44)

	// Reporting bookkeeping — low frequency (only touched by the usage
	// reporter sweep goroutine), guarded by mu.
	mu                 sync.Mutex
	LastReportedVolume uint64    // baseline for VOLTH re-arm
	StartTime          time.Time // measurement window start (Start Time IE)
	LastPeriodicReport time.Time
	Installed          bool // true only when a Create URR was actually parsed
}

// AddULVolume records n bytes (and one packet) of uplink user-plane traffic
// against the session's URR. No-op if no URR is installed. Ref: TS 29.244
// §5.2.2.4 (volume measurement, VOLUM method).
func (s *Session) AddULVolume(n int) {
	if n <= 0 || !s.URRState.Installed {
		return
	}
	s.URRState.ULVolume.Add(uint64(n))
	s.URRState.ULPackets.Add(1)
}

// AddDLVolume records n bytes (and one packet) of downlink user-plane
// traffic against the session's URR. No-op if no URR is installed.
func (s *Session) AddDLVolume(n int) {
	if n <= 0 || !s.URRState.Installed {
		return
	}
	s.URRState.DLVolume.Add(uint64(n))
	s.URRState.DLPackets.Add(1)
}

// SessionTable is a concurrency-safe store shared by PFCP and GTP-U servers.
type SessionTable struct {
	mu       sync.RWMutex
	bySEID   map[uint64]*Session     // keyed by UP SEID
	byULTEID map[uint32]*Session     // keyed by UL TEID (GTP-U uplink fast path)
	byUEIP   map[netip.Addr]*Session // keyed by UE IPv4 (TUN downlink fast path; no per-packet String())
	// byUEIPv6Net is keyed by the delegated /64 network string (e.g.
	// "2001:db8:60::/64"), not the full UE address: the UE forms its own IID
	// via SLAAC (and may use temporary/privacy addresses), so IPv6 downlink is
	// matched by prefix, not exact address. Each session owns a distinct /64,
	// so this is unambiguous. Ref: TS 23.501 §5.8.2.2.2.
	byUEIPv6Net map[string]*Session
}

// NewSessionTable creates an empty session table.
func NewSessionTable() *SessionTable {
	return &SessionTable{
		bySEID:      make(map[uint64]*Session),
		byULTEID:    make(map[uint32]*Session),
		byUEIP:      make(map[netip.Addr]*Session),
		byUEIPv6Net: make(map[string]*Session),
	}
}

// GetByULTEID returns the session for the given UL TEID (called on every GTP-U packet).
func (t *SessionTable) GetByULTEID(teid uint32) *Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byULTEID[teid]
}

// GetByUEIP returns the session for the given UE IPv4 (called on every IPv4 TUN read).
func (t *SessionTable) GetByUEIP(ip net.IP) *Session {
	a, ok := ueAddr(ip)
	if !ok {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byUEIP[a]
}

// GetByUEIPv6Prefix returns the session whose delegated /64 contains ip (called
// on every IPv6 TUN read). Matches by prefix so the UE's chosen interface
// identifier (SLAAC/privacy) is irrelevant. Ref: TS 23.501 §5.8.2.2.2.
func (t *SessionTable) GetByUEIPv6Prefix(ip net.IP) *Session {
	prefix := ueV6Prefix(ip)
	if prefix == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byUEIPv6Net[prefix.String()]
}

// ueAddr converts a UE IP to the map key used by byUEIP (4-in-6 unmapped).
func ueAddr(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	return a.Unmap(), ok
}

// Add inserts sess into every lookup index. The PFCP handlers use the same
// path; it is exported for benchmarks and tests that need a populated table.
func (t *SessionTable) Add(sess *Session) { t.store(sess) }

func (t *SessionTable) store(sess *Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bySEID[sess.UPSEID] = sess
	if sess.ULTEID != 0 {
		t.byULTEID[sess.ULTEID] = sess
	}
	if len(sess.UEIP) > 0 {
		if a, ok := ueAddr(sess.UEIP); ok {
			t.byUEIP[a] = sess
		}
	}
	if prefix := ueV6Prefix(sess.UEIPv6); prefix != nil {
		t.byUEIPv6Net[prefix.String()] = sess
	}
}

func (t *SessionTable) delete(upSEID uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if sess, ok := t.bySEID[upSEID]; ok {
		delete(t.byULTEID, sess.ULTEID)
		if len(sess.UEIP) > 0 {
			if a, ok := ueAddr(sess.UEIP); ok {
				delete(t.byUEIP, a)
			}
		}
		if prefix := ueV6Prefix(sess.UEIPv6); prefix != nil {
			delete(t.byUEIPv6Net, prefix.String())
		}
		delete(t.bySEID, upSEID)
	}
}

// Snapshot returns a point-in-time slice of all active sessions. Used by the
// usage-reporter sweep so it need not hold the table lock while emitting
// PFCP Session Report Requests (which involve UDP I/O).
func (t *SessionTable) Snapshot() []*Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*Session, 0, len(t.bySEID))
	for _, sess := range t.bySEID {
		out = append(out, sess)
	}
	return out
}

// Config holds PFCP server configuration.
type Config struct {
	Address string // "0.0.0.0:8805"
	NodeIP  string // UPF N3 IP announced to SMF

	// RAInterval bounds the per-session periodic Router Advertisement cadence
	// (TS 23.501 §5.8.2.2.2, RFC 4861 §6.2.1). Zero uses ra.MaxRtrAdvInterval.
	// Exposed so tests can inject a short interval.
	RAInterval time.Duration

	// DNNIPv6Prefixes maps DNN name to its configured base IPv6 prefix
	// (nf/upf/config/dev.yaml `dnns[].ue_ipv6_prefix`), mirroring the SMF's
	// per-DNN IPv6 pool. Used only as a consistency guard/log at session
	// establishment — the /64 actually advertised always comes from the PFCP
	// UE IP Address IE, never from this map. Ref: TS 23.501 §5.8.2.2.
	DNNIPv6Prefixes map[string]string

	// QoS configures MBR / Session-AMBR enforcement (AmbrEnforcement, UPF-005).
	// The zero value enforces with qos.DefaultBurstMs and the real clock.
	QoS QoSConfig
}

// RASender delivers a downlink IP packet (a Router Advertisement) to the UE
// over the user plane. Implemented by the GTP-U server; this is the seam
// between the PFCP (N4/control) and GTP-U (N3/user-plane) packages so pfcp
// need not import gtpu. Ref: TS 23.501 §5.8.2.2.2.
type RASender interface {
	SendDownlink(sess *Session, ipPkt []byte)
}

// Server is the UPF PFCP server.
type Server struct {
	cfg        Config
	logger     *slog.Logger
	conn       *net.UDPConn
	sessions   *SessionTable
	reportSeq  atomic.Uint32 // Session Report Request sequence number generator
	raSender   RASender
	raInterval time.Duration
	// recoveryTS is the UPF start time, advertised as Recovery Time Stamp in
	// Association Setup and Heartbeat responses. Ref: TS 29.244 §8.2.65, TS 23.007 §19A.
	recoveryTS time.Time
	// qosCfg is the normalised QoS enforcement configuration.
	qosCfg QoSConfig
}

// New creates a PFCP server.
func New(cfg Config, logger *slog.Logger, sessions *SessionTable) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("pfcp: resolve address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("pfcp: listen: %w", err)
	}
	raInterval := cfg.RAInterval
	if raInterval <= 0 {
		raInterval = ra.MaxRtrAdvInterval
	}
	return &Server{
		cfg:        cfg,
		logger:     logger.With("component", "pfcp"),
		conn:       conn,
		sessions:   sessions,
		raInterval: raInterval,
		recoveryTS: time.Now().UTC().Truncate(time.Second),
		qosCfg:     cfg.QoS.normalized(),
	}, nil
}

// SetRASender wires the GTP-U server as the downlink sender for Router
// Advertisements built by this PFCP server's per-session advertisers.
func (s *Server) SetRASender(sender RASender) {
	s.raSender = sender
}

// Start runs the PFCP receive loop and the usage-reporter sweep goroutine.
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("PFCP server listening", "addr", s.cfg.Address)
	go s.runUsageReporter(ctx)
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, raddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logger.Warn("PFCP read error", "error", err)
			continue
		}

		msg, err := pfcpmsg.Parse(buf[:n])
		if err != nil {
			s.logger.Warn("PFCP parse error", "error", err, "bytes", n)
			continue
		}

		s.logger.Info("PFCP message received", "type", msg.MessageTypeName(), "remote", raddr)
		s.dispatch(ctx, raddr, msg)
	}
}

func (s *Server) dispatch(ctx context.Context, raddr *net.UDPAddr, msg pfcpmsg.Message) {
	switch m := msg.(type) {
	case *pfcpmsg.AssociationSetupRequest:
		s.handleAssociationSetup(raddr, m)
	case *pfcpmsg.SessionEstablishmentRequest:
		s.handleSessionEstablishment(ctx, raddr, m)
	case *pfcpmsg.SessionModificationRequest:
		s.handleSessionModification(ctx, raddr, m)
	case *pfcpmsg.SessionDeletionRequest:
		s.handleSessionDeletion(ctx, raddr, m)
	case *pfcpmsg.HeartbeatRequest:
		s.handleHeartbeat(raddr, m)
	case *pfcpmsg.SessionReportResponse:
		s.handleSessionReportResponse(ctx, raddr, m)
	default:
		s.logger.Info("PFCP unhandled message", "type", msg.MessageTypeName())
	}
}

func (s *Server) handleAssociationSetup(raddr *net.UDPAddr, req *pfcpmsg.AssociationSetupRequest) {
	resp := pfcpmsg.NewAssociationSetupResponse(
		req.Sequence(),
		pfcpie.NewNodeID("", "", upfNodeFQDN),
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
		pfcpie.NewRecoveryTimeStamp(s.recoveryTS),
	)
	s.sendResponse(raddr, resp)
	s.logger.Info("PFCP AssociationSetup accepted", "remote", raddr,
		"spec_ref", "TS 29.244 §7.4.4.2")
}

func (s *Server) handleHeartbeat(raddr *net.UDPAddr, req *pfcpmsg.HeartbeatRequest) {
	resp := pfcpmsg.NewHeartbeatResponse(req.Sequence(), pfcpie.NewRecoveryTimeStamp(s.recoveryTS))
	s.sendResponse(raddr, resp)
}

// upfNodeFQDN is the Node ID (FQDN type) the UPF announces in Association
// Setup and Session Establishment responses. Ref: TS 29.244 §8.2.38,
// §7.4.4.2, §7.5.3.1 (Node ID is mandatory in the Establishment Response).
const upfNodeFQDN = "upf"

// handleSessionEstablishment processes Create PDR/FAR IEs, stores session keyed by UL TEID.
func (s *Server) handleSessionEstablishment(ctx context.Context, raddr *net.UDPAddr, req *pfcpmsg.SessionEstablishmentRequest) {
	seq := req.Sequence()

	// Extract CP F-SEID
	var cpSEID uint64
	if req.CPFSEID != nil {
		if f, err := req.CPFSEID.FSEID(); err == nil {
			cpSEID = f.SEID
		}
	}

	// Extract UL TEID, UE IP (v4/v6) and DNN from Create PDR → PDI →
	// F-TEID / UE-IP-Address / Network Instance. Ref: TS 29.244 §8.2.62
	// (UE IP Address), §6.3.3.14 (Network Instance).
	var ulTEID uint32
	var ueIP, ueIPv6 net.IP
	var dnn string
	var pdrStates []*PDRState
	for _, pdr := range req.CreatePDR {
		pdrIEs, err := pdr.CreatePDR()
		if err != nil {
			continue
		}
		// QoS view of the PDR: ID, precedence, Source Interface, QER ID list
		// (TS 29.244 §7.5.2.2).
		ps, rej := parsePDRQoS(pdrIEs, s.warnFn(ctx, cpSEID))
		if rej != nil {
			s.rejectEstablishment(ctx, raddr, seq, cpSEID, rej)
			return
		}
		pdrStates = append(pdrStates, ps)
		for _, child := range pdrIEs {
			if child.Type != pfcpie.PDI {
				continue
			}
			pdiIEs, err := child.PDI()
			if err != nil {
				continue
			}
			for _, pdiChild := range pdiIEs {
				switch pdiChild.Type {
				case pfcpie.FTEID:
					if f, err := pdiChild.FTEID(); err == nil {
						ulTEID = f.TEID
					}
				case pfcpie.UEIPAddress:
					if u, err := pdiChild.UEIPAddress(); err == nil {
						// go-pfcp's UEIPAddress() decode returns net.IP slices that alias
						// the server's single reused UDP read buffer (net.IP.To16() does
						// not copy a 16-byte input) — deep-copy before storing on the
						// long-lived Session, otherwise the next PFCP message received
						// (from any session, including heartbeats) silently corrupts this
						// value in place. Mirrors the GNBIP copy pattern below.
						if u.IPv4Address != nil {
							ueIP = make(net.IP, len(u.IPv4Address))
							copy(ueIP, u.IPv4Address)
						}
						if u.IPv6Address != nil {
							ueIPv6 = make(net.IP, len(u.IPv6Address))
							copy(ueIPv6, u.IPv6Address)
						}
					}
				case pfcpie.NetworkInstance:
					if v, err := pdiChild.NetworkInstance(); err == nil {
						dnn = v
					}
				}
			}
		}
	}

	// UP SEID = CP SEID (simplified; avoids SMF needing to track a separate value)
	upSEID := cpSEID

	sess := &Session{
		CPSEID: cpSEID,
		UPSEID: upSEID,
		ULTEID: ulTEID,
		UEIP:   ueIP,
		UEIPv6: ueIPv6,
		DNN:    dnn,
		// The SMF's persistent PFCP receiver is bound to :8805 on the same
		// host that sent this establishment request. Node-initiated Session
		// Report Requests are sent there. Ref: TS 29.244 §7.5.5, §6.2.1.
		SMFAddr: &net.UDPAddr{IP: raddr.IP, Port: smfPFCPPort},
	}

	// Create QER — QoS enforcement rules, several per session keyed by QER ID,
	// referenced by the PDRs' QER ID lists. Validated in full before the session
	// is stored. Ref: TS 29.244 §7.5.2.2, §7.5.2.5, §5.2.5.
	qers, pdrs, rej := establishmentQoS(req.CreateQER, pdrStates, s.warnFn(ctx, upSEID))
	if rej != nil {
		s.rejectEstablishment(ctx, raddr, seq, cpSEID, rej)
		return
	}
	sess.QERs, sess.PDRs = qers, pdrs
	sess.RebuildQoS(s.qosCfg)
	for _, id := range sortedQERIDs(sess.QERs) {
		s.logQER(ctx, "create", specCreateQER, upSEID, id, sess.QERs[id])
	}
	if v := sess.qos.Load(); len(sess.QERs) > 0 && (v == nil || !v.hasQFI) {
		s.warnNoQFI(ctx, upSEID)
	}

	// Create URR — Usage Reporting Rule for active volume/periodic reporting.
	// Only sessions with a Create URR ever emit Usage Reports (Installed
	// stays false otherwise). Ref: TS 29.244 §7.5.2.4, §5.2.2.4.
	for _, urr := range req.CreateURR {
		urrIEs, err := urr.CreateURR()
		if err != nil {
			continue
		}
		sess.URRState.Installed = true
		now := time.Now()
		sess.URRState.StartTime = now
		sess.URRState.LastPeriodicReport = now
		// Default per the design doc: if Measurement Method is absent or
		// ambiguous, treat the URR as measuring both volume and duration.
		sess.URRState.MeasureVolume = true
		sess.URRState.MeasureDuration = true
		for _, child := range urrIEs {
			switch child.Type {
			case pfcpie.URRID:
				if v, err := child.URRID(); err == nil {
					sess.URRState.URRID = v
				}
			case pfcpie.MeasurementMethod:
				sess.URRState.MeasureVolume = child.HasVOLUM()
				sess.URRState.MeasureDuration = child.HasDURAT()
			case pfcpie.ReportingTriggers:
				sess.URRState.TriggerVOLTH = child.HasVOLTH()
				sess.URRState.TriggerPERIO = child.HasPERIO()
			case pfcpie.VolumeThreshold:
				if v, err := child.VolumeThreshold(); err == nil {
					sess.URRState.VolumeThreshold = v.TotalVolume
				}
			case pfcpie.MeasurementPeriod:
				if v, err := child.MeasurementPeriod(); err == nil {
					sess.URRState.MeasurementPeriod = v
				}
			case pfcpie.TimeThreshold:
				// TIMTH cadence is treated equivalently to Measurement Period
				// (PERIO) for the MVP when no Measurement Period was given.
				if sess.URRState.MeasurementPeriod == 0 {
					if v, err := child.TimeThreshold(); err == nil {
						sess.URRState.MeasurementPeriod = time.Duration(v) * time.Second
					}
				}
			}
		}
	}

	s.sessions.store(sess)
	metrics.UPFPFCPSessionsActive.Inc()

	s.logger.Info("PFCP Session established",
		"cpSEID", cpSEID, "ulTEID", ulTEID, "ueIP", ueIP, "ueIPv6", ueIPv6, "dnn", dnn,
		"qer_count", len(sess.QERs), "dl_qfi", sess.DLQFI(),
		"urr_installed", sess.URRState.Installed, "urr_id", sess.URRState.URRID,
		"volume_threshold", sess.URRState.VolumeThreshold,
		"measurement_period", sess.URRState.MeasurementPeriod,
		"spec_ref", "TS 29.244 §7.5.2.5")

	// Start the per-session Router Advertisement advertiser for delegated
	// IPv6/IPv4v6 sessions (human sign-off 2026-07-22, same PFCP-path
	// exception precedent as UPF-001). Ref: TS 23.501 §5.8.2.2.2.
	if ueIPv6 != nil {
		if _, ok := s.cfg.DNNIPv6Prefixes[dnn]; !ok {
			// Consistency guard: the SMF only delegates IPv6 for a DNN it
			// believes is v6-enabled — a missing local anchor here is a
			// config drift signal, not a reason to withhold the RA (the
			// delegated /64 in the PFCP IE is still authoritative).
			s.logger.Warn("IPv6PrefixDelegation: DNN has no configured ue_ipv6_prefix anchor",
				"dnn", dnn, "spec_ref", "TS 23.501 §5.8.2.2")
		}
		s.startRAAdvertiser(ctx, sess)
	}

	resp := pfcpmsg.NewSessionEstablishmentResponse(
		0, 0, cpSEID, seq, 0,
		pfcpie.NewNodeID("", "", upfNodeFQDN),
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
		pfcpie.NewFSEID(upSEID, net.ParseIP(s.cfg.NodeIP), nil),
	)
	s.sendResponse(raddr, resp)
}

// rejectEstablishment answers a Session Establishment Request with a rejection
// Cause plus the Offending IE / Failed Rule ID, storing no session. Ref:
// TS 29.244 §7.5.3, §8.2.1, §8.2.80.
func (s *Server) rejectEstablishment(ctx context.Context, raddr *net.UDPAddr, seq uint32, cpSEID uint64, rej *pfcpReject) {
	s.logReject(ctx, cpSEID, rej)
	s.sendResponse(raddr, pfcpmsg.NewSessionEstablishmentResponse(
		0, 0, cpSEID, seq, 0,
		append([]*pfcpie.IE{pfcpie.NewNodeID("", "", upfNodeFQDN), pfcpie.NewCause(rej.cause)}, rej.ies...)...))
}

// warnNoQFI logs (once, at PFCP time) that no QER of the session carries a
// QFI, so DL packets get QFI 0 in the PDU Session Container.
func (s *Server) warnNoQFI(ctx context.Context, seid uint64) {
	logging.NewProcedureLogger(ctx, s.logger, procAmbrEnforcement).Warn("no QER carries a QFI, DL QFI defaults to 0",
		"interface", "N4", "direction", "IN",
		"spec_ref", "TS 29.244 §8.2.89", "seid", seid)
}

// applyActionFORW is the FORW bit (bit 2) of the Apply Action IE.
// Ref: TS 29.244 §8.2.26.
const applyActionFORW uint8 = 0x02

// procPduSessionModification is the canonical procedure name for N4 session
// modification logs.
const procPduSessionModification = "PduSessionModification"

// handleSessionModification updates the FAR with DL TEID + gNB IP from UpdateFAR,
// or clears the DL tunnel when Update FAR carries an Apply Action without FORW.
func (s *Server) handleSessionModification(ctx context.Context, raddr *net.UDPAddr, req *pfcpmsg.SessionModificationRequest) {
	seq := req.Sequence()
	upSEID := req.SEID()

	s.sessions.mu.RLock()
	sess := s.sessions.bySEID[upSEID]
	s.sessions.mu.RUnlock()

	if sess == nil {
		s.logger.Warn("PFCP SessionModification: session not found", "upSEID", upSEID)
		resp := pfcpmsg.NewSessionModificationResponse(
			0, 0, upSEID, seq, 0,
			pfcpie.NewCause(pfcpie.CauseSessionContextNotFound),
		)
		s.sendResponse(raddr, resp)
		return
	}

	// Create/Update/Remove QER and the PDR QER ID lists: validate everything
	// first, then apply atomically (no partial application on rejection).
	// A NW-initiated QoS modification pushes the new Session-AMBR here before
	// the UE is signalled. Ref: TS 29.244 §7.5.4, §7.5.4.5, §7.5.4.9.
	s.sessions.mu.RLock()
	plan, rej := planModificationQoS(sess, req, s.warnFn(ctx, upSEID))
	s.sessions.mu.RUnlock()
	if rej != nil {
		s.logReject(ctx, upSEID, rej)
		s.sendResponse(raddr, pfcpmsg.NewSessionModificationResponse(
			0, 0, sess.CPSEID, seq, 0,
			append([]*pfcpie.IE{pfcpie.NewCause(rej.cause)}, rej.ies...)...))
		return
	}
	if !plan.empty() {
		s.sessions.mu.Lock()
		changed := s.applyQoS(sess, plan)
		infos := make([]QERState, len(changed))
		for i, c := range changed {
			infos[i] = c.q
		}
		s.sessions.mu.Unlock()
		for i, c := range changed {
			if c.op == "remove" {
				s.logQER(ctx, c.op, c.spec, upSEID, c.id, nil)
			} else {
				s.logQER(ctx, c.op, c.spec, upSEID, c.id, &infos[i])
			}
		}
		for _, u := range plan.pdrs {
			s.logUpdatePDR(ctx, upSEID, u)
		}
	}

	// Update FAR: Apply Action + Update Forwarding Parameters.
	// - Apply Action with FORW + Outer Header Creation: set the DL tunnel.
	// - Apply Action without FORW (DROP, BUFF, NOCP): clear the DL tunnel so
	//   the datapath drops DL traffic ("dl_tunnel_not_ready"). Used by the SMF
	//   for UP deactivation, e.g. N2 handover. Ref: TS 29.244 §7.5.4.3, §8.2.26.
	// - Apply Action absent: only the Outer Header Creation is honoured.
	for _, ufar := range req.UpdateFAR {
		ufarIEs, err := ufar.UpdateFAR()
		if err != nil {
			continue
		}
		var (
			haveAA bool
			aa     uint8
		)
		for _, child := range ufarIEs {
			if child.Type == pfcpie.ApplyAction {
				if v, err := child.ApplyAction(); err == nil {
					haveAA, aa = true, v
				}
			}
		}
		if haveAA && aa&applyActionFORW == 0 {
			s.sessions.mu.Lock()
			sess.DLTEID = 0
			sess.GNBIP = nil
			s.sessions.mu.Unlock()
			logging.NewProcedureLogger(ctx, s.logger, procPduSessionModification).Info("PFCP Session DL tunnel cleared",
				"nf", "UPF", "interface", "N4", "direction", "IN",
				"seid", upSEID, "apply_action", aa,
				"spec_ref", "TS 29.244 §7.5.4.3")
			continue
		}
		for _, child := range ufarIEs {
			if child.Type != pfcpie.UpdateForwardingParameters {
				continue
			}
			if ohc, err := child.OuterHeaderCreation(); err == nil && ohc.IPv4Address != nil {
				s.sessions.mu.Lock()
				sess.DLTEID = ohc.TEID
				sess.GNBIP = make(net.IP, len(ohc.IPv4Address))
				copy(sess.GNBIP, ohc.IPv4Address)
				s.sessions.mu.Unlock()
				s.logger.Info("PFCP Session DL tunnel updated",
					"upSEID", upSEID, "dlTEID", ohc.TEID, "gnbIP", ohc.IPv4Address)
			}
		}
	}

	resp := pfcpmsg.NewSessionModificationResponse(
		0, 0, sess.CPSEID, seq, 0,
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
	)
	s.sendResponse(raddr, resp)
}

func (s *Server) handleSessionDeletion(ctx context.Context, raddr *net.UDPAddr, req *pfcpmsg.SessionDeletionRequest) {
	upSEID := req.SEID()

	// Stop this session's Router Advertisement advertiser, if any, before
	// removing it from the table. Ref: TS 23.501 §5.8.2.2.2.
	s.sessions.mu.Lock()
	sess, found := s.sessions.bySEID[upSEID]
	if found && sess.raCancel != nil {
		sess.raCancel()
	}
	s.sessions.mu.Unlock()

	if !found {
		// Unknown SEID: Cause 65. Ref: TS 29.244 §7.5.7, §8.2.1.
		s.logger.Warn("PFCP Session deletion for unknown SEID", "upSEID", upSEID,
			"spec_ref", "TS 29.244 §7.5.7", "result", "REJECT")
		s.sendResponse(raddr, pfcpmsg.NewSessionDeletionResponse(
			0, 0, 0, req.Sequence(), 0,
			pfcpie.NewCause(pfcpie.CauseSessionContextNotFound),
		))
		return
	}

	// Drop the QoS snapshot first so a datapath goroutine still holding the
	// session pointer enforces and forwards nothing stale.
	sess.qos.Store(nil)
	s.sessions.delete(upSEID)
	metrics.UPFPFCPSessionsActive.Dec()
	s.logger.Info("PFCP Session deleted", "upSEID", upSEID)
	resp := pfcpmsg.NewSessionDeletionResponse(
		0, 0, upSEID, req.Sequence(), 0,
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
	)
	s.sendResponse(raddr, resp)
}

// handleSessionReportResponse acknowledges a Session Report Response from
// the SMF. Best-effort MVP: no retransmission is attempted regardless of the
// cause value; the next trigger produces a fresh report with an incremented
// UR-SEQN. Ref: TS 29.244 §7.5.9.
func (s *Server) handleSessionReportResponse(ctx context.Context, raddr *net.UDPAddr, resp *pfcpmsg.SessionReportResponse) {
	var cause uint8
	if resp.Cause != nil {
		if c, err := resp.Cause.Cause(); err == nil {
			cause = c
		}
	}
	logger := logging.NewProcedureLogger(ctx, s.logger, "UsageReporting")
	logger.Info("PFCP Session Report Response received",
		"nf", "UPF", "interface", "N4", "direction", "IN",
		"spec_ref", "TS 29.244 §7.5.9",
		"seid", resp.SEID(), "remote", raddr, "result", "OK", "cause", cause)
}

// runUsageReporter periodically sweeps all sessions for VOLTH/PERIO triggers
// until ctx is cancelled. Ref: TS 29.244 §5.2.2.4.
func (s *Server) runUsageReporter(ctx context.Context) {
	ticker := time.NewTicker(usageReportTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepUsageReports(ctx)
		}
	}
}

// sweepUsageReports evaluates every session's URR against its configured
// triggers and emits a Session Report Request for each one that fires.
// VOLTH re-arms its baseline immediately after selection (one report per
// crossing, per sweep — coalescing multiple crossings between ticks).
// Ref: TS 29.244 §5.2.2.4.
func (s *Server) sweepUsageReports(ctx context.Context) {
	for _, sess := range s.sessions.Snapshot() {
		if !sess.URRState.Installed {
			continue
		}

		sess.URRState.mu.Lock()
		total := sess.URRState.ULVolume.Load() + sess.URRState.DLVolume.Load()
		volthDue := sess.URRState.TriggerVOLTH && sess.URRState.VolumeThreshold > 0 &&
			total-sess.URRState.LastReportedVolume >= sess.URRState.VolumeThreshold
		if volthDue {
			sess.URRState.LastReportedVolume = total
		}
		perioDue := sess.URRState.TriggerPERIO && sess.URRState.MeasurementPeriod > 0 &&
			time.Since(sess.URRState.LastPeriodicReport) >= sess.URRState.MeasurementPeriod
		if perioDue {
			sess.URRState.LastPeriodicReport = time.Now()
		}
		sess.URRState.mu.Unlock()

		if volthDue {
			s.emitUsageReport(ctx, sess, usageReportTriggerVOLTH, "VOLTH")
		}
		if perioDue {
			s.emitUsageReport(ctx, sess, usageReportTriggerPERIO, "PERIO")
		}
	}
}

// emitUsageReport builds and sends a PFCP Session Report Request carrying a
// Usage Report for sess's URR, tagged with the given trigger. Best-effort:
// on any send failure it logs a warning and returns — never blocks or
// panics, and never retransmits (matches the SMF client's existing
// "no response" tolerance on establishment). Ref: TS 29.244 §7.5.5, §7.5.8.
func (s *Server) emitUsageReport(ctx context.Context, sess *Session, trigger uint8, triggerName string) {
	if sess.SMFAddr == nil {
		s.logger.Warn("PFCP usage report: no SMF address, dropping", "seid", sess.CPSEID)
		return
	}

	seq := s.reportSeq.Add(1)
	urSeqn := sess.URRState.URSeqn.Add(1)

	ul := sess.URRState.ULVolume.Load()
	dl := sess.URRState.DLVolume.Load()
	ulPkt := sess.URRState.ULPackets.Load()
	dlPkt := sess.URRState.DLPackets.Load()
	total := ul + dl
	totalPkt := ulPkt + dlPkt
	duration := time.Since(sess.URRState.StartTime)

	report := pfcpmsg.NewSessionReportRequest(0, 0, sess.CPSEID, seq, 0,
		pfcpie.NewReportType(0, 0, 1, 0), // USAR=1
		pfcpie.NewUsageReportWithinSessionReportRequest(
			pfcpie.NewURRID(sess.URRState.URRID),
			pfcpie.NewURSEQN(urSeqn),
			pfcpie.NewUsageReportTrigger(trigger, 0x00, 0x00),
			pfcpie.NewVolumeMeasurement(volumeMeasurementFlags, total, ul, dl, totalPkt, ulPkt, dlPkt),
			pfcpie.NewDurationMeasurement(duration),
		),
	)

	b := make([]byte, report.MarshalLen())
	if err := report.MarshalTo(b); err != nil {
		s.logger.Error("PFCP usage report marshal", "error", fmt.Errorf("upf: usage report: %w", err), "seid", sess.CPSEID)
		return
	}
	if _, err := s.conn.WriteToUDP(b, sess.SMFAddr); err != nil {
		s.logger.Warn("PFCP usage report send failed",
			"error", fmt.Errorf("upf: usage report: %w", err), "seid", sess.CPSEID, "smf", sess.SMFAddr)
		return
	}

	metrics.UPFUsageReportsTotal.WithLabelValues(triggerName).Inc()

	logger := logging.NewProcedureLogger(ctx, s.logger, "UsageReporting")
	logger.Info("PFCP Session Report Request sent",
		"nf", "UPF", "interface", "N4", "direction", "OUT",
		"spec_ref", "TS 29.244 §7.5.5",
		"seid", sess.CPSEID, "urr_id", sess.URRState.URRID, "ur_seqn", urSeqn,
		"trigger", triggerName, "total_volume", total, "ul_volume", ul, "dl_volume", dl,
		"duration_ms", duration.Milliseconds())
}

// startRAAdvertiser launches the per-session Router Advertisement advertiser
// goroutine for an IPv6/IPv4v6 session (TS 23.501 §5.8.2.2.2). It ticks at
// s.raInterval (bounded by RFC 4861 §6.2.1) and skips a tick — logging once
// at Debug — whenever the DL tunnel (DL TEID + gNB IP) is not yet known. The
// goroutine is stopped by cancelling sess.raCancel, called from
// handleSessionDeletion. Ref: TS 23.501 §5.8.2.2.2.
func (s *Server) startRAAdvertiser(ctx context.Context, sess *Session) {
	advCtx, cancel := context.WithCancel(ctx)
	s.sessions.mu.Lock()
	sess.raCancel = cancel
	s.sessions.mu.Unlock()
	go s.runRAAdvertiser(advCtx, sess)
}

// runRAAdvertiser periodically emits an unsolicited Router Advertisement for
// sess until advCtx is cancelled (session deletion or server shutdown).
// Ref: RFC 4861 §6.2.1, TS 23.501 §5.8.2.2.2.
func (s *Server) runRAAdvertiser(advCtx context.Context, sess *Session) {
	ticker := time.NewTicker(s.raInterval)
	defer ticker.Stop()
	for {
		select {
		case <-advCtx.Done():
			return
		case <-ticker.C:
			s.emitRA(advCtx, sess, nil, "periodic")
		}
	}
}

// TriggerSolicitedRA immediately sends a unicast Router Advertisement to
// srcLL — the source address of a Router Solicitation the GTP-U server just
// decapsulated from the uplink — per RFC 4861 §6.2.6. No-op if the session
// carries no delegated IPv6 address.
func (s *Server) TriggerSolicitedRA(ctx context.Context, sess *Session, srcLL net.IP) {
	s.emitRA(ctx, sess, srcLL, "solicited")
}

// ueV6Prefix derives the /64 network the UE's delegated IPv6 address belongs
// to, for use as the Prefix Information option in a Router Advertisement.
func ueV6Prefix(ueIPv6 net.IP) *net.IPNet {
	ip16 := ueIPv6.To16()
	if ip16 == nil {
		return nil
	}
	mask := net.CIDRMask(64, 128)
	network := make(net.IP, net.IPv6len)
	copy(network, ip16.Mask(mask))
	return &net.IPNet{IP: network, Mask: mask}
}

// emitRA builds and sends a Router Advertisement for sess's delegated /64.
// dst is nil for a periodic (all-nodes multicast) RA, or the UE's
// link-local address for a unicast solicited RA. Skips (Debug-logged) when
// the session has no delegated IPv6 address, no RASender is wired, or the
// downlink tunnel (DL TEID + gNB IP, learned at PFCP Session Modification)
// is not yet known. Ref: TS 23.501 §5.8.2.2.2, RFC 4861 §4.2.
func (s *Server) emitRA(ctx context.Context, sess *Session, dst net.IP, kind string) {
	s.sessions.mu.RLock()
	ueIPv6 := sess.UEIPv6
	dnn := sess.DNN
	dlTEID := sess.DLTEID
	gnbIP := sess.GNBIP
	s.sessions.mu.RUnlock()

	if ueIPv6 == nil || s.raSender == nil {
		return
	}
	prefix := ueV6Prefix(ueIPv6)
	if prefix == nil {
		return
	}
	if dlTEID == 0 || gnbIP == nil {
		s.logger.Debug("IPv6PrefixDelegation: DL tunnel not ready, skipping Router Advertisement",
			"seid", sess.UPSEID, "dnn", dnn, "kind", kind, "spec_ref", "TS 23.501 §5.8.2.2.2")
		return
	}

	start := time.Now()
	pkt, err := ra.BuildRouterAdvertisement(prefix, ra.Options{Dst: dst})
	if err != nil {
		s.logger.Error("upf: build router advertisement", "error", err, "seid", sess.UPSEID)
		return
	}
	s.raSender.SendDownlink(sess, pkt)
	metrics.UPFRouterAdvertisementsTotal.WithLabelValues(kind).Inc()

	logger := logging.NewProcedureLogger(ctx, s.logger, "IPv6PrefixDelegation")
	logger.Info("Router Advertisement sent",
		"nf", "UPF", "interface", "N3", "direction", "OUT",
		"spec_ref", "TS 23.501 §5.8.2.2.2",
		"seid", sess.UPSEID, "dlTEID", dlTEID, "gnbIP", gnbIP,
		"dnn", dnn, "ue_ipv6", ueIPv6.String(), "prefix", prefix.String(),
		"kind", kind, "result", "OK", "duration_ms", time.Since(start).Milliseconds())
}

func (s *Server) sendResponse(raddr *net.UDPAddr, msg pfcpmsg.Message) {
	b := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(b); err != nil {
		s.logger.Error("PFCP marshal response", "error", err)
		return
	}
	if _, err := s.conn.WriteToUDP(b, raddr); err != nil {
		s.logger.Error("PFCP send response", "error", err)
	}
}

// Close closes the PFCP server.
func (s *Server) Close() error {
	return s.conn.Close()
}
