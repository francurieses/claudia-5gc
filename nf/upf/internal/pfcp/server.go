// Package pfcp implements the PFCP server (N4 interface) for UPF.
// Ref: 3GPP TS 29.244
package pfcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// Session holds per-PDU-session state shared between PFCP and GTP-U.
type Session struct {
	CPSEID uint64 // CP F-SEID (assigned by SMF)
	UPSEID uint64 // UP F-SEID (assigned by UPF — equals CP SEID for simplicity)
	ULTEID uint32 // UL TEID: gNB sends GTP-U packets here
	UEIP   net.IP // UE IPv4 address
	GNBIP  net.IP // gNB N3 IP: UPF sends DL GTP-U here
	DLTEID uint32 // DL TEID: used in GTP-U header when sending to gNB

	// QoS enforcement state from the QER (TS 29.244 §7.5.2.5 / §8.2).
	QER QERState
}

// QERState mirrors the QoS Enforcement Rule installed by the SMF.
// MBR values are in kbps per TS 29.244 §8.2.8.
type QERState struct {
	QERID     uint32
	QFI       uint8
	GateUL    uint8 // 0 = OPEN, 1 = CLOSED (TS 29.244 §8.2.7)
	GateDL    uint8
	MBRULKbps uint64
	MBRDLKbps uint64
}

// SessionTable is a concurrency-safe store shared by PFCP and GTP-U servers.
type SessionTable struct {
	mu       sync.RWMutex
	bySEID   map[uint64]*Session // keyed by UP SEID
	byULTEID map[uint32]*Session // keyed by UL TEID (GTP-U uplink fast path)
	byUEIP   map[string]*Session // keyed by UE IP string (TUN downlink fast path)
}

// NewSessionTable creates an empty session table.
func NewSessionTable() *SessionTable {
	return &SessionTable{
		bySEID:   make(map[uint64]*Session),
		byULTEID: make(map[uint32]*Session),
		byUEIP:   make(map[string]*Session),
	}
}

// GetByULTEID returns the session for the given UL TEID (called on every GTP-U packet).
func (t *SessionTable) GetByULTEID(teid uint32) *Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byULTEID[teid]
}

// GetByUEIP returns the session for the given UE IP (called on every TUN read).
func (t *SessionTable) GetByUEIP(ip net.IP) *Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byUEIP[ip.String()]
}

func (t *SessionTable) store(sess *Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bySEID[sess.UPSEID] = sess
	if sess.ULTEID != 0 {
		t.byULTEID[sess.ULTEID] = sess
	}
	if len(sess.UEIP) > 0 {
		t.byUEIP[sess.UEIP.String()] = sess
	}
}

func (t *SessionTable) delete(upSEID uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if sess, ok := t.bySEID[upSEID]; ok {
		delete(t.byULTEID, sess.ULTEID)
		if len(sess.UEIP) > 0 {
			delete(t.byUEIP, sess.UEIP.String())
		}
		delete(t.bySEID, upSEID)
	}
}

// Config holds PFCP server configuration.
type Config struct {
	Address string // "0.0.0.0:8805"
	NodeIP  string // UPF N3 IP announced to SMF
}

// Server is the UPF PFCP server.
type Server struct {
	cfg      Config
	logger   *slog.Logger
	conn     *net.UDPConn
	sessions *SessionTable
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
	return &Server{
		cfg:      cfg,
		logger:   logger.With("component", "pfcp"),
		conn:     conn,
		sessions: sessions,
	}, nil
}

// Start runs the PFCP receive loop.
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("PFCP server listening", "addr", s.cfg.Address)
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
		s.dispatch(raddr, msg)
	}
}

func (s *Server) dispatch(raddr *net.UDPAddr, msg pfcpmsg.Message) {
	switch m := msg.(type) {
	case *pfcpmsg.AssociationSetupRequest:
		s.handleAssociationSetup(raddr, m)
	case *pfcpmsg.SessionEstablishmentRequest:
		s.handleSessionEstablishment(raddr, m)
	case *pfcpmsg.SessionModificationRequest:
		s.handleSessionModification(raddr, m)
	case *pfcpmsg.SessionDeletionRequest:
		s.handleSessionDeletion(raddr, m)
	case *pfcpmsg.HeartbeatRequest:
		s.handleHeartbeat(raddr, m)
	default:
		s.logger.Info("PFCP unhandled message", "type", msg.MessageTypeName())
	}
}

func (s *Server) handleAssociationSetup(raddr *net.UDPAddr, req *pfcpmsg.AssociationSetupRequest) {
	resp := pfcpmsg.NewAssociationSetupResponse(
		req.Sequence(),
		pfcpie.NewNodeID("", "", "upf"),
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
	)
	s.sendResponse(raddr, resp)
	s.logger.Info("PFCP AssociationSetup accepted", "remote", raddr)
}

func (s *Server) handleHeartbeat(raddr *net.UDPAddr, req *pfcpmsg.HeartbeatRequest) {
	resp := pfcpmsg.NewHeartbeatResponse(req.Sequence(), nil)
	s.sendResponse(raddr, resp)
}

// handleSessionEstablishment processes Create PDR/FAR IEs, stores session keyed by UL TEID.
func (s *Server) handleSessionEstablishment(raddr *net.UDPAddr, req *pfcpmsg.SessionEstablishmentRequest) {
	seq := req.Sequence()

	// Extract CP F-SEID
	var cpSEID uint64
	if req.CPFSEID != nil {
		if f, err := req.CPFSEID.FSEID(); err == nil {
			cpSEID = f.SEID
		}
	}

	// Extract UL TEID and UE IP from Create PDR → PDI → F-TEID / UE-IP-Address
	var ulTEID uint32
	var ueIP net.IP
	for _, pdr := range req.CreatePDR {
		pdrIEs, err := pdr.CreatePDR()
		if err != nil {
			continue
		}
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
						ueIP = u.IPv4Address
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
	}

	// Create QER — QoS enforcement state for the session's default flow.
	// Ref: TS 29.244 §7.5.2.5 (Create QER), §8.2.7/§8.2.8 (Gate Status / MBR)
	for _, qer := range req.CreateQER {
		qerIEs, err := qer.CreateQER()
		if err != nil {
			continue
		}
		for _, child := range qerIEs {
			switch child.Type {
			case pfcpie.QERID:
				if v, err := child.QERID(); err == nil {
					sess.QER.QERID = v
				}
			case pfcpie.QFI:
				if v, err := child.QFI(); err == nil {
					sess.QER.QFI = v
				}
			case pfcpie.GateStatus:
				if v, err := child.GateStatusUL(); err == nil {
					sess.QER.GateUL = v
				}
				if v, err := child.GateStatusDL(); err == nil {
					sess.QER.GateDL = v
				}
			case pfcpie.MBR:
				if v, err := child.MBRUL(); err == nil {
					sess.QER.MBRULKbps = v
				}
				if v, err := child.MBRDL(); err == nil {
					sess.QER.MBRDLKbps = v
				}
			}
		}
	}

	s.sessions.store(sess)
	metrics.UPFPFCPSessionsActive.Inc()

	s.logger.Info("PFCP Session established",
		"cpSEID", cpSEID, "ulTEID", ulTEID, "ueIP", ueIP,
		"qer_id", sess.QER.QERID, "qfi", sess.QER.QFI,
		"mbr_ul_kbps", sess.QER.MBRULKbps, "mbr_dl_kbps", sess.QER.MBRDLKbps,
		"spec_ref", "TS 29.244 §7.5.2.5")

	resp := pfcpmsg.NewSessionEstablishmentResponse(
		0, 0, cpSEID, seq, 0,
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
		pfcpie.NewFSEID(upSEID, net.ParseIP(s.cfg.NodeIP), nil),
	)
	s.sendResponse(raddr, resp)
}

// handleSessionModification updates the FAR with DL TEID + gNB IP from UpdateFAR.
func (s *Server) handleSessionModification(raddr *net.UDPAddr, req *pfcpmsg.SessionModificationRequest) {
	seq := req.Sequence()
	upSEID := req.SEID()

	s.sessions.mu.Lock()
	sess := s.sessions.bySEID[upSEID]
	s.sessions.mu.Unlock()

	if sess == nil {
		s.logger.Warn("PFCP SessionModification: session not found", "upSEID", upSEID)
		resp := pfcpmsg.NewSessionModificationResponse(
			0, 0, upSEID, seq, 0,
			pfcpie.NewCause(pfcpie.CauseSessionContextNotFound),
		)
		s.sendResponse(raddr, resp)
		return
	}

	// Update QER — apply the new QoS enforcement parameters (NW-initiated QoS
	// modification pushes a new MBR/QFI here before the UE is signalled).
	// Ref: TS 29.244 §7.5.4 (Session Modification), §7.5.2.5 (Update QER)
	for _, uqer := range req.UpdateQER {
		qerIEs, err := uqer.UpdateQER()
		if err != nil {
			continue
		}
		s.sessions.mu.Lock()
		for _, child := range qerIEs {
			switch child.Type {
			case pfcpie.QERID:
				if v, err := child.QERID(); err == nil {
					sess.QER.QERID = v
				}
			case pfcpie.QFI:
				if v, err := child.QFI(); err == nil {
					sess.QER.QFI = v
				}
			case pfcpie.GateStatus:
				if v, err := child.GateStatusUL(); err == nil {
					sess.QER.GateUL = v
				}
				if v, err := child.GateStatusDL(); err == nil {
					sess.QER.GateDL = v
				}
			case pfcpie.MBR:
				if v, err := child.MBRUL(); err == nil {
					sess.QER.MBRULKbps = v
				}
				if v, err := child.MBRDL(); err == nil {
					sess.QER.MBRDLKbps = v
				}
			}
		}
		qer := sess.QER
		s.sessions.mu.Unlock()
		s.logger.Info("PFCP QER updated — QoS enforcement applied",
			"upSEID", upSEID, "qer_id", qer.QERID, "qfi", qer.QFI,
			"mbr_ul_kbps", qer.MBRULKbps, "mbr_dl_kbps", qer.MBRDLKbps,
			"gate_ul", qer.GateUL, "gate_dl", qer.GateDL,
			"spec_ref", "TS 29.244 §7.5.2.5")
	}

	// Extract DL TEID + gNB IP from UpdateFAR → UpdateForwardingParameters → OuterHeaderCreation
	for _, ufar := range req.UpdateFAR {
		ufarIEs, err := ufar.UpdateFAR()
		if err != nil {
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

func (s *Server) handleSessionDeletion(raddr *net.UDPAddr, req *pfcpmsg.SessionDeletionRequest) {
	upSEID := req.SEID()
	s.sessions.delete(upSEID)
	metrics.UPFPFCPSessionsActive.Dec()
	s.logger.Info("PFCP Session deleted", "upSEID", upSEID)
	resp := pfcpmsg.NewSessionDeletionResponse(
		0, 0, upSEID, req.Sequence(), 0,
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
	)
	s.sendResponse(raddr, resp)
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
