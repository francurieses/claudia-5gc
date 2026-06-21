// Package ngap implements the AMF side of the NGAP protocol (3GPP TS 38.413).
//
// NGAP runs over SCTP (TS 38.412). Each connected gNB establishes one
// SCTP association with the AMF; the AMF accepts connections on port 38412.
//
// This package handles:
//   - NG Setup (§8.7.1) — establishes the gNB ↔ AMF association
//   - Uplink NAS Transport (§8.6.3) — delivers NAS PDUs from UE to AMF
//   - Downlink NAS Transport (§8.6.2) — sends NAS PDUs from AMF to UE
//   - Initial UE Message (§8.6.1) — first UE message on a new connection
//   - Initial Context Setup (§8.3.1) — establishes radio context + NAS security
//   - UE Context Release (§8.3.4) — releases resources
//
// ASN.1 PER aligned encoding/decoding uses the free5GC aper library
// (Apache-2.0) via github.com/free5gc/ngap.
//
// Ref: 3GPP TS 38.413 v17.x.x
package ngap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

// ---- NGAP Message Types (subset) (TS 38.413 §9.1) -----------------------

// ProcedureCode identifies the NGAP procedure.
type ProcedureCode uint8

const (
	// Elementary Procedures
	ProcNGSetup                    ProcedureCode = 21
	ProcInitialContextSetup        ProcedureCode = 14
	ProcUEContextRelease           ProcedureCode = 41
	ProcUEContextReleaseRequest    ProcedureCode = 42 // gNB-initiated (TS 38.413 §8.3.4)
	ProcInitialUEMessage           ProcedureCode = 15
	ProcUplinkNASTransport         ProcedureCode = 46
	ProcDownlinkNASTransport       ProcedureCode = 4
	ProcPDUSessionResourceSetup    ProcedureCode = 29
	ProcPDUSessionResourceRelease  ProcedureCode = 28
	ProcPDUSessionResourceModify   ProcedureCode = 26
	ProcPathSwitchRequest          ProcedureCode = 25
	ProcHandoverNotification       ProcedureCode = 11 // HandoverNotify (target gNB → AMF, step 5)
	ProcHandoverPreparation        ProcedureCode = 12 // HandoverRequired (src→AMF) + HandoverCommand (AMF→src)
	ProcHandoverResourceAllocation ProcedureCode = 13 // HandoverRequest (AMF→tgt) + HandoverRequestAck (tgt→AMF)
	ProcUEContextModification      ProcedureCode = 26
	ProcNGReset                    ProcedureCode = 20
	ProcNGApplicationIndication    ProcedureCode = 18
	// TS 38.413 Table 9.1.1-1: ErrorIndication has procedure code 9.
	ProcErrorIndication ProcedureCode = 9
)

// Criticality per TS 38.413 §9.1.
type Criticality uint8

const (
	CriticalityReject Criticality = 0
	CriticalityIgnore Criticality = 1
	CriticalityNotify Criticality = 2
)

// Message is a decoded NGAP PDU.
type Message struct {
	// PDU type: 0=InitiatingMessage, 1=SuccessfulOutcome, 2=UnsuccessfulOutcome
	Type          uint8
	ProcedureCode ProcedureCode
	Criticality   Criticality
	// Decoded content — type depends on ProcedureCode
	Value interface{}
}

// ---- GNB Context ---------------------------------------------------------

// GNBContext represents a connected gNB.
type GNBContext struct {
	mu           sync.Mutex
	GlobalGNBID  []byte
	Name         string
	SupportedTAs []SupportedTA
	Conn         *sctp.SCTPConn
	// CM-CONNECTED UEs indexed by RAN UE NGAP ID.
	UEs map[int64]*amfctx.UEContext
	// CM-IDLE UEs still logically associated with this gNB (went idle via
	// UEContextRelease but never reconnected or deregistered). When the gNB
	// SCTP association closes, these UEs are also cleaned up so PDU sessions
	// do not linger after a container stop.
	IdleUEs map[int64]*amfctx.UEContext
}

// SupportedTA is a Tracking Area supported by the gNB.
type SupportedTA struct {
	TAC            uint32
	BroadcastPLMNs []PLMNSlice
}

// PLMNSlice is a PLMN + its slices.
type PLMNSlice struct {
	MCC, MNC     string
	SliceSupport []amfctx.SNSSAISubscribed
}

// ---- Handler interface ---------------------------------------------------

// NASHandler is the callback interface for NAS PDUs delivered by NGAP.
// The NGAP package calls this when an NAS message arrives from the UE.
type NASHandler interface {
	HandleNASMessage(ctx context.Context, ue *amfctx.UEContext, nasPDU []byte) error
}

// ---- AMF Config ----------------------------------------------------------

// AMFConfig holds AMF identity fields needed for NGAP message construction.
type AMFConfig struct {
	Name     string
	MCC, MNC string
	RegionID byte
	SetID    uint16
	AMFID    byte
	// SNSSAIs is the list of slices this AMF serves, advertised in NG Setup Response.
	SNSSAIs []amfctx.SNSSAISubscribed
}

// ---- Timer Config --------------------------------------------------------

// TimerConfig holds the durations for UE lifecycle timers managed by the NGAP server.
// Ref: TS 23.501 §5.3.2 (Mobile Reachable, Implicit Detach),
//
//	TS 38.413 §8.3.5 (PendingRemoval watchdog).
//
// To change values: edit nf/amf/config/dev.yaml section "timers:" and restart the AMF.
type TimerConfig struct {
	// MobileReachable is the total duration of the Mobile Reachable Timer.
	// = T3512 + guard period. Started when UE goes CM-IDLE or completes registration.
	// Reset on Periodic Registration Update or Service Request.
	MobileReachable time.Duration
	// ImplicitDetach is the duration of the Implicit Detach Timer.
	// Started when MobileReachable expires. On expiry → implicit detach.
	ImplicitDetach time.Duration
	// PendingRemoval is the watchdog timeout after UEContextReleaseCommand.
	// If UEContextReleaseComplete does not arrive within this time → force-remove.
	PendingRemoval time.Duration
}

// ---- Server --------------------------------------------------------------

// Server is the NGAP SCTP server.
type Server struct {
	addr       string // e.g. "0.0.0.0:38412"
	mgr        *amfctx.Manager
	nasHandler NASHandler
	cfg        AMFConfig
	logger     *slog.Logger
	mu         sync.RWMutex
	gnbs       map[string]*GNBContext // key: remote SCTP addr

	// onPDUSessionSetup is called when gNB confirms PDU session resources.
	// Carries the smContextRef and raw N2SM response transfer bytes.
	onPDUSessionSetup func(ctx context.Context, smContextRef string, n2SmTransfer []byte)

	// onPDUSessionRelease is called when gNB confirms PDU session resource release.
	onPDUSessionRelease func(ctx context.Context, amfUENGAPID int64)

	// onANRelease is called when the UE Context Release Complete is received and the UE
	// transitions to CM-IDLE. The AMF should notify SMF for each PDU session.
	// Ref: TS 23.502 §4.2.6
	onANRelease func(ctx context.Context, ue *amfctx.UEContext)

	// onGNBDisconnect is called for each UE still in CM-CONNECTED state when an SCTP
	// association with a gNB drops unexpectedly (container stop, network failure).
	// The callback must release PDU sessions at SMF, deregister from UDM, and remove
	// the UE context from the manager.
	// Ref: TS 23.502 §4.2.6 (implicit detach on RAN failure)
	onGNBDisconnect func(ctx context.Context, ue *amfctx.UEContext)

	// onImplicitDetach is called when the Implicit Detach Timer fires for a UE.
	// The callback must release PDU sessions at SMF, deregister from UDM, and
	// remove the UE context. Runs in a timer goroutine.
	// Ref: TS 23.501 §5.3.2
	onImplicitDetach func(ctx context.Context, ue *amfctx.UEContext)

	// onPathSwitchPDUSession is called for each PDU session during Xn handover.
	// It receives the SMF smContextRef and the raw PathSwitchRequestTransfer bytes
	// so the SMF can update the PFCP session with the target gNB's DL GTP-U endpoint.
	// If nil, PFCP update is skipped (data plane may briefly be suboptimal).
	// Ref: TS 23.502 §4.9.1.2 step 6
	onPathSwitchPDUSession func(ctx context.Context, smContextRef string, pathSwitchTransfer []byte)

	// onN2HandoverComplete is called after HandoverNotify when the UE context has
	// been migrated to the target gNB. The callback should notify SMF to update
	// PFCP with the new DL endpoint (similar to Xn path switch).
	// If nil, the PFCP update is skipped.
	// Ref: TS 23.502 §4.9.1.3 step 12
	onN2HandoverComplete func(ctx context.Context, smContextRef string, hoAckTransfer []byte)

	// pendingN2HO tracks in-progress N2 handovers indexed by AMF UE NGAP ID.
	// Created on HandoverRequired (step 1), consumed on HandoverNotify (step 5).
	pendingN2HO   map[int64]*n2HandoverState
	pendingN2HOMu sync.Mutex

	// timerCfg holds the timer durations for UE lifecycle management.
	timerCfg TimerConfig
}

// NewServer constructs the NGAP SCTP server. NASHandler can be nil and set later
// via SetNASHandler to break the circular dependency AMF→NGAP→NAS→procedures.
func NewServer(addr string, mgr *amfctx.Manager, nas NASHandler, cfg AMFConfig, logger *slog.Logger) *Server {
	return &Server{
		addr:        addr,
		mgr:         mgr,
		nasHandler:  nas,
		cfg:         cfg,
		logger:      logger.With("component", "ngap"),
		gnbs:        make(map[string]*GNBContext),
		pendingN2HO: make(map[int64]*n2HandoverState),
	}
}

// SetNASHandler wires the NAS handler after the server is built.
// This breaks the circular dependency: NGAP → NAS → NGAP.
func (s *Server) SetNASHandler(h NASHandler) {
	s.nasHandler = h
}

// SetPDUSessionResponseHandler registers a callback invoked when the gNB confirms
// PDU session resource setup. The callback receives the SMF smContextRef and the
// raw N2SM response transfer bytes so the SMF can update the PFCP session with the
// gNB's DL tunnel parameters.
func (s *Server) SetPDUSessionResponseHandler(fn func(ctx context.Context, smContextRef string, n2SmTransfer []byte)) {
	s.onPDUSessionSetup = fn
}

// SetPDUSessionReleaseHandler registers a callback invoked when the gNB confirms
// PDU session resource release.
func (s *Server) SetPDUSessionReleaseHandler(fn func(ctx context.Context, amfUENGAPID int64)) {
	s.onPDUSessionRelease = fn
}

// SetANReleaseHandler registers a callback invoked when the UE context is fully
// released by the gNB (UEContextReleaseComplete received). The UE is already
// transitioned to CM-IDLE when the callback fires.
// Ref: TS 23.502 §4.2.6
func (s *Server) SetANReleaseHandler(fn func(ctx context.Context, ue *amfctx.UEContext)) {
	s.onANRelease = fn
}

// SetGNBDisconnectHandler registers a callback invoked for each UE that was in
// CM-CONNECTED state when an SCTP association with a gNB drops abruptly. The
// callback is responsible for releasing SMF sessions, deregistering from UDM,
// and removing the UE context from the manager.
func (s *Server) SetGNBDisconnectHandler(fn func(ctx context.Context, ue *amfctx.UEContext)) {
	s.onGNBDisconnect = fn
}

// SetImplicitDetachHandler registers the callback invoked when the Implicit Detach
// Timer fires for a CM-IDLE UE that has not been reachable since its Mobile Reachable
// Timer expired. The callback must release SMF sessions, deregister from UDM, and
// remove the UE context.
// Ref: TS 23.501 §5.3.2
func (s *Server) SetImplicitDetachHandler(fn func(ctx context.Context, ue *amfctx.UEContext)) {
	s.onImplicitDetach = fn
}

// SetPathSwitchHandler registers a callback invoked for each PDU session during
// Xn handover. It receives the SMF smContextRef and the raw PathSwitchRequestTransfer
// so the SMF can update the PFCP session with the target gNB's DL GTP-U endpoint.
// Ref: TS 23.502 §4.9.1.2 step 6
func (s *Server) SetPathSwitchHandler(fn func(ctx context.Context, smContextRef string, pathSwitchTransfer []byte)) {
	s.onPathSwitchPDUSession = fn
}

// SetN2HandoverCompleteHandler registers a callback invoked after HandoverNotify
// for each admitted PDU session. The callback should notify SMF to update PFCP
// with the target gNB's new DL GTP-U endpoint (via the HO Ack transfer bytes).
// Ref: TS 23.502 §4.9.1.3 step 12
func (s *Server) SetN2HandoverCompleteHandler(fn func(ctx context.Context, smContextRef string, hoAckTransfer []byte)) {
	s.onN2HandoverComplete = fn
}

// WithTimerConfig sets the UE lifecycle timer durations.
// Call this before Start().
func (s *Server) WithTimerConfig(cfg TimerConfig) {
	s.timerCfg = cfg
}

// ---- UE lifecycle timer helpers -------------------------------------------
// These run from timer goroutines (time.AfterFunc) and must not hold ue.mu
// when making external calls.

// StartMobileReachableTimer arms (or resets) the Mobile Reachable Timer for ue.
// When it fires it starts the Implicit Detach Timer.
// The timer only runs while the UE is CM-IDLE: a CM-CONNECTED UE has a NAS
// signalling connection and is reachable by definition (T3512 periodic
// registration only runs at the UE in 5GMM-IDLE, TS 24.501 §5.3.7). Call this
// on AN Release; call StopUETimers when the UE enters CM-CONNECTED.
// Ref: TS 23.501 §5.3.2
func (s *Server) StartMobileReachableTimer(ue *amfctx.UEContext) {
	if s.timerCfg.MobileReachable == 0 {
		return
	}
	ue.Lock()
	if ue.MobileReachableTimer != nil {
		ue.MobileReachableTimer.Stop()
	}
	ue.MobileReachableTimer = time.AfterFunc(s.timerCfg.MobileReachable, func() {
		ue.Lock()
		connected := ue.CMState == amfctx.CMConnected
		ue.Unlock()
		if connected {
			// The UE returned to CM-CONNECTED after this timer was armed (the
			// stop raced the firing). A reachable UE must not be detached.
			return
		}
		s.logger.Info("Mobile Reachable Timer expired — starting Implicit Detach Timer",
			"procedure", "ImplicitDetach",
			"supi", ue.SUPI,
			"mobile_reachable_dur", s.timerCfg.MobileReachable,
			"spec_ref", "TS 23.501 §5.3.2",
		)
		s.startImplicitDetachTimer(ue)
	})
	ue.Unlock()
}

// StopUETimers cancels the Mobile Reachable and Implicit Detach timers.
// Call whenever the UE enters CM-CONNECTED (registration complete, service
// request, registration update): a UE with a NAS signalling connection is
// reachable, so the CM-IDLE watchdogs must not run.
// Ref: TS 23.501 §5.3.2
func (s *Server) StopUETimers(ue *amfctx.UEContext) {
	ue.Lock()
	if ue.MobileReachableTimer != nil {
		ue.MobileReachableTimer.Stop()
	}
	if ue.ImplicitDetachTimer != nil {
		ue.ImplicitDetachTimer.Stop()
	}
	ue.Unlock()
}

// startImplicitDetachTimer arms (or resets) the Implicit Detach Timer for ue.
// When it fires it calls onImplicitDetach (releases PDU sessions, deregisters UDM,
// removes context). Ref: TS 23.501 §5.3.2
func (s *Server) startImplicitDetachTimer(ue *amfctx.UEContext) {
	if s.timerCfg.ImplicitDetach == 0 {
		return
	}
	ue.Lock()
	if ue.ImplicitDetachTimer != nil {
		ue.ImplicitDetachTimer.Stop()
	}
	ue.ImplicitDetachTimer = time.AfterFunc(s.timerCfg.ImplicitDetach, func() {
		ue.Lock()
		connected := ue.CMState == amfctx.CMConnected
		ue.Unlock()
		if connected {
			// UE made contact before the implicit detach window closed.
			// Ref: TS 24.501 §5.3.7 — abort implicit detach on UE contact.
			return
		}
		s.logger.Info("Implicit Detach Timer expired — performing implicit detach",
			"procedure", "ImplicitDetach",
			"supi", ue.SUPI,
			"implicit_detach_dur", s.timerCfg.ImplicitDetach,
			"result", "OK",
			"spec_ref", "TS 23.501 §5.3.2",
		)
		s.removeUEFromIdleUEs(ue)
		if s.onImplicitDetach != nil {
			s.onImplicitDetach(context.Background(), ue)
		}
	})
	ue.Unlock()
}

// startPendingRemovalTimer arms the PendingRemoval watchdog for ue after a
// UEContextReleaseCommand has been sent. If UEContextReleaseComplete does not
// arrive within the configured timeout the context is force-removed.
// Ref: TS 38.413 §8.3.5
func (s *Server) startPendingRemovalTimer(ue *amfctx.UEContext) {
	if s.timerCfg.PendingRemoval == 0 {
		return
	}
	ue.Lock()
	if ue.PendingRemovalTimer != nil {
		ue.PendingRemovalTimer.Stop()
	}
	ue.PendingRemovalTimer = time.AfterFunc(s.timerCfg.PendingRemoval, func() {
		s.logger.Warn("PendingRemoval watchdog fired — force-removing stuck UE context",
			"procedure", "Deregistration",
			"supi", ue.SUPI,
			"watchdog_dur", s.timerCfg.PendingRemoval,
			"spec_ref", "TS 38.413 §8.3.5",
		)
		s.removeUEFromIdleUEs(ue)
		s.mgr.Remove(context.Background(), ue)
	})
	ue.Unlock()
}

// removeUEFromIdleUEs removes ue from the IdleUEs map of whichever gNB holds it.
// Called by timer callbacks before mgr.Remove to keep gNB maps consistent.
func (s *Server) removeUEFromIdleUEs(ue *amfctx.UEContext) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, gnb := range s.gnbs {
		gnb.mu.Lock()
		for ranID, idle := range gnb.IdleUEs {
			if idle == ue {
				delete(gnb.IdleUEs, ranID)
				break
			}
		}
		gnb.mu.Unlock()
	}
}

// Start begins accepting SCTP connections.
func (s *Server) Start(ctx context.Context) error {
	sctpAddr, err := sctp.ResolveSCTPAddr("sctp", s.addr)
	if err != nil {
		return fmt.Errorf("ngap: resolve %s: %w", s.addr, err)
	}
	l, err := sctp.ListenSCTP("sctp", sctpAddr)
	if err != nil {
		return fmt.Errorf("ngap: listen %s: %w", s.addr, err)
	}
	s.logger.Info("NGAP server listening",
		"addr", s.addr,
		"protocol", "SCTP",
		"spec_ref", "TS 38.412 §5",
	)

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		conn, err := l.AcceptSCTP()
		if err != nil {
			if ctx.Err() != nil {
				return nil // normal shutdown
			}
			s.logger.Error("NGAP accept error", "error", err)
			continue
		}
		go s.handleGNBConn(ctx, conn)
	}
}

// handleGNBConn reads NGAP PDUs from a gNB connection.
func (s *Server) handleGNBConn(ctx context.Context, conn *sctp.SCTPConn) {
	remoteAddr := conn.RemoteAddr().String()
	log := s.logger.With("gnb_addr", remoteAddr)
	log.Info("gNB connected", "direction", "IN", "interface", "N2")

	gnb := &GNBContext{
		Conn:    conn,
		UEs:     make(map[int64]*amfctx.UEContext),
		IdleUEs: make(map[int64]*amfctx.UEContext),
	}
	s.mu.Lock()
	s.gnbs[remoteAddr] = gnb
	s.mu.Unlock()

	defer func() {
		// Collect all UEs still associated with this gNB:
		// - CM-CONNECTED UEs (abrupt disconnect, never got UEContextRelease)
		// - CM-IDLE UEs (went idle via UEContextRelease but gNB is now closing)
		// Both sets need their PDU sessions released and UE contexts removed.
		gnb.mu.Lock()
		ues := make([]*amfctx.UEContext, 0, len(gnb.UEs)+len(gnb.IdleUEs))
		for _, ue := range gnb.UEs {
			ues = append(ues, ue)
		}
		for _, ue := range gnb.IdleUEs {
			ues = append(ues, ue)
		}
		gnb.mu.Unlock()

		// Release PDU sessions and remove context for all UEs.
		// Use a fresh background context: the server ctx may already be cancelled.
		if s.onGNBDisconnect != nil {
			cleanCtx := context.Background()
			for _, ue := range ues {
				s.onGNBDisconnect(cleanCtx, ue)
			}
		}

		conn.Close()
		s.mu.Lock()
		delete(s.gnbs, remoteAddr)
		s.mu.Unlock()
		log.Info("gNB disconnected", "ues_cleaned_up", len(ues))
	}()

	for {
		buf := make([]byte, 65536)
		n, err := conn.Read(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				log.Error("NGAP read error", "error", err)
			}
			return
		}
		// Process NGAP messages serially per gNB association. SCTP delivers
		// in order; a goroutine-per-message would race on per-UE NAS state
		// (notably SecurityCtx.UplinkCount) when the UE sends back-to-back
		// messages such as RegistrationComplete + UL NAS Transport.
		s.dispatch(ctx, gnb, buf[:n])
	}
}

// dispatch decodes and routes a raw NGAP PDU to the appropriate handler.
func (s *Server) dispatch(ctx context.Context, gnb *GNBContext, data []byte) {
	msg, err := DecodeNGAPPDU(data)
	if err != nil {
		s.logger.Error("NGAP decode error", "error", err,
			"pdu_len", len(data))
		return
	}
	log := s.logger.With("procedure_code", msg.ProcedureCode)
	switch msg.ProcedureCode {
	case ProcNGSetup:
		s.handleNGSetup(ctx, gnb, msg)
	case ProcInitialUEMessage:
		s.handleInitialUEMessage(ctx, gnb, msg)
	case ProcUplinkNASTransport:
		s.handleUplinkNASTransport(ctx, gnb, msg)
	case ProcPDUSessionResourceSetup:
		if msg.Type == 1 { // SuccessfulOutcome
			s.handlePDUSessionResourceSetupResponse(ctx, gnb, msg)
		}
	case ProcPDUSessionResourceRelease:
		if msg.Type == 1 { // SuccessfulOutcome
			s.handlePDUSessionResourceReleaseResponse(ctx, gnb, msg)
		}
	case ProcPDUSessionResourceModify:
		if msg.Type == 1 { // SuccessfulOutcome
			s.handlePDUSessionResourceModifyResponse(ctx, gnb, msg)
		}
	case ProcUEContextReleaseRequest:
		if msg.Type == 0 { // InitiatingMessage from gNB
			s.handleUEContextReleaseRequest(ctx, gnb, msg)
		}
	case ProcUEContextRelease:
		if msg.Type == 1 { // SuccessfulOutcome (Release Complete from gNB)
			s.handleUEContextReleaseComplete(ctx, gnb, msg)
		}
	case ProcErrorIndication:
		// gNB signals a protocol error (e.g. DL NAS Transport on an already-released UE).
		// Log and continue — no recovery action needed at this layer.
		// Ref: TS 38.413 §8.1
		errInd, _ := msg.Value.(*ErrorIndicationMsg)
		errIndFields := []any{
			"procedure", "ErrorIndication",
			"interface", "N2",
			"direction", "IN",
			"gnb_addr", gnb.Conn.RemoteAddr().String(),
			"spec_ref", "TS 38.413 §8.1",
		}
		if errInd != nil {
			if errInd.AMFUENGAPId != 0 {
				errIndFields = append(errIndFields, "amf_ue_ngap_id", errInd.AMFUENGAPId)
			}
			if errInd.RANUENGAPId != 0 {
				errIndFields = append(errIndFields, "ran_ue_ngap_id", errInd.RANUENGAPId)
			}
			if errInd.CausePresent != 0 {
				errIndFields = append(errIndFields, "cause_present", errInd.CausePresent, "cause_value", errInd.CauseValue)
			}
		}
		log.Warn("Error Indication received from gNB", errIndFields...)
	case ProcPathSwitchRequest:
		if msg.Type == 0 { // InitiatingMessage from target gNB
			s.handlePathSwitchRequest(ctx, gnb, msg)
		}
	case ProcHandoverPreparation:
		if msg.Type == 0 { // InitiatingMessage: HandoverRequired from source gNB
			s.handleHandoverRequired(ctx, gnb, msg)
		}
	case ProcHandoverResourceAllocation:
		if msg.Type == 1 { // SuccessfulOutcome: HandoverRequestAcknowledge from target gNB
			s.handleHandoverRequestAcknowledge(ctx, gnb, msg)
		}
	case ProcHandoverNotification:
		if msg.Type == 0 { // InitiatingMessage: HandoverNotify from target gNB
			s.handleHandoverNotify(ctx, gnb, msg)
		}
	default:
		log.Warn("unhandled NGAP procedure", "proc", msg.ProcedureCode)
	}
}

// handlePDUSessionResourceSetupResponse processes the gNB's confirmation that
// PDU session resources have been set up. Extracts the gNB's GTP-U tunnel info
// and notifies the SMF so it can update PFCP with the DL TEID.
// Ref: TS 38.413 §8.4.1
func (s *Server) handlePDUSessionResourceSetupResponse(ctx context.Context, gnb *GNBContext, msg *Message) {
	resp, ok := msg.Value.(*PDUSessionResourceSetupResponseMsg)
	if !ok || s.onPDUSessionSetup == nil {
		return
	}

	ue, ok := s.mgr.GetByNGAPId(resp.AMFUENGAPId)
	if !ok {
		s.logger.Error("PDUSessionResourceSetupResponse: UE not found",
			"amf_ue_ngap_id", resp.AMFUENGAPId)
		return
	}

	for _, setup := range resp.Setups {
		ue.Lock()
		pduSess, hasSess := ue.PDUSessions[setup.PDUSessionID]
		var smContextRef string
		if hasSess {
			smContextRef = pduSess.SMFInstanceID
		}
		ue.Unlock()

		if smContextRef == "" {
			s.logger.Warn("PDUSessionResourceSetupResponse: no smContextRef",
				"pdu_session_id", setup.PDUSessionID)
			continue
		}

		s.logger.Info("PDU session resources confirmed by gNB, notifying SMF",
			"procedure", "PDUSessionEstablishment",
			"interface", "N2",
			"direction", "IN",
			"spec_ref", "TS 38.413 §8.4.1",
			"pdu_session_id", setup.PDUSessionID,
			"smContextRef", smContextRef,
		)
		go s.onPDUSessionSetup(ctx, smContextRef, setup.N2SMTransferBytes)
	}
}

// ---- PDU Session Resource Release Response (TS 38.413 §8.4.2) -----------

func (s *Server) handlePDUSessionResourceReleaseResponse(ctx context.Context, gnb *GNBContext, msg *Message) {
	resp, ok := msg.Value.(*PDUSessionResourceReleaseResponseMsg)
	if !ok {
		return
	}
	s.logger.Info("PDU Session Resource Release confirmed by gNB",
		"procedure", "PDUSessionRelease",
		"interface", "N2",
		"direction", "IN",
		"message_type", "PDUSessionResourceReleaseResponse",
		"amf_ue_ngap_id", resp.AMFUENGAPId,
		"spec_ref", "TS 38.413 §8.4.2",
	)
	if s.onPDUSessionRelease != nil {
		s.onPDUSessionRelease(ctx, resp.AMFUENGAPId)
	}
}

// ---- NG Setup (TS 38.413 §8.7.1) ----------------------------------------

// handleNGSetup processes the NG Setup Request from the gNB.
func (s *Server) handleNGSetup(ctx context.Context, gnb *GNBContext, msg *Message) {
	log := s.logger.With(
		"procedure", "NGSetup",
		"interface", "N2",
		"direction", "IN",
		"message_type", "NGSetupRequest",
		"spec_ref", "TS 38.413 §8.7.1",
	)
	req, ok := msg.Value.(*NGSetupRequest)
	if !ok {
		log.Error("NGSetupRequest body decode failed")
		return
	}
	gnb.mu.Lock()
	gnb.GlobalGNBID = req.GlobalRANNodeID
	gnb.Name = req.RANNodeName
	gnb.SupportedTAs = req.SupportedTAList
	gnb.mu.Unlock()

	log.Info("NG Setup Request received",
		"gnb_name", req.RANNodeName,
		"result", "OK",
	)
	log.Info("sending NG Setup Response",
		"direction", "OUT",
		"message_type", "NGSetupResponse",
	)

	resp := BuildNGSetupResponse(s.cfg.Name, s.cfg.MCC, s.cfg.MNC,
		s.cfg.RegionID, s.cfg.SetID, s.cfg.AMFID, s.cfg.SNSSAIs)
	if _, err := gnb.Conn.Write(resp); err != nil {
		log.Error("send NG Setup Response failed", "error", err)
	}
}

// ---- Initial UE Message (TS 38.413 §8.6.1) ------------------------------

// handleInitialUEMessage processes the first NAS message from a UE on a new
// SCTP stream. Two cases:
//   - Fresh registration: no 5G-S-TMSI IE → allocate new UE context.
//   - Service Request (CM-IDLE → CM-CONNECTED): 5G-S-TMSI present → look up
//     existing UE context and re-use the stored security context.
//
// Ref: TS 38.413 §8.6.1, TS 23.502 §4.2.3
func (s *Server) handleInitialUEMessage(ctx context.Context, gnb *GNBContext, msg *Message) {
	req, ok := msg.Value.(*InitialUEMessage)
	if !ok {
		s.logger.Error("InitialUEMessage body decode failed")
		return
	}

	// Returning UE path: 5G-S-TMSI present AND NAS PDU is not a plain Initial
	// Registration Request. UERANSIM always includes 5G-S-TMSI in InitialUEMessage
	// even for Service Requests and secured Registration Updates (Periodic/Mobility).
	// Plain Initial Registration (SHT=0x00, MT=0x41) always starts fresh.
	// Service Requests and security-protected Registration Updates (SHT≠0x00) reach
	// an existing UE context; the NAS handler dispatches further based on message type.
	// Ref: TS 24.501 §5.5.1.2.1, §5.6.1.1; TS 38.413 §8.6.1
	isPlainRegistrationRequest := len(req.NASPdu) >= 3 &&
		req.NASPdu[0] == 0x7E &&
		req.NASPdu[1]&0x0F == 0x00 &&
		req.NASPdu[2] == 0x41

	if req.FiveGSTMSI != nil && !isPlainRegistrationRequest {
		if ue, found := s.mgr.GetByTMSI(*req.FiveGSTMSI); found {
			// Update N2 context for the new gNB radio connection.
			ue.Lock()
			ue.RANUENGAPId = req.RANUENGAPId
			ue.GNBAddr = gnb.Conn.RemoteAddr().String()
			if req.TAI != nil {
				ue.TAI = amfctx.TAI{MCC: req.TAI.MCC, MNC: req.TAI.MNC, TAC: req.TAI.TAC}
			}
			ue.CMState = amfctx.CMConnected
			// UE is reconnecting — cancel Mobile Reachable and Implicit Detach timers.
			// Ref: TS 23.501 §5.3.2
			ue.StopAllTimers()
			ue.Unlock()

			// Promote from IdleUEs back to active UEs (old RAN ID may differ).
			gnb.mu.Lock()
			for ranID, idle := range gnb.IdleUEs {
				if idle == ue {
					delete(gnb.IdleUEs, ranID)
					break
				}
			}
			gnb.UEs[req.RANUENGAPId] = ue
			gnb.mu.Unlock()

			s.logger.Info("returning CM-IDLE UE — routing to NAS handler",
				"interface", "N2",
				"direction", "IN",
				"message_type", "InitialUEMessage",
				"ran_ue_ngap_id", req.RANUENGAPId,
				"amf_ue_ngap_id", ue.AMFUENGAPId,
				"supi", ue.SUPI,
				"tmsi", fmt.Sprintf("%08x", *req.FiveGSTMSI),
				"spec_ref", "TS 23.502 §4.2.3 / §4.2.2.2.3 / §4.2.2.2.4",
			)
			if err := s.nasHandler.HandleNASMessage(ctx, ue, req.NASPdu); err != nil {
				s.logger.Error("NAS handler error (returning UE)", "error", err,
					"amf_ue_ngap_id", ue.AMFUENGAPId)
			}
			return
		}
		// TMSI not found (AMF restarted or context evicted). Send Service Reject
		// cause 0x09 ("UE identity cannot be derived by the network") to force the
		// UE to start a fresh Initial Registration.
		// Ref: TS 24.501 §5.6.1.5.2, §9.11.3.2; TS 24.501 §8.2.17
		s.logger.Warn("Service Request: TMSI not found — sending ServiceReject",
			"tmsi", fmt.Sprintf("%08x", *req.FiveGSTMSI),
			"spec_ref", "TS 24.501 §5.6.1.5.2",
		)
		// Allocate a temporary context just to supply AMF UE NGAP ID for the NGAP PDU.
		tempUE := s.mgr.AllocateUEContext(req.RANUENGAPId)
		gnb.mu.Lock()
		gnb.UEs[req.RANUENGAPId] = tempUE
		gnb.mu.Unlock()
		// Plain NAS PDU: EPD=0x7E | SHT=0x00 | MT=0x4D (ServiceReject) | Cause=0x09
		rejectPDU := []byte{0x7E, 0x00, 0x4D, 0x09}
		if _, err := gnb.Conn.Write(BuildDownlinkNASTransport(tempUE.AMFUENGAPId, req.RANUENGAPId, rejectPDU)); err != nil {
			s.logger.Error("send ServiceReject failed", "error", err)
		}
		gnb.mu.Lock()
		delete(gnb.UEs, req.RANUENGAPId)
		gnb.mu.Unlock()
		s.mgr.Remove(ctx, tempUE)
		return
	}

	// Fresh registration path.
	ue := s.mgr.AllocateUEContext(req.RANUENGAPId)
	corrID := logging.CorrelationID(ctx)
	if corrID == "" {
		corrID = fmt.Sprintf("init-reg-%d", req.RANUENGAPId)
	}

	log := s.logger.With(
		"procedure", "InitialRegistration",
		"interface", "N2",
		"direction", "IN",
		"message_type", "InitialUEMessage",
		"ran_ue_ngap_id", req.RANUENGAPId,
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"correlation_id", corrID,
		"spec_ref", "TS 38.413 §8.6.1",
	)
	log.Info("Initial UE Message received")

	// Pin this UE to its serving gNB by address. RANUENGAPId is only unique
	// per gNB, so routing by it across multiple gNBs is non-deterministic when
	// two gNBs happen to assign the same RAN-local ID to different UEs.
	ue.GNBAddr = gnb.Conn.RemoteAddr().String()
	gnb.mu.Lock()
	gnb.UEs[req.RANUENGAPId] = ue
	gnb.mu.Unlock()

	// Store gNB association and TAI
	if req.TAI != nil {
		ue.TAI = amfctx.TAI{MCC: req.TAI.MCC, MNC: req.TAI.MNC, TAC: req.TAI.TAC}
	}

	// Hand NAS PDU to NAS handler
	if err := s.nasHandler.HandleNASMessage(ctx, ue, req.NASPdu); err != nil {
		log.Error("NAS handler error", "error", err)
	}
}

// ---- Uplink NAS Transport (TS 38.413 §8.6.3) ----------------------------

func (s *Server) handleUplinkNASTransport(ctx context.Context, gnb *GNBContext, msg *Message) {
	req, ok := msg.Value.(*UplinkNASTransport)
	if !ok {
		s.logger.Error("UplinkNASTransport decode failed")
		return
	}
	ue, found := s.mgr.GetByNGAPId(req.AMFUENGAPId)
	if !found {
		s.logger.Warn("UplinkNASTransport for unknown AMF UE NGAP ID",
			"amf_ue_ngap_id", req.AMFUENGAPId)
		return
	}

	// Drop NAS messages on a context that is pending N2 release (deregistration
	// in progress). The UE may send a new Registration Request immediately after
	// receiving the Deregistration Accept but before the gNB issues RRC Release.
	// Processing it here would start a new auth flow on the old NGAP ID, which
	// the gNB will reject with ErrorIndication once it releases the UE context.
	// The UE will re-register cleanly after the RRC Release.
	// Ref: TS 23.502 §4.2.2.3.2, TS 38.413 §8.3.5
	ue.Lock()
	pending := ue.PendingRemoval
	ue.Unlock()
	if pending {
		s.logger.Info("UplinkNASTransport dropped — UE context pending N2 release",
			"procedure", "Deregistration",
			"interface", "N2",
			"direction", "IN",
			"message_type", "UplinkNASTransport",
			"amf_ue_ngap_id", req.AMFUENGAPId,
			"supi", ue.SUPI,
			"spec_ref", "TS 23.502 §4.2.2.3.2",
		)
		return
	}

	s.logger.Info("Uplink NAS Transport",
		"procedure", "NASTransport",
		"interface", "N2",
		"direction", "IN",
		"message_type", "UplinkNASTransport",
		"amf_ue_ngap_id", req.AMFUENGAPId,
		"supi", ue.SUPI,
	)
	if err := s.nasHandler.HandleNASMessage(ctx, ue, req.NASPdu); err != nil {
		s.logger.Error("NAS handler error", "error", err,
			"amf_ue_ngap_id", req.AMFUENGAPId)
	}
}

// findGNBForUE returns the GNBContext serving the given UE using a direct
// address lookup. RANUENGAPId is gNB-local and not globally unique — routing
// by scanning all gNBs is non-deterministic when two gNBs assign the same ID.
// GNBAddr is set at UE context creation (handleInitialUEMessage) and updated
// on every handover, so it always points to the current serving gNB.
func (s *Server) findGNBForUE(ue *amfctx.UEContext) *GNBContext {
	ue.Lock()
	addr := ue.GNBAddr
	ue.Unlock()
	if addr == "" {
		return nil
	}
	s.mu.RLock()
	gnb := s.gnbs[addr]
	s.mu.RUnlock()
	return gnb
}

// ---- Send Downlink NAS Transport ----------------------------------------

// SendDownlinkNASTransport sends a NAS PDU to the UE via the gNB.
// Ref: TS 38.413 §8.6.2
func (s *Server) SendDownlinkNASTransport(ue *amfctx.UEContext, nasPDU []byte) error {
	gnb := s.findGNBForUE(ue)
	if gnb == nil {
		return fmt.Errorf("ngap: no gNB found for UE %d", ue.RANUENGAPId)
	}

	pdu := BuildDownlinkNASTransport(ue.AMFUENGAPId, ue.RANUENGAPId, nasPDU)
	s.logger.Info("Downlink NAS Transport",
		"procedure", "NASTransport",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "DownlinkNASTransport",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"spec_ref", "TS 38.413 §8.6.2",
	)
	_, err := gnb.Conn.Write(pdu)
	return err
}

// ---- Send Initial Context Setup Request ---------------------------------

// SendInitialContextSetupRequest sends an Initial Context Setup Request to the
// gNB that serves the UE.  It carries KgNB (AS security base key), UE security
// capability bitmaps, and the integrity-protected RegistrationAccept NAS PDU.
// Ref: TS 38.413 §8.3.1
func (s *Server) SendInitialContextSetupRequest(
	ue *amfctx.UEContext,
	nasPDU []byte,
	kgnb [32]byte,
	cipherAlg, integAlg byte,
	encAlgsBitmap, intAlgsBitmap uint16,
) error {
	gnb := s.findGNBForUE(ue)
	if gnb == nil {
		return fmt.Errorf("ngap: no gNB found for UE %d", ue.RANUENGAPId)
	}

	pdu := BuildInitialContextSetupRequest(
		ue.AMFUENGAPId, ue.RANUENGAPId,
		nasPDU, kgnb,
		encAlgsBitmap, intAlgsBitmap,
		s.cfg.MCC, s.cfg.MNC,
		s.cfg.RegionID, s.cfg.SetID, s.cfg.AMFID,
		ue.AllowedNSSAI,
		ue.RFSP,
	)
	s.logger.Info("Initial Context Setup Request",
		"procedure", "InitialRegistration",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "InitialContextSetupRequest",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"rfsp", ue.RFSP,
		"spec_ref", "TS 38.413 §8.3.1",
	)
	_, err := gnb.Conn.Write(pdu)
	return err
}

// SendPDUSessionResourceSetupRequest sends a PDU Session Resource Setup Request to gNB
// Ref: TS 38.413 §8.4.1
func (s *Server) SendPDUSessionResourceSetupRequest(
	ue *amfctx.UEContext,
	pduSessionID uint8,
	nasPDU []byte,
	n2SmInfo []byte,
) error {
	gnb := s.findGNBForUE(ue)
	if gnb == nil {
		return fmt.Errorf("ngap: no gNB found for UE %d", ue.RANUENGAPId)
	}

	// Look up the resolved S-NSSAI for this PDU session
	var sst uint8 = 1
	var sdBytes []byte = []byte{0x00, 0x00, 0x01}
	ue.Lock()
	if sess, ok := ue.PDUSessions[pduSessionID]; ok {
		sst = sess.SNSSAI.SST
		sdBytes = snssaiSDBytes(sess.SNSSAI.SD)
	}
	ue.Unlock()

	pdu := BuildPDUSessionResourceSetupRequest(
		ue.AMFUENGAPId, ue.RANUENGAPId,
		pduSessionID, nasPDU, n2SmInfo,
		sst, sdBytes,
	)

	s.logger.Info("PDU Session Resource Setup Request",
		"procedure", "PDUSessionEstablishment",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "PDUSessionResourceSetupRequest",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"pdu_session_id", pduSessionID,
		"supi", ue.SUPI,
		"spec_ref", "TS 38.413 §8.4.1",
	)

	_, err := gnb.Conn.Write(pdu)
	return err
}

// ---- Send PDU Session Resource Modify Request ---------------------------

// SendPDUSessionResourceModifyRequest sends an NGAP PDU Session Resource Modify Request
// to the gNB serving the UE. The nasPDU must be a secured DL NAS Transport containing
// the 5GSM PDU Session Modification Command. n2SmInfo is the APER-encoded
// PDUSessionResourceModifyRequestTransfer.
// Ref: TS 38.413 §8.2.1
func (s *Server) SendPDUSessionResourceModifyRequest(
	ue *amfctx.UEContext,
	pduSessionID uint8,
	nasPDU []byte,
	n2SmInfo []byte,
) error {
	gnb := s.findGNBForUE(ue)
	if gnb == nil {
		return fmt.Errorf("ngap: no gNB found for UE %d", ue.RANUENGAPId)
	}

	pdu := BuildPDUSessionResourceModifyRequest(
		ue.AMFUENGAPId, ue.RANUENGAPId,
		pduSessionID, nasPDU, n2SmInfo,
	)
	if pdu == nil {
		return fmt.Errorf("ngap: BuildPDUSessionResourceModifyRequest returned nil")
	}

	s.logger.Info("PDU Session Resource Modify Request",
		"procedure", "PDUSessionModification",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "PDUSessionResourceModifyRequest",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"pdu_session_id", pduSessionID,
		"supi", ue.SUPI,
		"spec_ref", "TS 38.413 §8.2.1",
	)
	_, err := gnb.Conn.Write(pdu)
	return err
}

// handlePDUSessionResourceModifyResponse processes the gNB's confirmation that
// PDU session resources have been modified.
// Ref: TS 38.413 §8.2.1
func (s *Server) handlePDUSessionResourceModifyResponse(ctx context.Context, gnb *GNBContext, msg *Message) {
	resp, ok := msg.Value.(*PDUSessionResourceModifyResponseMsg)
	if !ok {
		return
	}
	s.logger.Info("PDU Session Resource Modify confirmed by gNB",
		"procedure", "PDUSessionModification",
		"interface", "N2",
		"direction", "IN",
		"message_type", "PDUSessionResourceModifyResponse",
		"amf_ue_ngap_id", resp.AMFUENGAPId,
		"spec_ref", "TS 38.413 §8.2.1",
	)
}

// ---- Send PDU Session Resource Release Command --------------------------

// SendPDUSessionResourceReleaseCommand sends an NGAP PDU Session Resource Release Command
// to the gNB serving the UE. The nasPDU must be a secured DL NAS Transport containing
// the 5GSM PDU Session Release Command.
// Ref: TS 38.413 §8.4.2
func (s *Server) SendPDUSessionResourceReleaseCommand(ue *amfctx.UEContext, pduSessionID uint8, nasPDU []byte) error {
	gnb := s.findGNBForUE(ue)
	if gnb == nil {
		return fmt.Errorf("ngap: no gNB found for UE %d", ue.RANUENGAPId)
	}

	pdu := BuildPDUSessionResourceReleaseCommand(ue.AMFUENGAPId, ue.RANUENGAPId, pduSessionID, nasPDU)
	s.logger.Info("PDU Session Resource Release Command",
		"procedure", "PDUSessionRelease",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "PDUSessionResourceReleaseCommand",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"pdu_session_id", pduSessionID,
		"supi", ue.SUPI,
		"spec_ref", "TS 38.413 §8.4.2",
	)
	_, err := gnb.Conn.Write(pdu)
	return err
}

// SendUEContextReleaseCommandForUE sends a UE Context Release Command to the gNB
// that is currently serving the given UE. Used for AMF-initiated releases such as
// network-side deregistration and UE deregistration while CM-CONNECTED.
// If the UE is already CM-IDLE (no gNB entry), this is a no-op.
// Ref: TS 38.413 §8.3.5
func (s *Server) SendUEContextReleaseCommandForUE(ue *amfctx.UEContext, causePresent int, causeValue int64) error {
	gnb := s.findGNBForUE(ue)
	if gnb == nil {
		// UE is already CM-IDLE or not tracked — no N2 connection to release.
		// This is normal when the gNB initiated AN Release before deregistration
		// reached this point, or when the SCTP association is already gone.
		s.logger.Info("UE Context Release Command skipped — UE already CM-IDLE or no gNB",
			"procedure", "ANRelease",
			"interface", "N2",
			"direction", "OUT",
			"amf_ue_ngap_id", ue.AMFUENGAPId,
			"supi", ue.SUPI,
			"spec_ref", "TS 38.413 §8.3.5",
		)
		return nil
	}
	if err := s.SendUEContextReleaseCommand(gnb, ue.AMFUENGAPId, ue.RANUENGAPId, causePresent, causeValue); err != nil {
		return err
	}
	// Arm the PendingRemoval watchdog if the UE context is being torn down (deregistration,
	// NW-initiated release). The caller must set ue.PendingRemoval = true BEFORE calling
	// this function so that the watchdog is always armed when needed.
	// Ref: TS 38.413 §8.3.5
	ue.Lock()
	pending := ue.PendingRemoval
	ue.Unlock()
	if pending {
		s.startPendingRemovalTimer(ue)
	}
	return nil
}

// SendPaging emits an NGAP Paging for a CM-IDLE UE to every connected gNB whose
// supported Tracking Areas cover the UE's registration TAI. If no connected gNB
// advertises that TAC, the Paging is broadcast to all connected gNBs as a best
// effort (the UE may have moved within the registration area).
// Ref: TS 38.413 §9.2.8, TS 23.502 §4.2.3.3 step 4a.
func (s *Server) SendPaging(ue *amfctx.UEContext) error {
	ue.Lock()
	guti := ue.GUTI
	tai := ue.TAI
	supi := ue.SUPI
	ue.Unlock()

	if guti == nil {
		return fmt.Errorf("amf: paging %s: no GUTI/5G-TMSI assigned", supi)
	}

	plmn := plmnFromMCCMNC(tai.MCC, tai.MNC)
	if tai.MCC == "" {
		plmn = plmnFromMCCMNC(s.cfg.MCC, s.cfg.MNC)
	}
	tais := []TAIForPaging{{PLMN: plmn, TAC: tai.TAC}}
	pdu := BuildPaging(s.cfg.SetID, s.cfg.AMFID, guti.TMSI, tais)
	if pdu == nil {
		return fmt.Errorf("amf: paging %s: encode failed", supi)
	}

	s.mu.RLock()
	gnbs := make([]*GNBContext, 0, len(s.gnbs))
	for _, g := range s.gnbs {
		gnbs = append(gnbs, g)
	}
	s.mu.RUnlock()

	if len(gnbs) == 0 {
		return fmt.Errorf("amf: paging %s: no gNB connected", supi)
	}

	// Prefer gNBs that advertise the UE's TAC.
	var targets []*GNBContext
	for _, g := range gnbs {
		for _, ta := range g.SupportedTAs {
			if ta.TAC == tai.TAC {
				targets = append(targets, g)
				break
			}
		}
	}
	if len(targets) == 0 {
		targets = gnbs // best-effort broadcast
	}

	var sent int
	for _, g := range targets {
		if _, err := g.Conn.Write(pdu); err != nil {
			s.logger.Warn("paging write failed",
				"procedure", "NetworkTriggeredServiceRequest",
				"interface", "N2", "direction", "OUT",
				"supi", supi, "gnb", g.Name, "error", err,
			)
			continue
		}
		sent++
	}
	if sent == 0 {
		return fmt.Errorf("amf: paging %s: no gNB accepted the Paging", supi)
	}

	s.logger.Info("NGAP Paging sent",
		"procedure", "NetworkTriggeredServiceRequest",
		"interface", "N2", "direction", "OUT",
		"supi", supi,
		"tmsi", fmt.Sprintf("%08x", guti.TMSI),
		"tac", tai.TAC,
		"gnbs_paged", sent,
		"spec_ref", "TS 38.413 §9.2.8",
	)
	return nil
}

// ---- UE Context Release (TS 38.413 §8.3.4 and §8.3.5) -------------------

// handleUEContextReleaseRequest processes the gNB's unsolicited UE Context Release
// Request and responds immediately with a UE Context Release Command.
// Ref: TS 38.413 §8.3.4
func (s *Server) handleUEContextReleaseRequest(ctx context.Context, gnb *GNBContext, msg *Message) {
	req, ok := msg.Value.(*UEContextReleaseRequestMsg)
	if !ok {
		s.logger.Error("UEContextReleaseRequest body decode failed")
		return
	}

	ue, found := s.mgr.GetByNGAPId(req.AMFUENGAPId)
	if !found {
		s.logger.Warn("UEContextReleaseRequest: unknown AMF UE NGAP ID",
			"amf_ue_ngap_id", req.AMFUENGAPId)
		return
	}

	s.logger.Info("UE Context Release Request received — sending Command",
		"procedure", "ANRelease",
		"interface", "N2",
		"direction", "IN",
		"message_type", "UEContextReleaseRequest",
		"amf_ue_ngap_id", req.AMFUENGAPId,
		"ran_ue_ngap_id", req.RANUENGAPId,
		"cause_present", req.CausePresent,
		"cause_value", req.CauseValue,
		"supi", ue.SUPI,
		"spec_ref", "TS 38.413 §8.3.4",
	)

	if err := s.SendUEContextReleaseCommand(gnb, req.AMFUENGAPId, req.RANUENGAPId,
		req.CausePresent, req.CauseValue); err != nil {
		s.logger.Error("SendUEContextReleaseCommand failed",
			"amf_ue_ngap_id", req.AMFUENGAPId, "error", err)
	}
}

// handleUEContextReleaseComplete processes the gNB's confirmation that the UE context
// has been released. Transitions the UE to CM-IDLE and notifies the SMF.
// Ref: TS 38.413 §8.3.5
func (s *Server) handleUEContextReleaseComplete(ctx context.Context, gnb *GNBContext, msg *Message) {
	cpl, ok := msg.Value.(*UEContextReleaseCompleteMsg)
	if !ok {
		s.logger.Error("UEContextReleaseComplete body decode failed")
		return
	}

	// Move UE from UEs (CM-CONNECTED) to IdleUEs (CM-IDLE).
	// We keep the UE in IdleUEs so that if the gNB SCTP connection closes before
	// the UE reconnects via Service Request, the defer in handleGNBConn can still
	// find it and clean up its PDU sessions. Using cpl.RANUENGAPId rather than
	// ue.RANUENGAPId avoids a nil-deref if the lookup below fails.
	gnb.mu.Lock()
	if ue, ok := gnb.UEs[cpl.RANUENGAPId]; ok {
		gnb.IdleUEs[cpl.RANUENGAPId] = ue
	}
	delete(gnb.UEs, cpl.RANUENGAPId)
	gnb.mu.Unlock()

	ue, found := s.mgr.GetByNGAPId(cpl.AMFUENGAPId)
	if !found {
		// Context already gone (e.g. manager cleared it). Remove from IdleUEs too.
		gnb.mu.Lock()
		delete(gnb.IdleUEs, cpl.RANUENGAPId)
		gnb.mu.Unlock()
		s.logger.Warn("UEContextReleaseComplete: unknown AMF UE NGAP ID",
			"amf_ue_ngap_id", cpl.AMFUENGAPId)
		return
	}

	// Transition UE to CM-IDLE.
	ue.Lock()
	ue.CMState = amfctx.CMIdle
	pending := ue.PendingRemoval
	ue.Unlock()

	s.logger.Info("UE Context Release Complete — UE is CM-IDLE",
		"procedure", "ANRelease",
		"interface", "N2",
		"direction", "IN",
		"message_type", "UEContextReleaseComplete",
		"amf_ue_ngap_id", cpl.AMFUENGAPId,
		"ran_ue_ngap_id", cpl.RANUENGAPId,
		"supi", ue.SUPI,
		"cm_state", "CM-IDLE",
		"pending_removal", pending,
		"spec_ref", "TS 38.413 §8.3.5",
	)

	if pending {
		// Deregistration: the UE context is being fully torn down; remove from
		// IdleUEs so onGNBDisconnect does not attempt a redundant cleanup.
		// Also stop the PendingRemoval watchdog — the release completed normally.
		gnb.mu.Lock()
		delete(gnb.IdleUEs, cpl.RANUENGAPId)
		gnb.mu.Unlock()

		ue.Lock()
		if ue.PendingRemovalTimer != nil {
			ue.PendingRemovalTimer.Stop()
		}
		ue.Unlock()

		s.mgr.Remove(ctx, ue)
		s.logger.Info("UE context removed after deregistration N2 release",
			"procedure", "Deregistration",
			"amf_ue_ngap_id", cpl.AMFUENGAPId,
			"supi", ue.SUPI,
			"spec_ref", "TS 23.502 §4.2.2.3.2",
		)
		return
	}
	// Normal AN Release: UE stays in IdleUEs so onGNBDisconnect can release
	// its PDU sessions if the gNB SCTP association closes before reconnection.

	// Normal AN Release (no deregistration): notify SMF to deactivate DL forwarding.
	if s.onANRelease != nil {
		s.onANRelease(ctx, ue)
	}

	// Start Mobile Reachable Timer: UE is now CM-IDLE. If it does not reconnect
	// (Service Request or Periodic Registration) before this expires, the AMF
	// will initiate implicit detach.
	// Ref: TS 23.501 §5.3.2
	s.StartMobileReachableTimer(ue)
}

// SendUEContextReleaseCommand sends an NGAP UE Context Release Command to the gNB.
// Used both for AMF-initiated release and as the response to a gNB Release Request.
// Ref: TS 38.413 §8.3.5
func (s *Server) SendUEContextReleaseCommand(gnb *GNBContext, amfUEID, ranUEID int64, causePresent int, causeValue int64) error {
	pdu := BuildUEContextReleaseCommand(amfUEID, ranUEID, causePresent, causeValue)
	if pdu == nil {
		return fmt.Errorf("ngap: BuildUEContextReleaseCommand returned nil")
	}
	s.logger.Info("UE Context Release Command",
		"procedure", "ANRelease",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "UEContextReleaseCommand",
		"amf_ue_ngap_id", amfUEID,
		"ran_ue_ngap_id", ranUEID,
		"spec_ref", "TS 38.413 §8.3.5",
	)
	_, err := gnb.Conn.Write(pdu)
	return err
}

// ---- Stub message types (kept for handler interface compatibility) ------

// NGSetupRequest holds decoded fields from an NG Setup Request.
type NGSetupRequest struct {
	GlobalRANNodeID []byte
	RANNodeName     string
	SupportedTAList []SupportedTA
}

// TAI is a Tracking Area Identity extracted from NGAP IEs.
type TAI struct {
	MCC string
	MNC string
	TAC uint32
}

// InitialUEMessage holds decoded fields from an Initial UE Message.
type InitialUEMessage struct {
	RANUENGAPId int64
	NASPdu      []byte
	TAI         *TAI
	// FiveGSTMSI is present when the UE is known to the network (returning from CM-IDLE).
	// A non-nil value means this is a Service Request, not a fresh registration.
	// The uint32 value is the 5G-TMSI extracted from the 5G-S-TMSI IE.
	// Ref: TS 38.413 §9.3.3.5, TS 23.502 §4.2.3
	FiveGSTMSI *uint32
}

// UplinkNASTransport holds decoded fields from an Uplink NAS Transport.
type UplinkNASTransport struct {
	AMFUENGAPId int64
	RANUENGAPId int64
	NASPdu      []byte
}
