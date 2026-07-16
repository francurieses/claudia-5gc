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
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// NGAP Cause values for releasing the logical NGAP connection after the AMF
// rejects an initial NAS message it cannot associate with a UE context.
// Ref: TS 38.413 §9.3.1.2 (Cause), Table 9.3.1.2-1.
const (
	ngapCausePresentNas             = 3 // ngapType.CausePresentNas
	ngapCauseNasNormalRelease int64 = 0 // ngapType.CauseNasPresentNormalRelease
)

// rejectForUnknownTMSI picks the NAS reject for an initial NAS message whose
// 5G-GUTI the AMF has no context for (typically: the AMF restarted and purged
// its contexts). It returns the plain NAS PDU, plus a name and spec reference
// for logging.
//
// The reject must match the procedure the UE actually started. A UE in
// 5GMM-REGISTERED-INITIATED discards a SERVICE REJECT as "message not
// compatible with protocol state" and retries on T3512 forever, so answering
// every unknown TMSI with a Service Reject deadlocks any UE doing a mobility or
// periodic registration update.
//
// Ref: TS 24.501 §5.5.1.3.5, §5.6.1.5.2, §9.11.3.2.
func rejectForUnknownTMSI(msgType nas.MessageType, typeKnown bool) (pdu []byte, name, specRef string) {
	if typeKnown && msgType == nas.MsgTypeRegistrationRequest {
		// Mobility/periodic registration update with a 5G-GUTI the AMF has no
		// context for. 5GMM cause #10 states exactly what happened — the network
		// implicitly de-registered the UE — and per TS 24.501 §5.5.1.3.5 the UE
		// then enters 5GMM-DEREGISTERED.NORMAL-SERVICE and performs a fresh
		// initial registration with its SUCI, which the AMF can resolve.
		// Plain NAS: EPD | SHT=0x00 | MT=0x44 (RegistrationReject) | cause
		return []byte{nas.PDMobilityManagement, 0x00,
			byte(nas.MsgTypeRegistrationReject), byte(nas.CauseImplicitlyDeregistered)},
			"RegistrationReject", "TS 24.501 §5.5.1.3.5"
	}
	// Service Request / Control Plane Service Request, or a type that could not
	// be read (ciphered inner header). 5GMM cause #9 "UE identity cannot be
	// derived by the network" makes the UE clear its stale GUTI and re-register.
	// Plain NAS: EPD | SHT=0x00 | MT=0x4D (ServiceReject) | cause
	return []byte{nas.PDMobilityManagement, 0x00,
		byte(nas.MsgTypeServiceReject), byte(nas.CauseUEIdentityNotDerived)},
		"ServiceReject", "TS 24.501 §5.6.1.5.2"
}

// nasMessageTypeName renders a peeked 5GMM message type for logging. Only the
// types that can open an N1 connection with a 5G-GUTI are named; anything else
// is reported by value so an unexpected initial message is still diagnosable.
// Ref: TS 24.501 §9.7.
func nasMessageTypeName(t nas.MessageType, known bool) string {
	if !known {
		return "UNREADABLE" // ciphered or malformed inner header
	}
	switch t {
	case nas.MsgTypeRegistrationRequest:
		return "RegistrationRequest"
	case nas.MsgTypeServiceRequest:
		return "ServiceRequest"
	case nas.MsgTypeControlPlaneServiceRequest:
		return "ControlPlaneServiceRequest"
	case nas.MsgTypeDeregistrationRequestUE:
		return "DeregistrationRequestUE"
	default:
		return fmt.Sprintf("0x%02X", byte(t))
	}
}

// ngapPPID is the SCTP Payload Protocol Identifier for NGAP.
// TS 38.412 §7 / IANA: PPID 60 (0x3C) is assigned to NGAP over SCTP.
// The ishidawataru/sctp library applies htonl internally so we pass 60 in host byte order.
const ngapPPID uint32 = 60

// writeNGAP sends an NGAP PDU over the SCTP connection with PPID=60 set on the DATA chunk.
// Using PPID=0 (plain conn.Write) means the gNB/Wireshark cannot identify the protocol;
// PPID=60 is mandatory per TS 38.412 §7.
// Ref: TS 38.412 §7; IANA "Stream Control Transmission Protocol (SCTP) Parameters".
func writeNGAP(conn *sctp.SCTPConn, pdu []byte) (int, error) {
	return conn.SCTPWrite(pdu, &sctp.SndRcvInfo{PPID: ngapPPID})
}

// NRPPaResult is the result of an NGAP Downlink/Uplink UE-Associated NRPPa
// Transport exchange. Delivered to the Namf_Location dl-nrppa-info handler via a
// channel keyed by AMF-UE-NGAP-ID in the Server's pendingNRPPa map.
//
// The AMF is a pure relay: it does NOT decode the NRPPa-PDU bytes.
// Ref: TS 38.413 §8.17.3; TS 23.273 §7.2 step C; TS 29.518 §5.2.2.6.
type NRPPaResult struct {
	// NRPPaPDU is the opaque UL NRPPa PDU bytes received from the gNB.
	// The LMF decodes this; the AMF never inspects its content.
	NRPPaPDU []byte
	// RoutingID is the LMF routing identity extracted from the UL transport message.
	// Ref: TS 38.413 §9.3.x (Routing ID IE, id=89).
	RoutingID []byte
	// Err is non-nil on correlation failure, gNB disconnect, or timeout expiry.
	Err error
}

// LocationResult is the result of an NGAP LocationReportingControl/LocationReport
// exchange. Delivered to the Namf_Location handler via a channel keyed by
// AMF-UE-NGAP-ID in the Server's pendingLoc map.
// Ref: TS 38.413 §8.17.1; TS 29.518 §5.2.2.6.
type LocationResult struct {
	// NRCellID is the serving NR cell rendered as a 9-char hex string (36-bit cell id).
	// Ref: TS 38.413 §9.3.1.x, TS 29.572 §6.1.6.2.2.
	NRCellID string
	// TAI is the Tracking Area Identity reported by the gNB.
	TAI *TAI
	// Err is non-nil when the gNB could not provide a location (failure or timeout).
	Err error
}

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
	// UE Radio Capability Info Indication (gNB→AMF, InitiatingMessage, class 2).
	// Sent after the UE context is established so the AMF can store the UE's radio
	// capabilities for later use (e.g. HandoverRequest). No response is expected.
	// Ref: TS 38.413 Table 9.1-1, §8.7.6.
	ProcUERadioCapabilityInfoIndication ProcedureCode = 44
	// ProcLocationReportingControl is the procedure code for LocationReportingControl
	// (AMF→gNB, InitiatingMessage). Ref: TS 38.413 Table 9.1-1, §8.17.1.
	ProcLocationReportingControl ProcedureCode = 16
	// ProcLocationReport is the procedure code for LocationReport
	// (gNB→AMF, InitiatingMessage). Ref: TS 38.413 Table 9.1-1, §8.17.1.
	ProcLocationReport ProcedureCode = 18
	// TS 38.413 Table 9.1.1-1: ErrorIndication has procedure code 9.
	ProcErrorIndication ProcedureCode = 9

	// ProcDownlinkNonUEAssociatedNRPPaTransport is the NGAP procedure code for
	// Downlink Non-UE-Associated NRPPa Transport (AMF→gNB, InitiatingMessage).
	// Used for cell-level NRPPa signalling not tied to a specific UE context (e.g.
	// PositioningInformationRequest in some deployments).
	// Integer value 5 confirmed from TS 38.413 Table 9.1-1 and free5gc ngapType.
	// Ref: TS 38.413 §8.17.4.
	ProcDownlinkNonUEAssociatedNRPPaTransport ProcedureCode = 5

	// ProcDownlinkUEAssociatedNRPPaTransport is the NGAP procedure code for
	// Downlink UE-Associated NRPPa Transport (AMF→gNB, InitiatingMessage).
	// Used when the NRPPa exchange is scoped to a specific UE context (E-CID,
	// PositioningInformationRequest tied to a UE).
	// Integer value 8 confirmed from TS 38.413 Table 9.1-1 and free5gc ngapType.
	// Ref: TS 38.413 §8.17.3.
	ProcDownlinkUEAssociatedNRPPaTransport ProcedureCode = 8

	// ProcUplinkNonUEAssociatedNRPPaTransport is the NGAP procedure code for
	// Uplink Non-UE-Associated NRPPa Transport (gNB→AMF, InitiatingMessage).
	// Integer value 47 confirmed from TS 38.413 Table 9.1-1 and free5gc ngapType.
	// Ref: TS 38.413 §8.17.4.
	ProcUplinkNonUEAssociatedNRPPaTransport ProcedureCode = 47

	// ProcUplinkUEAssociatedNRPPaTransport is the NGAP procedure code for
	// Uplink UE-Associated NRPPa Transport (gNB→AMF, InitiatingMessage).
	// Integer value 50 confirmed from TS 38.413 Table 9.1-1 and free5gc ngapType.
	// Ref: TS 38.413 §8.17.3.
	ProcUplinkUEAssociatedNRPPaTransport ProcedureCode = 50
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

	// onPDUSessionSetupFailure is called for each PDU session the gNB reports in
	// PDUSessionResourceFailedToSetupListSURes so the SM context is released at
	// the SMF (frees the UE IP and the PFCP session).
	// Ref: TS 38.413 §8.4.1, TS 23.502 §4.3.2.2.1 step 16
	onPDUSessionSetupFailure func(ctx context.Context, smContextRef string)

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

	// pendingLoc holds one pending LocationResult channel per AMF-UE-NGAP-ID.
	// Inserted by SendLocationReportingControl; resolved (and deleted) by
	// handleLocationReport when the matching LocationReport arrives.
	// Ref: TS 38.413 §8.17.1; TS 29.518 §5.2.2.6.
	pendingLoc sync.Map // map[int64]chan LocationResult

	// pendingNRPPa holds one pending NRPPaResult channel per AMF-UE-NGAP-ID.
	// Inserted by SendDownlinkNRPPa; resolved (and deleted) by handleUplinkNRPPa
	// when the matching UplinkUEAssociatedNRPPaTransport arrives from the gNB.
	// Unmatched UL NRPPa PDUs (no pending entry) are logged as nrppa_orphan and dropped.
	// Ref: TS 38.413 §8.17.3; TS 29.518 §5.2.2.6; TS 23.273 §7.2 step C.
	pendingNRPPa sync.Map // map[int64]chan NRPPaResult

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

// SetPDUSessionSetupFailureHandler registers a callback invoked per PDU session
// the gNB failed to set up (FailedToSetupListSURes). Wire it to the SMF
// DeleteSMContext client so the session's resources are freed.
// Ref: TS 38.413 §8.4.1, TS 23.502 §4.3.2.2.1 step 16
func (s *Server) SetPDUSessionSetupFailureHandler(fn func(ctx context.Context, smContextRef string)) {
	s.onPDUSessionSetupFailure = fn
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
		// Decode and route NGAP messages in SCTP arrival order. Handlers that
		// can block on SBI calls (NAS procedures → AUSF/UDM/SMF) enqueue the
		// blocking work on the target UE's serial queue (UEContext.EnqueueSerial)
		// so one slow SBI call cannot delay other UEs' NGAP messages, while
		// per-UE NAS ordering (notably SecurityCtx.UplinkCount) is preserved.
		// A bare goroutine-per-message would race on that per-UE state when the
		// UE sends back-to-back messages such as RegistrationComplete + UL NAS
		// Transport — do not replace the queue with `go s.dispatch`.
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
	case ProcInitialContextSetup:
		if msg.Type == 1 { // SuccessfulOutcome: ICS Response from gNB
			s.handleInitialContextSetupResponse(ctx, gnb, msg)
		} else if msg.Type == 2 { // UnsuccessfulOutcome: ICS Failure from gNB
			s.handleInitialContextSetupFailure(ctx, gnb, msg)
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
	case ProcLocationReport:
		if msg.Type == 0 { // InitiatingMessage: LocationReport from gNB
			// Ref: TS 38.413 §8.17.1 (Location Report)
			s.handleLocationReport(ctx, gnb, msg)
		}
	case ProcUplinkUEAssociatedNRPPaTransport:
		if msg.Type == 0 { // InitiatingMessage from gNB
			// Ref: TS 38.413 §8.17.3 (Uplink UE Associated NRPPa Transport)
			s.handleUplinkUEAssociatedNRPPa(ctx, gnb, msg)
		}
	case ProcUplinkNonUEAssociatedNRPPaTransport:
		if msg.Type == 0 { // InitiatingMessage from gNB
			// Ref: TS 38.413 §8.17.4 (Uplink Non UE Associated NRPPa Transport)
			s.handleUplinkNonUEAssociatedNRPPa(ctx, gnb, msg)
		}
	case ProcUERadioCapabilityInfoIndication:
		if msg.Type == 0 { // InitiatingMessage from gNB
			// Ref: TS 38.413 §8.7.6 (UE Radio Capability Info Indication)
			s.handleUERadioCapabilityInfoIndication(ctx, gnb, msg)
		}
	default:
		log.Warn("unhandled NGAP procedure", "proc", msg.ProcedureCode)
	}
}

// handlePDUSessionResourceSetupResponse processes the gNB's confirmation that
// PDU session resources have been set up. Extracts the gNB's GTP-U tunnel info
// and notifies the SMF so it can update PFCP with the DL TEID. Sessions in the
// FailedToSetupListSURes are released at the SMF and removed from the UE
// context — leaving them would strand the UE IP / PFCP session and permanently
// block the PSI. Ref: TS 38.413 §8.4.1, TS 23.502 §4.3.2.2.1 step 16.
func (s *Server) handlePDUSessionResourceSetupResponse(ctx context.Context, gnb *GNBContext, msg *Message) {
	resp, ok := msg.Value.(*PDUSessionResourceSetupResponseMsg)
	if !ok {
		return
	}

	ue, ok := s.mgr.GetByNGAPId(resp.AMFUENGAPId)
	if !ok {
		s.logger.Error("PDUSessionResourceSetupResponse: UE not found",
			"amf_ue_ngap_id", resp.AMFUENGAPId)
		return
	}

	for _, psi := range resp.FailedPSIs {
		ue.Lock()
		pduSess, hasSess := ue.PDUSessions[psi]
		var smContextRef string
		if hasSess {
			smContextRef = pduSess.SMFInstanceID
			delete(ue.PDUSessions, psi)
		}
		ue.Unlock()

		s.logger.Warn("PDU Session Resource Setup failed at gNB — releasing session",
			"procedure", "PDUSessionEstablishment",
			"interface", "N2",
			"direction", "IN",
			"message_type", "PDUSessionResourceSetupResponse",
			"amf_ue_ngap_id", resp.AMFUENGAPId,
			"pdu_session_id", psi,
			"smContextRef", smContextRef,
			"supi", ue.SUPI,
			"result", "FAILURE",
			"spec_ref", "TS 38.413 §8.4.1, TS 23.502 §4.3.2.2.1 step 16",
		)
		if smContextRef != "" && s.onPDUSessionSetupFailure != nil {
			go s.onPDUSessionSetupFailure(ctx, smContextRef)
		}
	}

	if s.onPDUSessionSetup == nil {
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

// handleInitialContextSetupResponse processes the gNB's Initial Context Setup
// Response. When the ICS Request carried PDUSessionResourceSetupListCxtReq
// (Service Request UP re-activation), the response's CxtRes list holds the
// gNB's DL GTP-U tunnel info per session — forward each transfer to the SMF so
// it re-activates DL forwarding at the UPF (same path as the standalone PDU
// Session Resource Setup Response). A response without a session list
// (Initial Registration) needs no action.
// Ref: TS 38.413 §8.3.1, TS 23.502 §4.2.3.2 step 12
func (s *Server) handleInitialContextSetupResponse(ctx context.Context, gnb *GNBContext, msg *Message) {
	resp, ok := msg.Value.(*InitialContextSetupResponseMsg)
	if !ok {
		return
	}

	for _, psi := range resp.FailedPSIs {
		s.logger.Warn("Initial Context Setup Response: gNB failed to set up PDU session",
			"procedure", "ServiceRequest",
			"interface", "N2",
			"direction", "IN",
			"message_type", "InitialContextSetupResponse",
			"amf_ue_ngap_id", resp.AMFUENGAPId,
			"pdu_session_id", psi,
			"spec_ref", "TS 38.413 §8.3.1",
		)
	}
	if len(resp.Setups) == 0 {
		// Initial Registration: the ICS Request carried no PDU sessions, so the
		// response confirms only that the UE context (and the NAS-PDU Registration
		// Accept it carried) was delivered. Log it for traceability, then wait for
		// the UE's Registration Complete over Uplink NAS Transport.
		// Ref: TS 38.413 §8.3.1, TS 23.502 §4.2.2.2.2 step 22.
		s.logger.Info("Initial Context Setup Response received (registration)",
			"procedure", "InitialRegistration",
			"interface", "N2",
			"direction", "IN",
			"message_type", "InitialContextSetupResponse",
			"amf_ue_ngap_id", resp.AMFUENGAPId,
			"spec_ref", "TS 38.413 §8.3.1",
		)
		return
	}
	if s.onPDUSessionSetup == nil {
		return
	}

	ue, found := s.mgr.GetByNGAPId(resp.AMFUENGAPId)
	if !found {
		s.logger.Error("InitialContextSetupResponse: UE not found",
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
			s.logger.Warn("InitialContextSetupResponse: no smContextRef",
				"pdu_session_id", setup.PDUSessionID)
			continue
		}

		s.logger.Info("PDU session re-activated by gNB (ICS Response), notifying SMF",
			"procedure", "ServiceRequest",
			"interface", "N2",
			"direction", "IN",
			"message_type", "InitialContextSetupResponse",
			"amf_ue_ngap_id", resp.AMFUENGAPId,
			"pdu_session_id", setup.PDUSessionID,
			"smContextRef", smContextRef,
			"supi", ue.SUPI,
			"spec_ref", "TS 23.502 §4.2.3.2 step 12",
		)
		go s.onPDUSessionSetup(ctx, smContextRef, setup.N2SMTransferBytes)
	}
}

// handleUERadioCapabilityInfoIndication stores the UE radio capabilities the gNB
// reports after the UE context is established. This is a class-2 procedure: no
// response is sent. The capability blob is opaque to the AMF and kept for later
// N2 use (e.g. included in a HandoverRequest to a target gNB). Its arrival also
// confirms the Initial Context Setup succeeded and the UE received the NAS-PDU
// (Registration Accept) carried in the ICS Request.
// Ref: TS 38.413 §8.7.6.
func (s *Server) handleUERadioCapabilityInfoIndication(_ context.Context, gnb *GNBContext, msg *Message) {
	ind, ok := msg.Value.(*UERadioCapabilityInfoIndicationMsg)
	if !ok {
		return
	}
	ue, found := s.mgr.GetByNGAPId(ind.AMFUENGAPId)
	if !found {
		s.logger.Warn("UERadioCapabilityInfoIndication: UE not found",
			"procedure", "InitialRegistration",
			"interface", "N2",
			"direction", "IN",
			"message_type", "UERadioCapabilityInfoIndication",
			"amf_ue_ngap_id", ind.AMFUENGAPId,
			"ran_ue_ngap_id", ind.RANUENGAPId,
			"spec_ref", "TS 38.413 §8.7.6",
		)
		return
	}
	ue.Lock()
	ue.UERadioCapability = ind.UERadioCapability
	supi := ue.SUPI
	ue.Unlock()
	s.logger.Info("UE Radio Capability stored",
		"procedure", "InitialRegistration",
		"interface", "N2",
		"direction", "IN",
		"message_type", "UERadioCapabilityInfoIndication",
		"amf_ue_ngap_id", ind.AMFUENGAPId,
		"ran_ue_ngap_id", ind.RANUENGAPId,
		"supi", supi,
		"radio_cap_bytes", len(ind.UERadioCapability),
		"spec_ref", "TS 38.413 §8.7.6",
	)
}

// ngapCauseReleaseDueTo5gcGeneratedReason is used to release the N2 signalling
// connection after the AMF itself aborts a procedure (e.g. a failed Initial
// Context Setup), as opposed to a radio-side or NAS-side reason.
// Ref: TS 38.413 §9.3.1.2, ngapType.CauseRadioNetworkPresentReleaseDueTo5gcGeneratedReason.
const ngapCauseReleaseDueTo5gcGeneratedReason int64 = 4

// handleInitialContextSetupFailure processes the gNB's rejection of an
// Initial Context Setup Request. By the time the AMF sends that request the
// registration has already been committed on its side — GMMRegistered,
// GUTI assigned, NAS security keys pushed to the gNB (Phase3_ProcessSMCComplete,
// nf/amf/internal/procedures/registration.go) — because the Registration
// Accept rides inside the request's NAS-PDU IE. If the gNB rejects the
// request, that NAS-PDU never reaches the UE, so the "registered" state on
// the AMF side is stale: left alone, the UE's inevitable retry arrives as a
// fresh InitialUEMessage that collides with the old context (observed live
// against a real Nokia gNB: ASN.1 abstract-syntax-error-reject on the ICS
// Request, then the UE's retry immediately fails Authentication with cause
// #71 "ngKSI already in use" because nothing ever released the failed
// attempt). This handler undoes the premature transition and releases the
// N2 connection so the retry starts clean.
// Ref: TS 38.413 §8.3.1, §8.3.5
func (s *Server) handleInitialContextSetupFailure(ctx context.Context, gnb *GNBContext, msg *Message) {
	fail, ok := msg.Value.(*InitialContextSetupFailureMsg)
	if !ok {
		return
	}

	ue, found := s.mgr.GetByNGAPId(fail.AMFUENGAPId)
	if !found {
		s.logger.Error("InitialContextSetupFailure: UE not found",
			"procedure", "InitialRegistration",
			"interface", "N2",
			"direction", "IN",
			"message_type", "InitialContextSetupFailure",
			"amf_ue_ngap_id", fail.AMFUENGAPId,
			"ran_ue_ngap_id", fail.RANUENGAPId,
			"cause_present", fail.CausePresent,
			"cause_value", fail.CauseValue,
			"result", "FAILURE",
			"spec_ref", "TS 38.413 §8.3.1",
		)
		return
	}

	s.logger.Error("InitialContextSetupFailure — gNB rejected Initial Context Setup Request",
		"procedure", "InitialRegistration",
		"interface", "N2",
		"direction", "IN",
		"message_type", "InitialContextSetupFailure",
		"amf_ue_ngap_id", fail.AMFUENGAPId,
		"ran_ue_ngap_id", fail.RANUENGAPId,
		"supi", ue.SUPI,
		"cause_present", fail.CausePresent,
		"cause_value", fail.CauseValue,
		"result", "FAILURE",
		"spec_ref", "TS 38.413 §8.3.1",
	)

	// The UE never received the Registration Accept the failed request was
	// carrying, so from the UE's point of view it is still unregistered —
	// undo the transition made in Phase3_ProcessSMCComplete before it sent
	// this request.
	ue.TransitionTo(amfctx.GMMDeregistered)

	// PendingRemoval must be set BEFORE SendUEContextReleaseCommandForUE so the
	// watchdog is armed and handleUEContextReleaseComplete removes the context
	// (same invariant as UE-initiated deregistration — see nf/amf/CLAUDE.md §9).
	ue.PendingRemoval = true
	if err := s.SendUEContextReleaseCommandForUE(
		ue, ngapCausePresentRadioNetwork, ngapCauseReleaseDueTo5gcGeneratedReason); err != nil {
		s.logger.Warn("SendUEContextReleaseCommandForUE failed after ICS failure — gNB may self-release",
			"error", err,
			"amf_ue_ngap_id", fail.AMFUENGAPId,
			"supi", ue.SUPI,
		)
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
	if _, err := writeNGAP(gnb.Conn, resp); err != nil {
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
			// NAS procedures make blocking SBI calls — run on the UE's serial
			// queue so other UEs' NGAP messages are not delayed.
			nasPDU := req.NASPdu
			ue.EnqueueSerial(func() {
				if err := s.nasHandler.HandleNASMessage(ctx, ue, nasPDU); err != nil {
					s.logger.Error("NAS handler error (returning UE)", "error", err,
						"amf_ue_ngap_id", ue.AMFUENGAPId)
				}
			})
			return
		}
		// TMSI not found (AMF restarted or context evicted).
		msgType, typeKnown := nas.PeekMessageType(req.NASPdu)
		rejectPDU, rejectName, specRef := rejectForUnknownTMSI(msgType, typeKnown)
		s.logger.Warn("initial NAS message: TMSI not found — rejecting",
			"tmsi", fmt.Sprintf("%08x", *req.FiveGSTMSI),
			"message_type", nasMessageTypeName(msgType, typeKnown),
			"reject", rejectName,
			"spec_ref", specRef,
		)
		// Allocate a temporary context just to supply AMF UE NGAP ID for the NGAP PDU.
		tempUE := s.mgr.AllocateUEContext(req.RANUENGAPId)
		gnb.mu.Lock()
		gnb.UEs[req.RANUENGAPId] = tempUE
		gnb.mu.Unlock()
		if _, err := writeNGAP(gnb.Conn, BuildDownlinkNASTransport(tempUE.AMFUENGAPId, req.RANUENGAPId, rejectPDU)); err != nil {
			s.logger.Error("send reject failed", "error", err, "reject", rejectName)
			gnb.mu.Lock()
			delete(gnb.UEs, req.RANUENGAPId)
			gnb.mu.Unlock()
			s.mgr.Remove(ctx, tempUE)
			return
		}
		// Release the logical NGAP/RRC connection instead of dropping the context
		// on the floor. The reject makes the UE start a *new* registration
		// immediately; if the RRC connection is left up, that registration arrives
		// as an UplinkNASTransport against an AMF UE NGAP ID we already removed and
		// is discarded, stalling the UE until T3510 expires (~16 s). Releasing here
		// puts the UE in RRC-IDLE so its retry arrives as a fresh InitialUEMessage.
		// PendingRemoval must be set BEFORE the command so the watchdog is armed and
		// handleUEContextReleaseComplete removes the context (nf/amf/CLAUDE.md §9).
		// The gNB is addressed directly rather than via SendUEContextReleaseCommandForUE:
		// that resolves the gNB through ue.GNBAddr, which a temp context never has, so
		// it would silently skip the release *and* return nil — leaking tempUE.
		// Ref: TS 38.413 §8.3.3, TS 24.501 §5.5.1.3.5.
		tempUE.PendingRemoval = true
		if err := s.SendUEContextReleaseCommand(gnb, tempUE.AMFUENGAPId, req.RANUENGAPId,
			ngapCausePresentNas, ngapCauseNasNormalRelease); err != nil {
			// Could not ask the gNB to release: clean up locally so the temp
			// context does not linger (the gNB will self-release on RRC timeout).
			s.logger.Warn("UEContextReleaseCommand after reject failed — cleaning up locally",
				"error", err, "amf_ue_ngap_id", tempUE.AMFUENGAPId)
			gnb.mu.Lock()
			delete(gnb.UEs, req.RANUENGAPId)
			gnb.mu.Unlock()
			s.mgr.Remove(ctx, tempUE)
			return
		}
		// Backstop: if UEContextReleaseComplete never arrives, force-remove tempUE.
		s.startPendingRemovalTimer(tempUE)
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

	// Hand NAS PDU to NAS handler on the UE's serial queue: registration
	// drives blocking SBI calls (AUSF auth, UDM SDM, PCF) that must not stall
	// the SCTP read loop for other UEs during registration bursts.
	nasPDU := req.NASPdu
	ue.EnqueueSerial(func() {
		if err := s.nasHandler.HandleNASMessage(ctx, ue, nasPDU); err != nil {
			log.Error("NAS handler error", "error", err)
		}
	})
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
	// NAS procedures (e.g. UL NAS Transport → Nsmf_PDUSession_CreateSMContext)
	// block on SBI calls — run on the UE's serial queue so one slow SMF call
	// cannot back up NGAP processing for every other UE on this association.
	nasPDU := req.NASPdu
	ue.EnqueueSerial(func() {
		if err := s.nasHandler.HandleNASMessage(ctx, ue, nasPDU); err != nil {
			s.logger.Error("NAS handler error", "error", err,
				"amf_ue_ngap_id", req.AMFUENGAPId)
		}
	})
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
	_, err := writeNGAP(gnb.Conn, pdu)
	return err
}

// ---- Send Initial Context Setup Request ---------------------------------

// SendInitialContextSetupRequest sends an Initial Context Setup Request to the
// gNB that serves the UE.  It carries KgNB (AS security base key), UE security
// capability bitmaps, and the integrity-protected RegistrationAccept NAS PDU.
// pduSessions, when non-empty, is the PDUSessionResourceSetupListCxtReq for
// user-plane re-activation during Service Request (TS 23.502 §4.2.3 step 6);
// pass nil for Initial Registration.
// Ref: TS 38.413 §8.3.1
func (s *Server) SendInitialContextSetupRequest(
	ue *amfctx.UEContext,
	nasPDU []byte,
	kgnb [32]byte,
	cipherAlg, integAlg byte,
	encAlgsBitmap, intAlgsBitmap uint16,
	pduSessions []PDUSessionSetupItemCxtReq,
) error {
	gnb := s.findGNBForUE(ue)
	if gnb == nil {
		return fmt.Errorf("ngap: no gNB found for UE %d", ue.RANUENGAPId)
	}

	// Subscribed UE-AMBR from UDM am-data is stored in kbit/s; NGAP BitRate is
	// bit/s. Zero (no subscription value) falls back to the builder's default.
	// Ref: TS 38.413 §9.3.1.58
	pdu := BuildInitialContextSetupRequest(
		ue.AMFUENGAPId, ue.RANUENGAPId,
		nasPDU, kgnb,
		encAlgsBitmap, intAlgsBitmap,
		s.cfg.MCC, s.cfg.MNC,
		s.cfg.RegionID, s.cfg.SetID, s.cfg.AMFID,
		ue.AllowedNSSAI,
		int64(ue.SubscribedAMBR.UL)*1000, int64(ue.SubscribedAMBR.DL)*1000,
		ue.RFSP,
		pduSessions,
	)
	s.logger.Info("Initial Context Setup Request",
		"procedure", "InitialRegistration",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "InitialContextSetupRequest",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"rfsp", ue.RFSP,
		"pdu_sessions_cxt_req", len(pduSessions),
		"spec_ref", "TS 38.413 §8.3.1",
	)
	_, err := writeNGAP(gnb.Conn, pdu)
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

	_, err := writeNGAP(gnb.Conn, pdu)
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
	_, err := writeNGAP(gnb.Conn, pdu)
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
	_, err := writeNGAP(gnb.Conn, pdu)
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
		if _, err := writeNGAP(g.Conn, pdu); err != nil {
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
	// The callback makes one blocking SBI call per PDU session — run it on the
	// UE's serial queue so a Service Request arriving right after (same UE) is
	// processed after the deactivation, and other UEs are not delayed.
	if s.onANRelease != nil {
		ue.EnqueueSerial(func() {
			s.onANRelease(ctx, ue)
		})
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
	_, err := writeNGAP(gnb.Conn, pdu)
	return err
}

// ---- Location Reporting Control / Location Report (TS 38.413 §8.17.1) ------

// SendLocationReportingControl sends an NGAP LocationReportingControl PDU to the
// gNB serving ue, then returns a channel on which the caller can block for the
// matching LocationReport. The caller is responsible for cleaning up the pending
// map entry on timeout (see LocateUE).
//
// Ref: TS 38.413 §8.17.1; TS 23.273 §7.2 (Cell-ID positioning).
func (s *Server) SendLocationReportingControl(ue *amfctx.UEContext) (<-chan LocationResult, error) {
	gnb := s.findGNBForUE(ue)
	if gnb == nil {
		return nil, fmt.Errorf("amf: send location reporting control: no gNB for UE %d",
			ue.AMFUENGAPId)
	}

	pdu := BuildLocationReportingControl(ue.AMFUENGAPId, ue.RANUENGAPId)
	if pdu == nil {
		return nil, fmt.Errorf("amf: send location reporting control: encode failed")
	}

	// Buffer of 1: the LocationReport handler sends and moves on even if the
	// caller has already timed out (avoids goroutine leak in the handler).
	ch := make(chan LocationResult, 1)
	s.pendingLoc.Store(ue.AMFUENGAPId, ch)

	s.logger.Info("NGAP LocationReportingControl sent",
		"procedure", "ProvideLocationInfo",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "LocationReportingControl",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"ran_ue_ngap_id", ue.RANUENGAPId,
		"supi", ue.SUPI,
		"spec_ref", "TS 38.413 §8.17.1",
	)

	if _, err := writeNGAP(gnb.Conn, pdu); err != nil {
		s.pendingLoc.Delete(ue.AMFUENGAPId)
		return nil, fmt.Errorf("amf: send location reporting control: write: %w", err)
	}
	return ch, nil
}

// handleLocationReport processes an NGAP LocationReport received from the gNB.
// It resolves the pending channel keyed by AMF-UE-NGAP-ID and delivers the result.
// Ref: TS 38.413 §8.17.1; TS 23.273 §7.2.
func (s *Server) handleLocationReport(ctx context.Context, gnb *GNBContext, msg *Message) {
	rep, ok := msg.Value.(*LocationReportMsg)
	if !ok || rep == nil {
		s.logger.Error("LocationReport body decode failed",
			"procedure", "ProvideLocationInfo",
			"interface", "N2",
			"direction", "IN",
			"spec_ref", "TS 38.413 §8.17.1",
		)
		return
	}

	s.logger.Info("NGAP LocationReport received",
		"procedure", "ProvideLocationInfo",
		"interface", "N2",
		"direction", "IN",
		"message_type", "LocationReport",
		"amf_ue_ngap_id", rep.AMFUENGAPId,
		"ran_ue_ngap_id", rep.RANUENGAPId,
		"nr_cell_id", rep.NRCellID,
		"spec_ref", "TS 38.413 §8.17.1",
	)

	val, loaded := s.pendingLoc.LoadAndDelete(rep.AMFUENGAPId)
	if !loaded {
		// Late or spurious LocationReport — no waiting caller.
		s.logger.Warn("LocationReport: no pending locate request",
			"amf_ue_ngap_id", rep.AMFUENGAPId,
			"spec_ref", "TS 38.413 §8.17.1",
		)
		return
	}
	ch, ok := val.(chan LocationResult)
	if !ok {
		return
	}
	// Non-blocking send: ch is buffered(1). If the caller already timed out the
	// send simply succeeds into the buffer and the channel is GC'd.
	ch <- LocationResult{NRCellID: rep.NRCellID, TAI: rep.TAI}
}

// ---- NGAP NRPPa Transport (TS 38.413 §8.17.3 / §8.17.4) ------------------

// SendDownlinkNRPPa sends an NGAP DownlinkUEAssociatedNRPPaTransport PDU to
// the gNB serving the UE. The nrppaPDU bytes are carried as an opaque NRPPa-PDU
// IE — the AMF never decodes them. routingID may be nil if not yet established.
//
// A buffered channel is registered in pendingNRPPa keyed by ue.AMFUENGAPId;
// the caller blocks on it until the matching UL NRPPa arrives or times out.
// The caller is responsible for cleaning up the pending entry on timeout.
//
// Ref: TS 38.413 §8.17.3; TS 23.273 §7.2 step C; TS 29.518 §5.2.2.6.
func (s *Server) SendDownlinkNRPPa(ue *amfctx.UEContext, nrppaPDU []byte, routingID []byte) (<-chan NRPPaResult, error) {
	gnb := s.findGNBForUE(ue)
	if gnb == nil {
		return nil, fmt.Errorf("amf: send downlink nrppa: no gNB for UE %d", ue.AMFUENGAPId)
	}

	pdu := BuildDownlinkUEAssociatedNRPPaTransport(ue.AMFUENGAPId, ue.RANUENGAPId, nrppaPDU, routingID)
	if pdu == nil {
		return nil, fmt.Errorf("amf: send downlink nrppa: encode failed")
	}

	// Buffer of 1: the handleUplinkNRPPa handler sends into the buffer and
	// continues even if the caller has already timed out (no goroutine leak).
	ch := make(chan NRPPaResult, 1)
	s.pendingNRPPa.Store(ue.AMFUENGAPId, ch)

	s.logger.Info("NGAP DownlinkUEAssociatedNRPPaTransport sent",
		"procedure", "NRPPaTransport",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "DownlinkUEAssociatedNRPPaTransport",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"ran_ue_ngap_id", ue.RANUENGAPId,
		"supi", ue.SUPI,
		"nrppa_pdu_len", len(nrppaPDU),
		"spec_ref", "TS 38.413 §8.17.3",
	)
	metrics.AMFNRPPaTransportTotal.WithLabelValues("DL", "UE").Inc()

	if _, err := writeNGAP(gnb.Conn, pdu); err != nil {
		s.pendingNRPPa.Delete(ue.AMFUENGAPId)
		return nil, fmt.Errorf("amf: send downlink nrppa: write: %w", err)
	}
	return ch, nil
}

// handleUplinkUEAssociatedNRPPa processes an NGAP UplinkUEAssociatedNRPPaTransport
// message received from the gNB. It resolves the pending channel keyed by
// AMF-UE-NGAP-ID and delivers the opaque NRPPa-PDU bytes to the waiting caller
// (the dl-nrppa-info SBI handler that is blocking on the channel).
//
// If no pending channel is found the PDU is an orphan and is dropped with a
// warning log. The AMF never decodes the NRPPa-PDU content.
//
// Ref: TS 38.413 §8.17.3; TS 23.273 §7.2 step C.
func (s *Server) handleUplinkUEAssociatedNRPPa(ctx context.Context, gnb *GNBContext, msg *Message) {
	ul, ok := msg.Value.(*UplinkUEAssociatedNRPPaTransportMsg)
	if !ok || ul == nil {
		s.logger.Error("UplinkUEAssociatedNRPPaTransport body decode failed",
			"procedure", "NRPPaTransport",
			"interface", "N2",
			"direction", "IN",
			"spec_ref", "TS 38.413 §8.17.3",
		)
		return
	}

	s.logger.Info("UplinkNRPPa received",
		"procedure", "NRPPaTransport",
		"interface", "N2",
		"direction", "IN",
		"message_type", "UplinkUEAssociatedNRPPaTransport",
		"amf_ue_ngap_id", ul.AMFUENGAPId,
		"ran_ue_ngap_id", ul.RANUENGAPId,
		"nrppa_pdu_len", len(ul.NRPPaPDU),
		"spec_ref", "TS 38.413 §8.17.3",
	)
	metrics.AMFNRPPaTransportTotal.WithLabelValues("UL", "UE").Inc()

	val, loaded := s.pendingNRPPa.LoadAndDelete(ul.AMFUENGAPId)
	if !loaded {
		// No matching pending DL NRPPa request — this is an orphan.
		// Log and drop: the LMF must handle the missing UL NRPPa via its own
		// guard timer. Ref: TS 23.273 §7.2 (error table: nrppa_orphan).
		s.logger.Warn("UplinkNRPPa orphan — no pending dl-nrppa-info request",
			"procedure", "NRPPaTransport",
			"amf_ue_ngap_id", ul.AMFUENGAPId,
			"result", "nrppa_orphan",
			"spec_ref", "TS 38.413 §8.17.3",
		)
		return
	}
	ch, ok := val.(chan NRPPaResult)
	if !ok {
		return
	}
	// Non-blocking send: ch is buffered(1). If the caller has already timed out
	// the send succeeds into the buffer and the channel is GC'd.
	ch <- NRPPaResult{NRPPaPDU: ul.NRPPaPDU, RoutingID: ul.RoutingID}
}

// handleUplinkNonUEAssociatedNRPPa processes an NGAP UplinkNonUEAssociatedNRPPaTransport
// message received from the gNB. In the E-CID MVP this path is exercised only by
// unit tests (cell-level NRPPa signalling not tied to a UE context). The AMF logs
// the event and drops the PDU unless a non-UE relay path is wired.
//
// Ref: TS 38.413 §8.17.4.
func (s *Server) handleUplinkNonUEAssociatedNRPPa(ctx context.Context, gnb *GNBContext, msg *Message) {
	ul, ok := msg.Value.(*UplinkNonUEAssociatedNRPPaTransportMsg)
	if !ok || ul == nil {
		s.logger.Error("UplinkNonUEAssociatedNRPPaTransport body decode failed",
			"procedure", "NRPPaTransport",
			"interface", "N2",
			"direction", "IN",
			"spec_ref", "TS 38.413 §8.17.4",
		)
		return
	}

	s.logger.Info("UplinkNRPPa received (non-UE-associated)",
		"procedure", "NRPPaTransport",
		"interface", "N2",
		"direction", "IN",
		"message_type", "UplinkNonUEAssociatedNRPPaTransport",
		"nrppa_pdu_len", len(ul.NRPPaPDU),
		"spec_ref", "TS 38.413 §8.17.4",
	)
	metrics.AMFNRPPaTransportTotal.WithLabelValues("UL", "NON_UE").Inc()
	// Non-UE-associated relay to LMF is wired in pass 2 (LMF side).
	// For pass 1 the AMF logs and drops.
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
