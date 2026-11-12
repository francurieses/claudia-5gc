// Package context manages UE and gNB contexts in the AMF.
//
// Each registered UE has a UEContext which lives for the lifetime of the
// registration. Each connected gNB has a RANContext.
//
// Ref: 3GPP TS 23.501 §5.3 (UE context), TS 38.413 §9.2 (NGAP IDs)
package context

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/store"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// ---- CM State Machine (TS 23.501 §5.3.2) --------------------------------

// CMState represents the Connection Management state of a UE.
// CM-IDLE: no N2 connection; CM-CONNECTED: active N2 association with gNB.
type CMState int

const (
	// CMIdle: UE has no N2 signalling connection (no radio context at gNB).
	CMIdle CMState = iota
	// CMConnected: UE has an active N2/N3 connection.
	CMConnected
)

func (s CMState) String() string {
	switch s {
	case CMIdle:
		return "CM-IDLE"
	case CMConnected:
		return "CM-CONNECTED"
	default:
		return "unknown"
	}
}

// ---- 5GMM State Machine (TS 24.501 §5.1.3) ------------------------------

// GMM5State represents the 5GMM state of a UE as seen by the AMF.
type GMM5State int

const (
	// GMMDeregistered: No registration context. Initial state.
	GMMDeregistered GMM5State = iota
	// GMMRegistered: UE is successfully registered.
	GMMRegistered
	// GMMDeregisteredInitiated: Deregistration procedure initiated.
	GMMDeregisteredInitiated
	// GMMServiceRequestInitiated: Service Request procedure ongoing.
	GMMServiceRequestInitiated
	// GMMCommonProcedureInitiated: the AMF has started a common procedure and
	// waits for the UE's answer; for a registration it is the state between the
	// REGISTRATION ACCEPT carrying a new 5G-GUTI (T3550 running) and the
	// REGISTRATION COMPLETE. Appended after the existing values so persisted
	// state numbers keep their meaning. Ref: TS 24.501 §5.1.3.3, §5.5.1.2.4
	GMMCommonProcedureInitiated
)

func (s GMM5State) String() string {
	switch s {
	case GMMDeregistered:
		return "5GMM-DEREGISTERED"
	case GMMRegistered:
		return "5GMM-REGISTERED"
	case GMMDeregisteredInitiated:
		return "5GMM-DEREGISTERED-INITIATED"
	case GMMServiceRequestInitiated:
		return "5GMM-SERVICE-REQUEST-INITIATED"
	case GMMCommonProcedureInitiated:
		return "5GMM-COMMON-PROCEDURE-INITIATED"
	default:
		return "unknown"
	}
}

// ---- NAS Security Context (TS 33.501 §6.7) ------------------------------

// SecurityContext holds the active NAS security context for a UE.
type SecurityContext struct {
	// Key set identifier assigned by AMF
	NGKSI byte
	// Selected algorithms
	IntegrityAlgID byte // 0=NIA0, 1=NIA1, 2=NIA2, 3=NIA3
	CipheringAlgID byte // 0=NEA0, 1=NEA1, 2=NEA2, 3=NEA3
	// Keys (256-bit each)
	KAMF    []byte
	KNASint []byte // 128-bit NAS integrity key
	KNASenc []byte // 128-bit NAS ciphering key
	// Counters
	UplinkCount   uint32
	DownlinkCount uint32
	// Status
	Active bool
}

// ---- GUTI (TS 23.501 §5.9.1) -------------------------------------------

// GUTI5G is the 5G Globally Unique Temporary Identifier assigned by AMF.
type GUTI5G struct {
	MCC         string
	MNC         string
	AMFRegionID byte
	AMFSetID    uint16 // 10 bits
	AMFID       byte   // 6 bits (=AMF pointer within set)
	TMSI        uint32 // 5G-TMSI (32 bits)
}

func (g GUTI5G) String() string {
	return fmt.Sprintf("mcc=%s mnc=%s amf=%02x set=%d id=%02x tmsi=%08x",
		g.MCC, g.MNC, g.AMFRegionID, g.AMFSetID, g.AMFID, g.TMSI)
}

// ---- UE Context ---------------------------------------------------------

// UEContext is the central per-UE state object in the AMF.
// Access is serialized through mu — do not hold mu across SBI calls.
//
// oapi: none AMF-internal UE state, not an SBI body (persisted as store.UERecord)
type UEContext struct {
	mu sync.Mutex

	// Identifiers
	SUPI string // Permanent identifier (available after authentication)
	SUCI string // Concealed identifier (from Registration Request)
	GUTI *GUTI5G
	PEI  string // Permanent Equipment Identifier (IMEISV)
	// GPSI is the UE's public identifier from the Nudm_SDM am-data "gpsis"
	// (msisdn- form preferred, "" when none). Runtime-only, not persisted.
	// Ref: TS 29.503 §6.1.6.2.4
	GPSI string

	// NGAP IDs (TS 38.413 §9.3.3)
	AMFUENGAPId int64  // assigned by AMF
	RANUENGAPId int64  // assigned by gNB
	RANUEID     string // for logging

	// gNB association
	RANNID  string // RAN Node ID (gNB ID)
	TAI     TAI    // Tracking Area Identity where UE is located
	GNBAddr string // remote addr of the serving gNB SCTP connection (used for CM-IDLE tracking)
	// KgNB is the current AS base key shared with the serving gNB.
	// Stored after each Initial Context Setup or Service Request so that
	// the N2 handover handler can derive NH for the target gNB.
	// Ref: TS 33.501 §A.9, §A.11
	KgNB [32]byte
	// NH / NCC / NHValid hold the AMF's locally kept Next Hop chain
	// (TS 33.501 §6.9.2.1.1, §6.9.2.3.2, Annex A.10). Always go through
	// SetKgNB / NextNH — they keep the three fields consistent. N2-connection
	// scoped like UEAMBRSentToRAN: deliberately NOT persisted.
	NH      [32]byte
	NCC     uint8
	NHValid bool

	// CM state (TS 23.501 §5.3.2)
	CMState CMState

	// NASOnNewN2Connection is true only while the NAS message being processed
	// arrived in an INITIAL UE MESSAGE, i.e. it is the message that moved the UE
	// from CM-IDLE to CM-CONNECTED. Only then is a new KgNB derived from its
	// uplink NAS COUNT and an INITIAL CONTEXT SETUP REQUEST sent; a message
	// received over an existing N2 connection (UPLINK NAS TRANSPORT) derives
	// none. In-memory only (not persisted); set/cleared by the NGAP layer around
	// HandleNASMessage. Ref: TS 33.501 §6.8.1.2.1
	NASOnNewN2Connection bool

	// 5GMM state machine
	State GMM5State
	// Registration type of ongoing procedure
	RegistrationType byte

	// Security
	SecurityCtx SecurityContext
	// secCtxPending / prevSecurityCtx: a SECURITY MODE COMMAND is taking SecurityCtx
	// into use; prevSecurityCtx is the context in use before it (secctx.go).
	secCtxMu        sync.Mutex
	secCtxPending   bool
	prevSecurityCtx *SecurityContext
	// secureExchange: the secure exchange of NAS messages is established for the
	// current N1 signalling connection (secctx.go). In-memory only, never persisted.
	secureExchange bool
	// UE security capabilities (reported in Registration Request)
	UESecCapEA [8]bool // EA0..EA7
	UESecCapIA [8]bool // IA0..IA7
	// RawUESecCap stores the verbatim wire bytes of the UE Security Capability IE
	// so they can be replayed exactly in the Security Mode Command.
	RawUESecCap []byte
	// UERadioCapability is the opaque UE radio-capability blob reported by the gNB
	// in a UE Radio Capability Info Indication (TS 38.413 §8.7.6). Kept for later
	// N2 use such as populating a HandoverRequest to a target gNB.
	UERadioCapability []byte

	// Authentication state (used during auth procedure)
	AuthCtxID   string   // AUSF auth context ID
	PendingRAND [16]byte // RAND sent to UE in AuthenticationRequest; needed for AUTS resync
	// PendingNGKSI is the ngKSI the AMF allocated for the in-flight authentication.
	// It must differ from the ngKSI of the UE's existing native 5G security context
	// (which the UE reports in the Registration Request) or the UE rejects the
	// Authentication Request with 5GMM cause #71 "ngKSI already in use".
	// The same value is carried into the SecurityModeCommand and the resulting
	// SecurityContext. Ref: TS 24.501 §5.4.1.2.1, §5.4.1.3.2, §5.4.1.3.7.
	PendingNGKSI byte
	// PendingAUTN is the AUTN of the in-flight 5G authentication challenge, kept
	// so that the same challenge can be re-sent with a new ngKSI after an
	// AUTHENTICATION FAILURE #71. Ref: TS 24.501 §5.4.1.3.7 e)
	PendingAUTN [16]byte `json:"-"`
	// AuthViaGUTI is true while the in-flight authentication runs on the SUPI
	// resolved from a 5G-GUTI (not on a SUCI); it selects identification versus
	// AUTHENTICATION REJECT after a #20 / #26 failure. Ref: TS 24.501 §5.4.1.3.7 c), d)
	AuthViaGUTI bool `json:"-"`
	// AuthSynchFailures / AuthNgKSIFailures count consecutive AUTHENTICATION
	// FAILURE #21 / #71 messages of the in-flight authentication (reset by a new
	// REGISTRATION REQUEST). Ref: TS 24.501 §5.4.1.3.7 e), f) NOTE 4
	AuthSynchFailures int `json:"-"`
	AuthNgKSIFailures int `json:"-"`
	KAUSF             []byte
	KSEAF             []byte

	// Subscription data (from UDM)
	AllowedNSSAI []SNSSAISubscribed
	// RequestedNSSAI stores the slices the UE requested at registration,
	// used to compute the intersection with AllowedNSSAI.
	// Ref: TS 23.502 §4.2.2.2.2 step 1
	RequestedNSSAI []SNSSAISubscribed

	// NSSAA (Network Slice-Specific Authentication and Authorization, TS 23.502 §4.2.9).
	// Slices flagged subjectToNssaa are held in PendingNSSAA (excluded from the initial
	// Allowed NSSAI) until slice-level EAP auth succeeds. NSSAAInProgress is the slice
	// currently awaiting a NETWORK SLICE-SPECIFIC AUTHENTICATION COMPLETE; NSSAAEAPID is
	// the EAP identifier of its in-flight exchange. RejectedNSSAI collects slices that
	// failed NSSAA (5GMM cause #3).
	PendingNSSAA    []SNSSAISubscribed
	NSSAAInProgress *SNSSAISubscribed
	NSSAAEAPID      byte
	// NSSAAPendingStatus holds slices whose NSSAA could not be completed (no
	// GPSI, NSSAAF unreachable/5xx): status PENDING, neither allowed nor rejected.
	// Ref: TS 29.526 §5.2.2.2.1, TS 23.502 §4.2.9.2
	NSSAAPendingStatus []SNSSAISubscribed
	// RejectedNSSAI holds the slices that failed (or lost) NSSAA. Under rel19 the
	// AMF reports them with Rejected NSSAI cause "failed or revoked NSSAA" (2,
	// TS 24.501 Table 9.11.3.46.1); the legacy rel17 text called it "cause #3".
	RejectedNSSAI []SNSSAISubscribed
	// SubscribedNSSAI is the subscription's S-NSSAI list as read from am-data
	// nssai.defaultSingleNssais (the only list the AMF reads), with the
	// subjectToNetworkSliceSpecificAuthenticationAndAuthorization flag. It is
	// what "default S-NSSAIs" means for the rel19 de-registration decision of
	// TS 24.501 §4.6.2.4 c) / TS 23.502 §4.2.9.2 step 19b. Set at registration.
	SubscribedNSSAI []SNSSAISubscribed
	// EmergencyPDUSession reports that the UE has (or is establishing) an
	// emergency PDU session; it selects the Configuration Update exception of
	// TS 24.501 §4.6.2.4 c). The AMF does not establish emergency PDU sessions
	// yet, so nothing sets it: the exception is not reachable in a running AMF.
	EmergencyPDUSession bool
	// NSSAAPendingAt records, per slice (see procedures.NSSAASliceKey), when the
	// slice was last left PENDING; the PENDING retry waits a minimum interval
	// from it (implementation choice, not a 3GPP value). Serial-queue only.
	NSSAAPendingAt map[string]time.Time
	// NSSAAResultsChanged (rel19) is set whenever a slice's NSSAA ends with a new
	// result (EAP-Success, EAP-Failure, T3575 abort) and cleared when the one
	// CONFIGURATION UPDATE COMMAND of the drained queue is sent.
	// Ref: TS 23.502 §4.2.9.2 step 19a. Serial-queue only.
	NSSAAResultsChanged bool
	// NSSAAAuthCtxID is the Nnssaaf authCtxId of the in-flight multi-round
	// exchange of NSSAAInProgress (rel19: set from the 201 SliceAuthContext /
	// Location, used for the PUT of every following EAP-Response); empty when
	// the AAA-S has no open context. NSSAARounds counts the EAP-Requests the
	// AAA-S has relayed for that exchange. Both are reset when the slice
	// resolves. Ref: TS 29.526 §5.2.2.2.1 steps 4-9, §6.1.3.3.3.1, TS 23.502 §4.2.9.2 steps 7-14
	NSSAAAuthCtxID string
	NSSAARounds    int
	// NSSAARestarts counts the restarts of the current exchange after the NSSAAF
	// lost the context (404 on the PUT); bounded by procedures.NSSAAMaxContextRestarts.
	NSSAARestarts  int
	SubscribedAMBR struct {
		UL, DL uint64 // kbps
	}

	// UEAMBRSentToRAN is true once the serving gNB has been given the UE-AMBR in
	// the current UE-associated logical NG connection (via an ICS Request carrying
	// PDU sessions, a PDU Session Resource Setup Request, or a Handover Request).
	// It is reset whenever that connection is released or replaced. N2-context
	// scoped: deliberately NOT persisted (Redis/Postgres ignore it).
	// Ref: TS 38.413 §8.2.1.2, §9.2.2.1; TS 23.501 §5.7.2.6
	UEAMBRSentToRAN bool

	// PDU Sessions
	PDUSessions map[uint8]*PDUSession

	// PendingRemoval is set during UE-initiated deregistration. The context is
	// kept alive until UEContextReleaseComplete arrives from the gNB so that
	// gnb.UEs can be cleaned up atomically.
	PendingRemoval bool

	// Transferred is set when this (old) AMF has handed the UE context to a new
	// AMF via Namf_Communication_UEContextTransfer. The context is kept until the
	// new AMF confirms success (RegistrationStatusUpdate) or the implicit-detach
	// timers expire. Ref: TS 23.502 §4.2.2.2.3, TS 29.518 §5.3.2
	Transferred bool

	// PendingN1N2 is set when the AMF has paged a CM-IDLE UE in response to a
	// Namf_Communication_N1N2MessageTransfer (mobile-terminated data). It is cleared
	// once the UE returns to CM-CONNECTED via Service Request and the user plane is
	// re-activated. Ref: TS 23.502 §4.2.3.3
	PendingN1N2 bool

	// pagedPDUSessions holds the PSIs for which an Namf_Communication_N1N2MessageTransfer
	// arrived while the UE was CM-IDLE (the session whose downlink data triggered
	// paging). The paging-triggered Service Request (service type "mobile
	// terminated services", no Uplink Data Status) re-activates exactly these
	// sessions; the set is consumed (cleared) by TakePagedPDUSessions.
	// In-memory only; guarded by mu.
	// Ref: TS 23.502 §4.2.3.3 step 6 → §4.2.3.2 steps 4/12, TS 24.501 §5.6.1.4.1
	pagedPDUSessions map[uint8]struct{}

	// Timestamps
	RegistrationTime time.Time
	LastActivity     time.Time

	// Policy state (N15 interface, Npcf_UEPolicyControl)
	// PolicyAssociationID is the PCF UE policy association identifier (URSP, npcf-ue-policy-control).
	// Empty when no N15 call was made or when PCF is unavailable.
	PolicyAssociationID string
	// AMPolicyAssocID is the PCF AM policy association identifier (npcf-am-policy-control, TS 29.507).
	// Empty when PCF AM policy association was not created.
	AMPolicyAssocID string
	// SDMSubscriptionID is the Nudm_SDM subscription id (last segment of the
	// Location of the 201) created at registration; "" when none. In memory
	// only. Removed (DELETE) where the AMF calls Nudm_UECM_Deregistration.
	// Ref: TS 29.503 §5.2.2.3, §6.1.3.2
	// Access through SetSDMSubscriptionID / TakeSDMSubscriptionID (own mutex).
	SDMSubscriptionID string
	sdmMu             sync.Mutex
	// RFSP is the Radio Frequency Selection Priority index returned by PCF (1-256).
	// Zero means PCF did not provide one.
	// Ref: TS 23.501 §5.3.4.2, TS 29.507 §6.1.1.2.4
	RFSP int
	// ServAreaRes holds the service area restriction from PCF AM policy.
	// Nil when PCF returned no restriction (UE is unrestricted).
	// Ref: TS 23.501 §5.3.4, TS 29.507 §6.1.1.2.5
	ServAreaRes *ServiceAreaRestriction
	// PendingPolicyContainer holds the UE Policy Container bytes fetched from PCF
	// during Phase3 (registration) that must be delivered via UCU after the UE sends
	// RegistrationComplete. Cleared once the UCU is sent.
	// Ref: TS 23.502 §4.2.2.2.2 step 17b, TS 29.525 §4.2.2.2
	PendingPolicyContainer []byte
	// URSPVersion is incremented each time a ConfigurationUpdateComplete is received
	// from the UE, confirming successful delivery of updated URSP rules.
	// Ref: TS 29.525 §4.2.2.2, TS 24.501 §8.2.30
	URSPVersion uint8

	// Network-side lifecycle timers (TS 23.501 §5.3.2, TS 24.501 §10.2).
	// All timers are protected by mu. Callbacks run in separate goroutines
	// and must not hold mu when calling external services.
	//
	// MobileReachableTimer: started when UE goes CM-IDLE or completes registration.
	// When it fires → ImplicitDetachTimer starts.
	// Reset on each Periodic Registration Update or Service Request.
	//
	// ImplicitDetachTimer: started when MobileReachableTimer fires.
	// When it fires → AMF releases all PDU sessions, deregisters from UDM,
	// and removes the UE context (implicit detach, TS 23.501 §5.3.2).
	//
	// PendingRemovalTimer: watchdog started after SendUEContextReleaseCommand
	// when PendingRemoval=true. If UEContextReleaseComplete never arrives the
	// context is force-removed to prevent a permanent leak.
	MobileReachableTimer *time.Timer
	ImplicitDetachTimer  *time.Timer

	// T3512SentSecs is the T3512 value (seconds) sent to the UE in its last
	// REGISTRATION ACCEPT; 0 means unknown. Used so that, after an O&M
	// lowering of T3512, the mobile reachable timer stays longer than the T3512
	// the UE actually holds (TS 24.501 §5.3.7). Guarded by mu; use
	// SetT3512SentSecs / T3512Sent.
	T3512SentSecs int `json:"t3512_sent_secs,omitempty"`
	// MobileReachableDur / ImplicitDetachDur record the duration used when the
	// corresponding timer was last armed (observability and tests). Guarded by mu;
	// use ArmedDurations.
	MobileReachableDur  time.Duration `json:"-"`
	ImplicitDetachDur   time.Duration `json:"-"`
	PendingRemovalTimer *time.Timer

	// Per-UE serial task queue used by the NGAP layer to process this UE's
	// messages in arrival order without blocking the shared SCTP read loop
	// (one slow SBI call for one UE must not delay other UEs' NGAP messages).
	// Guarded by taskMu — separate from mu because queued tasks themselves
	// take mu. See EnqueueSerial.
	taskMu       sync.Mutex
	taskQueue    []func()
	taskDraining bool

	// mgr is the Manager that allocated this context (nil for contexts built
	// outside AllocateUEContext). The serial-queue panic containment uses it to
	// log and release the UE (panic.go).
	mgr *Manager

	// prevTMSI is the 5G-TMSI of the previous 5G-GUTI, kept in the Manager's
	// 5G-TMSI index only until the new 5G-GUTI is confirmed (ConfirmGUTI) or the
	// context is removed. Guarded by Manager.mu. Ref: TS 24.501 §5.5.1.3.8 a)
	prevTMSI    uint32
	hasPrevTMSI bool

	// Supervision timers kept on the UE context (rel19 only) so that Remove /
	// re-registration stop them and nothing is keyed by SUPI in a handler-wide
	// map: T3575 of the NSSAA COMMAND (nas/nssaa_timer.go) and T3522 of the
	// network-initiated DEREGISTRATION REQUEST (nas/dereg_timer.go). Each has
	// its own leaf lock, never held across a call out.
	nssaaT RetxTimer
	deregT RetxTimer

	// regT supervises the one outstanding registration common-procedure message
	// (T3550 / T3560 / T3570, see regproc.go); regProc is the pending-procedure
	// marker. Guarded by regProcMu (leaf lock).
	regT       RetxTimer
	regProcMu  sync.Mutex
	regProc    regProcState
	pendingICS ICSKind // procedure of the in-flight ICS Request (guarded by regProcMu)

	// ERNSSAISupported records the ER-NSSAI bit of the 5GMM capability IE of the
	// UE's last REGISTRATION REQUEST (octet 5 bit 5, TS 24.501 §9.11.3.1): the
	// UE supports the Extended rejected NSSAI IE. It selects which IE carries the
	// rejected NSSAI in the REGISTRATION ACCEPT, CONFIGURATION UPDATE COMMAND and
	// network-initiated DEREGISTRATION REQUEST (rel19, TS 24.501 §5.5.1.2.4,
	// §5.4.4.2, §5.5.2.3.1). Runtime-only: not persisted (ueContextToRecord
	// ignores it), so a restored context reads "not supported" until the UE's
	// next REGISTRATION REQUEST. Written on the UE's serial queue.
	ERNSSAISupported bool `json:"-"`

	// Capability5GMM is the decoded 5GMM capability IE of the UE's last
	// REGISTRATION REQUEST, nil when the UE did not send it (TS 24.501
	// §9.11.3.1). Persisted as raw value octets (UERecord.Capability5GMM) and
	// re-decoded on restore. Written on the UE's serial queue.
	Capability5GMM *nas.FiveGMMCapability `json:"-"`
}

// TimerStopper is the stop handle of a scheduled timer (*time.Timer or a test
// fake).
type TimerStopper interface{ Stop() bool }

// NSSAATimerStopper is the T3575 name of TimerStopper (kept for callers).
type NSSAATimerStopper = TimerStopper

// RetxTimer is a retransmission-supervised timer (T3575, T3522): the scheduled
// timer, a generation counter that invalidates callbacks already fired when it
// is stopped or re-armed, the message to retransmit and the expiry count. The
// zero value is ready; every method is safe from any goroutine.
type RetxTimer struct {
	mu       sync.Mutex
	timer    TimerStopper
	gen      uint64
	expiries int
	msg      any
}

// Arm (re)starts the timer: it stops any running one, bumps the generation so
// callbacks of the old timer are ignored, and stores msg (what to retransmit)
// with the expiry count. start receives the new generation and returns the
// scheduled timer; it must not block or re-enter the UE context.
func (r *RetxTimer) Arm(msg any, expiries int, start func(gen uint64) TimerStopper) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		r.timer.Stop()
	}
	r.gen++
	r.msg, r.expiries = msg, expiries
	r.timer = start(r.gen)
}

// Stop stops the timer and invalidates callbacks already fired. Safe when none
// is armed.
func (r *RetxTimer) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.gen++
	r.msg = nil
}

// Current returns the message and expiry count of the timer armed with
// generation gen, or ok=false when it was stopped or replaced meanwhile.
func (r *RetxTimer) Current(gen uint64) (msg any, expiries int, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if gen != r.gen || r.msg == nil {
		return nil, 0, false
	}
	return r.msg, r.expiries, true
}

// State returns the message and expiry count of the armed timer whatever its
// generation, or ok=false when none is armed.
func (r *RetxTimer) State() (msg any, expiries int, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.msg == nil {
		return nil, 0, false
	}
	return r.msg, r.expiries, true
}

// Running reports whether the timer is armed.
func (r *RetxTimer) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.timer != nil
}

// ArmNSSAATimer (re)starts T3575 supervision (see RetxTimer.Arm); cmd is the
// COMMAND to retransmit.
func (u *UEContext) ArmNSSAATimer(cmd any, expiries int, start func(gen uint64) NSSAATimerStopper) {
	u.nssaaT.Arm(cmd, expiries, start)
}

// StopNSSAATimer stops T3575 and invalidates callbacks already fired. Safe on a
// UE with no timer, from any goroutine.
func (u *UEContext) StopNSSAATimer() { u.nssaaT.Stop() }

// NSSAATimerCurrent returns the COMMAND and expiry count of the T3575 armed
// with generation gen, or ok=false when it was stopped or replaced meanwhile.
func (u *UEContext) NSSAATimerCurrent(gen uint64) (cmd any, expiries int, ok bool) {
	return u.nssaaT.Current(gen)
}

// NSSAATimerRunning reports whether a T3575 supervision is armed.
func (u *UEContext) NSSAATimerRunning() bool { return u.nssaaT.Running() }

// ArmDeregTimer (re)starts T3522 supervision of a network-initiated
// DEREGISTRATION REQUEST; req is the message to retransmit.
// Ref: TS 24.501 §5.5.2.3.1, §5.5.2.3.5 a)
func (u *UEContext) ArmDeregTimer(req any, expiries int, start func(gen uint64) TimerStopper) {
	u.deregT.Arm(req, expiries, start)
}

// StopDeregTimer stops T3522 (DEREGISTRATION ACCEPT received, procedure aborted
// or context removed) and invalidates callbacks already fired. Safe on a UE with
// no timer, from any goroutine.
func (u *UEContext) StopDeregTimer() { u.deregT.Stop() }

// DeregTimerCurrent returns the DEREGISTRATION REQUEST and expiry count of the
// T3522 armed with generation gen, or ok=false when it was stopped or replaced.
func (u *UEContext) DeregTimerCurrent(gen uint64) (req any, expiries int, ok bool) {
	return u.deregT.Current(gen)
}

// DeregTimerRunning reports whether a T3522 supervision is armed.
func (u *UEContext) DeregTimerRunning() bool { return u.deregT.Running() }

// EnqueueSerial appends f to this UE's serial task queue and returns
// immediately. Tasks run one at a time in FIFO order on a lazily started
// drain goroutine, so per-UE NAS ordering (notably SecurityCtx.UplinkCount)
// is preserved while tasks for different UEs run concurrently.
func (u *UEContext) EnqueueSerial(f func()) {
	u.taskMu.Lock()
	u.taskQueue = append(u.taskQueue, f)
	if u.taskDraining {
		u.taskMu.Unlock()
		return
	}
	u.taskDraining = true
	u.taskMu.Unlock()

	go func() {
		for {
			u.taskMu.Lock()
			if len(u.taskQueue) == 0 {
				u.taskDraining = false
				u.taskMu.Unlock()
				return
			}
			next := u.taskQueue[0]
			u.taskQueue = u.taskQueue[1:]
			u.taskMu.Unlock()
			u.runSerialTask(next)
		}
	}()
}

// TAI is a Tracking Area Identity.
type TAI struct {
	MCC string
	MNC string
	TAC uint32 // Tracking Area Code (24 bits)
}

// ServiceAreaRestriction is the access restriction policy returned by PCF.
// Ref: TS 29.507 §6.1.1.2.5, TS 23.501 §5.3.4
type ServiceAreaRestriction struct {
	// RestrictionType is "ALLOWED_AREAS" or "NOT_ALLOWED_AREAS".
	RestrictionType string
	// AllowedTACs lists the allowed TAC hex strings (e.g., "000001") when
	// RestrictionType == "ALLOWED_AREAS".
	AllowedTACs []string
	// NotAllowedTACs lists the restricted TAC hex strings when
	// RestrictionType == "NOT_ALLOWED_AREAS".
	NotAllowedTACs []string
}

// AllowsTAC reports whether tac is inside the allowed area defined by the
// restriction. A nil restriction, an unknown restriction type, or ALLOWED_AREAS
// with an absent (nil) area list means "no restriction". ALLOWED_AREAS with a
// non-nil EMPTY list means the UE is allowed nowhere (TS 29.571 §5.4.4.18 note:
// "the empty array is used when service is allowed/restricted nowhere").
// Ref: TS 23.501 §5.3.4.1, TS 29.507 §6.1.1.2.5
func (s *ServiceAreaRestriction) AllowsTAC(tac uint32) bool {
	if s == nil {
		return true
	}
	tacHex := fmt.Sprintf("%06x", tac)
	switch s.RestrictionType {
	case "ALLOWED_AREAS":
		if s.AllowedTACs == nil {
			return true
		}
		for _, allowed := range s.AllowedTACs {
			if strings.EqualFold(allowed, tacHex) {
				return true
			}
		}
		return false
	case "NOT_ALLOWED_AREAS":
		for _, blocked := range s.NotAllowedTACs {
			if strings.EqualFold(blocked, tacHex) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

// InNonAllowedArea reports whether the UE's current TA is a Non-Allowed Area or
// lies outside its Allowed Area (TS 23.501 §3.1, §5.3.4.1). It is the single
// decision point for the 5GMM cause #28 enforcement paths.
//
// It takes the UE lock to snapshot ServAreaRes and the TAI: callers must not
// hold it.
func (u *UEContext) InNonAllowedArea() bool {
	if u == nil {
		return false
	}
	sar, tac := u.ServiceAreaSnapshot()
	if sar == nil {
		return false
	}
	return !sar.AllowsTAC(tac)
}

// ServiceAreaSnapshot returns a copy of the PCF service area restriction (nil
// when none) and the current TAC, read consistently under the UE lock. Callers
// must not hold the UE lock.
func (u *UEContext) ServiceAreaSnapshot() (*ServiceAreaRestriction, uint32) {
	u.Lock()
	defer u.Unlock()
	if u.ServAreaRes == nil {
		return nil, u.TAI.TAC
	}
	c := *u.ServAreaRes
	if u.ServAreaRes.AllowedTACs != nil { // nil (no list) differs from empty (allowed nowhere)
		c.AllowedTACs = append([]string{}, u.ServAreaRes.AllowedTACs...)
	}
	c.NotAllowedTACs = append([]string(nil), u.ServAreaRes.NotAllowedTACs...)
	return &c, u.TAI.TAC
}

// SetServiceAreaRestriction stores the PCF service area restriction under the
// UE lock.
func (u *UEContext) SetServiceAreaRestriction(sar *ServiceAreaRestriction) {
	u.Lock()
	u.ServAreaRes = sar
	u.Unlock()
}

// SNSSAISubscribed mirrors the UDR subscription type.
// DNN carries the portal-assigned preferred DNN for this slice; when non-empty
// the AMF enforces it at PDU session establishment regardless of what the UE requests.
type SNSSAISubscribed struct {
	SST uint8
	SD  string
	DNN string // preferred DNN (empty = no preference, use UE-requested DNN)
	// SubjectToNSSAA mirrors the subscription flag
	// subjectToNetworkSliceSpecificAuthenticationAndAuthorization (TS 29.503 / TS 23.501
	// §5.15.10). When true, the slice requires NSSAA before being added to Allowed NSSAI.
	SubjectToNSSAA bool
}

// PDUSession represents an established PDU session in the AMF.
// SMFInstanceID holds the SM context reference returned by the SMF, not the
// SMF NF instance id.
//
// oapi: none AMF-internal PDU session state, not an SBI body (persisted as store.PDUSessionRecord)
type PDUSession struct {
	PDUSessionID   uint8
	SMFInstanceID  string
	SMFAddress     string
	SNSSAI         SNSSAISubscribed
	DNN            string
	PDUSessionType string
	QFIs           []uint8
	// N2SmTransfer is the APER-encoded PDUSessionResourceSetupRequestTransfer from
	// the SMF at session establishment. Cached here so the AMF can populate the
	// HandoverRequestTransfer during N2 handover without re-querying the SMF.
	// Ref: TS 38.413 §9.3.4.1 (PDU Session Resource Setup Request Transfer, also used as the Handover Request Transfer)
	N2SmTransfer []byte
	// Features is the Nsmf_PDUSession supportedFeatures set negotiated with
	// the SMF when the session was created (TS 29.500 §6.6.2, TS 29.502
	// §6.1.8): the intersection of what this AMF offered and what the SMF
	// answered. Empty when nothing was offered (rel17 profile) or negotiated.
	// Runtime-only: tagged json:"-" so any JSON encoding of the session, and
	// therefore the persisted context_json, is unchanged; after a restart the
	// set is simply empty again.
	Features features.Set `json:"-"`
}

// nccModulus is the Next Hop Chaining Count range: NCC is a 3-bit counter
// (INTEGER 0..7). Ref: TS 38.413 §9.3.1.18, TS 33.501 §6.9.2.1.1.
const nccModulus = 8

// InitialNCC is the NCC associated with the first NH derived after a new KgNB:
// the KgNB itself is tied to a virtual NH with NCC 0, "the derived NH value is
// associated with the NCC value one". Ref: TS 33.501 §6.9.2.1.1.
const InitialNCC uint8 = 1

// AddPagedPDUSession records psi as the target of a network-triggered Service
// Request so the paging response re-activates its user plane. Safe for
// concurrent use; takes ue.mu — do not call with the lock held.
// Ref: TS 23.502 §4.2.3.3 step 3a
func (u *UEContext) AddPagedPDUSession(psi uint8) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.pagedPDUSessions == nil {
		u.pagedPDUSessions = make(map[uint8]struct{})
	}
	u.pagedPDUSessions[psi] = struct{}{}
}

// PagedPDUSessions returns the recorded paged PSIs in ascending order without
// clearing them (read accessor). Takes ue.mu.
func (u *UEContext) PagedPDUSessions() []uint8 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.sortedPagedLocked()
}

// TakePagedPDUSessions returns the recorded paged PSIs in ascending order and
// clears the set, so it never leaks into a later Service Request. Takes ue.mu.
// Ref: TS 23.502 §4.2.3.3 step 6
func (u *UEContext) TakePagedPDUSessions() []uint8 {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := u.sortedPagedLocked()
	u.pagedPDUSessions = nil
	return out
}

// sortedPagedLocked returns the paged PSIs sorted ascending; caller holds u.mu.
func (u *UEContext) sortedPagedLocked() []uint8 {
	if len(u.pagedPDUSessions) == 0 {
		return nil
	}
	out := make([]uint8, 0, len(u.pagedPDUSessions))
	for psi := range u.pagedPDUSessions {
		out = append(out, psi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// SetKgNB stores a newly established KgNB and (re)starts the NH chain:
// NH1 = KNH(KAMF, KgNB), NCC = 1. Call it from every site that sets a new KgNB
// (Registration, Service Request, Registration Update). It takes ue.mu — do not
// call with the lock held (use SetKgNBLocked). If KAMF is not set the chain stays
// invalid. Ref: TS 33.501 §6.9.2.1.1, Annex A.10.
func (u *UEContext) SetKgNB(kgnb [32]byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.SetKgNBLocked(kgnb)
}

// SetKgNBLocked is SetKgNB for callers that already hold ue.mu.
func (u *UEContext) SetKgNBLocked(kgnb [32]byte) {
	u.KgNB = kgnb
	u.NHValid = false
	u.NH = [32]byte{}
	u.NCC = 0
	if !kamfUsable(u.SecurityCtx.KAMF) {
		return
	}
	copy(u.NH[:], kdf.KNH(u.SecurityCtx.KAMF, kgnb[:]))
	u.NCC = InitialNCC
	u.NHValid = true
}

// NextNH advances the NH chain and returns the new pair: NCC := (NCC+1) mod 8,
// NH := KNH(KAMF, NH_prev). Used for each Path Switch Request Acknowledge and
// each HANDOVER REQUEST; atomic under ue.mu. ok is false (chain untouched) when
// no usable chain exists (no KgNB established yet or KAMF unusable).
// Ref: TS 33.501 §6.9.2.3.2, §6.9.2.3.3, Annex A.10.
func (u *UEContext) NextNH() (nh [32]byte, ncc uint8, ok bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.NextNHLocked()
}

// NextNHLocked is NextNH for callers that already hold ue.mu.
func (u *UEContext) NextNHLocked() (nh [32]byte, ncc uint8, ok bool) {
	if !u.NHValid || !kamfUsable(u.SecurityCtx.KAMF) {
		return [32]byte{}, 0, false
	}
	u.NCC = (u.NCC + 1) % nccModulus
	copy(u.NH[:], kdf.KNH(u.SecurityCtx.KAMF, u.NH[:]))
	return u.NH, u.NCC, true
}

// NHChainUsableLocked reports whether NextNHLocked would succeed (chain initialised and
// KAMF usable) without advancing it. Caller holds ue.mu. Used to pre-check a Path Switch
// Request before the SMF leg so a request that would be rejected never switches the UPF.
func (u *UEContext) NHChainUsableLocked() bool {
	return u.NHValid && kamfUsable(u.SecurityCtx.KAMF)
}

// NHState returns the current chain state without advancing it (diagnostics,
// tests). valid is false until a KgNB has been set.
func (u *UEContext) NHState() (nh [32]byte, ncc uint8, valid bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.NH, u.NCC, u.NHValid
}

// SetNHState overwrites the chain state (restoring a chain, test setup).
func (u *UEContext) SetNHState(nh [32]byte, ncc uint8) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.NH, u.NCC, u.NHValid = nh, ncc%nccModulus, true
}

// kamfUsable reports whether KAMF is a non-empty, non-zero key.
func kamfUsable(kamf []byte) bool {
	for _, b := range kamf {
		if b != 0 {
			return true
		}
	}
	return false
}

// SetT3512SentSecs records the T3512 sent to the UE in a Registration Accept.
// It takes the UE lock; the caller must not hold it.
func (u *UEContext) SetT3512SentSecs(secs int) {
	u.mu.Lock()
	u.T3512SentSecs = secs
	u.mu.Unlock()
}

// T3512Sent returns the T3512 (seconds) last sent to the UE, 0 if unknown.
func (u *UEContext) T3512Sent() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.T3512SentSecs
}

// ArmedDurations returns the durations used when the Mobile Reachable and
// Implicit Detach timers were last armed (0 if never armed).
func (u *UEContext) ArmedDurations() (mobileReachable, implicitDetach time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.MobileReachableDur, u.ImplicitDetachDur
}

// Lock/Unlock expose the mutex for procedures that need to hold state across steps.
func (u *UEContext) Lock()   { u.mu.Lock() }
func (u *UEContext) Unlock() { u.mu.Unlock() }

// StopAllTimers cancels every running lifecycle timer for this UE.
// Must be called before Remove() to prevent callbacks from firing on a deleted context.
// Caller must hold u.mu or be the sole owner.
func (u *UEContext) StopAllTimers() {
	if u.MobileReachableTimer != nil {
		u.MobileReachableTimer.Stop()
	}
	if u.ImplicitDetachTimer != nil {
		u.ImplicitDetachTimer.Stop()
	}
	if u.PendingRemovalTimer != nil {
		u.PendingRemovalTimer.Stop()
	}
}

// TransitionTo changes the 5GMM state and logs the transition.
func (u *UEContext) TransitionTo(newState GMM5State) {
	old := u.State
	u.State = newState
	// Caller is responsible for logging with the procedure logger.
	_ = old
}

// ---- Context Store -------------------------------------------------------

// Manager stores all UE and RAN contexts in the AMF.
// When store and cache are non-nil, all mutations are written through to
// PostgreSQL (store) and the TMSI counter uses Redis (cache).
type Manager struct {
	mu sync.RWMutex

	// Key: AMF UE NGAP ID
	uesByNGAPId map[int64]*UEContext
	// Key: SUPI (after authentication)
	uesBySUPI map[string]*UEContext
	// Key: GUTI TMSI (for fast lookup on mobility)
	uesByTMSI map[uint32]*UEContext

	// NGAP ID counter (per-process atomic; NGAP-IDs reset on restart, which is safe
	// because gNBs also re-establish N2 associations after an AMF restart).
	ngapIDCounter atomic.Int64

	// TMSI counter fallback (used when cache is nil).
	tmsiCounter atomic.Uint32

	// AMF identity (used to build GUTIs)
	AMFID AMFIdentity

	// Persistence (both optional; nil = in-memory only, useful in tests).
	db     store.Store
	cache  store.Cache
	logger *slog.Logger

	// releaseSMContext releases one SM context at the SMF. Set via
	// SetSMContextReleaser by the wiring in cmd/amf; nil = no SMF client
	// configured (tests, dev without a stack), in which case the startup
	// release is skipped. Injected rather than importing an SBI client here:
	// the context package must not depend on the SBI layer.
	// Ref: TS 23.007 §16, TS 29.502 §5.2.2.3.3.
	releaseSMContext func(ctx context.Context, smContextRef string) error

	// panicReleaser releases a UE after a recovered serial-queue panic
	// (panic.go). Guarded by mu; set via SetPanicReleaser.
	panicReleaser PanicReleaser
}

// SetSMContextReleaser installs the callback LoadFromStore uses to release the
// SM contexts of purged UEs at the SMF. Must be called before LoadFromStore.
func (m *Manager) SetSMContextReleaser(fn func(ctx context.Context, smContextRef string) error) {
	m.releaseSMContext = fn
}

// AMFIdentity identifies this AMF instance.
type AMFIdentity struct {
	MCC         string
	MNC         string
	AMFRegionID byte
	AMFSetID    uint16
	AMFID       byte
}

// NewManager creates an empty context manager.
// db and cache may be nil for in-memory-only operation (tests, dev without Docker).
func NewManager(id AMFIdentity, db store.Store, cache store.Cache, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		uesByNGAPId: make(map[int64]*UEContext),
		uesBySUPI:   make(map[string]*UEContext),
		uesByTMSI:   make(map[uint32]*UEContext),
		AMFID:       id,
		db:          db,
		cache:       cache,
		logger:      logger,
	}
}

// LoadFromStore purges stale UE contexts left in PostgreSQL from a previous AMF
// run, then seeds the TMSI counter to avoid reuse. It intentionally does NOT
// reload contexts into the in-memory maps: after a restart all gNB SCTP
// associations are lost, so every UE context is effectively stale. UEs will
// re-register, creating fresh contexts.
//
// Before purging it releases those contexts' SM contexts at the SMF: the rows
// are the AMF's only record of which PDU sessions exist, so dropping them
// without telling the SMF orphans an SMF session, a UPF PFCP session and a UE
// IP per PDU session, permanently, on every restart.
// Ref: TS 23.007 §16 (restoration of data in the AMF).
func (m *Manager) LoadFromStore(ctx context.Context) error {
	if m.db == nil {
		return nil
	}
	// Read max TMSI before purging so the counter can continue from where it left off.
	maxTMSI, err := m.db.MaxTMSI(ctx)
	if err != nil {
		m.logger.Warn("amf: could not read max TMSI before purge", "error", err)
	}

	m.releaseStaleSMContexts(ctx)

	purged, err := m.db.PurgeAllUEContexts(ctx)
	if err != nil {
		return fmt.Errorf("amf manager: LoadFromStore purge: %w", err)
	}
	m.logger.Info("amf: purged stale UE contexts from previous run — starting fresh",
		"purged", purged,
		"max_tmsi_seeded", maxTMSI,
	)

	if maxTMSI > 0 {
		if m.cache != nil {
			if err := m.cache.SeedTMSIIfLower(ctx, maxTMSI); err != nil {
				m.logger.Warn("amf: could not seed TMSI counter", "error", err)
			}
		} else {
			m.tmsiCounter.Store(maxTMSI)
		}
	}
	return nil
}

// releaseStaleSMContexts releases, at the SMF, the SM contexts of every UE
// context persisted by a previous AMF run. Called by LoadFromStore immediately
// before the rows are purged — after the purge the AMF has no record of which
// PDU sessions existed, so this is the last chance to free them.
//
// Best-effort by design: a failure here must not stop the AMF from starting
// (the SMF may still be booting, or a session may already be gone), so every
// error is logged and the purge proceeds. Deleting an unknown smContextRef is
// harmless — the SMF answers 204 and logs "session not found".
//
// Ref: TS 23.007 §16, TS 23.502 §4.3.4, TS 29.502 §5.2.2.3.3.
func (m *Manager) releaseStaleSMContexts(ctx context.Context) {
	if m.releaseSMContext == nil {
		return // no SMF client wired (tests, dev without a stack)
	}
	records, err := m.db.ListAllUEContexts(ctx)
	if err != nil {
		m.logger.Warn("amf: could not list stale UE contexts — SM contexts may leak at the SMF",
			"error", err)
		return
	}

	var released, failed int
	for _, rec := range records {
		for _, sess := range rec.PDUSessions {
			if sess.SMFInstanceID == "" {
				continue
			}
			if err := m.releaseSMContext(ctx, sess.SMFInstanceID); err != nil {
				failed++
				m.logger.Warn("amf: releasing stale SM context failed — SMF/UPF session may leak",
					"supi", rec.SUPI,
					"pdu_session_id", sess.PDUSessionID,
					"smContextRef", sess.SMFInstanceID,
					"error", err,
					"spec_ref", "TS 29.502 §5.2.2.3.3",
				)
				continue
			}
			released++
		}
	}
	if released > 0 || failed > 0 {
		m.logger.Info("amf: released stale SM contexts from previous run",
			"released", released,
			"failed", failed,
			"interface", "Nsmf",
			"direction", "OUT",
			"spec_ref", "TS 23.007 §16",
		)
	}
}

// PersistUE writes the UE context to PostgreSQL. No-op when store is nil.
// Errors are logged and do not abort the caller.
func (m *Manager) PersistUE(ctx context.Context, ue *UEContext) {
	if m.db == nil {
		return
	}
	ue.Lock()
	rec := ueContextToRecord(ue)
	ue.Unlock()
	if err := m.db.UpsertUE(ctx, rec); err != nil {
		m.logger.Error("amf: PersistUE failed", "supi", ue.SUPI, "error", err)
	}
}

// AllocateUEContext creates a new UEContext with a fresh AMF UE NGAP ID.
// NGAP-IDs are per-process monotone counters; they reset on AMF restart,
// which is safe because gNBs re-establish N2 after a restart anyway.
func (m *Manager) AllocateUEContext(ranID int64) *UEContext {
	amfID := m.ngapIDCounter.Add(1)
	ue := &UEContext{
		AMFUENGAPId:  amfID,
		RANUENGAPId:  ranID,
		State:        GMMDeregistered,
		PDUSessions:  make(map[uint8]*PDUSession),
		LastActivity: time.Now(),
		mgr:          m,
	}
	m.mu.Lock()
	m.uesByNGAPId[amfID] = ue
	m.mu.Unlock()
	return ue
}

// GetByNGAPId looks up a UE by AMF UE NGAP ID.
func (m *Manager) GetByNGAPId(id int64) (*UEContext, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ue, ok := m.uesByNGAPId[id]
	return ue, ok
}

// GetBySUPI looks up a UE by SUPI.
func (m *Manager) GetBySUPI(supi string) (*UEContext, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ue, ok := m.uesBySUPI[supi]
	return ue, ok
}

// GetByTMSI looks up a UE by 5G-TMSI (from GUTI). Used in Service Request to
// identify a returning CM-IDLE UE without a full re-registration.
// Ref: TS 23.502 §4.2.3
func (m *Manager) GetByTMSI(tmsi uint32) (*UEContext, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ue, ok := m.uesByTMSI[tmsi]
	return ue, ok
}

// SetSUPI associates a SUPI with a UE context after successful authentication.
// Returns any UEContext that previously held the same SUPI (the "displaced" stale
// context). The caller must release that context's PDU sessions and remove it from
// the manager. Returns nil when there is no prior context for that SUPI.
// Ref: TS 23.502 §4.2.2.2.2 — new registration supersedes a stale one for same SUPI.
func (m *Manager) SetSUPI(ue *UEContext, supi string) *UEContext {
	ue.SUPI = supi
	m.mu.Lock()
	old := m.uesBySUPI[supi]
	if old == ue {
		m.mu.Unlock()
		return nil
	}
	m.uesBySUPI[supi] = ue
	m.mu.Unlock()
	return old
}

// AssignGUTI creates and assigns a new 5G-GUTI to the UE.
// Returns the allocated GUTI.
func (m *Manager) AssignGUTI(ctx context.Context, ue *UEContext) *GUTI5G {
	var tmsi uint32
	if m.cache != nil {
		if v, err := m.cache.NextTMSI(ctx); err == nil {
			tmsi = v
		} else {
			m.logger.Warn("amf: Redis NextTMSI failed, falling back to local counter", "error", err)
			tmsi = m.tmsiCounter.Add(1)
		}
	} else {
		tmsi = m.tmsiCounter.Add(1)
	}
	guti := &GUTI5G{
		MCC:         m.AMFID.MCC,
		MNC:         m.AMFID.MNC,
		AMFRegionID: m.AMFID.AMFRegionID,
		AMFSetID:    m.AMFID.AMFSetID,
		AMFID:       m.AMFID.AMFID,
		TMSI:        tmsi,
	}
	ue.Lock()
	old := ue.GUTI
	ue.GUTI = guti
	ue.Unlock()

	// The previous 5G-TMSI stays resolvable only until the new 5G-GUTI is
	// confirmed (ConfirmGUTI): the index holds at most the current and one
	// previous 5G-TMSI per UE, so repeated reallocation cannot grow it.
	// Ref: TS 24.501 §5.5.1.2.4, §5.5.1.3.8 a) 1) i)
	m.mu.Lock()
	if old != nil && old.TMSI != tmsi {
		if ue.hasPrevTMSI {
			m.dropTMSILocked(ue, ue.prevTMSI)
		}
		ue.prevTMSI, ue.hasPrevTMSI = old.TMSI, true
	}
	m.uesByTMSI[tmsi] = ue
	m.mu.Unlock()
	return guti
}

// ConfirmGUTI drops the previous 5G-TMSI of ue from the 5G-TMSI index once the
// new 5G-GUTI is in use (REGISTRATION COMPLETE received): from then on the old
// 5G-GUTI is invalid. No-op when no previous 5G-TMSI is pending.
// Ref: TS 24.501 §5.5.1.2.4, §5.5.1.3.8 a) 1) i)
func (m *Manager) ConfirmGUTI(ue *UEContext) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ue.hasPrevTMSI {
		m.dropTMSILocked(ue, ue.prevTMSI)
		ue.prevTMSI, ue.hasPrevTMSI = 0, false
	}
}

// dropTMSILocked deletes the 5G-TMSI index entry tmsi only if it still points to
// ue (a value reused by another context is left alone). Caller holds m.mu.
func (m *Manager) dropTMSILocked(ue *UEContext, tmsi uint32) {
	if m.uesByTMSI[tmsi] == ue {
		delete(m.uesByTMSI, tmsi)
	}
}

// RegisteredCount returns the number of UEs currently in GMMRegistered state.
func (m *Manager) RegisteredCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, ue := range m.uesByNGAPId {
		if ue.State == GMMRegistered {
			n++
		}
	}
	return n
}

// ConnectedCount returns the total number of UE contexts (N2-associated).
func (m *Manager) ConnectedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.uesByNGAPId)
}

// SliceKey identifies an S-NSSAI for per-slice UE counting.
type SliceKey struct {
	SST uint8
	SD  string
}

// CountBySlice returns the number of registered UEs per S-NSSAI.
// Only UEs in GMMRegistered state with at least one AllowedNSSAI entry are counted.
func (m *Manager) CountBySlice() map[SliceKey]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	counts := make(map[SliceKey]int)
	for _, ue := range m.uesByNGAPId {
		if ue.State != GMMRegistered {
			continue
		}
		for _, s := range ue.AllowedNSSAI {
			counts[SliceKey{SST: s.SST, SD: s.SD}]++
		}
	}
	return counts
}

// UESnapshot is a flat, JSON-safe view of a UEContext exposing only the fields
// that are safe to surface on the read-only management API (no keys, no
// pointers). Consumed by the MCP server's ue_list / ue_context_get tools.
//
// oapi: none O&M view on the plain-HTTP mgmt port :9002, not an SBI body
type UESnapshot struct {
	SUPI             string    `json:"supi"`
	SUCI             string    `json:"suci,omitempty"`
	GUTI             string    `json:"guti,omitempty"`
	PEI              string    `json:"pei,omitempty"`
	AMFUENGAPId      int64     `json:"amf_ue_ngap_id"`
	RANUENGAPId      int64     `json:"ran_ue_ngap_id"`
	GMMState         string    `json:"gmm_state"`
	CMState          string    `json:"cm_state"`
	RegistrationTime time.Time `json:"registration_time"`
	LastActivity     time.Time `json:"last_activity"`
	// PDUSessionIDs is []int (not []uint8) so encoding/json emits a numeric array
	// instead of a base64 string. Ascending order.
	PDUSessionIDs []int `json:"pdu_session_ids"`
	// Capability5GMM is the UE's 5GMM capability IE value octets (hex) and
	// Capability5GMMBits the names of the set bits; "" and [] when the UE never
	// sent the IE. Ref: TS 24.501 §9.11.3.1
	Capability5GMM     string   `json:"capability_5gmm"`
	Capability5GMMBits []string `json:"capability_5gmm_bits"`
}

// Snapshot returns a JSON-safe view of the UE context. It takes the per-UE lock
// to copy fields consistently; callers must hold only a *UEContext (not m.mu).
func (u *UEContext) Snapshot() UESnapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	snap := UESnapshot{
		SUPI:             u.SUPI,
		SUCI:             u.SUCI,
		PEI:              u.PEI,
		AMFUENGAPId:      u.AMFUENGAPId,
		RANUENGAPId:      u.RANUENGAPId,
		GMMState:         u.State.String(),
		CMState:          u.CMState.String(),
		RegistrationTime: u.RegistrationTime,
		LastActivity:     u.LastActivity,
	}
	if u.GUTI != nil {
		snap.GUTI = u.GUTI.String()
	}
	for psi := range u.PDUSessions {
		snap.PDUSessionIDs = append(snap.PDUSessionIDs, int(psi))
	}
	sort.Ints(snap.PDUSessionIDs)
	snap.Capability5GMM = u.Capability5GMM.RawHex()
	snap.Capability5GMMBits = u.Capability5GMM.SetBitNames()
	if snap.Capability5GMMBits == nil {
		snap.Capability5GMMBits = []string{}
	}
	return snap
}

// ListContexts returns snapshots of every active UE context (read-only). The
// snapshots are taken outside m.mu to avoid holding the manager lock across the
// per-UE locks.
func (m *Manager) ListContexts() []UESnapshot {
	m.mu.RLock()
	ues := make([]*UEContext, 0, len(m.uesByNGAPId))
	for _, ue := range m.uesByNGAPId {
		ues = append(ues, ue)
	}
	m.mu.RUnlock()

	out := make([]UESnapshot, 0, len(ues))
	for _, ue := range ues {
		out = append(out, ue.Snapshot())
	}
	return out
}

// Remove removes a UE context from all indexes and deletes it from PostgreSQL.
// When called on a context that was displaced by a newer registration for the same
// SUPI, it safely skips the SUPI map and DB deletion (the new context already owns
// those). This prevents accidental erasure of the live registration record.
func (m *Manager) Remove(ctx context.Context, ue *UEContext) {
	// Cancel any running lifecycle timers before removing the context so that
	// callbacks cannot fire on a context that no longer exists in the manager.
	ue.Lock()
	ue.StopAllTimers()
	ue.Unlock()
	// The NSSAA T3575 supervision dies with the context (it is not a lifecycle
	// timer: StopAllTimers also runs on a UE's reconnection).
	ue.StopNSSAATimer()
	ue.StopDeregTimer()
	ue.StopRegTimer() // T3550 / T3560 / T3570 die with the context

	m.mu.Lock()
	delete(m.uesByNGAPId, ue.AMFUENGAPId)
	// Guard: only remove the SUPI slot if this context still owns it. If a new
	// registration for the same SUPI has already replaced it, leave the new entry
	// intact and skip the DB deletion — the new context will upsert its own record.
	ownsSUPI := ue.SUPI != "" && m.uesBySUPI[ue.SUPI] == ue
	if ownsSUPI {
		delete(m.uesBySUPI, ue.SUPI)
	}
	if ue.GUTI != nil {
		delete(m.uesByTMSI, ue.GUTI.TMSI)
	}
	if ue.hasPrevTMSI {
		m.dropTMSILocked(ue, ue.prevTMSI)
		ue.prevTMSI, ue.hasPrevTMSI = 0, false
	}
	m.mu.Unlock()

	if m.db != nil && ownsSUPI {
		if err := m.db.DeleteUE(ctx, ue.SUPI); err != nil {
			m.logger.Error("amf: Remove DeleteUE failed", "supi", ue.SUPI, "error", err)
		}
	}
}

// CorrelationID returns a stable log correlation ID for the UE.
func (u *UEContext) CorrelationID() string {
	if u.SUPI != "" {
		return u.SUPI
	}
	if u.SUCI != "" {
		// Last 8 characters; a shorter value (e.g. the "unknown" placeholder of
		// a non-SUCI identity) is used whole instead of slicing out of range.
		s := u.SUCI
		if len(s) > correlationSUCISuffixLen {
			s = s[len(s)-correlationSUCISuffixLen:]
		}
		return "suci-" + s
	}
	return fmt.Sprintf("amf-ue-ngap-%d", u.AMFUENGAPId)
}

// ---- Persistence conversion helpers -------------------------------------

// capability5GMMRaw returns the value octets of c for persistence, nil if absent.
func capability5GMMRaw(c *nas.FiveGMMCapability) []byte {
	if c == nil {
		return nil
	}
	b, err := nas.Encode5GMMCapability(c)
	if err != nil {
		slog.Debug("amf: encode 5GMM capability for persistence", "error", err)
		return nil
	}
	return b
}

// capability5GMMFromRaw re-decodes persisted 5GMM capability octets; empty or
// invalid input yields nil (capability unknown).
func capability5GMMFromRaw(b []byte) *nas.FiveGMMCapability {
	if len(b) == 0 {
		return nil
	}
	c, err := nas.Decode5GMMCapability(b)
	if err != nil {
		slog.Debug("amf: decode persisted 5GMM capability", "error", err)
		return nil
	}
	return c
}

// ueContextToRecord converts an in-memory UEContext to a serialisable UERecord.
// Caller must hold ue.mu (or be the sole owner) while calling.
func ueContextToRecord(ue *UEContext) *store.UERecord {
	sc := ue.persistableSecurityCtx()
	rec := &store.UERecord{
		SUPI:             ue.SUPI,
		GMMState:         int(ue.State),
		CMState:          int(ue.CMState),
		RawUESecCap:      ue.RawUESecCap,
		Capability5GMM:   capability5GMMRaw(ue.Capability5GMM),
		SubscribedAMBRUL: ue.SubscribedAMBR.UL,
		SubscribedAMBRDL: ue.SubscribedAMBR.DL,
		RegistrationTime: ue.RegistrationTime,
		LastActivity:     time.Now(),
		SecurityCtx: store.SecurityRecord{
			NGKSI:          sc.NGKSI,
			IntegrityAlgID: sc.IntegrityAlgID,
			CipheringAlgID: sc.CipheringAlgID,
			KAMF:           sc.KAMF,
			KNASint:        sc.KNASint,
			KNASenc:        sc.KNASenc,
			UplinkCount:    sc.UplinkCount,
			DownlinkCount:  sc.DownlinkCount,
			Active:         sc.Active,
		},
	}
	if ue.GUTI != nil {
		rec.GUTI = &store.GUTIRecord{
			MCC:         ue.GUTI.MCC,
			MNC:         ue.GUTI.MNC,
			AMFRegionID: ue.GUTI.AMFRegionID,
			AMFSetID:    ue.GUTI.AMFSetID,
			AMFID:       ue.GUTI.AMFID,
			TMSI:        ue.GUTI.TMSI,
		}
	}
	for _, s := range ue.AllowedNSSAI {
		rec.AllowedNSSAI = append(rec.AllowedNSSAI, store.SNSSAIRecord{SST: s.SST, SD: s.SD, DNN: s.DNN})
	}
	for _, s := range ue.RequestedNSSAI {
		rec.RequestedNSSAI = append(rec.RequestedNSSAI, store.SNSSAIRecord{SST: s.SST, SD: s.SD})
	}
	for _, ps := range ue.PDUSessions {
		rec.PDUSessions = append(rec.PDUSessions, store.PDUSessionRecord{
			PDUSessionID:   ps.PDUSessionID,
			SMFInstanceID:  ps.SMFInstanceID,
			SMFAddress:     ps.SMFAddress,
			SNSSAI:         store.SNSSAIRecord{SST: ps.SNSSAI.SST, SD: ps.SNSSAI.SD},
			DNN:            ps.DNN,
			PDUSessionType: ps.PDUSessionType,
			QFIs:           ps.QFIs,
			N2SmTransfer:   ps.N2SmTransfer,
		})
	}
	return rec
}

// recordToUEContext reconstructs an in-memory UEContext from a stored UERecord.
// The AMFUENGAPId is set to 0 (reconnected UEs get a fresh NGAP-ID on next attach).
func recordToUEContext(rec *store.UERecord) *UEContext {
	ue := &UEContext{
		SUPI:             rec.SUPI,
		State:            GMM5State(rec.GMMState),
		CMState:          CMState(rec.CMState),
		RawUESecCap:      rec.RawUESecCap,
		Capability5GMM:   capability5GMMFromRaw(rec.Capability5GMM),
		PDUSessions:      make(map[uint8]*PDUSession),
		RegistrationTime: rec.RegistrationTime,
		LastActivity:     rec.LastActivity,
		SecurityCtx: SecurityContext{
			NGKSI:          rec.SecurityCtx.NGKSI,
			IntegrityAlgID: rec.SecurityCtx.IntegrityAlgID,
			CipheringAlgID: rec.SecurityCtx.CipheringAlgID,
			KAMF:           rec.SecurityCtx.KAMF,
			KNASint:        rec.SecurityCtx.KNASint,
			KNASenc:        rec.SecurityCtx.KNASenc,
			UplinkCount:    rec.SecurityCtx.UplinkCount,
			DownlinkCount:  rec.SecurityCtx.DownlinkCount,
			Active:         rec.SecurityCtx.Active,
		},
	}
	ue.SubscribedAMBR.UL = rec.SubscribedAMBRUL
	ue.SubscribedAMBR.DL = rec.SubscribedAMBRDL
	if rec.GUTI != nil {
		ue.GUTI = &GUTI5G{
			MCC:         rec.GUTI.MCC,
			MNC:         rec.GUTI.MNC,
			AMFRegionID: rec.GUTI.AMFRegionID,
			AMFSetID:    rec.GUTI.AMFSetID,
			AMFID:       rec.GUTI.AMFID,
			TMSI:        rec.GUTI.TMSI,
		}
	}
	for _, s := range rec.AllowedNSSAI {
		ue.AllowedNSSAI = append(ue.AllowedNSSAI, SNSSAISubscribed{SST: s.SST, SD: s.SD, DNN: s.DNN})
	}
	for _, s := range rec.RequestedNSSAI {
		ue.RequestedNSSAI = append(ue.RequestedNSSAI, SNSSAISubscribed{SST: s.SST, SD: s.SD})
	}
	for _, ps := range rec.PDUSessions {
		ue.PDUSessions[ps.PDUSessionID] = &PDUSession{
			PDUSessionID:   ps.PDUSessionID,
			SMFInstanceID:  ps.SMFInstanceID,
			SMFAddress:     ps.SMFAddress,
			SNSSAI:         SNSSAISubscribed{SST: ps.SNSSAI.SST, SD: ps.SNSSAI.SD},
			DNN:            ps.DNN,
			PDUSessionType: ps.PDUSessionType,
			QFIs:           ps.QFIs,
			N2SmTransfer:   ps.N2SmTransfer,
		}
	}
	return ue
}

// SetSDMSubscriptionID records the Nudm_SDM subscription id.
func (u *UEContext) SetSDMSubscriptionID(id string) {
	u.sdmMu.Lock()
	u.SDMSubscriptionID = id
	u.sdmMu.Unlock()
}

// TakeSDMSubscriptionID returns the Nudm_SDM subscription id and clears it, so
// the subscription is deleted once.
func (u *UEContext) TakeSDMSubscriptionID() string {
	u.sdmMu.Lock()
	defer u.sdmMu.Unlock()
	id := u.SDMSubscriptionID
	u.SDMSubscriptionID = ""
	return id
}
