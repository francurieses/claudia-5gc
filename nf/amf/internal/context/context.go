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
	"sync"
	"sync/atomic"
	"time"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/store"
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
type UEContext struct {
	mu sync.Mutex

	// Identifiers
	SUPI string // Permanent identifier (available after authentication)
	SUCI string // Concealed identifier (from Registration Request)
	GUTI *GUTI5G
	PEI  string // Permanent Equipment Identifier (IMEISV)

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

	// CM state (TS 23.501 §5.3.2)
	CMState CMState

	// 5GMM state machine
	State GMM5State
	// Registration type of ongoing procedure
	RegistrationType byte

	// Security
	SecurityCtx SecurityContext
	// UE security capabilities (reported in Registration Request)
	UESecCapEA [8]bool // EA0..EA7
	UESecCapIA [8]bool // IA0..IA7
	// RawUESecCap stores the verbatim wire bytes of the UE Security Capability IE
	// so they can be replayed exactly in the Security Mode Command.
	RawUESecCap []byte

	// Authentication state (used during auth procedure)
	AuthCtxID   string   // AUSF auth context ID
	PendingRAND [16]byte // RAND sent to UE in AuthenticationRequest; needed for AUTS resync
	KAUSF       []byte
	KSEAF       []byte

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
	RejectedNSSAI   []SNSSAISubscribed
	SubscribedAMBR  struct {
		UL, DL uint64 // kbps
	}

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

	// Timestamps
	RegistrationTime time.Time
	LastActivity     time.Time

	// Policy state (N15 interface, Npcf_UEPolicyControl)
	// PolicyAssociationID is the PCF UE policy association identifier (URSP, npcf-ue-policy-control).
	// Empty when no N15 call was made or when PCF is unavailable.
	PolicyAssociationID string
	// AMPolicyAssocID is the PCF AM policy association identifier (npcf-ampolicycontrol, TS 29.507).
	// Empty when PCF AM policy association was not created.
	AMPolicyAssocID string
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
	PendingRemovalTimer  *time.Timer

	// Per-UE serial task queue used by the NGAP layer to process this UE's
	// messages in arrival order without blocking the shared SCTP read loop
	// (one slow SBI call for one UE must not delay other UEs' NGAP messages).
	// Guarded by taskMu — separate from mu because queued tasks themselves
	// take mu. See EnqueueSerial.
	taskMu       sync.Mutex
	taskQueue    []func()
	taskDraining bool
}

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
			next()
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
	// Ref: TS 38.413 §9.3.4.1, §9.3.4.2
	N2SmTransfer []byte
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
func (m *Manager) LoadFromStore(ctx context.Context) error {
	if m.db == nil {
		return nil
	}
	// Read max TMSI before purging so the counter can continue from where it left off.
	maxTMSI, err := m.db.MaxTMSI(ctx)
	if err != nil {
		m.logger.Warn("amf: could not read max TMSI before purge", "error", err)
	}

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
	ue.GUTI = guti
	ue.Unlock()

	m.mu.Lock()
	m.uesByTMSI[tmsi] = ue
	m.mu.Unlock()
	return guti
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
	PDUSessionIDs    []uint8   `json:"pdu_session_ids"`
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
		snap.PDUSessionIDs = append(snap.PDUSessionIDs, psi)
	}
	sort.Slice(snap.PDUSessionIDs, func(i, j int) bool {
		return snap.PDUSessionIDs[i] < snap.PDUSessionIDs[j]
	})
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
		return "suci-" + u.SUCI[len(u.SUCI)-8:]
	}
	return fmt.Sprintf("amf-ue-ngap-%d", u.AMFUENGAPId)
}

// ---- Persistence conversion helpers -------------------------------------

// ueContextToRecord converts an in-memory UEContext to a serialisable UERecord.
// Caller must hold ue.mu (or be the sole owner) while calling.
func ueContextToRecord(ue *UEContext) *store.UERecord {
	rec := &store.UERecord{
		SUPI:             ue.SUPI,
		GMMState:         int(ue.State),
		CMState:          int(ue.CMState),
		RawUESecCap:      ue.RawUESecCap,
		SubscribedAMBRUL: ue.SubscribedAMBR.UL,
		SubscribedAMBRDL: ue.SubscribedAMBR.DL,
		RegistrationTime: ue.RegistrationTime,
		LastActivity:     time.Now(),
		SecurityCtx: store.SecurityRecord{
			NGKSI:          ue.SecurityCtx.NGKSI,
			IntegrityAlgID: ue.SecurityCtx.IntegrityAlgID,
			CipheringAlgID: ue.SecurityCtx.CipheringAlgID,
			KAMF:           ue.SecurityCtx.KAMF,
			KNASint:        ue.SecurityCtx.KNASint,
			KNASenc:        ue.SecurityCtx.KNASenc,
			UplinkCount:    ue.SecurityCtx.UplinkCount,
			DownlinkCount:  ue.SecurityCtx.DownlinkCount,
			Active:         ue.SecurityCtx.Active,
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
