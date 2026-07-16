// Package store implements the UDR (Unified Data Repository) data store.
//
// The UDR persists subscriber data, policy data, application data, and
// exposure data per 3GPP TS 29.504 §4.2 / TS 29.505.
//
// This in-memory implementation is for development. Replace with PostgreSQL
// in Phase 1+ by implementing the Store interface.
package store

import (
	"fmt"
	"sync"

	"github.com/francurieses/claudia-5gc/shared/types"
)

// Re-export shared policy types so existing callers using store.URSPRule etc.
// continue to compile without changes.
type URSPRule = types.URSPRule
type TrafficDescriptor = types.TrafficDescriptor
type PortRange = types.PortRange
type RouteSelectionDescriptor = types.RouteSelectionDescriptor
type PolicySubscription = types.PolicySubscription
type SmPolicyData = types.SmPolicyData
type SmPolicySnssaiData = types.SmPolicySnssaiData
type SmPolicyDnnData = types.SmPolicyDnnData

// ---- Subscriber Data (TS 29.505 §5) ------------------------------------

// AuthenticationSubscription holds the authentication credentials for a SUPI.
// Maps to 3GPP TS 29.505 §5.2.2 (resource AuthenticationSubscription).
type AuthenticationSubscription struct {
	SUPI                          string
	AuthenticationMethod          string // "5G_AKA" or "EAP_AKA_PRIME"
	EncPermanentKey               string // Hex-encoded K (encrypted, or plain for dev)
	ProtectionParameterID         string
	SequenceNumber                SequenceNumber
	AuthenticationManagementField string // AMF hex (2 bytes), e.g. "8000"
	AlgorithmID                   string // "milenage" or "tuak"
	EncOpcKey                     string // Hex-encoded OPc
	EncTopcKey                    string // For TUAK
}

// SequenceNumber holds SQN management state per TS 33.501 Annex C.3.2.
type SequenceNumber struct {
	// SQN stored as 6-byte hex string
	SQN string // e.g. "000000000020"
	// SQN_HE: server-side SQN (incremented on each auth)
	SQNScheme string // "NON_TIME_BASED" or "TIME_BASED"
	// Delta: allowed delta between SQN_MS and SQN_HE
	IndividualSQNs []string
}

// AccessAndMobilitySubscriptionData is a subset of the full type.
// Ref: TS 29.505 §5.2.2 (UDR resource AccessAndMobilitySubscriptionData)
type AccessAndMobilitySubscriptionData struct {
	SUPI             string
	GPSIS            []string // Generic Public Subscription Identifiers
	NSSAI            AllowedNSSAI
	InternalGroupIDs []string
	// Subscribed AMBR (kbps)
	SubscribedUEAMBRUplink   uint64
	SubscribedUEAMBRDownlink uint64
}

// AllowedNSSAI holds the list of allowed S-NSSAIs for a subscriber.
type AllowedNSSAI struct {
	SNSSAIs []SNSSAISubscribed
}

// SNSSAISubscribed is an S-NSSAI with optional mapped home S-NSSAI and a
// portal-assigned preferred DNN. The DNN field is populated when the management
// portal assigns a specific DNN to a subscriber's slice; it is propagated via
// AM subscription data so the AMF can enforce it at PDU session establishment.
// JSON tags use lowercase keys to match the portal's JSONB writes.
type SNSSAISubscribed struct {
	SST       uint8  `json:"sst"`
	SD        string `json:"sd,omitempty"` // "" = not set; "000001" etc
	MappedSST uint8  `json:"mappedSst,omitempty"`
	MappedSD  string `json:"mappedSd,omitempty"`
	DNN       string `json:"dnn,omitempty"` // preferred DNN for this slice (portal-configured, optional)
}

// SessionManagementSubscriptionData holds the per-slice session management
// subscription, including the subscribed default QoS profile per DNN.
// Ref: TS 29.503 §6.1.6.2.7 (SessionManagementSubscriptionData), TS 29.505 §5.2.2
type SessionManagementSubscriptionData struct {
	SingleNSSAI       SNSSAIKey                   `json:"singleNssai"`
	DNNConfigurations map[string]DNNConfiguration `json:"dnnConfigurations"`
}

// SNSSAIKey identifies the slice this SM subscription entry applies to.
type SNSSAIKey struct {
	SST uint8  `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

// DNNConfiguration holds per-DNN session subscription data.
// Ref: TS 29.503 §6.1.6.2.8 (DnnConfiguration)
type DNNConfiguration struct {
	PDUSessionTypes PDUSessionTypes `json:"pduSessionTypes"`
	// DefaultQos is the subscribed default QoS profile; serialized as
	// "5gQosProfile" per the TS 29.503 JSON schema.
	DefaultQos  FiveGQoSProfile `json:"5gQosProfile"`
	SessionAMBR AMBR            `json:"sessionAmbr"`
}

// PDUSessionTypes lists the allowed PDU session types for a DNN.
type PDUSessionTypes struct {
	DefaultSessionType  string   `json:"defaultSessionType"`
	AllowedSessionTypes []string `json:"allowedSessionTypes,omitempty"`
}

// FiveGQoSProfile is the subscribed default QoS (TS 29.503 §6.1.6.2.9).
type FiveGQoSProfile struct {
	FiveQI        int `json:"5qi"`
	ARP           ARP `json:"arp"`
	PriorityLevel int `json:"priorityLevel,omitempty"`
}

// ARP is the Allocation and Retention Priority (TS 29.571 §5.5.2).
type ARP struct {
	PriorityLevel int    `json:"priorityLevel"`
	PreemptCap    string `json:"preemptCap"`  // MAY_PREEMPT | NOT_PREEMPT
	PreemptVuln   string `json:"preemptVuln"` // PREEMPTABLE | NOT_PREEMPTABLE
}

// AMBR holds bit-rate strings like "100 Mbps" (TS 29.571 §5.5.2).
type AMBR struct {
	Uplink   string `json:"uplink"`
	Downlink string `json:"downlink"`
}

// SMFSelectionSubscriptionData holds DNN + S-NSSAI combos for session setup.
type SMFSelectionSubscriptionData struct {
	SUPI                  string
	SubscribedSnssaiInfos []SnssaiDnnInfo
}

// SnssaiDnnInfo links an S-NSSAI to its allowed DNNs.
type SnssaiDnnInfo struct {
	SST  uint8
	SD   string
	DNNs []DnnInfo
}

// DnnInfo holds subscription data per DNN.
type DnnInfo struct {
	DNN                 string
	DefaultDNNIndicator bool
	// PDU session types allowed
	PDUSessionTypes []string // "IPV4", "IPV6", "IPV4V6", "UNSTRUCTURED"
}

// ---- Store interface ---------------------------------------------------

// Store is the UDR data access contract.
type Store interface {
	// Authentication subscription
	GetAuthSubscription(supi string) (*AuthenticationSubscription, error)
	PutAuthSubscription(sub *AuthenticationSubscription) error
	UpdateSQN(supi string, sqn string) error

	// Access and mobility subscription
	GetAMSubscription(supi string) (*AccessAndMobilitySubscriptionData, error)
	PutAMSubscription(sub *AccessAndMobilitySubscriptionData) error

	// SMF selection subscription
	GetSMFSelectionSubscription(supi string) (*SMFSelectionSubscriptionData, error)
	PutSMFSelectionSubscription(sub *SMFSelectionSubscriptionData) error

	// Session management subscription — one entry per subscribed slice.
	// GetSMSubscriptions returns nil, nil when no SM data is provisioned.
	GetSMSubscriptions(supi string) ([]SessionManagementSubscriptionData, error)
	PutSMSubscriptions(supi string, subs []SessionManagementSubscriptionData) error

	// Policy subscription — URSP rules (TS 29.525 / TS 24.526)
	// GetPolicySubscription returns rules for a given SUPI.
	// Returns nil, nil when no per-subscriber override exists.
	GetPolicySubscription(supi string) (*PolicySubscription, error)
	PutPolicySubscription(sub *PolicySubscription) error
	DeletePolicySubscription(supi string) error
	ListPolicySubscriptions() ([]*PolicySubscription, error)

	// SM policy data (TS 29.519 §5.6.2.4) — per-S-NSSAI/per-DNN authorized QoS.
	// GetSmPolicyData returns nil, nil when no SM policy data is provisioned.
	// PatchSmPolicyData merges the provided smPolicySnssaiData entries into the
	// existing record (per-S-NSSAI-key replace); it returns ErrNotFound when no
	// record exists yet.
	GetSmPolicyData(supi string) (*SmPolicyData, error)
	PutSmPolicyData(data *SmPolicyData) error
	PatchSmPolicyData(supi string, patch *SmPolicyData) error
}

// ErrNotFound is returned by PatchSmPolicyData when the target record is absent.
var ErrNotFound = fmt.Errorf("udr: record not found")

// ---- InMemory Store ---------------------------------------------------

// InMemory is a thread-safe in-memory implementation of Store.
type InMemory struct {
	mu         sync.RWMutex
	authSubs   map[string]*AuthenticationSubscription
	amSubs     map[string]*AccessAndMobilitySubscriptionData
	smfSubs    map[string]*SMFSelectionSubscriptionData
	smSubs     map[string][]SessionManagementSubscriptionData
	policySubs map[string]*PolicySubscription // keyed by SUPI; "" = operator default
	smPolicy   map[string]*SmPolicyData       // keyed by SUPI
}

func NewInMemory() *InMemory {
	return &InMemory{
		authSubs:   make(map[string]*AuthenticationSubscription),
		amSubs:     make(map[string]*AccessAndMobilitySubscriptionData),
		smfSubs:    make(map[string]*SMFSelectionSubscriptionData),
		smSubs:     make(map[string][]SessionManagementSubscriptionData),
		policySubs: make(map[string]*PolicySubscription),
		smPolicy:   make(map[string]*SmPolicyData),
	}
}

func (s *InMemory) GetAuthSubscription(supi string) (*AuthenticationSubscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.authSubs[supi]
	if !ok {
		return nil, fmt.Errorf("udr: auth subscription not found: %s", supi)
	}
	return sub, nil
}

func (s *InMemory) PutAuthSubscription(sub *AuthenticationSubscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authSubs[sub.SUPI] = sub
	return nil
}

func (s *InMemory) UpdateSQN(supi, sqn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.authSubs[supi]
	if !ok {
		return fmt.Errorf("udr: not found: %s", supi)
	}
	sub.SequenceNumber.SQN = sqn
	return nil
}

func (s *InMemory) GetAMSubscription(supi string) (*AccessAndMobilitySubscriptionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.amSubs[supi]
	if !ok {
		return nil, fmt.Errorf("udr: AM subscription not found: %s", supi)
	}
	return sub, nil
}

func (s *InMemory) PutAMSubscription(sub *AccessAndMobilitySubscriptionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.amSubs[sub.SUPI] = sub
	return nil
}

func (s *InMemory) GetSMFSelectionSubscription(supi string) (*SMFSelectionSubscriptionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.smfSubs[supi]
	if !ok {
		return nil, fmt.Errorf("udr: SMF selection subscription not found: %s", supi)
	}
	return sub, nil
}

func (s *InMemory) PutSMFSelectionSubscription(sub *SMFSelectionSubscriptionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smfSubs[sub.SUPI] = sub
	return nil
}

func (s *InMemory) GetSMSubscriptions(supi string) ([]SessionManagementSubscriptionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.smSubs[supi], nil
}

func (s *InMemory) PutSMSubscriptions(supi string, subs []SessionManagementSubscriptionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smSubs[supi] = subs
	return nil
}

func (s *InMemory) GetPolicySubscription(supi string) (*PolicySubscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.policySubs[supi]
	if !ok {
		return nil, nil
	}
	return sub, nil
}

func (s *InMemory) PutPolicySubscription(sub *PolicySubscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policySubs[sub.SUPI] = sub
	return nil
}

func (s *InMemory) DeletePolicySubscription(supi string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policySubs, supi)
	return nil
}

func (s *InMemory) ListPolicySubscriptions() ([]*PolicySubscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*PolicySubscription, 0, len(s.policySubs))
	for _, v := range s.policySubs {
		out = append(out, v)
	}
	return out, nil
}

func (s *InMemory) GetSmPolicyData(supi string) (*SmPolicyData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.smPolicy[supi]
	if !ok {
		return nil, nil
	}
	return data, nil
}

func (s *InMemory) PutSmPolicyData(data *SmPolicyData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smPolicy[data.SUPI] = data
	return nil
}

func (s *InMemory) PatchSmPolicyData(supi string, patch *SmPolicyData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.smPolicy[supi]
	if !ok || cur == nil {
		return ErrNotFound
	}
	if cur.SmPolicySnssaiData == nil {
		cur.SmPolicySnssaiData = make(map[string]SmPolicySnssaiData)
	}
	for k, v := range patch.SmPolicySnssaiData {
		cur.SmPolicySnssaiData[k] = v
	}
	return nil
}

// ---- Seed helpers for dev/test ----------------------------------------

// SeedTestSubscriber adds a complete test subscriber profile with the default
// internet slice (SST=1, SD=000001).
func SeedTestSubscriber(s Store, supi, kHex, opcHex, amfHex, sqnHex string) error {
	return SeedTestSubscriberWithNSSAI(s, supi, kHex, opcHex, amfHex, sqnHex,
		[]SNSSAISubscribed{{SST: 1, SD: "000001"}})
}

// SeedTestSubscriberWithNSSAI adds a complete test subscriber profile with a
// custom list of allowed S-NSSAIs. Used to seed multi-slice test scenarios.
func SeedTestSubscriberWithNSSAI(s Store, supi, kHex, opcHex, amfHex, sqnHex string, snssais []SNSSAISubscribed) error {
	if err := s.PutAuthSubscription(&AuthenticationSubscription{
		SUPI:                          supi,
		AuthenticationMethod:          "5G_AKA",
		EncPermanentKey:               kHex,
		EncOpcKey:                     opcHex,
		AuthenticationManagementField: amfHex,
		AlgorithmID:                   "milenage",
		SequenceNumber: SequenceNumber{
			SQN:       sqnHex,
			SQNScheme: "NON_TIME_BASED",
		},
	}); err != nil {
		return err
	}
	if err := s.PutAMSubscription(&AccessAndMobilitySubscriptionData{
		SUPI: supi,
		NSSAI: AllowedNSSAI{
			SNSSAIs: snssais,
		},
		SubscribedUEAMBRUplink:   100_000,
		SubscribedUEAMBRDownlink: 100_000,
	}); err != nil {
		return err
	}

	return s.PutSMSubscriptions(supi, BuildSMSubscriptions(snssais))
}

// BuildSMSubscriptions derives session management subscription data from a
// subscriber's allowed S-NSSAIs: one entry per slice, each with a non-zero
// subscribed default 5QI (TS 29.503 §6.1.6.2.7).
//
// This is the single place that maps a slice to its DNN configuration. Both the
// dev seed and the portal-driven resync (SyncSMDataFromAM) go through it, so a
// slice provisioned through either path gets identical QoS.
//
// A slice's DNN is the portal-assigned one when set (SNSSAISubscribed.DNN),
// falling back to "internet" — the DNN every dev slice is expected to carry.
// Without this, a slice provisioned with a non-default DNN would have no
// matching DNNConfiguration and the SMF would fall back to OPERATOR_DEFAULT QoS.
func BuildSMSubscriptions(snssais []SNSSAISubscribed) []SessionManagementSubscriptionData {
	smSubs := make([]SessionManagementSubscriptionData, 0, len(snssais))
	for _, n := range snssais {
		dnn := n.DNN
		if dnn == "" {
			dnn = "internet"
		}
		smSubs = append(smSubs, SessionManagementSubscriptionData{
			SingleNSSAI: SNSSAIKey{SST: n.SST, SD: n.SD},
			DNNConfigurations: map[string]DNNConfiguration{
				dnn: {
					PDUSessionTypes: PDUSessionTypes{
						DefaultSessionType:  "IPV4",
						AllowedSessionTypes: []string{"IPV4"},
					},
					DefaultQos:  DefaultQoSForSlice(n.SST, n.SD),
					SessionAMBR: DefaultAMBRForSlice(n.SST, n.SD),
				},
			},
		})
	}
	return smSubs
}

// SyncSMDataFromAM regenerates a subscriber's session management subscription
// data from the slices currently in its AM subscription, and returns the number
// of slices written.
//
// The management portal provisions slices by writing subscription_am directly.
// Nothing derived sm-data from that, so a portal-added slice had an Allowed
// NSSAI entry but no session management data: the SMF found no DNNConfiguration
// for it and silently fell back to OPERATOR_DEFAULT QoS. Calling this after an
// am-data write keeps the two consistent.
func SyncSMDataFromAM(s Store, supi string) (int, error) {
	am, err := s.GetAMSubscription(supi)
	if err != nil {
		return 0, fmt.Errorf("udr: sync sm-data: read am subscription: %w", err)
	}
	if am == nil {
		return 0, fmt.Errorf("udr: sync sm-data: no am subscription for %s", supi)
	}
	smSubs := BuildSMSubscriptions(am.NSSAI.SNSSAIs)
	if err := s.PutSMSubscriptions(supi, smSubs); err != nil {
		return 0, fmt.Errorf("udr: sync sm-data: write sm subscriptions: %w", err)
	}
	return len(smSubs), nil
}

// DefaultQoSForSlice maps the dev slices to subscribed default QoS profiles.
// 5QI values per TS 23.501 Table 5.7.4-1 (all non-GBR):
//
//	internet (1/000001) → 5QI 9 (best-effort default)
//	gold     (1/000002) → 5QI 7 (voice + video interactive)
//	silver   (2/000001) → 5QI 8 (video buffered streaming)
//	bronze   (3/000001) → 5QI 9
func DefaultQoSForSlice(sst uint8, sd string) FiveGQoSProfile {
	arp := ARP{PriorityLevel: 8, PreemptCap: "NOT_PREEMPT", PreemptVuln: "NOT_PREEMPTABLE"}
	switch {
	case sst == 1 && sd == "000002":
		return FiveGQoSProfile{FiveQI: 7, ARP: ARP{PriorityLevel: 5, PreemptCap: "MAY_PREEMPT", PreemptVuln: "NOT_PREEMPTABLE"}, PriorityLevel: 70}
	case sst == 2:
		return FiveGQoSProfile{FiveQI: 8, ARP: arp, PriorityLevel: 80}
	default:
		return FiveGQoSProfile{FiveQI: 9, ARP: arp, PriorityLevel: 90}
	}
}

// DefaultAMBRForSlice maps the dev slices to subscribed session AMBR values.
func DefaultAMBRForSlice(sst uint8, sd string) AMBR {
	switch {
	case sst == 1 && sd == "000002": // gold
		return AMBR{Uplink: "200 Mbps", Downlink: "500 Mbps"}
	case sst == 2: // silver
		return AMBR{Uplink: "100 Mbps", Downlink: "200 Mbps"}
	case sst == 3: // bronze
		return AMBR{Uplink: "50 Mbps", Downlink: "50 Mbps"}
	default: // internet
		return AMBR{Uplink: "100 Mbps", Downlink: "100 Mbps"}
	}
}
