// Package registry implements the NRF NF profile registry (3GPP TS 29.510).
//
// In-memory implementation for MVP. Production deployments must back this
// with Redis or PostgreSQL for persistence and multi-instance NRF.
package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// NFType per 3GPP TS 29.510 §6.1.6.3.3 (Rel-17 enum plus the Rel-19 additions).
//
// The schema is anyOf [enum, string]: the type is extensible, so values not
// listed below MUST be accepted and stored as-is. The NRF therefore never
// validates NFType against this list. Wire values use underscores
// (e.g. "MB_SMF", "5G_EIR").
type NFType string

const (
	NFTypeAMF   NFType = "AMF"
	NFTypeSMF   NFType = "SMF"
	NFTypeAUSF  NFType = "AUSF"
	NFTypeNEF   NFType = "NEF"
	NFTypePCF   NFType = "PCF"
	NFTypeSMSF  NFType = "SMSF"
	NFTypeNSSF  NFType = "NSSF"
	NFTypeUDM   NFType = "UDM"
	NFTypeUDR   NFType = "UDR"
	NFTypeUDSF  NFType = "UDSF"
	NFTypeUPF   NFType = "UPF"
	NFTypeN3IWF NFType = "N3IWF"
	NFTypeAF    NFType = "AF"
	NFTypeNRF   NFType = "NRF"
	NFTypeBSF   NFType = "BSF"
	NFTypeCHF   NFType = "CHF"
	NFTypeNWDAF NFType = "NWDAF"
	NFTypeSCP   NFType = "SCP"
	NFTypeEASDF NFType = "EASDF"
	NFTypeLMF   NFType = "LMF"  // Location Management Function (TS 23.273, TS 29.572)
	NFTypeGMLC  NFType = "GMLC" // Gateway Mobile Location Centre (TS 23.273, TS 29.515)

	// Remaining Rel-17 values (TS 29.510 §6.1.6.3.3).
	NFType5GEIR     NFType = "5G_EIR"
	NFTypeSEPP      NFType = "SEPP"
	NFTypePCSCF     NFType = "PCSCF"
	NFTypeCBCF      NFType = "CBCF"
	NFTypeHSS       NFType = "HSS"
	NFTypeUCMF      NFType = "UCMF"
	NFTypeSORAF     NFType = "SOR_AF"
	NFTypeSPAF      NFType = "SPAF"
	NFTypeMME       NFType = "MME"
	NFTypeSCSAS     NFType = "SCSAS"
	NFTypeSCEF      NFType = "SCEF"
	NFTypeNSSAAF    NFType = "NSSAAF"
	NFTypeICSCF     NFType = "ICSCF"
	NFTypeSCSCF     NFType = "SCSCF"
	NFTypeDRA       NFType = "DRA"
	NFTypeIMSAS     NFType = "IMS_AS"
	NFTypeAANF      NFType = "AANF"
	NFType5GDDNMF   NFType = "5G_DDNMF"
	NFTypeNSACF     NFType = "NSACF"
	NFTypeMFAF      NFType = "MFAF"
	NFTypeDCCF      NFType = "DCCF"
	NFTypeMBSMF     NFType = "MB_SMF"
	NFTypeTSCTSF    NFType = "TSCTSF"
	NFTypeADRF      NFType = "ADRF"
	NFTypeGBABSF    NFType = "GBA_BSF"
	NFTypeCEF       NFType = "CEF"
	NFTypeMBUPF     NFType = "MB_UPF"
	NFTypeNSWOF     NFType = "NSWOF"
	NFTypePKMF      NFType = "PKMF"
	NFTypeMNPF      NFType = "MNPF"
	NFTypeSMSGMSC   NFType = "SMS_GMSC"
	NFTypeSMSIWMSC  NFType = "SMS_IWMSC"
	NFTypeMBSF      NFType = "MBSF"
	NFTypeMBSTF     NFType = "MBSTF"
	NFTypePANF      NFType = "PANF"
	NFTypeIPSMGW    NFType = "IP_SM_GW"
	NFTypeSMSRouter NFType = "SMS_ROUTER"

	// Rel-19 additions (TS 29.510 V19 §6.1.6.3.3).
	NFTypeDCSF   NFType = "DCSF"
	NFTypeMRF    NFType = "MRF"
	NFTypeMRFP   NFType = "MRFP"
	NFTypeMF     NFType = "MF"
	NFTypeSLPKMF NFType = "SLPKMF"
	NFTypeRH     NFType = "RH"
	NFTypeEIF    NFType = "EIF"
	NFTypeAIOTF  NFType = "AIOTF"
	NFTypeADM    NFType = "ADM"
)

// NFStatus per TS 29.510 §6.1.6.3.4.
type NFStatus string

const (
	NFStatusRegistered     NFStatus = "REGISTERED"
	NFStatusSuspended      NFStatus = "SUSPENDED"
	NFStatusUndiscoverable NFStatus = "UNDISCOVERABLE"
)

// NFProfile is a minimal subset of the NFProfile data type (TS 29.510 §6.1.6.2.2).
// Many optional fields are omitted; expand as new procedures need them.
type NFProfile struct {
	NFInstanceID   string      `json:"nfInstanceId"`
	NFType         NFType      `json:"nfType"`
	NFStatus       NFStatus    `json:"nfStatus"`
	HeartBeatTimer int         `json:"heartBeatTimer,omitempty"`
	PLMNList       []PLMN      `json:"plmnList,omitempty"`
	SNSSAIs        []SNSSAI    `json:"sNssais,omitempty"`
	NSIList        []string    `json:"nsiList,omitempty"`
	FQDN           string      `json:"fqdn,omitempty"`
	IPv4Addresses  []string    `json:"ipv4Addresses,omitempty"`
	NFServices     []NFService `json:"nfServices,omitempty"`
	// DNNList is the list of Data Network Names served by this NF (e.g. SMF/UPF).
	// Ref: TS 29.510 §6.1.6.2.2 (SMFInfo/UPFInfo)
	DNNList  []string `json:"dnnList,omitempty"`
	Capacity int      `json:"capacity,omitempty"` // 0..65535
	Priority int      `json:"priority,omitempty"` // 0..65535
	// NFServiceList is the map form (serviceInstanceId -> NFService) that
	// replaces the deprecated NFServices array from Rel-17 on (TS 29.510 §6.1.6.2.2).
	NFServiceList map[string]NFService `json:"nfServiceList,omitempty"`

	// raw is the registered JSON object exactly as received (or as stored),
	// kept next to the parsed subset so attributes this NRF does not model
	// (Rel-18/19 additions, nested unknown keys) survive. Never mutated after
	// being set, so copies of the struct may share it.
	raw json.RawMessage

	// internal bookkeeping (not serialized to clients)
	registeredAt time.Time `json:"-"`
	lastSeen     time.Time `json:"-"`
}

// profileAlias has the NFProfile fields but none of its methods; it avoids
// recursion in (Un)MarshalJSON.
type profileAlias NFProfile

// authoritativeKeys are the top-level NFProfile keys the NRF itself sets or
// mutates after decoding a registration (nfInstanceId from the URI, nfStatus
// defaulted to REGISTERED, heartBeatTimer defaulted/forced). In the merged
// JSON these come from the parsed struct; every other key is the raw value.
// Any new NRF-side mutation of a modeled NFProfile field MUST be added here,
// otherwise the mutation is silently lost in GET/discovery responses.
var authoritativeKeys = []string{"nfInstanceId", "nfStatus", "heartBeatTimer"}

// UnmarshalJSON parses the modeled subset and records the raw object.
func (p *NFProfile) UnmarshalJSON(b []byte) error {
	if string(bytes.TrimSpace(b)) == "null" {
		return nil
	}
	var parsed profileAlias
	if err := json.Unmarshal(b, &parsed); err != nil {
		return err
	}
	parsed.registeredAt, parsed.lastSeen = p.registeredAt, p.lastSeen
	parsed.raw = append(json.RawMessage(nil), b...)
	*p = NFProfile(parsed)
	return nil
}

// MarshalJSON returns the merged profile: with no raw it is byte-identical to
// the plain struct encoding; with raw it is every raw key (sorted) with the
// authoritativeKeys overridden from the parsed fields. Pointer receiver on
// purpose: it never copies the struct, so it does not race with the
// lastSeen bookkeeping done under the registry lock.
func (p *NFProfile) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal((*profileAlias)(p))
	if err != nil {
		return nil, fmt.Errorf("nrf: marshal profile: %w", err)
	}
	if len(p.raw) == 0 {
		return base, nil
	}
	var merged, parsed map[string]json.RawMessage
	if err := json.Unmarshal(p.raw, &merged); err != nil || merged == nil {
		return base, nil // unusable raw: fall back to the parsed subset
	}
	if err := json.Unmarshal(base, &parsed); err != nil {
		return nil, fmt.Errorf("nrf: merge profile: %w", err)
	}
	for _, k := range authoritativeKeys {
		if v, ok := parsed[k]; ok {
			merged[k] = v
		} else {
			delete(merged, k)
		}
	}
	out, err := json.Marshal(merged) // map keys are emitted sorted
	if err != nil {
		return nil, fmt.Errorf("nrf: marshal merged profile: %w", err)
	}
	return out, nil
}

// allServices returns the NFServices of both the deprecated array and the
// nfServiceList map (sorted by instance id for determinism).
func (p *NFProfile) allServices() []NFService {
	if len(p.NFServiceList) == 0 {
		return p.NFServices
	}
	out := make([]NFService, 0, len(p.NFServices)+len(p.NFServiceList))
	out = append(out, p.NFServices...)
	ids := make([]string, 0, len(p.NFServiceList))
	for id := range p.NFServiceList {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, p.NFServiceList[id])
	}
	return out
}

type PLMN struct {
	MCC string `json:"mcc"`
	MNC string `json:"mnc"`
}

type SNSSAI struct {
	SST int    `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

type NFService struct {
	ServiceInstanceID string             `json:"serviceInstanceId"`
	ServiceName       string             `json:"serviceName"` // e.g. "namf-comm"
	Versions          []NFServiceVersion `json:"versions"`
	Scheme            string             `json:"scheme"`          // "https"
	NFServiceStatus   string             `json:"nfServiceStatus"` // "REGISTERED"
	FQDN              string             `json:"fqdn,omitempty"`
	IPEndpoints       []IPEndpoint       `json:"ipEndPoints,omitempty"`
	APIPrefix         string             `json:"apiPrefix,omitempty"`
	// SupportedFeatures is the NF service's feature bitmask, hex string
	// (TS 29.510 §6.1.6.2.3, type SupportedFeatures TS 29.571 §5.2.2).
	SupportedFeatures string `json:"supportedFeatures,omitempty"`
}

type NFServiceVersion struct {
	APIVersionInURI string `json:"apiVersionInUri"` // "v1"
	APIFullVersion  string `json:"apiFullVersion"`  // "1.0.0"
}

type IPEndpoint struct {
	IPv4Address string `json:"ipv4Address,omitempty"`
	Port        int    `json:"port,omitempty"`
}

// Registry is the contract for NF profile storage.
type Registry interface {
	Register(p *NFProfile) error
	Update(id string, p *NFProfile) error
	Deregister(id string) error
	Get(id string) (*NFProfile, bool)
	ListAll() []*NFProfile
	Discover(filter DiscoveryFilter) []*NFProfile
	Heartbeat(id string) error
}

// DiscoveryFilter mirrors a subset of TS 29.510 §6.2.3.2.3.1 query parameters.
type DiscoveryFilter struct {
	TargetNFType    NFType
	RequesterNFType NFType
	ServiceNames    []string
	SNSSAIs         []SNSSAI
	// DNN filters to NFs that serve the given Data Network Name (TS 29.510 §6.2.3.2.3.1).
	DNN string
	// SupportedFeatures is the discovery "supported-features" query value
	// (TS 29.510 §6.2.3.2.3.1). It only applies when ServiceNames has exactly
	// one entry and is ignored otherwise. Rel-19 "required-features" is not
	// implemented.
	SupportedFeatures string
}

// DefaultHeartbeatTimer is the heartbeat interval suggested to NFs on register.
// Per TS 29.510 §6.1.6.2.2 guidance.
const DefaultHeartbeatTimer = 60 // seconds

// InMemory is the MVP implementation.
type InMemory struct {
	mu       sync.RWMutex
	profiles map[string]*NFProfile
	logger   *slog.Logger
}

// NewInMemory builds an in-memory Registry.
func NewInMemory(logger *slog.Logger) *InMemory {
	return &InMemory{
		profiles: make(map[string]*NFProfile),
		logger:   logger.With("component", "registry"),
	}
}

func (r *InMemory) Register(p *NFProfile) error {
	if p.NFInstanceID == "" {
		return fmt.Errorf("nfInstanceId required")
	}
	if p.NFType == "" {
		return fmt.Errorf("nfType required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	p.registeredAt = now
	p.lastSeen = now
	if p.NFStatus == "" {
		p.NFStatus = NFStatusRegistered
	}
	r.profiles[p.NFInstanceID] = p
	r.logger.Info("NF registered",
		"procedure", "NFRegister",
		"interface", "Nnrf",
		"direction", "IN",
		"target_nf_instance_id", p.NFInstanceID,
		"target_nf_type", p.NFType,
		"spec_ref", "TS 29.510 §5.2.2.2.2",
	)
	return nil
}

func (r *InMemory) Update(id string, p *NFProfile) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.profiles[id]
	if !ok {
		return fmt.Errorf("not found: %s", id)
	}
	p.NFInstanceID = id
	p.registeredAt = existing.registeredAt
	p.lastSeen = time.Now().UTC()
	r.profiles[id] = p
	r.logger.Info("NF profile updated",
		"procedure", "NFUpdate",
		"interface", "Nnrf",
		"target_nf_instance_id", id,
		"spec_ref", "TS 29.510 §5.2.2.3",
	)
	return nil
}

func (r *InMemory) Deregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.profiles[id]; !ok {
		return fmt.Errorf("not found: %s", id)
	}
	delete(r.profiles, id)
	r.logger.Info("NF deregistered",
		"procedure", "NFDeregister",
		"interface", "Nnrf",
		"target_nf_instance_id", id,
		"spec_ref", "TS 29.510 §5.2.2.4",
	)
	return nil
}

func (r *InMemory) Get(id string) (*NFProfile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[id]
	return p, ok
}

// ListAll returns all currently registered NF profiles.
// Implements TS 29.510 §5.2.2.6 NFListRetrieval.
func (r *InMemory) ListAll() []*NFProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*NFProfile, 0, len(r.profiles))
	for _, p := range r.profiles {
		out = append(out, p)
	}
	return out
}

func (r *InMemory) Heartbeat(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.profiles[id]
	if !ok {
		return fmt.Errorf("not found: %s", id)
	}
	p.lastSeen = time.Now().UTC()
	return nil
}

// StartEviction runs a background goroutine that evicts NFs whose lastSeen
// exceeds timeout. Per TS 29.510 §5.2.2.3.4, the NRF must deregister NFs
// that miss their heartbeat timer by more than 2×heartBeatTimer.
// Here we use a configurable timeout (typically 2× the heartBeatTimer).
func (r *InMemory) StartEviction(ctx context.Context, timeout time.Duration) {
	go func() {
		ticker := time.NewTicker(timeout / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.evictStale(timeout)
			}
		}
	}()
}

func (r *InMemory) evictStale(timeout time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	for id, p := range r.profiles {
		if now.Sub(p.lastSeen) > timeout {
			delete(r.profiles, id)
			r.logger.Warn("NF evicted (missed heartbeat)",
				"procedure", "NFEviction",
				"target_nf_instance_id", id,
				"target_nf_type", p.NFType,
				"last_seen_ago_s", int(now.Sub(p.lastSeen).Seconds()),
				"spec_ref", "TS 29.510 §5.2.2.3.4",
			)
		}
	}
}

// Discover returns profiles matching the filter, ordered by Priority asc.
// Implements core of TS 29.510 §5.3.2.2.2.
func (r *InMemory) Discover(filter DiscoveryFilter) []*NFProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*NFProfile, 0, len(r.profiles))
	for _, p := range r.profiles {
		if !matches(p, filter) {
			continue
		}
		out = append(out, p)
	}
	r.logger.Info("NF discovery",
		"procedure", "NFDiscover",
		"interface", "Nnrf",
		"target_nf_type", filter.TargetNFType,
		"requester_nf_type", filter.RequesterNFType,
		"results", len(out),
		"spec_ref", "TS 29.510 §5.3.2.2.2",
	)
	return out
}

// matches is the single discovery predicate shared by every Registry backend.
func matches(p *NFProfile, f DiscoveryFilter) bool {
	if f.TargetNFType != "" && p.NFType != f.TargetNFType {
		return false
	}
	services := p.allServices()
	if !matchServices(services, f.ServiceNames) {
		return false
	}
	if !matchSupportedFeatures(services, f.ServiceNames, f.SupportedFeatures) {
		return false
	}
	if !matchSNSSAIs(p.SNSSAIs, f.SNSSAIs) {
		return false
	}
	if f.DNN != "" && !containsDNN(p.DNNList, f.DNN) {
		return false
	}
	return true
}

// matchSupportedFeatures implements the supported-features discovery filter
// (TS 29.510 §6.2.3.2.3.1): applicable only with exactly one service name; a
// profile matches if at least one NFService of that name supports every
// requested feature bit. A service without (or with unparseable)
// supportedFeatures supports none. The SupportedFeatures type has no length
// limit (TS 29.571 §5.2.2), so over-long values are evaluated after trimming
// leading zeros; bits beyond features.MaxFeatures cannot be known to be
// supported, so such a request fails closed (no match).
func matchSupportedFeatures(services []NFService, serviceNames []string, requested string) bool {
	if requested == "" || len(serviceNames) != 1 {
		return true
	}
	req, ok := parseTrimmed(requested)
	if !ok {
		return false // fail closed; the server rejects non-hex values with 400
	}
	if req.IsEmpty() {
		return true
	}
	for _, s := range services {
		if s.ServiceName != serviceNames[0] {
			continue
		}
		have, ok := parseTrimmed(s.SupportedFeatures)
		if !ok {
			continue
		}
		if req.Intersect(have).Equal(req) {
			return true
		}
	}
	return false
}

// parseTrimmed parses a SupportedFeatures string after dropping leading '0'
// digits (high-order, no information). ok is false when the value is invalid
// or still exceeds features.MaxHexChars.
func parseTrimmed(v string) (features.Set, bool) {
	set, err := features.Parse(strings.TrimLeft(v, "0"))
	return set, err == nil
}

// matchServices implements the service-names discovery filter: a profile
// matches if it has at least one NF service matching one of the requested
// names (TS 29.510 Table 6.2.3.2.3.1-1).
func matchServices(have []NFService, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		for _, h := range have {
			if h.ServiceName == w {
				return true
			}
		}
	}
	return false
}

func containsDNN(list []string, dnn string) bool {
	for _, d := range list {
		if d == dnn {
			return true
		}
	}
	return false
}

func matchSNSSAIs(have, want []SNSSAI) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		found := false
		for _, h := range have {
			if h.SST == w.SST && h.SD == w.SD {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
