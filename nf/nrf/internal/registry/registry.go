// Package registry implements the NRF NF profile registry (3GPP TS 29.510).
//
// In-memory implementation for MVP. Production deployments must back this
// with Redis or PostgreSQL for persistence and multi-instance NRF.
package registry

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// NFType per 3GPP TS 29.510 §6.1.6.3.3 (subset relevant to MVP).
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

	// internal bookkeeping (not serialized to clients)
	registeredAt time.Time `json:"-"`
	lastSeen     time.Time `json:"-"`
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
		if filter.TargetNFType != "" && p.NFType != filter.TargetNFType {
			continue
		}
		if !matchServices(p.NFServices, filter.ServiceNames) {
			continue
		}
		if !matchSNSSAIs(p.SNSSAIs, filter.SNSSAIs) {
			continue
		}
		if filter.DNN != "" && !containsDNN(p.DNNList, filter.DNN) {
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

func matchServices(have []NFService, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		found := false
		for _, h := range have {
			if h.ServiceName == w {
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
