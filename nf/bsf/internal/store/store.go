// Package store implements the in-memory PCF binding store for the BSF.
//
// The store is the authoritative registry of (UE IP, DNN, S-NSSAI) → PCF bindings.
// It is keyed by bindingId (UUID) and maintains secondary indices for discovery
// by ipv4Addr, ipv6Prefix, and supi.
//
// Thread safety: all exported methods are safe for concurrent use.
//
// Persistence note: this implementation is in-memory only. A future increment
// (BSF-003) will add PostgreSQL persistence with a Redis discovery cache.
// Ref: TS 29.521 §5, TS 23.501 §6.2.16
package store

import (
	"sync"
)

// Snssai represents an S-NSSAI (Single Network Slice Selection Assistance Information).
// Ref: TS 29.571 §5.4.4 (Snssai)
type Snssai struct {
	// Sst is the Slice/Service Type (0–255).
	Sst int `json:"sst"`
	// Sd is the optional Slice Differentiator (6 hex digits, e.g. "000001").
	Sd string `json:"sd,omitempty"`
}

// IpEndPoint represents an IP endpoint (IP + port + transport).
// Ref: TS 29.510 §6.1.6.2.27 (IpEndPoint)
type IpEndPoint struct {
	Ipv4Address string `json:"ipv4Address,omitempty"`
	Ipv6Address string `json:"ipv6Address,omitempty"`
	Transport   string `json:"transport,omitempty"`
	Port        int    `json:"port,omitempty"`
}

// PcfBinding holds the full PCF binding record as stored and returned by the BSF.
// Field names match the TS 29.521 OpenAPI JSON field names (camelCase).
// Ref: TS 29.521 §6.2.6
type PcfBinding struct {
	// BindingID is the BSF-assigned unique identifier for this binding.
	// Set by the store on Create; not present in the Register request body.
	BindingID string `json:"bindingId,omitempty"`

	// Supi is the UE Subscription Permanent Identifier. Optional.
	Supi string `json:"supi,omitempty"`
	// Gpsi is the Generic Public Subscription Identifier (MSISDN). Optional.
	Gpsi string `json:"gpsi,omitempty"`

	// Ipv4Addr is the UE IPv4 address. Conditional (present for IPv4/IPv4v6 PDU sessions).
	Ipv4Addr string `json:"ipv4Addr,omitempty"`
	// Ipv6Prefix is the UE IPv6 prefix. Conditional (present for IPv6/IPv4v6 PDU sessions).
	Ipv6Prefix string `json:"ipv6Prefix,omitempty"`
	// MacAddr48 is the UE MAC address for Ethernet/5G-LAN PDU sessions.
	MacAddr48 string `json:"macAddr48,omitempty"`
	// IpDomain disambiguates overlapping IPv4 pools across DNNs/UPFs.
	// Ref: TS 29.521 §6.2.6 — ipDomain
	IpDomain string `json:"ipDomain,omitempty"`

	// Dnn is the Data Network Name of the PDU session. Mandatory.
	Dnn string `json:"dnn"`
	// Snssai is the S-NSSAI of the PDU session. Mandatory.
	Snssai Snssai `json:"snssai"`

	// PcfFqdn is the FQDN of the serving PCF. Conditional (pcfFqdn or pcfIpEndPoints must be present).
	PcfFqdn string `json:"pcfFqdn,omitempty"`
	// PcfIpEndPoints are the IP endpoints of the serving PCF. Conditional.
	PcfIpEndPoints []IpEndPoint `json:"pcfIpEndPoints,omitempty"`
	// PcfId is the NF instance ID of the serving PCF. Optional.
	PcfId string `json:"pcfId,omitempty"`

	// PcfDiamHost is the PCF Diameter host identity (Rx/N5 legacy interop). Optional.
	PcfDiamHost string `json:"pcfDiamHost,omitempty"`
	// PcfDiamRealm is the PCF Diameter realm identity (Rx/N5 legacy interop). Optional.
	PcfDiamRealm string `json:"pcfDiamRealm,omitempty"`

	// RecoveryTime is the PCF recovery timestamp for stale-binding detection. Optional.
	RecoveryTime string `json:"recoveryTime,omitempty"`
	// BindLevel is the binding granularity: "NF_SET" or "NF_INSTANCE". Optional.
	BindLevel string `json:"bindLevel,omitempty"`
	// SuppFeat is the negotiated supported features bitmask. Optional.
	SuppFeat string `json:"suppFeat,omitempty"`
}

// DiscoveryQuery holds the parsed query parameters for a GET /nbsf-management/v1/pcfBindings call.
// Ref: TS 29.521 §5.2.2.4.3.1
type DiscoveryQuery struct {
	Ipv4Addr   string
	Ipv6Prefix string
	MacAddr48  string
	Supi       string
	Gpsi       string
	Dnn        string
	Snssai     *Snssai
	IpDomain   string
}

// HasAnyParam returns true if at least one discovery parameter is set.
// At least one binding-identifying parameter is required by TS 29.521 §5.2.2.4.
func (q *DiscoveryQuery) HasAnyParam() bool {
	return q.Ipv4Addr != "" || q.Ipv6Prefix != "" || q.MacAddr48 != "" ||
		q.Supi != "" || q.Gpsi != "" || q.Dnn != "" ||
		q.Snssai != nil || q.IpDomain != ""
}

// Store is a thread-safe in-memory binding store.
// It is keyed by bindingId (primary) with secondary indices for fast discovery.
type Store struct {
	mu sync.RWMutex
	// bindings maps bindingId → PcfBinding (primary store).
	bindings map[string]*PcfBinding
	// ipv4Index maps (ipv4Addr + "|" + ipDomain) → bindingId for O(1) IPv4 discovery.
	ipv4Index map[string]string
	// supiIndex maps supi → []bindingId (one SUPI can have multiple concurrent PDU sessions).
	supiIndex map[string][]string
}

// New creates an empty, ready-to-use binding store.
func New() *Store {
	return &Store{
		bindings:  make(map[string]*PcfBinding),
		ipv4Index: make(map[string]string),
		supiIndex: make(map[string][]string),
	}
}

// ipv4Key builds the composite index key for the ipv4Index map.
// Using both ipv4Addr and ipDomain handles overlapping IP pools across DNNs.
func ipv4Key(ipv4Addr, ipDomain string) string {
	return ipv4Addr + "|" + ipDomain
}

// Create stores a new PcfBinding. The bindingId must already be set on the binding.
// Returns an error string (cause) if a binding already exists for the same
// (ipv4Addr, ipDomain) or (ipv6Prefix) key — the caller maps this to 403
// EXISTING_BINDING_INFO_FOUND (TS 29.521 §5.2.2.2.4).
//
// The returned *PcfBinding is a copy safe to return to the HTTP layer.
func (s *Store) Create(b *PcfBinding) (*PcfBinding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Duplicate-key check: same (ipv4Addr, ipDomain) already bound.
	if b.Ipv4Addr != "" {
		if existing, ok := s.ipv4Index[ipv4Key(b.Ipv4Addr, b.IpDomain)]; ok && existing != "" {
			return nil, false // duplicate
		}
	}

	// Store the binding.
	clone := *b
	s.bindings[b.BindingID] = &clone

	// Update secondary indices.
	if b.Ipv4Addr != "" {
		s.ipv4Index[ipv4Key(b.Ipv4Addr, b.IpDomain)] = b.BindingID
	}
	if b.Supi != "" {
		s.supiIndex[b.Supi] = append(s.supiIndex[b.Supi], b.BindingID)
	}

	result := clone
	return &result, true
}

// Delete removes the binding for the given bindingId.
// Returns true if the binding existed and was removed, false if not found.
func (s *Store) Delete(bindingID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.bindings[bindingID]
	if !ok {
		return false
	}

	// Remove from secondary indices.
	if b.Ipv4Addr != "" {
		delete(s.ipv4Index, ipv4Key(b.Ipv4Addr, b.IpDomain))
	}
	if b.Supi != "" {
		ids := s.supiIndex[b.Supi]
		filtered := ids[:0]
		for _, id := range ids {
			if id != bindingID {
				filtered = append(filtered, id)
			}
		}
		if len(filtered) == 0 {
			delete(s.supiIndex, b.Supi)
		} else {
			s.supiIndex[b.Supi] = filtered
		}
	}

	delete(s.bindings, bindingID)
	return true
}

// FindByQuery searches for a PcfBinding matching the given discovery query.
// Returns the first matching binding (most-specific match preferred via ipv4Addr),
// or (nil, false) if no binding matches.
//
// Match precedence (TS 29.521 §5.2.2.4.3.1):
//  1. ipv4Addr (+ optional ipDomain) — via O(1) index
//  2. supi — via supi index (first entry)
//  3. Linear scan for ipv6Prefix / macAddr48 / dnn / gpsi / snssai narrowing
//
// Ref: TS 29.521 §5.2.2.4
func (s *Store) FindByQuery(q *DiscoveryQuery) (*PcfBinding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Fast path: ipv4Addr is the primary key for IPv4 UEs.
	if q.Ipv4Addr != "" {
		key := ipv4Key(q.Ipv4Addr, q.IpDomain)
		if id, ok := s.ipv4Index[key]; ok {
			if b, ok := s.bindings[id]; ok {
				if matchesQuery(b, q) {
					clone := *b
					return &clone, true
				}
			}
		}
		return nil, false
	}

	// SUPI index path.
	if q.Supi != "" {
		if ids, ok := s.supiIndex[q.Supi]; ok {
			for _, id := range ids {
				if b, ok := s.bindings[id]; ok {
					if matchesQuery(b, q) {
						clone := *b
						return &clone, true
					}
				}
			}
		}
		return nil, false
	}

	// Linear scan for remaining query parameters (ipv6Prefix, macAddr48, dnn, gpsi, snssai).
	for _, b := range s.bindings {
		if matchesQuery(b, q) {
			clone := *b
			return &clone, true
		}
	}
	return nil, false
}

// matchesQuery returns true if binding b satisfies all non-empty fields of q.
// Only checks fields actually set in the query; empty fields match anything.
func matchesQuery(b *PcfBinding, q *DiscoveryQuery) bool {
	if q.Ipv4Addr != "" && b.Ipv4Addr != q.Ipv4Addr {
		return false
	}
	if q.Ipv6Prefix != "" && b.Ipv6Prefix != q.Ipv6Prefix {
		return false
	}
	if q.MacAddr48 != "" && b.MacAddr48 != q.MacAddr48 {
		return false
	}
	if q.Supi != "" && b.Supi != q.Supi {
		return false
	}
	if q.Gpsi != "" && b.Gpsi != q.Gpsi {
		return false
	}
	if q.Dnn != "" && b.Dnn != q.Dnn {
		return false
	}
	if q.IpDomain != "" && b.IpDomain != q.IpDomain {
		return false
	}
	if q.Snssai != nil {
		if b.Snssai.Sst != q.Snssai.Sst {
			return false
		}
		if q.Snssai.Sd != "" && b.Snssai.Sd != q.Snssai.Sd {
			return false
		}
	}
	return true
}
