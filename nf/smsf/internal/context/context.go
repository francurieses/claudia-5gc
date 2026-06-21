// Package context maintains the per-UE SMS context for the SMSF.
//
// State machine:
//
//	INACTIVE → ACTIVE  on Nsmsf_SMService_Activate
//	ACTIVE   → INACTIVE on Nsmsf_SMService_Deactivate
//
// Ref: TS 29.540 §5.2, TS 23.502 §4.13.2
package context

import "sync"

// State is the per-UE SMS context state.
type State int

const (
	// StateInactive: no SMS context exists for this SUPI.
	StateInactive State = iota
	// StateActive: Activate completed; UDM UECM registration done.
	StateActive
)

// UESMSContext holds the SMSF's per-UE SMS context.
// Ref: TS 29.540 §6.1.6.2.2 (UeSmsContextData)
type UESMSContext struct {
	// SUPI is the Subscription Permanent Identifier.
	SUPI string
	// GPSI is the Generic Public Subscriber Identifier (optional).
	GPSI string
	// PEI is the Permanent Equipment Identifier (optional).
	PEI string
	// AmfID is the NF instance ID of the serving AMF.
	AmfID string
	// AccessType is "3GPP_ACCESS" or "NON_3GPP_ACCESS".
	AccessType string
	// AmfCallbackURI is the URI the SMSF uses to push MT SMS and MO acks back to the AMF.
	// Format: https://<amf_host>/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages
	// Ref: TS 29.518 §5.2.2.3
	AmfCallbackURI string
	// State is the current SMS context state.
	State State
}

// Store is a thread-safe in-memory store of UE SMS contexts, keyed by SUPI.
// In a production system this would be backed by Redis for HA. This in-memory
// implementation is adequate for unit + functional tests and a single-instance lab.
type Store struct {
	mu       sync.RWMutex
	contexts map[string]*UESMSContext // key: supiOrGpsi
}

// NewStore creates an empty context store.
func NewStore() *Store {
	return &Store{
		contexts: make(map[string]*UESMSContext),
	}
}

// Set creates or replaces the SMS context for the given SUPI/GPSI.
func (s *Store) Set(key string, ctx *UESMSContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contexts[key] = ctx
}

// Get returns the SMS context for the given SUPI/GPSI key.
// Returns (nil, false) if no context exists.
func (s *Store) Get(key string) (*UESMSContext, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.contexts[key]
	return c, ok
}

// Delete removes the SMS context for the given SUPI/GPSI key.
// Returns true if the context existed, false otherwise.
func (s *Store) Delete(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.contexts[key]
	delete(s.contexts, key)
	return ok
}
