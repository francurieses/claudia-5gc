package registry

import (
	"sync"

	"github.com/google/uuid"
)

// NFEvent represents an NF status event type per TS 29.510 §6.1.6.3.6.
type NFEvent string

const (
	NFEventRegistered      NFEvent = "NF_REGISTERED"
	NFEventDeregistered    NFEvent = "NF_DEREGISTERED"
	NFEventProfileChanged  NFEvent = "NF_PROFILE_CHANGED"
)

// Subscription is one NFStatus subscription (TS 29.510 §5.2.2.7-9).
type Subscription struct {
	SubscriptionID  string
	NotificationURI string
	// ReqNFType filters events to a specific NF type (empty = all types).
	ReqNFType NFType
	// ReqNFInstanceID filters events to a specific NF instance (empty = all).
	ReqNFInstanceID string
}

// NotificationData is the body of a NFStatusNotify POST (TS 29.510 §6.1.6.2.3).
type NotificationData struct {
	Event          NFEvent    `json:"event"`
	NFInstanceURI  string     `json:"nfInstanceUri"`
	NFProfile      *NFProfile `json:"nfProfile,omitempty"`
}

// SubscriptionStore holds NF status subscriptions in memory.
// Thread-safe; does not persist across restarts.
type SubscriptionStore struct {
	mu   sync.RWMutex
	subs map[string]*Subscription
}

// NewSubscriptionStore constructs an empty store.
func NewSubscriptionStore() *SubscriptionStore {
	return &SubscriptionStore{subs: make(map[string]*Subscription)}
}

// Add stores a subscription and returns its ID.
func (ss *SubscriptionStore) Add(s *Subscription) string {
	if s.SubscriptionID == "" {
		s.SubscriptionID = uuid.NewString()
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.subs[s.SubscriptionID] = s
	return s.SubscriptionID
}

// Delete removes a subscription by ID. No-op if not found.
func (ss *SubscriptionStore) Delete(id string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.subs, id)
}

// Matching returns all subscriptions that match the given NF type and instance.
func (ss *SubscriptionStore) Matching(nfType NFType, nfInstanceID string) []*Subscription {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	var result []*Subscription
	for _, s := range ss.subs {
		if s.ReqNFType != "" && s.ReqNFType != nfType {
			continue
		}
		if s.ReqNFInstanceID != "" && s.ReqNFInstanceID != nfInstanceID {
			continue
		}
		result = append(result, s)
	}
	return result
}
