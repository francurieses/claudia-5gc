package n32c

import (
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// MaxContexts bounds the store: one context per remote PLMN, so this is the
// maximum number of simultaneous roaming partners. When full, Replace evicts
// the oldest context (by CreatedAt) before storing a new PLMN. The value is an
// implementation limit, not a 3GPP parameter.
const MaxContexts = 1024

// Context is the N32 context of one remote PLMN (TLS mode). It deliberately
// holds no Rel-19-only IE and no n32fContextId (TLS mode has none).
// Ref: TS 29.573 §5.2.2 (both SEPPs store the PLMN to N32 connection mapping).
type Context struct {
	RemotePLMN PlmnId
	// SecCapability is the selected security capability (TLS).
	SecCapability SecurityCapability
	// TargetAPIRootHeader is true iff both SEPPs support 3gpp-Sbi-Target-apiRoot.
	TargetAPIRootHeader bool
	// Features is the negotiated supportedFeatures set (TS 29.573 §6.1.7).
	Features features.Set
	// NFTLST is true iff feature NFTLST was negotiated (N32-f TLS teardown via NONE).
	NFTLST bool
	// PeerFQDN is the peer SEPP FQDN (sender).
	PeerFQDN  string
	CreatedAt time.Time
}

// StoreEvent describes a store mutation, for observers and tests.
type StoreEvent struct {
	Op   string // "delete" | "create"
	PLMN PlmnId
}

// Store is a thread-safe N32 context store keyed by remote PLMN.
type Store struct {
	mu       sync.RWMutex
	m        map[string]Context
	observer func(StoreEvent)
}

// NewStore returns an empty store. observer (optional) is called for every
// delete and create, in order, while the store lock is held.
func NewStore(observer func(StoreEvent)) *Store {
	return &Store{m: map[string]Context{}, observer: observer}
}

// Get returns the context of the remote PLMN.
func (s *Store) Get(p PlmnId) (Context, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.m[p.Key()]
	return c, ok
}

// Len returns the number of contexts.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// Delete removes the context of the remote PLMN and reports whether it existed.
func (s *Store) Delete(p PlmnId) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(p)
}

func (s *Store) deleteLocked(p PlmnId) bool {
	if _, ok := s.m[p.Key()]; !ok {
		return false
	}
	delete(s.m, p.Key())
	if s.observer != nil {
		s.observer(StoreEvent{Op: "delete", PLMN: p})
	}
	return true
}

// Replace deletes the existing context of c.RemotePLMN (if any) and then
// creates c, as TS 29.573 §5.2.2 step 2a requires. It returns the previous
// context when there was one.
func (s *Store) Replace(c Context) (prev Context, existed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, existed = s.m[c.RemotePLMN.Key()]
	s.deleteLocked(c.RemotePLMN)
	if len(s.m) >= MaxContexts {
		s.evictOldestLocked()
	}
	s.m[c.RemotePLMN.Key()] = c
	if s.observer != nil {
		s.observer(StoreEvent{Op: "create", PLMN: c.RemotePLMN})
	}
	return prev, existed
}

// evictOldestLocked removes the context with the earliest CreatedAt.
func (s *Store) evictOldestLocked() {
	var oldest Context
	found := false
	for _, c := range s.m {
		if !found || c.CreatedAt.Before(oldest.CreatedAt) {
			oldest, found = c, true
		}
	}
	if found {
		s.deleteLocked(oldest.RemotePLMN)
	}
}
