package nrf

import (
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

type featureKey struct{ nfInstanceID, service string }

type featureEntry struct {
	set     features.Set
	expires time.Time
}

// FeatureCache stores the negotiated supported-feature set per peer NF
// service, keyed by (nfInstanceId, serviceName). Entries expire after the
// NRF's validityPeriod; expired entries are reported absent and evicted.
// It is safe for concurrent use. The zero value is not usable; use
// NewFeatureCache.
//
// Ref: TS 29.510 §6.2.6.2.2 (SearchResult validityPeriod),
// TS 29.500 §6.6.2 (negotiation = intersection).
type FeatureCache struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[featureKey]featureEntry
}

// NewFeatureCache returns an empty cache using the wall clock.
func NewFeatureCache() *FeatureCache {
	return &FeatureCache{now: time.Now, m: map[featureKey]featureEntry{}}
}

// SetClock replaces the clock (tests).
func (fc *FeatureCache) SetClock(now func() time.Time) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.now = now
}

// Put stores set for (nfInstanceID, service) for ttl. A non-positive ttl
// stores nothing.
func (fc *FeatureCache) Put(nfInstanceID, service string, set features.Set, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.m[featureKey{nfInstanceID, service}] = featureEntry{set: set, expires: fc.now().Add(ttl)}
}

// Get returns the cached negotiated set. An expired entry is evicted and
// reported absent.
func (fc *FeatureCache) Get(nfInstanceID, service string) (features.Set, bool) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	k := featureKey{nfInstanceID, service}
	e, ok := fc.m[k]
	if !ok {
		return features.Set{}, false
	}
	if !fc.now().Before(e.expires) {
		delete(fc.m, k)
		return features.Set{}, false
	}
	return e.set, true
}

// Len returns the number of stored entries (including not-yet-evicted
// expired ones).
func (fc *FeatureCache) Len() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return len(fc.m)
}

// StoreResult negotiates and caches the features of every NFService of every
// instance in res: negotiated = offered(serviceName) ∩ service.supportedFeatures.
// A missing or invalid supportedFeatures value yields the empty set (fail
// closed). TTL is res.ValidityPeriod seconds; when it is absent or <= 0 (it
// is optional in Rel-17) nothing is cached and 0 is returned, so the caller
// negotiates from the discovery result each time. It returns the number of
// entries stored. offered may be nil (everything negotiates to empty).
// Ref: TS 29.510 §6.2.6.2.2, §6.1.6.2.3; TS 29.500 §6.6.2.
func (fc *FeatureCache) StoreResult(res *SearchResult, offered func(service string) features.Set) int {
	if res == nil || res.ValidityPeriod <= 0 {
		return 0
	}
	ttl := time.Duration(res.ValidityPeriod) * time.Second
	n := 0
	for _, p := range res.NFInstances {
		for _, s := range p.NFServices {
			var local features.Set
			if offered != nil {
				local = offered(s.ServiceName)
			}
			peer, err := features.Parse(s.SupportedFeatures)
			if err != nil {
				peer = features.Set{}
			}
			fc.Put(p.NFInstanceID, s.ServiceName, local.Intersect(peer), ttl)
			n++
		}
	}
	return n
}
