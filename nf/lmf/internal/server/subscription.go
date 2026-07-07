// Package server — subscription registry for Nlmf_Location EventSubscription.
//
// This file implements the in-memory subscription registry and the AOI
// (Area-of-Interest) polygon containment check used by the EventSubscription
// service (TS 29.572 §5.2.3).
//
// Design summary:
//   - One goroutine per active subscription, started at Create, stopped at
//     DELETE or duration expiry.
//   - AOI containment uses the ray-casting (even-odd crossing) algorithm — no
//     external geometry dependency.
//   - The registry is a map[string]*subscription guarded by sync.RWMutex; all
//     reads under RLock, mutations under Lock.
//
// Ref: TS 29.572 §5.2.3 (EventSubscription), TS 23.273 §7.2 step B2.
package server

import (
	"context"
	"sync"
	"time"
)

// EventTrigger enumerates the supported subscription trigger types.
// Ref: TS 29.572 §5.2.3.2 (eventTrigger IE).
const (
	EventTriggerPeriodic = "PERIODIC_REPORTING"
	EventTriggerAOI      = "AREA_OF_INTEREST"
)

// aoiState is the per-subscription Area-of-Interest state machine value.
// Ref: TS 29.572 §5.2.3 (AOI subscription state).
type aoiState int

const (
	aoiStateUnknown aoiState = iota // initial — baseline not yet established
	aoiStateIn                      // UE is inside the polygon
	aoiStateOut                     // UE is outside the polygon
)

func (s aoiState) String() string {
	switch s {
	case aoiStateIn:
		return "IN"
	case aoiStateOut:
		return "OUT"
	default:
		return "UNKNOWN"
	}
}

// subscription is a single active EventSubscription resource.
// The cancel function stops the goroutine; it is called by DELETE or by
// context.WithTimeout expiry.
//
// Ref: TS 29.571 §5.2 (subscription resource schema).
type subscription struct {
	SubId             string
	UEContextId       string
	EventTrigger      string
	NotificationUri   string
	ReportingInterval time.Duration
	SamplingInterval  time.Duration
	AreaOfInterest    []LatLon // polygon vertices; nil for PERIODIC_REPORTING
	Duration          time.Duration
	Created           time.Time
	LastNotified      time.Time // zero until first notification
	State             aoiState  // AOI only; meaningless for PERIODIC_REPORTING

	cancel context.CancelFunc // stops the goroutine
}

// subscriptionRegistry is the in-memory store of active subscriptions.
// All read operations use RLock; mutations use Lock.
type subscriptionRegistry struct {
	mu   sync.RWMutex
	subs map[string]*subscription
}

func newRegistry() *subscriptionRegistry {
	return &subscriptionRegistry{subs: make(map[string]*subscription)}
}

// add inserts a subscription into the registry.
func (r *subscriptionRegistry) add(s *subscription) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subs[s.SubId] = s
}

// get returns the subscription for subId, or (nil, false) if not found.
func (r *subscriptionRegistry) get(subId string) (*subscription, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.subs[subId]
	return s, ok
}

// delete removes the subscription for subId and calls its cancel function to
// stop the associated goroutine. Returns false if subId is unknown.
func (r *subscriptionRegistry) delete(subId string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.subs[subId]
	if !ok {
		return false
	}
	s.cancel()
	delete(r.subs, subId)
	return true
}

// count returns the current number of active subscriptions.
func (r *subscriptionRegistry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.subs)
}

// markNotified updates LastNotified for the subscription under a write lock.
// Called after each successful or attempted notification delivery.
func (r *subscriptionRegistry) markNotified(subId string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.subs[subId]; ok {
		s.LastNotified = time.Now()
	}
}

// updateAOIState updates the AOI state for the subscription.
func (r *subscriptionRegistry) updateAOIState(subId string, state aoiState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.subs[subId]; ok {
		s.State = state
	}
}

// snapshot returns a shallow copy of the subscription for safe reading
// outside of the lock (fields are value types or immutable slices).
func (r *subscriptionRegistry) snapshot(subId string) (*subscription, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.subs[subId]
	if !ok {
		return nil, false
	}
	// shallow copy — caller must not modify AreaOfInterest slice
	cp := *s
	return &cp, true
}

// cancelAll cancels every subscription's goroutine and clears the registry.
// Called on graceful LMF shutdown to drain all goroutines.
func (r *subscriptionRegistry) cancelAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.subs {
		s.cancel()
	}
	r.subs = make(map[string]*subscription)
}

// ---- AOI polygon containment (ray-casting / even-odd crossing rule) ----------
//
// Algorithm reference: W. Randolph Franklin, "PNPOLY — Point Inclusion in
// Polygon Test" (https://wrf.ecse.rpi.edu/Research/Short_Notes/pnpoly.html).
// No external dependency; pure Go.
//
// The polygon is treated as a closed ring: the edge from the last vertex to the
// first is implicit (the loop below wraps via modular indexing). Vertices are
// WGS84 (lat, lon) treated as a flat Cartesian plane — adequate for the
// small polygons used in location services (< 100 km²).
//
// Returns true when the point is strictly inside or on the polygon boundary
// according to the even-odd rule.

// pointInPolygon reports whether the point (lat, lon) is inside the polygon
// defined by the ordered slice of vertices.
//
// Ray-casting (even-odd) algorithm. Returns true for a point that is inside
// the polygon. Boundary points may return true or false (undefined per spec).
//
// Ref: TS 29.572 §6.1.6.2.2 (areaOfInterest polygon); TS 23.273 §7.2 step B2.
func pointInPolygon(lat, lon float64, poly []LatLon) bool {
	n := len(poly)
	inside := false
	j := n - 1
	for i := 0; i < n; i++ {
		yi, xi := poly[i].Lat, poly[i].Lon
		yj, xj := poly[j].Lat, poly[j].Lon
		// Standard even-odd crossing test.
		if (yi > lat) != (yj > lat) && lon < (xj-xi)*(lat-yi)/(yj-yi)+xi {
			inside = !inside
		}
		j = i
	}
	return inside
}
