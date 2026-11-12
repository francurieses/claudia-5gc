// Package capability holds the Rel-19 feature registry and the gating
// machinery (ADR-5): Release, Feature, Register/Lookup (registry), Profile
// (per-NF release profile plus per-feature enable map, loaded from the NF YAML
// "release:" block) and Gate (the single runtime decision point).
//
// Gated behaviour defaults to OFF and legacy peers must see byte-identical
// messages, so callers never compare releases ad hoc: they call Gate.
//
// Private-edition code registers features through files named *_private.go,
// which are stripped from the public snapshot.
package capability

import (
	"errors"
	"fmt"
	"sync"
)

// Release is a 3GPP release the core can be uplifted to.
type Release int

// Supported 3GPP releases.
const (
	Rel15 Release = 15
	Rel16 Release = 16
	Rel17 Release = 17
	Rel18 Release = 18
	Rel19 Release = 19
	Rel20 Release = 20
)

// String renders the release as "Rel-NN".
func (r Release) String() string { return fmt.Sprintf("Rel-%d", int(r)) }

// Feature describes one gated capability.
type Feature struct {
	ID         string   // unique feature identifier
	Title      string   // human-readable title
	Release    Release  // release that introduced the feature
	Normative  bool     // true if mandated by the specification
	Visibility string   // "public" or "private"
	SpecRef    string   // spec reference, e.g. "TS 23.501 §5.x"
	NFs        []string // NFs the feature applies to
}

var (
	mu       sync.RWMutex
	registry = map[string]Feature{}
)

// Register adds f to the registry. It rejects an empty or duplicate ID.
func Register(f Feature) error {
	if f.ID == "" {
		return errors.New("capability: register: empty feature ID")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[f.ID]; dup {
		return fmt.Errorf("capability: register %q: duplicate feature ID", f.ID)
	}
	registry[f.ID] = f
	return nil
}

// MustRegister is Register that panics on error; for use in init() only.
func MustRegister(f Feature) {
	if err := Register(f); err != nil {
		panic(err)
	}
}

// Lookup returns the feature registered under id.
func Lookup(id string) (Feature, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := registry[id]
	return f, ok
}
