// Profile and its configuration: the per-NF release profile and the
// per-feature enable map (REL19-2.1, ADR-5).

package capability

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
)

// EnvReleaseProfile is the environment variable that overrides the configured
// profile name.
const EnvReleaseProfile = "NF_RELEASE_PROFILE"

// Profile names accepted in configuration and in EnvReleaseProfile.
const (
	ProfileRel17 = "rel17" // Rel-17 behaviour (frozen legacy baseline)
	ProfileRel19 = "rel19" // Rel-19 behaviour (default), features still opt-in
)

// DefaultProfile is the release profile used when neither the YAML release.profile
// nor EnvReleaseProfile names one.
const DefaultProfile = ProfileRel19

// ReleaseConfig is the NF YAML "release:" block:
//
//	release:
//	  profile: rel19      # rel17 | rel19 (default rel19)
//	  features:
//	    XR-001: true
type ReleaseConfig struct {
	Profile  string          `yaml:"profile" json:"profile"`
	Features map[string]bool `yaml:"features" json:"features"`
}

// Profile is an immutable release profile; safe for concurrent use.
type Profile struct {
	name    string
	release Release
	enabled map[string]bool
}

// profileRelease maps a profile name to its release ceiling.
func profileRelease(name string) (Release, bool) {
	switch name {
	case ProfileRel17:
		return Rel17, true
	case ProfileRel19:
		return Rel19, true
	}
	return 0, false
}

// NewProfile builds a Profile from cfg. A non-empty EnvReleaseProfile (read
// through getenv; nil means os.Getenv) overrides cfg.Profile; an empty name
// means "rel19" (DefaultProfile). Unknown profile names and unregistered feature IDs are
// errors, so call it after all init() registrations have run (i.e. from
// main, never from a package initialiser).
func NewProfile(cfg ReleaseConfig, getenv func(string) string) (*Profile, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	name := cfg.Profile
	if v := getenv(EnvReleaseProfile); v != "" {
		name = v
	}
	if name == "" {
		name = DefaultProfile
	}
	rel, ok := profileRelease(name)
	if !ok {
		return nil, fmt.Errorf("capability: load profile: unknown profile %q (want %s|%s)", name, ProfileRel17, ProfileRel19)
	}
	enabled := make(map[string]bool, len(cfg.Features))
	for id, on := range cfg.Features {
		if _, known := Lookup(id); !known {
			return nil, fmt.Errorf("capability: load profile: feature %q is not registered", id)
		}
		if on {
			enabled[id] = true
		}
	}
	return &Profile{name: name, release: rel, enabled: enabled}, nil
}

// Name returns the effective profile name.
func (p *Profile) Name() string { return p.name }

// Release returns the highest release the profile permits.
func (p *Profile) Release() Release { return p.release }

// Enabled reports whether id is switched on in the enable map (it says
// nothing about release or peers; use Gate for the decision).
func (p *Profile) Enabled(id string) bool {
	return p != nil && p.enabled[id]
}

// Gate applies the ADR-5 decision: the feature is registered and enabled, its
// release is within the profile, and every peer allows it. A nil Profile
// gates everything off. No I/O, no allocation.
func (p *Profile) Gate(featureID string, peers ...PeerCap) bool {
	if p == nil || !p.enabled[featureID] {
		return false
	}
	f, ok := Lookup(featureID)
	if !ok || f.Release > p.release {
		return false
	}
	for _, peer := range peers {
		if peer == nil || !peer.Allows(f) {
			return false
		}
	}
	return true
}

type ctxKey struct{}

// WithProfile returns a context carrying p for Gate.
func WithProfile(ctx context.Context, p *Profile) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// ProfileFrom returns the Profile in ctx, else the process default, else nil.
func ProfileFrom(ctx context.Context) *Profile {
	if ctx != nil {
		if p, ok := ctx.Value(ctxKey{}).(*Profile); ok && p != nil {
			return p
		}
	}
	return defaultProfile.Load()
}

var defaultProfile atomic.Pointer[Profile]

// SetDefault installs the process-wide fallback profile (typically from
// main after NewProfile). Passing nil clears it.
func SetDefault(p *Profile) { defaultProfile.Store(p) }

// Gate resolves the Profile from ctx (falling back to the SetDefault
// profile) and applies Profile.Gate. With no profile at all it returns false
// (equivalent to rel17 with nothing enabled).
func Gate(ctx context.Context, featureID string, peers ...PeerCap) bool {
	return ProfileFrom(ctx).Gate(featureID, peers...)
}
