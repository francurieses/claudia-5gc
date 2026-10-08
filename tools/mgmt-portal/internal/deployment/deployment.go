// Package deployment works out which RAN simulators (UERANSIM, PacketRusher)
// are deployed next to the 5G core, so the portal can hide pages for tools that
// are not part of the current deployment mode.
//
// Detection probes Docker (compose project containers, any state) and can be
// forced with PORTAL_RAN_TOOLS. The gNBs page does not depend on it: gNB data
// comes from the AMF.
package deployment

import (
	"context"
	"strings"
	"sync"
	"time"

	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
)

// Deployment modes reported in Capabilities.Mode.
const (
	ModeStandalone   = "standalone"
	ModeUERANSIM     = "ueransim"
	ModePacketRusher = "packetrusher"
	ModeBoth         = "both"
)

// Detection sources reported in Capabilities.Source.
const (
	SourceDocker      = "docker"
	SourceOverride    = "override"
	SourceUnavailable = "unavailable"
)

// cacheTTL is how long a detection result is reused. Lab UX value, not a 3GPP timer.
const cacheTTL = 5 * time.Second

// ContainerState is one simulator container.
type ContainerState struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Running bool   `json:"running"`
}

// ToolState describes one RAN simulator family.
type ToolState struct {
	// Deployed is true when any container of the family exists in the compose
	// project, in any state (including created but not started).
	Deployed bool `json:"deployed"`
	// Running is true when any container of the family is running.
	Running    bool             `json:"running"`
	Containers []ContainerState `json:"containers"`
}

// Capabilities is the deployment mode served by GET /api/v1/deployment.
type Capabilities struct {
	Mode         string    `json:"mode"`
	UERANSIM     ToolState `json:"ueransim"`
	PacketRusher ToolState `json:"packetrusher"`
	Source       string    `json:"source"`
	DetectedAt   time.Time `json:"detected_at"`
}

// Lister lists the containers of the compose project.
type Lister interface {
	List(ctx context.Context) ([]dockerclient.Service, error)
}

// IsUERANSIMName reports whether a container belongs to the UERANSIM family.
func IsUERANSIMName(name string) bool { return strings.HasPrefix(name, "ueransim-") }

// IsPacketRusherName reports whether a container belongs to the PacketRusher family.
func IsPacketRusherName(name string) bool {
	return name == "packetrusher" || name == "packetrusher-n2"
}

func modeOf(ueransim, packetrusher bool) string {
	switch {
	case ueransim && packetrusher:
		return ModeBoth
	case ueransim:
		return ModeUERANSIM
	case packetrusher:
		return ModePacketRusher
	}
	return ModeStandalone
}

// Detect derives the capabilities from a container list. override is one of
// "", "auto", "none", "ueransim", "packetrusher", "both"; anything other than
// "" / "auto" forces the result and keeps the container lists for display.
func Detect(services []dockerclient.Service, override string, now time.Time) Capabilities {
	caps := Capabilities{Source: SourceDocker, DetectedAt: now}
	caps.UERANSIM.Containers = []ContainerState{}
	caps.PacketRusher.Containers = []ContainerState{}
	for _, s := range services {
		name := strings.TrimPrefix(s.Name, "/")
		cs := ContainerState{Name: name, State: s.State, Running: s.State == "running"}
		switch {
		case IsUERANSIMName(name):
			caps.UERANSIM.Containers = append(caps.UERANSIM.Containers, cs)
			caps.UERANSIM.Deployed = true
			caps.UERANSIM.Running = caps.UERANSIM.Running || cs.Running
		case IsPacketRusherName(name):
			caps.PacketRusher.Containers = append(caps.PacketRusher.Containers, cs)
			caps.PacketRusher.Deployed = true
			caps.PacketRusher.Running = caps.PacketRusher.Running || cs.Running
		}
	}
	switch strings.ToLower(strings.TrimSpace(override)) {
	case "", "auto":
	case "none":
		caps.UERANSIM.Deployed, caps.PacketRusher.Deployed = false, false
		caps.Source = SourceOverride
	case ModeUERANSIM:
		caps.UERANSIM.Deployed, caps.PacketRusher.Deployed = true, false
		caps.Source = SourceOverride
	case ModePacketRusher:
		caps.UERANSIM.Deployed, caps.PacketRusher.Deployed = false, true
		caps.Source = SourceOverride
	case ModeBoth:
		caps.UERANSIM.Deployed, caps.PacketRusher.Deployed = true, true
		caps.Source = SourceOverride
	}
	caps.Mode = modeOf(caps.UERANSIM.Deployed, caps.PacketRusher.Deployed)
	return caps
}

// Detector caches Detect results for cacheTTL.
type Detector struct {
	lister   Lister
	override string
	now      func() time.Time

	mu     sync.Mutex
	cached Capabilities
	at     time.Time
}

// NewDetector builds a Detector. lister may be nil (Docker socket not mounted):
// the result is then the override if set, else standalone with source "unavailable".
func NewDetector(lister Lister, override string) *Detector {
	return &Detector{lister: lister, override: override, now: time.Now}
}

// Get returns the current capabilities, probing Docker at most once per cacheTTL.
func (d *Detector) Get(ctx context.Context) Capabilities {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if !d.at.IsZero() && now.Sub(d.at) < cacheTTL {
		return d.cached
	}
	var caps Capabilities
	if d.lister == nil {
		caps = Detect(nil, d.override, now)
		if caps.Source == SourceDocker {
			caps.Source = SourceUnavailable
		}
	} else if svcs, err := d.lister.List(ctx); err != nil {
		caps = Detect(nil, d.override, now)
		if caps.Source == SourceDocker {
			caps.Source = SourceUnavailable
		}
	} else {
		caps = Detect(svcs, d.override, now)
	}
	d.cached, d.at = caps, now
	return caps
}

// Has reports whether the tool ("ueransim" or "packetrusher") is deployed.
func (c Capabilities) Has(tool string) bool {
	switch tool {
	case ModeUERANSIM:
		return c.UERANSIM.Deployed
	case ModePacketRusher:
		return c.PacketRusher.Deployed
	}
	return false
}
