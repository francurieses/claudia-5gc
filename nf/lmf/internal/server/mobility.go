// mobility.go — synthetic UE-motion model for the LMF.
//
// Cell-ID positioning yields only the serving NR cell on the N2/NGAP wire (NRCGI + TAI); it
// carries no latitude/longitude. To present a believable, *moving* location (e.g. on the
// management-portal map) the LMF synthesizes WGS84 coordinates here: each UE follows a smooth,
// bounded, deterministic walk anchored at its serving cell's base coordinate.
//
// The trajectory is a pure function of (supi, serving cell, wall-clock time): deterministic and
// continuous, so repeated polls trace a coherent path and the model survives process restarts
// (the UE re-anchors onto the same path). Different SUPIs diverge via a per-SUPI seed.
//
// This is a simulation aid — NOT a positioning method. The authoritative output of
// DetermineLocation remains the serving NRCGI/TAI reported by the gNB.
package server

import (
	"hash/fnv"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
)

// metersPerDegLat is the approximate number of metres per degree of latitude (WGS84).
const metersPerDegLat = 111320.0

// mobilityModel synthesizes artificial-but-realistic coordinates for UEs.
type mobilityModel struct {
	cells   map[string]config.CellCoord
	def     config.CellCoord
	enabled bool
	radiusM float64
	speedM  float64

	mu    sync.Mutex
	walks map[string]*walkParams
}

// walkParams are the per-SUPI seeded constants that shape a UE's trajectory. The position is
// the superposition of two circular motions (a slow primary loop + a faster, smaller wiggle),
// which yields a smooth, bounded path that does not look obviously periodic over short windows.
type walkParams struct {
	a1, a2 float64 // radial amplitudes as a fraction of radiusM (a1+a2 < 1 keeps it bounded)
	w1, w2 float64 // angular speeds (rad/s)
	p1, p2 float64 // initial phases (rad)
}

// newMobilityModel builds the model from config, applying sane defaults.
func newMobilityModel(cfg *config.Config) *mobilityModel {
	radius := cfg.Mobility.RadiusM
	if radius <= 0 {
		radius = 500
	}
	speed := cfg.Mobility.SpeedMps
	if speed <= 0 {
		speed = 5
	}
	return &mobilityModel{
		cells:   cfg.CellCoordinates,
		def:     cfg.DefaultCoord,
		enabled: cfg.Mobility.Enabled,
		radiusM: radius,
		speedM:  speed,
		walks:   make(map[string]*walkParams),
	}
}

// anchor returns the base coordinate for a serving cell, falling back to the default.
func (m *mobilityModel) anchor(nrCellId string) config.CellCoord {
	if c, ok := m.cells[nrCellId]; ok {
		return c
	}
	return m.def
}

// position returns the synthesized WGS84 coordinate and horizontal accuracy (metres) for the
// given UE at time now. With mobility disabled it returns the static cell anchor.
func (m *mobilityModel) position(supi, nrCellId string, now time.Time) (lat, lon, accuracyM float64) {
	base := m.anchor(nrCellId)
	if !m.enabled {
		return base.Lat, base.Lon, m.radiusM / 2
	}

	wp := m.walkFor(supi)
	t := float64(now.UnixNano()) / 1e9

	// Offsets (metres) from two superposed circular motions.
	east := m.radiusM * (wp.a1*math.Cos(wp.w1*t+wp.p1) + wp.a2*math.Cos(wp.w2*t+wp.p2))
	north := m.radiusM * (wp.a1*math.Sin(wp.w1*t+wp.p1) + wp.a2*math.Sin(wp.w2*t+wp.p2))

	latRad := base.Lat * math.Pi / 180
	dLat := north / metersPerDegLat
	dLon := east / (metersPerDegLat * math.Cos(latRad))

	// Horizontal accuracy: realistic for Cell-ID positioning (tens to a few hundred metres).
	accuracyM = m.radiusM / 3
	return base.Lat + dLat, base.Lon + dLon, accuracyM
}

// walkFor returns (and lazily creates) the per-SUPI seeded trajectory constants.
func (m *mobilityModel) walkFor(supi string) *walkParams {
	m.mu.Lock()
	defer m.mu.Unlock()
	if wp, ok := m.walks[supi]; ok {
		return wp
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(supi))
	rng := rand.New(rand.NewSource(int64(h.Sum64()))) //nolint:gosec // deterministic sim, not security

	// Base angular speed from desired ground speed: w = v / R (rad/s).
	wBase := m.speedM / m.radiusM
	wp := &walkParams{
		a1: 0.35 + 0.25*rng.Float64(), // 0.35..0.60 of radius (primary loop)
		a2: 0.10 + 0.10*rng.Float64(), // 0.10..0.20 of radius (finer wiggle) → max sum 0.80 < 1
		w1: wBase * (0.8 + 0.4*rng.Float64()),
		w2: wBase * (2.5 + 1.5*rng.Float64()), // faster secondary component
		p1: rng.Float64() * 2 * math.Pi,
		p2: rng.Float64() * 2 * math.Pi,
	}
	m.walks[supi] = wp
	return wp
}
