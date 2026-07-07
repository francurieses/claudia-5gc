package server

import (
	"math"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
)

func testMobilityCfg() *config.Config {
	cfg := &config.Config{}
	cfg.CellCoordinates = map[string]config.CellCoord{
		"000000010": {Lat: 40.4168, Lon: -3.7038},
	}
	cfg.DefaultCoord = config.CellCoord{Lat: 10, Lon: 20}
	cfg.Mobility = config.MobilityConfig{Enabled: true, RadiusM: 500, SpeedMps: 5}
	return cfg
}

// haversineM returns the great-circle distance in metres between two WGS84 points.
func haversineM(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371000.0
	rad := math.Pi / 180
	dLat := (lat2 - lat1) * rad
	dLon := (lon2 - lon1) * rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * R * math.Asin(math.Sqrt(a))
}

func TestMobility_Deterministic(t *testing.T) {
	m1 := newMobilityModel(testMobilityCfg())
	m2 := newMobilityModel(testMobilityCfg())
	ts := time.Unix(1_700_000_000, 0)

	lat1, lon1, acc1 := m1.position("imsi-001010000000001", "000000010", ts)
	lat2, lon2, acc2 := m2.position("imsi-001010000000001", "000000010", ts)

	if lat1 != lat2 || lon1 != lon2 || acc1 != acc2 {
		t.Fatalf("non-deterministic: (%v,%v,%v) != (%v,%v,%v)", lat1, lon1, acc1, lat2, lon2, acc2)
	}
}

func TestMobility_BoundedWithinRadius(t *testing.T) {
	cfg := testMobilityCfg()
	m := newMobilityModel(cfg)
	base := cfg.CellCoordinates["000000010"]

	// Sample the trajectory over a long window; it must never leave the cell radius.
	start := time.Unix(1_700_000_000, 0)
	for i := 0; i < 5000; i++ {
		ts := start.Add(time.Duration(i) * time.Second)
		lat, lon, _ := m.position("imsi-001010000000099", "000000010", ts)
		d := haversineM(base.Lat, base.Lon, lat, lon)
		if d > cfg.Mobility.RadiusM+1 { // +1 m tolerance
			t.Fatalf("strayed %0.1f m beyond radius %0.0f m at t+%ds", d, cfg.Mobility.RadiusM, i)
		}
	}
}

func TestMobility_MovesOverTime(t *testing.T) {
	m := newMobilityModel(testMobilityCfg())
	t0 := time.Unix(1_700_000_000, 0)
	lat0, lon0, _ := m.position("imsi-001010000000001", "000000010", t0)

	// Two polls a few seconds apart should yield a measurable displacement.
	lat1, lon1, _ := m.position("imsi-001010000000001", "000000010", t0.Add(10*time.Second))
	if haversineM(lat0, lon0, lat1, lon1) < 1.0 {
		t.Fatalf("UE did not move over 10s: (%v,%v) ~ (%v,%v)", lat0, lon0, lat1, lon1)
	}
}

func TestMobility_DistinctSupisDiverge(t *testing.T) {
	m := newMobilityModel(testMobilityCfg())
	ts := time.Unix(1_700_000_000, 0)
	latA, lonA, _ := m.position("imsi-001010000000001", "000000010", ts)
	latB, lonB, _ := m.position("imsi-001010000000002", "000000010", ts)
	if haversineM(latA, lonA, latB, lonB) < 1.0 {
		t.Fatalf("distinct SUPIs produced near-identical positions")
	}
}

func TestMobility_UnknownCellUsesDefault(t *testing.T) {
	cfg := testMobilityCfg()
	cfg.Mobility.Enabled = false // static → returns the anchor exactly
	m := newMobilityModel(cfg)
	lat, lon, _ := m.position("imsi-001010000000001", "ffffffff0", time.Unix(1_700_000_000, 0))
	if lat != cfg.DefaultCoord.Lat || lon != cfg.DefaultCoord.Lon {
		t.Fatalf("unknown cell did not fall back to default: got (%v,%v)", lat, lon)
	}
}

func TestMobility_DisabledReturnsAnchor(t *testing.T) {
	cfg := testMobilityCfg()
	cfg.Mobility.Enabled = false
	m := newMobilityModel(cfg)
	base := cfg.CellCoordinates["000000010"]
	lat, lon, _ := m.position("imsi-001010000000001", "000000010", time.Unix(1_700_000_000, 0))
	if lat != base.Lat || lon != base.Lon {
		t.Fatalf("disabled mobility should return static anchor, got (%v,%v)", lat, lon)
	}
}
