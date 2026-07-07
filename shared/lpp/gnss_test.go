package lpp

import "testing"

// madridLat/madridLon is the "Madrid Puerta del Sol" survey point used
// throughout this project's LMF test fixtures (mirrors LMF-004/LMF-006).
const (
	madridLat = 40.416775
	madridLon = -3.703790
)

// TestGeodeticECEFRoundTrip verifies GeodeticToECEF/ECEFToGeodetic agree with
// each other within a small tolerance.
func TestGeodeticECEFRoundTrip(t *testing.T) {
	cases := []struct {
		lat, lon, alt float64
	}{
		{madridLat, madridLon, 0},
		{0, 0, 0},
		{51.5074, -0.1278, 100},  // London
		{-33.8688, 151.2093, 50}, // Sydney
	}
	for _, c := range cases {
		x, y, z := GeodeticToECEF(c.lat, c.lon, c.alt)
		gotLat, gotLon, gotAlt := ECEFToGeodetic(x, y, z)
		if abs(gotLat-c.lat) > 1e-6 {
			t.Errorf("lat round-trip: got %v want %v", gotLat, c.lat)
		}
		if abs(gotLon-c.lon) > 1e-6 {
			t.Errorf("lon round-trip: got %v want %v", gotLon, c.lon)
		}
		if abs(gotAlt-c.alt) > 1e-3 {
			t.Errorf("alt round-trip: got %v want %v", gotAlt, c.alt)
		}
	}
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

// TestSolveWLS_KnownGeometry verifies that a synthetic 4-satellite geometry
// anchored at a known point, measured from a (slightly displaced) true UE
// position with a receiver clock bias, recovers the true position within a
// small tolerance via the WLS solver.
// Ref: docs/procedures/LPPRelay.md §Simplified WLS GNSS position calculation;
// §Validation approach ("4 SVs with a known geometry -> expected WGS84 fix
// within tolerance").
func TestSolveWLS_KnownGeometry(t *testing.T) {
	anchorLat, anchorLon := madridLat, madridLon
	eph := GenerateSyntheticEphemeris(anchorLat, anchorLon)
	if len(eph) < WLSMinSatellites {
		t.Fatalf("GenerateSyntheticEphemeris returned %d satellites, want >= %d", len(eph), WLSMinSatellites)
	}

	// True UE position is a small displacement from the anchor (a few tens of
	// metres), plus a synthetic receiver clock bias (metres).
	trueLat := anchorLat + 0.0002 // ~22 m north
	trueLon := anchorLon + 0.0002
	const clockBiasM = 12345.0

	meas := SimulateMeasurements(eph, trueLat, trueLon, 0, clockBiasM)

	result, ok := SolveWLS(anchorLat, anchorLon, eph, meas)
	if !ok {
		t.Fatal("SolveWLS: ok = false, want true")
	}
	if result.SatelliteCount != len(eph) {
		t.Errorf("SatelliteCount = %d, want %d", result.SatelliteCount, len(eph))
	}

	gotX, gotY, gotZ := GeodeticToECEF(result.Lat, result.Lon, 0)
	wantX, wantY, wantZ := GeodeticToECEF(trueLat, trueLon, 0)
	dx, dy, dz := gotX-wantX, gotY-wantY, gotZ-wantZ
	errM := sqrt(dx*dx + dy*dy + dz*dz)
	if errM > 5.0 {
		t.Errorf("position error = %.3f m, want <= 5 m (got lat=%v lon=%v, want lat=%v lon=%v)",
			errM, result.Lat, result.Lon, trueLat, trueLon)
	}

	if result.UncertaintyM > 50.0 {
		t.Errorf("UncertaintyM = %v, want <= 50", result.UncertaintyM)
	}
	if result.UncertaintyM < wlsUncertaintyMinM {
		t.Errorf("UncertaintyM = %v, want >= %v (clamped floor)", result.UncertaintyM, wlsUncertaintyMinM)
	}
}

func sqrt(v float64) float64 {
	// local sqrt to avoid importing math twice for one call in the test file
	if v <= 0 {
		return 0
	}
	x := v
	for i := 0; i < 40; i++ {
		x = 0.5 * (x + v/x)
	}
	return x
}

// TestSolveWLS_TooFewSatellites verifies the < 4 satellite fallback signal.
func TestSolveWLS_TooFewSatellites(t *testing.T) {
	eph := GenerateSyntheticEphemeris(madridLat, madridLon)[:3] // only 3 SVs
	meas := SimulateMeasurements(eph, madridLat, madridLon, 0, 0)

	_, ok := SolveWLS(madridLat, madridLon, eph, meas)
	if ok {
		t.Fatal("SolveWLS with 3 satellites: ok = true, want false (< WLSMinSatellites)")
	}
}

// TestSolveWLS_NoMatchingSatellites verifies that measurements reporting
// SVIDs absent from the ephemeris are not matched (0 usable satellites).
func TestSolveWLS_NoMatchingSatellites(t *testing.T) {
	eph := GenerateSyntheticEphemeris(madridLat, madridLon)
	// Measurements for SVIDs that don't exist in the ephemeris.
	meas := []Measurement{
		{SVID: 90, PseudorangeMeters: 20000000},
		{SVID: 91, PseudorangeMeters: 21000000},
	}
	_, ok := SolveWLS(madridLat, madridLon, eph, meas)
	if ok {
		t.Fatal("SolveWLS with unmatched SVIDs: ok = true, want false")
	}
}

// TestGenerateSyntheticEphemeris_Deterministic verifies the ephemeris
// generator is deterministic (same anchor -> same output), required for
// reproducible tests and for the LMF/UE to agree on assistance data.
func TestGenerateSyntheticEphemeris_Deterministic(t *testing.T) {
	a := GenerateSyntheticEphemeris(madridLat, madridLon)
	b := GenerateSyntheticEphemeris(madridLat, madridLon)
	if len(a) != len(b) {
		t.Fatalf("len mismatch: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("ephemeris[%d] differs: %+v vs %+v", i, a[i], b[i])
		}
	}
}
