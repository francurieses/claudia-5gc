// Package lpp — simplified WGS84/ECEF geometry, weighted least-squares (WLS)
// GNSS position solver, and the TS 37.355/TS 23.032 quantization converters.
//
// This file implements the "Simplified WLS GNSS position calculation"
// described in docs/procedures/LPPRelay.md: it turns a synthetic per-SV
// ephemeris (SatEphemeris, ECEF metres) plus reported pseudorange
// measurements (Measurement, metres) into a WGS84 lat/lon fix, following
// the classic GNSS Gauss-Newton trilateration-with-clock-bias approach:
//
//  1. Linearise ρ_i = |S_i − X| + c·δt around an initial guess X0 (the
//     serving-cell anchor) and iterate a few Gauss-Newton steps for the
//     receiver ECEF position X and clock bias term c·δt.
//  2. Convert the ECEF solution to WGS84 lat/lon (2-D MVP; altitude discarded).
//  3. Derive uncertainty from the WLS residual RMS, clamped to the GNSS
//     accuracy band (target <= 50 m CEP50).
//
// This is a deterministic, config-anchored approximation — not a full GNSS
// engine — matching the philosophy of the LMF-004 E-CID centroid and the
// LMF-006 synthetic mobility model. It is not a 3GPP-defined algorithm (TS
// 23.273 §6.2.10 leaves the actual position-computation method
// implementation-defined); no 3GPP constant is invented here.
package lpp

import (
	"fmt"
	"math"
)

// ---- Local (non-wire) geometry value types ------------------------------------
//
// Neither type appears on the wire: satellite positions are NOT carried in
// any LPP message (no gnss-GenericAssistData / navigation model is sent) —
// both ends recompute the same deterministic constellation from the
// wire-quantized reference location (the quantized-anchor rule,
// docs/procedures/LPPRelay.md); pseudoranges ride the wire as
// codePhase/integerCodePhase fields (SatMeas, lpp.go), converted via
// PseudorangeToCodePhase / CodePhaseToPseudorange below.

// SatEphemeris is a per-satellite synthetic ephemeris entry: the
// constellation index (1-based; rides the wire as SV-ID.satellite-id =
// SVID − 1) plus the satellite's ECEF position in metres.
type SatEphemeris struct {
	SVID                                  uint8
	ECEFXMeters, ECEFYMeters, ECEFZMeters float64
}

// Measurement is a per-satellite pseudorange in metres (constellation-index
// keyed, decoded from the wire codePhase fields).
type Measurement struct {
	SVID              uint8
	PseudorangeMeters float64
}

// ---- WGS84 ellipsoid constants (TS 23.032 / NIMA TR8350.2) ------------------

const (
	wgs84SemiMajorAxisM = 6378137.0         // a
	wgs84Flattening     = 1 / 298.257223563 // f
)

var wgs84EccentricitySquared = wgs84Flattening * (2 - wgs84Flattening) // e^2

// ---- WLS solver tunables (implementation aid, not a 3GPP value) -------------

const (
	// WLSMinSatellites is the minimum number of matched (ephemeris ∩
	// measurement) satellites required to solve for a 3-D position + clock
	// bias (3 for position, 1 for the receiver clock bias).
	// Ref: docs/procedures/LPPRelay.md §Simplified WLS GNSS position calculation.
	WLSMinSatellites = 4

	// wlsIterations is the number of Gauss-Newton iterations performed.
	wlsIterations = 8

	// wlsUncertaintyMinM / wlsUncertaintyMaxM bound the derived uncertainty to
	// the GNSS accuracy band. Ref: LPPRelay.md target "<= 50 m CEP50".
	wlsUncertaintyMinM = 5.0
	wlsUncertaintyMaxM = 50.0

	// wlsResidualToUncertaintyFactor is a simple geometry (DOP-like) scaling
	// factor applied to the WLS residual RMS to derive the reported
	// uncertainty. An implementation aid, not an invented 3GPP constant.
	wlsResidualToUncertaintyFactor = 3.0
)

// ---- WGS84 <-> ECEF conversions ----------------------------------------------

// GeodeticToECEF converts a WGS84 (lat, lon, altitude) coordinate (degrees,
// degrees, metres) to ECEF (x, y, z) metres.
func GeodeticToECEF(latDeg, lonDeg, altM float64) (x, y, z float64) {
	lat := latDeg * math.Pi / 180.0
	lon := lonDeg * math.Pi / 180.0
	sinLat, cosLat := math.Sin(lat), math.Cos(lat)
	sinLon, cosLon := math.Sin(lon), math.Cos(lon)

	n := wgs84SemiMajorAxisM / math.Sqrt(1-wgs84EccentricitySquared*sinLat*sinLat)
	x = (n + altM) * cosLat * cosLon
	y = (n + altM) * cosLat * sinLon
	z = (n*(1-wgs84EccentricitySquared) + altM) * sinLat
	return x, y, z
}

// ECEFToGeodetic converts ECEF (x, y, z) metres to WGS84 (lat, lon, altitude)
// (degrees, degrees, metres) using Bowring's iterative method.
func ECEFToGeodetic(x, y, z float64) (latDeg, lonDeg, altM float64) {
	lon := math.Atan2(y, x)
	p := math.Sqrt(x*x + y*y)

	// Initial latitude guess (spherical approximation), then iterate.
	lat := math.Atan2(z, p*(1-wgs84EccentricitySquared))
	var n float64
	for i := 0; i < 6; i++ {
		sinLat := math.Sin(lat)
		n = wgs84SemiMajorAxisM / math.Sqrt(1-wgs84EccentricitySquared*sinLat*sinLat)
		alt := p/math.Cos(lat) - n
		lat = math.Atan2(z, p*(1-wgs84EccentricitySquared*(n/(n+alt))))
	}
	sinLat := math.Sin(lat)
	n = wgs84SemiMajorAxisM / math.Sqrt(1-wgs84EccentricitySquared*sinLat*sinLat)
	alt := p/math.Cos(lat) - n

	return lat * 180.0 / math.Pi, lon * 180.0 / math.Pi, alt
}

// ---- Synthetic ephemeris generation (mock assistance data) -------------------

// satGeometry is a fixed (elevation, azimuth) pair (degrees) used to place a
// synthetic satellite around an anchor point. The specific angles are an
// implementation choice giving good (non-degenerate) satellite geometry for
// the WLS solve — not a real GNSS constellation almanac.
type satGeometry struct {
	elevationDeg, azimuthDeg float64
}

// defaultSatGeometries places 4 synthetic satellites at high, well-spread
// elevation/azimuth angles — enough for a well-conditioned 4-unknown
// (position + clock bias) WLS solve.
var defaultSatGeometries = []satGeometry{
	{elevationDeg: 75, azimuthDeg: 0},
	{elevationDeg: 60, azimuthDeg: 90},
	{elevationDeg: 45, azimuthDeg: 200},
	{elevationDeg: 30, azimuthDeg: 300},
}

// gnssSlantRangeM is the representative satellite-to-receiver slant range
// used to place the synthetic satellites (typical GPS MEO slant range,
// roughly 20,000-25,000 km). An implementation choice for the mock geometry,
// not a real per-satellite computation.
const gnssSlantRangeM = 22_000_000.0

// GenerateSyntheticEphemeris returns the deterministic 4-satellite synthetic
// ephemeris (ECEF positions) anchored at (anchorLat, anchorLon). The anchor
// MUST be the wire-quantized reference location (DecodeLatitude/
// DecodeLongitude of the encoded gnss-ReferenceLocation) so the LMF and the
// UE-side mirror compute byte-identical geometry — the quantized-anchor rule.
// Ref: docs/procedures/LPPRelay.md §Synthetic satellite geometry.
func GenerateSyntheticEphemeris(anchorLat, anchorLon float64) []SatEphemeris {
	anchorX, anchorY, anchorZ := GeodeticToECEF(anchorLat, anchorLon, 0)

	out := make([]SatEphemeris, 0, len(defaultSatGeometries))
	for i, g := range defaultSatGeometries {
		dx, dy, dz := enuUnitVectorToECEF(anchorLat, anchorLon, g.elevationDeg, g.azimuthDeg)
		out = append(out, SatEphemeris{
			SVID:        uint8(i + 1),
			ECEFXMeters: anchorX + dx*gnssSlantRangeM,
			ECEFYMeters: anchorY + dy*gnssSlantRangeM,
			ECEFZMeters: anchorZ + dz*gnssSlantRangeM,
		})
	}
	return out
}

// enuUnitVectorToECEF converts a local East-North-Up unit direction (given by
// elevation/azimuth, degrees, at a WGS84 anchor point) into an ECEF unit
// direction vector.
func enuUnitVectorToECEF(anchorLat, anchorLon, elevationDeg, azimuthDeg float64) (dx, dy, dz float64) {
	el := elevationDeg * math.Pi / 180.0
	az := azimuthDeg * math.Pi / 180.0
	e := math.Cos(el) * math.Sin(az)
	n := math.Cos(el) * math.Cos(az)
	u := math.Sin(el)

	lat := anchorLat * math.Pi / 180.0
	lon := anchorLon * math.Pi / 180.0
	sinLat, cosLat := math.Sin(lat), math.Cos(lat)
	sinLon, cosLon := math.Sin(lon), math.Cos(lon)

	dx = -sinLon*e - sinLat*cosLon*n + cosLat*cosLon*u
	dy = cosLon*e - sinLat*sinLon*n + cosLat*sinLon*u
	dz = cosLat*n + sinLat*u
	return dx, dy, dz
}

// ---- Weighted least-squares position solve -----------------------------------

// WLSResult is the outcome of SolveWLS.
type WLSResult struct {
	Lat, Lon       float64
	UncertaintyM   float64
	SatelliteCount int
	ResidualRMSM   float64
}

// SolveWLS computes a WGS84 position fix from a synthetic ephemeris and
// reported pseudorange measurements, anchored at (anchorLat, anchorLon) for
// the initial guess (the serving-cell coordinate — TS 23.273 §6.2.10 leaves
// the actual solver implementation-defined).
//
// Only satellites present in BOTH ephemeris and measurements (matched by
// SVID) are used. Returns ok=false when fewer than WLSMinSatellites (4) are
// matched, or the solve does not converge to a finite result — both signal
// the caller to fall back to E-CID/Cell-ID (TS 23.273 §6.2.10).
func SolveWLS(anchorLat, anchorLon float64, ephemeris []SatEphemeris, measurements []Measurement) (WLSResult, bool) {
	measBySVID := make(map[uint8]float64, len(measurements))
	for _, m := range measurements {
		measBySVID[m.SVID] = m.PseudorangeMeters
	}

	type sat struct {
		x, y, z float64
		rangeM  float64
	}
	var sats []sat
	for _, e := range ephemeris {
		if rho, ok := measBySVID[e.SVID]; ok {
			sats = append(sats, sat{x: e.ECEFXMeters, y: e.ECEFYMeters, z: e.ECEFZMeters, rangeM: rho})
		}
	}
	if len(sats) < WLSMinSatellites {
		return WLSResult{}, false
	}

	// Initial guess: anchor ECEF, zero clock bias.
	x, y, z := GeodeticToECEF(anchorLat, anchorLon, 0)
	dt := 0.0

	var residualRMS float64
	for iter := 0; iter < wlsIterations; iter++ {
		// Normal equations G^T*G*delta = G^T*r for params [x,y,z,dt].
		var gtg [4][4]float64
		var gtr [4]float64
		var sumSq float64

		for _, s := range sats {
			dxr, dyr, dzr := x-s.x, y-s.y, z-s.z
			rangeEst := math.Sqrt(dxr*dxr + dyr*dyr + dzr*dzr)
			if rangeEst < 1 {
				return WLSResult{}, false // degenerate geometry
			}
			predicted := rangeEst + dt
			residual := s.rangeM - predicted
			sumSq += residual * residual

			g := [4]float64{dxr / rangeEst, dyr / rangeEst, dzr / rangeEst, 1}
			for r := 0; r < 4; r++ {
				gtr[r] += g[r] * residual
				for c := 0; c < 4; c++ {
					gtg[r][c] += g[r] * g[c]
				}
			}
		}
		residualRMS = math.Sqrt(sumSq / float64(len(sats)))

		delta, ok := solve4x4(gtg, gtr)
		if !ok {
			return WLSResult{}, false
		}
		x += delta[0]
		y += delta[1]
		z += delta[2]
		dt += delta[3]
	}

	if math.IsNaN(x) || math.IsNaN(y) || math.IsNaN(z) {
		return WLSResult{}, false
	}

	lat, lon, _ := ECEFToGeodetic(x, y, z)

	uncertainty := residualRMS * wlsResidualToUncertaintyFactor
	if uncertainty < wlsUncertaintyMinM {
		uncertainty = wlsUncertaintyMinM
	}
	if uncertainty > wlsUncertaintyMaxM {
		uncertainty = wlsUncertaintyMaxM
	}

	return WLSResult{
		Lat:            lat,
		Lon:            lon,
		UncertaintyM:   uncertainty,
		SatelliteCount: len(sats),
		ResidualRMSM:   residualRMS,
	}, true
}

// SimulateMeasurements is a test/fixture helper that computes the pseudorange
// each satellite in ephemeris would report from a true UE position, given a
// receiver clock bias (metres, i.e. c·δt). Used by this package's own unit
// tests and by nf/lmf test doubles to fabricate deterministic
// ProvideLocationInformation measurements for a known ground-truth position —
// it is NOT used on the production LMF/UE code path (real pseudoranges are
// reported by the UE over the LPP wire; the LMF never computes them itself).
func SimulateMeasurements(ephemeris []SatEphemeris, trueLat, trueLon, trueAltM, clockBiasM float64) []Measurement {
	x, y, z := GeodeticToECEF(trueLat, trueLon, trueAltM)
	out := make([]Measurement, 0, len(ephemeris))
	for _, e := range ephemeris {
		dx, dy, dz := x-e.ECEFXMeters, y-e.ECEFYMeters, z-e.ECEFZMeters
		rangeM := math.Sqrt(dx*dx + dy*dy + dz*dz)
		out = append(out, Measurement{SVID: e.SVID, PseudorangeMeters: rangeM + clockBiasM})
	}
	return out
}

// solve4x4 solves the 4x4 linear system a*x = b via Gaussian elimination with
// partial pivoting. Returns ok=false for a (near-)singular matrix.
func solve4x4(a [4][4]float64, b [4]float64) ([4]float64, bool) {
	// Augment and reduce.
	var m [4][5]float64
	for r := 0; r < 4; r++ {
		copy(m[r][:4], a[r][:])
		m[r][4] = b[r]
	}

	for col := 0; col < 4; col++ {
		// Partial pivot.
		pivot := col
		maxAbs := math.Abs(m[col][col])
		for r := col + 1; r < 4; r++ {
			if v := math.Abs(m[r][col]); v > maxAbs {
				maxAbs = v
				pivot = r
			}
		}
		if maxAbs < 1e-12 {
			return [4]float64{}, false
		}
		m[col], m[pivot] = m[pivot], m[col]

		for r := 0; r < 4; r++ {
			if r == col {
				continue
			}
			factor := m[r][col] / m[col][col]
			for c := col; c < 5; c++ {
				m[r][c] -= factor * m[col][c]
			}
		}
	}

	var x [4]float64
	for r := 0; r < 4; r++ {
		if math.Abs(m[r][r]) < 1e-12 {
			return [4]float64{}, false
		}
		x[r] = m[r][4] / m[r][r]
	}
	return x, true
}

// ---- TS 37.355 / TS 23.032 quantization converters ------------------------------
//
// These converters are the single source of truth for both ends of the LPP
// exchange: the C++ UE patch (tools/ueransim/patches/0042-lpp-gnss.patch)
// mirrors these formulas exactly and byte-matches this package's golden-hex
// test dumps (tools/ueransim/CLAUDE.md §4 — Go is the source of truth).

// Speed-of-light / code-phase constants (TS 37.355 §6.5.2
// GNSS-MeasurementList field descriptions: codePhase + integerCodePhase carry
// the pseudorange in milliseconds of light-travel time).
const (
	// SpeedOfLightMPerS is c in m/s.
	SpeedOfLightMPerS = 299792458.0
	// MetersPerMsOfRange is the range represented by 1 ms of light travel:
	// c × 1 ms = 299792.458 m.
	MetersPerMsOfRange = 299792.458
	// CodePhaseUnitsPerMs is the codePhase resolution: 2^21 units per ms
	// (each unit ≈ 0.1430 m of range).
	CodePhaseUnitsPerMs = 1 << 21
	// maxIntegerCodePhase is the integerCodePhase upper bound (0..127 whole ms).
	maxIntegerCodePhase = 127
)

// GPS time constants (TS 37.355 §6.5.2 GNSS-SystemTime; gnss-DayNumber /
// gnss-TimeOfDay are continuous GPS time — no leap seconds).
const (
	// GPSEpochUnix is 1980-01-06T00:00:00Z, the GPS epoch, as a Unix second.
	GPSEpochUnix int64 = 315964800
	// GPSUTCLeapSeconds is the GPS−UTC leap-second offset (documented
	// implementation constant, valid since 2017; a real network derives it
	// from the GNSS broadcast).
	GPSUTCLeapSeconds int64 = 18
)

// Synthetic-UE model constants (docs/procedures/LPPRelay.md §Synthetic
// satellite geometry — the UE patch's deterministic true position and clock
// bias; exported so test fixtures and the C++ mirror share one definition).
const (
	// UEOffsetNorthM / UEOffsetEastM displace the UE's synthetic true
	// position from the wire-quantized anchor via the local ENU frame.
	UEOffsetNorthM = 25.0
	UEOffsetEastM  = 15.0
	// UEClockBiasM is the receiver clock bias (metres of range, c·δt) the
	// synthetic UE adds to every pseudorange; SolveWLS solves it out.
	UEClockBiasM = 150.0
)

// PseudorangeToCodePhase converts a pseudorange in metres to the wire
// (integerCodePhase, codePhase) pair (UE side):
//
//	total_ms         = pseudorange_m / 299792.458
//	integerCodePhase = floor(total_ms)              (must be ≤ 127)
//	codePhase        = round((total_ms − integerCodePhase) × 2^21)
//	                   (a rounding carry to 2^21 increments integerCodePhase)
//
// Ref: TS 37.355 §6.5.2; docs/procedures/LPPRelay.md §Pseudorange encoding.
func PseudorangeToCodePhase(pseudorangeM float64) (integerCodePhase uint8, codePhase uint32, err error) {
	if pseudorangeM < 0 {
		return 0, 0, fmt.Errorf("lpp: pseudorange %f m is negative", pseudorangeM)
	}
	totalMs := pseudorangeM / MetersPerMsOfRange
	icp := math.Floor(totalMs)
	cp := math.Round((totalMs - icp) * CodePhaseUnitsPerMs)
	if cp >= CodePhaseUnitsPerMs { // rounding carry
		cp = 0
		icp++
	}
	if icp > maxIntegerCodePhase {
		return 0, 0, fmt.Errorf("lpp: pseudorange %f m exceeds integerCodePhase range (%d ms)", pseudorangeM, maxIntegerCodePhase)
	}
	return uint8(icp), uint32(cp), nil
}

// CodePhaseToPseudorange converts the wire (integerCodePhase, codePhase)
// pair back to a pseudorange in metres (LMF side):
//
//	pseudorange_m = (integerCodePhase + codePhase / 2^21) × 299792.458
//
// Ref: TS 37.355 §6.5.2; docs/procedures/LPPRelay.md §Pseudorange encoding.
func CodePhaseToPseudorange(integerCodePhase uint8, codePhase uint32) float64 {
	return (float64(integerCodePhase) + float64(codePhase)/CodePhaseUnitsPerMs) * MetersPerMsOfRange
}

// UnixToGPSDayTime converts a Unix UTC second count to the GNSS-SystemTime
// gnss-DayNumber / gnss-TimeOfDay pair:
//
//	gpsSeconds     = unixUTC − GPSEpochUnix + GPSUTCLeapSeconds
//	gnss-DayNumber = ⌊gpsSeconds / 86400⌋   (fits 0..32767 until 2069)
//	gnss-TimeOfDay = gpsSeconds mod 86400
//
// Ref: TS 37.355 §6.5.2 GNSS-SystemTime; docs/procedures/LPPRelay.md.
func UnixToGPSDayTime(unixUTC int64) (dayNumber uint16, timeOfDay uint32) {
	gpsSeconds := unixUTC - GPSEpochUnix + GPSUTCLeapSeconds
	return uint16(gpsSeconds / 86400), uint32(gpsSeconds % 86400)
}

// GPSTODMsec computes MeasurementReferenceTime.gnss-TOD-msec (0..3599999):
// milliseconds into the current GPS hour at measurement time.
//
//	gnss-TOD-msec = (gpsSeconds mod 3600)·1000 + msec
//
// Ref: TS 37.355 §6.5.2 MeasurementReferenceTime; docs/procedures/LPPRelay.md.
func GPSTODMsec(unixUTC int64, msec int) uint32 {
	gpsSeconds := unixUTC - GPSEpochUnix + GPSUTCLeapSeconds
	return uint32((gpsSeconds%3600)*1000 + int64(msec))
}

// EncodeLatitude quantizes a WGS84 latitude (degrees) to the TS 23.032 §6
// (latitudeSign, degreesLatitude) pair: N = ⌊(|lat°|/90)·2^23⌋, clamped to
// the 23-bit ceiling. Sign: 0 = north, 1 = south.
func EncodeLatitude(latDeg float64) (sign uint8, raw uint32) {
	if latDeg < 0 {
		sign = 1
		latDeg = -latDeg
	}
	n := math.Floor(latDeg / 90.0 * (1 << 23))
	if n > 8388607 {
		n = 8388607
	}
	return sign, uint32(n)
}

// DecodeLatitude recovers degrees from the (latitudeSign, degreesLatitude)
// pair: lat = raw × 90/2^23, negated for south. This is the quantized value
// BOTH ends must seed the synthetic geometry with (quantized-anchor rule).
func DecodeLatitude(sign uint8, raw uint32) float64 {
	lat := float64(raw) * 90.0 / (1 << 23)
	if sign == 1 {
		return -lat
	}
	return lat
}

// EncodeLongitude quantizes a WGS84 longitude (degrees) to the TS 23.032 §6
// degreesLongitude value: N = ⌊(lon°/360)·2^24⌋ — floor toward −∞ per
// TS 23.032 ("N ≤ X < N+1"; NOT truncation toward zero — for the Madrid
// anchor −3.7038° this yields −172610, not −172609), clamped to the signed
// 24-bit range.
func EncodeLongitude(lonDeg float64) int32 {
	n := math.Floor(lonDeg / 360.0 * (1 << 24))
	if n > 8388607 {
		n = 8388607
	}
	if n < -8388608 {
		n = -8388608
	}
	return int32(n)
}

// DecodeLongitude recovers degrees from the raw degreesLongitude value:
// lon = raw × 360/2^24 (quantized-anchor rule counterpart of DecodeLatitude).
func DecodeLongitude(raw int32) float64 {
	return float64(raw) * 360.0 / (1 << 24)
}

// EncodeCodePhaseRMSError encodes an RMS error in metres to the
// codePhaseRMSError integer k = 8·y + x (3-bit exponent y in the MSBs,
// 3-bit mantissa x in the LSBs; RMS = 0.5·(1 + x/8)·2^y m — packing order
// confirmed against the tshark LPP dissector, lpp_tshark_test.go). Values
// below/above the representable range clamp to k=0 / k=63.
func EncodeCodePhaseRMSError(rmsM float64) uint8 {
	best := uint8(0)
	bestErr := math.Inf(1)
	for k := 0; k < 64; k++ {
		d := math.Abs(DecodeCodePhaseRMSError(uint8(k)) - rmsM)
		if d < bestErr {
			bestErr = d
			best = uint8(k)
		}
	}
	return best
}

// DecodeCodePhaseRMSError decodes the codePhaseRMSError integer k = 8·y + x
// to metres: RMS = 0.5·(1 + x/8)·2^y (k=20 ⇒ x=4, y=2 ⇒ exactly 3.0 m).
func DecodeCodePhaseRMSError(k uint8) float64 {
	x := float64(k & 0x07)
	y := float64((k >> 3) & 0x07)
	return 0.5 * (1 + x/8) * math.Pow(2, y)
}

// OffsetGeodetic displaces a WGS84 point by (northM, eastM) metres via the
// local ENU frame (the same enuUnitVectorToECEF math the ephemeris uses), so
// the LMF tests and the C++ UE mirror compute the identical synthetic true
// position from the quantized anchor.
func OffsetGeodetic(latDeg, lonDeg, northM, eastM float64) (float64, float64) {
	x, y, z := GeodeticToECEF(latDeg, lonDeg, 0)
	// East unit vector.
	ex, ey, ez := enuUnitVectorToECEF(latDeg, lonDeg, 0, 90)
	// North unit vector.
	nx, ny, nz := enuUnitVectorToECEF(latDeg, lonDeg, 0, 0)
	x += eastM*ex + northM*nx
	y += eastM*ey + northM*ny
	z += eastM*ez + northM*nz
	outLat, outLon, _ := ECEFToGeodetic(x, y, z)
	return outLat, outLon
}
