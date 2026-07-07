package lpp

// lpp_test.go — golden-hex + round-trip unit tests for the TS 37.355 A-GNSS
// UPER codec (LMF-009).
//
// Every golden hex string below was validated against the tshark 4.6.4 LPP
// dissector (zero malformed dissection, per-field spot checks) via the
// NGAP/NAS-5GS embedding oracle in lpp_tshark_test.go before being pinned
// here. This is the LMF-004 lesson: round-trip tests alone cannot catch an
// encoding rule that is wrong on both sides — pin the exact bytes AND check
// them against an independent decoder. The C++ UE patch
// (tools/ueransim/patches/0042-lpp-gnss.patch) byte-matches these dumps
// (tools/ueransim/CLAUDE.md §4 — Go is the source of truth).
//
// Ref: TS 37.355 §4/§5.2/§6; docs/procedures/LPPRelay.md §Validation approach.

import (
	"encoding/hex"
	"math"
	"testing"
)

// ---- Shared golden fixtures (also used by lpp_tshark_test.go) ------------------

// Golden transaction IDs: legs 1/2/3 use LMF-assigned numbers 1/2/3 with
// initiator=locationServer; UL messages echo the DL transaction (TS 37.355 §5.2).
var (
	goldenTxn1 = TransactionID{Initiator: InitiatorLocationServer, Number: 1}
	goldenTxn2 = TransactionID{Initiator: InitiatorLocationServer, Number: 2}
	goldenTxn3 = TransactionID{Initiator: InitiatorLocationServer, Number: 3}
)

// goldenUnixTime is the pinned build time for the assistance-data /
// measurement goldens: 2025-07-04T11:33:20Z. GPS conversion (leap = 18 s):
// gpsSeconds = 1435664018 → day 16616, timeOfDay 41618, and with 250 ms →
// gnss-TOD-msec 2018250.
const goldenUnixTime int64 = 1751628800

// Golden Madrid anchor (docs/procedures/LPPRelay.md leg-2 table):
// 40.4168 N → raw 3767118; −3.7038 E → raw −172610 (floor toward −∞).
const (
	goldenAnchorLat = 40.4168
	goldenAnchorLon = -3.7038
)

// goldenAssistanceData returns the pinned leg-2 payload.
func goldenAssistanceData() AssistanceData {
	sign, rawLat := EncodeLatitude(goldenAnchorLat)
	day, tod := UnixToGPSDayTime(goldenUnixTime)
	return AssistanceData{
		DayNumber:        day,
		TimeOfDay:        tod,
		ReferenceTimeUnc: ReferenceTimeUncDefault,
		ReferenceLocation: ReferenceLocation{
			LatitudeSign:         sign,
			DegreesLatitude:      rawLat,
			DegreesLongitude:     EncodeLongitude(goldenAnchorLon),
			AltitudeDirection:    0,
			Altitude:             0,
			UncertaintySemiMajor: 42, // ≈538 m — Cell-ID anchor band
			UncertaintySemiMinor: 42,
			OrientationMajorAxis: 0,
			UncertaintyAltitude:  127, // altitude not modelled
			Confidence:           68,  // 1-σ convention
		},
	}
}

// goldenPseudorangesM are the pinned leg-3 per-SV pseudoranges (metres).
var goldenPseudorangesM = []float64{22000000.0, 22345678.9, 21987654.3, 23456789.1}

// goldenMeasurements returns the pinned leg-3 payload: 4 SVs (satellite-id
// 0..3), cNo 44, mpathDet low, codePhaseRMSError 20.
func goldenMeasurements(t *testing.T) LocationMeasurements {
	t.Helper()
	var sats []SatMeas
	for i, m := range goldenPseudorangesM {
		icp, cp, err := PseudorangeToCodePhase(m)
		if err != nil {
			t.Fatalf("PseudorangeToCodePhase(%f): %v", m, err)
		}
		sats = append(sats, SatMeas{
			SVID:              uint8(i),
			CNo:               CNoDefault,
			MpathDet:          MpathDetLow,
			CodePhase:         cp,
			IntegerCodePhase:  icp,
			CodePhaseRMSError: CodePhaseRMSErrorDefault,
		})
	}
	return LocationMeasurements{GNSSTODMsec: GPSTODMsec(goldenUnixTime, 250), Sats: sats}
}

// Golden hex dumps — tshark-validated (see file header).
const (
	goldenHexRequestCapabilities     = "9002002100"
	goldenHexProvideCapabilitiesGPS  = "900308210000e40800"
	goldenHexProvideCapabilitiesNone = "90030800"
	goldenHexProvideAssistanceData   = "900518223100207428a4900e5ed39f576f8000152a00ff10"
	goldenHexRequestLocationInfo     = "9006206000878000"
	goldenHexProvideLocationInfo     = "9007282100f65e50000000640161625474950806c31306e94a1015855f269254203b09f289a728"
	goldenHexProvideLocationInfoErr  = "900728205040"
)

func mustDecode(t *testing.T, b []byte) *PDU {
	t.Helper()
	pdu, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v (bytes: %s)", err, hex.EncodeToString(b))
	}
	return pdu
}

func assertHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("%s hex = %s, want %s", name, hex.EncodeToString(got), want)
	}
}

func assertTxn(t *testing.T, pdu *PDU, want TransactionID) {
	t.Helper()
	if !pdu.HasTransactionID {
		t.Fatal("HasTransactionID = false, want true")
	}
	if pdu.TransactionID != want {
		t.Fatalf("TransactionID = %+v, want %+v", pdu.TransactionID, want)
	}
}

// ---- Golden-hex + round-trip tests ---------------------------------------------

func TestGoldenRequestCapabilities(t *testing.T) {
	b, err := BuildRequestCapabilities(goldenTxn1)
	if err != nil {
		t.Fatalf("BuildRequestCapabilities: %v", err)
	}
	assertHex(t, "BuildRequestCapabilities", b, goldenHexRequestCapabilities)

	pdu := mustDecode(t, b)
	if pdu.Type != MsgRequestCapabilities {
		t.Fatalf("Type = %d, want MsgRequestCapabilities", pdu.Type)
	}
	assertTxn(t, pdu, goldenTxn1)
	if pdu.EndTransaction {
		t.Fatal("EndTransaction = true, want false (request leg — TS 37.355 §5.2)")
	}
}

func TestGoldenProvideCapabilitiesSupported(t *testing.T) {
	b, err := BuildProvideCapabilities(goldenTxn1, true)
	if err != nil {
		t.Fatalf("BuildProvideCapabilities: %v", err)
	}
	assertHex(t, "BuildProvideCapabilities(gps)", b, goldenHexProvideCapabilitiesGPS)

	pdu := mustDecode(t, b)
	if pdu.Type != MsgProvideCapabilities {
		t.Fatalf("Type = %d, want MsgProvideCapabilities", pdu.Type)
	}
	assertTxn(t, pdu, goldenTxn1)
	if !pdu.EndTransaction {
		t.Fatal("EndTransaction = false, want true (closing response)")
	}
	caps := pdu.ProvideCapabilities
	if caps == nil || !caps.AGNSSSupported || !caps.GPSUEAssisted {
		t.Fatalf("ProvideCapabilities = %+v, want AGNSSSupported + GPSUEAssisted", caps)
	}
	if len(caps.SupportedGNSS) != 1 || caps.SupportedGNSS[0] != GNSSIDGPS {
		t.Fatalf("SupportedGNSS = %v, want [gps]", caps.SupportedGNSS)
	}
}

func TestGoldenProvideCapabilitiesNone(t *testing.T) {
	b, err := BuildProvideCapabilities(goldenTxn1, false)
	if err != nil {
		t.Fatalf("BuildProvideCapabilities: %v", err)
	}
	assertHex(t, "BuildProvideCapabilities(none)", b, goldenHexProvideCapabilitiesNone)

	pdu := mustDecode(t, b)
	if pdu.Type != MsgProvideCapabilities {
		t.Fatalf("Type = %d, want MsgProvideCapabilities", pdu.Type)
	}
	caps := pdu.ProvideCapabilities
	if caps == nil || caps.AGNSSSupported || caps.GPSUEAssisted {
		t.Fatalf("ProvideCapabilities = %+v, want GNSS=NONE (all false)", caps)
	}
}

func TestGoldenProvideAssistanceData(t *testing.T) {
	ad := goldenAssistanceData()

	// The doc-pinned raw coordinate values must hold exactly.
	if ad.ReferenceLocation.DegreesLatitude != 3767118 {
		t.Fatalf("EncodeLatitude(%v) raw = %d, want 3767118", goldenAnchorLat, ad.ReferenceLocation.DegreesLatitude)
	}
	if ad.ReferenceLocation.DegreesLongitude != -172610 {
		t.Fatalf("EncodeLongitude(%v) = %d, want -172610 (floor toward −∞, TS 23.032 §6)", goldenAnchorLon, ad.ReferenceLocation.DegreesLongitude)
	}
	if ad.DayNumber != 16616 || ad.TimeOfDay != 41618 {
		t.Fatalf("UnixToGPSDayTime(%d) = (%d, %d), want (16616, 41618)", goldenUnixTime, ad.DayNumber, ad.TimeOfDay)
	}

	b, err := BuildProvideAssistanceData(goldenTxn2, ad)
	if err != nil {
		t.Fatalf("BuildProvideAssistanceData: %v", err)
	}
	assertHex(t, "BuildProvideAssistanceData", b, goldenHexProvideAssistanceData)

	pdu := mustDecode(t, b)
	if pdu.Type != MsgProvideAssistanceData {
		t.Fatalf("Type = %d, want MsgProvideAssistanceData", pdu.Type)
	}
	assertTxn(t, pdu, goldenTxn2)
	if !pdu.EndTransaction {
		t.Fatal("EndTransaction = false, want true (single-message transaction — no UL reply)")
	}
	if pdu.AssistanceData == nil || *pdu.AssistanceData != ad {
		t.Fatalf("AssistanceData round-trip = %+v, want %+v", pdu.AssistanceData, ad)
	}
}

func TestGoldenRequestLocationInformation(t *testing.T) {
	b, err := BuildRequestLocationInformation(goldenTxn3)
	if err != nil {
		t.Fatalf("BuildRequestLocationInformation: %v", err)
	}
	assertHex(t, "BuildRequestLocationInformation", b, goldenHexRequestLocationInfo)

	pdu := mustDecode(t, b)
	if pdu.Type != MsgRequestLocationInformation {
		t.Fatalf("Type = %d, want MsgRequestLocationInformation", pdu.Type)
	}
	assertTxn(t, pdu, goldenTxn3)
	if pdu.EndTransaction {
		t.Fatal("EndTransaction = true, want false (request leg)")
	}
}

func TestGoldenProvideLocationInformation(t *testing.T) {
	meas := goldenMeasurements(t)
	if meas.GNSSTODMsec != 2018250 {
		t.Fatalf("GPSTODMsec = %d, want 2018250", meas.GNSSTODMsec)
	}
	// Pinned codePhase integers (byte-match reference for the C++ UE patch).
	wantCP := []struct {
		icp uint8
		cp  uint32
	}{{73, 805518}, {74, 1126510}, {73, 719156}, {78, 510502}}
	for i, w := range wantCP {
		if meas.Sats[i].IntegerCodePhase != w.icp || meas.Sats[i].CodePhase != w.cp {
			t.Fatalf("sat %d codePhase = (%d, %d), want (%d, %d)",
				i, meas.Sats[i].IntegerCodePhase, meas.Sats[i].CodePhase, w.icp, w.cp)
		}
	}

	b, err := BuildProvideLocationInformation(goldenTxn3, meas)
	if err != nil {
		t.Fatalf("BuildProvideLocationInformation: %v", err)
	}
	assertHex(t, "BuildProvideLocationInformation", b, goldenHexProvideLocationInfo)

	pdu := mustDecode(t, b)
	if pdu.Type != MsgProvideLocationInformation {
		t.Fatalf("Type = %d, want MsgProvideLocationInformation", pdu.Type)
	}
	assertTxn(t, pdu, goldenTxn3)
	if !pdu.EndTransaction {
		t.Fatal("EndTransaction = false, want true (closing response)")
	}
	if pdu.TargetDeviceErrorCause != nil {
		t.Fatalf("TargetDeviceErrorCause = %v, want nil", *pdu.TargetDeviceErrorCause)
	}
	got := pdu.LocationMeasurements
	if got == nil || got.GNSSTODMsec != meas.GNSSTODMsec || len(got.Sats) != len(meas.Sats) {
		t.Fatalf("LocationMeasurements = %+v, want %+v", got, meas)
	}
	for i := range meas.Sats {
		if got.Sats[i] != meas.Sats[i] {
			t.Fatalf("Sats[%d] = %+v, want %+v", i, got.Sats[i], meas.Sats[i])
		}
	}
}

func TestGoldenProvideLocationInformationError(t *testing.T) {
	b, err := BuildProvideLocationInformationError(goldenTxn3, GNSSErrorAssistanceDataMissing)
	if err != nil {
		t.Fatalf("BuildProvideLocationInformationError: %v", err)
	}
	assertHex(t, "BuildProvideLocationInformationError", b, goldenHexProvideLocationInfoErr)

	pdu := mustDecode(t, b)
	if pdu.Type != MsgProvideLocationInformation {
		t.Fatalf("Type = %d, want MsgProvideLocationInformation", pdu.Type)
	}
	if pdu.LocationMeasurements != nil {
		t.Fatal("LocationMeasurements non-nil on the error variant")
	}
	if pdu.TargetDeviceErrorCause == nil || *pdu.TargetDeviceErrorCause != GNSSErrorAssistanceDataMissing {
		t.Fatalf("TargetDeviceErrorCause = %v, want assistanceDataMissing", pdu.TargetDeviceErrorCause)
	}
}

// ---- Transaction semantics (TS 37.355 §5.2) -------------------------------------

func TestNextTransactionIDWrapsMod256(t *testing.T) {
	transactionCounter = 254
	if got := NextTransactionID(); got.Number != 255 || got.Initiator != InitiatorLocationServer {
		t.Fatalf("NextTransactionID = %+v, want {locationServer, 255}", got)
	}
	if got := NextTransactionID(); got.Number != 0 {
		t.Fatalf("NextTransactionID after 255 = %d, want 0 (mod 256 wrap — TransactionNumber INTEGER(0..255))", got.Number)
	}
	transactionCounter = 0
}

func TestBuildRejectsOutOfRangeValues(t *testing.T) {
	if _, err := BuildProvideLocationInformation(goldenTxn3, LocationMeasurements{}); err == nil {
		t.Fatal("BuildProvideLocationInformation with 0 satellites: want error")
	}
	if _, err := BuildProvideLocationInformation(goldenTxn3, LocationMeasurements{
		GNSSTODMsec: 4000000, Sats: []SatMeas{{}},
	}); err == nil {
		t.Fatal("BuildProvideLocationInformation with gnss-TOD-msec > 3599999: want error")
	}
	if _, err := BuildProvideLocationInformationError(goldenTxn3, 200); err == nil {
		t.Fatal("BuildProvideLocationInformationError with out-of-root cause: want error")
	}
	ad := goldenAssistanceData()
	ad.ReferenceLocation.Confidence = 101
	if _, err := BuildProvideAssistanceData(goldenTxn2, ad); err == nil {
		t.Fatal("BuildProvideAssistanceData with confidence > 100: want error")
	}
}

// ---- Converter tests --------------------------------------------------------------

func TestPseudorangeCodePhaseRoundTrip(t *testing.T) {
	// One codePhase LSB = 2⁻²¹ ms × 299792.458 m/ms ≈ 0.1430 m: round-trip
	// error must be < 0.15 m (half of one LSB rounding + margin).
	cases := append([]float64{0, 0.07, 299792.458, 22_000_000.123, 38_000_000}, goldenPseudorangesM...)
	for _, m := range cases {
		icp, cp, err := PseudorangeToCodePhase(m)
		if err != nil {
			t.Fatalf("PseudorangeToCodePhase(%f): %v", m, err)
		}
		back := CodePhaseToPseudorange(icp, cp)
		if math.Abs(back-m) > 0.15 {
			t.Errorf("round-trip %f m -> (%d, %d) -> %f m: error %.4f > 0.15 m", m, icp, cp, back, math.Abs(back-m))
		}
	}
}

func TestPseudorangeCodePhaseCarry(t *testing.T) {
	// A fraction that rounds up to 2^21 must carry into integerCodePhase.
	m := 74*MetersPerMsOfRange - 0.00001
	icp, cp, err := PseudorangeToCodePhase(m)
	if err != nil {
		t.Fatalf("PseudorangeToCodePhase: %v", err)
	}
	if icp != 74 || cp != 0 {
		t.Fatalf("carry case: got (%d, %d), want (74, 0)", icp, cp)
	}
}

func TestPseudorangeCodePhaseRejectsOutOfRange(t *testing.T) {
	if _, _, err := PseudorangeToCodePhase(128 * MetersPerMsOfRange); err == nil {
		t.Fatal("pseudorange > 127 ms: want error (integerCodePhase INTEGER(0..127))")
	}
	if _, _, err := PseudorangeToCodePhase(-1); err == nil {
		t.Fatal("negative pseudorange: want error")
	}
}

func TestUnixToGPSDayTime(t *testing.T) {
	// GPS epoch itself: day 0, tod = leap seconds.
	day, tod := UnixToGPSDayTime(GPSEpochUnix)
	if day != 0 || tod != uint32(GPSUTCLeapSeconds) {
		t.Fatalf("UnixToGPSDayTime(epoch) = (%d, %d), want (0, %d)", day, tod, GPSUTCLeapSeconds)
	}
	day, tod = UnixToGPSDayTime(goldenUnixTime)
	if day != 16616 || tod != 41618 {
		t.Fatalf("UnixToGPSDayTime(%d) = (%d, %d), want (16616, 41618)", goldenUnixTime, day, tod)
	}
}

func TestLatLonQuantization(t *testing.T) {
	// Doc-pinned Madrid values.
	sign, raw := EncodeLatitude(goldenAnchorLat)
	if sign != 0 || raw != 3767118 {
		t.Fatalf("EncodeLatitude(%v) = (%d, %d), want (0, 3767118)", goldenAnchorLat, sign, raw)
	}
	if got := EncodeLongitude(goldenAnchorLon); got != -172610 {
		t.Fatalf("EncodeLongitude(%v) = %d, want -172610 (floor, NOT truncation to -172609)", goldenAnchorLon, got)
	}
	// Southern hemisphere sign.
	sign, _ = EncodeLatitude(-33.8688)
	if sign != 1 {
		t.Fatalf("EncodeLatitude(south) sign = %d, want 1", sign)
	}
	// Quantization steps: ≈1.07e-5° lat, ≈2.15e-5° lon.
	for _, latDeg := range []float64{goldenAnchorLat, 0.00001, 89.999} {
		s, r := EncodeLatitude(latDeg)
		if got := DecodeLatitude(s, r); math.Abs(got-latDeg) > 90.0/(1<<23) {
			t.Errorf("lat quantization round-trip %v -> %v: error > 1 LSB", latDeg, got)
		}
	}
	for _, lonDeg := range []float64{goldenAnchorLon, 179.999, -179.999, 0.00001} {
		if got := DecodeLongitude(EncodeLongitude(lonDeg)); math.Abs(got-lonDeg) > 360.0/(1<<24) {
			t.Errorf("lon quantization round-trip %v -> %v: error > 1 LSB", lonDeg, got)
		}
	}
}

func TestCodePhaseRMSError(t *testing.T) {
	// k = 8·y + x with the exponent in the 3 MSBs: k=20 ⇒ x=4, y=2 ⇒ 3.0 m
	// exactly (packing order confirmed against the tshark LPP dissector).
	if got := DecodeCodePhaseRMSError(CodePhaseRMSErrorDefault); got != 3.0 {
		t.Fatalf("DecodeCodePhaseRMSError(20) = %v, want 3.0", got)
	}
	if got := EncodeCodePhaseRMSError(3.0); got != CodePhaseRMSErrorDefault {
		t.Fatalf("EncodeCodePhaseRMSError(3.0) = %d, want 20", got)
	}
	if got := DecodeCodePhaseRMSError(0); got != 0.5 {
		t.Fatalf("DecodeCodePhaseRMSError(0) = %v, want 0.5", got)
	}
	if got := DecodeCodePhaseRMSError(63); got != 0.5*(1+7.0/8)*128 {
		t.Fatalf("DecodeCodePhaseRMSError(63) = %v, want 120", got)
	}
}

// ---- Quantized-anchor rule --------------------------------------------------------

func TestQuantizedAnchorRule(t *testing.T) {
	// Encoding then decoding the anchor must yield the exact value used to
	// seed the ephemeris on both ends (identical geometry, no drift).
	sign, rawLat := EncodeLatitude(goldenAnchorLat)
	rawLon := EncodeLongitude(goldenAnchorLon)
	qLat := DecodeLatitude(sign, rawLat)
	qLon := DecodeLongitude(rawLon)

	// Round-tripping the wire encoding of the quantized value is lossless.
	sign2, rawLat2 := EncodeLatitude(qLat)
	if sign2 != sign || rawLat2 != rawLat {
		t.Fatalf("quantized lat re-encode = (%d, %d), want (%d, %d)", sign2, rawLat2, sign, rawLat)
	}
	if rawLon2 := EncodeLongitude(qLon); rawLon2 != rawLon {
		t.Fatalf("quantized lon re-encode = %d, want %d", rawLon2, rawLon)
	}

	// Both ends generate byte-identical ephemeris from the quantized anchor.
	a := GenerateSyntheticEphemeris(qLat, qLon)
	b := GenerateSyntheticEphemeris(qLat, qLon)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("ephemeris[%d] differs: %+v vs %+v", i, a[i], b[i])
		}
	}
}

// ---- Decode robustness --------------------------------------------------------------

func TestDecodeMalformedBytes(t *testing.T) {
	for _, b := range [][]byte{nil, {}, {0xFF}, {0x90}, {0x90, 0x02, 0x00}} {
		if _, err := Decode(b); err == nil {
			t.Fatalf("Decode(%x): want error", b)
		}
	}
}

// TestDecodeSkipsSequenceExtensions proves the decoder tolerates a future
// peer setting the extension bit on an extensible SEQUENCE: a hand-crafted
// ProvideCapabilities-r9-IEs with the extension bit set and one extension
// addition present (open-type skipped) must still decode as GNSS=NONE.
func TestDecodeSkipsSequenceExtensions(t *testing.T) {
	w := &bitWriter{}
	writeEnvelope(w, goldenTxn1, true, c1ProvideCapabilities)
	w.writeBit(1)           // r9-IEs extension bit SET
	w.writeBits(0b00000, 5) // all root OPTIONALs absent (GNSS=NONE)
	// Extension additions block: normally-small length (count−1 = 0),
	// one presence bit (present), open type of 2 octets.
	w.writeBit(0)
	w.writeBits(0, 6)
	w.writeBit(1)
	w.writeBits(2, 8) // general length = 2
	w.writeBits(0xABCD, 16)

	pdu, err := Decode(w.bytes())
	if err != nil {
		t.Fatalf("Decode with extension additions: %v", err)
	}
	if pdu.Type != MsgProvideCapabilities || pdu.ProvideCapabilities == nil {
		t.Fatalf("Type = %d, want MsgProvideCapabilities", pdu.Type)
	}
	if pdu.ProvideCapabilities.AGNSSSupported {
		t.Fatal("AGNSSSupported = true, want false")
	}
}

// TestDecodeRejectsOutOfSubsetRootOptionals proves that a root OPTIONAL
// outside the A-GNSS subset (not skippable in PER — no per-field length)
// is a decode error, which the LMF maps to a graceful fallback.
func TestDecodeRejectsOutOfSubsetRootOptionals(t *testing.T) {
	w := &bitWriter{}
	writeEnvelope(w, goldenTxn1, true, c1ProvideCapabilities)
	w.writeBit(0)
	w.writeBits(0b00100, 5) // otdoa-ProvideCapabilities present (outside subset)
	if _, err := Decode(w.bytes()); err == nil {
		t.Fatal("Decode with otdoa root OPTIONAL present: want error")
	}
}
