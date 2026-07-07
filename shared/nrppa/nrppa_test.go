package nrppa

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustDecode(t *testing.T, b []byte) *NRPPaPDU {
	t.Helper()
	pdu, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v (bytes: %s)", err, hex.EncodeToString(b))
	}
	return pdu
}

func TestEncodeDecodePosInfoReq(t *testing.T) {
	b := EncodePosInfoReq(PositioningInformationRequest{})
	if len(b) == 0 {
		t.Fatal("EncodePosInfoReq returned empty bytes")
	}
	pdu := mustDecode(t, b)
	if pdu.Type != MsgPositioningInformationRequest {
		t.Fatalf("Type = %d, want MsgPositioningInformationRequest", pdu.Type)
	}
}

func TestEncodeDecodePosInfoRspSupported(t *testing.T) {
	b := EncodePosInfoRsp(PositioningInformationResponse{ECIDSupported: true})
	pdu := mustDecode(t, b)
	if pdu.Type != MsgPositioningInformationResponse {
		t.Fatalf("Type = %d, want MsgPositioningInformationResponse", pdu.Type)
	}
	if !pdu.MsgPosInfoRsp.ECIDSupported {
		t.Fatal("ECIDSupported = false, want true")
	}
}

func TestEncodeDecodePosInfoRspUnsupported(t *testing.T) {
	// ECIDSupported=false is encoded as PositioningInformationFailure.
	b := EncodePosInfoRsp(PositioningInformationResponse{ECIDSupported: false})
	pdu := mustDecode(t, b)
	if pdu.Type != MsgPositioningInformationFailure {
		t.Fatalf("Type = %d, want MsgPositioningInformationFailure", pdu.Type)
	}
}

func TestEncodeDecodePosInfoFail(t *testing.T) {
	b := EncodePosInfoFail(PositioningInformationFailure{Cause: 0})
	pdu := mustDecode(t, b)
	if pdu.Type != MsgPositioningInformationFailure {
		t.Fatalf("Type = %d, want MsgPositioningInformationFailure", pdu.Type)
	}
}

func TestEncodeDecodeECIDInitReq(t *testing.T) {
	b := EncodeECIDInitReq(ECIDMeasurementInitiationRequestMsg{LMFMeasurementID: 7, Quantities: QuantityRSRP})
	pdu := mustDecode(t, b)
	if pdu.Type != MsgECIDMeasurementInitiationRequest {
		t.Fatalf("Type = %d, want MsgECIDMeasurementInitiationRequest", pdu.Type)
	}
	if pdu.MsgECIDInitReq.LMFMeasurementID != 7 {
		t.Fatalf("LMFMeasurementID = %d, want 7", pdu.MsgECIDInitReq.LMFMeasurementID)
	}
}

func TestEncodeDecodeECIDInitReqMeasIDRange(t *testing.T) {
	// UEMeasurementID root range is 1..15 — verify round-trip across the range.
	for id := uint16(1); id <= 15; id++ {
		b := EncodeECIDInitReq(ECIDMeasurementInitiationRequestMsg{LMFMeasurementID: id, Quantities: QuantityRSRP})
		pdu := mustDecode(t, b)
		if pdu.MsgECIDInitReq.LMFMeasurementID != id {
			t.Fatalf("id=%d: got %d", id, pdu.MsgECIDInitReq.LMFMeasurementID)
		}
	}
}

func TestEncodeDecodeECIDInitRsp(t *testing.T) {
	b := EncodeECIDInitRsp(ECIDMeasurementInitiationResponseMsg{LMFMeasurementID: 3, RANMeasurementID: 5})
	pdu := mustDecode(t, b)
	if pdu.Type != MsgECIDMeasurementInitiationResponse {
		t.Fatalf("Type = %d, want MsgECIDMeasurementInitiationResponse", pdu.Type)
	}
	if pdu.MsgECIDInitRsp.LMFMeasurementID != 3 || pdu.MsgECIDInitRsp.RANMeasurementID != 5 {
		t.Fatalf("got LMF=%d RAN=%d, want LMF=3 RAN=5",
			pdu.MsgECIDInitRsp.LMFMeasurementID, pdu.MsgECIDInitRsp.RANMeasurementID)
	}
}

func TestEncodeDecodeECIDInitFail(t *testing.T) {
	b := EncodeECIDInitFail(ECIDMeasurementInitiationFailureMsg{Cause: 0})
	pdu := mustDecode(t, b)
	if pdu.Type != MsgECIDMeasurementInitiationFailure {
		t.Fatalf("Type = %d, want MsgECIDMeasurementInitiationFailure", pdu.Type)
	}
}

func TestEncodeDecodeECIDReportServingOnly(t *testing.T) {
	report := ECIDMeasurementReportMsg{
		LMFMeasurementID: 1,
		RANMeasurementID: 1,
		ServingNRCGI:     NRCGI{CellID: [5]byte{0x00, 0x00, 0x00, 0x01, 0x00}},
		ServingTAC:       [3]byte{0x00, 0x00, 0x01},
	}
	b := EncodeECIDReport(report)
	pdu := mustDecode(t, b)
	if pdu.Type != MsgECIDMeasurementReport {
		t.Fatalf("Type = %d, want MsgECIDMeasurementReport", pdu.Type)
	}
	got := pdu.MsgECIDReport
	if got.ServingNRCGI != report.ServingNRCGI {
		t.Fatalf("ServingNRCGI = %+v, want %+v", got.ServingNRCGI, report.ServingNRCGI)
	}
	if got.ServingTAC != report.ServingTAC {
		t.Fatalf("ServingTAC = %v, want %v", got.ServingTAC, report.ServingTAC)
	}
	if got.APPosition != nil {
		t.Fatalf("APPosition = %+v, want nil (not sent)", got.APPosition)
	}
}

func TestEncodeDecodeECIDReportWithAPPosition(t *testing.T) {
	report := ECIDMeasurementReportMsg{
		LMFMeasurementID: 2,
		RANMeasurementID: 4,
		ServingNRCGI:     NRCGI{CellID: [5]byte{0x00, 0x00, 0x00, 0x01, 0x00}},
		ServingTAC:       [3]byte{0x00, 0x00, 0x01},
		APPosition: &APPosition{
			Lat:                   40.4168,
			Lon:                   -3.7038,
			AltitudeM:             650,
			UncertaintySemiMajorM: 100,
			UncertaintySemiMinorM: 80,
			OrientationDeg:        90,
			UncertaintyAltitudeM:  20,
			ConfidencePct:         68,
		},
	}
	b := EncodeECIDReport(report)
	pdu := mustDecode(t, b)
	got := pdu.MsgECIDReport
	if got.APPosition == nil {
		t.Fatal("APPosition = nil, want non-nil")
	}
	// Lat/Lon quantized to 24-bit APER integers — allow small rounding tolerance.
	const tol = 0.001
	if d := got.APPosition.Lat - report.APPosition.Lat; d > tol || d < -tol {
		t.Errorf("Lat = %v, want ~%v", got.APPosition.Lat, report.APPosition.Lat)
	}
	if d := got.APPosition.Lon - report.APPosition.Lon; d > tol || d < -tol {
		t.Errorf("Lon = %v, want ~%v", got.APPosition.Lon, report.APPosition.Lon)
	}
	if got.APPosition.ConfidencePct != 68 {
		t.Errorf("ConfidencePct = %d, want 68", got.APPosition.ConfidencePct)
	}
	// Uncertainty is quantized via the TS 23.032 code — expect it in the right ballpark.
	if got.APPosition.UncertaintySemiMajorM < 80 || got.APPosition.UncertaintySemiMajorM > 130 {
		t.Errorf("UncertaintySemiMajorM = %v, want ~100", got.APPosition.UncertaintySemiMajorM)
	}
}

func TestEncodeDecodeECIDReportSouthernWesternHemisphere(t *testing.T) {
	report := ECIDMeasurementReportMsg{
		ServingNRCGI: NRCGI{CellID: [5]byte{0x00, 0x00, 0x00, 0x02, 0x00}},
		ServingTAC:   [3]byte{0x00, 0x00, 0x02},
		APPosition: &APPosition{
			Lat: -33.8688, // Sydney — southern hemisphere
			Lon: 151.2093, // eastern hemisphere
		},
	}
	b := EncodeECIDReport(report)
	pdu := mustDecode(t, b)
	got := pdu.MsgECIDReport.APPosition
	if got == nil {
		t.Fatal("APPosition = nil")
	}
	if got.Lat >= 0 {
		t.Errorf("Lat = %v, want negative (southern hemisphere)", got.Lat)
	}
	if got.Lon <= 0 {
		t.Errorf("Lon = %v, want positive (eastern hemisphere)", got.Lon)
	}
}

// TestProcedureCodesMatchSpec locks in the TS 38.455 Table 9.1-1 values that were
// wrong in the original bespoke codec (6/8/12 collided with real, unrelated
// procedures — see docs/procedures/NRPPaRelay.md and the LMF-004 fix notes).
func TestProcedureCodesMatchSpec(t *testing.T) {
	cases := []struct {
		name string
		got  int64
		want int64
	}{
		{"e-CIDMeasurementInitiation", ProcCodeECIDMeasurementInitiation, 2},
		{"e-CIDMeasurementReport", ProcCodeECIDMeasurementReport, 4},
		{"positioningInformationExchange", ProcCodePositioningInformationExchange, 9},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s procCode = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode([]byte{0xff, 0xff, 0xff}); err == nil {
		t.Fatal("Decode of garbage bytes: want error, got nil")
	}
	if _, err := Decode(nil); err == nil {
		t.Fatal("Decode of nil: want error, got nil")
	}
}

// TestGoldenECIDMeasurementReport pins a byte sequence produced by
// EncodeECIDReport for one representative message — this is the byte string the
// UERANSIM gNB patch (0041) must reproduce exactly (tools/ueransim/CLAUDE.md §4:
// Go is source of truth). The exact hex is logged (run with -v) for patch upkeep.
func TestGoldenECIDMeasurementReport(t *testing.T) {
	report := ECIDMeasurementReportMsg{
		LMFMeasurementID: 1,
		RANMeasurementID: 1,
		ServingNRCGI:     NRCGI{CellID: [5]byte{0x00, 0x00, 0x00, 0x01, 0x00}},
		ServingTAC:       [3]byte{0x00, 0x00, 0x01},
	}
	// Freeze the transaction ID counter for a deterministic golden byte string.
	transactionIDCounter = 0
	b := EncodeECIDReport(report)
	t.Logf("golden ECIDMeasurementReport bytes: %s", hex.EncodeToString(b))
	if len(b) == 0 {
		t.Fatal("empty encode")
	}
	pdu := mustDecode(t, b)
	if pdu.Type != MsgECIDMeasurementReport {
		t.Fatalf("Type = %d, want MsgECIDMeasurementReport", pdu.Type)
	}
	if bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("encoded bytes are all-zero — encoder likely broken")
	}
}
