package server

// lpp_test.go — unit tests for GNSS positioning via LPP relay (LMF-005,
// rewired for the LMF-009 spec-faithful UPER codec and three-leg flow).
//
// Covers: selectMethod truth table (including the GNSS/LPP band), the LPP
// per-SUPI state machine transitions across the three legs, GNSS success
// (WLS over decoded codePhase pseudoranges seeded by the quantized anchor),
// GNSS=NONE -> E-CID fallback, leg-2/-3 failure fallbacks, gnss-Error
// fallback, and the warn-only echoed-transaction verification. Also proves
// the E-CID and Cell-ID paths (LMF-004/LMF-001) are unchanged for their
// existing bands.
//
// Ref: TS 37.355 §5.2/§6; TS 23.273 §6.2.10; docs/procedures/LPPRelay.md.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/lpp"
	"github.com/francurieses/claudia-5gc/shared/nrppa"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// ---- selectMethod truth table (extended for LMF-005) -------------------------

// TestSelectMethod_TruthTable proves the method-selection bands: GNSS/LPP for
// hAccuracy < 50, E-CID for 50-200 (inclusive), Cell-ID for > 200 or absent.
// The E-CID and Cell-ID bands must be byte-for-byte unchanged from LMF-004.
func TestSelectMethod_TruthTable(t *testing.T) {
	cases := []struct {
		hAccuracy float64
		want      positioningMethod
	}{
		{hAccuracy: 0, want: methodCellID},
		{hAccuracy: -5, want: methodCellID},
		{hAccuracy: 300, want: methodCellID},
		{hAccuracy: 200.1, want: methodCellID},
		{hAccuracy: 200, want: methodECID}, // upper E-CID boundary, inclusive
		{hAccuracy: 100, want: methodECID},
		{hAccuracy: 50, want: methodECID},  // lower E-CID boundary, inclusive
		{hAccuracy: 49.9, want: methodLPP}, // just under the GNSS/LPP ceiling
		{hAccuracy: 40, want: methodLPP},   // feature-file AC value
		{hAccuracy: 30, want: methodLPP},   // feature-file AC value
		{hAccuracy: 0.1, want: methodLPP},
	}
	for _, tc := range cases {
		got := selectMethod(tc.hAccuracy)
		if got != tc.want {
			t.Errorf("selectMethod(%v) = %v, want %v", tc.hAccuracy, got, tc.want)
		}
	}
}

// TestPositioningMethod_String verifies the log-friendly String() values,
// including the GNSS method, without altering the existing CELL_ID/ECID
// strings.
func TestPositioningMethod_String(t *testing.T) {
	cases := map[positioningMethod]string{
		methodCellID: "CELL_ID",
		methodECID:   "ECID",
		methodLPP:    "GNSS",
	}
	for method, want := range cases {
		if got := method.String(); got != want {
			t.Errorf("%v.String() = %q, want %q", method, got, want)
		}
	}
}

// ---- fake LPP client (test double for LPPSender) ------------------------------

// fakeLPPClient decodes the DL LPP-PDU it receives and replies per leg,
// mirroring the UERANSIM 0042 patch's spec-encoded UPER replies:
//
//	Leg 1 RequestCapabilities         -> ProvideCapabilities (echo txn)
//	Leg 2 ProvideAssistanceData       -> stores the wire-quantized anchor;
//	                                     no UL reply (expectUlResponse=false)
//	Leg 3 RequestLocationInformation  -> ProvideLocationInformation with
//	                                     codePhase pseudoranges computed from
//	                                     the stored quantized anchor's
//	                                     ephemeris + the configured true
//	                                     position + clock bias
type fakeLPPClient struct {
	// gnssSupported controls the ProvideCapabilities reply.
	gnssSupported bool
	// capsErr, if set, is returned directly from leg 1 (relay/timeout failure).
	capsErr error
	// assistErr, if set, is returned from leg 2 (DL-only send failure).
	assistErr error
	// measurementErr, if set, is returned from leg 3.
	measurementErr error
	// gnssError, if set, makes leg 3 reply with gnss-Error{cause} instead of
	// measurements.
	gnssError *uint8
	// tooFewSatellites, if true, reports only 2 measurements (< WLSMinSatellites).
	tooFewSatellites bool
	// echoWrongTxn, if true, echoes a mismatching transactionID on UL replies
	// (exercises the warn-only lpp_txn_mismatch path).
	echoWrongTxn bool
	// trueLat/trueLon is the ground-truth UE position used to simulate
	// pseudorange measurements from the quantized-anchor ephemeris.
	trueLat, trueLon float64
	// clockBiasM is the receiver clock bias added to every pseudorange.
	clockBiasM float64

	mu         sync.Mutex
	calls      int
	dlPDUs     [][]byte
	anchorLat  float64
	anchorLon  float64
	haveAnchor bool
}

func (f *fakeLPPClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeLPPClient) echoTxn(txn lpp.TransactionID) lpp.TransactionID {
	if f.echoWrongTxn {
		return lpp.TransactionID{Initiator: lpp.InitiatorTargetDevice, Number: txn.Number + 1}
	}
	return txn
}

func (f *fakeLPPClient) SendDLLPP(_ context.Context, _ string, lppPDU []byte, expectUlResponse bool) ([]byte, string, error) {
	f.mu.Lock()
	f.calls++
	f.dlPDUs = append(f.dlPDUs, lppPDU)
	f.mu.Unlock()

	pdu, err := lpp.Decode(lppPDU)
	if err != nil {
		return nil, "", fmt.Errorf("fakeLPPClient: decode DL PDU: %w", err)
	}

	switch pdu.Type {
	case lpp.MsgRequestCapabilities:
		if !expectUlResponse {
			return nil, "", fmt.Errorf("fakeLPPClient: RequestCapabilities must use expectUlResponse=true")
		}
		if f.capsErr != nil {
			return nil, "UE_NOT_REACHABLE", f.capsErr
		}
		rsp, err := lpp.BuildProvideCapabilities(f.echoTxn(pdu.TransactionID), f.gnssSupported)
		return rsp, "", err

	case lpp.MsgProvideAssistanceData:
		if expectUlResponse {
			return nil, "", fmt.Errorf("fakeLPPClient: ProvideAssistanceData is DL-only (expectUlResponse must be false)")
		}
		if f.assistErr != nil {
			return nil, "UE_NOT_REACHABLE", f.assistErr
		}
		// Store the wire-quantized anchor — mirror of the UE patch behaviour.
		loc := pdu.AssistanceData.ReferenceLocation
		f.mu.Lock()
		f.anchorLat = lpp.DecodeLatitude(loc.LatitudeSign, loc.DegreesLatitude)
		f.anchorLon = lpp.DecodeLongitude(loc.DegreesLongitude)
		f.haveAnchor = true
		f.mu.Unlock()
		return nil, "", nil // AMF 204 No Content

	case lpp.MsgRequestLocationInformation:
		if !expectUlResponse {
			return nil, "", fmt.Errorf("fakeLPPClient: RequestLocationInformation must use expectUlResponse=true")
		}
		if f.measurementErr != nil {
			return nil, "UE_NOT_REACHABLE", f.measurementErr
		}
		if f.gnssError != nil {
			rsp, err := lpp.BuildProvideLocationInformationError(f.echoTxn(pdu.TransactionID), *f.gnssError)
			return rsp, "", err
		}
		f.mu.Lock()
		haveAnchor, aLat, aLon := f.haveAnchor, f.anchorLat, f.anchorLon
		f.mu.Unlock()
		if !haveAnchor {
			rsp, err := lpp.BuildProvideLocationInformationError(f.echoTxn(pdu.TransactionID), lpp.GNSSErrorAssistanceDataMissing)
			return rsp, "", err
		}
		eph := lpp.GenerateSyntheticEphemeris(aLat, aLon)
		meas := lpp.SimulateMeasurements(eph, f.trueLat, f.trueLon, 0, f.clockBiasM)
		var sats []lpp.SatMeas
		for _, m := range meas {
			icp, cp, err := lpp.PseudorangeToCodePhase(m.PseudorangeMeters)
			if err != nil {
				return nil, "", fmt.Errorf("fakeLPPClient: codePhase: %w", err)
			}
			sats = append(sats, lpp.SatMeas{
				SVID:              m.SVID - 1, // constellation index i rides as satellite-id = i − 1
				CNo:               lpp.CNoDefault,
				MpathDet:          lpp.MpathDetLow,
				CodePhase:         cp,
				IntegerCodePhase:  icp,
				CodePhaseRMSError: lpp.CodePhaseRMSErrorDefault,
			})
		}
		if f.tooFewSatellites {
			sats = sats[:2]
		}
		rsp, err := lpp.BuildProvideLocationInformation(f.echoTxn(pdu.TransactionID),
			lpp.LocationMeasurements{GNSSTODMsec: 123456, Sats: sats})
		return rsp, "", err

	default:
		return nil, "", fmt.Errorf("fakeLPPClient: unexpected LPP message type %d", pdu.Type)
	}
}

// ---- fake NRPPa sender (test double for DLNRPPASender, E-CID fallback) -------

// fakeNRPPaSenderForLPP answers the two-round NRPPa E-CID exchange
// (performECIDOrFallback's dependency) so GNSS-fallback tests can assert a
// successful E-CID downgrade rather than falling all the way to Cell-ID.
type fakeNRPPaSenderForLPP struct {
	ecidSupported bool
}

func (f *fakeNRPPaSenderForLPP) SendDLNRPPa(_ context.Context, _ string, pdu []byte) ([]byte, string, error) {
	decoded, err := nrppa.Decode(pdu)
	if err != nil {
		return nil, "", err
	}
	switch decoded.Type {
	case nrppa.MsgPositioningInformationRequest:
		return nrppa.EncodePosInfoRsp(nrppa.PositioningInformationResponse{ECIDSupported: f.ecidSupported}), "", nil
	case nrppa.MsgECIDMeasurementInitiationRequest:
		report := nrppa.EncodeECIDReport(nrppa.ECIDMeasurementReportMsg{
			LMFMeasurementID: 1,
			RANMeasurementID: 1,
			ServingNRCGI:     nrppa.NRCGI{CellID: [5]byte{0x00, 0x00, 0x00, 0x01, 0x00}}, // "000000010"
			ServingTAC:       [3]byte{0x00, 0x00, 0x01},
			APPosition: &nrppa.APPosition{
				Lat: 40.416775, Lon: -3.703790,
				UncertaintySemiMajorM: 90, UncertaintySemiMinorM: 90,
			},
		})
		return report, "", nil
	default:
		return nil, "", fmt.Errorf("fakeNRPPaSenderForLPP: unexpected msg type %d", decoded.Type)
	}
}

// ---- test server builder -------------------------------------------------------

// newLPPTestServerWithLogger builds an LMF server with the fake AMF client
// (Cell-ID fallback data), the DefaultCoord anchor, no privacy check, and the
// given slog sink.
func newLPPTestServerWithLogger(t *testing.T, sink io.Writer) *Server {
	t.Helper()
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.DefaultCoord = config.CellCoord{Lat: 40.416775, Lon: -3.703790}
	cfg.CellCoordinates = map[string]config.CellCoord{
		"000000010": {Lat: 40.416775, Lon: -3.703790},
	}
	logger := slog.New(slog.NewTextHandler(sink, nil))
	amfClient := &mockAMFClient{
		ProvideFunc: func(_ context.Context, ueContextID string) (*LocationData, string, error) {
			return &LocationData{
				NRCellId: "000000010",
				Tai:      &TaiLoc{PlmnId: PlmnID{MCC: "001", MNC: "01"}, Tac: "000001"},
			}, "", nil
		},
	}
	return New(cfg, logger, amfClient, nil)
}

func newLPPTestServer(t *testing.T) *Server {
	t.Helper()
	return newLPPTestServerWithLogger(t, io.Discard)
}

// newGNSSSuccessClient returns a fake UE near the anchor with the pinned
// synthetic offsets (+25 m N / +15 m E, +150 m clock bias — LPPRelay.md).
func newGNSSSuccessClient() *fakeLPPClient {
	trueLat, trueLon := lpp.OffsetGeodetic(40.416775, -3.703790, lpp.UEOffsetNorthM, lpp.UEOffsetEastM)
	return &fakeLPPClient{
		gnssSupported: true,
		trueLat:       trueLat,
		trueLon:       trueLon,
		clockBiasM:    lpp.UEClockBiasM,
	}
}

// ---- performLPPOrFallback tests -------------------------------------------------

// TestPerformLPPOrFallback_GNSSSuccess verifies the happy path: three legs
// (capability, DL-only assistance, measurement), 4 codePhase-encoded
// satellite pseudoranges from the pinned synthetic true position, WLS solve
// around the quantized anchor, method=gnss, uncertainty<=50.
func TestPerformLPPOrFallback_GNSSSuccess(t *testing.T) {
	s := newLPPTestServer(t)
	lppClient := newGNSSSuccessClient()
	s.SetLPPClient(lppClient)

	before := testutil.ToFloat64(metrics.LMFGNSSTotal.WithLabelValues("OK"))

	loc, cause, err := s.performLPPOrFallback(context.Background(), "imsi-001010000000001", "imsi-001010000000001")
	if err != nil {
		t.Fatalf("performLPPOrFallback: err=%v cause=%s", err, cause)
	}
	if loc.LocationEstimate == nil || loc.LocationEstimate.Shape != "POINT" {
		t.Fatalf("LocationEstimate = %+v, want shape=POINT", loc.LocationEstimate)
	}
	if len(loc.PositioningDataList) != 1 || loc.PositioningDataList[0] != "gnss" {
		t.Fatalf("PositioningDataList = %v, want [gnss]", loc.PositioningDataList)
	}
	if loc.LocationEstimate.Uncertainty <= 0 || loc.LocationEstimate.Uncertainty > 50 {
		t.Fatalf("Uncertainty = %v, want (0, 50]", loc.LocationEstimate.Uncertainty)
	}
	if got := lppClient.callCount(); got != 3 {
		t.Fatalf("SendDLLPP called %d times, want 3 (capability + assistance + measurement)", got)
	}

	after := testutil.ToFloat64(metrics.LMFGNSSTotal.WithLabelValues("OK"))
	if after != before+1 {
		t.Errorf("fivegc_lmf_gnss_total{result=OK} = %v, want %v", after, before+1)
	}

	// State must be cleaned up after completion (no leaked entry).
	if state := s.lppState.get("imsi-001010000000001"); state != lppStateIdle {
		t.Errorf("lppState after completion = %s, want %s (deleted -> default IDLE)", state, lppStateIdle)
	}
}

// TestPerformLPPOrFallback_GNSSNoneFallsBackToECID verifies that a UE
// reporting GNSS=NONE triggers a transparent downgrade to E-CID (not
// Cell-ID directly), and that no assistance/measurement leg is attempted.
func TestPerformLPPOrFallback_GNSSNoneFallsBackToECID(t *testing.T) {
	s := newLPPTestServer(t)
	lppClient := &fakeLPPClient{gnssSupported: false}
	s.SetLPPClient(lppClient)
	s.SetNRPPAClient(&fakeNRPPaSenderForLPP{ecidSupported: true})

	before := testutil.ToFloat64(metrics.LMFGNSSTotal.WithLabelValues("FALLBACK_ECID"))

	loc, _, err := s.performLPPOrFallback(context.Background(), "imsi-001010000000002", "imsi-001010000000002")
	if err != nil {
		t.Fatalf("performLPPOrFallback: %v", err)
	}
	if len(loc.PositioningDataList) != 1 || loc.PositioningDataList[0] != "eCID" {
		t.Fatalf("PositioningDataList = %v, want [eCID]", loc.PositioningDataList)
	}
	if got := lppClient.callCount(); got != 1 {
		t.Fatalf("SendDLLPP called %d times, want 1 (capability leg only — no legs 2/3 after GNSS=NONE)", got)
	}

	after := testutil.ToFloat64(metrics.LMFGNSSTotal.WithLabelValues("FALLBACK_ECID"))
	if after != before+1 {
		t.Errorf("fivegc_lmf_gnss_total{result=FALLBACK_ECID} = %v, want %v", after, before+1)
	}
}

// TestPerformLPPOrFallback_CapabilityTimeoutFallsBackToECID verifies that a
// capability-leg relay failure (guard-timer/UE_NOT_REACHABLE) downgrades to
// E-CID, mirroring the GNSS=NONE case.
func TestPerformLPPOrFallback_CapabilityTimeoutFallsBackToECID(t *testing.T) {
	s := newLPPTestServer(t)
	lppClient := &fakeLPPClient{capsErr: fmt.Errorf("dl-lpp-info guard timer")}
	s.SetLPPClient(lppClient)
	s.SetNRPPAClient(&fakeNRPPaSenderForLPP{ecidSupported: true})

	loc, _, err := s.performLPPOrFallback(context.Background(), "imsi-001010000000005", "imsi-001010000000005")
	if err != nil {
		t.Fatalf("performLPPOrFallback: %v", err)
	}
	if len(loc.PositioningDataList) != 1 || loc.PositioningDataList[0] != "eCID" {
		t.Fatalf("PositioningDataList = %v, want [eCID]", loc.PositioningDataList)
	}
}

// TestPerformLPPOrFallback_AssistanceSendFailureFallsBackToECID verifies the
// leg-2 error row of the state table: a non-2xx on the DL-only
// ProvideAssistanceData POST means the assistance is undeliverable → fallback
// (docs/procedures/LPPRelay.md §Error table).
func TestPerformLPPOrFallback_AssistanceSendFailureFallsBackToECID(t *testing.T) {
	s := newLPPTestServer(t)
	lppClient := &fakeLPPClient{gnssSupported: true, assistErr: fmt.Errorf("dl-lpp-info 504")}
	s.SetLPPClient(lppClient)
	s.SetNRPPAClient(&fakeNRPPaSenderForLPP{ecidSupported: true})

	loc, _, err := s.performLPPOrFallback(context.Background(), "imsi-001010000000003", "imsi-001010000000003")
	if err != nil {
		t.Fatalf("performLPPOrFallback: %v", err)
	}
	if len(loc.PositioningDataList) != 1 || loc.PositioningDataList[0] != "eCID" {
		t.Fatalf("PositioningDataList = %v, want [eCID]", loc.PositioningDataList)
	}
	if got := lppClient.callCount(); got != 2 {
		t.Fatalf("SendDLLPP called %d times, want 2 (no leg 3 after a failed leg 2)", got)
	}
}

// TestPerformLPPOrFallback_MeasurementTimeoutFallsBackAllTheWayToCellID
// mirrors feature scenario 4: leg 3 fails (never receives a UL
// ProvideLocationInformation), and the E-CID leg is also unavailable
// (gNB capability NONE), so the chain bottoms out at Cell-ID — still 200,
// never an error.
func TestPerformLPPOrFallback_MeasurementTimeoutFallsBackAllTheWayToCellID(t *testing.T) {
	s := newLPPTestServer(t)
	lppClient := &fakeLPPClient{
		gnssSupported:  true,
		measurementErr: fmt.Errorf("dl-lpp-info guard timer"),
	}
	s.SetLPPClient(lppClient)
	s.SetNRPPAClient(&fakeNRPPaSenderForLPP{ecidSupported: false}) // E-CID also unavailable

	before := testutil.ToFloat64(metrics.LMFGNSSTotal.WithLabelValues("FALLBACK_CELLID"))

	loc, _, err := s.performLPPOrFallback(context.Background(), "imsi-001010000000004", "imsi-001010000000004")
	if err != nil {
		t.Fatalf("performLPPOrFallback: %v", err)
	}
	for _, m := range loc.PositioningDataList {
		if m == "gnss" || m == "eCID" {
			t.Fatalf("PositioningDataList = %v, want neither gnss nor eCID (Cell-ID fallback)", loc.PositioningDataList)
		}
	}
	if loc.NRCellId != "000000010" {
		t.Errorf("NRCellId = %q, want 000000010 (from AMF Cell-ID fallback)", loc.NRCellId)
	}

	after := testutil.ToFloat64(metrics.LMFGNSSTotal.WithLabelValues("FALLBACK_CELLID"))
	if after != before+1 {
		t.Errorf("fivegc_lmf_gnss_total{result=FALLBACK_CELLID} = %v, want %v", after, before+1)
	}
}

// TestPerformLPPOrFallback_GNSSErrorFallsBack verifies that a decoded
// gnss-Error.targetDeviceErrorCauses in ProvideLocationInformation triggers
// the same fallback path as a leg failure (LPPRelay.md §Error table).
func TestPerformLPPOrFallback_GNSSErrorFallsBack(t *testing.T) {
	s := newLPPTestServer(t)
	cause := lpp.GNSSErrorNotEnoughSatellites
	lppClient := &fakeLPPClient{gnssSupported: true, gnssError: &cause}
	s.SetLPPClient(lppClient)
	s.SetNRPPAClient(&fakeNRPPaSenderForLPP{ecidSupported: true})

	loc, _, err := s.performLPPOrFallback(context.Background(), "imsi-001010000000006", "imsi-001010000000006")
	if err != nil {
		t.Fatalf("performLPPOrFallback: %v", err)
	}
	if len(loc.PositioningDataList) != 1 || loc.PositioningDataList[0] != "eCID" {
		t.Fatalf("PositioningDataList = %v, want [eCID] (fallback after gnss-Error)", loc.PositioningDataList)
	}
}

// TestPerformLPPOrFallback_TooFewSatellitesFallsBack verifies that a
// measurement report with fewer than lpp.WLSMinSatellites usable satellites
// triggers the same fallback path as a WLS convergence failure.
func TestPerformLPPOrFallback_TooFewSatellitesFallsBack(t *testing.T) {
	s := newLPPTestServer(t)
	lppClient := newGNSSSuccessClient()
	lppClient.tooFewSatellites = true
	s.SetLPPClient(lppClient)
	s.SetNRPPAClient(&fakeNRPPaSenderForLPP{ecidSupported: true})

	loc, _, err := s.performLPPOrFallback(context.Background(), "imsi-001010000000007", "imsi-001010000000007")
	if err != nil {
		t.Fatalf("performLPPOrFallback: %v", err)
	}
	if len(loc.PositioningDataList) != 1 || loc.PositioningDataList[0] != "eCID" {
		t.Fatalf("PositioningDataList = %v, want [eCID] (fallback after < 4 usable satellites)", loc.PositioningDataList)
	}
}

// TestPerformLPPOrFallback_ClientNotWired verifies that a nil lppClient
// downgrades directly to E-CID without attempting any LPP leg.
func TestPerformLPPOrFallback_ClientNotWired(t *testing.T) {
	s := newLPPTestServer(t)
	// Intentionally do not call s.SetLPPClient.
	s.SetNRPPAClient(&fakeNRPPaSenderForLPP{ecidSupported: true})

	loc, _, err := s.performLPPOrFallback(context.Background(), "imsi-001010000000008", "imsi-001010000000008")
	if err != nil {
		t.Fatalf("performLPPOrFallback: %v", err)
	}
	if len(loc.PositioningDataList) != 1 || loc.PositioningDataList[0] != "eCID" {
		t.Fatalf("PositioningDataList = %v, want [eCID]", loc.PositioningDataList)
	}
}

// TestPerformLPPOrFallback_TxnMismatchWarnsAndContinues verifies the
// TS 37.355 §5.2 echo rule: an echoed transactionID mismatch is log-warned
// (lpp_txn_mismatch) but the exchange completes successfully — correlation
// is by AMF-UE-NGAP-ID, not by the LPP transaction.
func TestPerformLPPOrFallback_TxnMismatchWarnsAndContinues(t *testing.T) {
	var buf strings.Builder
	s := newLPPTestServerWithLogger(t, &buf)
	lppClient := newGNSSSuccessClient()
	lppClient.echoWrongTxn = true
	s.SetLPPClient(lppClient)

	loc, _, err := s.performLPPOrFallback(context.Background(), "imsi-001010000000009", "imsi-001010000000009")
	if err != nil {
		t.Fatalf("performLPPOrFallback: %v", err)
	}
	if len(loc.PositioningDataList) != 1 || loc.PositioningDataList[0] != "gnss" {
		t.Fatalf("PositioningDataList = %v, want [gnss] (mismatch is warn-only, not an abort)", loc.PositioningDataList)
	}
	if !strings.Contains(buf.String(), "lpp_txn_mismatch") {
		t.Fatalf("log does not contain lpp_txn_mismatch:\n%s", buf.String())
	}
}

// TestPerformLPPOrFallback_StateMachineTransitions verifies the per-SUPI LPP
// state machine advances through CAPS_REQUESTED and ASSIST_SENT (proxy for
// feature scenario 3's assertion — the state is transient (deleted on
// completion via defer), so this test observes it mid-flight via an LPP
// client that inspects s.lppState from inside SendDLLPP.
func TestPerformLPPOrFallback_StateMachineTransitions(t *testing.T) {
	s := newLPPTestServer(t)
	var observedAtCapsLeg, observedAtAssistLeg, observedAtMeasureLeg string

	probe := &observingLPPClient{
		fakeLPPClient: *newGNSSSuccessClient(),
		onRequestCapabilities: func() {
			observedAtCapsLeg = s.lppState.get("imsi-001010000000001")
		},
		onAssistData: func() { observedAtAssistLeg = s.lppState.get("imsi-001010000000001") },
		onRequestLocation: func() {
			observedAtMeasureLeg = s.lppState.get("imsi-001010000000001")
		},
	}
	s.SetLPPClient(probe)

	if _, _, err := s.performLPPOrFallback(context.Background(), "imsi-001010000000001", "imsi-001010000000001"); err != nil {
		t.Fatalf("performLPPOrFallback: %v", err)
	}

	if observedAtCapsLeg != lppStateCapsRequested {
		t.Errorf("state during capability leg = %s, want %s", observedAtCapsLeg, lppStateCapsRequested)
	}
	if observedAtAssistLeg != lppStateAssistSent {
		t.Errorf("state during assistance leg = %s, want %s", observedAtAssistLeg, lppStateAssistSent)
	}
	if observedAtMeasureLeg != lppStateAssistSent {
		t.Errorf("state during measurement leg = %s, want %s (leg 3 fires from ASSIST_SENT)", observedAtMeasureLeg, lppStateAssistSent)
	}
}

// observingLPPClient wraps fakeLPPClient with hooks invoked just before each
// leg replies, so the test can observe the transient per-SUPI state.
type observingLPPClient struct {
	fakeLPPClient
	onRequestCapabilities func()
	onAssistData          func()
	onRequestLocation     func()
}

func (o *observingLPPClient) SendDLLPP(ctx context.Context, ueContextID string, lppPDU []byte, expectUlResponse bool) ([]byte, string, error) {
	pdu, err := lpp.Decode(lppPDU)
	if err == nil {
		switch pdu.Type {
		case lpp.MsgRequestCapabilities:
			if o.onRequestCapabilities != nil {
				o.onRequestCapabilities()
			}
		case lpp.MsgProvideAssistanceData:
			if o.onAssistData != nil {
				o.onAssistData()
			}
		case lpp.MsgRequestLocationInformation:
			if o.onRequestLocation != nil {
				o.onRequestLocation()
			}
		}
	}
	return o.fakeLPPClient.SendDLLPP(ctx, ueContextID, lppPDU, expectUlResponse)
}
