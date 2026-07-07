//go:build functional

// Package features_test — godog BDD step definitions for the LMF LPP relay
// and GNSS positioning procedure (LMF-005).
//
// This file is in the same package as determine_location_steps_test.go and is
// wired into the godog suite by initLPPRelaySteps(sc, c, w), called from
// InitializeScenario in determine_location_steps_test.go right after
// initNRPPARelaySteps (which constructs and returns the shared *ecidWorld w).
//
// Architecture:
//
//   - lpp_relay.feature reuses the *ecidWorld defined in
//     nrppa_relay_steps_test.go rather than introducing a second in-process
//     server: the GNSS fallback chain (GNSS -> E-CID -> Cell-ID) requires the
//     same server instance to have SetLPPClient, SetNRPPAClient and the
//     shared c.amf / c.udm fakes all wired together. ecidWorld.buildServer
//     already wires all four.
//   - Several Given/Then steps used by lpp_relay.feature are byte-for-byte
//     identical to steps already registered in nrppa_relay_steps_test.go or
//     determine_location_steps_test.go (e.g. the E-CID success/NONE Given
//     steps, the generic positioningDataList includes/does-not-include Then
//     steps, the generic "accuracy is at most N" Then step, the shared
//     "Namf LocationData" Given step, and the shared hAccuracy When step).
//     This file does NOT re-register any of those regexes — godog treats the
//     ScenarioContext as a single flat namespace, so re-registering an
//     identical pattern here would make every matching line ambiguous. Only
//     the LPP-specific text that has no NRPPa/Cell-ID analogue is registered
//     below.
//   - fakeLPPSender implements LPPSender (nf/lmf/internal/server/lpp.go) and
//     returns canned LPP PDUs built with the shared/lpp Build*/Decode/
//     SimulateMeasurements helpers, mirroring the production UE's LPP replies.
//   - syncBuffer captures the LMF server's structured (slog TextHandler) log
//     output for the scenario so Then steps can assert on "UplinkLPP
//     received" / per-SUPI lpp_state log lines that are not observable
//     through the HTTP response alone (the per-SUPI state tracker entry is
//     deleted via defer once handleDetermineLocation returns).
//
// Ref: TS 37.355 §6; TS 24.501 §8.7.4; TS 24.501 §9.11.3.40; TS 38.413 §8.6.2/
// §8.6.3; TS 23.273 §6.2.10 / §7.2; TS 29.572 §5.2.2.2 / §6.1.6.2.2.
package features_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/shared/lpp"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// ---- syncBuffer ---------------------------------------------------------------

// syncBuffer is a mutex-protected io.Writer + String() accumulator used as the
// slog.TextHandler sink for an ecidWorld's LMF server, so that Then steps
// running in the test goroutine can safely read log output written by the
// httptest.Server's handler goroutine (avoids a data race under `go test -race`;
// slog's built-in handlers already serialise Handle() calls internally, but the
// underlying io.Writer itself must still be safe for the test goroutine's read).
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

// Write implements io.Writer.
func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

// String returns a snapshot of the accumulated log text.
func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// logHasLineContaining reports whether any line of buf contains every one of
// substrs. Used to assert on structured slog TextHandler key=value log lines
// (e.g. `msg="UplinkLPP received" ... lpp_msg=ProvideCapabilities ...`) without
// depending on attribute ordering.
func logHasLineContaining(buf string, substrs ...string) bool {
	for _, line := range strings.Split(buf, "\n") {
		all := true
		for _, s := range substrs {
			if !strings.Contains(line, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// ---- fakeLPPSender --------------------------------------------------------
//
// fakeLPPSender implements lmfsrv.LPPSender and returns canned spec-encoded
// UPER LPP PDUs built with the shared/lpp Build*/Decode helpers, mirroring
// the production UE's (UERANSIM patch 0042) LPP replies over the AMF NAS N1
// relay across the LMF-009 three-leg flow. Configured by Given steps before
// the When step fires.
//
// Ref: TS 37.355 §5.2/§6 (LPP message types + transactions);
// TS 29.518 §5.2.2.6 (dl-lpp-info, expectUlResponse);
// TS 24.501 §8.7.4 (DL/UL NAS Transport carrying LPP, payload container type 0x03).

// lppSenderMode enumerates the canned behaviours of fakeLPPSender.
type lppSenderMode int

const (
	// lppModeRecordOnly counts calls but returns an error if actually called.
	// Used as the safe default and for the privacy-blocked scenario, where
	// SendDLLPP must never be invoked (the privacy gate fires first).
	lppModeRecordOnly lppSenderMode = iota

	// lppModeGNSSSuccess implements the full three-leg happy path:
	//   Leg 1 (RequestCapabilities)        -> ProvideCapabilities{gps, ue-assisted}
	//   Leg 2 (ProvideAssistanceData)      -> stores the wire-quantized anchor;
	//                                         no UL reply (expectUlResponse=false)
	//   Leg 3 (RequestLocationInformation) -> ProvideLocationInformation with
	//     per-SV codePhase pseudoranges computed from the quantized-anchor
	//     ephemeris against trueLat/trueLon, so the LMF's WLS solve converges
	//     near that fix.
	lppModeGNSSSuccess

	// lppModeGNSSNone returns ProvideCapabilities with
	// a-gnss-ProvideCapabilities absent (GNSS=NONE) on leg 1. A leg-2/3 call
	// in this mode is a test bug (the LMF must not continue after GNSS=NONE)
	// and errors.
	lppModeGNSSNone

	// lppModeGNSSSuccessNoMeasurement answers legs 1 and 2 normally, then
	// simulates a guard-timer expiry (an error) on leg 3 — the UE never
	// relays a ProvideLocationInformation report.
	lppModeGNSSSuccessNoMeasurement

	// lppModeRejectImmediate simulates the AMF itself rejecting dl-lpp-info
	// (e.g. the UE is CM-IDLE / unreachable on N1) — the very first SendDLLPP
	// call (the capability leg) fails with rejectCause.
	lppModeRejectImmediate
)

// lppCallRecord captures one SendDLLPP round trip for Then-step introspection.
type lppCallRecord struct {
	reqPDU []byte // the LPP PDU dispatched to the (simulated) AMF/UE
	rspPDU []byte // the LPP PDU returned, or nil on a simulated failure
}

// fakeLPPSender is the test double for lmfsrv.LPPSender.
type fakeLPPSender struct {
	mode      lppSenderMode
	callCount int32 // accessed via atomic

	// GNSS fix parameters for lppModeGNSSSuccess (populated by the Given step).
	trueLat, trueLon float64
	// satelliteCount limits how many matched (ephemeris ∩ synthetic) satellites
	// are used to compute measurements; 0 (default) uses every generated
	// satellite (GenerateSyntheticEphemeris always returns exactly
	// lpp.WLSMinSatellites=4, matching every scenario's "4 satellite
	// pseudoranges" wording).
	satelliteCount int

	// rejectCause is returned by lppModeRejectImmediate.
	rejectCause string

	mu    sync.Mutex
	calls []lppCallRecord
	// anchorLat/anchorLon is the wire-quantized reference location stored on
	// leg 2 (the quantized-anchor rule — the UE mirror seeds its ephemeris
	// from it, never from a config float). haveAnchor guards leg 3.
	anchorLat, anchorLon float64
	haveAnchor           bool
}

// record appends a call record under the mutex.
func (f *fakeLPPSender) record(reqPDU, rspPDU []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, lppCallRecord{reqPDU: reqPDU, rspPDU: rspPDU})
}

// recordedCalls returns a snapshot copy of all recorded calls.
func (f *fakeLPPSender) recordedCalls() []lppCallRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]lppCallRecord, len(f.calls))
	copy(out, f.calls)
	return out
}

// SendDLLPP implements lmfsrv.LPPSender.
// Increments callCount atomically before dispatching to the mode handler.
func (f *fakeLPPSender) SendDLLPP(_ context.Context, _ string, lppPDU []byte, expectUlResponse bool) ([]byte, string, error) {
	atomic.AddInt32(&f.callCount, 1)
	switch f.mode {
	case lppModeRecordOnly:
		f.record(lppPDU, nil)
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeLPPSender: unexpected call in record-only mode")

	case lppModeRejectImmediate:
		f.record(lppPDU, nil)
		cause := f.rejectCause
		if cause == "" {
			cause = "UE_NOT_REACHABLE"
		}
		// Ref: TS 23.273 §6.2.10 (dl-lpp-info rejection is a hard relay
		// failure at the GNSS tier; the LMF must downgrade gracefully).
		return nil, cause, fmt.Errorf("fakeLPPSender: simulated dl-lpp-info rejection: %s", cause)

	case lppModeGNSSNone:
		return f.handleGNSSNone(lppPDU)

	case lppModeGNSSSuccess:
		return f.handleGNSSSuccess(lppPDU, expectUlResponse)

	case lppModeGNSSSuccessNoMeasurement:
		return f.handleGNSSSuccessNoMeasurement(lppPDU, expectUlResponse)

	default:
		f.record(lppPDU, nil)
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeLPPSender: unhandled mode %d", f.mode)
	}
}

// handleGNSSNone returns ProvideCapabilities with a-gnss-ProvideCapabilities
// absent (GNSS=NONE — the form patch 0042 emits under LPP_GNSS_NONE=1). Only
// leg 1 (capability) is expected; a leg-2/3 call in this mode is an
// unexpected-message-type error.
// Ref: TS 37.355 §6 (Capability Transfer); TS 23.273 §6.2.10 (graceful downgrade).
func (f *fakeLPPSender) handleGNSSNone(pduBytes []byte) ([]byte, string, error) {
	pdu, err := lpp.Decode(pduBytes)
	if err != nil {
		f.record(pduBytes, nil)
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeLPPSender(gnssNone): decode: %w", err)
	}
	if pdu.Type != lpp.MsgRequestCapabilities {
		f.record(pduBytes, nil)
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeLPPSender(gnssNone): unexpected msg type 0x%02x — legs 2/3 must not be attempted after GNSS=NONE", pdu.Type)
	}
	resp, err := lpp.BuildProvideCapabilities(pdu.TransactionID, false) // GNSS=NONE
	if err != nil {
		return nil, "LOCATION_FAILURE", err
	}
	f.record(pduBytes, resp)
	return resp, "", nil
}

// handleGNSSSuccess implements the three-leg happy path (echoing each leg's
// transactionID per TS 37.355 §5.2):
//   - Leg 1 (RequestCapabilities) -> ProvideCapabilities{gps, ue-assisted}
//   - Leg 2 (ProvideAssistanceData, expectUlResponse=false) -> stores the
//     wire-quantized anchor, replies (nil, "", nil) — the AMF's 204.
//   - Leg 3 (RequestLocationInformation) -> ProvideLocationInformation with
//     per-SV codePhase pseudoranges from the quantized-anchor ephemeris so
//     the LMF's WLS solve converges at (trueLat, trueLon).
//
// Ref: TS 37.355 §6 (A-GNSS Capability/Assistance/Location Information Transfer);
// TS 23.273 §6.2.10; docs/procedures/LPPRelay.md §Synthetic satellite geometry.
func (f *fakeLPPSender) handleGNSSSuccess(pduBytes []byte, expectUlResponse bool) ([]byte, string, error) {
	pdu, err := lpp.Decode(pduBytes)
	if err != nil {
		f.record(pduBytes, nil)
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeLPPSender(gnssOK): decode: %w", err)
	}

	switch pdu.Type {
	case lpp.MsgRequestCapabilities:
		resp, err := lpp.BuildProvideCapabilities(pdu.TransactionID, true)
		if err != nil {
			return nil, "LOCATION_FAILURE", err
		}
		f.record(pduBytes, resp)
		return resp, "", nil

	case lpp.MsgProvideAssistanceData:
		if expectUlResponse {
			f.record(pduBytes, nil)
			return nil, "LOCATION_FAILURE",
				fmt.Errorf("fakeLPPSender(gnssOK): ProvideAssistanceData is DL-only — expectUlResponse must be false")
		}
		loc := pdu.AssistanceData.ReferenceLocation
		f.mu.Lock()
		f.anchorLat = lpp.DecodeLatitude(loc.LatitudeSign, loc.DegreesLatitude)
		f.anchorLon = lpp.DecodeLongitude(loc.DegreesLongitude)
		f.haveAnchor = true
		f.mu.Unlock()
		f.record(pduBytes, nil)
		return nil, "", nil // AMF returns 204 No Content

	case lpp.MsgRequestLocationInformation:
		f.mu.Lock()
		haveAnchor, aLat, aLon := f.haveAnchor, f.anchorLat, f.anchorLon
		f.mu.Unlock()
		if !haveAnchor {
			f.record(pduBytes, nil)
			return nil, "LOCATION_FAILURE",
				fmt.Errorf("fakeLPPSender(gnssOK): RequestLocationInformation before ProvideAssistanceData (no stored anchor)")
		}
		ephemeris := lpp.GenerateSyntheticEphemeris(aLat, aLon)
		n := len(ephemeris)
		if f.satelliteCount > 0 && f.satelliteCount < n {
			n = f.satelliteCount
		}
		meas := lpp.SimulateMeasurements(ephemeris[:n], f.trueLat, f.trueLon, 0, lpp.UEClockBiasM)
		var sats []lpp.SatMeas
		for _, m := range meas {
			icp, cp, err := lpp.PseudorangeToCodePhase(m.PseudorangeMeters)
			if err != nil {
				f.record(pduBytes, nil)
				return nil, "LOCATION_FAILURE", fmt.Errorf("fakeLPPSender(gnssOK): codePhase: %w", err)
			}
			sats = append(sats, lpp.SatMeas{
				SVID:              m.SVID - 1, // satellite-id = constellation index − 1
				CNo:               lpp.CNoDefault,
				MpathDet:          lpp.MpathDetLow,
				CodePhase:         cp,
				IntegerCodePhase:  icp,
				CodePhaseRMSError: lpp.CodePhaseRMSErrorDefault,
			})
		}
		resp, err := lpp.BuildProvideLocationInformation(pdu.TransactionID,
			lpp.LocationMeasurements{GNSSTODMsec: 123456, Sats: sats})
		if err != nil {
			return nil, "LOCATION_FAILURE", err
		}
		f.record(pduBytes, resp)
		return resp, "", nil

	default:
		f.record(pduBytes, nil)
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeLPPSender(gnssOK): unexpected msg type 0x%02x", pdu.Type)
	}
}

// handleGNSSSuccessNoMeasurement answers legs 1 and 2 normally, then
// simulates an LPP guard-timer expiry (an error, no UL
// ProvideLocationInformation) on leg 3. Ref: TS 23.273 §6.2.10 (graceful
// degradation on measurement-leg timeout, not a hard error).
func (f *fakeLPPSender) handleGNSSSuccessNoMeasurement(pduBytes []byte, expectUlResponse bool) ([]byte, string, error) {
	pdu, err := lpp.Decode(pduBytes)
	if err != nil {
		f.record(pduBytes, nil)
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeLPPSender(gnssTimeout): decode: %w", err)
	}

	switch pdu.Type {
	case lpp.MsgRequestCapabilities:
		resp, err := lpp.BuildProvideCapabilities(pdu.TransactionID, true)
		if err != nil {
			return nil, "LOCATION_FAILURE", err
		}
		f.record(pduBytes, resp)
		return resp, "", nil

	case lpp.MsgProvideAssistanceData:
		if expectUlResponse {
			f.record(pduBytes, nil)
			return nil, "LOCATION_FAILURE",
				fmt.Errorf("fakeLPPSender(gnssTimeout): ProvideAssistanceData is DL-only — expectUlResponse must be false")
		}
		f.record(pduBytes, nil)
		return nil, "", nil // leg 2 delivered (204)

	case lpp.MsgRequestLocationInformation:
		f.record(pduBytes, nil)
		return nil, "UE_NOT_REACHABLE",
			fmt.Errorf("fakeLPPSender(gnssTimeout): simulated LPP measurement guard-timer expiry")

	default:
		f.record(pduBytes, nil)
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeLPPSender(gnssTimeout): unexpected msg type 0x%02x", pdu.Type)
	}
}

// ---- initLPPRelaySteps registers all LPP relay / GNSS step definitions.
//
// Called from InitializeScenario in determine_location_steps_test.go with the
// shared lmfCtx pointer c and the *ecidWorld w returned by
// initNRPPARelaySteps, following the same aggregator pattern as
// initEventSubscriptionSteps / initNRPPARelaySteps.
//
// Ref: TS 37.355 §6; TS 24.501 §8.7.4; TS 23.273 §6.2.10; TS 29.572 §5.2.2.2.
func initLPPRelaySteps(sc *godog.ScenarioContext, c *lmfCtx, w *ecidWorld) {
	// No separate Before/After hooks: w.lpp / w.gnssMetricBaseline / w.logBuf
	// are reset by initNRPPARelaySteps' sc.Before hook (nrppa_relay_steps_test.go),
	// which always runs before every scenario in this suite, including the
	// lpp_relay.feature scenarios.

	// =========================================================================
	// Background step
	// =========================================================================

	// "a mock AMF is available for Namf_Location ProvideLocationInfo,
	//  Namf_Location dl-nrppa-info and Namf_Location dl-lpp-info"
	// All three are wired structurally: c.amf (ProvideLocationInfo),
	// w.nrppa (dl-nrppa-info) and w.lpp (dl-lpp-info) are always non-nil.
	sc.Step(
		`^a mock AMF is available for Namf_Location ProvideLocationInfo, Namf_Location dl-nrppa-info and Namf_Location dl-lpp-info$`,
		func() error { return nil },
	)

	// =========================================================================
	// Given steps — fakeLPPSender configuration
	// =========================================================================

	// Scenario 1 (happy path) — GNSS success with a UE-reported fix near
	// (lat, lon). Ref: TS 37.355 §6; TS 23.273 §6.2.10.
	sc.Step(
		`^the mock AMF relays LPP for ueContextId "([^"]+)" with UE capability "GNSS_SUPPORTED" and ProvideLocationInformation reporting (\d+) satellite pseudoranges near lat "([^"]+)" lon "([^"]+)"$`,
		func(_ string, satCountStr, latStr, lonStr string) error {
			satCount, err := strconv.Atoi(satCountStr)
			if err != nil {
				return fmt.Errorf("bad satellite count %q: %w", satCountStr, err)
			}
			lat, err := strconv.ParseFloat(latStr, 64)
			if err != nil {
				return fmt.Errorf("bad lat %q: %w", latStr, err)
			}
			lon, err := strconv.ParseFloat(lonStr, 64)
			if err != nil {
				return fmt.Errorf("bad lon %q: %w", lonStr, err)
			}
			w.lpp.mode = lppModeGNSSSuccess
			w.lpp.trueLat = lat
			w.lpp.trueLon = lon
			w.lpp.satelliteCount = satCount
			w.buildServer(c)
			return nil
		},
	)

	// Scenario 2 — GNSS capability NONE: no assistance/measurement round is
	// attempted. Ref: TS 37.355 §6; TS 23.273 §6.2.10 (graceful downgrade).
	sc.Step(
		`^the mock AMF relays LPP for ueContextId "([^"]+)" with UE capability "GNSS_NONE" and no ProvideLocationInformation report$`,
		func(_ string) error {
			w.lpp.mode = lppModeGNSSNone
			w.buildServer(c)
			return nil
		},
	)

	// Scenario 4 — GNSS capability SUPPORTED but the measurement round times
	// out (guard timer expiry, no UL ProvideLocationInformation).
	// Ref: TS 23.273 §6.2.10 (graceful degradation, one tier at a time).
	sc.Step(
		`^the mock AMF relays LPP for ueContextId "([^"]+)" with UE capability "GNSS_SUPPORTED" but never relays a UL ProvideLocationInformation report$`,
		func(_ string) error {
			w.lpp.mode = lppModeGNSSSuccessNoMeasurement
			w.buildServer(c)
			return nil
		},
	)

	// Scenario 5 — AMF rejects dl-lpp-info outright (UE not reachable on N1).
	// Ref: TS 23.273 §6.2.10 (hard relay failure at the GNSS tier -> graceful
	// downgrade, never surfaced as a 5xx to the LCS consumer).
	sc.Step(
		`^the mock AMF rejects dl-lpp-info for ueContextId "([^"]+)" with cause "([^"]+)"$`,
		func(_, cause string) error {
			w.lpp.mode = lppModeRejectImmediate
			w.lpp.rejectCause = cause
			w.buildServer(c)
			return nil
		},
	)

	// Scenario 6 — privacy-blocked: record any dl-lpp-info calls (expect zero).
	// w.lpp is already in record-only mode (zero value); this step exists for
	// readability, mirroring "the mock AMF records any dl-nrppa-info calls it
	// receives" in nrppa_relay_steps_test.go.
	sc.Step(
		`^the mock AMF records any dl-lpp-info calls it receives$`,
		func() error { return nil },
	)

	// =========================================================================
	// Then steps — dl-lpp-info / ul-lpp-info exchange assertions
	// =========================================================================

	// "every dl-lpp-info and ul-lpp-info exchange used NAS payload container type 3"
	//
	// The LPPSender interface (nf/lmf/internal/server/lpp.go) abstracts the AMF
	// NAS N1 relay as opaque bytes — the payload container type IE itself is a
	// production-only NAS/AMF-side detail (TS 24.501 §9.11.3.40) that is not
	// observable at this LMF-only SBI boundary. The strongest assertion
	// available at this layer is the architectural invariant documented in
	// nf/lmf/internal/server/lpp.go and shared/lpp/lpp.go: every SendDLLPP
	// round trip carries a genuine LPP-Message (never NAS SM info / a
	// different container), which is exactly what payload container type 0x03
	// (vs 0x01) means. We assert that at least one exchange happened and that
	// every recorded request/response decodes as a valid LPP-Message.
	// Ref: TS 24.501 §9.11.3.40; TS 24.501 §8.7.4; TS 37.355 §6.2.
	sc.Step(
		`^every dl-lpp-info and ul-lpp-info exchange used NAS payload container type (\d+)$`,
		func(containerType int) error {
			if containerType != 3 {
				return fmt.Errorf("test expectation error: NAS payload container type for LPP is always 3 (TS 24.501 §9.11.3.40), got %d in feature text", containerType)
			}
			calls := w.lpp.recordedCalls()
			if len(calls) == 0 {
				return fmt.Errorf("no dl-lpp-info exchanges recorded")
			}
			for i, call := range calls {
				if _, err := lpp.Decode(call.reqPDU); err != nil {
					return fmt.Errorf("dl-lpp-info exchange %d: request PDU is not a valid LPP-Message (would not be payload container type 3): %w", i, err)
				}
				if call.rspPDU != nil {
					if _, err := lpp.Decode(call.rspPDU); err != nil {
						return fmt.Errorf("dl-lpp-info exchange %d: response PDU is not a valid LPP-Message (would not be payload container type 3): %w", i, err)
					}
				}
			}
			return nil
		},
	)

	// "the mock AMF received a dl-lpp-info dispatch for ueContextId "..."
	//  carrying an LPP RequestCapabilities message over NAS payload container type 3"
	// Asserts the first recorded exchange's request PDU is a RequestCapabilities
	// LPP-Message (the capability round is always round 1).
	// Ref: TS 37.355 §6 (Capability Transfer); TS 24.501 §8.7.4/§9.11.3.40.
	sc.Step(
		`^the mock AMF received a dl-lpp-info dispatch for ueContextId "([^"]+)" carrying an LPP RequestCapabilities message over NAS payload container type (\d+)$`,
		func(_ string, containerType int) error {
			if containerType != 3 {
				return fmt.Errorf("test expectation error: expected NAS payload container type 3, got %d in feature text", containerType)
			}
			calls := w.lpp.recordedCalls()
			if len(calls) == 0 {
				return fmt.Errorf("no dl-lpp-info exchanges recorded")
			}
			pdu, err := lpp.Decode(calls[0].reqPDU)
			if err != nil {
				return fmt.Errorf("dl-lpp-info exchange 0: request PDU decode error: %w", err)
			}
			if pdu.Type != lpp.MsgRequestCapabilities {
				return fmt.Errorf("dl-lpp-info exchange 0: LPP message type = %d, want RequestCapabilities (%d)", pdu.Type, lpp.MsgRequestCapabilities)
			}
			return nil
		},
	)

	// "the mock AMF received no ProvideAssistanceData or RequestLocationInformation
	//  LPP messages for ueContextId "..."" — asserts neither leg 2
	// (ProvideAssistanceData) nor leg 3 (RequestLocationInformation) was ever
	// dispatched, confirming the LMF stopped after a GNSS=NONE capability reply.
	// Ref: TS 37.355 §6; TS 23.273 §6.2.10 (graceful downgrade after the capability leg).
	sc.Step(
		`^the mock AMF received no ProvideAssistanceData or RequestLocationInformation LPP messages for ueContextId "([^"]+)"$`,
		func(_ string) error {
			for i, call := range w.lpp.recordedCalls() {
				pdu, err := lpp.Decode(call.reqPDU)
				if err != nil {
					continue // decode errors are covered by other assertions
				}
				if pdu.Type == lpp.MsgProvideAssistanceData || pdu.Type == lpp.MsgRequestLocationInformation {
					return fmt.Errorf("dl-lpp-info exchange %d unexpectedly carried LPP message type %d after GNSS=NONE", i, pdu.Type)
				}
			}
			return nil
		},
	)

	// "the mock AMF received no dl-lpp-info calls" — used by the privacy-blocked
	// scenario to confirm the privacy gate fires before any GNSS/LPP attempt.
	// Ref: TS 23.273 §9.1 (privacy gate before positioning); TS 23.273 §6.2.10.
	sc.Step(
		`^the mock AMF received no dl-lpp-info calls$`,
		func() error {
			count := atomic.LoadInt32(&w.lpp.callCount)
			if count != 0 {
				return fmt.Errorf("expected 0 dl-lpp-info (SendDLLPP) calls, got %d", count)
			}
			return nil
		},
	)

	// =========================================================================
	// Then steps — log assertions (UplinkLPP received / per-SUPI lpp_state)
	// =========================================================================

	// "the LMF logged an "UplinkLPP received" event with lpp_msg "ProvideCapabilities""
	// Ref: nf/lmf/internal/server/lpp.go (log.Info("UplinkLPP received", "lpp_msg", ...)).
	sc.Step(
		`^the LMF logged an "([^"]+)" event with lpp_msg "([^"]+)"$`,
		func(msg, lppMsg string) error {
			logs := w.logBuf.String()
			if !logHasLineContaining(logs, `msg="`+msg+`"`, "lpp_msg="+lppMsg) {
				return fmt.Errorf("no log line found containing msg=%q and lpp_msg=%q (captured log:\n%s)", msg, lppMsg, logs)
			}
			return nil
		},
	)

	// "the LMF per-SUPI LPP state for ueContextId "..." advanced through state "CAPS_REQUESTED""
	// The per-SUPI state tracker entry itself is deleted (defer) once
	// handleDetermineLocation returns, so this asserts on the transition log
	// line recorded while the state machine was in that state.
	// Ref: nf/lmf/internal/server/lpp.go (lppStateTracker; log.Info(..., "lpp_state", lppStateCapsRequested)).
	sc.Step(
		`^the LMF per-SUPI LPP state for ueContextId "([^"]+)" advanced through state "([^"]+)"$`,
		func(ueContextID, state string) error {
			logs := w.logBuf.String()
			if !logHasLineContaining(logs, "ue_context_id="+ueContextID, "lpp_state="+state) {
				return fmt.Errorf("no log line found with ue_context_id=%s and lpp_state=%s (captured log:\n%s)", ueContextID, state, logs)
			}
			return nil
		},
	)

	// =========================================================================
	// Then steps — metric assertions (fivegc_lmf_gnss_total)
	// =========================================================================

	// "the metric fivegc_lmf_gnss_total with label result "OK" is incremented"
	// Delta assertion: current − baseline ≥ 1.
	// Ref: TS 23.273 §6.2.10; metrics.LMFGNSSTotal.
	sc.Step(
		`^the metric fivegc_lmf_gnss_total with label result "([^"]+)" is incremented$`,
		func(result string) error {
			baseline := w.gnssMetricBaseline[result]
			current := testutil.ToFloat64(metrics.LMFGNSSTotal.WithLabelValues(result))
			delta := current - baseline
			if delta < 1 {
				return fmt.Errorf(
					"fivegc_lmf_gnss_total{result=%q} delta=%g, want >=1 (baseline=%.0f current=%.0f)",
					result, delta, baseline, current)
			}
			return nil
		},
	)

	// "the metric fivegc_lmf_gnss_total with label result "OK" is not incremented"
	// Delta assertion: current − baseline == 0.
	// Used by the privacy-blocked scenario to confirm the privacy gate fires
	// before any GNSS/LPP attempt. Ref: TS 23.273 §9.1; TS 23.273 §6.2.10.
	sc.Step(
		`^the metric fivegc_lmf_gnss_total with label result "([^"]+)" is not incremented$`,
		func(result string) error {
			baseline := w.gnssMetricBaseline[result]
			current := testutil.ToFloat64(metrics.LMFGNSSTotal.WithLabelValues(result))
			delta := current - baseline
			if delta != 0 {
				return fmt.Errorf(
					"fivegc_lmf_gnss_total{result=%q} delta=%g, want 0 (baseline=%.0f current=%.0f)",
					result, delta, baseline, current)
			}
			return nil
		},
	)
}
