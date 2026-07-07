//go:build functional

// Package features_test — godog BDD step definitions for the LMF
// NRPPa relay and E-CID positioning procedure (LMF-004).
//
// This file is in the same package as determine_location_steps_test.go and is
// wired into the godog suite by initNRPPARelaySteps(sc, c) called from
// InitializeScenario in determine_location_steps_test.go.
//
// Architecture:
//
//   - Each scenario gets a fresh ecidWorld whose LMF server has SetNRPPAClient
//     wired — enabling the quality-driven E-CID path in handleDetermineLocation.
//   - The ecidWorld server reuses c.amf (fakeAMFClient) and c.udm (fakeUDMClient)
//     from the parent lmfCtx so all existing Given steps ("the mock AMF returns a
//     Namf LocationData ...", "the subscriber location privacy for ... is ...") work
//     without re-registration.
//   - fakeNRPPASender implements DLNRPPASender and returns canned NRPPa PDUs built
//     with the shared/nrppa Encode helpers, mirroring the production gNB patch.
//   - When step bridges its response into c.lastResp / c.lastBody so all shared
//     Then steps (HTTP status, locationEstimate shape, nrCellId, tac, ProblemDetails
//     cause) work for the ECID scenarios without re-registration.
//   - Metric assertions delta-compare metrics.LMFECIDTotal captured around the When step.
//   - SendDLNRPPa call count uses atomic int32 (race-safe).
//
// Ref: TS 38.455 §8; TS 38.413 §8.17.3; TS 23.273 §6.2.9; TS 29.572 §5.2.2.2;
// TS 29.518 §5.2.2.6 (Namf_Location dl-nrppa-info).
package features_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"

	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus/testutil"

	lmfcfg "github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	lmfsrv "github.com/francurieses/claudia-5gc/nf/lmf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/nrppa"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// ---- fakeNRPPASender --------------------------------------------------------
//
// fakeNRPPASender implements lmfsrv.DLNRPPASender and returns canned NRPPa PDUs
// built with the shared/nrppa Encode helpers. Configured by Given steps before
// the When step fires. SendDLNRPPa is called from the handler goroutine, so
// callCount uses atomic; all other fields are written before serving starts.
//
// Ref: TS 38.455 §8 (NRPPa message types); TS 29.518 §5.2.2.6 (dl-nrppa-info).

// nrppaSenderMode enumerates the canned behaviours of fakeNRPPASender.
type nrppaSenderMode int

const (
	// nrppaModeRecordOnly counts calls but returns an error if actually called.
	// Used as the safe default and for Scenarios 4 and 5 where SendDLNRPPa must
	// not be called (hAccuracy > 200 / privacy blocked).
	nrppaModeRecordOnly nrppaSenderMode = iota

	// nrppaModeECIDSuccess returns PositioningInformationResponse{ECIDSupported:true}
	// on the first call and an ECIDMeasurementReport on the second call.
	// Used for Scenario 1 (happy path).
	nrppaModeECIDSuccess

	// nrppaModeTimeout always returns an error, simulating guard-timer expiry.
	// The LMF must fall back to Cell-ID transparently (FALLBACK_CELLID result).
	// Used for Scenario 2.
	nrppaModeTimeout

	// nrppaModeCapabilityNone returns PositioningInformationResponse{ECIDSupported:false}
	// on the first call. The LMF must not attempt a measurement round.
	// Used for Scenario 3.
	nrppaModeCapabilityNone
)

// fakeNRPPASender is the test double for lmfsrv.DLNRPPASender.
type fakeNRPPASender struct {
	mode      nrppaSenderMode
	callCount int32 // accessed via atomic

	// E-CID success scenario parameters (populated by the Given step).
	servingCellId string
	mcc, mnc      string
	tac           string
	apLat, apLon  float64
	apUncertainty float64
}

// SendDLNRPPa implements lmfsrv.DLNRPPASender.
// Increments callCount atomically before dispatching to the mode handler.
func (f *fakeNRPPASender) SendDLNRPPa(_ context.Context, _ string, pduBytes []byte) ([]byte, string, error) {
	atomic.AddInt32(&f.callCount, 1)
	switch f.mode {
	case nrppaModeRecordOnly:
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeNRPPASender: unexpected call in record-only mode")

	case nrppaModeTimeout:
		// Simulate a guard-timer expiry / no UL NRPPa response.
		// The LMF treats any non-nil error as a cue to fall back to Cell-ID.
		// Ref: TS 23.273 §6.2.9 (graceful downgrade on timeout).
		return nil, "UE_NOT_REACHABLE",
			fmt.Errorf("fakeNRPPASender: simulated NRPPa guard-timer expiry")

	case nrppaModeCapabilityNone:
		return f.handleCapabilityNone(pduBytes)

	case nrppaModeECIDSuccess:
		return f.handleECIDSuccess(pduBytes)

	default:
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeNRPPASender: unhandled mode %d", f.mode)
	}
}

// handleCapabilityNone returns PositioningInformationResponse{ECIDSupported:false}.
// Only the capability round (round 1) is expected; a second call is an error.
func (f *fakeNRPPASender) handleCapabilityNone(pduBytes []byte) ([]byte, string, error) {
	pdu, err := nrppa.Decode(pduBytes)
	if err != nil {
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeNRPPASender(capNone): decode: %w", err)
	}
	if pdu.Type == nrppa.MsgPositioningInformationRequest {
		// gNB reports E-CID not supported → LMF must fall back to Cell-ID.
		// Ref: TS 38.455 §8.2; TS 23.273 §6.2.9 (capability mismatch).
		resp := nrppa.EncodePosInfoRsp(nrppa.PositioningInformationResponse{
			ECIDSupported: false,
		})
		return resp, "", nil
	}
	return nil, "LOCATION_FAILURE",
		fmt.Errorf("fakeNRPPASender(capNone): unexpected msg type 0x%02x after NONE capability", pdu.Type)
}

// handleECIDSuccess implements the two-round happy path:
//   - Round 1 (PositioningInformationRequest) → PositioningInformationResponse{ECIDSupported:true}
//   - Round 2 (E-CIDMeasurementInitiationRequest) → E-CIDMeasurementReport carrying the
//     gNB's own NG-RANAccessPointPosition estimate (TS 38.455 §9 — a real, optional IE,
//     TS 23.032 Ellipsoid Point with Uncertainty Ellipse shape).
//
// Ref: TS 38.455 §8 (E-CID NRPPa procedures); TS 23.273 §6.2.9.
func (f *fakeNRPPASender) handleECIDSuccess(pduBytes []byte) ([]byte, string, error) {
	pdu, err := nrppa.Decode(pduBytes)
	if err != nil {
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeNRPPASender(ecidOK): decode: %w", err)
	}

	switch pdu.Type {
	case nrppa.MsgPositioningInformationRequest:
		// Capability round: gNB reports E-CID supported.
		// Ref: TS 38.455 §8.2 (PositioningInformationResponse).
		resp := nrppa.EncodePosInfoRsp(nrppa.PositioningInformationResponse{
			ECIDSupported: true,
		})
		return resp, "", nil

	case nrppa.MsgECIDMeasurementInitiationRequest:
		// Measurement round: return the gNB's serving cell + AP position estimate.
		// Ref: TS 38.455 §8.x (E-CIDMeasurementReport); TS 23.273 §6.2.9.
		measID := pdu.MsgECIDInitReq.LMFMeasurementID
		serving := hexToNRCGI(f.servingCellId)
		var tac [3]byte
		tacVal, _ := strconv.ParseUint(f.tac, 16, 32)
		tac[0] = byte(tacVal >> 16)
		tac[1] = byte(tacVal >> 8)
		tac[2] = byte(tacVal)
		report := nrppa.EncodeECIDReport(nrppa.ECIDMeasurementReportMsg{
			LMFMeasurementID: measID,
			RANMeasurementID: 42,
			ServingNRCGI:     serving,
			ServingTAC:       tac,
			APPosition: &nrppa.APPosition{
				Lat:                   f.apLat,
				Lon:                   f.apLon,
				UncertaintySemiMajorM: f.apUncertainty,
				UncertaintySemiMinorM: f.apUncertainty,
				ConfidencePct:         68,
			},
		})
		return report, "", nil

	default:
		return nil, "LOCATION_FAILURE",
			fmt.Errorf("fakeNRPPASender(ecidOK): unexpected msg type 0x%02x", pdu.Type)
	}
}

// hexToNRCGI converts a 9-character lowercase hex NR Cell Identity string to an NRCGI.
// This is the inverse of nrcgiToHex in nf/lmf/internal/server/ecid.go.
//
// The 36-bit cell identity is packed into the most significant 36 bits of the 5-byte
// CellID field (bottom 4 bits of byte 4 are always zero). PLMN bytes are left as zero
// because nrcgiToHex only uses the CellID bytes for the lookup key.
//
// Example: "000000010" (hex 16) → val=16, val<<4=256=0x100 → [0x00,0x00,0x00,0x01,0x00].
// Ref: TS 38.413 §9.3.1.x; nf/lmf/internal/server/ecid.go nrcgiToHex.
func hexToNRCGI(hexStr string) nrppa.NRCGI {
	val, _ := strconv.ParseUint(hexStr, 16, 64)
	val <<= 4 // shift left 4 to add the 4 zero-padding bits (byte 4 low nibble)
	return nrppa.NRCGI{
		CellID: [5]byte{
			byte(val >> 32),
			byte(val >> 24),
			byte(val >> 16),
			byte(val >> 8),
			byte(val),
		},
	}
}

// ---- ecidWorld ---------------------------------------------------------------
//
// ecidWorld holds per-scenario state for the NRPPa relay feature.
// It mirrors the subWorld pattern from event_subscription_steps_test.go.

// ecidWorld holds per-scenario state for the NRPPa relay / E-CID feature.
//
// It is also reused by the LPP relay / GNSS feature (LMF-005, lpp_relay.feature
// via lpp_relay_steps_test.go / initLPPRelaySteps) so that GNSS scenarios which
// fall back to E-CID or Cell-ID exercise the exact same server instance and
// AMF/UDM fakes as the LMF-004 scenarios — SetLPPClient and SetNRPPAClient are
// both wired onto every ecidWorld server. initNRPPARelaySteps returns *w so the
// LPP aggregator can extend the same world without re-registering any step that
// already matches lpp_relay.feature's Given text verbatim (e.g. the E-CID
// success/no-capability Given steps are shared verbatim between both features).
type ecidWorld struct {
	// nrppa is the configurable fake DLNRPPASender injected via SetNRPPAClient.
	// Always non-nil (initialised in the Before hook).
	nrppa *fakeNRPPASender

	// lpp is the configurable fake LPPSender injected via SetLPPClient (LMF-005).
	// Always non-nil (initialised in the Before hook). Unused (never called) by
	// pure NRPPa/E-CID scenarios because their hAccuracy values (100, 300) never
	// select methodLPP. Ref: nf/lmf/internal/server/lpp.go; lpp_relay_steps_test.go.
	lpp *fakeLPPSender

	// srv, ts, client are set by buildServer (lazy).
	srv    *lmfsrv.Server
	ts     *httptest.Server
	client *http.Client

	// ecidMetricBaseline holds fivegc_lmf_ecid_total values captured just before
	// the When step fires so assertions are independent of test ordering.
	ecidMetricBaseline map[string]float64

	// gnssMetricBaseline holds fivegc_lmf_gnss_total values captured just before
	// the When step fires (LMF-005). Ref: metrics.LMFGNSSTotal.
	gnssMetricBaseline map[string]float64

	// logBuf captures the LMF server's structured logs for this scenario so LPP
	// Then steps can assert on "UplinkLPP received" / per-SUPI lpp_state log
	// lines that are not otherwise observable through the HTTP response (the
	// per-SUPI state tracker entry is deleted via defer once the request
	// completes). Ref: lpp_relay_steps_test.go; nf/lmf/internal/server/lpp.go.
	logBuf *syncBuffer
}

// buildServer constructs and starts an in-process LMF server with SetNRPPAClient
// wired to w.nrppa. It reuses c.amf and c.udm so all existing Given steps
// ("the mock AMF returns a Namf LocationData ...", "subscriber location privacy ...")
// affect this server without re-registration.
//
// The cell-coordinate map includes the serving cell ("000000010") as the
// Cell-ID/fallback anchor; Scenario 1's E-CID fix instead comes directly from
// the gNB-reported NG-RANAccessPointPosition (see handleECIDSuccess), clamped
// to [50, 150] m (the Scenario 1 acceptance criterion — ecidUncertaintyMaxM=150).
// Ref: TS 23.273 §6.2.9; TS 38.455 §9 (NG-RANAccessPointPosition).
func (w *ecidWorld) buildServer(c *lmfCtx) {
	if w.ts != nil {
		return // idempotent
	}
	cfg := &lmfcfg.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.SBI.TLS.CertFile = ""
	cfg.SBI.TLS.KeyFile = ""
	cfg.SBI.TLS.CAFile = ""
	// "000000010" is the serving cell used in all scenarios (Cell-ID fallback anchor).
	cfg.CellCoordinates = map[string]lmfcfg.CellCoord{
		"000000010": {Lat: 40.416775, Lon: -3.703790}, // Madrid, Puerta del Sol
	}
	cfg.DefaultCoord = lmfcfg.CellCoord{Lat: 40.416775, Lon: -3.703790}
	// Disable motion model so locate() returns the static cell anchor deterministically.
	cfg.Mobility = lmfcfg.MobilityConfig{Enabled: false}
	// Privacy check enabled; c.udm defaults to ALLOW_ALL so existing scenarios pass.
	cfg.PrivacyCheck = true
	cfg.LocationSubscription = lmfcfg.LocationSubscriptionConfig{
		DefaultSamplingIntervalS:  5,
		DefaultReportingIntervalS: 10,
		MaxDurationS:              3600,
		NotificationRetry:         0,
	}

	// Logs are captured (not discarded) so LPP Then steps can assert on
	// "UplinkLPP received" / lpp_state log lines. Ref: lpp_relay_steps_test.go.
	logger := slog.New(slog.NewTextHandler(w.logBuf, nil))
	// Reuse c.amf and c.udm so Given steps that configure them affect this server.
	srv := lmfsrv.New(cfg, logger, c.amf, c.udm)
	// Wire the NRPPa relay fake — enables the E-CID path in handleDetermineLocation.
	// Ref: TS 23.273 §6.2.9; NRPPaRelay.md §SetNRPPAClient.
	srv.SetNRPPAClient(w.nrppa)
	// Wire the LPP relay fake — enables the GNSS path in handleDetermineLocation
	// (LMF-005). Never called by pure NRPPa scenarios (hAccuracy always >= 50 there).
	// Ref: TS 23.273 §6.2.10; nf/lmf/internal/server/lpp.go §SetLPPClient.
	srv.SetLPPClient(w.lpp)
	w.srv = srv
	w.ts = httptest.NewServer(srv.Handler())
	w.client = w.ts.Client()
}

// teardown closes the httptest server.
func (w *ecidWorld) teardown() {
	if w.ts != nil {
		w.ts.Close()
		w.ts = nil
	}
}

// postWithHAccuracy sends a DetermineLocation POST to the ecidWorld server, bridges
// the response into c (lmfCtx) for shared Then steps, and captures ECID metric baselines.
func (w *ecidWorld) postWithHAccuracy(c *lmfCtx, ueContextID, supi string, hAccuracy float64) error {
	body := map[string]any{
		"supi": supi,
		"locationQoS": map[string]any{
			"hAccuracy": hAccuracy,
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("postWithHAccuracy: marshal body: %w", err)
	}
	url := w.ts.URL + "/nlmf-loc/v1/ue-contexts/" + ueContextID + "/provide-loc-info"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("postWithHAccuracy: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("postWithHAccuracy: do request: %w", err)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Bridge into lmfCtx so shared Then steps (HTTP status, locationEstimate shape,
	// nrCellId, tac, ProblemDetails cause) work without re-registration.
	c.lastResp = resp
	c.lastRawBody = rawBody
	c.lastBody = nil
	if len(rawBody) > 0 {
		var m map[string]any
		if json.Unmarshal(rawBody, &m) == nil {
			c.lastBody = m
		}
	}
	return nil
}

// ---- initNRPPARelaySteps registers all NRPPa relay / E-CID step definitions.
//
// Called from InitializeScenario in determine_location_steps_test.go with the shared
// lmfCtx pointer c, following the same pattern as initEventSubscriptionSteps.
//
// Returns the *ecidWorld instance so the LPP relay aggregator (LMF-005,
// lpp_relay_steps_test.go initLPPRelaySteps) can extend the same world with an
// LPP fake + GNSS metric baselines, without re-registering any step whose
// regex is already matched verbatim by lpp_relay.feature's Given text.
//
// Ref: TS 38.455 §8; TS 38.413 §8.17.3; TS 23.273 §6.2.9; TS 29.572 §5.2.2.2.
func initNRPPARelaySteps(sc *godog.ScenarioContext, c *lmfCtx) *ecidWorld {
	w := &ecidWorld{}

	// ---- Before: reset ecidWorld for every scenario --------------------------
	// Runs after c.startScenario (which initialises c.amf / c.udm / c.ts) so the
	// ecidWorld is always fresh and separate.
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.nrppa = &fakeNRPPASender{} // mode defaults to nrppaModeRecordOnly (zero value)
		w.lpp = &fakeLPPSender{}     // mode defaults to lppModeRecordOnly (zero value)
		w.srv = nil
		w.ts = nil
		w.client = nil
		w.ecidMetricBaseline = make(map[string]float64)
		w.gnssMetricBaseline = make(map[string]float64)
		w.logBuf = &syncBuffer{}
		return ctx, nil
	})

	// ---- After: teardown ecidWorld server ------------------------------------
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.teardown()
		return ctx, nil
	})

	// =========================================================================
	// Background steps — NRPPa relay feature
	// =========================================================================

	// "a mock AMF is available for Namf_Location ProvideLocationInfo and Namf_Location dl-nrppa-info"
	// Both are already wired via c.amf (ProvideLocationInfo) and w.nrppa (dl-nrppa-info).
	// Nothing to do here — satisfied structurally.
	sc.Step(
		`^a mock AMF is available for Namf_Location ProvideLocationInfo and Namf_Location dl-nrppa-info$`,
		func() error { return nil },
	)

	// =========================================================================
	// Given steps
	// =========================================================================

	// Scenario 1 — E-CID success.
	// Configures fakeNRPPASender for the two-round happy path and seeds c.amf
	// with TAI data so performECIDOrFallback's ProvideLocationInfo call for TAI succeeds.
	// Ref: TS 38.455 §8.2 (PosInfoRsp) + §8.x (ECIDMeasurementReport); TS 23.273 §6.2.9.
	sc.Step(
		`^the mock AMF relays NRPPa for ueContextId "([^"]+)" with gNB capability "E-CID_SUPPORTED" and E-CIDMeasurementReport serving nrCellId "([^"]+)" plmn mcc "([^"]+)" mnc "([^"]+)" tac "([^"]+)" and AP position lat "([^"]+)" lon "([^"]+)" uncertainty "([^"]+)"$`,
		func(_, servingCellId, mcc, mnc, tac, latStr, lonStr, uncertaintyStr string) error {
			lat, err := strconv.ParseFloat(latStr, 64)
			if err != nil {
				return fmt.Errorf("bad AP position lat %q: %w", latStr, err)
			}
			lon, err := strconv.ParseFloat(lonStr, 64)
			if err != nil {
				return fmt.Errorf("bad AP position lon %q: %w", lonStr, err)
			}
			uncertainty, err := strconv.ParseFloat(uncertaintyStr, 64)
			if err != nil {
				return fmt.Errorf("bad AP position uncertainty %q: %w", uncertaintyStr, err)
			}
			// Configure the NRPPa fake for the E-CID success path.
			w.nrppa.mode = nrppaModeECIDSuccess
			w.nrppa.servingCellId = servingCellId
			w.nrppa.mcc = mcc
			w.nrppa.mnc = mnc
			w.nrppa.tac = tac
			w.nrppa.apLat = lat
			w.nrppa.apLon = lon
			w.nrppa.apUncertainty = uncertainty

			// Seed c.amf with TAI data so the ProvideLocationInfo call inside
			// performECIDOrFallback (for fetching TAI after centroid computation) succeeds.
			// The LocationEstimate.Point is set so the server returns it directly (non-zero).
			// Ref: NRPPaRelay.md §Information Elements (TAI from AMF ProvideLocationInfo).
			c.amf.mu.Lock()
			c.amf.mode = amfModeSuccess
			c.amf.locationData = &lmfsrv.LocationData{
				LocationEstimate: &lmfsrv.GeographicArea{
					Shape: "POINT",
					Point: &lmfsrv.LatLon{Lat: 40.416775, Lon: -3.703790},
				},
				NRCellId: servingCellId,
				Tai: &lmfsrv.TaiLoc{
					PlmnId: lmfsrv.PlmnID{MCC: mcc, MNC: mnc},
					Tac:    tac,
				},
			}
			c.amf.mu.Unlock()

			// Build the ecidWorld server now that we know NRPPa is needed.
			w.buildServer(c)
			return nil
		},
	)

	// Scenario 2 — timeout / guard-timer expiry.
	// SendDLNRPPa returns an error → LMF falls back to Cell-ID (FALLBACK_CELLID).
	// Ref: NRPPaRelay.md §Error table; TS 23.273 §6.2.9 (graceful downgrade on timeout).
	sc.Step(
		`^the mock AMF accepts dl-nrppa-info for ueContextId "([^"]+)" but never relays a UL NRPPa response$`,
		func(_ string) error {
			w.nrppa.mode = nrppaModeTimeout
			w.buildServer(c)
			return nil
		},
	)

	// Scenario 3 — gNB capability NONE.
	// Round 1 returns PositioningInformationResponse{ECIDSupported:false} → FALLBACK_CELLID.
	// The LMF must NOT attempt round 2.
	// Ref: TS 38.455 §8.2; TS 23.273 §6.2.9 (capability mismatch fallback).
	sc.Step(
		`^the mock AMF relays NRPPa for ueContextId "([^"]+)" with gNB capability "E-CID_NONE" and no E-CID measurement report$`,
		func(_ string) error {
			w.nrppa.mode = nrppaModeCapabilityNone
			w.buildServer(c)
			return nil
		},
	)

	// Scenarios 4 and 5 — record dl-nrppa-info calls (expect zero).
	// w.nrppa is already in record-only mode (zero value); this step exists for
	// readability and to initialise ecidMetricBaseline before the "not incremented" check.
	sc.Step(
		`^the mock AMF records any dl-nrppa-info calls it receives$`,
		func() error { return nil },
	)

	// =========================================================================
	// When step
	// =========================================================================

	// POST DetermineLocation with locationQoS.hAccuracy — the quality-driven selector
	// that triggers GNSS (hAccuracy < 50), E-CID (hAccuracy ∈ [50, 200]) or
	// Cell-ID (hAccuracy > 200 or absent). Builds the ecidWorld server lazily
	// (for scenarios where no Given step calls buildServer explicitly). Captures
	// both ECID (LMF-004) and GNSS (LMF-005) metric baselines around the
	// request so both features' metric assertions are order-independent.
	// Ref: TS 23.273 §6.2.9 / §6.2.10; TS 29.572 §5.2.2.2.
	sc.Step(
		`^an LCS consumer POSTs a DetermineLocation request for ueContextId "([^"]+)" with supi "([^"]+)" and locationQoS hAccuracy (\d+)$`,
		func(ueContextID, supi string, hAccuracy int) error {
			// Ensure the ecidWorld server is running (some scenarios skip explicit buildServer).
			w.buildServer(c)
			// Capture ECID metric baselines before request.
			for _, lbl := range []string{"OK", "FALLBACK_CELLID", "FAILURE"} {
				w.ecidMetricBaseline[lbl] = testutil.ToFloat64(
					metrics.LMFECIDTotal.WithLabelValues(lbl))
			}
			// Capture GNSS metric baselines before request (LMF-005).
			for _, lbl := range []string{"OK", "FALLBACK_ECID", "FALLBACK_CELLID", "FAILURE"} {
				w.gnssMetricBaseline[lbl] = testutil.ToFloat64(
					metrics.LMFGNSSTotal.WithLabelValues(lbl))
			}
			return w.postWithHAccuracy(c, ueContextID, supi, float64(hAccuracy))
		},
	)

	// =========================================================================
	// Then steps — positioningDataList
	// =========================================================================

	// "the response LocationData positioningDataList includes method "eCID""
	// Asserts that the E-CID positioning method was applied.
	// Ref: TS 29.572 §6.1.6.2.2 (positioningDataList); TS 23.273 §6.2.9.
	sc.Step(
		`^the response LocationData positioningDataList includes method "([^"]+)"$`,
		func(want string) error {
			if c.lastBody == nil {
				return fmt.Errorf("response body empty or non-JSON (raw: %s)", c.lastRawBody)
			}
			list, ok := c.lastBody["positioningDataList"].([]any)
			if !ok {
				return fmt.Errorf("positioningDataList missing or wrong type (body: %s)", c.lastRawBody)
			}
			for _, item := range list {
				if s, ok := item.(string); ok && s == want {
					return nil
				}
			}
			return fmt.Errorf("positioningDataList does not include %q (body: %s)", want, c.lastRawBody)
		},
	)

	// "the response LocationData positioningDataList does not include method "eCID""
	// Asserts that E-CID was NOT used (Cell-ID fallback or Cell-ID selection).
	// Ref: TS 29.572 §6.1.6.2.2; TS 23.273 §6.2.9.
	sc.Step(
		`^the response LocationData positioningDataList does not include method "([^"]+)"$`,
		func(notWant string) error {
			if c.lastBody == nil {
				// No body or parse failure → positioningDataList absent → OK.
				return nil
			}
			list, ok := c.lastBody["positioningDataList"].([]any)
			if !ok {
				// Field absent → OK (Cell-ID path does not populate positioningDataList).
				return nil
			}
			for _, item := range list {
				if s, ok := item.(string); ok && s == notWant {
					return fmt.Errorf(
						"positioningDataList unexpectedly includes %q (body: %s)", notWant, c.lastRawBody)
				}
			}
			return nil
		},
	)

	// =========================================================================
	// Then steps — locationEstimate
	// =========================================================================

	// "the response LocationData locationEstimate point has a non-null latitude and longitude"
	// Asserts that the POINT estimate contains a real WGS84 coordinate (not 0,0).
	// Ref: TS 29.572 §6.1.6.2.2 (GeographicArea POINT shape); TS 23.273 §6.2.9.
	sc.Step(
		`^the response LocationData locationEstimate point has a non-null latitude and longitude$`,
		func() error {
			if c.lastBody == nil {
				return fmt.Errorf("response body empty or non-JSON (raw: %s)", c.lastRawBody)
			}
			est, ok := c.lastBody["locationEstimate"].(map[string]any)
			if !ok {
				return fmt.Errorf("locationEstimate missing or wrong type (body: %s)", c.lastRawBody)
			}
			pt, ok := est["point"].(map[string]any)
			if !ok {
				return fmt.Errorf("locationEstimate.point missing or wrong type (body: %s)", c.lastRawBody)
			}
			lat, _ := pt["lat"].(float64)
			lon, _ := pt["lon"].(float64)
			if lat == 0 && lon == 0 {
				return fmt.Errorf(
					"locationEstimate.point is (0,0) — expected non-null WGS84 coordinate (body: %s)",
					c.lastRawBody)
			}
			return nil
		},
	)

	// "the response LocationData accuracy is at most 150"
	// Asserts that locationEstimate.uncertainty ≤ N metres.
	// For E-CID success: uncertainty is the weighted-RMS clamped to [50, 150] m.
	// Ref: TS 23.273 §6.2.9 (E-CID accuracy ≈ 50–150 m); TS 29.572 §6.1.6.2.2.
	sc.Step(
		`^the response LocationData accuracy is at most (\d+)$`,
		func(maxAccuracy int) error {
			if c.lastBody == nil {
				return fmt.Errorf("response body empty or non-JSON (raw: %s)", c.lastRawBody)
			}
			est, ok := c.lastBody["locationEstimate"].(map[string]any)
			if !ok {
				return fmt.Errorf("locationEstimate missing or wrong type (body: %s)", c.lastRawBody)
			}
			uncertainty, ok := est["uncertainty"].(float64)
			if !ok {
				return fmt.Errorf(
					"locationEstimate.uncertainty missing or wrong type (body: %s)", c.lastRawBody)
			}
			if uncertainty > float64(maxAccuracy) {
				return fmt.Errorf(
					"locationEstimate.uncertainty = %.2f m, want ≤ %d m (body: %s)",
					uncertainty, maxAccuracy, c.lastRawBody)
			}
			return nil
		},
	)

	// =========================================================================
	// Then steps — metric assertions (fivegc_lmf_ecid_total)
	// =========================================================================

	// "the metric fivegc_lmf_ecid_total with label result "OK" is incremented"
	// Delta assertion: current − baseline ≥ 1.
	// Ref: TS 23.273 §6.2.9; metrics.LMFECIDTotal.
	sc.Step(
		`^the metric fivegc_lmf_ecid_total with label result "([^"]+)" is incremented$`,
		func(result string) error {
			baseline := w.ecidMetricBaseline[result]
			current := testutil.ToFloat64(metrics.LMFECIDTotal.WithLabelValues(result))
			delta := current - baseline
			if delta < 1 {
				return fmt.Errorf(
					"fivegc_lmf_ecid_total{result=%q} delta=%g, want ≥1 (baseline=%.0f current=%.0f)",
					result, delta, baseline, current)
			}
			return nil
		},
	)

	// "the metric fivegc_lmf_ecid_total with label result "OK" is not incremented"
	// Delta assertion: current − baseline == 0.
	// Used by Scenario 5 to confirm the privacy gate fires before any E-CID attempt.
	// Ref: TS 23.273 §9.1 (privacy gate before positioning); TS 23.273 §6.2.9.
	sc.Step(
		`^the metric fivegc_lmf_ecid_total with label result "([^"]+)" is not incremented$`,
		func(result string) error {
			baseline := w.ecidMetricBaseline[result]
			current := testutil.ToFloat64(metrics.LMFECIDTotal.WithLabelValues(result))
			delta := current - baseline
			if delta != 0 {
				return fmt.Errorf(
					"fivegc_lmf_ecid_total{result=%q} delta=%g, want 0 (baseline=%.0f current=%.0f)",
					result, delta, baseline, current)
			}
			return nil
		},
	)

	// =========================================================================
	// Then steps — dl-nrppa-info call count
	// =========================================================================

	// "the mock AMF received no dl-nrppa-info calls"
	// Asserts that SendDLNRPPa was never invoked — confirms Cell-ID selection
	// (hAccuracy > 200) or privacy gate fires before NRPPa dispatch.
	// Ref: TS 23.273 §6.2.9 (method selection); TS 23.273 §9.1 (privacy gate).
	sc.Step(
		`^the mock AMF received no dl-nrppa-info calls$`,
		func() error {
			count := atomic.LoadInt32(&w.nrppa.callCount)
			if count != 0 {
				return fmt.Errorf(
					"expected 0 dl-nrppa-info (SendDLNRPPa) calls, got %d", count)
			}
			return nil
		},
	)

	return w
}
