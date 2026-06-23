//go:build functional

// Package features_test contains godog BDD step definitions for the LMF
// Nlmf_Location DetermineLocation procedure (TS 29.572 §5.2.2.2).
//
// Run with: go test -race -tags=functional ./nf/lmf/tests/...
//
// Architecture:
//
// Each scenario runs against a fresh in-process LMF server via
// httptest.NewServer(srv.Handler()) — plain HTTP, no TLS.
//
// The AMFLocationClient interface is injected with a configurable fake
// (fakeAMFClient) whose behaviour is set by Given steps before the When
// step fires. This mirrors exactly the mockAMFClient pattern from
// nf/lmf/internal/server/server_test.go.
//
// Metric assertions use prometheus/testutil.ToFloat64 to capture a
// before/after delta so scenarios are fully order-independent.
//
// Ref: TS 29.572 §5.2.2.2, TS 23.273 §7.2, TS 29.571 §5.2.4.1
package features_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus/testutil"

	lmfcfg "github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	lmfsrv "github.com/francurieses/claudia-5gc/nf/lmf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// ---- configurable fake AMF client --------------------------------------------

// amfMode enumerates the canned behaviours of the fake AMF client.
type amfMode int

const (
	amfModeSuccess      amfMode = iota // returns a valid LocationData
	amfModeNotFound                    // returns ErrUEContextNotFound + CONTEXT_NOT_FOUND
	amfModeLocationFail                // returns ErrLocationFailure + specified cause
	amfModeUnreachable                 // returns a connectivity error (ErrLocationFailure)
)

// fakeAMFClient is a test double for lmfsrv.AMFLocationClient.
// Configure mode, cause and locationData before the When step fires.
type fakeAMFClient struct {
	mu           sync.Mutex
	mode         amfMode
	cause        string               // returned on non-success modes
	locationData *lmfsrv.LocationData // returned on amfModeSuccess
}

// ProvideLocationInfo implements lmfsrv.AMFLocationClient.
func (f *fakeAMFClient) ProvideLocationInfo(_ context.Context, _ string) (*lmfsrv.LocationData, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch f.mode {
	case amfModeSuccess:
		return f.locationData, "", nil
	case amfModeNotFound:
		cause := f.cause
		if cause == "" {
			cause = "CONTEXT_NOT_FOUND"
		}
		return nil, cause, lmfsrv.ErrUEContextNotFound
	case amfModeLocationFail:
		cause := f.cause
		if cause == "" {
			cause = "LOCATION_FAILURE"
		}
		return nil, cause, fmt.Errorf("%w: cause %s", lmfsrv.ErrLocationFailure, cause)
	case amfModeUnreachable:
		// A connectivity error — wraps ErrLocationFailure so the handler maps to 504.
		return nil, "LOCATION_FAILURE", fmt.Errorf("%w: AMF unreachable", lmfsrv.ErrLocationFailure)
	default:
		return nil, "LOCATION_FAILURE", errors.New("fakeAMFClient: unhandled mode")
	}
}

// ---- per-scenario world -------------------------------------------------------

// lmfCtx holds state for a single godog scenario.
type lmfCtx struct {
	// amf is the configurable fake injected into the LMF server.
	amf *fakeAMFClient
	// ts is the httptest server wrapping the LMF handler (no TLS).
	ts *httptest.Server
	// client is the HTTP client used to drive the LMF.
	client *http.Client
	// lastResp is the HTTP response from the most recent When step.
	lastResp *http.Response
	// lastRawBody is the raw response body bytes.
	lastRawBody []byte
	// lastBody is the parsed JSON body (nil when body is empty or non-JSON).
	lastBody map[string]any
	// metricBaseline holds counters captured before the When step for delta assertions.
	metricBaseline map[string]float64
}

// startScenario is the Before hook — wires a fresh LMF server for every scenario.
func (c *lmfCtx) startScenario(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
	c.amf = &fakeAMFClient{mode: amfModeUnreachable} // safe default
	c.metricBaseline = make(map[string]float64)

	cfg := &lmfcfg.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	// Clear TLS paths so Handler() uses plain HTTP.
	cfg.SBI.TLS.CertFile = ""
	cfg.SBI.TLS.KeyFile = ""
	cfg.SBI.TLS.CAFile = ""
	// Seed a cell → coordinate mapping matching Scenario 1.
	cfg.CellCoordinates = map[string]lmfcfg.CellCoord{
		"000000010": {Lat: 40.416775, Lon: -3.703790},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := lmfsrv.New(cfg, logger, c.amf)
	c.ts = httptest.NewServer(srv.Handler())
	c.client = c.ts.Client()
	return ctx, nil
}

// stopScenario is the After hook — shuts down the httptest server.
func (c *lmfCtx) stopScenario(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
	if c.ts != nil {
		c.ts.Close()
		c.ts = nil
	}
	return ctx, nil
}

// ---- Background steps --------------------------------------------------------

// aCleanLMFInstanceIsRunning is satisfied by the Before hook.
func (c *lmfCtx) aCleanLMFInstanceIsRunning(_ string) error { return nil }

// lmfRegisteredWithNRF is a structural assertion — in-process tests skip real NRF.
func (c *lmfCtx) lmfRegisteredWithNRF(nfType, _ string) error {
	if nfType != "LMF" {
		return fmt.Errorf("expected nfType LMF, got %q", nfType)
	}
	return nil
}

// mockAMFAvailable — the fake AMF is already wired in startScenario.
func (c *lmfCtx) mockAMFAvailable() error { return nil }

// ---- Given steps — AMF mock configuration ------------------------------------

// givenMockAMFReturnsLocation wires the fake to return a successful LocationData
// for the given ueContextId.  The ueContextId is ignored in the fake because
// the feature file supplies the same ueContextId in both Given and When steps,
// so any call is accepted.
func (c *lmfCtx) givenMockAMFReturnsLocation(nrCellId, mcc, mnc, tac, _ string) error {
	c.amf.mu.Lock()
	defer c.amf.mu.Unlock()
	c.amf.mode = amfModeSuccess
	c.amf.locationData = &lmfsrv.LocationData{
		LocationEstimate: &lmfsrv.GeographicArea{
			Shape: "POINT",
			Point: &lmfsrv.LatLon{Lat: 0, Lon: 0},
		},
		NRCellId: nrCellId,
		Tai: &lmfsrv.TaiLoc{
			PlmnId: lmfsrv.PlmnID{MCC: mcc, MNC: mnc},
			Tac:    tac,
		},
		AgeOfLocationEstimate: 0,
	}
	return nil
}

// givenMockAMFReturns404 wires the fake to return ErrUEContextNotFound.
func (c *lmfCtx) givenMockAMFReturns404(_ string) error {
	c.amf.mu.Lock()
	defer c.amf.mu.Unlock()
	c.amf.mode = amfModeNotFound
	c.amf.cause = "CONTEXT_NOT_FOUND"
	return nil
}

// givenMockAMFReturns504 wires the fake to return ErrLocationFailure with
// the given cause (e.g. "LOCATION_FAILURE" or "UE_NOT_REACHABLE").
func (c *lmfCtx) givenMockAMFReturns504(cause, _ string) error {
	c.amf.mu.Lock()
	defer c.amf.mu.Unlock()
	c.amf.mode = amfModeLocationFail
	c.amf.cause = cause
	return nil
}

// givenMockAMFNotReachable wires the fake to return a connectivity error.
func (c *lmfCtx) givenMockAMFNotReachable() error {
	c.amf.mu.Lock()
	defer c.amf.mu.Unlock()
	c.amf.mode = amfModeUnreachable
	return nil
}

// ---- When steps ---------------------------------------------------------------

// captureMetricBaseline records the current counter values before the request
// fires so delta assertions are independent of test ordering.
func (c *lmfCtx) captureMetricBaseline() {
	for _, lbl := range []string{"OK", "FAILURE", "REJECT"} {
		c.metricBaseline[lbl] = testutil.ToFloat64(metrics.LMFLocateTotal.WithLabelValues(lbl))
	}
}

// whenLCSConsumerPOSTsWithSupi POSTs a DetermineLocation request carrying the given supi.
func (c *lmfCtx) whenLCSConsumerPOSTsWithSupi(ueContextID, supi string) error {
	c.captureMetricBaseline()
	return c.postLocInfo(ueContextID, map[string]string{"supi": supi})
}

// whenLCSConsumerPOSTsNoIdentity POSTs a DetermineLocation request with neither supi nor gpsi.
func (c *lmfCtx) whenLCSConsumerPOSTsNoIdentity(ueContextID string) error {
	c.captureMetricBaseline()
	return c.postLocInfo(ueContextID, map[string]string{})
}

// postLocInfo is the underlying HTTP helper used by all When steps.
func (c *lmfCtx) postLocInfo(ueContextID string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("postLocInfo: marshal body: %w", err)
	}
	url := c.ts.URL + "/nlmf-loc/v1/ue-contexts/" + ueContextID + "/provide-loc-info"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("postLocInfo: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("postLocInfo: do request: %w", err)
	}
	c.lastResp = resp
	c.lastRawBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	c.lastBody = nil
	if len(c.lastRawBody) > 0 {
		var m map[string]any
		if json.Unmarshal(c.lastRawBody, &m) == nil {
			c.lastBody = m
		}
	}
	return nil
}

// ---- Then steps — HTTP status ------------------------------------------------

func (c *lmfCtx) thenLMFRespondsWithStatus(want int) error {
	if c.lastResp == nil {
		return fmt.Errorf("no HTTP response captured — was a When step executed?")
	}
	if c.lastResp.StatusCode != want {
		return fmt.Errorf("HTTP status = %d, want %d (body: %s)",
			c.lastResp.StatusCode, want, c.lastRawBody)
	}
	return nil
}

// ---- Then steps — LocationData assertions ------------------------------------

func (c *lmfCtx) thenLocationDataContainsNRCellId(want string) error {
	if c.lastBody == nil {
		return fmt.Errorf("response body is empty or non-JSON (raw: %s)", c.lastRawBody)
	}
	got, _ := c.lastBody["nrCellId"].(string)
	if got != want {
		return fmt.Errorf("nrCellId = %q, want %q (body: %s)", got, want, c.lastRawBody)
	}
	return nil
}

func (c *lmfCtx) thenLocationDataContainsTaiWithTac(want string) error {
	if c.lastBody == nil {
		return fmt.Errorf("response body is empty or non-JSON (raw: %s)", c.lastRawBody)
	}
	tai, ok := c.lastBody["tai"].(map[string]any)
	if !ok {
		return fmt.Errorf("tai field missing or wrong type (body: %s)", c.lastRawBody)
	}
	got, _ := tai["tac"].(string)
	if got != want {
		return fmt.Errorf("tai.tac = %q, want %q (body: %s)", got, want, c.lastRawBody)
	}
	return nil
}

func (c *lmfCtx) thenLocationEstimateHasShape(want string) error {
	if c.lastBody == nil {
		return fmt.Errorf("response body is empty or non-JSON (raw: %s)", c.lastRawBody)
	}
	est, ok := c.lastBody["locationEstimate"].(map[string]any)
	if !ok {
		return fmt.Errorf("locationEstimate field missing or wrong type (body: %s)", c.lastRawBody)
	}
	got, _ := est["shape"].(string)
	if got != want {
		return fmt.Errorf("locationEstimate.shape = %q, want %q (body: %s)", got, want, c.lastRawBody)
	}
	return nil
}

func (c *lmfCtx) thenAgeOfLocationEstimateIsZero() error {
	if c.lastBody == nil {
		return fmt.Errorf("response body is empty or non-JSON (raw: %s)", c.lastRawBody)
	}
	// JSON numbers decode as float64 by default.
	age, ok := c.lastBody["ageOfLocationEstimate"].(float64)
	if !ok {
		return fmt.Errorf("ageOfLocationEstimate field missing or wrong type (body: %s)", c.lastRawBody)
	}
	if age != 0 {
		return fmt.Errorf("ageOfLocationEstimate = %g, want 0 (body: %s)", age, c.lastRawBody)
	}
	return nil
}

// ---- Then steps — ProblemDetails assertions ----------------------------------

func (c *lmfCtx) thenProblemDetailsCauseIs(want string) error {
	if c.lastBody == nil {
		return fmt.Errorf("response body is empty or non-JSON (raw: %s)", c.lastRawBody)
	}
	got, _ := c.lastBody["cause"].(string)
	if got != want {
		return fmt.Errorf("ProblemDetails.cause = %q, want %q (body: %s)", got, want, c.lastRawBody)
	}
	return nil
}

// ---- Then steps — metric delta assertions ------------------------------------

// thenMetricIsIncremented asserts that the named label counter increased by
// exactly 1 since the baseline captured in the When step.
func (c *lmfCtx) thenMetricIsIncremented(_, result string) error {
	baseline, ok := c.metricBaseline[result]
	if !ok {
		// Label not in baseline — treat as 0 (first request in process).
		baseline = 0
	}
	current := testutil.ToFloat64(metrics.LMFLocateTotal.WithLabelValues(result))
	delta := current - baseline
	if delta != 1 {
		return fmt.Errorf("fivegc_lmf_locate_total{result=%q} delta = %g, want 1 (baseline=%.0f current=%.0f)",
			result, delta, baseline, current)
	}
	return nil
}

// ---- godog wiring -----------------------------------------------------------

// InitializeScenario wires all step definitions to the godog scenario context.
func InitializeScenario(sc *godog.ScenarioContext) {
	c := &lmfCtx{}

	sc.Before(c.startScenario)
	sc.After(c.stopScenario)

	// --- Background ---
	sc.Step(
		`^a clean LMF instance is running on SBI port (\d+)$`,
		func(port string) error { return c.aCleanLMFInstanceIsRunning(port) },
	)
	sc.Step(
		`^the LMF has registered with nfType "([^"]+)" and service "([^"]+)" in the NRF$`,
		c.lmfRegisteredWithNRF,
	)
	sc.Step(
		`^a mock AMF is available for Namf_Location ProvideLocationInfo$`,
		func() error { return c.mockAMFAvailable() },
	)

	// --- Given — mock AMF happy path ---
	// "the mock AMF returns a Namf LocationData with nrCellId "000000010" and tai plmnId mcc "001" mnc "01" tac "0001" for ueContextId "imsi-..."
	sc.Step(
		`^the mock AMF returns a Namf LocationData with nrCellId "([^"]+)" and tai plmnId mcc "([^"]+)" mnc "([^"]+)" tac "([^"]+)" for ueContextId "([^"]+)"$`,
		c.givenMockAMFReturnsLocation,
	)

	// --- Given — mock AMF 404 ---
	// "the mock AMF returns 404 with cause "CONTEXT_NOT_FOUND" for ueContextId "..."
	sc.Step(
		`^the mock AMF returns 404 with cause "([^"]+)" for ueContextId "([^"]+)"$`,
		c.givenMockAMFReturns404,
	)

	// --- Given — mock AMF 504 with specific cause ---
	// "the mock AMF returns 504 with cause "LOCATION_FAILURE" for ueContextId "..."
	sc.Step(
		`^the mock AMF returns 504 with cause "([^"]+)" for ueContextId "([^"]+)"$`,
		c.givenMockAMFReturns504,
	)

	// --- Given — mock AMF unreachable ---
	sc.Step(
		`^the mock AMF is not reachable$`,
		c.givenMockAMFNotReachable,
	)

	// --- When — POST with supi ---
	// "an LCS consumer POSTs a DetermineLocation request for ueContextId "..." with supi "..."
	sc.Step(
		`^an LCS consumer POSTs a DetermineLocation request for ueContextId "([^"]+)" with supi "([^"]+)"$`,
		c.whenLCSConsumerPOSTsWithSupi,
	)

	// --- When — POST with neither supi nor gpsi ---
	// "an LCS consumer POSTs a DetermineLocation request for ueContextId "..." with neither supi nor gpsi in the request body"
	sc.Step(
		`^an LCS consumer POSTs a DetermineLocation request for ueContextId "([^"]+)" with neither supi nor gpsi in the request body$`,
		c.whenLCSConsumerPOSTsNoIdentity,
	)

	// --- Then — HTTP status ---
	sc.Step(
		`^the LMF responds with HTTP status (\d+)$`,
		c.thenLMFRespondsWithStatus,
	)

	// --- Then — LocationData fields ---
	sc.Step(
		`^the response LocationData contains nrCellId "([^"]+)"$`,
		c.thenLocationDataContainsNRCellId,
	)
	sc.Step(
		`^the response LocationData contains tai with tac "([^"]+)"$`,
		c.thenLocationDataContainsTaiWithTac,
	)
	sc.Step(
		`^the response locationEstimate has shape "([^"]+)"$`,
		c.thenLocationEstimateHasShape,
	)
	sc.Step(
		`^the response ageOfLocationEstimate is 0$`,
		c.thenAgeOfLocationEstimateIsZero,
	)

	// --- Then — ProblemDetails cause ---
	sc.Step(
		`^the response ProblemDetails cause is "([^"]+)"$`,
		c.thenProblemDetailsCauseIs,
	)

	// --- Then — metric delta ---
	// "the metric fivegc_lmf_locate_total with label result "OK" is incremented"
	sc.Step(
		`^the metric (fivegc_lmf_locate_total) with label result "([^"]+)" is incremented$`,
		c.thenMetricIsIncremented,
	)
}

// TestFeatures is the godog test suite entry point.
func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"./"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}

// TestMain is the test binary entry point.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
