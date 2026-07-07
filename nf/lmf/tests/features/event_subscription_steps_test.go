//go:build functional

// Package features_test — godog BDD step definitions for the LMF
// Nlmf_Location EventSubscription and CancelLocation procedures.
//
// This file is in the same package as determine_location_steps_test.go.
// It is wired into the godog suite by a single call to
//
//	initEventSubscriptionSteps(sc, c)
//
// at the bottom of InitializeScenario in determine_location_steps_test.go,
// following the same pattern as AMF tests (initAMFSBISteps / initNSSAASteps).
//
// Architecture:
//
//   - Each scenario gets a fresh LMF server built with NewWithNotifClient,
//     injecting a captureNotifSink (mock NotificationClient).
//   - The subWorld struct holds per-scenario state. When steps write their
//     HTTP response into BOTH subWorld.lastResp and the parent lmfCtx.lastResp
//     so that the shared "the LMF responds with HTTP status N" and
//     "the response ProblemDetails cause is" step handlers (registered in
//     determine_location_steps_test.go against lmfCtx) work for sub scenarios too.
//   - Timing-sensitive steps (periodic notification, AOI boundary crossing) poll
//     with a bounded deadline instead of fixed sleeps.
//   - The After hook calls srv.Shutdown() to cancel all subscription goroutines
//     before the next scenario starts, preventing goroutine leaks.
//
// Ref: TS 29.572 §5.2.3, §5.2.2.5, §6.1.6.2.4, §6.1.6.2.2.
// Ref: TS 23.273 §7.2 step B2 (deferred location subscription).
// Ref: TS 29.571 §5.2 (subscription resource schema).
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus/testutil"

	lmfcfg "github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	lmfsrv "github.com/francurieses/claudia-5gc/nf/lmf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// ---- mock notification sink --------------------------------------------------

// captureNotifSink is a mock NotificationClient that records every
// LocationNotification it receives. Safe for concurrent use.
type captureNotifSink struct {
	mu    sync.Mutex
	items []lmfsrv.LocationNotification
}

// PostNotification implements lmfsrv.NotificationClient.
func (s *captureNotifSink) PostNotification(_ context.Context, _ string, n lmfsrv.LocationNotification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, n)
	return nil
}

// count returns the number of received notifications.
func (s *captureNotifSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// snapshot returns a copy of the captured notifications.
func (s *captureNotifSink) snapshot() []lmfsrv.LocationNotification {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]lmfsrv.LocationNotification, len(s.items))
	copy(cp, s.items)
	return cp
}

// ---- static AMF client -------------------------------------------------------

// staticAMFForSub is a simple AMFLocationClient returning a fixed LocationData.
// Thread-safe for concurrent subscription goroutine calls.
type staticAMFForSub struct {
	mu   sync.Mutex
	data *lmfsrv.LocationData
}

// ProvideLocationInfo implements lmfsrv.AMFLocationClient.
func (a *staticAMFForSub) ProvideLocationInfo(_ context.Context, _ string) (*lmfsrv.LocationData, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.data == nil {
		return nil, "LOCATION_FAILURE", fmt.Errorf("staticAMFForSub: not configured")
	}
	cp := *a.data
	return &cp, "", nil
}

// ---- scripted AMF client for AOI scenario ------------------------------------

// scriptedPosition is one entry in the scripted AMF position sequence.
type scriptedPosition struct {
	lat, lon    float64
	description string
}

// scriptedAMFClient returns positions from a scripted sequence. Once exhausted
// it repeats the last position. Thread-safe.
type scriptedAMFClient struct {
	positions []scriptedPosition
	idx       atomic.Int32
	nrCellId  string
	mcc, mnc  string
	tac       string
}

// ProvideLocationInfo implements lmfsrv.AMFLocationClient.
func (c *scriptedAMFClient) ProvideLocationInfo(_ context.Context, _ string) (*lmfsrv.LocationData, string, error) {
	raw := c.idx.Add(1) - 1
	idx := int(raw)
	if idx >= len(c.positions) {
		idx = len(c.positions) - 1
	}
	p := c.positions[idx]
	return &lmfsrv.LocationData{
		LocationEstimate: &lmfsrv.GeographicArea{
			Shape: "POINT",
			Point: &lmfsrv.LatLon{Lat: p.lat, Lon: p.lon},
		},
		NRCellId: c.nrCellId,
		Tai: &lmfsrv.TaiLoc{
			PlmnId: lmfsrv.PlmnID{MCC: c.mcc, MNC: c.mnc},
			Tac:    c.tac,
		},
	}, "", nil
}

// ---- per-scenario event-subscription world -----------------------------------

// subWorld holds per-scenario state for the EventSubscription feature.
// It is reset in the Before hook of initEventSubscriptionSteps.
type subWorld struct {
	// srv is the LMF server under test.
	srv *lmfsrv.Server
	// ts is the httptest server wrapping srv.Handler().
	ts *httptest.Server
	// client is the plain HTTP client for step helpers.
	client *http.Client
	// sink is the mock NotificationClient injected into the LMF server.
	sink *captureNotifSink
	// amf is the mock AMF client; set by Given steps, defaulting to staticAMFForSub.
	amf lmfsrv.AMFLocationClient
	// polygon is the AOI polygon parsed by the polygon-vertices Given step.
	polygon []map[string]float64
	// lastResp is the HTTP response captured by the most recent When step.
	lastResp *http.Response
	// lastRawBody is the raw response body bytes.
	lastRawBody []byte
	// lastBody is the parsed JSON response body (nil when empty / non-JSON).
	lastBody map[string]any
	// createdSubId is the subId returned by the Create subscription step.
	createdSubId string
	// sinkCountBefore is captured just before the DELETE step for silence checks.
	sinkCountBefore int
	// subCreateRejectBaseline is the REJECT counter value before the When step.
	subCreateRejectBaseline float64
}

// buildServer constructs and starts an in-process LMF server with the current
// amf and sink. Called lazily from When steps so Given steps can configure the
// AMF first.
func (w *subWorld) buildServer() {
	cfg := &lmfcfg.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	// Disable TLS so Handler() uses plain HTTP.
	cfg.SBI.TLS.CertFile = ""
	cfg.SBI.TLS.KeyFile = ""
	cfg.SBI.TLS.CAFile = ""
	cfg.CellCoordinates = map[string]lmfcfg.CellCoord{
		"000000010": {Lat: 40.4168, Lon: -3.7038},
	}
	cfg.DefaultCoord = lmfcfg.CellCoord{Lat: 40.4168, Lon: -3.7038}
	// Static coordinates — no random walk so tests are deterministic.
	cfg.Mobility = lmfcfg.MobilityConfig{Enabled: false}
	cfg.LocationSubscription = lmfcfg.LocationSubscriptionConfig{
		DefaultSamplingIntervalS:  5,
		DefaultReportingIntervalS: 10,
		MaxDurationS:              3600,
		NotificationRetry:         0, // no retry — simplifies timing assertions
	}
	// Privacy check disabled: no UDM client injected.
	cfg.PrivacyCheck = false

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w.sink = &captureNotifSink{}
	w.srv = lmfsrv.NewWithNotifClient(cfg, logger, w.amf, nil, w.sink)
	w.ts = httptest.NewServer(w.srv.Handler())
	w.client = w.ts.Client()
}

// teardown shuts down the server, draining subscription goroutines, then
// closes the httptest server. Called in the After hook.
func (w *subWorld) teardown() {
	if w.ts != nil {
		w.ts.Close()
		w.ts = nil
	}
	if w.srv != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = w.srv.Shutdown(shutCtx)
		w.srv = nil
	}
}

// captureResponse reads the HTTP response and stores it in both the subWorld
// and the parent lmfCtx so that shared step handlers (HTTP status,
// ProblemDetails cause) also see the sub-world response.
func (w *subWorld) captureResponse(resp *http.Response, c *lmfCtx) {
	w.lastResp = resp
	w.lastRawBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	w.lastBody = nil
	if len(w.lastRawBody) > 0 {
		var m map[string]any
		if json.Unmarshal(w.lastRawBody, &m) == nil {
			w.lastBody = m
		}
	}

	// Bridge into the parent lmfCtx so that shared "LMF responds with HTTP
	// status" and "ProblemDetails cause" step handlers work for sub scenarios.
	if c != nil {
		c.lastResp = w.lastResp
		c.lastRawBody = w.lastRawBody
		c.lastBody = w.lastBody
	}

	// Extract subId from response body when present.
	if w.lastBody != nil {
		if id, ok := w.lastBody["subId"].(string); ok && id != "" {
			w.createdSubId = id
		}
	}
}

// postSubscription sends POST /nlmf-loc/v1/subscriptions with the given body.
func (w *subWorld) postSubscription(b map[string]any, c *lmfCtx) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("postSubscription: marshal: %w", err)
	}
	url := w.ts.URL + "/nlmf-loc/v1/subscriptions"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("postSubscription: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("postSubscription: do: %w", err)
	}
	w.captureResponse(resp, c)
	return nil
}

// doGet sends GET /nlmf-loc/v1/subscriptions/{subId}.
func (w *subWorld) doGet(subId string, c *lmfCtx) error {
	url := w.ts.URL + "/nlmf-loc/v1/subscriptions/" + subId
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("doGet: new request: %w", err)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("doGet: do: %w", err)
	}
	w.captureResponse(resp, c)
	return nil
}

// doDelete sends DELETE /nlmf-loc/v1/subscriptions/{subId}.
func (w *subWorld) doDelete(subId string, c *lmfCtx) error {
	url := w.ts.URL + "/nlmf-loc/v1/subscriptions/" + subId
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("doDelete: new request: %w", err)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("doDelete: do: %w", err)
	}
	w.captureResponse(resp, c)
	return nil
}

// doCancelLocation sends POST /nlmf-loc/v1/ue-contexts/{id}/cancel-loc.
func (w *subWorld) doCancelLocation(ueContextId string, c *lmfCtx) error {
	url := w.ts.URL + "/nlmf-loc/v1/ue-contexts/" + ueContextId + "/cancel-loc"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("doCancelLocation: new request: %w", err)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("doCancelLocation: do: %w", err)
	}
	w.captureResponse(resp, c)
	return nil
}

// pollSinkCount polls until sink.count() >= target within deadline, or returns false.
func pollSinkCount(sink *captureNotifSink, target int, deadline time.Duration) (int, bool) {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if sink.count() >= target {
			return sink.count(), true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return sink.count(), sink.count() >= target
}

// defaultStaticAMF builds the happy-path static AMF returning nrCellId "000000010".
func defaultStaticAMF() *staticAMFForSub {
	return &staticAMFForSub{
		data: &lmfsrv.LocationData{
			LocationEstimate: &lmfsrv.GeographicArea{
				Shape: "POINT",
				Point: &lmfsrv.LatLon{Lat: 40.4168, Lon: -3.7038},
			},
			NRCellId: "000000010",
			Tai: &lmfsrv.TaiLoc{
				PlmnId: lmfsrv.PlmnID{MCC: "001", MNC: "01"},
				Tac:    "0001",
			},
		},
	}
}

// parsePolygon parses "lat,lon lat,lon …" vertices (supports U+2212 minus sign).
func parsePolygon(verticesStr string) ([]map[string]float64, error) {
	// Normalise Unicode MINUS SIGN (U+2212 '−') → ASCII hyphen-minus (U+002D '-').
	verticesStr = strings.ReplaceAll(verticesStr, "−", "-")
	parts := strings.Fields(verticesStr)
	if len(parts) == 0 {
		return nil, fmt.Errorf("parsePolygon: empty vertices string")
	}
	out := make([]map[string]float64, 0, len(parts))
	for _, p := range parts {
		// Split on the last comma to handle negative longitude correctly.
		lastComma := strings.LastIndex(p, ",")
		if lastComma < 0 {
			return nil, fmt.Errorf("parsePolygon: bad vertex %q (no comma)", p)
		}
		latStr := p[:lastComma]
		lonStr := p[lastComma+1:]
		var lat, lon float64
		if _, err := fmt.Sscanf(latStr, "%f", &lat); err != nil {
			return nil, fmt.Errorf("parsePolygon: bad lat %q: %w", latStr, err)
		}
		if _, err := fmt.Sscanf(lonStr, "%f", &lon); err != nil {
			return nil, fmt.Errorf("parsePolygon: bad lon %q: %w", lonStr, err)
		}
		out = append(out, map[string]float64{"lat": lat, "lon": lon})
	}
	return out, nil
}

// ---- notifUri helper ---------------------------------------------------------

// mockNotifUri returns the notification URI pointing to the mock sink.
// The LMF's captureNotifSink ignores the URI (it captures all calls), so any
// non-empty URI is acceptable. We use a plausible URL so log lines look sensible.
func mockNotifUri(ts *httptest.Server) string {
	return ts.URL + "/mock-notify"
}

// ---- initEventSubscriptionSteps registers all EventSubscription step definitions.
//
// Called from InitializeScenario in determine_location_steps_test.go with the
// shared lmfCtx pointer c, so that When steps can bridge their responses into c
// and the shared "LMF responds with HTTP status" / "ProblemDetails cause" handlers
// (already registered for c) work correctly for sub scenarios.
//
// Ref: pattern from AMF tests: initAMFSBISteps / initNSSAASteps.
func initEventSubscriptionSteps(sc *godog.ScenarioContext, c *lmfCtx) {
	w := &subWorld{}

	// ---- Before: reset the sub world for every scenario ----------------------
	sc.Before(func(ctx context.Context, scenario *godog.Scenario) (context.Context, error) {
		// Reset sub world state regardless of feature file, so the world is clean.
		// The determine_location Before hook (c.startScenario) already built the
		// determine_location LMF server for non-sub scenarios; we don't interfere.
		w.lastResp = nil
		w.lastRawBody = nil
		w.lastBody = nil
		w.createdSubId = ""
		w.sinkCountBefore = 0
		w.polygon = nil
		w.sink = nil
		w.srv = nil
		w.ts = nil
		w.client = nil
		// Default AMF — happy path. Given steps can override before buildServer().
		w.amf = defaultStaticAMF()
		w.subCreateRejectBaseline = testutil.ToFloat64(
			metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT"))
		return ctx, nil
	})

	// ---- After: shut down the sub server to drain goroutines -----------------
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.teardown()
		return ctx, nil
	})

	// =========================================================================
	// Background steps (event_subscription.feature)
	// =========================================================================

	// "a mock notification sink server is running to receive LocationNotification callbacks"
	// The sink is wired at buildServer() time — nothing to do here.
	sc.Step(
		`^a mock notification sink server is running to receive LocationNotification callbacks$`,
		func() error { return nil },
	)

	// =========================================================================
	// Given steps
	// =========================================================================

	// "the mock AMF returns a scripted sequence of LocationData positions for ueContextId "...":
	//   | lat | lon | description |"
	// Used by Scenario 4 (AOI with scripted movement).
	sc.Step(
		`^the mock AMF returns a scripted sequence of LocationData positions for ueContextId "([^"]+)":$`,
		func(ueContextId string, table *godog.Table) error {
			var positions []scriptedPosition
			for i, row := range table.Rows {
				if i == 0 {
					continue // skip header row
				}
				if len(row.Cells) < 2 {
					return fmt.Errorf("scripted sequence: row %d has too few cells", i)
				}
				var lat, lon float64
				if _, err := fmt.Sscanf(row.Cells[0].Value, "%f", &lat); err != nil {
					return fmt.Errorf("scripted sequence: bad lat %q: %w", row.Cells[0].Value, err)
				}
				if _, err := fmt.Sscanf(row.Cells[1].Value, "%f", &lon); err != nil {
					return fmt.Errorf("scripted sequence: bad lon %q: %w", row.Cells[1].Value, err)
				}
				desc := ""
				if len(row.Cells) >= 3 {
					desc = row.Cells[2].Value
				}
				positions = append(positions, scriptedPosition{lat: lat, lon: lon, description: desc})
			}
			if len(positions) == 0 {
				return fmt.Errorf("scripted sequence: no position rows in table")
			}
			w.amf = &scriptedAMFClient{
				positions: positions,
				nrCellId:  "000000010",
				mcc:       "001",
				mnc:       "01",
				tac:       "0001",
			}
			return nil
		},
	)

	// "an LCS consumer has created a subscription with ueContextId "..." supi "..."
	//  eventTrigger "PERIODIC_REPORTING" reportingInterval N and notificationUri pointing to the mock sink"
	// (Given variant — pre-conditions a subscription before the main When step.)
	sc.Step(
		`^an LCS consumer has created a subscription with ueContextId "([^"]+)" supi "([^"]+)" eventTrigger "([^"]+)" reportingInterval (\d+) and notificationUri pointing to the mock sink$`,
		func(ueContextId, supi, eventTrigger string, reportingInterval int) error {
			if w.ts == nil {
				w.buildServer()
			}
			b := map[string]any{
				"ueContextId":       ueContextId,
				"supi":              supi,
				"eventTrigger":      eventTrigger,
				"notificationUri":   mockNotifUri(w.ts),
				"reportingInterval": reportingInterval,
			}
			if err := w.postSubscription(b, c); err != nil {
				return err
			}
			if w.lastResp.StatusCode != http.StatusCreated {
				return fmt.Errorf("Given create subscription: expected 201, got %d (body: %s)",
					w.lastResp.StatusCode, w.lastRawBody)
			}
			return nil
		},
	)

	// "the mock sink has received at least 1 LocationNotification"
	// (Given variant — blocks until ≥1 notification arrives as a pre-condition.)
	sc.Step(
		`^the mock sink has received at least 1 LocationNotification$`,
		func() error {
			if w.sink == nil {
				return fmt.Errorf("mock sink not initialized (was the server started?)")
			}
			_, ok := pollSinkCount(w.sink, 1, 8*time.Second)
			if !ok {
				return fmt.Errorf("Given: mock sink has not received a notification within 8 s")
			}
			// Snapshot count for use in the silence-check Then step.
			w.sinkCountBefore = w.sink.count()
			return nil
		},
	)

	// =========================================================================
	// When steps
	// =========================================================================

	// POST subscription — PERIODIC_REPORTING with reportingInterval
	// "an LCS consumer POSTs a subscription with ueContextId "..." supi "..."
	//  eventTrigger "..." reportingInterval N and notificationUri pointing to the mock sink"
	sc.Step(
		`^an LCS consumer POSTs a subscription with ueContextId "([^"]+)" supi "([^"]+)" eventTrigger "([^"]+)" reportingInterval (\d+) and notificationUri pointing to the mock sink$`,
		func(ueContextId, supi, eventTrigger string, reportingInterval int) error {
			if w.ts == nil {
				w.buildServer()
			}
			w.subCreateRejectBaseline = testutil.ToFloat64(
				metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT"))
			b := map[string]any{
				"ueContextId":       ueContextId,
				"supi":              supi,
				"eventTrigger":      eventTrigger,
				"notificationUri":   mockNotifUri(w.ts),
				"reportingInterval": reportingInterval,
			}
			return w.postSubscription(b, c)
		},
	)

	// POST subscription — AREA_OF_INTEREST with polygon vertices (no samplingInterval)
	// "an LCS consumer POSTs a subscription with ueContextId "..." supi "..."
	//  eventTrigger "..." polygon vertices "..." and notificationUri pointing to the mock sink"
	sc.Step(
		`^an LCS consumer POSTs a subscription with ueContextId "([^"]+)" supi "([^"]+)" eventTrigger "([^"]+)" polygon vertices "([^"]+)" and notificationUri pointing to the mock sink$`,
		func(ueContextId, supi, eventTrigger, verticesStr string) error {
			if w.ts == nil {
				w.buildServer()
			}
			w.subCreateRejectBaseline = testutil.ToFloat64(
				metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT"))
			poly, err := parsePolygon(verticesStr)
			if err != nil {
				return err
			}
			w.polygon = poly
			b := map[string]any{
				"ueContextId":     ueContextId,
				"supi":            supi,
				"eventTrigger":    eventTrigger,
				"notificationUri": mockNotifUri(w.ts),
				"areaOfInterest": map[string]any{
					"polygon": poly,
				},
			}
			return w.postSubscription(b, c)
		},
	)

	// POST subscription — AREA_OF_INTEREST with polygon + samplingInterval
	// "an LCS consumer POSTs a subscription with ueContextId "..." supi "..."
	//  eventTrigger "..." polygon vertices "..." samplingInterval N and notificationUri pointing to the mock sink"
	sc.Step(
		`^an LCS consumer POSTs a subscription with ueContextId "([^"]+)" supi "([^"]+)" eventTrigger "([^"]+)" polygon vertices "([^"]+)" samplingInterval (\d+) and notificationUri pointing to the mock sink$`,
		func(ueContextId, supi, eventTrigger, verticesStr string, samplingInterval int) error {
			if w.ts == nil {
				w.buildServer()
			}
			w.subCreateRejectBaseline = testutil.ToFloat64(
				metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT"))
			poly, err := parsePolygon(verticesStr)
			if err != nil {
				return err
			}
			w.polygon = poly
			b := map[string]any{
				"ueContextId":      ueContextId,
				"supi":             supi,
				"eventTrigger":     eventTrigger,
				"notificationUri":  mockNotifUri(w.ts),
				"samplingInterval": samplingInterval,
				"areaOfInterest": map[string]any{
					"polygon": poly,
				},
			}
			return w.postSubscription(b, c)
		},
	)

	// POST subscription — missing notificationUri (error scenario)
	// "an LCS consumer POSTs a subscription with ueContextId "..." supi "..."
	//  eventTrigger "..." and no notificationUri"
	sc.Step(
		`^an LCS consumer POSTs a subscription with ueContextId "([^"]+)" supi "([^"]+)" eventTrigger "([^"]+)" and no notificationUri$`,
		func(ueContextId, supi, eventTrigger string) error {
			if w.ts == nil {
				w.buildServer()
			}
			w.subCreateRejectBaseline = testutil.ToFloat64(
				metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT"))
			b := map[string]any{
				"ueContextId":  ueContextId,
				"supi":         supi,
				"eventTrigger": eventTrigger,
				// intentionally omitting notificationUri
			}
			return w.postSubscription(b, c)
		},
	)

	// POST subscription — unknown eventTrigger value (error scenario)
	// "an LCS consumer POSTs a subscription with ueContextId "..." supi "..."
	//  eventTrigger "CONTINUOUS_STREAMING" and notificationUri pointing to the mock sink"
	sc.Step(
		`^an LCS consumer POSTs a subscription with ueContextId "([^"]+)" supi "([^"]+)" eventTrigger "([^"]+)" and notificationUri pointing to the mock sink$`,
		func(ueContextId, supi, eventTrigger string) error {
			if w.ts == nil {
				w.buildServer()
			}
			w.subCreateRejectBaseline = testutil.ToFloat64(
				metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT"))
			b := map[string]any{
				"ueContextId":     ueContextId,
				"supi":            supi,
				"eventTrigger":    eventTrigger,
				"notificationUri": mockNotifUri(w.ts),
			}
			return w.postSubscription(b, c)
		},
	)

	// GET the subscription by the subId returned from the Create step
	// "an LCS consumer GETs the subscription resource at the returned subId"
	sc.Step(
		`^an LCS consumer GETs the subscription resource at the returned subId$`,
		func() error {
			if w.createdSubId == "" {
				return fmt.Errorf("GET: no createdSubId — was a Create subscription step executed?")
			}
			return w.doGet(w.createdSubId, c)
		},
	)

	// GET the subscription by an explicit (unknown) subId
	// "an LCS consumer GETs the subscription resource at subId "01NONEXISTENT0000000000000""
	sc.Step(
		`^an LCS consumer GETs the subscription resource at subId "([^"]+)"$`,
		func(subId string) error {
			if w.ts == nil {
				w.buildServer()
			}
			return w.doGet(subId, c)
		},
	)

	// DELETE the subscription by the subId returned from the Create step
	// "an LCS consumer DELETEs the subscription at the returned subId"
	sc.Step(
		`^an LCS consumer DELETEs the subscription at the returned subId$`,
		func() error {
			if w.createdSubId == "" {
				return fmt.Errorf("DELETE: no createdSubId — was a Create subscription step executed?")
			}
			// Snapshot count before DELETE for the silence-check Then step.
			w.sinkCountBefore = w.sink.count()
			return w.doDelete(w.createdSubId, c)
		},
	)

	// DELETE the subscription by an explicit (unknown) subId
	// "an LCS consumer DELETEs the subscription at subId "01NONEXISTENT0000000000000""
	sc.Step(
		`^an LCS consumer DELETEs the subscription at subId "([^"]+)"$`,
		func(subId string) error {
			if w.ts == nil {
				w.buildServer()
			}
			return w.doDelete(subId, c)
		},
	)

	// POST CancelLocation (one-shot cancel)
	// "an LCS consumer POSTs a CancelLocation for ueContextId "...""
	sc.Step(
		`^an LCS consumer POSTs a CancelLocation for ueContextId "([^"]+)"$`,
		func(ueContextId string) error {
			if w.ts == nil {
				w.buildServer()
			}
			return w.doCancelLocation(ueContextId, c)
		},
	)

	// =========================================================================
	// Then steps
	// =========================================================================

	// The "the LMF responds with HTTP status N" and "the response ProblemDetails cause is"
	// patterns are already registered in InitializeScenario against lmfCtx.
	// The captureResponse() method bridges w.lastResp → c.lastResp / c.lastBody so
	// those existing handlers inspect the correct response for sub scenarios.
	// We do NOT re-register those patterns here (would cause ambiguous step match).

	// "the response Location header matches "/nlmf-loc/v1/subscriptions/""
	sc.Step(
		`^the response Location header matches "([^"]+)"$`,
		func(prefix string) error {
			if w.lastResp == nil {
				return fmt.Errorf("no HTTP response — was a When step executed?")
			}
			loc := w.lastResp.Header.Get("Location")
			if !strings.HasPrefix(loc, prefix) {
				return fmt.Errorf("Location header = %q, want prefix %q", loc, prefix)
			}
			return nil
		},
	)

	// "the response body contains a non-empty subId"
	sc.Step(
		`^the response body contains a non-empty subId$`,
		func() error {
			if w.lastBody == nil {
				return fmt.Errorf("response body is empty or non-JSON (raw: %s)", w.lastRawBody)
			}
			id, _ := w.lastBody["subId"].(string)
			if id == "" {
				return fmt.Errorf("subId is empty or missing (body: %s)", w.lastRawBody)
			}
			return nil
		},
	)

	// "the response body contains ueContextId "...""
	sc.Step(
		`^the response body contains ueContextId "([^"]+)"$`,
		func(want string) error {
			if w.lastBody == nil {
				return fmt.Errorf("response body is empty or non-JSON (raw: %s)", w.lastRawBody)
			}
			got, _ := w.lastBody["ueContextId"].(string)
			if got != want {
				return fmt.Errorf("ueContextId = %q, want %q (body: %s)", got, want, w.lastRawBody)
			}
			return nil
		},
	)

	// "the response body contains eventTrigger "...""
	sc.Step(
		`^the response body contains eventTrigger "([^"]+)"$`,
		func(want string) error {
			if w.lastBody == nil {
				return fmt.Errorf("response body is empty or non-JSON (raw: %s)", w.lastRawBody)
			}
			got, _ := w.lastBody["eventTrigger"].(string)
			if got != want {
				return fmt.Errorf("eventTrigger = %q, want %q (body: %s)", got, want, w.lastRawBody)
			}
			return nil
		},
	)

	// "the response body echoes the areaOfInterest polygon with N vertices"
	sc.Step(
		`^the response body echoes the areaOfInterest polygon with (\d+) vertices$`,
		func(wantCount int) error {
			if w.lastBody == nil {
				return fmt.Errorf("response body is empty or non-JSON (raw: %s)", w.lastRawBody)
			}
			aoi, ok := w.lastBody["areaOfInterest"].(map[string]any)
			if !ok {
				return fmt.Errorf("areaOfInterest field missing or wrong type (body: %s)", w.lastRawBody)
			}
			poly, ok := aoi["polygon"].([]any)
			if !ok {
				return fmt.Errorf("areaOfInterest.polygon field missing or wrong type (body: %s)", w.lastRawBody)
			}
			if len(poly) != wantCount {
				return fmt.Errorf("areaOfInterest.polygon has %d vertices, want %d (body: %s)",
					len(poly), wantCount, w.lastRawBody)
			}
			return nil
		},
	)

	// "the mock sink receives at least N LocationNotification within M seconds"
	sc.Step(
		`^the mock sink receives at least (\d+) LocationNotification within (\d+) seconds$`,
		func(minCount int, deadlineSecs int) error {
			if w.sink == nil {
				return fmt.Errorf("mock sink not initialized — was a When step executed?")
			}
			_, ok := pollSinkCount(w.sink, minCount, time.Duration(deadlineSecs)*time.Second)
			if !ok {
				return fmt.Errorf("mock sink received %d notifications, want ≥%d within %d s",
					w.sink.count(), minCount, deadlineSecs)
			}
			return nil
		},
	)

	// "each received notification body contains a non-empty subId"
	sc.Step(
		`^each received notification body contains a non-empty subId$`,
		func() error {
			notifs := w.sink.snapshot()
			if len(notifs) == 0 {
				return fmt.Errorf("no notifications received")
			}
			for i, n := range notifs {
				if n.SubId == "" {
					return fmt.Errorf("notification[%d].subId is empty", i)
				}
			}
			return nil
		},
	)

	// "each received notification body contains notificationItems with locationData locationEstimate shape "...""
	sc.Step(
		`^each received notification body contains notificationItems with locationData locationEstimate shape "([^"]+)"$`,
		func(wantShape string) error {
			notifs := w.sink.snapshot()
			if len(notifs) == 0 {
				return fmt.Errorf("no notifications received")
			}
			for i, n := range notifs {
				if len(n.NotificationItems) == 0 {
					return fmt.Errorf("notification[%d].notificationItems is empty", i)
				}
				est := n.NotificationItems[0].LocationData.LocationEstimate
				if est == nil {
					return fmt.Errorf("notification[%d] locationEstimate is nil", i)
				}
				if est.Shape != wantShape {
					return fmt.Errorf("notification[%d] locationEstimate.shape = %q, want %q",
						i, est.Shape, wantShape)
				}
			}
			return nil
		},
	)

	// "each received notification body contains notificationItems with locationData nrCellId "...""
	sc.Step(
		`^each received notification body contains notificationItems with locationData nrCellId "([^"]+)"$`,
		func(wantNRCellId string) error {
			notifs := w.sink.snapshot()
			if len(notifs) == 0 {
				return fmt.Errorf("no notifications received")
			}
			for i, n := range notifs {
				if len(n.NotificationItems) == 0 {
					return fmt.Errorf("notification[%d].notificationItems is empty", i)
				}
				got := n.NotificationItems[0].LocationData.NRCellId
				if got != wantNRCellId {
					return fmt.Errorf("notification[%d] nrCellId = %q, want %q", i, got, wantNRCellId)
				}
			}
			return nil
		},
	)

	// "each received notification body contains notificationItems with locationData tai tac "...""
	sc.Step(
		`^each received notification body contains notificationItems with locationData tai tac "([^"]+)"$`,
		func(wantTac string) error {
			notifs := w.sink.snapshot()
			if len(notifs) == 0 {
				return fmt.Errorf("no notifications received")
			}
			for i, n := range notifs {
				if len(n.NotificationItems) == 0 {
					return fmt.Errorf("notification[%d].notificationItems is empty", i)
				}
				tai := n.NotificationItems[0].LocationData.Tai
				if tai == nil {
					return fmt.Errorf("notification[%d] tai is nil", i)
				}
				if tai.Tac != wantTac {
					return fmt.Errorf("notification[%d] tai.tac = %q, want %q", i, tai.Tac, wantTac)
				}
			}
			return nil
		},
	)

	// "the mock sink receives exactly N LocationNotification within M seconds"
	// Polls until exactly N notifications arrive, then waits an extra 2 s to
	// detect spurious extra notifications.
	sc.Step(
		`^the mock sink receives exactly (\d+) LocationNotification within (\d+) seconds$`,
		func(exactCount int, deadlineSecs int) error {
			if w.sink == nil {
				return fmt.Errorf("mock sink not initialized — was a When step executed?")
			}
			// Wait until we reach exactCount OR deadline passes.
			_, _ = pollSinkCount(w.sink, exactCount, time.Duration(deadlineSecs)*time.Second)
			// Extra 2 s dwell to catch spurious notifications (e.g. while stationary inside polygon).
			// The test uses samplingInterval=1 s, so two additional ticks fit in this window.
			time.Sleep(2 * time.Second)
			got := w.sink.count()
			if got != exactCount {
				return fmt.Errorf("mock sink received %d notifications, want exactly %d", got, exactCount)
			}
			return nil
		},
	)

	// "the received notification body contains notificationItems with locationData locationEstimate shape "POINT""
	// Singular variant — checks only the first received notification (used by the AOI scenario
	// which asserts on the single AREA_ENTERING notification body).
	sc.Step(
		`^the received notification body contains notificationItems with locationData locationEstimate shape "([^"]+)"$`,
		func(wantShape string) error {
			notifs := w.sink.snapshot()
			if len(notifs) == 0 {
				return fmt.Errorf("no notifications received")
			}
			n := notifs[0]
			if len(n.NotificationItems) == 0 {
				return fmt.Errorf("notification[0].notificationItems is empty")
			}
			est := n.NotificationItems[0].LocationData.LocationEstimate
			if est == nil {
				return fmt.Errorf("notification[0] locationEstimate is nil")
			}
			if est.Shape != wantShape {
				return fmt.Errorf("notification[0] locationEstimate.shape = %q, want %q", est.Shape, wantShape)
			}
			return nil
		},
	)

	// "the received notification areaEventInfo event is "AREA_ENTERING""
	sc.Step(
		`^the received notification areaEventInfo event is "([^"]+)"$`,
		func(wantEvent string) error {
			notifs := w.sink.snapshot()
			if len(notifs) == 0 {
				return fmt.Errorf("no notifications received — was a polling step executed?")
			}
			n := notifs[0]
			if len(n.NotificationItems) == 0 {
				return fmt.Errorf("notification[0].notificationItems is empty")
			}
			aei := n.NotificationItems[0].AreaEventInfo
			if aei == nil {
				return fmt.Errorf("notification[0].notificationItems[0].areaEventInfo is nil")
			}
			if aei.Event != wantEvent {
				return fmt.Errorf("areaEventInfo.event = %q, want %q", aei.Event, wantEvent)
			}
			return nil
		},
	)

	// "the response body contains the same subId as the created subscription"
	sc.Step(
		`^the response body contains the same subId as the created subscription$`,
		func() error {
			if w.lastBody == nil {
				return fmt.Errorf("response body is empty or non-JSON (raw: %s)", w.lastRawBody)
			}
			got, _ := w.lastBody["subId"].(string)
			if got == "" {
				return fmt.Errorf("subId field missing or empty (body: %s)", w.lastRawBody)
			}
			if got != w.createdSubId {
				return fmt.Errorf("subId = %q, want %q (created)", got, w.createdSubId)
			}
			return nil
		},
	)

	// "the response body contains a non-null created timestamp"
	sc.Step(
		`^the response body contains a non-null created timestamp$`,
		func() error {
			if w.lastBody == nil {
				return fmt.Errorf("response body is empty or non-JSON (raw: %s)", w.lastRawBody)
			}
			created, _ := w.lastBody["created"].(string)
			if created == "" {
				return fmt.Errorf("created field missing or empty (body: %s)", w.lastRawBody)
			}
			return nil
		},
	)

	// "the mock sink receives no further LocationNotification within N seconds after the delete"
	// Verifies that the subscription goroutine stopped: no new notifications arrive.
	sc.Step(
		`^the mock sink receives no further LocationNotification within (\d+) seconds after the delete$`,
		func(silenceSecs int) error {
			if w.sink == nil {
				return fmt.Errorf("mock sink not initialized")
			}
			baseline := w.sinkCountBefore
			// Wait for the silence window to elapse.
			time.Sleep(time.Duration(silenceSecs) * time.Second)
			got := w.sink.count()
			if got > baseline {
				return fmt.Errorf(
					"mock sink received %d new notifications after DELETE (baseline %d, now %d) — goroutine not stopped?",
					got-baseline, baseline, got)
			}
			return nil
		},
	)

	// "the metric fivegc_lmf_subscription_create_total with label result "REJECT" is incremented"
	// Delta assertion against the baseline captured at the start of the When step.
	sc.Step(
		`^the metric fivegc_lmf_subscription_create_total with label result "([^"]+)" is incremented$`,
		func(result string) error {
			baseline := w.subCreateRejectBaseline
			current := testutil.ToFloat64(metrics.LMFSubscriptionCreateTotal.WithLabelValues(result))
			delta := current - baseline
			if delta < 1 {
				return fmt.Errorf(
					"fivegc_lmf_subscription_create_total{result=%q} delta = %g, want ≥1 (baseline=%.0f current=%.0f)",
					result, delta, baseline, current)
			}
			return nil
		},
	)
}
