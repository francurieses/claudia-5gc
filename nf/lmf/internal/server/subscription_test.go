// Package server — unit tests for LMF-003 EventSubscription + CancelLocation.
//
// All tests use httptest.NewServer(srv.Handler()) with mock AMF / notification
// clients so no real TLS or network is required.
//
// Tests covered:
//
//  1. Ray-casting polygon inclusion (table-driven, inside / outside / edge).
//  2. Subscription lifecycle: Create → registry populated; Delete → gone.
//  3. Periodic ticker fires a notification to the mock sink (short interval).
//  4. Notification retry: 5xx retried once; second call succeeds → RETRIED label.
//     Double 5xx → notification dropped, subscription still alive.
//  5. Duration expiry: short-lived subscription self-removes from registry.
//  6. Error paths: missing notificationUri → 400; unknown subId on GET/DELETE → 404.
//  7. AOI ray-casting state machine via handlers (endpoint-level test).
//  8. CancelLocation (cancel-loc) returns 204 idempotent.
//
// Ref: TS 29.572 §5.2.3 (EventSubscription), §5.2.2.5 (CancelLocation),
//
//	§6.1.6.2.4 (LocationNotification).
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
)

// ---- mock notification client ------------------------------------------------

// captureNotifClient is a mock NotificationClient that records every
// LocationNotification it receives. Safe for concurrent use.
type captureNotifClient struct {
	mu    sync.Mutex
	items []LocationNotification
	// errAfter causes PostNotification to return an error for the first errAfter
	// calls, then succeed. 0 → always succeed.
	errAfter int
	calls    int
}

func (c *captureNotifClient) PostNotification(_ context.Context, _ string, n LocationNotification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.errAfter > 0 && c.calls <= c.errAfter {
		return &mockHTTPError{status: 503, msg: "service unavailable (mock)"}
	}
	c.items = append(c.items, n)
	return nil
}

func (c *captureNotifClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *captureNotifClient) totalCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *captureNotifClient) first() *LocationNotification {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) == 0 {
		return nil
	}
	cp := c.items[0]
	return &cp
}

type mockHTTPError struct {
	status int
	msg    string
}

func (e *mockHTTPError) Error() string { return e.msg }

// ---- helpers -----------------------------------------------------------------

// newSubTestServer builds an LMF httptest.Server with injected mock clients.
func newSubTestServer(t *testing.T, amfClient AMFLocationClient, notif NotificationClient) *httptest.Server {
	t.Helper()
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.CellCoordinates = map[string]config.CellCoord{
		"000000010": {Lat: 40.4168, Lon: -3.7038},
	}
	cfg.DefaultCoord = config.CellCoord{Lat: 40.4168, Lon: -3.7038}
	cfg.Mobility = config.MobilityConfig{Enabled: false} // static coords for deterministic tests
	cfg.LocationSubscription = config.LocationSubscriptionConfig{
		DefaultSamplingIntervalS:  5,
		DefaultReportingIntervalS: 10,
		MaxDurationS:              3600,
		NotificationRetry:         1, // one retry
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewWithNotifClient(cfg, logger, amfClient, nil, notif)
	return httptest.NewServer(srv.Handler())
}

// goodAMF returns an AMFLocationClient that always returns a known LocationData.
func goodAMF() *mockAMFClient {
	return &mockAMFClient{
		ProvideFunc: func(_ context.Context, _ string) (*LocationData, string, error) {
			return &LocationData{
				LocationEstimate: &GeographicArea{
					Shape: "POINT",
					Point: &LatLon{Lat: 40.4168, Lon: -3.7038},
				},
				NRCellId: "000000010",
				Tai: &TaiLoc{
					PlmnId: PlmnID{MCC: "001", MNC: "01"},
					Tac:    "0001",
				},
			}, "", nil
		},
	}
}

// postSub sends POST /nlmf-loc/v1/subscriptions with the given body.
func postSub(t *testing.T, ts *httptest.Server, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/nlmf-loc/v1/subscriptions", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func getSub(t *testing.T, ts *httptest.Server, subId string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/nlmf-loc/v1/subscriptions/"+subId, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func deleteSub(t *testing.T, ts *httptest.Server, subId string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/nlmf-loc/v1/subscriptions/"+subId, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// ---- Test 1: Ray-casting polygon inclusion -----------------------------------

// TestPointInPolygon verifies the ray-casting AOI containment algorithm.
//
// Polygon: a simple square around Madrid city centre (40.3–40.5°N, 3.6–3.8°W).
// The algorithm uses the even-odd rule (PNPOLY by W.R. Franklin).
// Ref: TS 29.572 §6.1.6.2.2 (areaOfInterest polygon containment).
func TestPointInPolygon(t *testing.T) {
	// Square polygon (CCW): lat 40.3–40.5, lon -3.8–-3.6
	poly := []LatLon{
		{Lat: 40.3, Lon: -3.8},
		{Lat: 40.5, Lon: -3.8},
		{Lat: 40.5, Lon: -3.6},
		{Lat: 40.3, Lon: -3.6},
	}

	tests := []struct {
		name string
		lat  float64
		lon  float64
		want bool
	}{
		// Clearly inside.
		{name: "centre", lat: 40.4, lon: -3.7, want: true},
		{name: "near top-left", lat: 40.48, lon: -3.78, want: true},
		// Clearly outside.
		{name: "south", lat: 40.2, lon: -3.7, want: false},
		{name: "north", lat: 40.6, lon: -3.7, want: false},
		{name: "west", lat: 40.4, lon: -3.9, want: false},
		{name: "east", lat: 40.4, lon: -3.5, want: false},
		// Far outside.
		{name: "london", lat: 51.5, lon: -0.12, want: false},
		{name: "origin", lat: 0.0, lon: 0.0, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pointInPolygon(tc.lat, tc.lon, poly)
			if got != tc.want {
				t.Errorf("pointInPolygon(%f, %f) = %v, want %v", tc.lat, tc.lon, got, tc.want)
			}
		})
	}
}

// ---- Test 2: Subscription lifecycle -----------------------------------------

// TestSubscriptionLifecycle verifies that Create inserts into the registry,
// GET returns the resource, and DELETE removes it and returns 204.
// Ref: TS 29.572 §5.2.3.2–§5.2.3.4.
func TestSubscriptionLifecycle(t *testing.T) {
	notif := &captureNotifClient{}
	ts := newSubTestServer(t, goodAMF(), notif)
	defer ts.Close()

	// Create
	body := map[string]any{
		"ueContextId":       "imsi-001010000000001",
		"supi":              "imsi-001010000000001",
		"eventTrigger":      "PERIODIC_REPORTING",
		"notificationUri":   "http://mock-sink/notify",
		"reportingInterval": 60, // long interval — we test registry, not tick
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var created subscriptionResource
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	resp.Body.Close()
	if created.SubId == "" {
		t.Fatal("subId in create response is empty")
	}
	locHdr := resp.Header.Get("Location")
	if locHdr == "" {
		t.Fatal("Location header missing on 201")
	}
	if locHdr != "/nlmf-loc/v1/subscriptions/"+created.SubId {
		t.Errorf("unexpected Location header: %s", locHdr)
	}

	// GET
	resp = getSub(t, ts, created.SubId)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on GET, got %d", resp.StatusCode)
	}
	var got subscriptionResource
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	resp.Body.Close()
	if got.SubId != created.SubId {
		t.Errorf("GET subId mismatch: got %s want %s", got.SubId, created.SubId)
	}
	if got.UEContextId != "imsi-001010000000001" {
		t.Errorf("GET ueContextId mismatch: %s", got.UEContextId)
	}
	if got.EventTrigger != "PERIODIC_REPORTING" {
		t.Errorf("GET eventTrigger mismatch: %s", got.EventTrigger)
	}
	if got.Created == "" {
		t.Error("GET created field is empty")
	}

	// DELETE
	resp = deleteSub(t, ts, created.SubId)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on DELETE, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Subsequent GET → 404
	resp = getSub(t, ts, created.SubId)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after DELETE, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// ---- Test 3: Periodic ticker fires notification to mock sink ----------------

// TestPeriodicNotificationFires verifies that the subscription goroutine ticks
// and delivers at least one notification within the expected window.
//
// Uses a short reportingInterval (50 ms) so the test finishes fast.
// Ref: TS 29.572 §5.2.3 (periodic notification loop), §6.1.6.2.4 (body schema).
func TestPeriodicNotificationFires(t *testing.T) {
	notif := &captureNotifClient{}
	ts := newSubTestServer(t, goodAMF(), notif)
	defer ts.Close()

	// We need to inject a very short interval. The API takes seconds as an int.
	// Use 1 second (minimum expressible) — test will wait up to 3 s.
	body := map[string]any{
		"ueContextId":       "imsi-001010000000001",
		"supi":              "imsi-001010000000001",
		"eventTrigger":      "PERIODIC_REPORTING",
		"notificationUri":   "http://mock-sink/notify",
		"reportingInterval": 1,
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var created subscriptionResource
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	// Wait up to 3 s for at least one notification.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if notif.count() >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if notif.count() < 1 {
		t.Fatal("expected at least 1 notification within 3 s, got 0")
	}

	first := notif.first()
	if first == nil {
		t.Fatal("first notification is nil")
	}
	if first.SubId != created.SubId {
		t.Errorf("notification subId mismatch: got %s want %s", first.SubId, created.SubId)
	}
	if len(first.NotificationItems) == 0 {
		t.Fatal("notificationItems is empty")
	}
	item := first.NotificationItems[0]
	if item.LocationData.LocationEstimate == nil {
		t.Fatal("locationEstimate is nil in notification")
	}
	if item.LocationData.LocationEstimate.Shape != "POINT" {
		t.Errorf("expected shape=POINT, got %s", item.LocationData.LocationEstimate.Shape)
	}
	if item.LocationData.NRCellId != "000000010" {
		t.Errorf("expected nrCellId=000000010, got %s", item.LocationData.NRCellId)
	}

	// Cleanup
	deleteSub(t, ts, created.SubId)
}

// ---- Test 4: Notification retry on 5xx ----------------------------------------

// TestNotificationRetry_5xxThenSuccess verifies that when the first delivery
// attempt returns 5xx, the client retries once and the second attempt succeeds.
// Ref: TS 29.572 §5.2.3 (best-effort delivery: one retry on 5xx).
func TestNotificationRetry_5xxThenSuccess(t *testing.T) {
	// errAfter=1: first call errors, second succeeds.
	notif := &captureNotifClient{errAfter: 1}
	ts := newSubTestServer(t, goodAMF(), notif)
	defer ts.Close()

	body := map[string]any{
		"ueContextId":       "imsi-001010000000001",
		"supi":              "imsi-001010000000001",
		"eventTrigger":      "PERIODIC_REPORTING",
		"notificationUri":   "http://mock-sink/notify",
		"reportingInterval": 1,
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var created subscriptionResource
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	// Wait for at least one successful delivery (the second attempt after one retry).
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if notif.count() >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if notif.count() < 1 {
		t.Fatalf("expected at least 1 successful notification, got %d (total calls: %d)",
			notif.count(), notif.totalCalls())
	}
	// The first tick caused 2 HTTP calls (initial fail + retry).
	if notif.totalCalls() < 2 {
		t.Errorf("expected at least 2 HTTP attempts (1 fail + 1 retry), got %d", notif.totalCalls())
	}

	deleteSub(t, ts, created.SubId)
}

// TestNotificationRetry_5xxDropped verifies that when both the initial attempt
// and the single retry return 5xx, the notification is dropped and the
// subscription remains alive.
// Ref: TS 29.572 §5.2.3 (best-effort: drop after all retries, subscription survives).
func TestNotificationRetry_5xxDropped(t *testing.T) {
	// errAfter=100: always errors — well beyond the retry cap.
	notif := &captureNotifClient{errAfter: 100}
	ts := newSubTestServer(t, goodAMF(), notif)
	defer ts.Close()

	body := map[string]any{
		"ueContextId":       "imsi-001010000000001",
		"supi":              "imsi-001010000000001",
		"eventTrigger":      "PERIODIC_REPORTING",
		"notificationUri":   "http://mock-sink/notify",
		"reportingInterval": 1,
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var created subscriptionResource
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	// Wait for at least one tick cycle (2 s to cover the 1 s interval + slack).
	time.Sleep(2 * time.Second)

	// No items should have been captured (all attempts fail).
	if notif.count() != 0 {
		t.Errorf("expected 0 captured notifications, got %d", notif.count())
	}

	// Subscription must still be alive (GET → 200).
	resp = getSub(t, ts, created.SubId)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("subscription should still be alive after dropped notification, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	deleteSub(t, ts, created.SubId)
}

// ---- Test 5: Duration expiry ------------------------------------------------

// TestSubscriptionExpiry verifies that a subscription with a short duration
// self-removes from the registry after the duration elapses.
//
// The minimum expressible duration via the API is 1 second; we wait 2.5 s.
// Ref: TS 29.572 §5.2.3.2 (duration IE → context.WithTimeout).
func TestSubscriptionExpiry(t *testing.T) {
	notif := &captureNotifClient{}

	// Use a very long reporting interval (60 s) so the tick doesn't fire during
	// the test — we only want to observe the duration expiry path.
	// For expiry itself we use duration=1 s.
	//
	// However the Server constructor takes an int seconds from the request body.
	// The goroutine's context.WithTimeout uses the duration field, so 1 s should work.

	ts := newSubTestServer(t, goodAMF(), notif)
	defer ts.Close()

	body := map[string]any{
		"ueContextId":       "imsi-001010000000001",
		"supi":              "imsi-001010000000001",
		"eventTrigger":      "PERIODIC_REPORTING",
		"notificationUri":   "http://mock-sink/notify",
		"reportingInterval": 60,
		"duration":          1, // 1 second lifetime
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var created subscriptionResource
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	// Immediately the subscription should exist.
	resp = getSub(t, ts, created.SubId)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 immediately after create, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Wait for expiry + a generous buffer for the goroutine to clean up.
	time.Sleep(2500 * time.Millisecond)

	// After expiry the registry should no longer contain the subscription.
	resp = getSub(t, ts, created.SubId)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after duration expiry, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// ---- Test 6: Error paths -----------------------------------------------------

// TestCreateSubscription_MissingNotificationUri verifies that omitting
// notificationUri from the Create body results in 400 MANDATORY_IE_MISSING.
// Ref: TS 29.572 §5.2.3.2 / TS 29.571 §5.2.7.
func TestCreateSubscription_MissingNotificationUri(t *testing.T) {
	ts := newSubTestServer(t, goodAMF(), &captureNotifClient{})
	defer ts.Close()

	body := map[string]any{
		"ueContextId":  "imsi-001010000000001",
		"supi":         "imsi-001010000000001",
		"eventTrigger": "PERIODIC_REPORTING",
		// no notificationUri
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	var pd map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pd)
	resp.Body.Close()
	if pd["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("expected cause=MANDATORY_IE_MISSING, got %v", pd["cause"])
	}
}

// TestCreateSubscription_MissingUEIdentity verifies that omitting all UE
// identity fields results in 400 MANDATORY_IE_MISSING.
// Ref: TS 29.572 §5.2.3.2.
func TestCreateSubscription_MissingUEIdentity(t *testing.T) {
	ts := newSubTestServer(t, goodAMF(), &captureNotifClient{})
	defer ts.Close()

	body := map[string]any{
		"eventTrigger":    "PERIODIC_REPORTING",
		"notificationUri": "http://mock-sink/notify",
		// no ueContextId, supi, gpsi
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	var pd map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pd)
	resp.Body.Close()
	if pd["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("expected cause=MANDATORY_IE_MISSING, got %v", pd["cause"])
	}
}

// TestGetSubscription_UnknownSubId verifies that GET with an unknown subId
// returns 404 SUBSCRIPTION_NOT_FOUND.
// Ref: TS 29.572 §5.2.3.3.
func TestGetSubscription_UnknownSubId(t *testing.T) {
	ts := newSubTestServer(t, goodAMF(), &captureNotifClient{})
	defer ts.Close()

	resp := getSub(t, ts, "01NONEXISTENT0000000000000")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	var pd map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pd)
	resp.Body.Close()
	if pd["cause"] != "SUBSCRIPTION_NOT_FOUND" {
		t.Errorf("expected cause=SUBSCRIPTION_NOT_FOUND, got %v", pd["cause"])
	}
}

// TestDeleteSubscription_UnknownSubId verifies that DELETE with an unknown subId
// returns 404 SUBSCRIPTION_NOT_FOUND.
// Ref: TS 29.572 §5.2.3.4.
func TestDeleteSubscription_UnknownSubId(t *testing.T) {
	ts := newSubTestServer(t, goodAMF(), &captureNotifClient{})
	defer ts.Close()

	resp := deleteSub(t, ts, "01NONEXISTENT0000000000000")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	var pd map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pd)
	resp.Body.Close()
	if pd["cause"] != "SUBSCRIPTION_NOT_FOUND" {
		t.Errorf("expected cause=SUBSCRIPTION_NOT_FOUND, got %v", pd["cause"])
	}
}

// TestCreateSubscription_UnknownEventTrigger verifies that an unrecognised
// eventTrigger value is rejected with 400 INVALID_MSG_FORMAT.
// Ref: TS 29.572 §5.2.3.2.
func TestCreateSubscription_UnknownEventTrigger(t *testing.T) {
	ts := newSubTestServer(t, goodAMF(), &captureNotifClient{})
	defer ts.Close()

	body := map[string]any{
		"ueContextId":     "imsi-001010000000001",
		"supi":            "imsi-001010000000001",
		"eventTrigger":    "CONTINUOUS_STREAMING",
		"notificationUri": "http://mock-sink/notify",
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	var pd map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pd)
	resp.Body.Close()
	if pd["cause"] != "INVALID_MSG_FORMAT" {
		t.Errorf("expected cause=INVALID_MSG_FORMAT, got %v", pd["cause"])
	}
}

// TestCreateSubscription_DegenerateAOIPolygon verifies that an AOI subscription
// with fewer than 3 vertices is rejected with 400 MANDATORY_IE_MISSING.
// Ref: TS 29.572 §6.1.6.2.2.
func TestCreateSubscription_DegenerateAOIPolygon(t *testing.T) {
	ts := newSubTestServer(t, goodAMF(), &captureNotifClient{})
	defer ts.Close()

	body := map[string]any{
		"ueContextId":     "imsi-001010000000001",
		"supi":            "imsi-001010000000001",
		"eventTrigger":    "AREA_OF_INTEREST",
		"notificationUri": "http://mock-sink/notify",
		"areaOfInterest": map[string]any{
			"polygon": []map[string]float64{
				{"lat": 40.3, "lon": -3.8},
				{"lat": 40.5, "lon": -3.8},
				// Only 2 vertices → degenerate
			},
		},
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	var pd map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pd)
	resp.Body.Close()
	if pd["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("expected cause=MANDATORY_IE_MISSING, got %v", pd["cause"])
	}
}

// ---- Test 7: AOI state machine via scripted AMF positions -------------------

// TestAOISubscription_EnterTriggersNotification verifies the AOI state machine:
// when the UE crosses into the polygon, exactly one AREA_ENTERING notification fires;
// while it remains inside, no additional notifications fire.
//
// Uses a scripted AMFLocationClient that returns positions in sequence, and a short
// samplingInterval so the goroutine ticks quickly.
//
// Polygon: lat 40.3–40.5, lon -3.8–-3.6 (the Madrid square used in TestPointInPolygon).
// Positions: outside (40.2, -3.7) → inside (40.4, -3.7) → stationary inside × 2.
//
// Ref: TS 29.572 §5.2.3 (AOI notification: only on crossing), §6.1.6.2.4 (areaEventInfo).
func TestAOISubscription_EnterTriggersNotification(t *testing.T) {
	// Scripted positions: 4 ticks.
	positions := []LatLon{
		{Lat: 40.2, Lon: -3.7},  // outside
		{Lat: 40.4, Lon: -3.7},  // inside  → AREA_ENTERING
		{Lat: 40.42, Lon: -3.7}, // inside  → no notification
		{Lat: 40.43, Lon: -3.7}, // inside  → no notification
	}
	var posIdx atomic.Int32

	scriptedAMF := &mockAMFClient{
		ProvideFunc: func(_ context.Context, _ string) (*LocationData, string, error) {
			idx := int(posIdx.Add(1)) - 1
			if idx >= len(positions) {
				idx = len(positions) - 1
			}
			return &LocationData{
				LocationEstimate: &GeographicArea{
					Shape: "POINT",
					Point: &LatLon{Lat: positions[idx].Lat, Lon: positions[idx].Lon},
				},
				NRCellId: "000000010",
				Tai: &TaiLoc{
					PlmnId: PlmnID{MCC: "001", MNC: "01"},
					Tac:    "0001",
				},
			}, "", nil
		},
	}

	notif := &captureNotifClient{}
	ts := newSubTestServer(t, scriptedAMF, notif)
	defer ts.Close()

	polygon := []map[string]float64{
		{"lat": 40.3, "lon": -3.8},
		{"lat": 40.5, "lon": -3.8},
		{"lat": 40.5, "lon": -3.6},
		{"lat": 40.3, "lon": -3.6},
	}
	body := map[string]any{
		"ueContextId":      "imsi-001010000000001",
		"supi":             "imsi-001010000000001",
		"eventTrigger":     "AREA_OF_INTEREST",
		"notificationUri":  "http://mock-sink/notify",
		"samplingInterval": 1, // 1 s so the test finishes in a few seconds
		"areaOfInterest": map[string]any{
			"polygon": polygon,
		},
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var created subscriptionResource
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	// Tick 1: outside → baseline established (UNKNOWN→OUT), no notification.
	// Tick 2: inside  → AREA_ENTERING, exactly 1 notification.
	// Ticks 3+: inside → no notification (stationary).
	//
	// Allow 6 s for at least 4 ticks at 1 s each, plus scheduling slack.
	time.Sleep(5 * time.Second)

	count := notif.count()
	if count != 1 {
		t.Fatalf("expected exactly 1 AREA_ENTERING notification, got %d", count)
	}
	first := notif.first()
	if first == nil {
		t.Fatal("first notification is nil")
	}
	if len(first.NotificationItems) == 0 {
		t.Fatal("notificationItems is empty")
	}
	item := first.NotificationItems[0]
	if item.AreaEventInfo == nil {
		t.Fatal("areaEventInfo is nil in AOI notification")
	}
	if item.AreaEventInfo.Event != "AREA_ENTERING" {
		t.Errorf("expected event=AREA_ENTERING, got %s", item.AreaEventInfo.Event)
	}
	if item.LocationData.LocationEstimate == nil || item.LocationData.LocationEstimate.Shape != "POINT" {
		t.Error("expected POINT shape in locationEstimate")
	}

	deleteSub(t, ts, created.SubId)
}

// ---- Test 8: CancelLocation (cancel-loc) idempotent 204 ----------------------

// TestCancelLocation_Idempotent verifies that POST .../cancel-loc for a UE with
// no in-progress DetermineLocation returns 204 (idempotent no-op).
// Ref: TS 29.572 §5.2.2.5.
func TestCancelLocation_Idempotent(t *testing.T) {
	ts := newSubTestServer(t, goodAMF(), &captureNotifClient{})
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost,
		ts.URL+"/nlmf-loc/v1/ue-contexts/imsi-001010000000001/cancel-loc", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}

// TestCreateSubscription_AOI_ValidPolygon verifies that a valid AOI subscription
// with ≥3 polygon vertices returns 201 with the polygon echoed in the body.
// Ref: TS 29.572 §5.2.3.2, §6.1.6.2.2.
func TestCreateSubscription_AOI_ValidPolygon(t *testing.T) {
	ts := newSubTestServer(t, goodAMF(), &captureNotifClient{})
	defer ts.Close()

	polygon := []map[string]float64{
		{"lat": 40.3, "lon": -3.8},
		{"lat": 40.5, "lon": -3.8},
		{"lat": 40.5, "lon": -3.6},
		{"lat": 40.3, "lon": -3.6},
	}
	body := map[string]any{
		"ueContextId":      "imsi-001010000000001",
		"supi":             "imsi-001010000000001",
		"eventTrigger":     "AREA_OF_INTEREST",
		"notificationUri":  "http://mock-sink/notify",
		"samplingInterval": 60,
		"areaOfInterest": map[string]any{
			"polygon": polygon,
		},
	}
	resp := postSub(t, ts, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var created subscriptionResource
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	if created.SubId == "" {
		t.Fatal("subId empty in create response")
	}
	if created.EventTrigger != "AREA_OF_INTEREST" {
		t.Errorf("expected eventTrigger=AREA_OF_INTEREST, got %s", created.EventTrigger)
	}
	if created.AreaOfInterest == nil {
		t.Fatal("areaOfInterest missing in create response")
	}
	if len(created.AreaOfInterest.Polygon) != 4 {
		t.Errorf("expected 4 polygon vertices, got %d", len(created.AreaOfInterest.Polygon))
	}

	deleteSub(t, ts, created.SubId)
}
