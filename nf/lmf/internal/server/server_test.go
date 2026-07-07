// Package server — unit tests for the LMF Nlmf_Location SBI server.
//
// Tests use httptest.NewServer(srv.Handler()) with a mock AMFLocationClient so
// no real TLS or network is required. Each test covers one outcome from the
// DetermineLocation handler (TS 29.572 §5.2.2.2):
//
//   - Happy path (200): nrCellId, tai, shape=POINT, ageOfLocationEstimate=0
//   - Unknown UE (404 CONTEXT_NOT_FOUND)
//   - AMF failure (504 LOCATION_FAILURE)
//   - Missing UE identity (400 MANDATORY_IE_MISSING)
//
// Ref: TS 29.572 §5.2.2.2; TS 29.571 §5.2.4.1 (ProblemDetails)
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// ---- mock AMF client ---------------------------------------------------------

// mockAMFClient is a test double for AMFLocationClient.
// Set ProvideFunc to control what ProvideLocationInfo returns.
type mockAMFClient struct {
	ProvideFunc func(ctx context.Context, ueContextID string) (*LocationData, string, error)
}

func (m *mockAMFClient) ProvideLocationInfo(ctx context.Context, ueContextID string) (*LocationData, string, error) {
	return m.ProvideFunc(ctx, ueContextID)
}

// ---- test helpers ------------------------------------------------------------

// newTestServer builds an LMF server using the supplied mock AMF client (no UDM
// client → privacy check disabled) and starts it via httptest.
// TLS is disabled — handler logic (not TLS) is under test.
func newTestServer(t *testing.T, amfClient AMFLocationClient) *httptest.Server {
	t.Helper()
	return newTestServerFull(t, amfClient, nil)
}

// newTestServerFull builds an LMF server with both an AMF and UDM client.
func newTestServerFull(t *testing.T, amfClient AMFLocationClient, udmClient UDMSDMClient) *httptest.Server {
	t.Helper()
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0" // not used by httptest
	cfg.CellCoordinates = map[string]config.CellCoord{
		"000000010": {Lat: 40.416775, Lon: -3.703790},
	}
	cfg.PrivacyCheck = udmClient != nil // enable check only when a UDM client is injected
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg, logger, amfClient, udmClient)
	return httptest.NewServer(srv.Handler())
}

// postLocInfo sends a POST request to the DetermineLocation endpoint.
// body is the JSON request body; use nil for an empty body.
func postLocInfo(t *testing.T, ts *httptest.Server, ueContextID string, body any) *http.Response {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader([]byte(`{}`))
	}
	url := ts.URL + "/nlmf-loc/v1/ue-contexts/" + ueContextID + "/provide-loc-info"
	req, err := http.NewRequest(http.MethodPost, url, reqBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// decodeJSON decodes the response body into v.
func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
}

// ---- tests -------------------------------------------------------------------

// TestDetermineLocation_HappyPath verifies the 200 response for a known UE.
// The mock AMF returns nrCellId "000000010" with a valid TAI.
// Expected: 200 + POINT shape + nrCellId + tai.tac + ageOfLocationEstimate=0.
// Ref: TS 29.572 §5.2.2.2 (AC 1).
func TestDetermineLocation_HappyPath(t *testing.T) {
	amfClient := &mockAMFClient{
		ProvideFunc: func(_ context.Context, ueContextID string) (*LocationData, string, error) {
			if ueContextID != "imsi-001010000000001" {
				return nil, "CONTEXT_NOT_FOUND", ErrUEContextNotFound
			}
			return &LocationData{
				LocationEstimate: &GeographicArea{
					Shape: "POINT",
					Point: &LatLon{Lat: 0, Lon: 0},
				},
				NRCellId: "000000010",
				Tai: &TaiLoc{
					PlmnId: PlmnID{MCC: "001", MNC: "01"},
					Tac:    "0001",
				},
				AgeOfLocationEstimate: 0,
			}, "", nil
		},
	}

	ts := newTestServer(t, amfClient)
	defer ts.Close()

	// Reset metric counter before test to get a clean increment.
	metrics.LMFLocateTotal.WithLabelValues("OK").Add(0) // ensure label exists

	resp := postLocInfo(t, ts, "imsi-001010000000001", map[string]string{
		"supi": "imsi-001010000000001",
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var loc LocationData
	decodeJSON(t, resp, &loc)

	if loc.NRCellId != "000000010" {
		t.Errorf("expected nrCellId=000000010, got %q", loc.NRCellId)
	}
	if loc.LocationEstimate == nil {
		t.Fatal("locationEstimate is nil")
	}
	if loc.LocationEstimate.Shape != "POINT" {
		t.Errorf("expected shape=POINT, got %q", loc.LocationEstimate.Shape)
	}
	if loc.Tai == nil {
		t.Fatal("tai is nil")
	}
	if loc.Tai.Tac != "0001" {
		t.Errorf("expected tac=0001, got %q", loc.Tai.Tac)
	}
	if loc.AgeOfLocationEstimate != 0 {
		t.Errorf("expected ageOfLocationEstimate=0, got %d", loc.AgeOfLocationEstimate)
	}
}

// TestDetermineLocation_HappyPath_CoordLookup verifies that when the nrCellId
// matches a configured entry the lat/lon are populated from the config map.
// Ref: TS 29.572 §6.1.6.2.2 (locationEstimate from config map).
func TestDetermineLocation_HappyPath_CoordLookup(t *testing.T) {
	amfClient := &mockAMFClient{
		ProvideFunc: func(_ context.Context, _ string) (*LocationData, string, error) {
			return &LocationData{
				NRCellId: "000000010", // configured in newTestServer
				Tai: &TaiLoc{
					PlmnId: PlmnID{MCC: "001", MNC: "01"},
					Tac:    "0001",
				},
			}, "", nil
		},
	}
	ts := newTestServer(t, amfClient)
	defer ts.Close()

	resp := postLocInfo(t, ts, "imsi-001010000000001", map[string]string{"supi": "imsi-001010000000001"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var loc LocationData
	decodeJSON(t, resp, &loc)

	if loc.LocationEstimate == nil || loc.LocationEstimate.Point == nil {
		t.Fatal("locationEstimate or point is nil")
	}
	// Configured: {Lat: 40.416775, Lon: -3.703790}
	if loc.LocationEstimate.Point.Lat != 40.416775 {
		t.Errorf("expected lat=40.416775, got %f", loc.LocationEstimate.Point.Lat)
	}
}

// TestDetermineLocation_UnknownUE verifies that a 404 CONTEXT_NOT_FOUND from the
// AMF is propagated as 404 CONTEXT_NOT_FOUND to the LCS consumer.
// Ref: TS 29.572 §5.2.2.2 (AC 2).
func TestDetermineLocation_UnknownUE(t *testing.T) {
	amfClient := &mockAMFClient{
		ProvideFunc: func(_ context.Context, _ string) (*LocationData, string, error) {
			return nil, "CONTEXT_NOT_FOUND", ErrUEContextNotFound
		},
	}

	ts := newTestServer(t, amfClient)
	defer ts.Close()

	resp := postLocInfo(t, ts, "imsi-001010000000099", map[string]string{
		"supi": "imsi-001010000000099",
	})

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}

	var pd map[string]any
	decodeJSON(t, resp, &pd)
	if pd["cause"] != "CONTEXT_NOT_FOUND" {
		t.Errorf("expected cause=CONTEXT_NOT_FOUND, got %v", pd["cause"])
	}
}

// TestDetermineLocation_AMFFailure verifies that a positioning failure from the
// AMF (e.g. NGAP timeout → 504 LOCATION_FAILURE) is propagated as 504
// LOCATION_FAILURE to the LCS consumer.
// Ref: TS 29.572 §5.2.2.2 (AC 3).
func TestDetermineLocation_AMFFailure(t *testing.T) {
	amfClient := &mockAMFClient{
		ProvideFunc: func(_ context.Context, _ string) (*LocationData, string, error) {
			return nil, "LOCATION_FAILURE", ErrLocationFailure
		},
	}

	ts := newTestServer(t, amfClient)
	defer ts.Close()

	resp := postLocInfo(t, ts, "imsi-001010000000001", map[string]string{
		"supi": "imsi-001010000000001",
	})

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("expected 504, got %d", resp.StatusCode)
	}

	var pd map[string]any
	decodeJSON(t, resp, &pd)
	if pd["cause"] != "LOCATION_FAILURE" {
		t.Errorf("expected cause=LOCATION_FAILURE, got %v", pd["cause"])
	}
}

// TestDetermineLocation_MissingUEIdentity verifies that a request with neither
// supi nor gpsi is rejected with 400 MANDATORY_IE_MISSING.
// Ref: TS 29.572 §5.2.2.2; error table: "UE not identifiable".
func TestDetermineLocation_MissingUEIdentity(t *testing.T) {
	amfClient := &mockAMFClient{
		ProvideFunc: func(_ context.Context, _ string) (*LocationData, string, error) {
			// Should not be called.
			t.Error("AMF client should not be called when UE identity is missing")
			return nil, "", nil
		},
	}

	ts := newTestServer(t, amfClient)
	defer ts.Close()

	// Send a body with neither supi nor gpsi (empty object).
	url := ts.URL + "/nlmf-loc/v1/ue-contexts/imsi-001010000000001/provide-loc-info"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	var pd map[string]any
	decodeJSON(t, resp, &pd)
	if pd["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("expected cause=MANDATORY_IE_MISSING, got %v", pd["cause"])
	}
}

// TestDetermineLocation_AMFUnreachable verifies that an AMF connectivity failure
// (client returns error with ErrLocationFailure) yields 504 LOCATION_FAILURE.
// Ref: TS 29.572 §5.2.2.2; error table: "LMF cannot reach AMF".
func TestDetermineLocation_AMFUnreachable(t *testing.T) {
	amfClient := &mockAMFClient{
		ProvideFunc: func(_ context.Context, _ string) (*LocationData, string, error) {
			return nil, "LOCATION_FAILURE", ErrLocationFailure
		},
	}

	ts := newTestServer(t, amfClient)
	defer ts.Close()

	resp := postLocInfo(t, ts, "imsi-001010000000001", map[string]string{
		"supi": "imsi-001010000000001",
	})

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("expected 504, got %d", resp.StatusCode)
	}

	var pd map[string]any
	decodeJSON(t, resp, &pd)
	if pd["cause"] != "LOCATION_FAILURE" {
		t.Errorf("expected cause=LOCATION_FAILURE, got %v", pd["cause"])
	}
}

// ---- mock UDM client ----------------------------------------------------------

// mockUDMClient is a test double for UDMSDMClient.
type mockUDMClient struct {
	LocationPrivacy string // returned in GetLcsPrivacyData
	called          int
}

func (m *mockUDMClient) GetLcsPrivacyData(_ context.Context, _ string) (*LcsPrivacyData, error) {
	m.called++
	return &LcsPrivacyData{LocationPrivacy: m.LocationPrivacy}, nil
}

// TestDetermineLocation_PrivacyAllowed verifies that when UDM returns ALLOW_ALL the
// location request proceeds normally and AMF is called.
// Ref: TS 23.273 §9.1; TS 29.572 §5.2.2.2.
func TestDetermineLocation_PrivacyAllowed(t *testing.T) {
	amfCallCount := 0
	amfClient := &mockAMFClient{
		ProvideFunc: func(_ context.Context, _ string) (*LocationData, string, error) {
			amfCallCount++
			return &LocationData{
				NRCellId: "000000010",
				Tai:      &TaiLoc{PlmnId: PlmnID{MCC: "001", MNC: "01"}, Tac: "0001"},
			}, "", nil
		},
	}
	udmClient := &mockUDMClient{LocationPrivacy: "ALLOW_ALL"}

	ts := newTestServerFull(t, amfClient, udmClient)
	defer ts.Close()

	resp := postLocInfo(t, ts, "imsi-001010000000001", map[string]string{"supi": "imsi-001010000000001"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if udmClient.called != 1 {
		t.Errorf("UDM client called %d times, want 1", udmClient.called)
	}
	if amfCallCount != 1 {
		t.Errorf("AMF client called %d times, want 1", amfCallCount)
	}
}

// TestDetermineLocation_PrivacyDenied verifies that when UDM returns BLOCK_ALL the
// LMF returns 403 PRIVACY_EXCEPTION_DENIED without calling the AMF.
// Ref: TS 23.273 §9.1; TS 29.572 §5.2.2.2 error table.
func TestDetermineLocation_PrivacyDenied(t *testing.T) {
	amfClient := &mockAMFClient{
		ProvideFunc: func(_ context.Context, _ string) (*LocationData, string, error) {
			t.Error("AMF client should not be called when privacy is BLOCK_ALL")
			return nil, "", nil
		},
	}
	udmClient := &mockUDMClient{LocationPrivacy: "BLOCK_ALL"}

	ts := newTestServerFull(t, amfClient, udmClient)
	defer ts.Close()

	resp := postLocInfo(t, ts, "imsi-001010000000001", map[string]string{"supi": "imsi-001010000000001"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	var pd map[string]any
	decodeJSON(t, resp, &pd)
	if pd["cause"] != "PRIVACY_EXCEPTION_DENIED" {
		t.Errorf("expected cause=PRIVACY_EXCEPTION_DENIED, got %v", pd["cause"])
	}
	if udmClient.called != 1 {
		t.Errorf("UDM client called %d times, want 1", udmClient.called)
	}
}
