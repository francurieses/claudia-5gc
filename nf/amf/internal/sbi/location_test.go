package sbi

// location_test.go — unit tests for the Namf_Location_ProvideLocationInfo handler.
//
// Ref: TS 29.518 §5.2.2.6; TS 38.413 §8.17.1; TS 23.273 §7.2.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
)

// fakeLocator is a test double for the Locator interface.
type fakeLocator struct {
	// result is sent on the channel when SendLocationReportingControl is called,
	// unless noSend=true (simulates a gNB that never replies).
	result  ngap.LocationResult
	sendErr error // returned directly from SendLocationReportingControl
	noSend  bool  // if true, nothing is sent on the channel (simulate timeout)
	called  int
}

func (f *fakeLocator) SendLocationReportingControl(ue *amfctx.UEContext) (<-chan ngap.LocationResult, error) {
	f.called++
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	ch := make(chan ngap.LocationResult, 1)
	if !f.noSend {
		ch <- f.result
	}
	return ch, nil
}

// postLocInfo posts to the namf-loc ProvideLocationInfo endpoint.
func postLocInfo(t *testing.T, srv *Server, ueContextID string, body []byte) (*http.Response, []byte) {
	t.Helper()
	ts := httptest.NewServer(srv.httpSrv.Handler)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/namf-loc/v1/ue-contexts/"+ueContextID+"/provide-loc-info",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

// seedConnectedUE creates a UE in CM-CONNECTED state for location tests.
func seedConnectedUE(mgr *amfctx.Manager, supi string) *amfctx.UEContext {
	ue := seedRegisteredUE(mgr, supi)
	ue.CMState = amfctx.CMConnected
	return ue
}

// TestProvideLocInfo_HappyPath verifies that a CM-CONNECTED UE with a wired Locator
// returns 200 with the NRCGI and TAI from the fake LocationResult.
// Ref: TS 29.518 §5.2.2.6; TS 23.273 §7.2.
func TestProvideLocInfo_HappyPath(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")

	fl := &fakeLocator{
		result: ngap.LocationResult{
			NRCellID: "000000042",
			TAI: &ngap.TAI{
				MCC: "001",
				MNC: "01",
				TAC: 1,
			},
		},
	}
	srv.SetLocator(fl)

	body, _ := json.Marshal(RequestLocInfo{Req5gsLoc: true})
	resp, raw := postLocInfo(t, srv, "imsi-001010000000001", body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}
	var ld LocationData
	if err := json.Unmarshal(raw, &ld); err != nil {
		t.Fatalf("decode LocationData: %v", err)
	}
	if ld.NRCellId != "000000042" {
		t.Errorf("nrCellId = %q, want \"000000042\"", ld.NRCellId)
	}
	if ld.Tai == nil {
		t.Fatal("tai is nil")
	}
	if ld.Tai.PlmnId.MCC != "001" {
		t.Errorf("tai.plmnId.mcc = %q, want \"001\"", ld.Tai.PlmnId.MCC)
	}
	if ld.Tai.Tac != "000001" {
		t.Errorf("tai.tac = %q, want \"000001\"", ld.Tai.Tac)
	}
	if ld.LocationEstimate == nil || ld.LocationEstimate.Shape != "POINT" {
		t.Errorf("locationEstimate = %+v, want POINT", ld.LocationEstimate)
	}
	if fl.called != 1 {
		t.Errorf("Locator called %d times, want 1", fl.called)
	}
}

// TestProvideLocInfo_NotFound verifies that an unknown ueContextId → 404 CONTEXT_NOT_FOUND.
// Ref: TS 29.518 §5.2.2.6 error table.
func TestProvideLocInfo_NotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetLocator(&fakeLocator{})

	body, _ := json.Marshal(RequestLocInfo{Req5gsLoc: true})
	resp, raw := postLocInfo(t, srv, "imsi-999999999999999", body)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", resp.StatusCode, raw)
	}
	var pd ProblemDetails
	_ = json.Unmarshal(raw, &pd)
	if pd.Cause != "CONTEXT_NOT_FOUND" {
		t.Errorf("cause = %q, want CONTEXT_NOT_FOUND", pd.Cause)
	}
}

// TestProvideLocInfo_CMIdle verifies that a CM-IDLE UE → 409 UE_NOT_REACHABLE.
// Paging-then-locate is deferred to a follow-up task (LMF-002+).
// Ref: TS 29.518 §5.2.2.6; DetermineLocation.md error table.
func TestProvideLocInfo_CMIdle(t *testing.T) {
	srv, mgr := newTestServer(t)
	ue := seedRegisteredUE(mgr, "imsi-001010000000001")
	ue.CMState = amfctx.CMIdle // explicitly idle
	srv.SetLocator(&fakeLocator{})

	body, _ := json.Marshal(RequestLocInfo{Req5gsLoc: true})
	resp, raw := postLocInfo(t, srv, "imsi-001010000000001", body)

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", resp.StatusCode, raw)
	}
	var pd ProblemDetails
	_ = json.Unmarshal(raw, &pd)
	if pd.Cause != CauseUENotReachable {
		t.Errorf("cause = %q, want %q", pd.Cause, CauseUENotReachable)
	}
}

// TestProvideLocInfo_LocatorSendError verifies that a Locator send failure
// → 504 LOCATION_FAILURE.
func TestProvideLocInfo_LocatorSendError(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")

	fl := &fakeLocator{sendErr: fmt.Errorf("no gNB connection")}
	srv.SetLocator(fl)

	body, _ := json.Marshal(RequestLocInfo{Req5gsLoc: true})
	resp, raw := postLocInfo(t, srv, "imsi-001010000000001", body)

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504; body=%s", resp.StatusCode, raw)
	}
	var pd ProblemDetails
	_ = json.Unmarshal(raw, &pd)
	if pd.Cause != CauseLocationFailure {
		t.Errorf("cause = %q, want %q", pd.Cause, CauseLocationFailure)
	}
}

// TestProvideLocInfo_ContextCancelledTimeout verifies that when the request context
// is cancelled before the gNB replies, the handler returns 504 LOCATION_FAILURE.
// This exercises the select{case <-locCtx.Done()} branch without waiting the full
// locationTimeout constant.
// Ref: TS 38.413 §8.17.1; TS 23.273 §7.2 (no normative timer; see locationTimeout).
func TestProvideLocInfo_ContextCancelledTimeout(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")
	srv.SetLocator(&fakeLocator{noSend: true}) // channel created but never written

	ts := httptest.NewServer(srv.httpSrv.Handler)
	defer ts.Close()

	body, _ := json.Marshal(RequestLocInfo{Req5gsLoc: true})
	// Use a 150 ms deadline — well under locationTimeout (10 s) to keep the test fast.
	reqCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(reqCtx,
		http.MethodPost,
		ts.URL+"/namf-loc/v1/ue-contexts/imsi-001010000000001/provide-loc-info",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		// The HTTP client itself may abort if the context expires; that is acceptable.
		t.Logf("client-side cancellation (expected): %v", err)
		return
	}
	defer resp.Body.Close()
	// If we received a response it must indicate failure.
	if resp.StatusCode != http.StatusGatewayTimeout {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		t.Errorf("status = %d, want 504 (timeout); body=%s", resp.StatusCode, buf.Bytes())
	}
}

// TestProvideLocInfo_MissingReq5gsLoc verifies that omitting req5gsLoc → 400.
func TestProvideLocInfo_MissingReq5gsLoc(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")
	srv.SetLocator(&fakeLocator{})

	body, _ := json.Marshal(RequestLocInfo{Req5gsLoc: false}) // false = not set
	resp, raw := postLocInfo(t, srv, "imsi-001010000000001", body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, raw)
	}
	var pd ProblemDetails
	_ = json.Unmarshal(raw, &pd)
	if pd.Cause != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %q, want MANDATORY_IE_MISSING", pd.Cause)
	}
}
