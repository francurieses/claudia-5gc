// Package server_test provides unit tests for the SMSF Nsmsf_SMService SBI server.
//
// Tests are in-process: the Server's handler is driven via httptest.NewServer,
// and a mock AMF HTTP server captures N1N2MessageTransfer callbacks.
// No TLS, no network calls to NRF/UDM required for unit tests.
package server_test

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
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/smsf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/smsf/internal/server"
)

// ---- mock AMF ---------------------------------------------------------------

// mockAMF records received N1N2MessageTransfer calls.
type mockAMF struct {
	srv      *httptest.Server
	mu       sync.Mutex
	received []n1n2Call
	udmCalls []string // recorded UECM registrations
}

type n1n2Call struct {
	Body       map[string]any
	ReceivedAt time.Time
}

func newMockAMF(t *testing.T) *mockAMF {
	t.Helper()
	m := &mockAMF{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/n1-n2-messages") {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.mu.Lock()
			m.received = append(m.received, n1n2Call{Body: body, ReceivedAt: time.Now()})
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"cause":"N1_N2_TRANSFER_INITIATED"}`))
			return
		}
		// UECM registration endpoint
		if strings.Contains(r.URL.Path, "/registrations/smsf-3gpp-access") {
			m.mu.Lock()
			m.udmCalls = append(m.udmCalls, r.URL.Path)
			m.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

// waitForCall blocks until the mock AMF has received at least one call or the
// deadline is exceeded. Returns false on timeout.
func (m *mockAMF) waitForCall(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		n := len(m.received)
		m.mu.Unlock()
		if n > 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// callsReceived returns a copy of all received N1N2 calls (safe for concurrent use).
func (m *mockAMF) callsReceived() []n1n2Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]n1n2Call, len(m.received))
	copy(out, m.received)
	return out
}

// udmCallsSeen returns a copy of recorded UDM calls (safe for concurrent use).
func (m *mockAMF) udmCallsSeen() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.udmCalls))
	copy(out, m.udmCalls)
	return out
}

// ---- mock clients -----------------------------------------------------------

// inMemoryAMFClient implements AMFClient for tests using a real HTTP client to
// the mock AMF server.
type inMemoryAMFClient struct {
	baseURL string
	client  *http.Client
}

func (c *inMemoryAMFClient) SendN1N2Message(ctx context.Context, callbackURI, supi string, smsPayload []byte) error {
	body, _ := json.Marshal(map[string]any{
		"n1MessageContainer": map[string]any{
			"n1MessageClass": "SMS",
		},
		"smsPayload":           fmt.Sprintf("%x", smsPayload), // hex for test inspection
		"payloadContainerType": 2,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, callbackURI, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("amf returned %d", resp.StatusCode)
	}
	return nil
}

// inMemoryUDMClient implements UDMClient for tests.
type inMemoryUDMClient struct {
	baseURL   string
	client    *http.Client
	callsSeen []string
}

func (c *inMemoryUDMClient) RegisterSMSF(ctx context.Context, supi, smsfInstanceID string) error {
	c.callsSeen = append(c.callsSeen, supi)
	url := fmt.Sprintf("%s/nudm-uecm/v1/%s/registrations/smsf-3gpp-access",
		c.baseURL, supi)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("udm returned %d", resp.StatusCode)
	}
	return nil
}

// ---- test helpers -----------------------------------------------------------

func newTestServer(t *testing.T, amfMock *mockAMF) (*httptest.Server, *server.Server) {
	t.Helper()
	cfg := &config.Config{}
	cfg.NFInstanceID = "test-smsf-001"
	cfg.SBI.Address = "127.0.0.1:0" // unused (httptest binds its own port)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, log)

	if amfMock != nil {
		amfClient := &inMemoryAMFClient{
			baseURL: amfMock.srv.URL,
			client:  amfMock.srv.Client(),
		}
		srv.WithAMFClient(amfClient)

		udmClient := &inMemoryUDMClient{
			baseURL: amfMock.srv.URL,
			client:  amfMock.srv.Client(),
		}
		srv.WithUDMClient(udmClient)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv
}

func activateBody(supi, accessType, amfID, callbackURI string) []byte {
	m := map[string]any{
		"supi":           supi,
		"accessType":     accessType,
		"amfId":          amfID,
		"amfCallbackUri": callbackURI,
	}
	b, _ := json.Marshal(m)
	return b
}

func postJSON(t *testing.T, client *http.Client, url string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want %d; body: %s", resp.StatusCode, want, body)
	}
}

func parseProblem(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return m
}

// ---- tests ------------------------------------------------------------------

// TestActivate_201 verifies that a valid Activate request returns 201 + context.
func TestActivate_201(t *testing.T) {
	mock := newMockAMF(t)
	ts, _ := newTestServer(t, mock)

	supi := "imsi-001010000000001"
	resp := postJSON(t, ts.Client(), ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi,
		activateBody(supi, "3GPP_ACCESS", "amf-001",
			mock.srv.URL+"/namf-comm/v1/ue-contexts/"+supi+"/n1-n2-messages"))
	defer resp.Body.Close()

	assertStatus(t, resp, http.StatusCreated)

	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["supi"] != supi {
		t.Errorf("response supi = %v, want %s", body["supi"], supi)
	}
	if body["accessType"] != "3GPP_ACCESS" {
		t.Errorf("response accessType = %v, want 3GPP_ACCESS", body["accessType"])
	}

	// Check Location header
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, supi) {
		t.Errorf("Location header %q does not contain supi %s", loc, supi)
	}
}

// TestActivate_MissingAccessType verifies that Activate with no accessType returns 400 MANDATORY_IE_MISSING.
func TestActivate_MissingAccessType(t *testing.T) {
	mock := newMockAMF(t)
	ts, _ := newTestServer(t, mock)

	supi := "imsi-001010000000001"
	body, _ := json.Marshal(map[string]any{
		"supi":  supi,
		"amfId": "amf-001",
		// accessType intentionally missing
	})
	resp := postJSON(t, ts.Client(), ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi, body)
	defer resp.Body.Close()

	assertStatus(t, resp, http.StatusBadRequest)
	prob := parseProblem(t, resp)
	if prob["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %v, want MANDATORY_IE_MISSING", prob["cause"])
	}
}

// TestActivate_MissingSupiInBody verifies that Activate with empty supi body returns 400.
func TestActivate_MissingSupiInBody(t *testing.T) {
	mock := newMockAMF(t)
	ts, _ := newTestServer(t, mock)

	supi := "imsi-001010000000001"
	body, _ := json.Marshal(map[string]any{
		// supi intentionally missing from body
		"accessType": "3GPP_ACCESS",
		"amfId":      "amf-001",
	})
	resp := postJSON(t, ts.Client(), ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi, body)
	defer resp.Body.Close()

	assertStatus(t, resp, http.StatusBadRequest)
	prob := parseProblem(t, resp)
	if prob["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %v, want MANDATORY_IE_MISSING", prob["cause"])
	}
}

// TestUplinkSMS_NoContext verifies that UplinkSMS for an unknown SUPI returns 404 CONTEXT_NOT_FOUND.
func TestUplinkSMS_NoContext(t *testing.T) {
	ts, _ := newTestServer(t, nil)

	body, _ := json.Marshal(map[string]any{
		"smsPayload":  "AQIDBA==",
		"smsRecordId": "rec-err-001",
	})
	resp := postJSON(t, ts.Client(),
		ts.URL+"/nsmsf-sms/v2/ue-contexts/imsi-999999999999/sendsms", body)
	defer resp.Body.Close()

	assertStatus(t, resp, http.StatusNotFound)
	prob := parseProblem(t, resp)
	if prob["cause"] != "CONTEXT_NOT_FOUND" {
		t.Errorf("cause = %v, want CONTEXT_NOT_FOUND", prob["cause"])
	}
}

// TestUplinkSMS_200_AndEchoMT verifies the full MO → MT round-trip via the loopback DTE.
// After UplinkSMS returns 200, the mock AMF must receive a N1N2MessageTransfer within 2s.
func TestUplinkSMS_200_AndEchoMT(t *testing.T) {
	mock := newMockAMF(t)
	ts, _ := newTestServer(t, mock)

	supi := "imsi-001010000000001"
	callbackURI := mock.srv.URL + "/namf-comm/v1/ue-contexts/" + supi + "/n1-n2-messages"

	// First: activate a context
	activateResp := postJSON(t, ts.Client(), ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi,
		activateBody(supi, "3GPP_ACCESS", "amf-001", callbackURI))
	defer activateResp.Body.Close()
	assertStatus(t, activateResp, http.StatusCreated)

	// Now send UplinkSMS
	uplinkBody, _ := json.Marshal(map[string]any{
		"smsPayload":  "AQIDBA==",
		"smsRecordId": "rec-mo-001",
	})
	resp := postJSON(t, ts.Client(),
		ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi+"/sendsms", uplinkBody)
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusOK)

	// The loopback DTE runs asynchronously — wait up to 2 seconds.
	if !mock.waitForCall(2 * time.Second) {
		t.Fatal("mock AMF did not receive N1N2MessageTransfer within 2 seconds")
	}

	calls := mock.callsReceived()
	call := calls[0]
	// Verify n1MessageClass = SMS
	n1Container, ok := call.Body["n1MessageContainer"].(map[string]any)
	if !ok {
		t.Fatalf("n1MessageContainer missing or wrong type in N1N2 body: %v", call.Body)
	}
	if n1Container["n1MessageClass"] != "SMS" {
		t.Errorf("n1MessageClass = %v, want SMS", n1Container["n1MessageClass"])
	}
	// Verify payloadContainerType = 2 (SMS = 0x02)
	pct, _ := call.Body["payloadContainerType"].(float64)
	if pct != 2 {
		t.Errorf("payloadContainerType = %v, want 2 (SMS)", pct)
	}
}

// TestDeactivate_204_ThenUplinkSMS_404 verifies deactivation followed by UplinkSMS returns 404.
func TestDeactivate_204_ThenUplinkSMS_404(t *testing.T) {
	mock := newMockAMF(t)
	ts, _ := newTestServer(t, mock)

	supi := "imsi-001010000000003"
	callbackURI := mock.srv.URL + "/namf-comm/v1/ue-contexts/" + supi + "/n1-n2-messages"

	// Activate
	aResp := postJSON(t, ts.Client(), ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi,
		activateBody(supi, "3GPP_ACCESS", "amf-001", callbackURI))
	defer aResp.Body.Close()
	assertStatus(t, aResp, http.StatusCreated)

	// Deactivate
	deactReq, _ := http.NewRequestWithContext(context.Background(),
		http.MethodDelete, ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi, nil)
	deactResp, err := ts.Client().Do(deactReq)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer deactResp.Body.Close()
	assertStatus(t, deactResp, http.StatusNoContent)

	// UplinkSMS after deactivation → 404
	uplinkBody, _ := json.Marshal(map[string]any{
		"smsPayload":  "AQIDBA==",
		"smsRecordId": "rec-post-deact-001",
	})
	resp := postJSON(t, ts.Client(),
		ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi+"/sendsms", uplinkBody)
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusNotFound)
	prob := parseProblem(t, resp)
	if prob["cause"] != "CONTEXT_NOT_FOUND" {
		t.Errorf("cause = %v, want CONTEXT_NOT_FOUND", prob["cause"])
	}
}

// TestDeactivate_404_UnknownContext verifies DELETE on unknown context returns 404.
func TestDeactivate_404_UnknownContext(t *testing.T) {
	ts, _ := newTestServer(t, nil)

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodDelete, ts.URL+"/nsmsf-sms/v2/ue-contexts/imsi-unknown", nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusNotFound)
}

// TestMTSMSTrigger_Internal verifies the internal MT SMS trigger endpoint.
func TestMTSMSTrigger_Internal(t *testing.T) {
	mock := newMockAMF(t)
	ts, _ := newTestServer(t, mock)

	supi := "imsi-001010000000002"
	callbackURI := mock.srv.URL + "/namf-comm/v1/ue-contexts/" + supi + "/n1-n2-messages"

	// Activate context first
	aResp := postJSON(t, ts.Client(), ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi,
		activateBody(supi, "3GPP_ACCESS", "amf-001", callbackURI))
	defer aResp.Body.Close()
	assertStatus(t, aResp, http.StatusCreated)

	// Trigger MT SMS via internal endpoint
	mtBody, _ := json.Marshal(map[string]string{"smsPayload": "dGVzdA=="})
	resp := postJSON(t, ts.Client(),
		ts.URL+"/nsmsf-sms-internal/v1/ue-contexts/"+supi+"/mt-sms", mtBody)
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusAccepted)

	// Mock AMF must receive the N1N2MessageTransfer
	if !mock.waitForCall(2 * time.Second) {
		t.Fatal("mock AMF did not receive N1N2MessageTransfer within 2 seconds")
	}
	calls := mock.callsReceived()
	call := calls[0]
	n1Container, ok := call.Body["n1MessageContainer"].(map[string]any)
	if !ok {
		t.Fatalf("n1MessageContainer missing in MT trigger response: %v", call.Body)
	}
	if n1Container["n1MessageClass"] != "SMS" {
		t.Errorf("n1MessageClass = %v, want SMS", n1Container["n1MessageClass"])
	}
}

// TestMTSMSTrigger_NoContext verifies internal MT trigger returns 404 when no context.
func TestMTSMSTrigger_NoContext(t *testing.T) {
	ts, _ := newTestServer(t, nil)

	body, _ := json.Marshal(map[string]string{"smsPayload": "dGVzdA=="})
	resp := postJSON(t, ts.Client(),
		ts.URL+"/nsmsf-sms-internal/v1/ue-contexts/imsi-nobody/mt-sms", body)
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusNotFound)
}

// TestHealthz verifies the liveness probe returns 200.
func TestHealthz(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	resp, err := ts.Client().Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusOK)
}

// TestUDMRegistration verifies that Activate calls the UDM UECM endpoint.
func TestUDMRegistration(t *testing.T) {
	mock := newMockAMF(t)
	ts, _ := newTestServer(t, mock)

	supi := "imsi-001010000000001"
	callbackURI := mock.srv.URL + "/namf-comm/v1/ue-contexts/" + supi + "/n1-n2-messages"

	resp := postJSON(t, ts.Client(), ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi,
		activateBody(supi, "3GPP_ACCESS", "amf-001", callbackURI))
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusCreated)

	// Give time for the UDM registration to complete (it is synchronous in Activate).
	// Check that the mock AMF (acting as UDM too) received the UECM registration.
	udmCalls := mock.udmCallsSeen()
	if len(udmCalls) == 0 {
		t.Error("UDM UECM registration was not called on Activate")
	} else {
		found := false
		for _, path := range udmCalls {
			if strings.Contains(path, supi) && strings.Contains(path, "smsf-3gpp-access") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("UDM UECM registration path not found for supi=%s; calls: %v", supi, udmCalls)
		}
	}
}
