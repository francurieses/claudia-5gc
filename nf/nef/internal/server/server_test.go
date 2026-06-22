// Package server — unit tests for the NEF Nnef_AFsessionWithQoS SBI server.
//
// Tests use httptest.NewServer(srv.Handler()) with mock BSFClient and mock
// PolicyAuthorizationClient so no real TLS or network is required.
// OAuth2 tokens are minted with oauth2pkg.IssueToken using the test secret.
//
// Ref: TS 29.522 §4.4.13 (Nnef_AFsessionWithQoS), TS 29.521 §5.2.2.4 (BSF),
// TS 29.514 §5.2.2.2 (Npcf_PolicyAuthorization)
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/francurieses/5gc-rel17/nf/nef/internal/config"
	oauth2pkg "github.com/francurieses/5gc-rel17/shared/oauth2"
)

// ---- test constants ----------------------------------------------------------

const testSecret = "5gc-dev-secret"
const testScope = "nnef-afsessionwithqos"

// ---- mock clients ------------------------------------------------------------

// mockBSFClient is a test-double for BSFClient.
// Configure DiscoverFunc to control what Discover returns.
type mockBSFClient struct {
	mu           sync.Mutex
	discoveredIP string // last IP queried
	DiscoverFunc func(ctx context.Context, ipv4Addr string) (*PcfBinding, error)
}

func (m *mockBSFClient) Discover(ctx context.Context, ipv4Addr string) (*PcfBinding, error) {
	m.mu.Lock()
	m.discoveredIP = ipv4Addr
	m.mu.Unlock()
	return m.DiscoverFunc(ctx, ipv4Addr)
}

// mockPCFClient is a test-double for PolicyAuthorizationClient.
// Configure CreateFunc / DeleteFunc to control what each method returns.
type mockPCFClient struct {
	mu                  sync.Mutex
	lastCreateReq       *AppSessionContextReqData
	lastCreateBaseURI   string
	lastDeleteBaseURI   string
	lastDeleteSessionID string
	deleteCallCount     int
	CreateFunc          func(ctx context.Context, pcfBaseURI string, req *AppSessionContextReqData) (string, error)
	DeleteFunc          func(ctx context.Context, pcfBaseURI, appSessionID string) error
}

func (m *mockPCFClient) CreateAppSession(ctx context.Context, pcfBaseURI string, req *AppSessionContextReqData) (string, error) {
	m.mu.Lock()
	m.lastCreateReq = req
	m.lastCreateBaseURI = pcfBaseURI
	m.mu.Unlock()
	return m.CreateFunc(ctx, pcfBaseURI, req)
}

func (m *mockPCFClient) DeleteAppSession(ctx context.Context, pcfBaseURI, appSessionID string) error {
	m.mu.Lock()
	m.lastDeleteBaseURI = pcfBaseURI
	m.lastDeleteSessionID = appSessionID
	m.deleteCallCount++
	m.mu.Unlock()
	return m.DeleteFunc(ctx, pcfBaseURI, appSessionID)
}

// ---- helpers -----------------------------------------------------------------

// testCfg returns a minimal Config sufficient for unit tests.
// TLS fields are empty so the server falls back to plain HTTP (h2c).
func testCfg() *config.Config {
	cfg := &config.Config{}
	cfg.NFInstanceID = "00000000-0000-4011-8000-000000000001"
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.SBI.FQDN = "nef.5gc.test"
	cfg.OAuth2.Secret = testSecret
	return cfg
}

// defaultBSF returns a mock BSFClient that returns a PcfBinding for any IP.
func defaultBSF() *mockBSFClient {
	return &mockBSFClient{
		DiscoverFunc: func(_ context.Context, _ string) (*PcfBinding, error) {
			return &PcfBinding{
				BindingID: "binding-001",
				PcfFqdn:   "pcf.5gc.test",
				PcfId:     "pcf-instance-001",
				Dnn:       "internet",
			}, nil
		},
	}
}

// defaultPCF returns a mock PCFClient that accepts any app-session.
func defaultPCF() *mockPCFClient {
	return &mockPCFClient{
		CreateFunc: func(_ context.Context, _ string, _ *AppSessionContextReqData) (string, error) {
			return "app-session-001", nil
		},
		DeleteFunc: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
}

// newTestServer creates a Server with the given clients and returns an httptest.Server.
// It uses the plain Handler() (no TLS) suitable for httptest.
func newTestServer(t *testing.T, bsf BSFClient, pcf PolicyAuthorizationClient) (*Server, *httptest.Server) {
	t.Helper()
	cfg := testCfg()
	logger := slog.Default()
	srv := New(cfg, logger, bsf, pcf)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// mintToken creates a valid HS256 JWT for the given scope.
func mintToken(t *testing.T, scope string) string {
	t.Helper()
	tok, err := oauth2pkg.IssueToken([]byte(testSecret), &oauth2pkg.Claims{
		Issuer:    "nrf",
		Subject:   "af-test",
		Scope:     scope,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return tok
}

// doJSON sends a JSON request and returns the response.
func doJSON(t *testing.T, client *http.Client, method, url string, body any, token string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, bodyReader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// decodeBody reads and JSON-decodes the response body into dst.
func decodeBody(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode body: %v", err)
	}
}

// problemBody reads the response and returns the decoded problem+json map.
func problemBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	decodeBody(t, resp, &m)
	return m
}

// ---- test cases --------------------------------------------------------------

// TestCreateHappyPath verifies the full successful Create flow:
// 201, Location header, body with subscriptionId, and that the mock BSF was
// queried with the UE IP and the mock PCF received the AppSessionContextReqData.
//
// Ref: TS 29.522 §4.4.13.2.5 (Create), TS 29.521 §5.2.2.4 (BSF discovery)
func TestCreateHappyPath(t *testing.T) {
	bsf := defaultBSF()
	pcf := defaultPCF()
	_, ts := newTestServer(t, bsf, pcf)

	tok := mintToken(t, testScope)
	reqBody := map[string]any{
		"ueIpv4Addr":   "10.60.0.1",
		"qosReference": "GBR-VIDEO",
	}

	resp := doJSON(t, ts.Client(), http.MethodPost,
		ts.URL+"/3gpp-as-session-with-qos/v1/af1/subscriptions",
		reqBody, tok)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	// Location header must contain the subscriptions path.
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/subscriptions/") {
		t.Errorf("Location %q does not contain /subscriptions/", loc)
	}

	// Response body must contain subscriptionId + echoed ueIpv4Addr + qosReference.
	var sub AsSessionWithQoSSubscription
	decodeBody(t, resp, &sub)
	if sub.SubscriptionID == "" {
		t.Error("body missing subscriptionId")
	}
	if sub.UeIpv4Addr != "10.60.0.1" {
		t.Errorf("body ueIpv4Addr = %q, want 10.60.0.1", sub.UeIpv4Addr)
	}
	if sub.QosReference != "GBR-VIDEO" {
		t.Errorf("body qosReference = %q, want GBR-VIDEO", sub.QosReference)
	}

	// BSF must have been queried with the UE IP.
	bsf.mu.Lock()
	gotIP := bsf.discoveredIP
	bsf.mu.Unlock()
	if gotIP != "10.60.0.1" {
		t.Errorf("BSF queried with IP %q, want 10.60.0.1", gotIP)
	}

	// PCF must have received AppSessionContextReqData with ueIpv4 + qosReference.
	pcf.mu.Lock()
	req := pcf.lastCreateReq
	pcf.mu.Unlock()
	if req == nil {
		t.Fatal("PCF CreateAppSession was not called")
	}
	if req.UeIpv4 != "10.60.0.1" {
		t.Errorf("PCF req.UeIpv4 = %q, want 10.60.0.1", req.UeIpv4)
	}
	if req.QosReference != "GBR-VIDEO" {
		t.Errorf("PCF req.QosReference = %q, want GBR-VIDEO", req.QosReference)
	}
}

// TestCreateMissingBearerToken verifies that a request without an Authorization
// header returns 401 with cause UNAUTHORIZED.
//
// Ref: TS 29.522 §6, TS 29.500 §5.2.7.2
func TestCreateMissingBearerToken(t *testing.T) {
	_, ts := newTestServer(t, defaultBSF(), defaultPCF())

	reqBody := map[string]any{"ueIpv4Addr": "10.60.0.1", "qosReference": "GBR-VIDEO"}
	resp := doJSON(t, ts.Client(), http.MethodPost,
		ts.URL+"/3gpp-as-session-with-qos/v1/af1/subscriptions",
		reqBody, "" /* no token */)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	prob := problemBody(t, resp)
	if prob["cause"] != "UNAUTHORIZED" {
		t.Errorf("cause = %v, want UNAUTHORIZED", prob["cause"])
	}
}

// TestCreateWrongScope verifies that a valid token with the wrong scope returns
// 403 with cause UNAUTHORIZED_AF.
//
// Ref: TS 29.522 §6 (scope enforcement)
func TestCreateWrongScope(t *testing.T) {
	_, ts := newTestServer(t, defaultBSF(), defaultPCF())

	tok := mintToken(t, "nnrf-disc") // wrong scope
	reqBody := map[string]any{"ueIpv4Addr": "10.60.0.1", "qosReference": "GBR-VIDEO"}
	resp := doJSON(t, ts.Client(), http.MethodPost,
		ts.URL+"/3gpp-as-session-with-qos/v1/af1/subscriptions",
		reqBody, tok)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	prob := problemBody(t, resp)
	if prob["cause"] != "UNAUTHORIZED_AF" {
		t.Errorf("cause = %v, want UNAUTHORIZED_AF", prob["cause"])
	}
}

// TestCreateMissingUEAddress verifies that a request without ueIpv4Addr or
// ueIpv6Addr returns 400 with cause MANDATORY_IE_MISSING.
//
// Ref: TS 29.522 §5.14.2.1.2 (mandatory IEs)
func TestCreateMissingUEAddress(t *testing.T) {
	_, ts := newTestServer(t, defaultBSF(), defaultPCF())

	tok := mintToken(t, testScope)
	// No ueIpv4Addr or ueIpv6Addr in body.
	reqBody := map[string]any{"qosReference": "GBR-VIDEO"}
	resp := doJSON(t, ts.Client(), http.MethodPost,
		ts.URL+"/3gpp-as-session-with-qos/v1/af1/subscriptions",
		reqBody, tok)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	prob := problemBody(t, resp)
	if prob["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %v, want MANDATORY_IE_MISSING", prob["cause"])
	}
}

// TestCreateMissingQosReference verifies that a request without qosReference
// returns 400 with cause MANDATORY_IE_MISSING.
//
// Ref: TS 29.522 §5.14.2.1.2 (qosReference mandatory)
func TestCreateMissingQosReference(t *testing.T) {
	_, ts := newTestServer(t, defaultBSF(), defaultPCF())

	tok := mintToken(t, testScope)
	reqBody := map[string]any{"ueIpv4Addr": "10.60.0.1"} // no qosReference
	resp := doJSON(t, ts.Client(), http.MethodPost,
		ts.URL+"/3gpp-as-session-with-qos/v1/af1/subscriptions",
		reqBody, tok)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	prob := problemBody(t, resp)
	if prob["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %v, want MANDATORY_IE_MISSING", prob["cause"])
	}
}

// TestCreateBSFDiscoveryMiss verifies that when the BSF returns
// ErrPcfBindingNotFound the NEF returns 404 with cause PCF_BINDING_NOT_FOUND.
//
// Ref: TS 29.521 §5.2.2.4.4 (discovery miss)
func TestCreateBSFDiscoveryMiss(t *testing.T) {
	bsf := &mockBSFClient{
		DiscoverFunc: func(_ context.Context, _ string) (*PcfBinding, error) {
			return nil, ErrPcfBindingNotFound
		},
	}
	_, ts := newTestServer(t, bsf, defaultPCF())

	tok := mintToken(t, testScope)
	reqBody := map[string]any{"ueIpv4Addr": "10.60.0.2", "qosReference": "GBR-VIDEO"}
	resp := doJSON(t, ts.Client(), http.MethodPost,
		ts.URL+"/3gpp-as-session-with-qos/v1/af1/subscriptions",
		reqBody, tok)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	prob := problemBody(t, resp)
	if prob["cause"] != "PCF_BINDING_NOT_FOUND" {
		t.Errorf("cause = %v, want PCF_BINDING_NOT_FOUND", prob["cause"])
	}
}

// TestCreatePCFRejects verifies that when the PCF returns a "403" error,
// the NEF propagates a 403 to the AF.
//
// Ref: TS 29.514 §5.2.2.2.4 (PCF authorization rejection)
func TestCreatePCFRejects(t *testing.T) {
	pcf := &mockPCFClient{
		CreateFunc: func(_ context.Context, _ string, _ *AppSessionContextReqData) (string, error) {
			return "", fmt.Errorf("403: pcf rejected policy authorization")
		},
		DeleteFunc: func(_ context.Context, _, _ string) error { return nil },
	}
	_, ts := newTestServer(t, defaultBSF(), pcf)

	tok := mintToken(t, testScope)
	reqBody := map[string]any{"ueIpv4Addr": "10.60.0.1", "qosReference": "RESTRICTED"}
	resp := doJSON(t, ts.Client(), http.MethodPost,
		ts.URL+"/3gpp-as-session-with-qos/v1/af1/subscriptions",
		reqBody, tok)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestGetExistingSubscription verifies that a GET on a previously created
// subscription returns 200 with the subscription body.
//
// Ref: TS 29.522 §4.4.13.2.5 (Get)
func TestGetExistingSubscription(t *testing.T) {
	_, ts := newTestServer(t, defaultBSF(), defaultPCF())
	tok := mintToken(t, testScope)

	// Create a subscription first.
	reqBody := map[string]any{"ueIpv4Addr": "10.60.0.3", "qosReference": "GBR-VOICE"}
	createResp := doJSON(t, ts.Client(), http.MethodPost,
		ts.URL+"/3gpp-as-session-with-qos/v1/af2/subscriptions",
		reqBody, tok)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", createResp.StatusCode)
	}
	loc := createResp.Header.Get("Location")
	createResp.Body.Close()

	// Extract subscriptionId from Location URL tail.
	parts := strings.Split(strings.TrimRight(loc, "/"), "/")
	subID := parts[len(parts)-1]

	// GET the subscription.
	getResp := doJSON(t, ts.Client(), http.MethodGet,
		ts.URL+"/3gpp-as-session-with-qos/v1/af2/subscriptions/"+subID,
		nil, tok)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", getResp.StatusCode)
	}
	var sub AsSessionWithQoSSubscription
	decodeBody(t, getResp, &sub)
	if sub.UeIpv4Addr != "10.60.0.3" {
		t.Errorf("get body ueIpv4Addr = %q, want 10.60.0.3", sub.UeIpv4Addr)
	}
}

// TestGetUnknownSubscription verifies that a GET on an unknown subscriptionId
// returns 404.
//
// Ref: TS 29.522 §4.4.13.2.5
func TestGetUnknownSubscription(t *testing.T) {
	_, ts := newTestServer(t, defaultBSF(), defaultPCF())
	tok := mintToken(t, testScope)

	resp := doJSON(t, ts.Client(), http.MethodGet,
		ts.URL+"/3gpp-as-session-with-qos/v1/af1/subscriptions/does-not-exist",
		nil, tok)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestDeleteExistingSubscription verifies that a DELETE on an existing
// subscription returns 204 and that the mock PCF's DeleteAppSession was called
// with the correct appSessionId.
//
// Ref: TS 29.522 §4.4.13.2.5 (Delete), TS 29.514 §5.2.2.4
func TestDeleteExistingSubscription(t *testing.T) {
	pcf := defaultPCF()
	_, ts := newTestServer(t, defaultBSF(), pcf)
	tok := mintToken(t, testScope)

	// Create a subscription so we have something to delete.
	reqBody := map[string]any{"ueIpv4Addr": "10.60.0.4", "qosReference": "GBR-VIDEO"}
	createResp := doJSON(t, ts.Client(), http.MethodPost,
		ts.URL+"/3gpp-as-session-with-qos/v1/af3/subscriptions",
		reqBody, tok)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", createResp.StatusCode)
	}
	loc := createResp.Header.Get("Location")
	createResp.Body.Close()

	parts := strings.Split(strings.TrimRight(loc, "/"), "/")
	subID := parts[len(parts)-1]

	// DELETE the subscription.
	delResp := doJSON(t, ts.Client(), http.MethodDelete,
		ts.URL+"/3gpp-as-session-with-qos/v1/af3/subscriptions/"+subID,
		nil, tok)
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", delResp.StatusCode)
	}
	delResp.Body.Close()

	// PCF DeleteAppSession must have been called with the app-session ID returned
	// by the mock Create ("app-session-001").
	pcf.mu.Lock()
	deletedID := pcf.lastDeleteSessionID
	deleteCount := pcf.deleteCallCount
	pcf.mu.Unlock()

	if deleteCount != 1 {
		t.Errorf("PCF DeleteAppSession called %d times, want 1", deleteCount)
	}
	if deletedID != "app-session-001" {
		t.Errorf("PCF DeleteAppSession got appSessionId %q, want app-session-001", deletedID)
	}
}

// TestDeleteUnknownSubscription verifies that a DELETE on an unknown
// subscriptionId returns 404.
//
// Ref: TS 29.522 §4.4.13.2.5
func TestDeleteUnknownSubscription(t *testing.T) {
	_, ts := newTestServer(t, defaultBSF(), defaultPCF())
	tok := mintToken(t, testScope)

	resp := doJSON(t, ts.Client(), http.MethodDelete,
		ts.URL+"/3gpp-as-session-with-qos/v1/af1/subscriptions/ghost-id",
		nil, tok)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
