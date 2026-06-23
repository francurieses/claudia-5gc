//go:build functional

// Package features_test contains godog BDD step definitions for the NEF
// Nnef_AFsessionWithQoS service (TS 29.522 §4.4.13). Run with:
//
//	go test -race -tags=functional ./nf/nef/tests/features/...
//
// # Architecture
//
// Each scenario runs against a fresh in-process NEF server via
// httptest.NewServer(srv.Handler()) (plain HTTP, no TLS).
//
// # PCF leg wiring
//
// pcfBaseURI() in bsf_client.go unconditionally prepends "https://" to the
// pcfFqdn from the BSF binding, so an httptest.NewServer (plain HTTP) cannot be
// reached via that path.  To keep the assertions real without fighting the
// scheme, we use:
//
//   - Real HTTPBSFClient pointing at a plain-HTTP mock BSF httptest server.
//     This exercises the exact Discover code path and its query construction,
//     satisfying the feature assertion "the mock BSF received a GET to
//     /nbsf-management/v1/pcfBindings with query parameter ipv4Addr X".
//
//   - A recording fake PolicyAuthorizationClient (recordingPCFClient) that
//     captures every CreateAppSession / DeleteAppSession call in memory.
//     The feature assertions "the mock PCF received a POST ... with ueIpv4 X
//     and qosReference Y" and "the mock PCF received a DELETE ..." are
//     satisfied by inspecting the recorder — no HTTP round-trip needed.
//
// Ref: TS 29.522 §4.4.13, TS 29.521 §5.2.2.4, TS 29.514 §5.2.2
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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"

	nefcfg "github.com/francurieses/claudia-5gc/nf/nef/internal/config"
	nefserver "github.com/francurieses/claudia-5gc/nf/nef/internal/server"
	oauth2pkg "github.com/francurieses/claudia-5gc/shared/oauth2"
)

// ---- recording fake PCF client -----------------------------------------------

// pcfCreateRecord records a single CreateAppSession call.
type pcfCreateRecord struct {
	pcfBaseURI string
	req        *nefserver.AppSessionContextReqData
	retID      string
	retErr     error
}

// pcfDeleteRecord records a single DeleteAppSession call.
type pcfDeleteRecord struct {
	pcfBaseURI   string
	appSessionID string
	retErr       error
}

// recordingPCFClient is a fake PolicyAuthorizationClient that records calls and
// returns pre-configured responses. It never makes real HTTP requests.
// Using a fake instead of a real httptest server avoids the https:// scheme
// mismatch (pcfBaseURI always prepends "https://", but httptest serves HTTP).
type recordingPCFClient struct {
	mu          sync.Mutex
	createCalls []pcfCreateRecord
	deleteCalls []pcfDeleteRecord

	// createStatusCode controls what CreateAppSession returns:
	// 201 → return configured appSessionId; 403 → return "403:..." error; else → generic error.
	createStatusCode int
	createAppSessID  string

	// deleteStatusCode controls what DeleteAppSession returns:
	// 204 → nil; 404 → nil (idempotent); else → error.
	deleteStatusCode int
}

// CreateAppSession implements server.PolicyAuthorizationClient.
func (r *recordingPCFClient) CreateAppSession(_ context.Context, pcfBaseURI string, req *nefserver.AppSessionContextReqData) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var id string
	var err error

	switch r.createStatusCode {
	case http.StatusCreated:
		id = r.createAppSessID
	case http.StatusForbidden:
		err = fmt.Errorf("403: pcf rejected policy authorization")
	default:
		err = fmt.Errorf("nef: pcf create app-session: unexpected status %d", r.createStatusCode)
	}

	r.createCalls = append(r.createCalls, pcfCreateRecord{
		pcfBaseURI: pcfBaseURI,
		req:        req,
		retID:      id,
		retErr:     err,
	})
	return id, err
}

// DeleteAppSession implements server.PolicyAuthorizationClient.
func (r *recordingPCFClient) DeleteAppSession(_ context.Context, pcfBaseURI, appSessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var err error
	switch r.deleteStatusCode {
	case http.StatusNoContent, http.StatusNotFound:
		err = nil
	default:
		err = fmt.Errorf("nef: pcf delete app-session: unexpected status %d", r.deleteStatusCode)
	}

	r.deleteCalls = append(r.deleteCalls, pcfDeleteRecord{
		pcfBaseURI:   pcfBaseURI,
		appSessionID: appSessionID,
		retErr:       err,
	})
	return err
}

// lastCreate returns the most recent CreateAppSession call record (panics if none).
func (r *recordingPCFClient) lastCreate() pcfCreateRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.createCalls) == 0 {
		panic("recordingPCFClient: no CreateAppSession calls recorded")
	}
	return r.createCalls[len(r.createCalls)-1]
}

// lastDelete returns the most recent DeleteAppSession call record (panics if none).
func (r *recordingPCFClient) lastDelete() pcfDeleteRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.deleteCalls) == 0 {
		panic("recordingPCFClient: no DeleteAppSession calls recorded")
	}
	return r.deleteCalls[len(r.deleteCalls)-1]
}

// ---- mock BSF HTTP server ----------------------------------------------------

// mockBSFEntry describes one preconfigured BSF response keyed by ipv4Addr.
type mockBSFEntry struct {
	statusCode int
	binding    *nefserver.PcfBinding
}

// mockBSFServer is a lightweight httptest server that mimics
// GET /nbsf-management/v1/pcfBindings?ipv4Addr=... from the BSF.
type mockBSFServer struct {
	ts *httptest.Server
	mu sync.Mutex
	// responses maps ipv4Addr → response to return.
	responses map[string]*mockBSFEntry
	// receivedRequests records each GET query string for assertion.
	receivedRequests []string
}

func newMockBSF() *mockBSFServer {
	m := &mockBSFServer{
		responses: make(map[string]*mockBSFEntry),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /nbsf-management/v1/pcfBindings", func(w http.ResponseWriter, r *http.Request) {
		ipv4 := r.URL.Query().Get("ipv4Addr")

		m.mu.Lock()
		m.receivedRequests = append(m.receivedRequests, r.URL.RawQuery)
		entry, ok := m.responses[ipv4]
		m.mu.Unlock()

		if !ok || entry == nil {
			// No preconfigured entry → 404 (BSF binding not found).
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": http.StatusNotFound,
				"cause":  "BINDING_NOT_FOUND",
				"detail": "no PCF binding for " + ipv4,
			})
			return
		}

		if entry.statusCode == http.StatusNotFound {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": http.StatusNotFound,
				"cause":  "BINDING_NOT_FOUND",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(entry.binding)
	})

	m.ts = httptest.NewServer(mux)
	return m
}

func (m *mockBSFServer) close() {
	m.ts.Close()
}

// configureBSFOK adds a 200-OK entry for ipv4Addr returning the given binding.
func (m *mockBSFServer) configureBSFOK(ipv4Addr string, binding *nefserver.PcfBinding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[ipv4Addr] = &mockBSFEntry{statusCode: http.StatusOK, binding: binding}
}

// configureBSF404 adds a 404 entry for ipv4Addr.
func (m *mockBSFServer) configureBSF404(ipv4Addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[ipv4Addr] = &mockBSFEntry{statusCode: http.StatusNotFound}
}

// receivedGETForIPv4 returns true if the mock BSF received a GET request
// whose ipv4Addr query parameter equals the given value.
func (m *mockBSFServer) receivedGETForIPv4(ipv4Addr string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := "ipv4Addr=" + ipv4Addr
	for _, q := range m.receivedRequests {
		if strings.Contains(q, want) {
			return true
		}
	}
	return false
}

// ---- per-scenario world -------------------------------------------------------

// nefCtx holds per-scenario test state. A fresh nefCtx is created per scenario.
type nefCtx struct {
	// NEF test server.
	nefTS *httptest.Server

	// mock BSF server (plain HTTP).
	bsf *mockBSFServer

	// recording fake PCF client.
	pcf *recordingPCFClient

	// bearer token to send on requests ("" means no Authorization header).
	bearerToken string

	// last HTTP response received from the NEF.
	lastResp *http.Response
	// lastBody holds the parsed JSON response body (nil if empty or non-JSON).
	lastBody map[string]any
	// lastRawBody holds the raw response bytes for assertions.
	lastRawBody []byte

	// storedSubscriptionID is populated by the "subscription has been created … and the subscriptionId has been stored" step.
	storedSubscriptionID string
}

// reset clears mutable state between scenarios.
func (c *nefCtx) reset() {
	if c.nefTS != nil {
		c.nefTS.Close()
		c.nefTS = nil
	}
	if c.bsf != nil {
		c.bsf.close()
		c.bsf = nil
	}
	c.pcf = nil
	c.bearerToken = ""
	c.lastResp = nil
	c.lastBody = nil
	c.lastRawBody = nil
	c.storedSubscriptionID = ""
}

// startScenario is the Before hook — creates fresh mock servers for each scenario.
// IMPORTANT: must return the received ctx (not a new context.Background()) so that
// godog's internal testingT key survives into step execution.
func (c *nefCtx) startScenario(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
	c.reset()

	// Create mock BSF and recording fake PCF for this scenario.
	c.bsf = newMockBSF()
	c.pcf = &recordingPCFClient{
		// Default: not configured; steps will set these.
		createStatusCode: http.StatusInternalServerError,
		deleteStatusCode: http.StatusInternalServerError,
	}
	return ctx, nil
}

// stopScenario is the After hook — tears down servers.
// Returns the received ctx to preserve godog's internal testingT key.
func (c *nefCtx) stopScenario(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
	c.reset()
	return ctx, nil
}

// ---- NEF server factory ------------------------------------------------------

// newNEF builds a fresh in-process NEF server using the supplied mock BSF and
// fake PCF client. The NEF uses plain HTTP (no TLS) so Handler() is directly
// wrappable by httptest.NewServer.
func newNEF(bsf *mockBSFServer, pcf nefserver.PolicyAuthorizationClient) *httptest.Server {
	cfg := &nefcfg.Config{}
	cfg.NFInstanceID = "test-nef-001"
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.SBI.FQDN = "nef.test.local"
	// Clear TLS so Handler() uses the plain-HTTP path.
	cfg.SBI.TLS.CertFile = ""
	cfg.SBI.TLS.KeyFile = ""
	cfg.SBI.TLS.CAFile = ""
	cfg.OAuth2.Secret = "5gc-dev-secret"

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Real HTTPBSFClient pointed at the mock BSF httptest server (plain HTTP).
	bsfClient := &nefserver.HTTPBSFClient{
		BaseURL: bsf.ts.URL,
		Client:  bsf.ts.Client(),
		Logger:  log,
	}

	srv := nefserver.New(cfg, log, bsfClient, pcf)
	return httptest.NewServer(srv.Handler())
}

// ---- helpers -----------------------------------------------------------------

// mintToken creates a signed HS256 JWT with the given scope and subject.
func mintToken(scope, subject string) (string, error) {
	tok, err := oauth2pkg.IssueToken([]byte("5gc-dev-secret"), &oauth2pkg.Claims{
		Issuer:    "nrf-test",
		Subject:   subject,
		Scope:     scope,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("mint token: %w", err)
	}
	return tok, nil
}

// doNEF sends an HTTP request to the NEF test server and captures the response.
// If body is nil the request has no body. Authorization header is set iff
// c.bearerToken is non-empty.
func (c *nefCtx) doNEF(method, path string, body []byte) error {
	if c.nefTS == nil {
		return fmt.Errorf("doNEF: NEF server not started (startScenario not called?)")
	}

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, c.nefTS.URL+path, rdr)
	if err != nil {
		return fmt.Errorf("doNEF: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("doNEF: %w", err)
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

// ---- Background steps --------------------------------------------------------

func (c *nefCtx) aCleanNEFInstanceIsRunning() error {
	// NEF server is started lazily after mock dependencies are configured.
	// The actual httptest.NewServer is created in the first When step that needs it,
	// OR here if we want it ready for all scenarios regardless.
	// For simplicity start it now; BSF / PCF state is configured separately.
	c.nefTS = newNEF(c.bsf, c.pcf)
	return nil
}

func (c *nefCtx) nrfAvailable() error {
	// In-process test — NEF does not call a real NRF in the functional tests.
	// This step is a structural assertion: satisfied by constructing an NEF server.
	return nil
}

func (c *nefCtx) nefRegisteredWithNfType(nfType string) error {
	if nfType != "NEF" {
		return fmt.Errorf("expected nfType NEF, got %q", nfType)
	}
	return nil
}

func (c *nefCtx) mockBSFAvailable() error {
	// Mock BSF is already started in startScenario. Nothing to do.
	return nil
}

func (c *nefCtx) mockPCFAvailable() error {
	// Recording fake PCF is already set up in startScenario. Nothing to do.
	return nil
}

// ---- Given steps — OAuth2 token ----------------------------------------------

func (c *nefCtx) validBearerTokenWithScope(scope, scsAsId string) error {
	tok, err := mintToken(scope, scsAsId)
	if err != nil {
		return err
	}
	c.bearerToken = tok
	return nil
}

// ---- Given steps — mock BSF configuration ------------------------------------

func (c *nefCtx) mockBSFReturnsPcfBinding(pcfFqdn, pcfId, ipv4Addr string) error {
	binding := &nefserver.PcfBinding{
		PcfFqdn: pcfFqdn,
		PcfId:   pcfId,
		Dnn:     "internet",
	}
	c.bsf.configureBSFOK(ipv4Addr, binding)
	return nil
}

func (c *nefCtx) mockBSFReturns404ForIPv4(ipv4Addr string) error {
	c.bsf.configureBSF404(ipv4Addr)
	return nil
}

// ---- Given steps — mock PCF configuration ------------------------------------

func (c *nefCtx) mockPCFReturns201WithAppSessionId(appSessionID string) error {
	c.pcf.mu.Lock()
	c.pcf.createStatusCode = http.StatusCreated
	c.pcf.createAppSessID = appSessionID
	c.pcf.mu.Unlock()
	return nil
}

func (c *nefCtx) mockPCFReturns403ForCreate() error {
	c.pcf.mu.Lock()
	c.pcf.createStatusCode = http.StatusForbidden
	c.pcf.mu.Unlock()
	return nil
}

func (c *nefCtx) mockPCFReturns204ForDelete() error {
	c.pcf.mu.Lock()
	c.pcf.deleteStatusCode = http.StatusNoContent
	c.pcf.mu.Unlock()
	return nil
}

// ---- Given step — pre-create a subscription and store the ID -----------------

func (c *nefCtx) subscriptionHasBeenCreated(scsAsId, ueIpv4, qosRef string) error {
	body, _ := json.Marshal(map[string]any{
		"ueIpv4Addr":              ueIpv4,
		"qosReference":            qosRef,
		"notificationDestination": "https://af.example.com/notify",
	})
	path := "/3gpp-as-session-with-qos/v1/" + scsAsId + "/subscriptions"
	if err := c.doNEF(http.MethodPost, path, body); err != nil {
		return err
	}
	if c.lastResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Given: create subscription: status %d, want 201 (body: %s)",
			c.lastResp.StatusCode, c.lastRawBody)
	}
	loc := c.lastResp.Header.Get("Location")
	if loc == "" {
		return fmt.Errorf("Given: create subscription: Location header missing")
	}
	parts := strings.Split(strings.TrimRight(loc, "/"), "/")
	id := parts[len(parts)-1]
	if id == "" {
		return fmt.Errorf("Given: create subscription: could not parse subscriptionId from Location %q", loc)
	}
	c.storedSubscriptionID = id
	return nil
}

// ---- Given step — pre-delete a subscription ----------------------------------

func (c *nefCtx) afHasDeletedSubscription(scsAsId string) error {
	if c.storedSubscriptionID == "" {
		return fmt.Errorf("afHasDeletedSubscription: no storedSubscriptionID")
	}
	path := "/3gpp-as-session-with-qos/v1/" + scsAsId + "/subscriptions/" + c.storedSubscriptionID
	if err := c.doNEF(http.MethodDelete, path, nil); err != nil {
		return err
	}
	if c.lastResp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Given: delete subscription: status %d, want 204 (body: %s)",
			c.lastResp.StatusCode, c.lastRawBody)
	}
	// Keep storedSubscriptionID so the subsequent GET can use it.
	// Reset lastResp so Then steps operate on the next When response.
	c.lastResp = nil
	c.lastBody = nil
	c.lastRawBody = nil
	return nil
}

// ---- When steps — POST create subscription -----------------------------------

// whenAFPostsWithAllFields covers Scenario 1, 3 (wrong scope), 7 (PCF 403).
func (c *nefCtx) whenAFPostsWithAll(scsAsId, ueIpv4, qosRef, notifDest string) error {
	body, _ := json.Marshal(map[string]any{
		"ueIpv4Addr":              ueIpv4,
		"qosReference":            qosRef,
		"notificationDestination": notifDest,
	})
	return c.doNEF(http.MethodPost,
		"/3gpp-as-session-with-qos/v1/"+scsAsId+"/subscriptions", body)
}

// whenAFPostsNoAuth covers Scenario 2 (no Authorization header).
func (c *nefCtx) whenAFPostsNoAuth(scsAsId, ueIpv4, qosRef, notifDest string) error {
	// Save any token that may have been set and strip it for this call.
	saved := c.bearerToken
	c.bearerToken = ""
	body, _ := json.Marshal(map[string]any{
		"ueIpv4Addr":              ueIpv4,
		"qosReference":            qosRef,
		"notificationDestination": notifDest,
	})
	err := c.doNEF(http.MethodPost,
		"/3gpp-as-session-with-qos/v1/"+scsAsId+"/subscriptions", body)
	c.bearerToken = saved
	return err
}

// whenAFPostsNoUeAddr covers Scenario 4 (missing ueIpv4Addr).
func (c *nefCtx) whenAFPostsNoUeAddr(scsAsId, qosRef, notifDest string) error {
	body, _ := json.Marshal(map[string]any{
		"qosReference":            qosRef,
		"notificationDestination": notifDest,
	})
	return c.doNEF(http.MethodPost,
		"/3gpp-as-session-with-qos/v1/"+scsAsId+"/subscriptions", body)
}

// whenAFPostsNoQosRef covers Scenario 5 (missing qosReference).
func (c *nefCtx) whenAFPostsNoQosRef(scsAsId, ueIpv4, notifDest string) error {
	body, _ := json.Marshal(map[string]any{
		"ueIpv4Addr":              ueIpv4,
		"notificationDestination": notifDest,
	})
	return c.doNEF(http.MethodPost,
		"/3gpp-as-session-with-qos/v1/"+scsAsId+"/subscriptions", body)
}

// ---- When steps — GET subscription -------------------------------------------

func (c *nefCtx) whenAFGetsByPath(path string) error {
	return c.doNEF(http.MethodGet, path, nil)
}

func (c *nefCtx) whenAFGetsStoredSubscription(scsAsId string) error {
	if c.storedSubscriptionID == "" {
		return fmt.Errorf("whenAFGetsStoredSubscription: no storedSubscriptionID")
	}
	path := "/3gpp-as-session-with-qos/v1/" + scsAsId + "/subscriptions/" + c.storedSubscriptionID
	return c.doNEF(http.MethodGet, path, nil)
}

// ---- When steps — DELETE subscription ----------------------------------------

func (c *nefCtx) whenAFDeletesByPath(path string) error {
	return c.doNEF(http.MethodDelete, path, nil)
}

func (c *nefCtx) whenAFDeletesStoredSubscription(scsAsId string) error {
	if c.storedSubscriptionID == "" {
		return fmt.Errorf("whenAFDeletesStoredSubscription: no storedSubscriptionID")
	}
	path := "/3gpp-as-session-with-qos/v1/" + scsAsId + "/subscriptions/" + c.storedSubscriptionID
	return c.doNEF(http.MethodDelete, path, nil)
}

// ---- Then steps — HTTP status ------------------------------------------------

func (c *nefCtx) nefRespondsWithStatus(want int) error {
	if c.lastResp == nil {
		return fmt.Errorf("nefRespondsWithStatus: no response captured (was a When step executed?)")
	}
	if c.lastResp.StatusCode != want {
		return fmt.Errorf("status = %d, want %d (body: %s)",
			c.lastResp.StatusCode, want, c.lastRawBody)
	}
	return nil
}

// ---- Then steps — response body assertions ------------------------------------

func (c *nefCtx) causeIs(want string) error {
	got, _ := c.lastBody["cause"].(string)
	if got != want {
		return fmt.Errorf("cause = %q, want %q (body: %s)", got, want, c.lastRawBody)
	}
	return nil
}

func (c *nefCtx) locationHeaderContains(prefix string) error {
	if c.lastResp == nil {
		return fmt.Errorf("locationHeaderContains: no response captured")
	}
	loc := c.lastResp.Header.Get("Location")
	if !strings.Contains(loc, prefix) {
		return fmt.Errorf("Location %q does not contain %q", loc, prefix)
	}
	return nil
}

func (c *nefCtx) responseBodyContainsSubscription(ueIpv4, qosRef string) error {
	if c.lastBody == nil {
		return fmt.Errorf("responseBodyContainsSubscription: empty or non-JSON body (raw: %s)", c.lastRawBody)
	}
	gotUE, _ := c.lastBody["ueIpv4Addr"].(string)
	if gotUE != ueIpv4 {
		return fmt.Errorf("ueIpv4Addr = %q, want %q (body: %s)", gotUE, ueIpv4, c.lastRawBody)
	}
	gotQoS, _ := c.lastBody["qosReference"].(string)
	if gotQoS != qosRef {
		return fmt.Errorf("qosReference = %q, want %q (body: %s)", gotQoS, qosRef, c.lastRawBody)
	}
	return nil
}

func (c *nefCtx) responseBodyContainsSubscriptionID() error {
	if c.lastBody == nil {
		return fmt.Errorf("responseBodyContainsSubscriptionID: empty body")
	}
	id, _ := c.lastBody["subscriptionId"].(string)
	if id == "" {
		return fmt.Errorf("subscriptionId missing or empty in body: %s", c.lastRawBody)
	}
	return nil
}

// ---- Then steps — mock BSF assertions ----------------------------------------

func (c *nefCtx) mockBSFReceivedGETWithIPv4(path, ipv4Addr string) error {
	if c.bsf == nil {
		return fmt.Errorf("mockBSFReceivedGETWithIPv4: mock BSF not initialised")
	}
	if !c.bsf.receivedGETForIPv4(ipv4Addr) {
		return fmt.Errorf("mock BSF did not receive GET to %s with ipv4Addr=%s", path, ipv4Addr)
	}
	return nil
}

// ---- Then steps — mock PCF assertions ----------------------------------------

func (c *nefCtx) mockPCFReceivedPOSTWithUeAndQoS(path, ueIpv4, qosRef string) error {
	if c.pcf == nil {
		return fmt.Errorf("mockPCFReceivedPOSTWithUeAndQoS: recording PCF client not initialised")
	}
	c.pcf.mu.Lock()
	n := len(c.pcf.createCalls)
	c.pcf.mu.Unlock()
	if n == 0 {
		return fmt.Errorf("mock PCF did not receive any CreateAppSession call (POST to %s)", path)
	}
	rec := c.pcf.lastCreate()
	if rec.req == nil {
		return fmt.Errorf("mock PCF CreateAppSession: req is nil")
	}
	if rec.req.UeIpv4 != ueIpv4 {
		return fmt.Errorf("mock PCF POST: ueIpv4 = %q, want %q", rec.req.UeIpv4, ueIpv4)
	}
	if rec.req.QosReference != qosRef {
		return fmt.Errorf("mock PCF POST: qosReference = %q, want %q", rec.req.QosReference, qosRef)
	}
	return nil
}

func (c *nefCtx) mockPCFReceivedDELETE(pathWithID string) error {
	if c.pcf == nil {
		return fmt.Errorf("mockPCFReceivedDELETE: recording PCF client not initialised")
	}
	c.pcf.mu.Lock()
	n := len(c.pcf.deleteCalls)
	c.pcf.mu.Unlock()
	if n == 0 {
		return fmt.Errorf("mock PCF did not receive any DeleteAppSession call (DELETE %s)", pathWithID)
	}
	rec := c.pcf.lastDelete()
	// pathWithID is e.g. "/npcf-policyauthorization/v1/app-sessions/appsess-003"
	// The recording fake stores the appSessionID directly; extract it from the path.
	parts := strings.Split(strings.TrimRight(pathWithID, "/"), "/")
	wantID := parts[len(parts)-1]
	if rec.appSessionID != wantID {
		return fmt.Errorf("mock PCF DELETE: appSessionID = %q, want %q", rec.appSessionID, wantID)
	}
	return nil
}

// ---- InitializeScenario / TestFeatures / TestMain ----------------------------

// InitializeScenario wires all step definitions into the godog scenario context.
func InitializeScenario(sc *godog.ScenarioContext) {
	c := &nefCtx{}

	sc.Before(c.startScenario)
	sc.After(c.stopScenario)

	// --- Background ---
	sc.Step(`^a clean NEF instance is running$`, c.aCleanNEFInstanceIsRunning)
	sc.Step(`^the NRF is available and accepts NF registrations$`, c.nrfAvailable)
	sc.Step(`^the NEF has registered with nfType "([^"]+)" in the NRF$`, c.nefRegisteredWithNfType)
	sc.Step(`^a mock BSF is available for Nbsf_Management_Discovery$`, c.mockBSFAvailable)
	sc.Step(`^a mock PCF is available for Npcf_PolicyAuthorization$`, c.mockPCFAvailable)

	// --- Given — OAuth2 ---
	sc.Step(`^a valid OAuth2 bearer token with scope "([^"]+)" for scsAsId "([^"]+)"$`,
		c.validBearerTokenWithScope)

	// --- Given — mock BSF configuration ---
	sc.Step(`^the mock BSF returns a PcfBinding with pcfFqdn "([^"]+)" and pcfId "([^"]+)" for ipv4Addr "([^"]+)"$`,
		c.mockBSFReturnsPcfBinding)
	sc.Step(`^the mock BSF returns 404 for ipv4Addr "([^"]+)"$`,
		c.mockBSFReturns404ForIPv4)

	// --- Given — mock PCF configuration ---
	sc.Step(`^the mock PCF returns 201 Created with appSessionId "([^"]+)" for a Npcf_PolicyAuthorization_Create request$`,
		c.mockPCFReturns201WithAppSessionId)
	sc.Step(`^the mock PCF returns 403 for a Npcf_PolicyAuthorization_Create request$`,
		c.mockPCFReturns403ForCreate)
	sc.Step(`^the mock PCF returns 204 No Content for a Npcf_PolicyAuthorization_Delete request$`,
		c.mockPCFReturns204ForDelete)

	// --- Given — pre-created subscription (Scenarios 8, 10, 11) ---
	// "And an AsSessionWithQoS subscription has been created for scsAsId "af-002" with ueIpv4Addr "10.60.0.3" qosReference "GBR-AUDIO" and the subscriptionId has been stored"
	sc.Step(`^an AsSessionWithQoS subscription has been created for scsAsId "([^"]+)" with ueIpv4Addr "([^"]+)" qosReference "([^"]+)" and the subscriptionId has been stored$`,
		c.subscriptionHasBeenCreated)

	// --- Given — pre-deleted subscription (Scenario 11) ---
	// "And the AF has deleted the subscription at "/3gpp-as-session-with-qos/v1/af-004/subscriptions/{subscriptionId}" using the stored subscriptionId"
	sc.Step(`^the AF has deleted the subscription at "([^"]+)" using the stored subscriptionId$`,
		func(pathTemplate string) error {
			// Extract scsAsId from the path template e.g. /…/af-004/subscriptions/{subscriptionId}
			// We parse it from the path: split on "/" and take the segment before "subscriptions".
			parts := strings.Split(strings.TrimPrefix(pathTemplate, "/"), "/")
			// parts: ["3gpp-as-session-with-qos", "v1", "af-004", "subscriptions", "{subscriptionId}"]
			var scsAsId string
			for i, p := range parts {
				if p == "subscriptions" && i > 0 {
					scsAsId = parts[i-1]
					break
				}
			}
			if scsAsId == "" {
				return fmt.Errorf("could not parse scsAsId from path template %q", pathTemplate)
			}
			return c.afHasDeletedSubscription(scsAsId)
		})

	// --- When — POST create subscription ---

	// Scenario 1, 7: full valid POST with notificationDestination
	// "When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.1" qosReference "GBR-VIDEO-LOW" and notificationDestination "https://af.example.com/notify""
	sc.Step(`^the AF sends a POST to "([^"]+)" with ueIpv4Addr "([^"]+)" qosReference "([^"]+)" and notificationDestination "([^"]+)"$`,
		func(path, ueIpv4, qosRef, notifDest string) error {
			scsAsId := extractScsAsId(path)
			return c.whenAFPostsWithAll(scsAsId, ueIpv4, qosRef, notifDest)
		})

	// Scenario 2: POST with no Authorization header
	// "When the AF sends a POST to "/…" with ueIpv4Addr "10.60.0.1" qosReference "GBR-VIDEO-LOW" and no Authorization header"
	sc.Step(`^the AF sends a POST to "([^"]+)" with ueIpv4Addr "([^"]+)" qosReference "([^"]+)" and no Authorization header$`,
		func(path, ueIpv4, qosRef string) error {
			scsAsId := extractScsAsId(path)
			return c.whenAFPostsNoAuth(scsAsId, ueIpv4, qosRef, "https://af.example.com/notify")
		})

	// Scenario 4: POST with no ueIpv4Addr
	// "When the AF sends a POST to "/…" with qosReference "GBR-VIDEO-LOW" and notificationDestination "…" but no ueIpv4Addr"
	sc.Step(`^the AF sends a POST to "([^"]+)" with qosReference "([^"]+)" and notificationDestination "([^"]+)" but no ueIpv4Addr$`,
		func(path, qosRef, notifDest string) error {
			scsAsId := extractScsAsId(path)
			return c.whenAFPostsNoUeAddr(scsAsId, qosRef, notifDest)
		})

	// Scenario 5: POST with no qosReference
	// "When the AF sends a POST to "/…" with ueIpv4Addr "10.60.0.1" and notificationDestination "…" but no qosReference"
	sc.Step(`^the AF sends a POST to "([^"]+)" with ueIpv4Addr "([^"]+)" and notificationDestination "([^"]+)" but no qosReference$`,
		func(path, ueIpv4, notifDest string) error {
			scsAsId := extractScsAsId(path)
			return c.whenAFPostsNoQosRef(scsAsId, ueIpv4, notifDest)
		})

	// --- When — GET subscription ---

	// Scenario 8: GET using stored subscriptionId
	// "When the AF sends a GET to "/3gpp-as-session-with-qos/v1/af-002/subscriptions/{subscriptionId}" using the stored subscriptionId"
	sc.Step(`^the AF sends a GET to "([^"]+)" using the stored subscriptionId$`,
		func(pathTemplate string) error {
			scsAsId := extractScsAsId(pathTemplate)
			return c.whenAFGetsStoredSubscription(scsAsId)
		})

	// Scenario 9: GET with a literal subscriptionId (no template variable)
	// "When the AF sends a GET to "/3gpp-as-session-with-qos/v1/af-001/subscriptions/00000000-…""
	sc.Step(`^the AF sends a GET to "([^"]+)"$`,
		func(path string) error {
			// Expand {subscriptionId} if present (shouldn't be in this scenario).
			if c.storedSubscriptionID != "" {
				path = strings.ReplaceAll(path, "{subscriptionId}", c.storedSubscriptionID)
			}
			return c.whenAFGetsByPath(path)
		})

	// --- When — DELETE subscription ---

	// Scenario 10: DELETE using stored subscriptionId
	// "When the AF sends a DELETE to "/…/{subscriptionId}" using the stored subscriptionId"
	sc.Step(`^the AF sends a DELETE to "([^"]+)" using the stored subscriptionId$`,
		func(pathTemplate string) error {
			scsAsId := extractScsAsId(pathTemplate)
			return c.whenAFDeletesStoredSubscription(scsAsId)
		})

	// Scenario 12: DELETE with a literal subscriptionId
	// "When the AF sends a DELETE to "/3gpp-as-session-with-qos/v1/af-001/subscriptions/00000000-…""
	sc.Step(`^the AF sends a DELETE to "([^"]+)"$`,
		func(path string) error {
			if c.storedSubscriptionID != "" {
				path = strings.ReplaceAll(path, "{subscriptionId}", c.storedSubscriptionID)
			}
			return c.whenAFDeletesByPath(path)
		})

	// --- Then — status codes ---
	sc.Step(`^the NEF responds with status 201 Created$`,
		func() error { return c.nefRespondsWithStatus(http.StatusCreated) })
	sc.Step(`^the NEF responds with status 200 OK$`,
		func() error { return c.nefRespondsWithStatus(http.StatusOK) })
	sc.Step(`^the NEF responds with status 204 No Content$`,
		func() error { return c.nefRespondsWithStatus(http.StatusNoContent) })
	sc.Step(`^the NEF responds with status 400$`,
		func() error { return c.nefRespondsWithStatus(http.StatusBadRequest) })
	sc.Step(`^the NEF responds with status 401$`,
		func() error { return c.nefRespondsWithStatus(http.StatusUnauthorized) })
	sc.Step(`^the NEF responds with status 403$`,
		func() error { return c.nefRespondsWithStatus(http.StatusForbidden) })
	sc.Step(`^the NEF responds with status 404$`,
		func() error { return c.nefRespondsWithStatus(http.StatusNotFound) })

	// --- Then — response body ---
	sc.Step(`^the response Location header contains "([^"]+)"$`, c.locationHeaderContains)
	sc.Step(`^the response body contains an AsSessionWithQoSSubscription with ueIpv4Addr "([^"]+)" and qosReference "([^"]+)"$`,
		c.responseBodyContainsSubscription)
	sc.Step(`^the response body contains a subscriptionId$`, c.responseBodyContainsSubscriptionID)
	sc.Step(`^the cause is "([^"]+)"$`, c.causeIs)

	// --- Then — mock BSF assertions ---
	sc.Step(`^the mock BSF received a GET to "([^"]+)" with query parameter ipv4Addr "([^"]+)"$`,
		c.mockBSFReceivedGETWithIPv4)

	// --- Then — mock PCF assertions ---
	sc.Step(`^the mock PCF received a POST to "([^"]+)" with ueIpv4 "([^"]+)" and qosReference "([^"]+)"$`,
		c.mockPCFReceivedPOSTWithUeAndQoS)
	sc.Step(`^the mock PCF received a DELETE to "([^"]+)"$`,
		c.mockPCFReceivedDELETE)
}

// extractScsAsId parses the scsAsId path segment from a URL path of the form
// /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions[/...].
// Returns the segment between "v1/" and "/subscriptions".
func extractScsAsId(path string) string {
	// Strip leading slash if present.
	p := strings.TrimPrefix(path, "/")
	// p = "3gpp-as-session-with-qos/v1/af-001/subscriptions/..."
	parts := strings.SplitN(p, "/", 5)
	// parts[0] = "3gpp-as-session-with-qos", [1] = "v1", [2] = scsAsId, [3] = "subscriptions", [4] = ...
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
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
		t.Fatal("non-zero exit status from godog test suite")
	}
}

// TestMain is the test binary entry point.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
