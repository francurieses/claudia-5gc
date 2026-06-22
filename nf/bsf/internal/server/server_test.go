// Package server_test provides unit tests for the BSF Nbsf_Management SBI server.
//
// Tests are in-process: the Server's handler is driven via httptest.NewServer.
// No TLS, no network calls to NRF required for unit tests.
//
// Coverage:
//   - POST /nbsf-management/v1/pcfBindings → 201 + Location + PcfBinding body
//   - POST → 400 MANDATORY_IE_MISSING (missing dnn, missing snssai, no IP key)
//   - POST → 403 EXISTING_BINDING_INFO_FOUND (duplicate ipv4Addr)
//   - DELETE /nbsf-management/v1/pcfBindings/{bindingId} → 204
//   - DELETE → 404 (unknown bindingId)
//   - GET /nbsf-management/v1/pcfBindings?ipv4Addr=… → 200 + PcfBinding
//   - GET → 200 with supi query parameter
//   - GET → 404 (no match)
//   - GET → 400 MANDATORY_IE_MISSING (no query parameters)
//   - GET /healthz → 200 UP
//
// Ref: TS 29.521 §5
package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/5gc-rel17/nf/bsf/internal/config"
	"github.com/francurieses/5gc-rel17/nf/bsf/internal/server"
)

// ---- helpers ----------------------------------------------------------------

func newTestServer(t *testing.T) (*httptest.Server, *server.Server) {
	t.Helper()
	cfg := &config.Config{}
	cfg.NFInstanceID = "test-bsf-001"
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.SBI.FQDN = "bsf.test.local"
	// No TLS paths — in-process test uses plain HTTP.

	logger := slog.Default()
	srv := server.New(cfg, logger)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv
}

func postBinding(t *testing.T, ts *httptest.Server, body map[string]any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(ts.URL+"/nbsf-management/v1/pcfBindings", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST pcfBindings: %v", err)
	}
	return resp
}

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode body: %v\nbody was: %s", err, string(raw))
	}
	return m
}

// validBinding returns a valid PcfBinding request body.
func validBinding(ipv4Addr string) map[string]any {
	return map[string]any{
		"supi":     "imsi-001010000000001",
		"ipv4Addr": ipv4Addr,
		"dnn":      "internet",
		"snssai":   map[string]any{"sst": 1, "sd": "000001"},
		"pcfFqdn":  "pcf.5gc.mnc001.mcc001.3gppnetwork.org",
		"pcfId":    "pcf-instance-001",
	}
}

// ---- Register (201) ---------------------------------------------------------

func TestRegister_Created(t *testing.T) {
	ts, _ := newTestServer(t)

	resp := postBinding(t, ts, validBinding("10.60.0.1"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/nbsf-management/v1/pcfBindings/") {
		t.Errorf("Location header missing or wrong: %q", location)
	}

	body := decodeBody(t, resp)
	if body["ipv4Addr"] != "10.60.0.1" {
		t.Errorf("body ipv4Addr = %v, want 10.60.0.1", body["ipv4Addr"])
	}
	if body["pcfFqdn"] != "pcf.5gc.mnc001.mcc001.3gppnetwork.org" {
		t.Errorf("body pcfFqdn = %v, want pcf FQDN", body["pcfFqdn"])
	}
	if body["bindingId"] == "" || body["bindingId"] == nil {
		t.Error("response body missing bindingId")
	}
}

// ---- Register — 400 MANDATORY_IE_MISSING ------------------------------------

func TestRegister_MissingDnn(t *testing.T) {
	ts, _ := newTestServer(t)

	body := map[string]any{
		"supi":     "imsi-001010000000001",
		"ipv4Addr": "10.60.0.4",
		"snssai":   map[string]any{"sst": 1, "sd": "000001"},
		"pcfFqdn":  "pcf.5gc.mnc001.mcc001.3gppnetwork.org",
		// dnn intentionally omitted
	}
	resp := postBinding(t, ts, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	m := decodeBody(t, resp)
	if m["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %v, want MANDATORY_IE_MISSING", m["cause"])
	}
}

func TestRegister_MissingSnssai(t *testing.T) {
	ts, _ := newTestServer(t)

	body := map[string]any{
		"supi":     "imsi-001010000000001",
		"ipv4Addr": "10.60.0.5",
		"dnn":      "internet",
		"pcfFqdn":  "pcf.5gc.mnc001.mcc001.3gppnetwork.org",
		// snssai intentionally omitted
	}
	resp := postBinding(t, ts, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	m := decodeBody(t, resp)
	if m["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %v, want MANDATORY_IE_MISSING", m["cause"])
	}
}

func TestRegister_NoIPKey(t *testing.T) {
	ts, _ := newTestServer(t)

	body := map[string]any{
		"supi":    "imsi-001010000000001",
		"dnn":     "internet",
		"snssai":  map[string]any{"sst": 1, "sd": "000001"},
		"pcfFqdn": "pcf.5gc.mnc001.mcc001.3gppnetwork.org",
		// no ipv4Addr, ipv6Prefix, or macAddr48
	}
	resp := postBinding(t, ts, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	m := decodeBody(t, resp)
	if m["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %v, want MANDATORY_IE_MISSING", m["cause"])
	}
}

func TestRegister_NoPCFEndpoint(t *testing.T) {
	ts, _ := newTestServer(t)

	body := map[string]any{
		"supi":     "imsi-001010000000001",
		"ipv4Addr": "10.60.0.55",
		"dnn":      "internet",
		"snssai":   map[string]any{"sst": 1, "sd": "000001"},
		// no pcfFqdn or pcfIpEndPoints
	}
	resp := postBinding(t, ts, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	m := decodeBody(t, resp)
	if m["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %v, want MANDATORY_IE_MISSING", m["cause"])
	}
}

// ---- Register — 403 EXISTING_BINDING_INFO_FOUND -----------------------------

func TestRegister_DuplicateIP_403(t *testing.T) {
	ts, _ := newTestServer(t)

	// First registration.
	resp1 := postBinding(t, ts, validBinding("10.60.0.6"))
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first register: expected 201, got %d", resp1.StatusCode)
	}
	resp1.Body.Close()

	// Duplicate registration for the same IPv4 address.
	resp2 := postBinding(t, ts, validBinding("10.60.0.6"))
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("duplicate register: expected 403, got %d", resp2.StatusCode)
	}
	m := decodeBody(t, resp2)
	if m["cause"] != "EXISTING_BINDING_INFO_FOUND" {
		t.Errorf("cause = %v, want EXISTING_BINDING_INFO_FOUND", m["cause"])
	}
}

// ---- Deregister (204) -------------------------------------------------------

func TestDeregister_NoContent(t *testing.T) {
	ts, _ := newTestServer(t)

	// Register a binding first.
	resp := postBinding(t, ts, validBinding("10.60.0.10"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	bindingID, _ := body["bindingId"].(string)
	if bindingID == "" {
		t.Fatal("no bindingId in register response")
	}

	// Deregister.
	req, _ := http.NewRequest(http.MethodDelete,
		ts.URL+"/nbsf-management/v1/pcfBindings/"+bindingID, nil)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", delResp.StatusCode)
	}
}

// ---- Deregister — 404 -------------------------------------------------------

func TestDeregister_NotFound(t *testing.T) {
	ts, _ := newTestServer(t)

	req, _ := http.NewRequest(http.MethodDelete,
		ts.URL+"/nbsf-management/v1/pcfBindings/00000000-0000-0000-0000-000000000000", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ---- Discovery — 200 --------------------------------------------------------

func TestDiscover_ByIPv4_OK(t *testing.T) {
	ts, _ := newTestServer(t)

	// Register.
	resp := postBinding(t, ts, validBinding("10.60.0.20"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Discover.
	getResp, err := http.Get(ts.URL + "/nbsf-management/v1/pcfBindings?ipv4Addr=10.60.0.20")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", getResp.StatusCode)
	}
	body := decodeBody(t, getResp)
	if body["ipv4Addr"] != "10.60.0.20" {
		t.Errorf("ipv4Addr = %v, want 10.60.0.20", body["ipv4Addr"])
	}
	if body["pcfFqdn"] != "pcf.5gc.mnc001.mcc001.3gppnetwork.org" {
		t.Errorf("pcfFqdn = %v, want pcf FQDN", body["pcfFqdn"])
	}
}

func TestDiscover_BySupi_OK(t *testing.T) {
	ts, _ := newTestServer(t)

	// Register with a known SUPI.
	b := validBinding("10.60.0.21")
	b["supi"] = "imsi-001010000000002"
	resp := postBinding(t, ts, b)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Discover by SUPI.
	getResp, err := http.Get(ts.URL + "/nbsf-management/v1/pcfBindings?supi=imsi-001010000000002")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", getResp.StatusCode)
	}
	body := decodeBody(t, getResp)
	if body["supi"] != "imsi-001010000000002" {
		t.Errorf("supi = %v, want imsi-001010000000002", body["supi"])
	}
}

// ---- Deregister then Discover → 404 -----------------------------------------

func TestDeregisterThenDiscover_NotFound(t *testing.T) {
	ts, _ := newTestServer(t)

	// Register.
	resp := postBinding(t, ts, validBinding("10.60.0.30"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.StatusCode)
	}
	regBody := decodeBody(t, resp)
	bindingID, _ := regBody["bindingId"].(string)

	// Deregister.
	req, _ := http.NewRequest(http.MethodDelete,
		ts.URL+"/nbsf-management/v1/pcfBindings/"+bindingID, nil)
	delResp, _ := http.DefaultClient.Do(req)
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", delResp.StatusCode)
	}

	// Discover — should be 404 now.
	getResp, err := http.Get(ts.URL + "/nbsf-management/v1/pcfBindings?ipv4Addr=10.60.0.30")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after deregister, got %d", getResp.StatusCode)
	}
}

// ---- Discovery — 404 (no match) ---------------------------------------------

func TestDiscover_NoMatch_404(t *testing.T) {
	ts, _ := newTestServer(t)

	getResp, err := http.Get(ts.URL + "/nbsf-management/v1/pcfBindings?ipv4Addr=10.60.0.99")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", getResp.StatusCode)
	}
}

// ---- Discovery — 400 MANDATORY_IE_MISSING (no params) -----------------------

func TestDiscover_NoQueryParam_400(t *testing.T) {
	ts, _ := newTestServer(t)

	getResp, err := http.Get(ts.URL + "/nbsf-management/v1/pcfBindings")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if getResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", getResp.StatusCode)
	}
	m := decodeBody(t, getResp)
	if m["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %v, want MANDATORY_IE_MISSING", m["cause"])
	}
}

// ---- Health -----------------------------------------------------------------

func TestHealthz(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "UP") {
		t.Errorf("healthz body = %s, want UP", string(body))
	}
}

// ---- Store: multi-session same SUPI, different IPs --------------------------

func TestDiscover_MultipleSessionsSUPI(t *testing.T) {
	ts, _ := newTestServer(t)

	// Register two PDU sessions for the same SUPI (different IPs).
	b1 := validBinding("10.60.0.40")
	b1["supi"] = "imsi-001010000000009"
	r1 := postBinding(t, ts, b1)
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("register 1: %d", r1.StatusCode)
	}
	r1.Body.Close()

	b2 := map[string]any{
		"supi":     "imsi-001010000000009",
		"ipv4Addr": "10.60.0.41",
		"dnn":      "ims",
		"snssai":   map[string]any{"sst": 1, "sd": "000002"},
		"pcfFqdn":  "pcf.5gc.mnc001.mcc001.3gppnetwork.org",
	}
	r2 := postBinding(t, ts, b2)
	if r2.StatusCode != http.StatusCreated {
		t.Fatalf("register 2: %d", r2.StatusCode)
	}
	r2.Body.Close()

	// Discovery by IP should return the correct session.
	getResp, _ := http.Get(ts.URL + "/nbsf-management/v1/pcfBindings?ipv4Addr=10.60.0.40")
	body := decodeBody(t, getResp)
	if body["dnn"] != "internet" {
		t.Errorf("expected dnn=internet, got %v", body["dnn"])
	}
}
