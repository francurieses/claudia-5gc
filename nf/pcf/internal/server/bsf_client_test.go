// Package server provides unit tests for the PCF BSF client integration.
//
// Tests verify:
//   - SmPolicyCreate with a configured mock BSF receives the correct PcfBinding POST
//     and the returned bindingId is stored indexed by smPolicyId.
//   - SmPolicyDelete calls DELETE /nbsf-management/v1/pcfBindings/{bindingId}.
//   - No BSF client configured (nil) → create + delete succeed unchanged (fail-open).
//   - BSF unreachable → create still returns 201 (fail-open, no regression).
//   - BSF returns 403 EXISTING_BINDING_INFO_FOUND → create still returns 201 (idempotent).
//
// Ref: TS 29.521 §5.2.2.2 (Register), §5.2.2.3 (Deregister)
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
)

// newTestPCFWithBSF creates a PCF server with a mock BSF httptest.Server wired in.
// It returns the PCF server, the mock BSF server, and an atomic counter of BSF
// POST calls received.
func newTestPCFWithBSF(t *testing.T, bsfHandler http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()
	bsfSrv := httptest.NewServer(bsfHandler)
	t.Cleanup(bsfSrv.Close)

	cfg := &config.Config{}
	cfg.DefaultSMPolicy.FiveQI = 9
	cfg.DefaultSMPolicy.ARPPriorityLevel = 8
	cfg.DefaultSMPolicy.SessionAMBRUplink = "100 Mbps"
	cfg.DefaultSMPolicy.SessionAMBRDownlink = "100 Mbps"
	cfg.NFInstanceID = "pcf-test-instance"
	cfg.SBI.FQDN = "pcf.test.local"

	s, err := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("New PCF: %v", err)
	}

	s.WithBSFClient(&HTTPBSFClient{
		BaseURL: bsfSrv.URL,
		Client:  bsfSrv.Client(),
		Logger:  s.logger,
		PcfFqdn: cfg.SBI.FQDN,
		PcfId:   cfg.NFInstanceID,
	})
	return s, bsfSrv
}

// postSmPolicyWithIP sends POST /npcf-smpolicycontrol/v1/sm-policies with a body
// that includes an ipv4Address field so the PCF can register a BSF binding.
// Returns the decoded response body and the smPolicyId.
func postSmPolicyWithIP(t *testing.T, s *Server, supi, dnn, ipv4 string) (map[string]any, string) {
	t.Helper()
	body := `{"supi":"` + supi + `","dnn":"` + dnn + `","ipv4Address":"` + ipv4 + `",` +
		`"snssai":{"sst":1,"sd":"000001"}}`
	r := httptest.NewRequest(http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateSmPolicy(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("handleCreateSmPolicy: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	smPolicyId, _ := resp["smPolicyId"].(string)
	if smPolicyId == "" {
		t.Fatal("smPolicyId missing in response")
	}
	return resp, smPolicyId
}

// waitBindingID polls the bsfBindingIDs map until the entry for smPolicyId appears
// or the timeout elapses (the BSF call runs in a detached goroutine).
func waitBindingID(t *testing.T, s *Server, smPolicyId string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.policiesMu.Lock()
		id := s.bsfBindingIDs[smPolicyId]
		s.policiesMu.Unlock()
		if id != "" {
			return id
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("timed out waiting for bsfBindingIDs[%s]", smPolicyId)
	return ""
}

// TestSmPolicyCreateRegistersBSFBinding verifies that handleCreateSmPolicy:
//  1. Returns 201 to the caller.
//  2. Sends POST /nbsf-management/v1/pcfBindings with correct supi/dnn/snssai/ipv4Addr.
//  3. Stores the returned bindingId in bsfBindingIDs[smPolicyId].
//
// Ref: TS 29.521 §5.2.2.2
func TestSmPolicyCreateRegistersBSFBinding(t *testing.T) {
	var received atomic.Int32
	const wantBindingID = "binding-001"

	s, _ := newTestPCFWithBSF(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/nbsf-management/v1/pcfBindings" {
			t.Errorf("BSF: unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		received.Add(1)

		// Verify the posted body contains the expected fields.
		var body PcfBindingRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("BSF: decode body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Supi != "imsi-001010000000001" {
			t.Errorf("BSF binding supi: got %q want imsi-001010000000001", body.Supi)
		}
		if body.Dnn != "internet" {
			t.Errorf("BSF binding dnn: got %q want internet", body.Dnn)
		}
		if body.Ipv4Addr != "10.60.0.1" {
			t.Errorf("BSF binding ipv4Addr: got %q want 10.60.0.1", body.Ipv4Addr)
		}
		if body.Snssai.Sst != 1 {
			t.Errorf("BSF binding snssai.sst: got %d want 1", body.Snssai.Sst)
		}
		if body.PcfFqdn != "pcf.test.local" {
			t.Errorf("BSF binding pcfFqdn: got %q want pcf.test.local", body.PcfFqdn)
		}
		if body.PcfId != "pcf-test-instance" {
			t.Errorf("BSF binding pcfId: got %q want pcf-test-instance", body.PcfId)
		}

		// Respond 201 with Location and body containing bindingId.
		w.Header().Set("Location", "/nbsf-management/v1/pcfBindings/"+wantBindingID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"bindingId": wantBindingID})
	})

	_, smPolicyId := postSmPolicyWithIP(t, s, "imsi-001010000000001", "internet", "10.60.0.1")

	// BSF call is async; wait for it.
	gotBindingID := waitBindingID(t, s, smPolicyId, 500*time.Millisecond)

	if received.Load() != 1 {
		t.Errorf("BSF POST count: got %d want 1", received.Load())
	}
	if gotBindingID != wantBindingID {
		t.Errorf("stored bindingId: got %q want %q", gotBindingID, wantBindingID)
	}
}

// TestSmPolicyDeleteDeregistersBSFBinding verifies that handleDeleteSmPolicy sends
// DELETE /nbsf-management/v1/pcfBindings/{bindingId} for the stored binding.
//
// Ref: TS 29.521 §5.2.2.3
func TestSmPolicyDeleteDeregistersBSFBinding(t *testing.T) {
	const wantBindingID = "binding-del-001"
	var deletedPath atomic.Value

	s, _ := newTestPCFWithBSF(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Location", "/nbsf-management/v1/pcfBindings/"+wantBindingID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"bindingId": wantBindingID})
		case http.MethodDelete:
			deletedPath.Store(r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("BSF: unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	_, smPolicyId := postSmPolicyWithIP(t, s, "imsi-001010000000001", "internet", "10.60.0.5")

	// Wait for BSF Register goroutine to populate bsfBindingIDs.
	waitBindingID(t, s, smPolicyId, 500*time.Millisecond)

	// Now delete the SM policy → should call BSF DELETE.
	r := httptest.NewRequest(http.MethodDelete,
		"/npcf-smpolicycontrol/v1/sm-policies/"+smPolicyId, nil)
	r.SetPathValue("smPolicyId", smPolicyId)
	w := httptest.NewRecorder()
	s.handleDeleteSmPolicy(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("handleDeleteSmPolicy: expected 204, got %d", w.Code)
	}

	// The DELETE to the BSF should have been called synchronously in handleDeleteSmPolicy.
	wantPath := "/nbsf-management/v1/pcfBindings/" + wantBindingID
	if got, _ := deletedPath.Load().(string); got != wantPath {
		t.Errorf("BSF DELETE path: got %q want %q", got, wantPath)
	}
}

// TestSmPolicyCreateNoBSFClient verifies no-regression when no BSF client is configured.
// handleCreateSmPolicy must return 201 unchanged.
//
// Ref: TS 29.521 §5 (fail-open behaviour)
func TestSmPolicyCreateNoBSFClient(t *testing.T) {
	s := newTestPCF(t) // bsfClient is nil

	_, smPolicyId := postSmPolicyWithIP(t, s, "imsi-001010000000001", "internet", "10.60.0.2")
	if smPolicyId == "" {
		t.Error("smPolicyId should not be empty")
	}
	// No BSF binding should be stored.
	s.policiesMu.Lock()
	_, hasBSF := s.bsfBindingIDs[smPolicyId]
	s.policiesMu.Unlock()
	if hasBSF {
		t.Error("bsfBindingIDs should not be populated when BSF client is nil")
	}
}

// TestSmPolicyDeleteNoBSFClient verifies no-regression on delete when no BSF is configured.
func TestSmPolicyDeleteNoBSFClient(t *testing.T) {
	s := newTestPCF(t)

	_, smPolicyId := postSmPolicyWithIP(t, s, "imsi-001010000000001", "internet", "10.60.0.3")

	r := httptest.NewRequest(http.MethodDelete,
		"/npcf-smpolicycontrol/v1/sm-policies/"+smPolicyId, nil)
	r.SetPathValue("smPolicyId", smPolicyId)
	w := httptest.NewRecorder()
	s.handleDeleteSmPolicy(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("handleDeleteSmPolicy (no BSF): expected 204, got %d", w.Code)
	}
}

// TestSmPolicyCreateBSFUnreachable verifies that a network-level BSF failure does NOT
// cause handleCreateSmPolicy to fail — the SM policy create returns 201 regardless.
//
// Ref: TS 23.501 §6.2.16, docs/procedures/binding-support.md (fail-open)
func TestSmPolicyCreateBSFUnreachable(t *testing.T) {
	cfg := &config.Config{}
	cfg.DefaultSMPolicy.FiveQI = 9
	cfg.DefaultSMPolicy.ARPPriorityLevel = 8
	cfg.DefaultSMPolicy.SessionAMBRUplink = "100 Mbps"
	cfg.DefaultSMPolicy.SessionAMBRDownlink = "100 Mbps"
	cfg.NFInstanceID = "pcf-test-unreachable"
	cfg.SBI.FQDN = "pcf.test.local"

	s, err := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("New PCF: %v", err)
	}

	// Point at an address that is guaranteed to be unreachable.
	s.WithBSFClient(&HTTPBSFClient{
		BaseURL: "http://127.0.0.1:1", // port 1 is always refused
		Client:  &http.Client{Timeout: 50 * time.Millisecond},
		Logger:  s.logger,
		PcfFqdn: cfg.SBI.FQDN,
		PcfId:   cfg.NFInstanceID,
	})

	// The create must still succeed despite the unreachable BSF.
	_, smPolicyId := postSmPolicyWithIP(t, s, "imsi-001010000000001", "internet", "10.60.0.4")
	if smPolicyId == "" {
		t.Error("smPolicyId should not be empty even when BSF is unreachable")
	}
}

// TestSmPolicyCreateBSFExistingBinding verifies that a 403 EXISTING_BINDING_INFO_FOUND
// response from the BSF is treated as idempotent: handleCreateSmPolicy returns 201.
//
// Ref: TS 29.521 §5.2.2.2.4
func TestSmPolicyCreateBSFExistingBinding(t *testing.T) {
	s, _ := newTestPCFWithBSF(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Simulate a pre-existing binding.
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"cause":     "EXISTING_BINDING_INFO_FOUND",
				"detail":    "binding already exists for ipv4Addr 10.60.0.9",
				"bindingId": "existing-binding-999",
			})
		}
	})

	// The SM policy create must succeed regardless of the 403 from BSF.
	_, smPolicyId := postSmPolicyWithIP(t, s, "imsi-001010000000001", "internet", "10.60.0.9")
	if smPolicyId == "" {
		t.Error("smPolicyId must be returned even when BSF returns 403")
	}
}

// TestSmPolicyCreateNoIPv4OmitsBSFCall verifies that when the SM policy create body
// does NOT contain an ipv4Address, the BSF is not called (IPv6-only sessions).
func TestSmPolicyCreateNoIPv4OmitsBSFCall(t *testing.T) {
	var bsfCalls atomic.Int32
	s, _ := newTestPCFWithBSF(t, func(w http.ResponseWriter, _ *http.Request) {
		bsfCalls.Add(1)
		w.WriteHeader(http.StatusCreated)
	})

	// Body without ipv4Address.
	body := `{"supi":"imsi-001010000000001","dnn":"internet","snssai":{"sst":1}}`
	r := httptest.NewRequest(http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateSmPolicy(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Give any goroutine a moment to run (it should not).
	time.Sleep(20 * time.Millisecond)
	if n := bsfCalls.Load(); n != 0 {
		t.Errorf("BSF calls: got %d want 0 (no IP → BSF should not be called)", n)
	}
}
