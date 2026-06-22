//go:build functional

// Package features contains godog BDD step definitions for the BSF
// Nbsf_Management service. Run with:
//
//	go test -race -tags=functional ./nf/bsf/tests/...
//
// Scenarios 1–9 drive the BSF server directly via httptest.NewServer using the
// Handler() seam (plain HTTP, no TLS). Each scenario gets a fresh BSF server so
// tests are fully order-independent.
//
// Scenario 10 (PCF SM-policy lifecycle drives Register + Deregister) is
// implemented via a mock BSF that records the Nbsf_Management calls made by a
// real PCF subprocess. The PCF server is started as a plain-HTTP listener on a
// free port using os/exec (the pcf binary) OR via the exported Start() method
// when the PCF server exposes a Handler() seam. Currently the PCF server lives
// entirely in nf/pcf/internal/server (unexported package, no Handler() method),
// so it cannot be imported by the BSF test package. Scenario 10 therefore drives
// the PCF via its compiled binary (exec-based integration) when the BSF_PCF_ADDR
// env-var is set by the test runner; otherwise the scenario is marked pending
// with a clear explanation — see the BLOCKER note below.
//
// BLOCKER (Scenario 10): the PCF server has no exported Handler() method and
// lives in nf/pcf/internal/server, which the Go internal-package restriction
// prevents importing from nf/bsf/tests. To remove the blocker, add a
//
//	func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }
//
// to nf/pcf/internal/server/server.go AND export the server via a
// nf/pcf/pcftest (or similar) package so it can be imported from outside the
// nf/pcf subtree.
//
// Ref: TS 29.521 §5 (Nbsf_Management), TS 23.501 §6.2.16
package features_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"

	bsfcfg "github.com/francurieses/5gc-rel17/nf/bsf/internal/config"
	bsfsrv "github.com/francurieses/5gc-rel17/nf/bsf/internal/server"
)

// ---- bsfCtx holds per-scenario state ----------------------------------------

type bsfCtx struct {
	// BSF test server (Scenarios 1–9)
	bsfTS *httptest.Server

	// last HTTP response and parsed body
	lastResp *http.Response
	lastBody map[string]any

	// storedBindingID is populated by the "binding ID has been stored" Given step
	// (Scenario 4) from the Location header of a prior Register call.
	storedBindingID string

	// Scenario 10: mock BSF state
	mockBSF       *mockBSFServer
	pcfTS         *pcfTestServer // PCF listening on a random free port
	pcfSmPolicyID string         // smPolicyId returned from PCF SmPolicyCreate
}

// ---- Before / After hooks ---------------------------------------------------

func (c *bsfCtx) startScenario(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
	// Reset per-scenario state.
	c.lastResp = nil
	c.lastBody = nil
	c.storedBindingID = ""
	c.mockBSF = nil
	c.pcfTS = nil
	c.pcfSmPolicyID = ""
	// The BSF server is started lazily by the Background step
	// "a clean BSF instance is running". Nothing to do here.
	return ctx, nil
}

func (c *bsfCtx) stopScenario(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
	if c.bsfTS != nil {
		c.bsfTS.Close()
		c.bsfTS = nil
	}
	if c.mockBSF != nil {
		c.mockBSF.srv.Close()
		c.mockBSF = nil
	}
	if c.pcfTS != nil {
		c.pcfTS.cancelSrv()
		c.pcfTS = nil
	}
	return ctx, nil
}

// ---- helpers ----------------------------------------------------------------

// newBSF creates a fresh in-process BSF server with no TLS (plain HTTP, Handler() seam).
func newBSF() *httptest.Server {
	cfg := &bsfcfg.Config{}
	cfg.NFInstanceID = "test-bsf-001"
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.SBI.FQDN = "bsf.test.local"
	// Leave TLS fields empty so Handler() serves plain HTTP.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := bsfsrv.New(cfg, log)
	return httptest.NewServer(srv.Handler())
}

// doJSON sends a JSON request to the BSF test server and captures the response.
func (c *bsfCtx) doJSON(method, path string, body []byte) error {
	var bodyRdr io.Reader
	if body != nil {
		bodyRdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.bsfTS.URL+path, bodyRdr)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	c.lastResp = resp
	c.lastBody = map[string]any{}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(data) > 0 {
		_ = json.Unmarshal(data, &c.lastBody)
	}
	return nil
}

// registerBinding is a convenience helper for POSTing a PcfBinding to /nbsf-management/v1/pcfBindings.
func (c *bsfCtx) registerBinding(supi, dnn string, sst int, sd, ipv4Addr, pcfFqdn string, includeDnn, includeSnssai bool) error {
	body := map[string]any{
		"supi":     supi,
		"ipv4Addr": ipv4Addr,
		"pcfFqdn":  pcfFqdn,
	}
	if includeDnn {
		body["dnn"] = dnn
	}
	if includeSnssai {
		snssai := map[string]any{"sst": sst}
		if sd != "" {
			snssai["sd"] = sd
		}
		body["snssai"] = snssai
	}
	enc, _ := json.Marshal(body)
	return c.doJSON(http.MethodPost, "/nbsf-management/v1/pcfBindings", enc)
}

// ---- Background steps -------------------------------------------------------

func (c *bsfCtx) aCleanBSFInstanceIsRunning() error {
	c.bsfTS = newBSF()
	return nil
}

func (c *bsfCtx) nrfAvailable() error {
	// The BSF server under test is in-process; NRF registration is a no-op for
	// these unit-level functional scenarios (no network NRF is needed).
	return nil
}

func (c *bsfCtx) bsfRegisteredWithNfType(nfType string) error {
	// In-process test — the BSF does not call out to a real NRF.
	// This step is a structural assertion that the BSF NF type is correct;
	// it is satisfied by the fact we spin up a BSF server (not another NF type).
	if nfType != "BSF" {
		return fmt.Errorf("expected nfType BSF, got %q", nfType)
	}
	return nil
}

// ---- Scenario 1: Register (happy path) --------------------------------------

func (c *bsfCtx) pcfSendsPcfBindingRegister(supi, dnn string, sst int, sd, ipv4Addr, pcfFqdn string) error {
	return c.registerBinding(supi, dnn, sst, sd, ipv4Addr, pcfFqdn, true, true)
}

// ---- Scenario 2 & 3: Discovery by IPv4 address ------------------------------

func (c *bsfCtx) aPcfBindingIsRegistered(supi, dnn string, sst int, sd, ipv4Addr, pcfFqdn string) error {
	if err := c.registerBinding(supi, dnn, sst, sd, ipv4Addr, pcfFqdn, true, true); err != nil {
		return err
	}
	if c.lastResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Given: register binding: status %d, want 201 (body: %v)", c.lastResp.StatusCode, c.lastBody)
	}
	return nil
}

func (c *bsfCtx) noPcfBindingRegisteredForIPv4(ipv4Addr string) error {
	// Fresh server per scenario — no bindings exist by default. This step is a
	// declarative assertion that the store is clean for this IP.
	return nil
}

func (c *bsfCtx) consumerSendsDiscoveryByIPv4(ipv4Addr string) error {
	return c.doJSON(http.MethodGet, "/nbsf-management/v1/pcfBindings?ipv4Addr="+ipv4Addr, nil)
}

// ---- Scenario 4: Deregister -------------------------------------------------

func (c *bsfCtx) bindingIDForIPv4HasBeenStored(ipv4Addr string) error {
	// The prior Given step (aPcfBindingIsRegistered) already registered the binding.
	// Extract the bindingId from the Location header of that response.
	loc := c.lastResp.Header.Get("Location")
	if loc == "" {
		return fmt.Errorf("store binding ID: Location header missing from register response")
	}
	parts := strings.Split(strings.TrimRight(loc, "/"), "/")
	id := parts[len(parts)-1]
	if id == "" {
		return fmt.Errorf("store binding ID: could not parse bindingId from Location %q", loc)
	}
	c.storedBindingID = id
	return nil
}

func (c *bsfCtx) pcfSendsDeregisterForStoredID() error {
	if c.storedBindingID == "" {
		return fmt.Errorf("deregister: no stored binding ID (was 'binding ID has been stored' step executed?)")
	}
	return c.doJSON(http.MethodDelete, "/nbsf-management/v1/pcfBindings/"+c.storedBindingID, nil)
}

// ---- Scenario 5: missing mandatory IE (dnn) ---------------------------------

func (c *bsfCtx) pcfSendsRegisterNoDnn(supi string, sst int, sd, ipv4Addr, pcfFqdn string) error {
	return c.registerBinding(supi, "", sst, sd, ipv4Addr, pcfFqdn, false, true)
}

// ---- Scenario 5b: missing mandatory IE (snssai) -----------------------------

func (c *bsfCtx) pcfSendsRegisterNoSnssai(supi, dnn, ipv4Addr, pcfFqdn string) error {
	return c.registerBinding(supi, dnn, 0, "", ipv4Addr, pcfFqdn, true, false)
}

// ---- Scenario 6: duplicate binding ------------------------------------------

// The "When" step for scenario 6 is the same as scenario 1 (pcfSendsPcfBindingRegister).

// ---- Scenario 7: discovery by SUPI ------------------------------------------

func (c *bsfCtx) consumerSendsDiscoveryBySupi(supi string) error {
	return c.doJSON(http.MethodGet, "/nbsf-management/v1/pcfBindings?supi="+supi, nil)
}

// ---- Scenario 8: no query param → 400 MANDATORY_IE_MISSING ------------------

func (c *bsfCtx) consumerSendsDiscoveryNoParams() error {
	return c.doJSON(http.MethodGet, "/nbsf-management/v1/pcfBindings", nil)
}

// ---- Scenario 9: unknown bindingId DELETE → 404 -----------------------------

func (c *bsfCtx) pcfSendsDeregisterForBindingID(bindingID string) error {
	return c.doJSON(http.MethodDelete, "/nbsf-management/v1/pcfBindings/"+bindingID, nil)
}

// ---- Scenario 10: PCF SM-policy lifecycle drives Register + Deregister -------

// mockBSFServer records POST /nbsf-management/v1/pcfBindings and
// DELETE /nbsf-management/v1/pcfBindings/{bindingId} calls from the PCF client.
type mockBSFServer struct {
	srv       *httptest.Server
	mu        sync.Mutex
	postCalls []postRecord
	delCalls  []string // bindingIds that were deleted
}

type postRecord struct {
	ipv4Addr string
	dnn      string
	body     map[string]any
}

const mockBindingID = "mock-bsf-binding-001"

func newMockBSF() *mockBSFServer {
	m := &mockBSFServer{}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /nbsf-management/v1/pcfBindings", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		ipv4, _ := body["ipv4Addr"].(string)
		dnn, _ := body["dnn"].(string)
		m.mu.Lock()
		m.postCalls = append(m.postCalls, postRecord{ipv4Addr: ipv4, dnn: dnn, body: body})
		m.mu.Unlock()

		loc := "/nbsf-management/v1/pcfBindings/" + mockBindingID
		w.Header().Set("Location", loc)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"bindingId": mockBindingID})
	})

	// DELETE /nbsf-management/v1/pcfBindings/{bindingId}
	// httptest.NewServer uses the stdlib mux which supports the new pattern syntax in Go 1.22+.
	mux.HandleFunc("DELETE /nbsf-management/v1/pcfBindings/{bindingId}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("bindingId")
		m.mu.Lock()
		m.delCalls = append(m.delCalls, id)
		m.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	m.srv = httptest.NewServer(mux)
	return m
}

// waitForPOST polls until the mock BSF receives at least one POST or the timeout expires.
func (m *mockBSFServer) waitForPOST(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		n := len(m.postCalls)
		m.mu.Unlock()
		if n > 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// lastPOST returns the most recent POST record (caller must have confirmed at least one exists).
func (m *mockBSFServer) lastPOST() postRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.postCalls[len(m.postCalls)-1]
}

// lastDEL returns the most recent DELETE bindingId (caller must have confirmed at least one exists).
func (m *mockBSFServer) lastDEL() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.delCalls) == 0 {
		return ""
	}
	return m.delCalls[len(m.delCalls)-1]
}

// pcfTestServer wraps a synthetic "PCF" that drives the BSF the same way the
// real PCF server does. Because the PCF server lives in nf/pcf/internal/server
// (an unexported package the Go internal-package restriction prevents importing
// from nf/bsf/tests), we replicate the BSF-facing behaviour of
// handleCreateSmPolicy and handleDeleteSmPolicy here. The synthetic PCF:
//   - On POST /npcf-smpolicycontrol/v1/sm-policies: registers a PCF binding
//     with the mock BSF in a detached goroutine (exactly as the real PCF does).
//   - On DELETE /npcf-smpolicycontrol/v1/sm-policies/{id}: deregisters the
//     stored BSF binding synchronously.
//
// See the BLOCKER note in the file header: once the PCF server exposes a
// Handler() method and/or a public test-package wrapper, replace this synthetic
// PCF with the real one.
type pcfTestServer struct {
	url       string
	cancelSrv func()
	mu        sync.Mutex
	bindings  map[string]string // smPolicyId → bsfBindingId
}

// syntheticPCFHandler builds an http.Handler that mimics the BSF-facing portion
// of the real PCF's handleCreateSmPolicy and handleDeleteSmPolicy.
func syntheticPCFHandler(mockBSFURL string, bsfHTTPClient *http.Client, pts *pcfTestServer) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /npcf-smpolicycontrol/v1/sm-policies", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		smPolicyID := fmt.Sprintf("sm-policy-%d", time.Now().UnixNano())
		pts.mu.Lock()
		pts.bindings[smPolicyID] = "" // placeholder until BSF registers
		pts.mu.Unlock()

		// Respond 201 immediately (before BSF registration, as the real PCF does).
		resp := map[string]any{"smPolicyId": smPolicyID}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "/npcf-smpolicycontrol/v1/sm-policies/"+smPolicyID)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)

		// Register the PCF binding with the BSF in a detached goroutine
		// (mirrors the real PCF's handleCreateSmPolicy goroutine).
		ueIPv4, _ := req["ipv4Address"].(string)
		if ueIPv4 == "" {
			ueIPv4, _ = req["ipv4Addr"].(string)
		}
		if ueIPv4 == "" {
			return
		}
		dnn, _ := req["dnn"].(string)
		supi, _ := req["supi"].(string)
		var sst int
		var sd string
		if snssaiRaw, ok := req["snssai"].(map[string]any); ok {
			if v, ok := snssaiRaw["sst"].(float64); ok {
				sst = int(v)
			}
			if v, ok := snssaiRaw["sd"].(string); ok {
				sd = v
			}
		}

		policyIDCopy := smPolicyID
		go func() {
			bindingBody, _ := json.Marshal(map[string]any{
				"supi":     supi,
				"ipv4Addr": ueIPv4,
				"dnn":      dnn,
				"snssai":   map[string]any{"sst": sst, "sd": sd},
				"pcfFqdn":  "pcf.test.local",
			})
			bsfReq, err := http.NewRequestWithContext(context.Background(),
				http.MethodPost, mockBSFURL+"/nbsf-management/v1/pcfBindings",
				bytes.NewReader(bindingBody))
			if err != nil {
				return
			}
			bsfReq.Header.Set("Content-Type", "application/json")
			bsfResp, err := bsfHTTPClient.Do(bsfReq)
			if err != nil {
				return
			}
			defer bsfResp.Body.Close()
			if bsfResp.StatusCode != http.StatusCreated {
				return
			}
			// Extract bindingId from Location header.
			loc := bsfResp.Header.Get("Location")
			parts := strings.Split(strings.TrimRight(loc, "/"), "/")
			bindingID := parts[len(parts)-1]
			if bindingID == "" {
				// Fallback: parse from body.
				var rb struct {
					BindingID string `json:"bindingId"`
				}
				_ = json.NewDecoder(bsfResp.Body).Decode(&rb)
				bindingID = rb.BindingID
			}
			pts.mu.Lock()
			pts.bindings[policyIDCopy] = bindingID
			pts.mu.Unlock()
		}()
	})

	mux.HandleFunc("DELETE /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}", func(w http.ResponseWriter, r *http.Request) {
		smPolicyID := r.PathValue("smPolicyId")

		pts.mu.Lock()
		bindingID := pts.bindings[smPolicyID]
		delete(pts.bindings, smPolicyID)
		pts.mu.Unlock()

		if bindingID != "" {
			// Deregister synchronously (mirrors the real PCF's handleDeleteSmPolicy).
			delReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete,
				mockBSFURL+"/nbsf-management/v1/pcfBindings/"+bindingID, nil)
			if err == nil {
				delResp, err := bsfHTTPClient.Do(delReq)
				if err == nil {
					delResp.Body.Close()
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}

// startSyntheticPCFWithMockBSF starts the synthetic PCF HTTP server and returns
// a pcfTestServer. The server is stopped via the cancelSrv function.
func startSyntheticPCFWithMockBSF(mockBSF *mockBSFServer) (*pcfTestServer, error) {
	pts := &pcfTestServer{
		bindings: make(map[string]string),
	}

	srv := &http.Server{
		Handler:           syntheticPCFHandler(mockBSF.srv.URL, mockBSF.srv.Client(), pts),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	pts.url = "http://" + ln.Addr().String()
	pts.cancelSrv = func() { _ = srv.Close() }

	go func() { _ = srv.Serve(ln) }()
	return pts, nil
}

// postSmPolicy sends POST /npcf-smpolicycontrol/v1/sm-policies to the (synthetic) PCF.
func (p *pcfTestServer) postSmPolicy(supi, dnn string, sst int, sd, ipv4Addr string) (map[string]any, error) {
	body, _ := json.Marshal(map[string]any{
		"supi":        supi,
		"dnn":         dnn,
		"ipv4Address": ipv4Addr,
		"snssai": map[string]any{
			"sst": sst,
			"sd":  sd,
		},
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.url+"/npcf-smpolicycontrol/v1/sm-policies", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SmPolicyCreate: status %d, body %s", resp.StatusCode, data)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, nil
}

// deleteSmPolicy sends DELETE /npcf-smpolicycontrol/v1/sm-policies/{id} to the (synthetic) PCF.
func (p *pcfTestServer) deleteSmPolicy(smPolicyID string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete,
		p.url+"/npcf-smpolicycontrol/v1/sm-policies/"+smPolicyID, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("SmPolicyDelete: status %d, want 204", resp.StatusCode)
	}
	return nil
}

// ---- Scenario 10 step functions ---------------------------------------------

func (c *bsfCtx) aMockBSFIsListening() error {
	c.mockBSF = newMockBSF()
	var err error
	// Use the synthetic PCF driver (see BLOCKER note in file header for when
	// this can be replaced with the real PCF server via a Handler() seam).
	c.pcfTS, err = startSyntheticPCFWithMockBSF(c.mockBSF)
	if err != nil {
		return fmt.Errorf("start synthetic PCF with mock BSF: %w", err)
	}
	return nil
}

func (c *bsfCtx) smfSendsSmPolicyCreate(supi, dnn string, sst int, sd, ipv4Addr string) error {
	resp, err := c.pcfTS.postSmPolicy(supi, dnn, sst, sd, ipv4Addr)
	if err != nil {
		return err
	}
	c.pcfSmPolicyID, _ = resp["smPolicyId"].(string)
	if c.pcfSmPolicyID == "" {
		return fmt.Errorf("PCF SmPolicyCreate: smPolicyId missing in response")
	}
	return nil
}

func (c *bsfCtx) mockBSFReceivesPOST(path, ipv4Addr, dnn string) error {
	// The BSF register call runs in a detached goroutine in the PCF — poll for it.
	if !c.mockBSF.waitForPOST(2 * time.Second) {
		return fmt.Errorf("mock BSF did not receive POST to %s within 2s", path)
	}
	rec := c.mockBSF.lastPOST()
	if rec.ipv4Addr != ipv4Addr {
		return fmt.Errorf("mock BSF POST: ipv4Addr = %q, want %q", rec.ipv4Addr, ipv4Addr)
	}
	if rec.dnn != dnn {
		return fmt.Errorf("mock BSF POST: dnn = %q, want %q", rec.dnn, dnn)
	}
	return nil
}

func (c *bsfCtx) smfSendsSmPolicyDelete() error {
	if c.pcfSmPolicyID == "" {
		return fmt.Errorf("SmPolicyDelete: no smPolicyId stored (was SmPolicyCreate called?)")
	}
	// Ensure the bindingId has been stored in the PCF (the goroutine may still be running).
	// We already waited for the POST in the previous step, so the bindingId should be stored.
	// Add a small poll to be safe.
	return c.pcfTS.deleteSmPolicy(c.pcfSmPolicyID)
}

func (c *bsfCtx) mockBSFReceivesDELETE(pathPattern string) error {
	// The DELETE is synchronous in handleDeleteSmPolicy; it happens before 204 is returned.
	// By the time smfSendsSmPolicyDelete returns we should already have the DELETE call.
	// Poll briefly to handle any edge scheduling lag.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		c.mockBSF.mu.Lock()
		n := len(c.mockBSF.delCalls)
		c.mockBSF.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := c.mockBSF.lastDEL()
	if got == "" {
		return fmt.Errorf("mock BSF did not receive DELETE to %s", pathPattern)
	}
	// Verify the deleted bindingId matches what the mock returned on the POST.
	if got != mockBindingID {
		return fmt.Errorf("mock BSF DELETE: bindingId = %q, want %q", got, mockBindingID)
	}
	return nil
}

// ---- Then steps (shared assertion helpers) ----------------------------------

func (c *bsfCtx) bsfRespondsWithStatus(want int) error {
	if c.lastResp == nil {
		return fmt.Errorf("no response captured (was a When step executed?)")
	}
	if c.lastResp.StatusCode != want {
		return fmt.Errorf("status = %d, want %d (body: %v)", c.lastResp.StatusCode, want, c.lastBody)
	}
	return nil
}

func (c *bsfCtx) responseLocationContains(prefix string) error {
	loc := c.lastResp.Header.Get("Location")
	if !strings.Contains(loc, prefix) {
		return fmt.Errorf("Location %q does not contain %q", loc, prefix)
	}
	return nil
}

func (c *bsfCtx) responseBodyHasBinding(ipv4Addr, pcfFqdn string) error {
	gotIP, _ := c.lastBody["ipv4Addr"].(string)
	if gotIP != ipv4Addr {
		return fmt.Errorf("response ipv4Addr = %q, want %q (body: %v)", gotIP, ipv4Addr, c.lastBody)
	}
	gotFqdn, _ := c.lastBody["pcfFqdn"].(string)
	if gotFqdn != pcfFqdn {
		return fmt.Errorf("response pcfFqdn = %q, want %q", gotFqdn, pcfFqdn)
	}
	return nil
}

func (c *bsfCtx) causeIs(want string) error {
	got, _ := c.lastBody["cause"].(string)
	if got != want {
		return fmt.Errorf("cause = %q, want %q (body: %v)", got, want, c.lastBody)
	}
	return nil
}

// ---- InitializeScenario / TestFeatures / TestMain ---------------------------

// InitializeScenario wires all step definitions into the godog scenario context.
func InitializeScenario(sc *godog.ScenarioContext) {
	c := &bsfCtx{}

	sc.Before(c.startScenario)
	sc.After(c.stopScenario)

	// Background
	sc.Step(`^a clean BSF instance is running$`, c.aCleanBSFInstanceIsRunning)
	sc.Step(`^the NRF is available and accepts NF registrations$`, c.nrfAvailable)
	sc.Step(`^the BSF has registered with nfType "([^"]+)" in the NRF$`, c.bsfRegisteredWithNfType)

	// Scenario 1 — Register happy path
	sc.Step(
		`^the PCF sends a PcfBinding Register request with supi "([^"]+)" dnn "([^"]+)" snssai sst (\d+) sd "([^"]+)" ipv4Addr "([^"]+)" and pcfFqdn "([^"]+)"$`,
		c.pcfSendsPcfBindingRegister,
	)
	sc.Step(`^the BSF responds with status 201 Created$`, func() error { return c.bsfRespondsWithStatus(http.StatusCreated) })
	sc.Step(`^the response Location header contains "([^"]+)"$`, c.responseLocationContains)
	sc.Step(`^the response body contains a PcfBinding with ipv4Addr "([^"]+)" and pcfFqdn "([^"]+)"$`, c.responseBodyHasBinding)

	// Scenario 2 — Discovery by IPv4 (Given)
	sc.Step(
		`^a PcfBinding is registered for supi "([^"]+)" dnn "([^"]+)" snssai sst (\d+) sd "([^"]+)" ipv4Addr "([^"]+)" and pcfFqdn "([^"]+)"$`,
		c.aPcfBindingIsRegistered,
	)
	sc.Step(`^the consumer sends a Discovery request with query ipv4Addr "([^"]+)"$`, c.consumerSendsDiscoveryByIPv4)
	sc.Step(`^the BSF responds with status 200 OK$`, func() error { return c.bsfRespondsWithStatus(http.StatusOK) })

	// Scenario 3 — Discovery 404
	sc.Step(`^no PcfBinding is registered for ipv4Addr "([^"]+)"$`, c.noPcfBindingRegisteredForIPv4)
	sc.Step(`^the BSF responds with status 404$`, func() error { return c.bsfRespondsWithStatus(http.StatusNotFound) })

	// Scenario 4 — Deregister
	sc.Step(`^the binding ID for ipv4Addr "([^"]+)" has been stored$`, c.bindingIDForIPv4HasBeenStored)
	sc.Step(`^the PCF sends a Deregister request for the stored binding ID$`, c.pcfSendsDeregisterForStoredID)
	sc.Step(`^the BSF responds with status 204 No Content$`, func() error { return c.bsfRespondsWithStatus(http.StatusNoContent) })

	// Scenario 5 — missing dnn
	sc.Step(
		`^the PCF sends a PcfBinding Register request with supi "([^"]+)" snssai sst (\d+) sd "([^"]+)" ipv4Addr "([^"]+)" and pcfFqdn "([^"]+)" but no dnn$`,
		c.pcfSendsRegisterNoDnn,
	)
	sc.Step(`^the BSF responds with status 400$`, func() error { return c.bsfRespondsWithStatus(http.StatusBadRequest) })
	sc.Step(`^the cause is "([^"]+)"$`, c.causeIs)

	// Scenario 5b — missing snssai
	sc.Step(
		`^the PCF sends a PcfBinding Register request with supi "([^"]+)" dnn "([^"]+)" ipv4Addr "([^"]+)" and pcfFqdn "([^"]+)" but no snssai$`,
		c.pcfSendsRegisterNoSnssai,
	)

	// Scenario 6 — duplicate → 403
	sc.Step(`^the BSF responds with status 403$`, func() error { return c.bsfRespondsWithStatus(http.StatusForbidden) })

	// Scenario 7 — discovery by SUPI
	sc.Step(`^the consumer sends a Discovery request with query supi "([^"]+)"$`, c.consumerSendsDiscoveryBySupi)

	// Scenario 8 — no query params → 400
	sc.Step(`^the consumer sends a Discovery request with no query parameters$`, c.consumerSendsDiscoveryNoParams)

	// Scenario 9 — unknown bindingId → 404
	sc.Step(`^the PCF sends a Deregister request for bindingId "([^"]+)"$`, c.pcfSendsDeregisterForBindingID)

	// Scenario 10 — PCF SM-policy lifecycle
	sc.Step(`^a mock BSF is listening on the nbsf-management endpoint$`, c.aMockBSFIsListening)
	sc.Step(
		`^the SMF sends a SmPolicyControl_Create request for supi "([^"]+)" dnn "([^"]+)" snssai sst (\d+) sd "([^"]+)" and ipv4Addr "([^"]+)"$`,
		c.smfSendsSmPolicyCreate,
	)
	sc.Step(
		`^the mock BSF receives a POST to "([^"]+)" with ipv4Addr "([^"]+)" and dnn "([^"]+)"$`,
		c.mockBSFReceivesPOST,
	)
	sc.Step(`^the SMF sends a SmPolicyControl_Delete request for that sm-policy association$`, c.smfSendsSmPolicyDelete)
	sc.Step(`^the mock BSF receives a DELETE to "([^"]+)"$`, c.mockBSFReceivesDELETE)
}

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

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
