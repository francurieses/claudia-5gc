//go:build functional

// Package features contains godog BDD step definitions for the SMSF.
// Run with: go test -tags=functional ./nf/smsf/tests/...
//
// The suite is fully in-process: a real SMSF server (driven via httptest),
// the production HTTPAMFClient, and three mock peers — NRF, UDM, AMF — captured
// with httptest. No running stack is required.
//
// Ref: TS 29.540 §5.2 (Nsmsf_SMService), TS 23.502 §4.13 (SMS over NAS),
//
//	TS 29.510 §5.2 (NRF), TS 29.503 §5.3.2 (UDM UECM), TS 29.518 §5.2.2.3 (N1N2).
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

	"github.com/francurieses/claudia-5gc/nf/smsf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/smsf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/nrf"
)

// ---- mock peers -------------------------------------------------------------

// mockAMF records Namf_Communication_N1N2MessageTransfer callbacks.
type mockAMF struct {
	srv      *httptest.Server
	mu       sync.Mutex
	received []map[string]any
}

func newMockAMF() *mockAMF {
	m := &mockAMF{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/n1-n2-messages") {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.mu.Lock()
			m.received = append(m.received, body)
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"cause":"N1_N2_TRANSFER_INITIATED"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	return m
}

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

func (m *mockAMF) lastCall() (map[string]any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.received) == 0 {
		return nil, false
	}
	return m.received[len(m.received)-1], true
}

// mockUDM records Nudm_UECM SMSF registrations.
type mockUDM struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls []string // recorded request paths
}

func newMockUDM() *mockUDM {
	m := &mockUDM{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/registrations/smsf-3gpp-access") {
			m.mu.Lock()
			m.calls = append(m.calls, r.URL.Path)
			m.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	return m
}

func (m *mockUDM) sawRegistration(supi, resource string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.calls {
		if strings.Contains(p, supi) && strings.Contains(p, resource) {
			return true
		}
	}
	return false
}

// mockNRF records NF registrations and answers NFDiscover queries.
type mockNRF struct {
	srv    *httptest.Server
	mu     sync.Mutex
	byType map[string][]map[string]any
}

func newMockNRF() *mockNRF {
	m := &mockNRF{byType: map[string][]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /nnrf-nfm/v1/nf-instances/{id}", func(w http.ResponseWriter, r *http.Request) {
		var profile map[string]any
		_ = json.NewDecoder(r.Body).Decode(&profile)
		nfType, _ := profile["nfType"].(string)
		m.mu.Lock()
		m.byType[nfType] = append(m.byType[nfType], profile)
		m.mu.Unlock()
		profile["heartBeatTimer"] = 60
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(profile)
	})
	mux.HandleFunc("GET /nnrf-disc/v1/nf-instances", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target-nf-type")
		m.mu.Lock()
		instances := append([]map[string]any{}, m.byType[target]...)
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"nfInstances": instances})
	})
	m.srv = httptest.NewServer(mux)
	return m
}

func (m *mockNRF) discover(target string) int {
	resp, err := http.Get(m.srv.URL + "/nnrf-disc/v1/nf-instances?target-nf-type=" + target + "&requester-nf-type=AMF")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var out struct {
		NFInstances []map[string]any `json:"nfInstances"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return len(out.NFInstances)
}

// testUDMClient drives the mock UDM over plain HTTP (the production HTTPUDMClient
// hardcodes the https:// scheme, which an httptest http server cannot serve).
type testUDMClient struct {
	baseURL string
}

func (c *testUDMClient) RegisterSMSF(ctx context.Context, supi, smsfInstanceID string) error {
	url := fmt.Sprintf("%s/nudm-uecm/v1/%s/registrations/smsf-3gpp-access", c.baseURL, supi)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader([]byte(`{"smsfInstanceId":"`+smsfInstanceID+`"}`)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("udm returned %d", resp.StatusCode)
	}
	return nil
}

// ---- per-scenario context ---------------------------------------------------

type smsfCtx struct {
	nrf      *mockNRF
	udm      *mockUDM
	amf      *mockAMF
	ts       *httptest.Server
	lastResp *http.Response
	lastBody map[string]any
}

func (c *smsfCtx) start(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
	c.nrf = newMockNRF()
	c.udm = newMockUDM()
	c.amf = newMockAMF()

	cfg := &config.Config{}
	cfg.NFInstanceID = "test-smsf-001"
	cfg.SBI.Address = "127.0.0.1:0"

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, log)
	// Production AMF client → echoes the SMS payload as base64 (assertions depend on this).
	srv.WithAMFClient(server.NewHTTPAMFClient(http.DefaultClient))
	srv.WithUDMClient(&testUDMClient{baseURL: c.udm.srv.URL})

	c.ts = httptest.NewServer(srv.Handler())
	return ctx, nil
}

func (c *smsfCtx) stop(_ context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
	if c.ts != nil {
		c.ts.Close()
	}
	if c.nrf != nil {
		c.nrf.srv.Close()
	}
	if c.udm != nil {
		c.udm.srv.Close()
	}
	if c.amf != nil {
		c.amf.srv.Close()
	}
	return context.Background(), nil
}

// callbackURI returns the mock AMF n1-n2 callback URL for a SUPI.
func (c *smsfCtx) callbackURI(supi string) string {
	return c.amf.srv.URL + "/namf-comm/v1/ue-contexts/" + supi + "/n1-n2-messages"
}

func (c *smsfCtx) postJSON(path string, body []byte) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.ts.URL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *smsfCtx) do(req *http.Request) error {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
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

// ---- background / given steps -----------------------------------------------

func (c *smsfCtx) noop() error { return nil }

func (c *smsfCtx) smsfRegisteredInNRF(nfType string) error {
	client := nrf.New(c.nrf.srv.URL, http.DefaultClient, slog.New(slog.NewTextHandler(io.Discard, nil)))
	profile := &nrf.NFProfile{
		NFInstanceID: "test-smsf-001",
		NFType:       nfType,
		NFStatus:     "REGISTERED",
	}
	if _, err := client.Register(context.Background(), profile); err != nil {
		return fmt.Errorf("SMSF NRF registration failed: %w", err)
	}
	return nil
}

func (c *smsfCtx) activeContextExists(supi string) error {
	body, _ := json.Marshal(map[string]any{
		"supi":           supi,
		"accessType":     "3GPP_ACCESS",
		"amfId":          "amf-instance-001",
		"amfCallbackUri": c.callbackURI(supi),
	})
	if err := c.postJSON("/nsmsf-sms/v2/ue-contexts/"+supi, body); err != nil {
		return err
	}
	if c.lastResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("activate setup: status %d, want 201", c.lastResp.StatusCode)
	}
	return nil
}

func (c *smsfCtx) noContextExists(_ string) error { return nil } // fresh server per scenario

// ---- when steps -------------------------------------------------------------

func (c *smsfCtx) sendActivate(supi, accessType, amfID, callbackURI string) error {
	body, _ := json.Marshal(map[string]any{
		"supi":           supi,
		"accessType":     accessType,
		"amfId":          amfID,
		"amfCallbackUri": callbackURI,
	})
	return c.postJSON("/nsmsf-sms/v2/ue-contexts/"+supi, body)
}

func (c *smsfCtx) sendActivateNoAccessType(supi, amfID, callbackURI string) error {
	body, _ := json.Marshal(map[string]any{
		"supi":           supi,
		"amfId":          amfID,
		"amfCallbackUri": callbackURI,
	})
	return c.postJSON("/nsmsf-sms/v2/ue-contexts/"+supi, body)
}

func (c *smsfCtx) sendActivateNoSupi(accessType, amfID string) error {
	body, _ := json.Marshal(map[string]any{
		"accessType": accessType,
		"amfId":      amfID,
	})
	// Path param carries a placeholder; the body lacks supi → 400.
	return c.postJSON("/nsmsf-sms/v2/ue-contexts/imsi-placeholder", body)
}

func (c *smsfCtx) sendUplinkSMS(supi, recordID, payload string) error {
	body, _ := json.Marshal(map[string]any{
		"smsPayload":  payload,
		"smsRecordId": recordID,
	})
	return c.postJSON("/nsmsf-sms/v2/ue-contexts/"+supi+"/sendsms", body)
}

func (c *smsfCtx) sendDeactivate(supi string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete,
		c.ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi, nil)
	if err != nil {
		return err
	}
	return c.do(req)
}

func (c *smsfCtx) originateMT(supi, payload string) error {
	body, _ := json.Marshal(map[string]string{"smsPayload": payload})
	return c.postJSON("/nsmsf-sms-internal/v1/ue-contexts/"+supi+"/mt-sms", body)
}

// ---- then steps -------------------------------------------------------------

func (c *smsfCtx) respondsWithStatus(status int) error {
	if c.lastResp.StatusCode != status {
		return fmt.Errorf("status = %d, want %d (body: %v)", c.lastResp.StatusCode, status, c.lastBody)
	}
	return nil
}

func (c *smsfCtx) bodyHasSupi(supi string) error {
	if got, _ := c.lastBody["supi"].(string); got != supi {
		return fmt.Errorf("response supi = %q, want %q", got, supi)
	}
	return nil
}

func (c *smsfCtx) udmGotRegistration(supi, resource string) error {
	if !c.udm.sawRegistration(supi, resource) {
		return fmt.Errorf("UDM did not record a UECM registration for %q at %q", supi, resource)
	}
	return nil
}

func (c *smsfCtx) discoverableInNRF(nfType string) error {
	if n := c.nrf.discover(nfType); n < 1 {
		return fmt.Errorf("expected SMSF discoverable for nfType %q, got %d instances", nfType, n)
	}
	return nil
}

func (c *smsfCtx) amfReceivedWithin(seconds int) error {
	if !c.amf.waitForCall(time.Duration(seconds) * time.Second) {
		return fmt.Errorf("mock AMF did not receive N1N2MessageTransfer within %ds", seconds)
	}
	return nil
}

func (c *smsfCtx) n1MessageClassIs(want string) error {
	call, ok := c.amf.lastCall()
	if !ok {
		return fmt.Errorf("no N1N2MessageTransfer received")
	}
	container, _ := call["n1MessageContainer"].(map[string]any)
	if got, _ := container["n1MessageClass"].(string); got != want {
		return fmt.Errorf("n1MessageClass = %q, want %q", got, want)
	}
	return nil
}

func (c *smsfCtx) payloadContainerTypeIsSMS() error {
	call, ok := c.amf.lastCall()
	if !ok {
		return fmt.Errorf("no N1N2MessageTransfer received")
	}
	if pct, _ := call["payloadContainerType"].(float64); pct != 2 {
		return fmt.Errorf("payloadContainerType = %v, want 2 (SMS 0x02)", call["payloadContainerType"])
	}
	return nil
}

func (c *smsfCtx) echoedPayloadMatches(want string) error {
	call, ok := c.amf.lastCall()
	if !ok {
		return fmt.Errorf("no N1N2MessageTransfer received")
	}
	if got, _ := call["smsPayload"].(string); got != want {
		return fmt.Errorf("echoed smsPayload = %q, want %q", got, want)
	}
	return nil
}

func (c *smsfCtx) causeIs(want string) error {
	if got, _ := c.lastBody["cause"].(string); got != want {
		return fmt.Errorf("cause = %q, want %q", got, want)
	}
	return nil
}

// ---- runner -----------------------------------------------------------------

func InitializeScenario(sc *godog.ScenarioContext) {
	c := &smsfCtx{}
	sc.Before(c.start)
	sc.After(c.stop)

	// Background
	sc.Step(`^a clean SMSF instance is running$`, c.noop)
	sc.Step(`^the NRF is available and accepts NF registrations$`, c.noop)
	sc.Step(`^the UDM is available and accepts UECM registrations$`, c.noop)
	sc.Step(`^a mock AMF namf-comm endpoint is listening for N1N2MessageTransfer callbacks$`, c.noop)

	// Given
	sc.Step(`^the SMSF has registered with nfType "([^"]+)" in the NRF$`, c.smsfRegisteredInNRF)
	sc.Step(`^an active SMS context exists for SUPI "([^"]+)" with amfCallbackUri pointing to the mock AMF$`, c.activeContextExists)
	sc.Step(`^no SMS context exists for SUPI "([^"]+)"$`, c.noContextExists)

	// When
	sc.Step(`^the AMF sends an Nsmsf_SMService Activate request for SUPI "([^"]+)" with accessType "([^"]+)" and amfId "([^"]+)" and amfCallbackUri "([^"]+)"$`, c.sendActivate)
	sc.Step(`^the AMF sends an Nsmsf_SMService Activate request for SUPI "([^"]+)" with no accessType and amfId "([^"]+)" and amfCallbackUri "([^"]+)"$`, c.sendActivateNoAccessType)
	sc.Step(`^the AMF sends an Nsmsf_SMService Activate request with no supi in the body and accessType "([^"]+)" and amfId "([^"]+)"$`, c.sendActivateNoSupi)
	sc.Step(`^the AMF sends an Nsmsf_SMService UplinkSMS request for SUPI "([^"]+)" with smsRecordId "([^"]+)" and smsPayload "([^"]+)" and Payload Container Type 0x02$`, c.sendUplinkSMS)
	sc.Step(`^the AMF sends an Nsmsf_SMService Deactivate request for SUPI "([^"]+)"$`, c.sendDeactivate)
	sc.Step(`^the SMSF originates an MT SMS for SUPI "([^"]+)" with smsPayload "([^"]+)" and Payload Container Type 0x02$`, c.originateMT)

	// Then
	sc.Step(`^the SMSF responds with status (\d+)(?: .*)?$`, c.respondsWithStatus)
	sc.Step(`^the response body contains a UeSmsContextData with supi "([^"]+)"$`, c.bodyHasSupi)
	sc.Step(`^the UDM received a UECM registration for SUPI "([^"]+)" at resource "([^"]+)"$`, c.udmGotRegistration)
	sc.Step(`^the SMSF instance is discoverable in the NRF for nfType "([^"]+)"$`, c.discoverableInNRF)
	sc.Step(`^the mock AMF receives a Namf_Communication_N1N2MessageTransfer request within (\d+) seconds$`, c.amfReceivedWithin)
	sc.Step(`^the N1N2MessageTransfer request carries n1MessageClass "([^"]+)"$`, c.n1MessageClassIs)
	sc.Step(`^the N1N2MessageTransfer request carries Payload Container Type 0x02$`, c.payloadContainerTypeIsSMS)
	sc.Step(`^the echoed smsPayload in the N1N2MessageTransfer matches "([^"]+)"$`, c.echoedPayloadMatches)
	sc.Step(`^the N1N2MessageTransfer n1MessageContainer smsPayload is "([^"]+)"$`, c.echoedPayloadMatches)
	sc.Step(`^the cause is "([^"]+)"$`, c.causeIs)
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
