//go:build functional

// Package features contains godog BDD step definitions for the NRF.
// Run with: go test -tags=functional ./tests/features/...
// Ref: TS 29.510 §5.2.2.2 (NFRegister), §5.3.2.2 (NFDiscover)
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
	"os"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/nf/nrf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/nrf/internal/registry"
	"github.com/francurieses/claudia-5gc/nf/nrf/internal/server"
)

// nrfCtx holds per-scenario state for NRF BDD tests.
type nrfCtx struct {
	srv        *server.Server
	baseURL    string
	profileID  string
	profile    map[string]interface{}
	lastResp   *http.Response
	lastBody   map[string]interface{}
}

// startServer creates a fresh NRF with in-memory registry bound to a random port.
func (c *nrfCtx) startServer(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0" // random port
	cfg.Metrics.Address = "127.0.0.1:0"
	cfg.OAuth2Secret = "test-secret"

	reg := registry.NewInMemory(slog.New(slog.NewTextHandler(io.Discard, nil)))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv, err := server.New(cfg, reg, logger)
	if err != nil {
		return ctx, fmt.Errorf("start NRF: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return ctx, err
	}

	go func() {
		_ = srv.ServeH2C(ln)
	}()

	c.srv = srv
	c.baseURL = "http://" + ln.Addr().String()
	// Wait for server to be ready
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err2 := http.Get(c.baseURL + "/healthz")
		if err2 == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ctx, nil
}

func (c *nrfCtx) stopServer(_ context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
	if c.srv != nil {
		_ = c.srv.Shutdown(context.Background())
	}
	return context.Background(), nil
}

// ---- Step definitions -----

func (c *nrfCtx) aCleanNRFInstanceIsRunning() error { return nil } // handled by startServer hook

func (c *nrfCtx) anNFProfileForAMFWithInstanceId(nfType, id string) error {
	c.profileID = id
	c.profile = map[string]interface{}{
		"nfInstanceId": id,
		"nfType":       nfType,
		"nfStatus":     "REGISTERED",
	}
	return nil
}

func (c *nrfCtx) theNFSendsAnNFRegisterRequest() error {
	return c.sendRegister(c.profileID)
}

func (c *nrfCtx) sendRegister(id string) error {
	body, _ := json.Marshal(c.profile)
	req, _ := http.NewRequest(http.MethodPut,
		c.baseURL+"/nnrf-nfm/v1/nf-instances/"+id,
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	c.lastResp = resp
	var m map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	c.lastBody = m
	return nil
}

func (c *nrfCtx) theNRFRespondsWith(statusCode int) error {
	if c.lastResp.StatusCode != statusCode {
		return fmt.Errorf("expected status %d, got %d", statusCode, c.lastResp.StatusCode)
	}
	return nil
}

func (c *nrfCtx) theResponseBodyContainsTheSameNfInstanceId() error {
	if got, _ := c.lastBody["nfInstanceId"].(string); got != c.profileID {
		return fmt.Errorf("expected nfInstanceId %q, got %q", c.profileID, got)
	}
	return nil
}

func (c *nrfCtx) theLocationHeaderIs(expected string) error {
	if got := c.lastResp.Header.Get("Location"); got != expected {
		return fmt.Errorf("expected Location %q, got %q", expected, got)
	}
	return nil
}

func (c *nrfCtx) theNFAppearsInSubsequentNFDiscoverQueriesForType(nfType string) error {
	resp, err := http.Get(c.baseURL + "/nnrf-disc/v1/nf-instances?target-nf-type=" + nfType + "&requester-nf-type=AMF")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	instances, _ := result["nfInstances"].([]interface{})
	if len(instances) == 0 {
		return fmt.Errorf("expected NF to appear in discovery results")
	}
	return nil
}

func (c *nrfCtx) theNFSendsAnNFRegisterRequestToURIFor(uriID string) error {
	body, _ := json.Marshal(c.profile)
	req, _ := http.NewRequest(http.MethodPut,
		c.baseURL+"/nnrf-nfm/v1/nf-instances/"+uriID,
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	c.lastResp = resp
	var m map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	c.lastBody = m
	return nil
}

func (c *nrfCtx) theCauseIs(cause string) error {
	if got, _ := c.lastBody["cause"].(string); got != cause {
		return fmt.Errorf("expected cause %q, got %q", cause, got)
	}
	return nil
}

func (c *nrfCtx) twoAMFsRegisteredOnlyOneAdvertisesService(serviceName string) error {
	// Register AMF 1 with the service
	c.profileID = "amf-id-1"
	c.profile = map[string]interface{}{
		"nfInstanceId": "amf-id-1",
		"nfType":       "AMF",
		"nfStatus":     "REGISTERED",
		"nfServices": []map[string]interface{}{
			{
				"serviceInstanceId": "amf-1-svc",
				"serviceName":       serviceName,
				"versions":          []map[string]string{{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}},
				"scheme":            "https",
				"nfServiceStatus":   "REGISTERED",
			},
		},
	}
	if err := c.sendRegister("amf-id-1"); err != nil {
		return err
	}
	if c.lastResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("register AMF-1 failed: %d", c.lastResp.StatusCode)
	}
	// Register AMF 2 without the service
	c.profile = map[string]interface{}{
		"nfInstanceId": "amf-id-2",
		"nfType":       "AMF",
		"nfStatus":     "REGISTERED",
	}
	if err := c.sendRegister("amf-id-2"); err != nil {
		return err
	}
	if c.lastResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("register AMF-2 failed: %d", c.lastResp.StatusCode)
	}
	return nil
}

func (c *nrfCtx) anSMFQueriesNFDiscoverForAMFsWithServiceNamesFilter(serviceNamesParam string) error {
	url := c.baseURL + "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF&service-names=" + serviceNamesParam
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	c.lastResp = resp
	var m map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&m)
	c.lastBody = m
	return nil
}

func (c *nrfCtx) exactlyNNFInstanceIsReturned(n int) error {
	instances, _ := c.lastBody["nfInstances"].([]interface{})
	if len(instances) != n {
		return fmt.Errorf("expected %d NF instances, got %d", n, len(instances))
	}
	return nil
}

// ---- Godog runner ----

func InitializeScenario(sc *godog.ScenarioContext) {
	c := &nrfCtx{}
	sc.Before(c.startServer)
	sc.After(c.stopServer)

	sc.Step(`^a clean NRF instance is running$`, c.aCleanNRFInstanceIsRunning)
	sc.Step(`^an NF profile for (AMF|SMF|UDM) with instance id "([^"]+)"$`, c.anNFProfileForAMFWithInstanceId)
	sc.Step(`^the NF sends an NFRegister request$`, c.theNFSendsAnNFRegisterRequest)
	sc.Step(`^the NRF responds with status (\d+)`, c.theNRFRespondsWith)
	sc.Step(`^the response body contains the same nfInstanceId$`, c.theResponseBodyContainsTheSameNfInstanceId)
	sc.Step(`^the Location header is "([^"]+)"$`, c.theLocationHeaderIs)
	sc.Step(`^the NF appears in subsequent NFDiscover queries for type "([^"]+)"$`, c.theNFAppearsInSubsequentNFDiscoverQueriesForType)
	sc.Step(`^the NF sends an NFRegister request to URI for "([^"]+)"$`, c.theNFSendsAnNFRegisterRequestToURIFor)
	sc.Step(`^the cause is "([^"]+)"$`, c.theCauseIs)
	sc.Step(`^two AMFs registered, only one advertises "([^"]+)" service$`, c.twoAMFsRegisteredOnlyOneAdvertisesService)
	sc.Step(`^an SMF queries NFDiscover for AMFs with service-names="([^"]+)"$`, c.anSMFQueriesNFDiscoverForAMFsWithServiceNamesFilter)
	sc.Step(`^exactly (\d+) NF instance is returned$`, c.exactlyNNFInstanceIsReturned)
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
