//go:build functional

// Package features contains godog BDD step definitions for UDM SDM Subscribe/Notify.
// Run with: go test -tags=functional ./nf/udm/tests/features/...
// Ref: TS 29.503 §5.3.2 (Subscribe), §5.3.3 (Notify)
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"

	udmsrv "github.com/francurieses/claudia-5gc/nf/udm/internal/server"
)

// udmCtx holds per-scenario state.
type udmCtx struct {
	srv            *udmsrv.Server
	baseURL        string
	callbackSrv    *httptest.Server
	callbackCh     chan []byte // receives raw callback body
	lastResp       *http.Response
	lastBody       []byte
	subscriptionID string
	client         *http.Client
}

// ---- stub UDR ---------------------------------------------------------------

type stubUDRClient struct{}

func (s *stubUDRClient) GetAuthSubscription(_ context.Context, supi string) (*udmsrv.UDRAuthSub, error) {
	return &udmsrv.UDRAuthSub{
		AuthMethod: "5G_AKA",
		K:          "465b5ce8b199b49faa5f0a2ee238a6bc",
		OPc:        "e8ed289deba952e4283b54e88e6183ca",
		AMF:        "8000",
		SQN:        "000000000001",
		AlgID:      "milenage",
	}, nil
}
func (s *stubUDRClient) UpdateSQN(_ context.Context, _, _ string) error { return nil }
func (s *stubUDRClient) GetAMData(_ context.Context, _ string) (*udmsrv.UDRAMData, error) {
	return &udmsrv.UDRAMData{AMBRUplink: 100000, AMBRDownlink: 100000}, nil
}
func (s *stubUDRClient) GetSMData(_ context.Context, _ string) (json.RawMessage, error) {
	return json.RawMessage(`[]`), nil
}

// ---- server lifecycle -------------------------------------------------------

func (c *udmCtx) startUDM(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
	c.client = &http.Client{Timeout: 5 * time.Second}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := udmsrv.New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org",
		udmsrv.TLSConfig{}, &stubUDRClient{}, logger)
	if err != nil {
		return ctx, fmt.Errorf("start UDM: %w", err)
	}
	// Use a plain HTTP/1.1 client for callbacks in tests.
	srv.WithNotifyClient(&http.Client{Timeout: 5 * time.Second})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return ctx, err
	}
	go func() { _ = srv.ServeH2C(ln) }()

	c.srv = srv
	c.baseURL = "http://" + ln.Addr().String()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err2 := c.client.Get(c.baseURL + "/healthz")
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

func (c *udmCtx) stopUDM(_ context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
	if c.callbackSrv != nil {
		c.callbackSrv.Close()
	}
	return context.Background(), nil
}

// ---- step definitions -------------------------------------------------------

func (c *udmCtx) aCleanUDMInstanceIsRunning() error { return nil } // startUDM hook handles it

func (c *udmCtx) subscriberExists(_ string) error { return nil } // stub UDR always succeeds

func (c *udmCtx) aCallbackListenerIsStarted() error {
	c.callbackCh = make(chan []byte, 4)
	mu := &sync.Mutex{}
	_ = mu
	c.callbackSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.callbackCh <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	return nil
}

func (c *udmCtx) amfSubscribesWithCallbackURI(supi string) error {
	sub := map[string]any{
		"callbackReference":   c.callbackSrv.URL + "/callback",
		"monitoredResourceUri": c.baseURL + "/nudm-sdm/v2/" + supi + "/am-data",
	}
	body, _ := json.Marshal(sub)
	resp, err := c.client.Post(
		c.baseURL+"/nudm-sdm/v2/"+supi+"/sdm-subscriptions",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	c.lastBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	c.lastResp = resp

	// extract subscriptionId for reuse
	var parsed map[string]any
	if err := json.Unmarshal(c.lastBody, &parsed); err == nil {
		if id, ok := parsed["subscriptionId"].(string); ok {
			c.subscriptionID = id
		}
	}
	return nil
}

func (c *udmCtx) responseStatusIs(expected int) error {
	if c.lastResp.StatusCode != expected {
		return fmt.Errorf("expected status %d, got %d; body: %s",
			expected, c.lastResp.StatusCode, c.lastBody)
	}
	return nil
}

func (c *udmCtx) responseContainsSubscriptionId() error {
	var parsed map[string]any
	if err := json.Unmarshal(c.lastBody, &parsed); err != nil {
		return fmt.Errorf("response not JSON: %w", err)
	}
	if _, ok := parsed["subscriptionId"]; !ok {
		return fmt.Errorf("subscriptionId missing from response: %s", c.lastBody)
	}
	return nil
}

func (c *udmCtx) locationHeaderContainsSubscriptionId() error {
	loc := c.lastResp.Header.Get("Location")
	if loc == "" {
		return fmt.Errorf("Location header missing")
	}
	if c.subscriptionID == "" {
		return fmt.Errorf("subscriptionId not captured")
	}
	if !strings.Contains(loc, c.subscriptionID) {
		return fmt.Errorf("Location %q does not contain subscriptionId %q", loc, c.subscriptionID)
	}
	return nil
}

func (c *udmCtx) dataChangeIsTriggered(supi string) error {
	changes := []map[string]any{{
		"changeType":   "REPLACE",
		"resourcePath": "/nudm-sdm/v2/" + supi + "/am-data",
		"newValue":     map[string]any{"subscribedUeAmbr": map[string]any{"uplink": "200Mbps", "downlink": "400Mbps"}},
	}}
	body, _ := json.Marshal(changes)
	resp, err := c.client.Post(
		c.baseURL+"/nudm-mgmt/v1/"+supi+"/data-change",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *udmCtx) callbackReceivedWithinSeconds(seconds int) error {
	select {
	case body := <-c.callbackCh:
		var notif map[string]any
		if err := json.Unmarshal(body, &notif); err != nil {
			return fmt.Errorf("callback body is not JSON: %w", err)
		}
		if _, ok := notif["resourceChanges"]; !ok {
			return fmt.Errorf("resourceChanges missing from notification: %s", body)
		}
		return nil
	case <-time.After(time.Duration(seconds) * time.Second):
		return fmt.Errorf("callback not received within %d seconds", seconds)
	}
}

func (c *udmCtx) amfHasSubscribed(supi string) error {
	return c.amfSubscribesWithCallbackURI(supi)
}

func (c *udmCtx) amfUnsubscribes(supi string) error {
	url := fmt.Sprintf("%s/nudm-sdm/v2/%s/sdm-subscriptions/%s",
		c.baseURL, supi, c.subscriptionID)
	req, _ := http.NewRequest("DELETE", url, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	c.lastBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	c.lastResp = resp
	return nil
}

func (c *udmCtx) unsubscribeResponseStatusIs(expected int) error {
	if c.lastResp.StatusCode != expected {
		return fmt.Errorf("expected %d, got %d", expected, c.lastResp.StatusCode)
	}
	return nil
}

func (c *udmCtx) callbackReceivedNoNotificationWithinMs(ms int) error {
	select {
	case body := <-c.callbackCh:
		return fmt.Errorf("unexpected callback received: %s", body)
	case <-time.After(time.Duration(ms) * time.Millisecond):
		return nil // good — no callback
	}
}

func (c *udmCtx) amfSubscribesWithoutCallbackReference(supi string) error {
	body, _ := json.Marshal(map[string]any{"nfInstanceId": "test-id"})
	resp, err := c.client.Post(
		c.baseURL+"/nudm-sdm/v2/"+supi+"/sdm-subscriptions",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	c.lastBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	c.lastResp = resp
	return nil
}

func (c *udmCtx) causeIs(expectedCause string) error {
	var parsed map[string]any
	if err := json.Unmarshal(c.lastBody, &parsed); err != nil {
		return fmt.Errorf("response not JSON: %w", err)
	}
	cause, _ := parsed["cause"].(string)
	if cause != expectedCause {
		return fmt.Errorf("expected cause %q, got %q", expectedCause, cause)
	}
	return nil
}

// ---- godog wiring -----------------------------------------------------------

func InitializeScenario(ctx *godog.ScenarioContext) {
	c := &udmCtx{}

	ctx.Before(c.startUDM)
	ctx.After(c.stopUDM)

	ctx.Step(`^a clean UDM instance is running$`, c.aCleanUDMInstanceIsRunning)
	ctx.Step(`^subscriber "([^"]*)" exists$`, c.subscriberExists)
	ctx.Step(`^a callback listener is started$`, c.aCallbackListenerIsStarted)
	ctx.Step(`^AMF subscribes to SDM changes for "([^"]*)" with the callback URI$`, c.amfSubscribesWithCallbackURI)
	ctx.Step(`^the response status is (\d+)$`, c.responseStatusIs)
	ctx.Step(`^the response contains a subscriptionId$`, c.responseContainsSubscriptionId)
	ctx.Step(`^the Location header contains the subscriptionId$`, c.locationHeaderContainsSubscriptionId)
	ctx.Step(`^a data change is triggered for "([^"]*)"$`, c.dataChangeIsTriggered)
	ctx.Step(`^the callback listener receives a ModificationNotification within (\d+) seconds$`, c.callbackReceivedWithinSeconds)
	ctx.Step(`^AMF has subscribed to SDM changes for "([^"]*)" with the callback URI$`, c.amfHasSubscribed)
	ctx.Step(`^AMF unsubscribes using the subscriptionId$`, func() error { return c.amfUnsubscribes("imsi-001010000000001") })
	ctx.Step(`^the unsubscribe response status is (\d+)$`, c.unsubscribeResponseStatusIs)
	ctx.Step(`^the callback listener receives no notification within (\d+) milliseconds$`, c.callbackReceivedNoNotificationWithinMs)
	ctx.Step(`^AMF subscribes without a callbackReference$`, func() error {
		return c.amfSubscribesWithoutCallbackReference("imsi-001010000000001")
	})
	ctx.Step(`^the cause is "([^"]*)"$`, c.causeIs)
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"nudm_sdm_subscribe.feature"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
