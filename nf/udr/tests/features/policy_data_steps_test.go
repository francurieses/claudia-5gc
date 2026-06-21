//go:build functional

// Package features contains godog BDD step definitions for the UDR policy-data
// (SM Policy Data + UE Policy Set) resource. Run with:
//
//	go test -tags=functional ./nf/udr/tests/features/...
//
// Ref: UDR-001, TS 29.504 §5.2.13 / TS 29.519 §5.6.2.4
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
	"testing"

	"github.com/cucumber/godog"

	udrsrv "github.com/francurieses/claudia-5gc/nf/udr/internal/server"
	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
)

type udrCtx struct {
	ts       *httptest.Server
	lastCode int
	lastBody []byte
}

func (c *udrCtx) aCleanUDRInstanceIsRunning() error {
	st := store.NewInMemory()
	srv, err := udrsrv.New(":0", udrsrv.TLSConfig{}, st, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return err
	}
	c.ts = httptest.NewServer(srv.Handler())
	return nil
}

func (c *udrCtx) stop() {
	if c.ts != nil {
		c.ts.Close()
		c.ts = nil
	}
}

func (c *udrCtx) req(method, path, body string) error {
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	}
	r, err := http.NewRequest(method, c.ts.URL+path, rdr)
	if err != nil {
		return err
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.ts.Client().Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	c.lastCode = resp.StatusCode
	c.lastBody, _ = io.ReadAll(resp.Body)
	return nil
}

func smDataBody(slice, sd string, sst int, dnn string, fiveQI int) string {
	return fmt.Sprintf(`{"smPolicySnssaiData":{"%s":{"snssai":{"sst":%d,"sd":"%s"},`+
		`"smPolicyDnnData":{"%s":{"dnn":"%s","5qi":%d}}}}}`, slice, sst, sd, dnn, dnn, fiveQI)
}

func sliceParts(slice string) (int, string) {
	var sst int
	var sd string
	parts := bytes.SplitN([]byte(slice), []byte("-"), 2)
	fmt.Sscanf(string(parts[0]), "%d", &sst)
	if len(parts) == 2 {
		sd = string(parts[1])
	}
	return sst, sd
}

func (c *udrCtx) pcfPutsSMData(supi, slice, dnn string, fiveQI int) error {
	sst, sd := sliceParts(slice)
	return c.req(http.MethodPut, "/nudr-dr/v2/policy-data/"+supi+"/sm-data",
		smDataBody(slice, sd, sst, dnn, fiveQI))
}

func (c *udrCtx) smDataProvisioned(supi, slice, dnn string, fiveQI int) error {
	if err := c.pcfPutsSMData(supi, slice, dnn, fiveQI); err != nil {
		return err
	}
	if c.lastCode != http.StatusNoContent {
		return fmt.Errorf("provision sm-data: status %d", c.lastCode)
	}
	return nil
}

func (c *udrCtx) pcfPatchesSMData(supi, slice, dnn string, fiveQI int) error {
	sst, sd := sliceParts(slice)
	return c.req(http.MethodPatch, "/nudr-dr/v2/policy-data/"+supi+"/sm-data",
		smDataBody(slice, sd, sst, dnn, fiveQI))
}

func (c *udrCtx) pcfGetsSMData(supi string) error {
	return c.req(http.MethodGet, "/nudr-dr/v2/policy-data/"+supi+"/sm-data", "")
}

func (c *udrCtx) statusIs(code int) error {
	if c.lastCode != code {
		return fmt.Errorf("expected status %d, got %d (%s)", code, c.lastCode, string(c.lastBody))
	}
	return nil
}

func (c *udrCtx) smDataHas5QI(fiveQI int, slice, dnn string) error {
	var data store.SmPolicyData
	if err := json.Unmarshal(c.lastBody, &data); err != nil {
		return err
	}
	got := data.SmPolicySnssaiData[slice].SmPolicyDnnData[dnn].FiveQI
	if got != fiveQI {
		return fmt.Errorf("slice %s dnn %s: 5qi got %d want %d", slice, dnn, got, fiveQI)
	}
	return nil
}

func (c *udrCtx) uePolicySetProvisioned(supi string, prec int) error {
	if err := c.req(http.MethodPut, "/nudr-dr/v2/policy-data/"+supi+"/ue-policy-set",
		fmt.Sprintf(`{"precedence":%d,"rules":[]}`, prec)); err != nil {
		return err
	}
	if c.lastCode != http.StatusNoContent {
		return fmt.Errorf("provision ue-policy-set: status %d", c.lastCode)
	}
	return nil
}

func (c *udrCtx) pcfPatchesUEPolicySet(supi string, prec int) error {
	return c.req(http.MethodPatch, "/nudr-dr/v2/policy-data/"+supi+"/ue-policy-set",
		fmt.Sprintf(`{"precedence":%d}`, prec))
}

func (c *udrCtx) pcfGetsUEPolicySet(supi string) error {
	return c.req(http.MethodGet, "/nudr-dr/v2/policy-data/"+supi+"/ue-policy-set", "")
}

func (c *udrCtx) uePolicySetPrecedenceIs(prec int) error {
	var sub store.PolicySubscription
	if err := json.Unmarshal(c.lastBody, &sub); err != nil {
		return err
	}
	if sub.Precedence != prec {
		return fmt.Errorf("precedence got %d want %d", sub.Precedence, prec)
	}
	return nil
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	c := &udrCtx{}
	ctx.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		c.stop()
		return ctx, nil
	})

	ctx.Step(`^a clean UDR instance is running$`, c.aCleanUDRInstanceIsRunning)
	ctx.Step(`^the PCF PUTs SM policy data for "([^"]*)" slice "([^"]*)" dnn "([^"]*)" with 5qi (\d+)$`, c.pcfPutsSMData)
	ctx.Step(`^SM policy data for "([^"]*)" slice "([^"]*)" dnn "([^"]*)" with 5qi (\d+) is provisioned$`, c.smDataProvisioned)
	ctx.Step(`^the PCF PATCHes SM policy data for "([^"]*)" slice "([^"]*)" dnn "([^"]*)" with 5qi (\d+)$`, c.pcfPatchesSMData)
	ctx.Step(`^the PCF GETs SM policy data for "([^"]*)"$`, c.pcfGetsSMData)
	ctx.Step(`^the policy-data response status is (\d+)$`, c.statusIs)
	ctx.Step(`^the SM policy data has 5qi (\d+) for slice "([^"]*)" dnn "([^"]*)"$`, c.smDataHas5QI)
	ctx.Step(`^UE policy set for "([^"]*)" with precedence (\d+) is provisioned$`, c.uePolicySetProvisioned)
	ctx.Step(`^the PCF PATCHes UE policy set for "([^"]*)" with precedence (\d+)$`, c.pcfPatchesUEPolicySet)
	ctx.Step(`^the PCF GETs UE policy set for "([^"]*)"$`, c.pcfGetsUEPolicySet)
	ctx.Step(`^the UE policy set precedence is (\d+)$`, c.uePolicySetPrecedenceIs)
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"policy_data.feature"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
