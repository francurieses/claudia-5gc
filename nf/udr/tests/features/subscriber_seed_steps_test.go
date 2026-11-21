//go:build functional

// Step definitions for subscriber_seed.feature (UDR-002): the UDR dev seed keys
// each slice's sm-data DnnConfiguration on the DNN configured per slice in
// operator.yaml. Shared steps (clean UDR, slice-qos list) come from
// slice_session_ambr_steps_test.go.
//
// Ref: TS 29.503 §6.1.6.2.8/§6.1.6.2.9, TS 23.502 §4.3.2.2.1 step 4
package features_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

const seedWarnText = "unknown seed DNN, falling back to internet"

var (
	seedSliceRe = regexp.MustCompile(`"([^"]*)"\s+(\d+)/(\w+)\s+dnn\s+"([^"]*)"`)

	// fallbackProfileIndex maps profile names to the built-in fallback profile
	// index (profile 0 = internet only, i = [internet, slice i]).
	fallbackProfileIndex = map[string]int{"internet": 0, "gold": 1, "silver": 2, "bronze": 3}
)

type seedCtx struct {
	*sqCtx
	op     *operatorcfg.OperatorConfig
	names  []string // slice names in operator.yaml order
	logBuf bytes.Buffer
	amBody []byte
	amCode int
	smCode int
	smBody []byte
}

func (c *seedCtx) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&c.logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (c *seedCtx) cleanUDR() error {
	c.op, c.names = &operatorcfg.OperatorConfig{}, nil
	c.logBuf.Reset()
	c.amBody, c.smBody, c.amCode, c.smCode = nil, nil, 0, 0
	return c.sqCtx.cleanUDR()
}

func (c *seedCtx) defineSlices(list string) error {
	m := seedSliceRe.FindAllStringSubmatch(list, -1)
	if len(m) == 0 {
		return fmt.Errorf("no slices parsed from %q", list)
	}
	for _, g := range m {
		if err := c.addSlice(g[1], g[2], g[3], g[4]); err != nil {
			return err
		}
	}
	return nil
}

func (c *seedCtx) addSlice(name, sst, sd, dnn string) error {
	var n int
	if _, err := fmt.Sscanf(sst, "%d", &n); err != nil {
		return fmt.Errorf("bad sst %q: %w", sst, err)
	}
	c.op.SNSSAIs = append(c.op.SNSSAIs, operatorcfg.SNSSAIEntry{SST: n, SD: sd, DNN: dnn})
	c.names = append(c.names, name)
	return nil
}

func (c *seedCtx) defineDNNs(list string) error {
	c.op.DNNs = nil
	for _, d := range strings.Split(list, ",") {
		c.op.DNNs = append(c.op.DNNs, operatorcfg.DNNEntry{Name: strings.TrimSpace(d)})
	}
	return nil
}

func (c *seedCtx) configAbsent() error {
	c.op, c.names = nil, nil
	return nil
}

// profileFor builds the seed profile for a named slice, as cmd/udr does.
func (c *seedCtx) profileFor(name string) ([]store.SNSSAISubscribed, error) {
	profiles := store.BuildSeedSliceProfiles(c.op, c.logger())
	idx := -1
	if c.op == nil {
		i, ok := fallbackProfileIndex[name]
		if !ok {
			return nil, fmt.Errorf("unknown fallback profile %q", name)
		}
		idx = i
	} else {
		for i, n := range c.names {
			if n == name {
				idx = i
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("slice profile %q not defined in operator config", name)
		}
	}
	if idx >= len(profiles) {
		return nil, fmt.Errorf("profile index %d out of range (%d profiles)", idx, len(profiles))
	}
	return profiles[idx], nil
}

func (c *seedCtx) seedSubscriber(supi, profile string) error {
	p, err := c.profileFor(profile)
	if err != nil {
		return err
	}
	// Existing subscribers are never overwritten (cmd/udr seed loop, step 4b).
	if existing, _ := c.st.GetAuthSubscription(supi); existing != nil {
		return nil
	}
	return store.SeedTestSubscriberWithNSSAI(c.st, supi, "00", "00", "8000", "000000000001", p)
}

func (c *seedCtx) preProvisioned(supi, slice, dnn string) error {
	sst, sd, err := parseSlice(slice)
	if err != nil {
		return err
	}
	return store.SeedTestSubscriberWithNSSAI(c.st, supi, "00", "00", "8000", "000000000001",
		[]store.SNSSAISubscribed{{SST: sst, SD: sd, DNN: dnn}})
}

func (c *seedCtx) getSM(supi, plmn string) error {
	if err := c.udmGetsSMData(supi, plmn); err != nil {
		return err
	}
	c.smCode, c.smBody = c.lastCode, c.lastBody
	return nil
}

func (c *seedCtx) getAM(supi, plmn string) error {
	code, b, err := c.do(http.MethodGet, "/nudr-dr/v2/subscription-data/"+supi+"/"+plmn+"/provisioned-data/am-data", "")
	if err != nil {
		return err
	}
	c.amCode, c.amBody = code, b
	return nil
}

func (c *seedCtx) syncSM(supi string) error {
	if err := c.req(http.MethodPost, "/nudr-internal/v1/subscribers/"+supi+"/sync-sm-data", ""); err != nil {
		return err
	}
	if c.lastCode < 200 || c.lastCode > 299 {
		return fmt.Errorf("sync-sm-data status %d (%s)", c.lastCode, c.lastBody)
	}
	return nil
}

func (c *seedCtx) seedQoS() error {
	_, err := store.SeedSliceDNNQoSFromOperator(context.Background(), c.st, c.op, c.logger())
	return err
}

func (c *seedCtx) smStatus(code int) error {
	if c.smCode != code {
		return fmt.Errorf("sm-data status %d, want %d (%s)", c.smCode, code, c.smBody)
	}
	return nil
}

func (c *seedCtx) amStatus(code int) error {
	if c.amCode != code {
		return fmt.Errorf("am-data status %d, want %d (%s)", c.amCode, code, c.amBody)
	}
	return nil
}

func (c *seedCtx) smEntry(slice string) (*store.SessionManagementSubscriptionData, error) {
	sst, sd, err := parseSlice(slice)
	if err != nil {
		return nil, err
	}
	var subs []store.SessionManagementSubscriptionData
	if err := json.Unmarshal(c.smBody, &subs); err != nil {
		return nil, fmt.Errorf("decode sm-data: %w (%s)", err, c.smBody)
	}
	for i := range subs {
		if subs[i].SingleNSSAI.SST == sst && subs[i].SingleNSSAI.SD == sd {
			return &subs[i], nil
		}
	}
	return nil, fmt.Errorf("slice %s not in sm-data: %s", slice, c.smBody)
}

func (c *seedCtx) smHasKey(slice, dnn string) error {
	e, err := c.smEntry(slice)
	if err != nil {
		return err
	}
	if _, ok := e.DNNConfigurations[dnn]; !ok {
		return fmt.Errorf("slice %s dnnConfigurations keys %v, want key %q", slice, seedKeysOf(e.DNNConfigurations), dnn)
	}
	return nil
}

func (c *seedCtx) smHasKeyQoS(slice, dnn string, fiveQI int) error {
	if err := c.smHasKey(slice, dnn); err != nil {
		return err
	}
	e, err := c.smEntry(slice)
	if err != nil {
		return err
	}
	if got := int(e.DNNConfigurations[dnn].DefaultQos.FiveQI); got != fiveQI {
		return fmt.Errorf("slice %s dnn %s 5QI %d, want %d", slice, dnn, got, fiveQI)
	}
	return nil
}

func (c *seedCtx) smNoKey(slice, dnn string) error {
	e, err := c.smEntry(slice)
	if err != nil {
		return err
	}
	if _, ok := e.DNNConfigurations[dnn]; ok {
		return fmt.Errorf("slice %s unexpectedly has dnnConfigurations key %q", slice, dnn)
	}
	return nil
}

func seedKeysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// amNoDNN asserts every S-NSSAI object (JSON object with an "sst" member) in
// the am-data body lacks the given member, and that at least one exists.
func (c *seedCtx) amNoDNN(attr string) error {
	var doc any
	if err := json.Unmarshal(c.amBody, &doc); err != nil {
		return fmt.Errorf("decode am-data: %w (%s)", err, c.amBody)
	}
	found := 0
	var walk func(v any) error
	walk = func(v any) error {
		switch t := v.(type) {
		case map[string]any:
			if _, ok := t["sst"]; ok {
				found++
				if _, has := t[attr]; has {
					return fmt.Errorf("am-data nssai entry carries %q: %v", attr, t)
				}
			}
			for _, x := range t {
				if err := walk(x); err != nil {
					return err
				}
			}
		case []any:
			for _, x := range t {
				if err := walk(x); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(doc); err != nil {
		return err
	}
	if found == 0 {
		return fmt.Errorf("no nssai entries (sst) found in am-data: %s", c.amBody)
	}
	return nil
}

func (c *seedCtx) loggedWarn(dnn string) error {
	dec := json.NewDecoder(bytes.NewReader(c.logBuf.Bytes()))
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			return fmt.Errorf("decode log record: %w", err)
		}
		if rec["level"] == "WARN" && rec["msg"] == seedWarnText && rec["dnn"] == dnn {
			return nil
		}
	}
	return fmt.Errorf("no WARN %q with dnn=%q in logs: %s", seedWarnText, dnn, c.logBuf.String())
}

func initializeSubscriberSeedScenario(ctx *godog.ScenarioContext) {
	c := &seedCtx{sqCtx: &sqCtx{}}
	ctx.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		c.stop()
		return ctx, nil
	})

	// Shared with slice_session_ambr.feature.
	ctx.Step(`^a clean UDR instance is running$`, c.cleanUDR)
	ctx.Step(`^the operator GETs the slice-dnn-qos list$`, c.list)
	ctx.Step(`^the slice-qos list contains slice "([^"]*)" dnn "([^"]*)" with source "([^"]*)"$`, c.listContainsSource)

	ctx.Step(`^the operator config defines slices (.+)$`, c.defineSlices)
	ctx.Step(`^the operator config defines slice "([^"]*)" (\d+)/(\w+) dnn "([^"]*)"$`, c.addSlice)
	ctx.Step(`^the operator config defines dnns "([^"]*)"$`, c.defineDNNs)
	ctx.Step(`^the operator config is absent$`, c.configAbsent)
	ctx.Step(`^subscriber "([^"]*)" is pre-provisioned with sm-data for slice "([^"]*)" keyed "([^"]*)"$`, c.preProvisioned)
	ctx.Step(`^the dev subscriber "([^"]*)" is seeded with the "([^"]*)" slice profile$`, c.seedSubscriber)
	ctx.Step(`^the UDM GETs seeded sm-data of "([^"]*)" for PLMN "([^"]*)"$`, c.getSM)
	ctx.Step(`^the UDM GETs seeded am-data of "([^"]*)" for PLMN "([^"]*)"$`, c.getAM)
	ctx.Step(`^the operator POSTs sync-sm-data for "([^"]*)"$`, c.syncSM)
	ctx.Step(`^the slice_dnn_qos table is seeded from the operator config$`, c.seedQoS)

	ctx.Step(`^the seeded sm-data status is (\d+)$`, c.smStatus)
	ctx.Step(`^the seeded am-data status is (\d+)$`, c.amStatus)
	ctx.Step(`^the seeded sm-data for slice "([^"]*)" has dnnConfigurations key "([^"]*)" with 5QI (\d+)$`, c.smHasKeyQoS)
	ctx.Step(`^the seeded sm-data for slice "([^"]*)" has dnnConfigurations key "([^"]*)"$`, c.smHasKey)
	ctx.Step(`^the seeded sm-data for slice "([^"]*)" has no dnnConfigurations key "([^"]*)"$`, c.smNoKey)
	ctx.Step(`^the seeded am-data nssai entries carry no "([^"]*)" attribute$`, c.amNoDNN)
	ctx.Step(`^the UDR logged a WARN about unknown seed DNN "([^"]*)"$`, c.loggedWarn)
}

func TestSubscriberSeedFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: initializeSubscriberSeedScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"subscriber_seed.feature"},
			Strict:   true,
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
