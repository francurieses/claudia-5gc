//go:build functional

// Step definitions for slice_session_ambr.feature (UDR-003): per (S-NSSAI, DNN)
// subscribed Session-AMBR managed through /nudr-internal/v1/slice-dnn-qos.
//
// Ref: TS 23.501 §5.7.2.6, TS 29.503 §6.1.6.2.8/§6.1.6.2.9, TS 29.571 §5.5.2
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
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	udrsrv "github.com/francurieses/claudia-5gc/nf/udr/internal/server"
	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
)

const sqBase = "/nudr-internal/v1/slice-dnn-qos"

type sqItem struct {
	Snssai struct {
		SST int    `json:"sst"`
		SD  string `json:"sd"`
	} `json:"snssai"`
	DNN         string `json:"dnn"`
	SessionAmbr struct {
		Uplink   string `json:"uplink"`
		Downlink string `json:"downlink"`
	} `json:"sessionAmbr"`
	Source             string `json:"source"`
	DefaultSessionAmbr struct {
		Uplink   string `json:"uplink"`
		Downlink string `json:"downlink"`
	} `json:"defaultSessionAmbr"`
	DefaultSource string `json:"defaultSource"`
}

type sqWrite struct {
	Item    sqItem `json:"item"`
	Changed bool   `json:"changed"`
	Resync  struct {
		AffectedSubscribers int               `json:"affectedSubscribers"`
		Synced              int               `json:"synced"`
		Failed              []json.RawMessage `json:"failed"`
	} `json:"resync"`
}

type sqProblem struct {
	Status        int    `json:"status"`
	Cause         string `json:"cause"`
	InvalidParams []struct {
		Param string `json:"param"`
	} `json:"invalidParams"`
}

type sqCtx struct {
	ts       *httptest.Server
	st       *store.InMemory
	slices   []store.SNSSAISubscribed
	lastCode int
	lastBody []byte
	lastSeed *store.SeedResult
}

func (c *sqCtx) stop() {
	if c.ts != nil {
		c.ts.Close()
		c.ts = nil
	}
}

func (c *sqCtx) do(method, path, body string) (int, []byte, error) {
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	}
	r, err := http.NewRequest(method, c.ts.URL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.ts.Client().Do(r)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

func (c *sqCtx) req(method, path, body string) error {
	code, b, err := c.do(method, path, body)
	if err != nil {
		return err
	}
	c.lastCode, c.lastBody = code, b
	return nil
}

func parseSlice(s string) (uint8, string, error) {
	p := strings.SplitN(s, "/", 2)
	if len(p) != 2 {
		return 0, "", fmt.Errorf("bad slice %q, want sst/sd", s)
	}
	n, err := strconv.ParseUint(p[0], 10, 8)
	if err != nil {
		return 0, "", fmt.Errorf("bad sst in %q: %w", s, err)
	}
	return uint8(n), p[1], nil
}

func sqBody(ul, dl string) string {
	return fmt.Sprintf(`{"sessionAmbr":{"uplink":%q,"downlink":%q}}`, ul, dl)
}

// ---- Given ----

func (c *sqCtx) cleanUDR() error {
	c.st = store.NewInMemory()
	srv, err := udrsrv.New(":0", udrsrv.TLSConfig{}, c.st, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return err
	}
	c.ts = httptest.NewServer(srv.Handler())
	return nil
}

func (c *sqCtx) seeded(a, b, dnn string) error {
	c.slices = nil
	for _, s := range []string{a, b} {
		sst, sd, err := parseSlice(s)
		if err != nil {
			return err
		}
		c.slices = append(c.slices, store.SNSSAISubscribed{SST: sst, SD: sd, DNN: dnn})
	}
	_, err := store.SeedSliceDNNQoSFromEntries(context.Background(), c.st, c.slices, nil)
	return err
}

func (c *sqCtx) seededDefaultIs(slice, dnn, ul, dl string) error {
	if err := c.get(slice + "/" + dnn); err != nil {
		return err
	}
	return c.itemAmbrIs(c.lastBody, ul, dl, "seeded default")
}

func (c *sqCtx) subscriberProvisioned(supi, slice, dnn string) error {
	sst, sd, err := parseSlice(slice)
	if err != nil {
		return err
	}
	return store.SeedTestSubscriberWithNSSAI(c.st, supi, "00", "00", "8000", "000000000001",
		[]store.SNSSAISubscribed{{SST: sst, SD: sd, DNN: dnn}})
}

func (c *sqCtx) wasEdited(key, ul, dl string) error {
	code, b, err := c.do(http.MethodPut, sqBase+"/"+key, sqBody(ul, dl))
	if err != nil {
		return err
	}
	if code != 200 && code != 201 {
		return fmt.Errorf("precondition edit of %s: status %d (%s)", key, code, b)
	}
	return nil
}

// ---- When ----

func (c *sqCtx) list() error { return c.req(http.MethodGet, sqBase, "") }

func (c *sqCtx) get(key string) error { return c.req(http.MethodGet, sqBase+"/"+key, "") }

func (c *sqCtx) del(key string) error { return c.req(http.MethodDelete, sqBase+"/"+key, "") }

func (c *sqCtx) put(key, ul, dl string) error {
	return c.req(http.MethodPut, sqBase+"/"+key, sqBody(ul, dl))
}

func (c *sqCtx) putRaw(key, body string) error { return c.req(http.MethodPut, sqBase+"/"+key, body) }

func (c *sqCtx) udmGetsSMData(supi, plmn string) error {
	return c.req(http.MethodGet, "/nudr-dr/v2/subscription-data/"+supi+"/"+plmn+"/provisioned-data/sm-data", "")
}

func (c *sqCtx) restart(entries []store.OperatorSeedEntry) error {
	// Same persistent store, UDR process "restarts": seed runs again (cmd/udr SeedAndResync).
	res, err := store.SeedSliceDNNQoSFromEntries(context.Background(), c.st, c.slices, entries)
	if err != nil {
		return err
	}
	c.lastSeed = res
	return nil
}

func (c *sqCtx) restartDefault() error { return c.restart(nil) }

func (c *sqCtx) restartOperator(slice, dnn, ul, dl string) error {
	sst, sd, err := parseSlice(slice)
	if err != nil {
		return err
	}
	return c.restart([]store.OperatorSeedEntry{{
		Key:  store.NewSliceKey(sst, sd, dnn),
		AMBR: store.AMBR{Uplink: ul, Downlink: dl},
	}})
}

// ---- Then ----

func (c *sqCtx) statusIs(code int) error {
	if c.lastCode != code {
		return fmt.Errorf("expected status %d, got %d (%s)", code, c.lastCode, c.lastBody)
	}
	return nil
}

func (c *sqCtx) listItems() ([]sqItem, error) {
	var l struct {
		Items []sqItem `json:"items"`
	}
	if err := json.Unmarshal(c.lastBody, &l); err != nil {
		return nil, fmt.Errorf("decode list: %w (%s)", err, c.lastBody)
	}
	return l.Items, nil
}

func (c *sqCtx) findInList(slice, dnn string) (*sqItem, error) {
	sst, sd, err := parseSlice(slice)
	if err != nil {
		return nil, err
	}
	items, err := c.listItems()
	if err != nil {
		return nil, err
	}
	for i := range items {
		if items[i].Snssai.SST == int(sst) && items[i].Snssai.SD == sd && items[i].DNN == dnn {
			return &items[i], nil
		}
	}
	return nil, fmt.Errorf("slice %s dnn %s not in list: %s", slice, dnn, c.lastBody)
}

func (c *sqCtx) listContainsFull(slice, dnn, ul, dl, src string) error {
	it, err := c.findInList(slice, dnn)
	if err != nil {
		return err
	}
	if it.SessionAmbr.Uplink != ul || it.SessionAmbr.Downlink != dl || it.Source != src {
		return fmt.Errorf("%s/%s: got %q/%q source %q, want %q/%q source %q",
			slice, dnn, it.SessionAmbr.Uplink, it.SessionAmbr.Downlink, it.Source, ul, dl, src)
	}
	return nil
}

func (c *sqCtx) listContainsSource(slice, dnn, src string) error {
	it, err := c.findInList(slice, dnn)
	if err != nil {
		return err
	}
	if it.Source != src {
		return fmt.Errorf("%s/%s: source %q, want %q", slice, dnn, it.Source, src)
	}
	return nil
}

func (c *sqCtx) listSorted() error {
	items, err := c.listItems()
	if err != nil {
		return err
	}
	if !sort.SliceIsSorted(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Snssai.SST != b.Snssai.SST {
			return a.Snssai.SST < b.Snssai.SST
		}
		if a.Snssai.SD != b.Snssai.SD {
			return a.Snssai.SD < b.Snssai.SD
		}
		return a.DNN < b.DNN
	}) {
		return fmt.Errorf("list not sorted by sst, sd, dnn: %s", c.lastBody)
	}
	return nil
}

// decodeItem accepts both a bare item (GET) and a write response (PUT/DELETE).
func decodeItem(b []byte) (*sqItem, error) {
	var w sqWrite
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("decode: %w (%s)", err, b)
	}
	if w.Item.DNN != "" {
		return &w.Item, nil
	}
	var it sqItem
	if err := json.Unmarshal(b, &it); err != nil || it.DNN == "" {
		return nil, fmt.Errorf("no item in body: %s", b)
	}
	return &it, nil
}

func (c *sqCtx) itemAmbrIs(b []byte, ul, dl, what string) error {
	it, err := decodeItem(b)
	if err != nil {
		return err
	}
	if it.SessionAmbr.Uplink != ul || it.SessionAmbr.Downlink != dl {
		return fmt.Errorf("%s: Session-AMBR %q/%q, want %q/%q", what, it.SessionAmbr.Uplink, it.SessionAmbr.Downlink, ul, dl)
	}
	return nil
}

func (c *sqCtx) itemHas(src, ul, dl string) error {
	it, err := decodeItem(c.lastBody)
	if err != nil {
		return err
	}
	if it.Source != src {
		return fmt.Errorf("item source %q, want %q", it.Source, src)
	}
	return c.itemAmbrIs(c.lastBody, ul, dl, "item")
}

func (c *sqCtx) itemKeepsDefault(ul, dl string) error {
	it, err := decodeItem(c.lastBody)
	if err != nil {
		return err
	}
	if it.DefaultSessionAmbr.Uplink != ul || it.DefaultSessionAmbr.Downlink != dl {
		return fmt.Errorf("default Session-AMBR %q/%q, want %q/%q", it.DefaultSessionAmbr.Uplink, it.DefaultSessionAmbr.Downlink, ul, dl)
	}
	return nil
}

func (c *sqCtx) itemSstNoSD(sst int) error {
	it, err := decodeItem(c.lastBody)
	if err != nil {
		return err
	}
	if it.Snssai.SST != sst || it.Snssai.SD != "" {
		return fmt.Errorf("snssai sst=%d sd=%q, want sst=%d and no sd", it.Snssai.SST, it.Snssai.SD, sst)
	}
	return nil
}

func (c *sqCtx) resyncReports(affected, synced int) error {
	var w sqWrite
	if err := json.Unmarshal(c.lastBody, &w); err != nil {
		return fmt.Errorf("decode write response: %w (%s)", err, c.lastBody)
	}
	if w.Resync.AffectedSubscribers != affected || w.Resync.Synced != synced || len(w.Resync.Failed) != 0 {
		return fmt.Errorf("resync affected=%d synced=%d failed=%d, want %d/%d/0",
			w.Resync.AffectedSubscribers, w.Resync.Synced, len(w.Resync.Failed), affected, synced)
	}
	return nil
}

func (c *sqCtx) changedIs(v string) error {
	var w sqWrite
	if err := json.Unmarshal(c.lastBody, &w); err != nil {
		return fmt.Errorf("decode write response: %w (%s)", err, c.lastBody)
	}
	if w.Changed != (v == "true") {
		return fmt.Errorf("changed=%v, want %s", w.Changed, v)
	}
	return nil
}

func (c *sqCtx) smDataAmbr(slice, dnn, ul, dl string) error {
	sst, sd, err := parseSlice(slice)
	if err != nil {
		return err
	}
	var subs []store.SessionManagementSubscriptionData
	if err := json.Unmarshal(c.lastBody, &subs); err != nil {
		return fmt.Errorf("decode sm-data: %w (%s)", err, c.lastBody)
	}
	for _, s := range subs {
		if s.SingleNSSAI.SST == sst && s.SingleNSSAI.SD == sd {
			cfg, ok := s.DNNConfigurations[dnn]
			if !ok {
				return fmt.Errorf("slice %s has no dnnConfigurations %q: %s", slice, dnn, c.lastBody)
			}
			if cfg.SessionAMBR.Uplink != ul || cfg.SessionAMBR.Downlink != dl {
				return fmt.Errorf("sm-data sessionAmbr %q/%q, want %q/%q", cfg.SessionAMBR.Uplink, cfg.SessionAMBR.Downlink, ul, dl)
			}
			return nil
		}
	}
	return fmt.Errorf("slice %s not in sm-data: %s", slice, c.lastBody)
}

func (c *sqCtx) problemCause(cause string) error {
	var p sqProblem
	if err := json.Unmarshal(c.lastBody, &p); err != nil {
		return fmt.Errorf("decode ProblemDetails: %w (%s)", err, c.lastBody)
	}
	if p.Cause != cause {
		return fmt.Errorf("problem cause %q, want %q (%s)", p.Cause, cause, c.lastBody)
	}
	return nil
}

func (c *sqCtx) problemNames(param string) error {
	var p sqProblem
	if err := json.Unmarshal(c.lastBody, &p); err != nil {
		return fmt.Errorf("decode ProblemDetails: %w (%s)", err, c.lastBody)
	}
	for _, ip := range p.InvalidParams {
		if ip.Param == param {
			return nil
		}
	}
	return fmt.Errorf("invalidParams does not name %q: %s", param, c.lastBody)
}

// fetch GETs key without touching the last response.
func (c *sqCtx) fetch(key string) (*sqItem, error) {
	code, b, err := c.do(http.MethodGet, sqBase+"/"+key, "")
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("GET %s: status %d (%s)", key, code, b)
	}
	return decodeItem(b)
}

func (c *sqCtx) stillSource(key, src string) error {
	it, err := c.fetch(key)
	if err != nil {
		return err
	}
	if it.Source != src {
		return fmt.Errorf("%s source %q, want %q", key, it.Source, src)
	}
	return nil
}

func (c *sqCtx) rowHas(key, src, ul, dl string) error {
	it, err := c.fetch(key)
	if err != nil {
		return err
	}
	if it.Source != src || it.SessionAmbr.Uplink != ul || it.SessionAmbr.Downlink != dl {
		return fmt.Errorf("%s: source %q AMBR %q/%q, want %q %q/%q", key, it.Source, it.SessionAmbr.Uplink, it.SessionAmbr.Downlink, src, ul, dl)
	}
	return nil
}

func (c *sqCtx) rowHasDefault(key, ul, dl, src string) error {
	it, err := c.fetch(key)
	if err != nil {
		return err
	}
	if it.DefaultSessionAmbr.Uplink != ul || it.DefaultSessionAmbr.Downlink != dl || it.DefaultSource != src {
		return fmt.Errorf("%s: default %q/%q source %q, want %q/%q source %q", key,
			it.DefaultSessionAmbr.Uplink, it.DefaultSessionAmbr.Downlink, it.DefaultSource, ul, dl, src)
	}
	return nil
}

func (c *sqCtx) resyncTriggered(slice, dnn string, want bool) error {
	sst, sd, err := parseSlice(slice)
	if err != nil {
		return err
	}
	if c.lastSeed == nil {
		return fmt.Errorf("no seed run recorded")
	}
	k := store.NewSliceKey(sst, sd, dnn)
	got := false
	for _, ck := range c.lastSeed.ChangedKeys {
		if ck == k {
			got = true
		}
	}
	if got != want {
		return fmt.Errorf("resync triggered for %s = %v, want %v (changed keys: %v)", k, got, want, c.lastSeed.ChangedKeys)
	}
	return nil
}

func (c *sqCtx) resyncYes(slice, dnn string) error { return c.resyncTriggered(slice, dnn, true) }
func (c *sqCtx) resyncNo(slice, dnn string) error  { return c.resyncTriggered(slice, dnn, false) }

func initializeSliceQoSScenario(ctx *godog.ScenarioContext) {
	c := &sqCtx{}
	ctx.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		c.stop()
		return ctx, nil
	})

	ctx.Step(`^a clean UDR instance is running$`, c.cleanUDR)
	ctx.Step(`^the slice/DNN QoS table is seeded with defaults for slices "([^"]*)" and "([^"]*)" on dnn "([^"]*)"$`, c.seeded)
	ctx.Step(`^the seeded default Session-AMBR for slice "([^"]*)" dnn "([^"]*)" is "([^"]*)" uplink and "([^"]*)" downlink$`, c.seededDefaultIs)
	ctx.Step(`^subscriber "([^"]*)" is provisioned on slice "([^"]*)" dnn "([^"]*)"$`, c.subscriberProvisioned)
	ctx.Step(`^slice-dnn-qos "([^"]*)" was edited to Session-AMBR uplink "([^"]*)" downlink "([^"]*)"$`, c.wasEdited)

	ctx.Step(`^the operator GETs the slice-dnn-qos list$`, c.list)
	ctx.Step(`^the operator GETs slice-dnn-qos "([^"]*)"$`, c.get)
	ctx.Step(`^the operator DELETEs slice-dnn-qos "([^"]*)"$`, c.del)
	ctx.Step(`^the operator PUTs slice-dnn-qos "([^"]*)" with Session-AMBR uplink "([^"]*)" downlink "([^"]*)"$`, c.put)
	ctx.Step(`^the operator PUTs slice-dnn-qos "([^"]*)" with raw body '(.*)'$`, c.putRaw)
	ctx.Step(`^the UDM GETs sm-data of "([^"]*)" for PLMN "([^"]*)"$`, c.udmGetsSMData)
	ctx.Step(`^the UDR is restarted and re-seeded with the default slice set$`, c.restartDefault)
	ctx.Step(`^the UDR is restarted and re-seeded with operator entry slice "([^"]*)" dnn "([^"]*)" Session-AMBR "([^"]*)" / "([^"]*)"$`, c.restartOperator)

	ctx.Step(`^the slice-qos response status is (\d+)$`, c.statusIs)
	ctx.Step(`^the slice-qos list contains slice "([^"]*)" dnn "([^"]*)" with Session-AMBR "([^"]*)" / "([^"]*)" and source "([^"]*)"$`, c.listContainsFull)
	ctx.Step(`^the slice-qos list contains slice "([^"]*)" dnn "([^"]*)" with source "([^"]*)"$`, c.listContainsSource)
	ctx.Step(`^the slice-qos list is sorted by sst, sd, dnn$`, c.listSorted)
	ctx.Step(`^the slice-qos item has source "([^"]*)" and Session-AMBR "([^"]*)" / "([^"]*)"$`, c.itemHas)
	ctx.Step(`^the slice-qos item keeps default Session-AMBR "([^"]*)" / "([^"]*)"$`, c.itemKeepsDefault)
	ctx.Step(`^the slice-qos item has sst (\d+) and no sd$`, c.itemSstNoSD)
	ctx.Step(`^the slice-qos resync reports affectedSubscribers (\d+) and synced (\d+) and no failures$`, c.resyncReports)
	ctx.Step(`^the slice-qos response reports changed (true|false)$`, c.changedIs)
	ctx.Step(`^the sm-data for slice "([^"]*)" has dnnConfigurations "([^"]*)" sessionAmbr "([^"]*)" / "([^"]*)"$`, c.smDataAmbr)
	ctx.Step(`^the slice-qos problem cause is "([^"]*)"$`, c.problemCause)
	ctx.Step(`^the slice-qos problem names invalid parameter "([^"]*)"$`, c.problemNames)
	ctx.Step(`^the slice-dnn-qos "([^"]*)" still has source "([^"]*)"$`, c.stillSource)
	ctx.Step(`^the slice-dnn-qos "([^"]*)" still has source "([^"]*)" and Session-AMBR "([^"]*)" / "([^"]*)"$`, c.rowHas)
	ctx.Step(`^the slice-dnn-qos "([^"]*)" has source "([^"]*)" and Session-AMBR "([^"]*)" / "([^"]*)"$`, c.rowHas)
	ctx.Step(`^the slice-dnn-qos "([^"]*)" has default Session-AMBR "([^"]*)" / "([^"]*)" with default source "([^"]*)"$`, c.rowHasDefault)
	ctx.Step(`^a sm-data resync is triggered for slice "([^"]*)" dnn "([^"]*)"$`, c.resyncYes)
	ctx.Step(`^no sm-data resync is triggered for slice "([^"]*)" dnn "([^"]*)"$`, c.resyncNo)
}

func TestSliceSessionAmbrFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: initializeSliceQoSScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"slice_session_ambr.feature"},
			Strict:   true,
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
