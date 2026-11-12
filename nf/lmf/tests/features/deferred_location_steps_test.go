//go:build functional

// Package features_test - godog step definitions for the LMF deferred location
// feature (deferred_location.feature): periodic / area-event activation with
// DetermineLocation, EventNotify callbacks to the GMLC hgmlcCallBackURI, and
// CancelLocation (REL19-3.5).
//
// Architecture: each scenario builds an in-process LMF (NewWithNotifClient)
// whose notification client is the production HTTPNotificationClient pointed
// at an httptest TLS receiver standing in for the GMLC. The receiver URL is
// https, as the LMF requires. All waits poll with a deadline.
//
// Ref: TS 29.572 §5.2.2.2.2, §5.2.2.4.2, callback EventNotify; TS 23.273 §6.3.
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
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/cucumber/godog"

	lmfcfg "github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	lmfsrv "github.com/francurieses/claudia-5gc/nf/lmf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

// cellSequenceAMF reports the configured NR cells in order, repeating the last
// one. Call 1 is the activation fix. Safe for concurrent use.
type cellSequenceAMF struct {
	mu    sync.Mutex
	cells []string
	calls int
}

// ProvideLocationInfo implements lmfsrv.AMFLocationClient.
func (a *cellSequenceAMF) ProvideLocationInfo(_ context.Context, _ string) (*lmfsrv.LocationData, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cells) == 0 {
		return nil, "LOCATION_FAILURE", fmt.Errorf("cellSequenceAMF: no cell configured")
	}
	i := a.calls
	if i >= len(a.cells) {
		i = len(a.cells) - 1
	}
	a.calls++
	return &lmfsrv.LocationData{
		LocationEstimate: &lmfsrv.GeographicArea{Shape: "POINT", Point: &lmfsrv.LatLon{Lat: 40.4168, Lon: -3.7038}},
		NRCellId:         a.cells[i],
		Tai:              &lmfsrv.TaiLoc{PlmnId: lmfsrv.PlmnID{MCC: "001", MNC: "01"}, Tac: "0001"},
	}, "", nil
}

// gmlcReceiver is the TLS httptest server acting as the GMLC EventNotify endpoint.
type gmlcReceiver struct {
	ts     *httptest.Server
	mu     sync.Mutex
	events []lmfsrv.EventNotifyData
}

func newGMLCReceiver() *gmlcReceiver {
	r := &gmlcReceiver{}
	r.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var n lmfsrv.EventNotifyData
		if err := json.NewDecoder(req.Body).Decode(&n); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.events = append(r.events, n)
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	return r
}

func (r *gmlcReceiver) uri() string { return r.ts.URL + "/notify" }

func (r *gmlcReceiver) snapshot() []lmfsrv.EventNotifyData {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]lmfsrv.EventNotifyData(nil), r.events...)
}

// deferredWorld is the per-scenario state of the deferred-location feature.
type deferredWorld struct {
	recv    *gmlcReceiver
	srv     *lmfsrv.Server
	ts      *httptest.Server
	amf     *cellSequenceAMF
	profile string
	capS    int
	body    map[string]any
}

// deferredPoll polls cond every 20 ms until it holds or the deadline passes.
func deferredPoll(deadline time.Duration, cond func() bool) bool {
	end := time.Now().Add(deadline)
	for {
		if cond() {
			return true
		}
		if time.Now().After(end) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (w *deferredWorld) reset() {
	w.teardown()
	w.amf = &cellSequenceAMF{}
	w.profile = ""
	w.capS = 3600
	w.body = nil
}

func (w *deferredWorld) teardown() {
	if w.ts != nil {
		w.ts.Close()
		w.ts = nil
	}
	if w.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = w.srv.Shutdown(ctx)
		cancel()
		w.srv = nil
	}
	if w.recv != nil {
		w.recv.ts.Close()
		w.recv = nil
	}
}

// build starts the in-process LMF with the configured profile, cap and AMF.
func (w *deferredWorld) build() error {
	if w.srv != nil {
		return nil
	}
	if w.recv == nil {
		return fmt.Errorf("the GMLC callback receiver was not started (missing Background step)")
	}
	cfg := &lmfcfg.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.DefaultCoord = lmfcfg.CellCoord{Lat: 40.4168, Lon: -3.7038}
	cfg.LocationSubscription = lmfcfg.LocationSubscriptionConfig{
		DefaultSamplingIntervalS: 1, DefaultReportingIntervalS: 1, MaxDurationS: w.capS, NotificationRetry: 0,
	}
	nc := &lmfsrv.HTTPNotificationClient{Client: w.recv.ts.Client()}
	w.srv = lmfsrv.NewWithNotifClient(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), w.amf, nil, nc)
	if w.profile != "" {
		p, err := capability.NewProfile(capability.ReleaseConfig{Profile: w.profile}, func(string) string { return "" })
		if err != nil {
			return fmt.Errorf("release profile %q: %w", w.profile, err)
		}
		w.srv.SetProfile(p)
	}
	w.ts = httptest.NewServer(w.srv.Handler())
	return nil
}

// post sends a JSON body to the LMF and bridges the response into the shared lmfCtx.
func (w *deferredWorld) post(c *lmfCtx, path string, body any) error {
	if err := w.build(); err != nil {
		return err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	resp, err := w.ts.Client().Post(w.ts.URL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	c.lastResp = resp
	c.lastRawBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	c.lastBody = nil
	w.body = nil
	if len(c.lastRawBody) > 0 {
		var m map[string]any
		if json.Unmarshal(c.lastRawBody, &m) == nil {
			c.lastBody = m
			w.body = m
		}
	}
	return nil
}

var (
	reAmount   = regexp.MustCompile(`reportingAmount (\d+)`)
	reIntMs    = regexp.MustCompile(`reportingIntervalMs (\d+)`)
	reInfinite = regexp.MustCompile(`infinite reporting`)
	reCell     = regexp.MustCompile(`an area of NR cell "([^"]+)"`)
	reSampling = regexp.MustCompile(`sampled every (\d+) second`)
	reDuration = regexp.MustCompile(`reportingDuration (\d+) second`)
	reURI      = regexp.MustCompile(`hgmlcCallBackURI "([^"]+)"`)
)

func atoiMatch(re *regexp.Regexp, s string) (int, bool) {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.Atoi(m[1])
	return n, true
}

// determineBody builds the DetermineLocation InputData from the step arguments.
func (w *deferredWorld) determineBody(supi, ldrType, ldr, tail string) map[string]any {
	uri := w.recv.uri()
	if m := reURI.FindStringSubmatch(tail); m != nil {
		uri = m[1]
	}
	b := map[string]any{
		"supi": supi, "ldrType": ldrType, "ldrReference": ldr, "hgmlcCallBackURI": uri,
	}
	amount, hasAmount := atoiMatch(reAmount, tail)
	ms, hasMs := atoiMatch(reIntMs, tail)
	infinite := reInfinite.MatchString(tail)
	if hasAmount || hasMs || infinite {
		if !hasAmount {
			amount = 1
		}
		p := map[string]any{"reportingAmount": amount, "reportingInterval": 1}
		if hasMs {
			p["reportingIntervalMs"] = ms
		}
		if infinite {
			p["reportingInfiniteInd"] = true
		}
		b["periodicEventInfo"] = p
	}
	if m := reCell.FindStringSubmatch(tail); m != nil {
		a := map[string]any{"areaDefinition": []any{map[string]any{
			"areaType": "NR_CELL_GLOBAL_IDENTITY",
			"ncgi":     map[string]any{"plmnId": map[string]any{"mcc": "001", "mnc": "01"}, "nrCellId": m[1]},
		}}}
		if n, ok := atoiMatch(reSampling, tail); ok {
			a["samplingInterval"] = n
		}
		if n, ok := atoiMatch(reDuration, tail); ok {
			a["reportingDuration"] = n
		}
		b["areaEventInfo"] = a
	}
	return b
}

func (w *deferredWorld) locationExt() (map[string]any, error) {
	if w.body == nil {
		return nil, fmt.Errorf("no JSON response body")
	}
	return w.body, nil
}

// initDeferredLocationSteps registers the deferred-location steps; c is the
// shared lmfCtx so the common HTTP status / ProblemDetails steps see our responses.
func initDeferredLocationSteps(sc *godog.ScenarioContext, c *lmfCtx) {
	w := &deferredWorld{}

	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.teardown()
		return ctx, nil
	})

	// Background.
	sc.Step(`^the 5GC is running with an LMF and a mock AMF for Namf_Location ProvideLocationInfo$`,
		func() error { return nil })
	sc.Step(`^a GMLC callback receiver is listening on an https hgmlcCallBackURI$`, func() error {
		w.recv = newGMLCReceiver()
		return nil
	})

	// Given.
	sc.Step(`^the LMF runs the "([^"]+)" release profile$`, func(p string) error {
		w.profile = p
		return nil
	})
	sc.Step(`^the LMF caps deferred location sessions at (\d+) seconds?$`, func(n int) error {
		w.capS = n
		return nil
	})
	sc.Step(`^the UE is reported in NR cell "([^"]+)"$`, func(cell string) error {
		w.amf.cells = []string{cell}
		return nil
	})
	sc.Step(`^the UE is reported in NR cell "([^"]+)" and then in NR cell "([^"]+)"$`, func(a, b string) error {
		w.amf.cells = []string{a, b}
		return nil
	})
	sc.Step(`^the GMLC has activated an infinite periodic location with ldrReference "([^"]+)" and reportingIntervalMs (\d+)$`,
		func(ldr string, ms int) error {
			if w.recv == nil {
				return fmt.Errorf("receiver not started")
			}
			body := w.determineBody("imsi-001010000000001", "PERIODIC", ldr,
				fmt.Sprintf("infinite reporting and reportingIntervalMs %d", ms))
			if err := w.post(c, "/nlmf-loc/v1/determine-location", body); err != nil {
				return err
			}
			if c.lastResp.StatusCode != http.StatusOK {
				return fmt.Errorf("activation: status %d, want 200 (body %s)", c.lastResp.StatusCode, c.lastRawBody)
			}
			return nil
		})
	sc.Step(`^the callback receiver has received at least 1 EventNotify$`, func() error {
		if !deferredPoll(8*time.Second, func() bool { return len(w.recv.snapshot()) >= 1 }) {
			return fmt.Errorf("no EventNotify within 8 s")
		}
		return nil
	})

	// When.
	sc.Step(`^the GMLC sends a DetermineLocation for "([^"]+)" with ldrType "([^"]+)", ldrReference "([^"]+)"(?:,| and) (.+)$`,
		func(supi, ldrType, ldr, tail string) error {
			if w.recv == nil {
				return fmt.Errorf("receiver not started")
			}
			return w.post(c, "/nlmf-loc/v1/determine-location", w.determineBody(supi, ldrType, ldr, tail))
		})
	sc.Step(`^the GMLC sends a CancelLocation with the hgmlcCallBackURI and ldrReference "([^"]+)"$`,
		func(ldr string) error {
			if w.recv == nil {
				return fmt.Errorf("receiver not started")
			}
			return w.post(c, "/nlmf-loc/v1/cancel-location",
				map[string]any{"hgmlcCallBackURI": w.recv.uri(), "ldrReference": ldr})
		})

	// Then - LocationDataExt.
	sc.Step(`^the LocationDataExt carries a locationEstimate and a timestampOfLocationEstimate$`, func() error {
		m, err := w.locationExt()
		if err != nil {
			return err
		}
		if m["locationEstimate"] == nil {
			return fmt.Errorf("locationEstimate missing: %s", c.lastRawBody)
		}
		ts, _ := m["timestampOfLocationEstimate"].(string)
		if _, perr := time.Parse(time.RFC3339, ts); perr != nil {
			return fmt.Errorf("timestampOfLocationEstimate %q is not date-time: %v", ts, perr)
		}
		return nil
	})
	sc.Step(`^the LocationDataExt carries a locationEstimate and no timestampOfLocationEstimate$`, func() error {
		m, err := w.locationExt()
		if err != nil {
			return err
		}
		if m["locationEstimate"] == nil {
			return fmt.Errorf("locationEstimate missing: %s", c.lastRawBody)
		}
		if _, ok := m["timestampOfLocationEstimate"]; ok {
			return fmt.Errorf("immediate LocationData must not carry timestampOfLocationEstimate: %s", c.lastRawBody)
		}
		if _, ok := m["acceptedPeriodicEventInfo"]; ok {
			return fmt.Errorf("immediate LocationData must not carry acceptedPeriodicEventInfo: %s", c.lastRawBody)
		}
		return nil
	})
	sc.Step(`^the LocationDataExt acceptedPeriodicEventInfo has reportingIntervalMs (\d+)$`, func(want int) error {
		m, err := w.locationExt()
		if err != nil {
			return err
		}
		acc, _ := m["acceptedPeriodicEventInfo"].(map[string]any)
		if acc == nil || acc["reportingIntervalMs"] != float64(want) {
			return fmt.Errorf("acceptedPeriodicEventInfo.reportingIntervalMs want %d: %s", want, c.lastRawBody)
		}
		return nil
	})
	sc.Step(`^the LocationDataExt acceptedPeriodicEventInfo has reportingInfiniteInd true$`, func() error {
		m, err := w.locationExt()
		if err != nil {
			return err
		}
		acc, _ := m["acceptedPeriodicEventInfo"].(map[string]any)
		if acc == nil || acc["reportingInfiniteInd"] != true {
			return fmt.Errorf("acceptedPeriodicEventInfo.reportingInfiniteInd want true: %s", c.lastRawBody)
		}
		return nil
	})

	// Then - EventNotify callbacks.
	sc.Step(`^the callback receiver gets (\d+) EventNotify callbacks within (\d+) seconds$`, func(n, secs int) error {
		if !deferredPoll(time.Duration(secs)*time.Second, func() bool { return len(w.recv.snapshot()) >= n }) {
			return fmt.Errorf("got %d EventNotify callbacks within %d s, want %d", len(w.recv.snapshot()), secs, n)
		}
		if got := len(w.recv.snapshot()); got != n {
			return fmt.Errorf("got %d EventNotify callbacks, want exactly %d", got, n)
		}
		return nil
	})
	sc.Step(`^the callback receiver gets at least (\d+) EventNotify callbacks within (\d+) seconds$`, func(n, secs int) error {
		if !deferredPoll(time.Duration(secs)*time.Second, func() bool { return len(w.recv.snapshot()) >= n }) {
			return fmt.Errorf("got %d EventNotify callbacks within %d s, want >= %d", len(w.recv.snapshot()), secs, n)
		}
		return nil
	})
	sc.Step(`^the callback receiver gets an EventNotify with reportedEventType "([^"]+)" within (\d+) seconds$`,
		func(typ string, secs int) error {
			found := func() bool {
				for _, e := range w.recv.snapshot() {
					if e.ReportedEventType == typ {
						return true
					}
				}
				return false
			}
			if !deferredPoll(time.Duration(secs)*time.Second, found) {
				return fmt.Errorf("no EventNotify %q within %d s (got %+v)", typ, secs, w.recv.snapshot())
			}
			return nil
		})
	sc.Step(`^every EventNotify has ldrReference "([^"]+)" and reportedEventType "([^"]+)"$`, func(ldr, typ string) error {
		for i, e := range w.recv.snapshot() {
			if e.LdrReference != ldr || e.ReportedEventType != typ {
				return fmt.Errorf("EventNotify %d = %+v, want ldrReference %q reportedEventType %q", i+1, e, ldr, typ)
			}
			if e.LocationEstimate == nil || e.TimestampOfLocationEstimate == "" {
				return fmt.Errorf("EventNotify %d lacks locationEstimate / timestampOfLocationEstimate: %+v", i+1, e)
			}
		}
		return nil
	})
	sc.Step(`^only the last EventNotify carries terminationCause "([^"]+)"$`, func(cause string) error {
		ev := w.recv.snapshot()
		for i, e := range ev {
			want := ""
			if i == len(ev)-1 {
				want = cause
			}
			if e.TerminationCause != want {
				return fmt.Errorf("EventNotify %d terminationCause = %q, want %q", i+1, e.TerminationCause, want)
			}
		}
		return nil
	})
	sc.Step(`^the first EventNotify has reportedEventType "([^"]+)" and ldrReference "([^"]+)"$`, func(typ, ldr string) error {
		ev := w.recv.snapshot()
		if len(ev) == 0 {
			return fmt.Errorf("no EventNotify received")
		}
		if ev[0].ReportedEventType != typ || ev[0].LdrReference != ldr {
			return fmt.Errorf("first EventNotify = %+v, want %q / ldrReference %q", ev[0], typ, ldr)
		}
		return nil
	})
	sc.Step(`^the last EventNotify has reportedEventType "([^"]+)" and terminationCause "([^"]+)"$`, func(typ, cause string) error {
		last := func() bool {
			ev := w.recv.snapshot()
			return len(ev) > 0 && ev[len(ev)-1].ReportedEventType == typ
		}
		if !deferredPoll(8*time.Second, last) {
			return fmt.Errorf("last EventNotify is not %q: %+v", typ, w.recv.snapshot())
		}
		ev := w.recv.snapshot()
		if got := ev[len(ev)-1].TerminationCause; got != cause {
			return fmt.Errorf("last EventNotify terminationCause = %q, want %q", got, cause)
		}
		return nil
	})
	// Absence after a cancel: wait until the callback stream is quiet for a
	// window longer than several report intervals, then require that the
	// LMF never sent a LOCATION_CANCELLATION_EVENT (GMLC-initiated release is silent).
	sc.Step(`^the callback receiver gets no EventNotify after the cancel$`, func() error {
		const quiet = 700 * time.Millisecond
		lastN, since := len(w.recv.snapshot()), time.Now()
		ok := deferredPoll(6*time.Second, func() bool {
			if n := len(w.recv.snapshot()); n != lastN {
				lastN, since = n, time.Now()
			}
			return time.Since(since) >= quiet
		})
		if !ok {
			return fmt.Errorf("EventNotify callbacks keep arriving after CancelLocation (%d so far)", lastN)
		}
		for _, e := range w.recv.snapshot() {
			if e.ReportedEventType == "LOCATION_CANCELLATION_EVENT" || e.TerminationCause != "" {
				return fmt.Errorf("GMLC-initiated cancel produced a termination EventNotify: %+v", e)
			}
		}
		return nil
	})
	// Absence of any callback over a bounded observation window.
	sc.Step(`^the callback receiver gets no EventNotify within the observation window$`, func() error {
		if deferredPoll(1200*time.Millisecond, func() bool { return len(w.recv.snapshot()) > 0 }) {
			return fmt.Errorf("unexpected EventNotify: %+v", w.recv.snapshot())
		}
		return nil
	})
	sc.Step(`^the problem invalidParams names "([^"]+)"$`, func(param string) error {
		if w.body == nil {
			return fmt.Errorf("no JSON response body")
		}
		list, _ := w.body["invalidParams"].([]any)
		for _, it := range list {
			if m, ok := it.(map[string]any); ok && m["param"] == param {
				return nil
			}
		}
		return fmt.Errorf("invalidParams does not name %q: %s", param, c.lastRawBody)
	})
}
