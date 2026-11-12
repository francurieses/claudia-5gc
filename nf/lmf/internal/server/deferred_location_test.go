package server

// deferred_location_test.go - TS 29.572 deferred (periodic / area-event)
// location via DetermineLocation + EventNotify callback + CancelLocation
// (REL19-3.5 slice D). Ref: TS 29.572 §5.2.2.2.2, §5.2.2.4.2.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// testUnit is the shortened "second" of the deferred-location parameters.
const testUnit = 20 * time.Millisecond

// eventSink records EventNotifyData callbacks (an EventNotifier test double).
type eventSink struct {
	mu    sync.Mutex
	got   []EventNotifyData
	uris  []string
	times []time.Time
}

func newEventSink() *eventSink { return &eventSink{} }

func (e *eventSink) PostNotification(context.Context, string, LocationNotification) error {
	return nil
}

func (e *eventSink) PostEventNotify(_ context.Context, uri string, n EventNotifyData) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.got = append(e.got, n)
	e.uris = append(e.uris, uri)
	e.times = append(e.times, time.Now())
	return nil
}

// eventually polls cond until it holds or a deadline passes.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// wait blocks for the n-th notification (1-based) or fails.
func (e *eventSink) wait(t *testing.T, n int) EventNotifyData {
	t.Helper()
	eventually(t, fmt.Sprintf("notification %d", n), func() bool { return e.count() >= n })
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.got[n-1]
}

func (e *eventSink) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.got)
}

func newDeferredLMF(t *testing.T, p *capability.Profile, amf AMFLocationClient, sink NotificationClient) (*httptest.Server, *Server) {
	return newDeferredLMFCap(t, p, amf, sink, 3600)
}

// newDeferredLMFCap is newDeferredLMF with an explicit LMF max duration (in
// shortened seconds).
func newDeferredLMFCap(t *testing.T, p *capability.Profile, amf AMFLocationClient, sink NotificationClient, maxDurS int) (*httptest.Server, *Server) {
	t.Helper()
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.LocationSubscription = config.LocationSubscriptionConfig{
		DefaultSamplingIntervalS: 1, DefaultReportingIntervalS: 1, MaxDurationS: maxDurS, NotificationRetry: 0,
	}
	srv := NewWithNotifClient(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), amf, nil, sink)
	srv.SetProfile(p)
	srv.timeUnit = testUnit
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		srv.registry.cancelAll()
		ts.Close()
		srv.drainBG(context.Background())
	})
	return ts, srv
}

func post(t *testing.T, ts *httptest.Server, path, body string) (*http.Response, string) {
	t.Helper()
	resp, err := ts.Client().Post(ts.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

const (
	cbURI = "https://gmlc.example.test/notify"
	ldr   = "0a1b2c"
	detLM = "/nlmf-loc/v1/determine-location"
	canLM = "/nlmf-loc/v1/cancel-location"
)

func periodicBody(amount int, infinite bool) string {
	return periodicBodyI(amount, 1, infinite)
}

func periodicBodyI(amount, interval int, infinite bool) string {
	inf := ""
	if infinite {
		inf = `,"reportingInfiniteInd":true`
	}
	return `{"supi":"imsi-001010000000001","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr +
		`","periodicEventInfo":{"reportingAmount":` + itoa(amount) + `,"reportingInterval":` + itoa(interval) + inf + `}}`
}

func itoa(n int) string { return strconv.Itoa(n) }

func cancelBody(uri, l string) string {
	return `{"hgmlcCallBackURI":"` + uri + `","ldrReference":"` + l + `"}`
}

func areaBody(ldrType, extra string) string {
	lt := ""
	if ldrType != "" {
		lt = `"ldrType":"` + ldrType + `",`
	}
	return `{"gpsi":"msisdn-34600000001",` + lt + `"hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr + `",` +
		`"areaEventInfo":{"areaDefinition":[{"areaType":"NR_CELL_GLOBAL_IDENTITY",` +
		`"ncgi":{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000010"}}],"samplingInterval":1` + extra + `}}`
}

// cellSeq returns an AMF double that reports the given cells in order (the
// last one repeats); call 1 is the activation fix.
func cellSeq(cells ...string) *mockAMFClient {
	var mu sync.Mutex
	calls := 0
	return &mockAMFClient{ProvideFunc: func(context.Context, string) (*LocationData, string, error) {
		mu.Lock()
		defer mu.Unlock()
		i := calls
		if i >= len(cells) {
			i = len(cells) - 1
		}
		calls++
		return &LocationData{
			LocationEstimate: &GeographicArea{Shape: "POINT", Point: &LatLon{Lat: 40.4, Lon: -3.7}},
			NRCellId:         cells[i],
		}, "", nil
	}}
}

func decodeMap(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("not JSON: %s", raw)
	}
	return m
}

func TestDeferredPeriodic_Rel19_ActivatesNotifiesAndEnds(t *testing.T) {
	sink := newEventSink()
	ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), sink)

	resp, body := post(t, ts, detLM, periodicBody(2, false))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	m := decodeMap(t, body)
	if m["locationEstimate"] == nil || m["timestampOfLocationEstimate"] == nil {
		t.Fatalf("LocationDataExt must carry the activation fix: %s", body)
	}
	if _, ok := m["acceptedPeriodicEventInfo"]; ok {
		t.Fatalf("acceptedPeriodicEventInfo only with infinite/ms: %s", body)
	}
	if srv.registry.countDeferred() != 1 {
		t.Fatalf("session not registered")
	}
	n1 := sink.wait(t, 1)
	if n1.ReportedEventType != reportedPeriodicEvent || n1.LdrReference != ldr ||
		n1.HgmlcCallBackURI != cbURI || n1.Supi != "imsi-001010000000001" ||
		n1.LocationEstimate == nil || n1.AgeOfLocationEstimate == nil || n1.TerminationCause != "" {
		t.Fatalf("unexpected first notification: %+v", n1)
	}
	if _, err := time.Parse(time.RFC3339, n1.TimestampOfLocationEstimate); err != nil {
		t.Fatalf("timestampOfLocationEstimate: %v", err)
	}
	n2 := sink.wait(t, 2)
	if n2.TerminationCause != terminationNormal {
		t.Fatalf("last report must carry terminationCause: %+v", n2)
	}
	if sink.uris[0] != cbURI {
		t.Fatalf("callback uri = %q", sink.uris[0])
	}
	eventually(t, "session removal", func() bool { return srv.registry.countDeferred() == 0 })
}

func TestDeferredPeriodic_Rel19_AcceptedInfoAndMilliseconds(t *testing.T) {
	sink := newEventSink()
	ts, _ := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), sink)
	// reportingIntervalMs wins over reportingInterval (1 unit = 20 ms).
	body := `{"supi":"imsi-001010000000001","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr +
		`","periodicEventInfo":{"reportingAmount":3,"reportingInterval":1,"reportingIntervalMs":200}}`
	resp, raw := post(t, ts, detLM, body)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
	acc, _ := decodeMap(t, raw)["acceptedPeriodicEventInfo"].(map[string]any)
	if acc == nil || acc["reportingIntervalMs"] != float64(200) {
		t.Fatalf("acceptedPeriodicEventInfo missing: %s", raw)
	}
	sink.wait(t, 2)
	sink.mu.Lock()
	gap := sink.times[1].Sub(sink.times[0])
	sink.mu.Unlock()
	if gap < 150*time.Millisecond {
		t.Fatalf("interval %v: reportingInterval was not ignored in favour of reportingIntervalMs", gap)
	}

	// Infinite indication is echoed too.
	ts2, _ := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), newEventSink())
	_, raw = post(t, ts2, detLM, periodicBody(8639999, true))
	acc, _ = decodeMap(t, raw)["acceptedPeriodicEventInfo"].(map[string]any)
	if acc == nil || acc["reportingInfiniteInd"] != true {
		t.Fatalf("accepted infinite ind missing: %s", raw)
	}
}

func TestDeferredCreate_Rel19_FixFailureCreatesNoSession(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
	}{
		"ue not found": {ErrUEContextNotFound, http.StatusNotFound},
		"amf failure":  {errors.New("boom"), http.StatusGatewayTimeout},
	} {
		t.Run(name, func(t *testing.T) {
			amf := &mockAMFClient{ProvideFunc: func(context.Context, string) (*LocationData, string, error) {
				return nil, "CAUSE", c.err
			}}
			ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), amf, newEventSink())
			resp, raw := post(t, ts, detLM, periodicBody(2, false))
			if resp.StatusCode != c.status {
				t.Fatalf("%d %s", resp.StatusCode, raw)
			}
			if srv.registry.count() != 0 {
				t.Fatalf("no session may exist after a failed activation fix")
			}
		})
	}
}

func TestDeferredCancel_Rel19_SilentAndUnknown403(t *testing.T) {
	sink := newEventSink()
	ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), sink)
	// Long interval: no report is due while the test runs.
	if resp, body := post(t, ts, detLM, periodicBodyI(5, 100000, false)); resp.StatusCode != 200 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	// lcsCorrelationID present: URI / ldrReference ignored, session untouched.
	resp, body := post(t, ts, canLM, `{"lcsCorrelationID":"abc","hgmlcCallBackURI":"`+cbURI+`","ldrReference":"ffff"}`)
	if resp.StatusCode != http.StatusNoContent || srv.registry.countDeferred() != 1 {
		t.Fatalf("lcsCorrelationID cancel: %d %s", resp.StatusCode, body)
	}
	resp, body = post(t, ts, canLM, cancelBody(cbURI, ldr))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("cancel: %d %s", resp.StatusCode, body)
	}
	if srv.registry.countDeferred() != 0 {
		t.Fatalf("session must be removed")
	}
	time.Sleep(3 * testUnit) // absence check: no EventNotify on a GMLC-initiated cancel
	if sink.count() != 0 {
		t.Fatalf("cancel must not send EventNotify: %+v", sink.got)
	}
	// Unknown session: 403 LOCATION_SESSION_UNKNOWN.
	resp, body = post(t, ts, canLM, cancelBody(cbURI, ldr))
	if resp.StatusCode != http.StatusForbidden || decodeMap(t, body)["cause"] != "LOCATION_SESSION_UNKNOWN" {
		t.Fatalf("second cancel: %d %s", resp.StatusCode, body)
	}
}

func TestDeferredCancel_Rel19_Validation(t *testing.T) {
	ts, _ := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), newEventSink())
	for name, body := range map[string]string{
		"missing ldr": `{"hgmlcCallBackURI":"` + cbURI + `"}`,
		"missing uri": `{"ldrReference":"` + ldr + `"}`,
		"bad ldr":     cancelBody(cbURI, "xyz"),
		"http uri":    cancelBody("http://gmlc.example.test/n", ldr),
	} {
		resp, raw := post(t, ts, canLM, body)
		if resp.StatusCode != 400 || !strings.Contains(raw, "invalidParams") {
			t.Errorf("%s: %d %s", name, resp.StatusCode, raw)
		}
	}
	big := `{"supi":"` + strings.Repeat("a", 2<<20) + `"}`
	if resp, _ := post(t, ts, canLM, big); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized cancel: %d", resp.StatusCode)
	}
	if resp, _ := post(t, ts, canLM, ``); resp.StatusCode != http.StatusNoContent {
		t.Errorf("empty cancel: %d", resp.StatusCode)
	}
}

func TestDeferredCreate_Rel19_Validation(t *testing.T) {
	ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), newEventSink())
	pe := `"periodicEventInfo":{"reportingAmount":1,"reportingInterval":1}`
	hd := `{"supi":"s","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr + `",`
	area := `"areaEventInfo":{"areaDefinition":[{"areaType":"NR_CELL_GLOBAL_IDENTITY"}]`
	cases := map[string]struct{ body, param string }{
		"missing ldr":  {`{"supi":"s","hgmlcCallBackURI":"` + cbURI + `",` + pe + `}`, "/ldrReference"},
		"missing uri":  {`{"supi":"s","ldrReference":"` + ldr + `",` + pe + `}`, "/hgmlcCallBackURI"},
		"relative uri": {`{"supi":"s","hgmlcCallBackURI":"/x","ldrReference":"` + ldr + `",` + pe + `}`, "/hgmlcCallBackURI"},
		"http uri":     {`{"supi":"s","hgmlcCallBackURI":"http://g.example/n","ldrReference":"` + ldr + `",` + pe + `}`, "/hgmlcCallBackURI"},
		"userinfo uri": {`{"supi":"s","hgmlcCallBackURI":"https://u:p@g.example/n","ldrReference":"` + ldr + `",` + pe + `}`, "/hgmlcCallBackURI"},
		"fragment uri": {`{"supi":"s","hgmlcCallBackURI":"https://g.example/n#x","ldrReference":"` + ldr + `",` + pe + `}`, "/hgmlcCallBackURI"},
		"bad ldr":      {`{"supi":"s","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"abc",` + pe + `}`, "/ldrReference"},
		"no interval": {hd + `"periodicEventInfo":{"reportingAmount":1}}`,
			"/periodicEventInfo/reportingInterval"},
		"product too big": {hd + `"periodicEventInfo":{"reportingAmount":3000000,"reportingInterval":3}}`,
			"/periodicEventInfo/reportingAmount"},
		"ms out of range": {hd + `"periodicEventInfo":{"reportingAmount":1,"reportingInterval":1,"reportingIntervalMs":1000}}`,
			"/periodicEventInfo/reportingIntervalMs"},
		"empty area": {hd + `"areaEventInfo":{"areaDefinition":[]}}`, "/areaEventInfo/areaDefinition"},
		"both":       {hd + pe + `,` + area + `}}`, "/areaEventInfo"},
		"PERIODIC with area": {`{"supi":"s","ldrType":"PERIODIC","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr + `",` +
			area + `}}`, "/periodicEventInfo"},
		"PERIODIC without info": {`{"supi":"s","ldrType":"PERIODIC","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr + `"}`,
			"/periodicEventInfo"},
		"area type with periodic": {`{"supi":"s","ldrType":"LEAVING_FROM_AREA","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr + `",` + pe + `}`,
			"/areaEventInfo"},
		"area type without info": {`{"supi":"s","ldrType":"BEING_INSIDE_AREA","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr + `"}`,
			"/areaEventInfo"},
		"UE_AVAILABLE with periodic": {`{"supi":"s","ldrType":"UE_AVAILABLE","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr + `",` + pe + `}`,
			"/ldrType"},
		"one-time with minInterval": {hd + area + `,"occurrenceInfo":"ONE_TIME_EVENT","minimumInterval":5}}`,
			"/areaEventInfo/minimumInterval"},
	}
	for name, c := range cases {
		resp, raw := post(t, ts, detLM, c.body)
		if resp.StatusCode != 400 || !strings.Contains(raw, c.param) || !strings.Contains(raw, "invalidParams") {
			t.Errorf("%s: %d %s", name, resp.StatusCode, raw)
		}
	}
	// Wrong attribute type.
	if resp, _ := post(t, ts, detLM, `{"supi":"s","periodicEventInfo":"x"}`); resp.StatusCode != 400 {
		t.Errorf("type error: %d", resp.StatusCode)
	}
	// Trailing garbage must not turn a deferred request into an immediate one.
	resp, raw := post(t, ts, detLM, periodicBody(1, false)+` garbage`)
	if resp.StatusCode != 400 || decodeMap(t, raw)["cause"] != "INVALID_MSG_FORMAT" {
		t.Errorf("trailing data: %d %s", resp.StatusCode, raw)
	}
	if srv.registry.count() != 0 {
		t.Fatalf("rejected requests must not create sessions")
	}
}

func TestDeferred_Rel19_MotionIsUnsupported(t *testing.T) {
	ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), newEventSink())
	for name, body := range map[string]string{
		"ldrType":    `{"supi":"s","ldrType":"MOTION","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr + `"}`,
		"motionInfo": `{"supi":"s","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr + `","motionEventInfo":{"linearDistance":10}}`,
	} {
		resp, raw := post(t, ts, detLM, body)
		if resp.StatusCode != http.StatusNotImplemented || decodeMap(t, raw)["cause"] != "UNSUPPORTED_EVENT_TYPE" {
			t.Errorf("%s: %d %s", name, resp.StatusCode, raw)
		}
	}
	if srv.registry.count() != 0 {
		t.Fatal("no session expected")
	}
}

// TestDeferredArea_Rel19_LeavingOneTime: activation fix inside cell A, then the
// UE moves to cell B -> LEAVING_AREA_EVENT, ONE_TIME_EVENT ends the session.
func TestDeferredArea_Rel19_LeavingOneTime(t *testing.T) {
	sink := newEventSink()
	ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), cellSeq("000000010", "000000020"), sink)
	if resp, raw := post(t, ts, detLM, areaBody("LEAVING_FROM_AREA", `,"occurrenceInfo":"ONE_TIME_EVENT"`)); resp.StatusCode != 200 {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	n := sink.wait(t, 1)
	if n.ReportedEventType != reportedLeavingAreaEvent || n.LdrReference != ldr ||
		n.Gpsi != "msisdn-34600000001" || n.TerminationCause != terminationNormal {
		t.Fatalf("unexpected: %+v", n)
	}
	eventually(t, "one-time session end", func() bool { return srv.registry.countDeferred() == 0 })
}

// TestDeferredArea_Rel19_OnlyRequestedEvent: ENTERING_INTO_AREA reports the
// re-entry, not the departure in between.
func TestDeferredArea_Rel19_OnlyRequestedEvent(t *testing.T) {
	sink := newEventSink()
	ts, _ := newDeferredLMF(t, profileNamed(t, "rel19"), cellSeq("000000010", "000000020", "000000020", "000000010"), sink)
	if resp, raw := post(t, ts, detLM, areaBody("ENTERING_INTO_AREA", "")); resp.StatusCode != 200 {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	if n := sink.wait(t, 1); n.ReportedEventType != reportedEnteringAreaEvent {
		t.Fatalf("first report must be the entering event: %+v", n)
	}
}

func TestDeferredArea_Rel19_BeingInside(t *testing.T) {
	sink := newEventSink()
	ts, _ := newDeferredLMF(t, profileNamed(t, "rel19"), cellSeq("000000010"), sink)
	if resp, raw := post(t, ts, detLM, areaBody("BEING_INSIDE_AREA", "")); resp.StatusCode != 200 {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	for i := 1; i <= 2; i++ {
		if n := sink.wait(t, i); n.ReportedEventType != reportedBeingInsideEvent {
			t.Fatalf("report %d: %+v", i, n)
		}
	}
}

func TestDeferred_Rel19_ExpiryTerminationNotify(t *testing.T) {
	// reportingDuration reached -> NORMAL_TERMINATION.
	sink := newEventSink()
	ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), cellSeq("000000020"), sink)
	if resp, raw := post(t, ts, detLM, areaBody("ENTERING_INTO_AREA", `,"reportingDuration":3`)); resp.StatusCode != 200 {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	n := sink.wait(t, 1)
	if n.ReportedEventType != reportedLocationCancellation || n.TerminationCause != terminationNormal || n.LocationEstimate != nil {
		t.Fatalf("unexpected: %+v", n)
	}
	eventually(t, "session removal", func() bool { return srv.registry.count() == 0 })

	// LMF max-duration cap -> TERMINATION_BY_NETWORK.
	sink2 := newEventSink()
	ts2, _ := newDeferredLMFCap(t, profileNamed(t, "rel19"), goldenAMF(), sink2, 3)
	if resp, raw := post(t, ts2, detLM, periodicBodyI(8639999, 100000, true)); resp.StatusCode != 200 {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	if n := sink2.wait(t, 1); n.TerminationCause != terminationByNetwork || n.ReportedEventType != reportedLocationCancellation {
		t.Fatalf("unexpected: %+v", n)
	}
}

func TestDeferred_Rel19_RepeatedLocateFailuresTerminate(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	amf := &mockAMFClient{ProvideFunc: func(context.Context, string) (*LocationData, string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return &LocationData{LocationEstimate: &GeographicArea{Shape: "POINT", Point: &LatLon{Lat: 1, Lon: 1}}, NRCellId: "10"}, "", nil
		}
		return nil, "X", errors.New("gone")
	}}
	sink := newEventSink()
	ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), amf, sink)
	if resp, raw := post(t, ts, detLM, periodicBodyI(8639999, 1, true)); resp.StatusCode != 200 {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	n := sink.wait(t, 1)
	if n.TerminationCause != terminationByNetwork {
		t.Fatalf("unexpected: %+v", n)
	}
	mu.Lock()
	c := calls
	mu.Unlock()
	if c != 1+maxConsecutiveLocateFailures {
		t.Fatalf("locate calls = %d", c)
	}
	eventually(t, "session removal", func() bool { return srv.registry.count() == 0 })
}

func TestDeferred_Rel19_ShutdownSendsNoNotify(t *testing.T) {
	sink := newEventSink()
	ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), sink)
	if resp, raw := post(t, ts, detLM, periodicBodyI(5, 100000, false)); resp.StatusCode != 200 {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	srv.registry.cancelAll()
	srv.drainBG(context.Background())
	if sink.count() != 0 {
		t.Fatalf("shutdown must not send EventNotify")
	}
	if srv.goBG(func() {}) {
		t.Fatal("goBG must refuse work once draining")
	}
}

func TestDeferred_Rel19_ReplaceAndLimit(t *testing.T) {
	ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), newEventSink())
	srv.deferredLimit = 2
	mk := func(l string) string {
		return strings.Replace(periodicBodyI(5, 100000, false), `"`+ldr+`"`, `"`+l+`"`, 1)
	}
	for _, l := range []string{"aa", "bb"} {
		if resp, raw := post(t, ts, detLM, mk(l)); resp.StatusCode != 200 {
			t.Fatalf("create %s: %d %s", l, resp.StatusCode, raw)
		}
	}
	if resp, _ := post(t, ts, detLM, mk("cc")); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over limit: %d", resp.StatusCode)
	}
	// Re-sending an existing (ldr, uri) replaces it even at the limit.
	old, _ := srv.registry.findDeferred("aa", cbURI)
	if resp, _ := post(t, ts, detLM, mk("aa")); resp.StatusCode != 200 {
		t.Fatalf("replace: %d", resp.StatusCode)
	}
	cur, _ := srv.registry.findDeferred("aa", cbURI)
	if srv.registry.countDeferred() != 2 || cur.SubId == old.SubId {
		t.Fatalf("session was not replaced (count=%d)", srv.registry.countDeferred())
	}
}

// TestRegistry_AddDeferredAtomicOnLimit: a refused replace keeps the old session.
func TestRegistry_AddDeferredAtomicOnLimit(t *testing.T) {
	r := newRegistry()
	mk := func(id, l string) *subscription {
		return &subscription{SubId: id, cancel: func() {},
			deferred: &deferredSession{LdrReference: l, HgmlcCallBackURI: cbURI}}
	}
	r.add(mk("1", "aa"))
	r.add(mk("2", "bb"))
	if _, ok := r.addDeferred(mk("3", "aa"), 1); ok {
		t.Fatal("must be refused: other sessions already at the limit")
	}
	if got, ok := r.get("1"); !ok || got.SubId != "1" {
		t.Fatal("old session must survive a refused replace")
	}
	if _, ok := r.get("3"); ok {
		t.Fatal("refused session must not be added")
	}
}

func TestDeferred_Rel19_ConcurrentCreates(t *testing.T) {
	ts, srv := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), newEventSink())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := fmt.Sprintf("%02x", i%10) // 10 distinct references, each sent twice
			body := strings.Replace(periodicBodyI(5, 100000, false), `"`+ldr+`"`, `"`+l+`"`, 1)
			resp, raw := post(t, ts, detLM, body)
			if resp.StatusCode != 200 {
				t.Errorf("create %s: %d %s", l, resp.StatusCode, raw)
			}
		}(i)
	}
	wg.Wait()
	if n := srv.registry.countDeferred(); n != 10 {
		t.Fatalf("sessions = %d, want 10", n)
	}
}

// TestDeferred_Rel17_IgnoresAttributes: under rel17 / no profile the deferred
// attributes are ignored: the answer is the immediate LocationData, byte-identical
// to the golden, and no session is created.
func TestDeferred_Rel17_IgnoresAttributes(t *testing.T) {
	for name, p := range map[string]*capability.Profile{"nil": nil, "rel17": profileNamed(t, "rel17")} {
		t.Run(name, func(t *testing.T) {
			sink := newEventSink()
			ts, srv := newDeferredLMF(t, p, goldenAMF(), sink)
			resp, raw := post(t, ts, detLM, periodicBody(2, false))
			checkGolden(t, "golden_determine_location_200.txt",
				"status: "+http.StatusText(resp.StatusCode)+"\nContent-Type: "+resp.Header.Get("Content-Type")+"\n\n"+raw)
			if srv.registry.count() != 0 || sink.count() != 0 {
				t.Fatalf("rel17 must not create a deferred session")
			}
			if r, _ := post(t, ts, canLM, `{"ldrReference":"zz"}`); r.StatusCode != 204 {
				t.Fatalf("rel17 cancel: %d", r.StatusCode)
			}
			// Trailing data stays tolerated outside the rel19 profile.
			if r, _ := post(t, ts, detLM, `{"supi":"imsi-001010000000001"} x`); r.StatusCode != 200 {
				t.Fatalf("rel17 trailing data: %d", r.StatusCode)
			}
		})
	}
}

// TestDeferred_Rel19_ImmediateStillWorks: without periodic/area attributes a
// rel19 DetermineLocation is an immediate location (200 LocationData).
func TestDeferred_Rel19_ImmediateStillWorks(t *testing.T) {
	ts, _ := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), newEventSink())
	resp, raw := post(t, ts, detLM, `{"supi":"imsi-001010000000001"}`)
	if resp.StatusCode != 200 || !strings.Contains(raw, "locationEstimate") {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
}

func TestAreaContains(t *testing.T) {
	tai := &TaiLoc{PlmnId: PlmnID{MCC: "001", MNC: "01"}, Tac: "000001"}
	loc := &LocationData{NRCellId: "000000010", Tai: tai}
	for name, c := range map[string]struct {
		areas []reportingArea
		want  bool
	}{
		"tai match, zero-padded differently": {[]reportingArea{{AreaType: areaTypeTai, Tai: &TaiLoc{PlmnId: tai.PlmnId, Tac: "0001"}}}, true},
		"tai other plmn":                     {[]reportingArea{{AreaType: areaTypeTai, Tai: &TaiLoc{PlmnId: PlmnID{MCC: "002", MNC: "01"}, Tac: "000001"}}}, false},
		"ncgi match":                         {[]reportingArea{{AreaType: areaTypeNcgi, Ncgi: &ncgiArea{NrCellId: "10"}}}, true},
		"ncgi other":                         {[]reportingArea{{AreaType: areaTypeNcgi, Ncgi: &ncgiArea{NrCellId: "11"}}}, false},
		"eps never":                          {[]reportingArea{{AreaType: areaTypeEcgi, Ecgi: &ecgiArea{EutraCellId: "10"}}}, false},
	} {
		if got := areaContains(c.areas, loc); got != c.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
}

func TestMulDurSaturates(t *testing.T) {
	if got := mulDur(8639999*8639999, time.Second); got <= 0 {
		t.Fatalf("overflowed: %v", got)
	}
	if got := mulDur(3, time.Second); got != 3*time.Second {
		t.Fatalf("got %v", got)
	}
}

// TestDeferred_Rel19_ProcedureTotal checks the fivegc_procedure_total deltas of
// the DeferredLocation procedure: OK on activation and on CancelLocation,
// REJECT on a validation error / unknown session, FAILURE on a failed fix.
func TestDeferred_Rel19_ProcedureTotal(t *testing.T) {
	cnt := func(res string) float64 {
		return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("LMF", "DeferredLocation", res))
	}
	ok0, rej0, fail0 := cnt("OK"), cnt("REJECT"), cnt("FAILURE")

	ts, _ := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), newEventSink())
	if resp, b := post(t, ts, detLM, periodicBodyI(5, 100000, false)); resp.StatusCode != 200 {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	if resp, _ := post(t, ts, canLM, cancelBody(cbURI, ldr)); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("cancel: %d", resp.StatusCode)
	}
	if resp, _ := post(t, ts, canLM, cancelBody(cbURI, ldr)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown cancel: %d", resp.StatusCode)
	}
	if got := cnt("OK") - ok0; got != 2 {
		t.Errorf("OK delta = %v, want 2 (activation + cancel)", got)
	}
	if got := cnt("REJECT") - rej0; got != 1 {
		t.Errorf("REJECT delta = %v, want 1", got)
	}

	amf := &mockAMFClient{ProvideFunc: func(context.Context, string) (*LocationData, string, error) {
		return nil, "CAUSE", errors.New("boom")
	}}
	ts2, _ := newDeferredLMF(t, profileNamed(t, "rel19"), amf, newEventSink())
	if resp, _ := post(t, ts2, detLM, periodicBody(2, false)); resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("failed fix: %d", resp.StatusCode)
	}
	if got := cnt("FAILURE") - fail0; got != 1 {
		t.Errorf("FAILURE delta = %v, want 1", got)
	}

	rej1 := cnt("REJECT")
	body := `{"supi":"s","ldrType":"MOTION","hgmlcCallBackURI":"` + cbURI + `","ldrReference":"` + ldr + `"}`
	if resp, _ := post(t, ts2, detLM, body); resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("motion: %d", resp.StatusCode)
	}
	if got := cnt("REJECT") - rej1; got != 1 {
		t.Errorf("REJECT delta (unsupported event) = %v, want 1", got)
	}
}

// TestValidateDeferred_UnknownLdrTypeIgnored: a value outside the LdrType
// enumeration is treated as absent (TS 29.500 §6.6.2), so the information
// present selects the type and the request is accepted.
func TestValidateDeferred_UnknownLdrTypeIgnored(t *testing.T) {
	d := &deferredInputData{
		LdrType: "FUTURE_TYPE", HgmlcCallBackURI: cbURI, LdrReference: ldr,
		PeriodicEventInfo: &periodicEventInfo{ReportingAmount: 1, ReportingInterval: 1},
	}
	if bad := validateDeferred(d); len(bad) != 0 || d.LdrType != "" {
		t.Errorf("bad=%v ldrType=%q", bad, d.LdrType)
	}
	// UE_AVAILABLE is a known value and keeps its 400.
	d = &deferredInputData{
		LdrType: ldrTypeUEAvailable, HgmlcCallBackURI: cbURI, LdrReference: ldr,
		PeriodicEventInfo: &periodicEventInfo{ReportingAmount: 1, ReportingInterval: 1},
	}
	if bad := validateDeferred(d); len(bad) == 0 {
		t.Error("UE_AVAILABLE with periodicEventInfo must stay rejected")
	}
}
