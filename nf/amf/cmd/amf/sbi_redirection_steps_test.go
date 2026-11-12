package main

// sbi_redirection_steps_test.go - godog runner for
// ../../tests/features/sbi_redirection.feature (SBI-FEAT-001, ES3XX).
//
// The suite lives in package main (not nf/amf/tests/features) because the
// system under test, HTTPSMFClient, is declared in package main. It carries no
// build tag, so `make -C nf/amf test` (go test -race ./nf/amf/...) runs it;
// `make test-functional` only covers ./nf/amf/tests/features/... and does not.
//
// The client is wired exactly as main.go does (sbi.ApplyRedirectPolicy on the
// SBI client); two in-process TLS servers play SMF-A and SMF-B.
// Ref: TS 29.502 §6.1.8 (feature 8 ES3XX), §6.1.10; TS 29.500 §6.10.9.1.

import (
	"bytes"
	"context"
	"encoding/json"
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

	"github.com/cucumber/godog"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// redirBaselineBody is the pre-negotiation (rel17) CreateSMContext body for
// supi imsi-001010000000001, dnn internet, PDU session 1, n1SmMsg 01 02 03,
// S-NSSAI sst 1 sd 000001: the bytes pinned by goldenSMContextCreateBody
// (golden_features_test.go) with pduSessionId 1 instead of 5.
const redirBaselineBody = `{"anType":"3GPP_ACCESS","dnn":"internet","n1SmMsg":"AQID","pduSessionId":1,"requestType":"INITIAL_REQUEST","servingNfId":"amf-001","snssai":{"sd":"000001","sst":1},"supi":"imsi-001010000000001"}`

// Headers a (tracing / correlation) transport adds to every outgoing request,
// as the production otelhttp + OAuth2 transports do. net/http snapshots the
// request headers before the transport runs, so only Content-Type is carried
// by the redirect policy itself; the transport re-adds these per hop. The
// "same headers" assertion therefore checks the policy (Content-Type) and
// that nothing else diverges between the hops.
const (
	redirHdrCorrelation = "X-Correlation-Id"
	redirHdrPriority    = "3gpp-Sbi-Message-Priority"
)

type redirResp struct {
	status  int
	headers map[string]string
	body    string
}

type redirReq struct {
	method string
	path   string
	body   string
	header http.Header
}

type redirMock struct {
	name   string
	srv    *httptest.Server
	mu     sync.Mutex
	def    *redirResp
	byPath map[string]*redirResp
	reqs   []redirReq
}

func newRedirMock(name string) *redirMock {
	m := &redirMock{name: name, byPath: map[string]*redirResp{}}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.reqs = append(m.reqs, redirReq{method: r.Method, path: r.URL.Path, body: string(raw), header: r.Header.Clone()})
		resp := m.byPath[r.URL.Path]
		if resp == nil {
			resp = m.def
		}
		m.mu.Unlock()
		if resp == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		for k, v := range resp.headers {
			w.Header().Set(k, v)
		}
		if resp.body != "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(resp.status)
		_, _ = io.WriteString(w, resp.body)
	}))
	return m
}

func (m *redirMock) received() []redirReq {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]redirReq(nil), m.reqs...)
}

// headerInjector sets the correlation / priority headers on every hop.
type headerInjector struct{ base http.RoundTripper }

func (h headerInjector) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set(redirHdrCorrelation, "01JTESTREDIRECT0000000000")
	req.Header.Set(redirHdrPriority, "5")
	return h.base.RoundTrip(req)
}

type redirLogBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *redirLogBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *redirLogBuf) records(procedure string) []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.b.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["procedure"] == procedure {
			out = append(out, m)
		}
	}
	return out
}

type redirWorld struct {
	mocks   map[string]*redirMock
	profile *capability.Profile
	logs    *redirLogBuf
	client  *HTTPSMFClient

	ctxRef string // SM context reference of "an SM context ... exists"

	ref      string
	neg      features.Set
	callErr  error
	called   bool
	requests int // total requests across mocks right after the call
}

func (w *redirWorld) mock(n string) *redirMock { return w.mocks[n] }

func (w *redirWorld) url(mock, path string) string { return w.mock(mock).srv.URL + path }

func (w *redirWorld) set(mock string, r *redirResp) error {
	m := w.mock(mock)
	if m == nil {
		return fmt.Errorf("unknown mock %q", mock)
	}
	m.mu.Lock()
	m.def = r
	m.mu.Unlock()
	return nil
}

// ---- Background ----

func (w *redirWorld) mocksRunning() error {
	w.mocks = map[string]*redirMock{"SMF-A": newRedirMock("SMF-A"), "SMF-B": newRedirMock("SMF-B")}
	w.logs = &redirLogBuf{}
	return nil
}

func (w *redirWorld) clientConfigured() error {
	if w.mock("SMF-A") == nil {
		return fmt.Errorf("mock SMF-A not running")
	}
	return nil
}

func (w *redirWorld) profileIs(name string) error {
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		return err
	}
	w.profile = p
	return nil
}

// buildClient wires the HTTPSMFClient to SMF-A as main.go does.
func (w *redirWorld) buildClient() {
	a := w.mock("SMF-A")
	hc := a.srv.Client()
	logger := slog.New(slog.NewJSONHandler(w.logs, nil)).With("nf", "AMF")
	sbi.ApplyRedirectPolicy(hc, logger)
	hc.Transport = headerInjector{base: hc.Transport}
	w.client = &HTTPSMFClient{
		address: strings.TrimPrefix(a.srv.URL, "https://"),
		client:  hc,
		profile: w.profile,
		logger:  logger,
	}
}

// ---- Given: mock behaviour ----

func (w *redirWorld) answersCreate201Features(m, sf string) error {
	return w.set(m, &redirResp{status: 201, body: `{"smContextRef":"ctx-a-1","supportedFeatures":` + strconv.Quote(sf) + `}`})
}

func (w *redirWorld) answersCreate201Ref(m, ref string) error {
	return w.set(m, &redirResp{status: 201, body: `{"smContextRef":` + strconv.Quote(ref) + `}`})
}

func (w *redirWorld) answersRedirectLocation(m string, status int, target, path string) error {
	return w.set(m, &redirResp{status: status, headers: map[string]string{"Location": w.url(target, path)}})
}

func (w *redirWorld) answersRedirectLocationAndHeader(m string, status int, target, path, hk, hv string) error {
	return w.set(m, &redirResp{status: status, headers: map[string]string{"Location": w.url(target, path), hk: hv}})
}

func (w *redirWorld) answersRelativeLocation(m string, status int, loc string) error {
	return w.set(m, &redirResp{status: status, headers: map[string]string{"Location": loc}})
}

func (w *redirWorld) answersRawLocation(m string, status int, loc string) error {
	return w.answersRelativeLocation(m, status, loc)
}

func (w *redirWorld) answersPathWith201(m, path, ref string) error {
	mk := w.mock(m)
	mk.mu.Lock()
	mk.byPath[path] = &redirResp{status: 201, body: `{"smContextRef":` + strconv.Quote(ref) + `}`}
	mk.mu.Unlock()
	return nil
}

func (w *redirWorld) answersRedirectResponse(m string, status int, locMock, locPath, cause, field, apiRootMock string) error {
	body, _ := json.Marshal(map[string]string{"cause": cause, field: w.mock(apiRootMock).srv.URL})
	return w.set(m, &redirResp{status: status, headers: map[string]string{"Location": w.url(locMock, locPath)}, body: string(body)})
}

func (w *redirWorld) answersRedirectResponseNoTarget(m string, status int, locMock, locPath, cause string) error {
	body, _ := json.Marshal(map[string]string{"cause": cause})
	return w.set(m, &redirResp{status: status, headers: map[string]string{"Location": w.url(locMock, locPath)}, body: string(body)})
}

func (w *redirWorld) answersNoLocationEmptyBody(m string, status int) error {
	return w.set(m, &redirResp{status: status})
}

func (w *redirWorld) answersStatus(m string, status int) error {
	return w.set(m, &redirResp{status: status})
}

func (w *redirWorld) smContextExists(ref string) error {
	w.ctxRef = ref
	return nil
}

// ---- When ----

func (w *redirWorld) callCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 20*time.Second)
}

func (w *redirWorld) finish() {
	w.called = true
	for _, m := range w.mocks {
		w.requests += len(m.received())
	}
}

func (w *redirWorld) createSMContext() error {
	w.buildClient()
	ctx, cancel := w.callCtx()
	defer cancel()
	w.ref, _, _, w.neg, w.callErr = w.client.CreateSMContext(ctx, "imsi-001010000000001", "internet", 1,
		[]byte{1, 2, 3}, amfctx.SNSSAISubscribed{SST: 1, SD: "000001"})
	w.finish()
	return nil
}

func (w *redirWorld) updateSMContext() error {
	w.buildClient()
	ctx, cancel := w.callCtx()
	defer cancel()
	w.callErr = w.client.UpdateSMContext(ctx, w.ctxRef, []byte{9})
	w.finish()
	return nil
}

func (w *redirWorld) deleteSMContext() error {
	w.buildClient()
	ctx, cancel := w.callCtx()
	defer cancel()
	w.callErr = w.client.DeleteSMContext(ctx, w.ctxRef)
	w.finish()
	return nil
}

// ---- Then ----

func (w *redirWorld) firstRequest(m string) (redirReq, error) {
	r := w.mock(m).received()
	if len(r) == 0 {
		return redirReq{}, fmt.Errorf("mock %s received no request", m)
	}
	return r[0], nil
}

func (w *redirWorld) offeredFeatures(m string) (string, bool, error) {
	r, err := w.firstRequest(m)
	if err != nil {
		return "", false, err
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(r.body), &body); err != nil {
		return "", false, fmt.Errorf("request body is not JSON: %w", err)
	}
	v, ok := body["supportedFeatures"].(string)
	return v, ok, nil
}

func (w *redirWorld) receivedFeatures(m, want string) error {
	got, ok, err := w.offeredFeatures(m)
	if err != nil {
		return err
	}
	if !ok || got != want {
		return fmt.Errorf("mock %s received supportedFeatures %q (present=%v), want %q", m, got, ok, want)
	}
	return nil
}

func (w *redirWorld) receivedNoFeatures(m string) error {
	got, ok, err := w.offeredFeatures(m)
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("mock %s received a supportedFeatures attribute %q, want none", m, got)
	}
	return nil
}

func (w *redirWorld) receivedBaseline(m string) error {
	r, err := w.firstRequest(m)
	if err != nil {
		return err
	}
	if r.body != redirBaselineBody {
		return fmt.Errorf("request body differs from the pre-negotiation baseline:\n got %s\nwant %s", r.body, redirBaselineBody)
	}
	return nil
}

func (w *redirWorld) storesNegotiated(want string, psi int) error {
	if w.callErr != nil {
		return fmt.Errorf("CreateSMContext failed: %w", w.callErr)
	}
	if got := w.neg.String(); got != want {
		return fmt.Errorf("negotiated feature set for PDU session %d = %q, want %q", psi, got, want)
	}
	return nil
}

func (w *redirWorld) receivedN(m string, n int) error {
	if got := len(w.mock(m).received()); got != n {
		return fmt.Errorf("mock %s received %d request(s), want %d", m, got, n)
	}
	return nil
}

func (w *redirWorld) receivedMethodPath(m, method, path string) error {
	r := w.mock(m).received()
	if len(r) == 0 {
		return fmt.Errorf("mock %s received no request", m)
	}
	last := r[len(r)-1]
	if last.method != method || last.path != path {
		return fmt.Errorf("mock %s received %s %s, want %s %s", m, last.method, last.path, method, path)
	}
	return nil
}

func (w *redirWorld) receivedSecondMethodPath(m, method, path string) error {
	r := w.mock(m).received()
	if len(r) < 2 {
		return fmt.Errorf("mock %s received %d request(s), want at least 2", m, len(r))
	}
	if r[1].method != method || r[1].path != path {
		return fmt.Errorf("mock %s second request is %s %s, want %s %s", m, r[1].method, r[1].path, method, path)
	}
	return nil
}

func (w *redirWorld) bodiesEqual(b, a string) error {
	ra, err := w.firstRequest(a)
	if err != nil {
		return err
	}
	rb, err := w.firstRequest(b)
	if err != nil {
		return err
	}
	if ra.body != rb.body {
		return fmt.Errorf("body at %s differs from body at %s:\n%s\n%s", b, a, rb.body, ra.body)
	}
	return nil
}

func (w *redirWorld) headersEqual(h1, h2, h3, b, a string) error {
	ra, err := w.firstRequest(a)
	if err != nil {
		return err
	}
	rb, err := w.firstRequest(b)
	if err != nil {
		return err
	}
	for _, h := range []string{h1, h2, h3} {
		va, vb := ra.header.Values(h), rb.header.Values(h)
		if len(va) == 0 {
			return fmt.Errorf("original request at %s carried no %s header (test harness precondition)", a, h)
		}
		if strings.Join(va, ",") != strings.Join(vb, ",") {
			return fmt.Errorf("header %s: %s received %q, %s received %q", h, a, va, b, vb)
		}
	}
	return nil
}

func (w *redirWorld) callSucceeds(op string) error {
	if !w.called {
		return fmt.Errorf("%s was not called", op)
	}
	if w.callErr != nil {
		return fmt.Errorf("%s failed: %w", op, w.callErr)
	}
	return nil
}

func (w *redirWorld) storesRef(ref string, psi int) error {
	if w.callErr != nil {
		return fmt.Errorf("CreateSMContext failed: %w", w.callErr)
	}
	if w.ref != ref {
		return fmt.Errorf("smContextRef for PDU session %d = %q, want %q", psi, w.ref, ref)
	}
	return nil
}

func (w *redirWorld) redirectLogFull(iface, dir, spec string, status int, nfid, result string) error {
	for _, r := range w.logs.records("HttpRedirection") {
		if r["interface"] == iface && r["direction"] == dir && r["spec_ref"] == spec &&
			r["http_status"] == float64(status) && r["target_nf_id"] == nfid && r["result"] == result {
			return nil
		}
	}
	return fmt.Errorf("no HttpRedirection log with interface=%s direction=%s spec_ref=%q http_status=%d target_nf_id=%s result=%s; got %v",
		iface, dir, spec, status, nfid, result, w.logs.records("HttpRedirection"))
}

func (w *redirWorld) redirectLogStatusResult(status int, result string) error {
	for _, r := range w.logs.records("HttpRedirection") {
		if r["http_status"] == float64(status) && r["result"] == result {
			return nil
		}
	}
	return fmt.Errorf("no HttpRedirection log with http_status=%d result=%s; got %v", status, result, w.logs.records("HttpRedirection"))
}

func (w *redirWorld) everyRequestPostWithBody(m string) error {
	r := w.mock(m).received()
	if len(r) == 0 {
		return fmt.Errorf("mock %s received no request", m)
	}
	for i, q := range r {
		if q.method != http.MethodPost || q.body == "" {
			return fmt.Errorf("mock %s request %d: method %s, body length %d", m, i, q.method, len(q.body))
		}
	}
	return nil
}

func (w *redirWorld) sameMethodPath(b, a string) error {
	ra, err := w.firstRequest(a)
	if err != nil {
		return err
	}
	rb, err := w.firstRequest(b)
	if err != nil {
		return err
	}
	if ra.method != rb.method || ra.path != rb.path {
		return fmt.Errorf("%s got %s %s, %s got %s %s", a, ra.method, ra.path, b, rb.method, rb.path)
	}
	if ra.method != http.MethodDelete {
		return fmt.Errorf("expected a DELETE, got %s", ra.method)
	}
	return nil
}

func (w *redirWorld) failsContaining(op, sub string) error {
	if !w.called {
		return fmt.Errorf("%s was not called", op)
	}
	if w.callErr == nil {
		return fmt.Errorf("%s succeeded, want an error containing %q", op, sub)
	}
	if !strings.Contains(w.callErr.Error(), sub) {
		return fmt.Errorf("%s error %q does not contain %q", op, w.callErr.Error(), sub)
	}
	return nil
}

func (w *redirWorld) totalIsMaxPlusOne() error {
	if want := sbi.MaxRedirects + 1; w.requests != want {
		return fmt.Errorf("total requests = %d, want MaxRedirects+1 = %d", w.requests, want)
	}
	return nil
}

func (w *redirWorld) noRetryBeyondMax() error {
	total := 0
	for _, m := range w.mocks {
		total += len(m.received())
	}
	if want := sbi.MaxRedirects + 1; total != want || total != w.requests {
		return fmt.Errorf("requests grew after the call: at return %d, now %d, max allowed %d", w.requests, total, want)
	}
	return nil
}

func initRedirectionScenario(sc *godog.ScenarioContext) {
	w := &redirWorld{}
	sc.After(func(ctx context.Context, _ *godog.Scenario, err error) (context.Context, error) {
		for _, m := range w.mocks {
			m.srv.Close()
		}
		return ctx, nil
	})

	const mk = `(SMF-[AB])`
	sc.Step(`^a mock SMF-A and a mock SMF-B are running$`, w.mocksRunning)
	sc.Step(`^the AMF Nsmf client is configured with the address of mock SMF-A$`, w.clientConfigured)
	sc.Step(`^the AMF runs with release profile "([^"]*)"$`, w.profileIs)

	sc.Step(`^mock `+mk+` answers CreateSMContext with 201 and supportedFeatures "([^"]*)"$`, w.answersCreate201Features)
	sc.Step(`^mock `+mk+` answers CreateSMContext with 201 and smContextRef "([^"]*)"$`, w.answersCreate201Ref)
	sc.Step(`^mock `+mk+` answers CreateSMContext with (\d+) and Location "mock `+mk+` ([^"]*)"$`, w.answersRedirectLocation)
	sc.Step(`^mock `+mk+` always answers CreateSMContext with (\d+) and Location "mock `+mk+` ([^"]*)"$`, w.answersRedirectLocation)
	sc.Step(`^mock `+mk+` answers CreateSMContext with (\d+), Location "mock `+mk+` ([^"]*)" and header "([^"]*)" "([^"]*)"$`, w.answersRedirectLocationAndHeader)
	sc.Step(`^mock `+mk+` answers CreateSMContext with (\d+) and the relative Location "([^"]*)"$`, w.answersRelativeLocation)
	sc.Step(`^mock `+mk+` answers CreateSMContext with (\d+) and the raw Location "([^"]*)"$`, w.answersRawLocation)
	sc.Step(`^mock `+mk+` answers a request to path "([^"]*)" with 201 and smContextRef "([^"]*)"$`, w.answersPathWith201)
	sc.Step(`^mock `+mk+` answers CreateSMContext with (\d+), Location "mock `+mk+` ([^"]*)" and RedirectResponse cause "([^"]*)" with (targetScp|targetSepp) "mock `+mk+` apiRoot"$`, w.answersRedirectResponse)
	sc.Step(`^mock `+mk+` answers CreateSMContext with (\d+), Location "mock `+mk+` ([^"]*)" and RedirectResponse cause "([^"]*)" without targetScp$`, w.answersRedirectResponseNoTarget)
	sc.Step(`^mock `+mk+` answers CreateSMContext with (\d+), no Location header and an empty body$`, w.answersNoLocationEmptyBody)
	sc.Step(`^an SM context "([^"]*)" exists for PDU session 1 on mock SMF-A$`, w.smContextExists)
	sc.Step(`^mock `+mk+` answers UpdateSMContext on "([^"]*)" with (\d+) and Location "mock `+mk+` ([^"]*)"$`,
		func(m, _ string, st int, t, p string) error { return w.answersRedirectLocation(m, st, t, p) })
	sc.Step(`^mock `+mk+` answers UpdateSMContext on "([^"]*)" with (\d+)$`,
		func(m, _ string, st int) error { return w.answersStatus(m, st) })
	sc.Step(`^mock `+mk+` answers the SM context deletion on "([^"]*)" with (\d+) and Location "mock `+mk+` ([^"]*)"$`,
		func(m, _ string, st int, t, p string) error { return w.answersRedirectLocation(m, st, t, p) })
	sc.Step(`^mock `+mk+` answers the SM context deletion on "([^"]*)" with (\d+)$`,
		func(m, _ string, st int) error { return w.answersStatus(m, st) })

	sc.Step(`^the AMF creates an SM context for PDU session 1$`, w.createSMContext)
	sc.Step(`^the AMF sends an UpdateSMContext for PDU session 1$`, w.updateSMContext)
	sc.Step(`^the AMF deletes the SM context for PDU session 1$`, w.deleteSMContext)

	sc.Step(`^mock `+mk+` received supportedFeatures "([^"]*)" in SmContextCreateData$`, w.receivedFeatures)
	sc.Step(`^the AMF stores the negotiated feature set "([^"]*)" on PDU session (\d+)$`, w.storesNegotiated)
	sc.Step(`^mock `+mk+` received SmContextCreateData without a supportedFeatures attribute$`, w.receivedNoFeatures)
	sc.Step(`^mock `+mk+` received a request body byte-identical to the pre-negotiation baseline$`, w.receivedBaseline)
	sc.Step(`^mock `+mk+` received (\d+) requests?$`, w.receivedN)
	sc.Step(`^mock `+mk+` received method "([^"]*)" and path "([^"]*)"$`, w.receivedMethodPath)
	sc.Step(`^mock `+mk+` received the second request with method "([^"]*)" and path "([^"]*)"$`, w.receivedSecondMethodPath)
	sc.Step(`^the request body received by mock `+mk+` equals the request body received by mock `+mk+`$`, w.bodiesEqual)
	sc.Step(`^the headers "([^"]*)", "([^"]*)" and "([^"]*)" received by mock `+mk+` equal those received by mock `+mk+`$`, w.headersEqual)
	sc.Step(`^the CreateSMContext call returns success$`, func() error { return w.callSucceeds("CreateSMContext") })
	sc.Step(`^the UpdateSMContext call returns success$`, func() error { return w.callSucceeds("UpdateSMContext") })
	sc.Step(`^the SM context deletion returns success$`, func() error { return w.callSucceeds("DeleteSMContext") })
	sc.Step(`^the AMF stores smContextRef "([^"]*)" for PDU session (\d+)$`, w.storesRef)
	sc.Step(`^a redirect log has interface "([^"]*)", direction "([^"]*)", spec_ref "([^"]*)", http_status (\d+), target_nf_id "([^"]*)" and result "([^"]*)"$`, w.redirectLogFull)
	sc.Step(`^a redirect log has http_status (\d+) and result "([^"]*)"$`, w.redirectLogStatusResult)
	sc.Step(`^every request received by mock `+mk+` has method "POST" and a non-empty body$`, w.everyRequestPostWithBody)
	sc.Step(`^mock `+mk+` received the same method and path as mock `+mk+` received for the deletion$`, w.sameMethodPath)
	sc.Step(`^the CreateSMContext call fails with an error containing "([^"]*)"$`, func(s string) error { return w.failsContaining("CreateSMContext", s) })
	sc.Step(`^the total number of requests received by mock SMF-A and mock SMF-B is the maximum redirects plus 1$`, w.totalIsMaxPlusOne)
	sc.Step(`^the AMF does not retry the redirect chain beyond the maximum$`, w.noRetryBeyondMax)
}

func TestSBIRedirectionFeature(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: initRedirectionScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/sbi_redirection.feature"},
			Strict:   true,
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
