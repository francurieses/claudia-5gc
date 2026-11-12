//go:build functional

package server

// sbi_redirection_functional_test.go - godog runner for
// ../../tests/features/sbi_redirection.feature (SBI-FEAT-001, ES3XX).
//
// Run with: go test -tags=functional ./nf/smf/...  (make -C nf/smf test-functional)
//
// The SMF is built with New() (so the redirect policy installed there is the
// one under test); only the transport is re-pointed at two in-process TLS
// servers playing AMF-A and AMF-B. The DL-data notification is driven through
// the real HTTP handler (handleDLDataNotification), the secondary
// authentication push through pushN1N2Message.
// Ref: TS 29.518 §6.1.8 (feature 7 ES3XX), §6.1.10; TS 29.500 §6.10.9.1.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// redirGoldenN1N2Body is the pre-negotiation (rel17) paging body, pinned by
// testdata/golden_n1n2_paging_body.json.
const redirGoldenN1N2Body = `{"pduSessionId":1}`

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
	served int // status the mock answered with
}

type redirMock struct {
	srv    *httptest.Server
	mu     sync.Mutex
	def    *redirResp
	byPath map[string]*redirResp
	reqs   []redirReq
}

func newRedirMock() *redirMock {
	m := &redirMock{byPath: map[string]*redirResp{}}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		resp := m.byPath[r.URL.Path]
		if resp == nil {
			resp = m.def
		}
		served := http.StatusNotFound
		if resp != nil {
			served = resp.status
		}
		m.reqs = append(m.reqs, redirReq{method: r.Method, path: r.URL.Path, body: string(raw), header: r.Header.Clone(), served: served})
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

// redirHeaderInjector adds correlation / priority headers on every hop, as
// the production tracing transport does (net/http snapshots request headers
// before the transport runs, so the redirect policy itself carries only the
// headers set by the caller, e.g. Content-Type).
type redirHeaderInjector struct{ base http.RoundTripper }

func (h redirHeaderInjector) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set(redirHdrCorrelation, "01JTESTREDIRECT0000000000")
	req.Header.Set(redirHdrPriority, "5")
	return h.base.RoundTrip(req)
}

type redirWorld struct {
	t       *testing.T
	mocks   map[string]*redirMock
	profile string
	srv     *Server
	logs    *syncBuffer

	// outcome of the last call
	called   bool
	cause    string // N1N2 cause returned by pushN1N2Message
	err      error  // error of pushN1N2Message
	httpCode int    // DL-data notification handler status
	httpBody map[string]any
	requests int
}

func (w *redirWorld) mock(n string) *redirMock { return w.mocks[n] }

func (w *redirWorld) url(m, path string) string { return w.mock(m).srv.URL + path }

func (w *redirWorld) set(m string, r *redirResp) error {
	mk := w.mock(m)
	if mk == nil {
		return fmt.Errorf("unknown mock %q", m)
	}
	mk.mu.Lock()
	mk.def = r
	mk.mu.Unlock()
	return nil
}

// ---- Background ----

func (w *redirWorld) mocksRunning() error {
	w.mocks = map[string]*redirMock{"AMF-A": newRedirMock(), "AMF-B": newRedirMock()}
	return nil
}

func (w *redirWorld) clientConfigured() error {
	if w.mock("AMF-A") == nil {
		return fmt.Errorf("mock AMF-A not running")
	}
	return nil
}

func (w *redirWorld) establishedSession(supi string) error {
	if supi != "imsi-001010000000001" {
		return fmt.Errorf("unexpected SUPI %q", supi)
	}
	return nil
}

func (w *redirWorld) profileIs(p string) error {
	w.profile = p
	return nil
}

// build creates the SMF with New() (installs the redirect policy), points its
// SBI client at AMF-A and registers PDU session 1.
func (w *redirWorld) build() error {
	if w.srv != nil {
		return nil
	}
	s, logs := newFeatureServer(w.t, w.profile, nil, nil)
	if s.httpClient == nil || s.httpClient.CheckRedirect == nil {
		return fmt.Errorf("New() did not install the ES3XX redirect policy on the SBI client")
	}
	a := w.mock("AMF-A")
	hc := a.srv.Client()
	hc.CheckRedirect = s.httpClient.CheckRedirect
	hc.Transport = redirHeaderInjector{base: hc.Transport}
	s.httpClient = hc
	s.cfg.Peers.AMF = strings.TrimPrefix(a.srv.URL, "https://")
	s.sessionMu.Lock()
	s.sessions["ctx-1"] = &Session{SUPI: "imsi-001010000000001", PDUSessionID: 1, DNN: "internet"}
	s.sessionMu.Unlock()
	w.srv, w.logs = s, logs
	return nil
}

func (w *redirWorld) finish() {
	w.called = true
	for _, m := range w.mocks {
		w.requests += len(m.received())
	}
}

// ---- Given: mock behaviour ----

func (w *redirWorld) answers202(m, cause string) error {
	return w.set(m, &redirResp{status: 202, body: `{"cause":` + strconv.Quote(cause) + `}`})
}

func (w *redirWorld) answers200(m, cause string) error {
	return w.set(m, &redirResp{status: 200, body: `{"cause":` + strconv.Quote(cause) + `}`})
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

func (w *redirWorld) answersPathWith202(m, path, cause string) error {
	mk := w.mock(m)
	mk.mu.Lock()
	mk.byPath[path] = &redirResp{status: 202, body: `{"cause":` + strconv.Quote(cause) + `}`}
	mk.mu.Unlock()
	return nil
}

func (w *redirWorld) answersRedirectResponse(m string, status int, locMock, locPath, cause, field, apiRootMock string) error {
	body, _ := json.Marshal(map[string]string{"cause": cause, field: w.mock(apiRootMock).srv.URL})
	return w.set(m, &redirResp{status: status, headers: map[string]string{"Location": w.url(locMock, locPath)}, body: string(body)})
}

func (w *redirWorld) answersNoLocationEmptyBody(m string, status int) error {
	return w.set(m, &redirResp{status: status})
}

// ---- When ----

func (w *redirWorld) triggerDLData() error {
	if err := w.build(); err != nil {
		return err
	}
	r := httptest.NewRequest(http.MethodPost, "/nsmf-management/v1/sessions/1/dl-data-notification?supi=imsi-001010000000001", nil)
	r.SetPathValue("pduSessionId", "1")
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rec := httptest.NewRecorder()
	w.srv.handleDLDataNotification(rec, r.WithContext(ctx))
	w.httpCode = rec.Code
	w.httpBody = map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &w.httpBody)
	w.finish()
	return nil
}

func (w *redirWorld) triggerSecondaryAuth() error {
	if err := w.build(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	w.cause, w.err = w.srv.pushN1N2Message(ctx, "imsi-001010000000001", 1,
		[]byte{0x2e, 0x01, 0x05, 0xc5}, []byte{1, 2}, "PDU_RES_SETUP_REQ")
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

func (w *redirWorld) receivedFeatures(m, want string) error {
	r, err := w.firstRequest(m)
	if err != nil {
		return err
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(r.body), &body); err != nil {
		return fmt.Errorf("request body is not JSON: %w", err)
	}
	if got, ok := body["supportedFeatures"].(string); !ok || got != want {
		return fmt.Errorf("mock %s received supportedFeatures %q (present=%v), want %q", m, got, ok, want)
	}
	return nil
}

func (w *redirWorld) receivedNoFeatures(m string) error {
	r, err := w.firstRequest(m)
	if err != nil {
		return err
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(r.body), &body); err != nil {
		return fmt.Errorf("request body is not JSON: %w", err)
	}
	if v, ok := body["supportedFeatures"]; ok {
		return fmt.Errorf("mock %s received a supportedFeatures attribute %v, want none", m, v)
	}
	return nil
}

func (w *redirWorld) receivedBaseline(m string) error {
	r, err := w.firstRequest(m)
	if err != nil {
		return err
	}
	if r.body != redirGoldenN1N2Body {
		return fmt.Errorf("request body differs from the pre-negotiation baseline:\n got %s\nwant %s", r.body, redirGoldenN1N2Body)
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

// finalStatus is the 2xx status the AMF mocks served (exactly one hop answers).
func (w *redirWorld) finalStatus() (int, error) {
	for _, m := range w.mocks {
		for _, r := range m.received() {
			if r.served >= 200 && r.served < 300 {
				return r.served, nil
			}
		}
	}
	return 0, fmt.Errorf("no AMF mock served a 2xx answer")
}

func (w *redirWorld) dlResult(status int, cause string) error {
	if w.httpCode != http.StatusOK {
		return fmt.Errorf("DL-data notification handler status %d, body %v", w.httpCode, w.httpBody)
	}
	if got := w.httpBody["amfCause"]; got != cause {
		return fmt.Errorf("amfCause = %v, want %q", got, cause)
	}
	got, err := w.finalStatus()
	if err != nil {
		return err
	}
	if got != status {
		return fmt.Errorf("AMF answered %d, want %d", got, status)
	}
	return nil
}

func (w *redirWorld) dlFailsContaining(sub string) error {
	if !w.called {
		return fmt.Errorf("DL-data notification was not triggered")
	}
	if w.httpCode != http.StatusBadGateway {
		return fmt.Errorf("handler status %d, want 502 (AMF_TRANSFER_FAILED); body %v", w.httpCode, w.httpBody)
	}
	if d, _ := w.httpBody["detail"].(string); !strings.Contains(d, sub) {
		return fmt.Errorf("failure detail %q does not contain %q", d, sub)
	}
	return nil
}

// dlFailsAsUnexpected: the failure is the one produced for any non-2xx AMF
// answer: 502 AMF_TRANSFER_FAILED with detail "smf: N1N2MessageTransfer: status N".
func (w *redirWorld) dlFailsAsUnexpected(status int) error {
	if err := w.dlFailsContaining("status " + strconv.Itoa(status)); err != nil {
		return err
	}
	want := fmt.Sprintf("smf: N1N2MessageTransfer: status %d", status)
	if d, _ := w.httpBody["detail"].(string); d != want {
		return fmt.Errorf("failure detail %q, want exactly %q", d, want)
	}
	if c := w.httpBody["cause"]; c != "AMF_TRANSFER_FAILED" {
		return fmt.Errorf("problem cause %v, want AMF_TRANSFER_FAILED", c)
	}
	return nil
}

func (w *redirWorld) secondaryAuthSucceeds() error {
	if w.err != nil {
		return fmt.Errorf("secondary authentication N1N2MessageTransfer failed: %w", w.err)
	}
	if w.cause != "N1_N2_TRANSFER_INITIATED" {
		return fmt.Errorf("cause %q, want N1_N2_TRANSFER_INITIATED", w.cause)
	}
	return nil
}

func (w *redirWorld) redirectLogs() []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(w.logs.String()), "\n") {
		var m map[string]any
		if line != "" && json.Unmarshal([]byte(line), &m) == nil && m["procedure"] == "HttpRedirection" {
			out = append(out, m)
		}
	}
	return out
}

func (w *redirWorld) redirectLogFull(iface, dir, spec string, status int, nfid, result string) error {
	for _, r := range w.redirectLogs() {
		if r["interface"] == iface && r["direction"] == dir && r["spec_ref"] == spec &&
			r["http_status"] == float64(status) && r["target_nf_id"] == nfid && r["result"] == result {
			return nil
		}
	}
	return fmt.Errorf("no HttpRedirection log with interface=%s direction=%s spec_ref=%q http_status=%d target_nf_id=%s result=%s; got %v",
		iface, dir, spec, status, nfid, result, w.redirectLogs())
}

func (w *redirWorld) redirectLogStatusResult(status int, result string) error {
	for _, r := range w.redirectLogs() {
		if r["http_status"] == float64(status) && r["result"] == result {
			return nil
		}
	}
	return fmt.Errorf("no HttpRedirection log with http_status=%d result=%s; got %v", status, result, w.redirectLogs())
}

func (w *redirWorld) totalIsMaxPlusOne() error {
	if want := sbi.MaxRedirects + 1; w.requests != want {
		return fmt.Errorf("total requests = %d, want MaxRedirects+1 = %d", w.requests, want)
	}
	return nil
}

func initSBIRedirectionScenario(t *testing.T) func(*godog.ScenarioContext) {
	return func(sc *godog.ScenarioContext) {
		w := &redirWorld{t: t}
		sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
			for _, m := range w.mocks {
				m.srv.Close()
			}
			return ctx, nil
		})

		const mk = `(AMF-[AB])`
		sc.Step(`^a mock AMF-A and a mock AMF-B are running$`, w.mocksRunning)
		sc.Step(`^the SMF Namf client is configured with the address of mock AMF-A$`, w.clientConfigured)
		sc.Step(`^an established PDU session 1 for SUPI "([^"]*)" exists in the SMF$`, w.establishedSession)
		sc.Step(`^the SMF runs with release profile "([^"]*)"$`, w.profileIs)

		sc.Step(`^mock `+mk+` answers N1N2MessageTransfer with 202 "([^"]*)"$`, w.answers202)
		sc.Step(`^mock `+mk+` answers N1N2MessageTransfer with 200 "([^"]*)"$`, w.answers200)
		sc.Step(`^mock `+mk+` (?:always )?answers N1N2MessageTransfer with (\d+) and Location "mock `+mk+` ([^"]*)"$`, w.answersRedirectLocation)
		sc.Step(`^mock `+mk+` answers N1N2MessageTransfer with (\d+), Location "mock `+mk+` ([^"]*)" and header "([^"]*)" "([^"]*)"$`, w.answersRedirectLocationAndHeader)
		sc.Step(`^mock `+mk+` answers N1N2MessageTransfer with (\d+) and the relative Location "([^"]*)"$`, w.answersRelativeLocation)
		sc.Step(`^mock `+mk+` answers a request to path "([^"]*)" with 202 "([^"]*)"$`, w.answersPathWith202)
		sc.Step(`^mock `+mk+` answers N1N2MessageTransfer with (\d+), Location "mock `+mk+` ([^"]*)" and RedirectResponse cause "([^"]*)" with (targetScp|targetSepp) "mock `+mk+` apiRoot"$`, w.answersRedirectResponse)
		sc.Step(`^mock `+mk+` answers N1N2MessageTransfer with (\d+), no Location header and an empty body$`, w.answersNoLocationEmptyBody)

		sc.Step(`^the SMF triggers a DL-data notification for PDU session 1$`, w.triggerDLData)
		sc.Step(`^the SMF sends a secondary authentication N1N2MessageTransfer for PDU session 1$`, w.triggerSecondaryAuth)

		sc.Step(`^mock `+mk+` received supportedFeatures "([^"]*)" in N1N2MessageTransferReqData$`, w.receivedFeatures)
		sc.Step(`^mock `+mk+` received N1N2MessageTransferReqData without a supportedFeatures attribute$`, w.receivedNoFeatures)
		sc.Step(`^mock `+mk+` received a request body byte-identical to the pre-negotiation baseline$`, w.receivedBaseline)
		sc.Step(`^mock `+mk+` received (\d+) requests?$`, w.receivedN)
		sc.Step(`^mock `+mk+` received method "([^"]*)" and path "([^"]*)"$`, w.receivedMethodPath)
		sc.Step(`^mock `+mk+` received the second request with method "([^"]*)" and path "([^"]*)"$`, w.receivedSecondMethodPath)
		sc.Step(`^the request body received by mock `+mk+` equals the request body received by mock `+mk+`$`, w.bodiesEqual)
		sc.Step(`^the headers "([^"]*)", "([^"]*)" and "([^"]*)" received by mock `+mk+` equal those received by mock `+mk+`$`, w.headersEqual)
		sc.Step(`^the DL-data notification result is (\d+) with cause "([^"]*)"$`, w.dlResult)
		sc.Step(`^the secondary authentication N1N2MessageTransfer succeeds$`, w.secondaryAuthSucceeds)
		sc.Step(`^a redirect log has interface "([^"]*)", direction "([^"]*)", spec_ref "([^"]*)", http_status (\d+), target_nf_id "([^"]*)" and result "([^"]*)"$`, w.redirectLogFull)
		sc.Step(`^a redirect log has http_status (\d+) and result "([^"]*)"$`, w.redirectLogStatusResult)
		sc.Step(`^the DL-data notification fails with an error containing "([^"]*)"$`, w.dlFailsContaining)
		sc.Step(`^the DL-data notification fails exactly as for an unexpected status (\d+)$`, w.dlFailsAsUnexpected)
		sc.Step(`^the total number of requests received by mock AMF-A and mock AMF-B is the maximum redirects plus 1$`, w.totalIsMaxPlusOne)
	}
}

func TestSBIRedirectionFeature(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: initSBIRedirectionScenario(t),
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
