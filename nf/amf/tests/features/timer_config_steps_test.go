//go:build functional

// timer_config_steps_test.go -- in-process godog steps for timer_config.feature
// (MCP-011: AMF runtime timer configuration via O&M; TS 24.501 §5.3.7, §10.2
// Table 10.2.1; TS 23.501 §5.3.2, §5.4.1.1).
//
// The real mgmt.RegisterTimerConfig route is served by an httptest server
// backed by a real timercfg.Store. The same store is shared with a real
// procedures.RegistrationHandler (Registration Accept builders) and a real
// ngap.Server (Mobile Reachable / Implicit Detach arming). The "armed" timer
// durations are read through UEContext.ArmedDurations.
//
// Seam note: the Implicit Detach timer is armed only when the Mobile Reachable
// timer expires (unexported startImplicitDetachTimer). The O&M API refuses a
// Mobile Reachable below 60 s, so that scenario writes a 1 s Mobile Reachable
// straight into the store (bypassing API validation, test only), lets the real
// timer expire, and then restores the store; the Implicit Detach value being
// asserted (300 s) is the one set through the O&M API.
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
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/mgmt"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/timercfg"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

const (
	tcPath    = "/amf/v1/config/timers"
	tcGNBAddr = "172.30.1.20:48212"
)

// tcLockedBuf is a goroutine-safe log sink.
type tcLockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *tcLockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *tcLockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// tcUDM is a minimal UDM for Phase3_ProcessSMCComplete.
type tcUDM struct{}

func (tcUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (tcUDM) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	return &procedures.UDMAMSubscription{}, nil
}
func (tcUDM) DeregisterUECM(context.Context, string) error { return nil }

type tcWorld struct {
	store *timercfg.Store
	api   *httptest.Server
	logs  *tcLockedBuf
	srv   *amfngap.Server
	reg   *procedures.RegistrationHandler

	resp   *http.Response
	status int
	body   []byte

	ra *nas.RegistrationAccept

	concMu   sync.Mutex
	concResp []mgmt.TimerConfigResponse
}

var tcW = &tcWorld{}

func (w *tcWorld) teardown() {
	if w.api != nil {
		w.api.Close()
		w.api = nil
	}
	if w.srv != nil && sbiW.ue != nil {
		w.srv.StopUETimers(sbiW.ue)
	}
	w.srv, w.reg, w.store = nil, nil, nil
}

func (w *tcWorld) reset() {
	w.teardown()
	w.logs = &tcLockedBuf{}
	w.resp, w.status, w.body, w.ra = nil, 0, nil, nil
	w.concResp = nil
}

// ---- Background -----------------------------------------------------------

func (w *tcWorld) baseConfig(t3512, guard, implicit int) error {
	if sbiW.mgr == nil || sbiW.ue == nil {
		return fmt.Errorf("no UE seeded")
	}
	w.store = timercfg.New(timercfg.Values{T3512Secs: t3512, GuardSecs: guard, ImplicitDetachSecs: implicit})

	base := slog.New(slog.NewJSONHandler(w.logs, &slog.HandlerOptions{Level: slog.LevelDebug})).With("nf", "AMF")
	mux := http.NewServeMux()
	mgmt.RegisterTimerConfig(mux, w.store, base)
	w.api = httptest.NewServer(mux)

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	w.srv = amfngap.NewServer("", sbiW.mgr, nil, amfngap.AMFConfig{MCC: "001", MNC: "01"}, quiet)
	w.srv.WithTimerStore(w.store)

	w.reg = procedures.NewRegistrationHandler(sbiW.mgr, nil, tcUDM{}, nil, "nf", "001", "01", quiet)
	w.reg.WithTimerStore(w.store)
	return nil
}

// ---- HTTP -----------------------------------------------------------------

func (w *tcWorld) do(method string, body []byte) error {
	if w.api == nil {
		return fmt.Errorf("timer configuration API not running")
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, w.api.URL+tcPath, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := w.api.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	w.resp, w.status, w.body = resp, resp.StatusCode, buf.Bytes()
	// Shared steps ("the response status is", "the response Allow header is").
	sbiW.resp, sbiW.body = resp, w.body
	anW.resp, anW.body = resp, w.body
	return nil
}

func (w *tcWorld) read() error { return w.do(http.MethodGet, nil) }

func (w *tcWorld) put(body string) error { return w.do(http.MethodPut, []byte(body)) }

func (w *tcWorld) method(m string) error { return w.do(m, []byte("{}")) }

func (w *tcWorld) decodeResponse() (*mgmt.TimerConfigResponse, error) {
	var r mgmt.TimerConfigResponse
	if err := json.Unmarshal(w.body, &r); err != nil {
		return nil, fmt.Errorf("response is not a timer configuration: %v; body=%s", err, w.body)
	}
	return &r, nil
}

func checkValues(label string, got mgmt.TimerValues, t3512, guard, mr, implicit int) error {
	if got.T3512Secs != t3512 || got.MobileReachableGuard != guard ||
		got.MobileReachableSecs != mr || got.ImplicitDetachSecs != implicit {
		return fmt.Errorf("%s = %+v, want T3512 %d guard %d mobile reachable %d implicit detach %d",
			label, got, t3512, guard, mr, implicit)
	}
	return nil
}

func (w *tcWorld) effectiveIs(t3512, guard, mr, implicit int) error {
	r, err := w.decodeResponse()
	if err != nil {
		return err
	}
	return checkValues("effective", r.Effective, t3512, guard, mr, implicit)
}

func (w *tcWorld) baseIs(t3512, guard, mr, implicit int) error {
	r, err := w.decodeResponse()
	if err != nil {
		return err
	}
	return checkValues("base", r.Base, t3512, guard, mr, implicit)
}

func (w *tcWorld) persistedFalse() error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.body, &raw); err != nil {
		return fmt.Errorf("response is not JSON: %v; body=%s", err, w.body)
	}
	p, ok := raw["persisted"]
	if !ok || strings.TrimSpace(string(p)) != "false" {
		return fmt.Errorf("persisted = %s (present %v), want false", p, ok)
	}
	return nil
}

func (w *tcWorld) effectiveEqualsBase() error {
	if w.store == nil {
		return fmt.Errorf("timer store not initialised")
	}
	if e, b := w.store.Effective(), w.store.Base(); e != b {
		return fmt.Errorf("effective %+v != base %+v: a rejected request changed the configuration", e, b)
	}
	return nil
}

func (w *tcWorld) effectiveT3512Is(n int) error {
	if got := w.store.Effective().T3512Secs; got != n {
		return fmt.Errorf("effective T3512 = %d, want %d", got, n)
	}
	return nil
}

func (w *tcWorld) problemCauseIs(cause string) error {
	var p mgmt.TimerProblem
	if err := json.Unmarshal(w.body, &p); err != nil {
		return fmt.Errorf("body is not a problem document: %v; body=%s", err, w.body)
	}
	if p.Cause != cause {
		return fmt.Errorf("problem cause = %q, want %q; body=%s", p.Cause, cause, w.body)
	}
	if p.Status != w.status {
		return fmt.Errorf("problem status = %d, want %d", p.Status, w.status)
	}
	return nil
}

// ---- Registration Accept --------------------------------------------------

// buildAccept runs the real Phase 3 of Initial Registration (the point where the
// initial REGISTRATION ACCEPT is built), with a fake UDM.
func (w *tcWorld) buildAccept() error {
	ra, err := w.reg.Phase3_ProcessSMCComplete(context.Background(), sbiW.ue)
	if err != nil {
		return fmt.Errorf("build Registration Accept: %w", err)
	}
	w.ra = ra
	return nil
}

func (w *tcWorld) buildUpdateAccept() error {
	ra, err := w.reg.BuildRegistrationUpdateAccept(context.Background(), sbiW.ue)
	if err != nil {
		return fmt.Errorf("build Registration Update Accept: %w", err)
	}
	w.ra = ra
	return nil
}

func (w *tcWorld) acceptCarries(octetHex string) error {
	if w.ra == nil {
		return fmt.Errorf("no Registration Accept was built")
	}
	if w.ra.T3512Value == nil {
		return fmt.Errorf("Registration Accept has no T3512 value IE (0x5E)")
	}
	var want byte
	if _, err := fmt.Sscanf(octetHex, "%02X", &want); err != nil {
		return fmt.Errorf("bad octet %q: %w", octetHex, err)
	}
	if *w.ra.T3512Value != want {
		return fmt.Errorf("T3512 value octet = 0x%02X, want 0x%02X", *w.ra.T3512Value, want)
	}
	// Wire check: IEI 0x5E, length 1, value (TS 24.501 §8.2.7.1 / §9.11.2.5).
	wire, err := nas.EncodeRegistrationAccept(w.ra)
	if err != nil {
		return fmt.Errorf("encode Registration Accept: %w", err)
	}
	if !bytes.Contains(wire, []byte{0x5E, 0x01, want}) {
		return fmt.Errorf("encoded Registration Accept lacks 5E 01 %02X: % X", want, wire)
	}
	return nil
}

func (w *tcWorld) sentT3512(n int) error {
	if err := w.buildAccept(); err != nil {
		return err
	}
	if got := sbiW.ue.T3512Sent(); got != n {
		return fmt.Errorf("T3512 recorded as sent to the UE = %d, want %d", got, n)
	}
	return nil
}

// ---- Timers ---------------------------------------------------------------

func (w *tcWorld) releaseCompleteToIdle() error {
	ue := sbiW.ue
	g := &amfngap.GNBContext{
		Name:    "gnb-timer-config",
		UEs:     map[int64]*amfctx.UEContext{},
		IdleUEs: map[int64]*amfctx.UEContext{},
	}
	g.SetTransportForTest(tcGNBAddr, func(pdu []byte, _ *sctp.SndRcvInfo) (int, error) { return len(pdu), nil })
	w.srv.AddGNBForTest(tcGNBAddr, g)
	w.srv.CompleteNGSetupForTest(g)

	ue.Lock()
	ranID, amfID := ue.RANUENGAPId, ue.AMFUENGAPId
	ue.GNBAddr = tcGNBAddr
	ue.CMState = amfctx.CMConnected
	ue.Unlock()
	g.UEs[ranID] = ue

	pdu, err := buildReleaseComplete(amfID, ranID)
	if err != nil {
		return err
	}
	w.srv.DispatchNGAPForTest(context.Background(), g, pdu)
	w.srv.WaitUESerialForTest(amfID)

	deadline := time.Now().Add(2 * time.Second)
	for {
		if mr, _ := ue.ArmedDurations(); mr != 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Mobile Reachable timer was not armed after the AN release")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (w *tcWorld) mobileReachableExpiresAndImplicitArmed() error {
	ue := sbiW.ue
	ue.Lock()
	ue.CMState = amfctx.CMIdle
	ue.Unlock()

	// Test-only: shorten Mobile Reachable to 1 s directly in the store (the API
	// minimum is 60 s); the Implicit Detach value stays the O&M-configured one.
	cfg := w.store.Effective()
	short := cfg
	short.T3512Secs, short.GuardSecs = 0, 1
	w.store.Set(short)
	w.srv.StartMobileReachableTimer(ue)
	w.store.Set(cfg)

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, id := ue.ArmedDurations(); id != 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Implicit Detach timer was not armed after Mobile Reachable expiry")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (w *tcWorld) implicitIs(n int) error {
	_, id := sbiW.ue.ArmedDurations()
	if id != time.Duration(n)*time.Second {
		return fmt.Errorf("armed Implicit Detach duration = %v, want %ds", id, n)
	}
	return nil
}

func (w *tcWorld) mobileReachableIs(n int) error {
	mr, _ := sbiW.ue.ArmedDurations()
	if mr != time.Duration(n)*time.Second {
		return fmt.Errorf("armed Mobile Reachable duration = %v, want %ds", mr, n)
	}
	return nil
}

func (w *tcWorld) mobileReachableIsNot(n int) error {
	mr, _ := sbiW.ue.ArmedDurations()
	if mr == time.Duration(n)*time.Second {
		return fmt.Errorf("armed Mobile Reachable duration = %v, must not be %ds", mr, n)
	}
	return nil
}

// ---- Logs -----------------------------------------------------------------

func (w *tcWorld) logLines() []map[string]any {
	var out []map[string]any
	for _, ln := range strings.Split(w.logs.String(), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func (w *tcWorld) findLog(proc, iface, dir, result string) (map[string]any, error) {
	for _, m := range w.logLines() {
		if m["procedure"] == proc && m["interface"] == iface && m["direction"] == dir &&
			m["result"] == result && m["nf"] == "AMF" {
			return m, nil
		}
	}
	return nil, fmt.Errorf("no log line with nf=AMF procedure=%q interface=%q direction=%q result=%q in:\n%s",
		proc, iface, dir, result, w.logs.String())
}

func (w *tcWorld) logsLine(proc, iface, dir, result string) error {
	m, err := w.findLog(proc, iface, dir, result)
	if err != nil {
		return err
	}
	if s, _ := m["spec_ref"].(string); s == "" {
		return fmt.Errorf("log line has no spec_ref: %v", m)
	}
	return nil
}

func (w *tcWorld) loggedCause(cause string) error {
	m, err := w.findLog("TimerConfigChange", "OAM", "IN", "REJECT")
	if err != nil {
		return err
	}
	if m["cause"] != cause {
		return fmt.Errorf("logged cause = %v, want %q", m["cause"], cause)
	}
	return nil
}

// ---- Concurrency ----------------------------------------------------------

func (w *tcWorld) concurrent() error {
	vals := []string{
		`{"t3512_secs":120}`, `{"mobile_reachable_guard_secs":30}`, `{"t3512_secs":600}`,
		`{"mobile_reachable_guard_secs":300}`, `{"implicit_detach_secs":300}`, `{"reset":true}`,
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	record := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			method, body := http.MethodGet, io.Reader(nil)
			if i%2 == 0 {
				method, body = http.MethodPut, strings.NewReader(vals[(i/2)%len(vals)])
			}
			req, err := http.NewRequest(method, w.api.URL+tcPath, body)
			if err != nil {
				record(err)
				return
			}
			resp, err := w.api.Client().Do(req)
			if err != nil {
				record(err)
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				record(fmt.Errorf("status %d: %s", resp.StatusCode, b))
				return
			}
			var r mgmt.TimerConfigResponse
			if err := json.Unmarshal(b, &r); err != nil {
				record(fmt.Errorf("decode: %v: %s", err, b))
				return
			}
			w.concMu.Lock()
			w.concResp = append(w.concResp, r)
			w.concMu.Unlock()
		}(i)
	}
	wg.Wait()
	return firstErr
}

func (w *tcWorld) everyResponseConsistent() error {
	w.concMu.Lock()
	defer w.concMu.Unlock()
	if len(w.concResp) == 0 {
		return fmt.Errorf("no concurrent responses recorded")
	}
	for i, r := range w.concResp {
		for label, v := range map[string]mgmt.TimerValues{"effective": r.Effective, "base": r.Base} {
			if v.MobileReachableSecs != v.T3512Secs+v.MobileReachableGuard {
				return fmt.Errorf("response %d %s: mobile reachable %d != T3512 %d + guard %d",
					i, label, v.MobileReachableSecs, v.T3512Secs, v.MobileReachableGuard)
			}
		}
	}
	return nil
}

// initTimerConfigSteps registers the MCP-011 steps. Called from InitializeScenario.
func initTimerConfigSteps(sc *godog.ScenarioContext) {
	w := tcW
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.teardown()
		return ctx, nil
	})

	sc.Step(`^the AMF timer configuration has base T3512 (\d+), guard (\d+) and implicit detach (\d+) seconds$`, w.baseConfig)

	sc.Step(`^O&M reads the timer configuration$`, w.read)
	sc.Step(`^O&M changes the timer configuration with body '(.*)'$`, w.put)
	sc.Step(`^O&M sends an HTTP (\w+) to the timer configuration path$`, w.method)
	sc.Step(`^O&M issues concurrent timer configuration PUTs and GETs$`, w.concurrent)

	sc.Step(`^the timer effective values are T3512 (\d+), guard (\d+), mobile reachable (\d+) and implicit detach (\d+)$`, w.effectiveIs)
	sc.Step(`^the timer base values are T3512 (\d+), guard (\d+), mobile reachable (\d+) and implicit detach (\d+)$`, w.baseIs)
	sc.Step(`^the timer response has persisted false$`, w.persistedFalse)
	sc.Step(`^the timer effective values equal the timer base values$`, w.effectiveEqualsBase)
	sc.Step(`^the timer effective T3512 is (\d+)$`, w.effectiveT3512Is)
	sc.Step(`^the timer problem cause is "([^"]+)"$`, w.problemCauseIs)
	sc.Step(`^every timer response satisfies mobile reachable equals T3512 plus guard$`, w.everyResponseConsistent)

	sc.Step(`^the AMF builds a Registration Accept$`, w.buildAccept)
	sc.Step(`^the AMF builds a Registration Update Accept$`, w.buildUpdateAccept)
	sc.Step(`^the Registration Accept carries the T3512 value IE 0x5E with GPRS timer 3 octet 0x([0-9A-Fa-f]{2})$`, w.acceptCarries)
	sc.Step(`^the AMF sent the UE a Registration Accept with T3512 (\d+) seconds$`, w.sentT3512)

	sc.Step(`^the UE Mobile Reachable timer expires and the Implicit Detach timer is armed$`, w.mobileReachableExpiresAndImplicitArmed)
	sc.Step(`^the UE becomes CM-IDLE after an AN release$`, w.releaseCompleteToIdle)
	sc.Step(`^the armed Implicit Detach duration is (\d+) seconds$`, w.implicitIs)
	sc.Step(`^the armed Mobile Reachable duration is (\d+) seconds$`, w.mobileReachableIs)
	sc.Step(`^the armed Mobile Reachable duration of the UE is still (\d+) seconds$`, w.mobileReachableIs)
	sc.Step(`^the armed Mobile Reachable duration is not (\d+) seconds$`, w.mobileReachableIsNot)

	sc.Step(`^the AMF logs a line with procedure "([^"]+)", interface "([^"]+)", direction "([^"]+)" and result "([^"]+)"$`, w.logsLine)
	sc.Step(`^the logged cause is "([^"]+)"$`, w.loggedCause)
}
