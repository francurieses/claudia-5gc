package mgmt

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/timercfg"
)

func newTimerMux() (*http.ServeMux, *timercfg.Store) {
	st := timercfg.New(timercfg.Values{T3512Secs: 60, GuardSecs: 120, ImplicitDetachSecs: 60})
	mux := http.NewServeMux()
	RegisterTimerConfig(mux, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return mux, st
}

func doTimer(mux *http.ServeMux, method, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, timerConfigPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestTimerConfigGet(t *testing.T) {
	mux, _ := newTimerMux()
	rec := doTimer(mux, http.MethodGet, "")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var r TimerConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	want := TimerValues{T3512Secs: 60, MobileReachableGuard: 120, MobileReachableSecs: 180, ImplicitDetachSecs: 60,
		T3550Secs: 6, T3560Secs: 6, T3570Secs: 6} // TS 24.501 §10.2 Table 10.2.2 defaults
	if r.Effective != want || r.Base != want || r.Persisted {
		t.Fatalf("unexpected response %+v", r)
	}
}

func TestTimerConfigPutCauses(t *testing.T) {
	tests := []struct {
		name, body, cause string
	}{
		{"t3512 low", `{"t3512_secs":59}`, "T3512_OUT_OF_RANGE"},
		{"t3512 high", `{"t3512_secs":86401}`, "T3512_OUT_OF_RANGE"},
		{"not representable 61", `{"t3512_secs":61}`, "T3512_NOT_REPRESENTABLE"},
		{"not representable 2000", `{"t3512_secs":2000}`, "T3512_NOT_REPRESENTABLE"},
		{"not representable 3240", `{"t3512_secs":3240}`, "T3512_NOT_REPRESENTABLE"},
		{"guard high", `{"mobile_reachable_guard_secs":3601}`, "GUARD_OUT_OF_RANGE"},
		{"guard negative", `{"mobile_reachable_guard_secs":-1}`, "GUARD_OUT_OF_RANGE"},
		{"implicit low", `{"implicit_detach_secs":59}`, "IMPLICIT_DETACH_OUT_OF_RANGE"},
		{"implicit high", `{"implicit_detach_secs":86401}`, "IMPLICIT_DETACH_OUT_OF_RANGE"},
		{"t3550 low", `{"t3550_secs":0}`, "T3550_OUT_OF_RANGE"},
		{"t3550 high", `{"t3550_secs":61}`, "T3550_OUT_OF_RANGE"},
		{"t3560 low", `{"t3560_secs":0}`, "T3560_OUT_OF_RANGE"},
		{"t3560 high", `{"t3560_secs":61}`, "T3560_OUT_OF_RANGE"},
		{"t3570 low", `{"t3570_secs":-5}`, "T3570_OUT_OF_RANGE"},
		{"t3570 high", `{"t3570_secs":61}`, "T3570_OUT_OF_RANGE"},
		{"all or nothing", `{"t3512_secs":120,"implicit_detach_secs":59}`, "IMPLICIT_DETACH_OUT_OF_RANGE"},
		{"derived field", `{"mobile_reachable_secs":500}`, "READ_ONLY_FIELD"},
		{"unknown field", `{"t3512":120}`, "UNKNOWN_FIELD"},
		{"malformed", `{"t3512_secs":`, "MALFORMED_REQUEST"},
		{"string value", `{"t3512_secs":"120"}`, "MALFORMED_REQUEST"},
		{"float value", `{"t3512_secs":120.5}`, "MALFORMED_REQUEST"},
		{"null value", `{"t3512_secs":null}`, "MALFORMED_REQUEST"},
		{"trailing data", `{"t3512_secs":120}{}`, "MALFORMED_REQUEST"},
		{"reset exclusive", `{"reset":true,"t3512_secs":300}`, "RESET_EXCLUSIVE"},
		{"empty", ``, "NO_CHANGE"},
		{"empty object", `{}`, "NO_CHANGE"},
		{"reset false", `{"reset":false}`, "NO_CHANGE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux, st := newTimerMux()
			base := st.Effective()
			rec := doTimer(mux, http.MethodPut, tc.body)
			if rec.Code != 400 {
				t.Fatalf("status %d, want 400", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != problemContentType {
				t.Fatalf("content-type %q", ct)
			}
			var p TimerProblem
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if p.Cause != tc.cause || p.Status != 400 || p.Title == "" || p.Detail == "" {
				t.Fatalf("problem = %+v, want cause %s", p, tc.cause)
			}
			if st.Effective() != base {
				t.Fatalf("state changed on reject: %+v", st.Effective())
			}
		})
	}
}

func TestTimerConfigNotRepresentableDetailNamesNeighbours(t *testing.T) {
	mux, _ := newTimerMux()
	rec := doTimer(mux, http.MethodPut, `{"t3512_secs":3240}`)
	var p TimerProblem
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if !strings.Contains(p.Detail, "lower 3000") || !strings.Contains(p.Detail, "higher 3600") {
		t.Fatalf("detail %q", p.Detail)
	}
}

func TestTimerConfigPutAccepted(t *testing.T) {
	for _, v := range []int{60, 120, 600, 3600, 86400} {
		mux, st := newTimerMux()
		rec := doTimer(mux, http.MethodPut, `{"t3512_secs":`+itoa(v)+`}`)
		if rec.Code != 200 || st.Effective().T3512Secs != v {
			t.Fatalf("t3512 %d: status %d eff %+v", v, rec.Code, st.Effective())
		}
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestTimerConfigPartialAndReset(t *testing.T) {
	mux, st := newTimerMux()
	doTimer(mux, http.MethodPut, `{"t3512_secs":120}`)
	rec := doTimer(mux, http.MethodPut, `{"mobile_reachable_guard_secs":30}`)
	var r TimerConfigResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if r.Effective.T3512Secs != 120 || r.Effective.MobileReachableGuard != 30 || r.Effective.MobileReachableSecs != 150 || r.Effective.ImplicitDetachSecs != 60 {
		t.Fatalf("partial update: %+v", r.Effective)
	}
	if r.Base.T3512Secs != 60 || r.Persisted {
		t.Fatalf("base/persisted wrong: %+v", r)
	}
	rec = doTimer(mux, http.MethodPut, `{"mobile_reachable_guard_secs":0}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if r.Effective.MobileReachableSecs != 120 {
		t.Fatalf("guard 0: %+v", r.Effective)
	}
	doTimer(mux, http.MethodPut, `{"implicit_detach_secs":300}`)
	rec = doTimer(mux, http.MethodPut, `{"reset":true}`)
	if rec.Code != 200 || st.Effective() != st.Base() {
		t.Fatalf("reset: %d %+v", rec.Code, st.Effective())
	}
}

func TestTimerConfigMethodNotAllowed(t *testing.T) {
	mux, _ := newTimerMux()
	for _, m := range []string{http.MethodDelete, http.MethodPost, http.MethodPatch} {
		rec := doTimer(mux, m, "")
		if rec.Code != 405 || rec.Header().Get("Allow") != "GET, PUT" {
			t.Fatalf("%s: %d allow=%q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

func TestTimerConfigBodyTooLarge(t *testing.T) {
	mux, _ := newTimerMux()
	rec := doTimer(mux, http.MethodPut, `{"t3512_secs":120,"x":"`+strings.Repeat("a", timerConfigMaxBody)+`"}`)
	if rec.Code != 400 {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestTimerConfigConcurrentInvariant(t *testing.T) {
	mux, _ := newTimerMux()
	var wg sync.WaitGroup
	bodies := []string{`{"t3512_secs":120}`, `{"mobile_reachable_guard_secs":30}`, `{"t3512_secs":600,"mobile_reachable_guard_secs":10}`, `{"reset":true}`}
	errs := make(chan string, 400)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				var rec *httptest.ResponseRecorder
				if (i+j)%2 == 0 {
					rec = doTimer(mux, http.MethodPut, bodies[(i+j)%len(bodies)])
				} else {
					rec = doTimer(mux, http.MethodGet, "")
				}
				var r TimerConfigResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
					errs <- err.Error()
					return
				}
				if r.Effective.MobileReachableSecs != r.Effective.T3512Secs+r.Effective.MobileReachableGuard {
					errs <- "invariant broken"
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func TestTimerConfigCanonicalLog(t *testing.T) {
	var buf strings.Builder
	st := timercfg.New(timercfg.Values{T3512Secs: 60, GuardSecs: 120, ImplicitDetachSecs: 60})
	mux := http.NewServeMux()
	RegisterTimerConfig(mux, st, slog.New(slog.NewJSONHandler(&buf, nil)).With("nf", "AMF"))
	doTimer(mux, http.MethodPut, `{"t3512_secs":120}`)
	doTimer(mux, http.MethodPut, `{"t3512_secs":59}`)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("log lines: %v", lines)
	}
	for i, want := range []struct{ result, cause string }{{"OK", ""}, {"REJECT", "T3512_OUT_OF_RANGE"}} {
		var m map[string]any
		_ = json.Unmarshal([]byte(lines[i]), &m)
		if m["procedure"] != "TimerConfigChange" || m["interface"] != "OAM" || m["direction"] != "IN" ||
			m["result"] != want.result || m["nf"] != "AMF" || m["spec_ref"] == nil {
			t.Fatalf("line %d: %v", i, m)
		}
		if want.cause != "" && m["cause"] != want.cause {
			t.Fatalf("cause: %v", m["cause"])
		}
	}
}

// TestTimerConfigNASTimers: T3550/T3560/T3570 are readable, settable and reset
// to the base (TS 24.501 §10.2 Table 10.2.2 default 6 s when unset).
func TestTimerConfigNASTimers(t *testing.T) {
	mux, st := newTimerMux()
	rec := doTimer(mux, http.MethodPut, `{"t3550_secs":10,"t3560_secs":8,"t3570_secs":4}`)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var r TimerConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Effective.T3550Secs != 10 || r.Effective.T3560Secs != 8 || r.Effective.T3570Secs != 4 ||
		r.Base.T3550Secs != 6 || r.Base.T3560Secs != 6 || r.Base.T3570Secs != 6 {
		t.Fatalf("response %+v", r)
	}
	if v := st.Effective(); v.T3560().Seconds() != 8 || v.T3512Secs != 60 {
		t.Fatalf("store %+v", v)
	}
	if rec := doTimer(mux, http.MethodPut, `{"reset":true}`); rec.Code != 200 {
		t.Fatalf("reset status %d", rec.Code)
	}
	if v := st.Effective(); v.T3550().Seconds() != 6 || v.T3560().Seconds() != 6 || v.T3570().Seconds() != 6 {
		t.Fatalf("after reset %+v", v)
	}
}
