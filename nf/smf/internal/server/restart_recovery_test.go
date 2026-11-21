package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// orphanAMF is an AMF management mock with per-path scripted status codes.
type orphanAMF struct {
	mu     sync.Mutex
	script map[string][]int // path -> statuses in order; last one repeats
	calls  []string         // "path?query"
	times  map[string][]time.Time
	srv    *httptest.Server
}

func newOrphanAMF(t *testing.T, script map[string][]int) *orphanAMF {
	t.Helper()
	a := &orphanAMF{script: script, times: map[string][]time.Time{}}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.calls = append(a.calls, r.URL.Path+"?"+r.URL.RawQuery)
		a.times[r.URL.Path] = append(a.times[r.URL.Path], time.Now())
		seq := a.script[r.URL.Path]
		st := http.StatusAccepted
		if n := len(a.times[r.URL.Path]); len(seq) > 0 {
			st = seq[min(n, len(seq))-1]
		}
		a.mu.Unlock()
		w.WriteHeader(st)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// callsSnapshot returns a copy of the recorded calls under the mutex.
func (a *orphanAMF) callsSnapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

func (a *orphanAMF) host() string { return strings.TrimPrefix(a.srv.URL, "http://") }

func (a *orphanAMF) count(path string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.times[path])
}

const (
	orphPath1 = "/amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/1"
	orphPath2 = "/amf/v1/ue-contexts/imsi-001010000000002/pdu-sessions/2"
)

func orphanEnv(t *testing.T, script map[string][]int) (*nodeTestEnv, *orphanAMF) {
	t.Helper()
	e := newNodeEnv(t, rtsT1, http.StatusAccepted)
	amf := newOrphanAMF(t, script)
	e.s.cfg.Peers.AMFMgmt = amf.host()
	WithOrphanReleaseRetry(3, 20*time.Millisecond, 80*time.Millisecond)(e.s)
	e.s.orphanedByRestart = []restartOrphan{
		{supi: "imsi-001010000000001", psi: 1}, {supi: "imsi-001010000000002", psi: 2}}
	return e, amf
}

func TestOrphanRelease_Cause39AndSummary(t *testing.T) {
	tests := []struct {
		name                              string
		script                            map[string][]int
		calls1, released, already, failed int
		wantCause                         string
	}{
		{"both 202", nil, 1, 2, 0, 0, ""},
		{"503 then 202 retried", map[string][]int{orphPath1: {503, 202}}, 2, 2, 0, 0, ""},
		{"404 already released, no retry", map[string][]int{orphPath1: {404}}, 1, 1, 1, 0, causeAlreadyReleased},
		{"503 forever exhausts", map[string][]int{orphPath1: {503}, orphPath2: {503}}, 3, 0, 0, 2, causeAMFReleaseFailed},
		{"400 not retried", map[string][]int{orphPath1: {400}}, 1, 1, 0, 1, causeAMFReleaseFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, amf := orphanEnv(t, tc.script)
			e.s.releaseOrphansOfPreviousRun(context.Background())
			e.s.WaitOrphanRelease()
			if got := amf.count(orphPath1); got != tc.calls1 {
				t.Errorf("calls for PSI 1 = %d, want %d", got, tc.calls1)
			}
			for _, c := range amf.callsSnapshot() {
				if !strings.HasSuffix(c, "?cause=39") {
					t.Errorf("call %q lacks cause=39", c)
				}
			}
			e.logs.mu.Lock()
			logs := e.logs.b.String()
			e.logs.mu.Unlock()
			for _, w := range []string{`"procedure":"SmfRestartRecovery"`, `"spec_ref":"TS 23.527 §4.4.2"`} {
				if !strings.Contains(logs, w) {
					t.Errorf("logs miss %s", w)
				}
			}
			if tc.wantCause != "" && !strings.Contains(logs, `"cause":"`+tc.wantCause+`"`) {
				t.Errorf("logs miss cause %s", tc.wantCause)
			}
			var summary map[string]any
			for _, l := range strings.Split(logs, "\n") {
				if strings.Contains(l, "release finished") {
					if err := json.Unmarshal([]byte(l), &summary); err != nil {
						t.Fatal(err)
					}
				}
			}
			if summary == nil || summary["orphans"] != float64(2) || summary["released"] != float64(tc.released) ||
				summary["already_released"] != float64(tc.already) || summary["failed"] != float64(tc.failed) {
				t.Errorf("summary = %v", summary)
			}
		})
	}
}

func TestOrphanRelease_RetryWaitsBackoff(t *testing.T) {
	e, amf := orphanEnv(t, map[string][]int{orphPath1: {503, 202}})
	e.s.releaseOrphansOfPreviousRun(context.Background())
	e.s.WaitOrphanRelease()
	ts := amf.times[orphPath1]
	if len(ts) != 2 || ts[1].Sub(ts[0]) < 20*time.Millisecond {
		t.Errorf("second try not after backoff: %v", ts)
	}
}

func TestOrphanRelease_StopsOnContextCancel(t *testing.T) {
	e, _ := orphanEnv(t, map[string][]int{orphPath1: {503}, orphPath2: {503}})
	WithOrphanReleaseRetry(100, time.Hour, time.Hour)(e.s)
	ctx, cancel := context.WithCancel(context.Background())
	e.s.releaseOrphansOfPreviousRun(ctx)
	cancel()
	done := make(chan struct{})
	go func() { e.s.WaitOrphanRelease(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("orphan release goroutine leaked after ctx cancel")
	}
}

func TestOrphanRelease_OnlyAfterFirstAssociationResponse(t *testing.T) {
	e, amf := orphanEnv(t, nil)
	e.upf.set(func() { e.upf.dropAssoc = 1000 })
	e.startSupervisor(t)
	// Bounded negative poll: no release call may appear while the gate is shut.
	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if n := len(amf.callsSnapshot()); n != 0 {
			t.Fatalf("%d release calls before association", n)
		}
	}
	e.upf.set(func() { e.upf.dropAssoc = 0 })
	eventually(t, 5*time.Second, "orphans released", func() bool {
		return amf.count(orphPath1) == 1 && amf.count(orphPath2) == 1
	})
}

func TestRequestAMFRelease_CauseAnd404(t *testing.T) {
	e, amf := orphanEnv(t, map[string][]int{orphPath1: {404}})
	if err := e.s.requestAMFRelease(context.Background(), "imsi-001010000000001", 1, amfReleaseCause36); err != nil {
		t.Logf("404 is an error for non-orphan callers: %v", err)
	} else {
		t.Fatal("404 must stay an error for non-orphan callers")
	}
	if c := amf.callsSnapshot(); len(c) != 1 || c[0] != orphPath1+"?cause=36" {
		t.Errorf("calls = %q", c)
	}
}

func gateRequest(t *testing.T, e *nodeTestEnv) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"supi": "imsi-001010000000003", "pduSessionId": 5,
		"n1SmMsg": base64.StdEncoding.EncodeToString([]byte{0x2E, 0x05, 0x01, 0xC1})})
	rec := httptest.NewRecorder()
	var req map[string]any
	_ = json.Unmarshal(body, &req)
	e.s.passAssociationGate(context.Background(), e.s.logger, rec, req, "corr")
	return rec
}

func TestAssocGate_RejectsAfterTimeoutWith5GSMCause26(t *testing.T) {
	e := newNodeEnv(t, rtsT1, http.StatusAccepted)
	e.s.assocGateActive.Store(true)
	WithAssocGateTimeout(50 * time.Millisecond)(e.s)
	start := time.Now()
	rec := gateRequest(t, e)
	if time.Since(start) < 50*time.Millisecond {
		t.Error("gate did not wait")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	var out struct {
		N1 string `json:"n1SmMsg"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	n1, _ := base64.StdEncoding.DecodeString(out.N1)
	want := []byte{0x2E, 0x05, 0x01, 0xC3, 26}
	if string(n1) != string(want) {
		t.Errorf("n1SmMsg = %x, want %x", n1, want)
	}
}

func TestAssocGate_ProceedsOnceAssociated(t *testing.T) {
	e := newNodeEnv(t, rtsT1, http.StatusAccepted)
	e.s.assocGateActive.Store(true)
	WithAssocGateTimeout(5 * time.Second)(e.s)
	go func() { time.Sleep(50 * time.Millisecond); e.s.firstAssocOnce.Do(func() { close(e.s.firstAssoc) }) }()
	rec := gateRequest(t, e)
	if rec.Body.Len() != 0 {
		t.Errorf("gate wrote a reject: %s", rec.Body.String())
	}
}

func TestAssocGate_InactiveWithoutSupervisor(t *testing.T) {
	e := newNodeEnv(t, rtsT1, http.StatusAccepted)
	if rec := gateRequest(t, e); rec.Body.Len() != 0 {
		t.Error("gate must be inactive without a supervisor")
	}
}
