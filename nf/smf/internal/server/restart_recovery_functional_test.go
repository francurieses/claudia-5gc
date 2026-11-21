//go:build functional

// godog step definitions for smf_restart_recovery.feature (SMF-012): release of
// the PDU sessions persisted by a previous SMF run with 5GSM cause #39 after
// the first PFCP Association Setup, and the CreateSMContext association gate.
// Refs: TS 23.527 §4.4.2; TS 29.244 §6.2.6.2.2; TS 23.502 §4.3.4.2;
// TS 24.501 §6.3.3.3, §9.11.4.2.
//
// In-process: a scriptable fake UPF on a loopback UDP socket, an httptest AMF
// management API with per-path scripted statuses, a fake persisted store, and
// short retry / gate timers. Every scenario builds a fresh world (Before) and
// tears it down (After); asynchronous effects are polled with a deadline.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/smf/internal/store"
)

const (
	rrDeadline       = 10 * time.Second
	rrMaxAttempts    = 3
	rrBackoffInitial = 20 * time.Millisecond
	rrBackoffMax     = 80 * time.Millisecond
	rrGateTimeout    = 1500 * time.Millisecond
)

// ---- fake persisted store ---------------------------------------------------

type rrStore struct {
	mu      sync.Mutex
	records map[string]*store.SessionRecord
	deleted []string
}

func (s *rrStore) UpsertSession(context.Context, string, *store.SessionRecord) error { return nil }
func (s *rrStore) DeleteSession(_ context.Context, ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, ref)
	return nil
}
func (s *rrStore) ListSessions(context.Context) (map[string]*store.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*store.SessionRecord, len(s.records))
	for k, v := range s.records {
		c := *v
		out[k] = &c
	}
	return out, nil
}
func (s *rrStore) MaxCounters(context.Context) (uint64, uint32, error) { return 0, 0, nil }
func (s *rrStore) Close()                                              {}

// ---- fake UPF ---------------------------------------------------------------

type rrUPFMsg struct {
	typ    uint8
	at     time.Time
	cpSEID uint64
}

// rrUPF answers Association Setup only once released (hold gate), always
// answers Heartbeat and Session Establishment / Deletion.
type rrUPF struct {
	conn *net.UDPConn
	done chan struct{}
	rts  time.Time

	mu          sync.Mutex
	hold        bool
	answerCause uint8
	got         []rrUPFMsg
	releasedAt  time.Time
}

func newRRUPF() (*rrUPF, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("listen fake UPF: %w", err)
	}
	u := &rrUPF{conn: conn, done: make(chan struct{}), hold: true,
		rts: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC), answerCause: pfcpie.CauseRequestAccepted}
	go u.loop()
	return u, nil
}

func (u *rrUPF) addr() string { return u.conn.LocalAddr().String() }

func (u *rrUPF) close() {
	_ = u.conn.Close()
	<-u.done
}

func (u *rrUPF) loop() {
	defer close(u.done)
	buf := make([]byte, 4096)
	for {
		n, raddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg, err := pfcpmsg.Parse(append([]byte(nil), buf[:n]...))
		if err != nil {
			continue
		}
		rec := rrUPFMsg{typ: msg.MessageType(), at: time.Now()}
		var reply pfcpmsg.Message
		u.mu.Lock()
		switch m := msg.(type) {
		case *pfcpmsg.AssociationSetupRequest:
			if !u.hold {
				reply = pfcpmsg.NewAssociationSetupResponse(m.Sequence(),
					pfcpie.NewNodeID("", "", "upf"), pfcpie.NewCause(u.answerCause),
					pfcpie.NewRecoveryTimeStamp(u.rts))
			}
		case *pfcpmsg.HeartbeatRequest:
			reply = pfcpmsg.NewHeartbeatResponse(m.Sequence(), pfcpie.NewRecoveryTimeStamp(u.rts))
		case *pfcpmsg.SessionEstablishmentRequest:
			if m.CPFSEID != nil {
				if f, ferr := m.CPFSEID.FSEID(); ferr == nil {
					rec.cpSEID = f.SEID
				}
			}
			reply = pfcpmsg.NewSessionEstablishmentResponse(0, 0, rec.cpSEID, m.Sequence(), 0,
				pfcpie.NewCause(pfcpie.CauseRequestAccepted))
		case *pfcpmsg.SessionDeletionRequest:
			reply = pfcpmsg.NewSessionDeletionResponse(0, 0, m.SEID(), m.Sequence(), 0,
				pfcpie.NewCause(pfcpie.CauseRequestAccepted))
		}
		u.got = append(u.got, rec)
		u.mu.Unlock()
		if reply != nil {
			b := make([]byte, reply.MarshalLen())
			if reply.MarshalTo(b) == nil {
				_, _ = u.conn.WriteToUDP(b, raddr)
			}
		}
	}
}

func (u *rrUPF) count(typ uint8) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, m := range u.got {
		if m.typ == typ {
			n++
		}
	}
	return n
}

func (u *rrUPF) msgs(typ uint8) []rrUPFMsg {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []rrUPFMsg
	for _, m := range u.got {
		if m.typ == typ {
			out = append(out, m)
		}
	}
	return out
}

// release lets the UPF answer Association Setup Requests from now on.
func (u *rrUPF) release() time.Time {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.hold = false
	u.releasedAt = time.Now()
	return u.releasedAt
}

// ---- fake AMF management API -------------------------------------------------

type rrAMFCall struct {
	method, path, rawQuery string
	at                     time.Time
}

type rrAMF struct {
	srv *httptest.Server

	mu            sync.Mutex
	defaultStatus int
	script        map[string][]int // path -> statuses in order; last one repeats
	calls         []rrAMFCall
}

func newRRAMF() *rrAMF {
	a := &rrAMF{defaultStatus: http.StatusAccepted, script: map[string][]int{}}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.calls = append(a.calls, rrAMFCall{r.Method, r.URL.Path, r.URL.RawQuery, time.Now()})
		n := 0
		for _, c := range a.calls {
			if c.path == r.URL.Path {
				n++
			}
		}
		st := a.defaultStatus
		if seq := a.script[r.URL.Path]; len(seq) > 0 {
			st = seq[min(n, len(seq))-1]
		}
		a.mu.Unlock()
		w.WriteHeader(st)
	}))
	return a
}

func (a *rrAMF) host() string { return strings.TrimPrefix(a.srv.URL, "http://") }

func (a *rrAMF) setScript(path string, statuses ...int) {
	a.mu.Lock()
	a.script[path] = statuses
	a.mu.Unlock()
}

func (a *rrAMF) setDefault(st int) {
	a.mu.Lock()
	a.defaultStatus = st
	a.mu.Unlock()
}

func (a *rrAMF) forPath(path string) []rrAMFCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []rrAMFCall
	for _, c := range a.calls {
		if c.path == path {
			out = append(out, c)
		}
	}
	return out
}

func (a *rrAMF) total() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.calls)
}

// ---- world -------------------------------------------------------------------

type rrCreateResult struct {
	code int
	body []byte
}

type rrWorld struct {
	upf   *rrUPF
	amf   *rrAMF
	st    *rrStore
	logs  *lockedBuf
	s     *Server
	paths [2]string // AMF paths of the two persisted sessions

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	createStart  time.Time
	createDone   chan rrCreateResult
	createResult *rrCreateResult
	createSUPI   string
	createPSI    int
}

func (w *rrWorld) reset() {
	w.teardown()
	*w = rrWorld{}
	w.ctx, w.cancel = context.WithCancel(context.Background())
}

func (w *rrWorld) teardown() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
	if w.createDone != nil && w.createResult == nil {
		select {
		case <-w.createDone:
		case <-time.After(rrDeadline):
		}
	}
	if w.s != nil {
		w.s.WaitOrphanRelease()
		w.s.WaitPFCPRelease()
	}
	if w.upf != nil {
		w.upf.close()
	}
	if w.amf != nil {
		w.amf.srv.Close()
	}
}

func rrPoll(what string, cond func() bool) error {
	deadline := time.Now().Add(rrDeadline)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s waiting for %s", rrDeadline, what)
}

func rrAMFPath(supi string, psi int) string {
	return fmt.Sprintf("/amf/v1/ue-contexts/%s/pdu-sessions/%d", supi, psi)
}

// ---- Background ---------------------------------------------------------------

func (w *rrWorld) fakeUPFListening() error {
	u, err := newRRUPF()
	if err != nil {
		return err
	}
	w.upf = u
	return nil
}

func (w *rrWorld) fakeAMFRecording() error {
	w.amf = newRRAMF()
	return nil
}

func (w *rrWorld) storeHolds(supi1 string, psi1 int, supi2 string, psi2 int) error {
	if w.upf == nil || w.amf == nil {
		return fmt.Errorf("fake UPF and AMF must be started first")
	}
	w.st = &rrStore{records: map[string]*store.SessionRecord{
		"ref-1": {SUPI: supi1, PSI: uint8(psi1), DNN: "internet", UEIP: "10.60.0.1", SEID: 1, SST: 1, SD: "000001"},
		"ref-2": {SUPI: supi2, PSI: uint8(psi2), DNN: "internet", UEIP: "10.60.0.2", SEID: 2, SST: 1, SD: "000001"},
	}}
	w.paths = [2]string{rrAMFPath(supi1, psi1), rrAMFPath(supi2, psi2)}
	w.logs = &lockedBuf{}
	cfg := &config.Config{
		UEIPPool:  "10.60.0.0/24",
		UPFN3Addr: "192.0.2.10",
		DNNs:      []config.DNNConfig{{Name: "internet", UEIPPool: "10.60.0.0/24"}},
	}
	cfg.Peers.UPF = w.upf.addr()
	cfg.Peers.AMFMgmt = w.amf.host()
	s, err := New(cfg, slog.New(slog.NewJSONHandler(w.logs, &slog.HandlerOptions{Level: slog.LevelDebug})), w.st)
	if err != nil {
		return fmt.Errorf("new SMF server: %w", err)
	}
	w.s = s
	return nil
}

func (w *rrWorld) timersShort() error {
	if w.s == nil {
		return fmt.Errorf("SMF not built")
	}
	w.s.pfcpTimers = pfcpNodeTimers{
		heartbeatInterval: 100 * time.Millisecond,
		t1:                100 * time.Millisecond,
		n1:                1,
		assocRetryInitial: 50 * time.Millisecond,
		assocRetryMax:     200 * time.Millisecond,
	}
	WithOrphanReleaseRetry(rrMaxAttempts, rrBackoffInitial, rrBackoffMax)(w.s)
	WithAssocGateTimeout(rrGateTimeout)(w.s)
	return nil
}

// ---- AMF scripting --------------------------------------------------------------

func (w *rrWorld) amfDefault(status int) error {
	w.amf.setDefault(status)
	return nil
}

func (w *rrWorld) amfThen(first, second, psi int, supi string) error {
	w.amf.setScript(rrAMFPath(supi, psi), first, second)
	return nil
}

func (w *rrWorld) amfAccepts(supi string, psi, status int) error {
	w.amf.setScript(rrAMFPath(supi, psi), status)
	return nil
}

func (w *rrWorld) amfAnswers(status, psi int, supi string) error {
	w.amf.setScript(rrAMFPath(supi, psi), status)
	return nil
}

// ---- start ------------------------------------------------------------------------

func (w *rrWorld) smfStarted() error {
	if w.s == nil {
		return fmt.Errorf("SMF not built")
	}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.s.RunPFCPNodeSupervisor(w.ctx)
	}()
	return nil
}

func (w *rrWorld) smfStartedAndAssociated() error {
	w.upf.release()
	if err := w.smfStarted(); err != nil {
		return err
	}
	return rrPoll("PFCP association ASSOCIATED", func() bool {
		return w.s.PFCPAssociation().State == assocAssociated
	})
}

// ---- UPF expectations ---------------------------------------------------------------

func (w *rrWorld) upfReceivesAssocRequest() error {
	return rrPoll("PFCP Association Setup Request at the fake UPF", func() bool {
		return w.upf.count(pfcpmsg.MsgTypeAssociationSetupRequest) >= 1
	})
}

// settleHeld waits until the SMF has retransmitted the held Association Setup
// Request (two requests seen), i.e. real time passed with the UPF silent.
func (w *rrWorld) settleHeld() error {
	return rrPoll("a retransmitted PFCP Association Setup Request", func() bool {
		return w.upf.count(pfcpmsg.MsgTypeAssociationSetupRequest) >= 2
	})
}

func (w *rrWorld) noReleaseBeforeAnswer(cause string) error {
	if cause != "Request accepted" {
		return fmt.Errorf("unsupported Cause %q", cause)
	}
	if err := w.settleHeld(); err != nil {
		return err
	}
	if n := w.amf.total(); n != 0 {
		return fmt.Errorf("%d release request(s) reached the AMF before the Association Setup Response", n)
	}
	w.upf.mu.Lock()
	w.upf.answerCause = pfcpie.CauseRequestAccepted
	w.upf.mu.Unlock()
	releasedAt := w.upf.release()
	if err := rrPoll("PFCP association ASSOCIATED", func() bool {
		return w.s.PFCPAssociation().State == assocAssociated
	}); err != nil {
		return err
	}
	if err := rrPoll("both releases", func() bool {
		return len(w.amf.forPath(w.paths[0])) >= 1 && len(w.amf.forPath(w.paths[1])) >= 1
	}); err != nil {
		return err
	}
	for _, p := range w.paths {
		for _, c := range w.amf.forPath(p) {
			if c.at.Before(releasedAt) {
				return fmt.Errorf("release request for %s sent before the Association Setup Response", p)
			}
		}
	}
	return nil
}

// ---- AMF expectations ---------------------------------------------------------------

func (w *rrWorld) amfReceivesDelete(path, query string) error {
	if err := rrPoll("DELETE "+path, func() bool { return len(w.amf.forPath(path)) >= 1 }); err != nil {
		return err
	}
	c := w.amf.forPath(path)[0]
	if c.method != http.MethodDelete {
		return fmt.Errorf("%s: method %s, want DELETE", path, c.method)
	}
	if c.rawQuery != query {
		return fmt.Errorf("%s: query %q, want %q", path, c.rawQuery, query)
	}
	return nil
}

func (w *rrWorld) amfReceivesNDeletes(n int, query, supi string, psi int) error {
	path := rrAMFPath(supi, psi)
	if err := rrPoll(fmt.Sprintf("%d DELETEs on %s", n, path), func() bool { return len(w.amf.forPath(path)) >= n }); err != nil {
		return err
	}
	if err := w.settleOrphanRelease(); err != nil {
		return err
	}
	calls := w.amf.forPath(path)
	if len(calls) != n {
		return fmt.Errorf("%s: %d DELETE requests, want %d", path, len(calls), n)
	}
	for _, c := range calls {
		if c.method != http.MethodDelete || c.rawQuery != query {
			return fmt.Errorf("%s: %s ?%s, want DELETE ?%s", path, c.method, c.rawQuery, query)
		}
	}
	return nil
}

func (w *rrWorld) amfExactlyNDelete(n int, supi string, psi int) error {
	path := rrAMFPath(supi, psi)
	if err := rrPoll("a DELETE on "+path, func() bool { return len(w.amf.forPath(path)) >= 1 }); err != nil {
		return err
	}
	if err := w.settleOrphanRelease(); err != nil {
		return err
	}
	if got := len(w.amf.forPath(path)); got != n {
		return fmt.Errorf("%s: %d DELETE requests, want exactly %d", path, got, n)
	}
	return nil
}

// settleOrphanRelease waits for the orphan release goroutine to end so that
// request counts are final (no retry can still arrive).
func (w *rrWorld) settleOrphanRelease() error {
	done := make(chan struct{})
	go func() { w.s.WaitOrphanRelease(); close(done) }()
	select {
	case <-done:
		return nil
	case <-time.After(rrDeadline):
		return fmt.Errorf("orphan release did not finish within %s", rrDeadline)
	}
}

func (w *rrWorld) secondAfterBackoff() error {
	calls := w.amf.forPath(w.paths[0])
	if len(calls) < 2 {
		return fmt.Errorf("only %d request(s) for PSI 1", len(calls))
	}
	if gap := calls[1].at.Sub(calls[0].at); gap < rrBackoffInitial {
		return fmt.Errorf("second request %s after the first, want >= retry backoff %s", gap, rrBackoffInitial)
	}
	return nil
}

func (w *rrWorld) amfMaxAttempts() error {
	if err := w.settleOrphanRelease(); err != nil {
		return err
	}
	for _, p := range w.paths {
		calls := w.amf.forPath(p)
		if len(calls) != rrMaxAttempts {
			return fmt.Errorf("%s: %d DELETE requests, want the configured maximum %d", p, len(calls), rrMaxAttempts)
		}
		for _, c := range calls {
			if c.rawQuery != "cause=39" {
				return fmt.Errorf("%s: query %q, want cause=39", p, c.rawQuery)
			}
		}
	}
	return nil
}

// ---- logs -----------------------------------------------------------------------------

func (w *rrWorld) logsProcResultSpec(proc, result, spec string) error {
	return rrPoll("log "+proc+" "+result+" "+spec, func() bool {
		return w.logs.has(map[string]any{"procedure": proc, "result": result, "spec_ref": spec})
	})
}

func (w *rrWorld) logsResultCauseFor(result, cause, supi string) error {
	return rrPoll("log "+result+"/"+cause+" for "+supi, func() bool {
		return w.logs.has(map[string]any{"procedure": procSmfRestartRecovery, "result": result, "cause": cause, "supi": supi})
	})
}

func (w *rrWorld) logsResultCause(result, cause string) error {
	return rrPoll("log "+result+"/"+cause, func() bool {
		return w.logs.has(map[string]any{"procedure": procSmfRestartRecovery, "result": result, "cause": cause})
	})
}

func (w *rrWorld) summary(orphans, released, already, failed int) error {
	want := map[string]any{"procedure": procSmfRestartRecovery, "orphans": float64(orphans),
		"released": float64(released), "already_released": float64(already), "failed": float64(failed)}
	err := rrPoll("orphan release summary", func() bool {
		for _, e := range w.logs.entries() {
			if m, _ := e["msg"].(string); strings.Contains(m, "release finished") {
				return true
			}
		}
		return false
	})
	if err != nil {
		return err
	}
	for _, e := range w.logs.entries() {
		if m, _ := e["msg"].(string); !strings.Contains(m, "release finished") {
			continue
		}
		for k, v := range want {
			if e[k] != v {
				return fmt.Errorf("summary %s = %v, want %v (entry %v)", k, e[k], v, e)
			}
		}
		return nil
	}
	return fmt.Errorf("summary log vanished")
}

func (w *rrWorld) sbiStillAnswers() error {
	h := w.s.httpSrv.Handler
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		return fmt.Errorf("GET /healthz = %d, want 200", rec.Code)
	}
	return nil
}

func (w *rrWorld) assocStateIs(state string) error {
	return rrPoll("PFCP association state "+state, func() bool { return w.s.PFCPAssociation().State == state })
}

// ---- CreateSMContext gate ----------------------------------------------------------------

func (w *rrWorld) upfDelays() error {
	w.upf.mu.Lock()
	w.upf.hold = true
	w.upf.mu.Unlock()
	return nil
}

func (w *rrWorld) createArrives(supi string, psi int) error {
	body, _ := json.Marshal(map[string]any{
		"supi": supi, "dnn": "internet", "pduSessionId": psi,
		"n1SmMsg": base64.StdEncoding.EncodeToString(buildEstablishmentRequest(uint8(psi), 1)),
		"snssai":  map[string]any{"sst": 1, "sd": "000001"},
	})
	w.createSUPI, w.createPSI = supi, psi
	w.createDone = make(chan rrCreateResult, 1)
	w.createStart = time.Now()
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01RESTARTRECOVERYGATE000000")
	rec := httptest.NewRecorder()
	go func() {
		w.s.handleCreateSMContext(rec, r)
		w.createDone <- rrCreateResult{code: rec.Code, body: rec.Body.Bytes()}
	}()
	// The request is inside the gate once the SMF logged its receipt.
	return rrPoll("CreateSMContext received", func() bool {
		for _, e := range w.logs.entries() {
			if m, _ := e["msg"].(string); m == "Nsmf_PDUSession_CreateSMContext received" {
				return true
			}
		}
		return false
	})
}

func (w *rrWorld) createResultNow() (*rrCreateResult, error) {
	if w.createResult != nil {
		return w.createResult, nil
	}
	select {
	case r := <-w.createDone:
		w.createResult = &r
		return w.createResult, nil
	case <-time.After(rrDeadline):
		return nil, fmt.Errorf("CreateSMContext did not complete within %s", rrDeadline)
	}
}

func (w *rrWorld) noEstablishmentBeforeResponse() error {
	if err := w.settleHeld(); err != nil {
		return err
	}
	if n := w.upf.count(pfcpmsg.MsgTypeSessionEstablishmentRequest); n != 0 {
		return fmt.Errorf("%d PFCP Session Establishment Request(s) before the Association Setup Response", n)
	}
	select {
	case <-w.createDone:
		return fmt.Errorf("CreateSMContext completed while the PFCP association was not established")
	default:
	}
	return nil
}

func (w *rrWorld) upfAnswersWithinGate() error {
	if elapsed := time.Since(w.createStart); elapsed >= rrGateTimeout {
		return fmt.Errorf("%s elapsed, the association gate timeout %s already expired", elapsed, rrGateTimeout)
	}
	w.upf.release()
	return nil
}

func (w *rrWorld) upfThenReceivesEstablishment(psi int) error {
	if err := rrPoll("PFCP Session Establishment Request", func() bool {
		return w.upf.count(pfcpmsg.MsgTypeSessionEstablishmentRequest) >= 1
	}); err != nil {
		return err
	}
	req := w.upf.msgs(pfcpmsg.MsgTypeSessionEstablishmentRequest)[0]
	w.s.sessionMu.Lock()
	defer w.s.sessionMu.Unlock()
	for _, sess := range w.s.sessions {
		if int(sess.PDUSessionID) == psi && sess.SEID == req.cpSEID && req.cpSEID != 0 {
			return nil
		}
	}
	return fmt.Errorf("Session Establishment Request CP F-SEID %d does not belong to a session with PSI %d", req.cpSEID, psi)
}

func (w *rrWorld) createSucceeds(status int) error {
	r, err := w.createResultNow()
	if err != nil {
		return err
	}
	if r.code != status {
		return fmt.Errorf("CreateSMContext status %d, want %d (body %s)", r.code, status, r.body)
	}
	return nil
}

func (w *rrWorld) createRejected(cause int) error {
	r, err := w.createResultNow()
	if err != nil {
		return err
	}
	if elapsed := time.Since(w.createStart); elapsed < rrGateTimeout {
		return fmt.Errorf("rejected after %s, before the association gate timeout %s", elapsed, rrGateTimeout)
	}
	if r.code < 400 {
		return fmt.Errorf("CreateSMContext status %d, want an error status (body %s)", r.code, r.body)
	}
	var out struct {
		N1 string `json:"n1SmMsg"`
	}
	if err := json.Unmarshal(r.body, &out); err != nil {
		return fmt.Errorf("decode SmContextCreateError: %w", err)
	}
	n1, err := base64.StdEncoding.DecodeString(out.N1)
	if err != nil {
		return fmt.Errorf("n1SmMsg not base64: %w", err)
	}
	// EPD 5GSM | PSI | PTI (echoed) | PDU SESSION ESTABLISHMENT REJECT (0xC3) | 5GSM cause
	want := []byte{0x2E, uint8(w.createPSI), 1, 0xC3, uint8(cause)}
	if string(n1) != string(want) {
		return fmt.Errorf("n1SmMsg = %x, want %x", n1, want)
	}
	return nil
}

func (w *rrWorld) upfNeverAnswers() error { return w.upfDelays() }

func (w *rrWorld) upfNoEstablishment() error {
	if n := w.upf.count(pfcpmsg.MsgTypeSessionEstablishmentRequest); n != 0 {
		return fmt.Errorf("%d PFCP Session Establishment Request(s) at the fake UPF, want none", n)
	}
	return nil
}

func (w *rrWorld) noSMContextStored(supi string, psi int) error {
	w.s.sessionMu.Lock()
	defer w.s.sessionMu.Unlock()
	for ref, sess := range w.s.sessions {
		if sess.SUPI == supi && int(sess.PDUSessionID) == psi {
			return fmt.Errorf("SM context %s stored for %s PSI %d", ref, supi, psi)
		}
	}
	return nil
}

// ---- registration ---------------------------------------------------------------------------

// InitializeSmfRestartRecoveryScenario registers the steps of smf_restart_recovery.feature.
func InitializeSmfRestartRecoveryScenario(ctx *godog.ScenarioContext) {
	w := &rrWorld{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return c, nil
	})
	ctx.After(func(c context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.teardown()
		return c, nil
	})

	ctx.Step(`^a fake UPF PFCP peer listening on a loopback UDP socket$`, w.fakeUPFListening)
	ctx.Step(`^a fake AMF management API recording PDU session release requests$`, w.fakeAMFRecording)
	ctx.Step(`^the SMF store holds 2 PDU sessions of a previous run "([^"]*)" PSI (\d+) and "([^"]*)" PSI (\d+)$`, w.storeHolds)
	ctx.Step(`^the SMF orphan release retry timers and association gate timeout are short$`, w.timersShort)

	ctx.Step(`^the fake AMF management API accepts PDU session release requests with (\d+)$`, w.amfDefault)
	ctx.Step(`^the fake AMF management API answers (\d+) then (\d+) for PSI (\d+) of "([^"]*)"$`, w.amfThen)
	ctx.Step(`^the fake AMF management API accepts the release of "([^"]*)" PSI (\d+) with (\d+)$`, w.amfAccepts)
	ctx.Step(`^the fake AMF management API answers (\d+) for PSI (\d+) of "([^"]*)"$`, w.amfAnswers)
	ctx.Step(`^the fake AMF management API answers (\d+) for every request$`, w.amfDefault)

	ctx.Step(`^the SMF is started$`, w.smfStarted)
	ctx.Step(`^the SMF is started and associated with the fake UPF$`, w.smfStartedAndAssociated)

	ctx.Step(`^the fake UPF receives a PFCP Association Setup Request$`, w.upfReceivesAssocRequest)
	ctx.Step(`^no release request reaches the fake AMF before the fake UPF answers with a PFCP Association Setup Response with Cause "([^"]*)"$`, w.noReleaseBeforeAnswer)

	ctx.Step(`^the fake AMF receives DELETE "([^"]*)" with query "([^"]*)"$`, w.amfReceivesDelete)
	ctx.Step(`^the fake AMF receives (\d+) DELETE requests with query "([^"]*)" for "([^"]*)" PSI (\d+)$`, w.amfReceivesNDeletes)
	ctx.Step(`^the fake AMF receives exactly (\d+) DELETE request for "([^"]*)" PSI (\d+)$`, w.amfExactlyNDelete)
	ctx.Step(`^the second request is sent after the retry backoff$`, w.secondAfterBackoff)
	ctx.Step(`^the fake AMF receives the configured maximum number of DELETE requests for each of the 2 sessions$`, w.amfMaxAttempts)

	ctx.Step(`^the SMF logs procedure "([^"]*)" with result "([^"]*)" and spec_ref "([^"]*)"$`, w.logsProcResultSpec)
	ctx.Step(`^the SMF logs result "([^"]*)" with cause "([^"]*)" for "([^"]*)"$`, w.logsResultCauseFor)
	ctx.Step(`^the SMF logs result "([^"]*)" with cause "([^"]*)"$`, w.logsResultCause)
	ctx.Step(`^the SMF summary reports orphans (\d+), released (\d+), already_released (\d+), failed (\d+)$`, w.summary)
	ctx.Step(`^the SMF SBI server still answers requests$`, w.sbiStillAnswers)
	ctx.Step(`^the SMF PFCP association state is "([^"]*)"$`, w.assocStateIs)

	ctx.Step(`^the fake UPF delays its PFCP Association Setup Response$`, w.upfDelays)
	ctx.Step(`^the fake UPF never answers PFCP Association Setup Requests$`, w.upfNeverAnswers)
	ctx.Step(`^a CreateSMContext request for "([^"]*)" PSI (\d+) arrives before the first association completes$`, w.createArrives)
	ctx.Step(`^the fake UPF receives no PFCP Session Establishment Request before the Association Setup Response$`, w.noEstablishmentBeforeResponse)
	ctx.Step(`^the fake UPF answers the PFCP Association Setup Response within the association gate timeout$`, w.upfAnswersWithinGate)
	ctx.Step(`^the fake UPF then receives a PFCP Session Establishment Request for PSI (\d+)$`, w.upfThenReceivesEstablishment)
	ctx.Step(`^the CreateSMContext request succeeds with HTTP status (\d+)$`, w.createSucceeds)
	ctx.Step(`^the CreateSMContext request is rejected after the association gate timeout with PDU SESSION ESTABLISHMENT REJECT 5GSM cause (\d+)$`, w.createRejected)
	ctx.Step(`^the fake UPF receives no PFCP Session Establishment Request$`, w.upfNoEstablishment)
	ctx.Step(`^no SM context is stored for "([^"]*)" PSI (\d+)$`, w.noSMContextStored)
}

// TestSmfRestartRecoveryFeatures runs smf_restart_recovery.feature (SMF-012).
func TestSmfRestartRecoveryFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeSmfRestartRecoveryScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/smf_restart_recovery.feature"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
