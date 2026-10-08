package server

// pfcp_node_test.go — unit tests for the PFCP node-level supervisor (SMF-004):
// Association Setup / Heartbeat against a fake UPF on a loopback UDP socket,
// Recovery Time Stamp restart detection, release of stale sessions through a
// mock AMF management API and the local-release fallback.
// Ref: TS 29.244 §6.2.2, §6.2.6.2, §6.4, §8.2.65; TS 23.007 §19A; TS 23.527 §4.2, §4.3.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// ---- helpers --------------------------------------------------------------

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// entries returns the JSON log lines emitted so far.
func (l *lockedBuf) entries() []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(l.b.String(), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

// has reports whether a log line matches all key/value pairs (numbers compared as float64).
func (l *lockedBuf) has(kv map[string]any) bool {
	for _, e := range l.entries() {
		ok := true
		for k, v := range kv {
			if e[k] != v {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
}

type upfMsg struct {
	typ  uint8
	seq  uint32
	seid uint64
	rts  time.Time // zero when the message carries none
}

// fakeUPF is a scriptable PFCP peer on a loopback UDP socket.
type fakeUPF struct {
	conn *net.UDPConn

	mu         sync.Mutex
	rts        time.Time // RTS in Heartbeat Responses
	assocRTS   time.Time // RTS in Association Setup Responses (zero = omitted)
	assocCause uint8
	dropAssoc  int    // answer nothing to the next N Association Setup Requests
	hbMode     string // ok | drop | nonrts
	got        []upfMsg
}

func newFakeUPF(t *testing.T, rts time.Time) *fakeUPF {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen fake upf: %v", err)
	}
	f := &fakeUPF{conn: conn, rts: rts, assocRTS: rts, assocCause: pfcpie.CauseRequestAccepted, hbMode: "ok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.loop()
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return f
}

func (f *fakeUPF) addr() string { return f.conn.LocalAddr().String() }

func (f *fakeUPF) loop() {
	buf := make([]byte, 2048)
	for {
		n, raddr, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg, err := pfcpmsg.Parse(buf[:n])
		if err != nil {
			continue
		}
		rec := upfMsg{typ: msg.MessageType(), seq: msg.Sequence()}
		var reply pfcpmsg.Message
		f.mu.Lock()
		switch m := msg.(type) {
		case *pfcpmsg.AssociationSetupRequest:
			if m.RecoveryTimeStamp != nil {
				rec.rts, _ = m.RecoveryTimeStamp.RecoveryTimeStamp()
			}
			if f.dropAssoc > 0 {
				f.dropAssoc--
				break
			}
			ies := []*pfcpie.IE{pfcpie.NewNodeID("", "", "upf"), pfcpie.NewCause(f.assocCause)}
			if !f.assocRTS.IsZero() {
				ies = append(ies, pfcpie.NewRecoveryTimeStamp(f.assocRTS))
			}
			reply = pfcpmsg.NewAssociationSetupResponse(m.Sequence(), ies...)
		case *pfcpmsg.HeartbeatRequest:
			if m.RecoveryTimeStamp != nil {
				rec.rts, _ = m.RecoveryTimeStamp.RecoveryTimeStamp()
			}
			switch f.hbMode {
			case "drop":
			case "nonrts":
				reply = pfcpmsg.NewHeartbeatResponse(m.Sequence(), nil)
			default:
				reply = pfcpmsg.NewHeartbeatResponse(m.Sequence(), pfcpie.NewRecoveryTimeStamp(f.rts))
			}
		case *pfcpmsg.SessionDeletionRequest:
			rec.seid = m.SEID()
			reply = pfcpmsg.NewSessionDeletionResponse(0, 0, m.SEID(), m.Sequence(), 0, pfcpie.NewCause(pfcpie.CauseRequestAccepted))
		}
		f.got = append(f.got, rec)
		f.mu.Unlock()
		if reply != nil {
			b := make([]byte, reply.MarshalLen())
			if reply.MarshalTo(b) == nil {
				_, _ = f.conn.WriteToUDP(b, raddr)
			}
		}
	}
}

func (f *fakeUPF) set(fn func()) {
	f.mu.Lock()
	fn()
	f.mu.Unlock()
}

func (f *fakeUPF) msgs(typ uint8) []upfMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []upfMsg
	for _, m := range f.got {
		if m.typ == typ {
			out = append(out, m)
		}
	}
	return out
}

type amfCall struct {
	method, path, corrID string
}

// fakeAMF records AMF management API calls and answers with a settable status.
type fakeAMF struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status int
	calls  []amfCall
}

func newFakeAMF(t *testing.T, status int) *fakeAMF {
	t.Helper()
	a := &fakeAMF{status: status}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.calls = append(a.calls, amfCall{r.Method, r.URL.Path, r.Header.Get("X-Correlation-Id")})
		st := a.status
		a.mu.Unlock()
		w.WriteHeader(st)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeAMF) host() string { return strings.TrimPrefix(a.srv.URL, "http://") }

func (a *fakeAMF) count(path string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, c := range a.calls {
		if path == "" || c.path == path {
			n++
		}
	}
	return n
}

func (a *fakeAMF) snapshot() []amfCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]amfCall(nil), a.calls...)
}

type nodeTestEnv struct {
	s    *Server
	upf  *fakeUPF
	amf  *fakeAMF
	logs *lockedBuf
}

// newNodeEnv builds an SMF wired to the fake UPF/AMF with sub-second timers
// (T1=100ms, N1=1, heartbeat 100ms, association retry 50ms..200ms).
func newNodeEnv(t *testing.T, upfRTS time.Time, amfStatus int) *nodeTestEnv {
	t.Helper()
	upf := newFakeUPF(t, upfRTS)
	amf := newFakeAMF(t, amfStatus)
	logs := &lockedBuf{}
	cfg := &config.Config{UEIPPool: "10.60.0.0/24"}
	cfg.Peers.UPF = upf.addr()
	cfg.Peers.AMFMgmt = amf.host()
	s, err := New(cfg, slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.pfcpTimers = pfcpNodeTimers{
		heartbeatInterval: 100 * time.Millisecond,
		t1:                100 * time.Millisecond,
		n1:                1,
		assocRetryInitial: 50 * time.Millisecond,
		assocRetryMax:     200 * time.Millisecond,
	}
	return &nodeTestEnv{s: s, upf: upf, amf: amf, logs: logs}
}

// startSupervisor runs the supervisor and stops it (no goroutine leak) at cleanup.
func (e *nodeTestEnv) startSupervisor(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.s.RunPFCPNodeSupervisor(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("supervisor did not return after ctx cancel")
		}
		e.s.WaitPFCPRelease()
	})
}

func (e *nodeTestEnv) waitState(t *testing.T, state string) {
	t.Helper()
	eventually(t, 5*time.Second, "association state "+state, func() bool {
		return e.s.PFCPAssociation().State == state
	})
}

// addSession seeds an ACTIVE session N4-established at estAt with an allocated UE IP.
func (e *nodeTestEnv) addSession(t *testing.T, ref, supi string, psi uint8, seid uint64, estAt time.Time) *Session {
	t.Helper()
	ip, err := e.s.ipPools["internet"].Allocate()
	if err != nil {
		t.Fatalf("allocate ip: %v", err)
	}
	sess := &Session{
		SUPI: supi, PDUSessionID: psi, DNN: "internet", UEIP: ip, SEID: seid,
		State: "ACTIVE", CreatedAt: estAt, N4EstablishedAt: estAt,
	}
	e.s.sessionMu.Lock()
	e.s.sessions[ref] = sess
	e.s.sessionMu.Unlock()
	return sess
}

func (e *nodeTestEnv) sessionState(ref string) (string, bool, bool) {
	e.s.sessionMu.Lock()
	defer e.s.sessionMu.Unlock()
	sess, ok := e.s.sessions[ref]
	if !ok {
		return "", false, false
	}
	return sess.State, sess.N4Stale, true
}

func (e *nodeTestEnv) poolHas(ip net.IP) bool {
	p := e.s.ipPools["internet"]
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allocated[ip.String()]
}

var (
	rtsT1 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	rtsT0 = rtsT1.Add(-time.Hour)
)

const (
	pathSupi1 = "/amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/1"
	pathSupi2 = "/amf/v1/ue-contexts/imsi-001010000000002/pdu-sessions/1"
	pathSupi3 = "/amf/v1/ue-contexts/imsi-001010000000003/pdu-sessions/1"
)

// ---- Association Setup / baseline ----------------------------------------

func TestPFCPNode_AssociationThenHeartbeatBaseline(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	// The RTS in the Association Setup Response must NOT become the baseline.
	e.upf.set(func() { e.upf.assocRTS = rtsT0.Add(100 * time.Hour) })
	before := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "PfcpAssociationSetup", "OK"))
	e.startSupervisor(t)

	e.waitState(t, assocAssociated)
	eventually(t, 5*time.Second, "baseline from heartbeat", func() bool {
		return e.s.PFCPAssociation().RemoteRTS.Equal(rtsT0)
	})

	assoc := e.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest)
	if len(assoc) == 0 || !assoc[0].rts.Equal(e.s.RecoveryTimeStamp()) {
		t.Fatalf("association request RTS = %v, want SMF RTS %v", assoc, e.s.RecoveryTimeStamp())
	}
	hb := e.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest)
	if len(hb) == 0 || !hb[0].rts.Equal(e.s.RecoveryTimeStamp()) {
		t.Fatalf("heartbeat RTS = %v, want SMF RTS", hb)
	}
	if got := e.s.PFCPAssociation().PeerNodeID; got != "upf" {
		t.Errorf("peer node id = %q, want upf", got)
	}
	if !e.logs.has(map[string]any{"procedure": "PfcpAssociationSetup", "result": "OK", "spec_ref": "TS 29.244 §6.2.6.2"}) {
		t.Error("missing PfcpAssociationSetup OK log")
	}
	if d := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "PfcpAssociationSetup", "OK")) - before; d < 1 {
		t.Errorf("OK metric delta = %v", d)
	}
}

func TestPFCPNode_AssociationRejectedIsRetried(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	e.upf.set(func() { e.upf.assocCause = pfcpie.CauseRequestRejected })
	before := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "PfcpAssociationSetup", "REJECT"))
	e.startSupervisor(t)

	eventually(t, 5*time.Second, "two association attempts", func() bool {
		return len(e.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest)) >= 2
	})
	if st := e.s.PFCPAssociation().State; st != assocSetupPending {
		t.Errorf("state = %s, want SETUP_PENDING", st)
	}
	if n := len(e.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest)); n != 0 {
		t.Errorf("%d heartbeats sent without association", n)
	}
	if !e.logs.has(map[string]any{"procedure": "PfcpAssociationSetup", "result": "REJECT", "cause": float64(64)}) {
		t.Error("missing REJECT log with cause 64")
	}
	if d := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "PfcpAssociationSetup", "REJECT")) - before; d < 1 {
		t.Errorf("REJECT metric delta = %v", d)
	}
}

func TestPFCPNode_AssociationTimeoutRetransmitsSameSeqThenSucceeds(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	// n1=1 -> 2 transmissions per attempt: drop one whole attempt.
	e.upf.set(func() { e.upf.dropAssoc = 2 })
	e.startSupervisor(t)

	e.waitState(t, assocAssociated)
	reqs := e.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest)
	if len(reqs) < 3 {
		t.Fatalf("got %d association requests, want >= 3", len(reqs))
	}
	if reqs[0].seq != reqs[1].seq {
		t.Errorf("retransmission seq %d != first seq %d", reqs[1].seq, reqs[0].seq)
	}
	if reqs[2].seq == reqs[0].seq {
		t.Errorf("new attempt reused sequence number %d", reqs[2].seq)
	}
	if !e.logs.has(map[string]any{"procedure": "PfcpAssociationSetup", "result": "FAILURE", "cause": "PEER_NOT_RESPONDING"}) {
		t.Error("missing FAILURE/PEER_NOT_RESPONDING log")
	}
	// No heartbeat before the association was accepted.
	hbs := e.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest)
	if len(hbs) == 0 {
		t.Fatal("no heartbeat after association")
	}
}

// ---- steady state / restart detection ------------------------------------

func TestPFCPNode_SteadyHeartbeatsNoRelease(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	e.startSupervisor(t)
	e.waitState(t, assocAssociated)
	e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0.Add(-time.Minute))
	e.addSession(t, "ref-2", "imsi-001010000000002", 1, 12, rtsT0.Add(-time.Minute))

	start := len(e.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest))
	eventually(t, 5*time.Second, "3 more heartbeats", func() bool {
		return len(e.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest)) >= start+3
	})
	if n := e.amf.count(""); n != 0 {
		t.Errorf("%d AMF release calls in steady state", n)
	}
	for _, ref := range []string{"ref-1", "ref-2"} {
		if st, _, _ := e.sessionState(ref); st != "ACTIVE" {
			t.Errorf("%s state = %s, want ACTIVE", ref, st)
		}
	}
	if e.logs.has(map[string]any{"procedure": "PfcpNodeLevelRecovery"}) {
		t.Error("unexpected PfcpNodeLevelRecovery log")
	}
}

func TestPFCPNode_RTSChangeReleasesStaleOnceKeepsNewSessions(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	e.startSupervisor(t)
	e.waitState(t, assocAssociated)
	eventually(t, 5*time.Second, "baseline T0", func() bool { return e.s.PFCPAssociation().RemoteRTS.Equal(rtsT0) })

	before := e.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest)
	e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT1.Add(-10*time.Second))
	e.addSession(t, "ref-2", "imsi-001010000000002", 1, 12, rtsT1.Add(-20*time.Second))
	e.addSession(t, "ref-3", "imsi-001010000000003", 1, 13, rtsT1.Add(10*time.Second)) // on the new UPF instance

	e.upf.set(func() { e.upf.rts = rtsT1; e.upf.assocRTS = rtsT1 })

	eventually(t, 5*time.Second, "two AMF release calls", func() bool { return e.amf.count("") >= 2 })
	e.s.WaitPFCPRelease()

	if !e.logs.has(map[string]any{"procedure": "PfcpNodeLevelRecovery", "cause": "PEER_RESTART",
		"old_rts": "2026-10-05T11:00:00Z", "new_rts": "2026-10-05T12:00:00Z", "spec_ref": "TS 23.527 §4.2"}) {
		t.Error("missing PEER_RESTART detection log")
	}
	calls := e.amf.snapshot()
	if len(calls) != 2 {
		t.Fatalf("AMF calls = %d, want 2: %+v", len(calls), calls)
	}
	paths := map[string]int{}
	for _, c := range calls {
		if c.method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", c.method)
		}
		paths[c.path]++
		if c.corrID == "" || c.corrID != calls[0].corrID {
			t.Errorf("X-Correlation-Id %q differs from %q", c.corrID, calls[0].corrID)
		}
	}
	if paths[pathSupi1] != 1 || paths[pathSupi2] != 1 || paths[pathSupi3] != 0 {
		t.Errorf("paths = %v", paths)
	}
	for _, ref := range []string{"ref-1", "ref-2"} {
		st, stale, ok := e.sessionState(ref)
		if !ok || st != sessionStateReleasing || !stale {
			t.Errorf("%s: state=%s stale=%v present=%v, want RELEASING/true/true (AMF will call DeleteSMContext)", ref, st, stale, ok)
		}
	}
	if st, stale, _ := e.sessionState("ref-3"); st != "ACTIVE" || stale {
		t.Errorf("ref-3 state=%s stale=%v, want ACTIVE/false", st, stale)
	}

	// Re-association, then new baseline T1; further heartbeats cause no re-release.
	eventually(t, 5*time.Second, "re-association and baseline T1", func() bool {
		a := e.s.PFCPAssociation()
		return a.State == assocAssociated && a.RemoteRTS.Equal(rtsT1) &&
			len(e.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest)) > len(before)
	})
	start := len(e.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest))
	eventually(t, 5*time.Second, "2 more heartbeats", func() bool {
		return len(e.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest)) >= start+2
	})
	if n := e.amf.count(""); n != 2 {
		t.Errorf("AMF calls after steady state = %d, want 2", n)
	}
	// The AMF now calls DeleteSMContext: N4 deletion is skipped for the stale session.
	for _, ref := range []string{"ref-1", "ref-2"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/nsmf-pdusession/v1/sm-contexts/"+ref, nil)
		req.SetPathValue("smContextRef", ref)
		e.s.handleDeleteSMContext(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Errorf("delete %s: %d", ref, rec.Code)
		}
	}
	// Control: a non-stale session does get its PFCP Session Deletion.
	e.addSession(t, "ref-ctl", "imsi-001010000000009", 1, 99, rtsT1.Add(time.Minute))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/x", nil)
	req.SetPathValue("smContextRef", "ref-ctl")
	e.s.handleDeleteSMContext(rec, req)
	eventually(t, 5*time.Second, "control PFCP deletion", func() bool {
		return len(e.upf.msgs(pfcpmsg.MsgTypeSessionDeletionRequest)) >= 1
	})
	for _, m := range e.upf.msgs(pfcpmsg.MsgTypeSessionDeletionRequest) {
		if m.seid == 11 || m.seid == 12 {
			t.Errorf("PFCP Session Deletion sent for stale SEID %d", m.seid)
		}
	}
}

func TestPFCPNode_HeartbeatLossReleasesAllSessions(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	e.startSupervisor(t)
	e.waitState(t, assocAssociated)
	eventually(t, 5*time.Second, "baseline", func() bool { return !e.s.PFCPAssociation().RemoteRTS.IsZero() })
	// Sessions "from the future" must still be released on failure (cutoff = all).
	e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, time.Now().Add(time.Hour))
	e.addSession(t, "ref-2", "imsi-001010000000002", 1, 12, rtsT0)
	failBefore := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "PfcpHeartbeat", "FAILURE"))

	e.upf.set(func() { e.upf.hbMode = "drop"; e.upf.dropAssoc = 1 << 20 })

	eventually(t, 5*time.Second, "release of both sessions", func() bool { return e.amf.count("") >= 2 })
	e.s.WaitPFCPRelease()

	if !e.logs.has(map[string]any{"procedure": "PfcpNodeLevelRecovery", "cause": "PEER_NOT_RESPONDING"}) {
		t.Error("missing PEER_NOT_RESPONDING log")
	}
	if e.amf.count(pathSupi1) != 1 || e.amf.count(pathSupi2) != 1 {
		t.Errorf("AMF calls: %+v", e.amf.snapshot())
	}
	if _, stale, _ := e.sessionState("ref-1"); stale {
		t.Error("heartbeat-loss path must not set N4Stale (best-effort PFCP deletion kept)")
	}
	if d := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "PfcpHeartbeat", "FAILURE")) - failBefore; d < 1 {
		t.Errorf("heartbeat FAILURE metric delta = %v", d)
	}
	// Heartbeat retransmissions reuse the sequence number.
	hbs := e.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest)
	same := false
	for i := 1; i < len(hbs); i++ {
		if hbs[i].seq == hbs[i-1].seq {
			same = true
		}
	}
	if !same {
		t.Error("no heartbeat retransmission with the same sequence number")
	}
	// Leaves ASSOCIATED while the UPF is silent, returns once it answers again.
	if st := e.s.PFCPAssociation().State; st == assocAssociated {
		t.Errorf("state still ASSOCIATED")
	}
	e.upf.set(func() { e.upf.hbMode = "ok"; e.upf.dropAssoc = 0 })
	e.waitState(t, assocAssociated)
}

func TestPFCPNode_SecondDetectionDoesNotReleaseAgain(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0)

	first := e.s.markSessionsReleasing(time.Time{}, true, false)
	second := e.s.markSessionsReleasing(time.Time{}, true, false)
	if len(first) != 1 || len(second) != 0 {
		t.Fatalf("first=%d second=%d, want 1 and 0 (RELEASING is the idempotency guard)", len(first), len(second))
	}

	// beginRecovery is a no-op unless ASSOCIATED.
	if e.s.beginRecovery(t.Context(), causePeerRestart, rtsT0, rtsT1) {
		t.Error("beginRecovery ran while SETUP_PENDING")
	}
	e.s.setAssocState(assocAssociated)
	if !e.s.beginRecovery(t.Context(), causePeerRestart, rtsT0, rtsT1) {
		t.Fatal("first detection not handled")
	}
	if e.s.beginRecovery(t.Context(), causePeerRestart, rtsT0, rtsT1) {
		t.Error("second detection handled while RECOVERING")
	}
	e.s.WaitPFCPRelease()
}

// TS 23.007 §19A: stored > received is a possible race (older message arriving
// late): the message is obsolete and discarded, no recovery, baseline kept.
func TestPFCPNode_OlderRTSIsObsoleteAndDiscarded(t *testing.T) {
	e := newNodeEnv(t, rtsT1, http.StatusAccepted)
	e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT1.Add(time.Hour))
	e.s.assoc.mu.Lock()
	e.s.assoc.state = assocAssociated
	e.s.assoc.remoteRTS = rtsT1
	e.s.assoc.mu.Unlock()

	if e.s.observePeerRTS(t.Context(), pfcpie.NewRecoveryTimeStamp(rtsT0), "test") {
		t.Fatal("older RTS treated as restart")
	}
	e.s.WaitPFCPRelease()
	if e.amf.count("") != 0 {
		t.Errorf("AMF calls for an obsolete message: %+v", e.amf.snapshot())
	}
	if st, _, _ := e.sessionState("ref-1"); st != "ACTIVE" {
		t.Errorf("session state = %s, want ACTIVE", st)
	}
	a := e.s.PFCPAssociation()
	if a.State != assocAssociated || !a.RemoteRTS.Equal(rtsT1) {
		t.Errorf("state=%s baseline=%v, want ASSOCIATED/T1 unchanged", a.State, a.RemoteRTS)
	}
	if !e.logs.has(map[string]any{"level": "WARN", "spec_ref": "TS 23.007 §19A"}) {
		t.Error("missing obsolete-message WARN")
	}
}

func TestPFCPNode_NextPFCPSeqWrapsInto24Bits(t *testing.T) {
	var s Server
	s.pfcpSeq.Store(pfcpSeqMax - 2)
	want := []uint32{pfcpSeqMax - 1, pfcpSeqMax, 1, 2}
	for i, w := range want {
		if got := s.nextPFCPSeq(); got != w {
			t.Fatalf("call %d: got %#x, want %#x", i, got, w)
		}
	}
	// Never 0 and never above 24 bits over a full wrap boundary.
	s.pfcpSeq.Store(0xFFFFFFFE)
	for range 5 {
		if got := s.nextPFCPSeq(); got == 0 || got > pfcpSeqMax {
			t.Fatalf("out of range sequence %#x", got)
		}
	}
}

func TestPFCPNode_ReleaseGuardReleasesLocallyAfterAMFAccepted(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	e.s.pfcpTimers.releaseGuard = 150 * time.Millisecond
	sess := e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0)
	e.s.setAssocState(assocAssociated)
	e.s.assoc.mu.Lock()
	e.s.assoc.remoteRTS = rtsT0
	e.s.assoc.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	e.s.observePeerRTS(ctx, pfcpie.NewRecoveryTimeStamp(rtsT1), "test")
	e.s.WaitPFCPRelease()
	if _, _, present := e.sessionState("ref-1"); !present {
		t.Fatal("session freed before the guard expired")
	}
	eventually(t, 5*time.Second, "guard releases the session", func() bool {
		_, _, present := e.sessionState("ref-1")
		return !present
	})
	e.s.WaitReleaseGuards()
	if e.poolHas(sess.UEIP) {
		t.Error("UE IP not freed by the guard")
	}
}

func TestPFCPNode_ReleaseGuardCancelledByCtxAndSkippedWhenGone(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	e.s.pfcpTimers.releaseGuard = time.Hour
	e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0)
	e.s.setAssocState(assocAssociated)
	e.s.assoc.mu.Lock()
	e.s.assoc.remoteRTS = rtsT0
	e.s.assoc.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())

	e.s.observePeerRTS(ctx, pfcpie.NewRecoveryTimeStamp(rtsT1), "test")
	e.s.WaitPFCPRelease()
	cancel()
	done := make(chan struct{})
	go func() { e.s.WaitReleaseGuards(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("guard goroutine leaked after ctx cancel")
	}
	if st, _, present := e.sessionState("ref-1"); !present || st != sessionStateReleasing {
		t.Errorf("state=%s present=%v, want RELEASING kept", st, present)
	}
}

func TestPFCPNode_MissingRTSIsLivenessOnly(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	e.startSupervisor(t)
	e.waitState(t, assocAssociated)
	eventually(t, 5*time.Second, "baseline", func() bool { return e.s.PFCPAssociation().RemoteRTS.Equal(rtsT0) })
	e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0.Add(-time.Minute))

	e.upf.set(func() { e.upf.hbMode = "nonrts" })
	eventually(t, 5*time.Second, "RTS_MISSING warning", func() bool {
		return e.logs.has(map[string]any{"procedure": "PfcpHeartbeat", "cause": "RTS_MISSING", "level": "WARN"})
	})
	// Let a few more heartbeats go by: still associated, baseline kept, warned once.
	start := len(e.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest))
	eventually(t, 5*time.Second, "more heartbeats", func() bool {
		return len(e.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest)) >= start+3
	})
	a := e.s.PFCPAssociation()
	if a.State != assocAssociated || !a.RemoteRTS.Equal(rtsT0) {
		t.Errorf("state=%s baseline=%v, want ASSOCIATED/T0", a.State, a.RemoteRTS)
	}
	warns := 0
	for _, en := range e.logs.entries() {
		if en["cause"] == "RTS_MISSING" && en["level"] == "WARN" && en["procedure"] == "PfcpHeartbeat" {
			warns++
		}
	}
	if warns != 1 {
		t.Errorf("RTS_MISSING warnings = %d, want 1 per association", warns)
	}
	if e.amf.count("") != 0 || e.logs.has(map[string]any{"procedure": "PfcpNodeLevelRecovery"}) {
		t.Error("unexpected recovery")
	}
}

func TestPFCPNode_AssocSetupRTSNotUsedForDetection(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	e.s.assoc.mu.Lock()
	e.s.assoc.state = assocAssociated
	e.s.assoc.remoteRTS = rtsT0
	e.s.assoc.mu.Unlock()
	e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0)
	e.upf.set(func() { e.upf.assocRTS = rtsT1 })

	if !e.s.runAssociationSetup(t.Context()) {
		t.Fatal("association setup failed")
	}
	a := e.s.PFCPAssociation()
	if !a.RemoteRTS.Equal(rtsT0) || a.State != assocAssociated {
		t.Errorf("baseline=%v state=%s, want T0/ASSOCIATED", a.RemoteRTS, a.State)
	}
	if !e.logs.has(map[string]any{"procedure": "PfcpAssociationSetup", "peer_rts": "2026-10-05T12:00:00Z"}) {
		t.Error("peer RTS from Association Setup Response not logged")
	}
	if e.logs.has(map[string]any{"procedure": "PfcpNodeLevelRecovery"}) || e.amf.count("") != 0 {
		t.Error("detection triggered by Association Setup RTS")
	}
	if st, _, _ := e.sessionState("ref-1"); st != "ACTIVE" {
		t.Errorf("session state = %s", st)
	}
}

// ---- release path ---------------------------------------------------------

func TestPFCPNode_AMFFailureFallsBackToLocalRelease(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			e := newNodeEnv(t, rtsT0, status)
			sess := e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0)
			e.s.assoc.mu.Lock()
			e.s.assoc.state = assocAssociated
			e.s.assoc.remoteRTS = rtsT0
			e.s.assoc.mu.Unlock()
			failBefore := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "PfcpNodeLevelRecovery", "FAILURE"))

			if !e.s.observePeerRTS(t.Context(), pfcpie.NewRecoveryTimeStamp(rtsT1), "test") {
				t.Fatal("restart not detected")
			}
			e.s.WaitPFCPRelease()

			if e.amf.count(pathSupi1) != 1 {
				t.Errorf("AMF calls: %+v", e.amf.snapshot())
			}
			if _, _, present := e.sessionState("ref-1"); present {
				t.Error("session still in table after local release")
			}
			if e.poolHas(sess.UEIP) {
				t.Error("UE IP not returned to pool")
			}
			if !e.logs.has(map[string]any{"procedure": "PfcpNodeLevelRecovery", "result": "FAILURE", "cause": "AMF_RELEASE_FAILED"}) {
				t.Error("missing AMF_RELEASE_FAILED log")
			}
			if d := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "PfcpNodeLevelRecovery", "FAILURE")) - failBefore; d != 1 {
				t.Errorf("FAILURE metric delta = %v, want 1", d)
			}
		})
	}
}

func TestPFCPNode_AMFAcceptedKeepsSessionUntilDeleteSMContext(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	sess := e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0)
	e.s.setAssocState(assocAssociated)
	e.s.assoc.mu.Lock()
	e.s.assoc.remoteRTS = rtsT0
	e.s.assoc.mu.Unlock()

	e.s.observePeerRTS(t.Context(), pfcpie.NewRecoveryTimeStamp(rtsT1), "test")
	e.s.WaitPFCPRelease()
	if st, _, present := e.sessionState("ref-1"); !present || st != sessionStateReleasing {
		t.Fatalf("state=%s present=%v, want RELEASING and kept (202)", st, present)
	}
	if !e.poolHas(sess.UEIP) {
		t.Error("IP freed before the AMF's ReleaseSMContext")
	}
}

func TestReleaseSessionLocalIsIdempotent(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	sess := e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0)
	sess.N4Stale = true

	if !e.s.releaseSessionLocal(t.Context(), "ref-1", sess, true) {
		t.Fatal("first release returned false")
	}
	// The address is reused by another session; a second release must not free it.
	ip2, err := e.s.ipPools["internet"].Allocate()
	if err != nil || !ip2.Equal(sess.UEIP) {
		t.Fatalf("expected address reuse, got %v err=%v", ip2, err)
	}
	if e.s.releaseSessionLocal(t.Context(), "ref-1", sess, true) {
		t.Error("second release returned true")
	}
	if !e.poolHas(ip2) {
		t.Error("double free of the UE IP")
	}
	// DeleteSMContext for an unknown ref stays a clean 204.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/x", nil)
	req.SetPathValue("smContextRef", "ref-1")
	e.s.handleDeleteSMContext(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
	if !e.poolHas(ip2) {
		t.Error("double free via DeleteSMContext")
	}
}

func TestPFCPNode_ReleasingSessionSkipsN4Operations(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	sess := e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0)
	e.s.sessionMu.Lock()
	sess.State = sessionStateReleasing
	e.s.sessionMu.Unlock()

	e.s.sendPFCPSessionDeactivation(t.Context(), sess)
	e.s.sendPFCPSessionModification(t.Context(), sess, 1, net.ParseIP("10.0.0.1"))
	if n := len(e.upf.msgs(pfcpmsg.MsgTypeSessionModificationRequest)); n != 0 {
		t.Errorf("%d PFCP modifications sent for a RELEASING session", n)
	}
}

// ---- inbound Heartbeat Request on the receiver ---------------------------

func startReceiver(t *testing.T, e *nodeTestEnv) *net.UDPAddr {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().(*net.UDPAddr)
	l.Close()
	e.s.cfg.N4.ReportListen = addr.String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.s.StartPFCPReceiver(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	// Wait until the receiver is bound (log line emitted after listen).
	eventually(t, 5*time.Second, "receiver listening", func() bool {
		return e.logs.has(map[string]any{"msg": "SMF: PFCP receiver listening"})
	})
	return addr
}

func sendHeartbeatRequest(t *testing.T, to *net.UDPAddr, seq uint32, rts time.Time) *pfcpmsg.HeartbeatResponse {
	t.Helper()
	// Source IP 127.0.0.1 == the configured UPF peer IP.
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, to)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := pfcpmsg.NewHeartbeatRequest(seq, pfcpie.NewRecoveryTimeStamp(rts), nil)
	b := make([]byte, req.MarshalLen())
	if err := req.MarshalTo(b); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no heartbeat response: %v", err)
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	rsp, ok := msg.(*pfcpmsg.HeartbeatResponse)
	if !ok {
		t.Fatalf("got %T, want HeartbeatResponse", msg)
	}
	return rsp
}

func TestPFCPNode_InboundHeartbeatRequestAnsweredAndChecked(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	addr := startReceiver(t, e)
	e.s.assoc.mu.Lock()
	e.s.assoc.state = assocAssociated
	e.s.assoc.remoteRTS = rtsT0
	e.s.assoc.mu.Unlock()
	e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT1.Add(-time.Minute))

	// Same RTS: answered with the SMF RTS and sequence echoed, no release.
	rsp := sendHeartbeatRequest(t, addr, 77, rtsT0)
	if rsp.Sequence() != 77 {
		t.Errorf("seq = %d, want 77", rsp.Sequence())
	}
	got, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil || !got.Equal(e.s.RecoveryTimeStamp()) {
		t.Errorf("response RTS = %v err=%v, want %v", got, err, e.s.RecoveryTimeStamp())
	}
	if a := e.s.PFCPAssociation(); a.State != assocAssociated || e.amf.count("") != 0 {
		t.Errorf("state=%s amf=%d after steady inbound heartbeat", a.State, e.amf.count(""))
	}

	// Changed RTS: still answered, and restart detection runs.
	rsp = sendHeartbeatRequest(t, addr, 78, rtsT1)
	if rsp.Sequence() != 78 {
		t.Errorf("seq = %d, want 78", rsp.Sequence())
	}
	eventually(t, 5*time.Second, "AMF release after inbound RTS change", func() bool {
		return e.amf.count(pathSupi1) == 1
	})
	e.s.WaitPFCPRelease()
	if !e.logs.has(map[string]any{"procedure": "PfcpNodeLevelRecovery", "cause": "PEER_RESTART"}) {
		t.Error("missing PEER_RESTART log")
	}
}

func TestPFCPNode_TimersFromConfigDefaultsAndOverrides(t *testing.T) {
	d := pfcpTimersFromConfig(config.N4Config{})
	if d.heartbeatInterval != 2*time.Second || d.t1 != 3*time.Second || d.n1 != 3 ||
		d.assocRetryInitial != time.Second || d.assocRetryMax != 5*time.Second {
		t.Errorf("defaults = %+v", d)
	}
	o := pfcpTimersFromConfig(config.N4Config{HeartbeatIntervalSeconds: 7, T1Seconds: 4, N1Retransmissions: 2,
		AssociationRetryInitialSeconds: 2, AssociationRetryMaxSeconds: 9})
	if o.heartbeatInterval != 7*time.Second || o.t1 != 4*time.Second || o.n1 != 2 ||
		o.assocRetryInitial != 2*time.Second || o.assocRetryMax != 9*time.Second {
		t.Errorf("overrides = %+v", o)
	}
}

func TestPFCPNode_ReleasingSessionQoSModificationIsNoOp(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	sess := e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0)
	e.s.sessionMu.Lock()
	sess.State = sessionStateReleasing
	sess.N4Stale = true
	e.s.sessionMu.Unlock()
	if e.s.sendPFCPQoSModification(t.Context(), sess) {
		t.Error("QoS modification acknowledged for a RELEASING session")
	}
	if n := len(e.upf.msgs(pfcpmsg.MsgTypeSessionModificationRequest)); n != 0 {
		t.Errorf("%d PFCP modifications sent", n)
	}
	// Shutdown cleanup skips PFCP deletion for N4Stale sessions.
	e.s.cleanupAllSessions(t.Context())
	time.Sleep(100 * time.Millisecond)
	if n := len(e.upf.msgs(pfcpmsg.MsgTypeSessionDeletionRequest)); n != 0 {
		t.Errorf("%d PFCP deletions sent for an N4Stale session", n)
	}
}

func TestPFCPNode_UpdateSMContextRejectedWhileReleasing(t *testing.T) {
	e := newNodeEnv(t, rtsT0, http.StatusAccepted)
	e.s.cfg.UPFN3Addr = "172.30.3.100"
	sess := e.addSession(t, "ref-1", "imsi-001010000000001", 1, 11, rtsT0)
	e.s.sessionMu.Lock()
	sess.State = sessionStateReleasing
	e.s.sessionMu.Unlock()

	call := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
		r.SetPathValue("smContextRef", "ref-1")
		w := httptest.NewRecorder()
		e.s.handleUpdateSMContext(w, r)
		return w
	}
	w := call(`{"upCnxState":"ACTIVATING"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), causeSessionReleasing) {
		t.Errorf("ACTIVATING: %d %s, want 409 %s", w.Code, w.Body.String(), causeSessionReleasing)
	}
	if strings.Contains(w.Body.String(), "n2SmInfo") {
		t.Error("N2 SM info returned for a RELEASING session")
	}
	// AN release (deactivation) remains a successful no-op.
	if w := call(`{"upCnxState":"DEACTIVATED"}`); w.Code != http.StatusOK {
		t.Errorf("DEACTIVATED: %d, want 200", w.Code)
	}
	if st, _, _ := e.sessionState("ref-1"); st != sessionStateReleasing {
		t.Errorf("state = %s, want RELEASING kept", st)
	}
}

func TestMarkSessionActiveKeepsReleasing(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name, from, want string
		ok               bool
	}{
		{"idle becomes active", "IDLE", "ACTIVE", true},
		{"releasing preserved", sessionStateReleasing, sessionStateReleasing, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := &Session{State: tc.from}
			if got := s.markSessionActive(sess); got != tc.ok || sess.State != tc.want {
				t.Fatalf("ok=%v state=%q, want ok=%v state=%q", got, sess.State, tc.ok, tc.want)
			}
		})
	}
}
