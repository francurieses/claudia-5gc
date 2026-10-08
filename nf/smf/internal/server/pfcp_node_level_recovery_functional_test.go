//go:build functional

// godog step definitions for PFCP node-level recovery at the SMF (SMF-004):
// SMF-initiated Association Setup, Heartbeat supervision, UPF restart / failure
// detection and release of the affected PDU sessions.
// Refs: TS 29.244 §6.2.2, §6.2.6.2, §6.4, §7.4.2, §7.4.4, §8.2.65;
// TS 23.007 §19A; TS 23.527 §4.2, §4.3; TS 23.502 §4.3.4.2.
//
// Everything runs in-process: the SMF supervisor talks to a scriptable fake UPF
// on a loopback UDP socket and to a fake AMF management API (httptest) with
// sub-second T1 / N1 / heartbeat / association retry timers. Each scenario
// builds a fresh world (Before hook) and tears it down in the After hook, so
// scenarios are order-independent. Assertions on asynchronous effects poll with
// a deadline; there are no bare sleeps.
//
// Run with: go test -tags=functional ./nf/smf/...  (see Makefile test-functional)
package server

import (
	"context"
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
	"github.com/prometheus/client_golang/prometheus/testutil"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	// recStepDeadline bounds every polling assertion.
	recStepDeadline = 10 * time.Second
	// recT1 / recN1 are the shrunk PFCP reliable-delivery timers (TS 29.244 §6.4).
	recT1 = 100 * time.Millisecond
	recN1 = 1
)

// recNamedTS resolves the Recovery Time Stamp names used in the feature file.
// T0 / T1 are the UPF stamps (T1 newer), S0 is the SMF stamp.
func recNamedTS(name string) (time.Time, error) {
	switch name {
	case "T0":
		return rtsT0, nil
	case "T1":
		return rtsT1, nil
	case "S0":
		return time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC), nil
	}
	return time.Time{}, fmt.Errorf("unknown Recovery Time Stamp name %q", name)
}

// ---- fake UPF -------------------------------------------------------------

type recMsg struct {
	typ       uint8
	seq       uint32
	rts       time.Time // RTS carried by the request (zero if none)
	hasNode   bool      // Node ID IE present (Association Setup Request)
	at        time.Time
	answered  bool
	answerRTS time.Time // RTS carried by our answer (zero if none)
}

// recUPF is a scriptable PFCP peer on a loopback UDP socket.
type recUPF struct {
	conn *net.UDPConn
	done chan struct{}

	mu         sync.Mutex
	hbRTS      time.Time // RTS in Heartbeat Responses
	assocRTS   time.Time // RTS in Association Setup Responses (zero = omitted)
	assocCause uint8
	dropAssoc  int    // silently drop the next N Association Setup Requests
	hbMode     string // ok | nonrts
	down       bool   // answer nothing at all
	got        []recMsg
}

func newRecUPF(rts time.Time) (*recUPF, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("listen fake upf: %w", err)
	}
	f := &recUPF{conn: conn, done: make(chan struct{}), hbRTS: rts, assocRTS: rts,
		assocCause: pfcpie.CauseRequestAccepted, hbMode: "ok"}
	go func() {
		defer close(f.done)
		f.loop()
	}()
	return f, nil
}

func (f *recUPF) close() {
	_ = f.conn.Close()
	<-f.done
}

func (f *recUPF) addr() string { return f.conn.LocalAddr().String() }

func (f *recUPF) loop() {
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
		rec := recMsg{typ: msg.MessageType(), seq: msg.Sequence(), at: time.Now()}
		var reply pfcpmsg.Message
		f.mu.Lock()
		switch m := msg.(type) {
		case *pfcpmsg.AssociationSetupRequest:
			rec.hasNode = m.NodeID != nil
			if m.RecoveryTimeStamp != nil {
				rec.rts, _ = m.RecoveryTimeStamp.RecoveryTimeStamp()
			}
			if f.down {
				break
			}
			if f.dropAssoc > 0 {
				f.dropAssoc--
				break
			}
			ies := []*pfcpie.IE{pfcpie.NewNodeID("", "", "upf"), pfcpie.NewCause(f.assocCause)}
			if !f.assocRTS.IsZero() {
				ies = append(ies, pfcpie.NewRecoveryTimeStamp(f.assocRTS))
				rec.answerRTS = f.assocRTS
			}
			reply = pfcpmsg.NewAssociationSetupResponse(m.Sequence(), ies...)
		case *pfcpmsg.HeartbeatRequest:
			if m.RecoveryTimeStamp != nil {
				rec.rts, _ = m.RecoveryTimeStamp.RecoveryTimeStamp()
			}
			if f.down {
				break
			}
			if f.hbMode == "nonrts" {
				reply = pfcpmsg.NewHeartbeatResponse(m.Sequence(), nil)
			} else {
				reply = pfcpmsg.NewHeartbeatResponse(m.Sequence(), pfcpie.NewRecoveryTimeStamp(f.hbRTS))
				rec.answerRTS = f.hbRTS
			}
		case *pfcpmsg.SessionDeletionRequest:
			reply = pfcpmsg.NewSessionDeletionResponse(0, 0, m.SEID(), m.Sequence(), 0,
				pfcpie.NewCause(pfcpie.CauseRequestAccepted))
		}
		rec.answered = reply != nil
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

func (f *recUPF) set(fn func()) {
	f.mu.Lock()
	fn()
	f.mu.Unlock()
}

func (f *recUPF) msgs(typ uint8) []recMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recMsg
	for _, m := range f.got {
		if m.typ == typ {
			out = append(out, m)
		}
	}
	return out
}

func (f *recUPF) all() []recMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recMsg(nil), f.got...)
}

func (f *recUPF) answeredHB() int {
	n := 0
	for _, m := range f.msgs(pfcpmsg.MsgTypeHeartbeatRequest) {
		if m.answered {
			n++
		}
	}
	return n
}

// ---- fake AMF management API ----------------------------------------------

type recAMFCall struct{ method, path, corrID string }

type recAMF struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status int
	calls  []recAMFCall
}

func newRecAMF(status int) *recAMF {
	a := &recAMF{status: status}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.calls = append(a.calls, recAMFCall{r.Method, r.URL.Path, r.Header.Get("X-Correlation-Id")})
		st := a.status
		a.mu.Unlock()
		w.WriteHeader(st)
	}))
	return a
}

func (a *recAMF) host() string { return strings.TrimPrefix(a.srv.URL, "http://") }

func (a *recAMF) setStatus(st int) {
	a.mu.Lock()
	a.status = st
	a.mu.Unlock()
}

func (a *recAMF) snapshot() []recAMFCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]recAMFCall(nil), a.calls...)
}

func (a *recAMF) count(path string) int {
	n := 0
	for _, c := range a.snapshot() {
		if path == "" || c.path == path {
			n++
		}
	}
	return n
}

// ---- world ----------------------------------------------------------------

type recSession struct {
	ref  string
	supi string
	psi  uint8
	ip   net.IP
}

type recWorld struct {
	upf  *recUPF
	amf  *recAMF
	logs *lockedBuf
	s    *Server

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	sessions []recSession
	nextSEID uint64

	metricBase map[string]float64

	// marks taken at the time of the "When" step
	assocMark int

	// receiver (inbound Heartbeat Request scenarios)
	receiver  *net.UDPAddr
	inboundRs *pfcpmsg.HeartbeatResponse
}

func (w *recWorld) reset() {
	w.teardown()
	*w = recWorld{}
	w.ctx, w.cancel = context.WithCancel(context.Background())
}

// teardown stops goroutines and servers; safe to call on a partially built world.
func (w *recWorld) teardown() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
	if w.s != nil {
		w.s.WaitPFCPRelease()
	}
	if w.upf != nil {
		w.upf.close()
	}
	if w.amf != nil {
		w.amf.srv.Close()
	}
}

func recPoll(what string, cond func() bool) error {
	deadline := time.Now().Add(recStepDeadline)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s waiting for %s", recStepDeadline, what)
}

func recMetric(proc, result string) float64 {
	return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", proc, result))
}

func (w *recWorld) metricDelta(proc, result string) float64 {
	return recMetric(proc, result) - w.metricBase[proc+"/"+result]
}

func amfPath(supi string, psi int) string {
	return fmt.Sprintf("/amf/v1/ue-contexts/%s/pdu-sessions/%d", supi, psi)
}

// ---- Background -----------------------------------------------------------

func (w *recWorld) fakeUPFListening(name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	upf, err := newRecUPF(ts)
	if err != nil {
		return err
	}
	w.upf = upf
	return nil
}

func (w *recWorld) fakeAMFAccepts(status int) error {
	w.amf = newRecAMF(status)
	return nil
}

func (w *recWorld) supervisorConfigured() error {
	if w.upf == nil || w.amf == nil {
		return fmt.Errorf("fake UPF / AMF not set up")
	}
	w.logs = &lockedBuf{}
	cfg := &config.Config{UEIPPool: "10.60.0.0/24"}
	cfg.Peers.UPF = w.upf.addr()
	cfg.Peers.AMFMgmt = w.amf.host()
	s, err := New(cfg, slog.New(slog.NewJSONHandler(w.logs, &slog.HandlerOptions{Level: slog.LevelDebug})), nil)
	if err != nil {
		return fmt.Errorf("new SMF server: %w", err)
	}
	s.pfcpTimers = pfcpNodeTimers{
		heartbeatInterval: 100 * time.Millisecond,
		t1:                recT1,
		n1:                recN1,
		assocRetryInitial: 50 * time.Millisecond,
		assocRetryMax:     200 * time.Millisecond,
	}
	w.s = s
	w.metricBase = map[string]float64{}
	for _, p := range []string{procAssocSetup, procHeartbeat, procRecovery} {
		for _, r := range []string{"OK", "REJECT", "FAILURE"} {
			w.metricBase[p+"/"+r] = recMetric(p, r)
		}
	}
	return nil
}

func (w *recWorld) smfHasRTS(name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	if w.s == nil {
		return fmt.Errorf("SMF not configured")
	}
	w.s.recoveryTS = ts
	return nil
}

// ---- supervisor control ---------------------------------------------------

func (w *recWorld) startSupervisor() error {
	if w.s == nil {
		return fmt.Errorf("SMF not configured")
	}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.s.RunPFCPNodeSupervisor(w.ctx)
	}()
	return nil
}

func (w *recWorld) associatedWithBaseline(name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	if err := w.startSupervisor(); err != nil {
		return err
	}
	return recPoll("ASSOCIATED with baseline "+name, func() bool {
		a := w.s.PFCPAssociation()
		return a.State == assocAssociated && a.RemoteRTS.Equal(ts)
	})
}

// ---- sessions -------------------------------------------------------------

func (w *recWorld) seedSession(supi string, psi int, estAt time.Time) error {
	ip, err := w.s.ipPools["internet"].Allocate()
	if err != nil {
		return fmt.Errorf("allocate UE IP: %w", err)
	}
	w.nextSEID++
	ref := fmt.Sprintf("ref-%s-%d", supi, psi)
	sess := &Session{
		SUPI: supi, PDUSessionID: uint8(psi), DNN: "internet", UEIP: ip, SEID: 100 + w.nextSEID,
		State: "ACTIVE", CreatedAt: estAt, N4EstablishedAt: estAt,
	}
	w.s.sessionMu.Lock()
	w.s.sessions[ref] = sess
	w.s.sessionMu.Unlock()
	w.sessions = append(w.sessions, recSession{ref: ref, supi: supi, psi: uint8(psi), ip: ip})
	return nil
}

// recEstablishedAt resolves the "before / at or after Recovery Time Stamp" qualifier.
func recEstablishedAt(qualifier, name string) (time.Time, error) {
	t, err := recNamedTS(name)
	if err != nil {
		return time.Time{}, err
	}
	if qualifier == "before" {
		return t.Add(-10 * time.Second), nil
	}
	return t, nil // "at or after": the boundary instant itself
}

func (w *recWorld) holdsNSessions(n int) error {
	for i := 1; i <= n; i++ {
		if err := w.seedSession(fmt.Sprintf("imsi-00101000000000%d", i), 1, rtsT0.Add(-time.Minute)); err != nil {
			return err
		}
	}
	return nil
}

func (w *recWorld) holdsTwoNamedSessions(supiA string, psiA int, supiB string, psiB int, name string) error {
	at, err := recEstablishedAt("before", name)
	if err != nil {
		return err
	}
	if err := w.seedSession(supiA, psiA, at); err != nil {
		return err
	}
	return w.seedSession(supiB, psiB, at)
}

func (w *recWorld) holdsSessionQualified(supi string, psi int, qualifier, name string) error {
	at, err := recEstablishedAt(qualifier, name)
	if err != nil {
		return err
	}
	return w.seedSession(supi, psi, at)
}

func (w *recWorld) holdsActiveSession(supi string, psi int, _ string, name string) error {
	at := rtsT0.Add(-time.Minute)
	if name != "" {
		var err error
		if at, err = recEstablishedAt("before", name); err != nil {
			return err
		}
	}
	return w.seedSession(supi, psi, at)
}

func (w *recWorld) sessionByRef(ref string) (state string, present bool) {
	w.s.sessionMu.Lock()
	defer w.s.sessionMu.Unlock()
	sess, ok := w.s.sessions[ref]
	if !ok {
		return "", false
	}
	return sess.State, true
}

func (w *recWorld) allSessionsActive() error {
	if len(w.sessions) == 0 {
		return fmt.Errorf("no sessions were seeded")
	}
	for _, rs := range w.sessions {
		if st, ok := w.sessionByRef(rs.ref); !ok || st != "ACTIVE" {
			return fmt.Errorf("session %s state=%q present=%v, want ACTIVE", rs.supi, st, ok)
		}
	}
	return nil
}

func (w *recWorld) sessionRemainsActive(supi, want string) error {
	for _, rs := range w.sessions {
		if rs.supi != supi {
			continue
		}
		st, ok := w.sessionByRef(rs.ref)
		if !ok || st != want {
			return fmt.Errorf("session %s state=%q present=%v, want %q", supi, st, ok, want)
		}
		return nil
	}
	return fmt.Errorf("no seeded session for %s", supi)
}

// ---- fake UPF scripting ---------------------------------------------------

func (w *recWorld) upfDropsFirstAssoc(n int) error {
	w.upf.set(func() { w.upf.dropAssoc = n })
	return nil
}

func (w *recWorld) upfAnswersAssocWithCause(name string) error {
	cause, err := recCause(name)
	if err != nil {
		return err
	}
	w.upf.set(func() { w.upf.assocCause = cause })
	return nil
}

func recCause(name string) (uint8, error) {
	switch name {
	case "Request accepted":
		return pfcpie.CauseRequestAccepted, nil
	case "Request rejected":
		return pfcpie.CauseRequestRejected, nil
	}
	return 0, fmt.Errorf("unknown Cause name %q", name)
}

// upfStartsAnswering implements "starts answering PFCP Association Setup
// Requests with Cause ..." and "starts answering again".
func (w *recWorld) upfStartsAnsweringAssoc(name string) error {
	return w.upfStartsAnswering(name)
}

func (w *recWorld) upfStartsAnswering(name string) error {
	cause, err := recCause(name)
	if err != nil {
		return err
	}
	w.upf.set(func() { w.upf.dropAssoc = 0; w.upf.assocCause = cause; w.upf.down = false })
	return nil
}

func (w *recWorld) upfStartsAnsweringAgain() error {
	w.upf.set(func() { w.upf.dropAssoc = 0; w.upf.down = false })
	return nil
}

// upfStopsAnsweringHeartbeats models a UPF that is down: it answers neither
// Heartbeat nor Association Setup Requests, so the SMF stays out of ASSOCIATED
// long enough to be observed deterministically.
func (w *recWorld) upfStopsAnsweringHeartbeats() error {
	w.assocMark = len(w.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest))
	w.upf.set(func() { w.upf.down = true })
	return nil
}

// upfAnswersNextHBNewer implements both "restarts and answers the next ..." and
// "answers the next ... with the newer RTS": the restarted UPF reports the new
// stamp in Heartbeat and Association Setup Responses.
func (w *recWorld) upfAnswersNextHBNewer(name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	w.assocMark = len(w.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest))
	w.upf.set(func() { w.upf.hbRTS = ts; w.upf.assocRTS = ts })
	return nil
}

func (w *recWorld) upfAnswersNConsecutiveHB(n int, name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	w.upf.set(func() { w.upf.hbRTS = ts })
	start := w.upf.answeredHB()
	return recPoll(fmt.Sprintf("%d answered Heartbeat Requests", n), func() bool {
		return w.upf.answeredHB() >= start+n
	})
}

func (w *recWorld) upfAnswersHBWithoutRTS() error {
	w.upf.set(func() { w.upf.hbMode = "nonrts" })
	return recPoll("a Heartbeat Response without RTS", func() bool {
		for _, m := range w.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest) {
			if m.answered && m.answerRTS.IsZero() {
				return true
			}
		}
		return false
	})
}

func (w *recWorld) smfRerunsAssocWithDifferentRTS(name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	w.upf.set(func() { w.upf.assocRTS = ts; w.upf.assocCause = pfcpie.CauseRequestAccepted })
	if !w.s.runAssociationSetup(w.ctx) {
		return fmt.Errorf("re-run of PFCP Association Setup was not accepted")
	}
	return nil
}

// ---- UPF-side expectations (Association / Heartbeat sequence) ---------------

func (w *recWorld) upfReceivesAssocRequest(name string) error {
	want, err := recNamedTS(name)
	if err != nil {
		return err
	}
	if err := recPoll("an Association Setup Request", func() bool {
		return len(w.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest)) > 0
	}); err != nil {
		return err
	}
	m := w.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest)[0]
	if !m.hasNode {
		return fmt.Errorf("Association Setup Request lacks the Node ID IE")
	}
	if !m.rts.Equal(want) {
		return fmt.Errorf("Association Setup Request RTS = %v, want %s (%v)", m.rts, name, want)
	}
	return nil
}

func (w *recWorld) upfAnswersAssocResponse(causeName, rtsName string) error {
	cause, err := recCause(causeName)
	if err != nil {
		return err
	}
	ts, err := recNamedTS(rtsName)
	if err != nil {
		return err
	}
	if err := recPoll("an answered Association Setup Request", func() bool {
		for _, m := range w.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest) {
			if m.answered {
				return true
			}
		}
		return false
	}); err != nil {
		return err
	}
	w.upf.mu.Lock()
	gotCause, gotRTS := w.upf.assocCause, w.upf.assocRTS
	w.upf.mu.Unlock()
	if gotCause != cause || !gotRTS.Equal(ts) {
		return fmt.Errorf("fake UPF answered with cause=%d rts=%v, want cause=%d rts=%v", gotCause, gotRTS, cause, ts)
	}
	// The SMF must have accepted exactly that response.
	return recPoll("the SMF to accept the Association Setup Response", func() bool {
		return w.logs.has(map[string]any{"procedure": procAssocSetup, "result": "OK", "peer_rts": fmtRTS(ts)})
	})
}

func (w *recWorld) upfThenReceivesHB(name string) error {
	want, err := recNamedTS(name)
	if err != nil {
		return err
	}
	if err := recPoll("a Heartbeat Request after association", func() bool {
		return len(w.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest)) > 0
	}); err != nil {
		return err
	}
	var firstAssoc, firstHB = -1, -1
	for i, m := range w.upf.all() {
		if m.typ == pfcpmsg.MsgTypeAssociationSetupRequest && firstAssoc < 0 {
			firstAssoc = i
		}
		if m.typ == pfcpmsg.MsgTypeHeartbeatRequest && firstHB < 0 {
			firstHB = i
		}
	}
	if firstHB < firstAssoc {
		return fmt.Errorf("Heartbeat Request (#%d) precedes Association Setup Request (#%d)", firstHB, firstAssoc)
	}
	hb := w.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest)[0]
	if !hb.rts.Equal(want) {
		return fmt.Errorf("Heartbeat Request RTS = %v, want %s (%v)", hb.rts, name, want)
	}
	return nil
}

func (w *recWorld) upfAnswersHBCarrying(name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	return recPoll("a Heartbeat Response carrying "+name, func() bool {
		for _, m := range w.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest) {
			if m.answered && m.answerRTS.Equal(ts) {
				return true
			}
		}
		return false
	})
}

// ---- association state / baseline ----------------------------------------

func (w *recWorld) stateIs(want string) error {
	if got := w.s.PFCPAssociation().State; got != want {
		return fmt.Errorf("association state = %s, want %s", got, want)
	}
	return nil
}

func (w *recWorld) stateStays(want string) error {
	if err := recPoll("an Association Setup Request", func() bool {
		return len(w.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest)) > 0
	}); err != nil {
		return err
	}
	return w.stateIs(want)
}

func (w *recWorld) stateBecomesWithinDeadline(want string) error {
	return recPoll("association state "+want, func() bool { return w.s.PFCPAssociation().State == want })
}

func (w *recWorld) stateLeaves(state string) error {
	return recPoll("association state to leave "+state, func() bool { return w.s.PFCPAssociation().State != state })
}

func (w *recWorld) baselineIs(name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	return recPoll("baseline "+name, func() bool { return w.s.PFCPAssociation().RemoteRTS.Equal(ts) })
}

func (w *recWorld) baselineStill(name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	if got := w.s.PFCPAssociation().RemoteRTS; !got.Equal(ts) {
		return fmt.Errorf("baseline = %v, want still %s (%v)", got, name, ts)
	}
	return nil
}

func (w *recWorld) baselineIsNot(name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	if got := w.s.PFCPAssociation().RemoteRTS; got.Equal(ts) {
		return fmt.Errorf("baseline = %v must not be %s before a Heartbeat Response carries it", got, name)
	}
	return nil
}

// ---- logs / metrics -------------------------------------------------------

func (w *recWorld) logsProcResultSpec(proc, result, spec string) error {
	return recPoll(fmt.Sprintf("log procedure=%s result=%s spec_ref=%s", proc, result, spec), func() bool {
		return w.logs.has(map[string]any{"procedure": proc, "result": result, "spec_ref": spec})
	})
}

func (w *recWorld) logsProcResultCauseStr(proc, result, cause string) error {
	return recPoll(fmt.Sprintf("log procedure=%s result=%s cause=%s", proc, result, cause), func() bool {
		return w.logs.has(map[string]any{"procedure": proc, "result": result, "cause": cause})
	})
}

func (w *recWorld) logsProcResultCauseNum(proc, result string, cause int) error {
	return recPoll(fmt.Sprintf("log procedure=%s result=%s cause=%d", proc, result, cause), func() bool {
		return w.logs.has(map[string]any{"procedure": proc, "result": result, "cause": float64(cause)})
	})
}

func (w *recWorld) logsProcCauseOldNew(proc, cause, oldName, newName string) error {
	o, err := recNamedTS(oldName)
	if err != nil {
		return err
	}
	n, err := recNamedTS(newName)
	if err != nil {
		return err
	}
	return recPoll("recovery log with old/new RTS", func() bool {
		return w.logs.has(map[string]any{"procedure": proc, "cause": cause, "old_rts": fmtRTS(o), "new_rts": fmtRTS(n)})
	})
}

func (w *recWorld) logsProcCause(proc, cause string) error {
	return recPoll(fmt.Sprintf("log procedure=%s cause=%s", proc, cause), func() bool {
		return w.logs.has(map[string]any{"procedure": proc, "cause": cause})
	})
}

func (w *recWorld) logsSpecRef(spec string) error {
	return recPoll("recovery log with spec_ref "+spec, func() bool {
		return w.logs.has(map[string]any{"procedure": procRecovery, "spec_ref": spec})
	})
}

func (w *recWorld) doesNotLogProc(proc string) error {
	if w.logs.has(map[string]any{"procedure": proc}) {
		return fmt.Errorf("unexpected log with procedure %q", proc)
	}
	return nil
}

func (w *recWorld) doesNotLogProcCause(proc, cause string) error {
	if w.logs.has(map[string]any{"procedure": proc, "cause": cause}) {
		return fmt.Errorf("unexpected log with procedure %q cause %q", proc, cause)
	}
	return nil
}

func (w *recWorld) logsRTSMissingWarning(cause string) error {
	return recPoll("WARN log cause "+cause, func() bool {
		for _, e := range w.logs.entries() {
			msg, _ := e["msg"].(string)
			if e["level"] == "WARN" && e["cause"] == cause && strings.Contains(msg, "restart detection disabled") {
				return true
			}
		}
		return false
	})
}

func (w *recWorld) logsAssocRTSObservability(name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	return recPoll("Association Setup log with peer_rts "+name, func() bool {
		return w.logs.has(map[string]any{"procedure": procAssocSetup, "peer_rts": fmtRTS(ts)})
	})
}

func (w *recWorld) incrementsMetric(proc, result string) error {
	return recPoll(fmt.Sprintf("fivegc_procedure_total{SMF,%s,%s} to increase", proc, result), func() bool {
		return w.metricDelta(proc, result) >= 1
	})
}

// ---- transaction expectations ---------------------------------------------

// retransmitsSameSeq checks (for either message type) that one transaction was
// transmitted N1+1 times with the same sequence number, spaced by about T1.
func (w *recWorld) retransmitsSameSeq(typ uint8, what string) error {
	return recPoll(what+" transmitted N1+1 times with the same sequence number", func() bool {
		return recRetransmitGroupOK(w.upf.msgs(typ))
	})
}

func recRetransmitGroupOK(msgs []recMsg) bool {
	bySeq := map[uint32][]recMsg{}
	for _, m := range msgs {
		bySeq[m.seq] = append(bySeq[m.seq], m)
	}
	for _, g := range bySeq {
		if len(g) != recN1+1 {
			continue
		}
		ok := true
		for _, m := range g {
			if m.answered {
				ok = false
			}
		}
		for i := 1; i < len(g); i++ {
			if g[i].at.Sub(g[i-1].at) < recT1*8/10 {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (w *recWorld) assocRetransmitsAfterT1() error {
	return w.retransmitsSameSeq(pfcpmsg.MsgTypeAssociationSetupRequest, "Association Setup Request")
}

func (w *recWorld) hbRetransmitsAfterT1() error {
	return w.retransmitsSameSeq(pfcpmsg.MsgTypeHeartbeatRequest, "Heartbeat Request")
}

// firstAnsweredAssocIdx returns the index in the UPF log of the first answered
// Association Setup Request, or -1.
func (w *recWorld) firstAnsweredAssocIdx() int {
	for i, m := range w.upf.all() {
		if m.typ == pfcpmsg.MsgTypeAssociationSetupRequest && m.answered {
			return i
		}
	}
	return -1
}

func (w *recWorld) retriesAssocNoHeartbeatBeforeAccept() error {
	if err := recPoll("a new Association Setup attempt with a fresh sequence number", func() bool {
		reqs := w.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest)
		return len(reqs) > recN1+1 && reqs[recN1+1].seq != reqs[0].seq
	}); err != nil {
		return err
	}
	acc := -1
	if err := recPoll("an accepted Association Setup", func() bool {
		acc = w.firstAnsweredAssocIdx()
		return acc >= 0
	}); err != nil {
		return err
	}
	for i, m := range w.upf.all() {
		if m.typ == pfcpmsg.MsgTypeHeartbeatRequest && i < acc {
			return fmt.Errorf("Heartbeat Request (#%d) sent before the association was accepted (#%d)", i, acc)
		}
	}
	return nil
}

func (w *recWorld) hbImmediatelyAfterAccept() error {
	return recPoll("a Heartbeat Request after the accepted association", func() bool {
		acc := w.firstAnsweredAssocIdx()
		if acc < 0 {
			return false
		}
		for i, m := range w.upf.all() {
			if m.typ == pfcpmsg.MsgTypeHeartbeatRequest && i > acc {
				return true
			}
		}
		return false
	})
}

func (w *recWorld) noHeartbeatSent() error {
	if n := len(w.upf.msgs(pfcpmsg.MsgTypeHeartbeatRequest)); n != 0 {
		return fmt.Errorf("%d Heartbeat Requests sent without an association", n)
	}
	return nil
}

func (w *recWorld) anotherAssocAfterBackoff() error {
	return recPoll("another Association Setup Request (distinct sequence number)", func() bool {
		seqs := map[uint32]bool{}
		for _, m := range w.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest) {
			seqs[m.seq] = true
		}
		return len(seqs) >= 2
	})
}

func (w *recWorld) smfRerunsAssocSetup() error {
	return recPoll("a re-run of PFCP Association Setup", func() bool {
		return len(w.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest)) > w.assocMark
	})
}

func (w *recWorld) retriesAssocWithBackoff() error {
	return recPoll("repeated Association Setup attempts with distinct sequence numbers", func() bool {
		seqs := map[uint32]bool{}
		for i, m := range w.upf.msgs(pfcpmsg.MsgTypeAssociationSetupRequest) {
			if i >= w.assocMark {
				seqs[m.seq] = true
			}
		}
		return len(seqs) >= 2
	})
}

func (w *recWorld) noPFCPSessionDeletion() error {
	if n := len(w.upf.msgs(pfcpmsg.MsgTypeSessionDeletionRequest)); n != 0 {
		return fmt.Errorf("%d PFCP Session Deletion Requests sent to the UPF, want 0", n)
	}
	return nil
}

// ---- AMF expectations -----------------------------------------------------

// settleReleases waits for in-flight release workers; only called once a first
// release call is known to have been issued (so the worker is registered).
func (w *recWorld) settleReleases() { w.s.WaitPFCPRelease() }

func (w *recWorld) amfExactlyOneDelete(supi string, psi int) error {
	path := amfPath(supi, psi)
	if err := recPoll("AMF DELETE "+path, func() bool { return w.amf.count(path) >= 1 }); err != nil {
		return err
	}
	w.settleReleases()
	if n := w.amf.count(path); n != 1 {
		return fmt.Errorf("AMF received %d DELETE %s, want exactly 1 (calls: %+v)", n, path, w.amf.snapshot())
	}
	for _, c := range w.amf.snapshot() {
		if c.path == path && c.method != http.MethodDelete {
			return fmt.Errorf("method = %s, want DELETE", c.method)
		}
	}
	return nil
}

func (w *recWorld) amfReceivesNReleases(n int) error {
	w.settleReleases()
	if got := w.amf.count(""); got != n {
		return fmt.Errorf("AMF received %d release requests, want %d (calls: %+v)", got, n, w.amf.snapshot())
	}
	return nil
}

func (w *recWorld) amfNoReleaseFor(supi string) error {
	w.settleReleases()
	for _, c := range w.amf.snapshot() {
		if strings.Contains(c.path, supi) {
			return fmt.Errorf("unexpected release request for %s: %+v", supi, c)
		}
	}
	return nil
}

func (w *recWorld) amfSameCorrelationID() error {
	calls := w.amf.snapshot()
	if len(calls) == 0 {
		return fmt.Errorf("no release requests received")
	}
	for _, c := range calls {
		if c.corrID == "" || c.corrID != calls[0].corrID {
			return fmt.Errorf("X-Correlation-Id %q differs from %q", c.corrID, calls[0].corrID)
		}
	}
	return nil
}

func (w *recWorld) amfOneReleasePerSession() error {
	w.settleReleases()
	for _, rs := range w.sessions {
		if n := w.amf.count(amfPath(rs.supi, int(rs.psi))); n != 1 {
			return fmt.Errorf("session %s received %d release requests, want 1", rs.supi, n)
		}
	}
	return nil
}

func (w *recWorld) amfExactlyOneReleaseForEachOfN(n int) error {
	if err := recPoll(fmt.Sprintf("%d AMF release requests", n), func() bool { return w.amf.count("") >= n }); err != nil {
		return err
	}
	w.settleReleases()
	if len(w.sessions) != n {
		return fmt.Errorf("seeded %d sessions, step expects %d", len(w.sessions), n)
	}
	if got := w.amf.count(""); got != n {
		return fmt.Errorf("AMF received %d release requests, want %d", got, n)
	}
	return w.amfOneReleasePerSession()
}

func (w *recWorld) amfAnswersReleaseWith(status int) error {
	w.amf.setStatus(status)
	return nil
}

// ---- local release fallback ----------------------------------------------

func (w *recWorld) removedFromSessionTable() error {
	if len(w.sessions) == 0 {
		return fmt.Errorf("no sessions were seeded")
	}
	if err := recPoll("local release of the SM context", func() bool {
		for _, rs := range w.sessions {
			if _, ok := w.sessionByRef(rs.ref); ok {
				return false
			}
		}
		return true
	}); err != nil {
		return err
	}
	w.settleReleases()
	return nil
}

func (w *recWorld) ueIPReturnedToPool() error {
	p := w.s.ipPools["internet"]
	for _, rs := range w.sessions {
		p.mu.Lock()
		held := p.allocated[rs.ip.String()]
		p.mu.Unlock()
		if held {
			return fmt.Errorf("UE IP %s not returned to the pool", rs.ip)
		}
	}
	return nil
}

// ---- inbound Heartbeat Request on the receiver ----------------------------

func (w *recWorld) ensureReceiver() error {
	if w.receiver != nil {
		return nil
	}
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return fmt.Errorf("reserve receiver port: %w", err)
	}
	addr := l.LocalAddr().(*net.UDPAddr)
	_ = l.Close()
	w.s.cfg.N4.ReportListen = addr.String()
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		_ = w.s.StartPFCPReceiver(w.ctx)
	}()
	if err := recPoll("the PFCP receiver to listen", func() bool {
		return w.logs.has(map[string]any{"msg": "SMF: PFCP receiver listening"})
	}); err != nil {
		return err
	}
	w.receiver = addr
	return nil
}

func (w *recWorld) upfSendsInboundHB(seq int, name string) error {
	ts, err := recNamedTS(name)
	if err != nil {
		return err
	}
	if err := w.ensureReceiver(); err != nil {
		return err
	}
	// Source IP 127.0.0.1 equals the configured UPF peer IP.
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, w.receiver)
	if err != nil {
		return fmt.Errorf("dial receiver: %w", err)
	}
	defer c.Close()
	req := pfcpmsg.NewHeartbeatRequest(uint32(seq), pfcpie.NewRecoveryTimeStamp(ts), nil)
	b := make([]byte, req.MarshalLen())
	if err := req.MarshalTo(b); err != nil {
		return fmt.Errorf("marshal heartbeat request: %w", err)
	}
	if _, err := c.Write(b); err != nil {
		return fmt.Errorf("send heartbeat request: %w", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(recStepDeadline))
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		return fmt.Errorf("no Heartbeat Response from the SMF receiver: %w", err)
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	rsp, ok := msg.(*pfcpmsg.HeartbeatResponse)
	if !ok {
		return fmt.Errorf("got %T, want HeartbeatResponse", msg)
	}
	w.inboundRs = rsp
	return nil
}

func (w *recWorld) smfReturnsHBResponse(seq int, name string) error {
	want, err := recNamedTS(name)
	if err != nil {
		return err
	}
	if w.inboundRs == nil {
		return fmt.Errorf("no Heartbeat Response was received")
	}
	if w.inboundRs.Sequence() != uint32(seq) {
		return fmt.Errorf("sequence number = %d, want %d", w.inboundRs.Sequence(), seq)
	}
	if w.inboundRs.RecoveryTimeStamp == nil {
		return fmt.Errorf("Heartbeat Response carries no Recovery Time Stamp")
	}
	got, err := w.inboundRs.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		return fmt.Errorf("decode Recovery Time Stamp: %w", err)
	}
	if !got.Equal(want) {
		return fmt.Errorf("response RTS = %v, want %s (%v)", got, name, want)
	}
	return nil
}

// ---- wiring ---------------------------------------------------------------

// InitializePfcpNodeLevelRecoveryScenario wires every step of
// pfcp_node_level_recovery.feature. Named distinctly from the other scenario
// initializers in this package (godog forbids duplicates).
func InitializePfcpNodeLevelRecoveryScenario(ctx *godog.ScenarioContext) {
	w := &recWorld{}

	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return c, nil
	})
	ctx.After(func(c context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.teardown()
		return c, nil
	})

	// Background
	ctx.Step(`^a fake UPF PFCP peer listening on a loopback UDP socket with Recovery Time Stamp "([^"]*)"$`, w.fakeUPFListening)
	ctx.Step(`^a fake AMF management API that accepts PDU session release requests with (\d+)$`, func(st int) error { return w.fakeAMFAccepts(st) })
	ctx.Step(`^the SMF PFCP node supervisor is configured with the fake UPF as peer and short T1, N1, heartbeat interval and association retry timers$`, w.supervisorConfigured)
	ctx.Step(`^the SMF has Recovery Time Stamp "([^"]*)"$`, w.smfHasRTS)

	// Supervisor / state
	ctx.Step(`^the SMF PFCP node supervisor is started$`, w.startSupervisor)
	ctx.Step(`^the SMF is associated with the fake UPF with baseline Recovery Time Stamp "([^"]*)"$`, w.associatedWithBaseline)
	ctx.Step(`^the SMF PFCP association state is "([^"]*)"$`, w.stateIs)
	ctx.Step(`^the SMF PFCP association state stays "([^"]*)"$`, w.stateStays)
	ctx.Step(`^the SMF PFCP association state becomes "([^"]*)" within the deadline$`, w.stateBecomesWithinDeadline)
	ctx.Step(`^the SMF PFCP association state leaves "([^"]*)"$`, w.stateLeaves)
	ctx.Step(`^the SMF tracked UPF Recovery Time Stamp baseline is "([^"]*)"$`, w.baselineIs)
	ctx.Step(`^the SMF tracked UPF Recovery Time Stamp baseline is still "([^"]*)"$`, w.baselineStill)
	ctx.Step(`^the SMF tracked UPF Recovery Time Stamp baseline is not "([^"]*)" until a Heartbeat Response carries it$`, w.baselineIsNot)
	ctx.Step(`^the SMF tracked UPF Recovery Time Stamp baseline becomes "([^"]*)" after the next Heartbeat Response$`, w.baselineIs)

	// Sessions
	ctx.Step(`^the SMF holds (\d+) active PDU sessions established on the UPF$`, w.holdsNSessions)
	ctx.Step(`^the SMF holds 2 active PDU sessions "([^"]*)" PSI (\d+) and "([^"]*)" PSI (\d+) established on the UPF before Recovery Time Stamp "([^"]*)"$`, w.holdsTwoNamedSessions)
	ctx.Step(`^the SMF holds a PDU session "([^"]*)" PSI (\d+) established on the UPF (before|at or after) Recovery Time Stamp "([^"]*)"$`, w.holdsSessionQualified)
	ctx.Step(`^the SMF holds an active PDU session "([^"]*)" PSI (\d+)( with an allocated UE IP)? established on the UPF(?: before Recovery Time Stamp "([^"]*)")?$`, w.holdsActiveSession)
	ctx.Step(`^both PDU sessions remain in state "ACTIVE"$`, w.allSessionsActive)
	ctx.Step(`^the PDU session of "([^"]*)" remains in state "([^"]*)"$`, w.sessionRemainsActive)

	// Fake UPF scripting
	ctx.Step(`^the fake UPF drops the first (\d+) PFCP Association Setup Requests without answering$`, w.upfDropsFirstAssoc)
	ctx.Step(`^the fake UPF answers PFCP Association Setup Requests with Cause "([^"]*)"$`, w.upfAnswersAssocWithCause)
	ctx.Step(`^the fake UPF starts answering PFCP Association Setup Requests with Cause "([^"]*)"$`, w.upfStartsAnsweringAssoc)
	ctx.Step(`^the fake UPF starts answering again$`, w.upfStartsAnsweringAgain)
	ctx.Step(`^the fake UPF stops answering PFCP Heartbeat Requests$`, w.upfStopsAnsweringHeartbeats)
	ctx.Step(`^the fake UPF (?:restarts and )?answers the next PFCP Heartbeat Request with the newer Recovery Time Stamp "([^"]*)"$`, w.upfAnswersNextHBNewer)
	ctx.Step(`^the fake UPF answers (\d+) (?:consecutive periodic|further) PFCP Heartbeat Requests with Recovery Time Stamp "([^"]*)"$`, w.upfAnswersNConsecutiveHB)
	ctx.Step(`^the fake UPF answers the next PFCP Heartbeat Request with a Heartbeat Response that has no Recovery Time Stamp$`, w.upfAnswersHBWithoutRTS)
	ctx.Step(`^the SMF re-runs PFCP Association Setup and the fake UPF answers with Cause "Request accepted" and a different Recovery Time Stamp "([^"]*)"$`, w.smfRerunsAssocWithDifferentRTS)
	ctx.Step(`^the fake UPF sends a PFCP Heartbeat Request with sequence number (\d+) and (?:the newer )?Recovery Time Stamp "([^"]*)" to the SMF PFCP receiver$`, w.upfSendsInboundHB)

	// UPF-side expectations
	ctx.Step(`^the fake UPF receives a PFCP Association Setup Request with Node ID and Recovery Time Stamp "([^"]*)"$`, w.upfReceivesAssocRequest)
	ctx.Step(`^the fake UPF answers with a PFCP Association Setup Response with Cause "([^"]*)" and Recovery Time Stamp "([^"]*)"$`, w.upfAnswersAssocResponse)
	ctx.Step(`^the fake UPF then receives a PFCP Heartbeat Request carrying Recovery Time Stamp "([^"]*)"$`, w.upfThenReceivesHB)
	ctx.Step(`^the fake UPF answers with a PFCP Heartbeat Response carrying Recovery Time Stamp "([^"]*)"$`, w.upfAnswersHBCarrying)
	ctx.Step(`^the SMF retransmits the PFCP Association Setup Request with the same sequence number after T1, up to N1 retransmissions$`, w.assocRetransmitsAfterT1)
	ctx.Step(`^the SMF retransmits the PFCP Heartbeat Request with the same sequence number after T1, N1 times$`, w.hbRetransmitsAfterT1)
	ctx.Step(`^the SMF retries the PFCP Association Setup with backoff and no PFCP Heartbeat Request is sent before the association is accepted$`, w.retriesAssocNoHeartbeatBeforeAccept)
	ctx.Step(`^the SMF sends a PFCP Heartbeat Request immediately after the association is accepted$`, w.hbImmediatelyAfterAccept)
	ctx.Step(`^the SMF sends no PFCP Heartbeat Request$`, w.noHeartbeatSent)
	ctx.Step(`^the SMF sends another PFCP Association Setup Request after the retry backoff$`, w.anotherAssocAfterBackoff)
	ctx.Step(`^the SMF re-runs PFCP Association Setup with the fake UPF$`, w.smfRerunsAssocSetup)
	ctx.Step(`^the SMF retries PFCP Association Setup with backoff$`, w.retriesAssocWithBackoff)
	ctx.Step(`^no PFCP Session Deletion Request is sent to the UPF for the released sessions$`, w.noPFCPSessionDeletion)

	// Logs / metrics
	ctx.Step(`^the SMF logs procedure "([^"]*)" with result "([^"]*)" and spec_ref "([^"]*)"$`, w.logsProcResultSpec)
	ctx.Step(`^the SMF logs procedure "([^"]*)" with result "([^"]*)" and cause "([^"]*)"$`, w.logsProcResultCauseStr)
	ctx.Step(`^the SMF logs procedure "([^"]*)" with result "([^"]*)" and cause (\d+)$`, w.logsProcResultCauseNum)
	ctx.Step(`^the SMF logs procedure "([^"]*)" with cause "([^"]*)", old_rts "([^"]*)" and new_rts "([^"]*)"$`, w.logsProcCauseOldNew)
	ctx.Step(`^the SMF logs procedure "([^"]*)" with cause "([^"]*)"$`, w.logsProcCause)
	ctx.Step(`^the SMF logs spec_ref "([^"]*)"$`, w.logsSpecRef)
	ctx.Step(`^the SMF does not log procedure "([^"]*)"$`, w.doesNotLogProc)
	ctx.Step(`^the SMF does not log procedure "([^"]*)" with cause "([^"]*)"$`, w.doesNotLogProcCause)
	ctx.Step(`^the SMF logs a warning with cause "([^"]*)" that restart detection is disabled$`, w.logsRTSMissingWarning)
	ctx.Step(`^the SMF logs the UPF Recovery Time Stamp "([^"]*)" from the Association Setup Response for observability only$`, w.logsAssocRTSObservability)
	ctx.Step(`^the SMF increments fivegc_procedure_total for nf "SMF" procedure "([^"]*)" with result "([^"]*)"$`, w.incrementsMetric)

	// AMF management API
	ctx.Step(`^the fake AMF management API answers release requests with (\d+)$`, w.amfAnswersReleaseWith)
	ctx.Step(`^the fake AMF management API receives exactly one DELETE "/amf/v1/ue-contexts/([^/"]*)/pdu-sessions/(\d+)"$`, w.amfExactlyOneDelete)
	ctx.Step(`^the fake AMF management API receives (\d+) release requests$`, w.amfReceivesNReleases)
	ctx.Step(`^the fake AMF management API receives no release request for "([^"]*)"$`, w.amfNoReleaseFor)
	ctx.Step(`^each release request carries the same X-Correlation-Id header$`, w.amfSameCorrelationID)
	ctx.Step(`^the fake AMF management API still has exactly one release request per session$`, w.amfOneReleasePerSession)
	ctx.Step(`^the fake AMF management API receives exactly one release request for each of the (\d+) PDU sessions$`, w.amfExactlyOneReleaseForEachOfN)

	// Local release fallback
	ctx.Step(`^the SMF releases the SM context locally and the session is removed from the SMF session table$`, w.removedFromSessionTable)
	ctx.Step(`^the UE IP address is returned to the IP pool$`, w.ueIPReturnedToPool)

	// Inbound Heartbeat Request
	ctx.Step(`^the SMF returns a PFCP Heartbeat Response with sequence number (\d+) and Recovery Time Stamp "([^"]*)"$`, w.smfReturnsHBResponse)
}

// TestPfcpNodeLevelRecoveryFeatures runs pfcp_node_level_recovery.feature
// against the in-process SMF PFCP node supervisor (SMF-004).
func TestPfcpNodeLevelRecoveryFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializePfcpNodeLevelRecoveryScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/pfcp_node_level_recovery.feature"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
