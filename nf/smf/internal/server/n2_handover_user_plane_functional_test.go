//go:build functional

// godog step definitions for n2_handover_user_plane.feature (SMF-005): the synchronous DL path
// switch (N2 hoState COMPLETED, Xn PATH_SWITCH_REQ), the release-or-deactivate of target-failed
// PDU sessions (HANDOVER_RES_ALLOC_FAIL + upCnxState DEACTIVATED, PATH_SWITCH_SETUP_FAIL) and
// rule R1. The shared world (hoStepsWorld) and the common steps live in
// handover_n2sm_functional_test.go; this file adds the RESPONDING fake UPF (PFCP Session
// Modification Response with a configurable Cause, or silent), the recording AMF management
// API fake and the SMF-005 steps. In-process: the real handleUpdateSMContext runs behind an
// httptest.ResponseRecorder; no sleeps, only deadline polling.
// Run with: go test -tags=functional ./nf/smf/...
// Ref: TS 23.502 §4.9.1.3.2-3, §4.9.1.2.2, §4.3.7, §4.3.4.2; TS 29.502 §5.2.2.3.3-4;
// TS 29.244 §7.5.4, §7.5.5.
package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

const (
	// hoStepsUPFAnswerDelay is the processing time of the responding fake UPF; the "answered only
	// after the UPF responded" assertion needs the SMF to have waited at least this long.
	hoStepsUPFAnswerDelay = 60 * time.Millisecond
	// hoStepsWithin is the "within 2 seconds" budget of the feature.
	hoStepsWithin = 2 * time.Second
	// hoStepsDrainTimeout bounds the wait for detached SMF goroutines.
	hoStepsDrainTimeout = 6 * time.Second
	// FAR Apply Action bits, TS 29.244 §8.2.26.
	hoStepsApplyDROP = 0x01
	hoStepsApplyFORW = 0x02
)

// ---- responding fake UPF ---------------------------------------------------------------------

// hoStepsPFCPReq is one PFCP message received by the fake UPF.
type hoStepsPFCPReq struct {
	msg        pfcpmsg.Message
	answeredAt time.Time // taken just before the response is written; zero when not answered
}

// hoStepsUPF is a UDP fake UPF that records every PFCP message and answers Session
// Modification Requests per its mode.
type hoStepsUPF struct {
	conn *net.UDPConn
	done chan struct{}

	mu    sync.Mutex
	mode  string // "respond" | "nocause" | "silent"
	cause uint8
	reqs  []*hoStepsPFCPReq
}

func newHOStepsUPF() (*hoStepsUPF, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, fmt.Errorf("listen fake UPF: %w", err)
	}
	u := &hoStepsUPF{conn: conn, done: make(chan struct{}), mode: "respond", cause: pfcpie.CauseRequestAccepted}
	go u.serve()
	return u, nil
}

func (u *hoStepsUPF) addr() string { return u.conn.LocalAddr().String() }

func (u *hoStepsUPF) close() {
	_ = u.conn.Close()
	<-u.done
}

func (u *hoStepsUPF) serve() {
	defer close(u.done)
	buf := make([]byte, 4096)
	for {
		n, raddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg, err := pfcpmsg.Parse(buf[:n])
		if err != nil {
			continue
		}
		rec := &hoStepsPFCPReq{msg: msg}
		u.mu.Lock()
		u.reqs = append(u.reqs, rec)
		mode, cause := u.mode, u.cause
		u.mu.Unlock()
		req, ok := msg.(*pfcpmsg.SessionModificationRequest)
		if !ok || mode == "silent" {
			continue
		}
		time.Sleep(hoStepsUPFAnswerDelay) // simulated UPF processing time, not a synchronisation wait
		var ies []*pfcpie.IE
		if mode != "nocause" {
			ies = append(ies, pfcpie.NewCause(cause))
		}
		rsp := pfcpmsg.NewSessionModificationResponse(0, 0, req.SEID(), req.Sequence(), 0, ies...)
		b, err := rsp.Marshal()
		if err != nil {
			continue
		}
		u.mu.Lock()
		rec.answeredAt = time.Now()
		u.mu.Unlock()
		_, _ = u.conn.WriteToUDP(b, raddr)
	}
}

func (u *hoStepsUPF) setMode(mode string, cause uint8) {
	u.mu.Lock()
	u.mode, u.cause = mode, cause
	u.mu.Unlock()
}

func (u *hoStepsUPF) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

// modification returns the i-th received message as a Session Modification Request.
func (u *hoStepsUPF) modification(i int) (*pfcpmsg.SessionModificationRequest, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if i >= len(u.reqs) {
		return nil, fmt.Errorf("fake UPF received %d PFCP messages, want at least %d", len(u.reqs), i+1)
	}
	req, ok := u.reqs[i].msg.(*pfcpmsg.SessionModificationRequest)
	if !ok {
		return nil, fmt.Errorf("PFCP message #%d is %s, want Session Modification Request", i, u.reqs[i].msg.MessageTypeName())
	}
	return req, nil
}

func (u *hoStepsUPF) answeredAt(i int) time.Time {
	u.mu.Lock()
	defer u.mu.Unlock()
	if i >= len(u.reqs) {
		return time.Time{}
	}
	return u.reqs[i].answeredAt
}

// ---- recording AMF management API fake ---------------------------------------------------------

type hoStepsAMFCall struct{ method, path string }

// hoStepsAMF records the SMF-initiated PDU session release requests (DELETE
// /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}, TS 23.502 §4.3.4.2).
type hoStepsAMF struct {
	srv    *httptest.Server
	status atomic.Int32

	mu    sync.Mutex
	calls []hoStepsAMFCall
}

func newHOStepsAMF(status int) *hoStepsAMF {
	a := &hoStepsAMF{}
	a.status.Store(int32(status))
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.calls = append(a.calls, hoStepsAMFCall{r.Method, r.URL.Path})
		a.mu.Unlock()
		w.WriteHeader(int(a.status.Load()))
	}))
	return a
}

func (a *hoStepsAMF) host() string { return strings.TrimPrefix(a.srv.URL, "http://") }
func (a *hoStepsAMF) close()       { a.srv.Close() }

func (a *hoStepsAMF) snapshot() []hoStepsAMFCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]hoStepsAMFCall(nil), a.calls...)
}

// ---- polling helpers ----------------------------------------------------------------------------

// poll re-evaluates cond until it holds or the deadline passes; it returns the last error.
func hoStepsPoll(d time.Duration, cond func() error) error {
	deadline := time.Now().Add(d)
	for {
		err := cond()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// drain waits for the detached release / deactivation goroutines of the SMF.
func (w *hoStepsWorld) drain() error {
	done := make(chan struct{})
	go func() { w.srv.WaitHandoverTasks(); close(done) }()
	select {
	case <-done:
		return nil
	case <-time.After(hoStepsDrainTimeout):
		return fmt.Errorf("detached handover tasks still running after %s", hoStepsDrainTimeout)
	}
}

// exactlyOneWithin waits up to d for the first PFCP message, lets the detached tasks finish and
// asserts that exactly one message was sent.
func (w *hoStepsWorld) exactlyOneWithin(d time.Duration) error {
	if err := hoStepsPoll(d, func() error {
		if w.upf.count() == 0 {
			return fmt.Errorf("no PFCP message reached the UPF within %s", d)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := w.drain(); err != nil {
		return err
	}
	if n := w.upf.count(); n != 1 {
		return fmt.Errorf("PFCP sends = %d, want exactly 1", n)
	}
	return nil
}

// dlOuterHeader returns the Outer Header Creation of the first Update FAR's Update Forwarding Parameters.
func dlOuterHeader(req *pfcpmsg.SessionModificationRequest) (*pfcpie.OuterHeaderCreationFields, error) {
	if len(req.UpdateFAR) != 1 || req.UpdateFAR[0] == nil {
		return nil, fmt.Errorf("Session Modification Request carries %d Update FAR, want 1", len(req.UpdateFAR))
	}
	fp, err := req.UpdateFAR[0].UpdateForwardingParameters()
	if err != nil {
		return nil, fmt.Errorf("Update FAR has no Update Forwarding Parameters: %w", err)
	}
	for _, ie := range fp {
		if ie.Type != pfcpie.OuterHeaderCreation {
			continue
		}
		ohc, err := ie.OuterHeaderCreation()
		if err != nil {
			return nil, fmt.Errorf("Outer Header Creation does not parse: %w", err)
		}
		return ohc, nil
	}
	return nil, fmt.Errorf("no Outer Header Creation in the Update Forwarding Parameters")
}

// ---- Givens -------------------------------------------------------------------------------------

func (w *hoStepsWorld) upfAnswersCause(cause int) error {
	w.upf.setMode("respond", uint8(cause))
	return nil
}

func (w *hoStepsWorld) upfAnswersWithoutCause() error {
	w.upf.setMode("nocause", 0)
	return nil
}

func (w *hoStepsWorld) upfSilent() error {
	w.upf.setMode("silent", 0)
	return nil
}

func (w *hoStepsWorld) amfRelease(accept bool) error {
	if accept {
		w.amf.status.Store(http.StatusNoContent)
	} else {
		w.amf.status.Store(http.StatusInternalServerError)
	}
	return nil
}

func (w *hoStepsWorld) upSecurityPolicy(not string) error {
	w.srv.sessionMu.Lock()
	w.sess.UPSecurityRequired = not == ""
	w.srv.sessionMu.Unlock()
	return nil
}

// hasHOStateAndTunnel drives a valid HANDOVER_REQ_ACK (hoState PREPARED + stored tunnel) and
// then forces the HOState the scenario names.
func (w *hoStepsWorld) hasHOStateAndTunnel(ref, state string) error {
	if err := w.preparedWithTunnel(ref); err != nil {
		return err
	}
	w.srv.sessionMu.Lock()
	w.sess.HOState = state
	w.srv.sessionMu.Unlock()
	return nil
}

func (w *hoStepsWorld) sessionInState(ref, state string) error {
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	if w.srv.sessions[ref] != w.sess {
		return fmt.Errorf("session %q is not the scenario session", ref)
	}
	w.sess.State = state
	return nil
}

// sentCompletedAnswered200 is the Given form of the COMPLETED request.
func (w *hoStepsWorld) sentCompletedAnswered200(ref string) error {
	if err := w.completedNoN2(ref); err != nil {
		return err
	}
	if err := w.respondsStatus(200); err != nil {
		return fmt.Errorf("precondition COMPLETED: %w", err)
	}
	return nil
}

func (w *hoStepsWorld) pathSwitchReqBytes(ref, hexStr string) error {
	raw, err := decodeHex(hexStr)
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{
		"toBeSwitched": true, "n2SmInfoType": "PATH_SWITCH_REQ", "n2SmInfo": b64(raw)})
}

func (w *hoStepsWorld) setupFailCause(ref, cause string) error {
	v, ok := hoStepsRadioNetwork[cause]
	if !ok {
		return fmt.Errorf("unmapped radioNetwork cause %q", cause)
	}
	tr, err := hoStepsMarshal(ngapType.PathSwitchRequestSetupFailedTransfer{Cause: ngapType.Cause{
		Present: ngapType.CausePresentRadioNetwork, RadioNetwork: &ngapType.CauseRadioNetwork{Value: v}}})
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{
		"failedToBeSwitched": true, "n2SmInfoType": "PATH_SWITCH_SETUP_FAIL", "n2SmInfo": b64(tr)})
}

// resAllocFailCause posts HANDOVER_RES_ALLOC_FAIL with the named radioNetwork cause.
func (w *hoStepsWorld) resAllocFailCause(ref, cause string) error {
	v, ok := hoStepsRadioNetwork[cause]
	if !ok {
		return fmt.Errorf("unmapped radioNetwork cause %q", cause)
	}
	w.relayedCause = ngapCause(ngapType.CausePresentRadioNetwork, v)
	tr, err := hoStepsMarshal(ngapType.HandoverResourceAllocationUnsuccessfulTransfer{Cause: w.relayedCause})
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{
		"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_RES_ALLOC_FAIL", "n2SmInfo": b64(tr)})
}

// sentResAllocFail is the Given form: the request is made and must be answered 403.
func (w *hoStepsWorld) sentResAllocFail(ref, cause string) error {
	if err := w.resAllocFailCause(ref, cause); err != nil {
		return err
	}
	if err := w.respondsStatus(403); err != nil {
		return fmt.Errorf("precondition HANDOVER_RES_ALLOC_FAIL: %w", err)
	}
	return nil
}

func (w *hoStepsWorld) sentZeroPFCPSoFar() error {
	if n := w.upf.count(); n != 0 {
		return fmt.Errorf("SMF sent %d PFCP messages so far, want 0", n)
	}
	return nil
}

func (w *hoStepsWorld) deactivated(ref string) error {
	return w.post(ref, map[string]interface{}{"upCnxState": "DEACTIVATED"})
}

// ---- Thens: responses ---------------------------------------------------------------------------

func (w *hoStepsWorld) responds204() error {
	if err := w.respondsStatus(204); err != nil {
		return err
	}
	if w.rec.Body.Len() != 0 {
		return fmt.Errorf("204 carries a body: %q", w.rec.Body.String())
	}
	return nil
}

func (w *hoStepsWorld) pathSwitchFailTransferCause(group, name string) error {
	b, err := w.respTransfer()
	if err != nil {
		return err
	}
	var tr ngapType.PathSwitchRequestUnsuccessfulTransfer
	if err := aper.UnmarshalWithParams(b, &tr, "valueExt"); err != nil {
		return fmt.Errorf("PathSwitchRequestUnsuccessfulTransfer does not decode: %w", err)
	}
	return hoStepsCauseIs(tr.Cause, group, name)
}

func (w *hoStepsWorld) pathSwitchFailTransferCauseNum(group, name string, num int) error {
	if want, ok := hoStepsRadioNetwork[name]; ok && int(want) != num {
		return fmt.Errorf("feature maps %q to %d, TS 38.413 has %d", name, num, want)
	}
	return w.pathSwitchFailTransferCause(group, name)
}

func (w *hoStepsWorld) prepFailSameCause() error {
	tr, err := w.prepFailTransfer()
	if err != nil {
		return err
	}
	if tr.Cause.Present != w.relayedCause.Present || ngapCauseValue(tr.Cause) != ngapCauseValue(w.relayedCause) {
		return fmt.Errorf("HANDOVER_PREP_FAIL Cause = %+v, want the relayed %+v", tr.Cause, w.relayedCause)
	}
	return nil
}

func (w *hoStepsWorld) prepFailRadioCause(name string) error {
	tr, err := w.prepFailTransfer()
	if err != nil {
		return err
	}
	return hoStepsCauseIs(tr.Cause, "radioNetwork", name)
}

func (w *hoStepsWorld) answeredWithin2s() error {
	if d := w.postEnd.Sub(w.postStart); d >= hoStepsWithin {
		return fmt.Errorf("SMF answered after %s, want < %s", d, hoStepsWithin)
	}
	return nil
}

func (w *hoStepsWorld) answeredAfterUPF() error {
	if w.upf.count() == 0 {
		return fmt.Errorf("the UPF received no PFCP request")
	}
	at := w.upf.answeredAt(0)
	if at.IsZero() {
		return fmt.Errorf("the fake UPF never answered the PFCP request")
	}
	if at.After(w.postEnd) {
		return fmt.Errorf("the SMF answered the AMF at %s, before the UPF answered at %s", w.postEnd.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano))
	}
	if d := w.postEnd.Sub(w.postStart); d < hoStepsUPFAnswerDelay {
		return fmt.Errorf("the SMF answered after %s, less than the UPF processing time %s", d, hoStepsUPFAnswerDelay)
	}
	return nil
}

// ---- Thens: PFCP --------------------------------------------------------------------------------

func (w *hoStepsWorld) oneModificationNoTarget() error { return w.exactlyOneWithin(hoStepsWithin) }

func (w *hoStepsWorld) oneModificationInTotal() error {
	if err := w.drain(); err != nil {
		return err
	}
	if n := w.upf.count(); n != 1 {
		return fmt.Errorf("PFCP sends in total = %d, want exactly 1", n)
	}
	return nil
}

func (w *hoStepsWorld) updateFAR(action string) error {
	req, err := w.upf.modification(0)
	if err != nil {
		return err
	}
	if len(req.UpdateFAR) != 1 || req.UpdateFAR[0] == nil {
		return fmt.Errorf("Session Modification Request carries %d Update FAR, want 1", len(req.UpdateFAR))
	}
	children, err := req.UpdateFAR[0].UpdateFAR()
	if err != nil {
		return fmt.Errorf("Update FAR does not parse: %w", err)
	}
	var gotID uint32
	var gotAction uint8
	var haveID, haveAction bool
	for _, c := range children {
		switch c.Type {
		case pfcpie.FARID:
			gotID, _ = c.FARID()
			haveID = true
		case pfcpie.ApplyAction:
			gotAction, _ = c.ApplyAction()
			haveAction = true
		}
	}
	if !haveID || gotID != 1 {
		return fmt.Errorf("Update FAR FAR ID = %d (present %v), want 1", gotID, haveID)
	}
	want := uint8(hoStepsApplyFORW)
	if action == "DROP" {
		want = hoStepsApplyDROP
	}
	if !haveAction || gotAction != want {
		return fmt.Errorf("Update FAR Apply Action = %#x (present %v), want %s (%#x)", gotAction, haveAction, action, want)
	}
	return nil
}

func (w *hoStepsWorld) farOHCStored() error {
	req, err := w.upf.modification(0)
	if err != nil {
		return err
	}
	ohc, err := dlOuterHeader(req)
	if err != nil {
		return err
	}
	return w.checkOHC(ohc)
}

func (w *hoStepsWorld) checkOHC(ohc *pfcpie.OuterHeaderCreationFields) error {
	const gtpuUDPIPv4 = 0x0100 // TS 29.244 §8.2.56: GTP-U/UDP/IPv4
	if ohc.OuterHeaderCreationDescription != gtpuUDPIPv4 {
		return fmt.Errorf("Outer Header Creation description = %#x, want GTP-U/UDP/IPv4 (%#x)", ohc.OuterHeaderCreationDescription, gtpuUDPIPv4)
	}
	if ohc.TEID != w.sentTEID || !ohc.IPv4Address.Equal(net.IP(w.sentIP[:])) {
		return fmt.Errorf("Outer Header Creation = %s/%#x, want %v/%#x", ohc.IPv4Address, ohc.TEID, net.IP(w.sentIP[:]), w.sentTEID)
	}
	return nil
}

func (w *hoStepsWorld) farNoForwardingParams() error {
	req, err := w.upf.modification(0)
	if err != nil {
		return err
	}
	if len(req.UpdateFAR) != 1 || req.UpdateFAR[0] == nil {
		return fmt.Errorf("Session Modification Request carries %d Update FAR, want 1", len(req.UpdateFAR))
	}
	children, err := req.UpdateFAR[0].UpdateFAR()
	if err != nil {
		return err
	}
	for _, c := range children {
		if c.Type == pfcpie.UpdateForwardingParameters {
			return fmt.Errorf("Update FAR carries Update Forwarding Parameters, want none")
		}
	}
	return nil
}

func (w *hoStepsWorld) noOtherRules() error {
	req, err := w.upf.modification(0)
	if err != nil {
		return err
	}
	if n := len(req.CreatePDR) + len(req.UpdatePDR) + len(req.CreateQER) + len(req.UpdateQER); n != 0 {
		return fmt.Errorf("Session Modification Request carries Create PDR=%d Update PDR=%d Create QER=%d Update QER=%d, want none",
			len(req.CreatePDR), len(req.UpdatePDR), len(req.CreateQER), len(req.UpdateQER))
	}
	return nil
}

// ---- Thens: session state -----------------------------------------------------------------------

func (w *hoStepsWorld) stateIs(want string) error {
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	if w.sess.State != want {
		return fmt.Errorf("session state = %q, want %q", w.sess.State, want)
	}
	return nil
}

func (w *hoStepsWorld) stateIsNot(not string) error {
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	if w.sess.State == not {
		return fmt.Errorf("session state = %q, want anything else", not)
	}
	return nil
}

func (w *hoStepsWorld) stateWithin2s(want string) error {
	return hoStepsPoll(hoStepsWithin, func() error { return w.stateIs(want) })
}

func (w *hoStepsWorld) notReleased() error {
	if err := w.drain(); err != nil {
		return err
	}
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	for ref, s := range w.srv.sessions {
		if s == w.sess {
			if s.State == sessionStateReleasing {
				return fmt.Errorf("session %q is RELEASING, want not released", ref)
			}
			return nil
		}
	}
	return fmt.Errorf("session was removed from the SMF, want not released")
}

func (w *hoStepsWorld) targetFailed(want bool) error {
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	if w.sess.HOTargetFailed != want {
		return fmt.Errorf("session HOTargetFailed = %v, want %v", w.sess.HOTargetFailed, want)
	}
	return nil
}

// ---- Thens: AMF management API ------------------------------------------------------------------

func (w *hoStepsWorld) amfNoRelease() error {
	if err := w.drain(); err != nil {
		return err
	}
	if calls := w.amf.snapshot(); len(calls) != 0 {
		return fmt.Errorf("AMF management API received %d requests (%v), want none", len(calls), calls)
	}
	return nil
}

func (w *hoStepsWorld) amfReleaseWithin2s(ref string, psi int) error {
	w.srv.sessionMu.Lock()
	known := w.srv.sessions[ref] == w.sess
	w.srv.sessionMu.Unlock()
	if !known {
		return fmt.Errorf("session %q is not the scenario session", ref)
	}
	want := fmt.Sprintf("/amf/v1/ue-contexts/%s/pdu-sessions/%d", w.sess.SUPI, psi)
	return hoStepsPoll(hoStepsWithin, func() error {
		for _, c := range w.amf.snapshot() {
			if c.method == http.MethodDelete && c.path == want {
				return nil
			}
		}
		return fmt.Errorf("AMF management API did not receive DELETE %s (calls %v)", want, w.amf.snapshot())
	})
}

// ---- Thens: logs --------------------------------------------------------------------------------

func (w *hoStepsWorld) logsN4(proc, iface, dir, msgType, causeStr, specRef string) error {
	if _, ok := w.logs.find(func(r hoRec) bool {
		return r.attrs["procedure"] == proc && r.attrs["interface"] == iface && r.attrs["direction"] == dir &&
			r.attrs["message_type"] == msgType && r.attrs["spec_ref"] == specRef &&
			(causeStr == "" || r.attrs["pfcp_cause"] == causeStr)
	}); !ok {
		return fmt.Errorf("no log record with procedure %q interface %q direction %q message_type %q pfcp_cause %q spec_ref %q",
			proc, iface, dir, msgType, causeStr, specRef)
	}
	return nil
}

func (w *hoStepsWorld) logsAttrs(proc string, kv ...string) error {
	_, ok := w.logs.find(func(r hoRec) bool {
		if r.attrs["procedure"] != proc {
			return false
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if r.attrs[kv[i]] != kv[i+1] {
				return false
			}
		}
		return true
	})
	if !ok {
		return fmt.Errorf("no log record with procedure %q and %v", proc, kv)
	}
	return nil
}

func (w *hoStepsWorld) logsAttrsWithin2s(proc string, kv ...string) error {
	if err := hoStepsPoll(hoStepsWithin, func() error { return w.logsAttrs(proc, kv...) }); err != nil {
		return err
	}
	return nil
}

func (w *hoStepsWorld) logLevelAttr(level slog.Level, key, val string) bool {
	_, ok := w.logs.find(func(r hoRec) bool { return r.level == level && r.attrs[key] == val })
	return ok
}

func levelByName(name string) slog.Level {
	switch name {
	case "ERROR":
		return slog.LevelError
	case "WARN":
		return slog.LevelWarn
	case "INFO":
		return slog.LevelInfo
	}
	return slog.LevelDebug
}

func (w *hoStepsWorld) logsLevelAttr(level, key, val string) error {
	if !w.logLevelAttr(levelByName(level), key, val) {
		return fmt.Errorf("no %s log record with %s=%q", level, key, val)
	}
	return nil
}

func (w *hoStepsWorld) logsDLSwitchFailed(level, key, quoted, num string) error {
	val := quoted
	if val == "" {
		val = num
	}
	lvl := levelByName(level)
	if _, ok := w.logs.find(func(r hoRec) bool {
		return r.level == lvl && r.attrs["dl_switch"] == "failed" && r.attrs[key] == val
	}); !ok {
		return fmt.Errorf("no %s log record with dl_switch=failed and %s=%q", level, key, val)
	}
	return nil
}

func (w *hoStepsWorld) logsNotLevelAttr(level, key, val string) error {
	if w.logLevelAttr(levelByName(level), key, val) {
		return fmt.Errorf("unexpected %s log record with %s=%q", level, key, val)
	}
	return nil
}

func (w *hoStepsWorld) logsWarnUpDeactivationFailed() error {
	return hoStepsPoll(hoStepsWithin, func() error { return w.logsLevelAttr("WARN", "up_deactivation", "failed") })
}

func (w *hoStepsWorld) logsWarnReleaseFailed() error {
	if err := w.drain(); err != nil {
		return err
	}
	if _, ok := w.logs.find(func(r hoRec) bool {
		return r.level == slog.LevelWarn && strings.Contains(r.msg, "release failed")
	}); !ok {
		return fmt.Errorf("no WARN log record about the failed PDU session release")
	}
	return nil
}

// ---- E2E gating ---------------------------------------------------------------------------------

// e2eOnly skips the scenario unless E2E_TEST=1. With E2E_TEST=1 the live stack is driven through
// the MCP tools (ueransim_status / procedure_summary) by the operator or a CI job, not from this
// in-process suite, so the scenario reports pending rather than passing vacuously.
func (w *hoStepsWorld) e2eOnly() error {
	if os.Getenv("E2E_TEST") != "1" {
		return godog.ErrSkip
	}
	return godog.ErrPending
}

// registerUserPlaneSteps registers the SMF-005 steps on the shared world.
func registerUserPlaneSteps(ctx *godog.ScenarioContext, w *hoStepsWorld) {
	// Background
	ctx.Step(`^the fake UPF answers PFCP Session Modification Requests with PFCP Cause (\d+)$`, w.upfAnswersCause)
	ctx.Step(`^the fake UPF answers PFCP Session Modification Requests without a Cause IE$`, w.upfAnswersWithoutCause)
	ctx.Step(`^the fake UPF does not answer PFCP Session Modification Requests$`, w.upfSilent)
	ctx.Step(`^the AMF management API is a recording fake that accepts PDU session release requests$`, func() error { return w.amfRelease(true) })
	ctx.Step(`^the AMF management API is a recording fake that fails PDU session release requests$`, func() error { return w.amfRelease(false) })
	ctx.Step(`^the session UP security enforcement policy is (not )?"Required"$`, func(not string) error { return w.upSecurityPolicy(strings.TrimSpace(not)) })

	// Givens
	ctx.Step(`^the session "([^"]+)" is in state "([A-Z]+)"$`, w.sessionInState)
	ctx.Step(`^the AMF sent UpdateSMContext for "([^"]+)" with hoState "COMPLETED" and the SMF answered 200$`, w.sentCompletedAnswered200)
	ctx.Step(`^the AMF sent UpdateSMContext for "([^"]+)" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a valid HandoverResourceAllocationUnsuccessfulTransfer$`,
		func(ref string) error { return w.sentResAllocFail(ref, "unspecified") })
	ctx.Step(`^the AMF sent UpdateSMContext for "([^"]+)" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a HandoverResourceAllocationUnsuccessfulTransfer with radioNetwork Cause "([^"]+)"$`, w.sentResAllocFail)
	ctx.Step(`^the SMF sent zero PFCP messages to the UPF so far$`, w.sentZeroPFCPSoFar)

	// Whens
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with toBeSwitched true, n2SmInfoType "PATH_SWITCH_REQ" and the n2SmInfo bytes "([0-9a-f]+)"$`, w.pathSwitchReqBytes)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with failedToBeSwitched true, n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and a PathSwitchRequestSetupFailedTransfer with radioNetwork Cause "([^"]+)"$`, w.setupFailCause)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a HandoverResourceAllocationUnsuccessfulTransfer with radioNetwork Cause "([^"]+)"$`, w.resAllocFailCause)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with upCnxState "DEACTIVATED"$`, w.deactivated)

	// Responses
	ctx.Step(`^the SMF responds 204 with no body$`, w.responds204)
	ctx.Step(`^the response n2SmInfo is the base64 of a PathSwitchRequestUnsuccessfulTransfer with (radioNetwork) Cause "([^"]+)" \((\d+)\)$`, w.pathSwitchFailTransferCauseNum)
	ctx.Step(`^the response n2SmInfo is the base64 of a PathSwitchRequestUnsuccessfulTransfer with Cause "(protocol)" "([^"]+)"$`, w.pathSwitchFailTransferCause)
	ctx.Step(`^that HandoverPreparationUnsuccessfulTransfer carries the same Cause as the HandoverResourceAllocationUnsuccessfulTransfer of the request$`, w.prepFailSameCause)
	ctx.Step(`^that HandoverPreparationUnsuccessfulTransfer carries the radioNetwork Cause "([^"]+)"$`, w.prepFailRadioCause)
	ctx.Step(`^the SMF answered the AMF within 2 seconds, below the AMF handover UpdateSMContext timeout$`, w.answeredWithin2s)
	ctx.Step(`^the SMF answered the AMF only after the fake UPF had answered the PFCP Session Modification Request$`, w.answeredAfterUPF)

	// PFCP
	ctx.Step(`^exactly one PFCP Session Modification Request is sent to the UPF$`, w.oneModificationNoTarget)
	ctx.Step(`^within 2 seconds exactly one PFCP Session Modification Request is sent to the UPF$`, w.oneModificationNoTarget)
	ctx.Step(`^exactly one PFCP Session Modification Request has been sent to the UPF in total$`, w.oneModificationInTotal)
	ctx.Step(`^that PFCP Session Modification Request carries Update FAR with FAR ID 1 and Apply Action (FORW|DROP)$`, w.updateFAR)
	ctx.Step(`^that Update FAR carries Update Forwarding Parameters with Outer Header Creation GTP-U/UDP/IPv4 with the (?:stored target TEID and the stored target gNB IP|target DL F-TEID of the PathSwitchRequestTransfer)$`, w.farOHCStored)
	ctx.Step(`^that Update FAR carries no Update Forwarding Parameters$`, w.farNoForwardingParams)
	ctx.Step(`^that PFCP Session Modification Request carries no Create PDR, Update PDR, Create QER or Update QER$`, w.noOtherRules)

	// Session state
	ctx.Step(`^the session state is "([A-Z]+)"$`, w.stateIs)
	ctx.Step(`^the session state is not "([A-Z]+)"$`, w.stateIsNot)
	ctx.Step(`^within 2 seconds the session state is "([A-Z]+)"$`, w.stateWithin2s)
	ctx.Step(`^the session is not released$`, w.notReleased)
	ctx.Step(`^the stored target tunnel is cleared on the session$`, w.noTunnelStored)
	ctx.Step(`^the target tunnel is still stored on the session$`, w.tunnelStored)
	ctx.Step(`^the session is marked as target-failed$`, func() error { return w.targetFailed(true) })
	ctx.Step(`^the session is no longer marked as target-failed$`, func() error { return w.targetFailed(false) })

	// AMF management API
	ctx.Step(`^the AMF management API receives no PDU session release request$`, w.amfNoRelease)
	ctx.Step(`^within 2 seconds the AMF management API receives a PDU session release request for the SUPI of "([^"]+)" and PDU session id (\d+)$`, w.amfReleaseWithin2s)

	// Logs
	ctx.Step(`^the SMF logs procedure "([^"]+)" interface "([^"]+)" direction "([^"]+)" message_type "([^"]+)" with spec_ref "([^"]+)"$`,
		func(p, i, d, m, r string) error { return w.logsN4(p, i, d, m, "", r) })
	ctx.Step(`^the SMF logs procedure "([^"]+)" interface "([^"]+)" direction "([^"]+)" message_type "([^"]+)" with pfcp_cause (\d+) and spec_ref "([^"]+)"$`,
		func(p, i, d, m, c, r string) error { return w.logsN4(p, i, d, m, c, r) })
	ctx.Step(`^the SMF logs procedure "([^"]+)" interface "([^"]+)" direction "([^"]+)" with dl_switch "([^"]+)"$`,
		func(p, i, d, v string) error { return w.logsAttrs(p, "interface", i, "direction", d, "dl_switch", v) })
	ctx.Step(`^the SMF does not log a WARN with (dl_switch|followup) "([^"]+)"$`,
		func(k, v string) error { return w.logsNotLevelAttr("WARN", k, v) })
	ctx.Step(`^the SMF logs an (ERROR|INFO) with (followup) "([^"]+)"$`, w.logsLevelAttr)
	ctx.Step(`^the SMF logs an ERROR with dl_switch "failed" and (pfcp_cause|cause) (?:"([^"]+)"|(\d+))$`,
		func(k, q, n string) error { return w.logsDLSwitchFailed("ERROR", k, q, n) })
	ctx.Step(`^the SMF logs procedure "(XnHandover)" with target_failed_action "([^"]+)" and up_deactivation "([^"]+)"$`,
		func(p, a, u string) error {
			return w.logsAttrsWithin2s(p, "target_failed_action", a, "up_deactivation", u)
		})
	ctx.Step(`^the SMF logs procedure "(XnHandover)" with target_failed_action "release"$`,
		func(p string) error { return w.logsAttrsWithin2s(p, "target_failed_action", "release") })
	ctx.Step(`^the SMF logs procedure "(N2Handover)" with up_cnx_state "DEACTIVATED" and target_failed_action "(deactivate|release)"$`,
		func(p, a string) error {
			return w.logsAttrsWithin2s(p, "up_cnx_state", "DEACTIVATED", "target_failed_action", a)
		})
	ctx.Step(`^within 2 seconds the SMF logs a WARN with up_deactivation "failed"$`, w.logsWarnUpDeactivationFailed)
	ctx.Step(`^the SMF logs a WARN about the failed release$`, w.logsWarnReleaseFailed)

	// @e2e (skipped unless E2E_TEST=1)
	ctx.Step(`^the live 5GC stack is running with PacketRusher in the N2 handover scenario$`, w.e2eOnly)
	ctx.Step(`^a UE has an established PDU session and DL traffic towards the UE IP is running$`, func() error { return nil })
	ctx.Step(`^the N2 handover completes at HANDOVER NOTIFY$`, func() error { return nil })
	ctx.Step(`^the SMF logs one N2Handover PFCP Session Modification Request followed by dl_switch "done" for the PDU session$`, func() error { return nil })
	ctx.Step(`^the UPF logs "PFCP Session DL tunnel updated" with the target gNB IP$`, func() error { return nil })
	ctx.Step(`^downlink GTP-U packets reach the target gNB tunnel after the handover$`, func() error { return nil })
	ctx.Step(`^procedure_summary reports zero failures for N2HandoverDLSwitch$`, func() error { return nil })
}

// TestN2HandoverUserPlaneFeatures runs n2_handover_user_plane.feature against the real
// handleUpdateSMContext handler.
func TestN2HandoverUserPlaneFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeHandoverN2SMScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/n2_handover_user_plane.feature"},
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
