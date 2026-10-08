package server

// handover_n2_pfcp_test.go — unit tests for the SMF-005 N4 legs of the handover procedures: the
// synchronous DL path switch (N2 hoState COMPLETED, Xn PATH_SWITCH_REQ), the deactivation /
// release of target-failed PDU sessions (HANDOVER_RES_ALLOC_FAIL + DEACTIVATED,
// PATH_SWITCH_SETUP_FAIL) and rule R1. The fake UPF RESPONDS to Session Modification Requests
// with a configurable Cause (or stays silent / omits the Cause).
// Ref: TS 23.502 §4.9.1.3.3, §4.9.1.2.2, §4.3.7; TS 29.244 §7.5.4, §7.5.5.

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
	"github.com/prometheus/client_golang/prometheus/testutil"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// hoUPFReq is one Session Modification Request seen by the fake UPF.
type hoUPFReq struct {
	seid uint64
	far  []byte // marshaled first Update FAR IE
	n    int    // number of Update FAR IEs
}

// hoFakeUPF answers PFCP Session Modification Requests.
type hoFakeUPF struct {
	conn *net.UDPConn

	mu       sync.Mutex
	mode     string // "respond" | "nocause" | "silent"
	cause    uint8
	delay    time.Duration
	received []hoUPFReq
}

func newHOFakeUPF(t *testing.T) *hoFakeUPF {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen fake UPF: %v", err)
	}
	f := &hoFakeUPF{conn: conn, mode: "respond", cause: pfcpie.CauseRequestAccepted}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, err := pfcpmsg.Parse(buf[:n])
			if err != nil {
				continue
			}
			req, ok := msg.(*pfcpmsg.SessionModificationRequest)
			if !ok {
				continue
			}
			r := hoUPFReq{seid: req.SEID(), n: len(req.UpdateFAR)}
			if len(req.UpdateFAR) > 0 {
				r.far, _ = req.UpdateFAR[0].Marshal()
			}
			f.mu.Lock()
			f.received = append(f.received, r)
			mode, cause, delay := f.mode, f.cause, f.delay
			f.mu.Unlock()
			if mode == "silent" {
				continue
			}
			time.Sleep(delay)
			var ies []*pfcpie.IE
			if mode != "nocause" {
				ies = append(ies, pfcpie.NewCause(cause))
			}
			rsp := pfcpmsg.NewSessionModificationResponse(0, 0, req.SEID(), req.Sequence(), 0, ies...)
			if b, err := rsp.Marshal(); err == nil {
				_, _ = conn.WriteToUDP(b, raddr)
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return f
}

func (f *hoFakeUPF) set(mode string, cause uint8, delay time.Duration) {
	f.mu.Lock()
	f.mode, f.cause, f.delay = mode, cause, delay
	f.mu.Unlock()
}

func (f *hoFakeUPF) requests() []hoUPFReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hoUPFReq(nil), f.received...)
}

// hoRespFixture is hoFixture with a responding fake UPF and sub-second PFCP timers.
func hoRespFixture(t *testing.T) (*Server, *Session, *hoFakeUPF) {
	t.Helper()
	upf := newHOFakeUPF(t)
	s := newTestSMFServer(t)
	s.cfg.Peers.UPF = upf.conn.LocalAddr().String()
	s.cfg.UPFN3Addr = "10.0.0.1"
	s.pfcpTimers = pfcpNodeTimers{t1: 100 * time.Millisecond, n1: 1,
		heartbeatInterval: time.Hour, assocRetryInitial: time.Hour, assocRetryMax: time.Hour}
	sess := &Session{SUPI: "imsi-001010000000001", PDUSessionID: 1, DNN: "internet", SEID: 42, State: "ACTIVE",
		ULTEID: 0x1001, FiveQI: 9}
	s.sessions[hoTestRef] = sess
	return s, sess, upf
}

func hoState(s *Server, sess *Session) string {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	return sess.State
}

func farBytes(t *testing.T, far *pfcpie.IE) []byte {
	t.Helper()
	b, err := far.Marshal()
	if err != nil {
		t.Fatalf("marshal FAR: %v", err)
	}
	return b
}

// legacyDLSwitchFAR is the Update FAR exactly as sendPFCPSessionModification built it before
// SMF-005 (inline constructors): the shared builder must stay byte-identical.
func legacyDLSwitchFAR(teid uint32, ip net.IP) []byte {
	b, _ := pfcpie.NewUpdateFAR(
		pfcpie.NewFARID(1),
		pfcpie.NewApplyAction(0x02),
		pfcpie.NewUpdateForwardingParameters(
			pfcpie.NewOuterHeaderCreation(0x0100, teid, ip.String(), "", 0, 0, 0)),
	).Marshal()
	return b
}

func legacyDropFAR() []byte {
	b, _ := pfcpie.NewUpdateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x01)).Marshal()
	return b
}

func newJSONTestLogger(w *lockedBuf) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})).With("nf", "SMF")
}

func problemCause(t *testing.T, w *httptest.ResponseRecorder) (string, map[string]interface{}) {
	t.Helper()
	m := hoDecodeResp(t, w)
	e, _ := m["error"].(map[string]interface{})
	if e == nil {
		t.Fatalf("no error object: %s", w.Body.String())
	}
	c, _ := e["cause"].(string)
	return c, m
}

func TestDLSwitchFARByteIdentical(t *testing.T) {
	ip := net.IPv4(10, 0, 0, 7)
	if !bytes.Equal(farBytes(t, buildDLSwitchFAR(0xABCD, ip)), legacyDLSwitchFAR(0xABCD, ip)) {
		t.Error("DL switch FAR differs from the legacy encoding")
	}
	if !bytes.Equal(farBytes(t, buildDLDropFAR()), legacyDropFAR()) {
		t.Error("DROP FAR differs from the legacy encoding")
	}
}

func TestHoN4TimeoutBelowAMFBudget(t *testing.T) {
	const amfSMFHOUpdateTimeout = 2 * time.Second // nf/amf/internal/ngap/smf_leg.go smfHOUpdateTimeout
	if hoN4Timeout >= amfSMFHOUpdateTimeout {
		t.Fatalf("hoN4Timeout %s must stay below the AMF budget %s", hoN4Timeout, amfSMFHOUpdateTimeout)
	}
}

func TestReleaseOnTargetFailure(t *testing.T) {
	rn := func(v aper.Enumerated) ngapType.Cause {
		return ngapType.Cause{Present: ngapType.CausePresentRadioNetwork, RadioNetwork: &ngapType.CauseRadioNetwork{Value: v}}
	}
	cases := []struct {
		name     string
		c        ngapType.Cause
		required bool
		want     bool
	}{
		{"integrity + Required", rn(ngapType.CauseRadioNetworkPresentUpIntegrityProtectionNotPossible), true, true},
		{"confidentiality + Required", rn(ngapType.CauseRadioNetworkPresentUpConfidentialityProtectionNotPossible), true, true},
		{"integrity, not Required", rn(ngapType.CauseRadioNetworkPresentUpIntegrityProtectionNotPossible), false, false},
		{"other radio cause + Required", rn(ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable), true, false},
		{"protocol group + Required", ngapCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError), true, false},
		{"empty cause", ngapType.Cause{}, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := releaseOnTargetFailure(c.c, c.required); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func prepareHO(s *Server, sess *Session, state string) {
	s.sessionMu.Lock()
	sess.HOState, sess.HOTargetGNBIP, sess.HOTargetDLTEID = state, net.IPv4(10, 0, 0, 7), 0xABCD
	s.sessionMu.Unlock()
}

func completePost(s *Server) *httptest.ResponseRecorder {
	return hoPost(s, hoTestRef, map[string]interface{}{"hoState": "COMPLETED"})
}

func TestHandoverCompleteSwitchesDL(t *testing.T) {
	s, sess, upf := hoRespFixture(t)
	prepareHO(s, sess, "PREPARED")
	s.pfcpTimers.t1 = 600 * time.Millisecond // no retransmission while the UPF delays its answer
	upf.set("respond", pfcpie.CauseRequestAccepted, 150*time.Millisecond)

	start := time.Now()
	w := completePost(s)
	elapsed := time.Since(start)

	if w.Code != 200 {
		t.Fatalf("code = %d: %s", w.Code, w.Body.String())
	}
	if m := hoDecodeResp(t, w); m["hoState"] != "COMPLETED" || len(m) != 1 {
		t.Fatalf("resp = %v", m)
	}
	if elapsed < 150*time.Millisecond {
		t.Fatalf("answered after %s: before the PFCP response", elapsed)
	}
	reqs := upf.requests()
	if len(reqs) != 1 || reqs[0].n != 1 || reqs[0].seid != 42 {
		t.Fatalf("PFCP requests = %+v", reqs)
	}
	if !bytes.Equal(reqs[0].far, legacyDLSwitchFAR(0xABCD, net.IPv4(10, 0, 0, 7))) {
		t.Fatalf("Update FAR = %x", reqs[0].far)
	}
	if sess.HOState != "COMPLETED" || sess.HOTargetGNBIP != nil || sess.HOTargetDLTEID != 0 || sess.State != "ACTIVE" {
		t.Fatalf("state after switch: %+v", sess)
	}

	// Idempotent repeat: 200, no second PFCP.
	if w := completePost(s); w.Code != 200 {
		t.Fatalf("repeat code = %d", w.Code)
	}
	if n := len(upf.requests()); n != 1 {
		t.Fatalf("PFCP requests after repeat = %d, want 1", n)
	}
}

func TestHandoverCompleteLogsN4AndNsmf(t *testing.T) {
	s, sess, _ := hoRespFixture(t)
	buf := &lockedBuf{}
	s.logger = newJSONTestLogger(buf)
	prepareHO(s, sess, "PREPARED")
	if w := completePost(s); w.Code != 200 {
		t.Fatalf("code = %d", w.Code)
	}
	if !buf.has(map[string]any{"procedure": "N2Handover", "interface": "N4", "direction": "OUT",
		"message_type": "PFCPSessionModificationRequest", "nf": "SMF"}) {
		t.Error("missing N4 OUT log")
	}
	if !buf.has(map[string]any{"procedure": "N2Handover", "interface": "N4", "direction": "IN",
		"message_type": "PFCPSessionModificationResponse", "pfcp_cause": float64(1), "result": "OK",
		"spec_ref": "TS 29.244 §7.5.5"}) {
		t.Error("missing N4 IN log")
	}
	if !buf.has(map[string]any{"procedure": "N2Handover", "interface": "Nsmf", "direction": "OUT", "dl_switch": "done"}) {
		t.Error("missing Nsmf OUT dl_switch=done log")
	}
	for _, e := range buf.entries() {
		if e["dl_switch"] == "pending-human-approval" {
			t.Error("stale pending-human-approval log")
		}
	}
}

func TestHandoverCompleteN4Failures(t *testing.T) {
	cases := []struct {
		name       string
		mode       string
		cause      uint8
		wantStatus int
		wantCause  string
		wantLog    map[string]any
	}{
		{"cause 64", "respond", 64, 500, "SYSTEM_FAILURE", map[string]any{"pfcp_cause": float64(64)}},
		{"cause 65", "respond", 65, 500, "SYSTEM_FAILURE", map[string]any{"pfcp_cause": float64(65)}},
		{"cause 73", "respond", 73, 500, "SYSTEM_FAILURE", map[string]any{"pfcp_cause": float64(73)}},
		{"no cause IE", "nocause", 0, 500, "SYSTEM_FAILURE", map[string]any{"pfcp_cause": "missing"}},
		{"silent UPF", "silent", 0, 504, "UPF_NOT_RESPONDING", map[string]any{"cause": "pfcp-timeout"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, sess, upf := hoRespFixture(t)
			buf := &lockedBuf{}
			s.logger = newJSONTestLogger(buf)
			prepareHO(s, sess, "PREPARED")
			upf.set(c.mode, c.cause, 0)
			w := completePost(s)
			if w.Code != c.wantStatus {
				t.Fatalf("code = %d: %s", w.Code, w.Body.String())
			}
			cause, m := problemCause(t, w)
			if cause != c.wantCause {
				t.Fatalf("cause = %q", cause)
			}
			if _, has := m["n2SmInfo"]; has {
				t.Fatal("unexpected n2SmInfo")
			}
			if sess.HOState != "PREPARED" || sess.HOTargetDLTEID != 0xABCD || sess.HOTargetGNBIP == nil || sess.State != "ACTIVE" {
				t.Fatalf("state not kept: %+v", sess)
			}
			if n := len(upf.requests()); n == 0 {
				t.Fatal("no PFCP request")
			}
			want := map[string]any{"dl_switch": "failed", "procedure": "N2Handover", "level": "ERROR"}
			for k, v := range c.wantLog {
				want[k] = v
			}
			if !buf.has(want) {
				t.Errorf("missing ERROR log %v", want)
			}
		})
	}
}

func TestHandoverCompleteSilentUPFWithDefaultT1StaysWithinBudget(t *testing.T) {
	s, sess, upf := hoRespFixture(t)
	s.pfcpTimers.t1, s.pfcpTimers.n1 = 3*time.Second, 2 // spec default T1 > hoN4Timeout
	prepareHO(s, sess, "PREPARED")
	upf.set("silent", 0, 0)
	start := time.Now()
	w := completePost(s)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("took %s, must answer inside the AMF 2 s budget", el)
	}
	if w.Code != 504 {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestHandoverCompleteRejections(t *testing.T) {
	t.Run("no stored tunnel", func(t *testing.T) {
		s, _, upf := hoRespFixture(t)
		buf := &lockedBuf{}
		s.logger = newJSONTestLogger(buf)
		w := completePost(s)
		if cause, m := problemCause(t, w); w.Code != 500 || cause != "SYSTEM_FAILURE" || m["n2SmInfo"] != nil {
			t.Fatalf("code=%d cause=%q", w.Code, cause)
		}
		if n := len(upf.requests()); n != 0 {
			t.Fatalf("PFCP sent: %d", n)
		}
		if !buf.has(map[string]any{"level": "WARN", "detail": "no target tunnel"}) {
			t.Error("missing WARN detail=no target tunnel")
		}
	})
	t.Run("RELEASING", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		prepareHO(s, sess, "PREPARED")
		sess.State = sessionStateReleasing
		w := completePost(s)
		if cause, m := problemCause(t, w); w.Code != 409 || cause != causeSessionReleasing || m["n2SmInfo"] != nil {
			t.Fatalf("code=%d cause=%q", w.Code, cause)
		}
		if n := len(upf.requests()); n != 0 {
			t.Fatalf("PFCP sent: %d", n)
		}
		if sess.State != sessionStateReleasing {
			t.Fatalf("state = %q", sess.State)
		}
	})
	t.Run("not PREPARED but tunnel stored", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		prepareHO(s, sess, "NONE")
		buf := &lockedBuf{}
		s.logger = newJSONTestLogger(buf)
		if w := completePost(s); w.Code != 200 {
			t.Fatalf("code = %d", w.Code)
		}
		if n := len(upf.requests()); n != 1 {
			t.Fatalf("PFCP = %d", n)
		}
		if !buf.has(map[string]any{"level": "WARN", "previous_ho_state": "NONE"}) {
			t.Error("missing WARN previous_ho_state")
		}
	})
	t.Run("IDLE session restored on failure", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		prepareHO(s, sess, "PREPARED")
		sess.State = "IDLE"
		upf.set("respond", 64, 0)
		if w := completePost(s); w.Code != 500 {
			t.Fatalf("code = %d", w.Code)
		}
		if sess.State != "IDLE" {
			t.Fatalf("state = %q, want IDLE restored", sess.State)
		}
	})
}

func pathSwitchPost(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	tr := hoPathSwitchTransfer([4]byte{10, 0, 0, 9}, 0x1234)
	return hoPost(s, hoTestRef, map[string]interface{}{
		"toBeSwitched": true, "n2SmInfoType": "PATH_SWITCH_REQ",
		"n2SmInfo": base64.StdEncoding.EncodeToString(hoMarshal(t, tr)),
	})
}

func TestPathSwitchReqN4Failures(t *testing.T) {
	cases := []struct {
		name       string
		mode       string
		cause      uint8
		wantStatus int
		wantCause  string
	}{
		{"cause 64", "respond", 64, 500, "SYSTEM_FAILURE"},
		{"cause 65", "respond", 65, 500, "SYSTEM_FAILURE"},
		{"no cause IE", "nocause", 0, 500, "SYSTEM_FAILURE"},
		{"silent UPF", "silent", 0, 504, "UPF_NOT_RESPONDING"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, sess, upf := hoRespFixture(t)
			sess.State = "IDLE"
			upf.set(c.mode, c.cause, 0)
			w := pathSwitchPost(t, s)
			if w.Code != c.wantStatus {
				t.Fatalf("code = %d: %s", w.Code, w.Body.String())
			}
			cause, m := problemCause(t, w)
			if cause != c.wantCause || m["n2SmInfoType"] != "PATH_SWITCH_REQ_FAIL" {
				t.Fatalf("cause=%q type=%v", cause, m["n2SmInfoType"])
			}
			var u ngapType.PathSwitchRequestUnsuccessfulTransfer
			if err := aper.UnmarshalWithParams(hoRespTransfer(t, m), &u, "valueExt"); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if u.Cause.Present != ngapType.CausePresentRadioNetwork ||
				u.Cause.RadioNetwork.Value != ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem {
				t.Fatalf("cause = %+v", u.Cause)
			}
			if sess.State != "IDLE" {
				t.Fatalf("state = %q, want restored IDLE", sess.State)
			}
		})
	}
}

func TestPathSwitchReqRejectionsSendNoPFCP(t *testing.T) {
	t.Run("undecodable", func(t *testing.T) {
		s, _, upf := hoRespFixture(t)
		w := hoPost(s, hoTestRef, map[string]interface{}{"n2SmInfoType": "PATH_SWITCH_REQ",
			"n2SmInfo": base64.StdEncoding.EncodeToString([]byte{0xff, 0xff, 0xff, 0xff})})
		if w.Code != 422 {
			t.Fatalf("code = %d", w.Code)
		}
		if n := len(upf.requests()); n != 0 {
			t.Fatalf("PFCP = %d", n)
		}
	})
	t.Run("RELEASING", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		sess.State = sessionStateReleasing
		w := pathSwitchPost(t, s)
		if cause, m := problemCause(t, w); w.Code != 409 || cause != causeSessionReleasing || m["n2SmInfoType"] != "PATH_SWITCH_REQ_FAIL" {
			t.Fatalf("code=%d cause=%q", w.Code, cause)
		}
		if n := len(upf.requests()); n != 0 {
			t.Fatalf("PFCP = %d", n)
		}
	})
	t.Run("unknown context", func(t *testing.T) {
		s, _, upf := hoRespFixture(t)
		tr := hoPathSwitchTransfer([4]byte{10, 0, 0, 9}, 1)
		w := hoPost(s, "nope", map[string]interface{}{"n2SmInfoType": "PATH_SWITCH_REQ",
			"n2SmInfo": base64.StdEncoding.EncodeToString(hoMarshal(t, tr))})
		if w.Code != 404 {
			t.Fatalf("code = %d", w.Code)
		}
		if n := len(upf.requests()); n != 0 {
			t.Fatalf("PFCP = %d", n)
		}
	})
}

// fakeAMFRelease points the SMF's AMF management peer at a recording fake.
func fakeAMFRelease(t *testing.T, s *Server, status int) *fakeAMF {
	t.Helper()
	a := newFakeAMF(t, status)
	s.cfg.Peers.AMFMgmt = a.host()
	return a
}

func setupFailPost(t *testing.T, s *Server, c ngapType.Cause) *httptest.ResponseRecorder {
	t.Helper()
	tr := ngapType.PathSwitchRequestSetupFailedTransfer{Cause: c}
	return hoPost(s, hoTestRef, map[string]interface{}{
		"failedToBeSwitched": true, "n2SmInfoType": "PATH_SWITCH_SETUP_FAIL",
		"n2SmInfo": base64.StdEncoding.EncodeToString(hoMarshal(t, tr)),
	})
}

func TestPathSwitchSetupFailActions(t *testing.T) {
	upSec := ngapCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUpIntegrityProtectionNotPossible)
	other := ngapCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable)
	amfPath := "/amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/1"

	t.Run("deactivate on Cause 1", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		amf := fakeAMFRelease(t, s, 204)
		buf := &lockedBuf{}
		s.logger = newJSONTestLogger(buf)
		if w := setupFailPost(t, s, other); w.Code != 204 {
			t.Fatalf("code = %d", w.Code)
		}
		s.WaitHandoverTasks()
		reqs := upf.requests()
		if len(reqs) != 1 || !bytes.Equal(reqs[0].far, legacyDropFAR()) {
			t.Fatalf("PFCP = %+v", reqs)
		}
		if hoState(s, sess) != "IDLE" || amf.count("") != 0 {
			t.Fatalf("state=%q amf calls=%d", hoState(s, sess), amf.count(""))
		}
		if !buf.has(map[string]any{"procedure": "XnHandover", "up_deactivation": "done", "target_failed_action": "deactivate"}) {
			t.Error("missing up_deactivation=done log")
		}
	})
	for _, mode := range []struct {
		name  string
		m     string
		cause uint8
	}{{"UPF rejects", "respond", 64}, {"UPF silent", "silent", 0}} {
		t.Run("deactivation fails: "+mode.name, func(t *testing.T) {
			s, sess, upf := hoRespFixture(t)
			upf.set(mode.m, mode.cause, 0)
			buf := &lockedBuf{}
			s.logger = newJSONTestLogger(buf)
			if w := setupFailPost(t, s, other); w.Code != 204 {
				t.Fatalf("code = %d", w.Code)
			}
			s.WaitHandoverTasks()
			if hoState(s, sess) == "IDLE" {
				t.Fatal("state IDLE after failed deactivation")
			}
			if !buf.has(map[string]any{"level": "WARN", "up_deactivation": "failed"}) {
				t.Error("missing WARN up_deactivation=failed")
			}
		})
	}
	t.Run("release when UP security Required", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		sess.UPSecurityRequired = true
		amf := fakeAMFRelease(t, s, 204)
		if w := setupFailPost(t, s, upSec); w.Code != 204 {
			t.Fatalf("code = %d", w.Code)
		}
		s.WaitHandoverTasks()
		if amf.count(amfPath) != 1 || len(upf.requests()) != 0 {
			t.Fatalf("amf calls=%v pfcp=%d", amf.snapshot(), len(upf.requests()))
		}
	})
	t.Run("failed release falls back to deactivation", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		sess.UPSecurityRequired = true
		amf := fakeAMFRelease(t, s, 500)
		buf := &lockedBuf{}
		s.logger = newJSONTestLogger(buf)
		if w := setupFailPost(t, s, upSec); w.Code != 204 {
			t.Fatalf("code = %d", w.Code)
		}
		s.WaitHandoverTasks()
		reqs := upf.requests()
		if amf.count(amfPath) != 1 || len(reqs) != 1 || !bytes.Equal(reqs[0].far, legacyDropFAR()) {
			t.Fatalf("amf=%v pfcp=%+v", amf.snapshot(), reqs)
		}
		if hoState(s, sess) != "IDLE" {
			t.Fatalf("state = %q", hoState(s, sess))
		}
		if !buf.has(map[string]any{"level": "WARN", "target_failed_action": "release", "result": "FAILURE"}) {
			t.Error("missing WARN about failed release")
		}
	})
	t.Run("RELEASING takes no action", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		sess.State = sessionStateReleasing
		amf := fakeAMFRelease(t, s, 204)
		if w := setupFailPost(t, s, other); w.Code != 204 {
			t.Fatalf("code = %d", w.Code)
		}
		s.WaitHandoverTasks()
		if len(upf.requests()) != 0 || amf.count("") != 0 || sess.State != sessionStateReleasing {
			t.Fatal("action taken on a RELEASING session")
		}
	})
}

func resAllocFailPost(t *testing.T, s *Server, c ngapType.Cause) *httptest.ResponseRecorder {
	t.Helper()
	return hoPost(s, hoTestRef, map[string]interface{}{"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_RES_ALLOC_FAIL",
		"n2SmInfo": base64.StdEncoding.EncodeToString(hoMarshal(t,
			ngapType.HandoverResourceAllocationUnsuccessfulTransfer{Cause: c}))})
}

func deactivatedPost(s *Server) *httptest.ResponseRecorder {
	return hoPost(s, hoTestRef, map[string]interface{}{"upCnxState": "DEACTIVATED"})
}

func TestResAllocFailThenDeactivated(t *testing.T) {
	other := ngapCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable)
	upSec := ngapCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUpConfidentialityProtectionNotPossible)
	amfPath := "/amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/1"

	t.Run("403 with relayed cause, no PFCP, flag set", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		prepareHO(s, sess, "PREPARED")
		buf := &lockedBuf{}
		s.logger = newJSONTestLogger(buf)
		w := resAllocFailPost(t, s, other)
		cause, m := problemCause(t, w)
		if w.Code != 403 || cause != "HANDOVER_RESOURCE_ALLOCATION_FAILURE" || m["n2SmInfoType"] != "HANDOVER_PREP_FAIL" {
			t.Fatalf("code=%d cause=%q body=%s", w.Code, cause, w.Body.String())
		}
		var u ngapType.HandoverPreparationUnsuccessfulTransfer
		if err := aper.UnmarshalWithParams(hoRespTransfer(t, m), &u, "valueExt"); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if u.Cause.Present != ngapType.CausePresentRadioNetwork ||
			u.Cause.RadioNetwork.Value != ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable {
			t.Fatalf("relayed cause = %+v", u.Cause)
		}
		if sess.HOState != "NONE" || sess.HOTargetGNBIP != nil || sess.HOTargetDLTEID != 0 || !sess.HOTargetFailed || sess.HOReleaseOnDeactivate {
			t.Fatalf("session = %+v", sess)
		}
		if n := len(upf.requests()); n != 0 {
			t.Fatalf("PFCP = %d", n)
		}
		if !buf.has(map[string]any{"level": "INFO", "followup": "await-amf-deactivation", "target_failed_action": "deactivate"}) {
			t.Error("missing followup log")
		}
		for _, e := range buf.entries() {
			if e["followup"] == "release-or-deactivate-pending" {
				t.Error("stale release-or-deactivate-pending log")
			}
		}
	})
	t.Run("DEACTIVATED executes deactivation", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		resAllocFailPost(t, s, other)
		if w := deactivatedPost(s); w.Code != 200 {
			t.Fatalf("code = %d", w.Code)
		}
		s.WaitHandoverTasks()
		reqs := upf.requests()
		if len(reqs) != 1 || !bytes.Equal(reqs[0].far, legacyDropFAR()) {
			t.Fatalf("PFCP = %+v", reqs)
		}
		if hoState(s, sess) != "IDLE" || sess.HOTargetFailed {
			t.Fatalf("state=%q failed=%v", hoState(s, sess), sess.HOTargetFailed)
		}
	})
	t.Run("DEACTIVATED with rejected PFCP Cause: FAILURE, State kept, N4 log", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		buf := &lockedBuf{}
		s.logger = newJSONTestLogger(buf)
		upf.set("respond", 64, 0)
		before := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "HandoverTargetFailedDeactivate", "REJECT"))
		okBefore := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "HandoverTargetFailedDeactivate", "OK"))
		resAllocFailPost(t, s, other)
		if w := deactivatedPost(s); w.Code != 200 {
			t.Fatalf("code = %d", w.Code)
		}
		s.WaitHandoverTasks()
		if hoState(s, sess) == "IDLE" {
			t.Fatal("State set to IDLE despite rejected Cause")
		}
		if got := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "HandoverTargetFailedDeactivate", "REJECT")); got != before+1 {
			t.Fatalf("REJECT metric = %v, want %v", got, before+1)
		}
		if got := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", "HandoverTargetFailedDeactivate", "OK")); got != okBefore {
			t.Fatalf("OK metric moved: %v -> %v", okBefore, got)
		}
		if !buf.has(map[string]any{"up_deactivation": "failed", "interface": "N4", "pfcp_cause": float64(64)}) {
			t.Error("missing up_deactivation=failed N4 log")
		}
	})
	t.Run("DEACTIVATED executes release (UP security Required)", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		sess.UPSecurityRequired = true
		amf := fakeAMFRelease(t, s, 204)
		resAllocFailPost(t, s, upSec)
		if !sess.HOReleaseOnDeactivate {
			t.Fatal("R1 did not select release")
		}
		if w := deactivatedPost(s); w.Code != 200 {
			t.Fatalf("code = %d", w.Code)
		}
		s.WaitHandoverTasks()
		if amf.count(amfPath) != 1 || len(upf.requests()) != 0 || sess.HOTargetFailed {
			t.Fatalf("amf=%v pfcp=%d", amf.snapshot(), len(upf.requests()))
		}
	})
	t.Run("failed release falls back to deactivation", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		sess.UPSecurityRequired = true
		amf := fakeAMFRelease(t, s, 500)
		resAllocFailPost(t, s, upSec)
		deactivatedPost(s)
		s.WaitHandoverTasks()
		reqs := upf.requests()
		if amf.count(amfPath) != 1 || len(reqs) != 1 || hoState(s, sess) != "IDLE" {
			t.Fatalf("amf=%v pfcp=%d state=%q", amf.snapshot(), len(reqs), hoState(s, sess))
		}
	})
	t.Run("without AMF indication nothing happens", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		amf := fakeAMFRelease(t, s, 204)
		resAllocFailPost(t, s, other)
		s.WaitHandoverTasks()
		if len(upf.requests()) != 0 || amf.count("") != 0 || hoState(s, sess) != "ACTIVE" {
			t.Fatal("session touched without the AMF indication")
		}
	})
	t.Run("plain AN release keeps the legacy behaviour", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		if w := deactivatedPost(s); w.Code != 200 {
			t.Fatalf("code = %d", w.Code)
		}
		eventually(t, 2*time.Second, "DROP request", func() bool { return len(upf.requests()) == 1 })
		if hoState(s, sess) != "IDLE" {
			t.Fatalf("state = %q", hoState(s, sess))
		}
	})
	t.Run("RELEASING session: answered, no decision", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		sess.State = sessionStateReleasing
		if w := resAllocFailPost(t, s, other); w.Code != 403 {
			t.Fatalf("code = %d", w.Code)
		}
		if sess.HOTargetFailed || len(upf.requests()) != 0 || sess.State != sessionStateReleasing {
			t.Fatalf("session = %+v", sess)
		}
	})
	t.Run("PREPARING clears the flag", func(t *testing.T) {
		s, sess, _ := hoRespFixture(t)
		resAllocFailPost(t, s, other)
		if w := hoPost(s, hoTestRef, map[string]interface{}{"hoState": "PREPARING"}); w.Code != 200 {
			t.Fatalf("code = %d: %s", w.Code, w.Body.String())
		}
		if sess.HOTargetFailed {
			t.Fatal("flag not cleared by PREPARING")
		}
	})
}
