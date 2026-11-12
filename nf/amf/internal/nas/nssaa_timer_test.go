package nasmsg

// nssaa_timer_test.go - T3575 supervision of the NSSAA COMMAND, multi-round
// relay at the NAS layer, the PENDING retry trigger, the CONFIGURATION UPDATE
// COMMAND of a drained queue and the serial-queue concurrency model, with a fake
// clock.
// Ref: TS 24.501 §5.4.7.2.1-§5.4.7.2.3, TS 23.502 §4.2.9.2 steps 19a-19b

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// fakeClock records scheduled timers; fire runs one (also a stopped one, to
// prove a late callback is ignored). Safe for concurrent use.
type fakeClock struct {
	mu     sync.Mutex
	timers []*fakeTimer
}

type fakeTimer struct {
	d       time.Duration
	f       func()
	stopped atomic.Bool
}

func (t *fakeTimer) Stop() bool { return !t.stopped.Swap(true) }

func (c *fakeClock) after(d time.Duration, f func()) nssaaStopper {
	t := &fakeTimer{d: d}
	// a fired timer is no longer running (time.Timer semantics)
	t.f = func() { t.stopped.Store(true); f() }
	c.mu.Lock()
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	return t
}

func (c *fakeClock) last() *fakeTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timers[len(c.timers)-1]
}

func (c *fakeClock) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// live reports the number of running T3575 timers (T3522 is counted by liveOf).
func (c *fakeClock) live() int { return c.liveOf(NSSAAT3575Duration) }

// liveOf reports the number of running timers scheduled with duration d.
func (c *fakeClock) liveOf(d time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if t.d == d && !t.stopped.Load() {
			n++
		}
	}
	return n
}

// recSender records every DL NAS PDU (the secured, ciphered form).
type recSender struct {
	fakeSender
	mu   sync.Mutex
	pdus [][]byte
}

func (r *recSender) SendDownlinkNASTransport(_ *amfctx.UEContext, pdu []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pdus = append(r.pdus, append([]byte(nil), pdu...))
	return nil
}

func (r *recSender) n() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pdus)
}

// sentMsg is one decoded DL message: its type and the plain body bytes.
type sentMsg struct {
	typ  nas.MessageType
	body []byte
}

// msgs deciphers every recorded PDU (NEA2, DL, count = SQN of the test UE, which
// only ever receives NSSAA traffic and stays below 256 messages).
func (r *recSender) msgs(t *testing.T, ue *amfctx.UEContext) []sentMsg {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []sentMsg
	for _, pdu := range r.pdus {
		inner, err := nea.NEA2(ue.SecurityCtx.KNASenc, uint32(pdu[6]), 0x01, 0x01, pdu[7:])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sentMsg{typ: nas.MessageType(inner[2]), body: inner[3:]})
	}
	return out
}

func (r *recSender) ofType(t *testing.T, ue *amfctx.UEContext, typ nas.MessageType) []sentMsg {
	var out []sentMsg
	for _, m := range r.msgs(t, ue) {
		if m.typ == typ {
			out = append(out, m)
		}
	}
	return out
}

// nssaaScript is the AAA-S: Authenticate/Confirm answer from a script.
type nssaaScript struct {
	first    *procedures.NSSAAAuthResult
	confirms []*procedures.NSSAAAuthResult
}

func (s *nssaaScript) Authenticate(context.Context, string, string, uint8, string, []byte) (*procedures.NSSAAAuthResult, error) {
	return s.first, nil
}

func (s *nssaaScript) Confirm(context.Context, string, string, uint8, string, string, []byte) (*procedures.NSSAAAuthResult, error) {
	r := s.confirms[0]
	s.confirms = s.confirms[1:]
	return r, nil
}

func nssaaTestHandler(t *testing.T, spec bool, aaa procedures.NSSAAClient) (*Handler, *recSender, *fakeClock, *amfctx.UEContext) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	reg := procedures.NewRegistrationHandler(mgr, nil, nil, nil, "test-amf", "001", "01", logger)
	reg.WithNSSAA(aaa)
	reg.WithNSSAASpecLiteral(spec)
	sender := &recSender{}
	h := NewHandler(sender, reg, logger)
	clk := &fakeClock{}
	h.SetTimerSchedulerForTest(clk.after)
	ue := newTestUE(t)
	ue.GPSI = "msisdn-12025550100"
	ue.State = amfctx.GMMRegistered
	return h, sender, clk, ue
}

func sliceN(sst uint8, sd string) amfctx.SNSSAISubscribed {
	return amfctx.SNSSAISubscribed{SST: sst, SD: sd, SubjectToNSSAA: true}
}

// withPlainDefault gives ue a subscription with, besides its NSSAA slice, a
// default S-NSSAI that is not subject to NSSAA: it can always be allowed, so a
// failed NSSAA ends in a Configuration Update Command and not in a
// de-registration (TS 24.501 §4.6.2.4 b)).
func withPlainDefault(ue *amfctx.UEContext) {
	ue.SubscribedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003"), {SST: 1, SD: "000009"}}
}

func completeMsg(ue *amfctx.UEContext, sst uint8, sd uint32) *nas.Message {
	return &nas.Message{Body: &nas.NSSAAuthComplete{
		SNSSAI:     nas.SNSSAI{SST: sst, SD: sd},
		EAPMessage: eap.BuildIdentityResponse(ue.NSSAAEAPID, "alice@nssaa"),
	}}
}

func hasIn(list []amfctx.SNSSAISubscribed, sst uint8, sd string) bool {
	for _, s := range list {
		if s.SST == sst && s.SD == sd {
			return true
		}
	}
	return false
}

// barrier returns once every task queued so far on ue's serial queue ran.
func barrier(ue *amfctx.UEContext) {
	done := make(chan struct{})
	ue.EnqueueSerial(func() { close(done) })
	<-done
}

// fire delivers the timer callback and waits for the expiry work it posts.
func fire(ue *amfctx.UEContext, t *fakeTimer) {
	t.f()
	barrier(ue)
}

// startOnQueue starts NSSAA like handleRegistrationComplete (on the queue).
func startOnQueue(h *Handler, ue *amfctx.UEContext) {
	onUESerialQueue(ue, func() { h.StartNSSAA(context.Background(), ue) })
}

// decodeCUC decodes a Configuration Update Command body.
func decodeCUC(t *testing.T, m sentMsg) *nas.ConfigurationUpdateCommand {
	t.Helper()
	c, err := nas.DecodeConfigurationUpdateCommand(m.body)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// T3575: 15 s, four retransmissions; the fifth expiry completes the procedure as
// a failure (TS 24.501 §5.4.7.2.3 a): no RESULT, slice in the Rejected NSSAI and
// neither allowed nor PENDING, one CUC carrying the Rejected NSSAI (cause 2).
func TestNSSAAT3575RetransmitAndAbort(t *testing.T) {
	h, sender, clk, ue := nssaaTestHandler(t, true, &nssaaScript{})
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	withPlainDefault(ue) // a default that can be allowed: CUC, not de-registration (AMF-022)
	startOnQueue(h, ue)
	if sender.n() != 1 || clk.count() != 1 || clk.last().d != NSSAAT3575Duration || NSSAAT3575Duration != 15*time.Second {
		t.Fatalf("start: sent=%d timers=%d", sender.n(), clk.count())
	}
	for i := 1; i <= NSSAAT3575MaxRetransmissions; i++ {
		fire(ue, clk.last())
		if sender.n() != 1+i || clk.live() != 1 {
			t.Fatalf("expiry %d: sent=%d live=%d", i, sender.n(), clk.live())
		}
	}
	before := sender.n()
	fire(ue, clk.last()) // fifth expiry
	if clk.live() != 0 || ue.NSSAATimerRunning() {
		t.Fatalf("abort: live=%d, want no timer", clk.live())
	}
	if got := sender.n() - before; got != 1 {
		t.Fatalf("abort sent %d messages, want exactly the Configuration Update Command", got)
	}
	if len(sender.ofType(t, ue, nas.MsgTypeNetworkSliceSpecificAuthResult)) != 0 {
		t.Fatal("no NSSAA RESULT may be sent on T3575 abort")
	}
	if !hasIn(ue.RejectedNSSAI, 1, "000003") || hasIn(ue.AllowedNSSAI, 1, "000003") ||
		len(ue.NSSAAPendingStatus) != 0 || len(ue.PendingNSSAA) != 0 || ue.NSSAAInProgress != nil {
		t.Fatalf("slice must be rejected, not allowed, not PENDING: %+v", ue)
	}
	cuc := sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)
	if len(cuc) != 1 {
		t.Fatalf("%d CUCs, want 1", len(cuc))
	}
	c := decodeCUC(t, cuc[0])
	want := []nas.RejectedSNSSAI{{Cause: nas.RejectedCauseNSSAAFailedOrRevoked, SNSSAI: nas.SNSSAI{SST: 1, SD: 3}}}
	// TS 24.501 §4.6.2.4 b): the only requested slice failed but a default S-NSSAI
	// (1-000009, not subject to NSSAA) can be allowed: it is the Allowed NSSAI of
	// the CUC, never an empty one.
	if len(c.RejectedNSSAI) != 1 || c.RejectedNSSAI[0] != want[0] ||
		c.AllowedNSSAI == nil || len(c.AllowedNSSAI.SNSSAIs) != 1 || c.AllowedNSSAI.SNSSAIs[0] != (nas.SNSSAI{SST: 1, SD: 9}) {
		t.Fatalf("CUC = %+v, want Rejected NSSAI %+v and Allowed NSSAI [1-000009]", c, want)
	}
}

// A slice failed by the T3575 abort is never retried: neither the PENDING retry
// nor a re-registration re-queues it.
func TestNSSAAT3575AbortedSliceNeverRetried(t *testing.T) {
	h, sender, clk, ue := nssaaTestHandler(t, true, &nssaaScript{})
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	startOnQueue(h, ue)
	for i := 0; i <= NSSAAT3575MaxRetransmissions; i++ {
		fire(ue, clk.last())
	}
	sent := sender.n()
	h.retryPendingNSSAA(context.Background(), ue, "service_request")
	if sender.n() != sent || ue.NSSAAInProgress != nil {
		t.Fatal("aborted slice must not be retried on a service request")
	}
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	h.reg.SplitPendingNSSAA(ue)
	if len(ue.PendingNSSAA) != 0 || len(ue.AllowedNSSAI) != 0 {
		t.Fatalf("re-registration must keep the failed slice out: %+v", ue)
	}
}

// After the abort the next queued slice is started; the single CUC comes when
// the whole queue is drained and carries the Allowed and the Rejected NSSAI.
func TestNSSAAT3575AbortStartsNextSliceOneCUC(t *testing.T) {
	aaa := &nssaaScript{first: &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}}
	h, sender, clk, ue := nssaaTestHandler(t, true, aaa)
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003"), sliceN(2, "000009")}
	startOnQueue(h, ue)
	for i := 0; i < NSSAAT3575MaxRetransmissions+1; i++ {
		fire(ue, clk.last())
	}
	if ue.NSSAAInProgress == nil || ue.NSSAAInProgress.SST != 2 || clk.live() != 1 {
		t.Fatalf("next slice not started: %+v live=%d", ue.NSSAAInProgress, clk.live())
	}
	if want := 1 + NSSAAT3575MaxRetransmissions + 1; sender.n() != want {
		t.Fatalf("sent = %d, want %d", sender.n(), want)
	}
	if len(sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)) != 0 {
		t.Fatal("CUC must wait for the queue to drain")
	}
	onUESerialQueue(ue, func() {
		if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 2, 9)); err != nil {
			t.Error(err)
		}
	})
	cuc := sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)
	if len(cuc) != 1 {
		t.Fatalf("%d CUCs, want exactly 1 for the whole queue", len(cuc))
	}
	c := decodeCUC(t, cuc[0])
	if c.AllowedNSSAI == nil || len(c.AllowedNSSAI.SNSSAIs) != 2 || len(c.RejectedNSSAI) != 1 ||
		c.RejectedNSSAI[0].Cause != nas.RejectedCauseNSSAAFailedOrRevoked || c.RejectedNSSAI[0].SNSSAI.SD != 3 {
		t.Fatalf("CUC = %+v", c)
	}
}

// A COMPLETE stops T3575; a callback already fired for the stopped timer is a no-op.
func TestNSSAAT3575StoppedByComplete(t *testing.T) {
	aaa := &nssaaScript{first: &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}}
	h, sender, clk, ue := nssaaTestHandler(t, true, aaa)
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	startOnQueue(h, ue)
	armed := clk.last()
	if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
		t.Fatal(err)
	}
	if !armed.stopped.Load() || clk.live() != 0 {
		t.Fatalf("T3575 still running: stopped=%v live=%d", armed.stopped.Load(), clk.live())
	}
	sent := sender.n()
	fire(ue, armed) // a stale callback delivered although the timer was stopped
	if sender.n() != sent {
		t.Fatal("late T3575 callback must not retransmit")
	}
	if !hasIn(ue.AllowedNSSAI, 1, "000003") {
		t.Fatalf("slice not allowed: %+v", ue.AllowedNSSAI)
	}
	// rel19 CUC: the new Allowed NSSAI, no Rejected NSSAI.
	c := decodeCUC(t, sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)[0])
	if c.AllowedNSSAI == nil || len(c.AllowedNSSAI.SNSSAIs) != 1 || len(c.RejectedNSSAI) != 0 {
		t.Fatalf("CUC = %+v", c)
	}
}

// rel19: an EAP-Failure result ends in one CUC with the Rejected NSSAI (cause 2)
// even though the Allowed NSSAI did not change; rel17 keeps no CUC at all.
func TestNSSAAConfigUpdateOnFailureRel19VsRel17(t *testing.T) {
	failure := &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultFailure, EAPPayload: eap.BuildFailure(1)}
	h, sender, _, ue := nssaaTestHandler(t, true, &nssaaScript{first: failure})
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	withPlainDefault(ue) // a default that can be allowed: CUC, not de-registration (AMF-022)
	startOnQueue(h, ue)
	if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
		t.Fatal(err)
	}
	if len(sender.ofType(t, ue, nas.MsgTypeNetworkSliceSpecificAuthResult)) != 1 {
		t.Fatal("EAP-Failure RESULT expected")
	}
	cuc := sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)
	if len(cuc) != 1 || len(decodeCUC(t, cuc[0]).RejectedNSSAI) != 1 {
		t.Fatalf("rel19 CUC = %d messages", len(cuc))
	}

	h, sender, _, ue = nssaaTestHandler(t, false, &nssaaScript{first: failure})
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	h.StartNSSAA(context.Background(), ue)
	if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
		t.Fatal(err)
	}
	if n := len(sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)); n != 0 {
		t.Fatalf("rel17 sent %d CUCs after a failed slice, want none (frozen)", n)
	}
}

// rel17 regression: the CUC after an authorized slice is byte-identical to the
// frozen one (Configuration update indication 0xD1 + Allowed NSSAI only).
func TestNSSAARel17ConfigUpdateBytesFrozen(t *testing.T) {
	aaa := &nssaaScript{first: &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}}
	h, sender, _, ue := nssaaTestHandler(t, false, aaa)
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	h.StartNSSAA(context.Background(), ue)
	if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
		t.Fatal(err)
	}
	cuc := sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)
	if len(cuc) != 1 {
		t.Fatalf("%d CUCs, want 1", len(cuc))
	}
	ack := byte(0xD1)
	allowed := nas.NSSAI{SNSSAIs: []nas.SNSSAI{{SST: 1, SD: 3}}}
	want, err := nas.EncodeConfigurationUpdateCommand(&nas.ConfigurationUpdateCommand{ConfigUpdateIndication: &ack, AllowedNSSAI: &allowed})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cuc[0].body, want) || !bytes.Equal(want, []byte{0xD1, 0x15, 0x05, 0x04, 0x01, 0x00, 0x00, 0x03}) {
		t.Fatalf("rel17 CUC = %x, want %x", cuc[0].body, want)
	}
}

// Multi-round: the non-terminal EAP-Request is sent in a COMMAND and T3575
// restarts; the terminal result sends a RESULT without a timer.
func TestNSSAAMultiRoundTimers(t *testing.T) {
	aaa := &nssaaScript{
		first: &procedures.NSSAAAuthResult{EAPRequest: []byte{eap.CodeRequest, 2, 0, 6, 4, 1}, AuthCtxID: "c1"},
		confirms: []*procedures.NSSAAAuthResult{
			{EAPRequest: []byte{eap.CodeRequest, 3, 0, 6, 4, 1}, AuthCtxID: "c1"},
			{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(4)},
		},
	}
	h, sender, clk, ue := nssaaTestHandler(t, true, aaa)
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	startOnQueue(h, ue)
	for round := 1; round <= 2; round++ {
		before := sender.n()
		if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
			t.Fatal(err)
		}
		if sender.n() != before+1 || clk.live() != 1 || ue.NSSAAAuthCtxID != "c1" {
			t.Fatalf("round %d: sent+%d live=%d ctx=%q", round, sender.n()-before, clk.live(), ue.NSSAAAuthCtxID)
		}
	}
	if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
		t.Fatal(err)
	}
	if clk.live() != 0 || !hasIn(ue.AllowedNSSAI, 1, "000003") || ue.NSSAAAuthCtxID != "" {
		t.Fatalf("terminal: live=%d allowed=%+v", clk.live(), ue.AllowedNSSAI)
	}
}

// rel17 keeps no T3575 supervision at all.
func TestNSSAARel17NoTimer(t *testing.T) {
	aaa := &nssaaScript{first: &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}}
	h, sender, clk, ue := nssaaTestHandler(t, false, aaa)
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	h.StartNSSAA(context.Background(), ue)
	if sender.n() != 1 || clk.count() != 0 || ue.NSSAATimerRunning() {
		t.Fatalf("rel17: sent=%d timers=%d", sender.n(), clk.count())
	}
	if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
		t.Fatal(err)
	}
	if clk.count() != 0 {
		t.Fatal("rel17 must never arm T3575")
	}
}

// PENDING retry on UE-initiated signalling (rel19 only); EAP-Failure slices never.
func TestNSSAARetryPendingOnUEProcedure(t *testing.T) {
	h, sender, clk, ue := nssaaTestHandler(t, true, &nssaaScript{})
	ue.NSSAAPendingStatus = []amfctx.SNSSAISubscribed{sliceN(1, "000003"), sliceN(1, "000004")}
	ue.RejectedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000004")}
	h.retryPendingNSSAA(context.Background(), ue, "service_request")
	if sender.n() != 1 || clk.live() != 1 || ue.NSSAAInProgress == nil || ue.NSSAAInProgress.SD != "000003" {
		t.Fatalf("retry: sent=%d live=%d inprogress=%+v", sender.n(), clk.live(), ue.NSSAAInProgress)
	}
	// Nothing left to retry, exchange running: no second COMMAND.
	h.retryPendingNSSAA(context.Background(), ue, "service_request")
	if sender.n() != 1 {
		t.Fatalf("sent = %d, want 1", sender.n())
	}

	h, sender, clk, ue = nssaaTestHandler(t, false, &nssaaScript{})
	ue.NSSAAPendingStatus = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	h.retryPendingNSSAA(context.Background(), ue, "service_request")
	if sender.n() != 0 || clk.count() != 0 {
		t.Fatal("rel17 must not retry")
	}
}

// A persistently failing NSSAAF is not hit on every Service Request: the same
// PENDING slice is retried at most once per NSSAAPendingRetryMinInterval.
func TestNSSAARetryMinInterval(t *testing.T) {
	h, sender, _, ue := nssaaTestHandler(t, true, &nssaaScript{})
	s := sliceN(1, "000003")
	ue.NSSAAPendingStatus = []amfctx.SNSSAISubscribed{s}
	ue.NSSAAPendingAt = map[string]time.Time{procedures.NSSAASliceKey(s): time.Now()}
	h.retryPendingNSSAA(context.Background(), ue, "service_request")
	if sender.n() != 0 || len(ue.NSSAAPendingStatus) != 1 {
		t.Fatalf("retry inside the interval: sent=%d pending=%+v", sender.n(), ue.NSSAAPendingStatus)
	}
	ue.NSSAAPendingAt[procedures.NSSAASliceKey(s)] = time.Now().Add(-procedures.NSSAAPendingRetryMinInterval - time.Second)
	h.retryPendingNSSAA(context.Background(), ue, "service_request")
	if sender.n() != 1 || ue.NSSAAInProgress == nil {
		t.Fatalf("retry after the interval: sent=%d", sender.n())
	}
}

// Item 7: the T3575 supervision dies with the exchange, de-registration, implicit
// detach / context removal and a re-registration; nothing is left keyed by SUPI.
func TestNSSAATimerStoppedOnTeardown(t *testing.T) {
	arm := func(t *testing.T) (*Handler, *fakeClock, *amfctx.UEContext) {
		h, _, clk, ue := nssaaTestHandler(t, true, &nssaaScript{})
		ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
		startOnQueue(h, ue)
		if clk.live() != 1 || !ue.NSSAATimerRunning() {
			t.Fatal("timer not armed")
		}
		return h, clk, ue
	}
	t.Run("context removal and implicit detach", func(t *testing.T) {
		h, clk, ue := arm(t)
		h.reg.RemoveUEContext(context.Background(), ue)
		if clk.live() != 0 || ue.NSSAATimerRunning() {
			t.Fatal("Manager.Remove must stop T3575")
		}
		fire(ue, clk.last()) // already-fired callback: nothing to do, nothing sent
	})
	t.Run("displaced by a fresh registration", func(t *testing.T) {
		h, clk, ue := arm(t)
		h.releaseDisplacedContext(context.Background(), ue)
		if clk.live() != 0 {
			t.Fatal("displaced context must stop T3575")
		}
	})
	t.Run("UE-initiated deregistration", func(t *testing.T) {
		h, clk, ue := arm(t)
		ue.SUPI = "" // no UDM/PCF legs in this unit test
		msg := &nas.Message{Body: &nas.DeregistrationRequest{SwitchOff: true}}
		if err := h.handleDeregistration(context.Background(), ue, msg); err != nil {
			t.Fatal(err)
		}
		if clk.live() != 0 {
			t.Fatal("de-registration must stop T3575")
		}
	})
	t.Run("network-initiated deregistration", func(t *testing.T) {
		h, clk, ue := arm(t)
		if err := h.SendNetworkDeregistration(context.Background(), ue, 0, 1, true); err != nil {
			t.Fatal(err)
		}
		if clk.live() != 0 {
			t.Fatal("NW de-registration must stop T3575")
		}
	})
	t.Run("re-registration recomputing the Allowed NSSAI", func(t *testing.T) {
		h, clk, ue := arm(t)
		ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
		onUESerialQueue(ue, func() { h.reg.SplitPendingNSSAA(ue) })
		if clk.live() != 0 || ue.NSSAAInProgress != nil {
			t.Fatalf("SplitPendingNSSAA must stop T3575: live=%d", clk.live())
		}
	})
}

// Item 6: the T3575 callback only posts to the UE's serial queue. Fired
// concurrently with a COMPLETE it can neither race the state nor act after the
// timer was stopped (run with -race).
func TestNSSAAT3575RaceWithComplete(t *testing.T) {
	for i := 0; i < 30; i++ {
		aaa := &nssaaScript{first: &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}}
		h, _, clk, ue := nssaaTestHandler(t, true, aaa)
		ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
		startOnQueue(h, ue)
		armed := clk.last()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() { // timer goroutine storm
			defer wg.Done()
			for j := 0; j < 5; j++ {
				armed.f()
			}
		}()
		ue.EnqueueSerial(func() {
			if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
				t.Error(err)
			}
		})
		wg.Wait()
		barrier(ue)
		if !hasIn(ue.AllowedNSSAI, 1, "000003") || clk.live() != 0 || ue.NSSAAInProgress != nil {
			t.Fatalf("iteration %d: allowed=%+v live=%d", i, ue.AllowedNSSAI, clk.live())
		}
	}
}

// Item 6: the same against a re-registration (SplitPendingNSSAA on the queue).
func TestNSSAAT3575RaceWithReRegistration(t *testing.T) {
	for i := 0; i < 30; i++ {
		h, _, clk, ue := nssaaTestHandler(t, true, &nssaaScript{})
		ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
		ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
		startOnQueue(h, ue)
		armed := clk.last()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				armed.f()
			}
		}()
		ue.EnqueueSerial(func() { // registration: recompute, then Registration Complete
			ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
			h.reg.SplitPendingNSSAA(ue)
			h.StartNSSAA(context.Background(), ue)
		})
		wg.Wait()
		barrier(ue)
		if ue.NSSAAInProgress == nil || clk.live() != 1 || !ue.NSSAATimerRunning() {
			t.Fatalf("iteration %d: inprogress=%v live=%d", i, ue.NSSAAInProgress, clk.live())
		}
	}
}
