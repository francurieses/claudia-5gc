package procedures

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// scriptNSSAA answers Authenticate once, then Confirm from a script.
type scriptNSSAA struct {
	first    *NSSAAAuthResult
	confirms []*NSSAAAuthResult
	cErr     error // returned by Confirm when set
	authN    int
	confN    int
	lastCtx  string
}

func (s *scriptNSSAA) Authenticate(context.Context, string, string, uint8, string, []byte) (*NSSAAAuthResult, error) {
	s.authN++
	return s.first, nil
}

func (s *scriptNSSAA) Confirm(_ context.Context, _, _ string, _ uint8, _, id string, _ []byte) (*NSSAAAuthResult, error) {
	s.confN++
	s.lastCtx = id
	if s.cErr != nil {
		return nil, s.cErr
	}
	r := s.confirms[0]
	s.confirms = s.confirms[1:]
	return r, nil
}

func eapReq(id byte) []byte { return []byte{eap.CodeRequest, id, 0, 6, 4, 1} }

func nonTerminal(id byte) *NSSAAAuthResult {
	return &NSSAAAuthResult{EAPRequest: eapReq(id), AuthCtxID: "ctx-1"}
}

func complete(ue *amfctx.UEContext) *nas.NSSAAuthComplete {
	return &nas.NSSAAuthComplete{
		SNSSAI:     nas.SNSSAI{SST: 1, SD: 0x000003},
		EAPMessage: eap.BuildIdentityResponse(ue.NSSAAEAPID, "alice@nssaa"),
	}
}

// Multi-round rel19: n EAP-Requests are relayed in COMMANDs for the same
// S-NSSAI with the authCtxId kept, then the terminal result is a RESULT.
func TestNSSAAMultiRound(t *testing.T) {
	for _, requests := range []int{1, 2, 3} { // EAP-Requests after the identity round
		for _, final := range []string{NSSAAResultSuccess, NSSAAResultFailure} {
			c := &scriptNSSAA{first: nonTerminal(2)}
			for i := 1; i < requests; i++ {
				c.confirms = append(c.confirms, nonTerminal(byte(2+i)))
			}
			term := &NSSAAAuthResult{AuthResult: final, EAPPayload: eap.BuildSuccess(9)}
			if final == NSSAAResultFailure {
				term.EAPPayload = eap.BuildFailure(9)
			}
			c.confirms = append(c.confirms, term)

			h := testHandler(c)
			h.WithNSSAASpecLiteral(true)
			ue, comp := startedUE(t, h, "msisdn-1")
			for r := 1; r <= requests; r++ {
				out, err := h.ProcessNSSAAComplete(context.Background(), ue, comp)
				if err != nil {
					t.Fatal(err)
				}
				if out.Result != nil || out.NextCommand == nil || out.NextCommand.SNSSAI != comp.SNSSAI {
					t.Fatalf("round %d: out=%+v, want a COMMAND for the same S-NSSAI", r, out)
				}
				if got, _ := eap.Code(out.NextCommand.EAPMessage); got != eap.CodeRequest {
					t.Fatalf("round %d: EAP code %d", r, got)
				}
				if ue.NSSAAAuthCtxID != "ctx-1" || ue.NSSAAInProgress == nil || ue.NSSAARounds != r {
					t.Fatalf("round %d: ctx=%q rounds=%d", r, ue.NSSAAAuthCtxID, ue.NSSAARounds)
				}
				comp = complete(ue)
			}
			out, err := h.ProcessNSSAAComplete(context.Background(), ue, comp)
			if err != nil || out.Result == nil {
				t.Fatalf("terminal: out=%+v err=%v", out, err)
			}
			if c.authN != 1 || c.confN != requests || c.lastCtx != "ctx-1" {
				t.Fatalf("calls auth=%d confirm=%d ctx=%q", c.authN, c.confN, c.lastCtx)
			}
			ok := final == NSSAAResultSuccess
			if out.Authorized != ok || hasSlice(ue.AllowedNSSAI, "000003") != ok || hasSlice(ue.RejectedNSSAI, "000003") == ok {
				t.Fatalf("final %s: out=%+v allowed=%v rejected=%v", final, out, ue.AllowedNSSAI, ue.RejectedNSSAI)
			}
			if ue.NSSAAAuthCtxID != "" || ue.NSSAARounds != 0 || ue.NSSAAInProgress != nil {
				t.Fatalf("exchange state not reset: %+v", ue)
			}
		}
	}
}

func TestNSSAAMultiRoundLimit(t *testing.T) {
	c := &scriptNSSAA{first: nonTerminal(2)}
	for i := 0; i < NSSAAMaxEAPRounds+2; i++ {
		c.confirms = append(c.confirms, nonTerminal(byte(3+i)))
	}
	h := testHandler(c)
	h.WithNSSAASpecLiteral(true)
	ue, comp := startedUE(t, h, "msisdn-1")
	for r := 1; r <= NSSAAMaxEAPRounds; r++ {
		out, err := h.ProcessNSSAAComplete(context.Background(), ue, comp)
		if err != nil || out.NextCommand == nil {
			t.Fatalf("round %d: out=%+v err=%v", r, out, err)
		}
		comp = complete(ue)
	}
	out, err := h.ProcessNSSAAComplete(context.Background(), ue, comp)
	if err != nil || out.Result != nil || out.NextCommand != nil {
		t.Fatalf("round limit: out=%+v err=%v", out, err)
	}
	assertPending(t, ue)
}

func assertPending(t *testing.T, ue *amfctx.UEContext) {
	t.Helper()
	if hasSlice(ue.AllowedNSSAI, "000003") || hasSlice(ue.RejectedNSSAI, "000003") {
		t.Fatal("PENDING slice must be neither allowed nor rejected")
	}
	if !hasSlice(ue.NSSAAPendingStatus, "000003") || ue.NSSAAInProgress != nil ||
		len(ue.PendingNSSAA) != 0 || ue.NSSAAAuthCtxID != "" || ue.NSSAARounds != 0 {
		t.Fatalf("pending state wrong: %+v", ue)
	}
}

// A transport error on the PUT keeps the slice PENDING (no RESULT, not rejected).
func TestNSSAAMultiRoundPutErrorPending(t *testing.T) {
	c := &scriptNSSAA{first: nonTerminal(2), cErr: errors.New("amf: nssaa confirm: dial")}
	h := testHandler(c)
	h.WithNSSAASpecLiteral(true)
	ue, comp := startedUE(t, h, "msisdn-1")
	if out, err := h.ProcessNSSAAComplete(context.Background(), ue, comp); err != nil || out.NextCommand == nil {
		t.Fatalf("round 1: %+v %v", out, err)
	}
	out, err := h.ProcessNSSAAComplete(context.Background(), ue, complete(ue))
	if err != nil || out.Result != nil || out.NextCommand != nil {
		t.Fatalf("put error: out=%+v err=%v", out, err)
	}
	assertPending(t, ue)
}

// A client without Confirm cannot continue a multi-round exchange: PENDING.
func TestNSSAAMultiRoundNoConfirmer(t *testing.T) {
	type onlyAuth struct{ NSSAAClient }
	c := &scriptNSSAA{first: nonTerminal(2)}
	h := testHandler(onlyAuth{c})
	h.WithNSSAASpecLiteral(true)
	ue, comp := startedUE(t, h, "msisdn-1")
	h.ProcessNSSAAComplete(context.Background(), ue, comp)
	out, err := h.ProcessNSSAAComplete(context.Background(), ue, complete(ue))
	if err != nil || out.Result != nil {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	assertPending(t, ue)
}

// T3575 abort (rel19, TS 24.501 §5.4.7.2.3 a "completed as a failure"): the slice
// is rejected - not PENDING, not allowed - and the next queued slice starts; rel17
// has no T3575 so the call is a no-op.
func TestAbortNSSAA(t *testing.T) {
	h := testHandler(&scriptNSSAA{})
	ue, _ := startedUE(t, h, "msisdn-1")
	if h.AbortNSSAA(ue, errors.New("t3575")) != nil || ue.NSSAAInProgress == nil {
		t.Fatal("rel17 has no T3575 abort: must be a no-op")
	}
	h.WithNSSAASpecLiteral(true)
	ue.PendingNSSAA = append(ue.PendingNSSAA, amfctx.SNSSAISubscribed{SST: 2, SD: "000009"})
	ue.NSSAAPendingStatus = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000003"}}
	out := h.AbortNSSAA(ue, errors.New("t3575"))
	if out == nil || out.Result != nil || out.NextCommand == nil || out.NextCommand.SNSSAI.SST != 2 || out.ConfigUpdate {
		t.Fatalf("abort: %+v", out)
	}
	if !hasSlice(ue.RejectedNSSAI, "000003") || hasSlice(ue.NSSAAPendingStatus, "000003") ||
		hasSlice(ue.AllowedNSSAI, "000003") || hasSlice(ue.PendingNSSAA, "000003") {
		t.Fatalf("slice must be rejected, out of Allowed and of PENDING: %+v", ue)
	}
	if !ue.NSSAAResultsChanged {
		t.Fatal("the abort is a new result: results-changed must be set")
	}
	// Never retried while registered: neither retry nor re-registration queues it.
	if h.RetryPendingNSSAA(ue) {
		t.Fatal("aborted slice must not be retried")
	}
}

// Queue drain decides the CONFIGURATION UPDATE COMMAND: rel19 once for the whole
// queue when any slice got a result (also failures and aborts); rel17 only when
// the last COMPLETE was authorized (frozen).
func TestNSSAAConfigUpdateTrigger(t *testing.T) {
	success := &NSSAAAuthResult{AuthResult: NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}
	failure := &NSSAAAuthResult{AuthResult: NSSAAResultFailure, EAPPayload: eap.BuildFailure(1)}
	run := func(spec bool, first, second *NSSAAAuthResult) (*NSSAACompleteOutcome, *NSSAACompleteOutcome) {
		c := &scriptNSSAA{first: first}
		h := testHandler(c)
		h.WithNSSAASpecLiteral(spec)
		ue, comp := startedUE(t, h, "msisdn-1")
		ue.PendingNSSAA = append(ue.PendingNSSAA, amfctx.SNSSAISubscribed{SST: 2, SD: "000009"})
		o1, err := h.ProcessNSSAAComplete(context.Background(), ue, comp)
		if err != nil || o1.NextCommand == nil {
			t.Fatalf("first: %+v %v", o1, err)
		}
		c.first = second
		o2, err := h.ProcessNSSAAComplete(context.Background(), ue, &nas.NSSAAuthComplete{
			SNSSAI: o1.NextCommand.SNSSAI, EAPMessage: eap.BuildIdentityResponse(ue.NSSAAEAPID, "x"),
		})
		if err != nil {
			t.Fatal(err)
		}
		return o1, o2
	}
	// slice 1 succeeds, slice 2 fails: rel19 one CUC at the drain; rel17 none (frozen).
	o1, o2 := run(true, success, failure)
	if o1.ConfigUpdate || !o2.ConfigUpdate {
		t.Fatalf("rel19 success then failure: CUC mid-queue=%v at drain=%v", o1.ConfigUpdate, o2.ConfigUpdate)
	}
	if _, o2 = run(false, success, failure); o2.ConfigUpdate {
		t.Fatal("rel17 success then failure must keep today's behaviour (no CUC)")
	}
	// slice 1 fails, slice 2 succeeds: both profiles send the CUC at the drain.
	if _, o2 = run(true, failure, success); !o2.ConfigUpdate {
		t.Fatal("rel19 failure then success: CUC expected")
	}
	if _, o2 = run(false, failure, success); !o2.ConfigUpdate || !o2.AllowedChanged {
		t.Fatal("rel17 failure then success: CUC expected (frozen)")
	}
	// all failed: rel19 network-initiated de-registration with the Rejected NSSAI
	// (AMF-022, no default S-NSSAI can be allowed), no CUC; rel17 none.
	if _, o2 = run(true, failure, failure); o2.ConfigUpdate || !o2.Deregister {
		t.Fatal("rel19 all failed: de-registration expected, not a CUC")
	}
	if _, o2 = run(false, failure, failure); o2.ConfigUpdate || o2.Deregister {
		t.Fatal("rel17 all failed: no CUC (frozen)")
	}
}

// Draining through keepNSSAAPending also sends the CUC when an earlier slice of
// the queue got a result.
func TestNSSAAConfigUpdateOnPendingDrain(t *testing.T) {
	c := &scriptNSSAA{first: &NSSAAAuthResult{AuthResult: NSSAAResultFailure, EAPPayload: eap.BuildFailure(1)}}
	h := testHandler(c)
	h.WithNSSAASpecLiteral(true)
	ue, comp := startedUE(t, h, "msisdn-1")
	ue.PendingNSSAA = append(ue.PendingNSSAA, amfctx.SNSSAISubscribed{SST: 2, SD: "000009"})
	o1, _ := h.ProcessNSSAAComplete(context.Background(), ue, comp)
	h.nssaa = errNSSAA{} // the NSSAAF fails for the second slice
	o2, err := h.ProcessNSSAAComplete(context.Background(), ue, &nas.NSSAAuthComplete{
		SNSSAI: o1.NextCommand.SNSSAI, EAPMessage: eap.BuildIdentityResponse(ue.NSSAAEAPID, "x"),
	})
	if err != nil || o2.Result != nil || !o2.ConfigUpdate {
		t.Fatalf("drain via PENDING: %+v %v", o2, err)
	}
}

type errNSSAA struct{}

func (errNSSAA) Authenticate(context.Context, string, string, uint8, string, []byte) (*NSSAAAuthResult, error) {
	return nil, errors.New("amf: nssaa create: connection refused")
}

// Item 8: a 404 on the PUT (NSSAAF lost the context) restarts the exchange once
// with a fresh EAP-Request/Identity (new create on the answer); the second loss
// keeps the slice PENDING. The orphaned authCtxId is logged on every abandon.
func TestNSSAAContextLostRestart(t *testing.T) {
	var buf bytes.Buffer
	c := &scriptNSSAA{first: nonTerminal(2), cErr: fmt.Errorf("status 404: %w", ErrNSSAAContextLost)}
	h := testHandler(c)
	h.logger = slog.New(slog.NewTextHandler(&buf, nil))
	h.WithNSSAASpecLiteral(true)
	ue, comp := startedUE(t, h, "msisdn-1")
	if out, err := h.ProcessNSSAAComplete(context.Background(), ue, comp); err != nil || out.NextCommand == nil {
		t.Fatalf("round 1: %+v %v", out, err)
	}
	out, err := h.ProcessNSSAAComplete(context.Background(), ue, complete(ue))
	if err != nil || out.Result != nil || out.NextCommand == nil || ue.NSSAAInProgress == nil {
		t.Fatalf("restart: out=%+v err=%v", out, err)
	}
	if code, _ := eap.Code(out.NextCommand.EAPMessage); code != eap.CodeRequest ||
		ue.NSSAAAuthCtxID != "" || ue.NSSAARestarts != 1 {
		t.Fatalf("restart state: ctx=%q restarts=%d", ue.NSSAAAuthCtxID, ue.NSSAARestarts)
	}
	if !strings.Contains(buf.String(), "auth_ctx_id=ctx-1") {
		t.Fatalf("orphaned authCtxId not logged:\n%s", buf.String())
	}
	// The UE answers the new identity request: a new create, not a PUT.
	if out, err = h.ProcessNSSAAComplete(context.Background(), ue, complete(ue)); err != nil || out.NextCommand == nil || c.authN != 2 {
		t.Fatalf("new create: out=%+v err=%v creates=%d", out, err, c.authN)
	}
	// Second context loss: bounded, the slice goes PENDING.
	out, err = h.ProcessNSSAAComplete(context.Background(), ue, complete(ue))
	if err != nil || out.Result != nil || out.NextCommand != nil {
		t.Fatalf("second loss: %+v %v", out, err)
	}
	assertPending(t, ue)
}

// Item 8: abandoning an exchange (PENDING on a transport error, round cap, abort,
// re-registration) logs the orphaned authCtxId.
func TestNSSAAOrphanedAuthCtxLogged(t *testing.T) {
	logs := func(f func(h *RegistrationHandler, ue *amfctx.UEContext)) string {
		var buf bytes.Buffer
		c := &scriptNSSAA{first: nonTerminal(2), cErr: errors.New("amf: nssaa confirm: dial")}
		h := testHandler(c)
		h.logger = slog.New(slog.NewTextHandler(&buf, nil))
		h.WithNSSAASpecLiteral(true)
		ue, comp := startedUE(t, h, "msisdn-1")
		if _, err := h.ProcessNSSAAComplete(context.Background(), ue, comp); err != nil {
			t.Fatal(err)
		}
		f(h, ue)
		return buf.String()
	}
	for name, f := range map[string]func(*RegistrationHandler, *amfctx.UEContext){
		"pending": func(h *RegistrationHandler, ue *amfctx.UEContext) {
			_, _ = h.ProcessNSSAAComplete(context.Background(), ue, complete(ue))
		},
		"abort": func(h *RegistrationHandler, ue *amfctx.UEContext) { h.AbortNSSAA(ue, errors.New("t3575")) },
		"registration": func(h *RegistrationHandler, ue *amfctx.UEContext) {
			ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000003", SubjectToNSSAA: true}}
			h.SplitPendingNSSAA(ue)
		},
	} {
		if out := logs(f); !strings.Contains(out, "auth_ctx_id=ctx-1") || !strings.Contains(out, "orphaned") {
			t.Errorf("%s: orphaned authCtxId not logged:\n%s", name, out)
		}
	}
}

// Item 3 (F3): rel19 Registration Accept carries the Pending NSSAI and the
// Rejected NSSAI (cause 2); rel17 adds neither.
func TestApplyNSSAAAcceptIEs(t *testing.T) {
	mk := func(spec bool) (*RegistrationHandler, *amfctx.UEContext) {
		h := testHandler(&scriptNSSAA{})
		h.WithNSSAASpecLiteral(spec)
		ue := &amfctx.UEContext{SUPI: "imsi-1"}
		ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
		ue.PendingNSSAA = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000003"}}
		ue.NSSAAPendingStatus = []amfctx.SNSSAISubscribed{{SST: 2, SD: "000009"}}
		ue.RejectedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000004"}}
		return h, ue
	}
	h, ue := mk(true)
	ra := &nas.RegistrationAccept{}
	h.applyNSSAAAcceptIEs(ra, ue)
	if ra.PendingNSSAI == nil || len(ra.PendingNSSAI.SNSSAIs) != 2 ||
		ra.PendingNSSAI.SNSSAIs[0] != (nas.SNSSAI{SST: 1, SD: 3}) || ra.PendingNSSAI.SNSSAIs[1] != (nas.SNSSAI{SST: 2, SD: 9}) {
		t.Fatalf("Pending NSSAI = %+v", ra.PendingNSSAI)
	}
	want, _ := nas.RejectedNSSAIValue([]nas.RejectedSNSSAI{{Cause: nas.RejectedCauseNSSAAFailedOrRevoked, SNSSAI: nas.SNSSAI{SST: 1, SD: 4}}})
	if !bytes.Equal(ra.RejectedNSSAI, want) || !bytes.Equal(want, []byte{0x42, 0x01, 0x00, 0x00, 0x04}) {
		t.Fatalf("Rejected NSSAI = %x, want %x", ra.RejectedNSSAI, want)
	}
	// A slice already allowed or rejected is not pending any more.
	ue.AllowedNSSAI = append(ue.AllowedNSSAI, amfctx.SNSSAISubscribed{SST: 1, SD: "000003"})
	ra = &nas.RegistrationAccept{}
	h.applyNSSAAAcceptIEs(ra, ue)
	if ra.PendingNSSAI == nil || len(ra.PendingNSSAI.SNSSAIs) != 1 {
		t.Fatalf("Pending NSSAI = %+v", ra.PendingNSSAI)
	}

	h, ue = mk(false)
	ra = &nas.RegistrationAccept{}
	h.applyNSSAAAcceptIEs(ra, ue)
	if ra.PendingNSSAI != nil || ra.RejectedNSSAI != nil {
		t.Fatalf("rel17 Registration Accept must stay unchanged: %+v", ra)
	}
}

// N1 (spec-verifier): with only NSSAA slices requested, rel19 omits the empty
// Allowed NSSAI and sets "NSSAA to be performed" (TS 24.501 §5.5.1.2.4 d),
// §9.11.3.6 octet 3 bit 5); rel17 keeps the legacy accept untouched.
func TestApplyNSSAAAcceptIEs_OnlyPending(t *testing.T) {
	for _, spec := range []bool{true, false} {
		h := testHandler(&scriptNSSAA{})
		h.WithNSSAASpecLiteral(spec)
		ue := &amfctx.UEContext{SUPI: "imsi-1"}
		ue.PendingNSSAA = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000003"}}
		empty := nas.NSSAI{}
		ra := &nas.RegistrationAccept{RegistrationResult: 0x01, AllowedNSSAI: &empty}
		h.applyNSSAAAcceptIEs(ra, ue)
		if spec {
			if ra.AllowedNSSAI != nil {
				t.Fatalf("rel19: empty Allowed NSSAI must be omitted, got %+v", ra.AllowedNSSAI)
			}
			if ra.RegistrationResult != 0x11 {
				t.Fatalf("rel19: RegistrationResult = %#x, want 0x11", ra.RegistrationResult)
			}
			if ra.PendingNSSAI == nil {
				t.Fatal("rel19: Pending NSSAI missing")
			}
			continue
		}
		if ra.AllowedNSSAI != &empty || ra.RegistrationResult != 0x01 {
			t.Fatalf("rel17 accept changed: %+v", ra)
		}
	}
}

func TestNASRejectedNSSAICap(t *testing.T) {
	var subs []amfctx.SNSSAISubscribed
	for i := 0; i < nas.MaxRejectedSNSSAIs+3; i++ {
		subs = append(subs, amfctx.SNSSAISubscribed{SST: uint8(i + 1)})
	}
	list, complete := NASRejectedNSSAI(subs)
	if len(list) != nas.MaxRejectedSNSSAIs || complete {
		t.Fatalf("len=%d complete=%v", len(list), complete)
	}
	if list[0].Cause != nas.RejectedCauseNSSAAFailedOrRevoked || list[0].SNSSAI.SD != nas.SDNotPresent {
		t.Fatalf("entry = %+v", list[0])
	}
}

// Item 9: the PENDING retry waits NSSAAPendingRetryMinInterval per slice.
func TestRetryPendingNSSAAMinInterval(t *testing.T) {
	pend := amfctx.SNSSAISubscribed{SST: 1, SD: "000003"}
	h := testHandler(&scriptNSSAA{})
	h.WithNSSAASpecLiteral(true)
	ue := &amfctx.UEContext{SUPI: "imsi-1", NSSAAPendingStatus: []amfctx.SNSSAISubscribed{pend},
		NSSAAPendingAt: map[string]time.Time{NSSAASliceKey(pend): time.Now()}}
	if h.RetryPendingNSSAA(ue) || len(ue.NSSAAPendingStatus) != 1 {
		t.Fatal("a slice left PENDING just now must not be retried")
	}
	ue.NSSAAPendingAt[NSSAASliceKey(pend)] = time.Now().Add(-NSSAAPendingRetryMinInterval - time.Second)
	if !h.RetryPendingNSSAA(ue) || len(ue.NSSAAPendingStatus) != 0 {
		t.Fatal("retry expected once the interval elapsed")
	}
}

func TestRetryPendingNSSAA(t *testing.T) {
	pend := amfctx.SNSSAISubscribed{SST: 1, SD: "000003"}
	failed := amfctx.SNSSAISubscribed{SST: 1, SD: "000004"}
	mk := func(spec bool) (*RegistrationHandler, *amfctx.UEContext) {
		h := testHandler(&scriptNSSAA{})
		h.WithNSSAASpecLiteral(spec)
		ue := &amfctx.UEContext{SUPI: "imsi-1"}
		ue.NSSAAPendingStatus = []amfctx.SNSSAISubscribed{pend, failed}
		ue.RejectedNSSAI = []amfctx.SNSSAISubscribed{failed}
		return h, ue
	}
	h, ue := mk(true)
	if !h.RetryPendingNSSAA(ue) {
		t.Fatal("rel19 must re-queue PENDING slices")
	}
	if !hasSlice(ue.PendingNSSAA, "000003") || hasSlice(ue.PendingNSSAA, "000004") || len(ue.NSSAAPendingStatus) != 0 {
		t.Fatalf("EAP-Failure slice must never be retried: pending=%+v", ue.PendingNSSAA)
	}
	if _, started := h.StartNSSAA(context.Background(), ue); !started {
		t.Fatal("retry must be startable")
	}
	if h.RetryPendingNSSAA(ue) {
		t.Fatal("no retry while an exchange runs")
	}
	h, ue = mk(false)
	if h.RetryPendingNSSAA(ue) || len(ue.PendingNSSAA) != 0 || len(ue.NSSAAPendingStatus) != 2 {
		t.Fatal("rel17 must not retry")
	}
}

// rel19 registration re-queues PENDING slices through SplitPendingNSSAA, keeps
// EAP-Failure slices out and resets a half-run exchange; rel17 is unchanged.
func TestSplitPendingNSSAARel19Retry(t *testing.T) {
	sub := func() []amfctx.SNSSAISubscribed {
		return []amfctx.SNSSAISubscribed{
			{SST: 1, SD: "000001"},
			{SST: 1, SD: "000003", SubjectToNSSAA: true},
			{SST: 1, SD: "000004", SubjectToNSSAA: true},
		}
	}
	h := testHandler(&scriptNSSAA{})
	h.WithNSSAASpecLiteral(true)
	ue := &amfctx.UEContext{SUPI: "imsi-1", AllowedNSSAI: sub()}
	ue.NSSAAPendingStatus = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000003"}}
	ue.RejectedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000004"}}
	ue.NSSAAInProgress = &amfctx.SNSSAISubscribed{SST: 1, SD: "000099"}
	ue.NSSAAAuthCtxID, ue.NSSAARounds = "stale", 3
	h.SplitPendingNSSAA(ue)
	if len(ue.AllowedNSSAI) != 1 || len(ue.PendingNSSAA) != 1 || !hasSlice(ue.PendingNSSAA, "000003") {
		t.Fatalf("allowed=%+v pending=%+v", ue.AllowedNSSAI, ue.PendingNSSAA)
	}
	if ue.NSSAAInProgress != nil || ue.NSSAAAuthCtxID != "" || len(ue.NSSAAPendingStatus) != 0 {
		t.Fatalf("exchange state not reset: %+v", ue)
	}
	// Idempotent: a second registration does not duplicate the queue.
	ue.AllowedNSSAI = sub()
	h.SplitPendingNSSAA(ue)
	if len(ue.PendingNSSAA) != 1 {
		t.Fatalf("pending = %+v", ue.PendingNSSAA)
	}

	// rel17: both flagged slices are queued again, state untouched.
	h = testHandler(&scriptNSSAA{})
	ue = &amfctx.UEContext{SUPI: "imsi-1", AllowedNSSAI: sub()}
	ue.RejectedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000004"}}
	h.SplitPendingNSSAA(ue)
	if len(ue.PendingNSSAA) != 2 {
		t.Fatalf("rel17 pending = %+v", ue.PendingNSSAA)
	}
}

// rel17 never runs the multi-round path, even if a client returned one.
func TestNSSAARel17IgnoresConfirm(t *testing.T) {
	c := &scriptNSSAA{first: &NSSAAAuthResult{AuthResult: NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}}
	h := testHandler(c)
	ue, comp := startedUE(t, h, "msisdn-1")
	out, err := h.ProcessNSSAAComplete(context.Background(), ue, comp)
	if err != nil || !out.Authorized || c.confN != 0 {
		t.Fatalf("out=%+v err=%v confirm=%d", out, err, c.confN)
	}
}
