package nasmsg

// nssaa_rework_test.go - rel19 NSSAA de-registration rework: Extended rejected
// NSSAI selection by the UE's ER-NSSAI capability (DEREGISTRATION REQUEST,
// CONFIGURATION UPDATE COMMAND), default S-NSSAIs in the CUC when every requested
// slice failed (TS 24.501 §4.6.2.4 b)), T3522 supervision of the NW-initiated
// DEREGISTRATION REQUEST (§5.5.2.3.1, §5.5.2.3.5 a)), the 5GMM-REGISTERED guard,
// the send-failure fallback and the rel17 freeze.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// flakySender records like recSender but fails the sends whose 1-based ordinal is
// in failOn, and counts the UE Context Release Commands.
type flakySender struct {
	recSender
	cmu      sync.Mutex
	calls    int
	failOn   map[int]bool
	releases int
}

func (f *flakySender) SendDownlinkNASTransport(ue *amfctx.UEContext, pdu []byte) error {
	f.cmu.Lock()
	f.calls++
	fail := f.failOn[f.calls]
	f.cmu.Unlock()
	if fail {
		return errors.New("n2: association down")
	}
	return f.recSender.SendDownlinkNASTransport(ue, pdu)
}

func (f *flakySender) SendUEContextReleaseCommandForUE(*amfctx.UEContext, int, int64) error {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.releases++
	return nil
}

// handlerWith builds the nssaaTestHandler but with sender s.
func handlerWith(t *testing.T, spec bool, s *flakySender) (*Handler, *fakeClock, *amfctx.UEContext) {
	t.Helper()
	h, _, clk, ue := nssaaTestHandler(t, spec, &nssaaScript{})
	h.sender = s
	return h, clk, ue
}

func rejectedA() []amfctx.SNSSAISubscribed { return []amfctx.SNSSAISubscribed{sliceN(1, "000003")} }

func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

// An ER-NSSAI capable UE gets the Extended rejected NSSAI IE (0x68) INSTEAD of the
// Rejected NSSAI IE (0x6D) in the DEREGISTRATION REQUEST; others the 0x6D one.
func TestNSSAADeregExtendedRejectedNSSAI(t *testing.T) {
	for _, tc := range []struct {
		name   string
		er     bool
		wantER bool
	}{
		{"rel19 ER-NSSAI UE", true, true},
		{"rel19 UE without ER-NSSAI", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &flakySender{}
			h, _, ue := handlerWith(t, true, s)
			ue.RejectedNSSAI = rejectedA()
			ue.ERNSSAISupported = tc.er
			h.deregisterForNSSAA(context.Background(), ue)
			d := s.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)
			if len(d) != 1 {
				t.Fatalf("%d DEREGISTRATION REQUESTs, want 1", len(d))
			}
			req, err := nas.DecodeDeregistrationRequestNW(d[0].body)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantER {
				if len(req.RejectedNSSAI) != 0 || req.ExtendedRejectedNSSAI == nil {
					t.Fatalf("want only the Extended rejected NSSAI IE, got %+v", req)
				}
				els := req.ExtendedRejectedNSSAI.Lists[0].Elements
				if len(els) != 1 || els[0].Cause != nas.RejectedCauseNSSAAFailedOrRevoked || els[0].SNSSAI != (nas.SNSSAI{SST: 1, SD: 3}) {
					t.Fatalf("Extended rejected NSSAI = %+v", els)
				}
				if !containsByte(d[0].body, nas.IEIExtendedRejectedNSSAI) || containsByte(d[0].body, nas.IEIDeregRejectedNSSAI) {
					t.Fatalf("want IEI 0x68 and not 0x6D in % x", d[0].body)
				}
			} else if len(req.RejectedNSSAI) != 1 || req.ExtendedRejectedNSSAI != nil {
				t.Fatalf("want only the Rejected NSSAI IE, got %+v", req)
			}
			if d[0].body[0]&0xF0 != 0 {
				t.Fatalf("rel19 spare half octet = %#x, want 0", d[0].body[0]&0xF0)
			}
		})
	}
}

// CUC: rejected NSSAI in the Extended rejected NSSAI IE for an ER-NSSAI UE, else
// in the Rejected NSSAI IE (TS 24.501 §5.4.4.2); rel17 frozen (ignores the capability).
func TestNSSAAConfigUpdateExtendedRejectedNSSAI(t *testing.T) {
	for _, tc := range []struct {
		name              string
		spec, er          bool
		wantER, wantPlain bool
	}{
		{"rel19 ER-NSSAI UE", true, true, true, false},
		{"rel19 plain UE", true, false, false, true},
		{"rel17 ER-NSSAI UE: Allowed NSSAI only", false, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, sender, _, ue := nssaaTestHandler(t, tc.spec, &nssaaScript{})
			ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000009"}}
			ue.RejectedNSSAI = rejectedA()
			ue.ERNSSAISupported = tc.er
			h.sendNSSAAConfigUpdate(context.Background(), ue)
			c := decodeCUC(t, sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)[0])
			if (c.ExtendedRejectedNSSAI != nil) != tc.wantER || (len(c.RejectedNSSAI) > 0) != tc.wantPlain {
				t.Fatalf("CUC = %+v", c)
			}
			if c.AllowedNSSAI == nil {
				t.Fatal("Allowed NSSAI missing")
			}
		})
	}
}

// TS 24.501 §4.6.2.4 b): every requested slice failed but a default S-NSSAI can be
// allowed -> the CUC carries it as the Allowed NSSAI (never an empty Allowed NSSAI
// CUC); a default subject to NSSAA does not count.
func TestNSSAADefaultAllowedInConfigUpdate(t *testing.T) {
	plain := amfctx.SNSSAISubscribed{SST: 1, SD: "000009"}
	wantDefault := nas.SNSSAI{SST: 1, SD: 9}
	t.Run("EAP-Failure", func(t *testing.T) {
		h, sender, _, ue := nssaaTestHandler(t, true, &seqAAA{results: []*procedures.NSSAAAuthResult{eapFailure()}})
		ue.PendingNSSAA = rejectedA()
		ue.SubscribedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003"), plain, sliceN(1, "00000a")}
		startOnQueue(h, ue)
		if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
			t.Fatal(err)
		}
		if n := len(sender.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)); n != 0 {
			t.Fatalf("%d de-registrations, want none (a default can be allowed)", n)
		}
		c := decodeCUC(t, sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)[0])
		if c.AllowedNSSAI == nil || len(c.AllowedNSSAI.SNSSAIs) != 1 || c.AllowedNSSAI.SNSSAIs[0] != wantDefault {
			t.Fatalf("CUC Allowed NSSAI = %+v, want [1-000009]", c.AllowedNSSAI)
		}
		if len(c.RejectedNSSAI) != 1 {
			t.Fatalf("CUC Rejected NSSAI = %+v", c.RejectedNSSAI)
		}
		if !hasIn(ue.AllowedNSSAI, 1, "000009") {
			t.Fatalf("UE context Allowed NSSAI = %+v", ue.AllowedNSSAI)
		}
	})
	t.Run("revocation of the last allowed slice", func(t *testing.T) {
		h, sender, _, ue := nssaaTestHandler(t, true, &nssaaScript{})
		ue.AllowedNSSAI = rejectedA()
		ue.SubscribedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003"), plain}
		if !h.RevokeNSSAASlice(context.Background(), ue, 1, "000003") {
			t.Fatal("not revoked")
		}
		c := decodeCUC(t, sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)[0])
		if c.AllowedNSSAI == nil || len(c.AllowedNSSAI.SNSSAIs) != 1 || c.AllowedNSSAI.SNSSAIs[0] != wantDefault {
			t.Fatalf("CUC Allowed NSSAI = %+v, want [1-000009]", c.AllowedNSSAI)
		}
	})
	t.Run("rel17 never adds defaults", func(t *testing.T) {
		h, sender, _, ue := nssaaTestHandler(t, false, &nssaaScript{})
		ue.AllowedNSSAI = rejectedA()
		ue.SubscribedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003"), plain}
		h.RevokeNSSAASlice(context.Background(), ue, 1, "000003")
		c := decodeCUC(t, sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)[0])
		if c.AllowedNSSAI == nil || len(c.AllowedNSSAI.SNSSAIs) != 0 || len(c.RejectedNSSAI) != 0 {
			t.Fatalf("rel17 CUC = %+v, want the frozen empty Allowed NSSAI only", c)
		}
	})
}

// The 5GMM-REGISTERED guard: a UE already being de-registered gets no second
// DEREGISTRATION REQUEST and no CUC, from any of the three entry points.
func TestNSSAANoSignallingUnlessRegistered(t *testing.T) {
	for _, st := range []amfctx.GMM5State{amfctx.GMMDeregisteredInitiated, amfctx.GMMDeregistered} {
		t.Run(st.String(), func(t *testing.T) {
			h, sender, clk, ue := nssaaTestHandler(t, true, &nssaaScript{})
			ue.State = st
			ue.RejectedNSSAI = rejectedA()
			ue.SubscribedNSSAI = rejectedA()
			h.deregisterForNSSAA(context.Background(), ue)
			h.finishNSSAA(context.Background(), ue, &procedures.NSSAACompleteOutcome{Deregister: true})
			h.finishNSSAA(context.Background(), ue, &procedures.NSSAACompleteOutcome{ConfigUpdate: true})
			ue.AllowedNSSAI = rejectedA()
			if !h.RevokeNSSAASlice(context.Background(), ue, 1, "000003") {
				t.Fatal("state update (revocation) must still happen")
			}
			if sender.n() != 0 || clk.liveOf(NWDeregT3522Duration) != 0 {
				t.Fatalf("%d messages sent, want none", sender.n())
			}
			if ue.State != st {
				t.Fatalf("state changed to %v", ue.State)
			}
		})
	}
}

// A failed DEREGISTRATION REQUEST send falls back to the CUC with the rejected
// NSSAI; the REJECT metric counts only a de-registration really sent.
func TestNSSAADeregSendFailureFallsBackToCUC(t *testing.T) {
	counter := metrics.ProcedureTotal.WithLabelValues("AMF", "NSSAA", "REJECT")
	before := testutil.ToFloat64(counter)

	s := &flakySender{failOn: map[int]bool{1: true}}
	h, clk, ue := handlerWith(t, true, s)
	ue.RejectedNSSAI = rejectedA()
	h.deregisterForNSSAA(context.Background(), ue)
	if got := testutil.ToFloat64(counter) - before; got != 0 {
		t.Fatalf("REJECT metric +%v after a failed send, want 0", got)
	}
	if ue.State != amfctx.GMMRegistered || clk.liveOf(NWDeregT3522Duration) != 0 {
		t.Fatalf("failed send must not change state / arm T3522: %v", ue.State)
	}
	if len(s.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)) != 0 {
		t.Fatal("de-registration reached the wire")
	}
	c := decodeCUC(t, s.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)[0])
	if len(c.RejectedNSSAI) != 1 {
		t.Fatalf("fallback CUC = %+v, want the rejected NSSAI", c)
	}

	// successful send: metric +1
	s2 := &flakySender{}
	h2, _, ue2 := handlerWith(t, true, s2)
	ue2.RejectedNSSAI = rejectedA()
	h2.deregisterForNSSAA(context.Background(), ue2)
	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Fatalf("REJECT metric +%v after a successful send, want 1", got)
	}
}

// T3522 (TS 24.501 §10.2 Table 10.2.2: 6 s; §5.5.2.3.5 a): four retransmissions,
// the fifth expiry aborts and de-registers the UE locally).
func TestDeregT3522RetransmitAndAbort(t *testing.T) {
	if NWDeregT3522Duration != 6*time.Second || NWDeregT3522MaxRetransmissions != 4 {
		t.Fatalf("T3522 = %v x%d, want 6 s x4", NWDeregT3522Duration, NWDeregT3522MaxRetransmissions)
	}
	s := &flakySender{}
	h, clk, ue := handlerWith(t, true, s)
	ue.SUPI = "" // no UDM/PCF legs
	if err := h.SendNetworkDeregistration(context.Background(), ue, 0, 1, true); err != nil {
		t.Fatal(err)
	}
	if clk.liveOf(NWDeregT3522Duration) != 1 || !ue.DeregTimerRunning() {
		t.Fatal("T3522 not started with the DEREGISTRATION REQUEST")
	}
	first := s.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)[0]
	for i := 1; i <= NWDeregT3522MaxRetransmissions; i++ {
		fire(ue, clk.last())
		d := s.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)
		if len(d) != 1+i || clk.liveOf(NWDeregT3522Duration) != 1 || ue.State != amfctx.GMMDeregisteredInitiated {
			t.Fatalf("expiry %d: %d requests, live=%d, state=%v", i, len(d), clk.liveOf(NWDeregT3522Duration), ue.State)
		}
		if string(d[i].body) != string(first.body) {
			t.Fatalf("retransmission %d differs from the first request", i)
		}
	}
	if s.releases != 0 {
		t.Fatal("released before the fifth expiry")
	}
	fire(ue, clk.last()) // fifth expiry
	if ue.State != amfctx.GMMDeregistered || !ue.PendingRemoval || s.releases != 1 {
		t.Fatalf("abort: state=%v pendingRemoval=%v releases=%d, want local de-registration + N2 release", ue.State, ue.PendingRemoval, s.releases)
	}
	if clk.liveOf(NWDeregT3522Duration) != 0 || ue.DeregTimerRunning() {
		t.Fatal("T3522 still running after the abort")
	}
	if n := len(s.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)); n != 1+NWDeregT3522MaxRetransmissions {
		t.Fatalf("%d requests sent in total, want %d", n, 1+NWDeregT3522MaxRetransmissions)
	}
}

// DEREGISTRATION ACCEPT stops T3522; a late callback is ignored; context removal,
// a UE-initiated de-registration and a state change also stop/neutralise it.
func TestDeregT3522Stopped(t *testing.T) {
	newUE := func(t *testing.T) (*Handler, *flakySender, *fakeClock, *amfctx.UEContext) {
		s := &flakySender{}
		h, clk, ue := handlerWith(t, true, s)
		ue.SUPI = "" // no UDM/PCF legs
		if err := h.SendNetworkDeregistration(context.Background(), ue, procedures.NSSAADeregCause5GMM, 1, false); err != nil {
			t.Fatal(err)
		}
		return h, s, clk, ue
	}
	t.Run("DEREGISTRATION ACCEPT", func(t *testing.T) {
		h, s, clk, ue := newUE(t)
		late := clk.last()
		if err := h.handleNWDeregistrationAccept(context.Background(), ue); err != nil {
			t.Fatal(err)
		}
		if clk.liveOf(NWDeregT3522Duration) != 0 || s.releases != 1 || ue.State != amfctx.GMMDeregistered {
			t.Fatalf("live=%d releases=%d state=%v", clk.liveOf(NWDeregT3522Duration), s.releases, ue.State)
		}
		fire(ue, late) // already fired: nothing to do
		if s.releases != 1 || len(s.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)) != 1 {
			t.Fatal("late T3522 callback acted")
		}
	})
	t.Run("context removal", func(t *testing.T) {
		h, _, clk, ue := newUE(t)
		h.reg.RemoveUEContext(context.Background(), ue)
		if clk.liveOf(NWDeregT3522Duration) != 0 {
			t.Fatal("Manager.Remove must stop T3522")
		}
	})
	t.Run("UE-initiated de-registration", func(t *testing.T) {
		h, _, clk, ue := newUE(t)
		msg := &nas.Message{Body: &nas.DeregistrationRequest{SwitchOff: true}}
		if err := h.handleDeregistration(context.Background(), ue, msg); err != nil {
			t.Fatal(err)
		}
		if clk.liveOf(NWDeregT3522Duration) != 0 {
			t.Fatal("UE-initiated de-registration must stop T3522")
		}
	})
	t.Run("expiry after the state moved on", func(t *testing.T) {
		_, s, clk, ue := newUE(t)
		ue.State = amfctx.GMMRegistered // e.g. a registration completed meanwhile
		fire(ue, clk.last())
		if s.releases != 0 || ue.State != amfctx.GMMRegistered || ue.DeregTimerRunning() {
			t.Fatal("T3522 expiry must not touch a UE that is no longer being de-registered")
		}
	})
}

// A failed retransmission is a lower-layer failure: the procedure is aborted.
func TestDeregT3522RetransmissionFailureAborts(t *testing.T) {
	s := &flakySender{failOn: map[int]bool{2: true}}
	h, clk, ue := handlerWith(t, true, s)
	ue.SUPI = ""
	if err := h.SendNetworkDeregistration(context.Background(), ue, 0, 1, false); err != nil {
		t.Fatal(err)
	}
	fire(ue, clk.last())
	if ue.State != amfctx.GMMDeregistered || s.releases != 1 {
		t.Fatalf("state=%v releases=%d", ue.State, s.releases)
	}
}

// rel17 (frozen): no T3522, legacy spare nibble 0x7 in the body.
func TestDeregRel17NoT3522LegacyBytes(t *testing.T) {
	s := &flakySender{}
	h, clk, ue := handlerWith(t, false, s)
	if err := h.SendNetworkDeregistration(context.Background(), ue, 0, 1, true); err != nil {
		t.Fatal(err)
	}
	if clk.count() != 0 || ue.DeregTimerRunning() {
		t.Fatalf("rel17 armed T3522 (%d timers)", clk.count())
	}
	d := s.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)
	if len(d) != 1 || d[0].body[0] != 0x75 { // spare nibble 0x7 | re-registration required 0x4 | 3GPP 0x1
		t.Fatalf("rel17 body = % x, want first octet 0x75", d[0].body)
	}
}

// rel19 on the same path: spare half octet zero, T3522 6 s.
func TestDeregRel19SpareZeroAndTimer(t *testing.T) {
	s := &flakySender{}
	h, clk, ue := handlerWith(t, true, s)
	if err := h.SendNetworkDeregistration(context.Background(), ue, 0, 1, true); err != nil {
		t.Fatal(err)
	}
	d := s.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)
	if d[0].body[0] != 0x05 || clk.last().d != 6*time.Second {
		t.Fatalf("rel19 body = % x timer = %v", d[0].body, clk.last().d)
	}
}
