package nasmsg

// nssaa_dereg_test.go - AMF-022: rel19 network-initiated de-registration with the
// Rejected NSSAI when NSSAA failed or was revoked for every S-NSSAI and no default
// S-NSSAI can be allowed (EAP-Failure, T3575 abort, re-authentication failure,
// revocation), the CONFIGURATION UPDATE COMMAND otherwise, rel17 frozen.
// Ref: TS 23.502 §4.2.9.2 step 19b, §4.2.9.3, §4.2.9.4;
// TS 24.501 §4.6.2.4 c), §5.5.2.3.1, Table 8.2.14.1.1

import (
	"context"
	"fmt"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// seqAAA answers the successive Authenticate calls with results in order.
type seqAAA struct{ results []*procedures.NSSAAAuthResult }

func (s *seqAAA) Authenticate(context.Context, string, string, uint8, string, []byte) (*procedures.NSSAAAuthResult, error) {
	r := s.results[0]
	s.results = s.results[1:]
	return r, nil
}

func eapFailure() *procedures.NSSAAAuthResult {
	return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultFailure, EAPPayload: eap.BuildFailure(1)}
}

func eapSuccess() *procedures.NSSAAAuthResult {
	return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}
}

// onlyDereg asserts exactly one DEREGISTRATION REQUEST (UE terminated), no CUC,
// and returns the decoded body.
func onlyDereg(t *testing.T, sender *recSender, ue *amfctx.UEContext) *nas.DeregistrationRequestNW {
	t.Helper()
	if n := len(sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)); n != 0 {
		t.Fatalf("%d CUCs, want none (de-registration instead)", n)
	}
	d := sender.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)
	if len(d) != 1 {
		t.Fatalf("%d DEREGISTRATION REQUESTs, want 1", len(d))
	}
	req, err := nas.DecodeDeregistrationRequestNW(d[0].body)
	if err != nil {
		t.Fatal(err)
	}
	if ue.State != amfctx.GMMDeregisteredInitiated {
		t.Fatalf("UE state = %v, want DEREGISTERED-INITIATED", ue.State)
	}
	return req
}

// assertNSSAADeregBody checks type, cause and the Rejected NSSAI of the request.
func assertNSSAADeregBody(t *testing.T, req *nas.DeregistrationRequestNW, rejected ...nas.SNSSAI) {
	t.Helper()
	if req.ReregistrationRequired {
		t.Error("de-registration type must be \"re-registration not required\"")
	}
	if req.AccessType != 1 {
		t.Errorf("access type = %d, want 1 (3GPP)", req.AccessType)
	}
	if req.Cause5GMM != 62 {
		t.Errorf("5GMM cause = %d, want #62 (No network slices available)", req.Cause5GMM)
	}
	if len(req.RejectedNSSAI) != len(rejected) {
		t.Fatalf("Rejected NSSAI = %+v, want %d entries", req.RejectedNSSAI, len(rejected))
	}
	for i, r := range req.RejectedNSSAI {
		want := nas.RejectedSNSSAI{Cause: nas.RejectedCauseNSSAAFailedOrRevoked, SNSSAI: rejected[i]}
		if r != want {
			t.Errorf("Rejected NSSAI[%d] = %+v, want %+v", i, r, want)
		}
	}
}

// All slices fail by EAP-Failure: RESULT per slice, then ONE DEREGISTRATION
// REQUEST with both slices in the Rejected NSSAI, no CUC.
func TestNSSAADeregAllSlicesFailed(t *testing.T) {
	h, sender, _, ue := nssaaTestHandler(t, true, &seqAAA{results: []*procedures.NSSAAAuthResult{eapFailure(), eapFailure()}})
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003"), sliceN(2, "000004")}
	ue.SubscribedNSSAI = append([]amfctx.SNSSAISubscribed(nil), ue.PendingNSSAA...)
	startOnQueue(h, ue)
	if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
		t.Fatal(err)
	}
	// First slice resolved, second still queued: no de-registration yet.
	if len(sender.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)) != 0 {
		t.Fatal("de-registered before the queue drained")
	}
	if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 2, 4)); err != nil {
		t.Fatal(err)
	}
	req := onlyDereg(t, sender, ue)
	assertNSSAADeregBody(t, req, nas.SNSSAI{SST: 1, SD: 3}, nas.SNSSAI{SST: 2, SD: 4})
}

// T3575 fifth expiry completes the slice as a failure -> de-registration.
func TestNSSAADeregT3575Abort(t *testing.T) {
	h, sender, clk, ue := nssaaTestHandler(t, true, &nssaaScript{})
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	ue.SubscribedNSSAI = append([]amfctx.SNSSAISubscribed(nil), ue.PendingNSSAA...)
	startOnQueue(h, ue)
	for i := 0; i <= NSSAAT3575MaxRetransmissions; i++ {
		fire(ue, clk.last())
	}
	req := onlyDereg(t, sender, ue)
	assertNSSAADeregBody(t, req, nas.SNSSAI{SST: 1, SD: 3})
	if clk.live() != 0 {
		t.Fatal("T3575 must be stopped")
	}
}

// Re-authentication (§4.2.9.3) of the only allowed slice fails -> de-registration.
func TestNSSAADeregReauthFailure(t *testing.T) {
	h, sender, _, ue := nssaaTestHandler(t, true, &seqAAA{results: []*procedures.NSSAAAuthResult{eapFailure()}})
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	ue.SubscribedNSSAI = append([]amfctx.SNSSAISubscribed(nil), ue.AllowedNSSAI...)
	if !h.ReauthNSSAASlice(context.Background(), ue, 1, "000003") {
		t.Fatal("re-auth not queued")
	}
	if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, 1, 3)); err != nil {
		t.Fatal(err)
	}
	assertNSSAADeregBody(t, onlyDereg(t, sender, ue), nas.SNSSAI{SST: 1, SD: 3})
	if len(ue.AllowedNSSAI) != 0 {
		t.Fatalf("Allowed NSSAI = %+v, want empty", ue.AllowedNSSAI)
	}
}

// Revocation (§4.2.9.4): the last allowed slice -> de-registration; one of two ->
// CUC (TS 24.501 §4.6.2.4 a).
func TestNSSAADeregRevocation(t *testing.T) {
	t.Run("last slice", func(t *testing.T) {
		h, sender, _, ue := nssaaTestHandler(t, true, &nssaaScript{})
		ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
		ue.SubscribedNSSAI = append([]amfctx.SNSSAISubscribed(nil), ue.AllowedNSSAI...)
		if !h.RevokeNSSAASlice(context.Background(), ue, 1, "000003") {
			t.Fatal("not revoked")
		}
		assertNSSAADeregBody(t, onlyDereg(t, sender, ue), nas.SNSSAI{SST: 1, SD: 3})
	})
	t.Run("one of two", func(t *testing.T) {
		h, sender, _, ue := nssaaTestHandler(t, true, &nssaaScript{})
		ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003"), sliceN(2, "000004")}
		ue.SubscribedNSSAI = append([]amfctx.SNSSAISubscribed(nil), ue.AllowedNSSAI...)
		if !h.RevokeNSSAASlice(context.Background(), ue, 1, "000003") {
			t.Fatal("not revoked")
		}
		if len(sender.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW)) != 0 ||
			len(sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)) != 1 {
			t.Fatal("want one CUC and no de-registration")
		}
		if ue.State != amfctx.GMMRegistered {
			t.Fatalf("state = %v", ue.State)
		}
	})
}

// The decision table: everything that must still end in a CUC.
func TestNSSAADeregDecision(t *testing.T) {
	plain := amfctx.SNSSAISubscribed{SST: 1, SD: "000009"}
	tests := []struct {
		name      string
		spec      bool
		first     *procedures.NSSAAAuthResult
		next      *procedures.NSSAAAuthResult
		pending   []amfctx.SNSSAISubscribed
		subscribe []amfctx.SNSSAISubscribed
		emergency bool
		wantDereg bool
		wantCUC   int
	}{
		{name: "all failed -> de-registration", spec: true, first: eapFailure(),
			pending: []amfctx.SNSSAISubscribed{sliceN(1, "000003")}, subscribe: []amfctx.SNSSAISubscribed{sliceN(1, "000003")},
			wantDereg: true},
		{name: "one success, one failure -> CUC", spec: true, first: eapFailure(), next: eapSuccess(),
			pending:   []amfctx.SNSSAISubscribed{sliceN(1, "000003"), sliceN(2, "000004")},
			subscribe: []amfctx.SNSSAISubscribed{sliceN(1, "000003"), sliceN(2, "000004")},
			wantCUC:   1},
		{name: "non-NSSAA default can be allowed -> CUC", spec: true, first: eapFailure(),
			pending: []amfctx.SNSSAISubscribed{sliceN(1, "000003")}, subscribe: []amfctx.SNSSAISubscribed{sliceN(1, "000003"), plain},
			wantCUC: 1},
		{name: "emergency PDU session -> CUC", spec: true, first: eapFailure(), emergency: true,
			pending: []amfctx.SNSSAISubscribed{sliceN(1, "000003")}, subscribe: []amfctx.SNSSAISubscribed{sliceN(1, "000003")},
			wantCUC: 1},
		{name: "rel17 unchanged: no CUC, no de-registration", spec: false, first: eapFailure(),
			pending: []amfctx.SNSSAISubscribed{sliceN(1, "000003")}, subscribe: []amfctx.SNSSAISubscribed{sliceN(1, "000003")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, sender, _, ue := nssaaTestHandler(t, tc.spec, &seqAAA{results: []*procedures.NSSAAAuthResult{tc.first, tc.next}})
			ue.PendingNSSAA = tc.pending
			ue.SubscribedNSSAI = tc.subscribe
			ue.EmergencyPDUSession = tc.emergency
			startOnQueue(h, ue)
			for _, s := range tc.pending {
				if err := h.handleNSSAAComplete(context.Background(), ue, completeMsg(ue, s.SST, nas.SDFromString(s.SD))); err != nil {
					t.Fatal(err)
				}
			}
			gotDereg := len(sender.ofType(t, ue, nas.MsgTypeDeregistrationRequestNW))
			if (gotDereg == 1) != tc.wantDereg || gotDereg > 1 {
				t.Fatalf("%d de-registrations, want dereg=%v", gotDereg, tc.wantDereg)
			}
			if n := len(sender.ofType(t, ue, nas.MsgTypeConfigurationUpdateCommand)); n != tc.wantCUC {
				t.Fatalf("%d CUCs, want %d", n, tc.wantCUC)
			}
			if tc.wantDereg == (ue.State == amfctx.GMMRegistered) {
				t.Fatalf("state = %v", ue.State)
			}
		})
	}
}

// A PENDING slice (NSSAAF outage) is not a failure: it keeps the registration.
func TestNSSAADeregNotWithPendingSlice(t *testing.T) {
	h, _, _, ue := nssaaTestHandler(t, true, &nssaaScript{})
	ue.RejectedNSSAI = []amfctx.SNSSAISubscribed{sliceN(1, "000003")}
	ue.NSSAAPendingStatus = []amfctx.SNSSAISubscribed{sliceN(2, "000004")}
	if dereg, _ := h.reg.NSSAADeregistrationRequired(ue); dereg {
		t.Fatal("PENDING slice must prevent de-registration")
	}
}

// The Rejected NSSAI IE carries at most 8 entries (TS 24.501 §9.11.3.46).
func TestNSSAADeregRejectedNSSAICap(t *testing.T) {
	h, sender, _, ue := nssaaTestHandler(t, true, &nssaaScript{})
	for i := 1; i <= nas.MaxRejectedSNSSAIs+2; i++ {
		ue.RejectedNSSAI = append(ue.RejectedNSSAI, sliceN(1, fmt.Sprintf("%06x", i)))
	}
	h.deregisterForNSSAA(context.Background(), ue)
	req := onlyDereg(t, sender, ue)
	if len(req.RejectedNSSAI) != nas.MaxRejectedSNSSAIs {
		t.Fatalf("%d Rejected NSSAI entries, want %d", len(req.RejectedNSSAI), nas.MaxRejectedSNSSAIs)
	}
}
