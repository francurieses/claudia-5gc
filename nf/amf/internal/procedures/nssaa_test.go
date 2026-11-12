package procedures

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeNSSAA returns a fixed authResult and echoes a terminal EAP packet.
type fakeNSSAA struct {
	result string
	calls  int
}

func (f *fakeNSSAA) Authenticate(_ context.Context, _, _ string, _ uint8, _ string, _ []byte) (*NSSAAAuthResult, error) {
	f.calls++
	if f.result == NSSAAResultSuccess {
		return &NSSAAAuthResult{AuthResult: NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}, nil
	}
	return &NSSAAAuthResult{AuthResult: NSSAAResultFailure, EAPPayload: eap.BuildFailure(1)}, nil
}

func testHandler(client NSSAAClient) *RegistrationHandler {
	return &RegistrationHandler{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		nssaa:  client,
	}
}

func hasSlice(list []amfctx.SNSSAISubscribed, sd string) bool {
	const sst = 1
	for _, s := range list {
		if s.SST == sst && s.SD == sd {
			return true
		}
	}
	return false
}

func TestSplitPendingNSSAA(t *testing.T) {
	h := testHandler(&fakeNSSAA{result: NSSAAResultSuccess})
	ue := &amfctx.UEContext{SUPI: "imsi-1"}
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{
		{SST: 1, SD: "000001"},
		{SST: 1, SD: "000003", SubjectToNSSAA: true},
	}
	h.SplitPendingNSSAA(ue)
	if len(ue.AllowedNSSAI) != 1 || !hasSlice(ue.AllowedNSSAI, "000001") {
		t.Fatalf("allowed = %+v, want only 1-000001", ue.AllowedNSSAI)
	}
	if len(ue.PendingNSSAA) != 1 || !hasSlice(ue.PendingNSSAA, "000003") {
		t.Fatalf("pending = %+v, want 1-000003", ue.PendingNSSAA)
	}
}

func TestSplitPendingNSSAA_NoClient_NoRegression(t *testing.T) {
	h := testHandler(nil) // NSSAA unconfigured
	ue := &amfctx.UEContext{SUPI: "imsi-1"}
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000003", SubjectToNSSAA: true}}
	h.SplitPendingNSSAA(ue)
	if len(ue.AllowedNSSAI) != 1 || len(ue.PendingNSSAA) != 0 {
		t.Fatal("with no NSSAA client the Allowed NSSAI must be unchanged")
	}
}

func TestNSSAASuccessFlow(t *testing.T) {
	fake := &fakeNSSAA{result: NSSAAResultSuccess}
	h := testHandler(fake)
	ue := &amfctx.UEContext{SUPI: "imsi-1"}
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000003"}}

	cmd, started := h.StartNSSAA(context.Background(), ue)
	if !started || cmd == nil {
		t.Fatal("StartNSSAA should have started")
	}
	if c, _ := eap.Code(cmd.EAPMessage); c != eap.CodeRequest {
		t.Fatalf("COMMAND EAP code = %d, want Request", c)
	}
	if ue.NSSAAInProgress == nil {
		t.Fatal("slice should be in progress")
	}

	complete := &nas.NSSAAuthComplete{
		SNSSAI:     nas.SNSSAI{SST: 1, SD: 0x000003},
		EAPMessage: eap.BuildIdentityResponse(ue.NSSAAEAPID, "alice@nssaa"),
	}
	out, err := h.ProcessNSSAAComplete(context.Background(), ue, complete)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Authorized || !out.AllowedChanged {
		t.Fatalf("expected authorized+changed, got %+v", out)
	}
	if c, _ := eap.Code(out.Result.EAPMessage); c != eap.CodeSuccess {
		t.Fatalf("RESULT EAP code = %d, want Success", c)
	}
	if !hasSlice(ue.AllowedNSSAI, "000003") {
		t.Fatal("slice should be in Allowed NSSAI")
	}
	if out.NextCommand != nil || len(ue.PendingNSSAA) != 0 {
		t.Fatal("queue should be drained")
	}
	if ue.NSSAAInProgress != nil {
		t.Fatal("in-progress should be cleared")
	}
}

func TestNSSAAFailureFlow(t *testing.T) {
	h := testHandler(&fakeNSSAA{result: NSSAAResultFailure})
	ue := &amfctx.UEContext{SUPI: "imsi-1"}
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000003"}}
	h.StartNSSAA(context.Background(), ue)

	complete := &nas.NSSAAuthComplete{
		SNSSAI:     nas.SNSSAI{SST: 1, SD: 0x000003},
		EAPMessage: eap.BuildIdentityResponse(ue.NSSAAEAPID, "mallory@reject"),
	}
	out, err := h.ProcessNSSAAComplete(context.Background(), ue, complete)
	if err != nil {
		t.Fatal(err)
	}
	if out.Authorized || out.AllowedChanged {
		t.Fatalf("expected rejected, got %+v", out)
	}
	if c, _ := eap.Code(out.Result.EAPMessage); c != eap.CodeFailure {
		t.Fatalf("RESULT EAP code = %d, want Failure", c)
	}
	if hasSlice(ue.AllowedNSSAI, "000003") {
		t.Fatal("rejected slice must not be in Allowed NSSAI")
	}
	if !hasSlice(ue.RejectedNSSAI, "000003") {
		t.Fatal("slice should be in Rejected NSSAI")
	}
}

func TestNSSAAMultiSliceQueue(t *testing.T) {
	h := testHandler(&fakeNSSAA{result: NSSAAResultSuccess})
	ue := &amfctx.UEContext{SUPI: "imsi-1"}
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{
		{SST: 1, SD: "000003"},
		{SST: 1, SD: "000004"},
	}
	h.StartNSSAA(context.Background(), ue)

	// Resolve the first slice → expect a NextCommand for the second.
	out, _ := h.ProcessNSSAAComplete(context.Background(), ue, &nas.NSSAAuthComplete{
		SNSSAI:     nas.SNSSAI{SST: 1, SD: 0x000003},
		EAPMessage: eap.BuildIdentityResponse(ue.NSSAAEAPID, "a@x"),
	})
	if out.NextCommand == nil {
		t.Fatal("expected NextCommand for the second slice")
	}
	if ue.NSSAAInProgress == nil || ue.NSSAAInProgress.SD != "000004" {
		t.Fatalf("second slice should be in progress, got %+v", ue.NSSAAInProgress)
	}
}

func TestRevokeNSSAA(t *testing.T) {
	h := testHandler(&fakeNSSAA{result: NSSAAResultSuccess})
	ue := &amfctx.UEContext{SUPI: "imsi-1"}
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{
		{SST: 1, SD: "000001"},
		{SST: 1, SD: "000003"},
	}
	if !h.RevokeNSSAA(ue, 1, "000003") {
		t.Fatal("revoke should report a change")
	}
	if hasSlice(ue.AllowedNSSAI, "000003") {
		t.Fatal("revoked slice must be removed from Allowed NSSAI")
	}
	if !hasSlice(ue.RejectedNSSAI, "000003") {
		t.Fatal("revoked slice should be in Rejected NSSAI")
	}
	if h.RevokeNSSAA(ue, 1, "000099") {
		t.Fatal("revoking an unknown slice should report no change")
	}
}

func TestProcessNSSAAComplete_MismatchedSlice(t *testing.T) {
	h := testHandler(&fakeNSSAA{result: NSSAAResultSuccess})
	ue := &amfctx.UEContext{SUPI: "imsi-1"}
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000003"}}
	h.StartNSSAA(context.Background(), ue)

	_, err := h.ProcessNSSAAComplete(context.Background(), ue, &nas.NSSAAuthComplete{
		SNSSAI:     nas.SNSSAI{SST: 2, SD: 0x000009},
		EAPMessage: eap.BuildIdentityResponse(1, "x@y"),
	})
	if err == nil {
		t.Fatal("expected error on mismatched S-NSSAI")
	}
}

// gpsiRecorder records the GPSI passed to the client and answers err / success.
type gpsiRecorder struct {
	gpsi  string
	calls int
	err   error
}

func (g *gpsiRecorder) Authenticate(_ context.Context, _, gpsi string, _ uint8, _ string, _ []byte) (*NSSAAAuthResult, error) {
	g.calls++
	g.gpsi = gpsi
	if g.err != nil {
		return nil, g.err
	}
	return &NSSAAAuthResult{AuthResult: NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}, nil
}

func startedUE(t *testing.T, h *RegistrationHandler, gpsi string) (*amfctx.UEContext, *nas.NSSAAuthComplete) {
	t.Helper()
	ue := &amfctx.UEContext{SUPI: "imsi-1", GPSI: gpsi}
	ue.PendingNSSAA = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000003"}}
	h.StartNSSAA(context.Background(), ue)
	return ue, &nas.NSSAAuthComplete{
		SNSSAI:     nas.SNSSAI{SST: 1, SD: 0x000003},
		EAPMessage: eap.BuildIdentityResponse(ue.NSSAAEAPID, "alice@nssaa"),
	}
}

func TestNSSAAGPSISource(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec bool
		want string
	}{
		{"rel17 keeps gpsi = SUPI", false, "imsi-1"},
		{"rel19 passes the real GPSI", true, "msisdn-12025550100"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &gpsiRecorder{}
			h := testHandler(rec)
			h.WithNSSAASpecLiteral(tc.spec)
			ue, complete := startedUE(t, h, "msisdn-12025550100")
			if _, err := h.ProcessNSSAAComplete(context.Background(), ue, complete); err != nil {
				t.Fatal(err)
			}
			if rec.gpsi != tc.want {
				t.Fatalf("gpsi = %q, want %q", rec.gpsi, tc.want)
			}
		})
	}
}

// rel19: a non-authentication failure keeps the slice PENDING (not allowed, not
// rejected, no RESULT); rel17 still rejects with cause #3.
func TestNSSAAPendingOnNonAuthFailure(t *testing.T) {
	cases := []struct {
		name   string
		spec   bool
		gpsi   string
		err    error
		wantCl int
	}{
		{"rel19 transport error", true, "msisdn-1", errors.New("amf: nssaa create: dial"), 1},
		{"rel19 no GPSI (client not called)", true, "", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &gpsiRecorder{err: tc.err}
			if tc.err == nil {
				rec.err = errors.New("must not be called")
			}
			h := testHandler(rec)
			h.WithNSSAASpecLiteral(tc.spec)
			ue, complete := startedUE(t, h, tc.gpsi)
			out, err := h.ProcessNSSAAComplete(context.Background(), ue, complete)
			if err != nil {
				t.Fatal(err)
			}
			if rec.calls != tc.wantCl {
				t.Fatalf("client calls = %d, want %d", rec.calls, tc.wantCl)
			}
			if out.Result != nil || out.Authorized || out.AllowedChanged {
				t.Fatalf("outcome %+v, want no result", out)
			}
			if hasSlice(ue.AllowedNSSAI, "000003") || hasSlice(ue.RejectedNSSAI, "000003") {
				t.Fatal("PENDING slice must be neither allowed nor rejected")
			}
			if !hasSlice(ue.NSSAAPendingStatus, "000003") || ue.NSSAAInProgress != nil || len(ue.PendingNSSAA) != 0 {
				t.Fatalf("pending state wrong: %+v", ue)
			}
		})
	}
	// rel17: transport error is a reject (unchanged).
	h := testHandler(&gpsiRecorder{err: errors.New("down")})
	ue, complete := startedUE(t, h, "msisdn-1")
	out, err := h.ProcessNSSAAComplete(context.Background(), ue, complete)
	if err != nil || out.Result == nil || out.Authorized || !hasSlice(ue.RejectedNSSAI, "000003") {
		t.Fatalf("rel17 transport error: out=%+v err=%v", out, err)
	}
	if c, _ := eap.Code(out.Result.EAPMessage); c != eap.CodeFailure {
		t.Fatalf("rel17 RESULT EAP code %d, want Failure", c)
	}
}

// rel19: a PENDING outcome (non-authentication failure) is counted as FAILURE
// in fivegc_procedure_total{nf="AMF",procedure="NSSAA"}; an AAA-S rejection of
// the slice (rel17 transport error path) is counted as REJECT.
func TestNSSAAProcedureTotal(t *testing.T) {
	cnt := func(res string) float64 {
		return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues(nfName, "NSSAA", res))
	}
	fail0, rej0 := cnt("FAILURE"), cnt("REJECT")

	h := testHandler(&gpsiRecorder{err: errors.New("down")})
	h.WithNSSAASpecLiteral(true)
	ue, complete := startedUE(t, h, "msisdn-1")
	if _, err := h.ProcessNSSAAComplete(context.Background(), ue, complete); err != nil {
		t.Fatal(err)
	}
	if d := cnt("FAILURE") - fail0; d != 1 {
		t.Errorf("FAILURE delta = %v, want 1 (PENDING)", d)
	}

	h = testHandler(&gpsiRecorder{err: errors.New("down")})
	ue, complete = startedUE(t, h, "msisdn-1")
	if _, err := h.ProcessNSSAAComplete(context.Background(), ue, complete); err != nil {
		t.Fatal(err)
	}
	if d := cnt("REJECT") - rej0; d != 1 {
		t.Errorf("REJECT delta = %v, want 1", d)
	}
	if d := cnt("PENDING"); d != 0 {
		t.Errorf("no PENDING label expected, got %v", d)
	}
}
