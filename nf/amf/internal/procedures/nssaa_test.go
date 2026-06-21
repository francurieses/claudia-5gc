package procedures

import (
	"context"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/nas"
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

func hasSlice(list []amfctx.SNSSAISubscribed, sst uint8, sd string) bool {
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
	if len(ue.AllowedNSSAI) != 1 || !hasSlice(ue.AllowedNSSAI, 1, "000001") {
		t.Fatalf("allowed = %+v, want only 1-000001", ue.AllowedNSSAI)
	}
	if len(ue.PendingNSSAA) != 1 || !hasSlice(ue.PendingNSSAA, 1, "000003") {
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
	if !hasSlice(ue.AllowedNSSAI, 1, "000003") {
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
	if hasSlice(ue.AllowedNSSAI, 1, "000003") {
		t.Fatal("rejected slice must not be in Allowed NSSAI")
	}
	if !hasSlice(ue.RejectedNSSAI, 1, "000003") {
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
	if hasSlice(ue.AllowedNSSAI, 1, "000003") {
		t.Fatal("revoked slice must be removed from Allowed NSSAI")
	}
	if !hasSlice(ue.RejectedNSSAI, 1, "000003") {
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
