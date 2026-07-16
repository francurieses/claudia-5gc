package nasmsg

import (
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func snssaiTransport(sst uint8, sd uint32) *nas.SNSSAITransport {
	return &nas.SNSSAITransport{SST: sst, SD: &sd}
}

// TestResolveSessionSNSSAI_AuthorisedReturnsSubscription checks that a slice in
// the Allowed NSSAI resolves to the *subscription* entry, so the operator's DNN
// for that slice is carried into PDU session setup rather than the UE's view.
func TestResolveSessionSNSSAI_AuthorisedReturnsSubscription(t *testing.T) {
	allowed := []amfctx.SNSSAISubscribed{
		{SST: 1, SD: "000001", DNN: "internet"},
		{SST: 1, SD: "001234", DNN: "gaming"},
	}
	got, ok := resolveSessionSNSSAI(snssaiTransport(1, 0x001234), allowed)
	if !ok {
		t.Fatal("authorised slice reported as not authorised")
	}
	if got.SST != 1 || got.SD != "001234" {
		t.Errorf("resolved slice: got %d/%s, want 1/001234", got.SST, got.SD)
	}
	if got.DNN != "gaming" {
		t.Errorf("subscription DNN not carried through: got %q, want %q", got.DNN, "gaming")
	}
}

// TestResolveSessionSNSSAI_UnauthorisedIsRejected is the regression guard for
// the silent-substitution bug: a UE asking for a slice outside its Allowed
// NSSAI used to have the request quietly moved to allowed[0] and established on
// the wrong slice. It must now be reported as unauthorised so the caller
// rejects. Ref: TS 23.501 §5.15.5.2.1
func TestResolveSessionSNSSAI_UnauthorisedIsRejected(t *testing.T) {
	allowed := []amfctx.SNSSAISubscribed{
		{SST: 1, SD: "000001", DNN: "internet"},
		{SST: 3, SD: "000001", DNN: "internet"},
	}
	got, ok := resolveSessionSNSSAI(snssaiTransport(1, 0x001234), allowed)
	if ok {
		t.Fatalf("unauthorised slice accepted, resolved to %d/%s", got.SST, got.SD)
	}
	if got.SST != 0 || got.SD != "" {
		t.Errorf("rejected slice must return a zero S-NSSAI, got %d/%s", got.SST, got.SD)
	}
}

// TestResolveSessionSNSSAI_SSTMatchSDMismatch guards the SD comparison: a
// matching SST alone must not authorise the session.
func TestResolveSessionSNSSAI_SSTMatchSDMismatch(t *testing.T) {
	allowed := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	if _, ok := resolveSessionSNSSAI(snssaiTransport(1, 0x000002), allowed); ok {
		t.Error("slice with matching SST but different SD was authorised")
	}
}

// TestResolveSessionSNSSAI_NoSliceRequested: the UE may omit the S-NSSAI, in
// which case the AMF selects the first allowed slice. That is a normal
// selection, not an authorisation failure.
func TestResolveSessionSNSSAI_NoSliceRequested(t *testing.T) {
	allowed := []amfctx.SNSSAISubscribed{
		{SST: 2, SD: "000001"},
		{SST: 1, SD: "000001"},
	}
	got, ok := resolveSessionSNSSAI(nil, allowed)
	if !ok {
		t.Fatal("UE omitting the S-NSSAI must not be rejected")
	}
	if got.SST != 2 || got.SD != "000001" {
		t.Errorf("expected first allowed slice 2/000001, got %d/%s", got.SST, got.SD)
	}
}

// TestResolveSessionSNSSAI_NoAllowedNSSAI: with no Allowed NSSAI on the context
// there is nothing to authorise against, so the request proceeds rather than
// being blocked on missing state.
func TestResolveSessionSNSSAI_NoAllowedNSSAI(t *testing.T) {
	got, ok := resolveSessionSNSSAI(snssaiTransport(1, 0x001234), nil)
	if !ok {
		t.Fatal("request rejected when no Allowed NSSAI is known")
	}
	if got.SST != 1 || got.SD != "001234" {
		t.Errorf("requested slice not honoured: got %d/%s, want 1/001234", got.SST, got.SD)
	}
}

func TestFormatAllowedNSSAI(t *testing.T) {
	got := formatAllowedNSSAI([]amfctx.SNSSAISubscribed{
		{SST: 1, SD: "000001"},
		{SST: 3, SD: "000001"},
	})
	if want := "1/000001,3/000001"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := formatAllowedNSSAI(nil); got != "" {
		t.Errorf("empty Allowed NSSAI: got %q, want empty", got)
	}
}

func TestRequestedSNSSAIForLog(t *testing.T) {
	sst, sd := requestedSNSSAIForLog(snssaiTransport(1, 0x001234))
	if sst != 1 || sd != "001234" {
		t.Errorf("got %d/%s, want 1/001234", sst, sd)
	}
	if sst, sd := requestedSNSSAIForLog(nil); sst != 0 || sd != "" {
		t.Errorf("nil transport: got %d/%s, want 0/empty", sst, sd)
	}
}
