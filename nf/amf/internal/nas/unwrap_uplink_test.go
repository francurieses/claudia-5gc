package nasmsg

import (
	"bytes"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// TestUnwrapUplinkPendingSMCUsesPreviousWithoutSwap: while an SMC is outstanding a
// non-new-SC message is verified against the previous context, whose COUNT
// advances, and ue.SecurityCtx (the unconfirmed one) is never modified or swapped.
func TestUnwrapUplinkPendingSMCUsesPreviousWithoutSwap(t *testing.T) {
	h := newTestHandler(&fakeSender{})
	ue := newTestUE(t) // confirmed context, UplinkCount 0
	pdu := buildULSecuredPDU(t, ue, nas.MsgTypeSecurityModeReject, []byte{0x00})
	ue.BeginSecurityCtxChange()
	ue.SecurityCtx = amfctx.SecurityContext{Active: true, IntegrityAlgID: 2, CipheringAlgID: 2,
		KNASint: bytes.Repeat([]byte{0x33}, 16), KNASenc: bytes.Repeat([]byte{0x44}, 16)}
	newCtx := ue.SecurityCtx
	ue.SetRegStage(amfctx.RegStageSMC)

	out, err := h.unwrapUplink(ue, pdu, nas.SecurityHeaderIntegrityProtectedAndCiphered)
	if err != nil || len(out) < 7 || out[7] != nas.PDMobilityManagement {
		t.Fatalf("out=%x err=%v", out, err)
	}
	if ue.SecurityCtx.UplinkCount != 0 || !bytes.Equal(ue.SecurityCtx.KNASint, newCtx.KNASint) {
		t.Fatalf("unconfirmed context touched: %+v", ue.SecurityCtx)
	}
	if prev := ue.PreviousSecurityCtx(); prev == nil || prev.UplinkCount != 1 {
		t.Fatalf("previous context COUNT not advanced: %+v", prev)
	}
	// A rollback after the unwrap restores the previous context with the advanced COUNT.
	if p, r := ue.RollbackSecurityCtxChange(); !p || !r || ue.SecurityCtx.UplinkCount != 1 {
		t.Fatalf("rollback p=%v r=%v count=%d", p, r, ue.SecurityCtx.UplinkCount)
	}
}
