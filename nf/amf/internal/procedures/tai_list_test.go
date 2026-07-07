package procedures

// Tests for the Registration Accept TAI list (registration area).
// Ref: TS 24.501 §9.11.3.9, §5.5.1.2.4

import (
	"bytes"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestBuildTAIList_ConfiguredTACs(t *testing.T) {
	h := &RegistrationHandler{plmnMCC: "001", plmnMNC: "01"}
	h.WithServedTACs([]uint32{1, 2})
	ue := &amfctx.UEContext{TAI: amfctx.TAI{MCC: "001", MNC: "01", TAC: 1}}

	got := h.buildTAIList(ue)
	want := nas.EncodeTAIList("001", "01", []uint32{1, 2})
	if !bytes.Equal(got, want) {
		t.Fatalf("buildTAIList: got %x, want %x", got, want)
	}
}

func TestBuildTAIList_AlwaysIncludesCurrentTAC(t *testing.T) {
	// The registration area must contain the UE's current TAI even when the
	// operator config does not list its TAC — otherwise the UE cancels
	// Service Request from CM-IDLE ("current TAI is not in the TAI list").
	h := &RegistrationHandler{plmnMCC: "001", plmnMNC: "01"}
	h.WithServedTACs([]uint32{7})
	ue := &amfctx.UEContext{TAI: amfctx.TAI{MCC: "001", MNC: "01", TAC: 3}}

	got := h.buildTAIList(ue)
	want := nas.EncodeTAIList("001", "01", []uint32{7, 3})
	if !bytes.Equal(got, want) {
		t.Fatalf("buildTAIList: got %x, want %x", got, want)
	}
}

func TestBuildTAIList_NoConfigFallsBackToCurrentTAI(t *testing.T) {
	h := &RegistrationHandler{plmnMCC: "001", plmnMNC: "01"}
	ue := &amfctx.UEContext{TAI: amfctx.TAI{MCC: "001", MNC: "01", TAC: 1}}

	got := h.buildTAIList(ue)
	want := nas.EncodeTAIList("001", "01", []uint32{1})
	if !bytes.Equal(got, want) {
		t.Fatalf("buildTAIList: got %x, want %x", got, want)
	}
}
