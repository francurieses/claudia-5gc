package ngap

// paging_test.go — unit tests for the NGAP Paging codec.
// Ref: 3GPP TS 38.413 §9.2.8, TS 23.502 §4.2.3.3

import (
	"testing"

	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// TestBuildPaging verifies that a Paging PDU encodes to a valid NGAP message that
// the free5GC decoder can re-parse, with the 5G-S-TMSI and TAIListForPaging IEs.
func TestBuildPaging(t *testing.T) {
	const setID uint16 = 1
	const amfID byte = 1
	const tmsi uint32 = 0x11223344
	plmn := plmnFromMCCMNC("001", "01")

	pdu := BuildPaging(setID, amfID, tmsi, []TAIForPaging{{PLMN: plmn, TAC: 0x000001}})
	if len(pdu) == 0 {
		t.Fatal("BuildPaging returned nil/empty PDU")
	}

	decoded, err := libngap.Decoder(pdu)
	if err != nil {
		t.Fatalf("re-decode failed: %v", err)
	}
	if decoded.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatalf("expected InitiatingMessage, got %d", decoded.Present)
	}
	im := decoded.InitiatingMessage
	if im.ProcedureCode.Value != ngapType.ProcedureCodePaging {
		t.Fatalf("expected ProcedureCodePaging (24), got %d", im.ProcedureCode.Value)
	}
	if im.Value.Paging == nil {
		t.Fatal("Paging is nil in decoded PDU")
	}

	var sawTMSI, sawTAI bool
	for _, ie := range im.Value.Paging.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.PagingIEsPresentUEPagingIdentity:
			id := ie.Value.UEPagingIdentity
			if id == nil || id.FiveGSTMSI == nil {
				t.Fatal("UEPagingIdentity/FiveGSTMSI missing")
			}
			got := id.FiveGSTMSI.FiveGTMSI.Value
			if len(got) != 4 || got[0] != 0x11 || got[1] != 0x22 || got[2] != 0x33 || got[3] != 0x44 {
				t.Errorf("5G-TMSI = %x, want 11223344", got)
			}
			sawTMSI = true
		case ngapType.PagingIEsPresentTAIListForPaging:
			lst := ie.Value.TAIListForPaging
			if lst == nil || len(lst.List) != 1 {
				t.Fatalf("TAIListForPaging = %+v, want 1 item", lst)
			}
			tac := lst.List[0].TAI.TAC.Value
			if len(tac) != 3 || tac[2] != 0x01 {
				t.Errorf("TAC = %x, want 000001", tac)
			}
			sawTAI = true
		}
	}
	if !sawTMSI || !sawTAI {
		t.Errorf("missing IEs: sawTMSI=%v sawTAI=%v", sawTMSI, sawTAI)
	}
}
