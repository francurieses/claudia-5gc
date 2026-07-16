package ngap

// initial_context_setup_test.go — codec round-trip tests for InitialContextSetupRequest.
// Ref: TS 38.413 §8.3.1, §9.3.1.27 (IndexToRFSP)

import (
	"testing"

	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

var testSecKey [32]byte

func buildTestICSR(rfsp int) []byte {
	return buildTestICSRWithSessions(rfsp, nil)
}

func buildTestICSRWithSessions(rfsp int, pduSessions []PDUSessionSetupItemCxtReq) []byte {
	return BuildInitialContextSetupRequest(
		1, 2,
		[]byte{0x01, 0x02},
		testSecKey,
		0x8000, 0x8000,
		"001", "01",
		0x80, 1, 0x01,
		[]amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}},
		0, 0, // subscribed UE-AMBR absent → builder falls back to 1 Gbps
		rfsp,
		pduSessions,
	)
}

func TestBuildInitialContextSetupRequest_WithRFSP(t *testing.T) {
	raw := buildTestICSR(1)
	if raw == nil {
		t.Fatal("encoder returned nil")
	}

	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("NGAP decode failed: %v", err)
	}
	if pdu.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatal("expected InitiatingMessage")
	}
	req := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	if req == nil {
		t.Fatal("InitialContextSetupRequest is nil")
	}

	var foundRFSP bool
	for _, ie := range req.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDIndexToRFSP {
			foundRFSP = true
			rfspVal := ie.Value.IndexToRFSP
			if rfspVal == nil {
				t.Fatal("IndexToRFSP IE value is nil")
			}
			if rfspVal.Value != 1 {
				t.Fatalf("expected RFSP=1, got %d", rfspVal.Value)
			}
		}
	}
	if !foundRFSP {
		t.Fatal("IndexToRFSP IE (id=31) not found in InitialContextSetupRequest")
	}
}

// TestBuildInitialContextSetupRequest_IEOrder pins the ProtocolIE-Container to
// TS 38.413 Table 9.2.2.1-1 tabular order. A real Nokia RAN rejects the whole
// PDU with abstract-syntax-error-reject on any out-of-order IE. The regression
// this guards: IndexToRFSP (id=31, position 15) must precede NAS-PDU (id=38,
// position 17) — an earlier build appended them reversed. Ref: TS 38.413 §8.1.
func TestBuildInitialContextSetupRequest_IEOrder(t *testing.T) {
	raw := buildTestICSR(1) // rfsp>0 and nasPDU non-empty → both tail IEs present
	if raw == nil {
		t.Fatal("encoder returned nil")
	}
	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("NGAP decode failed: %v", err)
	}
	req := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	if req == nil {
		t.Fatal("InitialContextSetupRequest is nil")
	}

	// Expected order of the IEs this builder emits, per the spec table.
	wantOrder := []int64{
		ngapType.ProtocolIEIDAMFUENGAPID,               // 10
		ngapType.ProtocolIEIDRANUENGAPID,               // 85
		ngapType.ProtocolIEIDUEAggregateMaximumBitRate, // 110
		ngapType.ProtocolIEIDGUAMI,                     // 28
		ngapType.ProtocolIEIDAllowedNSSAI,              // 0
		ngapType.ProtocolIEIDUESecurityCapabilities,    // 119
		ngapType.ProtocolIEIDSecurityKey,               // 94
		ngapType.ProtocolIEIDIndexToRFSP,               // 31 — must come BEFORE NAS-PDU
		ngapType.ProtocolIEIDNASPDU,                    // 38
	}
	var got []int64
	for _, ie := range req.ProtocolIEs.List {
		got = append(got, ie.Id.Value)
	}
	if len(got) != len(wantOrder) {
		t.Fatalf("IE count = %d, want %d (got ids %v)", len(got), len(wantOrder), got)
	}
	for i := range wantOrder {
		if got[i] != wantOrder[i] {
			t.Fatalf("IE order violated at position %d: got id=%d, want id=%d\nfull order: %v", i, got[i], wantOrder[i], got)
		}
	}
}

func TestBuildInitialContextSetupRequest_NoRFSP(t *testing.T) {
	raw := buildTestICSR(0) // rfsp=0 → IE must be absent
	if raw == nil {
		t.Fatal("encoder returned nil")
	}

	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("NGAP decode failed: %v", err)
	}
	req := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	for _, ie := range req.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDIndexToRFSP {
			t.Fatal("IndexToRFSP IE should be absent when rfsp=0")
		}
	}
}

func TestBuildInitialContextSetupRequest_RFSP256(t *testing.T) {
	raw := buildTestICSR(256) // max value per TS 38.413 §9.3.1.27
	if raw == nil {
		t.Fatal("encoder returned nil")
	}
	pdu, _ := libngap.Decoder(raw)
	req := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	for _, ie := range req.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDIndexToRFSP {
			if ie.Value.IndexToRFSP.Value != 256 {
				t.Fatalf("expected 256, got %d", ie.Value.IndexToRFSP.Value)
			}
			return
		}
	}
	t.Fatal("IndexToRFSP IE not found for rfsp=256")
}

// TestBuildInitialContextSetupRequest_WithPDUSessions verifies the
// PDUSessionResourceSetupListCxtReq IE (id=71) is encoded with the SMF's raw
// transfer bytes, in spec IE order (between GUAMI and AllowedNSSAI), and that
// it is absent when no sessions are passed.
// Ref: TS 38.413 §9.2.2.1, TS 23.502 §4.2.3.2 step 12
func TestBuildInitialContextSetupRequest_WithPDUSessions(t *testing.T) {
	transfer := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	raw := buildTestICSRWithSessions(1, []PDUSessionSetupItemCxtReq{
		{PDUSessionID: 5, SST: 1, SD: []byte{0x00, 0x00, 0x01}, Transfer: transfer},
	})
	if raw == nil {
		t.Fatal("encoder returned nil")
	}

	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("NGAP decode failed: %v", err)
	}
	req := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	if req == nil {
		t.Fatal("InitialContextSetupRequest is nil")
	}

	idxGUAMI, idxList, idxNSSAI := -1, -1, -1
	var found bool
	for i, ie := range req.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDGUAMI:
			idxGUAMI = i
		case ngapType.ProtocolIEIDAllowedNSSAI:
			idxNSSAI = i
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq:
			idxList = i
			list := ie.Value.PDUSessionResourceSetupListCxtReq
			if list == nil || len(list.List) != 1 {
				t.Fatal("PDUSessionResourceSetupListCxtReq missing or wrong length")
			}
			item := list.List[0]
			if item.PDUSessionID.Value != 5 {
				t.Errorf("PDUSessionID: want 5, got %d", item.PDUSessionID.Value)
			}
			got := []byte(item.PDUSessionResourceSetupRequestTransfer)
			if len(got) != len(transfer) {
				t.Fatalf("transfer bytes: want %x, got %x", transfer, got)
			}
			for i := range got {
				if got[i] != transfer[i] {
					t.Fatalf("transfer bytes: want %x, got %x", transfer, got)
				}
			}
			if item.SNSSAI.SST.Value[0] != 1 {
				t.Errorf("SNSSAI SST: want 1, got %d", item.SNSSAI.SST.Value[0])
			}
			found = true
		}
	}
	if !found {
		t.Fatal("PDUSessionResourceSetupListCxtReq IE (id=71) not found")
	}
	// TS 38.413 §8.1: IEs must appear in table order — id=71 sits between
	// GUAMI (id=28) and AllowedNSSAI (id=0).
	if !(idxGUAMI < idxList && idxList < idxNSSAI) {
		t.Fatalf("IE order violated: GUAMI=%d, CxtReq=%d, AllowedNSSAI=%d", idxGUAMI, idxList, idxNSSAI)
	}

	// Without sessions the IE must be absent (Initial Registration shape).
	raw = buildTestICSR(1)
	pdu, err = libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("NGAP decode (no sessions) failed: %v", err)
	}
	for _, ie := range pdu.InitiatingMessage.Value.InitialContextSetupRequest.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq {
			t.Fatal("PDUSessionResourceSetupListCxtReq present without sessions")
		}
	}
}

// TestDecodeInitialContextSetupResponse_WithCxtRes verifies that a gNB ICS
// Response carrying PDUSessionResourceSetupListCxtRes decodes into an
// InitialContextSetupResponseMsg with the raw response transfer preserved.
// Ref: TS 38.413 §9.2.2.2
func TestDecodeInitialContextSetupResponse_WithCxtRes(t *testing.T) {
	respTransfer := []byte{0xCA, 0xFE, 0x01}
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeInitialContextSetup},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentInitialContextSetupResponse,
				InitialContextSetupResponse: &ngapType.InitialContextSetupResponse{
					ProtocolIEs: ngapType.ProtocolIEContainerInitialContextSetupResponseIEs{
						List: []ngapType.InitialContextSetupResponseIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.InitialContextSetupResponseIEsValue{
									Present:     ngapType.InitialContextSetupResponseIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: 7},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.InitialContextSetupResponseIEsValue{
									Present:     ngapType.InitialContextSetupResponseIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: 3},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtRes},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.InitialContextSetupResponseIEsValue{
									Present: ngapType.InitialContextSetupResponseIEsPresentPDUSessionResourceSetupListCxtRes,
									PDUSessionResourceSetupListCxtRes: &ngapType.PDUSessionResourceSetupListCxtRes{
										List: []ngapType.PDUSessionResourceSetupItemCxtRes{
											{
												PDUSessionID:                            ngapType.PDUSessionID{Value: 1},
												PDUSessionResourceSetupResponseTransfer: respTransfer,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	raw, err := libngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode gNB ICS Response: %v", err)
	}

	msg, err := DecodeNGAPPDU(raw)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU: %v", err)
	}
	if msg.Type != 1 || msg.ProcedureCode != ProcInitialContextSetup {
		t.Fatalf("wrong routing: type=%d proc=%d", msg.Type, msg.ProcedureCode)
	}
	resp, ok := msg.Value.(*InitialContextSetupResponseMsg)
	if !ok {
		t.Fatalf("expected *InitialContextSetupResponseMsg, got %T", msg.Value)
	}
	if resp.AMFUENGAPId != 7 || resp.RANUENGAPId != 3 {
		t.Errorf("IDs: got amf=%d ran=%d", resp.AMFUENGAPId, resp.RANUENGAPId)
	}
	if len(resp.Setups) != 1 || resp.Setups[0].PDUSessionID != 1 {
		t.Fatalf("Setups: %+v", resp.Setups)
	}
	if len(resp.Setups[0].N2SMTransferBytes) != len(respTransfer) {
		t.Fatalf("transfer: want %x, got %x", respTransfer, resp.Setups[0].N2SMTransferBytes)
	}
}
