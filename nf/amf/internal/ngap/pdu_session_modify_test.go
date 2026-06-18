package ngap

// pdu_session_modify_test.go — unit tests for the PDU Session Modification procedure codec.
// Covers: BuildPDUSessionResourceModifyRequest (AMF→gNB) and
// extractPDUSessionResourceModifyResponse (gNB→AMF decode path).
// Ref: 3GPP TS 38.413 §8.2.1, §9.3.4.7; ProcedureCode = 26

import (
	"testing"

	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
)

// TestBuildPDUSessionResourceModifyRequest verifies the NGAP Modify Request
// encodes as a valid PDU (ProcedureCode=26, InitiatingMessage) with the correct
// AMF-UE-NGAP-ID, RAN-UE-NGAP-ID, PDU Session ID, NAS-PDU, and N2SM transfer.
func TestBuildPDUSessionResourceModifyRequest(t *testing.T) {
	const amfID int64 = 10
	const ranID int64 = 20
	const pduSessionID uint8 = 1
	nasPDU := []byte{0x7E, 0x02, 0xAA, 0xBB, 0xCC} // stub secured DL NAS Transport
	n2SmInfo := []byte{0x00}                          // stub APER-encoded modify transfer

	pdu := BuildPDUSessionResourceModifyRequest(amfID, ranID, pduSessionID, nasPDU, n2SmInfo)
	if len(pdu) == 0 {
		t.Fatal("BuildPDUSessionResourceModifyRequest returned nil/empty PDU")
	}

	decoded, err := libngap.Decoder(pdu)
	if err != nil {
		t.Fatalf("re-decode failed: %v", err)
	}
	if decoded.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatalf("expected InitiatingMessage, got %d", decoded.Present)
	}
	im := decoded.InitiatingMessage
	if im.ProcedureCode.Value != ngapType.ProcedureCodePDUSessionResourceModify {
		t.Fatalf("expected ProcedureCodePDUSessionResourceModify (26), got %d", im.ProcedureCode.Value)
	}
	req := im.Value.PDUSessionResourceModifyRequest
	if req == nil {
		t.Fatal("PDUSessionResourceModifyRequest is nil in decoded PDU")
	}

	sawAMFID, sawRANID, sawModList := false, false, false
	for _, ie := range req.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			sawAMFID = true
			if ie.Value.AMFUENGAPID == nil || ie.Value.AMFUENGAPID.Value != amfID {
				t.Errorf("AMF-UE-NGAP-ID: want %d, got %v", amfID, ie.Value.AMFUENGAPID)
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			sawRANID = true
			if ie.Value.RANUENGAPID == nil || ie.Value.RANUENGAPID.Value != ranID {
				t.Errorf("RAN-UE-NGAP-ID: want %d, got %v", ranID, ie.Value.RANUENGAPID)
			}
		case ngapType.ProtocolIEIDPDUSessionResourceModifyListModReq:
			sawModList = true
			list := ie.Value.PDUSessionResourceModifyListModReq
			if list == nil || len(list.List) != 1 {
				t.Fatalf("expected 1 item in ModifyList, got %v", list)
			}
			item := list.List[0]
			if item.PDUSessionID.Value != int64(pduSessionID) {
				t.Errorf("PDUSessionID: want %d, got %d", pduSessionID, item.PDUSessionID.Value)
			}
			if item.NASPDU == nil {
				t.Error("NAS-PDU is nil in modify item")
			} else if string(item.NASPDU.Value) != string(nasPDU) {
				t.Errorf("NAS-PDU mismatch: want %x, got %x", nasPDU, item.NASPDU.Value)
			}
		}
	}
	if !sawAMFID || !sawRANID || !sawModList {
		t.Errorf("missing IEs: amfID=%v ranID=%v modList=%v", sawAMFID, sawRANID, sawModList)
	}
}

// TestExtractPDUSessionResourceModifyResponse verifies that a synthetic gNB Modify
// Response (ProcedureCode=26, SuccessfulOutcome) is decoded correctly by
// DecodeNGAPPDU and extractPDUSessionResourceModifyResponse.
func TestExtractPDUSessionResourceModifyResponse(t *testing.T) {
	const amfID int64 = 10
	const ranID int64 = 20
	const pduSessionID uint8 = 1

	rawPDU := buildSyntheticModifyResponse(t, amfID, ranID, pduSessionID)

	msg, err := DecodeNGAPPDU(rawPDU)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU: %v", err)
	}
	if msg.Type != 1 { // SuccessfulOutcome
		t.Fatalf("expected SuccessfulOutcome (1), got %d", msg.Type)
	}
	if msg.ProcedureCode != ProcPDUSessionResourceModify {
		t.Fatalf("expected ProcPDUSessionResourceModify (%d), got %d", ProcPDUSessionResourceModify, msg.ProcedureCode)
	}

	result, ok := msg.Value.(*PDUSessionResourceModifyResponseMsg)
	if !ok || result == nil {
		t.Fatalf("Value is not *PDUSessionResourceModifyResponseMsg: %T", msg.Value)
	}
	if result.AMFUENGAPId != amfID {
		t.Errorf("AMFUENGAPId: want %d, got %d", amfID, result.AMFUENGAPId)
	}
	if result.RANUENGAPId != ranID {
		t.Errorf("RANUENGAPId: want %d, got %d", ranID, result.RANUENGAPId)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 modified session, got %d", len(result.Results))
	}
	if result.Results[0].PDUSessionID != pduSessionID {
		t.Errorf("PDUSessionID: want %d, got %d", pduSessionID, result.Results[0].PDUSessionID)
	}
}

// buildSyntheticModifyResponse constructs an APER-encoded PDU Session Resource Modify
// Response as UERANSIM would send it — used only for codec testing.
func buildSyntheticModifyResponse(t *testing.T, amfID, ranID int64, pduSessionID uint8) []byte {
	t.Helper()
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePDUSessionResourceModify},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentPDUSessionResourceModifyResponse,
				PDUSessionResourceModifyResponse: &ngapType.PDUSessionResourceModifyResponse{
					ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceModifyResponseIEs{
						List: []ngapType.PDUSessionResourceModifyResponseIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PDUSessionResourceModifyResponseIEsValue{
									Present:     ngapType.PDUSessionResourceModifyResponseIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PDUSessionResourceModifyResponseIEsValue{
									Present:     ngapType.PDUSessionResourceModifyResponseIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceModifyListModRes},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PDUSessionResourceModifyResponseIEsValue{
									Present: ngapType.PDUSessionResourceModifyResponseIEsPresentPDUSessionResourceModifyListModRes,
									PDUSessionResourceModifyListModRes: &ngapType.PDUSessionResourceModifyListModRes{
										List: []ngapType.PDUSessionResourceModifyItemModRes{
											{
												PDUSessionID:                             ngapType.PDUSessionID{Value: int64(pduSessionID)},
												PDUSessionResourceModifyResponseTransfer: aper.OctetString([]byte{}),
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
	b, err := libngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode synthetic ModifyResponse: %v", err)
	}
	return b
}
