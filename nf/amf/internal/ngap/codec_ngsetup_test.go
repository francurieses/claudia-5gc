package ngap

// codec_ngsetup_test.go — APER round-trip of the NG Setup Request decode used by
// the gNB registry. Ref: TS 38.413 §8.7.1, §9.3.1.5-6.

import (
	"testing"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// buildNGSetupRequestPDU encodes an NG Setup Request carrying a Global gNB ID of
// the given bit length, a RAN node name and two TAs (one with SD, one without).
func buildNGSetupRequestPDU(t *testing.T, gnbIDBytes []byte, bitLen uint64, name string) []byte {
	t.Helper()
	plmn := aper.OctetString{0x00, 0xF1, 0x10} // MCC 001, MNC 01
	sliceItem := func(sst byte, sd []byte) ngapType.SliceSupportItem {
		it := ngapType.SliceSupportItem{SNSSAI: ngapType.SNSSAI{SST: ngapType.SST{Value: aper.OctetString{sst}}}}
		if sd != nil {
			it.SNSSAI.SD = &ngapType.SD{Value: aper.OctetString(sd)}
		}
		return it
	}
	ta := func(tac []byte, slices ...ngapType.SliceSupportItem) ngapType.SupportedTAItem {
		return ngapType.SupportedTAItem{
			TAC: ngapType.TAC{Value: aper.OctetString(tac)},
			BroadcastPLMNList: ngapType.BroadcastPLMNList{List: []ngapType.BroadcastPLMNItem{{
				PLMNIdentity:        ngapType.PLMNIdentity{Value: plmn},
				TAISliceSupportList: ngapType.SliceSupportList{List: slices},
			}}},
		}
	}
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeNGSetup},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentNGSetupRequest,
				NGSetupRequest: &ngapType.NGSetupRequest{
					ProtocolIEs: ngapType.ProtocolIEContainerNGSetupRequestIEs{List: []ngapType.NGSetupRequestIEs{
						{
							Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDGlobalRANNodeID},
							Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
							Value: ngapType.NGSetupRequestIEsValue{
								Present: ngapType.NGSetupRequestIEsPresentGlobalRANNodeID,
								GlobalRANNodeID: &ngapType.GlobalRANNodeID{
									Present: ngapType.GlobalRANNodeIDPresentGlobalGNBID,
									GlobalGNBID: &ngapType.GlobalGNBID{
										PLMNIdentity: ngapType.PLMNIdentity{Value: plmn},
										GNBID: ngapType.GNBID{
											Present: ngapType.GNBIDPresentGNBID,
											GNBID:   &aper.BitString{Bytes: gnbIDBytes, BitLength: bitLen},
										},
									},
								},
							},
						},
						{
							Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANNodeName},
							Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
							Value: ngapType.NGSetupRequestIEsValue{
								Present:     ngapType.NGSetupRequestIEsPresentRANNodeName,
								RANNodeName: &ngapType.RANNodeName{Value: name},
							},
						},
						{
							Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDSupportedTAList},
							Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
							Value: ngapType.NGSetupRequestIEsValue{
								Present: ngapType.NGSetupRequestIEsPresentSupportedTAList,
								SupportedTAList: &ngapType.SupportedTAList{List: []ngapType.SupportedTAItem{
									ta([]byte{0x00, 0x00, 0x01}, sliceItem(1, []byte{0x00, 0x00, 0x01})),
									ta([]byte{0x00, 0x00, 0x02}, sliceItem(2, nil)),
								}},
							},
						},
						{
							Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDDefaultPagingDRX},
							Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
							Value: ngapType.NGSetupRequestIEsValue{
								Present:          ngapType.NGSetupRequestIEsPresentDefaultPagingDRX,
								DefaultPagingDRX: &ngapType.PagingDRX{Value: ngapType.PagingDRXPresentV128},
							},
						},
					}},
				},
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode NG Setup Request: %v", err)
	}
	return b
}

func TestDecodeNGSetupRequest_GNBID32Bit(t *testing.T) {
	b := buildNGSetupRequestPDU(t, []byte{0x00, 0x00, 0x00, 0x01}, 32, "gnb-a")
	msg, err := DecodeNGAPPDU(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	req, ok := msg.Value.(*NGSetupRequest)
	if !ok {
		t.Fatalf("value type = %T, want *NGSetupRequest", msg.Value)
	}
	n := req.RANNode
	if n.Type != RANNodeTypeGNB || n.MCC != "001" || n.MNC != "01" || n.GNBID != 1 || n.GNBIDBitLen != 32 {
		t.Fatalf("RANNode = %+v", n)
	}
	if got := n.IDString(); got != "00000001/32" {
		t.Errorf("IDString = %q", got)
	}
	if req.RANNodeName != "gnb-a" {
		t.Errorf("name = %q", req.RANNodeName)
	}
	// Flat bytes used by handover matching must be unchanged: PLMN(3) + gNB ID bytes(4).
	if len(req.GlobalRANNodeID) != 7 {
		t.Errorf("GlobalRANNodeID len = %d, want 7", len(req.GlobalRANNodeID))
	}
}

func TestDecodeNGSetupRequest_GNBID22Bit(t *testing.T) {
	// 22-bit value 0x155555 left-aligned in 3 octets: 0x155555 << 2 = 0x555554.
	b := buildNGSetupRequestPDU(t, []byte{0x55, 0x55, 0x54}, 22, "gnb-b")
	msg, err := DecodeNGAPPDU(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	n := msg.Value.(*NGSetupRequest).RANNode
	if n.GNBIDBitLen != 22 || n.GNBID != 0x155555 {
		t.Fatalf("RANNode = %+v, want id 0x155555 / 22 bits", n)
	}
	if n.hex() != "155555" {
		t.Errorf("hex = %q", n.hex())
	}
}

func TestDecodeNGSetupRequest_SupportedTAsAndSlices(t *testing.T) {
	b := buildNGSetupRequestPDU(t, []byte{0x00, 0x00, 0x00, 0x01}, 32, "gnb-a")
	msg, err := DecodeNGAPPDU(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	tas := msg.Value.(*NGSetupRequest).SupportedTAList
	if len(tas) != 2 {
		t.Fatalf("TAs = %d, want 2", len(tas))
	}
	if tas[0].TAC != 1 || len(tas[0].BroadcastPLMNs) != 1 {
		t.Fatalf("TA0 = %+v", tas[0])
	}
	ss := tas[0].BroadcastPLMNs[0].SliceSupport
	if len(ss) != 1 || ss[0].SST != 1 || ss[0].SD != "000001" {
		t.Errorf("TA0 slices = %+v, want SST 1 SD 000001", ss)
	}
	ss = tas[1].BroadcastPLMNs[0].SliceSupport
	if tas[1].TAC != 2 || len(ss) != 1 || ss[0].SST != 2 || ss[0].SD != "" {
		t.Errorf("TA1 = %+v, want TAC 2 SST 2 no SD", tas[1])
	}
}

func TestExtractGlobalRANNode_NonGNB(t *testing.T) {
	n := extractGlobalRANNode(&ngapType.GlobalRANNodeID{Present: ngapType.GlobalRANNodeIDPresentGlobalN3IWFID})
	if n.Type != RANNodeTypeN3IWF || n.IDString() != "" {
		t.Errorf("N3IWF node = %+v", n)
	}
}
