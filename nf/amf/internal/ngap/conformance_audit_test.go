package ngap

// conformance_audit_test.go — regression tests for the 3GPP conformance audit
// fixes (Jul 2026): subscribed UE-AMBR in InitialContextSetupRequest and
// FailedToSetupListSURes extraction from PDUSessionResourceSetupResponse.
// Ref: TS 38.413 §9.3.1.58, §8.4.1; TS 23.502 §4.3.2.2.1 step 16

import (
	"testing"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// TestBuildInitialContextSetupRequest_SubscribedAMBR verifies the UE-AMBR IE
// carries the subscribed values (bit/s) instead of a hardcoded default.
// Ref: TS 38.413 §9.3.1.58
func TestBuildInitialContextSetupRequest_SubscribedAMBR(t *testing.T) {
	const ulBps, dlBps = 200_000_000, 500_000_000
	raw := BuildInitialContextSetupRequest(
		1, 2, []byte{0x01}, testSecKey, 0x8000, 0x8000,
		"001", "01", 0x80, 1, 0x01,
		[]amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}},
		ulBps, dlBps, 1, nil,
	)
	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("NGAP decode failed: %v", err)
	}
	req := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	var found bool
	for _, ie := range req.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDUEAggregateMaximumBitRate {
			found = true
			ambr := ie.Value.UEAggregateMaximumBitRate
			if ambr.UEAggregateMaximumBitRateUL.Value != ulBps {
				t.Errorf("UE-AMBR UL: got %d, want %d", ambr.UEAggregateMaximumBitRateUL.Value, ulBps)
			}
			if ambr.UEAggregateMaximumBitRateDL.Value != dlBps {
				t.Errorf("UE-AMBR DL: got %d, want %d", ambr.UEAggregateMaximumBitRateDL.Value, dlBps)
			}
		}
	}
	if !found {
		t.Fatal("UEAggregateMaximumBitRate IE missing")
	}
}

// TestExtractPDUSessionResourceSetupResponse_FailedList verifies that PDU
// sessions reported in PDUSessionResourceFailedToSetupListSURes surface in
// FailedPSIs so the AMF can release them at the SMF.
// Ref: TS 38.413 §8.4.1, TS 23.502 §4.3.2.2.1 step 16
func TestExtractPDUSessionResourceSetupResponse_FailedList(t *testing.T) {
	resp := &ngapType.PDUSessionResourceSetupResponse{}
	resp.ProtocolIEs.List = []ngapType.PDUSessionResourceSetupResponseIEs{
		{
			Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
			Value: ngapType.PDUSessionResourceSetupResponseIEsValue{
				Present:     ngapType.PDUSessionResourceSetupResponseIEsPresentAMFUENGAPID,
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: 7},
			},
		},
		{
			Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListSURes},
			Value: ngapType.PDUSessionResourceSetupResponseIEsValue{
				Present: ngapType.PDUSessionResourceSetupResponseIEsPresentPDUSessionResourceFailedToSetupListSURes,
				PDUSessionResourceFailedToSetupListSURes: &ngapType.PDUSessionResourceFailedToSetupListSURes{
					List: []ngapType.PDUSessionResourceFailedToSetupItemSURes{
						{
							PDUSessionID: ngapType.PDUSessionID{Value: 5},
							PDUSessionResourceSetupUnsuccessfulTransfer: aper.OctetString{0x00},
						},
					},
				},
			},
		},
	}

	out := extractPDUSessionResourceSetupResponse(resp)
	if out.AMFUENGAPId != 7 {
		t.Errorf("AMFUENGAPId: got %d, want 7", out.AMFUENGAPId)
	}
	if len(out.FailedPSIs) != 1 || out.FailedPSIs[0] != 5 {
		t.Fatalf("FailedPSIs: got %v, want [5]", out.FailedPSIs)
	}
}
