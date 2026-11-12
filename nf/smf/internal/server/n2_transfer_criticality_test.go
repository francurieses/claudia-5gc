package server

import (
	"net"
	"testing"

	"github.com/free5gc/aper"

	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// TestPDUSessionResourceSetupRequestTransferIECriticality pins per-IE criticality to the
// PDUSessionResourceSetupRequestTransferIEs rows of NGAP-IEs.asn (V19.4.0): the PDU Session
// AMBR (130) is reject, like every other IE this builder emits. Ref: TS 38.413 §9.3.4.1.
func TestPDUSessionResourceSetupRequestTransferIECriticality(t *testing.T) {
	want := map[int64]aper.Enumerated{
		ngapType.ProtocolIEIDPDUSessionAggregateMaximumBitRate: ngapType.CriticalityPresentReject,
		ngapType.ProtocolIEIDULNGUUPTNLInformation:             ngapType.CriticalityPresentReject,
		ngapType.ProtocolIEIDDataForwardingNotPossible:         ngapType.CriticalityPresentReject,
		ngapType.ProtocolIEIDPDUSessionType:                    ngapType.CriticalityPresentReject,
		ngapType.ProtocolIEIDQosFlowSetupRequestList:           ngapType.CriticalityPresentReject,
	}
	for name, fwd := range map[string]bool{"plain": false, "data-forwarding-not-possible": true} {
		t.Run(name, func(t *testing.T) {
			b, err := buildPDUSessionResourceSetupRequestTransferOpts(net.ParseIP("10.0.0.1"), 1, 1, 9, 1000, 2000, ngapType.PDUSessionTypePresentIpv4, fwd)
			if err != nil {
				t.Fatal(err)
			}
			var tr ngapType.PDUSessionResourceSetupRequestTransfer
			if err := aper.UnmarshalWithParams(b, &tr, "valueExt"); err != nil {
				t.Fatal(err)
			}
			for _, ie := range tr.ProtocolIEs.List {
				w, ok := want[ie.Id.Value]
				if !ok {
					t.Fatalf("unexpected IE %d", ie.Id.Value)
				}
				if ie.Criticality.Value != w {
					t.Errorf("IE %d criticality = %d, want %d", ie.Id.Value, ie.Criticality.Value, w)
				}
			}
		})
	}
}
