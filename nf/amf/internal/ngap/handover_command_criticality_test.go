package ngap

import (
	"testing"

	"github.com/free5gc/aper"

	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// TestHandoverCommandIECriticality pins the per-IE criticality of HANDOVER COMMAND to the
// HandoverCommandIEs rows of NGAP-PDU-Contents.asn (V19.4.0): AMF/RAN UE NGAP ID, Handover
// Type and TargetToSource container are reject; the lists and Criticality Diagnostics are
// ignore. Ref: TS 38.413 §9.2.3.2 (criticality fix).
func TestHandoverCommandIECriticality(t *testing.T) {
	const (
		reject = ngapType.CriticalityPresentReject
		ignore = ngapType.CriticalityPresentIgnore
	)
	cd := &ngapType.CriticalityDiagnostics{}
	items := []PDUSessionHOCmdItem{{PDUSessionID: 5}}
	rel := []PDUSessionHOReleaseItem{{PDUSessionID: 6, CausePresent: ngapType.CausePresentRadioNetwork, CauseValue: 1}}
	for name, b := range map[string][]byte{
		"plain":        BuildHandoverCommand(1, 2, 0, items, nil, []byte{1, 2, 3}),
		"release+diag": BuildHandoverCommandWithDiagnostics(1, 2, 0, items, rel, []byte{1, 2, 3}, cd),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := libngap.Decoder(b)
			if err != nil || p.SuccessfulOutcome == nil || p.SuccessfulOutcome.Value.HandoverCommand == nil {
				t.Fatalf("decode: %v", err)
			}
			want := map[int64]aper.Enumerated{
				ngapType.ProtocolIEIDAMFUENGAPID:                          reject,
				ngapType.ProtocolIEIDRANUENGAPID:                          reject,
				ngapType.ProtocolIEIDHandoverType:                         reject,
				ngapType.ProtocolIEIDPDUSessionResourceHandoverList:       ignore,
				ngapType.ProtocolIEIDPDUSessionResourceToReleaseListHOCmd: ignore,
				ngapType.ProtocolIEIDTargetToSourceTransparentContainer:   reject,
				ngapType.ProtocolIEIDCriticalityDiagnostics:               ignore,
			}
			for _, ie := range p.SuccessfulOutcome.Value.HandoverCommand.ProtocolIEs.List {
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
