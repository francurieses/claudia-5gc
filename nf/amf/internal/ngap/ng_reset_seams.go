package ngap

import (
	"fmt"

	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// Test seams for NG Reset (the BDD suite lives in an external package). Production code
// does not call them.

// NGResetParams describes an NG RESET PDU for BuildNGResetForTest.
type NGResetParams struct {
	// OmitCause drops the Cause IE (criticality ignore).
	OmitCause bool
	// OmitResetType drops the mandatory Reset Type IE (id 88).
	OmitResetType bool
	// ResetAll selects nG-Interface reset-all; otherwise partOfNG-Interface with Items.
	ResetAll bool
	Items    []ResetItem
}

// BuildNGResetForTest encodes an NG RESET (InitiatingMessage, procedure code 20, criticality
// reject) with APER, IEs in the spec order Cause (15), Reset Type (88).
func BuildNGResetForTest(p NGResetParams) ([]byte, error) {
	var ies []ngapType.NGResetIEs
	if !p.OmitCause {
		ies = append(ies, ngapType.NGResetIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDCause},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.NGResetIEsValue{
				Present: ngapType.NGResetIEsPresentCause,
				Cause: &ngapType.Cause{
					Present: ngapType.CausePresentRadioNetwork,
					RadioNetwork: &ngapType.CauseRadioNetwork{
						Value: ngapType.CauseRadioNetworkPresentUnspecified},
				},
			},
		})
	}
	if !p.OmitResetType {
		rt := &ngapType.ResetType{}
		if p.ResetAll {
			rt.Present = ngapType.ResetTypePresentNGInterface
			rt.NGInterface = &ngapType.ResetAll{Value: ngapType.ResetAllPresentResetAll}
		} else {
			rt.Present = ngapType.ResetTypePresentPartOfNGInterface
			rt.PartOfNGInterface = &ngapType.UEAssociatedLogicalNGConnectionList{}
			for _, it := range p.Items {
				var li ngapType.UEAssociatedLogicalNGConnectionItem
				if it.AMF != nil {
					li.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: *it.AMF}
				}
				if it.RAN != nil {
					li.RANUENGAPID = &ngapType.RANUENGAPID{Value: *it.RAN}
				}
				rt.PartOfNGInterface.List = append(rt.PartOfNGInterface.List, li)
			}
		}
		ies = append(ies, ngapType.NGResetIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDResetType},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.NGResetIEsValue{
				Present:   ngapType.NGResetIEsPresentResetType,
				ResetType: rt,
			},
		})
	}
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeNGReset},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentNGReset,
				NGReset: &ngapType.NGReset{
					ProtocolIEs: ngapType.ProtocolIEContainerNGResetIEs{List: ies},
				},
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil, fmt.Errorf("ngap: encode NG Reset: %w", err)
	}
	return b, nil
}

// NGResetAckView is the decoded content of an NG RESET ACKNOWLEDGE.
type NGResetAckView struct {
	// ProcedureCode is the procedure code of the SuccessfulOutcome.
	ProcedureCode int64
	// IEIDs lists the IE ids in encoded order.
	IEIDs []int64
	// HasList reports the presence of IE 111; Items is its content in order.
	HasList bool
	Items   []ResetItem
	// HasDiagnostics reports the presence of IE 19.
	HasDiagnostics bool
}

// DecodeNGResetAckForTest decodes an outbound PDU; ok is false when it is not an NG RESET
// ACKNOWLEDGE.
func DecodeNGResetAckForTest(pdu []byte) (v NGResetAckView, ok bool, err error) {
	p, err := libngap.Decoder(pdu)
	if err != nil {
		return v, false, fmt.Errorf("ngap: decode: %w", err)
	}
	if p.Present != ngapType.NGAPPDUPresentSuccessfulOutcome || p.SuccessfulOutcome == nil ||
		p.SuccessfulOutcome.Value.NGResetAcknowledge == nil {
		return v, false, nil
	}
	v.ProcedureCode = p.SuccessfulOutcome.ProcedureCode.Value
	for _, ie := range p.SuccessfulOutcome.Value.NGResetAcknowledge.ProtocolIEs.List {
		v.IEIDs = append(v.IEIDs, ie.Id.Value)
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDUEAssociatedLogicalNGConnectionList:
			v.HasList = true
			for _, it := range ie.Value.UEAssociatedLogicalNGConnectionList.List {
				var ri ResetItem
				if it.AMFUENGAPID != nil {
					x := it.AMFUENGAPID.Value
					ri.AMF = &x
				}
				if it.RANUENGAPID != nil {
					x := it.RANUENGAPID.Value
					ri.RAN = &x
				}
				v.Items = append(v.Items, ri)
			}
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			v.HasDiagnostics = true
		}
	}
	return v, true, nil
}
