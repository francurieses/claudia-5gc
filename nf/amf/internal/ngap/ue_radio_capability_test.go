package ngap

// ue_radio_capability_test.go — decode of UE Radio Capability Info Indication.
// Ref: 3GPP TS 38.413 §8.7.6

import (
	"bytes"
	"testing"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// TestDecodeUERadioCapabilityInfoIndication builds a real APER-encoded
// UE Radio Capability Info Indication (proc 44) and verifies DecodeNGAPPDU maps
// it to our internal message with the AMF/RAN NGAP IDs and capability blob intact
// — i.e. it is no longer routed to the "unhandled NGAP procedure" default.
func TestDecodeUERadioCapabilityInfoIndication(t *testing.T) {
	const amfID int64 = 62
	const ranID int64 = 131073
	radioCap := []byte{0xde, 0xad, 0xbe, 0xef}

	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = &ngapType.InitiatingMessage{}
	pdu.InitiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeUERadioCapabilityInfoIndication
	pdu.InitiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore
	pdu.InitiatingMessage.Value.Present = ngapType.InitiatingMessagePresentUERadioCapabilityInfoIndication
	ind := &ngapType.UERadioCapabilityInfoIndication{}

	var amfIE ngapType.UERadioCapabilityInfoIndicationIEs
	amfIE.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	amfIE.Criticality.Value = ngapType.CriticalityPresentReject
	amfIE.Value.Present = ngapType.UERadioCapabilityInfoIndicationIEsPresentAMFUENGAPID
	amfIE.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfID}
	ind.ProtocolIEs.List = append(ind.ProtocolIEs.List, amfIE)

	var ranIE ngapType.UERadioCapabilityInfoIndicationIEs
	ranIE.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ranIE.Criticality.Value = ngapType.CriticalityPresentReject
	ranIE.Value.Present = ngapType.UERadioCapabilityInfoIndicationIEsPresentRANUENGAPID
	ranIE.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: ranID}
	ind.ProtocolIEs.List = append(ind.ProtocolIEs.List, ranIE)

	var capIE ngapType.UERadioCapabilityInfoIndicationIEs
	capIE.Id.Value = ngapType.ProtocolIEIDUERadioCapability
	capIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	capIE.Value.Present = ngapType.UERadioCapabilityInfoIndicationIEsPresentUERadioCapability
	capIE.Value.UERadioCapability = &ngapType.UERadioCapability{Value: aper.OctetString(radioCap)}
	ind.ProtocolIEs.List = append(ind.ProtocolIEs.List, capIE)

	pdu.InitiatingMessage.Value.UERadioCapabilityInfoIndication = ind

	raw, err := libngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	msg, err := DecodeNGAPPDU(raw)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU failed: %v", err)
	}
	if msg.ProcedureCode != ProcUERadioCapabilityInfoIndication {
		t.Fatalf("proc code = %d; want %d", msg.ProcedureCode, ProcUERadioCapabilityInfoIndication)
	}
	if msg.Type != 0 {
		t.Fatalf("msg.Type = %d; want 0 (InitiatingMessage)", msg.Type)
	}
	got, ok := msg.Value.(*UERadioCapabilityInfoIndicationMsg)
	if !ok {
		t.Fatalf("msg.Value type = %T; want *UERadioCapabilityInfoIndicationMsg", msg.Value)
	}
	if got.AMFUENGAPId != amfID {
		t.Errorf("AMFUENGAPId = %d; want %d", got.AMFUENGAPId, amfID)
	}
	if got.RANUENGAPId != ranID {
		t.Errorf("RANUENGAPId = %d; want %d", got.RANUENGAPId, ranID)
	}
	if !bytes.Equal(got.UERadioCapability, radioCap) {
		t.Errorf("UERadioCapability = %x; want %x", got.UERadioCapability, radioCap)
	}
}
