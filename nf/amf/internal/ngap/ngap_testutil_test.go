package ngap

import (
	"testing"

	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
	"github.com/free5gc/aper"
)

// buildULNAS encodes an UPLINK NAS TRANSPORT (AMF UE NGAP ID, RAN UE NGAP ID, NAS-PDU).
func buildULNAS(t *testing.T, amf, ran int64, nasPDU []byte) []byte {
	t.Helper()
	msg := &ngapType.UplinkNASTransport{}
	add := func(id int64, v ngapType.UplinkNASTransportIEsValue) {
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ngapType.UplinkNASTransportIEs{
			Id: ngapType.ProtocolIEID{Value: id}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject}, Value: v})
	}
	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.UplinkNASTransportIEsValue{
		Present: ngapType.UplinkNASTransportIEsPresentAMFUENGAPID, AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amf}})
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.UplinkNASTransportIEsValue{
		Present: ngapType.UplinkNASTransportIEsPresentRANUENGAPID, RANUENGAPID: &ngapType.RANUENGAPID{Value: ran}})
	if nasPDU != nil {
		add(ngapType.ProtocolIEIDNASPDU, ngapType.UplinkNASTransportIEsValue{
			Present: ngapType.UplinkNASTransportIEsPresentNASPDU, NASPDU: &ngapType.NASPDU{Value: aper.OctetString(nasPDU)}})
	}
	b, err := libngap.Encoder(ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeUplinkNASTransport},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentUplinkNASTransport, UplinkNASTransport: msg},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
