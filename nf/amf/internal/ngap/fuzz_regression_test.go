package ngap

// fuzz_regression_test.go — regressions for the decode-path crashes the NGAP fuzz targets
// (fuzz_test.go) and reading of the receive path found. Each test fails without its fix in
// codec.go / ngap.go.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/free5gc/aper"
	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// fuzzNAS accepts every NAS PDU (the NAS layer has its own fuzz targets in shared/nas); it lets
// the dispatch tests here and FuzzDispatchNGAP drive the NGAP receive path without a real NAS
// stack.
type fuzzNAS struct{}

func (fuzzNAS) HandleNASMessage(context.Context, *amfctx.UEContext, []byte) error { return nil }

// TestExtractGlobalRANNodeIDBytesChoiceExtension pins the fix for a nil dereference: a Global
// gNB ID whose GNB-ID uses the choice-Extensions alternative (TS 38.413 §9.3.1.6) has no gNB-ID
// BIT STRING, so GNBID.GNBID is nil. extractGlobalRANNodeIDBytes dereferenced it
// (`id.GlobalGNBID.GNBID.GNBID.Bytes`) and panicked on an NG SETUP REQUEST / HANDOVER REQUIRED
// carrying that alternative. It must return nil instead.
func TestExtractGlobalRANNodeIDBytesChoiceExtension(t *testing.T) {
	id := &ngapType.GlobalRANNodeID{
		Present: ngapType.GlobalRANNodeIDPresentGlobalGNBID,
		GlobalGNBID: &ngapType.GlobalGNBID{
			PLMNIdentity: ngapType.PLMNIdentity{Value: []byte{0x00, 0xf1, 0x10}},
			GNBID: ngapType.GNBID{
				Present:          ngapType.GNBIDPresentChoiceExtensions,
				ChoiceExtensions: &ngapType.ProtocolIESingleContainerGNBIDExtIEs{},
			},
		},
	}
	if got := extractGlobalRANNodeIDBytes(id); got != nil {
		t.Fatalf("extractGlobalRANNodeIDBytes(choice-extension) = %x, want nil", got)
	}
	if n := extractGlobalRANNode(id); n.Type != RANNodeTypeGNB {
		t.Fatalf("extractGlobalRANNode type = %v", n.Type)
	}
}

// TestRemoteAddrStringNilConn pins the fix for the nil net.Addr panic: SCTPConn.RemoteAddr
// returns a nil net.Addr when the kernel can no longer report the peer addresses (association
// shut down or aborted), and calling String on it panicked. remoteAddrString must return the
// address recorded at connect time, and never panic when neither a recorded address nor a live
// connection is available. Ref: the handleGNBConn nil-RemoteAddr note, TS 38.412 §7.
func TestRemoteAddrStringNilConn(t *testing.T) {
	g := &GNBContext{} // no Conn, no recorded address
	if got := g.remoteAddrString(); got != "" {
		t.Fatalf("remoteAddrString() = %q, want \"\"", got)
	}
	g.SetTransportForTest("203.0.113.7:38412", func([]byte, *sctp.SndRcvInfo) (int, error) { return 0, nil })
	if got := g.remoteAddrString(); got != "203.0.113.7:38412" {
		t.Fatalf("remoteAddrString() = %q, want the recorded address", got)
	}
}

// TestDispatchWriteReplaceWarningResponseNilConn feeds a PWS Write-Replace Warning Response
// (gNB→AMF, TS 38.413 §9.2.1.4) through the dispatcher against a gNB with no live SCTP
// connection, as a gNB whose association dropped mid-procedure would be.
// handleWriteReplaceWarningResponse read gnb.Conn.RemoteAddr() directly and panicked on the nil
// Conn; it must handle it and drop the uncorrelated response.
func TestDispatchWriteReplaceWarningResponseNilConn(t *testing.T) {
	mgr := amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	srv := NewServer("", mgr, fuzzNAS{}, AMFConfig{}, slog.New(slog.DiscardHandler))
	gnb := &GNBContext{UEs: map[int64]*amfctx.UEContext{}, IdleUEs: map[int64]*amfctx.UEContext{}}
	// A gNB with neither a recorded address nor a live Conn: the worst case for the call site.
	srv.DispatchNGAPForTest(context.Background(), gnb, writeReplaceWarningResponsePDU(t, 42, 7))
}

// writeReplaceWarningResponsePDU encodes a minimal PWS Write-Replace Warning Response carrying
// only Message Identifier and Serial Number (TS 38.413 §9.2.1.4).
func writeReplaceWarningResponsePDU(t *testing.T, msgID, serial uint16) []byte {
	t.Helper()
	ies := []ngapType.WriteReplaceWarningResponseIEs{
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDMessageIdentifier},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.WriteReplaceWarningResponseIEsValue{
				Present:           ngapType.WriteReplaceWarningResponseIEsPresentMessageIdentifier,
				MessageIdentifier: &ngapType.MessageIdentifier{Value: aper.BitString{Bytes: []byte{byte(msgID >> 8), byte(msgID)}, BitLength: 16}},
			},
		},
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDSerialNumber},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.WriteReplaceWarningResponseIEsValue{
				Present:      ngapType.WriteReplaceWarningResponseIEsPresentSerialNumber,
				SerialNumber: &ngapType.SerialNumber{Value: aper.BitString{Bytes: []byte{byte(serial >> 8), byte(serial)}, BitLength: 16}},
			},
		},
	}
	b, err := libngap.Encoder(ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeWriteReplaceWarning},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present:                     ngapType.SuccessfulOutcomePresentWriteReplaceWarningResponse,
				WriteReplaceWarningResponse: &ngapType.WriteReplaceWarningResponse{ProtocolIEs: ngapType.ProtocolIEContainerWriteReplaceWarningResponseIEs{List: ies}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
