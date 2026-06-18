package ngap

// an_release_test.go — unit tests for the AN Release procedure codec.
// Ref: 3GPP TS 38.413 §8.3.4, §8.3.5

import (
	"testing"

	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// TestBuildUEContextReleaseCommand_NAS verifies that a Release Command with NAS cause
// encodes as a valid NGAP PDU that the free5GC decoder can re-parse.
func TestBuildUEContextReleaseCommand_NAS(t *testing.T) {
	const amfID int64 = 42
	const ranID int64 = 7

	pdu := BuildUEContextReleaseCommand(amfID, ranID,
		ngapType.CausePresentNas,
		int64(ngapType.CauseNasPresentNormalRelease))

	if len(pdu) == 0 {
		t.Fatal("BuildUEContextReleaseCommand returned nil/empty PDU")
	}

	decoded, err := libngap.Decoder(pdu)
	if err != nil {
		t.Fatalf("re-decode failed: %v", err)
	}
	if decoded.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatalf("expected InitiatingMessage, got %d", decoded.Present)
	}
	im := decoded.InitiatingMessage
	if im.ProcedureCode.Value != ngapType.ProcedureCodeUEContextRelease {
		t.Fatalf("expected ProcedureCodeUEContextRelease (41), got %d", im.ProcedureCode.Value)
	}
	if im.Value.UEContextReleaseCommand == nil {
		t.Fatal("UEContextReleaseCommand is nil in decoded PDU")
	}

	// Verify IEs contain the correct AMF UE NGAP ID
	found := false
	for _, ie := range im.Value.UEContextReleaseCommand.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDUENGAPIDs {
			ids := ie.Value.UENGAPIDs
			if ids == nil || ids.UENGAPIDPair == nil {
				t.Fatal("UENGAPIDs or UENGAPIDPair is nil")
			}
			if ids.UENGAPIDPair.AMFUENGAPID.Value != amfID {
				t.Errorf("AMF UE NGAP ID: want %d, got %d", amfID, ids.UENGAPIDPair.AMFUENGAPID.Value)
			}
			if ids.UENGAPIDPair.RANUENGAPID.Value != ranID {
				t.Errorf("RAN UE NGAP ID: want %d, got %d", ranID, ids.UENGAPIDPair.RANUENGAPID.Value)
			}
			found = true
		}
	}
	if !found {
		t.Error("UENGAPIDs IE not found in decoded PDU")
	}
}

// TestBuildUEContextReleaseCommand_RadioNetwork verifies the RadioNetwork cause path.
func TestBuildUEContextReleaseCommand_RadioNetwork(t *testing.T) {
	pdu := BuildUEContextReleaseCommand(1, 2,
		ngapType.CausePresentRadioNetwork,
		int64(ngapType.CauseRadioNetworkPresentUserInactivity))

	if len(pdu) == 0 {
		t.Fatal("BuildUEContextReleaseCommand returned nil/empty PDU")
	}
	_, err := libngap.Decoder(pdu)
	if err != nil {
		t.Fatalf("re-decode failed: %v", err)
	}
}

// TestBuildMessage_UEContextReleaseComplete verifies that the codec correctly
// extracts an AMF UE NGAP ID from a synthetic UEContextReleaseComplete PDU.
func TestBuildMessage_UEContextReleaseComplete(t *testing.T) {
	const amfID int64 = 99
	const ranID int64 = 11

	rawPDU := buildSyntheticReleaseComplete(t, amfID, ranID)

	msg, err := DecodeNGAPPDU(rawPDU)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU: %v", err)
	}
	if msg.Type != 1 {
		t.Fatalf("expected SuccessfulOutcome (1), got %d", msg.Type)
	}
	if msg.ProcedureCode != ProcUEContextRelease {
		t.Fatalf("expected ProcUEContextRelease (41), got %d", msg.ProcedureCode)
	}

	cpl, ok := msg.Value.(*UEContextReleaseCompleteMsg)
	if !ok || cpl == nil {
		t.Fatalf("Value is not *UEContextReleaseCompleteMsg: %T", msg.Value)
	}
	if cpl.AMFUENGAPId != amfID {
		t.Errorf("AMFUENGAPId: want %d, got %d", amfID, cpl.AMFUENGAPId)
	}
	if cpl.RANUENGAPId != ranID {
		t.Errorf("RANUENGAPId: want %d, got %d", ranID, cpl.RANUENGAPId)
	}
}

// buildSyntheticReleaseComplete builds an APER-encoded UEContextReleaseComplete PDU
// using the free5GC encoder — mimics what UERANSIM would send.
func buildSyntheticReleaseComplete(t *testing.T, amfID, ranID int64) []byte {
	t.Helper()
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeUEContextRelease},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentUEContextReleaseComplete,
				UEContextReleaseComplete: &ngapType.UEContextReleaseComplete{
					ProtocolIEs: ngapType.ProtocolIEContainerUEContextReleaseCompleteIEs{
						List: []ngapType.UEContextReleaseCompleteIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.UEContextReleaseCompleteIEsValue{
									Present:     ngapType.UEContextReleaseCompleteIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.UEContextReleaseCompleteIEsValue{
									Present:     ngapType.UEContextReleaseCompleteIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
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
		t.Fatalf("encode synthetic ReleaseComplete: %v", err)
	}
	return b
}

// TestBuildMessage_UEContextReleaseRequest verifies decoding of a gNB-sent Release Request.
func TestBuildMessage_UEContextReleaseRequest(t *testing.T) {
	const amfID int64 = 5
	const ranID int64 = 3

	rawPDU := buildSyntheticReleaseRequest(t, amfID, ranID)

	msg, err := DecodeNGAPPDU(rawPDU)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU: %v", err)
	}
	if msg.Type != 0 {
		t.Fatalf("expected InitiatingMessage (0), got %d", msg.Type)
	}
	if msg.ProcedureCode != ProcUEContextReleaseRequest {
		t.Fatalf("expected ProcUEContextReleaseRequest (42), got %d", msg.ProcedureCode)
	}

	req, ok := msg.Value.(*UEContextReleaseRequestMsg)
	if !ok || req == nil {
		t.Fatalf("Value is not *UEContextReleaseRequestMsg: %T", msg.Value)
	}
	if req.AMFUENGAPId != amfID {
		t.Errorf("AMFUENGAPId: want %d, got %d", amfID, req.AMFUENGAPId)
	}
	if req.RANUENGAPId != ranID {
		t.Errorf("RANUENGAPId: want %d, got %d", ranID, req.RANUENGAPId)
	}
	if req.CausePresent != ngapType.CausePresentRadioNetwork {
		t.Errorf("CausePresent: want %d (RadioNetwork), got %d", ngapType.CausePresentRadioNetwork, req.CausePresent)
	}
}

// buildSyntheticReleaseRequest builds an APER-encoded UEContextReleaseRequest PDU.
func buildSyntheticReleaseRequest(t *testing.T, amfID, ranID int64) []byte {
	t.Helper()
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeUEContextReleaseRequest},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentUEContextReleaseRequest,
				UEContextReleaseRequest: &ngapType.UEContextReleaseRequest{
					ProtocolIEs: ngapType.ProtocolIEContainerUEContextReleaseRequestIEs{
						List: []ngapType.UEContextReleaseRequestIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.UEContextReleaseRequestIEsValue{
									Present:     ngapType.UEContextReleaseRequestIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.UEContextReleaseRequestIEsValue{
									Present:     ngapType.UEContextReleaseRequestIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDCause},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.UEContextReleaseRequestIEsValue{
									Present: ngapType.UEContextReleaseRequestIEsPresentCause,
									Cause: &ngapType.Cause{
										Present: ngapType.CausePresentRadioNetwork,
										RadioNetwork: &ngapType.CauseRadioNetwork{
											Value: ngapType.CauseRadioNetworkPresentUserInactivity,
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
		t.Fatalf("encode synthetic ReleaseRequest: %v", err)
	}
	return b
}
