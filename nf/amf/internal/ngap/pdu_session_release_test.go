package ngap

// pdu_session_release_test.go — unit tests for the PDU Session Resource Release
// NGAP messages (command + response decode).
// Ref: 3GPP TS 38.413 §8.4.2

import (
	"bytes"
	"testing"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// TestBuildPDUSessionResourceReleaseCommand verifies that the Release Command
// produces a 3GPP-compliant NGAP PDU that the free5GC decoder can re-parse.
// Key checks per TS 38.413 §9.1.3.1 and §9.3.4.6:
//   - ProcedureCode = 28 (PDUSessionResourceRelease)
//   - Mandatory IEs: AMF-UE-NGAP-ID, RAN-UE-NGAP-ID, PDUSessionResourceToReleaseListRelCmd
//   - Optional IE:   NAS-PDU (carrying the 5GSM PDU Session Release Command)
//   - Transfer APER-encoded with valueExt (extensible SEQUENCE per TS 38.413 §9.3.4.6)
func TestBuildPDUSessionResourceReleaseCommand(t *testing.T) {
	const (
		amfID        int64 = 42
		ranID        int64 = 7
		pduSessionID uint8 = 1
	)
	// Minimal secured NAS PDU: outer 5GMM security header (7 bytes) + DL NAS Transport
	// with 5GSM Release Command embedded. In production this comes from sendNASSecured;
	// here we use a plausible placeholder to verify NAS-PDU passthrough.
	nasPDU := []byte{
		0x7e, 0x02, 0x11, 0x22, 0x33, 0x44, // 5GMM outer security header
		0x00,                               // SQN
		0x7e, 0x00, 0x62,                   // DL NAS Transport plain header (MT=0x62)
		0x12, 0x01,                         // PDU Session ID IE (TV: IEI=0x12, value=1)
		0x59,                               // Payload container type (N1 SM = 1)
		0x00, 0x05,                         // Payload container length (LV-E)
		0x2e, 0x01, 0x01, 0xd3, 0x24,      // 5GSM: EPD|PSI|PTI|MT(0xD3)|Cause(0x24)
	}

	pdu := BuildPDUSessionResourceReleaseCommand(amfID, ranID, pduSessionID, nasPDU)
	if len(pdu) == 0 {
		t.Fatal("BuildPDUSessionResourceReleaseCommand returned nil/empty PDU")
	}

	// Re-decode with the free5GC decoder (same ASN.1 PER library UERANSIM uses).
	decoded, err := libngap.Decoder(pdu)
	if err != nil {
		t.Fatalf("APER re-decode failed: %v", err)
	}
	if decoded.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatalf("expected InitiatingMessage, got %d", decoded.Present)
	}
	im := decoded.InitiatingMessage
	if im.ProcedureCode.Value != ngapType.ProcedureCodePDUSessionResourceRelease {
		t.Fatalf("ProcedureCode: want %d (PDUSessionResourceRelease), got %d",
			ngapType.ProcedureCodePDUSessionResourceRelease, im.ProcedureCode.Value)
	}
	if im.Criticality.Value != ngapType.CriticalityPresentReject {
		t.Errorf("Criticality: want Reject, got %d", im.Criticality.Value)
	}
	if im.Value.PDUSessionResourceReleaseCommand == nil {
		t.Fatal("PDUSessionResourceReleaseCommand body is nil in decoded PDU")
	}

	// Verify all mandatory and optional IEs.
	var (
		gotAMF, gotRAN, gotList, gotNAS bool
	)
	for _, ie := range im.Value.PDUSessionResourceReleaseCommand.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID: // 10
			gotAMF = true
			if ie.Value.AMFUENGAPID == nil {
				t.Error("AMF-UE-NGAP-ID IE: value is nil")
			} else if ie.Value.AMFUENGAPID.Value != amfID {
				t.Errorf("AMF-UE-NGAP-ID: want %d, got %d", amfID, ie.Value.AMFUENGAPID.Value)
			}
			if ie.Criticality.Value != ngapType.CriticalityPresentReject {
				t.Errorf("AMF-UE-NGAP-ID criticality: want Reject, got %d", ie.Criticality.Value)
			}

		case ngapType.ProtocolIEIDRANUENGAPID: // 85
			gotRAN = true
			if ie.Value.RANUENGAPID == nil {
				t.Error("RAN-UE-NGAP-ID IE: value is nil")
			} else if ie.Value.RANUENGAPID.Value != ranID {
				t.Errorf("RAN-UE-NGAP-ID: want %d, got %d", ranID, ie.Value.RANUENGAPID.Value)
			}
			if ie.Criticality.Value != ngapType.CriticalityPresentReject {
				t.Errorf("RAN-UE-NGAP-ID criticality: want Reject, got %d", ie.Criticality.Value)
			}

		case ngapType.ProtocolIEIDNASPDU: // 38
			gotNAS = true
			if ie.Value.NASPDU == nil {
				t.Error("NAS-PDU IE: value is nil")
			} else if !bytes.Equal([]byte(ie.Value.NASPDU.Value), nasPDU) {
				t.Errorf("NAS-PDU mismatch: want %x, got %x", nasPDU, ie.Value.NASPDU.Value)
			}
			if ie.Criticality.Value != ngapType.CriticalityPresentIgnore {
				t.Errorf("NAS-PDU criticality: want Ignore, got %d", ie.Criticality.Value)
			}

		case ngapType.ProtocolIEIDPDUSessionResourceToReleaseListRelCmd: // 135
			gotList = true
			list := ie.Value.PDUSessionResourceToReleaseListRelCmd
			if list == nil || len(list.List) == 0 {
				t.Error("PDUSessionResourceToReleaseListRelCmd: empty list")
				continue
			}
			item := list.List[0]
			if int(item.PDUSessionID.Value) != int(pduSessionID) {
				t.Errorf("PDU Session ID: want %d, got %d", pduSessionID, item.PDUSessionID.Value)
			}
			if len(item.PDUSessionResourceReleaseCommandTransfer) == 0 {
				t.Error("PDUSessionResourceReleaseCommandTransfer: empty bytes")
				continue
			}
			// Verify the Transfer can be APER-decoded — this proves MarshalWithParams(…,"valueExt")
			// was used, matching free5GC/UERANSIM expectations (TS 38.413 §9.3.4.6 is extensible).
			var transfer ngapType.PDUSessionResourceReleaseCommandTransfer
			if err := aper.UnmarshalWithParams(
				item.PDUSessionResourceReleaseCommandTransfer, &transfer, "valueExt"); err != nil {
				t.Errorf("Transfer APER re-decode failed (missing valueExt?): %v", err)
			}
			// Cause must be set.
			if transfer.Cause.Present == 0 {
				t.Error("Transfer.Cause: not set")
			}
			if ie.Criticality.Value != ngapType.CriticalityPresentReject {
				t.Errorf("PDUSessionResourceToReleaseListRelCmd criticality: want Reject, got %d",
					ie.Criticality.Value)
			}
		}
	}

	if !gotAMF {
		t.Error("mandatory IE AMF-UE-NGAP-ID (id=10) not found")
	}
	if !gotRAN {
		t.Error("mandatory IE RAN-UE-NGAP-ID (id=85) not found")
	}
	if !gotList {
		t.Error("mandatory IE PDUSessionResourceToReleaseListRelCmd (id=135) not found")
	}
	if !gotNAS {
		t.Error("optional IE NAS-PDU (id=38) not found — Release Command not embedded")
	}
}

// TestPDUSessionResourceReleaseResponse_Decode verifies that the decoder correctly
// extracts AMF/RAN UE NGAP IDs from a synthetic PDU Session Resource Release Response,
// mimicking what UERANSIM sends in response to a Release Command.
// Ref: TS 38.413 §8.4.2
func TestPDUSessionResourceReleaseResponse_Decode(t *testing.T) {
	const (
		amfID int64 = 33
		ranID int64 = 44
	)

	rawPDU := buildSyntheticPDUSessionReleaseResponse(t, amfID, ranID)
	msg, err := DecodeNGAPPDU(rawPDU)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU: %v", err)
	}
	if msg.Type != 1 {
		t.Fatalf("expected SuccessfulOutcome (type=1), got %d", msg.Type)
	}
	if msg.ProcedureCode != ProcPDUSessionResourceRelease {
		t.Fatalf("ProcedureCode: want ProcPDUSessionResourceRelease (%d), got %d",
			ProcPDUSessionResourceRelease, msg.ProcedureCode)
	}

	resp, ok := msg.Value.(*PDUSessionResourceReleaseResponseMsg)
	if !ok || resp == nil {
		t.Fatalf("Value is not *PDUSessionResourceReleaseResponseMsg: %T", msg.Value)
	}
	if resp.AMFUENGAPId != amfID {
		t.Errorf("AMFUENGAPId: want %d, got %d", amfID, resp.AMFUENGAPId)
	}
	if resp.RANUENGAPId != ranID {
		t.Errorf("RANUENGAPId: want %d, got %d", ranID, resp.RANUENGAPId)
	}
}

// buildSyntheticPDUSessionReleaseResponse builds an APER-encoded PDU Session Resource
// Release Response using the free5GC encoder, mimicking what UERANSIM would send.
// Ref: TS 38.413 §8.4.2, Table 9.1.3.3-1
func buildSyntheticPDUSessionReleaseResponse(t *testing.T, amfID, ranID int64) []byte {
	t.Helper()
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePDUSessionResourceRelease},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentPDUSessionResourceReleaseResponse,
				PDUSessionResourceReleaseResponse: &ngapType.PDUSessionResourceReleaseResponse{
					ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceReleaseResponseIEs{
						List: []ngapType.PDUSessionResourceReleaseResponseIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PDUSessionResourceReleaseResponseIEsValue{
									Present:     ngapType.PDUSessionResourceReleaseResponseIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PDUSessionResourceReleaseResponseIEsValue{
									Present:     ngapType.PDUSessionResourceReleaseResponseIEsPresentRANUENGAPID,
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
		t.Fatalf("encode synthetic ReleaseResponse: %v", err)
	}
	return b
}
