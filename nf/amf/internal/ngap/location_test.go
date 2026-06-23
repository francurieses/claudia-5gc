package ngap

// location_test.go — unit tests for the NGAP LocationReportingControl builder and
// LocationReport decoder used by the Namf_Location (Cell-ID positioning) procedure.
//
// Ref: TS 38.413 §8.17.1; TS 23.273 §7.2; TS 29.518 §5.2.2.6.

import (
	"testing"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// TestBuildLocationReportingControl verifies that BuildLocationReportingControl
// produces a valid NGAP PDU that:
//   - re-decodes without error,
//   - is an InitiatingMessage with ProcedureCode=16,
//   - carries AMF-UE-NGAP-ID=42, RAN-UE-NGAP-ID=7,
//   - LocationReportingRequestType with EventType=Direct(0), ReportArea=Cell(0).
//
// Ref: TS 38.413 §8.17.1; ProcedureCodeLocationReportingControl=16.
func TestBuildLocationReportingControl(t *testing.T) {
	const amfID int64 = 42
	const ranID int64 = 7

	pdu := BuildLocationReportingControl(amfID, ranID)
	if len(pdu) == 0 {
		t.Fatal("BuildLocationReportingControl returned nil/empty PDU")
	}

	decoded, err := libngap.Decoder(pdu)
	if err != nil {
		t.Fatalf("re-decode failed: %v", err)
	}
	if decoded.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatalf("expected InitiatingMessage, got %d", decoded.Present)
	}
	im := decoded.InitiatingMessage
	if im.ProcedureCode.Value != ngapType.ProcedureCodeLocationReportingControl {
		t.Fatalf("ProcedureCode = %d, want %d (LocationReportingControl)",
			im.ProcedureCode.Value, ngapType.ProcedureCodeLocationReportingControl)
	}
	if im.Value.LocationReportingControl == nil {
		t.Fatal("LocationReportingControl is nil in decoded PDU")
	}

	var sawAMFID, sawRANID, sawReqType bool
	for _, ie := range im.Value.LocationReportingControl.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.LocationReportingControlIEsPresentAMFUENGAPID:
			if ie.Value.AMFUENGAPID == nil {
				t.Fatal("AMFUENGAPID is nil")
			}
			if ie.Value.AMFUENGAPID.Value != amfID {
				t.Errorf("AMF-UE-NGAP-ID = %d, want %d", ie.Value.AMFUENGAPID.Value, amfID)
			}
			sawAMFID = true
		case ngapType.LocationReportingControlIEsPresentRANUENGAPID:
			if ie.Value.RANUENGAPID == nil {
				t.Fatal("RANUENGAPID is nil")
			}
			if ie.Value.RANUENGAPID.Value != ranID {
				t.Errorf("RAN-UE-NGAP-ID = %d, want %d", ie.Value.RANUENGAPID.Value, ranID)
			}
			sawRANID = true
		case ngapType.LocationReportingControlIEsPresentLocationReportingRequestType:
			rt := ie.Value.LocationReportingRequestType
			if rt == nil {
				t.Fatal("LocationReportingRequestType is nil")
			}
			if rt.EventType.Value != ngapType.EventTypePresentDirect {
				t.Errorf("EventType = %v, want Direct(0)", rt.EventType.Value)
			}
			if rt.ReportArea.Value != ngapType.ReportAreaPresentCell {
				t.Errorf("ReportArea = %v, want Cell(0)", rt.ReportArea.Value)
			}
			sawReqType = true
		}
	}
	if !sawAMFID || !sawRANID || !sawReqType {
		t.Errorf("missing IEs: sawAMFID=%v sawRANID=%v sawReqType=%v",
			sawAMFID, sawRANID, sawReqType)
	}
}

// TestExtractLocationReport_HappyPath verifies that extractLocationReport decodes
// a hand-built LocationReport PDU and returns the expected NRCGI hex string and TAI.
//
// Ref: TS 38.413 §8.17.1 (LocationReport IEs 10, 85, 121).
func TestExtractLocationReport_HappyPath(t *testing.T) {
	// Build a synthetic LocationReport PDU using the free5gc ngapType library.
	// We set:
	//   AMF-UE-NGAP-ID = 42
	//   RAN-UE-NGAP-ID = 7
	//   UserLocationInformation → UserLocationInformationNR:
	//     NRCGI: PLMN=001/01, NRCellIdentity=1 (36-bit, value 0x000000001)
	//     TAI:   PLMN=001/01, TAC=0x000001
	plmn := plmnFromMCCMNC("001", "01")
	tac := []byte{0x00, 0x00, 0x01}

	// NRCellIdentity is 36 bits: pack value=1 into 5 bytes (big-endian, MSB-first).
	// 36 bits = 4 full bytes + 4 MSBs of the 5th byte.
	// value 1 = 0x000000001 in 36 bits → bytes: 00 00 00 00 10 (last nibble upper)
	// Actually: pack value into high bits of 5-byte array, then BitLength=36.
	// Shift left (8*5 - 36) = 4 bits: 0x01 << 4 = 0x10 in last byte.
	nrCellIDBytes := []byte{0x00, 0x00, 0x00, 0x00, 0x10}

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeLocationReport},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentLocationReport,
				LocationReport: &ngapType.LocationReport{
					ProtocolIEs: ngapType.ProtocolIEContainerLocationReportIEs{
						List: []ngapType.LocationReportIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.LocationReportIEsValue{
									Present:     ngapType.LocationReportIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: 42},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.LocationReportIEsValue{
									Present:     ngapType.LocationReportIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: 7},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUserLocationInformation},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.LocationReportIEsValue{
									Present: ngapType.LocationReportIEsPresentUserLocationInformation,
									UserLocationInformation: &ngapType.UserLocationInformation{
										Present: ngapType.UserLocationInformationPresentUserLocationInformationNR,
										UserLocationInformationNR: &ngapType.UserLocationInformationNR{
											NRCGI: ngapType.NRCGI{
												PLMNIdentity: ngapType.PLMNIdentity{Value: aper.OctetString(plmn)},
												NRCellIdentity: ngapType.NRCellIdentity{
													Value: aper.BitString{
														Bytes:     nrCellIDBytes,
														BitLength: 36,
													},
												},
											},
											TAI: ngapType.TAI{
												PLMNIdentity: ngapType.PLMNIdentity{Value: aper.OctetString(plmn)},
												TAC:          ngapType.TAC{Value: aper.OctetString(tac)},
											},
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

	raw, err := libngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode LocationReport: %v", err)
	}

	msg, err := DecodeNGAPPDU(raw)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU: %v", err)
	}
	if msg.ProcedureCode != ProcLocationReport {
		t.Fatalf("ProcedureCode = %d, want %d (ProcLocationReport)",
			msg.ProcedureCode, ProcLocationReport)
	}

	rep, ok := msg.Value.(*LocationReportMsg)
	if !ok || rep == nil {
		t.Fatal("Value is not *LocationReportMsg")
	}
	if rep.AMFUENGAPId != 42 {
		t.Errorf("AMFUENGAPId = %d, want 42", rep.AMFUENGAPId)
	}
	if rep.RANUENGAPId != 7 {
		t.Errorf("RANUENGAPId = %d, want 7", rep.RANUENGAPId)
	}
	// nrCellIDBytes with BitLength=36 → value 1 → hex "000000001"
	if rep.NRCellID != "000000001" {
		t.Errorf("NRCellID = %q, want \"000000001\"", rep.NRCellID)
	}
	if rep.TAI == nil {
		t.Fatal("TAI is nil")
	}
	if rep.TAI.MCC != "001" {
		t.Errorf("TAI.MCC = %q, want \"001\"", rep.TAI.MCC)
	}
	if rep.TAI.TAC != 1 {
		t.Errorf("TAI.TAC = %d, want 1", rep.TAI.TAC)
	}
}

// TestNRCellIdentityToHex checks the hex rendering helper for known inputs.
// Ref: TS 38.413 §9.3.1.x (NRCellIdentity, 36-bit BIT STRING).
func TestNRCellIdentityToHex(t *testing.T) {
	cases := []struct {
		bytes   []byte
		bitLen  uint64
		wantHex string
	}{
		// Value=1: packed as 00 00 00 00 10 (36 bits, last nibble = 0x10 meaning 1<<4)
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x10}, 36, "000000001"},
		// Value=0: all zeros
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00}, 36, "000000000"},
		// Value=0xFFFFFFFFF (all 36 bits set): bytes = 0xFF,0xFF,0xFF,0xFF,0xF0
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xF0}, 36, "fffffffff"},
	}
	for _, tc := range cases {
		got := nrCellIdentityToHex(tc.bytes, tc.bitLen)
		if got != tc.wantHex {
			t.Errorf("nrCellIdentityToHex(%x, %d) = %q, want %q",
				tc.bytes, tc.bitLen, got, tc.wantHex)
		}
	}
}
