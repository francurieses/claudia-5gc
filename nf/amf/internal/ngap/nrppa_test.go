package ngap

// nrppa_test.go — unit tests for the NGAP NRPPa Transport codec functions
// (BuildDownlinkUEAssociatedNRPPaTransport, BuildDownlinkNonUEAssociatedNRPPaTransport,
// extractUplinkUEAssociatedNRPPaTransport, extractUplinkNonUEAssociatedNRPPaTransport).
//
// Ref: TS 38.413 §8.17.3 (UE-associated NRPPa Transport),
//
//	TS 38.413 §8.17.4 (Non-UE-associated NRPPa Transport).

import (
	"testing"

	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// testNRPPaPDU is an arbitrary opaque NRPPa payload used across tests.
// The content is irrelevant (AMF is a pure relay); only the byte boundary matters.
var testNRPPaPDU = []byte{0x01, 0x00, 0x01, 0xBE, 0xEF}

// testRoutingID is an arbitrary LMF routing identity.
var testRoutingID = []byte{0x00, 0x01}

// ---- TestBuildDownlinkUEAssociatedNRPPaTransport -------------------------

// TestBuildDownlinkUEAssociatedNRPPaTransport verifies that the builder produces
// a valid NGAP PDU that:
//   - re-decodes without error via the free5gc library,
//   - is an InitiatingMessage with ProcedureCode=8,
//   - carries AMF-UE-NGAP-ID=42, RAN-UE-NGAP-ID=7, RoutingID, and NRPPa-PDU.
//
// Ref: TS 38.413 §8.17.3; ProcedureCodeDownlinkUEAssociatedNRPPaTransport=8.
func TestBuildDownlinkUEAssociatedNRPPaTransport(t *testing.T) {
	const amfID int64 = 42
	const ranID int64 = 7

	encoded := BuildDownlinkUEAssociatedNRPPaTransport(amfID, ranID, testNRPPaPDU, testRoutingID)
	if len(encoded) == 0 {
		t.Fatal("BuildDownlinkUEAssociatedNRPPaTransport returned nil/empty PDU")
	}

	decoded, err := libngap.Decoder(encoded)
	if err != nil {
		t.Fatalf("libngap.Decoder: %v", err)
	}
	if decoded.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatalf("expected InitiatingMessage, got %d", decoded.Present)
	}
	im := decoded.InitiatingMessage
	if im.ProcedureCode.Value != ngapType.ProcedureCodeDownlinkUEAssociatedNRPPaTransport {
		t.Fatalf("ProcedureCode = %d, want %d (DownlinkUEAssociatedNRPPaTransport)",
			im.ProcedureCode.Value, ngapType.ProcedureCodeDownlinkUEAssociatedNRPPaTransport)
	}
	msg := im.Value.DownlinkUEAssociatedNRPPaTransport
	if msg == nil {
		t.Fatal("DownlinkUEAssociatedNRPPaTransport body is nil in decoded PDU")
	}

	var sawAMFID, sawRANID, sawRoutingID, sawNRPPaPDU bool
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.DownlinkUEAssociatedNRPPaTransportIEsPresentAMFUENGAPID:
			if ie.Value.AMFUENGAPID == nil {
				t.Fatal("AMFUENGAPID is nil")
			}
			if ie.Value.AMFUENGAPID.Value != amfID {
				t.Errorf("AMF-UE-NGAP-ID = %d, want %d", ie.Value.AMFUENGAPID.Value, amfID)
			}
			sawAMFID = true
		case ngapType.DownlinkUEAssociatedNRPPaTransportIEsPresentRANUENGAPID:
			if ie.Value.RANUENGAPID == nil {
				t.Fatal("RANUENGAPID is nil")
			}
			if ie.Value.RANUENGAPID.Value != ranID {
				t.Errorf("RAN-UE-NGAP-ID = %d, want %d", ie.Value.RANUENGAPID.Value, ranID)
			}
			sawRANID = true
		case ngapType.DownlinkUEAssociatedNRPPaTransportIEsPresentRoutingID:
			if ie.Value.RoutingID == nil {
				t.Fatal("RoutingID IE is nil")
			}
			if string(ie.Value.RoutingID.Value) != string(testRoutingID) {
				t.Errorf("RoutingID = %v, want %v", ie.Value.RoutingID.Value, testRoutingID)
			}
			sawRoutingID = true
		case ngapType.DownlinkUEAssociatedNRPPaTransportIEsPresentNRPPaPDU:
			if ie.Value.NRPPaPDU == nil {
				t.Fatal("NRPPaPDU IE is nil")
			}
			if string(ie.Value.NRPPaPDU.Value) != string(testNRPPaPDU) {
				t.Errorf("NRPPaPDU = %v, want %v", ie.Value.NRPPaPDU.Value, testNRPPaPDU)
			}
			sawNRPPaPDU = true
		}
	}

	for _, pair := range []struct {
		name string
		got  bool
	}{
		{"AMF-UE-NGAP-ID", sawAMFID},
		{"RAN-UE-NGAP-ID", sawRANID},
		{"RoutingID", sawRoutingID},
		{"NRPPa-PDU", sawNRPPaPDU},
	} {
		if !pair.got {
			t.Errorf("IE %s not found in PDU", pair.name)
		}
	}
}

// TestBuildDownlinkUEAssociatedNRPPaTransport_NoRoutingID verifies that the
// RoutingID IE is omitted when routingID is nil, which is valid per TS 38.413 §8.17.3.
func TestBuildDownlinkUEAssociatedNRPPaTransport_NoRoutingID(t *testing.T) {
	encoded := BuildDownlinkUEAssociatedNRPPaTransport(1, 2, testNRPPaPDU, nil)
	if len(encoded) == 0 {
		t.Fatal("nil routingID should produce a valid PDU")
	}
	decoded, err := libngap.Decoder(encoded)
	if err != nil {
		t.Fatalf("Decoder: %v", err)
	}
	msg := decoded.InitiatingMessage.Value.DownlinkUEAssociatedNRPPaTransport
	var sawRoutingID bool
	for _, ie := range msg.ProtocolIEs.List {
		if ie.Value.Present == ngapType.DownlinkUEAssociatedNRPPaTransportIEsPresentRoutingID {
			sawRoutingID = true
		}
	}
	if sawRoutingID {
		t.Error("RoutingID IE present when routingID was nil")
	}
}

// ---- TestBuildDownlinkNonUEAssociatedNRPPaTransport ----------------------

// TestBuildDownlinkNonUEAssociatedNRPPaTransport verifies that the builder produces
// a valid NGAP PDU with ProcedureCode=5 and the correct NRPPa-PDU payload.
//
// Ref: TS 38.413 §8.17.4; ProcedureCodeDownlinkNonUEAssociatedNRPPaTransport=5.
func TestBuildDownlinkNonUEAssociatedNRPPaTransport(t *testing.T) {
	encoded := BuildDownlinkNonUEAssociatedNRPPaTransport(testNRPPaPDU, testRoutingID)
	if len(encoded) == 0 {
		t.Fatal("BuildDownlinkNonUEAssociatedNRPPaTransport returned nil/empty PDU")
	}
	decoded, err := libngap.Decoder(encoded)
	if err != nil {
		t.Fatalf("Decoder: %v", err)
	}
	if decoded.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatalf("expected InitiatingMessage, got %d", decoded.Present)
	}
	im := decoded.InitiatingMessage
	if im.ProcedureCode.Value != ngapType.ProcedureCodeDownlinkNonUEAssociatedNRPPaTransport {
		t.Fatalf("ProcedureCode = %d, want %d (DownlinkNonUEAssociatedNRPPaTransport)",
			im.ProcedureCode.Value, ngapType.ProcedureCodeDownlinkNonUEAssociatedNRPPaTransport)
	}
	msg := im.Value.DownlinkNonUEAssociatedNRPPaTransport
	if msg == nil {
		t.Fatal("DownlinkNonUEAssociatedNRPPaTransport body is nil")
	}
	var sawNRPPaPDU bool
	for _, ie := range msg.ProtocolIEs.List {
		if ie.Value.Present == ngapType.DownlinkNonUEAssociatedNRPPaTransportIEsPresentNRPPaPDU {
			if string(ie.Value.NRPPaPDU.Value) != string(testNRPPaPDU) {
				t.Errorf("NRPPaPDU content mismatch")
			}
			sawNRPPaPDU = true
		}
	}
	if !sawNRPPaPDU {
		t.Error("NRPPa-PDU IE not found in DownlinkNonUEAssociatedNRPPaTransport")
	}
}

// ---- TestExtractUplinkUEAssociatedNRPPaTransport -------------------------

// TestExtractUplinkUEAssociatedNRPPaTransport verifies that
// extractUplinkUEAssociatedNRPPaTransport correctly extracts all four IEs.
//
// This test builds a raw UplinkUEAssociatedNRPPaTransport PDU using the free5gc
// ngapType structs (simulating what a UERANSIM gNB would send) and then verifies
// that our extractor populates UplinkUEAssociatedNRPPaTransportMsg correctly.
//
// Ref: TS 38.413 §8.17.3; ProcedureCodeUplinkUEAssociatedNRPPaTransport=50.
func TestExtractUplinkUEAssociatedNRPPaTransport(t *testing.T) {
	const amfID int64 = 100
	const ranID int64 = 200

	// Build a raw UL NRPPa Transport PDU using free5gc types (simulates gNB send).
	ul := &ngapType.UplinkUEAssociatedNRPPaTransport{}
	ul.ProtocolIEs.List = append(ul.ProtocolIEs.List,
		ngapType.UplinkUEAssociatedNRPPaTransportIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.UplinkUEAssociatedNRPPaTransportIEsValue{
				Present:     ngapType.UplinkUEAssociatedNRPPaTransportIEsPresentAMFUENGAPID,
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfID},
			},
		},
		ngapType.UplinkUEAssociatedNRPPaTransportIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.UplinkUEAssociatedNRPPaTransportIEsValue{
				Present:     ngapType.UplinkUEAssociatedNRPPaTransportIEsPresentRANUENGAPID,
				RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
			},
		},
		ngapType.UplinkUEAssociatedNRPPaTransportIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRoutingID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.UplinkUEAssociatedNRPPaTransportIEsValue{
				Present:   ngapType.UplinkUEAssociatedNRPPaTransportIEsPresentRoutingID,
				RoutingID: &ngapType.RoutingID{Value: testRoutingID},
			},
		},
		ngapType.UplinkUEAssociatedNRPPaTransportIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNRPPaPDU},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.UplinkUEAssociatedNRPPaTransportIEsValue{
				Present:  ngapType.UplinkUEAssociatedNRPPaTransportIEsPresentNRPPaPDU,
				NRPPaPDU: &ngapType.NRPPaPDU{Value: testNRPPaPDU},
			},
		},
	)

	out := extractUplinkUEAssociatedNRPPaTransport(ul)
	if out.AMFUENGAPId != amfID {
		t.Errorf("AMFUENGAPId = %d, want %d", out.AMFUENGAPId, amfID)
	}
	if out.RANUENGAPId != ranID {
		t.Errorf("RANUENGAPId = %d, want %d", out.RANUENGAPId, ranID)
	}
	if string(out.RoutingID) != string(testRoutingID) {
		t.Errorf("RoutingID = %v, want %v", out.RoutingID, testRoutingID)
	}
	if string(out.NRPPaPDU) != string(testNRPPaPDU) {
		t.Errorf("NRPPaPDU content mismatch")
	}
}

// ---- TestExtractUplinkNonUEAssociatedNRPPaTransport ----------------------

// TestExtractUplinkNonUEAssociatedNRPPaTransport verifies extraction of
// RoutingID and NRPPa-PDU from a non-UE-associated UL NRPPa Transport.
//
// Ref: TS 38.413 §8.17.4; ProcedureCodeUplinkNonUEAssociatedNRPPaTransport=47.
func TestExtractUplinkNonUEAssociatedNRPPaTransport(t *testing.T) {
	ul := &ngapType.UplinkNonUEAssociatedNRPPaTransport{}
	ul.ProtocolIEs.List = append(ul.ProtocolIEs.List,
		ngapType.UplinkNonUEAssociatedNRPPaTransportIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRoutingID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.UplinkNonUEAssociatedNRPPaTransportIEsValue{
				Present:   ngapType.UplinkNonUEAssociatedNRPPaTransportIEsPresentRoutingID,
				RoutingID: &ngapType.RoutingID{Value: testRoutingID},
			},
		},
		ngapType.UplinkNonUEAssociatedNRPPaTransportIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNRPPaPDU},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.UplinkNonUEAssociatedNRPPaTransportIEsValue{
				Present:  ngapType.UplinkNonUEAssociatedNRPPaTransportIEsPresentNRPPaPDU,
				NRPPaPDU: &ngapType.NRPPaPDU{Value: testNRPPaPDU},
			},
		},
	)

	out := extractUplinkNonUEAssociatedNRPPaTransport(ul)
	if string(out.RoutingID) != string(testRoutingID) {
		t.Errorf("RoutingID = %v, want %v", out.RoutingID, testRoutingID)
	}
	if string(out.NRPPaPDU) != string(testNRPPaPDU) {
		t.Errorf("NRPPaPDU content mismatch")
	}
}

// ---- TestDecodeNGAPPDU_UplinkNRPPaTransport --------------------------------

// TestDecodeNGAPPDU_UplinkNRPPaTransport verifies the full round-trip:
// Build a DL NRPPa Transport, encode it, decode it via DecodeNGAPPDU (our internal
// path), and verify that the message type and proc code are correct.
//
// (The test uses DL here since UL PDUs come from the gNB; we test the DL→DecodeNGAPPDU
// path to confirm the proc-code constants align with the buildMessage dispatch table.)
//
// Ref: TS 38.413 §8.17.3; proc codes 8 (DL-UE) and 50 (UL-UE) per free5gc ngapType.
func TestDecodeNGAPPDU_NRPPaProcCodes(t *testing.T) {
	// DL UE-associated (ProcCode=8)
	pdu := BuildDownlinkUEAssociatedNRPPaTransport(1, 2, testNRPPaPDU, nil)
	if len(pdu) == 0 {
		t.Fatal("DL UE NRPPa builder failed")
	}
	msg, err := DecodeNGAPPDU(pdu)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU (DL-UE): %v", err)
	}
	if msg.ProcedureCode != ProcDownlinkUEAssociatedNRPPaTransport {
		t.Errorf("DL-UE proc code = %d, want %d", msg.ProcedureCode, ProcDownlinkUEAssociatedNRPPaTransport)
	}

	// DL non-UE-associated (ProcCode=5)
	pdu2 := BuildDownlinkNonUEAssociatedNRPPaTransport(testNRPPaPDU, nil)
	if len(pdu2) == 0 {
		t.Fatal("DL non-UE NRPPa builder failed")
	}
	msg2, err := DecodeNGAPPDU(pdu2)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU (DL-NonUE): %v", err)
	}
	if msg2.ProcedureCode != ProcDownlinkNonUEAssociatedNRPPaTransport {
		t.Errorf("DL-NonUE proc code = %d, want %d", msg2.ProcedureCode, ProcDownlinkNonUEAssociatedNRPPaTransport)
	}
}

// TestNRPPaProcedureCodes confirms the NGAP procedure code constants match
// TS 38.413 Table 9.1-1 and the free5gc ngapType values.
// This is an invariant guard: if the constants drift the tests above will still pass
// (free5gc uses int64, we use ProcedureCode = uint8) but the dispatch table would break.
//
// Ref: TS 38.413 Table 9.1-1; free5gc ngap@v1.1.3 ngapType/ProcedureCode.go.
func TestNRPPaProcedureCodes(t *testing.T) {
	tests := []struct {
		name string
		got  ProcedureCode
		want ProcedureCode
	}{
		{"DownlinkNonUEAssociated", ProcDownlinkNonUEAssociatedNRPPaTransport, 5},
		{"DownlinkUEAssociated", ProcDownlinkUEAssociatedNRPPaTransport, 8},
		{"UplinkNonUEAssociated", ProcUplinkNonUEAssociatedNRPPaTransport, 47},
		{"UplinkUEAssociated", ProcUplinkUEAssociatedNRPPaTransport, 50},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s: ProcedureCode = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}
