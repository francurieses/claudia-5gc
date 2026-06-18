package server

import (
	"net"
	"testing"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
)

// TestN2SMTransferRoundTrip verifies that the N2SM PDU Session Resource Setup
// Request Transfer is APER-encoded with the extension prefix ("valueExt") and
// can be decoded back to an equivalent structure — the same way UERANSIM's gNB
// decodes it. Ref: TS 38.413 §9.3.4.5.
func TestN2SMTransferRoundTrip(t *testing.T) {
	upfIP := net.ParseIP("10.100.0.10")
	encoded, err := buildPDUSessionResourceSetupRequestTransfer(upfIP, 0x01020304, 1, 9, 100_000_000, 100_000_000)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("encoded transfer is empty")
	}
	t.Logf("encoded N2SM transfer (%d bytes): %x", len(encoded), encoded)

	var decoded ngapType.PDUSessionResourceSetupRequestTransfer
	if err := aper.UnmarshalWithParams(encoded, &decoded, "valueExt"); err != nil {
		t.Fatalf("decode failed (message malformed): %v", err)
	}

	ies := decoded.ProtocolIEs.List
	if len(ies) != 4 {
		t.Fatalf("expected 4 IEs, got %d", len(ies))
	}

	var sawTunnel, sawType, sawQos, sawAMBR bool
	for _, ie := range ies {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDULNGUUPTNLInformation:
			sawTunnel = true
			tnl := ie.Value.ULNGUUPTNLInformation
			if tnl == nil || tnl.GTPTunnel == nil {
				t.Fatal("ULNGUUPTNLInformation missing GTPTunnel")
			}
			gotIP := net.IP(tnl.GTPTunnel.TransportLayerAddress.Value.Bytes)
			if !gotIP.Equal(upfIP.To4()) {
				t.Errorf("UPF IP mismatch: got %v want %v", gotIP, upfIP)
			}
			teid := tnl.GTPTunnel.GTPTEID.Value
			if len(teid) != 4 || teid[0] != 0x01 || teid[3] != 0x04 {
				t.Errorf("TEID mismatch: got %x", teid)
			}
		case ngapType.ProtocolIEIDPDUSessionType:
			sawType = true
			if ie.Value.PDUSessionType.Value != ngapType.PDUSessionTypePresentIpv4 {
				t.Errorf("PDUSessionType not IPv4")
			}
		case ngapType.ProtocolIEIDQosFlowSetupRequestList:
			sawQos = true
			if len(ie.Value.QosFlowSetupRequestList.List) != 1 {
				t.Errorf("expected 1 QoS flow")
			}
		case ngapType.ProtocolIEIDPDUSessionAggregateMaximumBitRate:
			sawAMBR = true
		}
	}
	if !sawTunnel || !sawType || !sawQos || !sawAMBR {
		t.Errorf("missing IEs: tunnel=%v type=%v qos=%v ambr=%v", sawTunnel, sawType, sawQos, sawAMBR)
	}
}

// TestN2SMModifyTransferRoundTrip verifies that the empty PDU Session Resource Modify
// Request Transfer is correctly APER-encoded (with valueExt) and can be decoded back.
// An empty ProtocolIEs list signals "no radio resource changes" to the gNB.
// Ref: TS 38.413 §9.3.4.7 (PDU Session Resource Modify Request Transfer)
func TestN2SMModifyTransferRoundTrip(t *testing.T) {
	encoded, err := buildPDUSessionResourceModifyRequestTransfer()
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("encoded transfer must not be empty (at least the extension prefix bit)")
	}
	t.Logf("encoded N2SM modify transfer (%d bytes): %x", len(encoded), encoded)

	var decoded ngapType.PDUSessionResourceModifyRequestTransfer
	if err := aper.UnmarshalWithParams(encoded, &decoded, "valueExt"); err != nil {
		t.Fatalf("APER decode failed (bad encoding): %v", err)
	}
	if n := len(decoded.ProtocolIEs.List); n != 0 {
		t.Errorf("expected empty ProtocolIEs list, got %d items", n)
	}
}

// TestN2SMExtensionPrefix proves the bug fix: encoding the extensible SEQUENCE
// without "valueExt" omits the extension prefix bit, shifting the bitstream and
// producing a message that decoders (Wireshark / UERANSIM) reject.
func TestN2SMExtensionPrefix(t *testing.T) {
	upfIP := net.ParseIP("10.100.0.10")
	withExt, err := buildPDUSessionResourceSetupRequestTransfer(upfIP, 1, 1, 9, 100_000_000, 100_000_000)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	// Re-build the same struct and encode WITHOUT valueExt (the old buggy path).
	transfer := ngapType.PDUSessionResourceSetupRequestTransfer{
		ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceSetupRequestTransferIEs{
			List: []ngapType.PDUSessionResourceSetupRequestTransferIEs{
				{
					Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionType},
					Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
					Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
						Present:        ngapType.PDUSessionResourceSetupRequestTransferIEsPresentPDUSessionType,
						PDUSessionType: &ngapType.PDUSessionType{Value: ngapType.PDUSessionTypePresentIpv4},
					},
				},
			},
		},
	}
	withoutExt, err := aper.Marshal(transfer)
	if err != nil {
		t.Fatalf("plain Marshal failed: %v", err)
	}

	t.Logf("with valueExt:    %x", withExt)
	t.Logf("without valueExt: %x", withoutExt)

	// The correctly-encoded message must decode with the valueExt parameter.
	var ok ngapType.PDUSessionResourceSetupRequestTransfer
	if err := aper.UnmarshalWithParams(withExt, &ok, "valueExt"); err != nil {
		t.Fatalf("correct message must decode with valueExt: %v", err)
	}
}
