package ngap

// initial_context_setup_test.go — codec round-trip tests for InitialContextSetupRequest.
// Ref: TS 38.413 §8.3.1, §9.3.1.27 (IndexToRFSP)

import (
	"testing"

	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

var testSecKey [32]byte

func buildTestICSR(rfsp int) []byte {
	return BuildInitialContextSetupRequest(
		1, 2,
		[]byte{0x01, 0x02},
		testSecKey,
		0x8000, 0x8000,
		"001", "01",
		0x80, 1, 0x01,
		[]amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}},
		rfsp,
	)
}

func TestBuildInitialContextSetupRequest_WithRFSP(t *testing.T) {
	raw := buildTestICSR(1)
	if raw == nil {
		t.Fatal("encoder returned nil")
	}

	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("NGAP decode failed: %v", err)
	}
	if pdu.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatal("expected InitiatingMessage")
	}
	req := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	if req == nil {
		t.Fatal("InitialContextSetupRequest is nil")
	}

	var foundRFSP bool
	for _, ie := range req.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDIndexToRFSP {
			foundRFSP = true
			rfspVal := ie.Value.IndexToRFSP
			if rfspVal == nil {
				t.Fatal("IndexToRFSP IE value is nil")
			}
			if rfspVal.Value != 1 {
				t.Fatalf("expected RFSP=1, got %d", rfspVal.Value)
			}
		}
	}
	if !foundRFSP {
		t.Fatal("IndexToRFSP IE (id=31) not found in InitialContextSetupRequest")
	}
}

func TestBuildInitialContextSetupRequest_NoRFSP(t *testing.T) {
	raw := buildTestICSR(0) // rfsp=0 → IE must be absent
	if raw == nil {
		t.Fatal("encoder returned nil")
	}

	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("NGAP decode failed: %v", err)
	}
	req := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	for _, ie := range req.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDIndexToRFSP {
			t.Fatal("IndexToRFSP IE should be absent when rfsp=0")
		}
	}
}

func TestBuildInitialContextSetupRequest_RFSP256(t *testing.T) {
	raw := buildTestICSR(256) // max value per TS 38.413 §9.3.1.27
	if raw == nil {
		t.Fatal("encoder returned nil")
	}
	pdu, _ := libngap.Decoder(raw)
	req := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	for _, ie := range req.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDIndexToRFSP {
			if ie.Value.IndexToRFSP.Value != 256 {
				t.Fatalf("expected 256, got %d", ie.Value.IndexToRFSP.Value)
			}
			return
		}
	}
	t.Fatal("IndexToRFSP IE not found for rfsp=256")
}
