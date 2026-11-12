package ngap

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// TestRoundTripErrorIndication encodes a minimal ErrorIndication and decodes it back.
func TestRoundTripErrorIndication(t *testing.T) {
	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = &ngapType.InitiatingMessage{
		ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeErrorIndication},
		Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
		Value: ngapType.InitiatingMessageValue{
			Present:         ngapType.InitiatingMessagePresentErrorIndication,
			ErrorIndication: &ngapType.ErrorIndication{},
		},
	}
	b, err := Encoder(pdu)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decoder(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := Encoder(*got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatalf("round trip mismatch %x vs %x", b, b2)
	}
}

func TestDecoderError(t *testing.T) {
	if _, err := Decoder([]byte{0xff}); err == nil {
		t.Fatal("expected error")
	}
}
