package gentest

import (
	"reflect"
	"testing"

	"github.com/free5gc/aper"
)

// params are the aper parameters for the extensible top-level PDU CHOICE (two root alternatives).
const pduParams = "valueExt,valueLB:0,valueUB:1"

func roundTrip[T any](t *testing.T, v T, params string) T {
	t.Helper()
	b, err := aper.MarshalWithParams(v, params)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	var out T
	if err := aper.UnmarshalWithParams(b, &out, params); err != nil {
		t.Fatalf("unmarshal %T from %x: %v", v, b, err)
	}
	return out
}

func octets(b ...byte) *aper.OctetString { o := aper.OctetString(b); return &o }

// TestHelloRoundTrip exercises the generated containers, the open-type IE value
// (referenceFieldValue / referenceFieldName), CHOICE alternatives and primitives through aper.
func TestHelloRoundTrip(t *testing.T) {
	level := func(v int64) Level { return Level{Value: v} }
	pt := Pt{X: level(7), Y: &Level{Value: 9}, Weight: 5}
	pdu := SYNPDU{
		Present: SYNPDUPresentInitiatingMessage,
		InitiatingMessage: &InitiatingMessage{
			ProcedureCode: ProcedureCode{Value: ProcedureCodeHelloProc},
			Criticality:   Criticality{Value: aper.Enumerated(0)},
			Value: InitiatingMessageValue{
				Present: InitiatingMessagePresentHello,
				Hello: &Hello{ProtocolIEs: ProtocolIEContainerHelloIEs{List: []HelloIEs{
					{
						Id:          ProtocolIEID{Value: ProtocolIEIDLevel},
						Criticality: Criticality{Value: aper.Enumerated(0)},
						Value:       HelloIEsValue{Present: HelloIEsPresentLevel, Level: &Level{Value: 200}},
					},
					{
						Id:          ProtocolIEID{Value: ProtocolIEIDShape},
						Criticality: Criticality{Value: aper.Enumerated(1)},
						Value: HelloIEsValue{Present: HelloIEsPresentShape, Shape: &Shape{
							Present: ShapePresentDot, Dot: &pt,
						}},
					},
					{
						Id:          ProtocolIEID{Value: ProtocolIEIDBlob},
						Criticality: Criticality{Value: aper.Enumerated(1)},
						Value:       HelloIEsValue{Present: HelloIEsPresentBlob, Blob: octets(1, 2, 3)},
					},
					{
						Id:          ProtocolIEID{Value: ProtocolIEIDLabel},
						Criticality: Criticality{Value: aper.Enumerated(1)},
						Value:       HelloIEsValue{Present: HelloIEsPresentLabel, Label: &Label{Value: aper.OctetString("héllo")}},
					},
					{
						Id:          ProtocolIEID{Value: ProtocolIEIDUrl},
						Criticality: Criticality{Value: aper.Enumerated(1)},
						Value:       HelloIEsValue{Present: HelloIEsPresentUrl, Url: &Url{Value: aper.OctetString("a_b@c")}},
					},
				}}},
			},
		},
	}
	got := roundTrip(t, pdu, pduParams)
	if got.Present != SYNPDUPresentInitiatingMessage {
		t.Fatalf("present = %d", got.Present)
	}
	ies := got.InitiatingMessage.Value.Hello.ProtocolIEs.List
	if len(ies) != 5 {
		t.Fatalf("decoded %d IEs, want 5", len(ies))
	}
	if ies[0].Value.Level.Value != 200 {
		t.Errorf("Level = %d", ies[0].Value.Level.Value)
	}
	if p := ies[1].Value.Shape.Dot; p == nil || p.X.Value != 7 || p.Y == nil || p.Y.Value != 9 || p.Weight != 5 {
		t.Errorf("Shape.Dot = %+v", p)
	}
	if !reflect.DeepEqual(*ies[2].Value.Blob, aper.OctetString{1, 2, 3}) {
		t.Errorf("Blob = %v", *ies[2].Value.Blob)
	}
	if string(ies[3].Value.Label.Value) != "héllo" {
		t.Errorf("Label = %q (UTF8String must not carry a PER-visible size constraint)", ies[3].Value.Label.Value)
	}
	if string(ies[4].Value.Url.Value) != "a_b@c" {
		t.Errorf("Url = %q (VisibleString outside the PrintableString alphabet)", ies[4].Value.Url.Value)
	}
}

// TestChoiceAlternatives round-trips each Shape alternative, including NULL and BIT STRING.
func TestChoiceAlternatives(t *testing.T) {
	tests := []struct {
		name  string
		shape Shape
	}{
		{"name", Shape{Present: ShapePresentName, Name: &Name{Value: "abc"}}},
		{"raw", Shape{Present: ShapePresentRaw, Raw: octets(0xAA, 0xBB)}},
		{"tag", Shape{Present: ShapePresentTag, Tag: &Tag{Value: aper.BitString{Bytes: []byte{0xFF, 0xC0}, BitLength: 10}}}},
		{"null", Shape{Present: ShapePresentEmpty, Empty: &Null{}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ie := HelloIEs{
				Id:          ProtocolIEID{Value: ProtocolIEIDShape},
				Criticality: Criticality{Value: 1},
				Value:       HelloIEsValue{Present: HelloIEsPresentShape, Shape: &tc.shape},
			}
			got := roundTrip(t, Hello{ProtocolIEs: ProtocolIEContainerHelloIEs{List: []HelloIEs{ie}}}, "valueExt")
			g := got.ProtocolIEs.List[0].Value.Shape
			if g == nil || g.Present != tc.shape.Present {
				t.Fatalf("decoded shape = %+v, want present %d", g, tc.shape.Present)
			}
			if !reflect.DeepEqual(g, &tc.shape) {
				t.Errorf("round trip changed value: got %+v want %+v", g, &tc.shape)
			}
		})
	}
}

// TestExtensionContainer covers ProtocolExtensionContainer instantiation (open type with id).
func TestExtensionContainer(t *testing.T) {
	pt := Pt{
		X: Level{Value: 1}, Weight: 5,
		IEExtensions: &ProtocolExtensionContainerPtExtIEs{List: []PtExtIEs{{
			Id:             ProtocolExtensionID{Value: ProtocolExtensionIDExtraLevel},
			Criticality:    Criticality{Value: 1},
			ExtensionValue: PtExtIEsExtensionValue{Present: PtExtIEsPresentExtraLevel, ExtraLevel: &Level{Value: 42}},
		}}},
	}
	got := roundTrip(t, pt, "valueExt")
	if got.IEExtensions == nil || got.IEExtensions.List[0].ExtensionValue.ExtraLevel.Value != 42 {
		t.Fatalf("extension lost: %+v", got.IEExtensions)
	}
}

// TestEnumAndInteger covers ENUMERATED root/extension and the union-collapsed INTEGER range.
func TestEnumAndInteger(t *testing.T) {
	if got := roundTrip(t, Color{Value: ColorPresentBlue}, ""); got.Value != ColorPresentBlue {
		t.Errorf("Color = %d", got.Value)
	}
	if got := roundTrip(t, Period{Value: 40}, ""); got.Value != 40 {
		t.Errorf("Period = %d", got.Value)
	}
}
