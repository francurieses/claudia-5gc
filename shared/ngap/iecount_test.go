package ngap

// iecount_test.go — the IE container count bound of Decoder (checkIEContainerCount): the
// amplification and truncation reproducers found by FuzzDecoder, and the proof that the count
// it reads is the one aper decodes, for every corpus vector and every message type.

import (
	"errors"
	"reflect"
	"runtime/metrics"
	"strings"
	"testing"

	"github.com/free5gc/aper"

	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// heapAllocs returns the cumulative heap bytes allocated by the process. runtime/metrics reads
// it without stopping the world (unlike runtime.ReadMemStats). Shared with fuzz_test.go.
func heapAllocs() uint64 {
	s := [1]metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}
	metrics.Read(s[:])
	return s[0].Value.Uint64()
}

// decodedIECount returns the length of the IE container of a decoded PDU's message.
func decodedIECount(t *testing.T, pdu *ngapType.NGAPPDU) int {
	t.Helper()
	var val reflect.Value
	switch pdu.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:
		val = reflect.ValueOf(pdu.InitiatingMessage.Value)
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		val = reflect.ValueOf(pdu.SuccessfulOutcome.Value)
	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		val = reflect.ValueOf(pdu.UnsuccessfulOutcome.Value)
	default:
		t.Fatalf("PDU alternative %d", pdu.Present)
	}
	p := int(val.Field(0).Int())
	if p <= 0 || val.Field(p).IsNil() {
		t.Fatalf("message value not populated (Present %d)", p)
	}
	return val.Field(p).Elem().Field(0).Field(0).Len()
}

// TestDecoderIEContainerAmplification pins the FuzzDecoder finding: 7-octet PDUs declaring
// 65535 IEs made aper allocate 65535 x item size before reading one IE (31.6 MB measured for
// InitialContextSetupRequest). Decoder now rejects them as a transfer syntax error (TS 38.413
// §10.2) without the allocation.
func TestDecoderIEContainerAmplification(t *testing.T) {
	for name, in := range map[string][]byte{
		"NGSetupRequest":             {0x00, 0x15, 0x00, 0x03, 0x00, 0xff, 0xff},
		"InitialContextSetupRequest": {0x00, 0x0e, 0x00, 0x03, 0x00, 0xff, 0xff},
		"HandoverRequest":            {0x00, 0x0d, 0x00, 0x03, 0x00, 0xff, 0xff},
		"NGSetupResponse":            {0x20, 0x15, 0x00, 0x03, 0x00, 0xff, 0xff},
		"two IEs in 8 octets":        {0x00, 0x15, 0x00, 0x04, 0x00, 0x00, 0x02, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			before := heapAllocs()
			_, err := Decoder(in)
			alloc := heapAllocs() - before
			if !errors.Is(err, ErrIEContainerCount) {
				t.Fatalf("Decoder(%x) err = %v, want ErrIEContainerCount", in, err)
			}
			if alloc > 1<<20 {
				t.Fatalf("Decoder(%x) allocated %d bytes, want < 1 MiB", in, alloc)
			}
		})
	}
}

// TestDecoderTruncatedIECount pins the second FuzzDecoder finding: a message value too short
// for the IE count. aper logs the count error and decodes an empty IE list, so a truncated PDU
// reached the AMF as a message without IEs (abstract syntax handling) instead of a transfer
// syntax error (TS 38.413 §10.2).
func TestDecoderTruncatedIECount(t *testing.T) {
	in := []byte{0x00, 0x15, 0x00, 0x01, 0x00} // NGSetupRequest, 1-octet value: no count
	var raw ngapType.NGAPPDU
	if err := aper.UnmarshalWithParams(in, &raw, pduParams); err != nil {
		t.Fatalf("aper behaviour changed (now rejects the truncated count: %v); the guard may be redundant", err)
	}
	if n := len(raw.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List); n != 0 {
		t.Fatalf("aper decoded %d IEs", n)
	}
	if _, err := Decoder(in); !errors.Is(err, ErrIEContainerCount) {
		t.Fatalf("Decoder err = %v, want ErrIEContainerCount", err)
	}
}

// TestIEContainerCountMatchesCorpus proves on every corpus PDU that the count the guard reads
// is the IE count aper decodes, and that the guard passes valid input.
func TestIEContainerCountMatchesCorpus(t *testing.T) {
	vecs, err := loadCorpus()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range vecs {
		if strings.HasPrefix(v.Name, "smf-") {
			continue
		}
		pdu, err := Decoder(v.Data)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		count, _, placed := ieContainerCount(v.Data)
		if !placed {
			t.Fatalf("%s: IE container not placed", v.Name)
		}
		if want := decodedIECount(t, pdu); count != want {
			t.Fatalf("%s: guard read %d IEs, aper decoded %d", v.Name, count, want)
		}
		n++
	}
	t.Logf("%d corpus PDUs checked", n)
}

// TestIEContainerLBCoversMessages fails when a message type of the generated NGAP-PDU is not
// in ieContainerLB (its struct shape changed), so the guard cannot silently stop applying.
func TestIEContainerLBCoversMessages(t *testing.T) {
	want := 0
	for _, vt := range []reflect.Type{
		reflect.TypeOf(ngapType.InitiatingMessageValue{}),
		reflect.TypeOf(ngapType.SuccessfulOutcomeValue{}),
		reflect.TypeOf(ngapType.UnsuccessfulOutcomeValue{}),
	} {
		want += vt.NumField() - 1 // minus Present
	}
	if len(ieContainerLB) != want {
		t.Fatalf("ieContainerLB has %d messages, the generated value types carry %d", len(ieContainerLB), want)
	}
}

// TestIEContainerCountEveryMessage encodes every message type with an empty IE container and
// checks that the guard places it at count 0 and Decoder accepts it.
func TestIEContainerCountEveryMessage(t *testing.T) {
	checked := 0
	for key, lb := range ieContainerLB {
		if lb != 0 {
			continue // PrivateMessage: SIZE (1..maxPrivateIEs), no empty encoding
		}
		var pdu ngapType.NGAPPDU
		var val reflect.Value
		switch key[0] {
		case 0:
			pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
			pdu.InitiatingMessage = &ngapType.InitiatingMessage{ProcedureCode: ngapType.ProcedureCode{Value: key[1]}}
			val = reflect.ValueOf(&pdu.InitiatingMessage.Value).Elem()
		case 1:
			pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
			pdu.SuccessfulOutcome = &ngapType.SuccessfulOutcome{ProcedureCode: ngapType.ProcedureCode{Value: key[1]}}
			val = reflect.ValueOf(&pdu.SuccessfulOutcome.Value).Elem()
		case 2:
			pdu.Present = ngapType.NGAPPDUPresentUnsuccessfulOutcome
			pdu.UnsuccessfulOutcome = &ngapType.UnsuccessfulOutcome{ProcedureCode: ngapType.ProcedureCode{Value: key[1]}}
			val = reflect.ValueOf(&pdu.UnsuccessfulOutcome.Value).Elem()
		}
		field := -1
		for i := 1; i < val.NumField(); i++ {
			if code, ok := aperTagInt(val.Type().Field(i).Tag.Get("aper"), "referenceFieldValue:"); ok && code == key[1] {
				field = i
			}
		}
		if field < 0 {
			t.Fatalf("%v: no message field", key)
		}
		val.Field(0).SetInt(int64(field))
		val.Field(field).Set(reflect.New(val.Field(field).Type().Elem()))
		b, err := Encoder(pdu)
		if err != nil {
			t.Fatalf("%v %s: encode: %v", key, val.Type().Field(field).Name, err)
		}
		if count, _, placed := ieContainerCount(b); !placed || count != 0 {
			t.Fatalf("%v %s: guard placed=%v count=%d on %x", key, val.Type().Field(field).Name, placed, count, b)
		}
		if _, err := Decoder(b); err != nil {
			t.Fatalf("%v %s: decode %x: %v", key, val.Type().Field(field).Name, b, err)
		}
		checked++
	}
	t.Logf("%d message types checked", checked)
}

// TestIEContainerCountFragmented covers the fragmented open-type length (a message value of
// 16384 octets or more): a DownlinkNASTransport with a 20000-octet NAS-PDU decodes, and the
// guard reads its 3 IEs.
func TestIEContainerCountFragmented(t *testing.T) {
	ies := []ngapType.DownlinkNASTransportIEs{
		{Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.DownlinkNASTransportIEsValue{Present: ngapType.DownlinkNASTransportIEsPresentAMFUENGAPID, AMFUENGAPID: &ngapType.AMFUENGAPID{Value: 1}}},
		{Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.DownlinkNASTransportIEsValue{Present: ngapType.DownlinkNASTransportIEsPresentRANUENGAPID, RANUENGAPID: &ngapType.RANUENGAPID{Value: 2}}},
		{Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNASPDU}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.DownlinkNASTransportIEsValue{Present: ngapType.DownlinkNASTransportIEsPresentNASPDU, NASPDU: &ngapType.NASPDU{Value: make(aper.OctetString, 20000)}}},
	}
	b, err := Encoder(ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeDownlinkNASTransport},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{
				Present:              ngapType.InitiatingMessagePresentDownlinkNASTransport,
				DownlinkNASTransport: &ngapType.DownlinkNASTransport{ProtocolIEs: ngapType.ProtocolIEContainerDownlinkNASTransportIEs{List: ies}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if b[3]&0xc0 != 0xc0 {
		t.Fatalf("open-type length octet %#x is not fragmented", b[3])
	}
	if count, _, placed := ieContainerCount(b); !placed || count != 3 {
		t.Fatalf("guard placed=%v count=%d, want 3", placed, count)
	}
	if _, err := Decoder(b); err != nil {
		t.Fatalf("decode: %v", err)
	}
}
