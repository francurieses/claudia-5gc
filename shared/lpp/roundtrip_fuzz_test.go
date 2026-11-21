package lpp

// roundtrip_fuzz_test.go — round-trip properties for the LPP UPER subset (CI-003).
//   - FuzzDecode: Decode never panics on arbitrary input; when it succeeds, rebuilding the message
//     with the Build* function its Type selects (same transaction ID and payload) decodes back to
//     the same Type, transaction ID and payload. EndTransaction and HasTransactionID are not
//     compared: the builders pin them per message type. ProvideCapabilities is compared on
//     AGNSSSupported only, the one input BuildProvideCapabilities takes.
//   - FuzzLatitude / FuzzLongitude: the TS 23.032 §6.1 quantisation is a fixpoint on the wire
//     value (Encode(Decode(raw)) == raw) and Decode(Encode(x)) is within one step below x.
//   - TestCodePhaseRMSErrorFixpoint: EncodeCodePhaseRMSError(DecodeCodePhaseRMSError(k)) == k.
// Ref: TS 37.355 §6.2, §6.5.2; TS 23.032 §6.1.

import (
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"testing"
)

// rebuild encodes p again with the builder for its Type; ok=false when p has no rebuildable payload.
func rebuild(p *PDU) ([]byte, bool, error) {
	txn := p.TransactionID
	switch p.Type {
	case MsgRequestCapabilities:
		b, err := BuildRequestCapabilities(txn)
		return b, true, err
	case MsgProvideCapabilities:
		if p.ProvideCapabilities == nil {
			return nil, false, nil
		}
		b, err := BuildProvideCapabilities(txn, p.ProvideCapabilities.AGNSSSupported)
		return b, true, err
	case MsgProvideAssistanceData:
		if p.AssistanceData == nil {
			return nil, false, nil
		}
		b, err := BuildProvideAssistanceData(txn, *p.AssistanceData)
		return b, true, err
	case MsgRequestLocationInformation:
		b, err := BuildRequestLocationInformation(txn)
		return b, true, err
	case MsgProvideLocationInformation:
		switch {
		case p.TargetDeviceErrorCause != nil && p.LocationMeasurements != nil:
			return nil, false, nil // both are optional in A-GNSS-ProvideLocationInformation; each builder emits one
		case p.TargetDeviceErrorCause != nil:
			b, err := BuildProvideLocationInformationError(txn, *p.TargetDeviceErrorCause)
			return b, true, err
		case p.LocationMeasurements != nil:
			b, err := BuildProvideLocationInformation(txn, *p.LocationMeasurements)
			return b, true, err
		}
	}
	return nil, false, nil
}

func FuzzDecode(f *testing.F) {
	for _, h := range []string{goldenHexRequestCapabilities, goldenHexProvideCapabilitiesGPS,
		goldenHexProvideCapabilitiesNone, goldenHexProvideAssistanceData, goldenHexRequestLocationInfo,
		goldenHexProvideLocationInfo, goldenHexProvideLocationInfoErr} {
		b, err := hex.DecodeString(h)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
		f.Add(b[:len(b)/2])
	}
	f.Add([]byte{})
	f.Add([]byte{0x90})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Decode(append([]byte(nil), b...))
		if err != nil {
			return
		}
		if p == nil {
			t.Fatal("Decode: nil PDU with nil error")
		}
		enc, ok, err := rebuild(p)
		if !ok || err != nil {
			return // no payload to rebuild, or a value the builder refuses (out of its domain)
		}
		p2, err := Decode(enc)
		if err != nil {
			t.Fatalf("re-decode of the rebuilt message failed: %v\n input %x\n enc   %x", err, b, enc)
		}
		if p.Type != p2.Type || p.TransactionID != p2.TransactionID {
			t.Fatalf("type/transaction changed: %d %+v -> %d %+v\n input %x\n enc   %x",
				p.Type, p.TransactionID, p2.Type, p2.TransactionID, b, enc)
		}
		if p.Type == MsgProvideCapabilities {
			if p.ProvideCapabilities.AGNSSSupported != p2.ProvideCapabilities.AGNSSSupported {
				t.Fatalf("AGNSSSupported changed\n input %x\n enc   %x", b, enc)
			}
			return
		}
		for _, pair := range [][2]any{
			{p.AssistanceData, p2.AssistanceData},
			{p.LocationMeasurements, p2.LocationMeasurements},
			{p.TargetDeviceErrorCause, p2.TargetDeviceErrorCause},
		} {
			if !reflect.DeepEqual(pair[0], pair[1]) {
				t.Fatalf("payload changed across rebuild/decode\n input %x\n enc   %x\n v1 %s\n v2 %s",
					b, enc, show(pair[0]), show(pair[1]))
			}
		}
	})
}

// show dereferences a payload pointer for failure messages.
func show(v any) string {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer && !rv.IsNil() {
		return fmt.Sprintf("&%+v", rv.Elem().Interface())
	}
	return fmt.Sprintf("%+v", v)
}

// latStep and lonStep are one quantisation step in degrees (TS 23.032 §6.1).
const (
	latStep = 90.0 / (1 << 23)
	lonStep = 360.0 / (1 << 24)
)

func FuzzLatitude(f *testing.F) {
	for _, x := range []float64{0, 40.4168, -33.8688, 90, -90, 89.99999, latStep, -latStep} {
		f.Add(x, uint32(0))
	}
	f.Add(0.0, uint32(8388607))
	f.Add(0.0, uint32(1))
	f.Fuzz(func(t *testing.T, x float64, raw uint32) {
		raw &= 0x7FFFFF
		for _, sign := range []uint8{0, 1} {
			if raw == 0 && sign == 1 {
				continue // -0 has no south encoding
			}
			if s2, r2 := EncodeLatitude(DecodeLatitude(sign, raw)); s2 != sign || r2 != raw {
				t.Fatalf("latitude is not a fixpoint: (%d,%d) -> %v -> (%d,%d)", sign, raw, DecodeLatitude(sign, raw), s2, r2)
			}
		}
		if math.IsNaN(x) || x < -90 || x > 90 {
			return
		}
		s, r := EncodeLatitude(x)
		got := DecodeLatitude(s, r)
		if math.Abs(got) > math.Abs(x)+1e-12 || math.Abs(x)-math.Abs(got) > latStep*(1+1e-9) { // ±90° clamps to 2^23-1: exactly one step
			t.Fatalf("latitude %v quantised to %v (sign %d raw %d): not within one step toward zero", x, got, s, r)
		}
	})
}

func FuzzLongitude(f *testing.F) {
	for _, x := range []float64{0, -3.7038, 151.2093, 180, -180, 179.99999, lonStep, -lonStep} {
		f.Add(x, int32(0))
	}
	f.Add(0.0, int32(8388607))
	f.Add(0.0, int32(-8388608))
	f.Add(0.0, int32(-172610))
	f.Fuzz(func(t *testing.T, x float64, raw int32) {
		raw = raw << 8 >> 8 // sign-extend to the 24-bit range
		if r2 := EncodeLongitude(DecodeLongitude(raw)); r2 != raw {
			t.Fatalf("longitude is not a fixpoint: %d -> %v -> %d", raw, DecodeLongitude(raw), r2)
		}
		if math.IsNaN(x) || x < -180 || x >= 180 {
			return
		}
		got := DecodeLongitude(EncodeLongitude(x))
		if got > x+1e-12 || x-got >= lonStep {
			t.Fatalf("longitude %v quantised to %v: not within one step below (floor)", x, got)
		}
	})
}

func TestCodePhaseRMSErrorFixpoint(t *testing.T) {
	for k := 0; k < 64; k++ {
		if got := EncodeCodePhaseRMSError(DecodeCodePhaseRMSError(uint8(k))); got != uint8(k) {
			t.Errorf("codePhaseRMSError k=%d -> %v m -> k=%d", k, DecodeCodePhaseRMSError(uint8(k)), got)
		}
	}
}
