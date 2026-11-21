package nrppa

// roundtrip_fuzz_test.go — native Go fuzz targets for the NRPPa codec (CI-003). Two properties:
//   - FuzzDecode: Decode never panics; a nil error implies a PDU of a known Type with its payload
//     set; when the PDU re-encodes, the encoding decodes to an equal value (nil and empty slices
//     are equal). The octets are not compared: every Encode* draws a fresh NRPPa transaction ID,
//     which NRPPaPDU does not carry.
//   - FuzzEncodeECIDReport: an E-CID Measurement Report built from fuzzed fields survives
//     Encode/Decode and the decoded report is a fixpoint. The AP position is checked for presence
//     only until LMF-011 fixes its quantisation (see knownGap).
// Ref: TS 38.455 §8.2.1, §8.2.4, §9.2; TS 23.032 §6 (point/ellipsoid quantisation).

import (
	"reflect"
	"testing"
)

func reportSeed() ECIDMeasurementReportMsg {
	return ECIDMeasurementReportMsg{
		LMFMeasurementID: 2, RANMeasurementID: 4,
		ServingNRCGI: NRCGI{CellID: [5]byte{0x00, 0x00, 0x00, 0x01, 0x00}},
		ServingTAC:   [3]byte{0x00, 0x00, 0x01},
		APPosition: &APPosition{Lat: 40.4168, Lon: -3.7038, AltitudeM: 650, UncertaintySemiMajorM: 100,
			UncertaintySemiMinorM: 80, OrientationDeg: 90, UncertaintyAltitudeM: 20, ConfidencePct: 68},
	}
}

func seedPDUs() [][]byte {
	plain := reportSeed()
	plain.APPosition = nil
	return [][]byte{
		EncodePosInfoReq(PositioningInformationRequest{}),
		EncodePosInfoRsp(PositioningInformationResponse{ECIDSupported: true}),
		EncodePosInfoRsp(PositioningInformationResponse{ECIDSupported: false}),
		EncodePosInfoFail(PositioningInformationFailure{Cause: 0}),
		EncodeECIDInitReq(ECIDMeasurementInitiationRequestMsg{LMFMeasurementID: 7, Quantities: QuantityRSRP}),
		EncodeECIDInitRsp(ECIDMeasurementInitiationResponseMsg{LMFMeasurementID: 3, RANMeasurementID: 5}),
		EncodeECIDInitFail(ECIDMeasurementInitiationFailureMsg{Cause: 0}),
		EncodeECIDReport(plain),
		EncodeECIDReport(reportSeed()),
	}
}

// reencode encodes p with the Encode* function its Type selects; nil when p has no encoding.
func reencode(p *NRPPaPDU) []byte {
	switch {
	case p.Type == MsgPositioningInformationRequest && p.MsgPosInfoReq != nil:
		return EncodePosInfoReq(*p.MsgPosInfoReq)
	case p.Type == MsgPositioningInformationResponse && p.MsgPosInfoRsp != nil:
		return EncodePosInfoRsp(*p.MsgPosInfoRsp)
	case p.Type == MsgPositioningInformationFailure && p.MsgPosInfoFail != nil:
		return EncodePosInfoFail(*p.MsgPosInfoFail)
	case p.Type == MsgECIDMeasurementInitiationRequest && p.MsgECIDInitReq != nil:
		return EncodeECIDInitReq(*p.MsgECIDInitReq)
	case p.Type == MsgECIDMeasurementInitiationResponse && p.MsgECIDInitRsp != nil:
		return EncodeECIDInitRsp(*p.MsgECIDInitRsp)
	case p.Type == MsgECIDMeasurementInitiationFailure && p.MsgECIDInitFail != nil:
		return EncodeECIDInitFail(*p.MsgECIDInitFail)
	case p.Type == MsgECIDMeasurementReport && p.MsgECIDReport != nil:
		return EncodeECIDReport(*p.MsgECIDReport)
	}
	return nil
}

func FuzzDecode(f *testing.F) {
	for _, s := range seedPDUs() {
		f.Add(s)
		f.Add(s[:len(s)/2])
	}
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Decode(append([]byte(nil), b...))
		if err != nil {
			return
		}
		if p == nil {
			t.Fatal("Decode: nil PDU with nil error")
		}
		if knownGap(p) {
			return
		}
		enc := reencode(p)
		if enc == nil {
			// A payload-less Type is a decoder bug; a value aper refuses to encode is out of domain.
			if p.Type < MsgPositioningInformationRequest || p.Type > MsgECIDMeasurementReport {
				t.Fatalf("Decode: unknown Type %d with nil error\n input %x", p.Type, b)
			}
			return
		}
		p2, err := Decode(enc)
		if err != nil {
			t.Fatalf("re-decode of the re-encoding failed: %v\n input %x\n enc   %x", err, b, enc)
		}
		if !sameValue(reflect.ValueOf(p), reflect.ValueOf(p2)) {
			t.Fatalf("value changed across encode/decode\n input %x\n enc   %x\n v1 %+v\n v2 %+v",
				b, enc, describe(p), describe(p2))
		}
	})
}

func FuzzEncodeECIDReport(f *testing.F) {
	s := reportSeed()
	p := s.APPosition
	f.Add(s.LMFMeasurementID, s.RANMeasurementID, s.ServingNRCGI.CellID[:], s.ServingTAC[:], true,
		p.Lat, p.Lon, p.AltitudeM, p.UncertaintySemiMajorM, p.UncertaintySemiMinorM, p.OrientationDeg,
		p.UncertaintyAltitudeM, p.ConfidencePct)
	f.Add(uint16(1), uint16(1), []byte{0, 0, 0, 0, 0}, []byte{0, 0, 0}, false,
		-90.0, 179.99, -100.0, 0.0, 0.0, 0.0, 0.0, uint8(0))
	f.Fuzz(func(t *testing.T, lmf, ran uint16, cell, tac []byte, hasAP bool,
		lat, lon, alt, smaj, smin, orient, ualt float64, conf uint8) {
		if lmf < 1 || lmf > 15 || ran < 1 || ran > 15 {
			return // LMF-011: IDs outside the root range 1..15 are clamped by measIDValue
		}
		m := ECIDMeasurementReportMsg{LMFMeasurementID: lmf, RANMeasurementID: ran}
		copy(m.ServingNRCGI.CellID[:], cell)
		m.ServingNRCGI.CellID[4] &= 0xF0 // NR Cell Identity is 36 bits (TS 38.455 §9.2.9): low nibble unused
		copy(m.ServingTAC[:], tac)
		if hasAP {
			m.APPosition = &APPosition{Lat: lat, Lon: lon, AltitudeM: alt, UncertaintySemiMajorM: smaj,
				UncertaintySemiMinorM: smin, OrientationDeg: orient, UncertaintyAltitudeM: ualt, ConfidencePct: conf}
		}
		enc := EncodeECIDReport(m)
		if enc == nil {
			return // out-of-range field values the encoder refuses (e.g. measurement IDs outside the ASN.1 range)
		}
		p1, err := Decode(enc)
		if err != nil || p1.MsgECIDReport == nil {
			t.Fatalf("Decode(EncodeECIDReport(m)) failed: %v\n m   %+v\n enc %x", err, m, enc)
		}
		got := p1.MsgECIDReport
		if got.LMFMeasurementID != m.LMFMeasurementID || got.RANMeasurementID != m.RANMeasurementID ||
			got.ServingNRCGI != m.ServingNRCGI || got.ServingTAC != m.ServingTAC ||
			(got.APPosition == nil) != (m.APPosition == nil) {
			t.Fatalf("report fields changed\n m   %+v\n got %+v", m, *got)
		}
		// The decoded report must be a fixpoint: encoding it decodes to it again. The AP position is
		// excluded until LMF-011 (quantisation is not a fixpoint, see knownGap).
		again := *got
		again.APPosition = nil
		p2, err := Decode(EncodeECIDReport(again))
		if err != nil || !sameValue(reflect.ValueOf(&again), reflect.ValueOf(p2.MsgECIDReport)) {
			t.Fatalf("quantised report is not a fixpoint (err %v)\n got  %+v\n got2 %+v", err, describe(p1), describe(p2))
		}
	})
}

// knownGap reports a decoded PDU in a gap tracked by LMF-011, which removes this function:
//   - a mandatory UE Measurement ID absent (decoded as 0, which measIDValue re-encodes as 1) or in
//     the extension range 16..256 (decoded, but measIDValue clamps it to 15);
//   - a Failure cause other than misc/unspecified: the uint8 Cause drops the cause group
//     (causeToByte) and EncodePosInfoFail / EncodeECIDInitFail always send misc/unspecified;
//   - an E-CID report with an AP position: toWire scales latitude by 2^23-1 and truncates toward
//     zero (TS 23.032 §6.1: 2^23 and floor), so the position drifts one step per re-encode, and
//     the decoder accepts confidence > 100.
func knownGap(p *NRPPaPDU) bool {
	if p.MsgECIDReport != nil && p.MsgECIDReport.APPosition != nil {
		return true
	}
	unspec := causeToByte(causeUnspecifiedMisc())
	if p.MsgPosInfoFail != nil && p.MsgPosInfoFail.Cause != unspec {
		return true
	}
	if p.MsgECIDInitFail != nil && p.MsgECIDInitFail.Cause != unspec {
		return true
	}
	zero := func(ids ...uint16) bool { // absent (0) or in the extension range (> 15, clamped by measIDValue)
		for _, id := range ids {
			if id == 0 || id > 15 {
				return true
			}
		}
		return false
	}
	switch {
	case p.MsgECIDInitReq != nil:
		return zero(p.MsgECIDInitReq.LMFMeasurementID)
	case p.MsgECIDInitRsp != nil:
		return zero(p.MsgECIDInitRsp.LMFMeasurementID, p.MsgECIDInitRsp.RANMeasurementID)
	case p.MsgECIDReport != nil:
		return zero(p.MsgECIDReport.LMFMeasurementID, p.MsgECIDReport.RANMeasurementID)
	}
	return false
}

// describe dereferences the payload pointers for failure messages.
func describe(p *NRPPaPDU) any {
	if p == nil {
		return nil
	}
	v := reflect.ValueOf(*p)
	out := map[string]any{"Type": p.Type}
	for i := 0; i < v.NumField(); i++ {
		if f := v.Field(i); f.Kind() == reflect.Pointer && !f.IsNil() {
			out[v.Type().Field(i).Name] = f.Elem().Interface()
		}
	}
	if p.MsgECIDReport != nil && p.MsgECIDReport.APPosition != nil {
		out["APPosition"] = *p.MsgECIDReport.APPosition
	}
	return out
}

// sameValue is reflect.DeepEqual except that a nil and an empty slice or map are equal.
func sameValue(a, b reflect.Value) bool {
	if !a.IsValid() || !b.IsValid() {
		return a.IsValid() == b.IsValid()
	}
	if a.Type() != b.Type() {
		return false
	}
	switch a.Kind() {
	case reflect.Slice, reflect.Array:
		if a.Len() != b.Len() {
			return false
		}
		for i := 0; i < a.Len(); i++ {
			if !sameValue(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Pointer, reflect.Interface:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return sameValue(a.Elem(), b.Elem())
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			if !sameValue(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	default:
		if a.CanInterface() && b.CanInterface() {
			return reflect.DeepEqual(a.Interface(), b.Interface())
		}
		return a.String() == b.String()
	}
}
