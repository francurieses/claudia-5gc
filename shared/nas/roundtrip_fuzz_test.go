package nas

// roundtrip_fuzz_test.go — round-trip properties for every Encode*/Decode* pair in this package
// (CI-003). fuzz_test.go only proves that decoders do not panic; here, for any input a decoder
// accepts, the decoded value v1 must re-encode, the encoding must re-decode to a value equal to v1
// (nil and empty slices compare equal), and re-encoding that value must give the same octets.
// A field the decoder fills but the encoder drops therefore fails, as does an encoder that
// emits octets its own decoder rejects. TestRoundTripCoversEncoders fails when an Encode*
// with a Decode* counterpart has no FuzzRoundTrip<Name> target and no entry in roundTripExempt.
// Ref: TS 24.501 §9 (message and IE coding), §11.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// roundTripExempt lists Encode*/Decode* pairs that are not inverse by design, with the reason.
var roundTripExempt = map[string]string{
	// The top-level pair is covered by FuzzRoundTripMessage on plain PDUs only: Encode builds plain
	// NAS, security-protected PDUs are produced by the NAS security layer, not by Encode.
}

// roundTrip runs the property for one codec pair. dec/enc wrap the typed functions.
func roundTrip(t *testing.T, name string, in []byte, dec func([]byte) (any, error), enc func(any) ([]byte, error)) {
	t.Helper()
	v1, err := dec(bytes.Clone(in))
	if err != nil {
		return
	}
	b1, err := enc(v1)
	if err != nil {
		// The encoders validate what the network may send (e.g. <= 8 rejected S-NSSAIs, a valid PLMN,
		// back-off timers only with cause #62); decoders are lenient receivers (TS 24.501 §7). A value
		// the encoder refuses is out of the property's domain — same rule as shared/ngap checkFixpoint.
		return
	}
	v2, err := dec(bytes.Clone(b1))
	if err != nil {
		t.Fatalf("%s: re-decode of the encoding failed: %v\n input %x\n enc   %x", name, err, in, b1)
	}
	if !sameValue(reflect.ValueOf(v1), reflect.ValueOf(v2)) {
		t.Fatalf("%s: value changed across encode/decode\n input %x\n enc   %x\n%s", name, in, b1, diffFields(v1, v2))
	}
	b2, err := enc(v2)
	if err != nil || !bytes.Equal(b1, b2) {
		t.Fatalf("%s: encoding is not a fixpoint (err %v)\n enc  %x\n enc2 %x", name, err, b1, b2)
	}
}

// diffFields names the top-level fields that differ (one level below a pointer), for triage.
func diffFields(v1, v2 any) string {
	a, b := reflect.Indirect(reflect.ValueOf(v1)), reflect.Indirect(reflect.ValueOf(v2))
	if a.Kind() == reflect.Struct && b.Kind() == reflect.Struct && a.Type() == b.Type() {
		var sb strings.Builder
		for i := 0; i < a.NumField(); i++ {
			if !sameValue(a.Field(i), b.Field(i)) {
				fmt.Fprintf(&sb, " field %s: %s -> %s\n", a.Type().Field(i).Name, show(a.Field(i)), show(b.Field(i)))
			}
		}
		return sb.String()
	}
	return fmt.Sprintf(" v1 %#v\n v2 %#v\n", v1, v2)
}

func show(v reflect.Value) string {
	if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && !v.IsNil() {
		return fmt.Sprintf("&%+v", v.Elem())
	}
	return fmt.Sprintf("%+v", v)
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
	case reflect.Slice:
		if a.Len() != b.Len() {
			return false
		}
		for i := 0; i < a.Len(); i++ {
			if !sameValue(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Map:
		if a.Len() != b.Len() {
			return false
		}
		for _, k := range a.MapKeys() {
			if !sameValue(a.MapIndex(k), b.MapIndex(k)) {
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
	case reflect.Array:
		for i := 0; i < a.Len(); i++ {
			if !sameValue(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	default:
		if a.CanInterface() && b.CanInterface() {
			return reflect.DeepEqual(a.Interface(), b.Interface())
		}
		return a.String() == b.String() // unexported scalar: compare its printed form
	}
}

// ptrPair adapts the common shape Encode(*T) ([]byte, error) / Decode([]byte) (*T, error).
func ptrPair[T any](dec func([]byte) (*T, error), enc func(*T) ([]byte, error)) (func([]byte) (any, error), func(any) ([]byte, error)) {
	return func(b []byte) (any, error) {
			v, err := dec(b)
			if err != nil || v == nil {
				return nil, errNil(err)
			}
			return v, nil
		}, func(v any) ([]byte, error) {
			return enc(v.(*T))
		}
}

type nilResult struct{}

func (nilResult) Error() string { return "nil result" }

func errNil(err error) error {
	if err != nil {
		return err
	}
	return nilResult{}
}

func fuzzRoundTrip(f *testing.F, name string, dec func([]byte) (any, error), enc func(any) ([]byte, error)) {
	fuzzDecoder(f, func(t *testing.T, b []byte) { roundTrip(t, name, b, dec, enc) }, seedMessages(f)...)
}

func FuzzRoundTripAuthenticationRequest(f *testing.F) {
	d, e := ptrPair(DecodeAuthenticationRequest, EncodeAuthenticationRequest)
	fuzzRoundTrip(f, "AuthenticationRequest", d, e)
}
func FuzzRoundTripIdentityRequest(f *testing.F) {
	d, e := ptrPair(DecodeIdentityRequest, EncodeIdentityRequest)
	fuzzRoundTrip(f, "IdentityRequest", d, e)
}
func FuzzRoundTripSecurityModeCommand(f *testing.F) {
	d, e := ptrPair(DecodeSecurityModeCommand, EncodeSecurityModeCommand)
	fuzzRoundTrip(f, "SecurityModeCommand", d, e)
}
func FuzzRoundTrip5GMMCapability(f *testing.F) {
	d, e := ptrPair(Decode5GMMCapability, Encode5GMMCapability)
	fuzzRoundTrip(f, "5GMMCapability", d, e)
}
func FuzzRoundTrip5GSMCapability(f *testing.F) {
	d, e := ptrPair(Decode5GSMCapability, Encode5GSMCapability)
	fuzzRoundTrip(f, "5GSMCapability", d, e)
}
func FuzzRoundTripConfigurationUpdateCommand(f *testing.F) {
	d, e := ptrPair(DecodeConfigurationUpdateCommand, EncodeConfigurationUpdateCommand)
	fuzzRoundTrip(f, "ConfigurationUpdateCommand", d, e)
}
func FuzzRoundTripConfigurationUpdateComplete(f *testing.F) {
	d, e := ptrPair(DecodeConfigurationUpdateComplete, EncodeConfigurationUpdateComplete)
	fuzzRoundTrip(f, "ConfigurationUpdateComplete", d, e)
}
func FuzzRoundTripExtendedRejectedNSSAI(f *testing.F) {
	d, e := ptrPair(DecodeExtendedRejectedNSSAI, EncodeExtendedRejectedNSSAI)
	fuzzRoundTrip(f, "ExtendedRejectedNSSAI", d, e)
}
func FuzzRoundTripDeregistrationRequestNW(f *testing.F) {
	d, e := ptrPair(DecodeDeregistrationRequestNW, EncodeDeregistrationRequestNW)
	fuzzRoundTrip(f, "DeregistrationRequestNW", d, e)
}
func FuzzRoundTripNSSAAuthCommand(f *testing.F) {
	d, e := ptrPair(DecodeNSSAAuthCommand, EncodeNSSAAuthCommand)
	fuzzRoundTrip(f, "NSSAAuthCommand", d, e)
}
func FuzzRoundTripNSSAAuthComplete(f *testing.F) {
	d, e := ptrPair(DecodeNSSAAuthComplete, EncodeNSSAAuthComplete)
	fuzzRoundTrip(f, "NSSAAuthComplete", d, e)
}
func FuzzRoundTripNSSAAuthResult(f *testing.F) {
	d, e := ptrPair(DecodeNSSAAuthResult, EncodeNSSAAuthResult)
	fuzzRoundTrip(f, "NSSAAuthResult", d, e)
}
func FuzzRoundTripRegistrationAccept(f *testing.F) {
	d, e := ptrPair(DecodeRegistrationAccept, EncodeRegistrationAccept)
	fuzzRoundTrip(f, "RegistrationAccept", d, e)
}
func FuzzRoundTripServiceAccept(f *testing.F) {
	d, e := ptrPair(DecodeServiceAccept, EncodeServiceAccept)
	fuzzRoundTrip(f, "ServiceAccept", d, e)
}
func FuzzRoundTripServiceAreaListValue(f *testing.F) {
	d, e := ptrPair(DecodeServiceAreaListValue, EncodeServiceAreaListValue)
	fuzzRoundTrip(f, "ServiceAreaListValue", d, e)
}
func FuzzRoundTripULNASTransport(f *testing.F) {
	d, e := ptrPair(DecodeULNASTransport, EncodeULNASTransport)
	fuzzRoundTrip(f, "ULNASTransport", d, e)
}

func FuzzRoundTripNSSAI(f *testing.F) {
	fuzzRoundTrip(f, "NSSAI",
		func(b []byte) (any, error) { return DecodeNSSAI(b) },
		func(v any) ([]byte, error) { return EncodeNSSAI(v.(NSSAI)), nil })
}
func FuzzRoundTripUESecurityCapability(f *testing.F) {
	fuzzRoundTrip(f, "UESecurityCapability",
		func(b []byte) (any, error) { return DecodeUESecurityCapability(b) },
		func(v any) ([]byte, error) { return EncodeUESecurityCapability(v.(UESecurityCapability)), nil })
}
func FuzzRoundTripRejectedNSSAI(f *testing.F) {
	fuzzRoundTrip(f, "RejectedNSSAI",
		func(b []byte) (any, error) { return DecodeRejectedNSSAI(b) },
		func(v any) ([]byte, error) { return EncodeRejectedNSSAI(v.([]RejectedSNSSAI)) })
}
func FuzzRoundTripPDUSessionReactivationResultErrorCause(f *testing.F) {
	fuzzRoundTrip(f, "PDUSessionReactivationResultErrorCause",
		func(b []byte) (any, error) { return DecodePDUSessionReactivationResultErrorCause(b) },
		func(v any) ([]byte, error) {
			// Encode returns the full TLV-E (IEI + 2-octet length); Decode takes the value only.
			ie := EncodePDUSessionReactivationResultErrorCause(v.([]PDUSessionErrorCause))
			if len(ie) < 3 {
				return nil, nilResult{}
			}
			return ie[3:], nil
		})
}
func FuzzRoundTripPDUSessionAuthenticationCommandBody(f *testing.F) {
	fuzzRoundTrip(f, "PDUSessionAuthenticationCommandBody",
		func(b []byte) (any, error) { return DecodePDUSessionAuthenticationCommandBody(b) },
		func(v any) ([]byte, error) { return EncodePDUSessionAuthenticationCommandBody(v.([]byte)), nil })
}
func FuzzRoundTripPDUSessionAuthenticationCompleteBody(f *testing.F) {
	fuzzRoundTrip(f, "PDUSessionAuthenticationCompleteBody",
		func(b []byte) (any, error) { return DecodePDUSessionAuthenticationCompleteBody(b) },
		func(v any) ([]byte, error) { return EncodePDUSessionAuthenticationCompleteBody(v.([]byte)), nil })
}
func FuzzRoundTripPDUSessionAuthenticationResultBody(f *testing.F) {
	fuzzRoundTrip(f, "PDUSessionAuthenticationResultBody",
		func(b []byte) (any, error) { return DecodePDUSessionAuthenticationResultBody(b) },
		func(v any) ([]byte, error) { return EncodePDUSessionAuthenticationResultBody(v.([]byte)), nil })
}
func FuzzRoundTripEAPMessageTLVE(f *testing.F) {
	fuzzRoundTrip(f, "EAPMessageTLVE",
		func(b []byte) (any, error) {
			eap, n, err := DecodeEAPMessageTLVE(b)
			if err != nil {
				return nil, err
			}
			_ = n
			return eap, nil
		},
		func(v any) ([]byte, error) { return EncodeEAPMessageTLVE(v.([]byte)), nil })
}

// FuzzRoundTripMessage covers the top-level Encode/Decode pair on plain PDUs.
func FuzzRoundTripMessage(f *testing.F) {
	dec := func(b []byte) (any, error) {
		m, err := Decode(b)
		if err != nil || m == nil {
			return nil, errNil(err)
		}
		if m.Header.SecurityHeaderType != SecurityHeaderPlainNAS {
			return nil, nilResult{} // protected PDUs are built by the security layer, not Encode
		}
		// Encode covers the messages the network sends; UE-originated types (Registration Request,
		// Service Request, ...) are decode-only by design.
		if _, err := Encode(m); err != nil && strings.Contains(err.Error(), "encode not implemented") {
			return nil, nilResult{}
		}
		return m, nil
	}
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		roundTrip(t, "Message", b, dec, func(v any) ([]byte, error) { return Encode(v.(*Message)) })
	}, append(topLevelSeeds(f), seedMessages(f)...)...)
}

// FuzzRoundTripNetworkName is the encode-side property: any text EncodeNetworkName accepts
// decodes back to the same text (the coding scheme is chosen by the encoder).
func FuzzRoundTripNetworkName(f *testing.F) {
	for _, s := range []string{"", "Claudia", "ClaudIA 5GC", "a@b_c", "0123456789"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if !utf8.ValidString(text) {
			return // the encoder maps invalid UTF-8 to U+FFFD; the property is for real text
		}
		b, err := EncodeNetworkName(0x43, text)
		if err != nil {
			return
		}
		if len(b) < 2 {
			t.Fatalf("EncodeNetworkName(%q) = %x: shorter than IEI+length", text, b)
		}
		nn, err := DecodeNetworkName(b[2:])
		if err != nil {
			t.Fatalf("DecodeNetworkName of EncodeNetworkName(%q) = %x failed: %v", text, b, err)
		}
		if nn.Text != text {
			t.Fatalf("NetworkName round trip: got %q want %q (enc %x)", nn.Text, text, b)
		}
	})
}

// TestRoundTripCoversEncoders fails when an exported Encode<X> with a Decode<X> counterpart has
// no FuzzRoundTrip<X> target here and no roundTripExempt entry.
func TestRoundTripCoversEncoders(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	enc, dec, fz := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, fn := range files {
		af, err := parser.ParseFile(fset, fn, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", fn, err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil {
				continue
			}
			n := fd.Name.Name
			switch {
			case fn == "roundtrip_fuzz_test.go" && strings.HasPrefix(n, "FuzzRoundTrip"):
				fz[strings.TrimPrefix(n, "FuzzRoundTrip")] = true
			case strings.HasSuffix(fn, "_test.go") || !fd.Name.IsExported():
			case strings.HasPrefix(n, "Encode"):
				enc[strings.TrimPrefix(n, "Encode")] = true
			case strings.HasPrefix(n, "Decode"):
				dec[strings.TrimPrefix(n, "Decode")] = true
			}
		}
	}
	pairs := 0
	for x := range enc {
		key := x
		if x == "" {
			key = "Message"
		}
		if !dec[x] {
			continue
		}
		pairs++
		if !fz[key] && roundTripExempt[key] == "" {
			t.Errorf("Encode%s/Decode%s has no FuzzRoundTrip%s target in roundtrip_fuzz_test.go (or a roundTripExempt reason)", x, x, key)
		}
	}
	if pairs < 10 {
		t.Fatalf("AST scan found only %d Encode/Decode pairs", pairs)
	}
}
