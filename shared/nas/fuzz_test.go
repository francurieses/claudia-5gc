package nas

// fuzz_test.go — native Go fuzz targets (go test -fuzz) for every exported
// Decode* function in this package plus ParseIPCPFromEPCO. Property: a decoder
// must never panic on arbitrary input, and a nil error implies a non-nil
// result. TestFuzzTargetsCoverDecoders fails when a new Decode* is added
// without a matching Fuzz<Name> target.
// Ref: TS 24.501 §7.7.1 (unknown/truncated IEs), TS 24.007 §11.2.4.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// commonSeeds are generic malformed/edge inputs added to every target.
var commonSeeds = [][]byte{
	{},
	{0x00},
	{0x7E},
	{0x7E, 0x00},
	{0x7E, 0x00, 0x41},
	{0x7E, 0x00, 0x41, 0x79, 0x00}, // truncated TLV-E
	{0x7E, 0x00, 0x41, 0x01, 0x02, 0xFF, 0xFF, 0xFF, 0xFF}, // unknown IEIs
	{0x7E, 0x00, 0x4C, 0x00, 0x00, 0x00},
	{0x2E, 0x01, 0x01, 0xC1},
	{0x7E, 0x00, 0x67, 0x01, 0x00, 0x04, 0x2E, 0x01, 0x01, 0xC1},
	{0x7E, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7E, 0x00, 0x41}, // integrity-protected
	{0x78, 0xFF, 0xFF}, // TLV-E with huge length
	{0x7B, 0x00, 0x02, 0x80, 0x00},
	{0x01, 0x00, 0x0B, 0xF2, 0x01, 0x01, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01}, // SUCI-like
	{0xF2, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01},       // GUTI-like
	{0x01, 0x01, 0x01, 0x02, 0x01, 0x03},                                           // S-NSSAI list
	{0x04, 0x01, 0x00, 0x00, 0x01},
}

// fuzzDecoder registers common + extra seeds and runs fn on each input. fn
// reports property violations with t.Fatalf; a panic also fails the run.
func fuzzDecoder(f *testing.F, fn func(t *testing.T, b []byte), extra ...[]byte) {
	for _, s := range commonSeeds {
		f.Add(s)
	}
	for _, s := range extra {
		f.Add(s)
		f.Add(s[:len(s)/2]) // truncated variant
	}
	f.Fuzz(fn)
}

// mustEnc returns the encoded seed or aborts the test binary setup when the
// Encode call failed or produced nothing, so seeds never drop silently.
func mustEnc(tb testing.TB, name string, b []byte, err error) []byte {
	tb.Helper()
	if err != nil {
		tb.Fatalf("seed %s: encode error: %v", name, err)
	}
	if len(b) == 0 {
		tb.Fatalf("seed %s: encoded to an empty/nil buffer", name)
	}
	return b
}

// checkResult fails when a decoder returns a nil result together with a nil error.
func checkResult(t *testing.T, name string, err error, resultNil bool) {
	t.Helper()
	if err == nil && resultNil {
		t.Fatalf("%s: nil result with nil error", name)
	}
}

// encMsg builds a full NAS PDU through the top-level Encode.
func encMsg(tb testing.TB, name string, hdr Header, body interface{}) []byte {
	tb.Helper()
	b, err := Encode(&Message{Header: hdr, Body: body})
	return mustEnc(tb, name, b, err)
}

func plain5GMM(mt MessageType) Header {
	return Header{ExtendedProtocolDiscriminator: PDMobilityManagement, SecurityHeaderType: SecurityHeaderPlainNAS, MessageType: mt}
}

func seedMessages(tb testing.TB) [][]byte {
	tb.Helper()
	smc := &SecurityModeCommand{
		SelectedNASSecurityAlgorithms:  NASSecurityAlgorithms{CipheringAlgorithmID: 2, IntegrityAlgorithmID: 2},
		ReplayedUESecurityCapabilities: UESecurityCapability{EA0: true, EA2: true, IA0: true, IA2: true},
	}
	nssai := NSSAI{SNSSAIs: []SNSSAI{{SST: 1, SD: SDNotPresent}, {SST: 2, SD: 0x010203}}}
	out := [][]byte{
		seedOf(tb, "AuthenticationRequest")(EncodeAuthenticationRequest(&AuthenticationRequest{})),
		seedOf(tb, "IdentityRequest")(EncodeIdentityRequest(&IdentityRequest{})),
		seedOf(tb, "SecurityModeCommand")(EncodeSecurityModeCommand(smc)),
		seedOf(tb, "ConfigurationUpdateCommand")(EncodeConfigurationUpdateCommand(&ConfigurationUpdateCommand{FullNameForNetwork: "Claudia", AllowedNSSAI: &nssai})),
		seedOf(tb, "DeregistrationRequestNW")(EncodeDeregistrationRequestNW(&DeregistrationRequestNW{})),
		seedOf(tb, "RegistrationAccept")(EncodeRegistrationAccept(&RegistrationAccept{})),
		seedOf(tb, "NSSAAuthCommand")(EncodeNSSAAuthCommand(&NSSAAuthCommand{})),
		seedOf(tb, "NSSAAuthComplete")(EncodeNSSAAuthComplete(&NSSAAuthComplete{})),
		seedOf(tb, "NSSAAuthResult")(EncodeNSSAAuthResult(&NSSAAuthResult{})),
		mustEnc(tb, "EAPMessageTLVE", EncodeEAPMessageTLVE([]byte{0x01, 0x02, 0x00, 0x05, 0x01}), nil),
		mustEnc(tb, "PDUSessionAuthenticationCommandBody", EncodePDUSessionAuthenticationCommandBody([]byte{0x01, 0x01, 0x00, 0x04}), nil),
		mustEnc(tb, "PDUSessionAuthenticationCompleteBody", EncodePDUSessionAuthenticationCompleteBody([]byte{0x02, 0x01, 0x00, 0x04}), nil),
		mustEnc(tb, "PDUSessionAuthenticationResultBody", EncodePDUSessionAuthenticationResultBody([]byte{0x03, 0x01, 0x00, 0x04}), nil),
		mustEnc(tb, "TAIList", EncodeTAIList("001", "01", []uint32{1, 2}), nil),
		mustEnc(tb, "NSSAI", EncodeNSSAI(nssai), nil),
		mustEnc(tb, "UESecurityCapability", EncodeUESecurityCapability(UESecurityCapability{EA0: true, IA2: true}), nil),
		mustEnc(tb, "PCODNSIPv4", EncodePCODNSIPv4([]byte{8, 8, 8, 8}), nil),
		mustEnc(tb, "PCODNSMTUAndIPCP", EncodePCODNSMTUAndIPCP(1400, nil), nil),
	}
	// Empty-body messages: seed through the top-level Encode with the 3-octet header.
	out = append(out,
		encMsg(tb, "ConfigurationUpdateComplete", plain5GMM(MsgTypeConfigurationUpdateComplete), &ConfigurationUpdateComplete{}),
		encMsg(tb, "DeregistrationAcceptUE", plain5GMM(MsgTypeDeregistrationAcceptUE), &DeregistrationAcceptUE{}),
	)
	// Network Name: skip the 2-octet IEI+length prefix so the seed is the IE value.
	nn, err := EncodeNetworkName(0x43, "Claudia")
	out = append(out, mustEnc(tb, "NetworkName", nn, err)[2:])
	rej, err := EncodeRejectedNSSAI([]RejectedSNSSAI{{Cause: 1, SNSSAI: SNSSAI{SST: 1, SD: SDNotPresent}}, {Cause: 2, SNSSAI: SNSSAI{SST: 2, SD: 0x0A0B0C}}})
	out = append(out, mustEnc(tb, "RejectedNSSAI", rej, err))
	ext, err := EncodeExtendedRejectedNSSAI(ExtendedRejectedNSSAIFromList([]RejectedSNSSAI{{Cause: 1, SNSSAI: SNSSAI{SST: 1, SD: 0x010203}}}))
	out = append(out, mustEnc(tb, "ExtendedRejectedNSSAI", ext, err))
	return out
}

// topLevelSeeds are complete NAS PDUs for FuzzDecode: plain 5GMM, plain 5GSM
// and one security-protected (integrity) PDU wrapping an Identity Request.
func topLevelSeeds(tb testing.TB) [][]byte {
	tb.Helper()
	smc := &SecurityModeCommand{
		SelectedNASSecurityAlgorithms:  NASSecurityAlgorithms{CipheringAlgorithmID: 2, IntegrityAlgorithmID: 2},
		ReplayedUESecurityCapabilities: UESecurityCapability{EA0: true, EA2: true, IA0: true, IA2: true},
	}
	idReq := encMsg(tb, "IdentityRequest", plain5GMM(MsgTypeIdentityRequest), &IdentityRequest{})
	sm, err := EncodePDUSessionEstablishmentAccept(1, 1, 1, 1, net.IPv4(10, 0, 0, 2), "internet")
	return [][]byte{
		encMsg(tb, "AuthenticationRequest", plain5GMM(MsgTypeAuthenticationRequest), &AuthenticationRequest{}),
		encMsg(tb, "SecurityModeCommand", plain5GMM(MsgTypeSecurityModeCommand), smc),
		idReq,
		encMsg(tb, "RegistrationAccept", plain5GMM(MsgTypeRegistrationAccept), &RegistrationAccept{}),
		encMsg(tb, "ULNASTransport", plain5GMM(MsgTypeULNASTransport), &ULNASTransport{}),
		mustEnc(tb, "PDUSessionEstablishmentAccept (5GSM)", sm, err),
		// EPD | SHT=1 | MAC(4) | SN | inner plain PDU
		append([]byte{PDMobilityManagement, byte(SecurityHeaderIntegrityProtected), 0xDE, 0xAD, 0xBE, 0xEF, 0x07}, idReq...),
	}
}

func FuzzDecode(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		m, err := Decode(b)
		if err != nil {
			return
		}
		if m == nil {
			t.Fatal("Decode: nil result with nil error")
		}
		if m.Header.ExtendedProtocolDiscriminator != b[0] {
			t.Fatalf("EPD mismatch: got %#x want %#x", m.Header.ExtendedProtocolDiscriminator, b[0])
		}
		sht := SecurityHeaderType(b[1] & 0x0F)
		if m.Header.SecurityHeaderType != sht {
			t.Fatalf("security header type mismatch: got %d want %d", m.Header.SecurityHeaderType, sht)
		}
		wantMT := b[2] // plain: EPD | SHT | MT
		if sht != SecurityHeaderPlainNAS {
			wantMT = b[9] // protected: EPD | SHT | MAC(4) | SN | inner EPD | inner SHT | MT
			if m.Header.SequenceNumber != b[6] || !bytes.Equal(m.Header.MessageAuthenticationCode[:], b[2:6]) {
				t.Fatalf("MAC/SN mismatch for security-protected PDU")
			}
		}
		if m.Header.MessageType != MessageType(wantMT) {
			t.Fatalf("message type mismatch: got %#x want %#x", m.Header.MessageType, wantMT)
		}
	}, append(topLevelSeeds(f), seedMessages(f)...)...)
}

func FuzzDecodeAuthenticationRequest(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeAuthenticationRequest(b)
		checkResult(t, "DecodeAuthenticationRequest", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeAuthenticationResponse(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeAuthenticationResponse(b)
		checkResult(t, "DecodeAuthenticationResponse", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeAuthenticationFailure(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeAuthenticationFailure(b)
		checkResult(t, "DecodeAuthenticationFailure", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeIdentityRequest(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeIdentityRequest(b)
		checkResult(t, "DecodeIdentityRequest", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeIdentityResponse(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeIdentityResponse(b)
		checkResult(t, "DecodeIdentityResponse", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeSecurityModeCommand(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeSecurityModeCommand(b)
		checkResult(t, "DecodeSecurityModeCommand", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeSecurityModeReject(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeSecurityModeReject(b)
		checkResult(t, "DecodeSecurityModeReject", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeSecurityModeComplete(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeSecurityModeComplete(b)
		checkResult(t, "DecodeSecurityModeComplete", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeConfigurationUpdateCommand(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeConfigurationUpdateCommand(b)
		checkResult(t, "DecodeConfigurationUpdateCommand", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeServiceAreaListValue(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeServiceAreaListValue(b)
		checkResult(t, "DecodeServiceAreaListValue", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeConfigurationUpdateComplete(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeConfigurationUpdateComplete(b)
		checkResult(t, "DecodeConfigurationUpdateComplete", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeDeregistrationRequest(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeDeregistrationRequest(b)
		checkResult(t, "DecodeDeregistrationRequest", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeDeregistrationRequestNW(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeDeregistrationRequestNW(b)
		checkResult(t, "DecodeDeregistrationRequestNW", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeExtendedRejectedNSSAI(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeExtendedRejectedNSSAI(b)
		checkResult(t, "DecodeExtendedRejectedNSSAI", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeNetworkFeatureSupport(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeNetworkFeatureSupport(b)
		checkResult(t, "DecodeNetworkFeatureSupport", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeMobileIdentity(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeMobileIdentity(b)
		checkResult(t, "DecodeMobileIdentity", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeNSSAI(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		n, err := DecodeNSSAI(b)
		if err != nil {
			return
		}
		// decode -> encode -> decode must be stable. (Raw bytes are NOT compared:
		// an SD or mapped HPLMN SD of 0xFFFFFF re-encodes in the shorter form.)
		n2, err := DecodeNSSAI(EncodeNSSAI(n))
		if err != nil || !reflect.DeepEqual(n, n2) {
			t.Fatalf("NSSAI round-trip: %+v -> %+v (err=%v)", n, n2, err)
		}
	}, append(seedMessages(f),
		// TS 24.501 §9.11.2.8 mapped HPLMN forms (contents length 2, 5, 8).
		[]byte{2, 1, 2, 5, 1, 0, 0, 1, 3, 8, 1, 0xFF, 0xFF, 0xFF, 3, 0, 0, 7},
	)...)
}
func FuzzDecodeNASSecurityAlgorithms(f *testing.F) {
	for _, s := range []byte{0x00, 0x22, 0xFF, 0x0F, 0xF0} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b byte) {
		a := DecodeNASSecurityAlgorithms(b)
		if a.Encode() != b {
			t.Fatalf("round-trip mismatch: 0x%02X -> 0x%02X", b, a.Encode())
		}
	})
}
func FuzzDecodeUESecurityCapability(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		c, err := DecodeUESecurityCapability(b)
		if err != nil {
			return
		}
		// Raw is preserved verbatim for SMC replay, so encode must return the input.
		if got := EncodeUESecurityCapability(c); !bytes.Equal(got, b) {
			t.Fatalf("UE security capability replay mismatch: % X -> % X", b, got)
		}
	}, seedMessages(f)...)
}

// capabilityFuzzSeeds returns seed values for the 5GMM/5GSM capability fuzzers.
func capabilityFuzzSeeds() [][]byte {
	return [][]byte{{0x00}, {0x07}, {0x80, 0x80, 0x10}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}
}

func FuzzDecode5GMMCapability(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		c, err := Decode5GMMCapability(b)
		checkResult(t, "Decode5GMMCapability", err, c == nil)
		if err != nil {
			return
		}
		enc, err := Encode5GMMCapability(c)
		if err != nil || !bytes.Equal(enc, b) {
			t.Fatalf("Raw round trip: got %x err=%v want %x", enc, err, b)
		}
		c.Raw = nil // re-encode from the bit fields: must decode to the same bits
		enc, err = Encode5GMMCapability(c)
		if err != nil {
			t.Fatalf("encode from bits: %v", err)
		}
		c2, err := Decode5GMMCapability(enc)
		if err != nil {
			t.Fatalf("decode of re-encoded bits: %v", err)
		}
		c2.Raw = nil
		if !reflect.DeepEqual(c, c2) {
			t.Fatalf("bit fields changed: %+v vs %+v", c, c2)
		}
	}, capabilityFuzzSeeds()...)
}

func FuzzDecode5GSMCapability(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		c, err := Decode5GSMCapability(b)
		checkResult(t, "Decode5GSMCapability", err, c == nil)
		if err != nil {
			return
		}
		enc, err := Encode5GSMCapability(c)
		if err != nil || !bytes.Equal(enc, b) {
			t.Fatalf("Raw round trip: got %x err=%v want %x", enc, err, b)
		}
		c.Raw = nil
		enc, err = Encode5GSMCapability(c)
		if err != nil {
			t.Fatalf("encode from bits: %v", err)
		}
		c2, err := Decode5GSMCapability(enc)
		if err != nil {
			t.Fatalf("decode of re-encoded bits: %v", err)
		}
		c2.Raw = nil
		if !reflect.DeepEqual(c, c2) {
			t.Fatalf("bit fields changed: %+v vs %+v", c, c2)
		}
	}, capabilityFuzzSeeds()...)
}

func FuzzDecodeNetworkName(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		n, err := DecodeNetworkName(b)
		checkResult(t, "DecodeNetworkName", err, n == nil)
		if err != nil || n.Text == "" {
			return // EncodeNetworkName rejects empty text by design
		}
		// Only the Text is compared: coding scheme (GSM7 vs UCS-2), spare bits and
		// Add CI are chosen by the encoder, so the wire bytes legitimately differ.
		enc, err := EncodeNetworkName(0x43, n.Text)
		if err != nil {
			if len(n.Text) > 100 {
				return // legitimately too long for the single length octet
			}
			t.Fatalf("EncodeNetworkName(%q): %v", n.Text, err)
		}
		n2, err := DecodeNetworkName(enc[2:])
		if err != nil {
			t.Fatalf("network name re-decode of %q: %v", n.Text, err)
		}
		if n2.Text != n.Text {
			t.Fatalf("network name round-trip: %q -> %q", n.Text, n2.Text)
		}
	}, seedMessages(f)...)
}
func FuzzDecodeNSSAAuthCommand(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeNSSAAuthCommand(b)
		checkResult(t, "DecodeNSSAAuthCommand", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeNSSAAuthComplete(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeNSSAAuthComplete(b)
		checkResult(t, "DecodeNSSAAuthComplete", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeNSSAAuthResult(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeNSSAAuthResult(b)
		checkResult(t, "DecodeNSSAAuthResult", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodePDUSessionEstablishmentRequest(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodePDUSessionEstablishmentRequest(b)
		checkResult(t, "DecodePDUSessionEstablishmentRequest", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeRejectedNSSAI(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		l, err := DecodeRejectedNSSAI(b)
		if err != nil || len(l) > MaxRejectedSNSSAIs {
			return // the encoder caps the list at 8 entries (TS 24.501 §9.11.3.46)
		}
		enc, err := EncodeRejectedNSSAI(l)
		if err != nil {
			t.Fatalf("EncodeRejectedNSSAI(%+v): %v", l, err)
		}
		l2, err := DecodeRejectedNSSAI(enc)
		if err != nil || !reflect.DeepEqual(l, l2) {
			t.Fatalf("rejected NSSAI round-trip: %+v -> %+v (err=%v)", l, l2, err)
		}
	}, seedMessages(f)...)
}
func FuzzDecodeServiceRequest(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeServiceRequest(b)
		checkResult(t, "DecodeServiceRequest", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeServiceAccept(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeServiceAccept(b)
		checkResult(t, "DecodeServiceAccept", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodePDUSessionReactivationResultErrorCause(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodePDUSessionReactivationResultErrorCause(b)
		checkResult(t, "DecodePDUSessionReactivationResultErrorCause", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeRegistrationRequest(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeRegistrationRequest(b)
		checkResult(t, "DecodeRegistrationRequest", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodeRegistrationAccept(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeRegistrationAccept(b)
		checkResult(t, "DecodeRegistrationAccept", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzDecodePDUSessionAuthenticationCommandBody(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) { _, _ = DecodePDUSessionAuthenticationCommandBody(b) }, seedMessages(f)...)
}
func FuzzDecodePDUSessionAuthenticationCompleteBody(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) { _, _ = DecodePDUSessionAuthenticationCompleteBody(b) }, seedMessages(f)...)
}
func FuzzDecodePDUSessionAuthenticationResultBody(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) { _, _ = DecodePDUSessionAuthenticationResultBody(b) }, seedMessages(f)...)
}
func FuzzDecodeEAPMessageTLVE(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		eap, n, e := DecodeEAPMessageTLVE(b)
		if e == nil && (n < 0 || n > len(b) || len(eap) > len(b)) {
			t.Fatalf("DecodeEAPMessageTLVE: inconsistent consumed length n=%d eap=%d in=%d", n, len(eap), len(b))
		}
	}, seedMessages(f)...)
}
func FuzzDecodeULNASTransport(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) {
		r, e := DecodeULNASTransport(b)
		checkResult(t, "DecodeULNASTransport", e, r == nil)
	}, seedMessages(f)...)
}
func FuzzParseIPCPFromEPCO(f *testing.F) {
	fuzzDecoder(f, func(t *testing.T, b []byte) { _ = ParseIPCPFromEPCO(b) }, seedMessages(f)...)
}

// TestFuzzTargetsCoverDecoders fails if an exported Decode* function in a
// non-test file of this package has no Fuzz<Name> target in fuzz_test.go.
func TestFuzzTargetsCoverDecoders(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{"ParseIPCPFromEPCO": true}
	declared := map[string]bool{}
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
			switch {
			case fn == "fuzz_test.go" && strings.HasPrefix(fd.Name.Name, "Fuzz"):
				declared[fd.Name.Name] = true
			case !strings.HasSuffix(fn, "_test.go") && fd.Name.IsExported() && strings.HasPrefix(fd.Name.Name, "Decode"):
				required[fd.Name.Name] = true
			}
		}
	}
	if len(required) < 2 || len(declared) == 0 {
		t.Fatal("AST scan found no decoders or no Fuzz targets")
	}
	for name := range required {
		if !declared["Fuzz"+name] {
			t.Errorf("%s has no Fuzz%s target in fuzz_test.go", name, name)
		}
	}
}

// seedOf adapts mustEnc to Encode* functions returning ([]byte, error), since
// Go cannot mix a multi-value call with other arguments.
func seedOf(tb testing.TB, name string) func([]byte, error) []byte {
	return func(b []byte, err error) []byte { return mustEnc(tb, name, b, err) }
}
