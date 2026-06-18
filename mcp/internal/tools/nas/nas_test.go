package nas

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
)

// args marshals a map into the json.RawMessage shape Invoke expects.
func args(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	return b
}

// asMCPErr asserts err is an *mcperr.Error with the expected code.
func asMCPErr(t *testing.T, err error, wantCode int) *mcperr.Error {
	t.Helper()
	e, ok := err.(*mcperr.Error)
	if !ok {
		t.Fatalf("want *mcperr.Error, got %T (%v)", err, err)
	}
	if e.Code != wantCode {
		t.Fatalf("error code: got %d, want %d (%s)", e.Code, wantCode, e.Message)
	}
	return e
}

// Minimal RegistrationRequest from shared/nas tests: 7e 00 41 | 11 00 01 00.
const regReqHex = "7e004111000100"

func TestDecode(t *testing.T) {
	tests := []struct {
		name    string
		hex     string
		wantErr int // 0 = success
		check   func(t *testing.T, r DecodeResult)
	}{
		{
			name: "valid registration request",
			hex:  regReqHex,
			check: func(t *testing.T, r DecodeResult) {
				if r.MessageTypeName != "RegistrationRequest" {
					t.Errorf("name: got %q", r.MessageTypeName)
				}
				if r.ProtocolDiscriminator != "5GMM" {
					t.Errorf("pd: got %q", r.ProtocolDiscriminator)
				}
				if r.RawBodyHex != "11000100" {
					t.Errorf("raw_body_hex: got %q", r.RawBodyHex)
				}
				if r.SpecRef == "" {
					t.Error("spec_ref empty")
				}
			},
		},
		{name: "too short", hex: "7e00", wantErr: mcperr.CodeToolError},
		{name: "invalid hex", hex: "zzzz", wantErr: mcperr.CodeInvalidParams},
		{name: "empty", hex: "", wantErr: mcperr.CodeInvalidParams},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := DecodeTool{}.Invoke(context.Background(), args(t, map[string]any{"hex": tc.hex}))
			if tc.wantErr != 0 {
				asMCPErr(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, out.(DecodeResult))
			}
		})
	}
}

func TestEncode(t *testing.T) {
	out, err := EncodeTool{}.Invoke(context.Background(), args(t, map[string]any{
		"message_type": "0x41",
		"body_hex":     "11000100",
	}))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	m := out.(map[string]any)
	if m["hex"] != regReqHex {
		t.Errorf("hex: got %v, want %s", m["hex"], regReqHex)
	}
	if m["length"] != 7 {
		t.Errorf("length: got %v, want 7", m["length"])
	}

	// Encode by message name resolves to the same byte.
	out2, err := EncodeTool{}.Invoke(context.Background(), args(t, map[string]any{
		"message_type": "RegistrationRequest",
		"body_hex":     "11000100",
	}))
	if err != nil {
		t.Fatalf("encode by name: %v", err)
	}
	if out2.(map[string]any)["hex"] != regReqHex {
		t.Errorf("encode by name hex mismatch")
	}

	// Secured header is rejected (assembler is plain-only).
	_, err = EncodeTool{}.Invoke(context.Background(), args(t, map[string]any{
		"message_type":         "0x41",
		"security_header_type": 2,
	}))
	asMCPErr(t, err, mcperr.CodeInvalidParams)
}

// TestRoundTrip asserts decode(encode(decode(x).raw_body)) reproduces the input.
func TestRoundTrip(t *testing.T) {
	dec, err := DecodeTool{}.Invoke(context.Background(), args(t, map[string]any{"hex": regReqHex}))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r := dec.(DecodeResult)

	enc, err := EncodeTool{}.Invoke(context.Background(), args(t, map[string]any{
		"extended_protocol_discriminator": r.ExtendedProtocolDiscriminator,
		"security_header_type":            r.SecurityHeaderType,
		"message_type":                    r.MessageType,
		"body_hex":                        r.RawBodyHex,
	}))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	gotHex := enc.(map[string]any)["hex"].(string)
	if gotHex != regReqHex {
		t.Fatalf("round-trip hex: got %s, want %s", gotHex, regReqHex)
	}

	// Re-decode and assert the message type matches.
	dec2, err := DecodeTool{}.Invoke(context.Background(), args(t, map[string]any{"hex": gotHex}))
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if dec2.(DecodeResult).MessageType != r.MessageType {
		t.Errorf("round-trip message type mismatch")
	}
}

func TestIEValidate(t *testing.T) {
	tests := []struct {
		name       string
		hex        string
		wantValid  bool
		wantCount  int
		wantOffset int // checked only when !wantValid
	}{
		{name: "valid single IE", hex: "6d0201ab", wantValid: true, wantCount: 1},
		{name: "valid two IEs", hex: "6d0201ab250101", wantValid: true, wantCount: 2},
		{name: "length overflow", hex: "6d05aabb", wantValid: false, wantCount: 0, wantOffset: 0},
		{name: "truncated tag", hex: "6d0201ab25", wantValid: false, wantCount: 1, wantOffset: 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := IEValidateTool{}.Invoke(context.Background(), args(t, map[string]any{"hex": tc.hex}))
			if err != nil {
				t.Fatalf("ie_validate: %v", err)
			}
			m := out.(map[string]any)
			if m["valid"] != tc.wantValid {
				t.Errorf("valid: got %v, want %v", m["valid"], tc.wantValid)
			}
			if m["ie_count"] != tc.wantCount {
				t.Errorf("ie_count: got %v, want %d", m["ie_count"], tc.wantCount)
			}
			if !tc.wantValid {
				errs := m["errors"].([]map[string]any)
				if len(errs) == 0 {
					t.Fatal("expected validation errors")
				}
				if errs[0]["offset"] != tc.wantOffset {
					t.Errorf("offset: got %v, want %d", errs[0]["offset"], tc.wantOffset)
				}
			}
		})
	}
}

func TestTLVInspect(t *testing.T) {
	out, err := TLVInspectTool{}.Invoke(context.Background(), args(t, map[string]any{"hex": "6d0201ab"}))
	if err != nil {
		t.Fatalf("tlv_inspect: %v", err)
	}
	m := out.(map[string]any)
	entries := m["entries"].([]tlvEntry)
	if len(entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Offset != 0 || e.IEI != 0x6d || e.Length != 2 || e.ValueHex != "01ab" {
		t.Errorf("entry: %+v", e)
	}

	// Truncated input reports the break offset.
	out2, err := TLVInspectTool{}.Invoke(context.Background(), args(t, map[string]any{"hex": "6d05aabb"}))
	if err != nil {
		t.Fatalf("tlv_inspect truncated: %v", err)
	}
	if out2.(map[string]any)["truncated_at"] != 0 {
		t.Errorf("truncated_at: got %v, want 0", out2.(map[string]any)["truncated_at"])
	}
}
