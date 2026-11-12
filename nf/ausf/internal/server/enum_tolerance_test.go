package server

import (
	"encoding/json"
	"testing"
)

// TestUDMAuthDataUnknownEnumTolerated checks the Nudm_UEAU consumer ignores
// enum values it does not know (TS 29.500 §6.6.2: unknown values shall be
// ignored; TS 29.501 §5.3.12 anyOf[enum,string]) instead of failing to decode.
func TestUDMAuthDataUnknownEnumTolerated(t *testing.T) {
	const rnd, autn, xres, kausf = "00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100", "aabbccddeeff00112233445566778899", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	tests := []struct {
		name     string
		body     map[string]any
		wantType string
	}{
		{"unknown avType, authType absent", map[string]any{"authenticationVector": map[string]any{"avType": "FUTURE_AV", "rand": rnd, "autn": autn, "xresStar": xres, "kausf": kausf}}, ""},
		{"known avType (unchanged)", map[string]any{"authenticationVector": map[string]any{"avType": "5G_HE_AKA", "rand": rnd, "autn": autn, "xresStar": xres, "kausf": kausf}}, "5G_AKA"},
		{"unknown authType passed through", map[string]any{"authType": "FUTURE_AUTH", "authenticationVector": map[string]any{"avType": "5G_HE_AKA", "rand": rnd, "autn": autn, "xresStar": xres, "kausf": kausf}}, "FUTURE_AUTH"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			var r UDMAuthDataResponse
			if err := json.Unmarshal(b, &r); err != nil {
				t.Fatalf("unknown enum value rejected: %v", err)
			}
			if r.AuthType != tc.wantType {
				t.Fatalf("AuthType = %q, want %q", r.AuthType, tc.wantType)
			}
			if r.Rand != rnd {
				t.Fatalf("vector not decoded: %+v", r)
			}
		})
	}
}
