package nas_test

// Table tests for registration-audit finding 29 (AMF-028): REGISTRATION
// REQUEST optional-IE error handling, SUCI SUPI format bits and the S-NSSAI
// mapped HPLMN forms.
// Ref: TS 24.501 §7.6.3, §7.7.1, §9.11.3.4, §9.11.2.8, §9.11.3.37

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// aud29RegBody is a minimal REGISTRATION REQUEST body (after the message
// type): ngKSI/registration type octet + 5GS mobile identity (SUCI, IMSI).
func aud29RegBody(opt ...byte) []byte {
	b := []byte{
		0x71,       // ngKSI 7 | FOR=0 | initial registration
		0x00, 0x0B, // mobile identity length 11
		0x01, 0x02, 0xF8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SUCI, IMSI format
	}
	return append(b, opt...)
}

func TestDecodeRegistrationRequest_AUD29OptionalIEs(t *testing.T) {
	ueSecCap := []byte{0x2E, 0x02, 0xF0, 0xF0}
	nssai := []byte{0x2F, 0x07, 0x01, 0x01, 0x04, 0x02, 0x00, 0x00, 0x01} // SST 1; SST 2 SD 000001
	gmmCap := []byte{0x10, 0x01, 0x07}

	tests := []struct {
		name       string
		body       []byte
		wantCap    []byte // 5GMM capability value, nil = absent
		wantSecCap bool   // UE security capability present with EA2 set
		wantNSSAI  []nas.SNSSAI
	}{
		{
			name:       "legacy valid IEs unchanged",
			body:       aud29RegBody(append(append(append([]byte(nil), gmmCap...), ueSecCap...), nssai...)...),
			wantCap:    []byte{0x07},
			wantSecCap: true,
			wantNSSAI:  []nas.SNSSAI{{SST: 1, SD: nas.SDNotPresent}, {SST: 2, SD: 1}},
		},
		{
			// §7.7.1: S-NSSAI length 5 with one octet present, IE length intact.
			name:       "malformed Requested NSSAI skipped, later IE still decoded",
			body:       aud29RegBody(append([]byte{0x2F, 0x02, 0x05, 0x01}, ueSecCap...)...),
			wantSecCap: true,
		},
		{
			// §7.7.1: reserved S-NSSAI contents length 3.
			name:      "reserved S-NSSAI length treated as not present",
			body:      aud29RegBody(append([]byte{0x2F, 0x04, 0x03, 0x01, 0x00, 0x00}, gmmCap...)...),
			wantCap:   []byte{0x07},
			wantNSSAI: nil,
		},
		{
			// §7.7.1: UE security capability with 1 content octet (min 2).
			name:      "short UE security capability skipped, NSSAI decoded",
			body:      aud29RegBody(append([]byte{0x2E, 0x01, 0xF0}, nssai...)...),
			wantNSSAI: []nas.SNSSAI{{SST: 1, SD: nas.SDNotPresent}, {SST: 2, SD: 1}},
		},
		{
			// §7.7.1: length overruns the message; parsing stops, no error.
			name:    "truncated last IE is not present",
			body:    aud29RegBody(append(append([]byte(nil), gmmCap...), 0x2F, 0x09, 0x01)...),
			wantCap: []byte{0x07},
		},
		{
			// §7.6.3: first occurrence wins.
			name:       "repeated UE security capability keeps first",
			body:       aud29RegBody(append(append([]byte(nil), ueSecCap...), 0x2E, 0x02, 0x00, 0x00)...),
			wantSecCap: true,
		},
		{
			name:      "repeated Requested NSSAI keeps first",
			body:      aud29RegBody(append(append([]byte(nil), nssai...), 0x2F, 0x02, 0x01, 0x09)...),
			wantNSSAI: []nas.SNSSAI{{SST: 1, SD: nas.SDNotPresent}, {SST: 2, SD: 1}},
		},
		{
			name:    "repeated 5GMM capability keeps first",
			body:    aud29RegBody(append(append([]byte(nil), gmmCap...), 0x10, 0x01, 0x00)...),
			wantCap: []byte{0x07},
		},
		{
			// A malformed first occurrence is still "the first": a later valid
			// repetition is ignored (§7.6.3 + §7.7.1).
			name: "malformed first occurrence, repetition ignored",
			body: aud29RegBody(append([]byte{0x2E, 0x01, 0xF0}, ueSecCap...)...),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := nas.DecodeRegistrationRequest(tc.body)
			if err != nil {
				t.Fatalf("DecodeRegistrationRequest: %v", err)
			}
			if !bytes.Equal(rr.FiveGMMCapability, tc.wantCap) {
				t.Errorf("5GMM capability = %x, want %x", rr.FiveGMMCapability, tc.wantCap)
			}
			gotSec := rr.UESecurityCapability != nil && rr.UESecurityCapability.EA2
			if gotSec != tc.wantSecCap {
				t.Errorf("UE security capability (EA2) = %v (%+v), want %v", gotSec, rr.UESecurityCapability, tc.wantSecCap)
			}
			var gotNSSAI []nas.SNSSAI
			if rr.RequestedNSSAI != nil {
				gotNSSAI = rr.RequestedNSSAI.SNSSAIs
			}
			if !reflect.DeepEqual(gotNSSAI, tc.wantNSSAI) {
				t.Errorf("Requested NSSAI = %+v, want %+v", gotNSSAI, tc.wantNSSAI)
			}
		})
	}
}

func TestDecodeMobileIdentity_AUD29SUPIFormat(t *testing.T) {
	tests := []struct {
		name  string
		oct4  byte
		wantF byte
	}{
		{"IMSI", 0x01, 0},
		{"NAI", 0x11, 1},
		{"GCI", 0x21, 2},
		{"GLI", 0x31, 3},
		{"spare bit 8 and bit 4 ignored", 0x89, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mi, err := nas.DecodeMobileIdentity([]byte{tc.oct4, 0x02, 0xF8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x01})
			if err != nil || mi.SUCI == nil {
				t.Fatalf("DecodeMobileIdentity: %v", err)
			}
			if mi.SUCI.SUPIFormat != tc.wantF {
				t.Errorf("SUPI format = %d, want %d (bits 5-7 of octet 4)", mi.SUCI.SUPIFormat, tc.wantF)
			}
		})
	}
}

func TestNSSAI_AUD29SNSSAIForms(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		want    nas.SNSSAI
		wantErr bool
	}{
		{name: "len 1 SST", wire: []byte{1, 0x01}, want: nas.SNSSAI{SST: 1, SD: nas.SDNotPresent}},
		{name: "len 4 SST SD", wire: []byte{4, 0x01, 0x00, 0x00, 0x2A}, want: nas.SNSSAI{SST: 1, SD: 0x2A}},
		{
			name: "len 2 SST mapped SST", wire: []byte{2, 0x01, 0x02},
			want: nas.SNSSAI{SST: 1, SD: nas.SDNotPresent, HasMappedHPLMN: true, MappedHPLMNSST: 2, MappedHPLMNSD: nas.SDNotPresent},
		},
		{
			name: "len 5 SST SD mapped SST", wire: []byte{5, 0x01, 0x00, 0x00, 0x2A, 0x03},
			want: nas.SNSSAI{SST: 1, SD: 0x2A, HasMappedHPLMN: true, MappedHPLMNSST: 3, MappedHPLMNSD: nas.SDNotPresent},
		},
		{
			name: "len 8 SST SD mapped SST SD", wire: []byte{8, 0x01, 0x00, 0x00, 0x2A, 0x03, 0x12, 0x34, 0x56},
			want: nas.SNSSAI{SST: 1, SD: 0x2A, HasMappedHPLMN: true, MappedHPLMNSST: 3, MappedHPLMNSD: 0x123456},
		},
		{
			name: "len 8 no SD associated with SST", wire: []byte{8, 0x01, 0xFF, 0xFF, 0xFF, 0x03, 0x00, 0x00, 0x07},
			want: nas.SNSSAI{SST: 1, SD: nas.SDNotPresent, HasMappedHPLMN: true, MappedHPLMNSST: 3, MappedHPLMNSD: 7},
		},
		{name: "len 0 reserved", wire: []byte{0}, wantErr: true},
		{name: "len 3 reserved", wire: []byte{3, 1, 2, 3}, wantErr: true},
		{name: "len 6 reserved", wire: []byte{6, 1, 2, 3, 4, 5, 6}, wantErr: true},
		{name: "len 7 reserved", wire: []byte{7, 1, 2, 3, 4, 5, 6, 7}, wantErr: true},
		{name: "len 9 reserved", wire: []byte{9, 1, 2, 3, 4, 5, 6, 7, 8, 9}, wantErr: true},
		{name: "len 5 truncated", wire: []byte{5, 0x01}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := nas.DecodeNSSAI(tc.wire)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("DecodeNSSAI(%x): want error, got %+v", tc.wire, n)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeNSSAI(%x): %v", tc.wire, err)
			}
			if len(n.SNSSAIs) != 1 || n.SNSSAIs[0] != tc.want {
				t.Fatalf("DecodeNSSAI(%x) = %+v, want %+v", tc.wire, n.SNSSAIs, tc.want)
			}
			// Canonical forms re-encode byte-identically.
			if got := nas.EncodeNSSAI(n); !bytes.Equal(got, tc.wire) {
				t.Errorf("EncodeNSSAI = %x, want %x", got, tc.wire)
			}
		})
	}
}

// TestEncodeNSSAI_AUD29LegacyGolden pins the pre-change wire bytes for
// S-NSSAIs without a mapped HPLMN S-NSSAI (Registration Accept / Configuration
// Update Command Allowed / Configured NSSAI).
func TestEncodeNSSAI_AUD29LegacyGolden(t *testing.T) {
	n := nas.NSSAI{SNSSAIs: []nas.SNSSAI{
		{SST: 1, SD: nas.SDNotPresent},
		{SST: 1, SD: 0x000001},
		{SST: 2, SD: 0xABCDEF},
	}}
	want := []byte{0x01, 0x01, 0x04, 0x01, 0x00, 0x00, 0x01, 0x04, 0x02, 0xAB, 0xCD, 0xEF}
	if got := nas.EncodeNSSAI(n); !bytes.Equal(got, want) {
		t.Fatalf("EncodeNSSAI = %x, want %x", got, want)
	}
}
