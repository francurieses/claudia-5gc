package procedures

import (
	"regexp"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/types"
)

// TestSUCIString covers the NAS->TS 29.571 §5.3.2 SUCI text mapping.
func TestSUCIString(t *testing.T) {
	pat := regexp.MustCompile(`^` + types.SUCIPattern + `$`)
	tests := []struct {
		name string
		in   nas.SUCIMobileIdentity
		want string
	}{
		{"null 2-digit MNC", nas.SUCIMobileIdentity{MCC: "001", MNC: "01", RoutingIndicator: "0000", SchemeOutput: []byte{0x00, 0x00, 0x00, 0x00, 0x10}}, "suci-0-001-01-0000-0-0-0000000001"},
		{"null 3-digit MNC", nas.SUCIMobileIdentity{MCC: "310", MNC: "260", RoutingIndicator: "0", SchemeOutput: []byte{0x21, 0x43}}, "suci-0-310-260-0-0-0-1234"},
		{"null odd MSIN F filler", nas.SUCIMobileIdentity{MCC: "001", MNC: "01", RoutingIndicator: "0000", SchemeOutput: []byte{0x21, 0xF3}}, "suci-0-001-01-0000-0-0-123"},
		{"profile A key 3", nas.SUCIMobileIdentity{MCC: "001", MNC: "01", RoutingIndicator: "0000", ProtectionSchemeID: 1, HomeNetworkPublicKeyID: 3, SchemeOutput: []byte{0xAB, 0x01}}, "suci-0-001-01-0000-1-3-ab01"},
		{"profile B key 255", nas.SUCIMobileIdentity{MCC: "001", MNC: "01", RoutingIndicator: "1234", ProtectionSchemeID: 2, HomeNetworkPublicKeyID: 255, SchemeOutput: []byte{0xFF}}, "suci-0-001-01-1234-2-255-ff"},
	}
	for _, tc := range tests {
		got, err := SUCIString(&tc.in)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
		if !pat.MatchString(got) {
			t.Errorf("%s: %q does not match SUCIPattern", tc.name, got)
		}
	}
}

func TestSUCIStringErrors(t *testing.T) {
	for name, in := range map[string]*nas.SUCIMobileIdentity{
		"nil":            nil,
		"NAI":            {SUPIFormat: 1, MCC: "001", MNC: "01", RoutingIndicator: "0", SchemeOutput: []byte{0x21}},
		"bad BCD":        {MCC: "001", MNC: "01", RoutingIndicator: "0", SchemeOutput: []byte{0xAB}},
		"empty null":     {MCC: "001", MNC: "01", RoutingIndicator: "0"},
		"profile key 0":  {MCC: "001", MNC: "01", RoutingIndicator: "0", ProtectionSchemeID: 1, SchemeOutput: []byte{1}},
		"profile no out": {MCC: "001", MNC: "01", RoutingIndicator: "0", ProtectionSchemeID: 1, HomeNetworkPublicKeyID: 1},
	} {
		if got, err := SUCIString(in); err == nil {
			t.Errorf("%s: got %q, want error", name, got)
		}
	}
}
