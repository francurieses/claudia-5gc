package nas

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewNetworkFeatureSupportLegacy(t *testing.T) {
	if got := NewNetworkFeatureSupport(true); !bytes.Equal(got, []byte{0x01, 0x00}) {
		t.Fatalf("true = %x", got)
	}
	if got := NewNetworkFeatureSupport(false); !bytes.Equal(got, []byte{0x00, 0x00}) {
		t.Fatalf("false = %x", got)
	}
}

func TestNetworkFeatureSupportEncodeBound(t *testing.T) {
	tests := []struct {
		name string
		n    NetworkFeatureSupport
		max  int
		want []byte
	}{
		{"legacy bound drops ext bits", NetworkFeatureSupport{IMSVoPS3GPP: true, NCR: true, RSLP: true}, NFSLegacyOctets, []byte{0x01, 0x00}},
		{"gate on, octet 5 bit set", NetworkFeatureSupport{IMSVoPS3GPP: true, NCR: true}, NFSMaxOctets, []byte{0x01, 0x00, 0x08}},
		{"gate on, octet 6 bit set", NetworkFeatureSupport{EF5L: true}, NFSMaxOctets, []byte{0x00, 0x00, 0x00, 0x20}},
		{"gate on, no ext bits: no trailing zeros", NetworkFeatureSupport{IMSVoPS3GPP: true}, NFSMaxOctets, []byte{0x01, 0x00}},
		{"bound 3 drops octet 6", NetworkFeatureSupport{NCR: true, SUPL: true}, 3, []byte{0x00, 0x00, 0x08}},
		{"bound below legacy is clamped", NetworkFeatureSupport{MPSI: true}, 0, []byte{0x80, 0x00}},
		{"bound above max is clamped", NetworkFeatureSupport{UNPER: true}, 9, []byte{0x00, 0x00, 0x80}},
		{"two-bit fields", NetworkFeatureSupport{EMC: 1, EMF: 2, RestrictEC: 3}, NFSMaxOctets, []byte{0x24, 0x0C}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.n.Encode(tc.max); !bytes.Equal(got, tc.want) {
				t.Fatalf("Encode(%d) = %x, want %x", tc.max, got, tc.want)
			}
		})
	}
}

func TestNetworkFeatureSupportRoundTrip(t *testing.T) {
	all := NetworkFeatureSupport{
		IMSVoPS3GPP: true, IMSVoPSN3GPP: true, EMC: 3, EMF: 2, IWKN26: true, MPSI: true,
		EMCN3: true, MCSI: true, RestrictEC: 1, CPCIoT: true, N3DataNotSupported: true, IPHCCPCIoT: true, UPCIoT: true,
		LCS: true, ATSInd: true, EHCCPCIoT: true, NCR: true, PIV: true, RPR: true, PR: true, UNPER: true,
		NAPS: true, LCSUPP: true, SUPL: true, RSLP: true, MLCSUP: true, EF5L: true,
	}
	for _, n := range []NetworkFeatureSupport{{}, {IMSVoPS3GPP: true}, {NCR: true}, {EF5L: true, MPSI: true}, all} {
		got, err := DecodeNetworkFeatureSupport(n.Encode(NFSMaxOctets))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(*got, n) {
			t.Fatalf("round trip: got %+v want %+v", *got, n)
		}
	}
}

func TestDecodeNetworkFeatureSupportLengths(t *testing.T) {
	for l := 1; l <= NFSMaxOctets+2; l++ {
		b := bytes.Repeat([]byte{0x01}, l)
		got, err := DecodeNetworkFeatureSupport(b)
		if err != nil || !got.IMSVoPS3GPP {
			t.Fatalf("len %d: %+v, %v", l, got, err)
		}
		if (l >= 3) != got.LCS || (l >= 4) != got.NAPS {
			t.Fatalf("len %d: missing octets must read as zero: %+v", l, got)
		}
	}
	if _, err := DecodeNetworkFeatureSupport(nil); err == nil {
		t.Fatal("empty content must error")
	}
}

func TestRegistrationAcceptNFSExtendedWire(t *testing.T) {
	ra := &RegistrationAccept{RegistrationResult: 1, NetworkFeatureSupport: NetworkFeatureSupport{NCR: true}.Encode(NFSMaxOctets)}
	b, err := EncodeRegistrationAccept(ra)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(b, []byte{0x21, 0x03, 0x00, 0x00, 0x08}) {
		t.Fatalf("wire = %x", b)
	}
	got, err := DecodeRegistrationAccept(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.NetworkFeatureSupport, []byte{0x00, 0x00, 0x08}) {
		t.Fatalf("decoded NFS = %x", got.NetworkFeatureSupport)
	}
}

// TestLimitToUECapabilityCouplings checks the §5.5.1.2.4 couplings: PR only with
// RPR and/or NCR, MLCSUP only with LCS-UPP, and nil capability clears UE-tied bits.
func TestLimitToUECapabilityCouplings(t *testing.T) {
	all := &FiveGMMCapability{NCR: true, RPR: true, PR: true, LCSUPP: true, MLCSUP: true}
	tests := []struct {
		name string
		in   NetworkFeatureSupport
		cap  *FiveGMMCapability
		want NetworkFeatureSupport
	}{
		{"PR with RPR", NetworkFeatureSupport{PR: true, RPR: true}, all, NetworkFeatureSupport{PR: true, RPR: true}},
		{"PR with NCR", NetworkFeatureSupport{PR: true, NCR: true}, all, NetworkFeatureSupport{PR: true, NCR: true}},
		{"PR alone cleared", NetworkFeatureSupport{PR: true}, all, NetworkFeatureSupport{}},
		{"PR cleared when UE lacks RPR", NetworkFeatureSupport{PR: true, RPR: true}, &FiveGMMCapability{PR: true}, NetworkFeatureSupport{}},
		{"MLCSUP alone cleared", NetworkFeatureSupport{MLCSUP: true}, all, NetworkFeatureSupport{}},
		{"MLCSUP with LCS-UPP", NetworkFeatureSupport{MLCSUP: true, LCSUPP: true}, all, NetworkFeatureSupport{MLCSUP: true, LCSUPP: true}},
		{"nil capability", NetworkFeatureSupport{PR: true, RPR: true, NCR: true}, nil, NetworkFeatureSupport{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.LimitToUECapability(tt.cap); got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
