package procedures

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// TestAcceptableUESecurityCapability: TS 24.501 §5.5.1.2.8 i) — the IE must be
// present and offer a selectable 5GS encryption algorithm and a non-null 5GS
// integrity algorithm.
func TestAcceptableUESecurityCapability(t *testing.T) {
	tests := []struct {
		name string
		sc   *nas.UESecurityCapability
		want bool
	}{
		{"absent", nil, false},
		{"all bits zero", &nas.UESecurityCapability{}, false},
		{"no encryption", &nas.UESecurityCapability{IA2: true}, false},
		{"NIA0 only", &nas.UESecurityCapability{EA2: true, IA0: true}, false},
		{"unimplemented only", &nas.UESecurityCapability{EA3: true, IA3: true}, false},
		{"NEA0 + NIA2", &nas.UESecurityCapability{EA0: true, IA2: true}, true},
		{"typical UE", &nas.UESecurityCapability{EA0: true, EA1: true, EA2: true, IA1: true, IA2: true}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := acceptableUESecurityCapability(tc.sc); got != tc.want {
				t.Fatalf("acceptableUESecurityCapability = %v, want %v", got, tc.want)
			}
		})
	}
}
