package procedures

import (
	"bytes"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// TestParseIntegrityOrder: valid lists parse in order; NIA0, unknown names,
// duplicates and empty lists are start-up errors. Ref: TS 33.501 §5.5.2, §6.7.1.1
func TestParseIntegrityOrder(t *testing.T) {
	got, err := ParseIntegrityOrder(" nia3 ,NIA1")
	if err != nil || !bytes.Equal(got, []byte{3, 1}) {
		t.Fatalf("got %v, %v", got, err)
	}
	if d, err := ParseIntegrityOrder(DefaultIntegrityOrder); err != nil || !bytes.Equal(d, []byte{2, 1, 3}) {
		t.Fatalf("default = %v, %v", d, err)
	}
	for _, bad := range []string{"", " , ", "NIA0, NIA2", "NIA4", "NEA2", "NIA2,NIA2"} {
		if _, err := ParseIntegrityOrder(bad); err == nil {
			t.Fatalf("%q: want error", bad)
		}
	}
}

// TestResolveIntegrityOrderEnv: the env var overrides the YAML value.
func TestResolveIntegrityOrderEnv(t *testing.T) {
	t.Setenv(EnvIntegrityOrder, "NIA1")
	if o, err := ResolveIntegrityOrder("NIA2"); err != nil || !bytes.Equal(o, []byte{1}) {
		t.Fatalf("got %v, %v", o, err)
	}
	t.Setenv(EnvIntegrityOrder, "")
	if o, err := ResolveIntegrityOrder(""); err != nil || !bytes.Equal(o, []byte{2, 1, 3}) {
		t.Fatalf("default: got %v, %v", o, err)
	}
}

// TestSelectIntegrityByOrder: over all IA0..IA3 masks the default order picks
// NIA2 > NIA1 > NIA3 and never NIA0; a configured order is honoured; the
// null-security debug mode keeps the selected real NIA. Ref: TS 33.501 §6.7.2
func TestSelectIntegrityByOrder(t *testing.T) {
	want := [16]struct {
		alg byte
		ok  bool
	}{
		0b0000: {0, false}, 0b0001: {0, false}, 0b0010: {1, true}, 0b0011: {1, true},
		0b0100: {2, true}, 0b0101: {2, true}, 0b0110: {2, true}, 0b0111: {2, true},
		0b1000: {3, true}, 0b1001: {3, true}, 0b1010: {1, true}, 0b1011: {1, true},
		0b1100: {2, true}, 0b1101: {2, true}, 0b1110: {2, true}, 0b1111: {2, true},
	}
	for _, null := range []bool{false, true} {
		h := &RegistrationHandler{nullSecurity: null}
		for m := 0; m < 16; m++ {
			ue := &amfctx.UEContext{}
			ue.UESecCapEA[2] = true
			for i := 0; i < 4; i++ {
				ue.UESecCapIA[i] = m&(1<<i) != 0
			}
			_, got, ok := h.selectSecurityAlgorithms(ue)
			if got != want[m].alg || ok != want[m].ok {
				t.Fatalf("null=%v mask %04b: got (%d,%v), want (%d,%v)", null, m, got, ok, want[m].alg, want[m].ok)
			}
		}
	}
	h := &RegistrationHandler{}
	h.WithIntegrityOrder([]byte{3, 1})
	ue := &amfctx.UEContext{}
	ue.UESecCapEA[2] = true
	ue.UESecCapIA[1], ue.UESecCapIA[2], ue.UESecCapIA[3] = true, true, true
	if _, got, ok := h.selectSecurityAlgorithms(ue); got != 3 || !ok {
		t.Fatalf("order NIA3,NIA1: got (%d,%v)", got, ok)
	}
	ue.UESecCapIA[1], ue.UESecCapIA[3] = false, false
	if _, _, ok := h.selectSecurityAlgorithms(ue); ok {
		t.Fatal("UE NIA2 only vs order NIA3,NIA1: want failure (never NIA0)")
	}
}
