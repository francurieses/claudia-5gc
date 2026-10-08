package context

// nh_chain_test.go — per-UE NH/NCC chain.
// Ref: TS 33.501 §6.9.2.1.1, §6.9.2.3.2, §6.9.2.3.3, Annex A.10

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
)

func nhTestUE() (*UEContext, [32]byte) {
	ue := &UEContext{}
	ue.SecurityCtx.KAMF = bytes.Repeat([]byte{0x42}, 32)
	var kgnb [32]byte
	for i := range kgnb {
		kgnb[i] = byte(i + 1)
	}
	return ue, kgnb
}

func TestSetKgNB_InitialisesChain(t *testing.T) {
	ue, kgnb := nhTestUE()
	ue.SetKgNB(kgnb)
	nh, ncc, valid := ue.NHState()
	if !valid || ncc != InitialNCC {
		t.Fatalf("state valid=%v ncc=%d, want valid NCC=1", valid, ncc)
	}
	if want := kdf.KNH(ue.SecurityCtx.KAMF, kgnb[:]); !bytes.Equal(nh[:], want) {
		t.Fatalf("NH1 != KNH(KAMF, KgNB)")
	}
	if ue.KgNB != kgnb {
		t.Fatalf("KgNB not stored")
	}
}

func TestNextNH_ChainsAndWraps(t *testing.T) {
	ue, kgnb := nhTestUE()
	ue.SetKgNB(kgnb)
	prev, _, _ := ue.NHState()
	wantNCC := []uint8{2, 3, 4, 5, 6, 7, 0, 1}
	for i, w := range wantNCC {
		nh, ncc, ok := ue.NextNH()
		if !ok || ncc != w {
			t.Fatalf("hop %d: ok=%v ncc=%d, want %d", i+1, ok, ncc, w)
		}
		if want := kdf.KNH(ue.SecurityCtx.KAMF, prev[:]); !bytes.Equal(nh[:], want) {
			t.Fatalf("hop %d: NH != KNH(KAMF, NH_prev)", i+1)
		}
		prev = nh
	}
}

func TestNextNH_FirstHopIsKNHOfKNH(t *testing.T) {
	ue, kgnb := nhTestUE()
	ue.SetKgNB(kgnb)
	nh, ncc, _ := ue.NextNH()
	nh1 := kdf.KNH(ue.SecurityCtx.KAMF, kgnb[:])
	if want := kdf.KNH(ue.SecurityCtx.KAMF, nh1); ncc != 2 || !bytes.Equal(nh[:], want) {
		t.Fatalf("first hop ncc=%d, want 2 with NH2 = KNH(KAMF, KNH(KAMF, KgNB))", ncc)
	}
}

func TestSetKgNB_ResetsAfterHops(t *testing.T) {
	ue, kgnb := nhTestUE()
	ue.SetKgNB(kgnb)
	for i := 0; i < 3; i++ {
		ue.NextNH()
	}
	ue.SetKgNB(kgnb)
	if _, ncc, _ := ue.NHState(); ncc != 1 {
		t.Fatalf("ncc after reset = %d, want 1", ncc)
	}
}

func TestNextNH_NoChain(t *testing.T) {
	tests := []struct {
		name string
		kamf []byte
	}{
		{"never set", bytes.Repeat([]byte{1}, 32)},
		{"zero KAMF", make([]byte, 32)},
		{"nil KAMF", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ue := &UEContext{}
			ue.SecurityCtx.KAMF = tc.kamf
			if tc.name != "never set" {
				ue.SetKgNB([32]byte{1})
			}
			if _, _, ok := ue.NextNH(); ok {
				t.Fatalf("NextNH ok with no usable chain")
			}
		})
	}
}

func TestSetNHState(t *testing.T) {
	ue, _ := nhTestUE()
	ue.SetNHState([32]byte{9}, 7)
	nh, ncc, ok := ue.NextNH()
	if !ok || ncc != 0 {
		t.Fatalf("ok=%v ncc=%d, want wrap to 0", ok, ncc)
	}
	if want := kdf.KNH(ue.SecurityCtx.KAMF, append([]byte{9}, make([]byte, 31)...)); !bytes.Equal(nh[:], want) {
		t.Fatalf("NH mismatch")
	}
}
