package snow3g

import (
	"slices"
	"testing"
)

// TestKeystream checks SNOW 3G keystream words against the SNOW 3G
// specification test sets (ETSI SAGE UEA2/UIA2 Document 3, reproduced in
// TS 35.217 / free5GC nas snow3g_test.go).
func TestKeystream(t *testing.T) {
	tests := []struct {
		name string
		k    [4]uint32
		iv   [4]uint32
		want []uint32
	}{
		{"set 1", [4]uint32{0x2bd6459f, 0x82c5b300, 0x952c4910, 0x4881ff48},
			[4]uint32{0xea024714, 0xad5c4d84, 0xdf1f9b25, 0x1c0bf45f},
			[]uint32{0xabee9704, 0x7ac31373}},
		{"set 2", [4]uint32{0x8ce33e2c, 0xc3c0b5fc, 0x1f3de8a6, 0xdc66b1f3},
			[4]uint32{0xd3c5d592, 0x327fb11c, 0xde551988, 0xceb2f9b7},
			[]uint32{0xeff8a342, 0xf751480f}},
		{"set 3", [4]uint32{0x4035c668, 0x0af8c6d1, 0xa8ff8667, 0xb1714013},
			[4]uint32{0x62a54098, 0x1ba6f9b7, 0x4592b0e7, 0x8690f71b},
			[]uint32{0xa8c874a9, 0x7ae7c4f8}},
		{"set 4", [4]uint32{0x0ded7263, 0x109cf92e, 0x3352255a, 0x140e0f76},
			[4]uint32{0x6b68079a, 0x41a7c4c9, 0x1befd79f, 0x7fdcc233},
			[]uint32{0xd712c05c, 0xa937c2a6, 0xeb7eaae3}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Keystream(tc.k, tc.iv, len(tc.want))
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %08x, want %08x", got, tc.want)
			}
		})
	}
}

func TestKeystreamNonPositive(t *testing.T) {
	for _, n := range []int{0, -1} {
		if got := Keystream([4]uint32{}, [4]uint32{}, n); len(got) != 0 {
			t.Errorf("n=%d: got %d words, want 0", n, len(got))
		}
	}
}
