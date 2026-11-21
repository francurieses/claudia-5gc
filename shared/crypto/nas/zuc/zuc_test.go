package zuc

import (
	"encoding/hex"
	"slices"
	"testing"
)

// TestKeystream checks ZUC keystream words against the ZUC specification
// test sets (GSMA/ETSI SAGE "EEA3 & EIA3 test data" v1.1, also in free5GC nas).
func TestKeystream(t *testing.T) {
	tests := []struct {
		name string
		key  string
		iv   string
		want []uint32
	}{
		{"set 1", "00000000000000000000000000000000", "00000000000000000000000000000000",
			[]uint32{0x27bede74, 0x018082da}},
		{"set 2", "ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffff",
			[]uint32{0x0657cfa0, 0x7096398b}},
		{"set 3", "3d4c4be96a82fdaeb58f641db17b455b", "84319aa8de6915ca1f6bda6bfbd8c766",
			[]uint32{0x14f1c272, 0x3279c419}},
		{"set 4", "4d320bfad4c285bfd6b8bd00f39d8b41", "52959daba0bf176ece2dc315049eb574",
			[]uint32{0xed4400e7, 0x0633e5c5}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k, _ := hex.DecodeString(tc.key)
			iv, _ := hex.DecodeString(tc.iv)
			got, err := Keystream(k, iv, len(tc.want))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %08x, want %08x", got, tc.want)
			}
		})
	}
}

func TestKeystreamErrors(t *testing.T) {
	ok := make([]byte, 16)
	tests := []struct {
		name  string
		key   []byte
		iv    []byte
		words int
	}{
		{"short key", make([]byte, 15), ok, 1},
		{"long key", make([]byte, 17), ok, 1},
		{"short iv", ok, make([]byte, 8), 1},
		{"negative words", ok, ok, -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Keystream(tc.key, tc.iv, tc.words); err == nil {
				t.Error("expected error")
			}
		})
	}
}
