package nea_test

// NEA2 regression vectors. The IV construction (COUNT(32b)|BEARER(5b)|DIR(1b)
// followed by 90 zero bits — TS 33.401 §B.1.2) is pinned by these vectors,
// which were recomputed after fixing the historical "repeated half" IV bug
// (the implementation is also validated end-to-end against UERANSIM NEA2).

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// TestNEA2_KnownVector_8Bytes uses the same key/params as the NIA2 test
// (regression vector — not a normative 3GPP vector).
func TestNEA2_KnownVector_8Bytes(t *testing.T) {
	key := mustHex(t, "d3c5d592327fb11c4035c6680af8c6d1")
	plaintext := mustHex(t, "484583d5afe082ae")
	wantCT := mustHex(t, "de928456a69cdace")

	ct, err := nea.NEA2(key, 0x398a59b4, 0x1a, 0x01, plaintext)
	if err != nil {
		t.Fatalf("NEA2: %v", err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Errorf("ciphertext\n got  %x\n want %x", ct, wantCT)
	}
}

// TestNEA2_ZeroParams verifies behaviour when COUNT, BEARER and DIR are all 0.
func TestNEA2_ZeroParams(t *testing.T) {
	key := mustHex(t, "d3c5d592327fb11c4035c6680af8c6d1")
	plaintext := make([]byte, 16)
	wantCT := mustHex(t, "9b71f299132915d3605211b5e5df8632")

	ct, err := nea.NEA2(key, 0x00000000, 0x00, 0x00, plaintext)
	if err != nil {
		t.Fatalf("NEA2: %v", err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Errorf("zero-params ciphertext\n got  %x\n want %x", ct, wantCT)
	}
}

// TestNEA2_Roundtrip32Bytes encrypts a 32-byte payload (two AES blocks) and decrypts it back.
func TestNEA2_Roundtrip32Bytes(t *testing.T) {
	key := mustHex(t, "2bd6459f82c5b300952c49104881ff48")
	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	wantCT := mustHex(t, "ba26358611248d2d02ba0d98d848702dd06f3affb26a155c66dcc8ce7fb2a7dd")

	ct, err := nea.NEA2(key, 0xc675a64b, 0x0c, 0x00, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Errorf("encrypt\n got  %x\n want %x", ct, wantCT)
	}

	recovered, err := nea.NEA2(key, 0xc675a64b, 0x0c, 0x00, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("decrypt\n got  %x\n want %x", recovered, plaintext)
	}
}

// TestNEA2_MaxBearer exercises the maximum bearer value (0x1F) and downlink direction.
func TestNEA2_MaxBearer(t *testing.T) {
	key := mustHex(t, "2bd6459f82c5b300952c49104881ff48")
	plaintext := mustHex(t, "deadbeefcafebabe")
	wantCT := mustHex(t, "08aff0d9082cf1dd")

	ct, err := nea.NEA2(key, 0xFFFFFFFF, 0x1F, 0x01, plaintext)
	if err != nil {
		t.Fatalf("NEA2: %v", err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Errorf("max-bearer ciphertext\n got  %x\n want %x", ct, wantCT)
	}
}

// TestNEA2_EmptyMessage verifies that encrypting an empty slice returns an empty slice.
func TestNEA2_EmptyMessage(t *testing.T) {
	key := mustHex(t, "d3c5d592327fb11c4035c6680af8c6d1")

	ct, err := nea.NEA2(key, 0x398a59b4, 0x1a, 0x01, []byte{})
	if err != nil {
		t.Fatalf("NEA2 empty: %v", err)
	}
	if len(ct) != 0 {
		t.Errorf("expected empty ciphertext, got %x", ct)
	}
}

// TestNEA2_Symmetric confirms CTR mode symmetry: Encrypt(Encrypt(m)) == m.
func TestNEA2_Symmetric(t *testing.T) {
	key := mustHex(t, "d3c5d592327fb11c4035c6680af8c6d1")
	original := []byte("5GNASsecurityTest!")

	ct, err := nea.NEA2(key, 0x12345678, 0x05, 0x00, original)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	recovered, err := nea.NEA2(key, 0x12345678, 0x05, 0x00, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(recovered, original) {
		t.Errorf("CTR symmetry broken\n got  %x\n want %x", recovered, original)
	}
}

// TestNEA2_DifferentDirections verifies that uplink (dir=0) and downlink (dir=1)
// produce different ciphertexts even with identical plaintext and COUNT.
func TestNEA2_DifferentDirections(t *testing.T) {
	key := mustHex(t, "d3c5d592327fb11c4035c6680af8c6d1")
	pt := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	ctUL, _ := nea.NEA2(key, 0x10000000, 0x05, 0x00, pt)
	ctDL, _ := nea.NEA2(key, 0x10000000, 0x05, 0x01, pt)

	if bytes.Equal(ctUL, ctDL) {
		t.Error("uplink and downlink should produce different ciphertexts (DIR bit differs in IV)")
	}
}

// TestNEA2_BadKey verifies that a key that is not exactly 16 bytes returns an error.
func TestNEA2_BadKey(t *testing.T) {
	_, err := nea.NEA2([]byte{0x01, 0x02, 0x03}, 0, 0, 0, []byte("hello"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

// TestNEA2_BadKey24Bytes tests 24-byte key (AES-192 is valid for AES but not 128-NEA2).
func TestNEA2_BadKey24Bytes(t *testing.T) {
	_, err := nea.NEA2(make([]byte, 24), 0, 0, 0, []byte("hello"))
	if err == nil {
		t.Fatal("expected error: NEA2 requires exactly 128-bit (16-byte) key")
	}
}

// TestNEA0_Passthrough verifies that NEA0 returns the plaintext unchanged.
func TestNEA0_Passthrough(t *testing.T) {
	msg := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	out := nea.NEA0(msg)

	if !bytes.Equal(out, msg) {
		t.Errorf("NEA0 should return copy: got %x, want %x", out, msg)
	}
	// Must be a copy, not the same slice.
	out[0] = 0xFF
	if msg[0] == 0xFF {
		t.Error("NEA0 returned same backing slice instead of a copy")
	}
}

// TestNEA0_Empty verifies NEA0 handles an empty message gracefully.
func TestNEA0_Empty(t *testing.T) {
	out := nea.NEA0(nil)
	if len(out) != 0 {
		t.Errorf("NEA0(nil) should return empty, got %x", out)
	}
}
