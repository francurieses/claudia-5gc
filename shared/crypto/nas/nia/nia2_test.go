package nia_test

// Test vectors from 3GPP TS 33.501 Annex D.3.2 / TS 33.401 Annex B §B.2
// Using EIA2 test vectors (NIA2 = EIA2 with same algorithm)
import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
)

func TestNIA2_KnownVector(t *testing.T) {
	// TS 33.401 Annex B §B.2 EIA2 Test Case 1
	key := mustHex(t, "d3c5d592327fb11c4035c6680af8c6d1")
	count := uint32(0x398a59b4)
	bearer := byte(0x1a)
	dir := byte(0x01)
	message := mustHex(t, "484583d5afe082ae")
	wantMAC := mustHex(t, "b93787e6")

	mac, err := nia.NIA2(key, count, bearer, dir, message)
	if err != nil {
		t.Fatalf("NIA2: %v", err)
	}
	if !bytes.Equal(mac, wantMAC) {
		t.Errorf("NIA2 MAC mismatch\n got  %x\n want %x", mac, wantMAC)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}
