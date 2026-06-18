package aka_test

// Tests for the 5G-AKA authentication context helpers.
// Ref: 3GPP TS 33.501 §6.1.3.2

import (
	"bytes"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/shared/aka"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
)

// ---- Store ------------------------------------------------------------------

func TestStore_PutGetDelete(t *testing.T) {
	s := aka.NewStore()
	ctx := &aka.AuthContext{SUPI: "imsi-208930000000001"}

	s.Put("id1", ctx)

	got, ok := s.Get("id1")
	if !ok {
		t.Fatal("Get: key not found after Put")
	}
	if got.SUPI != ctx.SUPI {
		t.Errorf("SUPI: got %q, want %q", got.SUPI, ctx.SUPI)
	}

	s.Delete("id1")
	_, ok = s.Get("id1")
	if ok {
		t.Error("Get after Delete should return false")
	}
}

func TestStore_GetMissing(t *testing.T) {
	s := aka.NewStore()
	_, ok := s.Get("does-not-exist")
	if ok {
		t.Error("Get on empty store should return false")
	}
}

func TestStore_OverwritesPrevious(t *testing.T) {
	s := aka.NewStore()
	s.Put("k", &aka.AuthContext{SUPI: "first"})
	s.Put("k", &aka.AuthContext{SUPI: "second"})

	got, _ := s.Get("k")
	if got.SUPI != "second" {
		t.Errorf("expected overwritten value %q, got %q", "second", got.SUPI)
	}
}

// ---- ParseHexKey ------------------------------------------------------------

func TestParseHexKey_Valid(t *testing.T) {
	hexStr := "465b5ce8b199b49faa5f0a2ee238a6bc"
	k, err := aka.ParseHexKey(hexStr)
	if err != nil {
		t.Fatalf("ParseHexKey: %v", err)
	}
	if k[0] != 0x46 || k[15] != 0xbc {
		t.Errorf("unexpected key value: %x", k)
	}
}

func TestParseHexKey_InvalidHex(t *testing.T) {
	_, err := aka.ParseHexKey("not-hex-string!!")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestParseHexKey_WrongLength(t *testing.T) {
	_, err := aka.ParseHexKey("deadbeef") // 4 bytes, want 16
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}

// ---- ParseHexSQN ------------------------------------------------------------

func TestParseHexSQN_Valid(t *testing.T) {
	sqn, err := aka.ParseHexSQN("ff9bb4d0b607")
	if err != nil {
		t.Fatalf("ParseHexSQN: %v", err)
	}
	if sqn != [6]byte{0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07} {
		t.Errorf("unexpected SQN: %x", sqn)
	}
}

func TestParseHexSQN_WrongLength(t *testing.T) {
	_, err := aka.ParseHexSQN("deadbeef") // 4 bytes, want 6
	if err == nil {
		t.Fatal("expected error for wrong SQN length")
	}
}

func TestParseHexSQN_InvalidHex(t *testing.T) {
	_, err := aka.ParseHexSQN("gg9bb4d0b607")
	if err == nil {
		t.Fatal("expected error for invalid hex in SQN")
	}
}

// ---- ParseHexAMF ------------------------------------------------------------

func TestParseHexAMF_Valid(t *testing.T) {
	amf, err := aka.ParseHexAMF("b9b9")
	if err != nil {
		t.Fatalf("ParseHexAMF: %v", err)
	}
	if amf != [2]byte{0xb9, 0xb9} {
		t.Errorf("unexpected AMF: %x", amf)
	}
}

func TestParseHexAMF_WrongLength(t *testing.T) {
	_, err := aka.ParseHexAMF("deadbeef") // 4 bytes, want 2
	if err == nil {
		t.Fatal("expected error for wrong AMF length")
	}
}

func TestParseHexAMF_InvalidHex(t *testing.T) {
	_, err := aka.ParseHexAMF("zzzz")
	if err == nil {
		t.Fatal("expected error for invalid hex in AMF")
	}
}

// ---- IncrementSQN -----------------------------------------------------------

func TestIncrementSQN_Basic(t *testing.T) {
	sqn := [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	got := aka.IncrementSQN(sqn)
	want := [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	if got != want {
		t.Errorf("IncrementSQN: got %x, want %x", got, want)
	}
}

func TestIncrementSQN_ByteRollover(t *testing.T) {
	sqn := [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xFF}
	got := aka.IncrementSQN(sqn)
	want := [6]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00}
	if got != want {
		t.Errorf("IncrementSQN byte rollover: got %x, want %x", got, want)
	}
}

func TestIncrementSQN_AllFF(t *testing.T) {
	sqn := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	got := aka.IncrementSQN(sqn)
	want := [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if got != want {
		t.Errorf("IncrementSQN all-FF rollover: got %x, want %x", got, want)
	}
}

func TestIncrementSQN_Zero(t *testing.T) {
	sqn := [6]byte{}
	got := aka.IncrementSQN(sqn)
	want := [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	if got != want {
		t.Errorf("IncrementSQN from zero: got %x, want %x", got, want)
	}
}

// ---- VerifyRES --------------------------------------------------------------

// buildTestContext constructs a minimal AuthContext with consistent XRES*/HRES*
// derived from a fixed RAND and an arbitrary XRES* value using kdf.HRESStar.
func buildTestContext(t *testing.T) (*aka.AuthContext, []byte) {
	t.Helper()

	rand := [16]byte{
		0xf9, 0x89, 0xf8, 0x42, 0xe5, 0xa1, 0xe5, 0x1c,
		0x3e, 0x70, 0xaf, 0x13, 0xa8, 0x1c, 0x0f, 0x8e,
	}
	// Use a fixed XRES* value (16 bytes).
	xresStar := make([]byte, 16)
	for i := range xresStar {
		xresStar[i] = byte(0x10 + i)
	}
	hresStar := kdf.HRESStar(rand, xresStar)
	kausf := bytes.Repeat([]byte{0xAB}, 32)

	ctx := &aka.AuthContext{
		SUPI:           "imsi-208930000000001",
		ServingNetName: "5G:mnc093.mcc208.3gppnetwork.org",
		RAND:           rand,
		XRESStar:       xresStar,
		HRESStar:       hresStar,
		KAUSF:          kausf,
		CreatedAt:      time.Now(),
	}
	return ctx, xresStar
}

// TestVerifyRES_CorrectXRESStar passes the expected XRES* and checks that
// KAUSF is returned and Confirmed is set.
func TestVerifyRES_CorrectXRESStar(t *testing.T) {
	ctx, xresStar := buildTestContext(t)

	retKAUSF, err := aka.VerifyRES(ctx, xresStar)
	if err != nil {
		t.Fatalf("VerifyRES: %v", err)
	}
	if !bytes.Equal(retKAUSF, ctx.KAUSF) {
		t.Errorf("returned KAUSF mismatch\n got  %x\n want %x", retKAUSF, ctx.KAUSF)
	}
	if !ctx.Confirmed {
		t.Error("ctx.Confirmed should be true after successful verification")
	}
}

// TestVerifyRES_CorrectHRESStar passes a resStar whose HRES* matches ctx.HRESStar.
// This exercises the primary path (HRES* check before direct XRESStar comparison).
func TestVerifyRES_CorrectHRESStar(t *testing.T) {
	ctx, xresStar := buildTestContext(t)

	// resStar == xresStar means HRESStar(rand, resStar) == ctx.HRESStar — both paths agree.
	retKAUSF, err := aka.VerifyRES(ctx, xresStar)
	if err != nil {
		t.Fatalf("VerifyRES via HRES* path: %v", err)
	}
	if !bytes.Equal(retKAUSF, ctx.KAUSF) {
		t.Errorf("KAUSF mismatch: got %x, want %x", retKAUSF, ctx.KAUSF)
	}
}

// TestVerifyRES_Wrong verifies that an incorrect RES* is rejected.
func TestVerifyRES_Wrong(t *testing.T) {
	ctx, _ := buildTestContext(t)
	wrongRES := bytes.Repeat([]byte{0xFF}, 16)

	_, err := aka.VerifyRES(ctx, wrongRES)
	if err == nil {
		t.Fatal("expected error for wrong RES*")
	}
}

// TestVerifyRES_Expired verifies that a stale authentication context is rejected.
func TestVerifyRES_Expired(t *testing.T) {
	ctx, xresStar := buildTestContext(t)
	ctx.CreatedAt = time.Now().Add(-10 * time.Minute) // older than 5-minute TTL

	_, err := aka.VerifyRES(ctx, xresStar)
	if err == nil {
		t.Fatal("expected error for expired auth context")
	}
}

// TestVerifyRES_Nil verifies that a nil context returns an error.
func TestVerifyRES_Nil(t *testing.T) {
	_, err := aka.VerifyRES(nil, []byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for nil AuthContext")
	}
}
