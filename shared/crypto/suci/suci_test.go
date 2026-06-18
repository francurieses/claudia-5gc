package suci_test

// Tests for SUCI ECIES concealment/deconcealment.
// Profile A (X25519) roundtrips are exercised with a fixed home-network keypair.
// Profile B (secp256r1) is tested for error paths only (no encrypt helper exists).
//
// Ref: 3GPP TS 33.501 §6.12 + Annex C

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/francurieses/claudia-5gc/shared/crypto/suci"
)

// Fixed home-network private key used across all Profile A tests.
// The corresponding public key is derived via X25519(privKey, Basepoint).
var testHNPrivKey = [32]byte{
	0xc8, 0x09, 0x49, 0xd0, 0xc3, 0xe4, 0xd7, 0x3a,
	0x54, 0xf8, 0xb4, 0x9f, 0xbe, 0xe7, 0x79, 0x3c,
	0x5c, 0x1d, 0xe6, 0x49, 0xd7, 0xe2, 0x6e, 0xf8,
	0xb0, 0x5e, 0x0a, 0x1e, 0x0c, 0x8c, 0x12, 0xe9,
}

func hnPubKey(t *testing.T) [32]byte {
	t.Helper()
	pub, err := curve25519.X25519(testHNPrivKey[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive HN public key: %v", err)
	}
	return [32]byte(pub)
}

// TestProfileA_Roundtrip encrypts an MSIN with the HN public key and decrypts
// it with the private key, verifying the MSIN is recovered correctly.
func TestProfileA_Roundtrip(t *testing.T) {
	pub := hnPubKey(t)
	msin := "0000000129"

	s, err := suci.EncryptProfileA(msin, pub, 0x01)
	if err != nil {
		t.Fatalf("EncryptProfileA: %v", err)
	}
	if s.ProtectionScheme != suci.ProfileA {
		t.Errorf("wrong scheme: got %d, want %d", s.ProtectionScheme, suci.ProfileA)
	}

	result, err := suci.DeconceaProfileA(s, testHNPrivKey)
	if err != nil {
		t.Fatalf("DeconceaProfileA: %v", err)
	}
	if result.MSIN != msin {
		t.Errorf("MSIN mismatch: got %q, want %q", result.MSIN, msin)
	}
}

// TestProfileA_SUPIReconstruction verifies the SUPI is built as "imsi-<MCC><MNC><MSIN>".
func TestProfileA_SUPIReconstruction(t *testing.T) {
	pub := hnPubKey(t)

	s, err := suci.EncryptProfileA("0000000129", pub, 0x01)
	if err != nil {
		t.Fatalf("EncryptProfileA: %v", err)
	}
	s.SUPIFormat = 0 // IMSI-based
	s.MCC = "208"
	s.MNC = "93"

	result, err := suci.DeconceaProfileA(s, testHNPrivKey)
	if err != nil {
		t.Fatalf("DeconceaProfileA: %v", err)
	}
	const wantSUPI = "imsi-208930000000129"
	if result.SUPI != wantSUPI {
		t.Errorf("SUPI: got %q, want %q", result.SUPI, wantSUPI)
	}
}

// TestProfileA_TamperedCiphertext verifies that a tampered ciphertext fails MAC check.
func TestProfileA_TamperedCiphertext(t *testing.T) {
	pub := hnPubKey(t)

	s, err := suci.EncryptProfileA("0000000129", pub, 0x01)
	if err != nil {
		t.Fatalf("EncryptProfileA: %v", err)
	}
	// SchemeOutput = ephPub (32 bytes) || ciphertext || MAC (8 bytes)
	// Flip a bit in the ciphertext region (byte 32 if present, else in the MAC).
	if len(s.SchemeOutput) > 33 {
		s.SchemeOutput[33] ^= 0xFF
	} else {
		s.SchemeOutput[len(s.SchemeOutput)-1] ^= 0xFF
	}

	_, err = suci.DeconceaProfileA(s, testHNPrivKey)
	if err == nil {
		t.Fatal("expected MAC failure on tampered scheme output")
	}
}

// TestProfileA_TamperedEphPub verifies that a corrupted ephemeral public key is rejected.
func TestProfileA_TamperedEphPub(t *testing.T) {
	pub := hnPubKey(t)

	s, _ := suci.EncryptProfileA("0000000129", pub, 0x01)
	s.SchemeOutput[0] ^= 0xFF

	_, err := suci.DeconceaProfileA(s, testHNPrivKey)
	if err == nil {
		t.Fatal("expected error on tampered ephemeral public key")
	}
}

// TestProfileA_WrongScheme verifies that passing a non-Profile-A SUCI returns an error.
func TestProfileA_WrongScheme(t *testing.T) {
	s := suci.SUCI{ProtectionScheme: suci.ProfileB}
	_, err := suci.DeconceaProfileA(s, testHNPrivKey)
	if err == nil {
		t.Fatal("expected error: wrong profile")
	}
}

// TestProfileA_ShortSchemeOutput verifies that a too-short scheme output is rejected.
func TestProfileA_ShortSchemeOutput(t *testing.T) {
	s := suci.SUCI{
		ProtectionScheme: suci.ProfileA,
		SchemeOutput:     []byte{0x01, 0x02, 0x03},
	}
	_, err := suci.DeconceaProfileA(s, testHNPrivKey)
	if err == nil {
		t.Fatal("expected error: scheme output too short")
	}
}

// TestProfileB_WrongScheme verifies that passing a non-Profile-B SUCI returns an error.
func TestProfileB_WrongScheme(t *testing.T) {
	s := suci.SUCI{ProtectionScheme: suci.ProfileA}
	_, err := suci.DeconceaProfileB(s, nil)
	if err == nil {
		t.Fatal("expected error: wrong profile")
	}
}

// TestProfileB_ShortSchemeOutput verifies that a too-short Profile B scheme output is rejected.
func TestProfileB_ShortSchemeOutput(t *testing.T) {
	s := suci.SUCI{
		ProtectionScheme: suci.ProfileB,
		SchemeOutput:     []byte{0x01, 0x02, 0x03},
	}
	_, err := suci.DeconceaProfileB(s, []byte{0x01})
	if err == nil {
		t.Fatal("expected error: scheme output too short")
	}
}

// TestProfileA_MultipleRoundtrips verifies multiple MSIN values survive the roundtrip.
func TestProfileA_MultipleRoundtrips(t *testing.T) {
	pub := hnPubKey(t)
	msins := []string{"0000000001", "1234567890", "9999999999", "0987654321"}

	for _, msin := range msins {
		s, err := suci.EncryptProfileA(msin, pub, 0x01)
		if err != nil {
			t.Fatalf("encrypt %q: %v", msin, err)
		}
		r, err := suci.DeconceaProfileA(s, testHNPrivKey)
		if err != nil {
			t.Fatalf("decrypt %q: %v", msin, err)
		}
		if r.MSIN != msin {
			t.Errorf("MSIN %q roundtrip: got %q", msin, r.MSIN)
		}
	}
}

// TestProfileA_Randomized confirms that two encryptions of the same MSIN produce
// different scheme outputs because the ephemeral key is freshly generated each time.
func TestProfileA_Randomized(t *testing.T) {
	pub := hnPubKey(t)

	s1, err := suci.EncryptProfileA("0000000129", pub, 0x01)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	s2, err := suci.EncryptProfileA("0000000129", pub, 0x01)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}

	if bytes.Equal(s1.SchemeOutput, s2.SchemeOutput) {
		t.Error("two encryptions of the same MSIN produced identical scheme outputs — ephemeral key must be randomized")
	}
}

// TestProfileA_SchemeOutputIs45Bytes verifies that Profile A with a 10-digit MSIN
// produces a 45-byte scheme output: 32 (ephPub) + 5 (BCD MSIN) + 8 (MAC).
// This matches the 45-byte scheme output generated by UERANSIM.
func TestProfileA_SchemeOutputIs45Bytes(t *testing.T) {
	pub := hnPubKey(t)
	s, err := suci.EncryptProfileA("0000000001", pub, 0x01)
	if err != nil {
		t.Fatalf("EncryptProfileA: %v", err)
	}
	if got := len(s.SchemeOutput); got != 45 {
		t.Errorf("scheme output length: got %d, want 45 (32+5+8)", got)
	}
}

// TestProfileA_UERANSIMVector verifies decryption of a real SUCI captured from
// UERANSIM v3.2.8. This is the golden test for UERANSIM interoperability.
// Captured: SUPI imsi-001010000000001, private key c80949d0...
func TestProfileA_UERANSIMVector(t *testing.T) {
	// Captured from a live UERANSIM v3.2.8 registration attempt.
	suciStr := "suci-00101-0000-0-1-78db8a7c628c71dc8f932f643c99d4105bead69bca51e4d85c4ecc7175e58e44edde0bdadc382e1e8b9d288222"
	parsed, err := suci.ParseSUCIString(suciStr)
	if err != nil {
		t.Fatalf("ParseSUCIString: %v", err)
	}
	result, err := suci.DeconceaProfileA(parsed, testHNPrivKey)
	if err != nil {
		t.Fatalf("DeconceaProfileA: %v", err)
	}
	if result.MSIN != "0000000001" {
		t.Errorf("MSIN: got %q, want %q", result.MSIN, "0000000001")
	}
	if result.SUPI != "imsi-001010000000001" {
		t.Errorf("SUPI: got %q, want %q", result.SUPI, "imsi-001010000000001")
	}
}

// TestProfileA_UERANSIMParsedSUCI verifies end-to-end roundtrip through the SUCI
// string path (ParseSUCIString → DeconceaProfileA) with a 45-byte scheme output.
// This is a regression guard for the "scheme output too short: 45" bug.
func TestProfileA_UERANSIMParsedSUCI(t *testing.T) {
	pub := hnPubKey(t)

	s, err := suci.EncryptProfileA("0000000001", pub, 0x01)
	if err != nil {
		t.Fatalf("EncryptProfileA: %v", err)
	}

	// Reconstruct the SUCI string the way the AMF does it.
	suciStr := "suci-00101-0000-0-1-" + hex.EncodeToString(s.SchemeOutput)

	parsed, err := suci.ParseSUCIString(suciStr)
	if err != nil {
		t.Fatalf("ParseSUCIString: %v", err)
	}

	result, err := suci.DeconceaProfileA(parsed, testHNPrivKey)
	if err != nil {
		t.Fatalf("DeconceaProfileA on parsed SUCI string: %v", err)
	}
	if result.MSIN != "0000000001" {
		t.Errorf("MSIN: got %q, want %q", result.MSIN, "0000000001")
	}
	if result.SUPI != "imsi-001010000000001" {
		t.Errorf("SUPI: got %q, want %q", result.SUPI, "imsi-001010000000001")
	}
}

// ---- ParseSUCIString --------------------------------------------------------

// TestParseSUCIString_NullScheme verifies the exact SUCI produced by UERANSIM
// for MCC=001, MNC=01, MSIN=0000000001 with null-scheme protection.
func TestParseSUCIString_NullScheme(t *testing.T) {
	s, err := suci.ParseSUCIString("suci-00101-0000-0-0-0000000010")
	if err != nil {
		t.Fatalf("ParseSUCIString: %v", err)
	}
	if s.MCC != "001" {
		t.Errorf("MCC: got %q, want %q", s.MCC, "001")
	}
	if s.MNC != "01" {
		t.Errorf("MNC: got %q, want %q", s.MNC, "01")
	}
	if s.RoutingIndicator != "0000" {
		t.Errorf("RoutingIndicator: got %q, want %q", s.RoutingIndicator, "0000")
	}
	if s.ProtectionScheme != suci.ProfileNull {
		t.Errorf("ProtectionScheme: got %d, want %d", s.ProtectionScheme, suci.ProfileNull)
	}
	if len(s.SchemeOutput) != 5 {
		t.Errorf("SchemeOutput length: got %d, want 5", len(s.SchemeOutput))
	}
}

func TestParseSUCIString_ThreeDigitMNC(t *testing.T) {
	// MCC=001, MNC=001 → combined field length 6
	s, err := suci.ParseSUCIString("suci-001001-0000-0-0-0000000010")
	if err != nil {
		t.Fatalf("ParseSUCIString 3-digit MNC: %v", err)
	}
	if s.MCC != "001" || s.MNC != "001" {
		t.Errorf("MCC/MNC: got %q/%q, want 001/001", s.MCC, s.MNC)
	}
}

func TestParseSUCIString_InvalidPrefix(t *testing.T) {
	_, err := suci.ParseSUCIString("imsi-001010000000001")
	if err == nil {
		t.Fatal("expected error for non-SUCI prefix")
	}
}

func TestParseSUCIString_TooFewFields(t *testing.T) {
	_, err := suci.ParseSUCIString("suci-00101-0000-0-0")
	if err == nil {
		t.Fatal("expected error for too few fields")
	}
}

func TestParseSUCIString_BadSchemeOutputHex(t *testing.T) {
	_, err := suci.ParseSUCIString("suci-00101-0000-0-0-ZZZZZZ")
	if err == nil {
		t.Fatal("expected error for non-hex scheme output")
	}
}

// ---- DeconceaNull -----------------------------------------------------------

// TestDeconceaNull_UERANSIMVector verifies the exact UERANSIM registration case:
// SUCI suci-00101-0000-0-0-0000000010 must produce SUPI imsi-001010000000001.
// The BCD encoding is low-nibble-first: MSIN 0000000001 → bytes 00 00 00 00 10.
func TestDeconceaNull_UERANSIMVector(t *testing.T) {
	s, err := suci.ParseSUCIString("suci-00101-0000-0-0-0000000010")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	result, err := suci.DeconceaNull(s)
	if err != nil {
		t.Fatalf("DeconceaNull: %v", err)
	}
	const wantSUPI = "imsi-001010000000001"
	if result.SUPI != wantSUPI {
		t.Errorf("SUPI: got %q, want %q", result.SUPI, wantSUPI)
	}
	if result.MSIN != "0000000001" {
		t.Errorf("MSIN: got %q, want %q", result.MSIN, "0000000001")
	}
}

// TestDeconceaNull_OddLengthMSIN verifies that a 9-digit MSIN padded with 0xF
// is decoded correctly.
func TestDeconceaNull_OddLengthMSIN(t *testing.T) {
	// MSIN "123456789" (9 digits) in BCD low-nibble-first:
	// pairs: (1,2)(3,4)(5,6)(7,8)(9,F) → bytes: 0x21, 0x43, 0x65, 0x87, 0xF9
	// hex string: "2143658709" — wait, let me recompute:
	// (1,2): low=1,high=2 → 0x21
	// (3,4): low=3,high=4 → 0x43
	// (5,6): low=5,high=6 → 0x65
	// (7,8): low=7,high=8 → 0x87
	// (9,F): low=9,high=F → 0xF9
	// hex: "214365 87F9"
	s := suci.SUCI{
		SUPIFormat:       0,
		MCC:              "001",
		MNC:              "01",
		ProtectionScheme: suci.ProfileNull,
		SchemeOutput:     []byte{0x21, 0x43, 0x65, 0x87, 0xF9},
	}
	result, err := suci.DeconceaNull(s)
	if err != nil {
		t.Fatalf("DeconceaNull odd MSIN: %v", err)
	}
	if result.MSIN != "123456789" {
		t.Errorf("MSIN: got %q, want %q", result.MSIN, "123456789")
	}
}

func TestDeconceaNull_WrongScheme(t *testing.T) {
	s := suci.SUCI{ProtectionScheme: suci.ProfileA}
	_, err := suci.DeconceaNull(s)
	if err == nil {
		t.Fatal("expected error for non-null scheme")
	}
}

// TestProfileNull_SchemeIDPreserved verifies the ProfileNull constant value.
func TestProfileNull_SchemeIDPreserved(t *testing.T) {
	if suci.ProfileNull != 0 {
		t.Errorf("ProfileNull should be 0, got %d", suci.ProfileNull)
	}
	if suci.ProfileA != 1 {
		t.Errorf("ProfileA should be 1, got %d", suci.ProfileA)
	}
	if suci.ProfileB != 2 {
		t.Errorf("ProfileB should be 2, got %d", suci.ProfileB)
	}
}
