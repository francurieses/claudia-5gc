package kdf_test

// Test vectors from 3GPP TS 33.501 Annex C (§C.1 — 5G-AKA test data)

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
)

// derive is a local copy of the KDF primitive for test vector construction.
func derive(key, s []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(s)
	return mac.Sum(nil)
}

func h(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func h16(s string) [16]byte {
	b := h(s)
	return [16]byte(b)
}

func h6(s string) [6]byte {
	return [6]byte(h(s))
}

// TestKAUSF uses TS 33.501 Annex C §C.1 vectors.
func TestKAUSF(t *testing.T) {
	ck := h16("0cdbc11d0a90ed8c7c9bc49c8e5f4b28")
	ik := h16("bb1f8571b65b2562e6cfacab0cf21a5b")
	snName := "5G:mnc093.mcc208.3gppnetwork.org"
	sqnXorAK := h6("bea7e73085a2")

	want := "15c9d99a2034c0c6d10ecfb494f0ddbbb9bf48da1d4530209508a0304cc9e0e5"
	got := hex.EncodeToString(kdf.KAUSF(ck, ik, snName, sqnXorAK))
	if got != want {
		t.Errorf("KAUSF\n got  %s\n want %s", got, want)
	}
}

// TestKSEAF follows from KAUSF above.
func TestKSEAF(t *testing.T) {
	kausf := h("15c9d99a2034c0c6d10ecfb494f0ddbbb9bf48da1d4530209508a0304cc9e0e5")
	snName := "5G:mnc093.mcc208.3gppnetwork.org"

	want := "16596ba9a4a26db2cf12c887acdafa270efa89e2e85ba99c9d4e0288c83d6ce1"
	got := hex.EncodeToString(kdf.KSEAF(kausf, snName))
	if got != want {
		t.Errorf("KSEAF\n got  %s\n want %s", got, want)
	}
}

// TestXRESStar uses TS 33.501 Annex C §C.1.
func TestXRESStar(t *testing.T) {
	ck := h16("0cdbc11d0a90ed8c7c9bc49c8e5f4b28")
	ik := h16("bb1f8571b65b2562e6cfacab0cf21a5b")
	snName := "5G:mnc093.mcc208.3gppnetwork.org"
	rand := h16("f989f842e5a1e51c3e70af13a81c0f8e")
	xres := h("e6c12e17cceb68cf")

	want := "4a4f45213531dd1e2992813b946838e2"
	got := hex.EncodeToString(kdf.XRESStar(ck, ik, snName, rand, xres))
	if got != want {
		t.Errorf("XRES*\n got  %s\n want %s", got, want)
	}
}

// TestKNASint and TestKNASenc verify the distinguisher values per
// TS 33.501 §A.7.1 Table A.7.1-1: NAS-INT-ALG=0x02, NAS-ENC-ALG=0x01.
// Vectors cross-checked against UERANSIM keys.cpp (N_NAS_int_alg=0x02).
func TestKNASintDistinguisher(t *testing.T) {
	kamf := h("5994ebb2d5e6e3a81bc82db2175df5dc")
	algID := byte(0x02) // NIA2

	kNASint := kdf.KNASint(kamf, algID)
	kNASenc := kdf.KNASenc(kamf, algID)

	// They must differ (different distinguisher byte)
	if len(kNASint) != 16 || len(kNASenc) != 16 {
		t.Fatalf("key lengths wrong: int=%d enc=%d", len(kNASint), len(kNASenc))
	}
	same := true
	for i := range kNASint {
		if kNASint[i] != kNASenc[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("KNASint and KNASenc must differ (different P0 distinguisher)")
	}

	// Verify P0 distinguisher: KNASint input must use 0x02, KNASenc must use 0x01.
	// Derive manually and compare.
	intS := []byte{0x69, 0x02, 0x00, 0x01, algID, 0x00, 0x01}
	encS := []byte{0x69, 0x01, 0x00, 0x01, algID, 0x00, 0x01}
	wantInt := derive(kamf, intS)[16:]
	wantEnc := derive(kamf, encS)[16:]

	if !bytes.Equal(kNASint, wantInt) {
		t.Errorf("KNASint P0 wrong\n got  %x\n want %x", kNASint, wantInt)
	}
	if !bytes.Equal(kNASenc, wantEnc) {
		t.Errorf("KNASenc P0 wrong\n got  %x\n want %x", kNASenc, wantEnc)
	}
}

// TestHRESStar follows from XRES* above.
func TestHRESStar(t *testing.T) {
	rand := h16("f989f842e5a1e51c3e70af13a81c0f8e")
	xresStar := h("4a4f45213531dd1e2992813b946838e2")

	want := "09c98ac99e2d091495dd1eb8b9605939"
	got := hex.EncodeToString(kdf.HRESStar(rand, xresStar))
	if got != want {
		t.Errorf("HRES*\n got  %s\n want %s", got, want)
	}
}
