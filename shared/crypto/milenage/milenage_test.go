package milenage_test

// Test vectors from 3GPP TS 35.207 v17.0.0 — §6 (Set 1)
// These are the normative test vectors for the Milenage algorithm set.

import (
	"encoding/hex"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/crypto/milenage"
)

// hexToBytes converts hex string to byte slice, panicking on error (test only).
func hexTo16(s string) [16]byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	if len(b) != 16 {
		panic("expected 16 bytes")
	}
	return [16]byte(b)
}

func hexTo6(s string) [6]byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return [6]byte(b)
}

func hexTo8(s string) [8]byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return [8]byte(b)
}

func hexTo2(s string) [2]byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return [2]byte(b)
}

// TestSet1 verifies using TS 35.207 §6 Set 1 vectors.
func TestSet1_ComputeOPc(t *testing.T) {
	// TS 35.207 Set 1
	k := hexTo16("465b5ce8b199b49faa5f0a2ee238a6bc")
	op := hexTo16("cdc202d5123e20f62b6d676ac72cb318")
	wantOPc := hexTo16("cd63cb71954a9f4e48a5994e37a02baf")

	opc, err := milenage.ComputeOPc(k, op)
	if err != nil {
		t.Fatalf("ComputeOPc: %v", err)
	}
	if opc != wantOPc {
		t.Errorf("OPc mismatch\n got  %x\n want %x", opc, wantOPc)
	}
}

func TestSet1_GenerateAV(t *testing.T) {
	// TS 35.207 Set 1
	k := hexTo16("465b5ce8b199b49faa5f0a2ee238a6bc")
	opc := hexTo16("cd63cb71954a9f4e48a5994e37a02baf")
	rand := hexTo16("23553cbe9637a89d218ae64dae47bf35")
	sqn := hexTo6("ff9bb4d0b607")
	amf := hexTo2("b9b9")

	av, ak, err := milenage.GenerateAV(k, opc, rand, sqn, amf)
	if err != nil {
		t.Fatalf("GenerateAV: %v", err)
	}

	wantXRES := hexTo8("a54211d5e3ba50bf")
	wantCK := hexTo16("b40ba9a3c58b2a05bbf0d987b21bf8cb")
	wantIK := hexTo16("f769bcd751044604127672711c6d3441")
	wantAK := hexTo6("aa689c648370")

	if av.XRES != wantXRES {
		t.Errorf("XRES mismatch\n got  %x\n want %x", av.XRES, wantXRES)
	}
	if av.CK != wantCK {
		t.Errorf("CK mismatch\n got  %x\n want %x", av.CK, wantCK)
	}
	if av.IK != wantIK {
		t.Errorf("IK mismatch\n got  %x\n want %x", av.IK, wantIK)
	}
	if ak != wantAK {
		t.Errorf("AK mismatch\n got  %x\n want %x", ak, wantAK)
	}
}

// TestSet1_ComputeMACS verifies f1* (MAC-S = OUT1[64..127]) against the
// normative TS 35.207 §6 Set 1 vector: f1* = 01cfaf9ec4e871e9.
func TestSet1_ComputeMACS(t *testing.T) {
	k := hexTo16("465b5ce8b199b49faa5f0a2ee238a6bc")
	opc := hexTo16("cd63cb71954a9f4e48a5994e37a02baf")
	rand := hexTo16("23553cbe9637a89d218ae64dae47bf35")
	sqn := hexTo6("ff9bb4d0b607")
	amf := hexTo2("b9b9")

	macS, err := milenage.ComputeMACS(k, opc, rand, sqn, amf)
	if err != nil {
		t.Fatalf("ComputeMACS: %v", err)
	}
	want := hexTo8("01cfaf9ec4e871e9")
	if macS != want {
		t.Errorf("MAC-S (f1*) mismatch\n got  %x\n want %x", macS, want)
	}
}

// TestSet1_F5Star verifies f5* against TS 35.207 §6 Set 1: f5* = 451e8beca43b.
func TestSet1_F5Star(t *testing.T) {
	k := hexTo16("465b5ce8b199b49faa5f0a2ee238a6bc")
	opc := hexTo16("cd63cb71954a9f4e48a5994e37a02baf")
	rand := hexTo16("23553cbe9637a89d218ae64dae47bf35")

	akStar, err := milenage.F5Star(k, opc, rand)
	if err != nil {
		t.Fatalf("F5Star: %v", err)
	}
	want := hexTo6("451e8beca43b")
	if akStar != want {
		t.Errorf("AK* (f5*) mismatch\n got  %x\n want %x", akStar, want)
	}
}
