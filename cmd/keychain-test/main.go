// keychain-test verifies the 5G NAS key chain computation against known values.
//
// Usage:
//   keychain-test                          — fixed RAND test vector
//   keychain-test <rand_hex> <kausf_hex>   — verify chain against AMF-logged KAUSF
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/crypto/milenage"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad hex %q: %v\n", s, err)
		os.Exit(1)
	}
	return b
}

// deriveChain computes the full NAS key chain from KAUSF.
func deriveChain(kausf []byte, snName, supi string, abba [2]byte, algID byte) {
	kseaf := kdf.KSEAF(kausf, snName)
	kamf := kdf.KAMF(kseaf, supi, abba)
	knasint := kdf.KNASint(kamf, algID)
	knasenc := kdf.KNASenc(kamf, algID)

	fmt.Printf("  KSEAF:   %x\n", kseaf)
	fmt.Printf("  KAMF:    %x\n", kamf)
	fmt.Printf("  KNASint: %x\n", knasint)
	fmt.Printf("  KNASenc: %x\n", knasenc)

	// NIA2 MAC for a typical SMC body (SQN=0, innerPDU=7e005d220004a0a0a0a0)
	innerPDU, _ := hex.DecodeString("7e005d220004a0a0a0a0")
	macInput := make([]byte, 1+len(innerPDU))
	macInput[0] = 0x00 // SQN=0
	copy(macInput[1:], innerPDU)
	mac, _ := nia.NIA2(knasint, 0, 0x01, 0x01, macInput)
	fmt.Printf("  NIA2 MAC (count=0, bearer=1, DL): %x\n", mac)
}

func main() {
	// UERANSIM UE config values (MCC=001, MNC=01)
	k := mustHex("465b5ce8b199b49faa5f0a2ee238a6bc")
	opc := mustHex("cd63cb71954a9f4e48a5994e37a02baf")
	amfBytes := mustHex("b9b9")
	snName := "5G:mnc001.mcc001.3gppnetwork.org"
	supiWithPrefix := "imsi-001010000000001"
	supiNoPrefix := "001010000000001"
	abba := [2]byte{0x00, 0x00}

	var K, OPc [16]byte
	var AMF [2]byte
	copy(K[:], k)
	copy(OPc[:], opc)
	copy(AMF[:], amfBytes)

	if len(os.Args) == 3 {
		// Verify chain against a logged KAUSF + RAND pair
		randBytes := mustHex(os.Args[1])
		kausfBytes := mustHex(os.Args[2])

		var RAND [16]byte
		copy(RAND[:], randBytes)

		// Use initial SQN (first cycle after install, SQN incremented to 0x21 for attempt 1)
		// We try SQN=0x20 since the UERANSIM log showed SQN=0x20
		sqnBytes := mustHex("000000000020")
		var SQN [6]byte
		copy(SQN[:], sqnBytes)

		av, ak, err := milenage.GenerateAV(K, OPc, RAND, SQN, AMF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "milenage: %v\n", err)
			os.Exit(1)
		}

		var sqnXorAK [6]byte
		for i := 0; i < 6; i++ {
			sqnXorAK[i] = SQN[i] ^ ak[i]
		}
		kausfComputed := kdf.KAUSF(av.CK, av.IK, snName, sqnXorAK)

		fmt.Printf("=== KAUSF verification ===\n")
		fmt.Printf("RAND:          %x\n", RAND)
		fmt.Printf("KAUSF(log):    %x\n", kausfBytes)
		fmt.Printf("KAUSF(comput): %x\n", kausfComputed)
		if hex.EncodeToString(kausfBytes) == hex.EncodeToString(kausfComputed) {
			fmt.Printf("KAUSF: MATCH ✓\n")
		} else {
			fmt.Printf("KAUSF: MISMATCH ✗\n")
		}

		fmt.Printf("\n=== Chain from logged KAUSF, supi='%s' ===\n", supiWithPrefix)
		deriveChain(kausfBytes, snName, supiWithPrefix, abba, 2)

		fmt.Printf("\n=== Chain from logged KAUSF, supi='%s' (no prefix) ===\n", supiNoPrefix)
		deriveChain(kausfBytes, snName, supiNoPrefix, abba, 2)
		return
	}

	// No args: use a fixed RAND for deterministic output
	randBytes := mustHex("23553cbe9637a89d218ae64dae47bf35")
	sqnBytes := mustHex("000000000001")
	var RAND [16]byte
	var SQN [6]byte
	copy(RAND[:], randBytes)
	copy(SQN[:], sqnBytes)

	av, ak, err := milenage.GenerateAV(K, OPc, RAND, SQN, AMF)
	if err != nil {
		fmt.Fprintf(os.Stderr, "milenage: %v\n", err)
		os.Exit(1)
	}

	var sqnXorAK [6]byte
	for i := 0; i < 6; i++ {
		sqnXorAK[i] = SQN[i] ^ ak[i]
	}

	kausf := kdf.KAUSF(av.CK, av.IK, snName, sqnXorAK)

	fmt.Printf("=== Fixed test vector ===\n")
	fmt.Printf("K:       %x\n", K)
	fmt.Printf("OPc:     %x\n", OPc)
	fmt.Printf("AMF:     %x\n", AMF)
	fmt.Printf("SQN:     %x\n", SQN)
	fmt.Printf("RAND:    %x\n", RAND)
	fmt.Printf("CK:      %x\n", av.CK)
	fmt.Printf("IK:      %x\n", av.IK)
	fmt.Printf("AK:      %x\n", ak)
	fmt.Printf("SQN^AK:  %x\n", sqnXorAK)
	fmt.Printf("KAUSF:   %x\n", kausf)

	fmt.Printf("\n--- Chain with supi='%s' ---\n", supiWithPrefix)
	deriveChain(kausf, snName, supiWithPrefix, abba, 2)

	fmt.Printf("\n--- Chain with supi='%s' (no imsi- prefix) ---\n", supiNoPrefix)
	deriveChain(kausf, snName, supiNoPrefix, abba, 2)
}
