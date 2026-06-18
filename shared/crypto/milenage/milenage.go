// Package milenage implements the Milenage authentication and key agreement
// algorithm set defined in 3GPP TS 35.206.
//
// Milenage is the ETSI/3GPP standard algorithm set used by most operators.
// The core is AES-128 (Rijndael). The operator-customizable constants OPc, r,
// and c define the specific variant.
//
// Reference: 3GPP TS 35.206 v17.0.0
// Test vectors: 3GPP TS 35.207 v17.0.0
package milenage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

const (
	KeyLen  = 16 // 128-bit key
	OPLen   = 16 // 128-bit OP/OPc
	RandLen = 16
	SQNLen  = 6
	AMFLen  = 2
)

// AV is a full 5G authentication vector (renamed fields vs EPS to match
// TS 33.501 §6.1.3.2).
type AV struct {
	RAND [16]byte // 128-bit random challenge
	XRES [8]byte  // 64-bit expected response
	AUTN [16]byte // authentication token (SQN ⊕ AK || AMF || MAC-A)
	CK   [16]byte // ciphering key
	IK   [16]byte // integrity key
}

// ComputeOPc derives OPc from OP and K per TS 35.206 §4:
//
//	OPc = OP ⊕ E[OP]_K
func ComputeOPc(k, op [16]byte) ([16]byte, error) {
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return [16]byte{}, err
	}
	var opc [16]byte
	block.Encrypt(opc[:], op[:])
	xor16P(&opc, &op)
	return opc, nil
}

// GenerateAV computes a full authentication vector given:
//
//	k    — subscriber secret key (128 bit)
//	opc  — operator variant AK (derived from OP via ComputeOPc)
//	rand — random challenge (128 bit); caller must generate randomly
//	sqn  — 48-bit sequence number (packed in 6 bytes)
//	amf  — 16-bit authentication management field
//
// Returns AV, plus the anonymity key AK (needed to recover SQN from AUTN).
// Ref: TS 35.206 §4.1
func GenerateAV(k, opc [16]byte, rand [16]byte, sqn [6]byte, amf [2]byte) (AV, [6]byte, error) {
	// f2, f3, f4, f5 (and f1) share the same AES keyed with K.
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return AV{}, [6]byte{}, err
	}

	// Temp = E[RAND ⊕ OPc]_K  (TS 35.206 §4.1 step 1)
	var temp [16]byte
	buf := xorBytes16(rand, opc)
	block.Encrypt(temp[:], buf[:])

	// ---- f1 (MAC-A) ----
	out1 := computeOut1(block, temp, opc, sqn, amf)
	macA := [8]byte(out1[0:8])

	// AUTN = (SQN ⊕ AK) || AMF || MAC-A  (AK extracted below from out2)

	// ---- f2 (XRES) and f5 (AK) — same cipher output, per TS 35.206 §4.1 ----
	// AK = OUT2[0..47], XRES = OUT2[64..127]
	var out2 [16]byte
	rot2 := rotateTowardMSB128(xorBytes16(temp, opc), rotR()[1])
	xorC := xorBytes16(rot2, applyConstC2())
	block.Encrypt(out2[:], xorC[:])
	xor16P(&out2, &opc)
	ak := [6]byte(out2[0:6])
	xres := [8]byte(out2[8:16])

	var autn [16]byte
	sqnXorAK := xorSQN(sqn, ak)
	copy(autn[0:], sqnXorAK[:])
	copy(autn[6:], amf[:])
	copy(autn[8:], macA[:])

	// ---- f3 (CK) ----
	var out3 [16]byte
	rot3 := rotateTowardMSB128(xorBytes16(temp, opc), rotR()[2])
	xorC3 := xorBytes16(rot3, applyConstC3())
	block.Encrypt(out3[:], xorC3[:])
	xor16P(&out3, &opc)
	ck := [16]byte(out3)

	// ---- f4 (IK) ----
	var out4 [16]byte
	rot4 := rotateTowardMSB128(xorBytes16(temp, opc), rotR()[3])
	xorC4 := xorBytes16(rot4, applyConstC4())
	block.Encrypt(out4[:], xorC4[:])
	xor16P(&out4, &opc)
	ik := [16]byte(out4)

	av := AV{
		RAND: rand,
		XRES: xres,
		AUTN: autn,
		CK:   ck,
		IK:   ik,
	}
	return av, ak, nil
}

// ComputeMACS computes f1* (the re-synchronisation MAC) for the given SQN_MS.
// MAC-S = OUT1[64..127] — the second half of the f1/f1* output block, NOT the
// f1 (MAC-A) half. For re-synchronisation the AMF input shall be the dummy
// value 0x0000 (TS 33.102 §6.3.3); callers pass amf explicitly so test vectors
// with other AMF values (TS 35.207 §6) can be verified too.
// Ref: TS 35.206 §4.1 (f1*), TS 33.102 §6.3.3
func ComputeMACS(k, opc [16]byte, rand [16]byte, sqnMS [6]byte, amf [2]byte) ([8]byte, error) {
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return [8]byte{}, err
	}
	var temp [16]byte
	buf := xorBytes16(rand, opc)
	block.Encrypt(temp[:], buf[:])
	out1 := computeOut1(block, temp, opc, sqnMS, amf)
	return [8]byte(out1[8:16]), nil
}

// VerifyMACS computes f1* over (RAND, SQN_MS, AMF=0x0000) and compares it with
// the MAC-S received in AUTS in constant time.
// Used by the network (UDM/ARPF) to validate a UE re-sync token.
// Ref: TS 35.206 §4.1 (f1*), TS 33.102 §6.3.3 / §6.3.5
func VerifyMACS(k, opc [16]byte, rand [16]byte, sqnMS [6]byte, _ [2]byte, macS [8]byte) (bool, error) {
	// AMF for MAC-S verification is the dummy value 0x0000 per TS 33.102 §6.3.3.
	expected, err := ComputeMACS(k, opc, rand, sqnMS, [2]byte{0x00, 0x00})
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected[:], macS[:]) == 1, nil
}

// computeOut1 evaluates the shared f1/f1* output block:
//
//	IN1  = SQN || AMF || SQN || AMF
//	OUT1 = E[TEMP ⊕ rot(IN1 ⊕ OPc, r1) ⊕ c1]_K ⊕ OPc
//
// MAC-A = OUT1[0..63], MAC-S = OUT1[64..127].
// Ref: TS 35.206 §4.1
func computeOut1(block cipher.Block, temp, opc [16]byte, sqn [6]byte, amf [2]byte) [16]byte {
	var in1 [16]byte
	copy(in1[0:], sqn[:])
	copy(in1[6:], amf[:])
	copy(in1[8:], sqn[:])
	copy(in1[14:], amf[:])

	var out1 [16]byte
	rot := rotateTowardMSB128(xorBytes16(xorBytes16(in1, opc), applyConstC1()), rotR()[0])
	xor16P(&rot, &temp)
	block.Encrypt(out1[:], rot[:])
	xor16P(&out1, &opc)
	return out1
}

// f5Star computes the re-sync anonymity key AK* (TS 35.206 §4.1 function f5*).
// Returns AK* (6 bytes) which allows the network to recover SQN from AUTS.
func F5Star(k, opc [16]byte, rand [16]byte) ([6]byte, error) {
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return [6]byte{}, err
	}
	var temp [16]byte
	buf := xorBytes16(rand, opc)
	block.Encrypt(temp[:], buf[:])

	// f5* uses rotation r5* and constant c5*
	rot := rotateTowardMSB128(xorBytes16(temp, opc), rotR()[4])
	xorC := xorBytes16(rot, applyConstC5())
	var out [16]byte
	block.Encrypt(out[:], xorC[:])
	xor16P(&out, &opc)
	return [6]byte(out[0:6]), nil
}

// SQNFromAUTS extracts SQN from AUTS (re-sync token from UE):
//
//	AUTS = SQN_MS ⊕ AK* || MAC-S (last 8 bytes)
//
// Returns SQN_MS (6 bytes) decoded.
func SQNFromAUTS(auts [14]byte, akStar [6]byte) [6]byte {
	var sqn [6]byte
	for i := 0; i < 6; i++ {
		sqn[i] = auts[i] ^ akStar[i]
	}
	return sqn
}

// ValidateAUTN checks AUTN received from the UE and extracts SQN.
// Returns (sqn, amf, macA, ok).
// Ref: TS 35.206 §4.1 — UE side verification (mirrored here for test purposes)
func ValidateAUTN(autn [16]byte, ak [6]byte) (sqn [6]byte, amf [2]byte, macA [8]byte, err error) {
	// Recover SQN
	for i := 0; i < 6; i++ {
		sqn[i] = autn[i] ^ ak[i]
	}
	copy(amf[:], autn[6:8])
	copy(macA[:], autn[8:16])
	if sqn == ([6]byte{}) && amf == ([2]byte{}) && macA == ([8]byte{}) {
		err = errors.New("AUTN appears zeroed — invalid")
	}
	return
}

// ---- Milenage internal constants (TS 35.206 §4.1) -----

// rotR: rotation offsets (bits) — r1..r5, r1*..r5* (same values)
func rotR() [5]int {
	return [5]int{64, 0, 32, 64, 96}
}

// The c constants (XOR masks), each 128 bits = 16 bytes.
func applyConstC1() [16]byte { return [16]byte{} }                   // c1 = 0^128
func applyConstC2() [16]byte { var c [16]byte; c[15] = 1; return c } // c2 = 0^126 || 01
func applyConstC3() [16]byte { var c [16]byte; c[15] = 2; return c } // c3 = 0^126 || 10
func applyConstC4() [16]byte { var c [16]byte; c[15] = 4; return c } // c4 = 0^125 || 100
func applyConstC5() [16]byte { var c [16]byte; c[15] = 8; return c } // c5 = 0^124 || 1000

// ---- bit helpers -------------------------------------------------------

func xorBytes16(a, b [16]byte) [16]byte {
	var out [16]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func xor16P(a, b *[16]byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}

func xorSQN(a, b [6]byte) [6]byte {
	var out [6]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// rotateTowardMSB128 cyclically rotates a 128-bit value by n bits toward the
// most significant bit (i.e. a left rotation), matching rot(x, r) in
// TS 35.206 §4.1. (Previously misnamed rotateRight128 — the byte indexing
// in fact shifts toward the MSB, which is what the spec requires.)
func rotateTowardMSB128(in [16]byte, n int) [16]byte {
	if n == 0 {
		return in
	}
	n = n % 128
	byteShift := n / 8
	bitShift := uint(n % 8)
	var out [16]byte
	for i := 0; i < 16; i++ {
		src := (i + byteShift) % 16
		out[i] = in[src] >> bitShift
		if bitShift > 0 {
			out[i] |= in[(src+1)%16] << (8 - bitShift)
		}
	}
	return out
}
