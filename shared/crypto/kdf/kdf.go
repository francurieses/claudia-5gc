// Package kdf implements the 5G key derivation functions defined in
// 3GPP TS 33.501 Annex A.
//
// All KDFs use the common PRF (HMAC-SHA-256) defined in §A.1:
//
//	KDF(key, S) = HMAC-SHA-256(key, S)   [first 256 bits = output]
//
// The parameter S is built by concatenating encoded TLV parameter blocks:
//
//	S = FC || P0 || L0 || P1 || L1 || ...
//
// where FC is the function code (1 byte) and Pn/Ln are (value || 2-byte-len) pairs.
package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// ---- KDF primitives --------------------------------------------------------

// derive computes HMAC-SHA-256(key, S) and returns the full 32-byte output.
func derive(key, s []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(s)
	return mac.Sum(nil)
}

// buildS constructs the KDF input string:
//   S = FC || (P0 || L0) || (P1 || L1) || ...
// Each parameter is: its value bytes followed by its 2-byte big-endian length.
func buildS(fc byte, params ...[]byte) []byte {
	s := []byte{fc}
	for _, p := range params {
		s = append(s, p...)
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(p)))
		s = append(s, l...)
	}
	return s
}

// ---- 5G-AKA key hierarchy (TS 33.501 §A) -----------------------------------

// KAUSF derives the 5G AUSF key from CK, IK, and Serving Network Name.
// FC = 0x6A, P0 = SN name (UTF-8), P1 = SQN ⊕ AK  (6 bytes)
// Ref: TS 33.501 §A.2
func KAUSF(ck, ik [16]byte, snName string, sqnXorAK [6]byte) []byte {
	key := append(ck[:], ik[:]...)
	s := buildS(0x6A, []byte(snName), sqnXorAK[:])
	return derive(key, s)
}

// KSEAF derives the SEAF key from KAUSF and Serving Network Name.
// FC = 0x6C, P0 = SN name
// Ref: TS 33.501 §A.6
func KSEAF(kausf []byte, snName string) []byte {
	s := buildS(0x6C, []byte(snName))
	return derive(kausf, s)
}

// KAMF derives the AMF key from KSEAF, SUPI, and ABBA.
// FC = 0x6D, P0 = SUPI (as UTF-8), P1 = ABBA (2 bytes)
// Ref: TS 33.501 §A.7
func KAMF(kseaf []byte, supi string, abba [2]byte) []byte {
	s := buildS(0x6D, []byte(supi), abba[:])
	return derive(kseaf, s)
}

// Algorithm type distinguishers for the algorithm key derivation function
// (TS 33.501 §A.8 Table A.8-1).
const (
	algDistNASEnc byte = 0x01 // N-NAS-enc-alg
	algDistNASInt byte = 0x02 // N-NAS-int-alg
	algDistRRCEnc byte = 0x03 // N-RRC-enc-alg
	algDistRRCInt byte = 0x04 // N-RRC-int-alg
	algDistUPEnc  byte = 0x05 // N-UP-enc-alg
	algDistUPInt  byte = 0x06 // N-UP-int-alg
)

// KNASint derives the NAS integrity key from KAMF.
// FC = 0x69, P0 = 0x02 (N-NAS-int-alg distinguisher per TS 33.501 §A.8 Table A.8-1),
// P1 = algorithm identity (1 byte). Returns bytes [16:32] of HMAC-SHA-256 output.
func KNASint(kamf []byte, algID byte) []byte {
	s := buildS(0x69, []byte{algDistNASInt}, []byte{algID})
	out := derive(kamf, s)
	return out[16:]
}

// KNASenc derives the NAS encryption key from KAMF.
// FC = 0x69, P0 = 0x01 (N-NAS-enc-alg distinguisher per TS 33.501 §A.8 Table A.8-1),
// P1 = algorithm identity (1 byte). Returns bytes [16:32] of HMAC-SHA-256 output.
func KNASenc(kamf []byte, algID byte) []byte {
	s := buildS(0x69, []byte{algDistNASEnc}, []byte{algID})
	out := derive(kamf, s)
	return out[16:]
}

// KRRCint derives the RRC integrity key from KgNB.
// FC = 0x69, P0 = 0x04 (N-RRC-int-alg), P1 = alg ID.
// Ref: TS 33.501 §A.8
func KRRCint(kgnb []byte, algID byte) []byte {
	s := buildS(0x69, []byte{algDistRRCInt}, []byte{algID})
	out := derive(kgnb, s)
	return out[16:]
}

// KRRCenc derives the RRC encryption key from KgNB.
// FC = 0x69, P0 = 0x03 (N-RRC-enc-alg), P1 = alg ID.
// Ref: TS 33.501 §A.8
func KRRCenc(kgnb []byte, algID byte) []byte {
	s := buildS(0x69, []byte{algDistRRCEnc}, []byte{algID})
	out := derive(kgnb, s)
	return out[16:]
}

// KUPint derives the UP integrity key from KgNB.
// FC = 0x69, P0 = 0x06 (N-UP-int-alg), P1 = alg ID.
// Ref: TS 33.501 §A.8
func KUPint(kgnb []byte, algID byte) []byte {
	s := buildS(0x69, []byte{algDistUPInt}, []byte{algID})
	out := derive(kgnb, s)
	return out[16:]
}

// KUPenc derives the UP encryption key from KgNB.
// FC = 0x69, P0 = 0x05 (N-UP-enc-alg), P1 = alg ID.
// Ref: TS 33.501 §A.8
func KUPenc(kgnb []byte, algID byte) []byte {
	s := buildS(0x69, []byte{algDistUPEnc}, []byte{algID})
	out := derive(kgnb, s)
	return out[16:]
}

// KNH derives the Next Hop (NH) key used for handover security refresh.
// synchInput is the previous NH (or the initial KgNB for NCC=1).
// FC = 0x6F, P0 = SYNC-input (32 bytes).
//
// NOTE (audit fix): the FC was previously 0x6C, which is the KSEAF derivation
// FC — TS 33.501 §A.10 specifies FC = 0x6F for NH. This changes the NH value
// sent to the target gNB in the N2 HandoverRequest SecurityContext IE.
// PacketRusher (the only N2-HO peer used in this lab) does not validate the
// AS key chain, so the flow is unaffected; a real gNB/UE pair requires 0x6F.
// Ref: TS 33.501 §A.10
func KNH(kamf []byte, synchInput []byte) []byte {
	s := buildS(0x6F, synchInput)
	return derive(kamf, s)
}

// KgNB derives KgNB (base key for AS layer) from KAMF.
// FC = 0x6E, P0 = NAS Count (4 bytes), P1 = access type (1 byte: 0x01=3GPP)
// Ref: TS 33.501 §A.9
func KgNB(kamf []byte, nasCount uint32, accessType byte) []byte {
	countB := make([]byte, 4)
	binary.BigEndian.PutUint32(countB, nasCount)
	s := buildS(0x6E, countB, []byte{accessType})
	return derive(kamf, s)
}

// ---- XRES* and HRES* (TS 33.501 §A.4 / §A.5) ------------------------------

// XRESStar computes XRES* from CK, IK, SN name, RAND, XRES.
// FC = 0x6B, P0 = SN name, P1 = RAND (16 bytes), P2 = XRES (variable)
// Ref: TS 33.501 §A.4
func XRESStar(ck, ik [16]byte, snName string, rand [16]byte, xres []byte) []byte {
	key := append(ck[:], ik[:]...)
	s := buildS(0x6B, []byte(snName), rand[:], xres)
	out := derive(key, s)
	// Return last 128 bits (lower 16 bytes) per spec
	return out[16:]
}

// HRESStar computes HRES* = SHA-256(RAND || XRES*) truncated to 128 bits.
// Ref: TS 33.501 §A.5
func HRESStar(rand [16]byte, xresStar []byte) []byte {
	h := sha256.New()
	h.Write(rand[:])
	h.Write(xresStar)
	out := h.Sum(nil)
	return out[16:] // lower 128 bits
}

// DeriveRaw calls the KDF PRF with an arbitrary FC and parameter list.
// Each param is encoded as value || 2-byte-big-endian-length per TS 33.220 §B.2.
// FC codes defined in TS 33.501 Annex A:
//
//	0x6A KAUSF  (§A.2)
//	0x6B XRES*  (§A.4)
//	0x6C KSEAF  (§A.6)
//	0x6D KAMF   (§A.7)
//	0x69 KNASint/KNASenc (§A.7.1)
//	0x6E KgNB   (§A.9)
//	0x73 KRRCint/KRRCenc/KUPint/KUPenc (§A.7.2)
func DeriveRaw(key []byte, fc byte, params [][]byte) []byte {
	s := buildS(fc, params...)
	return derive(key, s)
}
