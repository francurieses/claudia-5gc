// Package eapaka implements the EAP-AKA' (RFC 5448) key hierarchy and packet
// codec used by the AUSF as the EAP server in 5G primary authentication.
//
// It is additive crypto built on top of the existing shared/crypto/kdf PRF
// (HMAC-SHA-256); it does not modify any existing key-derivation primitive.
//
// Key hierarchy (RFC 5448 §3.3–§3.4, TS 33.501 §6.1.3.1):
//
//	CK'||IK' = KDF(CK||IK, FC=0x20, P0=SN-name, P1=SQN⊕AK)   (TS 33.402 A.2)
//	MK       = PRF'(IK'||CK', "EAP-AKA'" || Identity)
//	MK split : K_encr(16) | K_aut(32) | K_re(32) | MSK(64) | EMSK(64)
//	K_AUSF   = EMSK[0:32]
//
// Golden vectors: RFC 5448 Appendix C (see eapaka_test.go).
package eapaka

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
)

// FC for the CK'/IK' derivation (TS 33.402 Annex A.2).
const fcCKPrimeIKPrime = 0x20

// Lengths of the EAP-AKA' key-hierarchy outputs (bytes).
const (
	lenKEncr = 16
	lenKAut  = 32
	lenKRe   = 32
	lenMSK   = 64
	lenEMSK  = 64
	// mkLen is the total Master Key length consumed from PRF'.
	mkLen = lenKEncr + lenKAut + lenKRe + lenMSK + lenEMSK // 208
)

// prfPrimeLabel is the constant prepended to the Identity in MK derivation.
var prfPrimeLabel = []byte("EAP-AKA'")

// Keys holds the EAP-AKA' key hierarchy derived from CK'/IK' and the Identity.
type Keys struct {
	KEncr []byte // 16 bytes — AT_ENCR_DATA cipher key (unused here, kept for completeness)
	KAut  []byte // 32 bytes — AT_MAC key (HMAC-SHA-256-128)
	KRe   []byte // 32 bytes — re-authentication key
	MSK   []byte // 64 bytes
	EMSK  []byte // 64 bytes
}

// DeriveCKPrimeIKPrime computes CK' and IK' from CK, IK, the serving-network
// (access network) name and SQN⊕AK, per TS 33.402 Annex A.2 (KDF FC = 0x20).
func DeriveCKPrimeIKPrime(ck, ik [16]byte, snName string, sqnXorAK [6]byte) (ckPrime, ikPrime [16]byte) {
	key := make([]byte, 0, 32)
	key = append(key, ck[:]...)
	key = append(key, ik[:]...)
	out := kdf.DeriveRaw(key, fcCKPrimeIKPrime, [][]byte{[]byte(snName), sqnXorAK[:]})
	copy(ckPrime[:], out[0:16])
	copy(ikPrime[:], out[16:32])
	return ckPrime, ikPrime
}

// PRFPrime is the RFC 5448 §3.4 pseudo-random function:
//
//	PRF'(K,S) = T1 | T2 | T3 | …
//	T1 = HMAC-SHA-256(K, S | 0x01)
//	Tn = HMAC-SHA-256(K, T(n-1) | S | n)
//
// It returns the first outLen bytes of the concatenated blocks.
func PRFPrime(key, s []byte, outLen int) []byte {
	out := make([]byte, 0, ((outLen+31)/32)*32)
	var prev []byte
	for i := byte(1); len(out) < outLen; i++ {
		mac := hmac.New(sha256.New, key)
		mac.Write(prev)
		mac.Write(s)
		mac.Write([]byte{i})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:outLen]
}

// DeriveKeys derives the EAP-AKA' key hierarchy from CK'/IK' and the EAP Identity.
//
//	MK = PRF'(IK'||CK', "EAP-AKA'" || Identity)
//
// per RFC 5448 §3.3.
func DeriveKeys(ckPrime, ikPrime [16]byte, identity string) Keys {
	key := make([]byte, 0, 32)
	key = append(key, ikPrime[:]...) // note: IK' first, then CK'
	key = append(key, ckPrime[:]...)

	s := make([]byte, 0, len(prfPrimeLabel)+len(identity))
	s = append(s, prfPrimeLabel...)
	s = append(s, []byte(identity)...)

	mk := PRFPrime(key, s, mkLen)

	var off int
	next := func(n int) []byte {
		b := mk[off : off+n]
		off += n
		return b
	}
	return Keys{
		KEncr: next(lenKEncr),
		KAut:  next(lenKAut),
		KRe:   next(lenKRe),
		MSK:   next(lenMSK),
		EMSK:  next(lenEMSK),
	}
}

// KAUSFFromEMSK returns the K_AUSF used for EAP-AKA' in 5G: the 256 most
// significant bits of the EMSK (TS 33.501 §6.1.3.1).
func KAUSFFromEMSK(emsk []byte) []byte {
	out := make([]byte, 32)
	copy(out, emsk[:32])
	return out
}
