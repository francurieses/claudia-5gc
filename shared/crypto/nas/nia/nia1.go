// Portions derived from free5GC nas (github.com/free5gc/nas, internal/algo/nia.go),
// Copyright free5GC, Apache License 2.0. Project licence: GPL-3.0-or-later.

package nia

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/francurieses/claudia-5gc/shared/crypto/nas/snow3g"
)

// ErrKeyLength is returned when the NAS integrity key is not 128 bits.
var ErrKeyLength = errors.New("nia: key must be 128 bits")

// uia2PolyC is the constant c of the GF(2^64) multiplication in UIA2 f9
// (x^64 + x^4 + x^3 + x + 1). Ref: ETSI SAGE UEA2 & UIA2 Document 1 §4.3.
const uia2PolyC = 0x000000000000001b

// NIA1 computes the 32-bit NAS-MAC with 128-NIA1 (SNOW 3G based, identical to
// 128-EIA1 = UIA2 f9 with FRESH = BEARER || 0^27) over a whole-byte message.
//
// key is KNASint (128 bit), count the 32-bit NAS COUNT, bearer the 5-bit
// bearer identity, dir the direction bit (0 uplink, 1 downlink).
//
// Ref: TS 33.501 Annex D.3.1.2; TS 33.401 Annex B.2.2; TS 35.216/35.217.
func NIA1(key []byte, count uint32, bearer, dir byte, message []byte) ([]byte, error) {
	if len(message) > math.MaxInt/8 {
		return nil, fmt.Errorf("nia: message too long (%d bytes)", len(message))
	}
	return NIA1Bits(key, count, bearer, dir, message, len(message)*8)
}

// NIA1Bits is NIA1 for a message of bitLen bits (message holds at least
// ceil(bitLen/8) bytes, MSB first; bits past bitLen are ignored). NAS always
// uses whole bytes; the bit-length form exists for the TS 33.401 C.4 test sets.
func NIA1Bits(key []byte, count uint32, bearer, dir byte, message []byte, bitLen int) ([]byte, error) {
	if len(key) != 16 {
		return nil, ErrKeyLength
	}
	if err := checkBitLen(message, bitLen); err != nil {
		return nil, err
	}
	// UIA2 key/IV loading (SAGE UIA2 §4.2), word order as in snow3g.Keystream:
	// K[i] counted from the least significant end of the key.
	var k [4]uint32
	for i := range k {
		k[i] = binary.BigEndian.Uint32(key[4*(3-i):])
	}
	d := uint32(dir & 0x01)
	fresh := uint32(bearer&0x1F) << 27 // TS 33.401 B.2.2: FRESH = BEARER || 0^27
	iv := [4]uint32{fresh ^ d<<15, count ^ d<<31, fresh, count}

	z := snow3g.Keystream(k, iv, 5)
	p := uint64(z[0])<<32 | uint64(z[1])
	q := uint64(z[2])<<32 | uint64(z[3])

	// EVAL over the 64-bit message blocks (last one zero-padded), then the
	// length block with Q. Ref: SAGE UIA2 §4.3-4.4.
	var eval uint64
	for off := 0; off < bitLen; off += 64 {
		eval = mul64(eval^messageBlock(message, off, bitLen), p)
	}
	eval = mul64(eval^uint64(bitLen), q)

	mac := make([]byte, 4)
	binary.BigEndian.PutUint32(mac, uint32(eval>>32)^z[4])
	return mac, nil
}

// messageBlock returns the 64-bit block of message starting at bit off, MSB
// first, with every bit at or past bitLen cleared.
func messageBlock(message []byte, off, bitLen int) uint64 {
	var buf [8]byte
	copy(buf[:], message[off/8:min(len(message), off/8+8)])
	m := binary.BigEndian.Uint64(buf[:])
	if rem := bitLen - off; rem < 64 {
		m &= ^uint64(0) << (64 - uint(rem))
	}
	return m
}

// mul64 multiplies v by p in GF(2^64) per SAGE UIA2 §4.3 (MUL64(V, P, c)).
// It is constant-time: p and v derive from the SNOW 3G keystream and the
// message, so there are no secret-dependent branches or indexes; selection
// uses all-ones/all-zeros mask arithmetic.
func mul64(v, p uint64) uint64 {
	var r uint64
	for i := 0; i < 64; i++ {
		r ^= v & -(p >> uint(i) & 1)
		// v becomes MUL64x^(i+1)(V, c).
		v = v<<1 ^ uia2PolyC&-(v>>63)
	}
	return r
}

// checkBitLen validates bitLen against message.
func checkBitLen(message []byte, bitLen int) error {
	if bitLen < 0 {
		return fmt.Errorf("nia: negative bit length %d", bitLen)
	}
	if len(message) > math.MaxInt/8 || bitLen > 8*len(message) {
		return fmt.Errorf("nia: bit length %d exceeds message length of %d bytes", bitLen, len(message))
	}
	return nil
}
