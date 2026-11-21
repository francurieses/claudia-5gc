package nea

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/francurieses/claudia-5gc/shared/crypto/nas/snow3g"
)

// ErrKeyLength is returned when the NAS ciphering key is not 128 bits.
var ErrKeyLength = errors.New("nea: key must be 128 bits")

// NEA1 encrypts (or decrypts - the keystream XOR is symmetric) a whole-byte
// NAS message with 128-NEA1 (SNOW 3G based, identical to 128-EEA1 / UEA2).
//
// Parameters are as for NEA2: key is KNASenc (128 bit), count the 32-bit NAS
// COUNT, bearer the 5-bit bearer identity, dir the direction bit.
//
// Ref: TS 33.501 Annex D.2.1.2; TS 33.401 Annex B; TS 35.215/35.217.
func NEA1(key []byte, count uint32, bearer, dir byte, message []byte) ([]byte, error) {
	return NEA1Bits(key, count, bearer, dir, message, len(message)*8)
}

// NEA1Bits is NEA1 for a message of bitLen bits (message holds at least
// ceil(bitLen/8) bytes, MSB first). The returned slice has ceil(bitLen/8)
// bytes with any unused trailing bits of the last byte set to zero. NAS always
// uses whole bytes; the bit-length form exists for the TS 35.217 test sets.
func NEA1Bits(key []byte, count uint32, bearer, dir byte, message []byte, bitLen int) ([]byte, error) {
	if len(key) != 16 {
		return nil, ErrKeyLength
	}
	nBytes, err := bitLenBytes(message, bitLen)
	if err != nil {
		return nil, err
	}
	// TS 33.401 Annex B / UEA2: K[i] is the i-th 32-bit word counted from the
	// least significant end of the key.
	var k [4]uint32
	for i := range k {
		k[i] = binary.BigEndian.Uint32(key[4*(3-i):])
	}
	dirBearer := uint32(bearer&0x1F)<<27 | uint32(dir&0x01)<<26
	iv := [4]uint32{dirBearer, count, dirBearer, count}

	ks := snow3g.Keystream(k, iv, (bitLen+31)/32)
	return xorKeystream(message[:nBytes], ks, bitLen), nil
}

// bitLenBytes validates bitLen against message and returns ceil(bitLen/8).
func bitLenBytes(message []byte, bitLen int) (int, error) {
	if bitLen < 0 {
		return 0, fmt.Errorf("nea: negative bit length %d", bitLen)
	}
	// Compare against 8*len(message) first so bitLen+7 can never overflow.
	if len(message) > math.MaxInt/8 || bitLen > 8*len(message) {
		return 0, fmt.Errorf("nea: bit length %d exceeds message length of %d bytes", bitLen, len(message))
	}
	n := bitLen / 8
	if bitLen%8 != 0 {
		n++
	}
	if len(message) < n {
		return 0, fmt.Errorf("nea: message has %d bytes, need %d for %d bits", len(message), n, bitLen)
	}
	return n, nil
}

// xorKeystream XORs in with the big-endian keystream words and clears the
// unused trailing bits of the last byte.
func xorKeystream(in []byte, ks []uint32, bitLen int) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[i] ^ byte(ks[i/4]>>(8*(3-uint(i%4))))
	}
	if r := bitLen % 8; r != 0 {
		out[len(out)-1] &= 0xFF << (8 - uint(r))
	}
	return out
}
