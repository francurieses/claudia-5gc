package nea

import (
	"encoding/binary"
	"fmt"

	"github.com/francurieses/claudia-5gc/shared/crypto/nas/zuc"
)

// NEA3 encrypts (or decrypts - symmetric) a whole-byte NAS message with
// 128-NEA3 (ZUC based, identical to 128-EEA3). Parameters as for NEA2.
//
// Ref: TS 33.501 Annex D.2.1.4; TS 33.401 Annex B; TS 35.221/35.223.
func NEA3(key []byte, count uint32, bearer, dir byte, message []byte) ([]byte, error) {
	return NEA3Bits(key, count, bearer, dir, message, len(message)*8)
}

// NEA3Bits is NEA3 for a message of bitLen bits; see NEA1Bits for the
// semantics of bitLen and the returned slice.
func NEA3Bits(key []byte, count uint32, bearer, dir byte, message []byte, bitLen int) ([]byte, error) {
	if len(key) != 16 {
		return nil, ErrKeyLength
	}
	nBytes, err := bitLenBytes(message, bitLen)
	if err != nil {
		return nil, err
	}
	// ZUC IV (TS 33.401 Annex B.1.3): COUNT | BEARER(5) DIRECTION(1) 0^26,
	// with the 64-bit value repeated in the second half.
	var iv [16]byte
	binary.BigEndian.PutUint32(iv[0:4], count)
	iv[4] = (bearer&0x1F)<<3 | (dir&0x01)<<2
	copy(iv[8:], iv[:8])

	ks, err := zuc.Keystream(key, iv[:], (bitLen+31)/32)
	if err != nil {
		return nil, fmt.Errorf("nea: nea3 keystream: %w", err)
	}
	return xorKeystream(message[:nBytes], ks, bitLen), nil
}
