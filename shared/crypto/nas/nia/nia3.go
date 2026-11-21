// Portions derived from free5GC nas (github.com/free5gc/nas, internal/algo/nia.go),
// Copyright free5GC, Apache License 2.0. Project licence: GPL-3.0-or-later.

package nia

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/francurieses/claudia-5gc/shared/crypto/nas/zuc"
)

// NIA3 computes the 32-bit NAS-MAC with 128-NIA3 (ZUC based, identical to
// 128-EIA3) over a whole-byte message. Parameters as for NIA1.
//
// Ref: TS 33.501 Annex D.3.1.4; TS 33.401 Annex B.2.3; ETSI SAGE 128-EEA3 &
// 128-EIA3 Document 1 §4; TS 35.221/35.223.
func NIA3(key []byte, count uint32, bearer, dir byte, message []byte) ([]byte, error) {
	if len(message) > math.MaxInt/8 {
		return nil, fmt.Errorf("nia: message too long (%d bytes)", len(message))
	}
	return NIA3Bits(key, count, bearer, dir, message, len(message)*8)
}

// NIA3Bits is NIA3 for a message of bitLen bits; see NIA1Bits.
func NIA3Bits(key []byte, count uint32, bearer, dir byte, message []byte, bitLen int) ([]byte, error) {
	if len(key) != 16 {
		return nil, ErrKeyLength
	}
	if err := checkBitLen(message, bitLen); err != nil {
		return nil, err
	}
	// EIA3 IV (SAGE EIA3 §4.3): IV0..3 = COUNT, IV4 = BEARER || 000,
	// IV5..7 = 0, IV8 = IV0 ^ DIR<<7, IV9..13 = IV1..5, IV14 = IV6 ^ DIR<<7,
	// IV15 = IV7.
	var iv [16]byte
	binary.BigEndian.PutUint32(iv[0:4], count)
	iv[4] = (bearer & 0x1F) << 3
	copy(iv[8:], iv[:8])
	d := (dir & 0x01) << 7
	iv[8] ^= d
	iv[14] ^= d

	// L = ceil(LENGTH/32) + 2 keystream words.
	ks, err := zuc.Keystream(key, iv[:], (bitLen+31)/32+2)
	if err != nil {
		return nil, fmt.Errorf("nia: nia3 keystream: %w", err)
	}
	var t uint32
	for i := 0; i < bitLen; i++ {
		if message[i/8]>>(7-uint(i%8))&1 == 1 {
			t ^= keystreamWord(ks, i)
		}
	}
	t ^= keystreamWord(ks, bitLen)
	t ^= ks[len(ks)-1] // z_{32(L-1)}

	mac := make([]byte, 4)
	binary.BigEndian.PutUint32(mac, t)
	return mac, nil
}

// keystreamWord returns the 32-bit word of the keystream starting at bit i.
func keystreamWord(ks []uint32, i int) uint32 {
	w, s := i/32, uint(i%32)
	if s == 0 {
		return ks[w]
	}
	return ks[w]<<s | ks[w+1]>>(32-s)
}
