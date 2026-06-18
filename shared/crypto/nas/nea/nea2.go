// Package nea implements the 5G NAS ciphering algorithms.
//
// NEA0: Null ciphering (plaintext — acceptable in lab environments).
// NEA1: SNOW 3G based — not implemented.
// NEA2: AES-CTR (128-bit key) — THIS PACKAGE.
// NEA3: ZUC based — not implemented.
//
// Ref: TS 33.501 Annex D §D.3 (NEA2)
//      TS 33.401 Annex B §B.1 (EEA2, identical algorithm)
package nea

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// NEA2 encrypts (or decrypts — CTR is symmetric) a NAS message payload.
//
// Parameters:
//   key     — 128-bit NAS ciphering key (KNASenc)
//   count   — 32-bit NAS COUNT
//   bearer  — 5-bit bearer identity (0 for NAS)
//   dir     — 1-bit direction (0=uplink, 1=downlink)
//   message — plaintext (encrypt) or ciphertext (decrypt)
//
// Returns the XOR'd result.
// Ref: TS 33.501 Annex D.3.3
func NEA2(key []byte, count uint32, bearer, dir byte, message []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("nea2: key must be 128 bits")
	}

	// Build the 128-bit IV per TS 33.401 Annex B §B.1.2:
	// IV[127:96]=COUNT | IV[95:91]=BEARER | IV[90]=DIR | IV[89:0]=0
	// The second 64 bits are all zero (not a repeat of the first half).
	var iv [16]byte
	binary.BigEndian.PutUint32(iv[0:4], count)
	iv[4] = (bearer&0x1F)<<3 | (dir&0x01)<<2
	// iv[5:16] remain zero

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv[:])

	out := make([]byte, len(message))
	stream.XORKeyStream(out, message)
	return out, nil
}

// NEA0 is the null cipher — returns message unchanged.
func NEA0(message []byte) []byte {
	out := make([]byte, len(message))
	copy(out, message)
	return out
}
