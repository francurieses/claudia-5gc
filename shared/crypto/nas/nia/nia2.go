// Package nia implements the 5G NAS integrity algorithms.
//
// NIA0: Null integrity (no protection — emergency calls only).
// NIA1: SNOW 3G based — not implemented (use free5GC implementation).
// NIA2: AES-CMAC (128-bit key, 128-bit block) — THIS PACKAGE.
// NIA3: ZUC based — not implemented.
//
// Ref: TS 33.501 Annex D §D.2 (NIA2)
//      TS 33.401 Annex B §B.2 (EIA2, identical algorithm)
//      RFC 4493 (AES-CMAC)
package nia

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// NIA2 computes the NAS-MAC (32 bits) using 128-NIA2 (AES-CMAC truncated).
//
// Parameters:
//   key     — 128-bit NAS integrity key (KNASint)
//   count   — 32-bit NAS COUNT
//   bearer  — 5-bit bearer identity (0 for NAS)
//   dir     — 1-bit direction (0=uplink, 1=downlink)
//   message — the NAS message to protect
//
// Returns 4-byte MAC (truncated from 128-bit CMAC output per spec).
// Ref: TS 33.501 Annex D.3.2
func NIA2(key []byte, count uint32, bearer, dir byte, message []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("nia2: key must be 128 bits")
	}

	// Build the 8-byte input block: COUNT(4) | BEARER(5 bits) | DIR(1 bit) | SPARE(26 bits)
	// Ref: TS 33.501 Annex D.3.2 Figure D.3.2-1
	var msg0 [8]byte
	binary.BigEndian.PutUint32(msg0[0:4], count)
	msg0[4] = (bearer & 0x1F) << 3 // BEARER occupies bits 7..3 of byte 4
	msg0[4] |= (dir & 0x01) << 2   // DIR at bit 2
	// bytes 5,6,7 = 0x00 (spare)

	// Input to CMAC = msg0 (8 bytes) || message
	data := make([]byte, 8+len(message))
	copy(data[0:], msg0[:])
	copy(data[8:], message)

	// Compute AES-CMAC
	mac, err := aesCMAC(key, data)
	if err != nil {
		return nil, err
	}
	// Truncate to 32 bits (first 4 bytes) per TS 33.501 Annex D.3.2
	return mac[:4], nil
}

// NIA0 returns a zero MAC (null integrity). Only valid for emergency calls.
func NIA0(message []byte) []byte {
	return []byte{0, 0, 0, 0}
}

// Verify checks a NAS-MAC using NIA2.
func Verify(key []byte, count uint32, bearer, dir byte, message, mac []byte) (bool, error) {
	expected, err := NIA2(key, count, bearer, dir, message)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected, mac) == 1, nil
}

// ---- AES-CMAC (RFC 4493) ------------------------------------------------

const blockSize = aes.BlockSize

func aesCMAC(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate subkeys K1, K2
	k1, k2, err := generateSubkeys(block)
	if err != nil {
		return nil, err
	}

	// Pad data to multiple of block size
	n := len(data)
	lastCompleteBlock := n - (n % blockSize)
	flag := false // true if last block is complete

	if n == 0 {
		// Empty message: one padded block
		lastCompleteBlock = 0
		flag = false
	} else if n%blockSize == 0 {
		flag = true
		lastCompleteBlock = n - blockSize
	}

	var lastBlock [blockSize]byte
	if flag {
		// Last block XOR'd with K1
		copy(lastBlock[:], data[lastCompleteBlock:])
		xorBlock(&lastBlock, &k1)
	} else {
		// Pad last block: 0x80 followed by zeros, XOR'd with K2
		padLen := n % blockSize
		copy(lastBlock[:padLen], data[lastCompleteBlock:n])
		lastBlock[padLen] = 0x80
		xorBlock(&lastBlock, &k2)
	}

	// CBC-MAC over all blocks
	var x [blockSize]byte // IV = 0^128
	// Process all complete blocks
	for i := 0; i < lastCompleteBlock; i += blockSize {
		xorBlockBytes(&x, data[i:i+blockSize])
		block.Encrypt(x[:], x[:])
	}
	// Process last block
	xorBlock(&x, &lastBlock)
	block.Encrypt(x[:], x[:])

	return x[:], nil
}

func generateSubkeys(block interface{ Encrypt(dst, src []byte) }) ([blockSize]byte, [blockSize]byte, error) {
	var zero, L [blockSize]byte
	block.Encrypt(L[:], zero[:])

	var k1 [blockSize]byte
	shiftLeft1(&k1, &L)
	if L[0]&0x80 != 0 {
		k1[blockSize-1] ^= 0x87
	}

	var k2 [blockSize]byte
	shiftLeft1(&k2, &k1)
	if k1[0]&0x80 != 0 {
		k2[blockSize-1] ^= 0x87
	}
	return k1, k2, nil
}

func shiftLeft1(dst, src *[blockSize]byte) {
	carry := byte(0)
	for i := blockSize - 1; i >= 0; i-- {
		dst[i] = (src[i] << 1) | carry
		carry = src[i] >> 7
	}
}

func xorBlock(a *[blockSize]byte, b *[blockSize]byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}

func xorBlockBytes(a *[blockSize]byte, b []byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}
