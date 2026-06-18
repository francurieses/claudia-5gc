// Package suci implements SUCI (Subscription Concealed Identifier)
// deconcealment as defined in 3GPP TS 33.501 §6.12 and Annex C.
//
// SUCI hides the SUPI from passive eavesdroppers on the air interface by
// using ECIES (Elliptic Curve Integrated Encryption Scheme). The UE encrypts
// the MSIN portion of the SUPI using the operator's public key.
//
// Two ECIES protection scheme profiles are defined:
//   - Profile A: X25519 key exchange + AES-128-CTR + HMAC-SHA-256 (8-byte MAC tag)
//   - Profile B: secp256r1 + AES-128-CTR + HMAC-SHA-256 (8-byte MAC tag)
//
// Ref: TS 33.501 Annex C §C.3 (Profile A) and §C.4 (Profile B)
package suci

import (
	"crypto/aes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// Profile identifies which ECIES profile was used.
type Profile byte

const (
	ProfileNull Profile = 0 // No concealment — SUPI is transmitted in clear
	ProfileA    Profile = 1 // X25519
	ProfileB    Profile = 2 // secp256r1
)

// SUCI is the parsed form of a 5GS SUCI (TS 24.501 §9.11.3.4).
type SUCI struct {
	// SUPIFormat: 0 = IMSI, 1 = NAI
	SUPIFormat byte
	// MCC, MNC (3 digits each as string)
	MCC, MNC string
	// RoutingIndicator (4 digits, BCD)
	RoutingIndicator string
	// Protection scheme (0=null, 1=Profile A, 2=Profile B)
	ProtectionScheme Profile
	// HomeNetworkPublicKeyID (1 byte)
	HomeNetworkPublicKeyID byte
	// SchemeOutput: encrypted MSIN (or plaintext if null scheme)
	SchemeOutput []byte
}

// DeconceaResult carries the result of SUCI deconcealment.
type DeconceaResult struct {
	MSIN string // Decrypted Mobile Subscriber Identification Number
	SUPI string // Reconstructed SUPI: "imsi-<MCC><MNC><MSIN>" or NAI
}

// Deconcealment performs SUCI deconcealment using the operator's private key.
// The private key format depends on the profile:
//   - Profile A: 32-byte X25519 scalar
//   - Profile B: big.Int representing secp256r1 private key scalar
//
// Ref: TS 33.501 §6.12 + Annex C
func DeconceaProfileA(suci SUCI, homeNetPrivKey [32]byte) (DeconceaResult, error) {
	if suci.ProtectionScheme != ProfileA {
		return DeconceaResult{}, errors.New("suci: not profile A")
	}
	// Minimum: 32 (ephemeral pub key) + 8 (MAC tag); ciphertext may be 0+ bytes.
	if len(suci.SchemeOutput) < 32+8 {
		return DeconceaResult{}, fmt.Errorf("suci: scheme output too short: %d", len(suci.SchemeOutput))
	}

	// SchemeOutput = UE ephemeral public key (32 bytes) || ciphertext || MAC (8 bytes)
	ephPub := [32]byte(suci.SchemeOutput[:32])
	ciphertext := suci.SchemeOutput[32 : len(suci.SchemeOutput)-8]
	mac := suci.SchemeOutput[len(suci.SchemeOutput)-8:]

	// ECDH shared secret
	sharedSecret, err := curve25519.X25519(homeNetPrivKey[:], ephPub[:])
	if err != nil {
		return DeconceaResult{}, fmt.Errorf("suci: ECDH: %w", err)
	}

	// KDF per TS 33.501 §C.3.4: 64-byte X9.63 output.
	// Layout: encKey[0:16] | IV[16:32] | macKey[32:64]
	// The IV is derived (not zero) and macKey spans the full second SHA-256 block.
	encKey, ivAndMacKey, err := eciesKDF(sharedSecret, ephPub[:], 16, 48)
	if err != nil {
		return DeconceaResult{}, err
	}
	iv := ivAndMacKey[:16]
	macKey := ivAndMacKey[16:]

	// Verify MAC (HMAC-SHA-256, truncated to 8 bytes) over ciphertext.
	expectedMAC := hmacSHA256Truncated(macKey, ciphertext, 8)
	if !hmac.Equal(mac, expectedMAC) {
		return DeconceaResult{}, errors.New("suci: MAC verification failed")
	}

	// Decrypt: AES-128-CTR with KDF-derived IV.
	plaintext, err := aesCTRDecryptIV(encKey, iv, ciphertext)
	if err != nil {
		return DeconceaResult{}, err
	}

	// MSIN is BCD-encoded (low-nibble-first) per TS 33.501 §C.3 — same as null scheme.
	msin := decodeBCDLowNibbleFirst(plaintext)
	supi := buildSUPI(suci, msin)
	return DeconceaResult{MSIN: msin, SUPI: supi}, nil
}

// DeconceaProfileB performs deconcealment using secp256r1 (Profile B).
// homeNetPrivKeyD is the raw private scalar (32 bytes).
func DeconceaProfileB(suci SUCI, homeNetPrivKeyD []byte) (DeconceaResult, error) {
	if suci.ProtectionScheme != ProfileB {
		return DeconceaResult{}, errors.New("suci: not profile B")
	}
	// Minimum: 33 (compressed ephemeral pub key) + 8 (MAC tag); ciphertext may be 0+ bytes.
	if len(suci.SchemeOutput) < 33+8 {
		return DeconceaResult{}, fmt.Errorf("suci: scheme output too short: %d", len(suci.SchemeOutput))
	}

	// SchemeOutput = compressed UE ephemeral public key (33 bytes) || ciphertext || MAC (8 bytes)
	curve := elliptic.P256()
	ephPubBytes := suci.SchemeOutput[:33]
	ciphertext := suci.SchemeOutput[33 : len(suci.SchemeOutput)-8]
	mac := suci.SchemeOutput[len(suci.SchemeOutput)-8:]

	// Decompress point
	ephX, ephY := elliptic.UnmarshalCompressed(curve, ephPubBytes)
	if ephX == nil {
		return DeconceaResult{}, errors.New("suci: invalid compressed point")
	}

	// ECDH: privKeyD * ephPub. Per X9.63 the shared secret is the x-coordinate
	// as a fixed-length field element — left-pad to 32 bytes (big.Int.Bytes()
	// strips leading zeros, which would corrupt the KDF input ~1/256 of the time).
	d := new(big.Int).SetBytes(homeNetPrivKeyD)
	sx, _ := curve.ScalarMult(ephX, ephY, d.Bytes())
	sharedSecret := make([]byte, 32)
	sx.FillBytes(sharedSecret)

	// KDF per TS 33.501 §C.3.4 (same layout as Profile A):
	// encKey[0:16] | ICB/IV[16:32] | macKey[32:64]
	encKey, ivAndMacKey, err := eciesKDF(sharedSecret, ephPubBytes, 16, 48)
	if err != nil {
		return DeconceaResult{}, err
	}
	iv := ivAndMacKey[:16]
	macKey := ivAndMacKey[16:]

	expectedMAC := hmacSHA256Truncated(macKey, ciphertext, 8)
	if !hmac.Equal(mac, expectedMAC) {
		return DeconceaResult{}, errors.New("suci: MAC verification failed")
	}

	plaintext, err := aesCTRDecryptIV(encKey, iv, ciphertext)
	if err != nil {
		return DeconceaResult{}, err
	}

	// MSIN is BCD-encoded (low-nibble-first) per TS 33.501 §C.4 — same as Profile A.
	msin := decodeBCDLowNibbleFirst(plaintext)
	supi := buildSUPI(suci, msin)
	return DeconceaResult{MSIN: msin, SUPI: supi}, nil
}

// EncryptProfileA (UE side) — used in tests; normally runs on the UE.
func EncryptProfileA(msin string, homeNetPubKey [32]byte, schemeID byte) (SUCI, error) {
	// Generate ephemeral X25519 key pair
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return SUCI{}, err
	}
	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return SUCI{}, err
	}

	sharedSecret, err := curve25519.X25519(ephPriv[:], homeNetPubKey[:])
	if err != nil {
		return SUCI{}, err
	}

	// KDF: 64-byte output, same layout as DeconceaProfileA.
	encKey, ivAndMacKey, err := eciesKDF(sharedSecret, ephPub, 16, 48)
	if err != nil {
		return SUCI{}, err
	}
	iv := ivAndMacKey[:16]
	macKey := ivAndMacKey[16:]

	// BCD-encode MSIN before encryption to match UERANSIM and TS 33.501 §C.3.
	ciphertext, err := aesCTREncryptIV(encKey, iv, encodeBCDLowNibbleFirst(msin))
	if err != nil {
		return SUCI{}, err
	}
	mac := hmacSHA256Truncated(macKey, ciphertext, 8)

	schemeOutput := append(ephPub, ciphertext...)
	schemeOutput = append(schemeOutput, mac...)

	return SUCI{
		ProtectionScheme:       ProfileA,
		HomeNetworkPublicKeyID: schemeID,
		SchemeOutput:           schemeOutput,
	}, nil
}

// ---- Null-scheme and string parsing ----------------------------------------

// ParseSUCIString parses the internal SUCI text format produced by the AMF:
//
//	suci-{mcc}{mnc}-{routing_indicator}-0-{protection_scheme_id}-{scheme_output_hex}
//
// The hardcoded "0" in position 4 is the SUPI type (0 = IMSI). MCC is always
// 3 digits; MNC is 2 or 3 digits, giving a combined field of length 5 or 6.
// Ref: TS 23.003 §2.7.2, TS 24.501 §9.11.3.4
func ParseSUCIString(s string) (SUCI, error) {
	if !strings.HasPrefix(s, "suci-") {
		return SUCI{}, fmt.Errorf("suci: not a SUCI: %q", s)
	}
	parts := strings.SplitN(s, "-", 6)
	if len(parts) != 6 {
		return SUCI{}, fmt.Errorf("suci: invalid format (need 6 dash-separated fields): %q", s)
	}
	// parts: ["suci", "{mcc}{mnc}", "{ri}", "0", "{psi}", "{output_hex}"]
	encoded := parts[1]
	if len(encoded) < 5 || len(encoded) > 6 {
		return SUCI{}, fmt.Errorf("suci: MCC+MNC field must be 5 or 6 chars, got %q", encoded)
	}
	mcc := encoded[:3]
	mnc := encoded[3:]

	psi, err := strconv.ParseUint(parts[4], 10, 8)
	if err != nil {
		return SUCI{}, fmt.Errorf("suci: protection scheme %q: %w", parts[4], err)
	}

	schemeOutput, err := hex.DecodeString(parts[5])
	if err != nil {
		return SUCI{}, fmt.Errorf("suci: scheme output %q is not valid hex: %w", parts[5], err)
	}

	return SUCI{
		SUPIFormat:       0, // IMSI
		MCC:              mcc,
		MNC:              mnc,
		RoutingIndicator: parts[2],
		ProtectionScheme: Profile(psi),
		SchemeOutput:     schemeOutput,
	}, nil
}

// DeconceaNull handles null-scheme SUCI (ProtectionScheme = ProfileNull = 0).
// The MSIN is carried in SchemeOutput as 3GPP BCD (low nibble = first digit of
// each pair; 0xF high-nibble signals padding for odd-length MSINs).
// Ref: TS 33.501 §6.12, TS 24.501 §9.11.3.4
func DeconceaNull(s SUCI) (DeconceaResult, error) {
	if s.ProtectionScheme != ProfileNull {
		return DeconceaResult{}, fmt.Errorf("suci: DeconceaNull called with scheme %d", s.ProtectionScheme)
	}
	msin := decodeBCDLowNibbleFirst(s.SchemeOutput)
	return DeconceaResult{
		MSIN: msin,
		SUPI: buildSUPI(s, msin),
	}, nil
}

// encodeBCDLowNibbleFirst encodes a decimal digit string into 3GPP BCD format:
// low nibble = first digit of each pair, high nibble = second digit.
// Odd-length strings are padded with 0xF in the high nibble of the last byte.
func encodeBCDLowNibbleFirst(digits string) []byte {
	out := make([]byte, (len(digits)+1)/2)
	for i, c := range digits {
		d := byte(c - '0')
		if i%2 == 0 {
			out[i/2] = d
		} else {
			out[i/2] |= d << 4
		}
	}
	if len(digits)%2 == 1 {
		out[len(out)-1] |= 0xF0
	}
	return out
}

// decodeBCDLowNibbleFirst decodes the 3GPP OTA BCD format used in NAS messages:
// the low nibble of each byte carries the first (leftmost) digit of the pair,
// the high nibble carries the second. A high nibble of 0xF signals padding at
// the end of an odd-length digit string.
func decodeBCDLowNibbleFirst(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	for _, byt := range b {
		out = append(out, '0'+(byt&0x0F))
		if high := (byt >> 4) & 0x0F; high != 0x0F {
			out = append(out, '0'+high)
		}
	}
	return string(out)
}

// ---- helpers ---------------------------------------------------------------

func buildSUPI(s SUCI, msin string) string {
	if s.SUPIFormat == 0 {
		return fmt.Sprintf("imsi-%s%s%s", s.MCC, s.MNC, msin)
	}
	return msin
}

// eciesKDF derives enc+mac keys using X9.63 KDF with SHA-256.
// Returns (encKey[:encLen], macKey[:macLen]).
// Ref: TS 33.501 §C.3.4
func eciesKDF(sharedSecret, sharedInfo []byte, encLen, macLen int) ([]byte, []byte, error) {
	total := encLen + macLen
	// counter based key expansion
	var out []byte
	for counter := 1; len(out) < total; counter++ {
		h := sha256.New()
		h.Write(sharedSecret)
		ctr := []byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)}
		h.Write(ctr)
		h.Write(sharedInfo)
		out = append(out, h.Sum(nil)...)
	}
	return out[:encLen], out[encLen : encLen+macLen], nil
}

func hmacSHA256Truncated(key, data []byte, length int) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)[:length]
}

func aesCTREncryptIV(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	ctr := newCTR(block, iv)
	ctr.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func aesCTRDecryptIV(key, iv, ciphertext []byte) ([]byte, error) {
	return aesCTREncryptIV(key, iv, ciphertext) // CTR mode is symmetric
}

// Minimal CTR implementation to avoid dependency on cipher.NewCTR
func newCTR(block interface{ Encrypt(dst, src []byte) }, iv []byte) *ctrStream {
	counter := make([]byte, len(iv))
	copy(counter, iv)
	return &ctrStream{block: block, counter: counter, keystream: nil}
}

type ctrStream struct {
	block     interface{ Encrypt(dst, src []byte) }
	counter   []byte
	keystream []byte
}

func (c *ctrStream) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		if len(c.keystream) == 0 {
			c.keystream = make([]byte, len(c.counter))
			c.block.Encrypt(c.keystream, c.counter)
			// Increment counter
			for j := len(c.counter) - 1; j >= 0; j-- {
				c.counter[j]++
				if c.counter[j] != 0 {
					break
				}
			}
		}
		dst[i] = src[i] ^ c.keystream[0]
		c.keystream = c.keystream[1:]
	}
}
