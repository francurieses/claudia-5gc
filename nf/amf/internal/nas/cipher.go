package nasmsg

import (
	"crypto/subtle"
	"fmt"

	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
)

const (
	// nasBearer is the BEARER input of the NAS ciphering algorithms: the NAS
	// connection identifier, 0x01 for 3GPP access. Ref: TS 33.501 §6.4.3.1
	nasBearer = 0x01
	// nasDirUL / nasDirDL are the DIRECTION input (0 uplink, 1 downlink).
	// Ref: TS 33.501 §6.4.4
	nasDirUL = 0x00
	nasDirDL = 0x01
)

// cipherNAS applies the NAS ciphering algorithm alg (0 NEA0 identity, 1 128-NEA1,
// 2 128-NEA2, 3 128-NEA3) to msg. The keystream XOR is symmetric, so it both
// ciphers (dir DL) and deciphers (dir UL). An unknown algorithm returns an
// error; there is no fallback to NEA2 or to plaintext.
// Ref: TS 33.501 §5.11.1.1, Annex D.2
func cipherNAS(alg byte, key []byte, count uint32, dir byte, msg []byte) ([]byte, error) {
	switch alg {
	case nea0ID:
		return append([]byte(nil), msg...), nil
	case nea1ID:
		return nea.NEA1(key, count, nasBearer, dir, msg)
	case nea2ID:
		return nea.NEA2(key, count, nasBearer, dir, msg)
	case nea3ID:
		return nea.NEA3(key, count, nasBearer, dir, msg)
	}
	return nil, fmt.Errorf("nas: unknown NEA%d", alg)
}

// NAS integrity algorithm identifiers (TS 33.501 §5.11.1.2).
const (
	nia1ID = 1
	nia2ID = 2
	nia3ID = 3
)

// computeNASMAC computes the 32-bit NAS-MAC of msg with the selected NAS
// integrity algorithm alg (1 128-NIA1, 2 128-NIA2, 3 128-NIA3). NIA0 and any
// other value return an error: the AMF never selects NIA0 (no emergency
// services) and there is no fallback to NIA2.
// Ref: TS 33.501 §6.4.3, §6.7.2, Annex D.3
func computeNASMAC(alg byte, key []byte, count uint32, dir byte, msg []byte) ([]byte, error) {
	switch alg {
	case nia1ID:
		return nia.NIA1(key, count, nasBearer, dir, msg)
	case nia2ID:
		return nia.NIA2(key, count, nasBearer, dir, msg)
	case nia3ID:
		return nia.NIA3(key, count, nasBearer, dir, msg)
	}
	return nil, fmt.Errorf("nas: unsupported NAS integrity algorithm NIA%d", alg)
}

// verifyNASMAC reports whether mac is the NAS-MAC of msg under alg, compared
// in constant time. An unsupported algorithm is an error.
func verifyNASMAC(alg byte, key []byte, count uint32, dir byte, msg, mac []byte) (bool, error) {
	expected, err := computeNASMAC(alg, key, count, dir, msg)
	if err != nil {
		return false, err
	}
	if len(mac) != len(expected) {
		return false, nil
	}
	return subtle.ConstantTimeCompare(expected, mac) == 1, nil
}
