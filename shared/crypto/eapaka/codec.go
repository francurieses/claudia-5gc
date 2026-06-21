package eapaka

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// EAP codes (RFC 3748 §4).
const (
	CodeRequest  = 1
	CodeResponse = 2
	CodeSuccess  = 3
	CodeFailure  = 4
)

// EAP method type for EAP-AKA' (RFC 5448 §3.1).
const TypeEAPAKAPrime = 50

// EAP-AKA subtypes (RFC 4187 §11).
const subtypeAKAChallenge = 1

// EAP-AKA attribute types (RFC 4187 §11, RFC 5448 §3.1).
const (
	atRAND     = 1
	atAUTN     = 2
	atRES      = 3
	atMAC      = 11
	atKDFInput = 23
	atKDF      = 24
)

// kdfAKAPrime is the AT_KDF value for EAP-AKA' with the RFC 5448 key derivation.
const kdfAKAPrime = 1

// macLen is the AT_MAC output length (HMAC-SHA-256-128 → 16 bytes).
const macLen = 16

// headerLen is the EAP-AKA header: Code|Id|Length(2)|Type|Subtype|Reserved(2).
const headerLen = 8

// encodeAttr encodes a single EAP-AKA attribute: Type | Length | value, where
// Length is in 4-byte units and counts the 2 header bytes. The value is
// zero-padded so the whole attribute is a multiple of 4 bytes.
func encodeAttr(typ byte, value []byte) []byte {
	total := 2 + len(value)
	if pad := total % 4; pad != 0 {
		value = append(value, make([]byte, 4-pad)...)
		total = 2 + len(value)
	}
	out := make([]byte, 0, total)
	out = append(out, typ, byte(total/4))
	out = append(out, value...)
	return out
}

// fixedAttr builds AT_RAND/AT_AUTN/AT_MAC: 2 reserved bytes + 16-byte data.
func fixedAttr(typ byte, data []byte) []byte {
	v := make([]byte, 2+len(data))
	copy(v[2:], data)
	return encodeAttr(typ, v)
}

// resAttr builds AT_RES: 2-byte RES length in bits + RES bytes.
func resAttr(res []byte) []byte {
	v := make([]byte, 2+len(res))
	binary.BigEndian.PutUint16(v[0:2], uint16(len(res)*8))
	copy(v[2:], res)
	return encodeAttr(atRES, v)
}

// kdfInputAttr builds AT_KDF_INPUT: 2-byte actual length + network name.
func kdfInputAttr(networkName string) []byte {
	name := []byte(networkName)
	v := make([]byte, 2+len(name))
	binary.BigEndian.PutUint16(v[0:2], uint16(len(name)))
	copy(v[2:], name)
	return encodeAttr(atKDFInput, v)
}

// kdfAttr builds AT_KDF: a single 2-byte KDF identifier (no reserved field).
func kdfAttr(id uint16) []byte {
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, id)
	return encodeAttr(atKDF, v)
}

// frame assembles an EAP-AKA packet header + attributes and fixes the length.
func frame(code, identifier, subtype byte, attrs []byte) []byte {
	pkt := make([]byte, headerLen+len(attrs))
	pkt[0] = code
	pkt[1] = identifier
	// pkt[2:4] length set below
	pkt[4] = TypeEAPAKAPrime
	pkt[5] = subtype
	// pkt[6:8] reserved = 0
	copy(pkt[headerLen:], attrs)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	return pkt
}

// BuildChallenge builds an EAP-Request/AKA'-Challenge with AT_RAND, AT_AUTN,
// AT_KDF, AT_KDF_INPUT and a trailing AT_MAC keyed by kAut.
func BuildChallenge(identifier byte, rand, autn [16]byte, networkName string, kAut []byte) []byte {
	var attrs []byte
	attrs = append(attrs, fixedAttr(atRAND, rand[:])...)
	attrs = append(attrs, fixedAttr(atAUTN, autn[:])...)
	attrs = append(attrs, kdfAttr(kdfAKAPrime)...)
	attrs = append(attrs, kdfInputAttr(networkName)...)
	attrs = append(attrs, fixedAttr(atMAC, make([]byte, macLen))...) // zeroed MAC placeholder

	pkt := frame(CodeRequest, identifier, subtypeAKAChallenge, attrs)
	insertMAC(pkt, kAut)
	return pkt
}

// BuildResponse builds an EAP-Response/AKA'-Challenge with AT_RES and AT_MAC.
// Used by the UE side (and by tests simulating the UE).
func BuildResponse(identifier byte, res []byte, kAut []byte) []byte {
	var attrs []byte
	attrs = append(attrs, resAttr(res)...)
	attrs = append(attrs, fixedAttr(atMAC, make([]byte, macLen))...)
	pkt := frame(CodeResponse, identifier, subtypeAKAChallenge, attrs)
	insertMAC(pkt, kAut)
	return pkt
}

// BuildSuccess / BuildFailure build the terminal EAP packets (RFC 3748 §4.2).
func BuildSuccess(identifier byte) []byte { return []byte{CodeSuccess, identifier, 0, 4} }
func BuildFailure(identifier byte) []byte { return []byte{CodeFailure, identifier, 0, 4} }

// insertMAC computes HMAC-SHA-256-128 over pkt (with the AT_MAC value zeroed,
// which it already is) and writes the result into the AT_MAC value field.
func insertMAC(pkt, kAut []byte) {
	off, ok := findAttr(pkt, atMAC)
	if !ok {
		return
	}
	mac := computeMAC(pkt, kAut)
	copy(pkt[off+4:off+4+macLen], mac) // skip 2 attr-header + 2 reserved bytes
}

// computeMAC returns HMAC-SHA-256(kAut, pkt) truncated to 16 bytes. The caller
// must ensure the AT_MAC value field is zeroed in pkt before calling.
func computeMAC(pkt, kAut []byte) []byte {
	m := hmac.New(sha256.New, kAut)
	m.Write(pkt)
	return m.Sum(nil)[:macLen]
}

// VerifyMAC recomputes the AT_MAC of an EAP packet and compares it against the
// embedded value in constant time.
func VerifyMAC(pkt, kAut []byte) bool {
	off, ok := findAttr(pkt, atMAC)
	if !ok || off+4+macLen > len(pkt) {
		return false
	}
	got := make([]byte, macLen)
	copy(got, pkt[off+4:off+4+macLen])

	clone := make([]byte, len(pkt))
	copy(clone, pkt)
	for i := 0; i < macLen; i++ {
		clone[off+4+i] = 0
	}
	want := computeMAC(clone, kAut)
	return hmac.Equal(got, want)
}

// ExtractRES returns the RES carried in an EAP-Response/AKA'-Challenge AT_RES.
func ExtractRES(pkt []byte) ([]byte, error) {
	off, ok := findAttr(pkt, atRES)
	if !ok {
		return nil, errors.New("eapaka: AT_RES not found")
	}
	if off+4 > len(pkt) {
		return nil, errors.New("eapaka: truncated AT_RES")
	}
	bits := binary.BigEndian.Uint16(pkt[off+2 : off+4])
	n := int((bits + 7) / 8)
	start := off + 4
	if start+n > len(pkt) {
		return nil, fmt.Errorf("eapaka: AT_RES length %d exceeds packet", n)
	}
	res := make([]byte, n)
	copy(res, pkt[start:start+n])
	return res, nil
}

// findAttr walks the attribute list of an EAP-AKA packet and returns the byte
// offset of the first attribute of type typ.
func findAttr(pkt []byte, typ byte) (int, bool) {
	if len(pkt) < headerLen {
		return 0, false
	}
	off := headerLen
	for off+2 <= len(pkt) {
		aTyp := pkt[off]
		aLen := int(pkt[off+1]) * 4
		if aLen == 0 || off+aLen > len(pkt) {
			break
		}
		if aTyp == typ {
			return off, true
		}
		off += aLen
	}
	return 0, false
}

// Validate performs basic structural validation of an EAP packet.
func Validate(pkt []byte) error {
	if len(pkt) < 4 {
		return errors.New("eapaka: packet too short")
	}
	declared := int(binary.BigEndian.Uint16(pkt[2:4]))
	if declared != len(pkt) {
		return fmt.Errorf("eapaka: length mismatch: header=%d actual=%d", declared, len(pkt))
	}
	return nil
}
