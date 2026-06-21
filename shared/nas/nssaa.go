package nas

import "fmt"

// NSSAA — Network Slice-Specific Authentication and Authorization NAS messages.
// Ref: TS 24.501 §8.2.31 (COMMAND), §8.2.32 (COMPLETE), §8.2.33 (RESULT).
//
// All three messages carry exactly two mandatory IEs, in this order and with no
// IEI on the wire:
//   1. S-NSSAI       — TS 24.501 §9.11.2.8, format LV  (1-octet length + value)
//   2. EAP message   — TS 24.501 §9.11.2.2, format LV-E (2-octet length + EAP packet)
//
// The EAP packet (RFC 3748 §4) is opaque to the AMF, which is an EAP pass-through
// authenticator relaying it between the UE (N1) and the AAA-S (via AUSF).

// NSSAAuthCommand is the NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND (0x50),
// sent AMF → UE. It carries an EAP-Request for the given S-NSSAI.
type NSSAAuthCommand struct {
	SNSSAI     SNSSAI
	EAPMessage []byte
}

// NSSAAuthComplete is the NETWORK SLICE-SPECIFIC AUTHENTICATION COMPLETE (0x51),
// sent UE → AMF. It carries the UE's EAP-Response for the given S-NSSAI.
type NSSAAuthComplete struct {
	SNSSAI     SNSSAI
	EAPMessage []byte
}

// NSSAAuthResult is the NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT (0x52),
// sent AMF → UE. It carries the terminal EAP-Success / EAP-Failure for the S-NSSAI.
type NSSAAuthResult struct {
	SNSSAI     SNSSAI
	EAPMessage []byte
}

// encodeSNSSAILV encodes a single S-NSSAI in LV form (TS 24.501 §9.11.2.8):
// length octet followed by SST (and the 3-octet SD when present).
func encodeSNSSAILV(s SNSSAI) []byte {
	if s.SD == SDNotPresent {
		return []byte{1, s.SST}
	}
	return []byte{4, s.SST, byte(s.SD >> 16), byte(s.SD >> 8), byte(s.SD)}
}

// decodeSNSSAILV parses a single LV-form S-NSSAI, returning it and the number of
// bytes consumed.
func decodeSNSSAILV(b []byte) (SNSSAI, int, error) {
	if len(b) < 1 {
		return SNSSAI{}, 0, fmt.Errorf("nas: S-NSSAI IE missing length")
	}
	length := int(b[0])
	if length < 1 || 1+length > len(b) {
		return SNSSAI{}, 0, fmt.Errorf("nas: S-NSSAI IE truncated (len %d)", length)
	}
	s := SNSSAI{SD: SDNotPresent, SST: b[1]}
	if length >= 4 {
		s.SD = uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4])
	}
	return s, 1 + length, nil
}

// encodeEAPMessageLVE encodes an EAP message IE in LV-E form (TS 24.501 §9.11.2.2):
// a 2-octet big-endian length followed by the EAP packet.
func encodeEAPMessageLVE(eap []byte) []byte {
	out := make([]byte, 2+len(eap))
	out[0] = byte(len(eap) >> 8)
	out[1] = byte(len(eap))
	copy(out[2:], eap)
	return out
}

// decodeEAPMessageLVE parses an LV-E EAP message IE, returning the EAP packet.
func decodeEAPMessageLVE(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("nas: EAP message IE missing length")
	}
	length := int(b[0])<<8 | int(b[1])
	if 2+length > len(b) {
		return nil, fmt.Errorf("nas: EAP message IE truncated (len %d)", length)
	}
	eap := make([]byte, length)
	copy(eap, b[2:2+length])
	return eap, nil
}

func encodeNSSAABody(s SNSSAI, eap []byte) []byte {
	out := encodeSNSSAILV(s)
	return append(out, encodeEAPMessageLVE(eap)...)
}

func decodeNSSAABody(b []byte) (SNSSAI, []byte, error) {
	s, n, err := decodeSNSSAILV(b)
	if err != nil {
		return SNSSAI{}, nil, err
	}
	eap, err := decodeEAPMessageLVE(b[n:])
	if err != nil {
		return SNSSAI{}, nil, err
	}
	return s, eap, nil
}

// EncodeNSSAAuthCommand serialises a COMMAND body (after the 3-octet 5GMM header).
func EncodeNSSAAuthCommand(c *NSSAAuthCommand) ([]byte, error) {
	return encodeNSSAABody(c.SNSSAI, c.EAPMessage), nil
}

// DecodeNSSAAuthCommand parses a COMMAND body.
func DecodeNSSAAuthCommand(b []byte) (*NSSAAuthCommand, error) {
	s, eap, err := decodeNSSAABody(b)
	if err != nil {
		return nil, err
	}
	return &NSSAAuthCommand{SNSSAI: s, EAPMessage: eap}, nil
}

// EncodeNSSAAuthComplete serialises a COMPLETE body.
func EncodeNSSAAuthComplete(c *NSSAAuthComplete) ([]byte, error) {
	return encodeNSSAABody(c.SNSSAI, c.EAPMessage), nil
}

// DecodeNSSAAuthComplete parses a COMPLETE body.
func DecodeNSSAAuthComplete(b []byte) (*NSSAAuthComplete, error) {
	s, eap, err := decodeNSSAABody(b)
	if err != nil {
		return nil, err
	}
	return &NSSAAuthComplete{SNSSAI: s, EAPMessage: eap}, nil
}

// EncodeNSSAAuthResult serialises a RESULT body.
func EncodeNSSAAuthResult(r *NSSAAuthResult) ([]byte, error) {
	return encodeNSSAABody(r.SNSSAI, r.EAPMessage), nil
}

// DecodeNSSAAuthResult parses a RESULT body.
func DecodeNSSAAuthResult(b []byte) (*NSSAAuthResult, error) {
	s, eap, err := decodeNSSAABody(b)
	if err != nil {
		return nil, err
	}
	return &NSSAAuthResult{SNSSAI: s, EAPMessage: eap}, nil
}
