// Package eap provides minimal generic EAP (RFC 3748) packet helpers used by the
// NSSAA EAP pass-through relay. The EAP method between the UE and the AAA-S is
// opaque to the AMF, so only Identity / Success / Failure framing is needed here;
// EAP-AKA' (the primary-auth method) lives in shared/crypto/eapaka instead.
//
// Ref: RFC 3748 §4 (EAP packet format).
package eap

import "fmt"

// EAP codes (RFC 3748 §4).
const (
	CodeRequest  byte = 1
	CodeResponse byte = 2
	CodeSuccess  byte = 3
	CodeFailure  byte = 4
)

// EAP types (RFC 3748 §5).
const (
	TypeIdentity byte = 1
)

// BuildIdentityRequest builds an EAP-Request/Identity packet.
func BuildIdentityRequest(identifier byte) []byte {
	return buildTyped(CodeRequest, identifier, TypeIdentity, nil)
}

// BuildIdentityResponse builds an EAP-Response/Identity carrying the identity NAI.
func BuildIdentityResponse(identifier byte, identity string) []byte {
	return buildTyped(CodeResponse, identifier, TypeIdentity, []byte(identity))
}

// BuildSuccess builds an EAP-Success packet (length always 4, no data).
func BuildSuccess(identifier byte) []byte {
	return []byte{CodeSuccess, identifier, 0, 4}
}

// BuildFailure builds an EAP-Failure packet (length always 4, no data).
func BuildFailure(identifier byte) []byte {
	return []byte{CodeFailure, identifier, 0, 4}
}

func buildTyped(code, identifier, typ byte, data []byte) []byte {
	length := 5 + len(data) // code+id+len(2)+type + data
	pkt := make([]byte, length)
	pkt[0] = code
	pkt[1] = identifier
	pkt[2] = byte(length >> 8)
	pkt[3] = byte(length)
	pkt[4] = typ
	copy(pkt[5:], data)
	return pkt
}

// Code returns the EAP code of a packet.
func Code(pkt []byte) (byte, error) {
	if len(pkt) < 4 {
		return 0, fmt.Errorf("eap: packet too short (%d bytes)", len(pkt))
	}
	return pkt[0], nil
}

// Identifier returns the EAP identifier of a packet.
func Identifier(pkt []byte) (byte, error) {
	if len(pkt) < 4 {
		return 0, fmt.Errorf("eap: packet too short (%d bytes)", len(pkt))
	}
	return pkt[1], nil
}

// Type returns the EAP type for Request/Response packets.
func Type(pkt []byte) (byte, error) {
	if len(pkt) < 5 {
		return 0, fmt.Errorf("eap: packet has no type field (%d bytes)", len(pkt))
	}
	if pkt[0] != CodeRequest && pkt[0] != CodeResponse {
		return 0, fmt.Errorf("eap: code %d has no type field", pkt[0])
	}
	return pkt[4], nil
}

// Identity returns the identity NAI from an EAP-Response/Identity packet.
func Identity(pkt []byte) (string, error) {
	t, err := Type(pkt)
	if err != nil {
		return "", err
	}
	if t != TypeIdentity {
		return "", fmt.Errorf("eap: not an Identity packet (type %d)", t)
	}
	return string(pkt[5:]), nil
}

// Validate checks the length field is consistent with the packet.
func Validate(pkt []byte) error {
	if len(pkt) < 4 {
		return fmt.Errorf("eap: packet too short (%d bytes)", len(pkt))
	}
	length := int(pkt[2])<<8 | int(pkt[3])
	if length != len(pkt) {
		return fmt.Errorf("eap: length field %d != packet len %d", length, len(pkt))
	}
	return nil
}
