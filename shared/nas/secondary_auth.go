package nas

// Secondary Authentication / Authorization by a DN-AAA server — 5GSM NAS
// messages for the EAP-in-5GSM exchange between the UE and an external Data
// Network AAA server, with the SMF acting as an EAP pass-through
// authenticator (TS 23.501 §5.6.6, TS 23.502 §4.3.2.3).
//
// All three procedure messages (AUTH COMMAND/COMPLETE/RESULT) carry exactly
// one mandatory IE — the EAP message (TS 24.501 §9.11.2.2, LV-E: 2-octet
// length + EAP packet, no IEI) — after the common 4-octet 5GSM header
// (EPD | PDU session ID | PTI | Message type). Ref: TS 24.501 §8.3.5-§8.3.7.
//
// The ESTABLISHMENT ACCEPT/REJECT messages carry the terminal EAP-Success /
// EAP-Failure as an *optional* IE instead: TLV-E, IEI 0x78 (§9.11.2.2).
//
// This file reuses encodeEAPMessageLVE/decodeEAPMessageLVE from nssaa.go
// (same LV-E framing, different message types) — no bespoke codec.

import "fmt"

// EncodePDUSessionAuthenticationCommandBody encodes the mandatory EAP message
// IE (LV-E, no IEI) of a PDU SESSION AUTHENTICATION COMMAND body.
// Ref: TS 24.501 §8.3.5, Table 8.3.5.1.1.
func EncodePDUSessionAuthenticationCommandBody(eapMsg []byte) []byte {
	return encodeEAPMessageLVE(eapMsg)
}

// DecodePDUSessionAuthenticationCommandBody parses an AUTH COMMAND body
// (bytes after the 4-octet 5GSM header) and returns the EAP packet.
func DecodePDUSessionAuthenticationCommandBody(b []byte) ([]byte, error) {
	return decodeEAPMessageLVE(b)
}

// WrapPDUSessionAuthenticationCommandBody builds a complete 5GSM PDU SESSION
// AUTHENTICATION COMMAND message: EPD | PSI | PTI | MT (0xC5) | EAP message.
// Ref: TS 24.501 §8.3.5, §9.1.1.
func WrapPDUSessionAuthenticationCommandBody(pduSessionID, pti uint8, eapMsg []byte) []byte {
	msg := []byte{PDGroupSessionManagement, pduSessionID, pti, byte(MsgTypePDUSessionAuthenticationCommand)}
	return append(msg, EncodePDUSessionAuthenticationCommandBody(eapMsg)...)
}

// EncodePDUSessionAuthenticationCompleteBody encodes the mandatory EAP
// message IE of a PDU SESSION AUTHENTICATION COMPLETE body.
// Ref: TS 24.501 §8.3.6, Table 8.3.6.1.1.
func EncodePDUSessionAuthenticationCompleteBody(eapMsg []byte) []byte {
	return encodeEAPMessageLVE(eapMsg)
}

// DecodePDUSessionAuthenticationCompleteBody parses an AUTH COMPLETE body and
// returns the EAP packet (the UE's EAP-Response).
func DecodePDUSessionAuthenticationCompleteBody(b []byte) ([]byte, error) {
	return decodeEAPMessageLVE(b)
}

// WrapPDUSessionAuthenticationCompleteBody builds a complete 5GSM PDU SESSION
// AUTHENTICATION COMPLETE message: EPD | PSI | PTI | MT (0xC6) | EAP message.
// Ref: TS 24.501 §8.3.6, §9.1.1. Exported for symmetry / test use — the SMF
// only decodes this message (sent UE → SMF); it never encodes one.
func WrapPDUSessionAuthenticationCompleteBody(pduSessionID, pti uint8, eapMsg []byte) []byte {
	msg := []byte{PDGroupSessionManagement, pduSessionID, pti, byte(MsgTypePDUSessionAuthenticationComplete)}
	return append(msg, EncodePDUSessionAuthenticationCompleteBody(eapMsg)...)
}

// EncodePDUSessionAuthenticationResultBody encodes the mandatory EAP message
// IE of a PDU SESSION AUTHENTICATION RESULT body.
// Ref: TS 24.501 §8.3.7, Table 8.3.7.1.1.
func EncodePDUSessionAuthenticationResultBody(eapMsg []byte) []byte {
	return encodeEAPMessageLVE(eapMsg)
}

// DecodePDUSessionAuthenticationResultBody parses an AUTH RESULT body and
// returns the terminal EAP packet.
func DecodePDUSessionAuthenticationResultBody(b []byte) ([]byte, error) {
	return decodeEAPMessageLVE(b)
}

// WrapPDUSessionAuthenticationResultBody builds a complete 5GSM PDU SESSION
// AUTHENTICATION RESULT message: EPD | PSI | PTI | MT (0xC7) | EAP message.
// Ref: TS 24.501 §8.3.7, §9.1.1.
func WrapPDUSessionAuthenticationResultBody(pduSessionID, pti uint8, eapMsg []byte) []byte {
	msg := []byte{PDGroupSessionManagement, pduSessionID, pti, byte(MsgTypePDUSessionAuthenticationResult)}
	return append(msg, EncodePDUSessionAuthenticationResultBody(eapMsg)...)
}

// IEIEAPMessage is the EAP message IE identifier used as an *optional* TLV-E
// IE in the PDU SESSION ESTABLISHMENT ACCEPT / REJECT messages — as opposed
// to the mandatory LV-E form used in the AUTH COMMAND/COMPLETE/RESULT
// messages above. Ref: TS 24.501 §9.11.2.2, Tables 8.3.2.1.1 / 8.3.3.1.1.
const IEIEAPMessage uint8 = 0x78

// EncodeEAPMessageTLVE encodes the optional EAP message IE carried in the
// ESTABLISHMENT ACCEPT (EAP-Success) / REJECT (EAP-Failure) messages:
// IEI (1 octet) | length (2 octets, big-endian) | EAP packet.
// Ref: TS 24.501 §9.11.2.2.
func EncodeEAPMessageTLVE(eapMsg []byte) []byte {
	out := make([]byte, 0, 3+len(eapMsg))
	out = append(out, IEIEAPMessage, byte(len(eapMsg)>>8), byte(len(eapMsg)))
	return append(out, eapMsg...)
}

// DecodeEAPMessageTLVE parses an EAP message TLV-E IE at the START of b
// (b[0] must be IEIEAPMessage) and returns the EAP packet plus the number of
// bytes consumed. Used to round-trip the IE this package encodes; it does not
// walk past unrelated optional IEs (this codebase has no full
// ESTABLISHMENT ACCEPT/REJECT optional-IE decoder to plug into — see
// docs/procedures/SecondaryAuthentication.md).
func DecodeEAPMessageTLVE(b []byte) ([]byte, int, error) {
	if len(b) < 3 {
		return nil, 0, fmt.Errorf("nas: EAP message TLV-E: too short (%d bytes)", len(b))
	}
	if b[0] != IEIEAPMessage {
		return nil, 0, fmt.Errorf("nas: EAP message TLV-E: unexpected IEI 0x%02X (want 0x%02X)", b[0], IEIEAPMessage)
	}
	length := int(b[1])<<8 | int(b[2])
	if 3+length > len(b) {
		return nil, 0, fmt.Errorf("nas: EAP message TLV-E: truncated (len %d)", length)
	}
	eapMsg := make([]byte, length)
	copy(eapMsg, b[3:3+length])
	return eapMsg, 3 + length, nil
}

// WrapPDUSessionEstablishmentRejectBody builds a complete 5GSM PDU SESSION
// ESTABLISHMENT REJECT message: EPD | PSI | PTI | MT (0xC3) | 5GSM cause
// (mandatory V, 1 octet, no IEI) | optional EAP message (TLV-E, IEI 0x78).
// eapMessage may be nil/empty (e.g. DN-AAA unreachable/timeout — the IE is
// optional per TS 24.501 §9.11.4.2's error table).
// Ref: TS 24.501 §8.3.3, Table 8.3.3.1.1.
func WrapPDUSessionEstablishmentRejectBody(pduSessionID, pti, cause5GSM uint8, eapMessage []byte) []byte {
	msg := []byte{PDGroupSessionManagement, pduSessionID, pti, byte(MsgTypePDUSessionEstablishmentReject), cause5GSM}
	if len(eapMessage) > 0 {
		msg = append(msg, EncodeEAPMessageTLVE(eapMessage)...)
	}
	return msg
}

// Cause5GSMUserAuthOrAuthorizationFailed is 5GSM cause #29 "User
// authentication or authorization failed" (TS 24.501 §9.11.4.2, Table
// 9.11.4.2.1) — the mandatory PDU SESSION ESTABLISHMENT REJECT cause when
// secondary DN-AAA authentication fails or the DN-AAA is unreachable/times
// out (TS 23.502 §4.3.2.3).
//
// Note: this package already has a same-valued constant
// Cause5GSMReactivationRequested = 0x1D with a stale/misleading name (dead
// code — grep shows no callers); that pre-existing naming issue is out of
// scope here and left untouched. The value 0x1D = 29 is correct for both.
const Cause5GSMUserAuthOrAuthorizationFailed uint8 = 0x1D // 29
