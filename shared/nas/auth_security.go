package nas

import (
	"fmt"
)

// ---- Authentication Request (TS 24.501 §8.2.1.1) -------------------------

// AuthenticationRequest is the 5GMM Authentication Request message.
type AuthenticationRequest struct {
	// Mandatory
	NGKSI NGKSI
	// Mandatory
	ABBA ABBA
	// IEI 0x21 — Authentication parameter RAND (TV, 16 bytes)
	RAND [16]byte
	// IEI 0x20 — Authentication parameter AUTN (TLV, 16 bytes)
	// Ref: TS 24.501 Table 8.2.1.1.1 (IEI 20, format from TS 24.008 §10.5.3.1.1)
	AUTN [16]byte
	// Optional (IEI 0x78 — EAP message)
	EAPMessage []byte
}

// EncodeAuthenticationRequest serialises an AuthenticationRequest.
// Ref: TS 24.501 §8.2.1.1 Figure 8.2.1.1.1
func EncodeAuthenticationRequest(ar *AuthenticationRequest) ([]byte, error) {
	var out []byte

	// Octet 4: spare(4) | ngKSI type(1) | ngKSI value(3)
	out = append(out, ((ar.NGKSI.Type&0x01)<<3)|ar.NGKSI.KeySetIdentifier&0x07)

	// ABBA (TS 24.501 §9.11.3.10): mandatory LV format — no IEI on the wire.
	// TS 24.501 §8.2.1.1 Table 8.2.1.1.1 lists ABBA with format "LV", meaning
	// only Length + Value are sent; the IEI 0x21 is a table identifier only.
	out = append(out, byte(len(ar.ABBA)))
	out = append(out, ar.ABBA[:]...)

	// IEI 0x21 — RAND (16 bytes): TV per TS 24.501 Table 8.2.1.1.1 — no length byte
	out = append(out, 0x21)
	out = append(out, ar.RAND[:]...)

	// IEI 0x20 — AUTN (16 bytes): TLV per TS 24.501 Table 8.2.1.1.1
	out = append(out, 0x20, 0x10)
	out = append(out, ar.AUTN[:]...)

	return out, nil
}

// DecodeAuthenticationRequest parses an AuthenticationRequest body.
func DecodeAuthenticationRequest(b []byte) (*AuthenticationRequest, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("nas: AuthenticationRequest too short")
	}
	ar := &AuthenticationRequest{}
	rdr := NewReader(b)

	ngksi, _ := rdr.ReadByte()
	ar.NGKSI = NGKSI{
		KeySetIdentifier: ngksi & 0x07,
		Type:             (ngksi >> 3) & 0x01,
	}

	// ABBA: mandatory LV (no IEI) per TS 24.501 §8.2.1.1 Table 8.2.1.1.1.
	if l, err := rdr.ReadByte(); err == nil {
		if abbaBytes, err := rdr.ReadBytes(int(l)); err == nil && len(abbaBytes) >= 2 {
			ar.ABBA = ABBA{abbaBytes[0], abbaBytes[1]}
		}
	}

	// Optional IEs: RAND IEI=0x21 TV (no length), AUTN IEI=0x20 TLV, EAP IEI=0x78 TLV-E.
	// Ref: TS 24.501 Table 8.2.1.1.1
	for rdr.Len() > 0 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}
		switch iei {
		case 0x21: // RAND (TV, 16 bytes) — IEI + 16 bytes, no length byte
			randBytes, _ := rdr.ReadBytes(16)
			copy(ar.RAND[:], randBytes)
		case 0x20: // AUTN (TLV) — UERANSIM uses 0x20 instead of spec's 0x28
			l, _ := rdr.ReadByte()
			autnBytes, _ := rdr.ReadBytes(int(l))
			copy(ar.AUTN[:], autnBytes)
		case 0x78: // EAP message
			hi, _ := rdr.ReadByte()
			lo, _ := rdr.ReadByte()
			l := int(hi)<<8 | int(lo)
			ar.EAPMessage, _ = rdr.ReadBytes(l)
		default:
			l, _ := rdr.ReadByte()
			_, _ = rdr.ReadBytes(int(l))
		}
	}
	return ar, nil
}

// ---- Authentication Response (TS 24.501 §8.2.2.1) -----------------------

// AuthenticationResponse carries the UE's RES* (or EAP response).
type AuthenticationResponse struct {
	// IEI 0x2D — Authentication response parameter (RES*), TLV
	RES []byte
	// IEI 0x78 — EAP message
	EAPMessage []byte
}

// DecodeAuthenticationResponse parses the body after the message type.
func DecodeAuthenticationResponse(b []byte) (*AuthenticationResponse, error) {
	ar := &AuthenticationResponse{}
	rdr := NewReader(b)
	for rdr.Len() > 0 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}
		switch iei {
		case 0x2D: // RES* — TLV
			l, _ := rdr.ReadByte()
			ar.RES, _ = rdr.ReadBytes(int(l))
		case 0x78: // EAP — LV-E
			hi, _ := rdr.ReadByte()
			lo, _ := rdr.ReadByte()
			l := int(hi)<<8 | int(lo)
			ar.EAPMessage, _ = rdr.ReadBytes(l)
		default:
			l, _ := rdr.ReadByte()
			_, _ = rdr.ReadBytes(int(l))
		}
	}
	return ar, nil
}

// ---- Authentication Failure (TS 24.501 §8.2.3.1) ------------------------

// AuthenticationFailure is sent by the UE on MAC/synch failure.
type AuthenticationFailure struct {
	Cause5GMM Cause5GMM
	// IEI 0x30 — AUTS for resync
	AUTS []byte
}

// DecodeAuthenticationFailure parses the body.
func DecodeAuthenticationFailure(b []byte) (*AuthenticationFailure, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("nas: AuthenticationFailure empty")
	}
	af := &AuthenticationFailure{}
	rdr := NewReader(b)
	cause, _ := rdr.ReadByte()
	af.Cause5GMM = Cause5GMM(cause)
	for rdr.Len() > 0 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}
		if iei == 0x30 { // AUTS
			l, _ := rdr.ReadByte()
			af.AUTS, _ = rdr.ReadBytes(int(l))
		} else {
			l, _ := rdr.ReadByte()
			_, _ = rdr.ReadBytes(int(l))
		}
	}
	return af, nil
}

// ---- Identity Request (TS 24.501 §8.2.13.1) ------------------------------

// IdentityRequest asks the UE to provide its identity.
type IdentityRequest struct {
	IdentityType MobileIdentityType
}

// EncodeIdentityRequest serialises the body (1 byte).
func EncodeIdentityRequest(ir *IdentityRequest) ([]byte, error) {
	return []byte{byte(ir.IdentityType) & 0x07}, nil
}

// DecodeIdentityRequest parses the body.
func DecodeIdentityRequest(b []byte) (*IdentityRequest, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("nas: IdentityRequest empty")
	}
	return &IdentityRequest{IdentityType: MobileIdentityType(b[0] & 0x07)}, nil
}

// ---- Identity Response (TS 24.501 §8.2.14.1) ----------------------------

// IdentityResponse carries the UE's mobile identity.
type IdentityResponse struct {
	MobileIdentity MobileIdentity
}

// DecodeIdentityResponse parses the body.
// 5GS Mobile Identity is LV-E (2-byte big-endian length) per TS 24.501 Table 8.2.14.1.2.
func DecodeIdentityResponse(b []byte) (*IdentityResponse, error) {
	if len(b) < 3 {
		return nil, fmt.Errorf("nas: IdentityResponse too short")
	}
	l := int(b[0])<<8 | int(b[1])
	if len(b) < 2+l {
		return nil, fmt.Errorf("nas: IdentityResponse truncated: need %d got %d", 2+l, len(b))
	}
	mi, err := DecodeMobileIdentity(b[2 : 2+l])
	if err != nil {
		return nil, err
	}
	return &IdentityResponse{MobileIdentity: *mi}, nil
}

// ---- Security Mode Command (TS 24.501 §8.2.25.1) -------------------------

// SecurityModeCommand selects NAS security algorithms and starts NAS security.
type SecurityModeCommand struct {
	// Mandatory
	SelectedNASSecurityAlgorithms  NASSecurityAlgorithms
	NGKSI                          NGKSI
	ReplayedUESecurityCapabilities UESecurityCapability
	// Optional
	// IEI 0xE- — IMEISV request (TV ½, TS 24.501 §9.11.3.28; value 1 = requested)
	IMEISVRequest *byte
	// IEI 0x36 — Additional 5G security information (TLV 3, TS 24.501 §9.11.3.12).
	// Value octet: bit 1 = HDP (horizontal derivation), bit 2 = RINMR
	// (retransmission of the initial NAS message requested). The AMF sets RINMR
	// when the initial NAS message was sent without integrity protection so the
	// UE retransmits the full message (with non-cleartext IEs) in the NAS message
	// container of the Security Mode Complete. Ref: TS 24.501 §4.4.6, §5.4.2.2.
	Additional5GSecurityInfo *byte
	// IEI 0x71 — NAS message container (replayed Registration Request)
	NASMessageContainer []byte
}

// Additional 5G security information value bits (TS 24.501 §9.11.3.12).
const (
	Additional5GSecInfoHDP   byte = 0x01 // horizontal derivation of KAMF required
	Additional5GSecInfoRINMR byte = 0x02 // retransmission of initial NAS message requested
)

// IMEISVRequested is the IMEISV request IE value "IMEISV requested"
// (TS 24.501 §9.11.3.28 → TS 24.008 §10.5.5.10).
const IMEISVRequested byte = 0x01

// EncodeSecurityModeCommand serialises the message body.
// Ref: TS 24.501 §8.2.25.1 Figure 8.2.25.1.1
func EncodeSecurityModeCommand(smc *SecurityModeCommand) ([]byte, error) {
	var out []byte

	// Octet 4: selected NAS security algorithms
	out = append(out, smc.SelectedNASSecurityAlgorithms.Encode())

	// Octet 5: spare(4) | ngKSI type(1) | ngKSI value(3)
	out = append(out, ((smc.NGKSI.Type&0x01)<<3)|smc.NGKSI.KeySetIdentifier&0x07)

	// Replayed UE Security Capabilities (mandatory, LV format).
	// Length is dynamic: UERANSIM sends 4 bytes (5G-EA+5G-IA+EPS-EA+EPS-IA);
	// replaying fewer bytes causes "Replayed UE security capability mismatch".
	caps := EncodeUESecurityCapability(smc.ReplayedUESecurityCapabilities)
	out = append(out, byte(len(caps)))
	out = append(out, caps...)

	// IEI 0xE- — IMEISV request (TV ½: IEI in high nibble, value in low nibble).
	// Ordered per TS 24.501 Table 8.2.25.1.1 (before Additional 5G security info).
	if smc.IMEISVRequest != nil {
		out = append(out, 0xE0|(*smc.IMEISVRequest&0x07))
	}

	// IEI 0x36 — Additional 5G security information (TLV, 1-octet value)
	if smc.Additional5GSecurityInfo != nil {
		out = append(out, 0x36, 0x01, *smc.Additional5GSecurityInfo)
	}

	// IEI 0x71 — NAS message container (replayed Registration Request, optional)
	if len(smc.NASMessageContainer) > 0 {
		length := len(smc.NASMessageContainer)
		out = append(out, 0x71, byte(length>>8), byte(length))
		out = append(out, smc.NASMessageContainer...)
	}

	return out, nil
}

// DecodeSecurityModeCommand parses the body.
func DecodeSecurityModeCommand(b []byte) (*SecurityModeCommand, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("nas: SecurityModeCommand too short: %d", len(b))
	}
	smc := &SecurityModeCommand{}
	rdr := NewReader(b)

	algByte, _ := rdr.ReadByte()
	smc.SelectedNASSecurityAlgorithms = DecodeNASSecurityAlgorithms(algByte)
	ngksi, _ := rdr.ReadByte()
	smc.NGKSI = NGKSI{
		KeySetIdentifier: ngksi & 0x07,
		Type:             (ngksi >> 3) & 0x01,
	}
	capLen, _ := rdr.ReadByte()
	capBytes, _ := rdr.ReadBytes(int(capLen))
	cap, _ := DecodeUESecurityCapability(capBytes)
	smc.ReplayedUESecurityCapabilities = cap

	for rdr.Len() > 0 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}
		// TV ½ IEs: IEI in high nibble. 0xE- = IMEISV request.
		if iei>>4 == 0xE {
			v := iei & 0x07
			smc.IMEISVRequest = &v
			continue
		}
		switch iei {
		case 0x36: // Additional 5G security information — TLV
			l, _ := rdr.ReadByte()
			if v, err := rdr.ReadBytes(int(l)); err == nil && len(v) > 0 {
				val := v[0]
				smc.Additional5GSecurityInfo = &val
			}
		case 0x71:
			hi, _ := rdr.ReadByte()
			lo, _ := rdr.ReadByte()
			l := int(hi)<<8 | int(lo)
			smc.NASMessageContainer, _ = rdr.ReadBytes(l)
		default:
			if iei < 0x80 {
				l, _ := rdr.ReadByte()
				_, _ = rdr.ReadBytes(int(l))
			}
		}
	}
	return smc, nil
}

// ---- Security Mode Reject (TS 24.501 §8.2.27.1) -------------------------

// SecurityModeReject is sent by the UE when it rejects the Security Mode Command.
// Cause 24 (0x18) = "Security mode rejected, unspecified" — used by UERANSIM v3.2.8
// for both MAC verification failure and UE security capabilities mismatch.
type SecurityModeReject struct {
	Cause5GMM Cause5GMM
}

// DecodeSecurityModeReject parses the body.
func DecodeSecurityModeReject(b []byte) (*SecurityModeReject, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("nas: SecurityModeReject too short")
	}
	return &SecurityModeReject{Cause5GMM: Cause5GMM(b[0])}, nil
}

// ---- Security Mode Complete (TS 24.501 §8.2.26.1) -----------------------

// SecurityModeComplete is sent by the UE after applying NAS security.
type SecurityModeComplete struct {
	// IEI 0x77 — IMEISV (optional)
	IMEISV *MobileIdentity
	// IEI 0x71 — NAS message container (ciphered Registration Request, optional)
	NASMessageContainer []byte
}

// DecodeSecurityModeComplete parses the body.
func DecodeSecurityModeComplete(b []byte) (*SecurityModeComplete, error) {
	smc := &SecurityModeComplete{}
	rdr := NewReader(b)
	for rdr.Len() > 0 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}
		switch iei {
		case 0x77: // IMEISV — LV-E
			hi, _ := rdr.ReadByte()
			lo, _ := rdr.ReadByte()
			l := int(hi)<<8 | int(lo)
			imeiBytes, _ := rdr.ReadBytes(l)
			mi, _ := DecodeMobileIdentity(imeiBytes)
			smc.IMEISV = mi
		case 0x71: // NAS message container — LV-E
			hi, _ := rdr.ReadByte()
			lo, _ := rdr.ReadByte()
			l := int(hi)<<8 | int(lo)
			smc.NASMessageContainer, _ = rdr.ReadBytes(l)
		default:
			if iei < 0x80 {
				l, _ := rdr.ReadByte()
				_, _ = rdr.ReadBytes(int(l))
			}
		}
	}
	return smc, nil
}
