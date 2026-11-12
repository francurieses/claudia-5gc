package nas

// deregistration.go — 5GMM Deregistration messages codec.
// Ref: 3GPP TS 24.501 §8.2.11 (UE-initiated), §8.2.12 (NW-initiated)

import "fmt"

// ---- UE-Initiated Deregistration Request (TS 24.501 §8.2.11.1) -----------

// DeregistrationRequest is the decoded form of a 5GMM Deregistration Request
// message sent by the UE to the network.
type DeregistrationRequest struct {
	// SwitchOff: true if the UE is powering off and no Deregistration Accept is expected.
	// Ref: TS 24.501 §9.11.3.20 bit 3
	SwitchOff bool

	// AccessType: 1=3GPP access, 2=non-3GPP access, 3=both.
	// Ref: TS 24.501 §9.11.3.20 bits 1-2
	AccessType uint8

	// NGKSI: NAS key set identifier packed in the same octet as AccessType.
	// Bits 7-5 = spare/TSC/KSI, bits 4-1 = SwitchOff/AccessType.
	NGKSI NGKSI

	// MobileIdentity: 5G-GUTI or SUCI identifying the UE.
	MobileIdentity MobileIdentity
}

// DecodeDeregistrationRequest parses the bytes after the NAS message type.
// Format (TS 24.501 §8.2.11.1 Table 8.2.11.1-1):
//
//	Octet 4: ½-oct = NGKSI | ½-oct = De-registration type
//	         De-registration type: bit3=SwitchOff, bits2-1=AccessType
//	Octet 5-N: 5GS Mobile Identity (LV-E)
func DecodeDeregistrationRequest(b []byte) (*DeregistrationRequest, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("nas: DeregistrationRequest too short: %d bytes", len(b))
	}
	rdr := NewReader(b)

	// Octet 4: shared ½-octet fields — NGKSI upper nibble, DeregType lower nibble.
	combined, err := rdr.ReadByte()
	if err != nil {
		return nil, err
	}
	r := &DeregistrationRequest{}
	r.NGKSI = NGKSI{
		Type:             (combined >> 7) & 0x01,
		KeySetIdentifier: (combined >> 4) & 0x07,
	}
	r.SwitchOff = (combined>>3)&0x01 == 1
	r.AccessType = combined & 0x03

	// 5GS Mobile Identity: mandatory LV-E (2-byte length).
	miHi, err := rdr.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("nas: DeregistrationRequest: mobile identity length hi: %w", err)
	}
	miLo, err := rdr.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("nas: DeregistrationRequest: mobile identity length lo: %w", err)
	}
	miLen := int(miHi)<<8 | int(miLo)
	miBytes, err := rdr.ReadBytes(miLen)
	if err != nil {
		return nil, fmt.Errorf("nas: DeregistrationRequest: mobile identity: %w", err)
	}
	mi, err := DecodeMobileIdentity(miBytes)
	if err != nil {
		return nil, fmt.Errorf("nas: DeregistrationRequest: decode mobile identity: %w", err)
	}
	r.MobileIdentity = *mi
	return r, nil
}

// ---- Deregistration Accept UE (TS 24.501 §8.2.12.1) ----------------------
// No IEs — the message body is empty.

// DeregistrationAcceptUE is the empty body of a Deregistration Accept
// message sent by the AMF to the UE (only for non-switch-off deregistration).
type DeregistrationAcceptUE struct{}

// EncodeDeregistrationAcceptUE returns an empty byte slice (no IEs).
func EncodeDeregistrationAcceptUE(_ *DeregistrationAcceptUE) ([]byte, error) {
	return []byte{}, nil
}

// ---- NW-Initiated Deregistration Request (TS 24.501 §8.2.14) -------------

// DeregistrationRequestNW is sent by the AMF to force the UE to deregister.
type DeregistrationRequestNW struct {
	// Cause: optional 5GMM cause (IEI=0x58). 0 = omit.
	Cause5GMM byte
	// ReregistrationRequired: bit 3 (0x04) of the De-registration type value.
	// TS 24.501 §9.11.3.20: bit 4 = switch off, bit 3 = re-registration required.
	ReregistrationRequired bool
	// AccessType: 1=3GPP, 2=non-3GPP, 3=both.
	AccessType uint8
	// RejectedNSSAI: optional Rejected NSSAI IE (IEI 0x6D, TLV, §9.11.3.46),
	// TS 24.501 Table 8.2.14.1.1: after 5GMM cause (0x58) and T3346 value (0x5F).
	// nil/empty = IE absent (bytes identical to the pre-AMF-022 encoding).
	RejectedNSSAI []RejectedSNSSAI
	// ExtendedRejectedNSSAI: optional Extended rejected NSSAI IE (IEI 0x68, TLV,
	// §9.11.3.75), Table 8.2.14.1.1: after Rejected NSSAI (0x6D) and CAG
	// information list (0x75). nil = IE absent.
	ExtendedRejectedNSSAI *ExtendedRejectedNSSAI
	// SpareHalfOctetZero: the high half octet of octet 4 is a spare half octet
	// (Table 8.2.14.1.1, §9.5: coded as zero). Default false keeps the legacy
	// 0x7 ("no key is available" ngKSI pattern) so Rel-15..17 bytes are unchanged;
	// set true to emit spare = 0.
	SpareHalfOctetZero bool
}

// IEIDeregRejectedNSSAI is the IEI of the Rejected NSSAI IE in the
// DEREGISTRATION REQUEST (UE terminated), TS 24.501 Table 8.2.14.1.1.
const IEIDeregRejectedNSSAI byte = 0x6D

// EncodeDeregistrationRequestNW serialises the NW-initiated Deregistration Request body.
// Format: Octet 4 = NGKSI nibble | DeregType nibble (SwitchOff|ReRegReq|AT2|AT1)
//
//	Octet 5+: optional 5GMM Cause (IEI 0x58, TV)
func EncodeDeregistrationRequestNW(r *DeregistrationRequestNW) ([]byte, error) {
	at := r.AccessType & 0x03
	var reReg byte
	if r.ReregistrationRequired {
		reReg = 0x04
	}
	// High nibble: legacy encoding writes 0x7 (ngKSI "no key is available");
	// TS 24.501 §9.5 / Table 8.2.14.1.1 define it as a spare half octet = 0.
	hi := byte(0x70)
	if r.SpareHalfOctetZero {
		hi = 0
	}
	b := []byte{hi | reReg | at}

	// Optional 5GMM Cause (IEI=0x58, T-V: 1 byte IEI + 1 byte value)
	if r.Cause5GMM != 0 {
		b = append(b, 0x58, r.Cause5GMM)
	}
	// Rejected NSSAI (IEI 0x6D, TLV) — Table 8.2.14.1.1, after 5GMM cause / T3346.
	if len(r.RejectedNSSAI) > 0 {
		rej, err := EncodeRejectedNSSAI(r.RejectedNSSAI)
		if err != nil {
			return nil, err
		}
		b = append(b, IEIDeregRejectedNSSAI, byte(len(rej)))
		b = append(b, rej...)
	}
	// Extended rejected NSSAI (IEI 0x68, TLV) — after Rejected NSSAI / CAG information list.
	if r.ExtendedRejectedNSSAI != nil {
		tlv, err := encodeExtendedRejectedNSSAITLV(r.ExtendedRejectedNSSAI)
		if err != nil {
			return nil, err
		}
		b = append(b, tlv...)
	}
	return b, nil
}

// DecodeDeregistrationRequestNW parses the body of a DEREGISTRATION REQUEST
// (UE terminated), TS 24.501 §8.2.14. Octet 1 carries NGKSI (high nibble) and
// the de-registration type (low nibble). Known optional IEs: 5GMM cause (0x58, TV),
// T3346 value (0x5F, TLV, skipped), Rejected NSSAI (0x6D, TLV), Extended rejected
// NSSAI (0x68, TLV). Unknown IEIs below 0x80 are skipped as TLV using their length;
// an IEI >= 0x80 (half-octet TV, none defined for this message) is skipped as a
// single octet.
func DecodeDeregistrationRequestNW(b []byte) (*DeregistrationRequestNW, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("nas: deregistration request (NW): empty body")
	}
	r := &DeregistrationRequestNW{
		ReregistrationRequired: b[0]&0x04 != 0,
		AccessType:             b[0] & 0x03,
	}
	for i := 1; i < len(b); {
		iei := b[i]
		if iei == 0x58 {
			if i+2 > len(b) {
				return nil, fmt.Errorf("nas: deregistration request (NW): truncated 5GMM cause")
			}
			r.Cause5GMM = b[i+1]
			i += 2
			continue
		}
		if iei >= 0x80 { // half-octet TV IE, not defined for this message
			i++
			continue
		}
		if i+2 > len(b) || i+2+int(b[i+1]) > len(b) {
			return nil, fmt.Errorf("nas: deregistration request (NW): truncated IE %#x", iei)
		}
		val := b[i+2 : i+2+int(b[i+1])]
		if iei == IEIDeregRejectedNSSAI {
			rej, err := DecodeRejectedNSSAI(val)
			if err != nil {
				return nil, fmt.Errorf("nas: deregistration request (NW): rejected NSSAI: %w", err)
			}
			r.RejectedNSSAI = rej
		}
		if iei == IEIExtendedRejectedNSSAI {
			ext, err := DecodeExtendedRejectedNSSAI(val)
			if err != nil {
				return nil, fmt.Errorf("nas: deregistration request (NW): extended rejected NSSAI: %w", err)
			}
			r.ExtendedRejectedNSSAI = ext
		}
		i += 2 + int(b[i+1])
	}
	return r, nil
}
