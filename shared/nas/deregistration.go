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

// ---- NW-Initiated Deregistration Request (TS 24.501 §8.2.13.1) -----------

// DeregistrationRequestNW is sent by the AMF to force the UE to deregister.
type DeregistrationRequestNW struct {
	// Cause: optional 5GMM cause (IEI=0x58). 0 = omit.
	Cause5GMM byte
	// ReregistrationRequired: bit 4 of the De-registration type octet.
	ReregistrationRequired bool
	// AccessType: 1=3GPP, 2=non-3GPP, 3=both.
	AccessType uint8
}

// EncodeDeregistrationRequestNW serialises the NW-initiated Deregistration Request body.
// Format: Octet 4 = DeregType (spare|spare|ReRegReq|SwitchOff|AT2|AT1) | spare nibble
//
//	Octet 5+: optional 5GMM Cause (IEI 0x58, TV)
func EncodeDeregistrationRequestNW(r *DeregistrationRequestNW) ([]byte, error) {
	at := r.AccessType & 0x03
	var reReg byte
	if r.ReregistrationRequired {
		reReg = 0x08
	}
	// NGKSI nibble: set to "no key is available" (0x07) for NW-initiated deregistration.
	ngksi := byte(0x70)
	b := []byte{ngksi | reReg | at}

	// Optional 5GMM Cause (IEI=0x58, T-V: 1 byte IEI + 1 byte value)
	if r.Cause5GMM != 0 {
		b = append(b, 0x58, r.Cause5GMM)
	}
	return b, nil
}
