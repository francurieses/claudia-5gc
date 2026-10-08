package nas

// service_request.go — 5GMM Service Request / Service Accept codec.
// Ref: 3GPP TS 24.501 §8.2.16 (Service Request), §8.2.17 (Service Accept)

import "fmt"

// ServiceTypeSignalling is the service type value for NAS signalling.
// Ref: TS 24.501 §9.11.3.50
const (
	ServiceTypeSignalling         = 0x00
	ServiceTypeData               = 0x01
	ServiceTypeMobileTerminated   = 0x02
	ServiceTypeEmergencyServices  = 0x03
	ServiceTypeHighPriorityAccess = 0x07
)

// ServiceRequest is the decoded body of a 5GMM Service Request (0x4C).
// Ref: TS 24.501 §8.2.16.1.1 Table 8.2.16.1.1-1
type ServiceRequest struct {
	// ServiceType: upper nibble of combined byte (TS 24.501 §9.11.3.50).
	ServiceType byte
	// NGKSI: NAS key set identifier (lower nibble of combined byte).
	NGKSI NGKSI
	// TMSI: the 5G-S-TMSI carried in the mandatory 5G-S-TMSI IE (LV).
	// Zero when the IE was absent or truncated. Ref: TS 24.501 §9.11.3.4
	TMSI uint32
	// UplinkDataStatus: bitmask of PDU Session IDs with pending UL data (optional).
	// Bit N set → PSI N has UL data. Ref: TS 24.501 §9.11.3.57
	UplinkDataStatus *uint16
	// PDUSessionStatus: bitmask of PDU Session IDs the UE considers active (optional).
	PDUSessionStatus *uint16
}

// DecodeServiceRequest parses the body bytes after the NAS message type octet.
// Format: Octet 4 = ServiceType (upper nibble) + ngKSI (lower nibble)
//
//	Octet 5-N: optional IEs (UL data status, PDU session status, etc.)
func DecodeServiceRequest(b []byte) (*ServiceRequest, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("nas: ServiceRequest too short: %d bytes", len(b))
	}
	rdr := NewReader(b)

	combined, err := rdr.ReadByte()
	if err != nil {
		return nil, err
	}
	r := &ServiceRequest{
		ServiceType: (combined >> 4) & 0x0F,
		NGKSI: NGKSI{
			KeySetIdentifier: combined & 0x07,
			Type:             (combined >> 3) & 0x01,
		},
	}

	// 5G-S-TMSI: mandatory LV-E (2-byte big-endian length) per TS 24.501
	// Table 8.2.16.1.1 — the 5GS mobile identity IE (§9.11.3.4) is format LV-E,
	// total 9 octets. Value layout (7 bytes): identity-type octet (0xF4) |
	// AMF Set ID(10b) + AMF Pointer(6b) | 5G-TMSI (4 bytes).
	// (Fix: this was previously read as a 1-byte-length LV, shifting the parser
	// so UplinkDataStatus/PDUSessionStatus were lost on UERANSIM messages.)
	if hi, err := rdr.ReadByte(); err == nil {
		if lo, err := rdr.ReadByte(); err == nil {
			if val, err := rdr.ReadBytes(int(hi)<<8 | int(lo)); err == nil && len(val) >= 7 {
				r.TMSI = uint32(val[3])<<24 | uint32(val[4])<<16 | uint32(val[5])<<8 | uint32(val[6])
			}
		}
	}

	// Optional IEs
	for rdr.Len() >= 2 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}

		// NAS message container — TLV-E (2-byte length), TS 24.501 §9.11.3.33.
		// A UE with a valid security context sends the *complete* Service
		// Request (including Uplink Data Status / PDU Session Status) inside
		// this container; the outer message carries only ngKSI + 5G-S-TMSI.
		// Per TS 24.501 §4.4.6 / §5.6.1.4 the network uses the contained
		// message. The container is plaintext under NEA0 (dev null-ciphering);
		// with a real cipher the caller must decipher before decoding.
		if iei == 0x71 {
			hi, err := rdr.ReadByte()
			if err != nil {
				break
			}
			lo, err := rdr.ReadByte()
			if err != nil {
				break
			}
			val, err := rdr.ReadBytes(int(hi)<<8 | int(lo))
			if err != nil {
				break
			}
			// val is a complete plain NAS message: EPD | SHT | MsgType | body.
			if len(val) >= 4 && val[0] == PDMobilityManagement && MessageType(val[2]) == MsgTypeServiceRequest {
				if inner, err := DecodeServiceRequest(val[3:]); err == nil {
					if inner.UplinkDataStatus != nil {
						r.UplinkDataStatus = inner.UplinkDataStatus
					}
					if inner.PDUSessionStatus != nil {
						r.PDUSessionStatus = inner.PDUSessionStatus
					}
				}
			}
			continue
		}

		length, err := rdr.ReadByte()
		if err != nil {
			break
		}
		val, err := rdr.ReadBytes(int(length))
		if err != nil {
			break
		}
		switch iei {
		case 0x40: // Uplink data status
			if len(val) >= 2 {
				v := uint16(val[0])<<8 | uint16(val[1])
				r.UplinkDataStatus = &v
			}
		case 0x50: // PDU session status
			if len(val) >= 2 {
				v := uint16(val[0])<<8 | uint16(val[1])
				r.PDUSessionStatus = &v
			}
		}
	}
	return r, nil
}

// PSIInStatus reports whether PDU session ID psi is flagged in a decoded
// Uplink Data Status / PDU Session Status bitmask as stored by
// DecodeServiceRequest (first wire octet in the high byte: PSI 0-7 → bits
// 8-15, second wire octet in the low byte: PSI 8-15 → bits 0-7).
// Ref: TS 24.501 §9.11.3.57 (Uplink data status), §9.11.3.44 (PDU session status)
func PSIInStatus(mask uint16, psi uint8) bool {
	switch {
	case psi <= 7:
		return mask>>(8+psi)&1 == 1
	case psi <= 15:
		return mask>>(psi-8)&1 == 1
	default:
		return false
	}
}

// PSIMask builds a PDU session bitmask in the layout used by
// DecodeServiceRequest and PSIInStatus (first wire octet — PSI 0-7 — in the
// high byte, second wire octet — PSI 8-15 — in the low byte). PSIs above 15
// are ignored. PSI 0 is spare on the wire and is never set.
// Ref: TS 24.501 §9.11.3.44 (PDU session status), §9.11.3.42 (PDU session
// reactivation result)
func PSIMask(psis ...uint8) uint16 {
	var m uint16
	for _, psi := range psis {
		switch {
		case psi == 0:
			// spare bit
		case psi <= 7:
			m |= 1 << (8 + psi)
		case psi <= 15:
			m |= 1 << (psi - 8)
		}
	}
	return m
}

// IEI values of the optional IEs of SERVICE ACCEPT.
// Ref: TS 24.501 §8.2.17.1.1 Table 8.2.17.1.1
const (
	// IEIPDUSessionReactivationResult — PDU session reactivation result
	// (TLV, length 2-32), TS 24.501 §9.11.3.42.
	IEIPDUSessionReactivationResult = 0x26
)

// ServiceAccept is the body of a 5GMM Service Accept (0x4E). All IEs are
// optional. A nil field is omitted from the encoding.
// Ref: TS 24.501 §8.2.17.1.1 Table 8.2.17.1.1
type ServiceAccept struct {
	// PDUSessionStatus — IEI 0x50, TLV length 2 (TS 24.501 §9.11.3.44).
	// Bit set → the PDU session is active in the AMF. Mandatory when the
	// SERVICE REQUEST carried a PDU session status IE (§5.6.1.4.1).
	// Mask layout as in PSIMask.
	PDUSessionStatus *uint16
	// PDUSessionReactivationResult — IEI 0x26, TLV length 2 (TS 24.501
	// §9.11.3.42). Bit set → user-plane re-establishment for that PSI failed or
	// was not performed; bit clear → not requested or successful. Mandatory
	// when the SERVICE REQUEST carried an Uplink data status IE (§5.6.1.4.1).
	// Mask layout as in PSIMask.
	PDUSessionReactivationResult *uint16
}

// EncodeServiceAccept encodes the Service Accept body (the octets after the
// message type). IEs are written in Table 8.2.17.1.1 order: 0x50 then 0x26.
// Ref: TS 24.501 §8.2.17.1.1
func EncodeServiceAccept(a *ServiceAccept) ([]byte, error) {
	b := []byte{}
	if a == nil {
		return b, nil
	}
	if a.PDUSessionStatus != nil {
		v := *a.PDUSessionStatus
		b = append(b, IEIPDUSessionStatus, 0x02, byte(v>>8), byte(v))
	}
	if a.PDUSessionReactivationResult != nil {
		v := *a.PDUSessionReactivationResult
		b = append(b, IEIPDUSessionReactivationResult, 0x02, byte(v>>8), byte(v))
	}
	return b, nil
}

// DecodeServiceAccept parses a Service Accept body. Only the PDU session
// status and PDU session reactivation result IEs are decoded (first two
// octets of their value); other IEs are skipped by their TLV/TLV-E length.
// Ref: TS 24.501 §8.2.17.1.1
func DecodeServiceAccept(b []byte) (*ServiceAccept, error) {
	a := &ServiceAccept{}
	rdr := NewReader(b)
	for rdr.Len() >= 2 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}
		var n int
		switch iei {
		case 0x72, 0x78: // TLV-E: reactivation result error cause, EAP message
			hi, err1 := rdr.ReadByte()
			lo, err2 := rdr.ReadByte()
			if err1 != nil || err2 != nil {
				return a, fmt.Errorf("nas: ServiceAccept: truncated TLV-E length (IEI 0x%02X)", iei)
			}
			n = int(hi)<<8 | int(lo)
		default:
			l, err := rdr.ReadByte()
			if err != nil {
				return a, fmt.Errorf("nas: ServiceAccept: truncated length (IEI 0x%02X)", iei)
			}
			n = int(l)
		}
		val, err := rdr.ReadBytes(n)
		if err != nil {
			return a, fmt.Errorf("nas: ServiceAccept: truncated IE 0x%02X: %w", iei, err)
		}
		if len(val) < 2 {
			continue
		}
		v := uint16(val[0])<<8 | uint16(val[1])
		switch iei {
		case IEIPDUSessionStatus:
			a.PDUSessionStatus = &v
		case IEIPDUSessionReactivationResult:
			a.PDUSessionReactivationResult = &v
		}
	}
	return a, nil
}

// ServiceReject is the body of a 5GMM Service Reject (0x4D).
// Ref: TS 24.501 §8.2.18
type ServiceReject struct {
	// Cause5GMM — TS 24.501 §9.11.3.2.
	// 0x09 = UE identity cannot be derived by the network.
	Cause5GMM byte
}

// EncodeServiceReject encodes a Service Reject body (1 byte: cause).
func EncodeServiceReject(r *ServiceReject) ([]byte, error) {
	return []byte{r.Cause5GMM}, nil
}
