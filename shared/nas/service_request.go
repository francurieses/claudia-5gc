package nas

// service_request.go — 5GMM Service Request / Service Accept codec.
// Ref: 3GPP TS 24.501 §8.2.16 (Service Request), §8.2.17 (Service Accept)

import "fmt"

// Service type values (TS 24.501 §9.11.3.50, Table 9.11.3.50.1, V19.8.0).
// ServiceTypeHighPriorityAccess was previously 0x07; the table assigns 0101
// (0x05) and marks 0111 as unused ("shall be interpreted as signalling").
const (
	ServiceTypeSignalling                = 0x00 // signalling
	ServiceTypeData                      = 0x01 // data
	ServiceTypeMobileTerminated          = 0x02 // mobile terminated services
	ServiceTypeEmergencyServices         = 0x03 // emergency services
	ServiceTypeEmergencyServicesFallback = 0x04 // emergency services fallback
	ServiceTypeHighPriorityAccess        = 0x05 // high priority access
	ServiceTypeElevatedSignalling        = 0x06 // elevated signalling
)

// InterpretServiceType returns the service type the network shall act on for
// a received service type value, and whether the value is defined or has a
// spec-mandated interpretation. Table 9.11.3.50.1: 0111 and 1000 are unused
// and "shall be interpreted as signalling, if received by the network"; 1001,
// 1010 and 1011 are unused and "shall be interpreted as data"; "All other
// values are reserved" (ok=false, value returned unchanged).
func InterpretServiceType(v byte) (byte, bool) {
	switch {
	case v <= ServiceTypeElevatedSignalling:
		return v, true
	case v == 0x07 || v == 0x08:
		return ServiceTypeSignalling, true
	case v >= 0x09 && v <= 0x0B:
		return ServiceTypeData, true
	}
	return v, false
}

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

		if iei != IEIUplinkDataStatus && iei != IEIPDUSessionStatus {
			// Allowed PDU session status, UE request type, Paging restriction
			// and unknown IEs: skipped by table / TS 24.007 §11.2.4. A
			// syntactically incorrect IE is treated as not present and stops
			// optional-IE parsing. Ref: TS 24.501 §7.6.1, §7.7.1
			if err := rdr.skipIE(IEMsgServiceRequest); err != nil {
				break
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
	// PDUSessionReactivationResultErrorCause — IEI 0x72, TLV-E (TS 24.501
	// §9.11.3.43), after IEI 0x26. nil/empty = IE absent.
	PDUSessionReactivationResultErrorCause []PDUSessionErrorCause
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
	b = append(b, EncodePDUSessionReactivationResultErrorCause(a.PDUSessionReactivationResultErrorCause)...)
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
		if iei == IEIPDUSessionReactivationResultErrorCause {
			lb, err := rdr.ReadBytes(2)
			if err != nil {
				return a, fmt.Errorf("nas: ServiceAccept: truncated length (IEI 0x72)")
			}
			val, err := rdr.ReadBytes(int(lb[0])<<8 | int(lb[1]))
			if err != nil {
				return a, fmt.Errorf("nas: ServiceAccept: truncated IE 0x72: %w", err)
			}
			if list, err := DecodePDUSessionReactivationResultErrorCause(val); err == nil {
				a.PDUSessionReactivationResultErrorCause = list
			}
			continue
		}
		if iei != IEIPDUSessionStatus && iei != IEIPDUSessionReactivationResult {
			// Reactivation result error cause (TLV-E), EAP message (TLV-E),
			// T3448 and every unknown IE: skipped by table / TS 24.007
			// §11.2.4 so a TLV-E IE never shifts the following IEs.
			if err := rdr.skipIE(IEMsgServiceAccept); err != nil {
				return a, fmt.Errorf("nas: ServiceAccept: %w", err)
			}
			continue
		}
		l, err := rdr.ReadByte()
		if err != nil {
			return a, fmt.Errorf("nas: ServiceAccept: truncated length (IEI 0x%02X)", iei)
		}
		val, err := rdr.ReadBytes(int(l))
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

// PSIsFromStatusBytes converts the value octets of a PDU session status /
// uplink data status / PDU session reactivation result IE (wire order: octet 3
// bit1=PSI0..bit8=PSI7, octet 4 PSI8..15; further octets spare) into the sorted
// PSIs flagged (PSI 0 is spare and omitted). Ref: TS 24.501 §9.11.3.44, §9.11.3.57
func PSIsFromStatusBytes(v []byte) []uint8 {
	var out []uint8
	for psi := uint8(1); psi <= 15; psi++ {
		oct := psi / 8
		if int(oct) < len(v) && v[oct]>>(psi%8)&1 == 1 {
			out = append(out, psi)
		}
	}
	return out
}

// StatusMaskFromBytes converts status IE value octets into the uint16 layout
// used by DecodeServiceRequest / PSIInStatus (first octet in the high byte).
// Returns 0 when fewer than 2 octets are present.
func StatusMaskFromBytes(v []byte) uint16 {
	if len(v) < 2 {
		return 0
	}
	return uint16(v[0])<<8 | uint16(v[1])
}
