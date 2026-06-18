package nas

// service_request.go — 5GMM Service Request / Service Accept codec.
// Ref: 3GPP TS 24.501 §8.2.15 (Service Request), §8.2.16 (Service Accept)

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
// Ref: TS 24.501 §8.2.15.1.1 Table 8.2.15.1.1-1
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

	// 5G-S-TMSI: mandatory LV (1-byte length) per TS 24.501 §8.2.16.1.
	// Value layout (7 bytes): identity-type octet (0xF4) | AMF Set ID(10b) +
	// AMF Pointer(6b) | 5G-TMSI (4 bytes).
	// (Audit fix: this IE was previously not consumed, so its length byte was
	// misread as an optional IEI and UplinkDataStatus/PDUSessionStatus were lost.)
	if tmsiLen, err := rdr.ReadByte(); err == nil {
		if val, err := rdr.ReadBytes(int(tmsiLen)); err == nil && len(val) >= 7 {
			r.TMSI = uint32(val[3])<<24 | uint32(val[4])<<16 | uint32(val[5])<<8 | uint32(val[6])
		}
	}

	// Optional TLV IEs
	for rdr.Len() >= 2 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
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

// ServiceAccept is the (empty) body of a 5GMM Service Accept (0x4E).
// All IEs are optional; for the initial Service Request happy path none are needed.
// Ref: TS 24.501 §8.2.16.1.1
type ServiceAccept struct{}

// EncodeServiceAccept returns an empty byte slice (no mandatory IEs).
func EncodeServiceAccept(_ *ServiceAccept) ([]byte, error) {
	return []byte{}, nil
}

// ServiceReject is the body of a 5GMM Service Reject (0x4D).
// Ref: TS 24.501 §8.2.17
type ServiceReject struct {
	// Cause5GMM — TS 24.501 §9.11.3.2.
	// 0x09 = UE identity cannot be derived by the network.
	Cause5GMM byte
}

// EncodeServiceReject encodes a Service Reject body (1 byte: cause).
func EncodeServiceReject(r *ServiceReject) ([]byte, error) {
	return []byte{r.Cause5GMM}, nil
}
