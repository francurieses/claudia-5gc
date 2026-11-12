// Package nas — Rejected NSSAI information element (TS 24.501 §9.11.3.46).
package nas

import "fmt"

// Rejected NSSAI cause values (TS 24.501 Table 9.11.3.46.1, cause value, bits 4-1).
// All other values are reserved.
const (
	// RejectedCauseNotAvailableInPLMN — "S-NSSAI not available in the current PLMN or SNPN" (0b0000).
	RejectedCauseNotAvailableInPLMN uint8 = 0x00
	// RejectedCauseNotAvailableInRA — "S-NSSAI not available in the current registration area" (0b0001).
	RejectedCauseNotAvailableInRA uint8 = 0x01
	// RejectedCauseNSSAAFailedOrRevoked — "S-NSSAI not available due to the failed or
	// revoked network slice-specific authentication and authorization" (0b0010).
	RejectedCauseNSSAAFailedOrRevoked uint8 = 0x02
)

// MaxRejectedSNSSAIs is the maximum number of rejected S-NSSAIs in one Rejected
// NSSAI IE (TS 24.501 §9.11.3.46 NOTE 0; the UE stores only the first 8).
const MaxRejectedSNSSAIs = 8

// RejectedSNSSAI is one rejected S-NSSAI with its cause value
// (TS 24.501 Figure 9.11.3.46.2). SNSSAI.SD == SDNotPresent means no SD octets.
type RejectedSNSSAI struct {
	Cause  uint8 // 4-bit cause value, RejectedCause* constants
	SNSSAI SNSSAI
}

// EncodeRejectedNSSAI encodes the value part of the Rejected NSSAI IE (octets 3..v,
// without IEI and length). Each element is: (length of rejected S-NSSAI, 4 bits |
// cause, 4 bits), SST, [SD x3]. The length field counts the S-NSSAI octets (1 or 4)
// that follow the first octet. An empty list yields nil.
func EncodeRejectedNSSAI(list []RejectedSNSSAI) ([]byte, error) {
	if len(list) > MaxRejectedSNSSAIs {
		return nil, fmt.Errorf("nas: rejected NSSAI: %d entries exceed maximum %d", len(list), MaxRejectedSNSSAIs)
	}
	var out []byte
	for i, r := range list {
		if r.Cause > 0x0F {
			return nil, fmt.Errorf("nas: rejected NSSAI[%d]: cause %#x exceeds 4 bits", i, r.Cause)
		}
		if r.SNSSAI.SD == SDNotPresent {
			out = append(out, 1<<4|r.Cause, r.SNSSAI.SST)
			continue
		}
		if r.SNSSAI.SD > 0xFFFFFF {
			return nil, fmt.Errorf("nas: rejected NSSAI[%d]: SD %#x exceeds 24 bits", i, r.SNSSAI.SD)
		}
		out = append(out, 4<<4|r.Cause, r.SNSSAI.SST,
			byte(r.SNSSAI.SD>>16), byte(r.SNSSAI.SD>>8), byte(r.SNSSAI.SD))
	}
	return out, nil
}

// DecodeRejectedNSSAI parses the value part of the Rejected NSSAI IE. Lengths other
// than 1 (SST) or 4 (SST+SD), or a truncated element, are errors.
func DecodeRejectedNSSAI(b []byte) ([]RejectedSNSSAI, error) {
	var out []RejectedSNSSAI
	for i := 0; i < len(b); {
		l := int(b[i] >> 4)
		cause := b[i] & 0x0F
		i++
		if l != 1 && l != 4 {
			return nil, fmt.Errorf("nas: rejected NSSAI: invalid length of rejected S-NSSAI %d", l)
		}
		if i+l > len(b) {
			return nil, fmt.Errorf("nas: rejected NSSAI: truncated element")
		}
		r := RejectedSNSSAI{Cause: cause, SNSSAI: SNSSAI{SST: b[i], SD: SDNotPresent}}
		if l == 4 {
			r.SNSSAI.SD = uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
		}
		i += l
		out = append(out, r)
	}
	return out, nil
}
