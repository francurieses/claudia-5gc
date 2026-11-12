package nas

import (
	"errors"
	"fmt"
)

// Service area list information element (TS 24.501 §9.11.3.49, IEI 0x27,
// TLV, type 4). Used by REGISTRATION ACCEPT (Table 8.2.7.1.1) and
// CONFIGURATION UPDATE COMMAND (Table 8.2.19.1.1).

// IEIServiceAreaList is the IEI of the Service area list IE (TS 24.501 §9.11.3.49).
const IEIServiceAreaList byte = 0x27

// Type-of-list values (octet 1 bits 7-6 of a partial service area list,
// TS 24.501 Table 9.11.3.49.1).
const (
	// ServiceAreaTypeNonConsecutiveTACs: list of TACs of one PLMN, non-consecutive values.
	ServiceAreaTypeNonConsecutiveTACs byte = 0x0
	// ServiceAreaTypeConsecutiveTACs: list of TACs of one PLMN, consecutive values.
	ServiceAreaTypeConsecutiveTACs byte = 0x1
	// ServiceAreaTypeDifferentPLMNs: list of TAIs belonging to different PLMNs.
	ServiceAreaTypeDifferentPLMNs byte = 0x2
	// ServiceAreaTypeAllTAIs: all TAIs of the PLMNs in the registration area are
	// in the allowed area (only valid with allowed type 0).
	ServiceAreaTypeAllTAIs byte = 0x3
)

const (
	// serviceAreaMaxTAIs is the maximum number of TAIs in the IE (TS 24.501 §9.11.3.49).
	serviceAreaMaxTAIs = 16
	// serviceAreaMaxLen is the maximum value length (IE max 114 octets incl. IEI and length, §9.11.3.49).
	serviceAreaMaxLen = 112
	// serviceAreaMinLen is the minimum length of the value part (TS 24.501 §9.11.3.49).
	serviceAreaMinLen = 4
)

// ServiceAreaTAI is one TAI of a type-10 partial list.
type ServiceAreaTAI struct {
	MCC string
	MNC string
	TAC uint32 // 24 bits
}

// PartialServiceAreaList is one partial service area list (Figures 9.11.3.49.2-5).
type PartialServiceAreaList struct {
	// NonAllowed is the "allowed type" bit: false = TAIs in the allowed area,
	// true = TAIs in the non-allowed area. Must be equal in all partial lists.
	NonAllowed bool
	// TypeOfList is one of the ServiceAreaType* constants.
	TypeOfList byte
	// MCC/MNC: the PLMN for types 00, 01 and 11.
	MCC, MNC string
	// TACs: types 00 (any values) and 01 (consecutive values; only the first
	// is on the wire, the count is the number of elements).
	TACs []uint32
	// TAIs: type 10 only.
	TAIs []ServiceAreaTAI
}

// ServiceAreaList is the Service area list IE value.
type ServiceAreaList struct {
	Partial []PartialServiceAreaList
}

func validPLMN(mcc, mnc string) bool {
	if len(mcc) != 3 || (len(mnc) != 2 && len(mnc) != 3) {
		return false
	}
	for _, s := range []string{mcc, mnc} {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
	}
	return true
}

// EncodeServiceAreaListValue encodes the value part (octets 3..n) of the IE.
func EncodeServiceAreaListValue(l *ServiceAreaList) ([]byte, error) {
	if l == nil || len(l.Partial) == 0 {
		return nil, errors.New("nas: service area list: no partial lists")
	}
	var out []byte
	total := 0
	nonAllowed := l.Partial[0].NonAllowed
	for i, p := range l.Partial {
		if p.NonAllowed != nonAllowed {
			return nil, fmt.Errorf("nas: service area list: partial %d: mixed allowed types", i)
		}
		var n int // number of elements on the wire
		switch p.TypeOfList {
		case ServiceAreaTypeNonConsecutiveTACs, ServiceAreaTypeConsecutiveTACs:
			if !validPLMN(p.MCC, p.MNC) {
				return nil, fmt.Errorf("nas: service area list: partial %d: invalid PLMN", i)
			}
			n = len(p.TACs)
			if n == 0 {
				return nil, fmt.Errorf("nas: service area list: partial %d: no TACs", i)
			}
		case ServiceAreaTypeDifferentPLMNs:
			n = len(p.TAIs)
			if n == 0 {
				return nil, fmt.Errorf("nas: service area list: partial %d: no TAIs", i)
			}
			for _, t := range p.TAIs {
				if !validPLMN(t.MCC, t.MNC) {
					return nil, fmt.Errorf("nas: service area list: partial %d: invalid PLMN", i)
				}
			}
		case ServiceAreaTypeAllTAIs:
			if p.NonAllowed {
				return nil, fmt.Errorf("nas: service area list: partial %d: type 11 requires allowed type 0", i)
			}
			if !validPLMN(p.MCC, p.MNC) {
				return nil, fmt.Errorf("nas: service area list: partial %d: invalid PLMN", i)
			}
		default:
			return nil, fmt.Errorf("nas: service area list: partial %d: invalid type of list %d", i, p.TypeOfList)
		}
		total += n
		if total > serviceAreaMaxTAIs || n > serviceAreaMaxTAIs {
			return nil, fmt.Errorf("nas: service area list: more than %d TAIs", serviceAreaMaxTAIs)
		}
		hdr := p.TypeOfList << 5
		if p.NonAllowed {
			hdr |= 0x80
		}
		if n > 0 {
			hdr |= byte(n-1) & 0x1F
		}
		out = append(out, hdr)
		switch p.TypeOfList {
		case ServiceAreaTypeNonConsecutiveTACs:
			out = append(out, encodeMCCMNC(p.MCC, p.MNC)...)
			for _, t := range p.TACs {
				out = append(out, byte(t>>16), byte(t>>8), byte(t))
			}
		case ServiceAreaTypeConsecutiveTACs:
			for j := 1; j < n; j++ {
				if p.TACs[j] != p.TACs[j-1]+1 {
					return nil, fmt.Errorf("nas: service area list: partial %d: TACs not consecutive", i)
				}
			}
			t := p.TACs[0]
			out = append(out, encodeMCCMNC(p.MCC, p.MNC)...)
			out = append(out, byte(t>>16), byte(t>>8), byte(t))
		case ServiceAreaTypeDifferentPLMNs:
			for _, t := range p.TAIs {
				out = append(out, encodeMCCMNC(t.MCC, t.MNC)...)
				out = append(out, byte(t.TAC>>16), byte(t.TAC>>8), byte(t.TAC))
			}
		case ServiceAreaTypeAllTAIs:
			out = append(out, encodeMCCMNC(p.MCC, p.MNC)...)
		}
	}
	if len(out) < serviceAreaMinLen || len(out) > serviceAreaMaxLen {
		return nil, fmt.Errorf("nas: service area list: length %d out of range", len(out))
	}
	return out, nil
}

// EncodeServiceAreaList encodes the full TLV (IEI 0x27 + length + value).
func EncodeServiceAreaList(l *ServiceAreaList) ([]byte, error) {
	v, err := EncodeServiceAreaListValue(l)
	if err != nil {
		return nil, err
	}
	return append([]byte{IEIServiceAreaList, byte(len(v))}, v...), nil
}

// DecodeServiceAreaListValue parses the value part of the IE. Type-00 and
// type-10 lists are returned as-is; type-01 is expanded to its TACs.
func DecodeServiceAreaListValue(b []byte) (*ServiceAreaList, error) {
	l := &ServiceAreaList{}
	for len(b) > 0 {
		hdr := b[0]
		b = b[1:]
		p := PartialServiceAreaList{NonAllowed: hdr&0x80 != 0, TypeOfList: (hdr >> 5) & 0x3}
		n := int(hdr&0x1F) + 1
		if n > serviceAreaMaxTAIs {
			n = serviceAreaMaxTAIs
		}
		need := 3
		switch p.TypeOfList {
		case ServiceAreaTypeNonConsecutiveTACs:
			need = 3 + 3*n
		case ServiceAreaTypeConsecutiveTACs:
			need = 6
		case ServiceAreaTypeDifferentPLMNs:
			need = 6 * n
		}
		if len(b) < need {
			return nil, errors.New("nas: service area list: truncated partial list")
		}
		tac := func(x []byte) uint32 { return uint32(x[0])<<16 | uint32(x[1])<<8 | uint32(x[2]) }
		switch p.TypeOfList {
		case ServiceAreaTypeNonConsecutiveTACs:
			p.MCC, p.MNC = decodeMCCMNC(b[:3])
			for j := 0; j < n; j++ {
				p.TACs = append(p.TACs, tac(b[3+3*j:]))
			}
		case ServiceAreaTypeConsecutiveTACs:
			p.MCC, p.MNC = decodeMCCMNC(b[:3])
			first := tac(b[3:])
			for j := 0; j < n; j++ {
				p.TACs = append(p.TACs, first+uint32(j))
			}
		case ServiceAreaTypeDifferentPLMNs:
			for j := 0; j < n; j++ {
				mcc, mnc := decodeMCCMNC(b[6*j : 6*j+3])
				p.TAIs = append(p.TAIs, ServiceAreaTAI{MCC: mcc, MNC: mnc, TAC: tac(b[6*j+3:])})
			}
		case ServiceAreaTypeAllTAIs:
			p.MCC, p.MNC = decodeMCCMNC(b[:3])
		}
		b = b[need:]
		l.Partial = append(l.Partial, p)
	}
	if len(l.Partial) == 0 {
		return nil, errors.New("nas: service area list: empty")
	}
	return l, nil
}
