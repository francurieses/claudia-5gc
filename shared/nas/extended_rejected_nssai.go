// Package nas — Extended rejected NSSAI information element (TS 24.501 §9.11.3.75).
package nas

import "fmt"

// IEIExtendedRejectedNSSAI is the IEI of the Extended rejected NSSAI IE (TLV,
// 1-byte length) in REGISTRATION ACCEPT (Table 8.2.7.1.1), DEREGISTRATION
// REQUEST UE-terminated (Table 8.2.14.1.1) and CONFIGURATION UPDATE COMMAND
// (Table 8.2.19.1.1).
const IEIExtendedRejectedNSSAI byte = 0x68

// Cause values of a rejected S-NSSAI in the Extended rejected NSSAI IE
// (TS 24.501 Table 9.11.3.75.1, "Cause value", bits 4-1). The values 0..2 are
// identical to the Rejected NSSAI IE (RejectedCause* in rejected_nssai.go);
// the extended table adds 0b0011. All other values are reserved.
const (
	// ExtRejectedCauseMaxUEsReached — "S-NSSAI not available due to maximum
	// number of UEs reached" (0b0011). Only valid in the extended IE.
	ExtRejectedCauseMaxUEsReached uint8 = 0x03
)

// Type of list values (TS 24.501 Table 9.11.3.75.1, octet 3 bits 7-5).
const (
	extRejListNoTimer uint8 = 0 // 000: list without back-off timer
	extRejListTimer   uint8 = 1 // 001: list with one back-off timer for all entries
	extRejMaxElements       = 8 // NOTE 0 / number of elements 1..8
	extRejMinIELen          = 5 // §9.11.3.75: IE minimum length (incl. IEI and length octets)
	extRejMaxIELen          = 90
	extRejIEOverhead        = 2 // IEI + length octet
)

// ExtendedRejectedSNSSAI is one rejected S-NSSAI of the Extended rejected NSSAI
// IE (Figure 9.11.3.75.4).
type ExtendedRejectedSNSSAI struct {
	// Cause is the 4-bit cause value (RejectedCause*, ExtRejectedCause*).
	Cause uint8
	// SNSSAI is the rejected S-NSSAI; SD == SDNotPresent means the SST has no
	// SD ("no SD value associated with the SST", 0xFFFFFF on the wire when a
	// mapped S-NSSAI follows).
	SNSSAI SNSSAI
	// Mapped is the optional mapped HPLMN S-NSSAI (octets x+5..x+8). It shall
	// not be present for cause NSSAA failed/revoked (Table 9.11.3.75.1 NOTE 5/6).
	Mapped *SNSSAI
}

// PartialExtendedRejectedNSSAIList is one partial extended rejected NSSAI list
// (Figures 9.11.3.75.2 and .3).
type PartialExtendedRejectedNSSAIList struct {
	// BackoffTimer, when non-nil, selects type of list = 001 and carries the
	// back-off timer value (GPRS timer 3 value part, TS 24.008 §10.5.7.4a) that
	// applies to every entry. Per NOTE 7 it is only valid with cause
	// ExtRejectedCauseMaxUEsReached. nil = type of list 000.
	BackoffTimer *uint8
	// Elements holds 1..8 rejected S-NSSAIs.
	Elements []ExtendedRejectedSNSSAI
}

// ExtendedRejectedNSSAI is the value part of the Extended rejected NSSAI IE.
type ExtendedRejectedNSSAI struct {
	Lists []PartialExtendedRejectedNSSAIList
}

// ExtendedRejectedNSSAIFromList builds a single type-000 partial list from
// Rejected NSSAI style entries (no mapped S-NSSAI, no back-off timer). Returns
// nil for an empty input.
func ExtendedRejectedNSSAIFromList(list []RejectedSNSSAI) *ExtendedRejectedNSSAI {
	if len(list) == 0 {
		return nil
	}
	els := make([]ExtendedRejectedSNSSAI, len(list))
	for i, r := range list {
		els[i] = ExtendedRejectedSNSSAI{Cause: r.Cause, SNSSAI: r.SNSSAI}
	}
	return &ExtendedRejectedNSSAI{Lists: []PartialExtendedRejectedNSSAIList{{Elements: els}}}
}

// EncodeExtendedRejectedNSSAI encodes the value part (octets 3..v, no IEI/length).
// A nil or empty value yields nil (IE absent). Errors: more than 8 S-NSSAIs in
// total, empty list, cause > 4 bits, back-off timer list with a cause other than
// "maximum number of UEs reached", mapped S-NSSAI with the NSSAA cause, or a
// resulting IE longer than 90 octets.
func EncodeExtendedRejectedNSSAI(e *ExtendedRejectedNSSAI) ([]byte, error) {
	if e == nil || len(e.Lists) == 0 {
		return nil, nil
	}
	var out []byte
	total := 0
	for li, l := range e.Lists {
		n := len(l.Elements)
		if n < 1 || n > extRejMaxElements {
			return nil, fmt.Errorf("nas: extended rejected NSSAI: list %d has %d elements (1..%d)", li, n, extRejMaxElements)
		}
		total += n
		if total > extRejMaxElements {
			return nil, fmt.Errorf("nas: extended rejected NSSAI: more than %d rejected S-NSSAIs", extRejMaxElements)
		}
		typ := extRejListNoTimer
		if l.BackoffTimer != nil {
			typ = extRejListTimer
		}
		out = append(out, typ<<4|byte(n-1))
		if l.BackoffTimer != nil {
			out = append(out, *l.BackoffTimer)
		}
		for ei, el := range l.Elements {
			if el.Cause > 0x0F {
				return nil, fmt.Errorf("nas: extended rejected NSSAI[%d][%d]: cause %#x exceeds 4 bits", li, ei, el.Cause)
			}
			if l.BackoffTimer != nil && el.Cause != ExtRejectedCauseMaxUEsReached {
				return nil, fmt.Errorf("nas: extended rejected NSSAI[%d][%d]: back-off timer list requires cause %#x", li, ei, ExtRejectedCauseMaxUEsReached)
			}
			if el.Mapped != nil && el.Cause == RejectedCauseNSSAAFailedOrRevoked {
				return nil, fmt.Errorf("nas: extended rejected NSSAI[%d][%d]: mapped S-NSSAI not allowed for NSSAA cause", li, ei)
			}
			body, err := encodeExtRejSNSSAI(el)
			if err != nil {
				return nil, fmt.Errorf("nas: extended rejected NSSAI[%d][%d]: %w", li, ei, err)
			}
			out = append(out, byte(len(body))<<4|el.Cause)
			out = append(out, body...)
		}
	}
	if len(out)+extRejIEOverhead > extRejMaxIELen || len(out)+extRejIEOverhead < extRejMinIELen {
		return nil, fmt.Errorf("nas: extended rejected NSSAI: IE length %d outside %d..%d", len(out)+extRejIEOverhead, extRejMinIELen, extRejMaxIELen)
	}
	return out, nil
}

// encodeExtRejSNSSAI returns SST, [SD], [mapped SST, [mapped SD]] octets.
func encodeExtRejSNSSAI(el ExtendedRejectedSNSSAI) ([]byte, error) {
	if el.SNSSAI.SD > 0xFFFFFF {
		return nil, fmt.Errorf("SD %#x exceeds 24 bits", el.SNSSAI.SD)
	}
	b := []byte{el.SNSSAI.SST}
	if el.SNSSAI.SD != SDNotPresent || el.Mapped != nil {
		// With a mapped S-NSSAI the SD octets are always present (NOTE 3).
		b = append(b, byte(el.SNSSAI.SD>>16&0xFF), byte(el.SNSSAI.SD>>8&0xFF), byte(el.SNSSAI.SD&0xFF))
	}
	if m := el.Mapped; m != nil {
		if m.SD > 0xFFFFFF {
			return nil, fmt.Errorf("mapped SD %#x exceeds 24 bits", m.SD)
		}
		b = append(b, m.SST)
		if m.SD != SDNotPresent {
			b = append(b, byte(m.SD>>16&0xFF), byte(m.SD>>8&0xFF), byte(m.SD&0xFF))
		}
	}
	return b, nil
}

// DecodeExtendedRejectedNSSAI parses the value part of the Extended rejected
// NSSAI IE. Reserved type of list, a truncated list/element, or an element
// length other than 1, 4, 5 or 8 are errors. A number-of-elements field above 7
// is read as 8 (Table 9.11.3.75.1). Spare bits are ignored.
func DecodeExtendedRejectedNSSAI(b []byte) (*ExtendedRejectedNSSAI, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("nas: extended rejected NSSAI: empty value")
	}
	e := &ExtendedRejectedNSSAI{}
	for i := 0; i < len(b); {
		hdr := b[i]
		i++
		typ := (hdr >> 4) & 0x07
		n := int(hdr&0x0F) + 1
		if n > extRejMaxElements {
			n = extRejMaxElements
		}
		var l PartialExtendedRejectedNSSAIList
		switch typ {
		case extRejListNoTimer:
		case extRejListTimer:
			if i >= len(b) {
				return nil, fmt.Errorf("nas: extended rejected NSSAI: truncated back-off timer")
			}
			t := b[i]
			l.BackoffTimer = &t
			i++
		default:
			return nil, fmt.Errorf("nas: extended rejected NSSAI: reserved type of list %d", typ)
		}
		for k := 0; k < n; k++ {
			if i >= len(b) {
				return nil, fmt.Errorf("nas: extended rejected NSSAI: truncated list (element %d of %d)", k+1, n)
			}
			ln := int(b[i] >> 4)
			cause := b[i] & 0x0F
			i++
			if ln != 1 && ln != 4 && ln != 5 && ln != 8 {
				return nil, fmt.Errorf("nas: extended rejected NSSAI: invalid length of rejected S-NSSAI %d", ln)
			}
			if i+ln > len(b) {
				return nil, fmt.Errorf("nas: extended rejected NSSAI: truncated element")
			}
			v := b[i : i+ln]
			i += ln
			el := ExtendedRejectedSNSSAI{Cause: cause, SNSSAI: SNSSAI{SST: v[0], SD: SDNotPresent}}
			if ln >= 4 {
				el.SNSSAI.SD = uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
			}
			if ln >= 5 {
				m := SNSSAI{SST: v[4], SD: SDNotPresent}
				if ln == 8 {
					m.SD = uint32(v[5])<<16 | uint32(v[6])<<8 | uint32(v[7]) //nolint:gosec // G602: ln == 8 checked above
				}
				el.Mapped = &m
			}
			l.Elements = append(l.Elements, el)
		}
		e.Lists = append(e.Lists, l)
	}
	return e, nil
}

// encodeExtendedRejectedNSSAITLV returns IEI 0x68 + length + value, or nil when
// the IE is absent.
func encodeExtendedRejectedNSSAITLV(e *ExtendedRejectedNSSAI) ([]byte, error) {
	v, err := EncodeExtendedRejectedNSSAI(e)
	if err != nil || len(v) == 0 {
		return nil, err
	}
	return append([]byte{IEIExtendedRejectedNSSAI, byte(len(v))}, v...), nil
}

// ERNSSAISupported reports whether the 5GMM capability value octets (without
// IEI/length) have the ER-NSSAI bit set: octet 5, bit 5 (TS 24.501
// §9.11.3.1, Table 9.11.3.1.1). Octet 5 is optional; a shorter IE means "not
// supported".
func ERNSSAISupported(fiveGMMCapability []byte) bool {
	c, err := Decode5GMMCapability(fiveGMMCapability)
	return err == nil && c.ERNSSAI
}

// ERNSSAISupported reports whether the UE set the ER-NSSAI bit in the 5GMM
// capability IE of this REGISTRATION REQUEST (TS 24.501 §5.5.1.2.4).
func (r *RegistrationRequest) ERNSSAISupported() bool {
	return r != nil && ERNSSAISupported(r.FiveGMMCapability)
}
