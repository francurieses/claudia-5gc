// Package gsm7 implements the GSM 7-bit default alphabet character table and
// septet packing algorithm (3GPP TS 23.038 §6.1.2.2, §6.2.1), plus the CBS
// (Cell Broadcast) Data Coding Scheme alphabet determination (TS 23.038 §5).
// Used by the AMF's Public Warning System (NGAP Write-Replace Warning,
// TS 38.413 §8.9.1) to encode WarningMessageContents per the DCS the CBC
// (management portal) selects, instead of sending unpacked raw octets that a
// GSM7-declaring DCS would make Wireshark misdecode.
package gsm7

// Alphabet identifies which TS 23.038 §5 character set a CBS Data Coding
// Scheme octet selects.
type Alphabet int

const (
	// AlphabetGSM7 is the GSM 7 bit default alphabet (TS 23.038 §6.2.1),
	// septet-packed. Also the fallback for every reserved/unassigned CBS DCS
	// coding group, per the explicit instruction in TS 23.038 §5: "Any
	// reserved codings shall be assumed to be the GSM 7 bit default alphabet".
	AlphabetGSM7 Alphabet = iota
	// Alphabet8Bit is user-defined 8-bit data — raw octets, no packing.
	Alphabet8Bit
	// AlphabetUCS2 is UCS2 (16-bit) text, 2 bytes per character, big-endian.
	AlphabetUCS2
)

// ESC is the escape-to-extension-table character (TS 23.038 §6.2.1 NOTE 1).
const ESC byte = 0x1B

// AlphabetFromCBSDCS returns the character set selected by a CBS Data Coding
// Scheme octet, implementing the coding-group table of TS 23.038 §5 ("CBS
// Data Coding Scheme"). Note this table differs from the SMS DCS table in
// TS 23.038 §4: for CBS, coding groups 0000-0011 are the language-indication
// groups (not "General Data Coding"), and "General Data Coding" is instead
// group 01xx.
//
// Language sub-selection (the specific language a 0000-0011 group or a
// language-indication-prefix implies) is not modelled — only the resulting
// alphabet is; this mirrors how a receiving entity displays the text
// regardless of which language table entry produced it. The optional
// "message preceded by language indication" text framing (first 2-3
// characters carry an ISO 639 language code) is a documented limitation:
// callers get the alphabet right, but do not prepend/strip that framing.
func AlphabetFromCBSDCS(dcs byte) Alphabet {
	group := dcs >> 4
	switch group {
	case 0x0, 0x2, 0x3:
		// 0000: language using GSM7 (bits3-0 = language code, incl. 1111 =
		// unspecified). 0010/0011: specific-language / reserved-for-other-
		// language groups, all GSM7 per TS 23.038 §5 Table 5.
		return AlphabetGSM7
	case 0x1:
		// 0001 0000 = GSM7 + language-indication prefix; 0001 0001..1111 =
		// UCS2 + language-indication prefix.
		if dcs&0x0F == 0 {
			return AlphabetGSM7
		}
		return AlphabetUCS2
	case 0x4, 0x5, 0x6, 0x7:
		// 01xx: General Data Coding indication. Bits3-2 select the alphabet;
		// bits5-4 (compression / message-class-flag) don't affect it.
		switch (dcs >> 2) & 0x03 {
		case 0b00:
			return AlphabetGSM7
		case 0b01:
			return Alphabet8Bit
		case 0b10:
			return AlphabetUCS2
		default: // 0b11 reserved
			return AlphabetGSM7
		}
	case 0x9:
		// 1001: Message with User Data Header structure. Bits3-2 select the
		// alphabet the same way as the general group; the UDH framing itself
		// (TS 23.040 §9.2.3.24) is not implemented — a documented limitation.
		switch (dcs >> 2) & 0x03 {
		case 0b01:
			return Alphabet8Bit
		case 0b10:
			return AlphabetUCS2
		default:
			return AlphabetGSM7
		}
	case 0xF:
		// 1111: Data coding/message class. Bit2: 0=GSM7, 1=8-bit (no UCS2 in
		// this group).
		if dcs&0x04 != 0 {
			return Alphabet8Bit
		}
		return AlphabetGSM7
	default:
		// 1000, 1010-1110: reserved coding groups → GSM7 per the blanket
		// reserved-codings rule.
		return AlphabetGSM7
	}
}

// EncodeText maps a UTF-8 string to GSM 7-bit default alphabet septets
// (TS 23.038 §6.2.1 basic table + §6.2.1.1 extension table via ESC). A
// character with no mapping is encoded as '?' (0x3F) rather than dropped, so
// the septet count callers plan pagination around stays predictable.
func EncodeText(text string) []byte {
	septets := make([]byte, 0, len(text))
	for _, r := range text {
		if v, ok := basicRuneToSeptet[r]; ok {
			septets = append(septets, v)
			continue
		}
		if v, ok := extRuneToSeptet[r]; ok {
			septets = append(septets, ESC, v)
			continue
		}
		septets = append(septets, '?')
	}
	return septets
}

// DecodeSeptets reverses EncodeText: unpacked septet values back to a UTF-8
// string. An ESC (0x1B) not followed by a mapped extension-table septet is
// displayed as a space, per TS 23.038 §6.2.1 NOTE 1.
func DecodeSeptets(septets []byte) string {
	out := make([]rune, 0, len(septets))
	for i := 0; i < len(septets); i++ {
		s := septets[i] & 0x7F
		if s == ESC {
			if i+1 < len(septets) {
				i++
				if r, ok := extSeptetToRune[septets[i]&0x7F]; ok {
					out = append(out, r)
					continue
				}
			}
			out = append(out, ' ')
			continue
		}
		out = append(out, basicSeptetToRune[s])
	}
	return string(out)
}

// PackSeptets packs 7-bit values (only the low 7 bits of each byte are used)
// into 8-bit octets, LSB-first, per TS 23.038 §6.1.2.2.1 ("CBS Packing" — the
// same bit-packing algorithm as SMS §6.1.2.1.1, verified bit-for-bit against
// the spec's own "two characters in two octets" / "eight characters in seven
// octets" worked examples). Unused bits in the final octet are zero.
func PackSeptets(septets []byte) []byte {
	n := len(septets)
	packed := make([]byte, (n*7+7)/8)
	for i, s := range septets {
		s &= 0x7F
		bitPos := i * 7
		bytePos := bitPos / 8
		bitOffset := uint(bitPos % 8)
		packed[bytePos] |= s << bitOffset
		if bitOffset > 1 && bytePos+1 < len(packed) {
			packed[bytePos+1] |= s >> (8 - bitOffset)
		}
	}
	return packed
}

// UnpackSeptets reverses PackSeptets, extracting exactly count septets.
//
// count must be supplied by the caller, not derived from len(packed): TS
// 23.041 §9.3.20 defines CBS-Message-Information-Length as an *octet* count,
// and octet-count -> septet-count is inherently ambiguous at 8-septet
// boundaries (7 septets and 8 septets both pack into 7 octets — the classic
// CBS/SMS 7-bit corner case). Real dissectors (Wireshark included) resolve it
// as floor(octetCount*8/7), which is exactly what callers decoding from a
// CBS-Message-Information-Length should pass as count; this is a property of
// the wire format, not a bug in this decoder.
func UnpackSeptets(packed []byte, count int) []byte {
	septets := make([]byte, count)
	for i := 0; i < count; i++ {
		bitPos := i * 7
		bytePos := bitPos / 8
		bitOffset := uint(bitPos % 8)
		var v byte
		if bytePos < len(packed) {
			v = packed[bytePos] >> bitOffset
		}
		if bitOffset > 1 && bytePos+1 < len(packed) {
			v |= packed[bytePos+1] << (8 - bitOffset)
		}
		septets[i] = v & 0x7F
	}
	return septets
}

// SeptetCountForOctets returns the septet count a receiving entity derives
// from an octet-based length field (see UnpackSeptets doc for why this is
// floor(n*8/7), not a simple inverse of PackSeptets' byte count).
func SeptetCountForOctets(octets int) int {
	return (octets * 8) / 7
}
