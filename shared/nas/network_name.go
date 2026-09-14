package nas

import (
	"fmt"
	"unicode/utf16"
)

// ---- Network name IE (TS 24.501 §9.11.3.35 / §9.11.3.36) ----------------
//
// The "Full name for network" (IEI 0x43) and "Short name for network"
// (IEI 0x45) IEs of the CONFIGURATION UPDATE COMMAND carry the operator name
// a handset shows on its status bar. TS 24.501 §9.11.3.35 does not restate
// the layout; it points at the Network Name IE of TS 24.008 §10.5.3.5a.
//
// Layout (TLV, 1-byte length):
//
//	octet 1     IEI (0x43 or 0x45)
//	octet 2     length of the contents (octets 3..n)
//	octet 3     1 ext | 3 coding scheme | 1 Add CI | 3 spare bits in last octet
//	octet 4..n  the text, encoded per the coding scheme
//
// Two coding schemes are defined. 0b000 is the GSM 7-bit default alphabet
// packed into octets; 0b001 is UCS-2 big endian. EncodeNetworkName picks the
// first when every rune is in the GSM basic set (the common case, and the
// best-travelled path through handset modems) and falls back to UCS-2 when it
// is not, which is the only way to carry accents or non-Latin scripts.
//
// Ref: TS 24.501 §9.11.3.35, §9.11.3.36; TS 24.008 §10.5.3.5a

// NetworkNameCodingGSM7 is coding scheme 0b000: cell broadcast data coding
// scheme, GSM default alphabet, language unspecified. Ref: TS 24.008 §10.5.3.5a
const NetworkNameCodingGSM7 byte = 0x00

// NetworkNameCodingUCS2 is coding scheme 0b001: UCS-2, big endian.
// Ref: TS 24.008 §10.5.3.5a
const NetworkNameCodingUCS2 byte = 0x01

// NetworkName is a decoded Network Name IE.
type NetworkName struct {
	// CodingScheme is NetworkNameCodingGSM7 or NetworkNameCodingUCS2.
	CodingScheme byte
	// AddCI is the "add country initials" bit. The UE prefixes the country
	// initials of the PLMN to the name when set. Left false here: on test PLMN
	// 001/01 there are no meaningful country initials to add.
	AddCI bool
	// Text is the decoded name.
	Text string
}

// gsm7BasicSet maps a rune to its GSM 7-bit default alphabet septet value.
// Only the basic set is covered: a rune needing the extension table (|, ^, {,
// }, [, ], ~, \, and the euro sign) is treated as unencodable so the caller
// falls back to UCS-2 rather than emitting a two-septet escape sequence.
// Ref: TS 23.038 §6.2.1 Table 6.2.1.1
var gsm7BasicSet = map[rune]byte{
	'@': 0x00, '£': 0x01, '$': 0x02, '¥': 0x03, 'è': 0x04, 'é': 0x05,
	'ù': 0x06, 'ì': 0x07, 'ò': 0x08, 'Ç': 0x09, '\n': 0x0A, 'Ø': 0x0B,
	'ø': 0x0C, '\r': 0x0D, 'Å': 0x0E, 'å': 0x0F,
	'Δ': 0x10, '_': 0x11, 'Φ': 0x12, 'Γ': 0x13, 'Λ': 0x14, 'Ω': 0x15,
	'Π': 0x16, 'Ψ': 0x17, 'Σ': 0x18, 'Θ': 0x19, 'Ξ': 0x1A,
	'Æ': 0x1C, 'æ': 0x1D, 'ß': 0x1E, 'É': 0x1F,
	' ': 0x20, '!': 0x21, '"': 0x22, '#': 0x23, '¤': 0x24, '%': 0x25,
	'&': 0x26, '\'': 0x27, '(': 0x28, ')': 0x29, '*': 0x2A, '+': 0x2B,
	',': 0x2C, '-': 0x2D, '.': 0x2E, '/': 0x2F,
	'0': 0x30, '1': 0x31, '2': 0x32, '3': 0x33, '4': 0x34, '5': 0x35,
	'6': 0x36, '7': 0x37, '8': 0x38, '9': 0x39, ':': 0x3A, ';': 0x3B,
	'<': 0x3C, '=': 0x3D, '>': 0x3E, '?': 0x3F,
	'¡': 0x40, 'A': 0x41, 'B': 0x42, 'C': 0x43, 'D': 0x44, 'E': 0x45,
	'F': 0x46, 'G': 0x47, 'H': 0x48, 'I': 0x49, 'J': 0x4A, 'K': 0x4B,
	'L': 0x4C, 'M': 0x4D, 'N': 0x4E, 'O': 0x4F,
	'P': 0x50, 'Q': 0x51, 'R': 0x52, 'S': 0x53, 'T': 0x54, 'U': 0x55,
	'V': 0x56, 'W': 0x57, 'X': 0x58, 'Y': 0x59, 'Z': 0x5A, 'Ä': 0x5B,
	'Ö': 0x5C, 'Ñ': 0x5D, 'Ü': 0x5E, '§': 0x5F,
	'¿': 0x60, 'a': 0x61, 'b': 0x62, 'c': 0x63, 'd': 0x64, 'e': 0x65,
	'f': 0x66, 'g': 0x67, 'h': 0x68, 'i': 0x69, 'j': 0x6A, 'k': 0x6B,
	'l': 0x6C, 'm': 0x6D, 'n': 0x6E, 'o': 0x6F,
	'p': 0x70, 'q': 0x71, 'r': 0x72, 's': 0x73, 't': 0x74, 'u': 0x75,
	'v': 0x76, 'w': 0x77, 'x': 0x78, 'y': 0x79, 'z': 0x7A, 'ä': 0x7B,
	'ö': 0x7C, 'ñ': 0x7D, 'ü': 0x7E, 'à': 0x7F,
}

// gsm7Reverse is the inverse of gsm7BasicSet, built once at init.
var gsm7Reverse = func() map[byte]rune {
	m := make(map[byte]rune, len(gsm7BasicSet))
	for r, v := range gsm7BasicSet {
		m[v] = r
	}
	return m
}()

// packGSM7 packs septets into octets, least significant bit first, and returns
// the packed bytes plus the number of unused bits in the final octet.
// Ref: TS 23.038 §6.1.2.1.1
func packGSM7(septets []byte) (packed []byte, spareBits byte) {
	bitLen := len(septets) * 7
	octetLen := (bitLen + 7) / 8
	packed = make([]byte, octetLen)
	for i, s := range septets {
		bitPos := i * 7
		octet := bitPos / 8
		shift := bitPos % 8
		packed[octet] |= byte(s<<shift) & 0xFF
		// A septet straddling an octet boundary spills its high bits into the
		// next octet.
		if shift > 1 {
			packed[octet+1] |= s >> (8 - shift)
		}
	}
	return packed, byte(octetLen*8 - bitLen)
}

// unpackGSM7 reverses packGSM7. spareBits says how many bits of the last octet
// are padding and are therefore not part of a septet.
func unpackGSM7(packed []byte, spareBits byte) []byte {
	if len(packed) == 0 {
		return nil
	}
	total := (len(packed)*8 - int(spareBits)) / 7
	septets := make([]byte, 0, total)
	for i := 0; i < total; i++ {
		bitPos := i * 7
		octet := bitPos / 8
		shift := bitPos % 8
		v := packed[octet] >> shift
		if shift > 1 && octet+1 < len(packed) {
			v |= packed[octet+1] << (8 - shift)
		}
		septets = append(septets, v&0x7F)
	}
	return septets
}

// gsm7Septets converts text to GSM 7-bit septets. ok is false when any rune is
// outside the basic set, in which case the caller must use UCS-2.
func gsm7Septets(text string) (septets []byte, ok bool) {
	septets = make([]byte, 0, len(text))
	for _, r := range text {
		v, found := gsm7BasicSet[r]
		if !found {
			return nil, false
		}
		septets = append(septets, v)
	}
	return septets, true
}

// EncodeNetworkName serialises one Network Name IE, including its IEI and
// length byte. iei is 0x43 for the full name or 0x45 for the short name.
//
// The coding scheme is chosen automatically: GSM 7-bit packed when every rune
// is in the basic set, UCS-2 big endian otherwise.
//
// Ref: TS 24.008 §10.5.3.5a; TS 24.501 §9.11.3.35, §9.11.3.36
func EncodeNetworkName(iei byte, text string) ([]byte, error) {
	if text == "" {
		return nil, fmt.Errorf("nas: empty network name")
	}

	var coding, spareBits byte
	var body []byte

	if septets, ok := gsm7Septets(text); ok {
		coding = NetworkNameCodingGSM7
		body, spareBits = packGSM7(septets)
	} else {
		coding = NetworkNameCodingUCS2
		for _, u := range utf16.Encode([]rune(text)) {
			body = append(body, byte(u>>8), byte(u))
		}
		spareBits = 0
	}

	// octet 3 + the text must fit the single length byte.
	if len(body)+1 > 255 {
		return nil, fmt.Errorf("nas: network name too long: %d octets", len(body)+1)
	}

	// octet 3: ext=1 | coding scheme (3 bits) | Add CI=0 | spare bits (3 bits)
	header := byte(0x80) | ((coding & 0x07) << 4) | (spareBits & 0x07)

	out := make([]byte, 0, len(body)+3)
	out = append(out, iei, byte(len(body)+1), header)
	out = append(out, body...)
	return out, nil
}

// DecodeNetworkName parses the contents of a Network Name IE, i.e. the bytes
// after the IEI and the length byte (octet 3 onwards).
// Ref: TS 24.008 §10.5.3.5a
func DecodeNetworkName(b []byte) (*NetworkName, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("nas: network name too short")
	}
	header := b[0]
	n := &NetworkName{
		CodingScheme: (header >> 4) & 0x07,
		AddCI:        header&0x08 != 0,
	}
	spareBits := header & 0x07
	body := b[1:]

	switch n.CodingScheme {
	case NetworkNameCodingUCS2:
		if len(body)%2 != 0 {
			return nil, fmt.Errorf("nas: UCS-2 network name has odd length %d", len(body))
		}
		units := make([]uint16, 0, len(body)/2)
		for i := 0; i+1 < len(body); i += 2 {
			units = append(units, uint16(body[i])<<8|uint16(body[i+1]))
		}
		n.Text = string(utf16.Decode(units))
	case NetworkNameCodingGSM7:
		runes := make([]rune, 0, len(body)*8/7)
		for _, s := range unpackGSM7(body, spareBits) {
			r, ok := gsm7Reverse[s]
			if !ok {
				return nil, fmt.Errorf("nas: septet 0x%02X is not in the GSM basic set", s)
			}
			runes = append(runes, r)
		}
		n.Text = string(runes)
	default:
		return nil, fmt.Errorf("nas: unsupported network name coding scheme %d", n.CodingScheme)
	}
	return n, nil
}
