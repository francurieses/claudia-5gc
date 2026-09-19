package gsm7

// basicSeptetToRune is the GSM 7 bit default alphabet basic character set
// (TS 23.038 §6.2.1, Table). Index = septet value (b7 b6 b5 as the high 3
// bits / column, b4 b3 b2 b1 as the low 4 bits / row of the spec's table).
// Transcribed directly from the 3GPP TS 23.038 V9.1.1 clause 6.2.1 table.
var basicSeptetToRune = [128]rune{
	0x00: '@', 0x01: '£', 0x02: '$', 0x03: '¥', 0x04: 'è', 0x05: 'é', 0x06: 'ù', 0x07: 'ì',
	0x08: 'ò', 0x09: 'Ç', 0x0A: '\n', 0x0B: 'Ø', 0x0C: 'ø', 0x0D: '\r', 0x0E: 'Å', 0x0F: 'å',
	0x10: 'Δ', 0x11: '_', 0x12: 'Φ', 0x13: 'Γ', 0x14: 'Λ', 0x15: 'Ω', 0x16: 'Π', 0x17: 'Ψ',
	0x18: 'Σ', 0x19: 'Θ', 0x1A: 'Ξ', 0x1B: ' ' /* ESC, handled specially */, 0x1C: 'Æ', 0x1D: 'æ', 0x1E: 'ß', 0x1F: 'É',
	0x20: ' ', 0x21: '!', 0x22: '"', 0x23: '#', 0x24: '¤', 0x25: '%', 0x26: '&', 0x27: '\'',
	0x28: '(', 0x29: ')', 0x2A: '*', 0x2B: '+', 0x2C: ',', 0x2D: '-', 0x2E: '.', 0x2F: '/',
	0x30: '0', 0x31: '1', 0x32: '2', 0x33: '3', 0x34: '4', 0x35: '5', 0x36: '6', 0x37: '7',
	0x38: '8', 0x39: '9', 0x3A: ':', 0x3B: ';', 0x3C: '<', 0x3D: '=', 0x3E: '>', 0x3F: '?',
	0x40: '¡', 0x41: 'A', 0x42: 'B', 0x43: 'C', 0x44: 'D', 0x45: 'E', 0x46: 'F', 0x47: 'G',
	0x48: 'H', 0x49: 'I', 0x4A: 'J', 0x4B: 'K', 0x4C: 'L', 0x4D: 'M', 0x4E: 'N', 0x4F: 'O',
	0x50: 'P', 0x51: 'Q', 0x52: 'R', 0x53: 'S', 0x54: 'T', 0x55: 'U', 0x56: 'V', 0x57: 'W',
	0x58: 'X', 0x59: 'Y', 0x5A: 'Z', 0x5B: 'Ä', 0x5C: 'Ö', 0x5D: 'Ñ', 0x5E: 'Ü', 0x5F: '§',
	0x60: '¿', 0x61: 'a', 0x62: 'b', 0x63: 'c', 0x64: 'd', 0x65: 'e', 0x66: 'f', 0x67: 'g',
	0x68: 'h', 0x69: 'i', 0x6A: 'j', 0x6B: 'k', 0x6C: 'l', 0x6D: 'm', 0x6E: 'n', 0x6F: 'o',
	0x70: 'p', 0x71: 'q', 0x72: 'r', 0x73: 's', 0x74: 't', 0x75: 'u', 0x76: 'v', 0x77: 'w',
	0x78: 'x', 0x79: 'y', 0x7A: 'z', 0x7B: 'ä', 0x7C: 'ö', 0x7D: 'ñ', 0x7E: 'ü', 0x7F: 'à',
}

// extSeptetToRune is the GSM 7 bit default alphabet extension table
// (TS 23.038 §6.2.1.1), reached via <ESC><septet>. Only the populated cells
// (of international significance — currency, brackets) map to a character;
// every other cell is reserved and falls back to a displayed space per
// NOTE 1. 0x0A (Page Break) and 0x1B (reserved for further extension) are
// intentionally not included — neither is a displayable character.
var extSeptetToRune = map[byte]rune{
	0x14: '^',
	0x28: '{',
	0x29: '}',
	0x2F: '\\',
	0x3C: '[',
	0x3D: '~',
	0x3E: ']',
	0x40: '|',
	0x65: '€',
}

// basicRuneToSeptet and extRuneToSeptet are the reverse maps, built once at
// init from the tables above.
var (
	basicRuneToSeptet = make(map[rune]byte, 128)
	extRuneToSeptet   = make(map[rune]byte, len(extSeptetToRune))
)

func init() {
	for septet, r := range basicSeptetToRune {
		if septet == 0x1B {
			continue // ESC is a control code, not a printable character to reverse-map
		}
		basicRuneToSeptet[r] = byte(septet)
	}
	for septet, r := range extSeptetToRune {
		extRuneToSeptet[r] = septet
	}
}
