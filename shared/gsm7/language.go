package gsm7

// language.go — Cell Broadcast language selection (TS 23.038 §5). A CBS /
// Write-Replace Warning message conveys its language in one of two ways:
//
//   (a) directly in the Data Coding Scheme byte, via the GSM 7-bit language
//       coding groups — group 0000 → DCS 0x00-0x0F (German … Polish,
//       0x0F = unspecified), group 0010 → DCS 0x20-0x24 (Czech, Hebrew,
//       Arabic, Russian, Icelandic). No message-content change; the receiving
//       entity reads the language straight off the DCS.
//
//   (b) as a two-character ISO 639 language-indication prefix inside the
//       message content — DCS 0x10 (GSM 7-bit) or 0x11 (UCS2). Used when the
//       language isn't one of the coding-group set, or when the script needs
//       UCS2 (CJK, etc.). Only the UCS2 prefix (0x11) is implemented here;
//       that's the one that unlocks language tagging for non-Latin alerts.

// cbsCodingGroupLanguages maps a GSM 7-bit language-coding-group DCS byte
// (TS 23.038 §5 groups 0000 and 0010) to its language name. Exactly the
// languages the spec assigns a dedicated DCS codepoint.
var cbsCodingGroupLanguages = map[byte]string{
	0x00: "German", 0x01: "English", 0x02: "Italian", 0x03: "French",
	0x04: "Spanish", 0x05: "Dutch", 0x06: "Swedish", 0x07: "Danish",
	0x08: "Portuguese", 0x09: "Finnish", 0x0A: "Norwegian", 0x0B: "Greek",
	0x0C: "Turkish", 0x0D: "Hungarian", 0x0E: "Polish", 0x0F: "Unspecified",
	0x20: "Czech", 0x21: "Hebrew", 0x22: "Arabic", 0x23: "Russian", 0x24: "Icelandic",
}

// LanguageNameFromCBSDCS returns the human-readable language a CBS Data Coding
// Scheme byte selects via the GSM 7-bit language coding groups (TS 23.038 §5),
// or "" if the DCS does not encode a language that way (general data coding
// 01xx, UCS2 0x48, 8-bit 0xF4 — for those the language, if present at all, is
// carried in a language-indication prefix, not the DCS byte). Intended for log
// lines and UI, not wire encoding.
func LanguageNameFromCBSDCS(dcs byte) string {
	return cbsCodingGroupLanguages[dcs]
}

// EncodeUCS2LanguagePrefix returns the 2-octet language-indication prefix for a
// UCS2 CBS message (DCS 0x11, TS 23.038 §5): the two ISO 639 characters
// GSM 7-bit septet-packed (14 bits) padded to the octet boundary with two zero
// bits. iso639 shorter than two characters is space-padded; longer is
// truncated to the first two. PackSeptets of two septets is always exactly two
// octets, with the upper two bits of the second octet zero — matching the
// spec's "padded to the octet boundary with two bits set to 0".
func EncodeUCS2LanguagePrefix(iso639 string) []byte {
	code := iso639
	for len(code) < 2 {
		code += " "
	}
	return PackSeptets(EncodeText(code[:2]))
}

// DecodeUCS2LanguagePrefix reverses EncodeUCS2LanguagePrefix, returning the
// two-character ISO 639 code from the leading two octets of a UCS2 (DCS 0x11)
// CBS page. Returns "" if there are fewer than two octets.
func DecodeUCS2LanguagePrefix(prefix []byte) string {
	if len(prefix) < 2 {
		return ""
	}
	return DecodeSeptets(UnpackSeptets(prefix[:2], 2))
}
