package gsm7

import "testing"

// TestPackUnpackSeptets verifies the septet packing algorithm against the
// worked examples in TS 23.038 §6.1.2.2.1 ("two characters in two octets",
// "eight characters in seven octets").
func TestPackUnpackSeptets(t *testing.T) {
	// "two characters in two octets": char1=0x41('A'), char2=0x01.
	// octet0 = char1 | ((char2&1)<<7); octet1 = char2>>1.
	got := PackSeptets([]byte{0x41, 0x01})
	want := []byte{0x41 | (1 << 7), 0x01 >> 1}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("PackSeptets(2 chars) = %x, want %x", got, want)
	}
	back := UnpackSeptets(got, 2)
	if back[0] != 0x41 || back[1] != 0x01 {
		t.Fatalf("UnpackSeptets round-trip = %x, want [41 01]", back)
	}

	// "eight characters in seven octets": all-1111111 (0x7F) septets should
	// pack into 7 fully-used octets (0 padding bits), the corner case that
	// motivates SeptetCountForOctets(7) == 8, not 7.
	eight := []byte{0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F}
	packed := PackSeptets(eight)
	if len(packed) != 7 {
		t.Fatalf("PackSeptets(8 septets) len = %d, want 7", len(packed))
	}
	if SeptetCountForOctets(7) != 8 {
		t.Fatalf("SeptetCountForOctets(7) = %d, want 8", SeptetCountForOctets(7))
	}
	back8 := UnpackSeptets(packed, 8)
	for i, s := range back8 {
		if s != 0x7F {
			t.Errorf("UnpackSeptets(8 septets)[%d] = %#02x, want 0x7F", i, s)
		}
	}
}

// TestEncodeDecodeTextRoundTrip verifies basic-table and extension-table
// characters survive Encode->Pack->Unpack->Decode.
func TestEncodeDecodeTextRoundTrip(t *testing.T) {
	cases := []string{
		"Hello",
		"Tsunami warning: move to higher ground",
		"Emergency alert: this is a test of the Public Warning System.",
		"€100 [test] {ok} ~end~", // extension-table characters
		"Ä Ö Ü ä ö ü à ñ",        // basic-table accented characters
	}
	for _, text := range cases {
		t.Run(text, func(t *testing.T) {
			septets := EncodeText(text)
			packed := PackSeptets(septets)
			unpacked := UnpackSeptets(packed, len(septets))
			got := DecodeSeptets(unpacked)
			if got != text {
				t.Errorf("round-trip: want %q, got %q", text, got)
			}
		})
	}
}

// TestEncodeTextUnmappableFallback verifies characters with no GSM7 mapping
// (e.g. emoji) fall back to '?' rather than corrupting septet alignment.
func TestEncodeTextUnmappableFallback(t *testing.T) {
	septets := EncodeText("A🚨B")
	if len(septets) != 3 {
		t.Fatalf("EncodeText(\"A🚨B\") septet count = %d, want 3 (A, ?, B)", len(septets))
	}
	if septets[0] != 'A' || septets[1] != '?' || septets[2] != 'B' {
		t.Errorf("EncodeText(\"A🚨B\") = %v, want [A ? B]", septets)
	}
}

// TestLanguageNameFromCBSDCS verifies the GSM7 language coding groups
// (TS 23.038 §5, groups 0000 and 0010) map to the right language names, and
// that non-language DCS values return "".
func TestLanguageNameFromCBSDCS(t *testing.T) {
	cases := []struct {
		dcs  byte
		want string
	}{
		{0x00, "German"},
		{0x01, "English"},
		{0x04, "Spanish"},
		{0x0E, "Polish"},
		{0x0F, "Unspecified"},
		{0x20, "Czech"},
		{0x22, "Arabic"},
		{0x24, "Icelandic"},
		{0x48, ""}, // UCS2 general data coding — language not in the DCS
		{0xF4, ""}, // 8-bit data — no language
		{0x11, ""}, // UCS2 + language prefix — language is in the content, not the DCS
	}
	for _, tc := range cases {
		if got := LanguageNameFromCBSDCS(tc.dcs); got != tc.want {
			t.Errorf("LanguageNameFromCBSDCS(%#02x) = %q, want %q", tc.dcs, got, tc.want)
		}
	}
}

// TestUCS2LanguagePrefixRoundTrip verifies the DCS 0x11 language-indication
// prefix (TS 23.038 §5) is exactly 2 octets and round-trips the ISO 639 code.
func TestUCS2LanguagePrefixRoundTrip(t *testing.T) {
	for _, iso := range []string{"en", "de", "ja", "ar", "ru"} {
		prefix := EncodeUCS2LanguagePrefix(iso)
		if len(prefix) != 2 {
			t.Fatalf("EncodeUCS2LanguagePrefix(%q) len = %d, want 2", iso, len(prefix))
		}
		// Upper two bits of the second octet must be the zero padding.
		if prefix[1]&0xC0 != 0 {
			t.Errorf("EncodeUCS2LanguagePrefix(%q): second octet %#02x has non-zero pad bits", iso, prefix[1])
		}
		if got := DecodeUCS2LanguagePrefix(prefix); got != iso {
			t.Errorf("UCS2 language prefix round-trip: want %q, got %q", iso, got)
		}
	}
	// Short code is space-padded to 2 chars.
	if got := DecodeUCS2LanguagePrefix(EncodeUCS2LanguagePrefix("x")); got != "x " {
		t.Errorf("short code padding: want %q, got %q", "x ", got)
	}
}

// TestAlphabetFromCBSDCS verifies the CBS Data Coding Scheme coding-group
// table (TS 23.038 §5) against known-value spot checks for every group.
func TestAlphabetFromCBSDCS(t *testing.T) {
	cases := []struct {
		name string
		dcs  byte
		want Alphabet
	}{
		{"0x00 German (language group)", 0x00, AlphabetGSM7},
		{"0x0F unspecified language", 0x0F, AlphabetGSM7},
		{"0x10 GSM7 + lang-indication prefix", 0x10, AlphabetGSM7},
		{"0x11 UCS2 + lang-indication prefix", 0x11, AlphabetUCS2},
		{"0x20 Czech (0010 group)", 0x20, AlphabetGSM7},
		{"0x30 reserved-for-other-language", 0x30, AlphabetGSM7},
		{"0x40 general data coding, GSM7", 0x40, AlphabetGSM7},
		{"0x44 general data coding, 8-bit (bits3-2=01)", 0x44, Alphabet8Bit},
		{"0x48 general data coding, UCS2 (bits3-2=10)", 0x48, AlphabetUCS2},
		{"0x4C general data coding, reserved->GSM7", 0x4C, AlphabetGSM7},
		{"0x80 reserved coding group", 0x80, AlphabetGSM7},
		{"0x90 UDH structure, GSM7", 0x90, AlphabetGSM7},
		{"0x94 UDH structure, 8-bit", 0x94, Alphabet8Bit},
		{"0x98 UDH structure, UCS2", 0x98, AlphabetUCS2},
		{"0xF0 data coding/message class, GSM7", 0xF0, AlphabetGSM7},
		{"0xF4 data coding/message class, 8-bit", 0xF4, Alphabet8Bit},
		{"0xFC data coding/message class class3, 8-bit", 0xFC, Alphabet8Bit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AlphabetFromCBSDCS(tc.dcs); got != tc.want {
				t.Errorf("AlphabetFromCBSDCS(%#02x) = %v, want %v", tc.dcs, got, tc.want)
			}
		})
	}
}
