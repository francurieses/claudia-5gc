package types

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestSUCIRoundTrip(t *testing.T) {
	pa := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefaabbccdd"
	tests := []struct {
		name string
		in   string
		want SUCI
	}{
		{"null", "suci-0-001-01-0000-0-0-0000000001",
			SUCI{MCC: "001", MNC: "01", RoutingIndicator: "0000", SchemeOutput: "0000000001"}},
		{"null RI 0 3-digit MNC", "suci-0-310-260-0-0-0-1234567890",
			SUCI{MCC: "310", MNC: "260", RoutingIndicator: "0", SchemeOutput: "1234567890"}},
		{"profile A", "suci-0-001-01-0000-1-1-" + pa,
			SUCI{MCC: "001", MNC: "01", RoutingIndicator: "0000", ProtectionScheme: 1, HNPublicKeyID: 1, SchemeOutput: pa}},
		{"profile B key 255", "suci-0-001-001-12-2-255-" + pa,
			SUCI{MCC: "001", MNC: "001", RoutingIndicator: "12", ProtectionScheme: 2, HNPublicKeyID: 255, SchemeOutput: pa}},
		{"nai", "suci-1-example.com-0-0-0-user",
			SUCI{SUPIType: 1, HomeNetworkID: "example.com", RoutingIndicator: "0", SchemeOutput: "user"}},
	}
	re := regexp.MustCompile(`^` + SUCIPattern + `$`)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSUCI(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
			if s := got.String(); s != tc.in || !re.MatchString(s) {
				t.Fatalf("String() = %q, want %q (pattern match %v)", s, tc.in, re.MatchString(s))
			}
		})
	}
}

func TestSUCIReject(t *testing.T) {
	for _, in := range []string{
		"",
		"suci-00101-0000-0-0-0000000010",
		"suci-0-001-01-0000-1-0-aabb",
		"suci-0-001-01-0000-1-256-aabb",
		"suci-0-001-01-0000-1-1-abc",
		"suci-0-001-01-0000-0-3-0000000001",
		"suci-0-001-01-0000-0-0-00000x0001",
		"imsi-001010000000001",
	} {
		if _, err := ParseSUCI(in); err == nil {
			t.Errorf("ParseSUCI(%q) accepted", in)
		}
	}
}

// TestSUCIErrorsDoNotLeakInput: parse errors never embed the input and
// oversized input is refused before the regexps run.
func TestSUCIErrorsDoNotLeakInput(t *testing.T) {
	for _, in := range []string{
		"suci-0-001-01-0000-0-0-00000x0001",
		"suci-0-001-01-0000-1-1-abc",
		"suci-0-001-01-0000-1-0-aabbccdd",
		"suci-0-001-01-0000-0-3-0000000001",
		"suci-0-001-01-0000-1-1-" + strings.Repeat("ab", MaxSUCILen),
	} {
		_, err := ParseSUCI(in)
		if err == nil {
			t.Fatalf("accepted %.40q", in)
		}
		for _, frag := range []string{"00000x0001", "abc", "aabbccdd", "0000000001", "abab"} {
			if strings.Contains(err.Error(), frag) {
				t.Errorf("error %q leaks %q", err, frag)
			}
		}
	}
	if _, err := ParseSUCI("suci-0-001-01-0000-1-1-" + strings.Repeat("ab", MaxSUCILen)); err == nil ||
		!strings.Contains(err.Error(), "longer than") {
		t.Errorf("length cap error = %v", err)
	}
}

func TestSUCIHelpers(t *testing.T) {
	if !IsSUCI("suci-0-001-01-0-0-0-1") || IsSUCI("imsi-1") {
		t.Fatal("IsSUCI")
	}
	s, _ := ParseSUCI("suci-0-001-01-0000-0-0-0000000001")
	if got, err := s.SUPI(); err != nil || got != "imsi-001010000000001" {
		t.Fatalf("SUPI %q %v", got, err)
	}
	if _, err := s.SchemeOutputBytes(); err == nil {
		t.Fatal("null scheme bytes accepted")
	}
	p, _ := ParseSUCI("suci-0-001-01-0-1-1-aabb")
	if b, err := p.SchemeOutputBytes(); err != nil || len(b) != 2 || b[0] != 0xaa {
		t.Fatalf("bytes %x %v", b, err)
	}
	if _, err := p.SUPI(); err == nil {
		t.Fatal("SUPI for concealed accepted")
	}
	for _, tc := range []struct {
		in      []byte
		want    string
		wantErr bool
	}{
		{[]byte{0x01, 0x32}, "1023", false},
		{[]byte{0x01, 0xF2}, "102", false},
		{[]byte{0xA1}, "", true},
		{nil, "", true},
	} {
		got, err := NullSchemeMSIN(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("NullSchemeMSIN(%x)=%q,%v", tc.in, got, err)
		}
	}
}

func TestParseSUCIAny_LegacyEqualsStandard(t *testing.T) {
	pa := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefaabbccdd"
	tests := []struct {
		name, legacy, std string
		keyID             uint8
	}{
		{"null", "suci-00101-0000-0-0-0000000010", "suci-0-001-01-0000-0-0-0000000001", 0},
		{"null 3-digit MNC odd MSIN", "suci-310260-0-0-0-21436587f9", "suci-0-310-260-0-0-0-123456789", 0},
		{"profile A", "suci-00101-0000-0-1-" + pa, "suci-0-001-01-0000-1-1-" + pa, 1},
		{"profile B", "suci-00101-0000-0-2-" + strings.ToUpper(pa), "suci-0-001-01-0000-2-2-" + pa, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, f, err := ParseSUCIAny(tc.legacy)
			if err != nil || f != SUCIFormatLegacy {
				t.Fatalf("legacy: f=%v err=%v", f, err)
			}
			want, f2, err := ParseSUCIAny(tc.std)
			if err != nil || f2 != SUCIFormatStandard {
				t.Fatalf("standard: f=%v err=%v", f2, err)
			}
			want.HNPublicKeyID = 0 // legacy form does not carry it
			if got != want {
				t.Fatalf("legacy %+v != standard %+v", got, want)
			}
			if tc.keyID == 0 {
				a, _ := got.SUPI()
				b, _ := want.SUPI()
				if a != b || a == "" {
					t.Fatalf("SUPI %q vs %q", a, b)
				}
			}
		})
	}
}

// TestParseSUCIAny_LegacyGolden pins the literal strings produced by the
// v2.6.0-rel17-final AMF (registration.go / nas.go Sprintf).
func TestParseSUCIAny_LegacyGolden(t *testing.T) {
	prev := func(mcc, mnc, ri string, scheme int, out []byte) string {
		return fmt.Sprintf("suci-%s%s-%s-0-%d-%s", mcc, mnc, ri, scheme, hex.EncodeToString(out))
	}
	pa := bytes.Repeat([]byte{0xab, 0x12}, 20)
	tests := []struct {
		name, got, lit string
		msin, supi     string
		scheme         uint8
	}{
		{"null", prev("001", "01", "0000", 0, []byte{0x00, 0x00, 0x00, 0x00, 0x10}),
			"suci-00101-0000-0-0-0000000010", "0000000001", "imsi-001010000000001", 0},
		{"null 3-digit MNC", prev("310", "260", "0", 0, []byte{0x21, 0x43, 0x65, 0x87, 0xf9}),
			"suci-310260-0-0-0-21436587f9", "123456789", "imsi-310260123456789", 0},
		{"profile A", prev("001", "01", "0000", 1, pa),
			"suci-00101-0000-0-1-" + strings.Repeat("ab12", 20), "", "", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.lit {
				t.Fatalf("prev-tag string %q != literal %q", tc.got, tc.lit)
			}
			s, f, err := ParseSUCIAny(tc.lit)
			if err != nil || f != SUCIFormatLegacy || s.ProtectionScheme != tc.scheme {
				t.Fatalf("s=%+v f=%v err=%v", s, f, err)
			}
			if tc.scheme == 0 {
				if s.SchemeOutput != tc.msin {
					t.Fatalf("msin %q want %q", s.SchemeOutput, tc.msin)
				}
				if supi, _ := s.SUPI(); supi != tc.supi {
					t.Fatalf("supi %q want %q", supi, tc.supi)
				}
			} else if s.SchemeOutput != strings.Repeat("ab12", 20) || s.HNPublicKeyID != 0 {
				t.Fatalf("output/keyid wrong: %+v", s)
			}
		})
	}
}

func TestParseSUCIAny_Malformed(t *testing.T) {
	tests := map[string]string{
		"field count":     "suci-00101-0000-0-0",
		"odd hex":         "suci-00101-0000-0-0-000000001",
		"non-hex":         "suci-00101-0000-0-1-zz",
		"4-digit mcc+mnc": "suci-0010-0000-0-0-00",
		"scheme 256":      "suci-00101-0000-0-256-aabb",
		"empty output":    "suci-00101-0000-0-1-",
		"oversized":       "suci-00101-0000-0-1-" + strings.Repeat("ab", MaxSUCILen),
		"null bad BCD":    "suci-00101-0000-0-0-ab",
		"supi":            "imsi-001010000000001",
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := ParseSUCIAny(in)
			if err == nil {
				t.Fatal("want error")
			}
			if len(in) < 100 && strings.Contains(err.Error(), in) {
				t.Fatalf("error embeds input: %v", err)
			}
		})
	}
}
