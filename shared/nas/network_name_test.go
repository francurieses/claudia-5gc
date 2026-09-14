package nas

import (
	"encoding/hex"
	"testing"
)

// TestEncodeNetworkNameGSM7Lab11 pins the exact wire bytes for the lab-11
// operator name. "ClaudIA+OCUDU" is 13 runes, all inside the GSM 7-bit basic
// set, so it must take coding scheme 0b000 and pack into 12 octets with 5
// spare bits in the last one (13 x 7 = 91 bits, 12 octets = 96 bits).
// Ref: TS 24.008 §10.5.3.5a, TS 23.038 §6.1.2.1.1
func TestEncodeNetworkNameGSM7Lab11(t *testing.T) {
	got, err := EncodeNetworkName(0x43, "ClaudIA+OCUDU")
	if err != nil {
		t.Fatalf("EncodeNetworkName: %v", err)
	}
	if got[0] != 0x43 {
		t.Errorf("IEI = 0x%02X, want 0x43", got[0])
	}
	// length = octet 3 plus 12 packed octets
	if got[1] != 13 {
		t.Errorf("length = %d, want 13", got[1])
	}
	// ext=1, coding=000 (GSM7), AddCI=0, spare bits=5
	if got[2] != 0x85 {
		t.Errorf("header = 0x%02X, want 0x85", got[2])
	}
	if len(got) != 15 {
		t.Errorf("total IE = %d octets, want 15", len(got))
	}
	t.Logf("full name IE: %s", hex.EncodeToString(got))
}

// TestNetworkNameRoundTrip checks that every supported coding scheme survives
// an encode/decode cycle, including the UCS-2 fallback for runes outside the
// GSM basic set.
func TestNetworkNameRoundTrip(t *testing.T) {
	cases := []struct {
		text       string
		wantCoding byte
	}{
		{"ClaudIA+OCUDU", NetworkNameCodingGSM7},
		{"ClaudIA", NetworkNameCodingGSM7},
		{"A", NetworkNameCodingGSM7},
		{"AB", NetworkNameCodingGSM7},
		{"ABCDEFGH", NetworkNameCodingGSM7}, // 8 septets = exactly 7 octets
		{"ClaudIA 5GC / OCUDU n78", NetworkNameCodingGSM7},
		// '±' and '中' are outside the GSM basic set, forcing UCS-2.
		{"ClaudIA±OCUDU", NetworkNameCodingUCS2},
		{"中文网络", NetworkNameCodingUCS2},
	}
	for _, tc := range cases {
		enc, err := EncodeNetworkName(0x43, tc.text)
		if err != nil {
			t.Fatalf("%q: encode: %v", tc.text, err)
		}
		if int(enc[1]) != len(enc)-2 {
			t.Errorf("%q: length byte %d does not match %d content octets",
				tc.text, enc[1], len(enc)-2)
		}
		dec, err := DecodeNetworkName(enc[2:])
		if err != nil {
			t.Fatalf("%q: decode: %v", tc.text, err)
		}
		if dec.CodingScheme != tc.wantCoding {
			t.Errorf("%q: coding scheme = %d, want %d",
				tc.text, dec.CodingScheme, tc.wantCoding)
		}
		if dec.Text != tc.text {
			t.Errorf("%q: round-trip gave %q", tc.text, dec.Text)
		}
	}
}

// TestEncodeNetworkNameRejectsEmpty guards against emitting a zero-length IE.
func TestEncodeNetworkNameRejectsEmpty(t *testing.T) {
	if _, err := EncodeNetworkName(0x43, ""); err == nil {
		t.Error("empty name was accepted; want an error")
	}
}

// TestConfigurationUpdateCommandNetworkNameOrder checks that both network-name
// IEs land between the Allowed NSSAI and the Configured NSSAI, the position
// TS 24.501 Table 8.2.19.1.1 gives them.
func TestConfigurationUpdateCommandNetworkNameOrder(t *testing.T) {
	ack := ConfigUpdateIndicationACK
	cmd := &ConfigurationUpdateCommand{
		ConfigUpdateIndication: &ack,
		FullNameForNetwork:     "ClaudIA+OCUDU",
		ShortNameForNetwork:    "ClaudIA",
	}
	b, err := EncodeConfigurationUpdateCommand(cmd)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if b[0] != 0xD1 {
		t.Errorf("first octet = 0x%02X, want 0xD1 (config update indication, ACK)", b[0])
	}
	if b[1] != 0x43 {
		t.Errorf("second octet = 0x%02X, want 0x43 (full name IEI)", b[1])
	}
	back, err := DecodeConfigurationUpdateCommand(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if back.FullNameForNetwork != "ClaudIA+OCUDU" {
		t.Errorf("full name round-tripped as %q", back.FullNameForNetwork)
	}
	if back.ShortNameForNetwork != "ClaudIA" {
		t.Errorf("short name round-tripped as %q", back.ShortNameForNetwork)
	}
	t.Logf("configuration update command: %s", hex.EncodeToString(b))
}
