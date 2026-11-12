package nas

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func u8p(v uint8) *uint8 { return &v }

// Golden values derived from TS 24.501 Figures 9.11.3.75.2-.4 and Table 9.11.3.75.1.
func TestExtendedRejectedNSSAIGolden(t *testing.T) {
	cases := []struct {
		name string
		in   *ExtendedRejectedNSSAI
		want []byte
	}{
		{"nssaa failed with SD (type 000)",
			&ExtendedRejectedNSSAI{Lists: []PartialExtendedRejectedNSSAIList{{Elements: []ExtendedRejectedSNSSAI{
				{Cause: RejectedCauseNSSAAFailedOrRevoked, SNSSAI: SNSSAI{SST: 1, SD: 1}}}}}},
			[]byte{0x00, 0x42, 0x01, 0x00, 0x00, 0x01}},
		{"SST only, minimum IE length 5",
			&ExtendedRejectedNSSAI{Lists: []PartialExtendedRejectedNSSAIList{{Elements: []ExtendedRejectedSNSSAI{
				{Cause: RejectedCauseNotAvailableInRA, SNSSAI: SNSSAI{SST: 1, SD: SDNotPresent}}}}}},
			[]byte{0x00, 0x11, 0x01}},
		{"back-off timer list, max UEs reached (type 001)",
			&ExtendedRejectedNSSAI{Lists: []PartialExtendedRejectedNSSAIList{{BackoffTimer: u8p(0x21), Elements: []ExtendedRejectedSNSSAI{
				{Cause: ExtRejectedCauseMaxUEsReached, SNSSAI: SNSSAI{SST: 1, SD: 0x010203}},
				{Cause: ExtRejectedCauseMaxUEsReached, SNSSAI: SNSSAI{SST: 2, SD: SDNotPresent}}}}}},
			[]byte{0x11, 0x21, 0x43, 0x01, 0x01, 0x02, 0x03, 0x13, 0x02}},
		{"mapped HPLMN S-NSSAI (length 5 and 8)",
			&ExtendedRejectedNSSAI{Lists: []PartialExtendedRejectedNSSAIList{{Elements: []ExtendedRejectedSNSSAI{
				{Cause: RejectedCauseNotAvailableInPLMN, SNSSAI: SNSSAI{SST: 1, SD: SDNotPresent}, Mapped: &SNSSAI{SST: 5, SD: SDNotPresent}},
				{Cause: RejectedCauseNotAvailableInPLMN, SNSSAI: SNSSAI{SST: 1, SD: SDNotPresent}, Mapped: &SNSSAI{SST: 5, SD: 0xAABBCC}}}}}},
			[]byte{0x01, 0x50, 0x01, 0xFF, 0xFF, 0xFF, 0x05, 0x80, 0x01, 0xFF, 0xFF, 0xFF, 0x05, 0xAA, 0xBB, 0xCC}},
		{"two lists",
			&ExtendedRejectedNSSAI{Lists: []PartialExtendedRejectedNSSAIList{
				{Elements: []ExtendedRejectedSNSSAI{{Cause: 2, SNSSAI: SNSSAI{SST: 1, SD: SDNotPresent}}}},
				{BackoffTimer: u8p(0x05), Elements: []ExtendedRejectedSNSSAI{{Cause: 3, SNSSAI: SNSSAI{SST: 3, SD: SDNotPresent}}}}}},
			[]byte{0x00, 0x12, 0x01, 0x10, 0x05, 0x13, 0x03}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := EncodeExtendedRejectedNSSAI(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, c.want) {
				t.Fatalf("got %x want %x", got, c.want)
			}
			dec, err := DecodeExtendedRejectedNSSAI(got)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(dec, c.in) {
				t.Fatalf("round trip: %+v != %+v", dec, c.in)
			}
		})
	}
}

func TestExtendedRejectedNSSAIAbsent(t *testing.T) {
	for _, in := range []*ExtendedRejectedNSSAI{nil, {}} {
		b, err := EncodeExtendedRejectedNSSAI(in)
		if err != nil || b != nil {
			t.Fatalf("got %x, %v", b, err)
		}
	}
	if ExtendedRejectedNSSAIFromList(nil) != nil {
		t.Fatal("empty list must give nil")
	}
	e := ExtendedRejectedNSSAIFromList([]RejectedSNSSAI{{RejectedCauseNSSAAFailedOrRevoked, SNSSAI{SST: 1, SD: 1}}})
	b, _ := EncodeExtendedRejectedNSSAI(e)
	if !bytes.Equal(b, []byte{0x00, 0x42, 0x01, 0x00, 0x00, 0x01}) {
		t.Fatalf("got %x", b)
	}
}

func TestExtendedRejectedNSSAIEncodeInvalid(t *testing.T) {
	el := func(c uint8) ExtendedRejectedSNSSAI {
		return ExtendedRejectedSNSSAI{Cause: c, SNSSAI: SNSSAI{SST: 1, SD: SDNotPresent}}
	}
	nine := make([]ExtendedRejectedSNSSAI, 9)
	for i := range nine {
		nine[i] = el(0)
	}
	cases := map[string]*ExtendedRejectedNSSAI{
		"empty list":           {Lists: []PartialExtendedRejectedNSSAIList{{}}},
		"nine elements":        {Lists: []PartialExtendedRejectedNSSAIList{{Elements: nine}}},
		"nine over two lists":  {Lists: []PartialExtendedRejectedNSSAIList{{Elements: nine[:5]}, {Elements: nine[:4]}}},
		"cause > 4 bits":       {Lists: []PartialExtendedRejectedNSSAIList{{Elements: []ExtendedRejectedSNSSAI{el(0x10)}}}},
		"timer w/ wrong cause": {Lists: []PartialExtendedRejectedNSSAIList{{BackoffTimer: u8p(1), Elements: []ExtendedRejectedSNSSAI{el(2)}}}},
		"mapped with NSSAA cause": {Lists: []PartialExtendedRejectedNSSAIList{{Elements: []ExtendedRejectedSNSSAI{
			{Cause: 2, SNSSAI: SNSSAI{SST: 1, SD: 1}, Mapped: &SNSSAI{SST: 1, SD: 1}}}}}},
		"SD over 24 bits": {Lists: []PartialExtendedRejectedNSSAIList{{Elements: []ExtendedRejectedSNSSAI{
			{SNSSAI: SNSSAI{SST: 1, SD: 0x1000000}}}}}},
	}
	for name, in := range cases {
		if _, err := EncodeExtendedRejectedNSSAI(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestExtendedRejectedNSSAIMaxLength(t *testing.T) {
	// 8 elements x (1 + 8) octets + 1 list header = 73 value octets (IE 75 <= 90).
	els := make([]ExtendedRejectedSNSSAI, 8)
	for i := range els {
		els[i] = ExtendedRejectedSNSSAI{SNSSAI: SNSSAI{SST: 1, SD: 1}, Mapped: &SNSSAI{SST: 2, SD: 2}}
	}
	b, err := EncodeExtendedRejectedNSSAI(&ExtendedRejectedNSSAI{Lists: []PartialExtendedRejectedNSSAIList{{Elements: els}}})
	if err != nil || len(b) != 73 {
		t.Fatalf("len %d err %v", len(b), err)
	}
}

func TestExtendedRejectedNSSAIDecodeInvalid(t *testing.T) {
	cases := map[string][]byte{
		"empty":                 {},
		"reserved type 010":     {0x20, 0x11, 0x01},
		"missing timer":         {0x10},
		"missing element":       {0x00},
		"truncated element":     {0x00, 0x42, 0x01, 0x00},
		"element length 2":      {0x00, 0x20, 0x01, 0x02},
		"element length 0":      {0x00, 0x00},
		"second list truncated": {0x00, 0x11, 0x01, 0x00},
	}
	for name, b := range cases {
		if _, err := DecodeExtendedRejectedNSSAI(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Number of elements 8 for any value above 7 is a UE-side rule; here: nibble 0xF
	// means 8 elements, so a single element is a truncation.
	if _, err := DecodeExtendedRejectedNSSAI([]byte{0x0F, 0x11, 0x01}); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("err = %v", err)
	}
	// Spare bit 8 of octet 3 is ignored.
	if _, err := DecodeExtendedRejectedNSSAI([]byte{0x80, 0x11, 0x01}); err != nil {
		t.Fatal(err)
	}
}

func TestERNSSAISupported(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"nil", nil, false},
		{"octet 3 only", []byte{0xFF}, false},
		{"octets 3-4 only", []byte{0xFF, 0xFF}, false},
		{"octet 5 zero", []byte{0xFF, 0xFF, 0x00}, false},
		{"octet 5 bit 5", []byte{0x00, 0x00, 0x10}, true},
		{"octet 5 other bits", []byte{0x00, 0x00, 0xEF}, false},
		{"longer IE", []byte{0x01, 0x00, 0x10, 0x00, 0x00}, true},
	}
	for _, c := range cases {
		if got := ERNSSAISupported(c.b); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
		if got := (&RegistrationRequest{FiveGMMCapability: c.b}).ERNSSAISupported(); got != c.want {
			t.Errorf("%s (method): got %v", c.name, got)
		}
	}
	var nilReq *RegistrationRequest
	if nilReq.ERNSSAISupported() {
		t.Error("nil request")
	}
}

func TestRegistrationAcceptExtendedRejectedNSSAI(t *testing.T) {
	t3512 := byte(0x21)
	ra := &RegistrationAccept{
		RegistrationResult: 0x01,
		AllowedNSSAI:       &NSSAI{SNSSAIs: []SNSSAI{{SST: 1, SD: SDNotPresent}}},
		T3512Value:         &t3512,
		PendingNSSAI:       &NSSAI{SNSSAIs: []SNSSAI{{SST: 1, SD: 4}}},
	}
	legacy, err := EncodeRegistrationAccept(ra)
	if err != nil {
		t.Fatal(err)
	}
	ra.ExtendedRejectedNSSAI = ExtendedRejectedNSSAIFromList([]RejectedSNSSAI{{RejectedCauseNSSAAFailedOrRevoked, SNSSAI{SST: 1, SD: 1}}})
	got, err := EncodeRegistrationAccept(ra)
	if err != nil {
		t.Fatal(err)
	}
	// Table 8.2.7.1.1: 0x68 follows Pending NSSAI (0x39); legacy bytes are a strict prefix.
	want := append(append([]byte{}, legacy...), 0x68, 0x06, 0x00, 0x42, 0x01, 0x00, 0x00, 0x01)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	dec, err := DecodeRegistrationAccept(got)
	if err != nil || !reflect.DeepEqual(dec.ExtendedRejectedNSSAI, ra.ExtendedRejectedNSSAI) || dec.PendingNSSAI == nil {
		t.Fatalf("decode = %+v, %v", dec, err)
	}
	if _, err := DecodeRegistrationAccept(append(append([]byte{}, legacy...), 0x68, 0x02, 0x00, 0x42)); err == nil {
		t.Fatal("expected error for malformed 0x68")
	}
	if dec, _ := DecodeRegistrationAccept(legacy); dec.ExtendedRejectedNSSAI != nil {
		t.Fatal("legacy must decode without the IE")
	}
}

func TestConfigurationUpdateCommandExtendedRejectedNSSAI(t *testing.T) {
	ind := byte(0x1)
	base := &ConfigurationUpdateCommand{
		ConfiguredNSSAI:          &NSSAI{SNSSAIs: []SNSSAI{{SST: 1, SD: SDNotPresent}}},
		NetworkSlicingIndication: &ind,
		RejectedNSSAI:            []RejectedSNSSAI{{RejectedCauseNSSAAFailedOrRevoked, SNSSAI{SST: 1, SD: 3}}},
	}
	legacy, err := EncodeConfigurationUpdateCommand(base)
	if err != nil {
		t.Fatal(err)
	}
	c := *base
	c.ExtendedRejectedNSSAI = ExtendedRejectedNSSAIFromList([]RejectedSNSSAI{{RejectedCauseNSSAAFailedOrRevoked, SNSSAI{SST: 1, SD: 1}}})
	got, err := EncodeConfigurationUpdateCommand(&c)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, legacy...), 0x68, 0x06, 0x00, 0x42, 0x01, 0x00, 0x00, 0x01)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	dec, err := DecodeConfigurationUpdateCommand(got)
	if err != nil || !reflect.DeepEqual(dec.ExtendedRejectedNSSAI, c.ExtendedRejectedNSSAI) || len(dec.RejectedNSSAI) != 1 {
		t.Fatalf("decode = %+v, %v", dec, err)
	}
	if _, err := DecodeConfigurationUpdateCommand([]byte{0x68, 0x01, 0x20}); err == nil {
		t.Fatal("expected error for malformed 0x68")
	}
}

func TestDeregistrationRequestNWExtendedRejectedNSSAIAndSpare(t *testing.T) {
	base := &DeregistrationRequestNW{
		AccessType: 1, ReregistrationRequired: true, Cause5GMM: 0x16,
		RejectedNSSAI: []RejectedSNSSAI{{RejectedCauseNSSAAFailedOrRevoked, SNSSAI{SST: 1, SD: 3}}},
	}
	legacy, err := EncodeDeregistrationRequestNW(base)
	if err != nil {
		t.Fatal(err)
	}
	// Default: high half octet stays 0x7 (rel17 byte identity).
	wantLegacy := []byte{0x75, 0x58, 0x16, 0x6D, 0x05, 0x42, 0x01, 0x00, 0x00, 0x03}
	if !bytes.Equal(legacy, wantLegacy) {
		t.Fatalf("legacy got %x want %x", legacy, wantLegacy)
	}
	// Spare = 0 under the option; rest identical.
	z := *base
	z.SpareHalfOctetZero = true
	gz, err := EncodeDeregistrationRequestNW(&z)
	if err != nil || gz[0] != 0x05 || !bytes.Equal(gz[1:], legacy[1:]) {
		t.Fatalf("spare zero: %x, %v", gz, err)
	}
	// Extended rejected NSSAI goes after Rejected NSSAI (0x6D).
	x := *base
	x.ExtendedRejectedNSSAI = ExtendedRejectedNSSAIFromList([]RejectedSNSSAI{{RejectedCauseNSSAAFailedOrRevoked, SNSSAI{SST: 1, SD: 1}}})
	gx, err := EncodeDeregistrationRequestNW(&x)
	if err != nil {
		t.Fatal(err)
	}
	if want := append(append([]byte{}, legacy...), 0x68, 0x06, 0x00, 0x42, 0x01, 0x00, 0x00, 0x01); !bytes.Equal(gx, want) {
		t.Fatalf("got %x want %x", gx, want)
	}
	dec, err := DecodeDeregistrationRequestNW(gx)
	if err != nil || !reflect.DeepEqual(dec.ExtendedRejectedNSSAI, x.ExtendedRejectedNSSAI) ||
		!reflect.DeepEqual(dec.RejectedNSSAI, base.RejectedNSSAI) || dec.Cause5GMM != 0x16 || !dec.ReregistrationRequired {
		t.Fatalf("decode = %+v, %v", dec, err)
	}
	// Spare nibble does not affect decoding.
	dz, err := DecodeDeregistrationRequestNW(gz)
	if err != nil || dz.AccessType != 1 || !dz.ReregistrationRequired {
		t.Fatalf("decode zero spare = %+v, %v", dz, err)
	}
}

func TestDecodeDeregistrationRequestNWErrors(t *testing.T) {
	cases := []struct {
		name    string
		b       []byte
		wantErr string
	}{
		{"empty", nil, "empty body"},
		{"truncated 0x58", []byte{0x01, 0x58}, "truncated 5GMM cause"},
		{"TLV length overruns", []byte{0x01, 0x6D, 0x05, 0x42, 0x01}, "truncated IE 0x6d"},
		{"TLV length octet missing", []byte{0x01, 0x6D}, "truncated IE 0x6d"},
		{"bad rejected NSSAI wrapped", []byte{0x01, 0x6D, 0x01, 0x20}, "nas: deregistration request (NW): rejected NSSAI: "},
		{"bad extended rejected NSSAI wrapped", []byte{0x01, 0x68, 0x01, 0x20}, "nas: deregistration request (NW): extended rejected NSSAI: "},
	}
	for _, c := range cases {
		_, err := DecodeDeregistrationRequestNW(c.b)
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.wantErr)
		}
	}
}

func TestDecodeDeregistrationRequestNWUnknownTLVBetweenKnown(t *testing.T) {
	// 0x58 cause, unknown TLV 0x5F-like 0x7E (3 octets), Rejected NSSAI, unknown TLV 0x75, Extended rejected NSSAI.
	b := []byte{0x01,
		0x58, 0x16,
		0x7E, 0x03, 0xAA, 0xBB, 0xCC,
		0x6D, 0x02, 0x11, 0x01,
		0x75, 0x00,
		0x68, 0x03, 0x00, 0x11, 0x02}
	r, err := DecodeDeregistrationRequestNW(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Cause5GMM != 0x16 || len(r.RejectedNSSAI) != 1 || r.RejectedNSSAI[0].SNSSAI.SST != 1 ||
		r.ExtendedRejectedNSSAI == nil || r.ExtendedRejectedNSSAI.Lists[0].Elements[0].SNSSAI.SST != 2 {
		t.Fatalf("decoded = %+v", r)
	}
}
