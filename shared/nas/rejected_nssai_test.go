package nas

import (
	"bytes"
	"reflect"
	"testing"
)

func TestRejectedNSSAIGolden(t *testing.T) {
	tests := []struct {
		name string
		in   []RejectedSNSSAI
		want []byte
	}{
		{"sst-only plmn", []RejectedSNSSAI{{RejectedCauseNotAvailableInPLMN, SNSSAI{SST: 1, SD: SDNotPresent}}}, []byte{0x10, 0x01}},
		{"sst+sd nssaa failed", []RejectedSNSSAI{{RejectedCauseNSSAAFailedOrRevoked, SNSSAI{SST: 1, SD: 0x000003}}}, []byte{0x42, 0x01, 0x00, 0x00, 0x03}},
		{"two entries", []RejectedSNSSAI{
			{RejectedCauseNotAvailableInRA, SNSSAI{SST: 2, SD: SDNotPresent}},
			{RejectedCauseNSSAAFailedOrRevoked, SNSSAI{SST: 1, SD: 0x010203}}},
			[]byte{0x11, 0x02, 0x42, 0x01, 0x01, 0x02, 0x03}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EncodeRejectedNSSAI(tc.in)
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("encode = %x, %v; want %x", got, err, tc.want)
			}
			back, err := DecodeRejectedNSSAI(got)
			if err != nil || !reflect.DeepEqual(back, tc.in) {
				t.Fatalf("round trip = %+v, %v; want %+v", back, err, tc.in)
			}
		})
	}
}

func TestRejectedNSSAIInvalid(t *testing.T) {
	for name, b := range map[string][]byte{
		"len 0":     {0x00},
		"len 2":     {0x20, 0x01, 0x02},
		"len 5":     {0x50, 1, 2, 3, 4, 5},
		"truncated": {0x40, 0x01, 0x00},
	} {
		if _, err := DecodeRejectedNSSAI(b); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := EncodeRejectedNSSAI([]RejectedSNSSAI{{Cause: 0x10, SNSSAI: SNSSAI{SST: 1, SD: SDNotPresent}}}); err == nil {
		t.Error("cause > 4 bits: want error")
	}
	many := make([]RejectedSNSSAI, MaxRejectedSNSSAIs+1)
	for i := range many {
		many[i].SNSSAI = SNSSAI{SST: 1, SD: SDNotPresent}
	}
	if _, err := EncodeRejectedNSSAI(many); err == nil {
		t.Error("9 entries: want error")
	}
}

func TestCUCRejectedNSSAIPosition(t *testing.T) {
	ind := byte(0x1)
	base := &ConfigurationUpdateCommand{
		ConfiguredNSSAI:          &NSSAI{SNSSAIs: []SNSSAI{{SST: 1, SD: SDNotPresent}}},
		NetworkSlicingIndication: &ind,
	}
	legacy, err := EncodeConfigurationUpdateCommand(base)
	if err != nil {
		t.Fatal(err)
	}
	withRej := *base
	withRej.RejectedNSSAI = []RejectedSNSSAI{{RejectedCauseNSSAAFailedOrRevoked, SNSSAI{SST: 1, SD: 0x000003}}}
	got, err := EncodeConfigurationUpdateCommand(&withRej)
	if err != nil {
		t.Fatal(err)
	}
	// Rejected NSSAI follows Network slicing indication (0x9-) and Configured NSSAI (0x31), Table 8.2.19.1.1.
	want := append(append([]byte{}, legacy...), 0x11, 0x05, 0x42, 0x01, 0x00, 0x00, 0x03)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	if want[0] != 0x91 || !bytes.HasPrefix(got, legacy) {
		t.Fatalf("legacy prefix changed: %x", got)
	}
	dec, err := DecodeConfigurationUpdateCommand(got)
	if err != nil || !reflect.DeepEqual(dec.RejectedNSSAI, withRej.RejectedNSSAI) || dec.ConfiguredNSSAI == nil {
		t.Fatalf("decode = %+v, %v", dec, err)
	}
}

func TestRegistrationAcceptRejectedAndPendingNSSAI(t *testing.T) {
	t3512 := byte(0x21)
	ra := &RegistrationAccept{
		RegistrationResult: 0x01,
		AllowedNSSAI:       &NSSAI{SNSSAIs: []SNSSAI{{SST: 1, SD: SDNotPresent}}},
		ConfiguredNSSAI:    &NSSAI{SNSSAIs: []SNSSAI{{SST: 1, SD: SDNotPresent}}},
		T3512Value:         &t3512,
	}
	legacy, err := EncodeRegistrationAccept(ra)
	if err != nil {
		t.Fatal(err)
	}
	rej, err := RejectedNSSAIValue([]RejectedSNSSAI{{RejectedCauseNSSAAFailedOrRevoked, SNSSAI{SST: 1, SD: 0x000003}}})
	if err != nil {
		t.Fatal(err)
	}
	ra.RejectedNSSAI = rej
	ra.PendingNSSAI = &NSSAI{SNSSAIs: []SNSSAI{{SST: 1, SD: 0x000004}}}
	got, err := EncodeRegistrationAccept(ra)
	if err != nil {
		t.Fatal(err)
	}
	// Order: result, 0x15 Allowed, 0x11 Rejected, 0x31 Configured, 0x5E T3512, 0x39 Pending.
	want := []byte{0x01, 0x01,
		0x15, 0x02, 0x01, 0x01,
		0x11, 0x05, 0x42, 0x01, 0x00, 0x00, 0x03,
		0x31, 0x02, 0x01, 0x01,
		0x5E, 0x01, 0x21,
		0x39, 0x05, 0x04, 0x01, 0x00, 0x00, 0x04}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	dec, err := DecodeRegistrationAccept(got)
	if err != nil || !bytes.Equal(dec.RejectedNSSAI, rej) || dec.PendingNSSAI == nil ||
		dec.PendingNSSAI.SNSSAIs[0].SD != 4 || dec.T3512Value == nil {
		t.Fatalf("decode = %+v, %v", dec, err)
	}
	// Absent when unset: legacy bytes carry neither IEI.
	want0 := []byte{0x01, 0x01, 0x15, 0x02, 0x01, 0x01, 0x31, 0x02, 0x01, 0x01, 0x5E, 0x01, 0x21}
	if !bytes.Equal(legacy, want0) {
		t.Fatalf("legacy bytes changed: %x", legacy)
	}
}
