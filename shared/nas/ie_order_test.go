package nas_test

import (
	"encoding/hex"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// TestCUCGoldenLegacyBytes proves AMF-023: a CUC without the Network slicing
// indication encodes byte-identically to commit 4e176d9 (hex captured from that
// encoder), and with the indication only that IE's position changes
// (TS 24.501 Table 8.2.19.1.1: ... 45, 9-, 31, 11 ...).
func TestCUCGoldenLegacyBytes(t *testing.T) {
	b := func(v byte) *byte { return &v }
	n := func(s ...nas.SNSSAI) *nas.NSSAI { return &nas.NSSAI{SNSSAIs: s} }
	sst := func(v uint8) nas.SNSSAI { return nas.SNSSAI{SST: v, SD: nas.SDNotPresent} }
	rej := []nas.RejectedSNSSAI{{Cause: 1, SNSSAI: sst(3)}}

	cases := []struct {
		name string
		cuc  *nas.ConfigurationUpdateCommand
		want string // hex at HEAD 4e176d9 (for with-indication cases: the OLD, non-conformant order)
		new  string // hex now; empty = identical to want
	}{
		{"ack_only", &nas.ConfigurationUpdateCommand{ConfigUpdateIndication: b(1)}, "d1", ""},
		{"allowed_configured", &nas.ConfigurationUpdateCommand{ConfigUpdateIndication: b(1), AllowedNSSAI: n(sst(1)), ConfiguredNSSAI: n(nas.SNSSAI{SST: 1, SD: 0x010203})}, "d11502010131050401010203", ""},
		{"names_configured_rejected", &nas.ConfigurationUpdateCommand{FullNameForNetwork: "Claudia", ShortNameForNetwork: "C5", ConfiguredNSSAI: n(sst(2)), RejectedNSSAI: rej}, "4308874376b84e4e8701450382c31a3102010211021103", ""},
		{"tai_allowed_rejected", &nas.ConfigurationUpdateCommand{ConfigUpdateIndication: b(1), TAIList: []byte{0x00, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x01}, AllowedNSSAI: n(sst(1)), RejectedNSSAI: []nas.RejectedSNSSAI{{Cause: 0, SNSSAI: nas.SNSSAI{SST: 4, SD: 0xABCDEF}}}}, "d154070002f8390000011502010111054004abcdef", ""},
		// With Network slicing indication: only its position changes.
		{"indication_allowed_configured", &nas.ConfigurationUpdateCommand{ConfigUpdateIndication: b(1), AllowedNSSAI: n(sst(1)), ConfiguredNSSAI: n(nas.SNSSAI{SST: 1, SD: 0x010203}), NetworkSlicingIndication: b(1)},
			"d1150201013105040101020391", "d1150201019131050401010203"},
		{"indication_configured_rejected", &nas.ConfigurationUpdateCommand{ConfiguredNSSAI: n(sst(2)), NetworkSlicingIndication: b(3), RejectedNSSAI: rej},
			"310201029311021103", "933102010211021103"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := nas.EncodeConfigurationUpdateCommand(c.cuc)
			if err != nil {
				t.Fatal(err)
			}
			want := c.new
			if want == "" {
				want = c.want
			}
			if hex.EncodeToString(got) != want {
				t.Fatalf("got %x want %s", got, want)
			}
			if c.new != "" {
				t.Logf("before (4e176d9): %s", c.want)
				t.Logf("after  (AMF-023): %s", hex.EncodeToString(got))
			}
			// Tolerant receive: both orders decode to the same struct content.
			for _, h := range []string{c.want, want} {
				raw, _ := hex.DecodeString(h)
				d, err := nas.DecodeConfigurationUpdateCommand(raw)
				if err != nil {
					t.Fatal(err)
				}
				re, err := nas.EncodeConfigurationUpdateCommand(d)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(re) != want {
					t.Fatalf("decode(%s) re-encode = %x want %s", h, re, want)
				}
			}
		})
	}
}

// TestDeregistrationRequestNWRejectedNSSAI covers AMF-022 (Table 8.2.14.1.1, IEI 0x6D).
func TestDeregistrationRequestNWRejectedNSSAI(t *testing.T) {
	// Absent: bytes unchanged from the pre-AMF-022 encoder.
	got, _ := nas.EncodeDeregistrationRequestNW(&nas.DeregistrationRequestNW{Cause5GMM: 0x16, ReregistrationRequired: true, AccessType: 1})
	if hex.EncodeToString(got) != "755816" {
		t.Fatalf("legacy bytes changed: %x", got)
	}
	r := &nas.DeregistrationRequestNW{
		Cause5GMM: 0x16, ReregistrationRequired: true, AccessType: 1,
		RejectedNSSAI: []nas.RejectedSNSSAI{
			{Cause: nas.RejectedCauseNSSAAFailedOrRevoked, SNSSAI: nas.SNSSAI{SST: 1, SD: 0x010203}},
			{Cause: nas.RejectedCauseNotAvailableInRA, SNSSAI: nas.SNSSAI{SST: 2, SD: nas.SDNotPresent}},
		},
	}
	got, err := nas.EncodeDeregistrationRequestNW(r)
	if err != nil {
		t.Fatal(err)
	}
	const want = "7558166d0742010102031102"
	if hex.EncodeToString(got) != want {
		t.Fatalf("got %x want %s", got, want)
	}
	d, err := nas.DecodeDeregistrationRequestNW(got)
	if err != nil {
		t.Fatal(err)
	}
	if d.Cause5GMM != 0x16 || !d.ReregistrationRequired || d.AccessType != 1 || len(d.RejectedNSSAI) != 2 ||
		d.RejectedNSSAI[0] != r.RejectedNSSAI[0] || d.RejectedNSSAI[1] != r.RejectedNSSAI[1] {
		t.Fatalf("round trip mismatch: %+v", d)
	}
	// T3346 (0x5F) before the Rejected NSSAI is skipped.
	raw, _ := hex.DecodeString("755f01216d021102")
	if d, err = nas.DecodeDeregistrationRequestNW(raw); err != nil || len(d.RejectedNSSAI) != 1 {
		t.Fatalf("T3346 skip: %+v %v", d, err)
	}
	if _, err = nas.DecodeDeregistrationRequestNW([]byte{0x75, 0x6d, 0x05, 0x11}); err == nil {
		t.Fatal("expected truncation error")
	}
}
