package nas

import (
	"bytes"
	"testing"
	"time"
)

func TestEncodeRegistrationReject_LegacyGolden(t *testing.T) {
	got, err := EncodeRegistrationReject(&RegistrationReject{Cause5GMM: 0x4A})
	if err != nil || !bytes.Equal(got, []byte{0x4A}) {
		t.Fatalf("got %x err %v", got, err)
	}
}

func TestEncodeRegistrationReject_RejectedNSSAI(t *testing.T) {
	list := []RejectedSNSSAI{{Cause: 0, SNSSAI: SNSSAI{SST: 1, SD: SDNotPresent}}}
	got, err := EncodeRegistrationReject(&RegistrationReject{Cause5GMM: 62, RejectedNSSAI: list})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{62, 0x69, 0x02, 0x10, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	dec, err := DecodeRejectedNSSAI(got[3:])
	if err != nil || len(dec) != 1 || dec[0].SNSSAI.SST != 1 {
		t.Fatalf("decode: %v %v", dec, err)
	}
}

func TestEncodeRegistrationReject_ExtendedAndOrder(t *testing.T) {
	list := []RejectedSNSSAI{{Cause: 0, SNSSAI: SNSSAI{SST: 1, SD: SDNotPresent}}}
	got, err := EncodeRegistrationReject(&RegistrationReject{
		Cause5GMM: 62, RejectedNSSAI: list, ExtendedRejectedNSSAI: ExtendedRejectedNSSAIFromList(list),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != 0x69 || got[5] != IEIExtendedRejectedNSSAI {
		t.Fatalf("order wrong: %x", got)
	}
	ext := got[5:]
	dec, err := DecodeExtendedRejectedNSSAI(ext[2 : 2+int(ext[1])])
	if err != nil || len(dec.Lists) != 1 {
		t.Fatalf("decode: %v %v", dec, err)
	}
}

func TestEncodeGPRSTimer2(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want byte
	}{
		{0, 0x00}, {2 * time.Second, 0x01}, {62 * time.Second, 0x1F},
		{63 * time.Second, 0x22}, {12 * time.Minute, 0x2C}, {31 * time.Minute, 0x3F},
		{32 * time.Minute, 0x46}, {186 * time.Minute, 0x5F},
	}
	for _, tc := range tests {
		got, err := EncodeGPRSTimer2(tc.d)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %#x err %v want %#x", tc.d, got, err, tc.want)
		}
	}
	for _, d := range []time.Duration{-time.Second, 187 * time.Minute} {
		if _, err := EncodeGPRSTimer2(d); err == nil {
			t.Errorf("%s: expected error", d)
		}
	}
}

func TestEncodeRegistrationReject_T3346Golden(t *testing.T) {
	d := 12 * time.Minute
	list := []RejectedSNSSAI{{Cause: 0, SNSSAI: SNSSAI{SST: 1, SD: SDNotPresent}}}
	got, err := EncodeRegistrationReject(&RegistrationReject{Cause5GMM: 22, T3346: &d, RejectedNSSAI: list})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{22, 0x5F, 0x01, 0x2C, 0x69, 0x02, 0x10, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
}
