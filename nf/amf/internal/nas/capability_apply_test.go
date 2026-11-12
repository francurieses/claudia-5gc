package nasmsg

import (
	"encoding/hex"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// UERANSIM patch 0080 enabled-UE 5GMM capability value (ESI, ECI, UN-PER,
// RSLPVU, EF5L, LCSCDL), TS 24.501 §9.11.3.1.
const mmCapEnabledHex = "0000000000" + "0c040010" + "4008"

// regReqWithCap builds a plain REGISTRATION REQUEST (5G-GUTI identity) carrying
// the 5GMM capability IE (IEI 0x10) when capHex != "".
func regReqWithCap(t *testing.T, regType byte, capHex string) []byte {
	t.Helper()
	b := []byte{0x7e, 0x00, 0x41, 0x70 | regType, 0x00, 0x0b, 0xf2,
		0x00, 0xf1, 0x10, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}
	if capHex != "" {
		v, err := hex.DecodeString(capHex)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, 0x10, byte(len(v)))
		b = append(b, v...)
	}
	return b
}

func TestApplyRetransmittedRegistrationRequest_Capability5GMM(t *testing.T) {
	tests := []struct {
		name     string
		capHex   string
		prior    *nas.FiveGMMCapability
		wantHex  string
		wantNone bool
	}{
		{name: "enabled UE bits stored", capHex: mmCapEnabledHex, wantHex: mmCapEnabledHex},
		{name: "default UE single zero octet", capHex: "00", wantHex: "00"},
		{name: "IE absent leaves nil", capHex: "", wantNone: true},
		{name: "IE absent keeps prior", capHex: "", prior: &nas.FiveGMMCapability{Raw: []byte{0x01}}, wantHex: "01"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(&fakeSender{})
			ue := newTestUE(t)
			ue.Capability5GMM = tc.prior
			h.applyRetransmittedRegistrationRequest(ue, regReqWithCap(t, 1, tc.capHex))
			if tc.wantNone {
				if ue.Capability5GMM != nil {
					t.Fatalf("Capability5GMM = %x, want nil", ue.Capability5GMM.Raw)
				}
				return
			}
			if ue.Capability5GMM == nil {
				t.Fatal("Capability5GMM not stored")
			}
			if got := ue.Capability5GMM.RawHex(); got != tc.wantHex {
				t.Errorf("RawHex = %s, want %s", got, tc.wantHex)
			}
		})
	}
}

func TestApplyRetransmittedRegistrationRequest_Capability5GMMBits(t *testing.T) {
	h := newTestHandler(&fakeSender{})
	ue := newTestUE(t)
	h.applyRetransmittedRegistrationRequest(ue, regReqWithCap(t, 1, mmCapEnabledHex))
	c := ue.Capability5GMM
	if c == nil || !c.ESI || !c.ECI || !c.UNPER || !c.RSLPVU || !c.EF5L || !c.LCSCDL || c.S1Mode {
		t.Fatalf("decoded bits wrong: %+v", c)
	}
}

func TestHandleRegistrationUpdate_Capability5GMM(t *testing.T) {
	// Pure decode path used by handleRegistrationUpdate: the request type does
	// not matter for the IE decoding (mobility 2, periodic 3).
	for _, rt := range []byte{2, 3} {
		msg, err := nas.Decode(regReqWithCap(t, rt, mmCapEnabledHex))
		if err != nil {
			t.Fatal(err)
		}
		rr, ok := msg.Body.(*nas.RegistrationRequest)
		if !ok {
			t.Fatalf("body %T", msg.Body)
		}
		if got := rr.Capability5GMM().RawHex(); got != mmCapEnabledHex {
			t.Errorf("reg type %d: RawHex = %s", rt, got)
		}
	}
}
