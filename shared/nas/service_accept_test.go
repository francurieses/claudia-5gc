package nas_test

// service_accept_test.go — Service Accept optional IEs (PDU session status,
// PDU session reactivation result).
// Ref: TS 24.501 §8.2.17.1.1, §9.11.3.44, §9.11.3.42

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestPSIMask_Layout(t *testing.T) {
	cases := []struct {
		psis []uint8
		want uint16
	}{
		{nil, 0x0000},
		{[]uint8{0}, 0x0000},  // PSI 0 is spare
		{[]uint8{1}, 0x0200},  // octet 3 bit 2
		{[]uint8{7}, 0x8000},  // octet 3 bit 8
		{[]uint8{8}, 0x0001},  // octet 4 bit 1
		{[]uint8{15}, 0x0080}, // octet 4 bit 8
		{[]uint8{1, 2, 9}, 0x0602},
		{[]uint8{16}, 0x0000}, // out of range ignored
	}
	for _, c := range cases {
		got := nas.PSIMask(c.psis...)
		if got != c.want {
			t.Errorf("PSIMask(%v) = %04X, want %04X", c.psis, got, c.want)
		}
		for psi := uint8(1); psi <= 15; psi++ {
			in := false
			for _, p := range c.psis {
				if p == psi {
					in = true
				}
			}
			if nas.PSIInStatus(got, psi) != in {
				t.Errorf("PSIInStatus(PSIMask(%v), %d) = %v, want %v", c.psis, psi, !in, in)
			}
		}
	}
}

func TestEncodeServiceAccept_IEs(t *testing.T) {
	status := nas.PSIMask(1, 2)
	result := nas.PSIMask(2)
	cases := []struct {
		name string
		in   *nas.ServiceAccept
		want []byte
	}{
		{"empty", &nas.ServiceAccept{}, []byte{}},
		{"nil", nil, []byte{}},
		{"status only", &nas.ServiceAccept{PDUSessionStatus: &status}, []byte{0x50, 0x02, 0x06, 0x00}},
		{"result only", &nas.ServiceAccept{PDUSessionReactivationResult: &result}, []byte{0x26, 0x02, 0x04, 0x00}},
		{"both, table order 0x50 then 0x26", &nas.ServiceAccept{PDUSessionStatus: &status, PDUSessionReactivationResult: &result},
			[]byte{0x50, 0x02, 0x06, 0x00, 0x26, 0x02, 0x04, 0x00}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := nas.EncodeServiceAccept(c.in)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !bytes.Equal(got, c.want) {
				t.Fatalf("got % X, want % X", got, c.want)
			}
		})
	}
}

func TestServiceAccept_RoundTripViaMessage(t *testing.T) {
	status := nas.PSIMask(1, 9)
	result := nas.PSIMask(9)
	msg := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			SecurityHeaderType:            nas.SecurityHeaderPlainNAS,
			MessageType:                   nas.MsgTypeServiceAccept,
		},
		Body: &nas.ServiceAccept{PDUSessionStatus: &status, PDUSessionReactivationResult: &result},
	}
	raw, err := nas.Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := nas.Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	sa, ok := dec.Body.(*nas.ServiceAccept)
	if !ok {
		t.Fatalf("body type %T", dec.Body)
	}
	if sa.PDUSessionStatus == nil || *sa.PDUSessionStatus != status {
		t.Errorf("PDUSessionStatus = %v, want %04X", sa.PDUSessionStatus, status)
	}
	if sa.PDUSessionReactivationResult == nil || *sa.PDUSessionReactivationResult != result {
		t.Errorf("PDUSessionReactivationResult = %v, want %04X", sa.PDUSessionReactivationResult, result)
	}
}

func TestDecodeServiceAccept_SkipsUnknownAndTLVE(t *testing.T) {
	// 0x72 error cause (TLV-E, 2 octets: PSI 2 cause #92) then 0x50 status.
	b := []byte{0x72, 0x00, 0x02, 0x02, 0x5C, 0x50, 0x02, 0x02, 0x00}
	sa, err := nas.DecodeServiceAccept(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sa.PDUSessionStatus == nil || *sa.PDUSessionStatus != nas.PSIMask(1) {
		t.Errorf("PDUSessionStatus = %v", sa.PDUSessionStatus)
	}
	if sa.PDUSessionReactivationResult != nil {
		t.Errorf("unexpected reactivation result")
	}
	if _, err := nas.DecodeServiceAccept([]byte{0x50, 0x02, 0x02}); err == nil {
		t.Error("expected error on truncated IE")
	}
}
