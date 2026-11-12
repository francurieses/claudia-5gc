package nas_test

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestReactivationResultErrorCause(t *testing.T) {
	list := []nas.PDUSessionErrorCause{{PDUSessionID: 5, Cause5GMM: 28}, {PDUSessionID: 6, Cause5GMM: 43}}
	if got, want := nas.EncodePDUSessionReactivationResultErrorCause(list), []byte{0x72, 0, 4, 5, 28, 6, 43}; !bytes.Equal(got, want) {
		t.Fatalf("got %X want %X", got, want)
	}
	if nas.EncodePDUSessionReactivationResultErrorCause(nil) != nil {
		t.Fatal("empty must be absent")
	}
	if got := nas.NewPDUSessionReactivationResult(5, 9); !bytes.Equal(got, []byte{0x20, 0x02}) {
		t.Fatalf("result %X", got)
	}
}

func TestRegistrationAcceptErrorCauseGolden(t *testing.T) {
	base := &nas.RegistrationAccept{PDUSessionReactivationResult: nas.NewPDUSessionReactivationResult(5)}
	legacy, err := nas.EncodeRegistrationAccept(base)
	if err != nil {
		t.Fatal(err)
	}
	with := *base
	with.PDUSessionReactivationResultErrorCause = []nas.PDUSessionErrorCause{{PDUSessionID: 5, Cause5GMM: 28}}
	enc, err := nas.EncodeRegistrationAccept(&with)
	if err != nil {
		t.Fatal(err)
	}
	ie := []byte{0x72, 0, 2, 5, 28}
	if !bytes.Contains(enc, append([]byte{0x26, 2, 0x20, 0x00}, ie...)) {
		t.Fatalf("IE not right after 0x26: %X", enc)
	}
	if !bytes.Equal(bytes.Replace(enc, ie, nil, 1), legacy) {
		t.Fatal("legacy bytes changed")
	}
	dec, err := nas.DecodeRegistrationAccept(enc)
	if err != nil || len(dec.PDUSessionReactivationResultErrorCause) != 1 || dec.PDUSessionReactivationResultErrorCause[0].Cause5GMM != 28 {
		t.Fatalf("decode: %v %+v", err, dec)
	}
}

func TestServiceAcceptErrorCause(t *testing.T) {
	r := uint16(0x0020)
	a := &nas.ServiceAccept{PDUSessionReactivationResult: &r,
		PDUSessionReactivationResultErrorCause: []nas.PDUSessionErrorCause{{PDUSessionID: 5, Cause5GMM: 69}}}
	b, err := nas.EncodeServiceAccept(a)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x26, 2, 0, 0x20, 0x72, 0, 2, 5, 69}; !bytes.Equal(b, want) {
		t.Fatalf("got %X", b)
	}
	d, err := nas.DecodeServiceAccept(b)
	if err != nil || len(d.PDUSessionReactivationResultErrorCause) != 1 || *d.PDUSessionReactivationResult != r {
		t.Fatalf("decode %v %+v", err, d)
	}
}
