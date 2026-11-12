package nasmsg

import (
	"bytes"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
)

// TestDecipherNASContainer covers the algorithm choice and the no-silent-fallback
// rule of TS 24.501 §4.4.6: NEA0 plain, NEA2 deciphered, a plain container under a
// non-null cipher refused, NEA1/NEA3 (no shared implementation) an error.
func TestDecipherNASContainer(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	inner := []byte{0x7E, 0x00, 0x41, 0x01, 0x02}
	enc, err := nea.NEA2(key, 5, 0x01, 0x00, inner)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(alg uint8, k []byte) *amfctx.UEContext {
		ue := &amfctx.UEContext{}
		ue.SecurityCtx.CipheringAlgID = alg
		ue.SecurityCtx.KNASenc = k
		return ue
	}
	tests := []struct {
		name    string
		ue      *amfctx.UEContext
		in      []byte
		wantErr bool
	}{
		{"NEA0 plain", mk(0, nil), inner, false},
		{"NEA2 ciphered", mk(2, key), enc, false},
		{"NEA2 plaintext container refused", mk(2, key), inner, true},
		{"NEA2 no key", mk(2, nil), enc, true},
		{"NEA1 unsupported", mk(1, key), enc, true},
		{"NEA3 unsupported", mk(3, key), enc, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decipherNASContainer(tc.ue, tc.in, 5)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && !bytes.Equal(got, inner) {
				t.Fatalf("plain = %x, want %x", got, inner)
			}
			if err != nil && got != nil {
				t.Fatalf("plain = %x on error, want nil", got)
			}
		})
	}
}
