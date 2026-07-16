package nasmsg

// security_header_test.go — regression tests for the DL NAS security header
// type selected by sendNASSecured.
//
// Once the 5G NAS security context is active, every downlink NAS message MUST be
// sent as "integrity protected and ciphered" (SHT=0x02) per TS 24.501 §4.4.5 —
// including when the selected ciphering algorithm is 5G-EA0 (null cipher), where
// the ciphering is a no-op but the security header type stays 0x02. A regression
// that downgrades to SHT=0x01 (integrity only) under NEA0 is silently tolerated
// by UERANSIM but makes real UEs (e.g. Nokia) discard the Registration Accept,
// breaking Registration Complete and the whole registration.

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestSendNASSecured_SecurityHeaderTypeAlways02(t *testing.T) {
	cases := []struct {
		name      string
		cipherAlg byte
	}{
		{"NEA0 null cipher", 0}, // the regression: must still be SHT=0x02
		{"NEA2 AES-CTR", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(&fakeSender{})
			ue := newTestUE(t)
			ue.SecurityCtx.CipheringAlgID = tc.cipherAlg
			ue.SecurityCtx.KNASenc = bytes.Repeat([]byte{0x00}, 16)

			pdu, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
				nas.MsgTypeRegistrationReject, &nas.RegistrationReject{Cause5GMM: 0x49})
			if err != nil {
				t.Fatalf("sendNASSecured: %v", err)
			}
			if len(pdu) < 7 {
				t.Fatalf("secured PDU too short: %d bytes", len(pdu))
			}
			got := nas.SecurityHeaderType(pdu[1] & 0x0F)
			if got != nas.SecurityHeaderIntegrityProtectedAndCiphered {
				t.Fatalf("SHT = 0x%02x, want 0x02 (integrity protected and ciphered) per "+
					"TS 24.501 §4.4.5; real UEs discard SHT=0x01 post-SMC", byte(got))
			}
		})
	}
}
