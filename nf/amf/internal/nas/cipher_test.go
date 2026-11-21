package nasmsg

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// ueCipher is the UE-side reference: it calls the shared algorithms directly
// (not cipherNAS) so the AMF dispatch is checked against an independent path.
func ueCipher(t *testing.T, alg byte, key []byte, count uint32, dir byte, msg []byte) []byte {
	t.Helper()
	var out []byte
	var err error
	switch alg {
	case 1:
		out, err = nea.NEA1(key, count, 0x01, dir, msg)
	case 2:
		out, err = nea.NEA2(key, count, 0x01, dir, msg)
	case 3:
		out, err = nea.NEA3(key, count, 0x01, dir, msg)
	default:
		t.Fatalf("bad alg %d", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCipherNASDispatch: identity for NEA0, each algorithm equals the direct
// call, an unknown id is an error with no output (no fallback to NEA2).
// Ref: TS 33.501 §5.11.1.1, Annex D.2
func TestCipherNASDispatch(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 16)
	msg := []byte{0x7e, 0x00, 0x42, 0x01, 0x02, 0x03}
	if got, err := cipherNAS(0, key, 1, nasDirDL, msg); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("NEA0 = %x, %v", got, err)
	}
	for _, alg := range []byte{1, 2, 3} {
		got, err := cipherNAS(alg, key, 9, nasDirDL, msg)
		if err != nil || !bytes.Equal(got, ueCipher(t, alg, key, 9, nasDirDL, msg)) || bytes.Equal(got, msg) {
			t.Fatalf("NEA%d = %x, %v", alg, got, err)
		}
	}
	for _, alg := range []byte{4, 5, 7, 0xff} {
		if got, err := cipherNAS(alg, key, 9, nasDirDL, msg); err == nil || got != nil {
			t.Fatalf("NEA%d: got %x err %v, want error and no output", alg, got, err)
		}
	}
}

// TestCipherProtectNASDLRoundTrip: cipherProtectNAS ciphers DL (dir 1) with the
// negotiated NEA and the UE-side decipher recovers the plain message; the MAC
// is over the ciphertext. Unknown id: error, COUNT not advanced.
// Ref: TS 24.501 §4.4.5; TS 33.501 §6.4.4, Annex D.3
func TestCipherProtectNASDLRoundTrip(t *testing.T) {
	plain := []byte{nas.PDMobilityManagement, 0x00, 0x42, 0xaa, 0xbb, 0xcc}
	for _, alg := range []byte{1, 2, 3} {
		h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
		ue.SecurityCtx.CipheringAlgID = alg
		ue.SecurityCtx.KNASenc = bytes.Repeat([]byte{0x11 * alg}, 16)
		ue.SecurityCtx.DownlinkCount = 7
		pdu, err := h.cipherProtectNAS(ue, plain)
		if err != nil {
			t.Fatalf("NEA%d: %v", alg, err)
		}
		if pdu[1] != byte(nas.SecurityHeaderIntegrityProtectedAndCiphered) {
			t.Fatalf("NEA%d: SHT %#x", alg, pdu[1])
		}
		if got := ueCipher(t, alg, ue.SecurityCtx.KNASenc, 7, nasDirDL, pdu[7:]); !bytes.Equal(got, plain) {
			t.Fatalf("NEA%d: UE decipher = %x, want %x", alg, got, plain)
		}
		mac, err := nia.NIA2(ue.SecurityCtx.KNASint, 7, 0x01, 0x01, append([]byte{pdu[6]}, pdu[7:]...))
		if err != nil || !bytes.Equal(mac, pdu[2:6]) {
			t.Fatalf("NEA%d: MAC not over ciphertext (%x vs %x, %v)", alg, mac, pdu[2:6], err)
		}
		if ue.SecurityCtx.DownlinkCount != 8 {
			t.Fatalf("NEA%d: DL COUNT %d", alg, ue.SecurityCtx.DownlinkCount)
		}
	}
	h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
	ue.SecurityCtx.CipheringAlgID = 5
	ue.SecurityCtx.DownlinkCount = 3
	if pdu, err := h.cipherProtectNAS(ue, plain); err == nil || pdu != nil || ue.SecurityCtx.DownlinkCount != 3 {
		t.Fatalf("unknown NEA: pdu=%x err=%v count=%d", pdu, err, ue.SecurityCtx.DownlinkCount)
	}
}

// TestUnwrapULDecipherNEA1NEA3: a UL SHT-2 message ciphered by the UE with NEA1 /
// NEA3 (dir 0) is MAC-verified over the ciphertext and deciphered; an unknown id
// is rejected without a plaintext result. Ref: TS 24.501 §4.4.4; TS 33.501 D.2
func TestUnwrapULDecipherNEA1NEA3(t *testing.T) {
	for _, alg := range []byte{1, 3} {
		h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
		ue.SecurityCtx.CipheringAlgID = alg
		ue.SecurityCtx.KNASenc = bytes.Repeat([]byte{0x33}, 16)
		ue.SecurityCtx.UplinkCount = 0
		sc := ue.SecurityCtx
		inner := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationComplete), 0x00}
		ct := ueCipher(t, alg, sc.KNASenc, 0, nasDirUL, inner)
		mac, err := nia.NIA2(sc.KNASint, 0, 0x01, 0x00, append([]byte{0}, ct...))
		if err != nil {
			t.Fatal(err)
		}
		pdu := append(append([]byte{nas.PDMobilityManagement, byte(nas.SecurityHeaderIntegrityProtectedAndCiphered)}, mac...), 0)
		pdu = append(pdu, ct...)
		out, err := h.unwrapWithContext(&ue.SecurityCtx, pdu)
		if err != nil {
			t.Fatalf("NEA%d: %v", alg, err)
		}
		if !bytes.HasSuffix(out, inner) {
			t.Fatalf("NEA%d: unwrapped %x does not carry %x", alg, out, inner)
		}
	}
	h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
	ue.SecurityCtx.CipheringAlgID = 6
	pdu := buildULAt(t, ue.SecurityCtx, 0, true, nas.MsgTypeRegistrationComplete, []byte{0})
	if out, err := h.unwrapWithContext(&ue.SecurityCtx, pdu); err == nil && out != nil {
		t.Fatalf("unknown NEA accepted: %x", out)
	}
}
