package nasmsg

import (
	"bytes"
	"errors"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// ueMAC is the UE-side NAS-MAC with the reference nia functions.
func ueMAC(t *testing.T, alg byte, key []byte, count uint32, dir byte, msg []byte) []byte {
	t.Helper()
	f := map[byte]func([]byte, uint32, byte, byte, []byte) ([]byte, error){
		1: nia.NIA1, 2: nia.NIA2, 3: nia.NIA3,
	}[alg]
	mac, err := f(key, count, 0x01, dir, msg)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}

// TestComputeNASMACDispatch: each NIA id selects its own algorithm (distinct
// MACs on the same input); NIA0 and unknown ids are errors, never a NIA2
// fallback. Ref: TS 33.501 §6.7.2, Annex D.3
func TestComputeNASMACDispatch(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 16)
	msg := []byte{0x03, 0x7e, 0x00, 0x5d, 0x02, 0x00}
	seen := map[string]byte{}
	for _, alg := range []byte{1, 2, 3} {
		got, err := computeNASMAC(alg, key, 9, nasDirDL, msg)
		if err != nil {
			t.Fatalf("NIA%d: %v", alg, err)
		}
		if want := ueMAC(t, alg, key, 9, nasDirDL, msg); !bytes.Equal(got, want) {
			t.Fatalf("NIA%d: MAC %x, want %x", alg, got, want)
		}
		if prev, dup := seen[string(got)]; dup {
			t.Fatalf("NIA%d and NIA%d give the same MAC %x", alg, prev, got)
		}
		seen[string(got)] = alg
	}
	for _, alg := range []byte{0, 4, 7} {
		if mac, err := computeNASMAC(alg, key, 9, nasDirDL, msg); err == nil || mac != nil {
			t.Fatalf("NIA%d: mac=%x err=%v, want error", alg, mac, err)
		}
	}
}

// TestDLIntegrityFollowsSelectedNIA: integrity-only (SMC path) and ciphered DL
// messages carry the MAC of the NIA selected in the SMC. An unsupported id
// sends nothing and does not advance the DL COUNT. Ref: TS 24.501 §4.4.3.1
func TestDLIntegrityFollowsSelectedNIA(t *testing.T) {
	plain := []byte{nas.PDMobilityManagement, 0x00, 0x42, 0xaa}
	for _, alg := range []byte{1, 2, 3} {
		h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
		ue.SecurityCtx.IntegrityAlgID = alg
		ue.SecurityCtx.KNASint = bytes.Repeat([]byte{0x20 + alg}, 16)
		ue.SecurityCtx.DownlinkCount = 4

		pdu, err := h.integrityProtectNAS(ue, plain, nas.SecurityHeaderIntegrityProtectedWithNewSC)
		if err != nil {
			t.Fatalf("NIA%d SMC: %v", alg, err)
		}
		if want := ueMAC(t, alg, ue.SecurityCtx.KNASint, 4, nasDirDL, pdu[6:]); !bytes.Equal(pdu[2:6], want) {
			t.Fatalf("NIA%d SMC: MAC %x, want %x", alg, pdu[2:6], want)
		}
		pdu, err = h.cipherProtectNAS(ue, plain)
		if err != nil {
			t.Fatalf("NIA%d ciphered: %v", alg, err)
		}
		if want := ueMAC(t, alg, ue.SecurityCtx.KNASint, 5, nasDirDL, pdu[6:]); !bytes.Equal(pdu[2:6], want) {
			t.Fatalf("NIA%d ciphered: MAC %x, want %x", alg, pdu[2:6], want)
		}
		if ue.SecurityCtx.DownlinkCount != 6 {
			t.Fatalf("NIA%d: DL COUNT %d, want 6", alg, ue.SecurityCtx.DownlinkCount)
		}
	}
	for _, alg := range []byte{0, 5} {
		h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
		ue.SecurityCtx.IntegrityAlgID = alg
		ue.SecurityCtx.DownlinkCount = 3
		if pdu, err := h.integrityProtectNAS(ue, plain, nas.SecurityHeaderIntegrityProtectedWithNewSC); err == nil || pdu != nil {
			t.Fatalf("NIA%d SMC: pdu=%x err=%v, want error", alg, pdu, err)
		}
		if pdu, err := h.cipherProtectNAS(ue, plain); err == nil || pdu != nil {
			t.Fatalf("NIA%d ciphered: pdu=%x err=%v, want error", alg, pdu, err)
		}
		if ue.SecurityCtx.DownlinkCount != 3 {
			t.Fatalf("NIA%d: DL COUNT advanced to %d", alg, ue.SecurityCtx.DownlinkCount)
		}
	}
}

// TestULIntegrityFollowsSelectedNIA: an UL message protected by the UE with
// the selected NIA1/NIA3 is accepted and advances the UL COUNT; the same
// message MAC-ed with NIA2 (the pre-SEC-007 behaviour) is rejected without
// advancing it. Ref: TS 24.501 §4.4.4.3; TS 33.501 §6.4.3
func TestULIntegrityFollowsSelectedNIA(t *testing.T) {
	inner := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationComplete), 0x00}
	build := func(alg byte, key []byte) []byte {
		mac := ueMAC(t, alg, key, 0, nasDirUL, append([]byte{0}, inner...))
		pdu := append([]byte{nas.PDMobilityManagement, byte(nas.SecurityHeaderIntegrityProtected)}, mac...)
		return append(append(pdu, 0), inner...)
	}
	for _, alg := range []byte{1, 3} {
		h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
		ue.SecurityCtx.IntegrityAlgID = alg
		ue.SecurityCtx.CipheringAlgID = 0
		ue.SecurityCtx.KNASint = bytes.Repeat([]byte{0x44}, 16)
		ue.SecurityCtx.UplinkCount = 0

		if _, err := h.unwrapWithContext(&ue.SecurityCtx, build(2, ue.SecurityCtx.KNASint)); !errors.Is(err, ErrNASIntegrity) {
			t.Fatalf("NIA%d selected, NIA2 MAC: err = %v, want ErrNASIntegrity", alg, err)
		}
		if ue.SecurityCtx.UplinkCount != 0 {
			t.Fatalf("NIA%d: UL COUNT advanced on a bad MAC", alg)
		}
		out, err := h.unwrapWithContext(&ue.SecurityCtx, build(alg, ue.SecurityCtx.KNASint))
		if err != nil {
			t.Fatalf("NIA%d: %v", alg, err)
		}
		if !bytes.HasSuffix(out, inner) {
			t.Fatalf("NIA%d: unwrapped %x does not carry %x", alg, out, inner)
		}
		if ue.SecurityCtx.UplinkCount != 1 {
			t.Fatalf("NIA%d: UL COUNT %d, want 1", alg, ue.SecurityCtx.UplinkCount)
		}
	}
}
