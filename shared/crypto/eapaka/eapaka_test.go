package eapaka

import (
	"encoding/hex"
	"testing"
)

// mustHex decodes a hex string or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// RFC 5448 Appendix C, Case 1 golden vector.
//
//	Identity     = "0555444333222111"
//	Network name = "WLAN"
//	SQN⊕AK       = AUTN[0:6] = bb52e91c747a
const (
	gvIdentity = "0555444333222111"
	gvNetwork  = "WLAN"
	gvAUTN     = "bb52e91c747ac3ab2a5c23d15ee351d5"
	gvCK       = "5349fbe098649f948f5d2e973a81c00f"
	gvIK       = "9744871ad32bf9bbd1dd5ce54e3e2e5a"
	gvCKPrime  = "0093962d0dd84aa5684b045c9edffa04"
	gvIKPrime  = "ccfc230ca74fcc96c0a5d61164f5a76c"
	gvKEncr    = "766fa0a6c317174b812d52fbcd11a179"
	gvKAut     = "0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea"
	gvKRe      = "cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a"
	gvMSK      = "67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a"
	gvEMSK     = "f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb"
)

func TestDeriveCKPrimeIKPrime_GoldenVector(t *testing.T) {
	var ck, ik [16]byte
	copy(ck[:], mustHex(t, gvCK))
	copy(ik[:], mustHex(t, gvIK))
	var sqnXorAK [6]byte
	copy(sqnXorAK[:], mustHex(t, gvAUTN)[:6])

	ckPrime, ikPrime := DeriveCKPrimeIKPrime(ck, ik, gvNetwork, sqnXorAK)

	if got := hex.EncodeToString(ckPrime[:]); got != gvCKPrime {
		t.Errorf("CK': got %s want %s", got, gvCKPrime)
	}
	if got := hex.EncodeToString(ikPrime[:]); got != gvIKPrime {
		t.Errorf("IK': got %s want %s", got, gvIKPrime)
	}
}

func TestDeriveKeys_GoldenVector(t *testing.T) {
	var ckPrime, ikPrime [16]byte
	copy(ckPrime[:], mustHex(t, gvCKPrime))
	copy(ikPrime[:], mustHex(t, gvIKPrime))

	keys := DeriveKeys(ckPrime, ikPrime, gvIdentity)

	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"K_encr", keys.KEncr, gvKEncr},
		{"K_aut", keys.KAut, gvKAut},
		{"K_re", keys.KRe, gvKRe},
		{"MSK", keys.MSK, gvMSK},
		{"EMSK", keys.EMSK, gvEMSK},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}

func TestKAUSFFromEMSK(t *testing.T) {
	emsk := mustHex(t, gvEMSK)
	kausf := KAUSFFromEMSK(emsk)
	if len(kausf) != 32 {
		t.Fatalf("KAUSF length: got %d want 32", len(kausf))
	}
	if got := hex.EncodeToString(kausf); got != gvEMSK[:64] {
		t.Errorf("KAUSF: got %s want %s", got, gvEMSK[:64])
	}
}

func TestChallengeResponseMACRoundTrip(t *testing.T) {
	var rand, autn [16]byte
	copy(rand[:], mustHex(t, "81e92b6c0ee0e12ebceba8d92a99dfa5"))
	copy(autn[:], mustHex(t, gvAUTN))
	kAut := mustHex(t, gvKAut)

	chal := BuildChallenge(7, rand, autn, gvNetwork, kAut)
	if err := Validate(chal); err != nil {
		t.Fatalf("challenge invalid: %v", err)
	}
	if chal[0] != CodeRequest || chal[4] != TypeEAPAKAPrime {
		t.Fatalf("challenge header wrong: code=%d type=%d", chal[0], chal[4])
	}
	if !VerifyMAC(chal, kAut) {
		t.Error("challenge AT_MAC failed self-verification")
	}

	// UE side: build a response with a known RES, verify AUSF can read + check it.
	res := mustHex(t, "28d7b0f2a2ec3de5")
	resp := BuildResponse(7, res, kAut)
	if err := Validate(resp); err != nil {
		t.Fatalf("response invalid: %v", err)
	}
	if !VerifyMAC(resp, kAut) {
		t.Error("response AT_MAC failed verification with correct key")
	}
	gotRES, err := ExtractRES(resp)
	if err != nil {
		t.Fatalf("ExtractRES: %v", err)
	}
	if hex.EncodeToString(gotRES) != hex.EncodeToString(res) {
		t.Errorf("RES: got %x want %x", gotRES, res)
	}

	// Tamper: flip a MAC byte → verification must fail.
	off, ok := findAttr(resp, atMAC)
	if !ok {
		t.Fatal("AT_MAC not found in response")
	}
	resp[off+4] ^= 0xff
	if VerifyMAC(resp, kAut) {
		t.Error("tampered AT_MAC unexpectedly verified")
	}
}

func TestBuildSuccessFailure(t *testing.T) {
	if got := BuildSuccess(3); len(got) != 4 || got[0] != CodeSuccess {
		t.Errorf("EAP-Success malformed: %x", got)
	}
	if got := BuildFailure(3); len(got) != 4 || got[0] != CodeFailure {
		t.Errorf("EAP-Failure malformed: %x", got)
	}
}
