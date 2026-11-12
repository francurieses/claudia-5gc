package server

// suci_test.go - SIDF de-concealment of the standard SUCI string (TS 29.571
// §5.3.2) in GenerateAuthData. Ref: TS 33.501 §6.12, Annex C; TS 29.503 §5.2.2.2.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	suciPkg "github.com/francurieses/claudia-5gc/shared/crypto/suci"
)

// recUDR records the SUPI the UDM asked the UDR for.
type recUDR struct {
	goldenUDR
	supi string
}

func (u *recUDR) GetAuthSubscription(ctx_ context.Context, supi string) (*UDRAuthSub, error) {
	u.supi = supi
	return u.goldenUDR.GetAuthSubscription(ctx_, supi)
}

func postSUCI(t *testing.T, s *Server, suci string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/"+suci+"/security-information/generate-auth-data",
		bytes.NewBufferString(`{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(b)
}

// encryptProfileB builds the Profile B SUCI scheme output (compressed ephemeral
// key || ciphertext || MAC) per TS 33.501 Annex C.3.4.
func encryptProfileB(t *testing.T, msin string, hn *ecdh.PublicKey) string {
	t.Helper()
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := eph.ECDH(hn)
	if err != nil {
		t.Fatal(err)
	}
	// compressed ephemeral public key from the uncompressed SEC1 encoding
	raw := eph.PublicKey().Bytes()
	comp := append([]byte{0x02 | raw[64]&1}, raw[1:33]...)
	var kdf []byte
	for c := uint32(1); len(kdf) < 64; c++ {
		h := sha256.New()
		h.Write(shared)
		h.Write([]byte{byte(c >> 24), byte(c >> 16), byte(c >> 8), byte(c)})
		h.Write(comp)
		kdf = append(kdf, h.Sum(nil)...)
	}
	bcd := make([]byte, (len(msin)+1)/2)
	for i := 0; i < len(msin); i++ {
		d := msin[i] - '0'
		if i%2 == 0 {
			bcd[i/2] |= d
		} else {
			bcd[i/2] |= d << 4
		}
	}
	if len(msin)%2 == 1 {
		bcd[len(bcd)-1] |= 0xF0
	}
	blk, _ := aes.NewCipher(kdf[:16])
	ct := make([]byte, len(bcd))
	cipher.NewCTR(blk, kdf[16:32]).XORKeyStream(ct, bcd)
	m := hmac.New(sha256.New, kdf[32:64])
	m.Write(ct)
	out := append(append(comp, ct...), m.Sum(nil)[:8]...)
	return hex.EncodeToString(out)
}

func TestGenerateAuthData_SUCIDeconceal(t *testing.T) {
	var privA [32]byte
	if _, err := rand.Read(privA[:]); err != nil {
		t.Fatal(err)
	}
	xk, err := ecdh.X25519().NewPrivateKey(privA[:])
	if err != nil {
		t.Fatal(err)
	}
	var pubA [32]byte
	copy(pubA[:], xk.PublicKey().Bytes())
	encA, err := suciPkg.EncryptProfileA("0000000001", pubA, 1)
	if err != nil {
		t.Fatal(err)
	}
	outA := hex.EncodeToString(encA.SchemeOutput)

	pk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	outB := encryptProfileB(t, "0000000001", pk.PublicKey())
	bad := outB[:len(outB)-2] + "00" // corrupt MAC

	tests := []struct {
		name       string
		suci       string
		cfgB       bool
		idA, idB   uint8
		wantStatus int
		wantCause  string
		wantSUPI   string
	}{
		{"null scheme", "suci-0-001-01-0000-0-0-0000000001", false, 0, 0, 200, "", "imsi-001010000000001"},
		{"profile A", "suci-0-001-01-0000-1-1-" + outA, false, 0, 0, 200, "", "imsi-001010000000001"},
		{"profile A matching key id", "suci-0-001-01-0000-1-1-" + outA, false, 1, 0, 200, "", "imsi-001010000000001"},
		{"profile A key id mismatch", "suci-0-001-01-0000-1-1-" + outA, false, 7, 0, 403, "INVALID_HN_PUBLIC_KEY_IDENTIFIER", ""},
		{"profile B", "suci-0-001-01-0000-2-2-" + outB, true, 0, 2, 200, "", "imsi-001010000000001"},
		{"profile B key id mismatch", "suci-0-001-01-0000-2-3-" + outB, true, 0, 2, 403, "INVALID_HN_PUBLIC_KEY_IDENTIFIER", ""},
		{"profile B bad MAC", "suci-0-001-01-0000-2-2-" + bad, true, 0, 0, 403, "INVALID_SCHEME_OUTPUT", ""},
		{"profile B not configured", "suci-0-001-01-0000-2-2-" + outB, false, 0, 0, 501, "UNSUPPORTED_PROTECTION_SCHEME", ""},
		{"unknown scheme", "suci-0-001-01-0000-3-1-" + outA, false, 0, 0, 501, "UNSUPPORTED_PROTECTION_SCHEME", ""},
		{"NAI SUPI type", "suci-1-example.com-0000-0-0-user", false, 0, 0, 501, "", ""},
		{"legacy private format", "suci-00101-0000-0-0-0000000010", false, 0, 0, 400, "MANDATORY_IE_INCORRECT", ""},
		{"malformed", "suci-0-001-01-0000-1-1-zz", false, 0, 0, 400, "MANDATORY_IE_INCORRECT", ""},
		{"profile A truncated output", "suci-0-001-01-0000-1-1-aabb", false, 0, 0, 403, "INVALID_SCHEME_OUTPUT", ""},
		{"oversized", "suci-0-001-01-0000-1-1-" + strings.Repeat("ab", 3000), false, 0, 0, 400, "MANDATORY_IE_INCORRECT", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			udr := &recUDR{goldenUDR: goldenUDR{method: "5G_AKA"}}
			s, err := New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org", TLSConfig{}, udr, discardLogger())
			if err != nil {
				t.Fatal(err)
			}
			if err := s.WithHomeNetPrivKeyA(hex.EncodeToString(privA[:])); err != nil {
				t.Fatal(err)
			}
			if tc.cfgB {
				if err := s.WithHomeNetPrivKeyB(hex.EncodeToString(pk.Bytes())); err != nil {
					t.Fatal(err)
				}
			}
			s.WithHNKeyIDs(tc.idA, tc.idB)
			code, body := postSUCI(t, s, tc.suci)
			if code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", code, tc.wantStatus, body)
			}
			if tc.wantCause != "" && !strings.Contains(body, tc.wantCause) {
				t.Fatalf("body %s lacks cause %s", body, tc.wantCause)
			}
			if tc.wantStatus == http.StatusNotImplemented && tc.wantCause == "" && strings.Contains(body, `"cause"`) {
				t.Fatalf("501 without a TS 29.503 cause must omit the cause attribute: %s", body)
			}
			// No ProblemDetails may echo the SUCI (MSIN / scheme output).
			if tc.wantStatus != 200 {
				for _, frag := range []string{tc.suci, "0000000001", "example.com", "-zz"} {
					if strings.Contains(body, frag) {
						t.Fatalf("body %s leaks %q", body, frag)
					}
				}
				var pd struct {
					Detail        string              `json:"detail"`
					InvalidParams []map[string]string `json:"invalidParams"`
				}
				if err := json.Unmarshal([]byte(body), &pd); err != nil {
					t.Fatal(err)
				}
				if tc.wantStatus == 400 && (len(pd.InvalidParams) != 1 || pd.InvalidParams[0]["param"] != "supiOrSuci") {
					t.Fatalf("400 lacks invalidParams supiOrSuci: %s", body)
				}
				if tc.wantStatus != 400 && pd.InvalidParams != nil {
					t.Fatalf("non-400 carries invalidParams: %s", body)
				}
				if tc.wantCause == "INVALID_SCHEME_OUTPUT" && pd.Detail != detailInvalidSchemeOutput {
					t.Fatalf("detail = %q, want fixed %q", pd.Detail, detailInvalidSchemeOutput)
				}
			}
			if tc.wantSUPI != "" && udr.supi != tc.wantSUPI {
				t.Fatalf("UDR queried for %q, want %q", udr.supi, tc.wantSUPI)
			}
		})
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestWithHomeNetPrivKeyB_RejectsInvalidScalar: zero and >= n scalars are
// refused at load time.
func TestWithHomeNetPrivKeyB_RejectsInvalidScalar(t *testing.T) {
	s, err := New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org", TLSConfig{}, &recUDR{}, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]string{
		"zero":  strings.Repeat("00", 32),
		"n":     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"ff":    strings.Repeat("ff", 32),
		"short": "01",
	} {
		if err := s.WithHomeNetPrivKeyB(k); err == nil {
			t.Errorf("%s scalar accepted", name)
		}
	}
	if s.homeNetPrivKeyB != nil {
		t.Fatal("invalid key stored")
	}
}
