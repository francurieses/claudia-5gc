package server

// udm_response_test.go - the AUSF decodes both Nudm_UEAU answer shapes
// whatever its own release profile (REL19-3.5 slice A).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/aka"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
)

func TestUDMAuthDataResponse_DecodesBothShapes(t *testing.T) {
	const (
		randHex = "000102030405060708090a0b0c0d0e0f"
		autnHex = "101112131415161718191a1b1c1d1e1f"
		xresStr = "202122232425262728292a2b2c2d2e2f"
		kausf   = "303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f"
		supi    = "imsi-001010000000001"
	)
	rb, _ := hex.DecodeString(randHex)
	xb, _ := hex.DecodeString(xresStr)
	wantHX := hex.EncodeToString(kdf.HRESStar([16]byte(rb), xb))
	const legacyHX = "ffffffffffffffffffffffffffffffff"

	tests := []struct {
		name string
		body string
		want UDMAuthDataResponse
	}{
		{name: "empty body", body: `{}`, want: UDMAuthDataResponse{}},
		{
			name: "nested 5G_HE_AKA, hxresStar derived",
			body: `{"authType":"5G_AKA","supportedFeatures":"0","authenticationVector":{"avType":"5G_HE_AKA","rand":"` + randHex +
				`","autn":"` + autnHex + `","xresStar":"` + xresStr + `","kausf":"` + kausf + `"},"supi":"` + supi + `"}`,
			want: UDMAuthDataResponse{AuthType: "5G_AKA", Rand: randHex, Autn: autnHex, XresStar: xresStr,
				HxresStar: wantHX, Kausf: kausf, Supi: supi, SupportedFeatures: "0"},
		},
		{
			name: "nested ignores flat hxresStar leftover",
			body: `{"authType":"5G_AKA","hxresStar":"` + legacyHX + `","authenticationVector":{"avType":"5G_HE_AKA","rand":"` + randHex +
				`","autn":"` + autnHex + `","xresStar":"` + xresStr + `","kausf":"` + kausf + `"},"supi":"` + supi + `"}`,
			want: UDMAuthDataResponse{AuthType: "5G_AKA", Rand: randHex, Autn: autnHex, XresStar: xresStr,
				HxresStar: wantHX, Kausf: kausf, Supi: supi},
		},
		{
			name: "flat 5G_AKA keeps UDM hxresStar",
			body: `{"authType":"5G_AKA","rand":"` + randHex + `","autn":"` + autnHex + `","xresStar":"` + xresStr +
				`","hxresStar":"` + legacyHX + `","kausf":"` + kausf + `","supi":"` + supi + `"}`,
			want: UDMAuthDataResponse{AuthType: "5G_AKA", Rand: randHex, Autn: autnHex, XresStar: xresStr,
				HxresStar: legacyHX, Kausf: kausf, Supi: supi},
		},
		{
			name: "flat 5G_AKA without hxresStar derives it",
			body: `{"authType":"5G_AKA","rand":"` + randHex + `","autn":"` + autnHex + `","xresStar":"` + xresStr +
				`","kausf":"` + kausf + `","supi":"` + supi + `"}`,
			want: UDMAuthDataResponse{AuthType: "5G_AKA", Rand: randHex, Autn: autnHex, XresStar: xresStr,
				HxresStar: wantHX, Kausf: kausf, Supi: supi},
		},
		{
			name: "nested EAP_AKA_PRIME",
			body: `{"authType":"EAP_AKA_PRIME","authenticationVector":{"avType":"EAP_AKA_PRIME","rand":"` + randHex + `","autn":"` + autnHex +
				`","xres":"2021222324252627","ckPrime":"aa","ikPrime":"bb"},"supi":"` + supi + `"}`,
			want: UDMAuthDataResponse{AuthType: "EAP_AKA_PRIME", Rand: randHex, Autn: autnHex,
				Xres: "2021222324252627", CkPrime: "aa", IkPrime: "bb", Supi: supi},
		},
		{
			name: "flat EAP_AKA_PRIME",
			body: `{"authType":"EAP_AKA_PRIME","rand":"` + randHex + `","autn":"` + autnHex +
				`","xres":"2021222324252627","ckPrime":"aa","ikPrime":"bb","supi":"` + supi + `"}`,
			want: UDMAuthDataResponse{AuthType: "EAP_AKA_PRIME", Rand: randHex, Autn: autnHex,
				Xres: "2021222324252627", CkPrime: "aa", IkPrime: "bb", Supi: supi},
		},
		{
			name: "nested without authType maps avType",
			body: `{"authenticationVector":{"avType":"5G_HE_AKA","rand":"` + randHex + `","autn":"` + autnHex +
				`","xresStar":"` + xresStr + `","kausf":"` + kausf + `"}}`,
			want: UDMAuthDataResponse{AuthType: "5G_AKA", Rand: randHex, Autn: autnHex, XresStar: xresStr,
				HxresStar: wantHX, Kausf: kausf},
		},
		{
			name: "bad rand leaves hxresStar empty",
			body: `{"authType":"5G_AKA","rand":"zz","xresStar":"` + xresStr + `"}`,
			want: UDMAuthDataResponse{AuthType: "5G_AKA", Rand: "zz", XresStar: xresStr},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got UDMAuthDataResponse
			if err := json.Unmarshal([]byte(tc.body), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestUDMAuthDataResponse_RejectsMalformedJSON(t *testing.T) {
	var got UDMAuthDataResponse
	if err := json.Unmarshal([]byte(`{"authType":5}`), &got); err == nil {
		t.Fatal("want decode error for non-string authType")
	}
}

// TestUDMAuthDataResponse_DerivedHXRESMatchesUDM pins that the AUSF-derived
// HXRES* equals the value the Rel-17-profile UDM sends (aka.GenerateFull).
func TestUDMAuthDataResponse_DerivedHXRESMatchesUDM(t *testing.T) {
	heav, err := aka.GenerateFull(testHEAVInput, testSNName)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(AuthenticationInfoResult{
		AuthType: authType5GAKA,
		AuthenticationVector: &AuthenticationVector{
			AvType: avType5GHEAKA, Rand: hex.EncodeToString(heav.RAND[:]), Autn: hex.EncodeToString(heav.AUTN[:]),
			XresStar: hex.EncodeToString(heav.XRESStar), Kausf: hex.EncodeToString(heav.KAUSF),
		},
		Supi: "imsi-001010000000099",
	})
	var got UDMAuthDataResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if want := hex.EncodeToString(heav.HRESStar); got.HxresStar != want {
		t.Fatalf("hxresStar = %s, want %s", got.HxresStar, want)
	}
}

// TestDeriveHXRESStarKnownAnswer pins HXRES* = last 16 bytes of
// SHA-256(RAND || XRES*) (TS 33.501 Annex A.5), computed here independently of
// the kdf helper. The fixed vector is also asserted literally so a change of
// both the helper and this recomputation cannot go unnoticed.
func TestDeriveHXRESStarKnownAnswer(t *testing.T) {
	const (
		randHex = "000102030405060708090a0b0c0d0e0f"
		xresHex = "202122232425262728292a2b2c2d2e2f"
	)
	rb, _ := hex.DecodeString(randHex)
	xb, _ := hex.DecodeString(xresHex)
	sum := sha256.Sum256(append(append([]byte{}, rb...), xb...))
	want := hex.EncodeToString(sum[16:])
	if got := deriveHXRESStar(randHex, xresHex); got != want {
		t.Fatalf("deriveHXRESStar = %s, want %s", got, want)
	}
	if want != knownHXRESStar {
		t.Fatalf("independent recomputation = %s, fixed vector %s", want, knownHXRESStar)
	}
}

// knownHXRESStar is SHA-256(RAND||XRES*)[16:] for the vector above.
const knownHXRESStar = "acc5770d8e61512db590e08855d7ad43"

// rawUDM returns a fixed decoded answer, standing in for the HTTP UDM client.
type rawUDM struct{ body string }

func (m rawUDM) GenerateAuthData(context.Context, string, *UDMAuthDataRequest) (*UDMAuthDataResponse, error) {
	var r UDMAuthDataResponse
	if err := json.Unmarshal([]byte(m.body), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// TestAuthenticate_InvalidNestedVector checks that a nested 5G_HE_AKA vector
// with a missing, non-hex or wrong-length element is answered 500 NF_FAILURE
// and that no authentication context is stored.
func TestAuthenticate_InvalidNestedVector(t *testing.T) {
	const (
		randHex = "000102030405060708090a0b0c0d0e0f"
		autnHex = "101112131415161718191a1b1c1d1e1f"
		xresStr = "202122232425262728292a2b2c2d2e2f"
		kausf   = "303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f"
	)
	vec := func(rand, autn, xres, ks string) string {
		return `{"authType":"5G_AKA","authenticationVector":{"avType":"5G_HE_AKA","rand":"` + rand + `","autn":"` + autn +
			`","xresStar":"` + xres + `","kausf":"` + ks + `"},"supi":"imsi-001010000000001"}`
	}
	tests := []struct {
		name, body string
		wantStatus int
	}{
		{"valid", vec(randHex, autnHex, xresStr, kausf), http.StatusCreated},
		{"empty xresStar", vec(randHex, autnHex, "", kausf), http.StatusInternalServerError},
		{"non-hex xresStar", vec(randHex, autnHex, "zz"+xresStr[2:], kausf), http.StatusInternalServerError},
		{"short xresStar", vec(randHex, autnHex, xresStr[:16], kausf), http.StatusInternalServerError},
		{"missing kausf", vec(randHex, autnHex, xresStr, ""), http.StatusInternalServerError},
		{"non-hex kausf", vec(randHex, autnHex, xresStr, strings.Repeat("g", 64)), http.StatusInternalServerError},
		{"short kausf", vec(randHex, autnHex, xresStr, kausf[:32]), http.StatusInternalServerError},
		{"short autn", vec(randHex, autnHex[:30], xresStr, kausf), http.StatusInternalServerError},
		{"empty object", `{}`, http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &countingStore{Store: aka.NewStore()}
			srv, err := New(Config{ServingNetworkName: testSNName}, rawUDM{tc.body}, store,
				slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()
			resp, err := http.Post(ts.URL+"/nausf-auth/v1/ue-authentications", "application/json",
				strings.NewReader(`{"supiOrSuci":"imsi-001010000000001","servingNetworkName":"`+testSNName+`"}`))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusInternalServerError {
				var pd struct {
					Cause string `json:"cause"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&pd)
				if pd.Cause != "NF_FAILURE" {
					t.Fatalf("cause %q, want NF_FAILURE", pd.Cause)
				}
				if store.puts != 0 {
					t.Fatalf("%d auth contexts stored, want 0", store.puts)
				}
			} else if store.puts != 1 {
				t.Fatalf("%d auth contexts stored, want 1", store.puts)
			}
		})
	}
}

// countingStore counts Put calls on top of the in-memory store.
type countingStore struct {
	*aka.Store
	puts int
}

func (c *countingStore) Put(id string, ctx *aka.AuthContext) {
	c.puts++
	c.Store.Put(id, ctx)
}
