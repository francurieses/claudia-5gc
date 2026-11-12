package main

// ausf_decode_test.go - drift-amf: decoding of the Nausf_UEAuthentication 201
// answer (UEAuthenticationCtx). TS 29.509 carries the 5G AV in 5gAuthData
// (Av5gAka: rand, hxresStar, autn, each 32 hex characters); the project AUSF
// still sends the legacy flat members. Both shapes must decode, and a missing,
// short or non-hex vector must be an error, never a panic (the slice to [16]byte
// conversion used to panic on such an answer).
// Ref: TS 29.509 §6.1.6.2.3 (UEAuthenticationCtx), Av5gAka; TS29509_Nausf_UEAuthentication.yaml.

import (
	"bytes"
	"net/http"
	"testing"
)

const (
	avRand  = "00112233445566778899aabbccddeeff"
	avAutn  = "ffeeddccbbaa99887766554433221100"
	avHxres = "0123456789abcdef0123456789abcdef"
)

func TestAUSFAuthCtxDecode(t *testing.T) {
	tests := []struct {
		name    string
		answer  string
		wantErr bool
	}{
		{"spec shape: Av5gAka in 5gAuthData, unknown Rel-19 members ignored",
			`{"authType":"5G_AKA","5gAuthData":{"rand":"` + avRand + `","hxresStar":"` + avHxres + `","autn":"` + avAutn +
				`","futureAttr":1},"_links":{"5g-aka":{"href":"x"}},"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org","rel20Ext":{"a":true}}`,
			false},
		{"legacy flat shape (project AUSF, rel17 baseline)",
			`{"authType":"5G_AKA","_links":{"5g-aka":{"href":"x"}},"rand":"` + avRand + `","autn":"` + avAutn +
				`","hxresStar":"` + avHxres + `","supi":"imsi-001010000000001"}`,
			false},
		{"legacy members next to an empty 5gAuthData",
			`{"authType":"5G_AKA","5gAuthData":{},"_links":{"5g-aka":{"href":"x"}},"rand":"` + avRand + `","autn":"` + avAutn +
				`","hxresStar":"` + avHxres + `"}`,
			false},
		{"no vector at all", `{"authType":"5G_AKA","_links":{"5g-aka":{"href":"x"}}}`, true},
		{"rand too short", `{"authType":"5G_AKA","5gAuthData":{"rand":"0011","hxresStar":"` + avHxres + `","autn":"` + avAutn + `"},"_links":{}}`, true},
		{"autn not hex", `{"authType":"5G_AKA","5gAuthData":{"rand":"` + avRand + `","hxresStar":"` + avHxres + `","autn":"zz` + avAutn[2:] + `"},"_links":{}}`, true},
		{"hxresStar missing", `{"authType":"5G_AKA","5gAuthData":{"rand":"` + avRand + `","autn":"` + avAutn + `"},"_links":{}}`, true},
		{"EAP payload instead of an AV", `{"authType":"EAP_AKA_PRIME","5gAuthData":"AQIDBA==","_links":{"eap-session":{"href":"x"}}}`, true},
		{"5gAuthData of the wrong JSON type", `{"authType":"5G_AKA","5gAuthData":[1,2],"_links":{}}`, true},
	}
	for _, call := range []string{"initiate", "resync"} {
		for _, tc := range tests {
			t.Run(call+"/"+tc.name, func(t *testing.T) {
				addr, _, hc := captureServer(t, http.StatusCreated, tc.answer, "https://ausf/nausf-auth/v1/ue-authentications/ctx-1")
				_, lg := newLogs()
				c := &HTTPAUSFClient{address: addr, client: hc, profile: testProfile(t, "rel17"), logger: lg}
				var (
					got interface {
						vec() ([16]byte, [16]byte, []byte)
					}
					err error
				)
				if call == "initiate" {
					r, e := c.InitiateAuth(t.Context(), goldenSUCI, goldenSN)
					err = e
					if r != nil {
						got = initResp{r.RAND, r.AUTN, r.HXRESStar}
					}
				} else {
					r, e := c.ResyncAuth(t.Context(), goldenSUCI, goldenSN, [16]byte{}, []byte{1, 2})
					err = e
					if r != nil {
						got = initResp{r.RAND, r.AUTN, r.HXRESStar}
					}
				}
				if tc.wantErr {
					if err == nil {
						t.Fatalf("want an error for %s", tc.answer)
					}
					return
				}
				if err != nil {
					t.Fatalf("decode failed: %v", err)
				}
				rnd, autn, hx := got.vec()
				if hexOf(rnd[:]) != avRand || hexOf(autn[:]) != avAutn || hexOf(hx) != avHxres {
					t.Errorf("AV = rand %x autn %x hxresStar %x", rnd, autn, hx)
				}
			})
		}
	}
}

type initResp struct {
	rand, autn [16]byte
	hxres      []byte
}

func (r initResp) vec() ([16]byte, [16]byte, []byte) { return r.rand, r.autn, r.hxres }

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	var buf bytes.Buffer
	for _, c := range b {
		buf.WriteByte(digits[c>>4])
		buf.WriteByte(digits[c&0x0f])
	}
	return buf.String()
}
