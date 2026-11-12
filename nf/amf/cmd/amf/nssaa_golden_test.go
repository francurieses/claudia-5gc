package main

// nssaa_golden_test.go - byte-identity golden for the AMF -> AUSF NSSAA relay
// request (REL19-3.5 slice E). rel17 / no profile = frozen legacy body (captured
// on the pre-change code); rel19 = TS 29.526 SliceAuthInfo.
// Ref: TS 29.526 §5.2.2.2

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func TestGolden_NSSAARequest(t *testing.T) {
	cases := []struct {
		name, golden string
		p            func(*testing.T) *capability.Profile
	}{
		{"noprofile", "golden_nssaa_req_rel17.txt", func(*testing.T) *capability.Profile { return nil }},
		{"rel17", "golden_nssaa_req_rel17.txt", func(t *testing.T) *capability.Profile { return smsfProfile(t, "rel17") }},
		{"rel19", "golden_nssaa_req_rel19.txt", func(t *testing.T) *capability.Profile { return smsfProfile(t, "rel19") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec string
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				rec = r.Method + " " + r.URL.RequestURI() + "\nContent-Type: " +
					r.Header.Get("Content-Type") + "\n\n" + string(b)
				w.Header().Set("Content-Type", "application/json")
				if strings.HasPrefix(r.URL.Path, "/nnssaaf-nssaa/") {
					w.Header().Set("Location", "https://x/nnssaaf-nssaa/v1/slice-authentications/ctx1")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"gpsi":"msisdn-12025550100","snssai":{"sst":1,"sd":"000003"},"authCtxId":"ctx1","eapMessage":"AwcABA=="}`))
					return
				}
				_, _ = w.Write([]byte(`{"authResult":"EAP_SUCCESS","eapPayload":"AwcABA=="}`))
			}))
			t.Cleanup(ts.Close)
			c := newNSSAAClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), tc.p(t))
			eapIDRsp := []byte{2, 7, 0, 9, 1, 'a', '@', 'b', 'c'}
			if _, err := c.Authenticate(context.Background(), "imsi-001010000000003", "msisdn-12025550100", 1, "000003", eapIDRsp); err != nil {
				t.Fatal(err)
			}
			smsfGoldenCheck(t, tc.golden, rec)
		})
	}
}
