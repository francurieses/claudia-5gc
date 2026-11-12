package main

// nssaa_client_test.go - HTTPNSSAAClient against a fake AUSF (the real handler
// lives in another NF's internal package and is not importable).
// Ref: TS 29.526 §5.2.2.2

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
)

func fakeNSSAAAUSF(t *testing.T, status int, eapMsg string, hits *int) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		if r.URL.Path != "/nnssaaf-nssaa/v1/slice-authentications" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"gpsi":"msisdn-1","snssai":{"sst":1},"authCtxId":"c1","eapMessage":"` + eapMsg + `"}`))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestNSSAAClientRel19(t *testing.T) {
	b64 := func(b ...byte) string { return base64.StdEncoding.EncodeToString(b) }
	cases := []struct {
		name    string
		status  int
		eap     string
		gpsi    string
		want    string
		wantErr string
		hits    int
	}{
		{"success", 201, b64(3, 7, 0, 4), "msisdn-12025550100", procedures.NSSAAResultSuccess, "", 1},
		{"failure", 201, b64(4, 7, 0, 4), "msisdn-12025550100", procedures.NSSAAResultFailure, "", 1},
		{"unexpected EAP code", 201, b64(2, 8, 0, 5, 1), "msisdn-12025550100", "", "unexpected EAP code", 1},
		{"http error", 403, b64(4, 7, 0, 4), "msisdn-12025550100", "", "status 403", 1},
		{"bad eap", 201, "!!", "msisdn-12025550100", "", "eapMessage", 1},
		{"eap length field mismatch", 201, b64(3, 7, 0, 9), "msisdn-12025550100", "", "length field", 1},
		{"eap too short", 201, b64(3, 7), "msisdn-12025550100", "", "too short", 1},
		{"no gpsi", 201, b64(3, 7, 0, 4), "", "", "no GPSI", 0},
		{"supi as gpsi", 201, b64(3, 7, 0, 4), "imsi-001010000000003", "", "no GPSI", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := 0
			ts := fakeNSSAAAUSF(t, tc.status, tc.eap, &hits)
			c := newNSSAAClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), smsfProfile(t, "rel19"))
			res, err := c.Authenticate(context.Background(), "imsi-001010000000003", tc.gpsi, 1, "", []byte{2, 7, 0, 5, 1})
			if hits != tc.hits {
				t.Fatalf("hits = %d, want %d", hits, tc.hits)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || res.AuthResult != tc.want {
				t.Fatalf("res = %+v err = %v, want %s", res, err, tc.want)
			}
		})
	}
}

// TestNSSAAClientLegacyNoGPSIRequirement: rel17 keeps sending whatever the
// caller passes (SUPI as GPSI today), unchanged.
func TestNSSAAClientLegacyNoGPSIRequirement(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"authResult":"EAP_SUCCESS","eapPayload":"AwcABA=="}`))
	}))
	defer ts.Close()
	c := newNSSAAClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), nil)
	res, err := c.Authenticate(context.Background(), "imsi-1", "imsi-1", 1, "", []byte{2, 7, 0, 5, 1})
	if err != nil || res.AuthResult != procedures.NSSAAResultSuccess {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

// TS 29.526 §5.2.2.2.1 step 3b: 403 SLICE_AUTH_REJECTED maps to EAP_FAILURE and
// the AMF builds the EAP-Failure itself, with the identifier of the UE's packet.
func TestNSSAAClientRel19Rejected403(t *testing.T) {
	cases := []struct {
		name, body string
		wantErr    bool
	}{
		{"rejected", `{"status":403,"cause":"SLICE_AUTH_REJECTED"}`, false},
		{"other 403 cause", `{"status":403,"cause":"UNSPECIFIED"}`, true},
		{"403 without body", ``, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer ts.Close()
			c := newNSSAAClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), smsfProfile(t, "rel19"))
			res, err := c.Authenticate(context.Background(), "imsi-1", "msisdn-1", 1, "", []byte{2, 9, 0, 5, 1})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", res)
				}
				return
			}
			if err != nil || res.AuthResult != procedures.NSSAAResultFailure {
				t.Fatalf("res=%+v err=%v", res, err)
			}
			if want := []byte{eap.CodeFailure, 9, 0, 4}; !bytes.Equal(res.EAPPayload, want) {
				t.Fatalf("EAP-Failure = %x, want %x", res.EAPPayload, want)
			}
		})
	}
}

// Regression (REL19 NSSAA gaps, c): under rel17/nil the legacy relay keeps the
// HEAD-bf9dd80 behaviour on a malformed base64 eapPayload: the decode error is
// ignored and the bytes decoded so far (possibly none) are forwarded. The
// reference is the bf9dd80 expression `eapBytes, _ := DecodeString(...)`.
// Under rel19 the relay is the TS 29.526 resource, which rejects bad base64.
func TestNSSAAClientLegacyBadBase64(t *testing.T) {
	for _, payload := range []string{"!!not-base64", "AwcABA==!!", "AwcA", "AwcABA"} {
		t.Run(payload, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"authResult":"EAP_SUCCESS","eapPayload":"` + payload + `"}`))
			}))
			defer ts.Close()
			want, _ := base64.StdEncoding.DecodeString(payload) // bf9dd80 behaviour
			for _, prof := range []*capability.Profile{nil, smsfProfile(t, "rel17")} {
				c := newNSSAAClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), prof)
				res, err := c.Authenticate(context.Background(), "imsi-1", "imsi-1", 1, "", []byte{2, 7, 0, 5, 1})
				if err != nil {
					t.Fatalf("rel17 must not fail on bad base64: %v", err)
				}
				if res.AuthResult != procedures.NSSAAResultSuccess || !bytes.Equal(res.EAPPayload, want) {
					t.Fatalf("res = %+v, want payload %x", res, want)
				}
			}
		})
	}
}

func TestPickGPSI(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"extid-a@x"}, "extid-a@x"},
		{[]string{"extid-a@x", "msisdn-123"}, "msisdn-123"},
		{[]string{"junk", "msisdn-"}, ""},
	}
	for _, tc := range cases {
		if got := pickGPSI(tc.in); got != tc.want {
			t.Errorf("pickGPSI(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGetAMSubscriptionDataGPSI(t *testing.T) {
	cases := []struct{ name, answer, want string }{
		{"with gpsis", `{"gpsis":["extid-x@y","msisdn-12025550100"],"nssai":{"defaultSingleNssais":[]}}`, "msisdn-12025550100"},
		{"without gpsis", `{"nssai":{"defaultSingleNssais":[]}}`, ""},
		{"empty gpsis", `{"gpsis":[]}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.answer))
			}))
			defer ts.Close()
			c := &HTTPUDMClient{address: strings.TrimPrefix(ts.URL, "https://"), client: ts.Client()}
			sub, err := c.GetAMSubscriptionData(context.Background(), "imsi-1")
			if err != nil || sub.GPSI != tc.want {
				t.Fatalf("sub=%+v err=%v, want GPSI %q", sub, err, tc.want)
			}
		})
	}
}
