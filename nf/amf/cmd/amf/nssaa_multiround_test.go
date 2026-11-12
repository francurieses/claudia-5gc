package main

// nssaa_multiround_test.go - HTTPNSSAAClient create + confirm against a fake
// multi-round Nnssaaf (TS 29.526 §5.2.2.2 / §5.2.2.3).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
)

func b64eap(b ...byte) string { return base64.StdEncoding.EncodeToString(b) }

// fakeNnssaaf serves POST (201 EAP-Request, Location only when locOnly) and PUT
// (200: EAP-Request for rounds-1 PUTs, then the terminal result).
func fakeNnssaaf(t *testing.T, rounds int, locOnly bool, puts *atomic.Int32, final string) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			id := `"authCtxId":"ctx-1",`
			if locOnly {
				id = ""
				w.Header().Set("Location", "https://ausf/nnssaaf-nssaa/v1/slice-authentications/ctx-1")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"gpsi":"msisdn-1","snssai":{"sst":1},` + id + `"eapMessage":"` + b64eap(1, 2, 0, 6, 4, 1) + `"}`))
		case http.MethodPut:
			if r.URL.Path != "/nnssaaf-nssaa/v1/slice-authentications/ctx-1" {
				t.Errorf("PUT path %s", r.URL.Path)
			}
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["gpsi"] != "msisdn-1" || in["eapMessage"] == nil {
				t.Errorf("PUT body %v", in)
			}
			n := int(puts.Add(1))
			if n < rounds {
				_, _ = w.Write([]byte(`{"gpsi":"msisdn-1","snssai":{"sst":1},"eapMessage":"` + b64eap(1, byte(2+n), 0, 6, 4, 1) + `"}`))
				return
			}
			if final == procedures.NSSAAResultSuccess {
				_, _ = w.Write([]byte(`{"gpsi":"msisdn-1","snssai":{"sst":1},"eapMessage":"` + b64eap(3, 9, 0, 4) + `","authResult":"EAP_SUCCESS"}`))
			} else {
				_, _ = w.Write([]byte(`{"gpsi":"msisdn-1","snssai":{"sst":1},"eapMessage":"` + b64eap(4, 9, 0, 4) + `","authResult":"EAP_FAILURE"}`))
			}
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestNSSAAClientMultiRound(t *testing.T) {
	for _, locOnly := range []bool{false, true} {
		for _, final := range []string{procedures.NSSAAResultSuccess, procedures.NSSAAResultFailure} {
			var puts atomic.Int32
			ts := fakeNnssaaf(t, 3, locOnly, &puts, final)
			c := newNSSAAClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), smsfProfile(t, "rel19"))
			ctx := context.Background()
			res, err := c.Authenticate(ctx, "imsi-1", "msisdn-1", 1, "", []byte{2, 1, 0, 5, 1})
			if err != nil || res.AuthResult != "" || len(res.EAPRequest) == 0 || res.AuthCtxID != "ctx-1" {
				t.Fatalf("create: res=%+v err=%v", res, err)
			}
			for i := 1; i <= 3; i++ {
				res, err = c.Confirm(ctx, "imsi-1", "msisdn-1", 1, "", "ctx-1", []byte{2, 2, 0, 5, 4})
				if err != nil {
					t.Fatal(err)
				}
				if i < 3 && (res.AuthResult != "" || res.AuthCtxID != "ctx-1" || res.EAPRequest[0] != eap.CodeRequest) {
					t.Fatalf("put %d: %+v", i, res)
				}
			}
			if res.AuthResult != final || len(res.EAPPayload) == 0 {
				t.Fatalf("final = %+v, want %s", res, final)
			}
		}
	}
}

func TestNSSAAClientConfirmErrors(t *testing.T) {
	const ids = `"gpsi":"msisdn-1","snssai":{"sst":1},`
	cases := []struct {
		name    string
		status  int
		body    string
		profile string
		id      string
		wantErr string
		want    string
	}{
		{"404", 404, `{"cause":"CONTEXT_NOT_FOUND"}`, "rel19", "ctx-1", "status 404", ""},
		{"403 rejected", 403, `{"cause":"SLICE_AUTH_REJECTED"}`, "rel19", "ctx-1", "", procedures.NSSAAResultFailure},
		{"inconsistent", 200, `{` + ids + `"eapMessage":"` + b64eap(3, 1, 0, 4) + `","authResult":"EAP_FAILURE"}`, "rel19", "ctx-1", "inconsistent", ""},
		{"success without authResult", 200, `{` + ids + `"eapMessage":"` + b64eap(3, 1, 0, 4) + `"}`, "rel19", "ctx-1", "inconsistent", ""},
		{"failure without authResult is still a failure", 200, `{` + ids + `"eapMessage":"` + b64eap(4, 1, 0, 4) + `"}`, "rel19", "ctx-1", "", procedures.NSSAAResultFailure},
		{"request with authResult", 200, `{` + ids + `"eapMessage":"` + b64eap(1, 1, 0, 6, 4, 1) + `","authResult":"EAP_SUCCESS"}`, "rel19", "ctx-1", "inconsistent", ""},
		{"gpsi mismatch", 200, `{"gpsi":"msisdn-2","snssai":{"sst":1},"eapMessage":"` + b64eap(3, 1, 0, 4) + `","authResult":"EAP_SUCCESS"}`, "rel19", "ctx-1", "do not match", ""},
		{"snssai mismatch", 200, `{"gpsi":"msisdn-1","snssai":{"sst":2},"eapMessage":"` + b64eap(3, 1, 0, 4) + `","authResult":"EAP_SUCCESS"}`, "rel19", "ctx-1", "do not match", ""},
		{"missing gpsi/snssai", 200, `{"eapMessage":"` + b64eap(3, 1, 0, 4) + `","authResult":"EAP_SUCCESS"}`, "rel19", "ctx-1", "do not match", ""},
		{"bad base64", 200, `{` + ids + `"eapMessage":"!!"}`, "rel19", "ctx-1", "eapMessage", ""},
		{"rel17 refused", 200, `{}`, "rel17", "ctx-1", "rel17", ""},
		{"bad ctx id", 200, `{}`, "rel19", "a/b", "invalid authCtxId", ""},
		{"dot ctx id", 200, `{}`, "rel19", ".", "invalid authCtxId", ""},
		{"dotdot ctx id", 200, `{}`, "rel19", "..", "invalid authCtxId", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer ts.Close()
			c := newNSSAAClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), smsfProfile(t, tc.profile))
			res, err := c.Confirm(context.Background(), "imsi-1", "msisdn-1", 1, "", tc.id, []byte{2, 5, 0, 5, 4})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || res.AuthResult != tc.want {
				t.Fatalf("res=%+v err=%v", res, err)
			}
		})
	}
}

// A 404 on the PUT is reported as ErrNSSAAContextLost so the AMF can restart the
// exchange once (TS 29.526 §6.1.3.3.3.1); any other status is a plain error.
func TestNSSAAClientConfirm404ContextLost(t *testing.T) {
	for status, lost := range map[int]bool{404: true, 500: false, 504: false} {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		c := newNSSAAClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), smsfProfile(t, "rel19"))
		_, err := c.Confirm(context.Background(), "imsi-1", "msisdn-1", 1, "", "ctx-1", []byte{2, 5, 0, 5, 4})
		ts.Close()
		if errors.Is(err, procedures.ErrNSSAAContextLost) != lost || err == nil {
			t.Errorf("status %d: err=%v, context lost=%v", status, err, lost)
		}
	}
}

func TestValidAuthCtxID(t *testing.T) {
	for id, want := range map[string]bool{
		"ctx-1": true, "A.b_c~d-9": true, strings.Repeat("a", 128): true,
		"": false, ".": false, "..": false, strings.Repeat("a", 129): false,
		"a/b": false, "a?b": false, "a#b": false, "a%2fb": false, "a b": false, "a\\b": false, "é": false,
	} {
		if validAuthCtxID(id) != want {
			t.Errorf("validAuthCtxID(%q) = %v, want %v", id, !want, want)
		}
	}
}

// The Location fallback only yields an id when the header addresses the
// slice-authentications collection.
func TestAuthCtxIDFromLocation(t *testing.T) {
	for loc, want := range map[string]string{
		"https://nssaaf/nnssaaf-nssaa/v1/slice-authentications/ctx-1":     "ctx-1",
		"/nnssaaf-nssaa/v1/slice-authentications/ctx-1":                   "ctx-1",
		"https://ausf:8000/root/nnssaaf-nssaa/v1/slice-authentications/x": "x",
		"https://ausf/nausf-auth/v1/ue-authentications/ctx-1":             "",
		"https://nssaaf/nnssaaf-nssaa/v1/slice-authentications/a/b":       "",
		"https://nssaaf/nnssaaf-nssaa/v1/slice-authentications/":          "",
		"ctx-1": "",
		"":      "",
	} {
		if got := authCtxIDFromLocation(loc); got != want {
			t.Errorf("authCtxIDFromLocation(%q) = %q, want %q", loc, got, want)
		}
	}
}

// An EAP-Request whose Location addresses another resource (and has no body id)
// is rejected rather than followed.
func TestNSSAAClientCreateBadLocation(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://ausf/nausf-auth/v1/ue-authentications/ctx-1")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"gpsi":"msisdn-1","snssai":{"sst":1},"eapMessage":"` + b64eap(1, 2, 0, 6, 4, 1) + `"}`))
	}))
	defer ts.Close()
	c := newNSSAAClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), smsfProfile(t, "rel19"))
	if _, err := c.Authenticate(context.Background(), "imsi-1", "msisdn-1", 1, "", []byte{2, 1, 0, 5, 1}); err == nil {
		t.Fatal("a Location outside the slice-authentications collection must be rejected")
	}
}
