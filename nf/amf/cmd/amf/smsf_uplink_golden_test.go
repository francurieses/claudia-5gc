package main

// smsf_uplink_golden_test.go - byte-identity goldens for the AMF -> SMSF
// Nsmsf_SMService_UplinkSMS request (REL19-3.5 slice C). rel17 / no profile =
// frozen JSON body; rel19 = multipart/related (TS 29.540 §5.2.4, §6.1.6.2.3;
// TS 29.500 §5.4) with a fixed boundary.
// Ref: TS 29.540 §5.2.4

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func smsfGoldenCheck(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	if got != string(b) {
		t.Fatalf("%s changed\n got: %q\nwant: %q", name, got, b)
	}
}

func TestGolden_UplinkSMS(t *testing.T) {
	cases := []struct {
		name, golden string
		p            func(*testing.T) *capability.Profile
	}{
		{"noprofile", "golden_smsf_uplink_rel17.txt", func(*testing.T) *capability.Profile { return nil }},
		{"rel17", "golden_smsf_uplink_rel17.txt", func(t *testing.T) *capability.Profile { return smsfProfile(t, "rel17") }},
		{"rel19", "golden_smsf_uplink_rel19.txt", func(t *testing.T) *capability.Profile { return smsfProfile(t, "rel19") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec string
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request body: %v", err)
				}
				rec = r.Method + " " + r.URL.RequestURI() + "\n" +
					"Content-Type: " + r.Header.Get("Content-Type") + "\n\n" + string(b)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"accepted"}`))
			}))
			t.Cleanup(ts.Close)
			c := newSMSFClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), tc.p(t))
			if err := c.UplinkSMS(context.Background(), "imsi-001010000000001", "rec-1", "AQIDBA=="); err != nil {
				t.Fatal(err)
			}
			smsfGoldenCheck(t, tc.golden, strings.ReplaceAll(rec, "\r\n", "\\r\\n\n"))
		})
	}
}

// TestUplinkSMS_ErrorPaths covers the rel19 non-base64 input error (no request
// is sent) and the non-2xx SMSF answer, bounded ProblemDetails decoding included.
func TestUplinkSMS_ErrorPaths(t *testing.T) {
	t.Run("rel19 non-base64 input", func(t *testing.T) {
		called := false
		ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		t.Cleanup(ts.Close)
		c := newSMSFClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), smsfProfile(t, "rel19"))
		err := c.UplinkSMS(context.Background(), "imsi-001010000000001", "rec-1", "%%%not base64%%%")
		if err == nil || !strings.Contains(err.Error(), "not base64") {
			t.Fatalf("err = %v, want not-base64 error", err)
		}
		if called {
			t.Error("request sent despite invalid payload")
		}
	})
	t.Run("rel17 passes any string through", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
		t.Cleanup(ts.Close)
		c := newSMSFClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), smsfProfile(t, "rel17"))
		if err := c.UplinkSMS(context.Background(), "imsi-001010000000001", "rec-1", "%%%"); err != nil {
			t.Fatalf("rel17 err = %v", err)
		}
	})
	for _, prof := range []string{"rel17", "rel19"} {
		for _, tc := range []struct {
			name, body, want string
			status           int
		}{
			{"problem json", `{"status":404,"cause":"CONTEXT_NOT_FOUND"}`, "status 404 cause=CONTEXT_NOT_FOUND", http.StatusNotFound},
			{"non-json body", `<html>`, "status 502", http.StatusBadGateway},
		} {
			t.Run(prof+"/non-2xx "+tc.name, func(t *testing.T) {
				ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
				}))
				t.Cleanup(ts.Close)
				c := newSMSFClientForTest(strings.TrimPrefix(ts.URL, "https://"), ts.Client(), smsfProfile(t, prof))
				err := c.UplinkSMS(context.Background(), "imsi-001010000000001", "rec-1", "AQIDBA==")
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("err = %v, want containing %q", err, tc.want)
				}
			})
		}
	}
}
