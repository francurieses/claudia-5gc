package main

// golden_hr_test.go - ROAM-002 home-routed PDU session, AMF side. The
// non-roaming CreateSMContext body is pinned byte-for-byte by golden files
// captured at the commit before the HR change (UPDATE_GOLDEN=1 writes them);
// the HR body carries hSmfUri, hplmnSnssai and the full DNN.
// Ref: TS 29.502 Table 6.1.6.2.2-1; TS 23.003 §9.1.2.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/roaming"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

func captureCreateBody(t *testing.T, profile *capability.Profile, withCtx func(*testing.T) (hr *roaming.HomeRouting)) string {
	t.Helper()
	var got string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"smContextRef":"ref-1","n1SmMsg":"AQID","n2SmInfo":"BAUG"}`))
	}))
	defer srv.Close()
	c := &HTTPSMFClient{address: strings.TrimPrefix(srv.URL, "https://"), client: srv.Client(), profile: profile}
	ctx := t.Context()
	if withCtx != nil {
		if hr := withCtx(t); hr != nil {
			ctx = roaming.WithHomeRouting(ctx, *hr)
		}
	}
	if _, _, _, _, err := c.CreateSMContext(ctx, "imsi-001010000000001", "internet", 5, []byte{1, 2, 3},
		amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}); err != nil {
		t.Fatalf("CreateSMContext: %v", err)
	}
	return got
}

// TestGolden_NonRoamingCreateSMContextByteIdentical: explicit rel17 pass and
// no-profile pass, each subtest owns its setup.
func TestGolden_NonRoamingCreateSMContextByteIdentical(t *testing.T) {
	cases := []struct {
		name    string
		profile func(*testing.T) *capability.Profile
	}{
		{"rel17", func(t *testing.T) *capability.Profile { return testProfile(t, "rel17") }},
		{"noprofile", func(*testing.T) *capability.Profile { return nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := captureCreateBody(t, tc.profile(t), nil)
			path := filepath.Join("testdata", "golden_hr_nonroaming_createsmcontext_"+tc.name+".txt")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if got != string(want) {
				t.Fatalf("non-roaming CreateSMContext body changed:\n got %s\nwant %s", got, want)
			}
		})
	}
}

func TestCreateSMContext_HomeRoutedBody(t *testing.T) {
	route := &roaming.Route{HomePLMN: roaming.PLMN{MCC: "001", MNC: "02"},
		SMFAPIRoot: "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004"}
	hr, ok := route.NewHomeRouting("internet", 1, "000001")
	if !ok {
		t.Fatal("route with smf_api_root must yield a descriptor")
	}
	got := captureCreateBody(t, nil, func(*testing.T) *roaming.HomeRouting { return &hr })
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	if m["hSmfUri"] != "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004/nsmf-pdusession/v1" {
		t.Errorf("hSmfUri = %v", m["hSmfUri"])
	}
	if m["dnn"] != "internet.mnc002.mcc001.gprs" {
		t.Errorf("dnn = %v", m["dnn"])
	}
	sn, _ := m["hplmnSnssai"].(map[string]any)
	if sn["sst"] != float64(1) || sn["sd"] != "000001" {
		t.Errorf("hplmnSnssai = %v", m["hplmnSnssai"])
	}
	// The VPLMN S-NSSAI stays in "snssai".
	if s, _ := m["snssai"].(map[string]any); s["sd"] != "000001" {
		t.Errorf("snssai = %v", m["snssai"])
	}
}

func TestCreateSMContext_HomeRoutedWidensTimeout(t *testing.T) {
	// The shared client keeps its timeout; only the HR copy is widened.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	hc := srv.Client()
	rt := &countingRT{next: hc.Transport}
	hc.Transport = rt
	c := &HTTPSMFClient{address: strings.TrimPrefix(srv.URL, "https://"), client: hc}
	ctx := roaming.WithHomeRouting(t.Context(), roaming.HomeRouting{HSMFURI: "https://h/nsmf-pdusession/v1", FullDNN: "a.mnc001.mcc001.gprs", HPLMNSST: 1})
	if _, _, _, _, err := c.CreateSMContext(ctx, "imsi-1", "a", 1, nil, amfctx.SNSSAISubscribed{SST: 1}); err != nil {
		t.Fatal(err)
	}
	if hc.Timeout != 0 {
		t.Errorf("shared client timeout mutated: %v", hc.Timeout)
	}
	if c.client != hc || hc.Transport != http.RoundTripper(rt) {
		t.Errorf("shared client / transport replaced: client same=%v", c.client == hc)
	}
	if rt.calls != 1 {
		t.Errorf("HR copy bypassed the shared Transport: calls=%d, want 1", rt.calls)
	}
	if hrCreateSMContextTimeout <= 10*1e9 {
		t.Errorf("HR timeout %v must exceed the 10s default", hrCreateSMContextTimeout)
	}
}

// countingRT counts the requests that go through the shared Transport.
type countingRT struct {
	next  http.RoundTripper
	calls int
}

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls++
	return c.next.RoundTrip(r)
}

// TestCreateSMContext_HomeRoutedEmptySDOmitted: an HPLMN S-NSSAI without SD is
// sent without the "sd" attribute (optional in Snssai, TS 29.571 §5.4.4.2).
func TestCreateSMContext_HomeRoutedEmptySDOmitted(t *testing.T) {
	hr := roaming.HomeRouting{HSMFURI: "https://h/nsmf-pdusession/v1", FullDNN: "a.mnc002.mcc001.gprs", HPLMNSST: 2}
	got := captureCreateBody(t, nil, func(*testing.T) *roaming.HomeRouting { return &hr })
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	sn, _ := m["hplmnSnssai"].(map[string]any)
	if _, has := sn["sd"]; has || sn["sst"] != float64(2) {
		t.Errorf("hplmnSnssai = %v, want sst only", m["hplmnSnssai"])
	}
}
