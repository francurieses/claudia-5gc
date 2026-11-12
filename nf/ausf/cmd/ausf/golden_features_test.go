package main

// golden_features_test.go - byte-identity goldens for the AUSF -> UDM
// Nudm_UEAuthentication request body (REL19-2.7 slice 2). Captured against the
// pre-change code; they must pass unchanged under rel17 / no profile
// (decision D2, dev/REL19_PROGRAM.md section 2).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ausfsrv "github.com/francurieses/claudia-5gc/nf/ausf/internal/server"
)

// captureUDM stands in for the UDM and returns each request body.
func captureUDM(t *testing.T) (*httptest.Server, <-chan string) {
	t.Helper()
	ch := make(chan string, 4)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- r.URL.Path + "\n" + string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"authType":"5G_AKA","rand":"00","autn":"00","supi":"imsi-001010000000001"}`)
	}))
	t.Cleanup(ts.Close)
	return ts, ch
}

func TestGolden_UDMRequestBody(t *testing.T) {
	tests := []struct {
		name   string
		req    *ausfsrv.UDMAuthDataRequest
		golden string
	}{
		{"plain", &ausfsrv.UDMAuthDataRequest{ServingNetworkName: "5G:mnc001.mcc001.3gppnetwork.org", AUSFInstanceID: "11111111-2222-3333-4444-555555555555"},
			"golden_udm_request_plain.txt"},
		{"resync", &ausfsrv.UDMAuthDataRequest{ServingNetworkName: "5G:mnc001.mcc001.3gppnetwork.org", AUSFInstanceID: "11111111-2222-3333-4444-555555555555",
			ResynchronizationInfo: &ausfsrv.ResyncInfo{RAND: "00112233445566778899aabbccddeeff", AUTS: "00112233445566778899aabbccdd"}},
			"golden_udm_request_resync.txt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts, ch := captureUDM(t)
			c := &HTTPUDMClient{address: strings.TrimPrefix(ts.URL, "https://"), client: ts.Client()}
			if _, err := c.GenerateAuthData(context.Background(), "imsi-001010000000001", tc.req); err != nil {
				t.Fatal(err)
			}
			got := <-ch
			checkGolden(t, tc.golden, got)
		})
	}
}

// checkGolden compares got with testdata/<name>. UPDATE_GOLDEN=1 rewrites the
// file; only ever used on the pre-change tree (git worktree at HEAD).
func checkGolden(t *testing.T, name, got string) {
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

// TestUDMClientOffersSupportedFeatures: a non-empty offer is sent as
// supportedFeatures and the UDM's answer is decoded; unknown response
// attributes are ignored (TS 29.500 §6.6.2).
func TestUDMClientOffersSupportedFeatures(t *testing.T) {
	ch := make(chan string, 1)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"authType":"5G_AKA","supi":"imsi-1","supportedFeatures":"1","futureAttr":{"x":1}}`)
	}))
	defer ts.Close()
	c := &HTTPUDMClient{address: strings.TrimPrefix(ts.URL, "https://"), client: ts.Client()}
	resp, err := c.GenerateAuthData(context.Background(), "imsi-1",
		&ausfsrv.UDMAuthDataRequest{ServingNetworkName: "sn", AUSFInstanceID: "id", SupportedFeatures: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if got := <-ch; got != `{"ausfInstanceId":"id","servingNetworkName":"sn","supportedFeatures":"0"}` {
		t.Errorf("body %s", got)
	}
	if resp.SupportedFeatures != "1" {
		t.Errorf("answer %q", resp.SupportedFeatures)
	}
}
