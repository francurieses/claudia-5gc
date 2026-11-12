package server

// notifuri_golden_test.go - REL19-3.5: ascReqData.notifUri is emitted only under
// the spec-literal profile (rel19). The rel17 / no-profile golden is captured at
// the pre-change HEAD and proves the legacy ascReqData bytes are unchanged.
// Ref: TS 29.514 §5.6.2.3 (notifUri required in AppSessionContextReqData).

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/nef/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

// captureRawAscReq runs one AsSessionWithQoS Create through the real
// HTTPPolicyAuthClient against a fake PCF and returns the raw request body the
// PCF received, plus the config used.
func captureRawAscReq(t *testing.T, p *capability.Profile) (string, *config.Config) {
	t.Helper()
	var (
		mu  sync.Mutex
		raw []byte
	)
	pcf := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		raw = b
		mu.Unlock()
		w.Header().Set("Location", "/npcf-policyauthorization/v1/app-sessions/as-1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(pcf.Close)

	bsf := &mockBSFClient{DiscoverFunc: func(context.Context, string) (*PcfBinding, error) {
		return &PcfBinding{BindingID: "b-1", PcfFqdn: strings.TrimPrefix(pcf.URL, "https://"), PcfId: "pcf-1", Dnn: "internet"}, nil
	}}
	cfg := testCfg()
	cfg.SBI.Address = "127.0.0.1:8011"
	client := &HTTPPolicyAuthClient{Client: pcf.Client()}
	client.WithFeatures(p, slog.Default())
	srv := New(cfg, slog.Default(), bsf, client)
	srv.SetProfile(p)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	reqBody := []byte(`{"ueIpv4Addr":"10.60.0.1","qosReference":"qos-1","afAppId":"app-1","dnn":"internet",` +
		`"flowInfo":[{"flowId":1,"flowDescriptions":["permit out ip from any to any"]}]}`)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/3gpp-as-session-with-qos/v1/af-1/subscriptions", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+mintToken(t, testScope))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	return string(raw), cfg
}

// TestGolden_AscReqData_NotifUri compares the raw body the fake PCF received.
// Legacy profiles match the HEAD-captured golden byte for byte; rel19 carries
// notifUri derived from the configured NEF apiRoot.
func TestGolden_AscReqData_NotifUri(t *testing.T) {
	for _, name := range []string{"noprofile", "rel17"} {
		t.Run(name, func(t *testing.T) {
			var p *capability.Profile
			if name == "rel17" {
				p = profileNamed(t, "rel17")
			}
			raw, _ := captureRawAscReq(t, p)
			checkGolden(t, "golden_ascreqdata_rel17.txt", raw)
		})
	}
	t.Run("rel19", func(t *testing.T) {
		raw, cfg := captureRawAscReq(t, profileNamed(t, "rel19"))
		_, port, err := net.SplitHostPort(cfg.SBI.Address)
		if err != nil {
			t.Fatal(err)
		}
		want := `"notifUri":"https://` + cfg.SBI.FQDN + ":" + port + pcfNotifyBasePath + `"`
		if !strings.Contains(raw, want) {
			t.Fatalf("want %s in %s", want, raw)
		}
	})
}

// TestAscReqData_NotifUri_NoEndpoint: rel19 without a configured apiRoot omits
// notifUri (WARN) and still serves the AF request; the Host header is never used.
func TestAscReqData_NotifUri_NoEndpoint(t *testing.T) {
	pcf := defaultPCF()
	cfg := testCfg() // Address port 0 -> no apiRoot
	srv := New(cfg, slog.Default(), defaultBSF(), pcf)
	srv.SetProfile(profileNamed(t, "rel19"))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/3gpp-as-session-with-qos/v1/af-1/subscriptions",
		strings.NewReader(`{"ueIpv4Addr":"10.60.0.1","qosReference":"qos-1","dnn":"internet"}`))
	req.Host = "evil.example"
	req.Header.Set("Authorization", "Bearer "+mintToken(t, testScope))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	pcf.mu.Lock()
	defer pcf.mu.Unlock()
	if pcf.lastCreateReq == nil || pcf.lastCreateReq.NotifUri != "" {
		t.Fatalf("notifUri must be omitted, got %+v", pcf.lastCreateReq)
	}
}

// TestPCFNotifyCallback covers the PCF notify/terminate callbacks.
// Ref: TS 29.514 §4.2.5.2, §4.2.5.3, §5.5.2.2
func TestPCFNotifyCallback(t *testing.T) {
	_, ts := newTestServer(t, defaultBSF(), defaultPCF())
	big := strings.Repeat("a", maxPCFNotifyBodyBytes+1)
	cases := []struct {
		name, method, op, body string
		want                   int
		allow                  string
	}{
		{"notify 204", http.MethodPost, "notify", `{"evNotifs":[]}`, http.StatusNoContent, ""},
		{"terminate 204", http.MethodPost, "terminate", `{"resourceUri":"x"}`, http.StatusNoContent, ""},
		{"GET 405", http.MethodGet, "notify", "", http.StatusMethodNotAllowed, "POST"},
		{"oversized 413", http.MethodPost, "notify", big, http.StatusRequestEntityTooLarge, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, ts.URL+pcfNotifyBasePath+"/"+tc.op, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			if got := resp.Header.Get("Allow"); got != tc.allow {
				t.Errorf("Allow = %q, want %q", got, tc.allow)
			}
			if tc.want >= 400 {
				if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
					t.Errorf("Content-Type = %q", ct)
				}
			}
		})
	}
}
