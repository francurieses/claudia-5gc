package n32c

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// SEPP-005 slice B: S1-S5 / E7-E10 of docs/procedures/N32InteropReadiness.md.

func TestInteropFeaturesPerProfile(t *testing.T) {
	for profile, want := range map[string]string{"rel17": "1", "rel19": "5"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile)
			w := f.send(t, peer1FQDN, validBody(`,"supportedFeatures":"7f"`))
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if got := decode[SecNegotiateRspData](t, w).SupportedFeatures; got != want {
				t.Fatalf("features %q want %q", got, want)
			}
		})
	}
}

func TestInteropPurposes(t *testing.T) {
	for _, profile := range []string{"rel17", "rel19"} {
		for _, tc := range []struct {
			name, req string
			status    int
			allowed   int
			rejected  int
		}{
			{"none requested", ``, 200, 0, 0},
			{"all allowed", `,"intendedUsagePurpose":[{"usagePurpose":"ROAMING"},{"usagePurpose":"INTER_PLMN_MOBILITY_TEST","cause":"x"}]`, 200, 2, 0},
			{"partial", `,"intendedUsagePurpose":[{"usagePurpose":"ROAMING"},{"usagePurpose":"SMS_ONLY"}]`, 200, 1, 1},
			{"all rejected", `,"intendedUsagePurpose":[{"usagePurpose":"SMS_ONLY"}]`, 403, 0, 0},
		} {
			t.Run(profile+"/"+tc.name, func(t *testing.T) {
				f := newFixture(t, profile)
				w := f.send(t, peer1FQDN, validBody(tc.req))
				if w.Code != tc.status {
					t.Fatalf("%d %s", w.Code, w.Body)
				}
				if tc.status == 403 {
					if decode[ProblemDetails](t, w).Cause != CausePurposeNotAllowed || f.svc.Store().Len() != 0 ||
						!strings.Contains(f.logBuf.String(), `"cause":"purpose_not_allowed"`) {
						t.Fatalf("bad 403 %s", w.Body)
					}
					return
				}
				r := decode[SecNegotiateRspData](t, w)
				if len(r.AllowedUsagePurpose) != tc.allowed || len(r.RejectedUsagePurpose) != tc.rejected {
					t.Fatalf("rsp %s", w.Body)
				}
				for _, p := range r.AllowedUsagePurpose {
					if p.Cause != "" {
						t.Fatal("allowed purpose carries cause")
					}
				}
				if tc.req == "" && (strings.Contains(w.Body.String(), "UsagePurpose")) {
					t.Fatalf("purpose IEs without request: %s", w.Body)
				}
			})
		}
	}
}

func rejectCount() float64 {
	return testutil.ToFloat64(n32cHandshakeTotal.WithLabelValues("001/001", RoleResponder, resultReject))
}

func TestInteropRejects(t *testing.T) {
	for _, tc := range []struct{ name, body, logCause string }{
		{"E8 target", validBody(`,"targetPlmnId":{"mcc":"001","mnc":"05"}`), "target_plmn_not_served"},
		{"E7 plmnIdList", validBody(`,"plmnIdList":[{"mcc":"001","mnc":"01"},{"mcc":"001","mnc":"05"}]`), "plmn_mismatch"},
		{"E9 other domain", `{"sender":"sepp.5gc.mnc005.mcc001.3gppnetwork.org","supportedSecCapabilityList":["TLS"]}`, "sender_domain_mismatch"},
		{"E9 no 5gc label", `{"sender":"sepp.mnc001.mcc001.3gppnetwork.org","supportedSecCapabilityList":["TLS"]}`, "sender_domain_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "rel19")
			before := rejectCount()
			w := f.send(t, peer1FQDN, tc.body)
			if w.Code != 403 || f.svc.Store().Len() != 0 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if !strings.Contains(f.logBuf.String(), `"cause":"`+tc.logCause+`"`) {
				t.Fatalf("log: %s", f.logBuf)
			}
			if got := w.Header().Get("Server"); got != "SEPP-"+localFQDN {
				t.Fatalf("Server header %q", got)
			}
			if rejectCount() != before+1 {
				t.Fatal("REJECT counter not incremented")
			}
		})
	}
}

func TestInteropAcceptsSenderSubdomainAndEqualPLMNList(t *testing.T) {
	f := newFixture(t, "rel19")
	w := f.send(t, peer1FQDN, `{"sender":"a.b.sepp.5gc.mnc001.mcc001.3gppnetwork.org","supportedSecCapabilityList":["TLS"],`+
		`"plmnIdList":[{"mcc":"001","mnc":"01"}],"targetPlmnId":{"mcc":"001","mnc":"02"}}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// S5 with a real TLS state: the certificate PLMN set comes from
// r.TLS.PeerCertificates[0] (n32trust.PLMNsFromCert).
func TestInteropCertPLMNSetFromTLSState(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{
		"sepp.5gc.mnc001.mcc001.3gppnetwork.org", "sepp.5gc.mnc003.mcc001.3gppnetwork.org"}}
	f := newFixture(t, "rel19")
	r := httptest.NewRequest(http.MethodPost, route, strings.NewReader(
		`{"sender":"sepp.5gc.mnc003.mcc001.3gppnetwork.org","supportedSecCapabilityList":["TLS"],`+
			`"plmnIdList":[{"mcc":"001","mnc":"01"},{"mcc":"001","mnc":"03"}]}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Test-Peer", peer1FQDN)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	f.svc.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func goldenCheck(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with UPDATE_GOLDEN=1): %v", err)
	}
	if string(want) != string(got) {
		t.Fatalf("golden %s differs:\nwant %s\ngot  %s", name, want, got)
	}
}

func TestInteropGoldens(t *testing.T) {
	for _, profile := range []string{"rel17", "rel19"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile)
			w := f.send(t, peer1FQDN, `{"sender":"`+peer1FQDN+`","supportedSecCapabilityList":["TLS"],`+
				`"3GppSbiTargetApiRootSupported":true,"supportedFeatures":"ff","targetPlmnId":{"mcc":"001","mnc":"02"}}`)
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			goldenCheck(t, "n32c_exchange_capability_"+profile+".json", w.Body.Bytes())
		})
	}
}

func TestInteropRel17InitiatorOfferGolden(t *testing.T) {
	var body []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		body = b[:n]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sender":"` + peer1FQDN + `","selectedSecCapability":"TLS"}`))
	}))
	defer ts.Close()
	f := newFixture(t, "rel17", func(c *Config) { c.HTTPClient = ts.Client() })
	if _, err := f.svc.Exchange(t.Context(), ts.URL, plmn1); err != nil {
		t.Fatal(err)
	}
	goldenCheck(t, "n32c_initiator_request_rel17.json", body)
}
