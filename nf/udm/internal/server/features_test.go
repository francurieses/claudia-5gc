package server

// features_test.go - producer-side supportedFeatures negotiation of Nudm_UEAU
// generate-auth-data (REL19-2.7 slice 2). Ref: TS 29.500 §6.6.2, §5.2.7.2;
// TS 29.571 §5.2.2; TS 29.503 §6.3.8.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

func profileNamed(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// subdmigCatalog implements Nudm_UEAU feature 1 SUBDMIG (Rel-19) so a
// non-empty set can be negotiated; unit tests only.
func subdmigCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NudmUEAUEntries(), 1)...)
}

func newFeatureUDM(t *testing.T, p *capability.Profile, cat *features.Catalog, method string) (*Server, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	s, err := New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org", TLSConfig{}, goldenUDR{method: method},
		slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.SetProfile(p)
	s.SetUEAUCatalog(cat)
	return s, logs
}

func postAuth(t *testing.T, s *Server, body string) (*http.Response, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost,
		"/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

const authReq = `{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"`

// TestNegotiationMatrix covers D1: rel17 omits the attribute when the request
// had none, rel19 always answers; a request that carries a value is answered
// with the intersection under both profiles. Both authentication methods.
func TestNegotiationMatrix(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		peer    string // "" = omitted
		cat     *features.Catalog
		want    string // "" = attribute absent
		wantLog string
	}{
		{"rel17 absent", "rel17", "", nil, "", "absent"},
		{"rel19 absent", "rel19", "", nil, "0", "absent"},
		{"rel17 peer, nothing implemented", "rel17", "1", nil, "0", "1"},
		{"rel19 peer, nothing implemented", "rel19", "ff", nil, "0", "ff"},
		{"rel19 SUBDMIG both", "rel19", "1", subdmigCatalog(), "1", "1"},
		{"rel19 SUBDMIG peer higher bits", "rel19", "ff", subdmigCatalog(), "1", "ff"},
		{"rel19 SUBDMIG peer lacks it", "rel19", "2", subdmigCatalog(), "0", "2"},
		{"rel17 SUBDMIG gated out (Rel19 bit)", "rel17", "1", subdmigCatalog(), "0", "1"},
		{"rel19 peer uppercase hex", "rel19", "FF", subdmigCatalog(), "1", "FF"},
	}
	for _, method := range []string{"5G_AKA", "EAP_AKA_PRIME"} {
		for _, tc := range tests {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				s, logs := newFeatureUDM(t, profileNamed(t, tc.profile), tc.cat, method)
				body := authReq
				if tc.peer != "" {
					body += `,"supportedFeatures":"` + tc.peer + `"`
				}
				resp, raw := postAuth(t, s, body+"}")
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				var got map[string]any
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				sf, present := got["supportedFeatures"]
				if tc.want == "" && present {
					t.Errorf("supportedFeatures must be absent, got %v", sf)
				}
				if tc.want != "" && sf != tc.want {
					t.Errorf("supportedFeatures=%v want %q", sf, tc.want)
				}
				var rec map[string]any
				for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
					if bytes.Contains(line, []byte(`"procedure":"FeatureNegotiation"`)) {
						_ = json.Unmarshal(line, &rec)
					}
				}
				if rec == nil || rec["features_peer"] != tc.wantLog || rec["peer_nf_type"] != "AUSF" ||
					rec["direction"] != "IN" || rec["interface"] != "Nudm" || rec["result"] != "OK" ||
					rec["spec_ref"] != "TS 29.500 §6.6.2" || rec["correlation_id"] != "01TESTCORRELATIONID00000000" {
					t.Errorf("log record %v", rec)
				}
			})
		}
	}
}

func TestInvalidSupportedFeaturesRejected(t *testing.T) {
	for _, tc := range []struct{ name, attr string }{
		{"non-hex", `"zz"`}, {"number", `7`}, {"array", `["1"]`}, {"bool", `false`},
	} {
		for _, prof := range []string{"rel17", "rel19"} {
			t.Run(prof+"/"+tc.name, func(t *testing.T) {
				s, logs := newFeatureUDM(t, profileNamed(t, prof), nil, "5G_AKA")
				resp, raw := postAuth(t, s, authReq+`,"supportedFeatures":`+tc.attr+"}")
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				var pd struct {
					Cause         string `json:"cause"`
					InvalidParams []struct {
						Param string `json:"param"`
					} `json:"invalidParams"`
				}
				if err := json.Unmarshal(raw, &pd); err != nil {
					t.Fatal(err)
				}
				if pd.Cause != "INVALID_MSG_FORMAT" || len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != "/supportedFeatures" {
					t.Errorf("problem %s", raw)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
					t.Errorf("content-type %q", ct)
				}
				if !bytes.Contains(logs.bytes(), []byte(`"result":"REJECT"`)) {
					t.Errorf("no REJECT log:\n%s", logs.bytes())
				}
			})
		}
	}
}

func TestNullAndEmptySupportedFeaturesAreAbsent(t *testing.T) {
	for _, attr := range []string{`null`, `""`} {
		s, _ := newFeatureUDM(t, profileNamed(t, "rel17"), nil, "5G_AKA")
		resp, raw := postAuth(t, s, authReq+`,"supportedFeatures":`+attr+"}")
		if resp.StatusCode != http.StatusOK || bytes.Contains(raw, []byte("supportedFeatures")) {
			t.Errorf("%s: status %d body %s", attr, resp.StatusCode, raw)
		}
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line.
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	s, logs := newFeatureUDM(t, profileNamed(t, "rel19"), subdmigCatalog(), "5G_AKA")
	postAuth(t, s, authReq+`,"supportedFeatures":"1"}`)
	postAuth(t, s, authReq+`,"supportedFeatures":"zz"}`)
	n := 0
	for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"procedure":"FeatureNegotiation"`)) {
			continue
		}
		n++
		for _, k := range []string{"nf", "procedure", "correlation_id", "interface", "direction", "spec_ref",
			"peer_nf_type", "features_local", "features_peer", "features_negotiated", "result"} {
			if c := bytes.Count(line, []byte(`"`+k+`":`)); c != 1 {
				t.Errorf("key %q appears %d times in %s", k, c, line)
			}
		}
	}
	if n != 2 {
		t.Fatalf("FeatureNegotiation lines = %d, want 2", n)
	}
}

// TestMissingCorrelationIDFallsBackToMiddleware: a request without
// X-Correlation-Id still gets the id the middleware minted in the log.
func TestMissingCorrelationIDFallsBackToMiddleware(t *testing.T) {
	s, logs := newFeatureUDM(t, profileNamed(t, "rel19"), nil, "5G_AKA")
	r := httptest.NewRequest(http.MethodPost,
		"/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data", strings.NewReader(authReq+"}"))
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, r)
	want := w.Result().Header.Get("X-Correlation-Id")
	if want == "" || !bytes.Contains(logs.bytes(), []byte(`"correlation_id":"`+want+`"`)) {
		t.Errorf("correlation id %q not in logs:\n%s", want, logs.bytes())
	}
}

// TestLongPeerValueTruncatedInLogAndBodyCapped: the logged features_peer is
// bounded and an oversized body is rejected.
func TestLongPeerValueTruncatedInLogAndBodyCapped(t *testing.T) {
	s, logs := newFeatureUDM(t, profileNamed(t, "rel19"), nil, "5G_AKA")
	long := strings.Repeat("f", 4000)
	if resp, raw := postAuth(t, s, authReq+`,"supportedFeatures":"`+long+`"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, raw)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
		var rec map[string]any
		_ = json.Unmarshal(line, &rec)
		if p, ok := rec["features_peer"].(string); ok && (len(p) != features.MaxLoggedPeerChars+3 || !strings.HasSuffix(p, "...")) {
			t.Errorf("features_peer not truncated: %d chars", len(p))
		}
	}
	huge := strings.Repeat("f", features.MaxRequestBodyBytes+10)
	if resp, _ := postAuth(t, s, authReq+`,"supportedFeatures":"`+huge+`"}`); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status %d", resp.StatusCode)
	}
}
