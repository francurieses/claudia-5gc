package server_test

// features_test.go - producer-side suppFeat negotiation of Nbsf_Management
// Register and Discovery (REL19-2.7 slice 3). Ref: TS 29.500 §6.6.2, §5.2.7.2;
// TS 29.571 §5.2.2; TS 29.521 §5.8.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/bsf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/bsf/internal/server"
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

// implCatalog implements Nbsf_Management features 1 MultiUeAddr (Rel-17) and
// 7 Recovery (Rel-19) so non-empty sets can be negotiated; unit tests only.
func implCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NbsfManagementEntries(), 1, 7)...)
}

func newFeatureBSF(t *testing.T, p *capability.Profile, cat *features.Catalog) (http.Handler, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	cfg := &config.Config{}
	cfg.NFInstanceID = "test-bsf-001"
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.SBI.FQDN = "bsf.test.local"
	// Like cmd/bsf/main.go, the process logger already carries nf.
	s := server.New(cfg, slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "BSF"))
	s.SetProfile(p)
	s.SetCatalog(cat)
	return s.Handler(), logs
}

func rawPost(t *testing.T, h http.Handler, body string) (*http.Response, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/nbsf-management/v1/pcfBindings", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func rawGet(t *testing.T, h http.Handler, query url.Values) (*http.Response, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/nbsf-management/v1/pcfBindings?"+query.Encode(), nil)
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// bindingJSON is a valid PcfBinding body, with suppFeat when attr != "".
func bindingJSON(ip, attr string) string {
	b := `{"supi":"imsi-001010000000001","ipv4Addr":"` + ip + `","dnn":"internet","snssai":{"sst":1,"sd":"000001"},"pcfFqdn":"pcf.example"`
	if attr != "" {
		b += `,"suppFeat":` + attr
	}
	return b + "}"
}

func negotiationRecords(logs *syncBuf) []map[string]any {
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
		if bytes.Contains(line, []byte(`"procedure":"FeatureNegotiation"`)) {
			var rec map[string]any
			_ = json.Unmarshal(line, &rec)
			out = append(out, rec)
		}
	}
	return out
}

// TestNegotiationMatrix covers D1 on Register: rel17 omits the attribute when
// the request had none, rel19 always answers; a request that carries a value is
// answered with the intersection under both profiles.
func TestNegotiationMatrix(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		peer    string // "" = omitted, else the raw JSON value of suppFeat
		cat     *features.Catalog
		want    string // "" = attribute absent
		wantLog string
	}{
		{"rel17 absent", "rel17", "", nil, "", "absent"},
		{"rel19 absent", "rel19", "", nil, "0", "absent"},
		{"rel17 peer, nothing implemented", "rel17", `"3"`, nil, "0", "3"},
		{"rel19 peer, nothing implemented", "rel19", `"ff"`, nil, "0", "ff"},
		{"rel19 MultiUeAddr both", "rel19", `"1"`, implCatalog(), "1", "1"},
		{"rel19 both bits peer has both", "rel19", `"41"`, implCatalog(), "41", "41"},
		{"rel19 peer higher bits", "rel19", `"ff"`, implCatalog(), "41", "ff"},
		{"rel19 peer lacks it", "rel19", `"2"`, implCatalog(), "0", "2"},
		{"rel17 Recovery gated out (Rel19 bit)", "rel17", `"41"`, implCatalog(), "1", "41"},
		{"rel17 absent, catalog implements", "rel17", "", implCatalog(), "", "absent"},
		{"rel19 peer uppercase hex", "rel19", `"FF"`, implCatalog(), "41", "FF"},
		{"explicit zero", "rel17", `"0"`, implCatalog(), "0", "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, logs := newFeatureBSF(t, profileNamed(t, tc.profile), tc.cat)
			resp, raw := rawPost(t, h, bindingJSON("10.60.0.1", tc.peer))
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status %d: %s", resp.StatusCode, raw)
			}
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			sf, present := got["suppFeat"]
			if tc.want == "" && present {
				t.Errorf("suppFeat must be absent, got %v", sf)
			}
			if tc.want != "" && sf != tc.want {
				t.Errorf("suppFeat=%v want %q", sf, tc.want)
			}
			recs := negotiationRecords(logs)
			if len(recs) != 1 {
				t.Fatalf("FeatureNegotiation lines = %d, want 1", len(recs))
			}
			rec := recs[0]
			if rec["features_peer"] != tc.wantLog || rec["peer_nf_type"] != "PCF" ||
				rec["direction"] != "IN" || rec["interface"] != "Nbsf" || rec["result"] != "OK" ||
				rec["spec_ref"] != "TS 29.500 §6.6.2" || rec["correlation_id"] != "01TESTCORRELATIONID00000000" ||
				rec["nf"] != "BSF" {
				t.Errorf("log record %v", rec)
			}
		})
	}
}

// TestNegotiatedValueIsStoredAndDiscovered: the stored binding carries the
// negotiated value, which Discovery returns when no supp-feat is queried; with
// supp-feat the response carries that GET's own intersection.
func TestNegotiatedValueIsStoredAndDiscovered(t *testing.T) {
	h, logs := newFeatureBSF(t, profileNamed(t, "rel19"), implCatalog())
	if resp, raw := rawPost(t, h, bindingJSON("10.60.0.1", `"ff"`)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %s", resp.StatusCode, raw)
	}
	get := func(q url.Values) map[string]any {
		resp, raw := rawGet(t, h, q)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discover %v: %d %s", q, resp.StatusCode, raw)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := get(url.Values{"ipv4Addr": {"10.60.0.1"}}); m["suppFeat"] != "41" {
		t.Errorf("stored suppFeat = %v, want the negotiated 41", m["suppFeat"])
	}
	if m := get(url.Values{"ipv4Addr": {"10.60.0.1"}, "supp-feat": {"1"}}); m["suppFeat"] != "1" {
		t.Errorf("GET with supp-feat=1: suppFeat = %v, want 1", m["suppFeat"])
	}
	if m := get(url.Values{"ipv4Addr": {"10.60.0.1"}, "supp-feat": {"2"}}); m["suppFeat"] != "0" {
		t.Errorf("GET with supp-feat=2: suppFeat = %v, want 0", m["suppFeat"])
	}
	// register + 2 GETs that carried supp-feat.
	recs := negotiationRecords(logs)
	if len(recs) != 3 || recs[1]["peer_nf_type"] != "NEF" || recs[1]["features_peer"] != "1" || recs[1]["features_negotiated"] != "1" {
		t.Errorf("records = %v", recs)
	}
}

// TestDiscoveryRel17WithoutQueryUnchanged: no supp-feat query and no stored
// value means no suppFeat in the answer under rel17.
func TestDiscoveryRel17WithoutQueryUnchanged(t *testing.T) {
	h, logs := newFeatureBSF(t, profileNamed(t, "rel17"), implCatalog())
	rawPost(t, h, bindingJSON("10.60.0.1", ""))
	resp, raw := rawGet(t, h, url.Values{"ipv4Addr": {"10.60.0.1"}})
	if resp.StatusCode != http.StatusOK || bytes.Contains(raw, []byte("suppFeat")) {
		t.Errorf("status %d body %s", resp.StatusCode, raw)
	}
	// The GET did not negotiate: only the Register line exists.
	if n := len(negotiationRecords(logs)); n != 1 {
		t.Errorf("FeatureNegotiation lines = %d, want 1", n)
	}
}

type problemBody struct {
	Cause         string `json:"cause"`
	InvalidParams []struct {
		Param string `json:"param"`
	} `json:"invalidParams"`
}

func TestInvalidSuppFeatRejected(t *testing.T) {
	for _, tc := range []struct{ name, attr string }{
		{"non-hex", `"zz"`}, {"number", `7`}, {"array", `["1"]`}, {"bool", `false`}, {"object", `{"a":1}`},
	} {
		for _, prof := range []string{"rel17", "rel19"} {
			t.Run(prof+"/"+tc.name, func(t *testing.T) {
				h, logs := newFeatureBSF(t, profileNamed(t, prof), nil)
				resp, raw := rawPost(t, h, bindingJSON("10.60.0.1", tc.attr))
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				var pd problemBody
				if err := json.Unmarshal(raw, &pd); err != nil {
					t.Fatal(err)
				}
				if pd.Cause != "INVALID_MSG_FORMAT" || len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != "/suppFeat" {
					t.Errorf("problem %s", raw)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
					t.Errorf("content-type %q", ct)
				}
				if !bytes.Contains(logs.bytes(), []byte(`"result":"REJECT"`)) {
					t.Errorf("no REJECT log:\n%s", logs.bytes())
				}
				// Nothing was stored: the same address registers cleanly afterwards.
				if resp, raw := rawPost(t, h, bindingJSON("10.60.0.1", "")); resp.StatusCode != http.StatusCreated {
					t.Errorf("binding must not exist after a rejected request: %d %s", resp.StatusCode, raw)
				}
			})
		}
	}
}

func TestInvalidSuppFeatQueryRejected(t *testing.T) {
	for _, prof := range []string{"rel17", "rel19"} {
		h, logs := newFeatureBSF(t, profileNamed(t, prof), nil)
		rawPost(t, h, bindingJSON("10.60.0.1", ""))
		resp, raw := rawGet(t, h, url.Values{"ipv4Addr": {"10.60.0.1"}, "supp-feat": {"xyz"}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: status %d: %s", prof, resp.StatusCode, raw)
		}
		var pd problemBody
		if err := json.Unmarshal(raw, &pd); err != nil {
			t.Fatal(err)
		}
		if pd.Cause != "OPTIONAL_QUERY_PARAM_INCORRECT" || len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != "query supp-feat" {
			t.Errorf("%s: problem %s", prof, raw)
		}
		if !bytes.Contains(logs.bytes(), []byte(`"result":"REJECT"`)) {
			t.Errorf("%s: no REJECT log", prof)
		}
	}
}

func TestNullAndEmptySuppFeatAreAbsent(t *testing.T) {
	for _, attr := range []string{`null`, `""`} {
		h, _ := newFeatureBSF(t, profileNamed(t, "rel17"), nil)
		var body string
		if attr == "null" {
			body = strings.Replace(bindingJSON("10.60.0.1", ""), `"pcfFqdn":"pcf.example"`, `"pcfFqdn":"pcf.example","suppFeat":null`, 1)
		} else {
			body = bindingJSON("10.60.0.1", attr)
		}
		resp, raw := rawPost(t, h, body)
		if resp.StatusCode != http.StatusCreated || bytes.Contains(raw, []byte("suppFeat")) {
			t.Errorf("%s: status %d body %s", attr, resp.StatusCode, raw)
		}
	}
}

// TestUnknownAttributesTolerated: unknown JSON attributes (future optional
// features) are ignored. TS 29.500 §6.6.2.
func TestUnknownAttributesTolerated(t *testing.T) {
	h, _ := newFeatureBSF(t, profileNamed(t, "rel19"), implCatalog())
	body := strings.Replace(bindingJSON("10.60.0.1", `"41"`), `"dnn"`, `"futureAttr":{"x":[1,2]},"dnn"`, 1)
	resp, raw := rawPost(t, h, body)
	if resp.StatusCode != http.StatusCreated || !bytes.Contains(raw, []byte(`"suppFeat":"41"`)) {
		t.Errorf("status %d body %s", resp.StatusCode, raw)
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line.
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	h, logs := newFeatureBSF(t, profileNamed(t, "rel19"), implCatalog())
	rawPost(t, h, bindingJSON("10.60.0.1", `"1"`))
	rawPost(t, h, bindingJSON("10.60.0.2", `"zz"`))
	rawGet(t, h, url.Values{"ipv4Addr": {"10.60.0.1"}, "supp-feat": {"1"}})
	rawGet(t, h, url.Values{"ipv4Addr": {"10.60.0.1"}, "supp-feat": {"zz"}})
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
	if n != 4 {
		t.Fatalf("FeatureNegotiation lines = %d, want 4", n)
	}
}

// TestLongPeerValueTruncatedInLogAndBodyCapped: the logged features_peer is
// bounded and an oversized body is rejected.
func TestLongPeerValueTruncatedInLogAndBodyCapped(t *testing.T) {
	h, logs := newFeatureBSF(t, profileNamed(t, "rel19"), nil)
	long := strings.Repeat("f", 4000)
	if resp, raw := rawPost(t, h, bindingJSON("10.60.0.1", `"`+long+`"`)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d %s", resp.StatusCode, raw)
	}
	for _, rec := range negotiationRecords(logs) {
		if p, _ := rec["features_peer"].(string); len(p) != features.MaxLoggedPeerChars+3 || !strings.HasSuffix(p, "...") {
			t.Errorf("features_peer not truncated: %d chars", len(p))
		}
	}
	huge := strings.Repeat("f", features.MaxRequestBodyBytes+10)
	if resp, _ := rawPost(t, h, bindingJSON("10.60.0.2", `"`+huge+`"`)); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status %d", resp.StatusCode)
	}
}

// TestLegacyMalformedBodyUnchanged: a syntactically broken body keeps the
// pre-existing 400 MANDATORY_IE_INCORRECT.
func TestLegacyMalformedBodyUnchanged(t *testing.T) {
	h, _ := newFeatureBSF(t, profileNamed(t, "rel19"), nil)
	resp, raw := rawPost(t, h, `{"dnn":`)
	var pd problemBody
	_ = json.Unmarshal(raw, &pd)
	if resp.StatusCode != http.StatusBadRequest || pd.Cause != "MANDATORY_IE_INCORRECT" {
		t.Errorf("status %d body %s", resp.StatusCode, raw)
	}
}
