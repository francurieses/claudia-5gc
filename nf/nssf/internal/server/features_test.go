package server

// features_test.go - producer-side supportedFeatures negotiation of
// Nnssf_NSSelection (REL19-2.7 slice 3). Ref: TS 29.500 §6.6.2, §5.2.7.2;
// TS 29.571 §5.2.2; TS 29.531 §6.1.8.

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

	"github.com/francurieses/claudia-5gc/nf/nssf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/nssf/internal/slice"
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

// implCatalog implements Nnssf_NSSelection feature 2 TargetNssai so a
// non-empty set can be negotiated; unit tests only.
func implCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NnssfNSSelectionEntries(), 2)...)
}

func newFeatureNSSF(t *testing.T, p *capability.Profile, cat *features.Catalog) (*Server, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	// Like cmd/nssf/main.go, the process logger already carries nf.
	s := New(cfg, slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "NSSF"))
	s.policy = slice.New([]slice.SliceID{{SST: 1, SD: "000001"}})
	s.SetProfile(p)
	s.SetCatalog(cat)
	return s, logs
}

func getNSSelection(t *testing.T, s *Server, extra url.Values) (*http.Response, []byte) {
	t.Helper()
	q := url.Values{"nf-type": {"AMF"}, "nf-id": {"amf-001"}}
	for k, v := range extra {
		q[k] = v
	}
	r := httptest.NewRequest(http.MethodGet, "/nnssf-nsselection/v2/network-slice-information?"+q.Encode(), nil)
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	s.handleNSSelection(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
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

// TestNegotiationMatrix covers D1: rel17 omits the attribute when the request
// had none, rel19 always answers; a request that carries a value is answered
// with the intersection under both profiles.
func TestNegotiationMatrix(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		peer    string // "" = query parameter omitted
		cat     *features.Catalog
		want    string // "" = attribute absent
		wantLog string
	}{
		{"rel17 absent", "rel17", "", nil, "", "absent"},
		{"rel19 absent", "rel19", "", nil, "0", "absent"},
		{"rel17 peer, nothing implemented", "rel17", "f", nil, "0", "f"},
		{"rel19 peer, nothing implemented", "rel19", "ff", nil, "0", "ff"},
		{"rel19 TargetNssai both", "rel19", "2", implCatalog(), "2", "2"},
		{"rel19 peer higher bits", "rel19", "ff", implCatalog(), "2", "ff"},
		{"rel19 peer lacks it", "rel19", "1", implCatalog(), "0", "1"},
		{"rel17 peer has it", "rel17", "3", implCatalog(), "2", "3"},
		{"rel17 absent, catalog implements", "rel17", "", implCatalog(), "", "absent"},
		{"rel19 peer uppercase hex", "rel19", "FF", implCatalog(), "2", "FF"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, logs := newFeatureNSSF(t, profileNamed(t, tc.profile), tc.cat)
			extra := url.Values{}
			if tc.peer != "" {
				extra.Set("supported-features", tc.peer)
			}
			resp, raw := getNSSelection(t, s, extra)
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
			if _, ok := got["allowedNssaiList"]; !ok {
				t.Errorf("allowedNssaiList missing: %s", raw)
			}
			recs := negotiationRecords(logs)
			if len(recs) != 1 {
				t.Fatalf("FeatureNegotiation lines = %d, want 1", len(recs))
			}
			rec := recs[0]
			if rec["features_peer"] != tc.wantLog || rec["peer_nf_type"] != "AMF" ||
				rec["direction"] != "IN" || rec["interface"] != "Nnssf" || rec["result"] != "OK" ||
				rec["spec_ref"] != "TS 29.500 §6.6.2" || rec["correlation_id"] != "01TESTCORRELATIONID00000000" ||
				rec["nf"] != "NSSF" {
				t.Errorf("log record %v", rec)
			}
		})
	}
}

type problemBody struct {
	Cause         string `json:"cause"`
	InvalidParams []struct {
		Param string `json:"param"`
	} `json:"invalidParams"`
}

func TestInvalidSupportedFeaturesQueryRejected(t *testing.T) {
	for _, v := range []string{"zz", "0x1", "1 2", "g"} {
		for _, prof := range []string{"rel17", "rel19"} {
			t.Run(prof+"/"+v, func(t *testing.T) {
				s, logs := newFeatureNSSF(t, profileNamed(t, prof), nil)
				resp, raw := getNSSelection(t, s, url.Values{"supported-features": {v}})
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				var pd problemBody
				if err := json.Unmarshal(raw, &pd); err != nil {
					t.Fatal(err)
				}
				if pd.Cause != "OPTIONAL_QUERY_PARAM_INCORRECT" || len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != "query supported-features" {
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

// TestMandatoryParamsCheckedFirst: the legacy mandatory-parameter 400 keeps
// precedence, so a request lacking nf-id never reaches the negotiation.
func TestMandatoryParamsCheckedFirst(t *testing.T) {
	s, logs := newFeatureNSSF(t, profileNamed(t, "rel19"), nil)
	r := httptest.NewRequest(http.MethodGet, "/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&supported-features=zz", nil)
	w := httptest.NewRecorder()
	s.handleNSSelection(w, r)
	var pd problemBody
	_ = json.Unmarshal(w.Body.Bytes(), &pd)
	if w.Code != http.StatusBadRequest || pd.Cause != "MANDATORY_QUERY_PARAM_MISSING" {
		t.Errorf("status %d body %s", w.Code, w.Body)
	}
	if n := len(negotiationRecords(logs)); n != 0 {
		t.Errorf("FeatureNegotiation lines = %d, want 0", n)
	}
}

// TestEmptyQueryValueIsAbsent: "supported-features=" is the same as no value.
func TestEmptyQueryValueIsAbsent(t *testing.T) {
	s, logs := newFeatureNSSF(t, profileNamed(t, "rel17"), nil)
	resp, raw := getNSSelection(t, s, url.Values{"supported-features": {""}})
	if resp.StatusCode != http.StatusOK || bytes.Contains(raw, []byte("supportedFeatures")) {
		t.Errorf("status %d body %s", resp.StatusCode, raw)
	}
	if recs := negotiationRecords(logs); len(recs) != 1 || recs[0]["features_peer"] != "absent" {
		t.Errorf("records %v", recs)
	}
}

// TestUnknownQueryParametersTolerated: unknown query parameters (future
// optional features) are ignored. TS 29.500 §6.6.2.
func TestUnknownQueryParametersTolerated(t *testing.T) {
	s, _ := newFeatureNSSF(t, profileNamed(t, "rel19"), implCatalog())
	resp, raw := getNSSelection(t, s, url.Values{"future-param": {"x"}, "supported-features": {"2"}})
	if resp.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte(`"supportedFeatures":"2"`)) {
		t.Errorf("status %d body %s", resp.StatusCode, raw)
	}
}

// TestZeroValueStructServerUsesDefaults: a Server built as a literal (no New,
// no profile, no catalog) behaves like rel17 with the default catalog.
func TestZeroValueStructServerUsesDefaults(t *testing.T) {
	s := newTestServer()
	resp, raw := getNSSelection(t, s, url.Values{"supported-features": {"f"}})
	if resp.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte(`"supportedFeatures":"0"`)) {
		t.Errorf("status %d body %s", resp.StatusCode, raw)
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line.
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	s, logs := newFeatureNSSF(t, profileNamed(t, "rel19"), implCatalog())
	getNSSelection(t, s, url.Values{"supported-features": {"2"}})
	getNSSelection(t, s, url.Values{"supported-features": {"zz"}})
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

// TestLongPeerValueTruncatedInLog: the logged features_peer is bounded.
func TestLongPeerValueTruncatedInLog(t *testing.T) {
	s, logs := newFeatureNSSF(t, profileNamed(t, "rel19"), nil)
	long := strings.Repeat("f", 4000)
	if resp, raw := getNSSelection(t, s, url.Values{"supported-features": {long}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, raw)
	}
	for _, rec := range negotiationRecords(logs) {
		if p, _ := rec["features_peer"].(string); len(p) != features.MaxLoggedPeerChars+3 || !strings.HasSuffix(p, "...") {
			t.Errorf("features_peer not truncated: %d chars", len(p))
		}
	}
}

// TestMissingCorrelationIDStillLogged: a request without X-Correlation-Id
// still gets a correlation id in the FeatureNegotiation line.
func TestMissingCorrelationIDStillLogged(t *testing.T) {
	s, logs := newFeatureNSSF(t, profileNamed(t, "rel19"), nil)
	r := httptest.NewRequest(http.MethodGet, "/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=a", nil)
	s.handleNSSelection(httptest.NewRecorder(), r)
	recs := negotiationRecords(logs)
	if len(recs) != 1 || recs[0]["correlation_id"] == nil || recs[0]["correlation_id"] == "" {
		t.Errorf("records %v", recs)
	}
}

// TestNSSelectionLogNFTypeSanitised: the peer-controlled nf-type query value is
// logged only when it is a valid NFType token, otherwise as UNKNOWN, in every
// log line (NSSelection and FeatureNegotiation).
func TestNSSelectionLogNFTypeSanitised(t *testing.T) {
	tests := []struct {
		name, nfType, want string
	}{
		{"valid", "AMF", "AMF"},
		{"newline injection", "AMF\n{\"forged\":true}", "UNKNOWN"},
		{"lowercase", "amf", "UNKNOWN"},
		{"unbounded", strings.Repeat("A", 4000), "UNKNOWN"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, logs := newFeatureNSSF(t, profileNamed(t, "rel19"), nil)
			getNSSelection(t, s, url.Values{"nf-type": {tc.nfType}})
			raw := logs.bytes()
			if tc.want == "UNKNOWN" && (bytes.Contains(raw, []byte("forged")) || bytes.Contains(raw, []byte("AAAAAAAAAAAAAAAAAAAAA"))) {
				t.Fatalf("raw nf-type leaked into logs: %.200s", raw)
			}
			found := false
			for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
				var rec map[string]any
				if err := json.Unmarshal(line, &rec); err != nil {
					t.Fatalf("log line not JSON: %v", err)
				}
				if rec["procedure"] == "NSSelection" {
					found = true
					if rec["nf_type"] != tc.want {
						t.Errorf("nf_type = %v, want %s", rec["nf_type"], tc.want)
					}
				}
			}
			if !found {
				t.Fatal("no NSSelection log line")
			}
		})
	}
}
