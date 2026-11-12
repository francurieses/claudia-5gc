package server

// features_test.go - producer-side supportedFeatures negotiation of
// Nlmf_Location DetermineLocation (REL19-2.7 slice 3). Ref: TS 29.500 §6.6.2,
// §5.2.7.2; TS 29.571 §5.2.2; TS 29.572 §6.1.9.

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

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
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

// implCatalog implements Nlmf_Location features 3 MUTIQOS (Rel-17) and 8 MCTX
// (Rel-19) so non-empty sets can be negotiated; unit tests only.
func implCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NlmfLocationEntries(), 3, 8)...)
}

func newFeatureLMF(t *testing.T, p *capability.Profile, cat *features.Catalog) (*httptest.Server, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	// Like cmd/lmf/main.go, the process logger already carries nf.
	srv := New(cfg, slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "LMF"), goldenAMF(), nil)
	srv.SetProfile(p)
	srv.SetCatalog(cat)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, logs
}

func postDetermine(t *testing.T, ts *httptest.Server, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/nlmf-loc/v1/determine-location",
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

const determineReq = `{"supi":"imsi-001010000000001"`

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
		peer    string // "" = omitted
		cat     *features.Catalog
		want    string // "" = attribute absent
		wantLog string
	}{
		{"rel17 absent", "rel17", "", nil, "", "absent"},
		{"rel19 absent", "rel19", "", nil, "0", "absent"},
		{"rel17 peer, nothing implemented", "rel17", "7", nil, "0", "7"},
		{"rel19 peer, nothing implemented", "rel19", "ff", nil, "0", "ff"},
		{"rel19 MUTIQOS both", "rel19", "4", implCatalog(), "4", "4"},
		{"rel19 MUTIQOS and MCTX", "rel19", "84", implCatalog(), "84", "84"},
		{"rel19 peer higher bits", "rel19", "1ff", implCatalog(), "84", "1ff"},
		{"rel19 peer lacks it", "rel19", "1", implCatalog(), "0", "1"},
		{"rel17 MCTX gated out (Rel19 bit)", "rel17", "84", implCatalog(), "4", "84"},
		{"rel17 absent, catalog implements", "rel17", "", implCatalog(), "", "absent"},
		{"rel19 peer uppercase hex", "rel19", "FF", implCatalog(), "84", "FF"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts, logs := newFeatureLMF(t, profileNamed(t, tc.profile), tc.cat)
			body := determineReq
			if tc.peer != "" {
				body += `,"supportedFeatures":"` + tc.peer + `"`
			}
			resp, raw := postDetermine(t, ts, body+"}")
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
			recs := negotiationRecords(logs)
			if len(recs) != 1 {
				t.Fatalf("FeatureNegotiation lines = %d, want 1", len(recs))
			}
			rec := recs[0]
			if rec["features_peer"] != tc.wantLog || rec["peer_nf_type"] != "AMF" ||
				rec["direction"] != "IN" || rec["interface"] != "Nlmf" || rec["result"] != "OK" ||
				rec["spec_ref"] != "TS 29.500 §6.6.2" || rec["correlation_id"] != "01TESTCORRELATIONID00000000" ||
				rec["nf"] != "LMF" {
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

func TestInvalidSupportedFeaturesRejected(t *testing.T) {
	for _, tc := range []struct{ name, attr string }{
		{"non-hex", `"zz"`}, {"number", `7`}, {"array", `["1"]`}, {"bool", `false`},
	} {
		for _, prof := range []string{"rel17", "rel19"} {
			t.Run(prof+"/"+tc.name, func(t *testing.T) {
				ts, logs := newFeatureLMF(t, profileNamed(t, prof), nil)
				resp, raw := postDetermine(t, ts, determineReq+`,"supportedFeatures":`+tc.attr+"}")
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				var pd problemBody
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
		ts, _ := newFeatureLMF(t, profileNamed(t, "rel17"), nil)
		resp, raw := postDetermine(t, ts, determineReq+`,"supportedFeatures":`+attr+"}")
		if resp.StatusCode != http.StatusOK || bytes.Contains(raw, []byte("supportedFeatures")) {
			t.Errorf("%s: status %d body %s", attr, resp.StatusCode, raw)
		}
	}
}

// TestUnknownAttributesTolerated: unknown JSON attributes are ignored.
func TestUnknownAttributesTolerated(t *testing.T) {
	ts, _ := newFeatureLMF(t, profileNamed(t, "rel19"), implCatalog())
	resp, raw := postDetermine(t, ts, determineReq+`,"futureAttr":{"x":1},"supportedFeatures":"4"}`)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte(`"supportedFeatures":"4"`)) {
		t.Errorf("status %d body %s", resp.StatusCode, raw)
	}
}

// TestLegacyBodyToleranceUnchanged: an empty body keeps the legacy 400
// MANDATORY_IE_MISSING (no identity) and a broken body is still tolerated up to
// that same check, not turned into a negotiation error.
func TestLegacyBodyToleranceUnchanged(t *testing.T) {
	for _, body := range []string{``, `{`, `{"locationQoS":"x"}`} {
		ts, _ := newFeatureLMF(t, profileNamed(t, "rel19"), nil)
		resp, raw := postDetermine(t, ts, body)
		var pd problemBody
		_ = json.Unmarshal(raw, &pd)
		if resp.StatusCode != http.StatusBadRequest || pd.Cause != "MANDATORY_IE_MISSING" {
			t.Errorf("body %q: status %d %s", body, resp.StatusCode, raw)
		}
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line (the
// LMF's own logger adds nf a second time, so the record is built from the
// process logger).
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	ts, logs := newFeatureLMF(t, profileNamed(t, "rel19"), implCatalog())
	postDetermine(t, ts, determineReq+`,"supportedFeatures":"4"}`)
	postDetermine(t, ts, determineReq+`,"supportedFeatures":"zz"}`)
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

// TestLongPeerValueTruncatedInLogAndBodyCapped: the logged features_peer is
// bounded and an oversized body is rejected.
func TestLongPeerValueTruncatedInLogAndBodyCapped(t *testing.T) {
	ts, logs := newFeatureLMF(t, profileNamed(t, "rel19"), nil)
	long := strings.Repeat("f", 4000)
	if resp, raw := postDetermine(t, ts, determineReq+`,"supportedFeatures":"`+long+`"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, raw)
	}
	for _, rec := range negotiationRecords(logs) {
		if p, _ := rec["features_peer"].(string); len(p) != features.MaxLoggedPeerChars+3 || !strings.HasSuffix(p, "...") {
			t.Errorf("features_peer not truncated: %d chars", len(p))
		}
	}
	huge := strings.Repeat("f", features.MaxRequestBodyBytes+10)
	if resp, _ := postDetermine(t, ts, determineReq+`,"supportedFeatures":"`+huge+`"}`); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status %d", resp.StatusCode)
	}
}

// TestSubscriptionNotificationCarriesNoFeatures: the LocationData embedded in
// EventSubscription notifications never carries supportedFeatures.
func TestSubscriptionNotificationCarriesNoFeatures(t *testing.T) {
	b, err := json.Marshal(NotificationItem{LocationData: LocationData{NRCellId: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("supportedFeatures")) {
		t.Errorf("notification item carries supportedFeatures: %s", b)
	}
}

// TestRejectedRequestHasNoOKNegotiationLine: the OK FeatureNegotiation record
// is emitted only once the request is accepted, so a body missing both supi and
// gpsi (400) leaves none; an oversized body leaves one PAYLOAD_TOO_LARGE
// REJECT warning.
func TestRejectedRequestHasNoOKNegotiationLine(t *testing.T) {
	ts, logs := newFeatureLMF(t, profileNamed(t, "rel19"), nil)
	if resp, _ := postDetermine(t, ts, `{"supportedFeatures":"4"}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	if n := len(negotiationRecords(logs)); n != 0 {
		t.Errorf("FeatureNegotiation lines = %d, want 0 on a rejected request", n)
	}
	huge := strings.Repeat("f", features.MaxRequestBodyBytes+10)
	if resp, _ := postDetermine(t, ts, determineReq+`,"supportedFeatures":"`+huge+`"}`); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status %d", resp.StatusCode)
	}
	if !bytes.Contains(logs.bytes(), []byte(`"cause":"PAYLOAD_TOO_LARGE"`)) {
		t.Errorf("no PAYLOAD_TOO_LARGE reject log: %s", logs.bytes())
	}
}
