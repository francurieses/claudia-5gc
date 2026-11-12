package server_test

// features_test.go - producer-side supportedFeatures negotiation of
// Nsmsf_SMService Activate (REL19-2.7 slice 3). Ref: TS 29.500 §6.6.2,
// §5.2.7.2; TS 29.571 §5.2.2; TS 29.540 §6.1.8.

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

	"github.com/francurieses/claudia-5gc/nf/smsf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/smsf/internal/server"
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

// implCatalog implements Nsmsf_SMService feature 2 PatchReport so a non-empty
// set can be negotiated; unit tests only.
func implCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NsmsfSMServiceEntries(), 2)...)
}

func newFeatureSMSF(t *testing.T, p *capability.Profile, cat *features.Catalog) (http.Handler, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	cfg := &config.Config{}
	cfg.NFInstanceID = "test-smsf-001"
	cfg.SBI.Address = "127.0.0.1:0"
	// Like cmd/smsf/main.go, the process logger already carries nf.
	s := server.New(cfg, slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "SMSF"))
	s.SetProfile(p)
	s.SetCatalog(cat)
	return s.Handler(), logs
}

func postActivate(t *testing.T, h http.Handler, body string) (*http.Response, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "/nsmsf-sms/v2/ue-contexts/imsi-001010000000001", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

const activateReq = `{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS","amfId":"amf-001"`

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
		{"rel17 peer, nothing implemented", "rel17", "1", nil, "0", "1"},
		{"rel19 peer, nothing implemented", "rel19", "ff", nil, "0", "ff"},
		{"rel19 PatchReport both", "rel19", "2", implCatalog(), "2", "2"},
		{"rel19 peer higher bits", "rel19", "ff", implCatalog(), "2", "ff"},
		{"rel19 peer lacks it", "rel19", "1", implCatalog(), "0", "1"},
		{"rel17 peer has it", "rel17", "3", implCatalog(), "2", "3"},
		{"rel17 absent, catalog implements", "rel17", "", implCatalog(), "", "absent"},
		{"rel19 peer uppercase hex", "rel19", "FF", implCatalog(), "2", "FF"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, logs := newFeatureSMSF(t, profileNamed(t, tc.profile), tc.cat)
			body := activateReq
			if tc.peer != "" {
				body += `,"supportedFeatures":"` + tc.peer + `"`
			}
			resp, raw := postActivate(t, h, body+"}")
			if resp.StatusCode != http.StatusCreated {
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
				rec["direction"] != "IN" || rec["interface"] != "Nsmsf" || rec["result"] != "OK" ||
				rec["spec_ref"] != "TS 29.500 §6.6.2" || rec["correlation_id"] != "01TESTCORRELATIONID00000000" ||
				rec["nf"] != "SMSF" {
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
				h, logs := newFeatureSMSF(t, profileNamed(t, prof), nil)
				resp, raw := postActivate(t, h, activateReq+`,"supportedFeatures":`+tc.attr+"}")
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
				// No SMS context was created: an UplinkSMS finds none.
				r := httptest.NewRequest(http.MethodPost, "/nsmsf-sms/v2/ue-contexts/imsi-001010000000001/sendsms",
					strings.NewReader(`{"smsPayload":"AA==","smsRecordId":"1"}`))
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusNotFound {
					t.Errorf("context exists after a rejected Activate: UplinkSMS status %d", w.Code)
				}
			})
		}
	}
}

func TestNullAndEmptySupportedFeaturesAreAbsent(t *testing.T) {
	for _, attr := range []string{`null`, `""`} {
		h, _ := newFeatureSMSF(t, profileNamed(t, "rel17"), nil)
		resp, raw := postActivate(t, h, activateReq+`,"supportedFeatures":`+attr+"}")
		if resp.StatusCode != http.StatusCreated || bytes.Contains(raw, []byte("supportedFeatures")) {
			t.Errorf("%s: status %d body %s", attr, resp.StatusCode, raw)
		}
	}
}

// TestUnknownAttributesTolerated: unknown JSON attributes are ignored.
func TestUnknownAttributesTolerated(t *testing.T) {
	h, _ := newFeatureSMSF(t, profileNamed(t, "rel19"), implCatalog())
	resp, raw := postActivate(t, h, activateReq+`,"futureAttr":{"x":1},"supportedFeatures":"2"}`)
	if resp.StatusCode != http.StatusCreated || !bytes.Contains(raw, []byte(`"supportedFeatures":"2"`)) {
		t.Errorf("status %d body %s", resp.StatusCode, raw)
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line.
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	h, logs := newFeatureSMSF(t, profileNamed(t, "rel19"), implCatalog())
	postActivate(t, h, activateReq+`,"supportedFeatures":"2"}`)
	postActivate(t, h, activateReq+`,"supportedFeatures":"zz"}`)
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
	h, logs := newFeatureSMSF(t, profileNamed(t, "rel19"), nil)
	long := strings.Repeat("f", 4000)
	if resp, raw := postActivate(t, h, activateReq+`,"supportedFeatures":"`+long+`"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d %s", resp.StatusCode, raw)
	}
	for _, rec := range negotiationRecords(logs) {
		if p, _ := rec["features_peer"].(string); len(p) != features.MaxLoggedPeerChars+3 || !strings.HasSuffix(p, "...") {
			t.Errorf("features_peer not truncated: %d chars", len(p))
		}
	}
	huge := strings.Repeat("f", features.MaxRequestBodyBytes+10)
	if resp, _ := postActivate(t, h, activateReq+`,"supportedFeatures":"`+huge+`"}`); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status %d", resp.StatusCode)
	}
}

// TestLegacyMalformedBodyUnchanged: a syntactically broken body keeps the
// pre-existing 400 MANDATORY_IE_MISSING.
func TestLegacyMalformedBodyUnchanged(t *testing.T) {
	h, _ := newFeatureSMSF(t, profileNamed(t, "rel19"), nil)
	resp, raw := postActivate(t, h, `{"supi":`)
	var pd problemBody
	_ = json.Unmarshal(raw, &pd)
	if resp.StatusCode != http.StatusBadRequest || pd.Cause != "MANDATORY_IE_MISSING" {
		t.Errorf("status %d body %s", resp.StatusCode, raw)
	}
}
