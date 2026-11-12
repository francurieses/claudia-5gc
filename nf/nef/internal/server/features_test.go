package server

// features_test.go - producer-side supportedFeatures negotiation of the NEF
// AsSessionWithQoS API (REL19-2.7 slice 2). Ref: TS 29.500 §6.6.2, §5.2.7.2;
// TS 29.122 §5.2.7, §5.14.4; TS 29.571 §5.2.2.

import (
	"bytes"
	"encoding/json"
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

// implCatalog implements AsSessionWithQoS features 9 (AppId, Rel-17) and 30
// (QoSMonCapRepo, Rel-19) so non-empty sets can be negotiated; unit tests only,
// the real NEF catalog implements nothing.
func implCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.AsSessionWithQoSEntries(), 9, 30)...)
}

type nefEnv struct {
	srv  *Server
	ts   *httptest.Server
	pcf  *mockPCFClient
	logs *syncBuf
}

func newNEFEnv(t *testing.T, p *capability.Profile, cat *features.Catalog) nefEnv {
	t.Helper()
	logs := &syncBuf{}
	pcf := defaultPCF()
	srv := New(testCfg(), slog.New(slog.NewJSONHandler(logs, nil)), defaultBSF(), pcf)
	srv.SetProfile(p)
	srv.SetCatalog(cat)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return nefEnv{srv: srv, ts: ts, pcf: pcf, logs: logs}
}

func (e nefEnv) create(t *testing.T, extra string) (*http.Response, []byte) {
	t.Helper()
	body := `{"ueIpv4Addr":"10.60.0.1","qosReference":"qos-1"` + extra + `}`
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/3gpp-as-session-with-qos/v1/af-1/subscriptions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, testScope))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	return resp, buf.Bytes()
}

func (e nefEnv) negotiationLines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(e.logs.bytes()), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"procedure":"`+features.ProcedureName+`"`)) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("invalid JSON log %s: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// TestNegotiationMatrix covers D1: rel17 omits the attribute when the request
// had none, rel19 always answers; a request that carries a value is answered
// with the intersection under both profiles - the AF's value is never echoed.
func TestNegotiationMatrix(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		peer    string // "" = omitted
		cat     *features.Catalog
		want    string // "" = attribute absent
	}{
		{"rel17 absent", "rel17", "", nil, ""},
		{"rel19 absent", "rel19", "", nil, "0"},
		{"rel17 peer, nothing implemented (was echoed)", "rel17", "ff", nil, "0"},
		{"rel19 peer, nothing implemented", "rel19", "3", nil, "0"},
		{"rel17 AppId only (Rel-19 bit gated out)", "rel17", "ffffffffff", implCatalog(), "100"},
		{"rel19 AppId + QoSMonCapRepo", "rel19", "ffffffffff", implCatalog(), "20000100"},
		{"rel19 peer lacks them", "rel19", "1", implCatalog(), "0"},
		{"rel19 peer zero", "rel19", "0", implCatalog(), "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newNEFEnv(t, profileNamed(t, tc.profile), tc.cat)
			extra := ""
			if tc.peer != "" {
				extra = `,"supportedFeatures":"` + tc.peer + `"`
			}
			resp, raw := e.create(t, extra)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status %d: %s", resp.StatusCode, raw)
			}
			var got AsSessionWithQoSSubscription
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got.SupportedFeatures != tc.want {
				t.Errorf("201 supportedFeatures=%q want %q", got.SupportedFeatures, tc.want)
			}
			// GET returns the same representation.
			gresp := doJSON(t, http.DefaultClient, http.MethodGet,
				e.ts.URL+"/3gpp-as-session-with-qos/v1/af-1/subscriptions/"+got.SubscriptionID, nil, mintToken(t, testScope))
			var again AsSessionWithQoSSubscription
			decodeBody(t, gresp, &again)
			if again.SupportedFeatures != tc.want {
				t.Errorf("GET supportedFeatures=%q want %q", again.SupportedFeatures, tc.want)
			}
			// The typed set is stored on the resource.
			e.srv.mu.RLock()
			stored := e.srv.subscriptions[got.SubscriptionID].negotiated
			e.srv.mu.RUnlock()
			wantSet := tc.want
			if wantSet == "" {
				wantSet = "0"
			}
			if stored.String() != wantSet {
				t.Errorf("stored negotiated=%q want %q", stored, wantSet)
			}
			lines := e.negotiationLines(t)
			if len(lines) != 1 {
				t.Fatalf("FeatureNegotiation lines=%d", len(lines))
			}
			rec := lines[0]
			wantPeer := tc.peer
			if wantPeer == "" {
				wantPeer = "absent"
			}
			if rec["interface"] != "Nnef" || rec["direction"] != "IN" || rec["peer_nf_type"] != "AF" ||
				rec["result"] != "OK" || rec["spec_ref"] != "TS 29.500 §6.6.2" ||
				rec["features_peer"] != wantPeer || rec["correlation_id"] != "01TESTCORRELATIONID00000000" {
				t.Errorf("record %v", rec)
			}
		})
	}
}

func TestInvalidSupportedFeaturesRejected(t *testing.T) {
	for _, tc := range []struct{ name, attr string }{
		{"non-hex", `"zz"`}, {"number", `3`}, {"array", `["1"]`}, {"object", `{}`}, {"bool", `true`},
	} {
		for _, prof := range []string{"rel17", "rel19"} {
			t.Run(prof+"/"+tc.name, func(t *testing.T) {
				e := newNEFEnv(t, profileNamed(t, prof), nil)
				resp, raw := e.create(t, `,"supportedFeatures":`+tc.attr)
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
					t.Errorf("content-type %q", ct)
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
				if e.pcf.lastCreateReq != nil {
					t.Error("PCF must not be called for a rejected request")
				}
				lines := e.negotiationLines(t)
				if len(lines) != 1 || lines[0]["result"] != "REJECT" || lines[0]["cause"] != "INVALID_MSG_FORMAT" {
					t.Errorf("log lines %v", lines)
				}
			})
		}
	}
}

// TestUnrelatedTypeErrorKeepsLegacyAnswer: a type error on another attribute
// is still the pre-existing 400 MANDATORY_IE_INCORRECT.
func TestUnrelatedTypeErrorKeepsLegacyAnswer(t *testing.T) {
	e := newNEFEnv(t, profileNamed(t, "rel19"), nil)
	resp, raw := e.create(t, `,"flowInfo":"notAnArray"`)
	if resp.StatusCode != http.StatusBadRequest || !bytes.Contains(raw, []byte("MANDATORY_IE_INCORRECT")) {
		t.Errorf("status %d body %s", resp.StatusCode, raw)
	}
}

// TestNullAndEmptySupportedFeaturesAreAbsent: null and "" behave as omitted.
func TestNullAndEmptySupportedFeaturesAreAbsent(t *testing.T) {
	for _, attr := range []string{`null`, `""`} {
		e := newNEFEnv(t, profileNamed(t, "rel17"), nil)
		resp, raw := e.create(t, `,"supportedFeatures":`+attr)
		if resp.StatusCode != http.StatusCreated || bytes.Contains(raw, []byte("supportedFeatures")) {
			t.Errorf("%s: status %d body %s", attr, resp.StatusCode, raw)
		}
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line.
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	e := newNEFEnv(t, profileNamed(t, "rel19"), implCatalog())
	e.create(t, `,"supportedFeatures":"100"`)
	e.create(t, `,"supportedFeatures":"zz"`)
	n := 0
	for _, line := range bytes.Split(bytes.TrimSpace(e.logs.bytes()), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"procedure":"`+features.ProcedureName+`"`)) {
			continue
		}
		n++
		for _, k := range []string{"nf", "nf_instance_id", "procedure", "correlation_id", "interface", "direction", "spec_ref",
			"peer_nf_type", "features_local", "features_peer", "features_negotiated", "result"} {
			if k == "nf_instance_id" {
				continue // the test logger has no instance id
			}
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
// bounded and an oversized body is rejected before any BSF/PCF call.
func TestLongPeerValueTruncatedInLogAndBodyCapped(t *testing.T) {
	e := newNEFEnv(t, profileNamed(t, "rel19"), nil)
	long := strings.Repeat("f", 4000)
	if resp, raw := e.create(t, `,"supportedFeatures":"`+long+`"`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d %s", resp.StatusCode, raw)
	}
	for _, l := range e.negotiationLines(t) {
		if p, _ := l["features_peer"].(string); len(p) != features.MaxLoggedPeerChars+3 || !strings.HasSuffix(p, "...") {
			t.Errorf("features_peer not truncated: %d chars", len(p))
		}
	}
	e2 := newNEFEnv(t, profileNamed(t, "rel19"), nil)
	huge := strings.Repeat("f", features.MaxRequestBodyBytes+10)
	resp, _ := e2.create(t, `,"supportedFeatures":"`+huge+`"`)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || e2.pcf.lastCreateReq != nil {
		t.Errorf("oversized body: status %d", resp.StatusCode)
	}
}
