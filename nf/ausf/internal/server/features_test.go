package server

// features_test.go - supportedFeatures negotiation of the AUSF (REL19-2.7
// slice 2): producer side of Nausf_UEAuthentication (AuthenticationInfo) and
// consumer side of Nudm_UEAU. Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571
// §5.2.2; TS 29.509 §6.1.9; TS 29.503 §6.3.8.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/aka"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// syncBuf is a goroutine-safe log sink.
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

// implCatalog implements Nausf feature 1 (ES3XX) so a non-empty set can be
// negotiated; unit tests only, the real AUSF catalog implements nothing.
func nausfImplCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NausfUEAuthenticationEntries(), 1)...)
}

// nudmImplCatalog implements Nudm_UEAU feature 1 (SUBDMIG, Rel-19).
func nudmImplCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NudmUEAUEntries(), 1)...)
}

// recUDM is a UDM double returning the fixed AV plus a configurable answer.
type recUDM struct {
	fixedUDM
	answer string
	calls  int
}

func (m *recUDM) GenerateAuthData(ctx context.Context, supi string, req *UDMAuthDataRequest) (*UDMAuthDataResponse, error) {
	m.calls++
	resp, err := m.fixedUDM.GenerateAuthData(ctx, supi, req)
	if resp != nil {
		resp.SupportedFeatures = m.answer
	}
	return resp, err
}

type featureEnv struct {
	srv  *Server
	udm  *recUDM
	logs *syncBuf
}

func newFeatureServer(t *testing.T, p *capability.Profile, nausf, nudm *features.Catalog, answer string) featureEnv {
	t.Helper()
	logs := &syncBuf{}
	udm := &recUDM{answer: answer}
	srv, err := New(Config{NFInstanceID: "11111111-2222-3333-4444-555555555555", ServingNetworkName: "5G:mnc001.mcc001.3gppnetwork.org"},
		udm, aka.NewStore(), slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetProfile(p)
	srv.SetCatalogs(nausf, nudm)
	return featureEnv{srv: srv, udm: udm, logs: logs}
}

func (e featureEnv) post(t *testing.T, body string) (*http.Response, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/nausf-auth/v1/ue-authentications", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// negotiationLines returns the decoded FeatureNegotiation log records.
func (e featureEnv) negotiationLines(t *testing.T) []map[string]any {
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

const authBody = `{"supiOrSuci":"suci-0-001-01-0000-0-0-0000000001","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"`

func TestProducerNegotiation(t *testing.T) {
	tests := []struct {
		name      string
		profile   string
		peer      string // "" = attribute omitted
		wantLocal string
		wantPeer  string
		wantNeg   string
	}{
		{"rel17 absent", "rel17", "", "1", "absent", "0"},
		{"rel19 absent", "rel19", "", "1", "absent", "0"},
		{"rel17 peer bit1", "rel17", "1", "1", "1", "1"},
		{"rel19 peer bit1+unknown", "rel19", "ff", "1", "ff", "1"},
		{"rel19 peer zero", "rel19", "0", "1", "0", "0"},
		{"rel17 peer uppercase hex", "rel17", "FF", "1", "FF", "1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newFeatureServer(t, profileNamed(t, tc.profile), nausfImplCatalog(), nil, "")
			body := authBody
			if tc.peer != "" {
				body += `,"supportedFeatures":"` + tc.peer + `"`
			}
			resp, raw := e.post(t, body+"}")
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status %d: %s", resp.StatusCode, raw)
			}
			// UEAuthenticationCtx has no supportedFeatures attribute.
			if bytes.Contains(raw, []byte("supportedFeatures")) {
				t.Errorf("201 body must not carry supportedFeatures: %s", raw)
			}
			var rec map[string]any
			for _, l := range e.negotiationLines(t) {
				if l["interface"] == "Nausf" {
					rec = l
				}
			}
			if rec == nil {
				t.Fatalf("no Nausf FeatureNegotiation line:\n%s", e.logs.bytes())
			}
			want := map[string]any{
				"direction": "IN", "peer_nf_type": "AMF", "spec_ref": "TS 29.500 §6.6.2", "result": "OK",
				"features_local": tc.wantLocal, "features_peer": tc.wantPeer, "features_negotiated": tc.wantNeg,
			}
			for k, v := range want {
				if rec[k] != v {
					t.Errorf("%s=%v want %v", k, rec[k], v)
				}
			}
		})
	}
}

// TestInvalidSupportedFeaturesRejected: a non-hex or non-string value is
// answered 400 INVALID_MSG_FORMAT with the JSON Pointer in invalidParams, the
// UDM is never called and no auth context is created.
func TestInvalidSupportedFeaturesRejected(t *testing.T) {
	for _, tc := range []struct{ name, attr string }{
		{"non-hex", `"zz"`},
		{"hex with space", `"1 2"`},
		{"number", `3`},
		{"array", `["a"]`},
		{"object", `{"a":1}`},
		{"bool", `true`},
	} {
		for _, prof := range []string{"rel17", "rel19"} {
			t.Run(prof+"/"+tc.name, func(t *testing.T) {
				e := newFeatureServer(t, profileNamed(t, prof), nil, nil, "")
				resp, raw := e.post(t, authBody+`,"supportedFeatures":`+tc.attr+"}")
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
					t.Errorf("content-type %q", ct)
				}
				var pd struct {
					Status        int    `json:"status"`
					Cause         string `json:"cause"`
					InvalidParams []struct {
						Param string `json:"param"`
					} `json:"invalidParams"`
				}
				if err := json.Unmarshal(raw, &pd); err != nil {
					t.Fatal(err)
				}
				if pd.Status != 400 || pd.Cause != "INVALID_MSG_FORMAT" ||
					len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != "/supportedFeatures" {
					t.Errorf("problem details %s", raw)
				}
				if e.udm.calls != 0 {
					t.Error("UDM must not be called for a rejected request")
				}
				lines := e.negotiationLines(t)
				if len(lines) != 1 || lines[0]["result"] != "REJECT" || lines[0]["cause"] != "INVALID_MSG_FORMAT" ||
					lines[0]["spec_ref"] != features.SpecRefInvalid {
					t.Errorf("log lines %v", lines)
				}
			})
		}
	}
}

// TestNullAndEmptySupportedFeaturesAreAbsent: JSON null and "" behave as an
// omitted attribute (Go omitempty cannot tell them apart).
func TestNullAndEmptySupportedFeaturesAreAbsent(t *testing.T) {
	for _, attr := range []string{`null`, `""`} {
		e := newFeatureServer(t, profileNamed(t, "rel17"), nil, nil, "")
		resp, raw := e.post(t, authBody+`,"supportedFeatures":`+attr+"}")
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: status %d %s", attr, resp.StatusCode, raw)
		}
	}
}

// TestConsumerOfferToUDM: D2 - nothing under rel17, the offered set (or "0")
// under rel19.
func TestConsumerOfferToUDM(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		cat     *features.Catalog
		want    string
	}{
		{"rel17 empty catalog", "rel17", nil, ""},
		{"rel17 implemented catalog", "rel17", nudmImplCatalog(), ""}, // SUBDMIG is Rel19, gated out
		{"rel19 empty catalog", "rel19", nil, "0"},
		{"rel19 SUBDMIG", "rel19", nudmImplCatalog(), "1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newFeatureServer(t, profileNamed(t, tc.profile), nil, tc.cat, "")
			if resp, raw := e.post(t, authBody+"}"); resp.StatusCode != http.StatusCreated {
				t.Fatalf("status %d %s", resp.StatusCode, raw)
			}
			if got := e.udm.lastReq.SupportedFeatures; got != tc.want {
				t.Errorf("offer=%q want %q", got, tc.want)
			}
		})
	}
}

func TestConsumerAcceptsUDMAnswer(t *testing.T) {
	tests := []struct {
		name       string
		answer     string
		wantNeg    string
		wantResult string
		wantPeer   string
	}{
		{"intersection", "3", "1", "OK", "3"},
		{"empty answer", "", "0", "OK", "absent"},
		{"zero answer", "0", "0", "OK", "0"},
		{"non-hex answer fails closed", "zz", "0", "FAILURE", "zz"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newFeatureServer(t, profileNamed(t, "rel19"), nil, nudmImplCatalog(), tc.answer)
			resp, raw := e.post(t, authBody+"}")
			if resp.StatusCode != http.StatusCreated { // R13: never fails the procedure
				t.Fatalf("status %d %s", resp.StatusCode, raw)
			}
			var rec map[string]any
			for _, l := range e.negotiationLines(t) {
				if l["interface"] == "Nudm" {
					rec = l
				}
			}
			if rec == nil {
				t.Fatalf("no Nudm line:\n%s", e.logs.bytes())
			}
			if rec["direction"] != "OUT" || rec["peer_nf_type"] != "UDM" || rec["result"] != tc.wantResult ||
				rec["features_negotiated"] != tc.wantNeg || rec["features_peer"] != tc.wantPeer ||
				rec["features_local"] != "1" || rec["spec_ref"] != "TS 29.500 §6.6.2" {
				t.Errorf("record %v", rec)
			}
		})
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line.
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	e := newFeatureServer(t, profileNamed(t, "rel19"), nausfImplCatalog(), nudmImplCatalog(), "1")
	e.post(t, authBody+`,"supportedFeatures":"1"}`)
	e.post(t, authBody+`,"supportedFeatures":"zz"}`)
	n := 0
	for _, line := range bytes.Split(bytes.TrimSpace(e.logs.bytes()), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"procedure":"`+features.ProcedureName+`"`)) {
			continue
		}
		n++
		for _, k := range []string{"nf", "nf_instance_id", "procedure", "correlation_id", "interface", "direction", "spec_ref",
			"peer_nf_type", "features_local", "features_peer", "features_negotiated", "result"} {
			if c := bytes.Count(line, []byte(`"`+k+`":`)); c != 1 {
				t.Errorf("key %q appears %d times in %s", k, c, line)
			}
		}
	}
	// success: Nausf + Nudm lines; reject: one Nausf line.
	if n != 3 {
		t.Fatalf("FeatureNegotiation lines = %d, want 3:\n%s", n, e.logs.bytes())
	}
}

// TestNonHexUDMAnswerIsFailureEvenWithEmptyOffer: features.Accept returns early
// on an empty offer (R14), so the AUSF validates the answer itself; a malformed
// UDM answer is logged result=FAILURE under both profiles and never fails the
// authentication.
func TestNonHexUDMAnswerIsFailureEvenWithEmptyOffer(t *testing.T) {
	for _, prof := range []string{"rel17", "rel19"} { // rel17: offer ""; rel19: offer "0"
		e := newFeatureServer(t, profileNamed(t, prof), nil, nil, "zz")
		resp, raw := e.post(t, authBody+"}")
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: status %d %s", prof, resp.StatusCode, raw)
		}
		var rec map[string]any
		for _, l := range e.negotiationLines(t) {
			if l["interface"] == "Nudm" {
				rec = l
			}
		}
		if rec == nil || rec["result"] != "FAILURE" || rec["features_negotiated"] != "0" {
			t.Errorf("%s: record %v", prof, rec)
		}
	}
}

// TestLongPeerValueTruncatedInLogAndBodyCapped: the logged features_peer is
// bounded and an oversized body is rejected without reaching the UDM.
func TestLongPeerValueTruncatedInLogAndBodyCapped(t *testing.T) {
	e := newFeatureServer(t, profileNamed(t, "rel19"), nil, nil, "")
	long := strings.Repeat("f", 4000)
	resp, _ := e.post(t, authBody+`,"supportedFeatures":"`+long+`"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("schema-valid long value: status %d", resp.StatusCode)
	}
	for _, l := range e.negotiationLines(t) {
		if l["interface"] != "Nausf" {
			continue
		}
		if p, _ := l["features_peer"].(string); len(p) != features.MaxLoggedPeerChars+3 || !strings.HasSuffix(p, "...") {
			t.Errorf("features_peer not truncated: %d chars", len(p))
		}
	}
	e2 := newFeatureServer(t, profileNamed(t, "rel19"), nil, nil, "")
	huge := strings.Repeat("f", features.MaxRequestBodyBytes+10)
	resp, _ = e2.post(t, authBody+`,"supportedFeatures":"`+huge+`"}`)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || e2.udm.calls != 0 {
		t.Errorf("oversized body: status %d, udm calls %d", resp.StatusCode, e2.udm.calls)
	}
}
