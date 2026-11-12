package server

// features_test.go - SBI supportedFeatures negotiation of the SMF
// (TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2), REL19-2.7. The legacy
// (rel17 / no profile) wire bytes are pinned by features_golden_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// testCatalog implements F1 (bit 1, Rel-17) and F9 (bit 9, Rel-19), mirroring
// the symbolic features of feature_negotiation.feature.
func testCatalog() *features.Catalog {
	return features.MustCatalog(
		features.Entry{Number: 1, Name: "F1", Release: capability.Rel17, Implemented: true},
		features.Entry{Number: 9, Name: "F9", Release: capability.Rel19, Implemented: true},
	)
}

func profileFor(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("NewProfile(%q): %v", name, err)
	}
	return p
}

// syncBuffer is a goroutine-safe log sink (the detached PFCP goroutine logs
// concurrently with the test reading).
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newFeatureServer builds a deterministic server with a captured JSON log.
func newFeatureServer(t *testing.T, profile string, nsmf, namf *features.Catalog) (*Server, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	cfg := &config.Config{
		UEIPPool:  "10.60.0.0/24",
		UPFN3Addr: "192.0.2.10",
		DNNs:      []config.DNNConfig{{Name: "internet", UEIPPool: "10.60.0.0/24"}},
	}
	opts := []Option{WithCatalogs(nsmf, namf)}
	if profile != "" {
		opts = append(opts, WithProfile(profileFor(t, profile)))
	}
	// main.go puts nf on the root logger; New does not add it.
	s, err := New(cfg, slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "SMF"), nil, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, logs
}

// negotiationLogs returns the FeatureNegotiation log records in logs.
func negotiationLogs(t *testing.T, logs *syncBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		if m["procedure"] == features.ProcedureName {
			out = append(out, m)
		}
	}
	return out
}

func singleSession(t *testing.T, s *Server) *Session {
	t.Helper()
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if len(s.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(s.sessions))
	}
	for _, sess := range s.sessions {
		return sess
	}
	return nil
}

// TestCreateSMContext_FeatureNegotiation covers decision D1 on the producer.
func TestCreateSMContext_FeatureNegotiation(t *testing.T) {
	absent := struct{}{}
	tests := []struct {
		name      string
		profile   string // "" = no profile loaded
		offer     any    // absent = attribute not sent
		wantAns   string // "" = attribute must be omitted
		wantStore string // canonical negotiated set stored on the Session
		wantPeer  string // features_peer in the log
		wantLocal string
	}{
		{"rel19 absent", "rel19", absent, "0", "0", "absent", "101"},
		{"rel19 empty", "rel19", "", "0", "0", "absent", "101"},
		{"rel19 zero", "rel19", "0", "0", "0", "0", "101"},
		{"rel19 000", "rel19", "000", "0", "0", "000", "101"},
		{"rel19 F1", "rel19", "1", "1", "1", "1", "101"},
		{"rel19 F1+F9", "rel19", "101", "101", "101", "101", "101"},
		{"rel19 uppercase", "rel19", "1B", "1", "1", "1B", "101"},
		{"rel19 leading zeros", "rel19", "00101", "101", "101", "00101", "101"},
		{"rel19 undefined high bit", "rel19", "8000000001", "1", "1", "8000000001", "101"},
		{"rel19 over-long valid", "rel19", "00000000000000000000000000000000000000000000000000000101", "101", "101", "00000000000000000000000000000000000000000000000000000101", "101"},
		{"rel19 no common feature", "rel19", "2", "0", "0", "2", "101"},
		{"rel17 absent", "rel17", absent, "", "0", "absent", "1"},
		{"rel17 empty", "rel17", "", "", "0", "absent", "1"},
		{"rel17 zero", "rel17", "0", "0", "0", "0", "1"},
		{"rel17 F1+F9 offer", "rel17", "101", "1", "1", "101", "1"},
		{"no profile absent", "", absent, "", "0", "absent", "1"},
		{"no profile F1", "", "1", "1", "1", "1", "1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, logs := newFeatureServer(t, tc.profile, testCatalog(), nil)
			extra := map[string]any{}
			if tc.offer != absent {
				extra["supportedFeatures"] = tc.offer
			}
			w := postCreateSMContext(t, s, extra)
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			got, has := body["supportedFeatures"]
			if tc.wantAns == "" && has {
				t.Fatalf("supportedFeatures must be omitted, got %v", got)
			}
			if tc.wantAns != "" && got != tc.wantAns {
				t.Fatalf("supportedFeatures = %v, want %q", got, tc.wantAns)
			}
			if st := singleSession(t, s).Features.String(); st != tc.wantStore {
				t.Fatalf("stored features = %q, want %q", st, tc.wantStore)
			}
			recs := negotiationLogs(t, logs)
			if len(recs) != 1 {
				t.Fatalf("FeatureNegotiation lines = %d, want 1", len(recs))
			}
			r := recs[0]
			for k, want := range map[string]string{
				"nf": "SMF", "interface": "Nsmf", "direction": "IN", "peer_nf_type": "AMF",
				"spec_ref": features.SpecRef, "result": "OK",
				"features_peer": tc.wantPeer, "features_local": tc.wantLocal,
				"features_negotiated": tc.wantStore, "correlation_id": "01TESTCORRELATIONID00000000",
				"supi": "imsi-001010000000001",
			} {
				if r[k] != want {
					t.Errorf("log %s = %v, want %q", k, r[k], want)
				}
			}
			if r["pdu_session_id"] != float64(1) {
				t.Errorf("log pdu_session_id = %v", r["pdu_session_id"])
			}
		})
	}
}

// TestCreateSMContext_InvalidSupportedFeatures: a non-hex or non-string value
// is rejected before any side effect, under both profiles (TS 29.500 §5.2.7.2).
func TestCreateSMContext_InvalidSupportedFeatures(t *testing.T) {
	for _, profile := range []string{"rel17", "rel19", ""} {
		for _, offer := range []any{"zz", "0x1", "1 01", " 1", float64(5), true, []any{"1"}} {
			t.Run(profile+"/"+jsonString(offer), func(t *testing.T) {
				s, logs := newFeatureServer(t, profile, testCatalog(), nil)
				w := postCreateSMContext(t, s, map[string]any{"supportedFeatures": offer})
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d: %s", w.Code, w.Body.String())
				}
				if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
					t.Errorf("content-type = %q", ct)
				}
				var pd struct {
					Cause         string              `json:"cause"`
					InvalidParams []map[string]string `json:"invalidParams"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &pd); err != nil {
					t.Fatal(err)
				}
				if pd.Cause != "INVALID_MSG_FORMAT" || len(pd.InvalidParams) != 1 || pd.InvalidParams[0]["param"] != "/supportedFeatures" {
					t.Fatalf("problem = %s", w.Body.String())
				}
				// No side effect: no session, no IP, no TEID/SEID consumed.
				s.sessionMu.Lock()
				n := len(s.sessions)
				s.sessionMu.Unlock()
				if n != 0 || s.nextTEID.Load() != 0 || s.nextSEID.Load() != 0 {
					t.Fatalf("side effects after 400: sessions=%d teid=%d seid=%d", n, s.nextTEID.Load(), s.nextSEID.Load())
				}
				fresh, _ := NewIPPool("10.60.0.0/24")
				wantIP, _ := fresh.Allocate()
				if ip, err := s.ipPools["internet"].Allocate(); err != nil || !ip.Equal(wantIP) {
					t.Fatalf("IP pool touched: first alloc = %v (want %v), %v", ip, wantIP, err)
				}
				recs := negotiationLogs(t, logs)
				if len(recs) != 1 {
					t.Fatalf("FeatureNegotiation lines = %d", len(recs))
				}
				r := recs[0]
				if r["result"] != "REJECT" || r["cause"] != "INVALID_MSG_FORMAT" || r["spec_ref"] != features.SpecRefInvalid || r["direction"] != "IN" {
					t.Errorf("log = %v", r)
				}
			})
		}
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestCreateSMContext_NullSupportedFeaturesIsAbsent: JSON null is treated as
// an absent attribute (rel17 -> omitted).
func TestCreateSMContext_NullSupportedFeaturesIsAbsent(t *testing.T) {
	s, _ := newFeatureServer(t, "rel17", testCatalog(), nil)
	w := postCreateSMContext(t, s, map[string]any{"supportedFeatures": nil})
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "supportedFeatures") {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

// TestCreateSMContext_Rel17ProfileBytesIdentical: an explicit rel17 profile and
// the default production catalog produce exactly the pre-change body.
func TestCreateSMContext_Rel17ProfileBytesIdentical(t *testing.T) {
	for _, profile := range []string{"rel17", ""} {
		s, _ := newFeatureServer(t, profile, nil, nil)
		w := postCreateSMContext(t, s, nil)
		got := uuidRE.ReplaceAllString(w.Body.String(), goldenSMContextRef)
		if want := string(readGolden(t, "golden_create_sm_context_201.json")); got != want {
			t.Fatalf("profile %q: body changed\n got: %q\nwant: %q", profile, got, want)
		}
	}
}

// TestCreateSMContext_Rel19DefaultCatalog: the production catalog implements
// nothing, so rel19 answers "0" and an offered bit negotiates to "0".
func TestCreateSMContext_Rel19DefaultCatalog(t *testing.T) {
	s, _ := newFeatureServer(t, "rel19", nil, nil)
	w := postCreateSMContext(t, s, map[string]any{"supportedFeatures": "ffff"})
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["supportedFeatures"] != "0" {
		t.Fatalf("body = %s", w.Body.String())
	}
}

// TestCreateSMContext_SecondaryAuthCarriesFeatures: the deferred (pending
// secondary authentication) 201 carries the answer, and the negotiated set
// reaches the Session created on authorization.
func TestCreateSMContext_SecondaryAuthCarriesFeatures(t *testing.T) {
	s, _ := newFeatureServer(t, "rel19", testCatalog(), nil)
	s.secondaryAuthDNNs[secondaryAuthDNN] = true
	pool, _ := NewIPPool("10.70.0.0/24")
	s.ipPools[secondaryAuthDNN] = pool
	s.n1n2Push = func(context.Context, string, uint8, []byte, []byte, string) (string, error) {
		return "N1_N2_TRANSFER_INITIATED", nil
	}
	w := postCreateSMContext(t, s, map[string]any{"dnn": secondaryAuthDNN, "supportedFeatures": "101"})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["supportedFeatures"] != "101" {
		t.Fatalf("pending 201 = %s", w.Body.String())
	}
	ref, _ := body["smContextRef"].(string)
	p := s.getPendingAuth(ref)
	if p == nil || p.Features.String() != "101" {
		t.Fatalf("pending features not recorded: %+v", p)
	}
}

// ---- consumer side ---------------------------------------------------------

func TestN1N2Paging_FeatureNegotiation(t *testing.T) {
	tests := []struct {
		name     string
		profile  string
		namf     *features.Catalog
		answer   string // AMF supportedFeatures answer ("" = none)
		wantBody string
		wantNeg  string
		wantRes  string
	}{
		{"rel17 sends nothing", "rel17", testCatalog(), "", `{"pduSessionId":1}`, "0", "OK"},
		{"no profile sends nothing", "", testCatalog(), "", `{"pduSessionId":1}`, "0", "OK"},
		{"rel17 ignores AMF answer", "rel17", testCatalog(), "101", `{"pduSessionId":1}`, "0", "OK"},
		{"rel19 default catalog offers 40 (ES3XX)", "rel19", nil, "", `{"pduSessionId":1,"supportedFeatures":"40"}`, "0", "OK"},
		{"rel19 default catalog ES3XX answered", "rel19", nil, "40", `{"pduSessionId":1,"supportedFeatures":"40"}`, "40", "OK"},
		{"rel19 offers F1+F9 answered F1", "rel19", testCatalog(), "1", `{"pduSessionId":1,"supportedFeatures":"101"}`, "1", "OK"},
		{"rel19 answer has unoffered bit", "rel19", testCatalog(), "103", `{"pduSessionId":1,"supportedFeatures":"101"}`, "101", "OK"},
		{"rel19 absent answer", "rel19", testCatalog(), "", `{"pduSessionId":1,"supportedFeatures":"101"}`, "0", "OK"},
		{"rel19 non-hex answer fails closed", "rel19", testCatalog(), "zz", `{"pduSessionId":1,"supportedFeatures":"101"}`, "0", "FAILURE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rsp := `{"cause":"ATTEMPTING_TO_REACH_UE"`
			if tc.answer != "" {
				rsp += `,"supportedFeatures":"` + tc.answer + `"`
			}
			rsp += "}"
			ts, ch := amfCapture(t, rsp)
			s, logs := newFeatureServer(t, tc.profile, nil, tc.namf)
			pointAtAMF(s, ts)
			cause, err := s.triggerN1N2MessageTransfer(context.Background(), "imsi-001010000000001", 1)
			if err != nil || cause != "ATTEMPTING_TO_REACH_UE" {
				t.Fatalf("procedure must not fail: cause=%q err=%v", cause, err)
			}
			if got := string(<-ch); got != tc.wantBody {
				t.Fatalf("body = %s, want %s", got, tc.wantBody)
			}
			recs := negotiationLogs(t, logs)
			if len(recs) != 1 {
				t.Fatalf("FeatureNegotiation lines = %d", len(recs))
			}
			r := recs[0]
			if r["features_negotiated"] != tc.wantNeg || r["result"] != tc.wantRes ||
				r["direction"] != "OUT" || r["interface"] != "Namf" || r["peer_nf_type"] != "AMF" ||
				r["spec_ref"] != features.SpecRef || r["nf"] != "SMF" {
				t.Errorf("log = %v", r)
			}
		})
	}
}

func TestN1N2Push_FeatureNegotiation(t *testing.T) {
	ts, ch := amfCapture(t, `{"cause":"N1_N2_TRANSFER_INITIATED","supportedFeatures":"1"}`)
	s, _ := newFeatureServer(t, "rel19", nil, testCatalog())
	pointAtAMF(s, ts)
	if _, err := s.pushN1N2Message(context.Background(), "imsi-001010000000001", 1, []byte{0x2e, 0x01, 0x05, 0xc5}, []byte{1, 2}, "PDU_RES_SETUP_REQ"); err != nil {
		t.Fatal(err)
	}
	want := `{"n1SmMsg":"LgEFxQ==","n2SmInfo":"AQI=","n2SmInfoType":"PDU_RES_SETUP_REQ","pduSessionId":1,"supportedFeatures":"101"}`
	if got := string(<-ch); got != want {
		t.Fatalf("body = %s", got)
	}
}

// TestN1N2_Rel17BodiesIdenticalToGolden: with an explicit rel17 profile (and a
// catalog that WOULD offer features) both N1N2 bodies equal the pre-change goldens.
func TestN1N2_Rel17BodiesIdenticalToGolden(t *testing.T) {
	ts, ch := amfCapture(t, `{"cause":"X"}`)
	s, _ := newFeatureServer(t, "rel17", nil, testCatalog())
	pointAtAMF(s, ts)
	if _, err := s.triggerN1N2MessageTransfer(context.Background(), "imsi-001010000000001", 1); err != nil {
		t.Fatal(err)
	}
	if got, want := string(<-ch), string(readGolden(t, "golden_n1n2_paging_body.json")); got != want {
		t.Fatalf("paging body = %s", got)
	}
	if _, err := s.pushN1N2Message(context.Background(), "imsi-001010000000001", 1,
		[]byte{0x2e, 0x01, 0x05, 0xc5}, []byte{0x01, 0x02}, "PDU_RES_SETUP_REQ"); err != nil {
		t.Fatal(err)
	}
	if got, want := string(<-ch), string(readGolden(t, "golden_n1n2_push_body.json")); got != want {
		t.Fatalf("push body = %s", got)
	}
}

// ---- NRF profile -----------------------------------------------------------

func TestBuildNFProfile_SupportedFeatures(t *testing.T) {
	cfg := &config.Config{
		NFInstanceID: "11111111-2222-3333-4444-555555555555",
		SNSSAIs: []struct {
			SST int    `yaml:"sst"`
			SD  string `yaml:"sd"`
		}{{SST: 1, SD: "000001"}, {SST: 2, SD: "000002"}},
		DNNs: []config.DNNConfig{{Name: "internet"}, {Name: "ims"}},
	}
	golden := string(readGolden(t, "golden_nf_profile.json"))
	for _, p := range []*capability.Profile{nil, profileFor(t, "rel17")} {
		b, _ := json.Marshal(BuildNFProfile(cfg, p))
		if string(b) != golden {
			t.Fatalf("rel17/nil profile changed:\n%s", b)
		}
	}
	b, _ := json.Marshal(BuildNFProfile(cfg, profileFor(t, "rel19")))
	want := strings.Replace(golden, `"nfServiceStatus":"REGISTERED"}]`, `"nfServiceStatus":"REGISTERED","supportedFeatures":"0"}]`, 1)
	rel19 := apiversion.Of(profileFor(t, "rel19"), apiversion.NsmfPDUSession).Full
	want = strings.Replace(want, `"apiFullVersion":"`+apiversion.Of(nil, apiversion.NsmfPDUSession).Full+`"`, `"apiFullVersion":"`+rel19+`"`, 1)
	if string(b) != want {
		t.Fatalf("rel19 profile:\n got %s\nwant %s", b, want)
	}
	if nsmfPDUSessionCatalog.Supported(profileFor(t, "rel19")).String() != "0" {
		t.Fatal("SMF must implement no Nsmf_PDUSession feature yet")
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so each canonical key must appear exactly once in the raw producer and
// consumer FeatureNegotiation lines (the producer line must not inherit the
// SmContextCreate handler logger's procedure/interface/direction).
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	check := func(t *testing.T, logs *syncBuffer, wantLines int, wantCorr bool) {
		t.Helper()
		n := 0
		for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
			if !strings.Contains(line, `"procedure":"`+features.ProcedureName+`"`) {
				continue
			}
			n++
			for _, k := range []string{"nf", "procedure", "interface", "direction", "spec_ref", "result", "features_peer"} {
				if c := strings.Count(line, `"`+k+`":`); c != 1 {
					t.Errorf("key %q appears %d times in %s", k, c, line)
				}
			}
			if c := strings.Count(line, `"correlation_id":`); wantCorr && c != 1 || !wantCorr && c > 1 {
				t.Errorf("correlation_id appears %d times in %s", c, line)
			}
		}
		if n != wantLines {
			t.Fatalf("FeatureNegotiation lines = %d, want %d", n, wantLines)
		}
	}
	t.Run("producer OK and REJECT", func(t *testing.T) {
		s, logs := newFeatureServer(t, "rel19", testCatalog(), nil)
		postCreateSMContext(t, s, map[string]any{"supportedFeatures": "101"})
		postCreateSMContext(t, s, map[string]any{"supportedFeatures": "zz"})
		check(t, logs, 2, true)
	})
	t.Run("consumer", func(t *testing.T) {
		ts, _ := amfCapture(t, `{"cause":"ATTEMPTING_TO_REACH_UE","supportedFeatures":"1"}`)
		s, logs := newFeatureServer(t, "rel19", nil, testCatalog())
		pointAtAMF(s, ts)
		ctx := logging.WithCorrelationID(context.Background(), "01TESTCORRELATIONID00000000")
		if _, err := s.triggerN1N2MessageTransfer(ctx, "imsi-001010000000001", 1); err != nil {
			t.Fatal(err)
		}
		check(t, logs, 1, true)
	})
}
