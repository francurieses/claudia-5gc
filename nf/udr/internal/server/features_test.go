package server

// features_test.go - producer-side supportedFeatures negotiation of
// Nudr_DataRepository (REL19-2.7 slice 5). Ref: TS 29.500 §6.6.2, §5.2.7.2;
// TS 29.571 §5.2.2; TS 29.504 §6.1.8; TS 29.505; TS 29.519 §5.4.2.4-5.

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

	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
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

// implCatalog implements Nudr feature 9 SessionManagementPolicyDataPatch and
// 1 ResourceRemovalNotificationPolicyData so a non-empty set can be
// negotiated; unit tests only.
func implCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NudrDataRepositoryEntries(), 1, 9)...)
}

const (
	supi   = "imsi-001010000000001"
	subURL = "/nudr-dr/v2/subscription-data/" + supi
	polURL = "/nudr-dr/v2/policy-data/" + supi
)

func newFeatureUDR(t *testing.T, p *capability.Profile, cat *features.Catalog) (*Server, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	st := store.NewInMemory()
	if err := store.SeedTestSubscriberWithNSSAI(st, supi, "465b5ce8b199b49faa5f0a2ee238a6bc",
		"cd63cb71954a9f4e48a5994e37a02baf", "b9b9", "000000000020",
		[]store.SNSSAISubscribed{{SST: 1, SD: "000001"}}); err != nil {
		t.Fatal(err)
	}
	// Like cmd/udr/main.go, the process logger already carries nf and New must
	// not add it again (TestFeatureNegotiationLogKeysOnce counts the keys).
	s, err := New(":0", TLSConfig{}, st, slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "UDR"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetProfile(p)
	s.SetCatalog(cat)
	return s, logs
}

func call(s *Server, method, path, body, ua string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func seedPolicy(t *testing.T, s *Server) {
	t.Helper()
	if rec := call(s, http.MethodPut, polURL+"/ue-policy-set", `{"precedence":10,"rules":[]}`, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT ue-policy-set: %d %s", rec.Code, rec.Body)
	}
	if rec := call(s, http.MethodPut, polURL+"/sm-data",
		`{"smPolicySnssaiData":{"1":{"snssai":{"sst":1}}}}`, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT sm-data: %d %s", rec.Code, rec.Body)
	}
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

func bodyMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	return m
}

type problemBody struct {
	Cause         string `json:"cause"`
	InvalidParams []struct {
		Param string `json:"param"`
	} `json:"invalidParams"`
}

func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, cause, param string) {
	t.Helper()
	var pd problemBody
	if err := json.Unmarshal(rec.Body.Bytes(), &pd); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	if rec.Code != http.StatusBadRequest || pd.Cause != cause || len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != param {
		t.Errorf("status %d problem %s, want 400 %s %s", rec.Code, rec.Body, cause, param)
	}
	if ct := rec.Result().Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("content-type %q", ct)
	}
}

// TestAnsweringGETs covers D1 on the three GETs whose response schema carries
// an attribute: rel17 omits it when the request had none, rel19 always
// answers, and a request that carries a value is answered with the
// intersection under both profiles.
func TestAnsweringGETs(t *testing.T) {
	endpoints := []struct {
		name, path, query, attr string
	}{
		{"am-data", subURL + "/00101/provisioned-data/am-data", "supported-features", "supportedFeatures"},
		{"ue-policy-set", polURL + "/ue-policy-set", "supp-feat", "suppFeat"},
		{"policy sm-data", polURL + "/sm-data", "supp-feat", "suppFeat"},
	}
	tests := []struct {
		name, profile, peer string // peer "" = query parameter omitted
		cat                 *features.Catalog
		want                string // "" = attribute absent
		wantLog             string
	}{
		{"rel17 absent", "rel17", "", nil, "", "absent"},
		{"rel19 absent", "rel19", "", nil, "0", "absent"},
		{"rel17 peer, nothing implemented", "rel17", "f", nil, "0", "f"},
		{"rel19 peer, nothing implemented", "rel19", "ff", nil, "0", "ff"},
		{"rel19 both bits", "rel19", "101", implCatalog(), "101", "101"},
		{"rel19 higher bits dropped", "rel19", "ffff", implCatalog(), "101", "ffff"},
		{"rel19 peer lacks them", "rel19", "2", implCatalog(), "0", "2"},
		{"rel17 peer has bit 1", "rel17", "3", implCatalog(), "1", "3"},
		{"rel17 absent, catalog implements", "rel17", "", implCatalog(), "", "absent"},
		{"rel19 uppercase", "rel19", "FF", implCatalog(), "1", "FF"},
	}
	for _, ep := range endpoints {
		for _, tc := range tests {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				s, logs := newFeatureUDR(t, profileNamed(t, tc.profile), tc.cat)
				seedPolicy(t, s)
				before := len(negotiationRecords(logs))
				path := ep.path
				if tc.peer != "" {
					path += "?" + ep.query + "=" + tc.peer
				}
				rec := call(s, http.MethodGet, path, "", "PCF-1234")
				if rec.Code != http.StatusOK {
					t.Fatalf("status %d: %s", rec.Code, rec.Body)
				}
				got := bodyMap(t, rec)
				sf, present := got[ep.attr]
				if tc.want == "" && present {
					t.Errorf("%s must be absent, got %v", ep.attr, sf)
				}
				if tc.want != "" && sf != tc.want {
					t.Errorf("%s=%v want %q", ep.attr, sf, tc.want)
				}
				recs := negotiationRecords(logs)[before:]
				if len(recs) != 1 {
					t.Fatalf("FeatureNegotiation lines = %d, want 1", len(recs))
				}
				rc := recs[0]
				if rc["features_peer"] != tc.wantLog || rc["peer_nf_type"] != "PCF" || rc["direction"] != "IN" ||
					rc["interface"] != "Nudr" || rc["result"] != "OK" || rc["spec_ref"] != "TS 29.500 §6.6.2" ||
					rc["correlation_id"] != "01TESTCORRELATIONID00000000" || rc["nf"] != "UDR" {
					t.Errorf("log record %v", rc)
				}
			})
		}
	}
}

// TestQueryOnlyEndpoints: authentication-subscription and sm-data have a
// features query parameter but no response attribute; the response bytes do
// not depend on the value, which is validated and logged.
func TestQueryOnlyEndpoints(t *testing.T) {
	for _, path := range []string{
		subURL + "/authentication-data/authentication-subscription",
		subURL + "/00101/provisioned-data/sm-data",
	} {
		for _, prof := range []string{"rel17", "rel19"} {
			t.Run(prof+path, func(t *testing.T) {
				s, logs := newFeatureUDR(t, profileNamed(t, prof), implCatalog())
				plain := call(s, http.MethodGet, path, "", "")
				withSF := call(s, http.MethodGet, path+"?supported-features=ff", "", "UDM-9")
				if plain.Code != http.StatusOK || withSF.Code != http.StatusOK || plain.Body.String() != withSF.Body.String() {
					t.Fatalf("response depends on supported-features: %d %q vs %d %q", plain.Code, plain.Body, withSF.Code, withSF.Body)
				}
				if bytes.Contains(withSF.Body.Bytes(), []byte("upportedFeatures")) {
					t.Errorf("unexpected attribute in %s", withSF.Body)
				}
				recs := negotiationRecords(logs)
				if len(recs) != 2 || recs[1]["features_peer"] != "ff" || recs[1]["features_negotiated"] != "1" || recs[1]["peer_nf_type"] != "UDM" {
					t.Errorf("records %v", recs)
				}
			})
		}
	}
}

func TestInvalidQueryRejected(t *testing.T) {
	cases := []struct{ method, path, body, param string }{
		{http.MethodGet, subURL + "/authentication-data/authentication-subscription", "", "supported-features"},
		{http.MethodPatch, subURL + "/authentication-data/authentication-subscription", `{"sequenceNumber":{"sqn":"000000000040"}}`, "supported-features"},
		{http.MethodGet, subURL + "/00101/provisioned-data/am-data", "", "supported-features"},
		{http.MethodGet, subURL + "/00101/provisioned-data/sm-data", "", "supported-features"},
		{http.MethodGet, polURL + "/ue-policy-set", "", "supp-feat"},
		{http.MethodGet, polURL + "/sm-data", "", "supp-feat"},
	}
	for _, c := range cases {
		for _, v := range []string{"zz", "0x1", "1%202", "g"} {
			for _, prof := range []string{"rel17", "rel19"} {
				t.Run(prof+"/"+c.method+c.path+"/"+v, func(t *testing.T) {
					s, logs := newFeatureUDR(t, profileNamed(t, prof), nil)
					seedPolicy(t, s)
					rec := call(s, c.method, c.path+"?"+c.param+"="+v, c.body, "")
					assertProblem(t, rec, "OPTIONAL_QUERY_PARAM_INCORRECT", "query "+c.param)
					if !bytes.Contains(logs.bytes(), []byte(`"result":"REJECT"`)) {
						t.Errorf("no REJECT log:\n%s", logs.bytes())
					}
				})
			}
		}
	}
}

// TestBodyAttributes: PUT ue-policy-set (suppFeat) and PUT amf-3gpp-access
// (supportedFeatures) validate the body attribute; their responses carry no
// body, so nothing is answered and nothing is stored or echoed.
func TestBodyAttributes(t *testing.T) {
	puts := []struct {
		name, path, attr string
		okStatus         int
		body             func(attr string) string
	}{
		{"ue-policy-set", polURL + "/ue-policy-set", "suppFeat", http.StatusNoContent,
			func(a string) string { return `{"precedence":10,"rules":[],"suppFeat":` + a + `}` }},
		{"amf-3gpp-access", subURL + "/context-data/amf-3gpp-access", "supportedFeatures", http.StatusCreated,
			func(a string) string {
				return `{"amfInstanceId":"11111111-2222-3333-4444-555555555555","supportedFeatures":` + a + `}`
			}},
	}
	for _, p := range puts {
		for _, prof := range []string{"rel17", "rel19"} {
			t.Run(p.name+"/"+prof+"/valid", func(t *testing.T) {
				s, logs := newFeatureUDR(t, profileNamed(t, prof), implCatalog())
				rec := call(s, http.MethodPut, p.path, p.body(`"101"`), "PCF-1")
				if rec.Code != p.okStatus || rec.Body.Len() != 0 {
					t.Fatalf("status %d body %q", rec.Code, rec.Body)
				}
				recs := negotiationRecords(logs)
				if len(recs) != 1 || recs[0]["features_peer"] != "101" || recs[0]["features_negotiated"] != "101" {
					t.Errorf("records %v", recs)
				}
			})
			for _, bad := range []string{`"zz"`, `"0x1"`, `7`, `true`, `{}`} {
				t.Run(p.name+"/"+prof+"/invalid "+bad, func(t *testing.T) {
					s, logs := newFeatureUDR(t, profileNamed(t, prof), nil)
					rec := call(s, http.MethodPut, p.path, p.body(bad), "")
					assertProblem(t, rec, "INVALID_MSG_FORMAT", "/"+p.attr)
					if !bytes.Contains(logs.bytes(), []byte(`"result":"REJECT"`)) {
						t.Errorf("no REJECT log:\n%s", logs.bytes())
					}
				})
			}
		}
	}
	t.Run("ue-policy-set invalid value is not stored", func(t *testing.T) {
		s, _ := newFeatureUDR(t, profileNamed(t, "rel19"), nil)
		call(s, http.MethodPut, polURL+"/ue-policy-set", `{"precedence":3,"rules":[],"suppFeat":"zz"}`, "")
		if rec := call(s, http.MethodGet, polURL+"/ue-policy-set", "", ""); rec.Code != http.StatusNotFound {
			t.Errorf("rejected PUT was stored: %d %s", rec.Code, rec.Body)
		}
	})
}

// TestClientSuppFeatNotEchoed: a suppFeat sent in a PUT body is never stored,
// so the GET answers only from its own query (response-only attribute).
func TestClientSuppFeatNotEchoed(t *testing.T) {
	s, _ := newFeatureUDR(t, profileNamed(t, "rel17"), nil)
	if rec := call(s, http.MethodPut, polURL+"/ue-policy-set", `{"precedence":10,"rules":[],"suppFeat":"ffff"}`, ""); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
	if rec := call(s, http.MethodPut, polURL+"/sm-data", `{"suppFeat":"ffff","smPolicySnssaiData":{"1":{"snssai":{"sst":1}}}}`, ""); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
	for _, path := range []string{polURL + "/ue-policy-set", polURL + "/sm-data"} {
		rec := call(s, http.MethodGet, path, "", "")
		if rec.Code != http.StatusOK || bytes.Contains(rec.Body.Bytes(), []byte("suppFeat")) {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
}

// TestLegacyErrorsKeepPrecedence: malformed bodies and unknown subscribers
// give their legacy answers and never an OK negotiation line.
func TestLegacyErrorsKeepPrecedence(t *testing.T) {
	s, logs := newFeatureUDR(t, profileNamed(t, "rel19"), nil)
	rec := call(s, http.MethodPut, polURL+"/ue-policy-set", `{`, "")
	var pd problemBody
	_ = json.Unmarshal(rec.Body.Bytes(), &pd)
	if rec.Code != http.StatusBadRequest || pd.Cause != "MANDATORY_IE_INCORRECT" {
		t.Errorf("malformed PUT: %d %s", rec.Code, rec.Body)
	}
	for _, path := range []string{
		"/nudr-dr/v2/subscription-data/imsi-001019999999999/authentication-data/authentication-subscription",
		"/nudr-dr/v2/subscription-data/imsi-001019999999999/00101/provisioned-data/am-data",
		"/nudr-dr/v2/subscription-data/imsi-001019999999999/00101/provisioned-data/sm-data",
		"/nudr-dr/v2/policy-data/imsi-001019999999999/ue-policy-set",
		"/nudr-dr/v2/policy-data/imsi-001019999999999/sm-data",
	} {
		if rec := call(s, http.MethodGet, path+"?supported-features=1&supp-feat=1", "", ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", path, rec.Code)
		}
	}
	if n := len(negotiationRecords(logs)); n != 0 {
		t.Errorf("FeatureNegotiation lines = %d, want 0", n)
	}
}

// TestAMFContextLegacyBodies: the registration body is optional input; an
// empty or non-JSON body keeps the legacy 201 under both profiles. A truly
// absent body ("" or null) is logged as features_peer=absent; a body that is
// not a JSON object is not negotiated at all, so no OK line claims "absent".
func TestAMFContextLegacyBodies(t *testing.T) {
	for _, prof := range []string{"rel17", "rel19"} {
		for _, tc := range []struct {
			body    string
			records int
		}{{"", 1}, {"null", 1}, {"{}", 1}, {"not json", 0}, {"[1,2]", 0}} {
			s, logs := newFeatureUDR(t, profileNamed(t, prof), nil)
			rec := call(s, http.MethodPut, subURL+"/context-data/amf-3gpp-access", tc.body, "")
			if rec.Code != http.StatusCreated || rec.Body.Len() != 0 {
				t.Errorf("%s body %q: %d %q", prof, tc.body, rec.Code, rec.Body)
			}
			recs := negotiationRecords(logs)
			if len(recs) != tc.records || (tc.records == 1 && recs[0]["features_peer"] != "absent") {
				t.Errorf("%s body %q: negotiation records %v, want %d", prof, tc.body, recs, tc.records)
			}
			if tc.records == 0 && !bytes.Contains(logs.bytes(), []byte("not a JSON object")) {
				t.Errorf("%s body %q: decode failure not logged:\n%s", prof, tc.body, logs.bytes())
			}
		}
	}
}

// errReader fails every read with a non-size error.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// TestOversizeAndUnreadableBodies: a body over features.MaxRequestBodyBytes is
// 413 (ProblemDetails without a cause, TS 29.500 §5.2.7.1) and an unreadable
// one 400; neither skips validation silently nor records a negotiation.
func TestOversizeAndUnreadableBodies(t *testing.T) {
	huge := `{"supportedFeatures":"1","pad":"` + strings.Repeat("x", features.MaxRequestBodyBytes) + `"}`
	hugePol := `{"suppFeat":"1","precedence":10,"pad":"` + strings.Repeat("x", features.MaxRequestBodyBytes) + `"}`
	for _, prof := range []string{"rel17", "rel19"} {
		for _, tc := range []struct{ name, path, body string }{
			{"amf ctx", subURL + "/context-data/amf-3gpp-access", huge},
			{"ue policy", polURL + "/ue-policy-set", hugePol},
		} {
			t.Run(prof+"/"+tc.name, func(t *testing.T) {
				s, logs := newFeatureUDR(t, profileNamed(t, prof), nil)
				rec := call(s, http.MethodPut, tc.path, tc.body, "")
				if rec.Code != http.StatusRequestEntityTooLarge {
					t.Fatalf("status %d: %.200s", rec.Code, rec.Body)
				}
				if ct := rec.Result().Header.Get("Content-Type"); ct != "application/problem+json" {
					t.Errorf("content-type %q", ct)
				}
				m := bodyMap(t, rec)
				if _, hasCause := m["cause"]; hasCause || m["status"] != float64(http.StatusRequestEntityTooLarge) {
					t.Errorf("problem %v", m)
				}
				if n := len(negotiationRecords(logs)); n != 0 {
					t.Errorf("FeatureNegotiation lines = %d, want 0", n)
				}
				if tc.name == "ue policy" {
					if g := call(s, http.MethodGet, tc.path, "", ""); g.Code != http.StatusNotFound {
						t.Errorf("oversize PUT stored a policy: %d", g.Code)
					}
				}
			})
		}
	}
	s, logs := newFeatureUDR(t, profileNamed(t, "rel17"), nil)
	for _, path := range []string{subURL + "/context-data/amf-3gpp-access", polURL + "/ue-policy-set"} {
		req := httptest.NewRequest(http.MethodPut, path, errReader{})
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s unreadable body: %d %s", path, rec.Code, rec.Body)
		}
	}
	if n := len(negotiationRecords(logs)); n != 0 {
		t.Errorf("FeatureNegotiation lines = %d, want 0", n)
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line.
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	s, logs := newFeatureUDR(t, profileNamed(t, "rel19"), implCatalog())
	call(s, http.MethodGet, subURL+"/00101/provisioned-data/am-data?supported-features=1", "", "")
	call(s, http.MethodGet, subURL+"/00101/provisioned-data/am-data?supported-features=zz", "", "")
	call(s, http.MethodPut, subURL+"/context-data/amf-3gpp-access", `{"supportedFeatures":"1"}`, "")
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
	if n != 3 {
		t.Fatalf("FeatureNegotiation lines = %d, want 3", n)
	}
}

func TestPeerNFTypeAndTruncation(t *testing.T) {
	s, logs := newFeatureUDR(t, profileNamed(t, "rel19"), nil)
	long := strings.Repeat("f", 4000)
	seedPolicy(t, s)
	before := len(negotiationRecords(logs))
	call(s, http.MethodGet, subURL+"/00101/provisioned-data/am-data?supported-features="+long, "", "evil\"-x")
	call(s, http.MethodGet, polURL+"/sm-data?supp-feat=1", "", "")
	recs := negotiationRecords(logs)[before:]
	if len(recs) != 2 {
		t.Fatalf("records %d", len(recs))
	}
	if p, _ := recs[0]["features_peer"].(string); len(p) != features.MaxLoggedPeerChars+3 || !strings.HasSuffix(p, "...") {
		t.Errorf("features_peer not truncated: %d chars", len(p))
	}
	if recs[0]["peer_nf_type"] != "UDM" || recs[1]["peer_nf_type"] != "PCF" {
		t.Errorf("fallback peer types %v %v", recs[0]["peer_nf_type"], recs[1]["peer_nf_type"])
	}
}

// TestZeroValueStructServerUsesDefaults: a Server with no profile and no
// catalog behaves like rel17 with the default catalog.
func TestZeroValueStructServerUsesDefaults(t *testing.T) {
	s, _ := newFeatureUDR(t, nil, nil)
	rec := call(s, http.MethodGet, subURL+"/00101/provisioned-data/am-data?supported-features=f", "", "")
	if rec.Code != http.StatusOK || bodyMap(t, rec)["supportedFeatures"] != "0" {
		t.Errorf("status %d body %s", rec.Code, rec.Body)
	}
	rec = call(s, http.MethodGet, subURL+"/00101/provisioned-data/am-data", "", "")
	if _, present := bodyMap(t, rec)["supportedFeatures"]; present {
		t.Errorf("rel17 default must omit the attribute: %s", rec.Body)
	}
}
