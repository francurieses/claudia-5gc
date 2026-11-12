package server

// features_test.go - producer-side supportedFeatures negotiation of the four
// Npcf APIs (REL19-2.7 slice 4). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571
// §5.2.2; TS 29.512 / 29.507 / 29.525 / 29.514 §5.8.

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

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
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

// apiCase describes one producer API for the table tests.
type apiCase struct {
	name     string
	kind     apiKind
	path     string
	consumer string // peer_nf_type fallback
	param    string // invalidParams[0].param
	// body renders a valid request; attr is the raw JSON value of suppFeat, or
	// "" to omit the attribute.
	body func(attr string) string
	// answer extracts the answered suppFeat from the 201 body.
	answer func(m map[string]any) (any, bool)
	// id extracts the minted resource id from the 201 body.
	id func(m map[string]any, loc string) string
	// stored returns the negotiated set kept on the resource context.
	stored func(s *Server, id string) (features.Set, bool)
	// count is the number of stored resources (rejected requests store none).
	count func(s *Server) int
	// legacyMalformed is the cause of a syntactically broken body (unchanged).
	legacyMalformed string
	// bits implemented by implCatalog: a Rel-17 bit and a Rel-19 bit.
	rel17Bit, rel19Bit int
	catalogs           func(c *features.Catalog) Catalogs
	entries            func() []features.Entry
}

func withAttr(base, attr string) string {
	if attr == "" {
		return base
	}
	return strings.Replace(base, "{", `{"suppFeat":`+attr+",", 1)
}

func apiCases() []apiCase {
	return []apiCase{
		{
			name: "Npcf_SMPolicyControl", kind: apiSMPolicy, path: "/npcf-smpolicycontrol/v1/sm-policies",
			consumer: "SMF", param: "/suppFeat", legacyMalformed: "MANDATORY_IE_MISSING",
			body: func(attr string) string {
				return withAttr(`{"supi":"imsi-001010000000001","pduSessionId":5,"pduSessionType":"IPV4","dnn":"internet","notificationUri":"https://smf/n","sliceInfo":{"sst":1,"sd":"000001"}}`, attr)
			},
			answer: func(m map[string]any) (any, bool) { v, ok := m["suppFeat"]; return v, ok },
			id:     func(m map[string]any, loc string) string { return lastSegment(loc) },
			stored: func(s *Server, id string) (features.Set, bool) {
				s.policiesMu.Lock()
				defer s.policiesMu.Unlock()
				v, ok := s.smFeatures[id]
				return v, ok
			},
			count: func(s *Server) int {
				s.policiesMu.Lock()
				defer s.policiesMu.Unlock()
				return len(s.policies) + len(s.smFeatures)
			},
			rel17Bit: 1, rel19Bit: 99,
			catalogs: func(c *features.Catalog) Catalogs { return Catalogs{SMPolicy: c} },
			entries:  features.NpcfSMPolicyControlEntries,
		},
		{
			name: "Npcf_AMPolicyControl", kind: apiAMPolicy, path: "/npcf-am-policy-control/v1/policies",
			consumer: "AMF", param: "/suppFeat", legacyMalformed: "MANDATORY_IE_MISSING",
			body: func(attr string) string {
				return withAttr(`{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS","notificationUri":"https://amf/n"}`, attr)
			},
			answer: func(m map[string]any) (any, bool) { v, ok := m["suppFeat"]; return v, ok },
			id:     func(m map[string]any, loc string) string { return lastSegment(loc) },
			stored: func(s *Server, id string) (features.Set, bool) {
				s.amPoliciesMu.Lock()
				defer s.amPoliciesMu.Unlock()
				a, ok := s.amPolicies[id]
				return a.Features, ok
			},
			count: func(s *Server) int {
				s.amPoliciesMu.Lock()
				defer s.amPoliciesMu.Unlock()
				return len(s.amPolicies)
			},
			rel17Bit: 1, rel19Bit: 22,
			catalogs: func(c *features.Catalog) Catalogs { return Catalogs{AMPolicy: c} },
			entries:  features.NpcfAMPolicyControlEntries,
		},
		{
			name: "Npcf_UEPolicyControl", kind: apiUEPolicy, path: "/npcf-ue-policy-control/v1/policies",
			consumer: "AMF", param: "/suppFeat", legacyMalformed: "MANDATORY_IE_MISSING",
			body: func(attr string) string {
				return withAttr(`{"supi":"imsi-001010000000001","servingPlmn":"00101","notificationUri":"https://amf/n"}`, attr)
			},
			answer: func(m map[string]any) (any, bool) { v, ok := m["suppFeat"]; return v, ok },
			id:     func(m map[string]any, loc string) string { return lastSegment(loc) },
			stored: func(s *Server, id string) (features.Set, bool) {
				s.policiesMu.Lock()
				defer s.policiesMu.Unlock()
				v, ok := s.ueFeatures[id]
				return v, ok
			},
			count: func(s *Server) int {
				s.policiesMu.Lock()
				defer s.policiesMu.Unlock()
				return len(s.policies) + len(s.ueFeatures)
			},
			rel17Bit: 1, rel19Bit: 26,
			catalogs: func(c *features.Catalog) Catalogs { return Catalogs{UEPolicy: c} },
			entries:  features.NpcfUEPolicyControlEntries,
		},
		{
			name: "Npcf_PolicyAuthorization", kind: apiPolicyAuth, path: "/npcf-policyauthorization/v1/app-sessions",
			consumer: "AF", param: "/ascReqData/suppFeat", legacyMalformed: "MANDATORY_IE_INCORRECT",
			body: func(attr string) string {
				b := `{"ascReqData":{"aspId":"af-test","ueIpv4":"10.60.0.1","qosReference":"qos-gold","dnn":"internet"}}`
				if attr != "" {
					b = strings.Replace(b, `{"aspId"`, `{"suppFeat":`+attr+`,"aspId"`, 1)
				}
				return b
			},
			answer: func(m map[string]any) (any, bool) {
				rd, ok := m["ascRespData"].(map[string]any)
				if !ok {
					return nil, false
				}
				v, ok := rd["suppFeat"]
				return v, ok
			},
			id: func(m map[string]any, loc string) string { return lastSegment(loc) },
			stored: func(s *Server, id string) (features.Set, bool) {
				s.appSessionsMu.Lock()
				defer s.appSessionsMu.Unlock()
				a, ok := s.appSessions[id]
				return a.Features, ok
			},
			count: func(s *Server) int {
				s.appSessionsMu.Lock()
				defer s.appSessionsMu.Unlock()
				return len(s.appSessions)
			},
			rel17Bit: 1, rel19Bit: 64,
			catalogs: func(c *features.Catalog) Catalogs { return Catalogs{PolicyAuth: c} },
			entries:  features.NpcfPolicyAuthorizationEntries,
		},
	}
}

// implCatalog implements the case's Rel-17 and Rel-19 bit so non-empty sets
// can be negotiated; unit tests only.
func (c apiCase) implCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(c.entries(), c.rel17Bit, c.rel19Bit)...)
}

func hexOf(nums ...int) string {
	var s features.Set
	for _, n := range nums {
		s = s.With(n)
	}
	return s.String()
}

func newFeaturePCF(t *testing.T, p *capability.Profile, c Catalogs) (*Server, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	cfg := &config.Config{}
	cfg.DefaultSMPolicy.FiveQI = 9
	cfg.DefaultSMPolicy.ARPPriorityLevel = 8
	cfg.DefaultSMPolicy.SessionAMBRUplink = "100 Mbps"
	cfg.DefaultSMPolicy.SessionAMBRDownlink = "100 Mbps"
	// Like cmd/pcf/main.go, the process logger already carries nf.
	s, err := New(cfg, slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "PCF"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetProfile(p)
	s.SetCatalogs(c)
	return s, logs
}

func post(t *testing.T, s *Server, path, body, userAgent string) (*http.Response, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	if userAgent != "" {
		r.Header.Set("User-Agent", userAgent)
	}
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, r)
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

// TestNegotiationMatrix covers D1 on every create: rel17 omits the attribute
// when the request had none, rel19 always answers; a request that carries a
// value is answered with the intersection under both profiles. The negotiated
// set is stored on the resource context.
func TestNegotiationMatrix(t *testing.T) {
	for _, api := range apiCases() {
		bothBits := hexOf(api.rel17Bit, api.rel19Bit)
		tests := []struct {
			name    string
			profile string
			peer    string // "" = omitted, else the raw JSON value
			impl    bool   // implement rel17Bit + rel19Bit
			want    string // "" = attribute absent
			wantLog string
		}{
			{"rel17 absent", "rel17", "", false, "", "absent"},
			{"rel19 absent", "rel19", "", false, "0", "absent"},
			{"rel17 peer, nothing implemented", "rel17", `"3"`, false, "0", "3"},
			{"rel19 peer, nothing implemented", "rel19", `"ff"`, false, "0", "ff"},
			{"rel19 both bits peer has both", "rel19", `"` + bothBits + `"`, true, bothBits, bothBits},
			{"rel19 peer lacks it", "rel19", `"` + hexOf(2) + `"`, true, "0", hexOf(2)},
			{"rel17 Rel19 bit gated out", "rel17", `"` + bothBits + `"`, true, hexOf(api.rel17Bit), bothBits},
			{"rel17 absent, catalog implements", "rel17", "", true, "", "absent"},
			{"rel19 peer uppercase hex", "rel19", `"` + strings.ToUpper(bothBits) + `"`, true, bothBits, strings.ToUpper(bothBits)},
			{"explicit zero", "rel17", `"0"`, true, "0", "0"},
		}
		for _, tc := range tests {
			t.Run(api.name+"/"+tc.name, func(t *testing.T) {
				var c Catalogs
				if tc.impl {
					c = api.catalogs(api.implCatalog())
				}
				s, logs := newFeaturePCF(t, profileNamed(t, tc.profile), c)
				resp, raw := post(t, s, api.path, api.body(tc.peer), "")
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				var got map[string]any
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				sf, present := api.answer(got)
				if tc.want == "" && present {
					t.Errorf("suppFeat must be absent, got %v", sf)
				}
				if tc.want != "" && sf != tc.want {
					t.Errorf("suppFeat=%v want %q", sf, tc.want)
				}
				// The negotiated set is stored on the resource context.
				set, ok := api.stored(s, api.id(got, resp.Header.Get("Location")))
				wantSet := tc.want
				if wantSet == "" {
					wantSet = "0"
				}
				if !ok || set.String() != wantSet {
					t.Errorf("stored set = %q (found %v), want %q", set.String(), ok, wantSet)
				}
				recs := negotiationRecords(logs)
				if len(recs) != 1 {
					t.Fatalf("FeatureNegotiation lines = %d, want 1", len(recs))
				}
				rec := recs[0]
				if rec["features_peer"] != tc.wantLog || rec["peer_nf_type"] != api.consumer ||
					rec["direction"] != "IN" || rec["interface"] != "Npcf" || rec["result"] != "OK" ||
					rec["spec_ref"] != "TS 29.500 §6.6.2" || rec["correlation_id"] != "01TESTCORRELATIONID00000000" ||
					rec["nf"] != "PCF" || rec["features_negotiated"] != wantSet {
					t.Errorf("log record %v", rec)
				}
			})
		}
	}
}

// TestPeerNFTypeFromUserAgent: the User-Agent NF type wins over the TS
// consumer default.
func TestPeerNFTypeFromUserAgent(t *testing.T) {
	for _, api := range apiCases() {
		s, logs := newFeaturePCF(t, profileNamed(t, "rel19"), Catalogs{})
		if resp, raw := post(t, s, api.path, api.body(""), "NEF-0123abcd"); resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: %d %s", api.name, resp.StatusCode, raw)
		}
		recs := negotiationRecords(logs)
		if len(recs) != 1 || recs[0]["peer_nf_type"] != "NEF" {
			t.Errorf("%s: records %v", api.name, recs)
		}
	}
}

type problemBody struct {
	Cause         string `json:"cause"`
	Detail        string `json:"detail"`
	InvalidParams []struct {
		Param string `json:"param"`
	} `json:"invalidParams"`
}

// TestInvalidSuppFeatRejected: a non-hex value or a JSON type error is a 400
// INVALID_MSG_FORMAT with a JSON Pointer to the attribute; nothing is stored,
// a REJECT line is logged and counted. Ref: TS 29.500 §5.2.7.2.
func TestInvalidSuppFeatRejected(t *testing.T) {
	for _, api := range apiCases() {
		for _, tc := range []struct{ name, attr, detail string }{
			{"non-hex", `"zz"`, detailNotHex}, {"number", `7`, detailNotString}, {"array", `["1"]`, detailNotString},
			{"bool", `false`, detailNotString}, {"object", `{"a":1}`, detailNotString},
		} {
			for _, prof := range []string{"rel17", "rel19"} {
				t.Run(api.name+"/"+prof+"/"+tc.name, func(t *testing.T) {
					s, logs := newFeaturePCF(t, profileNamed(t, prof), Catalogs{})
					resp, raw := post(t, s, api.path, api.body(tc.attr), "")
					if resp.StatusCode != http.StatusBadRequest {
						t.Fatalf("status %d: %s", resp.StatusCode, raw)
					}
					var pd problemBody
					if err := json.Unmarshal(raw, &pd); err != nil {
						t.Fatal(err)
					}
					if pd.Cause != "INVALID_MSG_FORMAT" || len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != api.param {
						t.Errorf("problem %s", raw)
					}
					if pd.Detail != tc.detail {
						t.Errorf("detail %q, want %q", pd.Detail, tc.detail)
					}
					if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
						t.Errorf("content-type %q", ct)
					}
					if !bytes.Contains(logs.bytes(), []byte(`"result":"REJECT"`)) {
						t.Errorf("no REJECT log:\n%s", logs.bytes())
					}
					if n := api.count(s); n != 0 {
						t.Errorf("%d resources stored after a rejected request", n)
					}
				})
			}
		}
	}
}

// TestNullAndEmptySuppFeatAreAbsent: JSON null and "" are an absent attribute.
func TestNullAndEmptySuppFeatAreAbsent(t *testing.T) {
	for _, api := range apiCases() {
		for _, attr := range []string{`null`, `""`} {
			s, _ := newFeaturePCF(t, profileNamed(t, "rel17"), Catalogs{})
			resp, raw := post(t, s, api.path, api.body(attr), "")
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			if _, present := api.answer(m); resp.StatusCode != http.StatusCreated || present {
				t.Errorf("%s/%s: status %d body %s", api.name, attr, resp.StatusCode, raw)
			}
		}
	}
}

// TestUnknownAttributesTolerated: unknown JSON attributes (future optional
// features) are ignored. TS 29.500 §6.6.2.
func TestUnknownAttributesTolerated(t *testing.T) {
	for _, api := range apiCases() {
		s, _ := newFeaturePCF(t, profileNamed(t, "rel19"), api.catalogs(api.implCatalog()))
		body := strings.Replace(api.body(`"`+hexOf(api.rel17Bit)+`"`), `{`, `{"futureAttr":{"x":[1,2]},`, 1)
		resp, raw := post(t, s, api.path, body, "")
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if sf, _ := api.answer(m); resp.StatusCode != http.StatusCreated || sf != hexOf(api.rel17Bit) {
			t.Errorf("%s: status %d body %s", api.name, resp.StatusCode, raw)
		}
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line.
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	for _, api := range apiCases() {
		s, logs := newFeaturePCF(t, profileNamed(t, "rel19"), api.catalogs(api.implCatalog()))
		post(t, s, api.path, api.body(`"`+hexOf(api.rel17Bit)+`"`), "")
		post(t, s, api.path, api.body(`"zz"`), "")
		n := 0
		for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
			if !bytes.Contains(line, []byte(`"procedure":"FeatureNegotiation"`)) {
				continue
			}
			n++
			for _, k := range []string{"nf", "procedure", "correlation_id", "interface", "direction", "spec_ref",
				"peer_nf_type", "features_local", "features_peer", "features_negotiated", "result"} {
				if c := bytes.Count(line, []byte(`"`+k+`":`)); c != 1 {
					t.Errorf("%s: key %q appears %d times in %s", api.name, k, c, line)
				}
			}
		}
		if n != 2 {
			t.Errorf("%s: FeatureNegotiation lines = %d, want 2", api.name, n)
		}
	}
}

// TestLongPeerValueTruncatedInLogAndBodyCapped: the logged features_peer is
// bounded and an oversized body is rejected with 413 (counted, logged).
func TestLongPeerValueTruncatedInLogAndBodyCapped(t *testing.T) {
	for _, api := range apiCases() {
		s, logs := newFeaturePCF(t, profileNamed(t, "rel19"), Catalogs{})
		long := strings.Repeat("f", 4000)
		if resp, raw := post(t, s, api.path, api.body(`"`+long+`"`), ""); resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: status %d %s", api.name, resp.StatusCode, raw)
		}
		for _, rec := range negotiationRecords(logs) {
			if p, _ := rec["features_peer"].(string); len(p) != features.MaxLoggedPeerChars+3 || !strings.HasSuffix(p, "...") {
				t.Errorf("%s: features_peer not truncated: %d chars", api.name, len(p))
			}
		}
		huge := strings.Repeat("f", features.MaxRequestBodyBytes+10)
		resp, _ := post(t, s, api.path, api.body(`"`+huge+`"`), "")
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: oversized body: status %d", api.name, resp.StatusCode)
		}
		if !bytes.Contains(logs.bytes(), []byte(`"cause":"PAYLOAD_TOO_LARGE"`)) {
			t.Errorf("%s: no PAYLOAD_TOO_LARGE log", api.name)
		}
	}
}

// TestLegacyMalformedBodyUnchanged: a syntactically broken body keeps the
// pre-existing 400 cause of each API.
func TestLegacyMalformedBodyUnchanged(t *testing.T) {
	for _, api := range apiCases() {
		s, _ := newFeaturePCF(t, profileNamed(t, "rel19"), Catalogs{})
		resp, raw := post(t, s, api.path, `{"supi":`, "")
		var pd problemBody
		_ = json.Unmarshal(raw, &pd)
		if resp.StatusCode != http.StatusBadRequest || pd.Cause != api.legacyMalformed {
			t.Errorf("%s: status %d body %s", api.name, resp.StatusCode, raw)
		}
	}
}

// TestRequiredAttributeMissingStillAccepted documents the mandatory-in-request
// finding: suppFeat is required by the OpenAPI schema of the AM, UE and
// PolicyAuthorization requests, but a request without it keeps being accepted
// (rel17 byte-identity); nothing is rejected for its absence in either profile.
func TestRequiredAttributeMissingStillAccepted(t *testing.T) {
	for _, api := range apiCases() {
		for _, prof := range []string{"rel17", "rel19"} {
			s, _ := newFeaturePCF(t, profileNamed(t, prof), Catalogs{})
			if resp, raw := post(t, s, api.path, api.body(""), ""); resp.StatusCode != http.StatusCreated {
				t.Errorf("%s/%s: status %d %s", api.name, prof, resp.StatusCode, raw)
			}
		}
	}
}

// TestPolicyAuthorizationOtherChecksKeep: with a valid suppFeat the existing
// mandatory-IE checks still apply and no FeatureNegotiation OK line precedes a
// rejection by them.
func TestPolicyAuthorizationOtherChecksKeep(t *testing.T) {
	s, logs := newFeaturePCF(t, profileNamed(t, "rel19"), Catalogs{})
	path := "/npcf-policyauthorization/v1/app-sessions"
	for _, body := range []string{
		`{}`,
		`{"ascReqData":{"suppFeat":"1","aspId":"x"}}`,
	} {
		resp, raw := post(t, s, path, body, "")
		var pd problemBody
		_ = json.Unmarshal(raw, &pd)
		if resp.StatusCode != http.StatusBadRequest || pd.Cause != "MANDATORY_IE_MISSING" {
			t.Errorf("%s: status %d body %s", body, resp.StatusCode, raw)
		}
	}
	if n := len(negotiationRecords(logs)); n != 0 {
		t.Errorf("FeatureNegotiation lines = %d for rejected requests, want 0", n)
	}
}

// TestPolicyAuthorizationRetrofit: the AF's ascReqData.suppFeat is echoed as
// received inside ascReqData and the negotiated value is answered in
// ascRespData.suppFeat (the former ad-hoc field was only an echo).
func TestPolicyAuthorizationRetrofit(t *testing.T) {
	api := apiCases()[3]
	s, _ := newFeaturePCF(t, profileNamed(t, "rel17"), api.catalogs(api.implCatalog()))
	resp, raw := post(t, s, api.path, api.body(`"`+hexOf(api.rel17Bit, 2)+`"`), "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d %s", resp.StatusCode, raw)
	}
	var m struct {
		AscReqData  map[string]any `json:"ascReqData"`
		AscRespData map[string]any `json:"ascRespData"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.AscReqData["suppFeat"] != hexOf(api.rel17Bit, 2) || m.AscRespData["suppFeat"] != hexOf(api.rel17Bit) {
		t.Errorf("req echo %v, resp %v", m.AscReqData, m.AscRespData)
	}
}

// TestDeleteForgetsNegotiatedSet: deleting an SM / UE policy drops the stored
// set.
func TestDeleteForgetsNegotiatedSet(t *testing.T) {
	s, _ := newFeaturePCF(t, profileNamed(t, "rel19"), Catalogs{})
	for _, tc := range []struct {
		create, del string
		id          func(map[string]any, string) string
		stored      func(string) bool
	}{
		{"/npcf-smpolicycontrol/v1/sm-policies", "/npcf-smpolicycontrol/v1/sm-policies/",
			func(m map[string]any, loc string) string { return lastSegment(loc) },
			func(id string) bool { _, ok := s.smFeatures[id]; return ok }},
		{"/npcf-ue-policy-control/v1/policies", "/npcf-ue-policy-control/v1/policies/",
			func(m map[string]any, loc string) string { return lastSegment(loc) },
			func(id string) bool { _, ok := s.ueFeatures[id]; return ok }},
	} {
		body := `{"supi":"imsi-001010000000001"}`
		resp, raw := post(t, s, tc.create, body, "")
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: %d %s", tc.create, resp.StatusCode, raw)
		}
		id := tc.id(m, resp.Header.Get("Location"))
		if !tc.stored(id) {
			t.Fatalf("%s: set not stored", tc.create)
		}
		method, suffix := http.MethodDelete, ""
		if strings.Contains(tc.del, "sm-policies") {
			method, suffix = http.MethodPost, "/delete" // custom operation, TS 29.512 §5.3.3.4.2
		}
		r := httptest.NewRequest(method, tc.del+id+suffix, nil)
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent || tc.stored(id) {
			t.Errorf("%s: delete status %d, still stored %v", tc.del, w.Code, tc.stored(id))
		}
	}
}

// TestClientAscRespDataNotEchoed: ascRespData is PCF-generated; one supplied by
// the client is dropped and never stored or returned. Under rel17 with no
// ascReqData.suppFeat the 201 carries none; under rel19 the PCF's own answer.
func TestClientAscRespDataNotEchoed(t *testing.T) {
	const body = `{"ascReqData":{"aspId":"af-test","ueIpv4":"10.60.0.1","qosReference":"qos-gold"},"ascRespData":{"suppFeat":"ff"}}`
	for _, tc := range []struct {
		profile string
		want    string // "" = ascRespData absent
	}{{"rel17", ""}, {"rel19", "0"}} {
		t.Run(tc.profile, func(t *testing.T) {
			s, _ := newFeaturePCF(t, profileNamed(t, tc.profile), Catalogs{})
			resp, raw := post(t, s, "/npcf-policyauthorization/v1/app-sessions", body, "")
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status %d: %s", resp.StatusCode, raw)
			}
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			rd, present := got["ascRespData"].(map[string]any)
			if tc.want == "" {
				if present {
					t.Fatalf("ascRespData must be absent, got %v", rd)
				}
			} else if rd["suppFeat"] != tc.want {
				t.Fatalf("ascRespData.suppFeat=%v want %q", rd["suppFeat"], tc.want)
			}
			id := lastSegment(resp.Header.Get("Location"))
			s.appSessionsMu.Lock()
			stored := s.appSessions[id]
			s.appSessionsMu.Unlock()
			if (stored.AscRespData != nil) != (tc.want != "") {
				t.Errorf("stored AscRespData = %v", stored.AscRespData)
			}
		})
	}
}
