package server

// features_test.go - producer-side supportedFeatures negotiation of the NRF
// (REL19-2.7 slice 5). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2;
// TS 29.510 §6.1.9, §6.2.9.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/nrf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/nrf/internal/registry"
	nrfsbi "github.com/francurieses/claudia-5gc/nf/nrf/internal/sbi"
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

// implMgmt implements Nnrf_NFManagement features 1 and 4 so a richer set can
// be negotiated; unit tests only.
func implMgmt() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NnrfNFManagementEntries(), 1, 4)...)
}

// implDisc implements Nnrf_NFDiscovery features 6 and 23; unit tests only.
func implDisc() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NnrfNFDiscoveryEntries(), 6, 23)...)
}

func newFeatureNRF(t *testing.T, p *capability.Profile, mgmt, disc *features.Catalog) (*Server, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.Metrics.Address = "127.0.0.1:0"
	cfg.OAuth2Secret = "test"
	// Like cmd/nrf/main.go, the process logger already carries nf.
	lg := slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "NRF")
	s, err := New(cfg, registry.NewInMemory(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))), lg)
	if err != nil {
		t.Fatal(err)
	}
	s.SetProfile(p)
	s.SetCatalogs(mgmt, disc)
	return s, logs
}

func doReq(s *Server, method, path, body, ua string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	rec := httptest.NewRecorder()
	s.sbiSrv.Handler.ServeHTTP(rec, req)
	return rec
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

func TestCatalogs(t *testing.T) {
	// Service-Map is the only bit the NRF implements, in both services.
	for _, name := range []string{"rel17", "rel19"} {
		p := profileNamed(t, name)
		if got := nrfsbi.NnrfNFManagementCatalog().Supported(p).String(); got != "1" {
			t.Errorf("%s: NFManagement offers %q, want 1", name, got)
		}
		if got := nrfsbi.NnrfNFDiscoveryCatalog().Supported(p).String(); got != "20" {
			t.Errorf("%s: NFDiscovery offers %q, want 20 (feature 6)", name, got)
		}
		if got := nrfsbi.NnrfAccessTokenCatalog().Supported(p); !got.IsEmpty() {
			t.Errorf("%s: AccessToken offers %q", name, got)
		}
	}
	if n := len(nrfsbi.NnrfNFDiscoveryCatalog().Entries()); n != 62 {
		t.Errorf("discovery catalog has %d entries", n)
	}
}

// TestSubscribeNegotiationMatrix covers D1: rel17 omits nrfSupportedFeatures
// when the request had no requesterFeatures, rel19 always includes it; a
// request that carries a value gets it under both profiles. The value is the
// NRF's own set (SubscriptionData.nrfSupportedFeatures = "Features supported
// by the NRF", TS 29.510 §6.1.6.2.16 Table 6.1.6.2.16-1), whatever the
// requester sent; the intersection is what is stored on the subscription and
// logged as features_negotiated.
func TestSubscribeNegotiationMatrix(t *testing.T) {
	tests := []struct {
		name, profile, peer string // peer "" = attribute omitted
		cat                 *features.Catalog
		want                string // nrfSupportedFeatures; "" = attribute absent
		wantNeg             string // intersection (stored, logged)
		wantLog             string
	}{
		{"rel17 absent", "rel17", "", nil, "", "0", "absent"},
		{"rel19 absent", "rel19", "", nil, "1", "0", "absent"},
		{"rel17 peer has Service-Map", "rel17", "1", nil, "1", "1", "1"},
		{"rel19 peer has Service-Map", "rel19", "1", nil, "1", "1", "1"},
		{"rel19 higher bits dropped", "rel19", "ff", nil, "1", "1", "ff"},
		{"rel17 peer lacks it, NRF set still answered", "rel17", "FE", nil, "1", "0", "FE"},
		{"rel19 peer zero, NRF set still answered", "rel19", "0", nil, "1", "0", "0"},
		{"rel19 two bits implemented", "rel19", "f", implMgmt(), "9", "9", "f"},
		{"rel19 NRF set exceeds the intersection", "rel19", "1", implMgmt(), "9", "1", "1"},
		{"rel17 absent, catalog implements", "rel17", "", implMgmt(), "", "0", "absent"},
		{"rel19 absent, catalog implements", "rel19", "", implMgmt(), "9", "0", "absent"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, logs := newFeatureNRF(t, profileNamed(t, tc.profile), tc.cat, nil)
			body := `{"nfStatusNotificationUri":"http://amf/cb","reqNfType":"AMF"`
			if tc.peer != "" {
				body += `,"requesterFeatures":"` + tc.peer + `"`
			}
			rec := doReq(s, http.MethodPost, "/nnrf-nfm/v1/subscriptions", body+"}", "")
			if rec.Code != http.StatusCreated {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			got := bodyMap(t, rec)
			sf, present := got["nrfSupportedFeatures"]
			if tc.want == "" && present {
				t.Errorf("nrfSupportedFeatures must be absent, got %v", sf)
			}
			if tc.want != "" && sf != tc.want {
				t.Errorf("nrfSupportedFeatures=%v want %q", sf, tc.want)
			}
			if got["subscriptionId"] == nil {
				t.Errorf("subscriptionId missing: %s", rec.Body)
			}
			recs := negotiationRecords(logs)
			if len(recs) != 1 {
				t.Fatalf("FeatureNegotiation lines = %d, want 1", len(recs))
			}
			rc := recs[0]
			if rc["features_peer"] != tc.wantLog || rc["peer_nf_type"] != "AMF" || rc["direction"] != "IN" ||
				rc["interface"] != "Nnrf" || rc["result"] != "OK" || rc["spec_ref"] != "TS 29.500 §6.6.2" ||
				rc["correlation_id"] != "01TESTCORRELATIONID00000000" || rc["nf"] != "NRF" ||
				rc["features_negotiated"] != tc.wantNeg {
				t.Errorf("log record %v", rc)
			}
			// The negotiated set (intersection) is stored on the subscription.
			subs := s.subs.Matching("AMF", "")
			if len(subs) != 1 || subs[0].Features.String() != tc.wantNeg {
				t.Errorf("stored features %v, want %q", subs, tc.wantNeg)
			}
		})
	}
}

// TestSubscribeEmptyRequesterFeatures: requesterFeatures null and "" carry no
// value (absent semantics): rel17 omits the answer, rel19 includes the NRF set.
func TestSubscribeEmptyRequesterFeatures(t *testing.T) {
	for _, attr := range []string{`null`, `""`} {
		for _, tc := range []struct{ profile, want string }{{"rel17", ""}, {"rel19", "1"}} {
			t.Run(tc.profile+"/"+attr, func(t *testing.T) {
				s, logs := newFeatureNRF(t, profileNamed(t, tc.profile), nil, nil)
				rec := doReq(s, http.MethodPost, "/nnrf-nfm/v1/subscriptions",
					`{"nfStatusNotificationUri":"http://amf/cb","requesterFeatures":`+attr+`}`, "")
				if rec.Code != http.StatusCreated {
					t.Fatalf("status %d: %s", rec.Code, rec.Body)
				}
				sf, present := bodyMap(t, rec)["nrfSupportedFeatures"]
				if tc.want == "" && present || tc.want != "" && sf != tc.want {
					t.Errorf("nrfSupportedFeatures=%v present=%v, want %q", sf, present, tc.want)
				}
				if recs := negotiationRecords(logs); len(recs) != 1 || recs[0]["features_peer"] != "absent" {
					t.Errorf("records %v", recs)
				}
			})
		}
	}
}

func TestSubscribeInvalidRequesterFeatures(t *testing.T) {
	for _, prof := range []string{"rel17", "rel19"} {
		for _, tc := range []struct{ name, attr string }{
			{"non-hex", `"zz"`}, {"0x prefix", `"0x1"`}, {"space", `"1 2"`}, {"number", `7`}, {"bool", `true`},
		} {
			t.Run(prof+"/"+tc.name, func(t *testing.T) {
				s, logs := newFeatureNRF(t, profileNamed(t, prof), nil, nil)
				rec := doReq(s, http.MethodPost, "/nnrf-nfm/v1/subscriptions",
					`{"nfStatusNotificationUri":"http://amf/cb","requesterFeatures":`+tc.attr+`}`, "")
				assertProblem(t, rec, "INVALID_MSG_FORMAT", "/requesterFeatures")
				if len(s.subs.Matching("", "")) != 0 {
					t.Error("subscription stored despite 400")
				}
				if !bytes.Contains(logs.bytes(), []byte(`"result":"REJECT"`)) {
					t.Errorf("no REJECT log:\n%s", logs.bytes())
				}
			})
		}
	}
}

// TestSubscribeOversizeBody: a body over features.MaxRequestBodyBytes is 413
// (ProblemDetails without a cause, TS 29.500 §5.2.7.1) under both profiles;
// nothing is stored and no negotiation is logged.
func TestSubscribeOversizeBody(t *testing.T) {
	huge := `{"nfStatusNotificationUri":"http://amf/cb","pad":"` + strings.Repeat("x", features.MaxRequestBodyBytes) + `"}`
	for _, prof := range []string{"rel17", "rel19"} {
		t.Run(prof, func(t *testing.T) {
			s, logs := newFeatureNRF(t, profileNamed(t, prof), nil, nil)
			rec := doReq(s, http.MethodPost, "/nnrf-nfm/v1/subscriptions", huge, "")
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
			if len(s.subs.Matching("", "")) != 0 {
				t.Error("subscription stored despite 413")
			}
			if n := len(negotiationRecords(logs)); n != 0 {
				t.Errorf("FeatureNegotiation lines = %d, want 0", n)
			}
		})
	}
}

// TestSubscribeLegacyErrorsKeepPrecedence: the legacy 400s are unchanged and
// never reach the negotiation.
func TestSubscribeLegacyErrorsKeepPrecedence(t *testing.T) {
	s, logs := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	for _, body := range []string{`{`, `{"requesterFeatures":"zz"}`, `{"requesterFeatures":"1"}`} {
		rec := doReq(s, http.MethodPost, "/nnrf-nfm/v1/subscriptions", body, "")
		if rec.Code != http.StatusBadRequest || !strings.HasPrefix(rec.Result().Header.Get("Content-Type"), "text/plain") {
			t.Errorf("%s: status %d ct %q", body, rec.Code, rec.Result().Header.Get("Content-Type"))
		}
	}
	if n := len(negotiationRecords(logs)); n != 0 {
		t.Errorf("FeatureNegotiation lines = %d, want 0", n)
	}
}

func registerSMF(t *testing.T, s *Server) {
	t.Helper()
	rec := doReq(s, http.MethodPut, "/nnrf-nfm/v1/nf-instances/aaaaaaaa-0000-0000-0000-00000000000a", goldenSMF, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
}

func TestDiscoverNegotiationMatrix(t *testing.T) {
	tests := []struct {
		name, profile, peer string
		cat                 *features.Catalog
		want                string // SearchResult.nrfSupportedFeatures (the NRF's own set, TS 29.510 §6.2.6.2.2 Table 6.2.6.2.2-1); "" = absent
		wantNeg             string // intersection, logged as features_negotiated
		wantLog             string
	}{
		{"rel17 absent", "rel17", "", nil, "", "0", "absent"},
		{"rel19 absent", "rel19", "", nil, "20", "0", "absent"},
		{"rel17 peer has Service-Map", "rel17", "20", nil, "20", "20", "20"},
		{"rel19 peer has Service-Map", "rel19", "20", nil, "20", "20", "20"},
		{"rel19 other bits dropped", "rel19", "ffff", nil, "20", "20", "ffff"},
		{"rel19 peer lacks it, NRF set still answered", "rel19", "1", nil, "20", "0", "1"},
		{"rel17 peer lacks it, NRF set still answered", "rel17", "1", nil, "20", "0", "1"},
		{"rel19 two bits implemented", "rel19", "400020", implDisc(), "400020", "400020", "400020"},
		{"rel19 NRF set exceeds the intersection", "rel19", "20", implDisc(), "400020", "20", "20"},
		{"rel17 absent, catalog implements", "rel17", "", implDisc(), "", "0", "absent"},
		{"rel19 uppercase hex", "rel19", "2A", nil, "20", "20", "2A"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, logs := newFeatureNRF(t, profileNamed(t, tc.profile), nil, tc.cat)
			registerSMF(t, s)
			path := "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF"
			if tc.peer != "" {
				path += "&requester-features=" + tc.peer
			}
			rec := doReq(s, http.MethodGet, path, "", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			got := bodyMap(t, rec)
			sf, present := got["nrfSupportedFeatures"]
			if tc.want == "" && present {
				t.Errorf("nrfSupportedFeatures must be absent, got %v", sf)
			}
			if tc.want != "" && sf != tc.want {
				t.Errorf("nrfSupportedFeatures=%v want %q", sf, tc.want)
			}
			if n, _ := got["nfInstances"].([]any); len(n) != 1 {
				t.Errorf("nfInstances = %v", got["nfInstances"])
			}
			recs := negotiationRecords(logs)
			if len(recs) != 1 {
				t.Fatalf("FeatureNegotiation lines = %d, want 1", len(recs))
			}
			rc := recs[0]
			if rc["features_peer"] != tc.wantLog || rc["peer_nf_type"] != "AMF" || rc["interface"] != "Nnrf" ||
				rc["result"] != "OK" || rc["direction"] != "IN" || rc["features_negotiated"] != tc.wantNeg {
				t.Errorf("log record %v", rc)
			}
		})
	}
}

// TestDiscoverSupportedFeaturesFilterUnchanged: the requester-features
// negotiation does not touch the supported-features target filter.
func TestDiscoverSupportedFeaturesFilterUnchanged(t *testing.T) {
	s, _ := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	registerSMF(t, s) // nsmf-pdusession supportedFeatures "8"
	base := "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&service-names=nsmf-pdusession"
	count := func(q string) int {
		rec := doReq(s, http.MethodGet, base+q, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", q, rec.Code, rec.Body)
		}
		n, _ := bodyMap(t, rec)["nfInstances"].([]any)
		return len(n)
	}
	if got := count("&supported-features=8"); got != 1 {
		t.Errorf("filter hit = %d", got)
	}
	if got := count("&supported-features=10"); got != 0 {
		t.Errorf("filter miss = %d", got)
	}
	if got := count("&supported-features=10&requester-features=20"); got != 0 {
		t.Errorf("filter miss with requester-features = %d", got)
	}
}

func TestDiscoverInvalidRequesterFeatures(t *testing.T) {
	for _, v := range []string{"zz", "0x1", "1%202", "g"} {
		for _, prof := range []string{"rel17", "rel19"} {
			t.Run(prof+"/"+v, func(t *testing.T) {
				s, logs := newFeatureNRF(t, profileNamed(t, prof), nil, nil)
				rec := doReq(s, http.MethodGet,
					"/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&requester-features="+v, "", "")
				assertProblem(t, rec, "OPTIONAL_QUERY_PARAM_INCORRECT", "query requester-features")
				if !bytes.Contains(logs.bytes(), []byte(`"result":"REJECT"`)) {
					t.Errorf("no REJECT log:\n%s", logs.bytes())
				}
			})
		}
	}
}

// TestDiscoverLegacyChecksFirst: the mandatory-parameter 400 and the
// supported-features filter 400 keep precedence over requester-features.
func TestDiscoverLegacyChecksFirst(t *testing.T) {
	s, logs := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	rec := doReq(s, http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-features=zz", "", "")
	var pd problemBody
	_ = json.Unmarshal(rec.Body.Bytes(), &pd)
	if rec.Code != http.StatusBadRequest || pd.Cause != "MANDATORY_QUERY_PARAM_INCORRECT" {
		t.Errorf("status %d body %s", rec.Code, rec.Body)
	}
	rec = doReq(s, http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&service-names=a&supported-features=zz&requester-features=zz", "", "")
	assertProblem(t, rec, "OPTIONAL_QUERY_PARAM_INCORRECT", "query supported-features")
	if n := len(negotiationRecords(logs)); n != 0 {
		t.Errorf("FeatureNegotiation lines = %d, want 0", n)
	}
}

func TestEmptyRequesterFeaturesIsAbsent(t *testing.T) {
	s, logs := newFeatureNRF(t, profileNamed(t, "rel17"), nil, nil)
	rec := doReq(s, http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&requester-features=", "", "")
	if rec.Code != http.StatusOK || bytes.Contains(rec.Body.Bytes(), []byte("nrfSupportedFeatures")) {
		t.Errorf("status %d body %s", rec.Code, rec.Body)
	}
	if recs := negotiationRecords(logs); len(recs) != 1 || recs[0]["features_peer"] != "absent" {
		t.Errorf("records %v", recs)
	}
}

// TestRetrieveRequesterFeatures: the NFProfile response has no
// supportedFeatures attribute; a value is validated and logged only.
func TestRetrieveRequesterFeatures(t *testing.T) {
	const url = "/nnrf-nfm/v1/nf-instances/aaaaaaaa-0000-0000-0000-00000000000a"
	s, logs := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	registerSMF(t, s)
	plain := doReq(s, http.MethodGet, url, "", "")
	if n := len(negotiationRecords(logs)); n != 0 {
		t.Fatalf("absent requester-features logged %d lines", n)
	}
	withRF := doReq(s, http.MethodGet, url+"?requester-features=1", "", "AMF-1234")
	if withRF.Code != http.StatusOK || withRF.Body.String() != plain.Body.String() {
		t.Errorf("response changed: %d %s", withRF.Code, withRF.Body)
	}
	recs := negotiationRecords(logs)
	if len(recs) != 1 || recs[0]["features_peer"] != "1" || recs[0]["features_negotiated"] != "1" || recs[0]["peer_nf_type"] != "AMF" {
		t.Errorf("records %v", recs)
	}
	assertProblem(t, doReq(s, http.MethodGet, url+"?requester-features=zz", "", ""),
		"OPTIONAL_QUERY_PARAM_INCORRECT", "query requester-features")
	// Unknown id: 404, and no OK line for a request that was not accepted.
	before := len(negotiationRecords(logs))
	rec := doReq(s, http.MethodGet, "/nnrf-nfm/v1/nf-instances/unknown?requester-features=1", "", "")
	if rec.Code != http.StatusNotFound || len(negotiationRecords(logs)) != before {
		t.Errorf("unknown id: %d, records %d -> %d", rec.Code, before, len(negotiationRecords(logs)))
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line.
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	s, logs := newFeatureNRF(t, profileNamed(t, "rel19"), implMgmt(), implDisc())
	doReq(s, http.MethodPost, "/nnrf-nfm/v1/subscriptions", `{"nfStatusNotificationUri":"http://a/cb","requesterFeatures":"1"}`, "")
	doReq(s, http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&requester-features=20", "", "")
	doReq(s, http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&requester-features=zz", "", "")
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

// TestPeerNFTypeSources: the User-Agent NF type wins, then the requester NF
// type from the request, and a hostile value is logged as UNKNOWN.
func TestPeerNFTypeSources(t *testing.T) {
	tests := []struct {
		name, ua, requester, want string
	}{
		{"user agent", "SMF-6a1f0c", "AMF", "SMF"},
		{"requester-nf-type fallback", "curl/8.0", "AMF", "AMF"},
		{"no user agent", "", "PCF", "PCF"},
		{"hostile requester-nf-type", "", `AMF"},{"forged":true}`, "UNKNOWN"},
		{"lowercase requester-nf-type", "", "amf", "UNKNOWN"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, logs := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
			q := "target-nf-type=SMF&requester-nf-type=" + strings.NewReplacer(`"`, "%22", "{", "%7B", "}", "%7D", ",", "%2C").Replace(tc.requester)
			doReq(s, http.MethodGet, "/nnrf-disc/v1/nf-instances?"+q, "", tc.ua)
			recs := negotiationRecords(logs)
			if len(recs) != 1 || recs[0]["peer_nf_type"] != tc.want {
				t.Errorf("records %v, want peer_nf_type %s", recs, tc.want)
			}
			if bytes.Contains(logs.bytes(), []byte("forged")) && tc.want == "UNKNOWN" {
				// the forged key must not appear as a log attribute
				for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
					var m map[string]any
					if json.Unmarshal(line, &m) == nil {
						if _, bad := m["forged"]; bad {
							t.Errorf("log injection: %s", line)
						}
					}
				}
			}
		})
	}
}

func TestLongPeerValueTruncatedInLog(t *testing.T) {
	s, logs := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	long := strings.Repeat("f", 4000)
	rec := doReq(s, http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&requester-features="+long, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	for _, rc := range negotiationRecords(logs) {
		if p, _ := rc["features_peer"].(string); len(p) != features.MaxLoggedPeerChars+3 || !strings.HasSuffix(p, "...") {
			t.Errorf("features_peer not truncated: %d chars", len(p))
		}
	}
}

// TestNoProfileBehavesAsRel17: a Server with no profile set (as in tests that
// build it with New only) behaves as rel17.
func TestNoProfileBehavesAsRel17(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodPost, "/nnrf-nfm/v1/subscriptions", `{"nfStatusNotificationUri":"http://a/cb"}`)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "nrfSupportedFeatures") {
		t.Errorf("status %d body %s", rec.Code, rec.Body)
	}
	rec = do(t, s, http.MethodPost, "/nnrf-nfm/v1/subscriptions", `{"nfStatusNotificationUri":"http://a/cb","requesterFeatures":"3"}`)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"nrfSupportedFeatures":"1"`) {
		t.Errorf("status %d body %s", rec.Code, rec.Body)
	}
}
