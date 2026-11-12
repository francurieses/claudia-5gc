package server

// sdm_uecm_features_test.go - producer-side supportedFeatures negotiation of
// Nudm_SDM (am-data, sm-data, sdm-subscriptions) and Nudm_UECM (AMF 3GPP
// access registration), REL19-2.7 slice 6a. Ref: TS 29.500 §6.6.2, §5.2.7.2;
// TS 29.503 §6.1.8, §6.2.8; TS 29.571 §5.2.2.

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

const testSUPI = "imsi-001010000000001"

// sdmTestCatalog implements Nudm_SDM 1 SharedData (Rel-17) and 25 PCPDEIVID
// (Rel-19) so non-empty sets can be negotiated; unit tests only.
func sdmTestCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NudmSDMEntries(), 1, 25)...)
}

// uecmTestCatalog implements Nudm_UECM 1 SharedData (Rel-17) and 6 SUBDMIG
// (Rel-19); unit tests only.
func uecmTestCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NudmUECMEntries(), 1, 6)...)
}

func newSDMUECMUDM(t *testing.T, p *capability.Profile, sdm, uecm *features.Catalog) (*Server, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	s, err := New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org", TLSConfig{}, sdmUDR{},
		slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.SetProfile(p)
	s.SetSDMCatalog(sdm)
	s.SetUECMCatalog(uecm)
	return s, logs
}

func do(t *testing.T, s *Server, method, target, body, ua string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// endpoint abstracts the four negotiating operations: send builds the request
// with the given offer ("" = omitted) and answer extracts the response
// supportedFeatures (present, value).
type endpoint struct {
	name   string
	status int
	cat    func() (sdm, uecm *features.Catalog)
	send   func(t *testing.T, s *Server, peer string) (*http.Response, []byte)
	answer func(t *testing.T, raw []byte) (string, bool)
}

func topLevelSF(t *testing.T, raw []byte) (string, bool) {
	t.Helper()
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("body %q: %v", raw, err)
	}
	v, ok := m["supportedFeatures"].(string)
	return v, ok
}

func endpoints() []endpoint {
	query := func(path string) func(*testing.T, *Server, string) (*http.Response, []byte) {
		return func(t *testing.T, s *Server, peer string) (*http.Response, []byte) {
			target := "/nudm-sdm/v2/" + testSUPI + path
			if peer != "" {
				target += "?supported-features=" + peer
			}
			return do(t, s, http.MethodGet, target, "", "AMF-0001")
		}
	}
	return []endpoint{
		{"am-data", 200, func() (*features.Catalog, *features.Catalog) { return sdmTestCatalog(), nil }, query("/am-data"), topLevelSF},
		{"sm-data", 200, func() (*features.Catalog, *features.Catalog) { return sdmTestCatalog(), nil }, query("/sm-data"),
			func(t *testing.T, raw []byte) (string, bool) {
				t.Helper()
				var arr []map[string]any
				if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
					t.Fatalf("sm-data body %q: %v", raw, err)
				}
				v, ok := arr[0]["supportedFeatures"].(string)
				for _, e := range arr {
					if e["supportedFeatures"] != arr[0]["supportedFeatures"] {
						t.Errorf("elements disagree on supportedFeatures: %v", arr)
					}
				}
				return v, ok
			}},
		{"sdm-subscribe", 201, func() (*features.Catalog, *features.Catalog) { return sdmTestCatalog(), nil },
			func(t *testing.T, s *Server, peer string) (*http.Response, []byte) {
				body := `{"nfInstanceId":"amf-1","callbackReference":"https://amf.example/cb","monitoredResourceUris":["https://udm/nudm-sdm/v2/` + testSUPI + `/am-data"]`
				if peer != "" {
					body += `,"supportedFeatures":"` + peer + `"`
				}
				return do(t, s, http.MethodPost, "/nudm-sdm/v2/"+testSUPI+"/sdm-subscriptions", body+"}", "AMF-0001")
			}, topLevelSF},
		{"amf-registration", 201, func() (*features.Catalog, *features.Catalog) { return nil, uecmTestCatalog() },
			func(t *testing.T, s *Server, peer string) (*http.Response, []byte) {
				body := `{"amfInstanceId":"11111111-2222-3333-4444-555555555555","deregCallbackUri":"https://amf/dereg"`
				if peer != "" {
					body += `,"supportedFeatures":"` + peer + `"`
				}
				return do(t, s, http.MethodPut, "/nudm-uecm/v1/"+testSUPI+"/registrations/amf-3gpp-access", body+"}", "AMF-0001")
			}, topLevelSF},
	}
}

// TestSDMUECMNegotiationMatrix covers D1: rel17 omits the attribute when the
// request had none, rel19 always answers; a request that carries a value is
// answered with the intersection under both profiles. Rel-19 bits are gated
// out under rel17.
func TestSDMUECMNegotiationMatrix(t *testing.T) {
	tests := []struct {
		name, profile, peer string
		withCat             bool
		// want is the answer for the SDM catalog (bits 1,25) and wantUECM for
		// the UECM catalog (bits 1,6); "" = attribute absent.
		want, wantUECM string
	}{
		{"rel17 absent", "rel17", "", true, "", ""},
		{"rel19 absent", "rel19", "", true, "0", "0"},
		{"rel17 peer, nothing implemented", "rel17", "ff", false, "0", "0"},
		{"rel19 peer, nothing implemented", "rel19", "ff", false, "0", "0"},
		{"rel17 peer bit1, rel19 bits gated out", "rel17", "1", true, "1", "1"},
		{"rel17 peer all, rel19 bits gated out", "rel17", "ffffffff", true, "1", "1"},
		{"rel19 peer all", "rel19", "ffffffff", true, "1000001", "21"},
		{"rel19 peer lacks bits", "rel19", "2", true, "0", "0"},
		{"rel19 uppercase hex", "rel19", "FF", true, "1", "21"},
		{"rel19 peer zero", "rel19", "0", true, "0", "0"},
	}
	for _, ep := range endpoints() {
		for _, tc := range tests {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				var sdm, uecm *features.Catalog
				if tc.withCat {
					sdm, uecm = ep.cat()
				}
				s, logs := newSDMUECMUDM(t, profileNamed(t, tc.profile), sdm, uecm)
				resp, raw := ep.send(t, s, tc.peer)
				if resp.StatusCode != ep.status {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				want := tc.want
				if ep.name == "amf-registration" {
					want = tc.wantUECM
				}
				if !tc.withCat && tc.peer != "" {
					want = "0"
				}
				got, present := ep.answer(t, raw)
				if want == "" && present {
					t.Errorf("attribute present (%q) under rel17 with no offer", got)
				}
				if want != "" && (!present || got != want) {
					t.Errorf("supportedFeatures = %q (present=%v), want %q; body %s", got, present, want, raw)
				}
				if !bytes.Contains(logs.bytes(), []byte(`"procedure":"FeatureNegotiation"`)) {
					t.Errorf("no FeatureNegotiation log:\n%s", logs.bytes())
				}
			})
		}
	}
}

func TestSDMUECMInvalidSupportedFeaturesRejected(t *testing.T) {
	type param struct {
		Param string `json:"param"`
	}
	for _, prof := range []string{"rel17", "rel19"} {
		for _, q := range []string{"zz", "1g", "0x1"} {
			for _, path := range []string{"/am-data", "/sm-data"} {
				t.Run(prof+"/query/"+path+"/"+q, func(t *testing.T) {
					s, logs := newSDMUECMUDM(t, profileNamed(t, prof), nil, nil)
					resp, raw := do(t, s, http.MethodGet, "/nudm-sdm/v2/"+testSUPI+path+"?supported-features="+q, "", "AMF-0001")
					var pd struct {
						Cause         string  `json:"cause"`
						InvalidParams []param `json:"invalidParams"`
					}
					_ = json.Unmarshal(raw, &pd)
					if resp.StatusCode != http.StatusBadRequest || pd.Cause != "OPTIONAL_QUERY_PARAM_INCORRECT" ||
						len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != "query supported-features" {
						t.Errorf("status %d body %s", resp.StatusCode, raw)
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
		for _, attr := range []string{`"zz"`, `7`, `["1"]`, `false`} {
			for _, tc := range []struct{ name, method, target, pre string }{
				{"subscribe", http.MethodPost, "/nudm-sdm/v2/" + testSUPI + "/sdm-subscriptions", `{"nfInstanceId":"amf-1","callbackReference":"https://amf/cb","monitoredResourceUris":["https://udm/nudm-sdm/v2/` + testSUPI + `/am-data"]`},
				{"registration", http.MethodPut, "/nudm-uecm/v1/" + testSUPI + "/registrations/amf-3gpp-access", `{"amfInstanceId":"x"`},
			} {
				t.Run(prof+"/body/"+tc.name+"/"+attr, func(t *testing.T) {
					s, logs := newSDMUECMUDM(t, profileNamed(t, prof), nil, nil)
					resp, raw := do(t, s, tc.method, tc.target, tc.pre+`,"supportedFeatures":`+attr+"}", "AMF-0001")
					var pd struct {
						Cause         string  `json:"cause"`
						InvalidParams []param `json:"invalidParams"`
					}
					_ = json.Unmarshal(raw, &pd)
					if resp.StatusCode != http.StatusBadRequest || pd.Cause != "INVALID_MSG_FORMAT" ||
						len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != "/supportedFeatures" {
						t.Errorf("status %d body %s", resp.StatusCode, raw)
					}
					if !bytes.Contains(logs.bytes(), []byte(`"result":"REJECT"`)) {
						t.Errorf("no REJECT log:\n%s", logs.bytes())
					}
				})
			}
		}
	}
}

// TestInvalidSupportedFeaturesStoresNothing: a rejected registration or
// subscription leaves no context behind.
func TestInvalidSupportedFeaturesStoresNothing(t *testing.T) {
	s, _ := newSDMUECMUDM(t, profileNamed(t, "rel19"), nil, nil)
	do(t, s, http.MethodPut, "/nudm-uecm/v1/"+testSUPI+"/registrations/amf-3gpp-access", `{"supportedFeatures":"zz"}`, "")
	do(t, s, http.MethodPost, "/nudm-sdm/v2/"+testSUPI+"/sdm-subscriptions", `{"callbackReference":"https://x/cb","supportedFeatures":"zz"}`, "")
	if n := len(s.listSubscriptions(testSUPI)); n != 0 {
		t.Errorf("%d subscriptions stored despite 400", n)
	}
}

// TestNegotiatedSetStoredOnContext: the negotiated set is kept on the SDM
// subscription (a bounded, existing resource). The UDM has no Nudm_UECM
// registration resource context yet, so nothing is kept for registrations.
func TestNegotiatedSetStoredOnContext(t *testing.T) {
	s, _ := newSDMUECMUDM(t, profileNamed(t, "rel19"), sdmTestCatalog(), uecmTestCatalog())
	if resp, raw := do(t, s, http.MethodPost, "/nudm-sdm/v2/"+testSUPI+"/sdm-subscriptions",
		`{"nfInstanceId":"amf-1","callbackReference":"https://amf/cb","monitoredResourceUris":["https://udm/nudm-sdm/v2/`+testSUPI+`/am-data"],"supportedFeatures":"3"}`, ""); resp.StatusCode != http.StatusCreated {
		t.Fatalf("subscribe %d %s", resp.StatusCode, raw)
	}
	subs := s.listSubscriptions(testSUPI)
	if len(subs) != 1 || subs[0].negotiated.String() != "1" || subs[0].SupportedFeatures != "1" {
		t.Fatalf("subscription context: %+v", subs)
	}
}

// TestRegistrationEchoesRepresentation: under rel19 the 201 carries the
// registration with the answer; unrelated attributes are preserved and the
// Location header is absolute with the SUPI path-escaped.
func TestRegistrationEchoesRepresentation(t *testing.T) {
	s, _ := newSDMUECMUDM(t, profileNamed(t, "rel19"), nil, nil)
	resp, raw := do(t, s, http.MethodPut, "/nudm-uecm/v1/"+testSUPI+"/registrations/amf-3gpp-access",
		`{"amfInstanceId":"a1","ratType":"NR"}`, "")
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if resp.StatusCode != http.StatusCreated || m["amfInstanceId"] != "a1" || m["ratType"] != "NR" || m["supportedFeatures"] != "0" ||
		resp.Header.Get("Location") != "https://example.com/nudm-uecm/v1/"+testSUPI+"/registrations/amf-3gpp-access" ||
		resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("status %d hdr %v body %s", resp.StatusCode, resp.Header, raw)
	}
}

// TestRegistrationLocationEscapesSUPI: a path SUPI with reserved characters is
// escaped in the Location header.
func TestRegistrationLocationEscapesSUPI(t *testing.T) {
	s, _ := newSDMUECMUDM(t, profileNamed(t, "rel19"), nil, nil)
	r := httptest.NewRequest(http.MethodPut, "/nudm-uecm/v1/x/registrations/amf-3gpp-access", strings.NewReader(`{}`))
	r.SetPathValue("supi", "a b/c?d")
	w := httptest.NewRecorder()
	s.handleAMFRegistration(w, r)
	if got, want := w.Header().Get("Location"), "https://example.com/nudm-uecm/v1/a%20b%2Fc%3Fd/registrations/amf-3gpp-access"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

// TestRegistrationLegacyNoLocation: rel17 without an offer keeps the legacy
// bare 201 (no Location, no body).
func TestRegistrationLegacyNoLocation(t *testing.T) {
	s, _ := newSDMUECMUDM(t, profileNamed(t, "rel17"), nil, nil)
	resp, raw := do(t, s, http.MethodPut, "/nudm-uecm/v1/"+testSUPI+"/registrations/amf-3gpp-access", `{"amfInstanceId":"a1"}`, "")
	if resp.StatusCode != http.StatusCreated || len(raw) != 0 || resp.Header.Get("Location") != "" {
		t.Errorf("status %d hdr %v body %q", resp.StatusCode, resp.Header, raw)
	}
}

// TestRegistrationNonObjectBody: rel19 rejects a body that is not a JSON
// object (TS 29.500 §5.2.7.2); rel17 keeps accepting it and logs a Warn.
func TestRegistrationNonObjectBody(t *testing.T) {
	for _, body := range []string{`{not json`, ``, `[1]`, `"x"`} {
		t.Run("rel19/"+body, func(t *testing.T) {
			s, logs := newSDMUECMUDM(t, profileNamed(t, "rel19"), nil, nil)
			resp, raw := do(t, s, http.MethodPut, "/nudm-uecm/v1/"+testSUPI+"/registrations/amf-3gpp-access", body, "")
			var pd struct {
				Cause string `json:"cause"`
			}
			_ = json.Unmarshal(raw, &pd)
			if resp.StatusCode != http.StatusBadRequest || pd.Cause != "INVALID_MSG_FORMAT" {
				t.Errorf("status %d body %s", resp.StatusCode, raw)
			}
			if !bytes.Contains(logs.bytes(), []byte(`"result":"REJECT"`)) {
				t.Errorf("no REJECT log:\n%s", logs.bytes())
			}
		})
		t.Run("rel17/"+body, func(t *testing.T) {
			s, logs := newSDMUECMUDM(t, profileNamed(t, "rel17"), nil, nil)
			resp, raw := do(t, s, http.MethodPut, "/nudm-uecm/v1/"+testSUPI+"/registrations/amf-3gpp-access", body, "")
			if resp.StatusCode != http.StatusCreated || len(raw) != 0 {
				t.Errorf("status %d body %q", resp.StatusCode, raw)
			}
			if !bytes.Contains(logs.bytes(), []byte(`"level":"WARN"`)) {
				t.Errorf("no Warn log for accepted malformed body:\n%s", logs.bytes())
			}
		})
	}
}

// TestAPIRootFallbacks covers the apiRoot authority order.
func TestAPIRootFallbacks(t *testing.T) {
	tests := []struct {
		name, addr, host, sni, want string
	}{
		{"request host", "0.0.0.0:8003", "udm.example:8003", "", "https://udm.example:8003"},
		{"sni", "0.0.0.0:8003", "", "udm.sni", "https://udm.sni:8003"},
		{"specified address", "10.0.0.5:8003", "", "", "https://10.0.0.5:8003"},
		{"unspecified address", "0.0.0.0:8003", "", "", ""},
		{"ipv6 unspecified", "[::]:8003", "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{addr: tc.addr}
			r := httptest.NewRequest(http.MethodPut, "/x", nil)
			r.Host = tc.host
			if tc.sni != "" {
				r.TLS = &tls.ConnectionState{ServerName: tc.sni}
			}
			if got := s.apiRoot(r); got != tc.want {
				t.Errorf("apiRoot = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSDMUECMLogFieldsAndPeer: canonical keys appear exactly once and the
// peer NF type comes from the User-Agent.
func TestSDMUECMLogFieldsAndPeer(t *testing.T) {
	for _, ep := range endpoints() {
		t.Run(ep.name, func(t *testing.T) {
			sdm, uecm := ep.cat()
			s, logs := newSDMUECMUDM(t, profileNamed(t, "rel19"), sdm, uecm)
			ep.send(t, s, "1")
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
				var rec map[string]any
				_ = json.Unmarshal(line, &rec)
				if rec["peer_nf_type"] != "AMF" || rec["interface"] != "Nudm" || rec["direction"] != "IN" ||
					rec["spec_ref"] != "TS 29.500 §6.6.2" || rec["nf"] != "UDM" ||
					rec["correlation_id"] != "01TESTCORRELATIONID00000000" || rec["features_peer"] != "1" {
					t.Errorf("record %s", line)
				}
			}
			if n != 1 {
				t.Fatalf("FeatureNegotiation lines = %d, want 1", n)
			}
		})
	}
}

func TestSDMUECMOversizedBodyAndUnknownAgent(t *testing.T) {
	s, logs := newSDMUECMUDM(t, profileNamed(t, "rel19"), nil, nil)
	huge := strings.Repeat("f", features.MaxRequestBodyBytes+10)
	if resp, _ := do(t, s, http.MethodPost, "/nudm-sdm/v2/"+testSUPI+"/sdm-subscriptions",
		`{"callbackReference":"https://x/cb","supportedFeatures":"`+huge+`"}`, ""); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("subscribe oversized: status %d", resp.StatusCode)
	}
	if resp, _ := do(t, s, http.MethodPut, "/nudm-uecm/v1/"+testSUPI+"/registrations/amf-3gpp-access",
		`{"supportedFeatures":"`+huge+`"}`, ""); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("registration oversized: status %d", resp.StatusCode)
	}
	do(t, s, http.MethodGet, "/nudm-sdm/v2/"+testSUPI+"/am-data?supported-features="+huge[:200], "", "not a valid agent!")
	if !bytes.Contains(logs.bytes(), []byte(`"peer_nf_type":"UNKNOWN"`)) {
		t.Errorf("fallback peer type missing:\n%s", logs.bytes())
	}
	for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
		var rec map[string]any
		_ = json.Unmarshal(line, &rec)
		if p, ok := rec["features_peer"].(string); ok && len(p) > features.MaxLoggedPeerChars+3 {
			t.Errorf("features_peer not truncated: %d chars", len(p))
		}
	}
}
