package server

// routes_test.go - REL19-2.7 / PCF-003 Rel-17 OpenAPI conformance: canonical
// paths, absolute Location headers, POST .../delete custom operations, removed
// legacy aliases, optional `triggers`, single `nf` log key, PolicyAssociation
// bodies without non-schema attributes.
// Ref: TS 29.507, TS 29.525, TS 29.512 §4.2.5.2 / §5.3.3.4.2, TS 29.514 §4.2.4.2 / §5.3.3.4.2.

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func serve(s *Server, method, path, body string) *httptest.ResponseRecorder {
	return serveReq(s, method, path, body, nil)
}

// serveReq is serve with extra request headers.
func serveReq(s *Server, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, r)
	return w
}

func lastSegment(loc string) string { return loc[strings.LastIndex(loc, "/")+1:] }

// wantAbsoluteLocation asserts loc is {apiRoot}+path with apiRoot an https
// authority (httptest requests carry Host example.com). Ref: TS 29.501 §4.4.1.
func wantAbsoluteLocation(t *testing.T, loc, pathPrefix string) {
	t.Helper()
	const root = "https://example.com"
	if !strings.HasPrefix(loc, root+pathPrefix) || len(loc) == len(root+pathPrefix) {
		t.Errorf("Location %q, want %q<id>", loc, root+pathPrefix)
	}
}

func TestAMPolicy_CanonicalPath(t *testing.T) {
	s := newTestPCF(t)
	body := `{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS","plmnId":{"mcc":"001","mnc":"01"}}`
	const root = "/npcf-am-policy-control/v1/policies"
	w := serve(s, http.MethodPost, root, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("%s: %d %s", root, w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	wantAbsoluteLocation(t, loc, root+"/")
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 201 body: %v", err)
	}
	if v, present := resp["triggers"]; present {
		t.Errorf("triggers must be omitted when empty (minItems 1), got %v", v)
	}
	// PolicyAssociation (TS 29.507 §5.6.2.2) has no polAssoId attribute.
	if _, present := resp["polAssoId"]; present {
		t.Error("201 body carries non-schema polAssoId")
	}
	if d := serve(s, http.MethodDelete, root+"/"+lastSegment(loc), ""); d.Code != http.StatusNoContent {
		t.Errorf("delete: %d", d.Code)
	}
}

func TestUEPolicy_CanonicalPath(t *testing.T) {
	s := newTestPCF(t)
	s.cfg.DefaultURSP.Rules = []config.URSPRuleConfig{{Precedence: 255}}
	s.cfg.DefaultURSP.Rules[0].TrafficDescriptor.MatchAll = true
	const root = "/npcf-ue-policy-control/v1/policies"
	w := serve(s, http.MethodPost, root, `{"supi":"imsi-001010000000001"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("%s: %d %s", root, w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	wantAbsoluteLocation(t, loc, root+"/")

	// PolicyAssociation (TS 29.525 §5.6.2.2): uePolicy is Bytes (base64), no
	// polAssoId / uePolicySections attributes.
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 201 body: %v", err)
	}
	for _, k := range []string{"polAssoId", "uePolicySections"} {
		if _, present := resp[k]; present {
			t.Errorf("201 body carries non-schema %s", k)
		}
	}
	up, ok := resp["uePolicy"].(string)
	if !ok || up == "" {
		t.Fatalf("uePolicy missing or not a string: %v", resp["uePolicy"])
	}
	if raw, err := base64.StdEncoding.DecodeString(up); err != nil || len(raw) == 0 {
		t.Errorf("uePolicy is not non-empty base64: %v", err)
	}

	if d := serve(s, http.MethodDelete, root+"/"+lastSegment(loc), ""); d.Code != http.StatusNoContent {
		t.Errorf("delete: %d", d.Code)
	}
}

// TestUEPolicy_DeleteUnknown: DELETE of an unknown polAssoId (never created,
// already deleted, or the id of an SM policy) is 404 POLICY_ASSOCIATION_NOT_FOUND.
// Ref: TS 29.525 §4.2.5, §5.7.3 (application error table).
func TestUEPolicy_DeleteUnknown(t *testing.T) {
	s := newTestPCF(t)
	const root = "/npcf-ue-policy-control/v1/policies/"
	assertNotFound := func(t *testing.T, id string) {
		t.Helper()
		d := serve(s, http.MethodDelete, root+id, "")
		if d.Code != http.StatusNotFound || d.Header().Get("Content-Type") != "application/problem+json" {
			t.Fatalf("delete %s: %d %s", id, d.Code, d.Header().Get("Content-Type"))
		}
		if c := problemCause(t, d); c != "POLICY_ASSOCIATION_NOT_FOUND" {
			t.Errorf("cause %q, want POLICY_ASSOCIATION_NOT_FOUND", c)
		}
	}
	t.Run("never created", func(t *testing.T) { assertNotFound(t, "nope") })
	t.Run("deleted twice", func(t *testing.T) {
		w := serve(s, http.MethodPost, "/npcf-ue-policy-control/v1/policies", `{"supi":"imsi-001010000000001"}`)
		id := lastSegment(w.Header().Get("Location"))
		if d := serve(s, http.MethodDelete, root+id, ""); d.Code != http.StatusNoContent {
			t.Fatalf("first delete: %d", d.Code)
		}
		assertNotFound(t, id)
	})
	t.Run("SM policy id is not a UE policy", func(t *testing.T) {
		smID := createSmPolicyID(t, s)
		assertNotFound(t, smID)
		if !smPolicyStored(s, smID) {
			t.Error("UE delete removed an SM policy")
		}
	})
}

// TestLegacyAliasesRemoved: the deprecated non-standard aliases are no longer
// routed (404 unknown path / 405 method not allowed on a known path), while the
// canonical operations keep working. Ref: TS 29.507, TS 29.525, TS 29.512
// §4.2.5.2, TS 29.514 §4.2.4.2 (YAML paths only).
func TestLegacyAliasesRemoved(t *testing.T) {
	s := newTestPCF(t)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/npcf-ampolicycontrol/v1/policies", `{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS"}`},
		{http.MethodDelete, "/npcf-ampolicycontrol/v1/policies/x", ""},
		{http.MethodPost, "/npcf-ue-policy-control/v1/ue-policies", `{"supi":"imsi-001010000000001"}`},
		{http.MethodDelete, "/npcf-ue-policy-control/v1/ue-policies/x", ""},
		{http.MethodDelete, "/npcf-smpolicycontrol/v1/sm-policies/x", ""},
		{http.MethodDelete, "/npcf-policyauthorization/v1/app-sessions/x", ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := serve(s, tc.method, tc.path, tc.body)
			if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
				t.Errorf("status %d, want 404 or 405 (alias must not be routed): %s", w.Code, w.Body.String())
			}
		})
	}
	smID := createSmPolicyID(t, s)
	if d := serve(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+smID+"/delete", ""); d.Code != http.StatusNoContent {
		t.Errorf("canonical SM delete: %d", d.Code)
	}
}

// TestApiRoot covers the {apiRoot} used in absolute Location headers.
// Ref: TS 29.501 §4.4.1.
func TestApiRoot(t *testing.T) {
	for _, tc := range []struct {
		name, fqdn, addr, host, sni, want string
	}{
		{"fqdn with port", "pcf.5gc.example", "0.0.0.0:8006", "ignored:1", "", "https://pcf.5gc.example:8006"},
		{"fqdn, address without port", "pcf", "weird", "ignored:1", "", "https://pcf"},
		{"no fqdn uses Host", "", "0.0.0.0:8006", "pcf:8006", "", "https://pcf:8006"},
		{"no fqdn, no Host uses SNI with port", "", "0.0.0.0:8006", "", "pcf.sni", "https://pcf.sni:8006"},
		{"no fqdn, no Host, specified address", "", "10.0.0.5:8006", "", "", "https://10.0.0.5:8006"},
		{"no fqdn, no Host, specified IPv6 address", "", "[2001:db8::1]:8006", "", "", "https://[2001:db8::1]:8006"},
		{"never 0.0.0.0", "", "0.0.0.0:8006", "", "", ""},
		{"never ::", "", "[::]:8006", "", "", ""},
		{"never empty host", "", ":8006", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: &config.Config{}}
			s.cfg.SBI.FQDN, s.cfg.SBI.Address = tc.fqdn, tc.addr
			r := httptest.NewRequest(http.MethodPost, "/x", nil)
			r.Host = tc.host
			if tc.sni != "" {
				r.TLS = &tls.ConnectionState{ServerName: tc.sni}
			}
			got := s.apiRoot(r)
			if got != tc.want {
				t.Errorf("apiRoot = %q, want %q", got, tc.want)
			}
			for _, bad := range []string{"0.0.0.0", "[::]", "https://:", "https:///"} {
				if strings.Contains(got, bad) {
					t.Errorf("apiRoot %q contains unspecified host %q", got, bad)
				}
			}
		})
	}
}

// TestLocationAbsoluteAllCreates: the four 201 Location headers are absolute
// and use the configured FQDN + SBI port. Ref: TS 29.501 §4.4.1.
func TestLocationAbsoluteAllCreates(t *testing.T) {
	s := newTestPCF(t)
	s.cfg.SBI.FQDN, s.cfg.SBI.Address = "pcf.5gc.example", "0.0.0.0:8006"
	for _, tc := range []struct{ path, body, prefix string }{
		{"/npcf-smpolicycontrol/v1/sm-policies", `{"supi":"imsi-001010000000001"}`, "/npcf-smpolicycontrol/v1/sm-policies/"},
		{"/npcf-am-policy-control/v1/policies", `{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS"}`, "/npcf-am-policy-control/v1/policies/"},
		{"/npcf-ue-policy-control/v1/policies", `{"supi":"imsi-001010000000001"}`, "/npcf-ue-policy-control/v1/policies/"},
		{"/npcf-policyauthorization/v1/app-sessions", `{"ascReqData":{"ueIpv4":"10.60.0.1"}}`, "/npcf-policyauthorization/v1/app-sessions/"},
	} {
		w := serve(s, http.MethodPost, tc.path, tc.body)
		if w.Code != http.StatusCreated {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
		loc := w.Header().Get("Location")
		if !strings.HasPrefix(loc, "https://pcf.5gc.example:8006"+tc.prefix) {
			t.Errorf("%s: Location %q", tc.path, loc)
		}
	}
}

// createSmPolicyID creates an SM policy and returns its id.
func createSmPolicyID(t *testing.T, s *Server) string {
	t.Helper()
	w := serve(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies", `{"supi":"imsi-001010000000001","dnn":"internet"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	return lastSegment(w.Header().Get("Location"))
}

func smPolicyStored(s *Server, id string) bool {
	s.policiesMu.Lock()
	defer s.policiesMu.Unlock()
	_, ok := s.policies[id]
	return ok
}

func problemCause(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var pd map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &pd); err != nil {
		t.Fatalf("decode ProblemDetails %q: %v", w.Body.String(), err)
	}
	c, _ := pd["cause"].(string)
	return c
}

// TestSmPolicyDelete_PostCustomOperation: POST .../delete with {} , empty body,
// invalid JSON, over-cap body and unknown ID.
// Ref: TS 29.512 §4.2.5.2, §5.3.3.4.2, §5.7.3, TS 29.500 §5.2.7.2.
func TestSmPolicyDelete_PostCustomOperation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantStatus int
		wantCause  string
		wantGone   bool
	}{
		{"empty object", `{}`, http.StatusNoContent, "", true},
		{"empty body", ``, http.StatusNoContent, "", true},
		{"populated body", `{"userLocationInfo":{}}`, http.StatusNoContent, "", true},
		{"invalid JSON", `{not json`, http.StatusBadRequest, "INVALID_MSG_FORMAT", false},
		{"over-cap body", `{"x":"` + strings.Repeat("a", features.MaxRequestBodyBytes+1) + `"}`, http.StatusRequestEntityTooLarge, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestPCF(t)
			id := createSmPolicyID(t, s)
			d := serve(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+id+"/delete", tc.body)
			if d.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", d.Code, tc.wantStatus, d.Body.String())
			}
			if tc.wantCause != "" && problemCause(t, d) != tc.wantCause {
				t.Errorf("cause %q, want %q", problemCause(t, d), tc.wantCause)
			}
			if gone := !smPolicyStored(s, id); gone != tc.wantGone {
				t.Errorf("policy removed = %v, want %v", gone, tc.wantGone)
			}
			if !tc.wantGone {
				return
			}
			// Second delete: unknown -> 404 ProblemDetails POLICY_ASSOCIATION_NOT_FOUND.
			d2 := serve(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+id+"/delete", `{}`)
			if d2.Code != http.StatusNotFound || d2.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("repeat delete: %d %s", d2.Code, d2.Header().Get("Content-Type"))
			}
			if c := problemCause(t, d2); c != "POLICY_ASSOCIATION_NOT_FOUND" {
				t.Errorf("repeat delete cause %q", c)
			}
		})
	}
}

// TestSmPolicyDelete_DeregistersBSFBinding: a stored BSF binding is always
// deregistered on POST .../delete, including
// when the policy map no longer holds the policy (404 path).
// Ref: TS 29.521 §5.2.2.3, TS 29.512 §4.2.5.2.
func TestSmPolicyDelete_DeregistersBSFBinding(t *testing.T) {
	for _, tc := range []struct {
		name       string
		method     string
		suffix     string
		dropPolicy bool
		wantStatus int
	}{
		{"POST delete", http.MethodPost, "/delete", false, http.StatusNoContent},
		{"POST delete, policy already gone", http.MethodPost, "/delete", true, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var deleted atomic.Value
			s, _ := newTestPCFWithBSF(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deleted.Store(r.URL.Path)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.WriteHeader(http.StatusMethodNotAllowed)
			})
			id := createSmPolicyID(t, s)
			s.policiesMu.Lock()
			s.bsfBindingIDs[id] = "bind-1"
			if tc.dropPolicy {
				delete(s.policies, id)
			}
			s.policiesMu.Unlock()

			d := serve(s, tc.method, "/npcf-smpolicycontrol/v1/sm-policies/"+id+tc.suffix, "")
			if d.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d", d.Code, tc.wantStatus)
			}
			if got, _ := deleted.Load().(string); got != "/nbsf-management/v1/pcfBindings/bind-1" {
				t.Errorf("BSF deregister path %q", got)
			}
			s.policiesMu.Lock()
			_, still := s.bsfBindingIDs[id]
			s.policiesMu.Unlock()
			if still {
				t.Error("bsfBindingIDs entry kept after delete")
			}
		})
	}
}

// TestAppSessionDelete_PostCustomOperation. Ref: TS 29.514 §4.2.4.2, §5.3.3.4.2, §5.7.3.
func TestAppSessionDelete_PostCustomOperation(t *testing.T) {
	createBody := `{"ascReqData":{"aspId":"af-test","ueIpv4":"10.60.0.1","qosReference":"qos-gold"}}`
	for _, tc := range []struct {
		name       string
		method     string
		suffix     string
		delBody    string
		wantStatus int
		wantGone   bool
	}{
		{"POST no body", http.MethodPost, "/delete", "", http.StatusNoContent, true},
		{"POST empty object", http.MethodPost, "/delete", `{}`, http.StatusNoContent, true},
		{"POST events body ignored", http.MethodPost, "/delete", `{"events":[]}`, http.StatusNoContent, true},
		{"POST invalid JSON", http.MethodPost, "/delete", `{oops`, http.StatusBadRequest, false},
		{"POST over-cap body", http.MethodPost, "/delete", `{"x":"` + strings.Repeat("a", features.MaxRequestBodyBytes+1) + `"}`, http.StatusRequestEntityTooLarge, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestPCF(t)
			w := serve(s, http.MethodPost, "/npcf-policyauthorization/v1/app-sessions", createBody)
			if w.Code != http.StatusCreated {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			loc := w.Header().Get("Location")
			id := lastSegment(loc)
			path := "/npcf-policyauthorization/v1/app-sessions/" + id + tc.suffix
			wantAbsoluteLocation(t, loc, "/npcf-policyauthorization/v1/app-sessions/")
			d := serve(s, tc.method, path, tc.delBody)
			if d.Code != tc.wantStatus {
				t.Fatalf("%s %s: %d %s, want %d", tc.method, path, d.Code, d.Body.String(), tc.wantStatus)
			}
			if tc.wantStatus == http.StatusBadRequest && problemCause(t, d) != "INVALID_MSG_FORMAT" {
				t.Errorf("cause %q, want INVALID_MSG_FORMAT", problemCause(t, d))
			}
			s.appSessionsMu.Lock()
			_, stored := s.appSessions[id]
			s.appSessionsMu.Unlock()
			if stored == tc.wantGone {
				t.Errorf("app-session stored = %v, want %v", stored, !tc.wantGone)
			}
			if !tc.wantGone {
				return
			}
			d2 := serve(s, tc.method, path, tc.delBody)
			if d2.Code != http.StatusNotFound {
				t.Fatalf("repeat %s %s: %d, want 404", tc.method, path, d2.Code)
			}
			if c := problemCause(t, d2); c != "APPLICATION_SESSION_CONTEXT_NOT_FOUND" {
				t.Errorf("repeat cause %q, want APPLICATION_SESSION_CONTEXT_NOT_FOUND", c)
			}
		})
	}
}

// TestLogLinesCarryExactlyOneNfKey mirrors cmd/pcf/main.go (logger already
// carries nf) and checks no emitted line repeats the "nf" key.
func TestLogLinesCarryExactlyOneNfKey(t *testing.T) {
	s, logs := newFeaturePCF(t, nil, Catalogs{})
	w := serve(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies", `{"supi":"imsi-001010000000001","dnn":"internet"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	serve(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+lastSegment(w.Header().Get("Location"))+"/delete", `{}`)
	lines := bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n"))
	if len(lines) < 2 {
		t.Fatalf("expected log lines, got %d", len(lines))
	}
	for _, l := range lines {
		if n := bytes.Count(l, []byte(`"nf":`)); n != 1 {
			t.Errorf("log line has %d nf keys: %s", n, l)
		}
	}
}
