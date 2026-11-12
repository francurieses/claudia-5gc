package main

// smf_features_test.go - REL19-2.7 consumer side of Nsmf_PDUSession
// supportedFeatures negotiation in HTTPSMFClient.CreateSMContext (decision D2,
// rules R11-R14). The rel17 request body is pinned by golden_features_test.go.
// Ref: TS 29.500 §6.6.2; TS 29.502 §6.1.8 (Table 6.1.8-1).

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfsbi "github.com/francurieses/claudia-5gc/nf/amf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func testProfile(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("NewProfile(%q): %v", name, err)
	}
	return p
}

// implementedCatalog is an Nsmf_PDUSession catalog with features 1 and 2
// marked implemented, to exercise real intersections.
func implementedCatalog() *features.Catalog {
	return features.MustCatalog(features.MustImplement(features.NsmfPDUSessionEntries(), 1, 2)...)
}

// smfFeaturesFixture serves a CreateSMContext answer and records the request
// body and the log output of the client.
func smfFeaturesFixture(t *testing.T, answerBody string) (c *HTTPSMFClient, body *string, logs *bytes.Buffer) {
	t.Helper()
	body, logs = new(string), new(bytes.Buffer)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		*body = string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(answerBody))
	}))
	t.Cleanup(srv.Close)
	c = &HTTPSMFClient{
		address: strings.TrimPrefix(srv.URL, "https://"),
		client:  srv.Client(),
		logger:  slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "AMF"),
	}
	return c, body, logs
}

func createSM(t *testing.T, c *HTTPSMFClient) (string, features.Set) {
	t.Helper()
	ref, _, _, neg, err := c.CreateSMContext(t.Context(), "imsi-001010000000001", "internet", 5,
		[]byte{1, 2, 3}, amfctx.SNSSAISubscribed{SST: 1, SD: "000001"})
	if err != nil {
		t.Fatalf("CreateSMContext must not fail on negotiation: %v", err)
	}
	return ref, neg
}

func offeredIn(t *testing.T, body string) (string, bool) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("request body: %v", err)
	}
	v, ok := m["supportedFeatures"].(string)
	return v, ok
}

func TestCreateSMContext_Rel17SendsNothingAndNegotiatesNothing(t *testing.T) {
	for _, p := range []*capability.Profile{nil, testProfile(t, "rel17")} {
		// A rel17 consumer never offers, so whatever the SMF answers (R14)
		// negotiates nothing.
		c, body, _ := smfFeaturesFixture(t, `{"smContextRef":"r","supportedFeatures":"ff"}`)
		c.profile, c.catalog = p, implementedCatalog()
		ref, neg := createSM(t, c)
		if _, present := offeredIn(t, *body); present {
			t.Errorf("rel17/nil profile must not send supportedFeatures: %s", *body)
		}
		if ref != "r" || !neg.IsEmpty() {
			t.Errorf("ref=%q negotiated=%s", ref, neg)
		}
	}
}

// TestCreateSMContext_Rel19RealCatalogOffersES3XX: the production catalog
// implements only Nsmf_PDUSession feature 8 ES3XX (SBI-FEAT-001), so rel19 sends
// "80" (TS 29.500 §6.6.2: client shall include it). The producer answer is
// intersected with the offer: only an answer carrying bit 8 negotiates ES3XX.
func TestCreateSMContext_Rel19RealCatalogOffersES3XX(t *testing.T) {
	for _, tc := range []struct {
		answer  string
		wantNeg string
	}{
		{`{"smContextRef":"r"}`, "0"},
		{`{"smContextRef":"r","supportedFeatures":"0"}`, "0"},
		{`{"smContextRef":"r","supportedFeatures":"7f"}`, "0"},
		{`{"smContextRef":"r","supportedFeatures":"80"}`, "80"},
		{`{"smContextRef":"r","supportedFeatures":"ff"}`, "80"},
	} {
		c, body, _ := smfFeaturesFixture(t, tc.answer)
		c.profile = testProfile(t, "rel19")
		_, neg := createSM(t, c)
		if v, ok := offeredIn(t, *body); !ok || v != "80" {
			t.Errorf("rel19 offer = %q (present=%v), want \"80\"", v, ok)
		}
		if neg.String() != tc.wantNeg {
			t.Errorf("answer %s negotiated %s, want %s", tc.answer, neg, tc.wantNeg)
		}
	}
}

func TestCreateSMContext_Rel19Intersection(t *testing.T) {
	tests := []struct {
		name       string
		answer     string // supportedFeatures in the 201 body ("-" = attribute absent)
		want       string
		wantResult string
		wantPeer   string
	}{
		{"R11 answer superset, only offered bits survive", "ff", "3", "OK", "ff"},
		{"R11 partial", "1", "1", "OK", "1"},
		{"R12 absent answer negotiates nothing", "-", "0", "OK", "absent"},
		{"R12 empty answer negotiates nothing", "", "0", "OK", "absent"},
		{"disjoint", "4", "0", "OK", "4"},
		{"uppercase hex", "3", "3", "OK", "3"},
		{"R13 non-hex answer fails closed", "zz", "0", "FAILURE", "zz"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			answer := `{"smContextRef":"r","unknownAttr":{"x":1}`
			if tc.answer != "-" {
				answer += `,"supportedFeatures":"` + tc.answer + `"`
			}
			answer += `}`
			c, body, logs := smfFeaturesFixture(t, answer)
			c.profile, c.catalog = testProfile(t, "rel19"), implementedCatalog()
			ref, neg := createSM(t, c)
			if v, _ := offeredIn(t, *body); v != "3" {
				t.Errorf("offer = %q, want 3", v)
			}
			if ref != "r" {
				t.Errorf("ref = %q (unknown attributes must be ignored)", ref)
			}
			if neg.String() != tc.want {
				t.Errorf("negotiated = %s, want %s", neg, tc.want)
			}
			rec := lastLog(t, logs, features.ProcedureName)
			for k, want := range map[string]string{
				"nf": "AMF", "interface": "Nsmf", "direction": "OUT", "spec_ref": features.SpecRef,
				"peer_nf_type": "SMF", "features_local": "3", "features_peer": tc.wantPeer,
				"features_negotiated": tc.want, "result": tc.wantResult, "supi": "imsi-001010000000001",
			} {
				if got, _ := rec[k].(string); got != want {
					t.Errorf("log %s = %q, want %q (record %v)", k, got, want, rec)
				}
			}
			if rec["pdu_session_id"] != float64(5) {
				t.Errorf("pdu_session_id = %v", rec["pdu_session_id"])
			}
		})
	}
}

func TestCreateSMContext_Rel17LogsNegotiationLine(t *testing.T) {
	c, _, logs := smfFeaturesFixture(t, `{"smContextRef":"r"}`)
	createSM(t, c)
	rec := lastLog(t, logs, features.ProcedureName)
	if rec["features_peer"] != features.PeerAbsent || rec["features_negotiated"] != "0" || rec["result"] != "OK" {
		t.Errorf("record = %v", rec)
	}
}

func TestWithAddressKeepsNegotiationConfig(t *testing.T) {
	p := testProfile(t, "rel19")
	c := &HTTPSMFClient{address: "a", profile: p, catalog: amfsbi.NsmfPDUSessionCatalog()}
	d := c.withAddress("b")
	if d.address != "b" || c.address != "a" || d.profile != p || d.catalog != c.catalog {
		t.Errorf("withAddress = %+v", d)
	}
}

func lastLog(t *testing.T, buf *bytes.Buffer, procedure string) map[string]any {
	t.Helper()
	var found map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var m map[string]any
		if json.Unmarshal(line, &m) == nil && m["procedure"] == procedure {
			found = m
		}
	}
	if found == nil {
		t.Fatalf("no %s log line in %s", procedure, buf)
	}
	return found
}

func TestBuildNFProfile_SupportedFeatures(t *testing.T) {
	cat := amfsbi.NamfCommunicationCatalog()
	rel19 := amfsbi.BuildNFProfile("amf-test-1", testProfile(t, "rel19"), cat)
	if got := rel19.NFServices[0].SupportedFeatures; got != "0" {
		t.Errorf("rel19 namf-comm supportedFeatures = %q, want \"0\" (nothing implemented)", got)
	}
	b, _ := json.Marshal(rel19)
	if !strings.Contains(string(b), `"supportedFeatures":"0"`) {
		t.Errorf("rel19 profile JSON lacks supportedFeatures: %s", b)
	}
	// With an implemented bit the rel19 value follows the catalog.
	impl := features.MustCatalog(features.MustImplement(features.NamfCommunicationEntries(), 1, 2)...)
	if got := amfsbi.BuildNFProfile("x", testProfile(t, "rel19"), impl).NFServices[0].SupportedFeatures; got != "3" {
		t.Errorf("implemented catalog value = %q, want 3", got)
	}
	// rel17 and nil profile: attribute absent, JSON equals the golden.
	for _, p := range []*capability.Profile{nil, testProfile(t, "rel17")} {
		b, _ := json.Marshal(amfsbi.BuildNFProfile("amf-test-1", p, impl))
		if string(b) != goldenNFProfileJSON {
			t.Errorf("rel17/nil NFProfile differs from golden:\n%s", b)
		}
	}
}

func TestConfig_ReleaseBlock(t *testing.T) {
	dir := t.TempDir()
	write := func(name, y string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct{ name, yaml, want string }{
		{"absent block defaults to rel19", "nf_instance_id: a\n", "rel19"},
		{"explicit rel17", "nf_instance_id: a\nrelease:\n  profile: rel17\n", "rel17"},
		{"rel19", "nf_instance_id: a\nrelease:\n  profile: rel19\n", "rel19"},
	} {
		cfg, err := loadConfig(write("c.yaml", tc.yaml))
		if err != nil {
			t.Fatalf("%s: loadConfig: %v", tc.name, err)
		}
		p, err := capability.NewProfile(cfg.Release, func(string) string { return "" })
		if err != nil || p.Name() != tc.want {
			t.Errorf("%s: profile = %v, %v; want %s", tc.name, p, err, tc.want)
		}
	}
	cfg, err := loadConfig(write("bad.yaml", "release:\n  profile: rel99\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capability.NewProfile(cfg.Release, func(string) string { return "" }); err == nil {
		t.Error("unknown profile must be an error (startup fails)")
	}
}
