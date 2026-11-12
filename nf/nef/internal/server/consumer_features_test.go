package server

// consumer_features_test.go - consumer-side supportedFeatures negotiation of
// the NEF towards the BSF (Nbsf_Management_Discovery, TS 29.521 §5.8) and the
// PCF (Npcf_PolicyAuthorization_Create, TS 29.514 §5.8), REL19-2.7 slice 7.
// Ref: TS 29.500 §6.6.2, §6.10.9.1; decision D2 of dev/REL19_PROGRAM.md §2.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	nefsbi "github.com/francurieses/claudia-5gc/nf/nef/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func baseLogger(buf *syncBuf) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil)).With("nf", "NEF")
}

func negLines(t *testing.T, buf *syncBuf) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.bytes()), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"procedure":"`+features.ProcedureName+`"`)) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func TestConsumerCatalogs(t *testing.T) {
	r19 := profileNamed(t, "rel19")
	r17 := profileNamed(t, "rel17")
	if got := features.Request(nefsbi.NbsfManagementCatalog(), r19); got != "8" {
		t.Errorf("Nbsf rel19 offer = %q, want 8", got)
	}
	if got := features.Request(nefsbi.NpcfPolicyAuthorizationCatalog(), r19); got != "2010000" {
		t.Errorf("Npcf rel19 offer = %q, want 2010000", got)
	}
	for _, c := range []*features.Catalog{nefsbi.NbsfManagementCatalog(), nefsbi.NpcfPolicyAuthorizationCatalog()} {
		if features.Request(c, r17) != "" || features.Request(c, nil) != "" {
			t.Error("rel17/nil profile must send no supportedFeatures")
		}
	}
}

func TestBSFDiscoverNegotiation(t *testing.T) {
	tests := []struct {
		name, profile, answer string // answer: raw JSON value of suppFeat, "" = absent
		status                int
		wantQuery             string
		wantResult            string // "" = no log line
		wantNeg               string
	}{
		{"rel17 no query, no answer", "rel17", "", 200, "ipv4Addr=10.60.0.1", "OK", "0"},
		{"rel19 offers 8", "rel19", "", 200, "ipv4Addr=10.60.0.1&supp-feat=8", "OK", "0"},
		{"rel19 intersection", "rel19", `"ff"`, 200, "ipv4Addr=10.60.0.1&supp-feat=8", "OK", "8"},
		{"non-string answer", "rel19", `5`, 200, "ipv4Addr=10.60.0.1&supp-feat=8", "FAILURE", "0"},
		{"non-hex answer", "rel19", `"zz"`, 200, "ipv4Addr=10.60.0.1&supp-feat=8", "FAILURE", "0"},
		{"rel17 empty offer, malformed answer", "rel17", `"zz"`, 200, "ipv4Addr=10.60.0.1", "FAILURE", "0"},
		{"204 no answer, no log", "rel19", "", 204, "ipv4Addr=10.60.0.1&supp-feat=8", "", ""},
		{"404 not found, no log", "rel19", "", 404, "ipv4Addr=10.60.0.1&supp-feat=8", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var gotQuery string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				gotQuery = r.URL.RawQuery
				mu.Unlock()
				if tc.status != 200 {
					w.WriteHeader(tc.status)
					return
				}
				body := `{"bindingId":"b1","pcfFqdn":"pcf.example"`
				if tc.answer != "" {
					body += `,"suppFeat":` + tc.answer
				}
				_, _ = w.Write([]byte(body + `}`))
			}))
			defer ts.Close()
			logs := &syncBuf{}
			c := (&HTTPBSFClient{BaseURL: ts.URL, Client: ts.Client(), Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}).
				WithFeatures(profileNamed(t, tc.profile), baseLogger(logs))
			b, err := c.Discover(context.Background(), "10.60.0.1")
			if tc.status == 204 || tc.status == 404 {
				if !errors.Is(err, ErrPcfBindingNotFound) {
					t.Fatalf("err = %v", err)
				}
			} else if err != nil || b.PcfFqdn != "pcf.example" {
				t.Fatalf("discovery must succeed even on a malformed answer: %v %+v", err, b)
			}
			mu.Lock()
			q := gotQuery
			mu.Unlock()
			if q != tc.wantQuery {
				t.Errorf("query = %q, want %q", q, tc.wantQuery)
			}
			lines := negLines(t, logs)
			if tc.wantResult == "" {
				if len(lines) != 0 {
					t.Fatalf("unexpected negotiation lines: %v", lines)
				}
				return
			}
			if len(lines) != 1 {
				t.Fatalf("lines = %d, want 1", len(lines))
			}
			l := lines[0]
			if l["result"] != tc.wantResult || l["peer_nf_type"] != "BSF" || l["interface"] != "Nbsf" ||
				l["direction"] != "OUT" || l["spec_ref"] != "TS 29.500 §6.6.2" || l["features_negotiated"] != tc.wantNeg {
				t.Errorf("record = %v", l)
			}
		})
	}
}

func TestBSFNon2xxUnchanged(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer ts.Close()
	logs := &syncBuf{}
	c := (&HTTPBSFClient{BaseURL: ts.URL, Client: ts.Client(), Logger: slog.Default()}).WithFeatures(profileNamed(t, "rel19"), baseLogger(logs))
	if _, err := c.Discover(context.Background(), "10.60.0.1"); err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("err = %v", err)
	}
	if len(negLines(t, logs)) != 0 {
		t.Error("no negotiation on a non-2xx answer")
	}
}

func TestPCFCreateNegotiation(t *testing.T) {
	tests := []struct {
		name, profile string
		status        int
		loc, body     string
		wantSent      string // expected ascReqData.suppFeat ("" = absent)
		wantResult    string
		wantNeg       string
		wantID        string
		wantErr       bool
	}{
		{"rel17 absent, no body", "rel17", 201, "/npcf-policyauthorization/v1/app-sessions/as-1", "", "", "OK", "0", "as-1", false},
		{"rel19 offer, no answer", "rel19", 201, "/npcf-policyauthorization/v1/app-sessions/as-1", "", "2010000", "OK", "0", "as-1", false},
		{"rel19 intersection", "rel19", 201, "/npcf-policyauthorization/v1/app-sessions/as-1", `{"ascRespData":{"suppFeat":"ffffffff"}}`, "2010000", "OK", "2010000", "as-1", false},
		{"non-string answer", "rel19", 201, "/npcf-policyauthorization/v1/app-sessions/as-1", `{"ascRespData":{"suppFeat":[1]}}`, "2010000", "FAILURE", "0", "as-1", false},
		{"non-hex answer", "rel19", 201, "/npcf-policyauthorization/v1/app-sessions/as-1", `{"ascRespData":{"suppFeat":"zz"}}`, "2010000", "FAILURE", "0", "as-1", false},
		{"rel17 empty offer, malformed answer", "rel17", 201, "/npcf-policyauthorization/v1/app-sessions/as-1", `{"ascRespData":{"suppFeat":"zz"}}`, "", "FAILURE", "0", "as-1", false},
		{"non-JSON body is a FAILURE, create succeeds", "rel19", 201, "/npcf-policyauthorization/v1/app-sessions/as-1", `<html>`, "2010000", "FAILURE", "0", "as-1", false},
		{"truncated JSON body is a FAILURE, create succeeds", "rel19", 201, "/npcf-policyauthorization/v1/app-sessions/as-1", `{"ascRespData":{"suppFeat":"20`, "2010000", "FAILURE", "0", "as-1", false},
		{"whitespace-only body is no answer", "rel19", 201, "/npcf-policyauthorization/v1/app-sessions/as-1", " \n", "2010000", "OK", "0", "as-1", false},
		{"legacy body id, trailing bytes tolerated", "rel19", 201, "", `{"appSessionId":"as-7"} trailing`, "2010000", "OK", "0", "as-7", false},
		{"legacy body id, concatenated JSON", "rel19", 201, "", `{"appSessionId":"as-8","ascRespData":{"suppFeat":"2000000"}}{"x":1}`, "2010000", "OK", "2000000", "as-8", false},
		{"legacy body id + answer", "rel19", 201, "", `{"appSessionId":"as-9","ascRespData":{"suppFeat":"2000000"}}`, "2010000", "OK", "2000000", "as-9", false},
		{"403", "rel19", 403, "", "", "2010000", "", "", "", true},
		{"500", "rel19", 500, "", "", "2010000", "", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var sent struct {
				AscReqData map[string]any `json:"ascReqData"`
			}
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				mu.Lock()
				_ = json.Unmarshal(b, &sent)
				mu.Unlock()
				if tc.loc != "" {
					w.Header().Set("Location", tc.loc)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer ts.Close()
			logs := &syncBuf{}
			c := (&HTTPPolicyAuthClient{Client: ts.Client(), Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}).
				WithFeatures(profileNamed(t, tc.profile), baseLogger(logs))
			id, neg, err := c.CreateAppSession(context.Background(), ts.URL, &AppSessionContextReqData{UeIpv4: "10.60.0.1"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			mu.Lock()
			sentSF, _ := sent.AscReqData["suppFeat"].(string)
			mu.Unlock()
			if sentSF != tc.wantSent {
				t.Errorf("ascReqData.suppFeat = %q, want %q", sentSF, tc.wantSent)
			}
			lines := negLines(t, logs)
			if tc.wantErr {
				if len(lines) != 0 {
					t.Error("no negotiation on a failed create")
				}
				return
			}
			if id != tc.wantID {
				t.Errorf("id = %q", id)
			}
			if neg.String() != tc.wantNeg {
				t.Errorf("negotiated = %q, want %q", neg.String(), tc.wantNeg)
			}
			if len(lines) != 1 {
				t.Fatalf("lines = %d", len(lines))
			}
			l := lines[0]
			if l["result"] != tc.wantResult || l["peer_nf_type"] != "PCF" || l["interface"] != "Npcf" || l["direction"] != "OUT" {
				t.Errorf("record = %v", l)
			}
		})
	}
}

// TestConsumerLogKeysOnce: slog's JSON handler does not de-duplicate keys.
func TestConsumerLogKeysOnce(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"pcfFqdn":"p","suppFeat":"8"}`))
			return
		}
		w.Header().Set("Location", "/npcf-policyauthorization/v1/app-sessions/as-1")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"ascRespData":{"suppFeat":"zz"}}`))
	}))
	defer ts.Close()
	logs := &syncBuf{}
	p := profileNamed(t, "rel19")
	ctx := logging.WithCorrelationID(context.Background(), "01TESTCORRELATIONID00000000")
	if _, err := (&HTTPBSFClient{BaseURL: ts.URL, Client: ts.Client(), Logger: slog.Default()}).WithFeatures(p, baseLogger(logs)).Discover(ctx, "10.60.0.1"); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if _, _, err := (&HTTPPolicyAuthClient{Client: ts.Client()}).WithFeatures(p, baseLogger(logs)).CreateAppSession(ctx, ts.URL, &AppSessionContextReqData{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	n := 0
	var results []string
	for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"procedure":"`+features.ProcedureName+`"`)) {
			continue
		}
		n++
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatal(err)
		}
		results = append(results, rec["peer_nf_type"].(string)+"="+rec["result"].(string))
		for _, k := range []string{"nf", "procedure", "correlation_id", "interface", "direction", "spec_ref",
			"peer_nf_type", "features_local", "features_peer", "features_negotiated", "result"} {
			if c := bytes.Count(line, []byte(`"`+k+`":`)); c != 1 {
				t.Errorf("key %q appears %d times in %s", k, c, line)
			}
		}
	}
	if n != 2 {
		t.Fatalf("lines = %d, want 2", n)
	}
	// BSF answered "8" (OK); the PCF answer "zz" is malformed -> FAILURE.
	if got := strings.Join(results, ","); got != "BSF=OK,PCF=FAILURE" {
		t.Errorf("results = %s", got)
	}
}

// errBody is a response body whose read fails after the headers.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errReadCloser) Close() error             { return nil }

type bodyErrTransport struct{ loc string }

func (b bodyErrTransport) RoundTrip(*http.Request) (*http.Response, error) {
	h := http.Header{}
	h.Set("Location", b.loc)
	return &http.Response{StatusCode: 201, Header: h, Body: errReadCloser{}}, nil
}

// TestPCFCreateBodyReadError: a failed body read yields exactly one
// FeatureNegotiation record, result=FAILURE, nothing negotiated, and the
// create still succeeds from Location (findings 1/2).
func TestPCFCreateBodyReadError(t *testing.T) {
	logs := &syncBuf{}
	c := (&HTTPPolicyAuthClient{Client: &http.Client{Transport: bodyErrTransport{loc: "/npcf-policyauthorization/v1/app-sessions/as-5"}}}).
		WithFeatures(profileNamed(t, "rel19"), baseLogger(logs))
	id, neg, err := c.CreateAppSession(context.Background(), "http://pcf", &AppSessionContextReqData{})
	if err != nil || id != "as-5" || neg.String() != "0" {
		t.Fatalf("id=%q neg=%q err=%v", id, neg.String(), err)
	}
	lines := negLines(t, logs)
	if len(lines) != 1 || lines[0]["result"] != "FAILURE" || lines[0]["cause"] != "BODY_READ_ERROR" || lines[0]["error"] == nil {
		t.Fatalf("records = %v", lines)
	}
}

// TestPCFCreateBodyOverBound: a body cut at the 1 MiB bound is not decodable
// -> one FAILURE record; the create still succeeds from Location.
func TestPCFCreateBodyOverBound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/npcf-policyauthorization/v1/app-sessions/as-6")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"ascRespData":{"suppFeat":"` + strings.Repeat("0", maxPCFCreateBodyBytes+10) + `"}}`))
	}))
	defer ts.Close()
	logs := &syncBuf{}
	c := (&HTTPPolicyAuthClient{Client: ts.Client()}).WithFeatures(profileNamed(t, "rel19"), baseLogger(logs))
	id, neg, err := c.CreateAppSession(context.Background(), ts.URL, &AppSessionContextReqData{})
	if err != nil || id != "as-6" || neg.String() != "0" {
		t.Fatalf("id=%q neg=%q err=%v", id, neg.String(), err)
	}
	lines := negLines(t, logs)
	if len(lines) != 1 || lines[0]["result"] != "FAILURE" {
		t.Fatalf("records = %v", lines)
	}
}

// TestPCFCreateDoesNotMutateRequest: the offer is set on a copy.
func TestPCFCreateDoesNotMutateRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/npcf-policyauthorization/v1/app-sessions/as-1")
		w.WriteHeader(201)
	}))
	defer ts.Close()
	req := &AppSessionContextReqData{UeIpv4: "10.60.0.1"}
	c := (&HTTPPolicyAuthClient{Client: ts.Client()}).WithFeatures(profileNamed(t, "rel19"), baseLogger(&syncBuf{}))
	if _, _, err := c.CreateAppSession(context.Background(), ts.URL, req); err != nil {
		t.Fatal(err)
	}
	if req.SuppFeat != "" {
		t.Errorf("caller request mutated: %q", req.SuppFeat)
	}
}

// TestNEFClientRedirectPolicy exercises the client main builds
// (NewOutboundClient, h2c dev branch): 307/308 are followed with method and
// body replayed; 301/302 are not followed and surface as the 3xx response
// (TS 29.500 §6.10.9.1). Removing ApplyRedirectPolicy from NewOutboundClient
// makes net/http follow 301/302 and rewrite POST to GET, failing this test.
func TestNEFClientRedirectPolicy(t *testing.T) {
	var mu sync.Mutex
	var hits []string // "<method> <body>" seen by the redirect target
	target := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		hits = append(hits, r.Method+" "+string(b))
		mu.Unlock()
		w.WriteHeader(200)
	}), &http2.Server{}))
	defer target.Close()

	cl, err := NewOutboundClient("", "", "", slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, code := range []int{301, 302, 307, 308} {
			mu.Lock()
			hits = nil
			mu.Unlock()
			redir := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				http.Redirect(w, r, target.URL, code)
			}), &http2.Server{}))
			var body io.Reader
			if method == http.MethodPost {
				body = strings.NewReader(`{"k":"v"}`)
			}
			req, _ := http.NewRequest(method, redir.URL, body)
			resp, err := cl.Do(req)
			if err != nil {
				t.Fatalf("%s %d: %v", method, code, err)
			}
			resp.Body.Close()
			redir.Close()
			mu.Lock()
			got := append([]string(nil), hits...)
			mu.Unlock()
			if code == 307 || code == 308 {
				wantBody := ""
				if method == http.MethodPost {
					wantBody = `{"k":"v"}`
				}
				if resp.StatusCode != 200 || len(got) != 1 || got[0] != method+" "+wantBody {
					t.Errorf("%s %d: status=%d hits=%q, want one replayed %q", method, code, resp.StatusCode, got, method+" "+wantBody)
				}
				continue
			}
			if resp.StatusCode != code || len(got) != 0 {
				t.Errorf("%s %d: status=%d hits=%q, want the 3xx returned and no follow", method, code, resp.StatusCode, got)
			}
		}
	}
}

// TestServerStoresPcfNegotiated: the Npcf negotiated set lands on the record.
func TestServerStoresPcfNegotiated(t *testing.T) {
	e := newNEFEnv(t, profileNamed(t, "rel19"), nil)
	set, err := features.Parse("2000000")
	if err != nil {
		t.Fatal(err)
	}
	e.pcf.createNegotiated = set
	resp, raw := e.create(t, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
	e.srv.mu.Lock()
	defer e.srv.mu.Unlock()
	n := 0
	for _, rec := range e.srv.subscriptions {
		n++
		if rec.pcfNegotiated.String() != "2000000" {
			t.Errorf("pcfNegotiated = %q", rec.pcfNegotiated.String())
		}
	}
	if n != 1 {
		t.Fatalf("records = %d", n)
	}
}
