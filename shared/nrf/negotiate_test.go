package nrf

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
	"time"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// goldenDiscoverURI is the NFDiscover request URI captured from the pre-change
// HEAD (git worktree) for the query used by goldenQuery: the legacy bytes.
const goldenDiscoverURI = "/nnrf-disc/v1/nf-instances?dnn=internet&requester-nf-instance-id=abc&requester-nf-type=AMF&service-names=nudm-sdm&snssais=%5B%7B%22sst%22%3A1%2C%22sd%22%3A%22010203%22%7D%5D&target-nf-type=UDM"

func goldenQuery() DiscoveryQuery {
	return DiscoveryQuery{
		TargetNFType: "UDM", RequesterNFType: "AMF", ServiceNames: []string{"nudm-sdm"},
		DNN: "internet", RequesterNFInstanceID: "abc", SNSSAIs: []SNSSAIEntry{{SST: 1, SD: "010203"}},
	}
}

func profileFor(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// capture runs one Discover against a private NRF stub answering body and
// returns the request URI, the Accept header, the result and the JSON log
// records emitted by the client.
func capture(t *testing.T, p *capability.Profile, cat *features.Catalog, q DiscoveryQuery, body string) (uri, accept string, res *SearchResult, logs []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		uri, accept = r.URL.RequestURI(), r.Header.Get("Accept")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	var buf bytes.Buffer
	c := New(srv.URL, &http.Client{Timeout: time.Second}, slog.New(slog.NewJSONHandler(&buf, nil)))
	if p != nil {
		c.SetProfile(p)
	}
	c.SetDiscoveryCatalog(cat)
	res, err := c.Discover(context.Background(), q)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		logs = append(logs, rec)
	}
	mu.Lock()
	defer mu.Unlock()
	return uri, accept, res, logs
}

func negotiationLog(t *testing.T, logs []map[string]any) map[string]any {
	t.Helper()
	for _, l := range logs {
		if l["procedure"] == features.ProcedureName {
			return l
		}
	}
	t.Fatalf("no FeatureNegotiation record in %v", logs)
	return nil
}

// TestDiscoverRel17Golden: nil profile and explicit rel17 send the legacy
// bytes (no requester-features), whatever the NRF answers.
func TestDiscoverRel17Golden(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *capability.Profile
	}{
		{"nil profile", nil},
		{"explicit rel17", profileFor(t, capability.ProfileRel17)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uri, accept, res, logs := capture(t, tc.p, nil, goldenQuery(), `{"nfInstances":[],"nrfSupportedFeatures":"3"}`)
			if uri != goldenDiscoverURI {
				t.Errorf("uri = %s\nwant  %s", uri, goldenDiscoverURI)
			}
			if accept != "application/json" {
				t.Errorf("Accept = %q", accept)
			}
			if !res.Negotiated.IsEmpty() {
				t.Errorf("Negotiated = %s, want empty (nothing offered)", res.Negotiated)
			}
			l := negotiationLog(t, logs)
			if l["interface"] != "Nnrf" || l["direction"] != "OUT" || l["peer_nf_type"] != "NRF" ||
				l["spec_ref"] != "TS 29.500 §6.6.2" || l["result"] != "OK" || l["features_negotiated"] != "0" {
				t.Errorf("log = %v", l)
			}
		})
	}
}

// TestDiscoverRel19Offer: rel19 sends requester-features, "0" with the default
// catalog (no bit implemented), and an implemented bit when injected.
func TestDiscoverRel19Offer(t *testing.T) {
	implemented, err := features.NewCatalog(features.MustImplement(features.NnrfNFDiscoveryEntries(), 1, 2)...)
	if err != nil {
		t.Fatal(err)
	}
	rel19 := profileFor(t, capability.ProfileRel19)
	tests := []struct {
		name      string
		cat       *features.Catalog
		query     func() DiscoveryQuery
		answer    string
		wantParam string
		wantNeg   string
		wantRes   string
	}{
		{"default catalog offers 0", nil, goldenQuery, `"3"`, "0", "0", "OK"},
		{"implemented bits intersect NRF set", implemented, goldenQuery, `"1"`, "3", "1", "OK"},
		{"NRF answers nothing", implemented, goldenQuery, "", "3", "0", "OK"},
		{"explicit caller value wins", nil, func() DiscoveryQuery {
			q := goldenQuery()
			q.RequesterFeatures = "a3"
			return q
		}, `"3"`, "a3", "3", "OK"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ans := ""
			if tc.answer != "" {
				ans = `,"nrfSupportedFeatures":` + tc.answer
			}
			uri, _, res, logs := capture(t, rel19, tc.cat, tc.query(), `{"nfInstances":[]`+ans+`}`)
			if !strings.Contains(uri, "requester-features="+tc.wantParam) {
				t.Errorf("uri %s lacks requester-features=%s", uri, tc.wantParam)
			}
			if got := res.Negotiated.String(); got != tc.wantNeg {
				t.Errorf("Negotiated = %s, want %s", got, tc.wantNeg)
			}
			l := negotiationLog(t, logs)
			if l["result"] != tc.wantRes || l["features_negotiated"] != tc.wantNeg {
				t.Errorf("log = %v", l)
			}
		})
	}
}

// TestDiscoverMalformedAnswer: a non-hex nrfSupportedFeatures negotiates
// nothing, logs FAILURE and still returns the discovery result, including with
// an offer of "0" (Accept alone skips validating then).
func TestDiscoverMalformedAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *capability.Profile
	}{
		{"rel19 offer 0", profileFor(t, capability.ProfileRel19)},
		{"rel17 nothing offered", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, res, logs := capture(t, tc.p, nil, goldenQuery(),
				`{"nfInstances":[{"nfInstanceId":"x","nfType":"UDM","nfStatus":"REGISTERED"}],"nrfSupportedFeatures":"zz"}`)
			if len(res.NFInstances) != 1 {
				t.Fatalf("discovery lost its result: %+v", res)
			}
			l := negotiationLog(t, logs)
			if l["result"] != "FAILURE" || l["features_negotiated"] != "0" || l["features_peer"] != "zz" || l["error"] == nil {
				t.Errorf("log = %v", l)
			}
			if l["level"] != "WARN" {
				t.Errorf("level = %v, want WARN", l["level"])
			}
		})
	}
}

// TestDiscoverNonStringAnswer: an nrfSupportedFeatures of the wrong JSON type
// must not fail the discovery (R13), under rel17 too; it is logged FAILURE.
func TestDiscoverNonStringAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *capability.Profile
		val  string
	}{
		{"rel19 number", profileFor(t, capability.ProfileRel19), `3`},
		{"rel17 array", nil, `["a"]`},
		{"rel17 object", nil, `{"a":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, res, logs := capture(t, tc.p, nil, goldenQuery(),
				`{"nfInstances":[{"nfInstanceId":"x","nfType":"UDM","nfStatus":"REGISTERED"}],"nrfSupportedFeatures":`+tc.val+`,"searchId":"s1"}`)
			if len(res.NFInstances) != 1 || res.NRFSupportedFeatures != "" || string(res.Extra["searchId"]) != `"s1"` {
				t.Fatalf("discovery lost its result: %+v", res)
			}
			if _, leaked := res.Extra["nrfSupportedFeatures"]; leaked {
				t.Errorf("known key leaked into Extra: %v", res.Extra)
			}
			l := negotiationLog(t, logs)
			if l["result"] != "FAILURE" || l["level"] != "WARN" || l["features_negotiated"] != "0" || l["error"] == nil {
				t.Errorf("log = %v", l)
			}
		})
	}
}
