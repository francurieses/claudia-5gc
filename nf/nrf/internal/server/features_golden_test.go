package server

// features_golden_test.go - byte-identity goldens for the NRF responses
// (REL19-2.7 slice 5). Captured against the pre-change code (git worktree at
// HEAD); they must pass UNCHANGED under rel17 / no profile for requests that
// carry no requester features (decision D1, dev/REL19_PROGRAM.md section 2).
// Only the generated ids (searchId ULID, subscription UUID) are masked; the
// fixed test instance ids appear verbatim so a wrong id or Location is caught.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

var (
	reSearchID = regexp.MustCompile(`"searchId":"[0-9A-Z]{26}"`)
	reSubID    = regexp.MustCompile(`(subscriptions/|"subscriptionId":")[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
)

// checkGolden compares got with testdata/<name>. UPDATE_GOLDEN=1 rewrites the
// file; only ever used on the pre-change tree (git worktree at HEAD).
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	if got != string(b) {
		t.Fatalf("%s changed\n got: %q\nwant: %q", name, got, b)
	}
}

// render serialises a recorded response: status, content type, Location and
// the body, with the generated ids masked.
func render(rec *httptest.ResponseRecorder) string {
	resp := rec.Result()
	body := reSearchID.ReplaceAllString(rec.Body.String(), `"searchId":"<ULID>"`)
	loc := resp.Header.Get("Location")
	out := "status: " + http.StatusText(resp.StatusCode) + "\n" +
		"Content-Type: " + resp.Header.Get("Content-Type") + "\n" +
		"Location: " + loc + "\n\n" + body
	return reSubID.ReplaceAllString(out, "${1}<SUBSCRIPTION_ID>")
}

const goldenSMF = `{"nfType":"SMF","fqdn":"smf.5gc","nfServices":[{"serviceInstanceId":"s1","serviceName":"nsmf-pdusession",` +
	`"versions":[{"apiVersionInUri":"v1","apiFullVersion":"1.0.0"}],"scheme":"https","nfServiceStatus":"REGISTERED","supportedFeatures":"8"}]}`

const goldenSMFMap = `{"nfType":"UDM","nfServiceList":{"m1":{"serviceInstanceId":"m1","serviceName":"nudm-sdm",` +
	`"versions":[{"apiVersionInUri":"v1","apiFullVersion":"1.0.0"}],"scheme":"https","nfServiceStatus":"REGISTERED"}}}`

const (
	goldenIDA = "aaaaaaaa-0000-0000-0000-00000000000a"
	goldenIDB = "bbbbbbbb-0000-0000-0000-00000000000b"
)

// goldenReq is one request of a golden scenario.
type goldenReq struct{ method, path, body string }

// TestGolden_NRFResponses runs every step on its own fresh server (the setup
// requests register whatever the step needs), so any subtest can run alone
// (-run 'TestGolden_NRFResponses/retrieve$') and in any order.
func TestGolden_NRFResponses(t *testing.T) { runNRFGoldens(t, nil) }

// TestGolden_NRFResponsesRel17Profile: the same goldens with an explicit rel17
// profile (decision D1: byte-identical to no profile and to the baseline).
func TestGolden_NRFResponsesRel17Profile(t *testing.T) {
	runNRFGoldens(t, profileNamed(t, "rel17"))
}

func runNRFGoldens(t *testing.T, prof *capability.Profile) {
	regA := goldenReq{http.MethodPut, "/nnrf-nfm/v1/nf-instances/" + goldenIDA, goldenSMF}
	regB := goldenReq{http.MethodPut, "/nnrf-nfm/v1/nf-instances/" + goldenIDB, goldenSMFMap}
	steps := []struct {
		name, golden string
		setup        []goldenReq
		goldenReq
	}{
		{"register", "golden_nrf_register_201.txt", nil, regA},
		{"register map", "golden_nrf_register_map_201.txt", nil, regB},
		{"register malformed", "golden_nrf_register_400.txt", nil, goldenReq{http.MethodPut, "/nnrf-nfm/v1/nf-instances/x", `{not json`}},
		{"retrieve", "golden_nrf_get_200.txt", []goldenReq{regA}, goldenReq{http.MethodGet, "/nnrf-nfm/v1/nf-instances/" + goldenIDA, ""}},
		{"retrieve unknown", "golden_nrf_get_404.txt", nil, goldenReq{http.MethodGet, "/nnrf-nfm/v1/nf-instances/unknown", ""}},
		{"discover", "golden_nrf_discover_200.txt", []goldenReq{regA, regB}, goldenReq{http.MethodGet,
			"/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF", ""}},
		{"discover filter", "golden_nrf_discover_filter_200.txt", []goldenReq{regA, regB}, goldenReq{http.MethodGet,
			"/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&service-names=nsmf-pdusession&supported-features=8", ""}},
		{"discover empty", "golden_nrf_discover_empty_200.txt", []goldenReq{regA, regB}, goldenReq{http.MethodGet,
			"/nnrf-disc/v1/nf-instances?target-nf-type=UPF&requester-nf-type=SMF", ""}},
		{"discover missing", "golden_nrf_discover_400.txt", nil, goldenReq{http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF", ""}},
		{"discover bad supported-features", "golden_nrf_discover_badsf_400.txt", nil, goldenReq{http.MethodGet,
			"/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&service-names=nsmf-pdusession&supported-features=zz", ""}},
		{"subscribe", "golden_nrf_subscribe_201.txt", nil, goldenReq{http.MethodPost, "/nnrf-nfm/v1/subscriptions",
			`{"nfStatusNotificationUri":"http://amf.5gc/cb","reqNfType":"AMF"}`}},
		{"subscribe no uri", "golden_nrf_subscribe_400.txt", nil, goldenReq{http.MethodPost, "/nnrf-nfm/v1/subscriptions", `{"reqNfType":"AMF"}`}},
		{"subscribe malformed", "golden_nrf_subscribe_malformed_400.txt", nil, goldenReq{http.MethodPost, "/nnrf-nfm/v1/subscriptions", `{`}},
		{"discover map", "golden_nrf_discover_map_200.txt", []goldenReq{regA, regB}, goldenReq{http.MethodGet,
			"/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF&service-names=nudm-sdm", ""}},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			s := newTestServer(t)
			if prof != nil {
				s.SetProfile(prof)
			}
			for _, pre := range st.setup {
				if rec := do(t, s, pre.method, pre.path, pre.body); rec.Code != http.StatusCreated {
					t.Fatalf("setup %s %s: %d %s", pre.method, pre.path, rec.Code, rec.Body)
				}
			}
			checkGolden(t, st.golden, render(do(t, s, st.method, st.path, st.body)))
		})
	}
}
