package server

// features_golden_test.go - byte-identity goldens for the UDR responses
// (REL19-2.7 slice 5). Captured against the pre-change code (git worktree at
// HEAD); they must pass UNCHANGED under rel17 / no profile for requests that
// carry no supported-features / supp-feat / suppFeat (decision D1,
// dev/REL19_PROGRAM.md section 2).

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
	"github.com/francurieses/claudia-5gc/shared/capability"
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

// goldenSUPI is seeded with the dev K/OPc and one slice.
const goldenSUPI = "imsi-001010000000001"

// goldenServer builds a fresh UDR with one seeded subscriber. prof nil leaves
// the Server without a profile (the zero value behaves as rel17).
func goldenServer(t *testing.T, prof *capability.Profile) *httptest.Server {
	t.Helper()
	st := store.NewInMemory()
	if err := store.SeedTestSubscriberWithNSSAI(st, goldenSUPI,
		"465b5ce8b199b49faa5f0a2ee238a6bc", "cd63cb71954a9f4e48a5994e37a02baf", "b9b9", "000000000020",
		[]store.SNSSAISubscribed{{SST: 1, SD: "000001"}}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(":0", TLSConfig{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)).With("nf", "UDR"))
	if err != nil {
		t.Fatalf("New UDR: %v", err)
	}
	if prof != nil {
		srv.SetProfile(prof)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// renderResp serialises a response: status, content type and body.
func renderResp(t *testing.T, ts *httptest.Server, method, path, body string) string {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return "status: " + http.StatusText(resp.StatusCode) + "\nContent-Type: " + resp.Header.Get("Content-Type") + "\n\n" + string(raw)
}

// goldenReq is one request of a golden scenario.
type goldenReq struct{ method, path, body string }

// TestGolden_UDRResponses runs every step on its own fresh server (the setup
// requests seed whatever state the step needs), so any subtest can run alone
// (-run 'TestGolden_UDRResponses/ue_policy_get$') and in any order.
func TestGolden_UDRResponses(t *testing.T) { runUDRGoldens(t, nil) }

// TestGolden_UDRResponsesRel17Profile: the same goldens with an explicit rel17
// profile (decision D1: byte-identical to no profile and to the baseline).
func TestGolden_UDRResponsesRel17Profile(t *testing.T) {
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: "rel17"}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	runUDRGoldens(t, p)
}

func runUDRGoldens(t *testing.T, prof *capability.Profile) {
	sub := "/nudr-dr/v2/subscription-data/" + goldenSUPI
	pol := "/nudr-dr/v2/policy-data/" + goldenSUPI
	const unknown = "imsi-001019999999999"
	putUEPol := goldenReq{http.MethodPut, pol + "/ue-policy-set", `{"precedence":10,"rules":[]}`}
	putSMPol := goldenReq{http.MethodPut, pol + "/sm-data",
		`{"smPolicySnssaiData":{"1-000001":{"snssai":{"sst":1,"sd":"000001"},"smPolicyDnnData":{"internet":{"dnn":"internet","5qi":7}}}}}`}
	steps := []struct {
		name, golden string
		setup        []goldenReq
		goldenReq
	}{
		{"auth get", "golden_udr_auth_get_200.txt", nil, goldenReq{http.MethodGet, sub + "/authentication-data/authentication-subscription", ""}},
		{"auth get 404", "golden_udr_auth_get_404.txt", nil, goldenReq{http.MethodGet,
			"/nudr-dr/v2/subscription-data/" + unknown + "/authentication-data/authentication-subscription", ""}},
		{"auth patch", "golden_udr_auth_patch_204.txt", nil, goldenReq{http.MethodPatch, sub + "/authentication-data/authentication-subscription",
			`{"sequenceNumber":{"sqn":"000000000040"}}`}},
		{"auth patch malformed", "golden_udr_auth_patch_400.txt", nil, goldenReq{http.MethodPatch, sub + "/authentication-data/authentication-subscription", `{`}},
		{"am get", "golden_udr_am_get_200.txt", nil, goldenReq{http.MethodGet, sub + "/00101/provisioned-data/am-data", ""}},
		{"am get 404", "golden_udr_am_get_404.txt", nil, goldenReq{http.MethodGet,
			"/nudr-dr/v2/subscription-data/" + unknown + "/00101/provisioned-data/am-data", ""}},
		{"sm get", "golden_udr_sm_get_200.txt", nil, goldenReq{http.MethodGet, sub + "/00101/provisioned-data/sm-data", ""}},
		{"sm get 404", "golden_udr_sm_get_404.txt", nil, goldenReq{http.MethodGet,
			"/nudr-dr/v2/subscription-data/" + unknown + "/00101/provisioned-data/sm-data", ""}},
		{"amf ctx put", "golden_udr_amfctx_put_201.txt", nil, goldenReq{http.MethodPut, sub + "/context-data/amf-3gpp-access",
			`{"amfInstanceId":"11111111-2222-3333-4444-555555555555","deregCallbackUri":"http://amf/cb"}`}},
		{"amf ctx put empty", "golden_udr_amfctx_put_empty_201.txt", nil, goldenReq{http.MethodPut, sub + "/context-data/amf-3gpp-access", ""}},
		{"ue policy get 404", "golden_udr_uepol_get_404.txt", nil, goldenReq{http.MethodGet, pol + "/ue-policy-set", ""}},
		{"ue policy put", "golden_udr_uepol_put_204.txt", nil, putUEPol},
		{"ue policy put malformed", "golden_udr_uepol_put_400.txt", nil, goldenReq{http.MethodPut, pol + "/ue-policy-set", `{`}},
		{"ue policy get", "golden_udr_uepol_get_200.txt", []goldenReq{putUEPol}, goldenReq{http.MethodGet, pol + "/ue-policy-set", ""}},
		{"ue policy patch", "golden_udr_uepol_patch_204.txt", []goldenReq{putUEPol}, goldenReq{http.MethodPatch, pol + "/ue-policy-set", `{"precedence":5}`}},
		{"ue policy delete", "golden_udr_uepol_delete_204.txt", []goldenReq{putUEPol}, goldenReq{http.MethodDelete, pol + "/ue-policy-set", ""}},
		{"sm policy get 404", "golden_udr_smpol_get_404.txt", nil, goldenReq{http.MethodGet, pol + "/sm-data", ""}},
		{"sm policy put", "golden_udr_smpol_put_204.txt", nil, putSMPol},
		{"sm policy get", "golden_udr_smpol_get_200.txt", []goldenReq{putSMPol}, goldenReq{http.MethodGet, pol + "/sm-data", ""}},
		{"sm policy patch", "golden_udr_smpol_patch_204.txt", []goldenReq{putSMPol}, goldenReq{http.MethodPatch, pol + "/sm-data",
			`{"smPolicySnssaiData":{"2-000001":{"snssai":{"sst":2,"sd":"000001"},"smPolicyDnnData":{"ims":{"dnn":"ims","5qi":1}}}}}`}},
		{"default policies", "golden_udr_defpol_200.txt", nil, goldenReq{http.MethodGet, "/nudr-dr/v2/policy-data/default-policies", ""}},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			ts := goldenServer(t, prof)
			for _, pre := range st.setup {
				if got := renderResp(t, ts, pre.method, pre.path, pre.body); !strings.HasPrefix(got, "status: No Content") {
					t.Fatalf("setup %s %s: %s", pre.method, pre.path, got)
				}
			}
			checkGolden(t, st.golden, renderResp(t, ts, st.method, st.path, st.body))
		})
	}
}
