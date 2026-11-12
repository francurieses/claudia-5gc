package server

// features_golden_test.go - byte-identity golden for the NSSF Nnssf_NSSelection
// answer (REL19-2.7 slice 3). Captured against the pre-change code (git
// worktree at HEAD); it must pass UNCHANGED under rel17 / no profile for a
// request WITHOUT supported-features (decision D1, dev/REL19_PROGRAM.md
// section 2).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
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

func TestGolden_NSSelection(t *testing.T) {
	s := newTestServer()
	for _, tc := range []struct {
		name, golden string
		q            url.Values
	}{
		{"no_requested", "golden_nsselection_all_200.txt", url.Values{"nf-type": {"AMF"}, "nf-id": {"amf-001"}}},
		{"requested_hit", "golden_nsselection_requested_200.txt", url.Values{"nf-type": {"AMF"}, "nf-id": {"amf-001"},
			"slice-info-request-for-registration.requestedNssai": {`[{"sst":1,"sd":"000001"},{"sst":9}]`}}},
		{"missing_params", "golden_nsselection_400.txt", url.Values{"nf-type": {"AMF"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/nnssf-nsselection/v2/network-slice-information?"+tc.q.Encode(), nil)
			w := httptest.NewRecorder()
			s.handleNSSelection(w, r)
			resp := w.Result()
			raw, _ := io.ReadAll(resp.Body)
			checkGolden(t, tc.golden, "status: "+http.StatusText(resp.StatusCode)+"\n"+
				"Content-Type: "+resp.Header.Get("Content-Type")+"\n\n"+string(raw))
		})
	}
}
