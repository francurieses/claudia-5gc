package server_test

// features_golden_test.go - byte-identity goldens for the BSF Nbsf_Management
// Register / Discovery answers (REL19-2.7 slice 3). Captured against the
// pre-change code (git worktree at HEAD); they must pass UNCHANGED under rel17
// / no profile for a request WITHOUT suppFeat (decision D1,
// dev/REL19_PROGRAM.md section 2). Only the minted bindingId (UUID) is
// normalised; keys, order and every other byte compare as-is.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/bsf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/bsf/internal/server"
)

var uuidRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

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

func newGoldenHandler(t *testing.T) http.Handler {
	t.Helper()
	cfg := &config.Config{}
	cfg.NFInstanceID = "test-bsf-001"
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.SBI.FQDN = "bsf.test.local"
	return server.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
}

// snapshot renders status, Content-Type, Location and the body with UUIDs
// replaced by <UUID>.
func snapshot(resp *http.Response) string {
	raw, _ := io.ReadAll(resp.Body)
	return "status: " + http.StatusText(resp.StatusCode) + "\n" +
		"Content-Type: " + resp.Header.Get("Content-Type") + "\n" +
		"Location: " + uuidRE.ReplaceAllString(resp.Header.Get("Location"), "<UUID>") + "\n\n" +
		uuidRE.ReplaceAllString(string(raw), "<UUID>")
}

func do(t *testing.T, h http.Handler, method, target string, body any) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, target, rd)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

func goldenBinding() map[string]any {
	return map[string]any{
		"supi":     "imsi-001010000000001",
		"ipv4Addr": "10.60.0.1",
		"dnn":      "internet",
		"snssai":   map[string]any{"sst": 1, "sd": "000001"},
		"pcfFqdn":  "pcf.5gc.mnc001.mcc001.3gppnetwork.org",
		"pcfId":    "11111111-2222-3333-4444-555555555555",
	}
}

func TestGolden_RegisterAndDiscover(t *testing.T) {
	h := newGoldenHandler(t)
	checkGolden(t, "golden_register_201.txt",
		snapshot(do(t, h, http.MethodPost, "/nbsf-management/v1/pcfBindings", goldenBinding())))
	checkGolden(t, "golden_discover_200.txt",
		snapshot(do(t, h, http.MethodGet, "/nbsf-management/v1/pcfBindings?ipv4Addr=10.60.0.1", nil)))
}
