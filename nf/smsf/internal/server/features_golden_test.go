package server_test

// features_golden_test.go - byte-identity golden for the SMSF Nsmsf_SMService
// Activate answer (REL19-2.7 slice 3). Captured against the pre-change code
// (git worktree at HEAD); it must pass UNCHANGED under rel17 / no profile for
// a request WITHOUT supportedFeatures (decision D1, dev/REL19_PROGRAM.md
// section 2).

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/smsf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/smsf/internal/server"
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

func TestGolden_Activate(t *testing.T) {
	cfg := &config.Config{}
	cfg.NFInstanceID = "test-smsf-001"
	cfg.SBI.Address = "127.0.0.1:0"
	h := server.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()

	const body = `{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS","amfId":"amf-001","amfCallbackUri":"https://amf:8001/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"}`
	r := httptest.NewRequest(http.MethodPut, "/nsmsf-sms/v2/ue-contexts/imsi-001010000000001", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	checkGolden(t, "golden_activate_201.txt",
		"status: "+http.StatusText(resp.StatusCode)+"\n"+
			"Content-Type: "+resp.Header.Get("Content-Type")+"\n"+
			"Location: "+resp.Header.Get("Location")+"\n\n"+string(raw))
}
