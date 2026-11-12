package server

// features_golden_test.go - byte-identity goldens for the UDM
// Nudm_UEAuthentication generate-auth-data answer (REL19-2.7 slice 2).
// Captured against the pre-change code (git worktree at HEAD); they must pass
// UNCHANGED under rel17 / no profile for a request WITHOUT supportedFeatures
// (decision D1, dev/REL19_PROGRAM.md section 2). Only the random AV values
// (RAND-derived hex strings) are normalised; keys, order and SUPI compare
// byte-for-byte.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// goldenUDR is a deterministic UDR returning fixed credentials.
type goldenUDR struct{ method string }

func (u goldenUDR) GetAuthSubscription(_ context.Context, _ string) (*UDRAuthSub, error) {
	return &UDRAuthSub{
		AuthMethod: u.method,
		K:          "465b5ce8b199b49faa5f0a2ee238a6bc",
		OPc:        "e8ed289deba952e4283b54e88e6183ca",
		AMF:        "8000",
		SQN:        "000000000021",
		AlgID:      "milenage",
	}, nil
}
func (goldenUDR) UpdateSQN(context.Context, string, string) error { return nil }
func (goldenUDR) GetAMData(context.Context, string) (*UDRAMData, error) {
	return &UDRAMData{}, nil
}
func (goldenUDR) GetSMData(context.Context, string) (json.RawMessage, error) { return nil, nil }

// avHexRE matches the random AV fields; their values are replaced by <HEX>.
var avHexRE = regexp.MustCompile(`"(rand|autn|xresStar|hxresStar|kausf|xres|ckPrime|ikPrime)":"[0-9a-f]+"`)

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

func newGoldenUDM(t *testing.T, method string) *Server {
	t.Helper()
	s, err := New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org", TLSConfig{}, goldenUDR{method: method},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// generateAuthDataSnapshot posts body and renders status, content type and the
// normalised answer.
func generateAuthDataSnapshot(t *testing.T, s *Server, body string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost,
		"/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	return "status: " + http.StatusText(resp.StatusCode) + "\n" +
		"Content-Type: " + resp.Header.Get("Content-Type") + "\n\n" +
		avHexRE.ReplaceAllString(string(raw), `"$1":"<HEX>"`)
}

func TestGolden_GenerateAuthData(t *testing.T) {
	const body = `{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org","ausfInstanceId":"11111111-2222-3333-4444-555555555555"}`
	tests := []struct{ name, method, golden string }{
		{"5g_aka", "5G_AKA", "golden_generate_auth_data_5gaka.txt"},
		{"eap_aka_prime", "EAP_AKA_PRIME", "golden_generate_auth_data_eap.txt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkGolden(t, tc.golden, generateAuthDataSnapshot(t, newGoldenUDM(t, tc.method), body))
		})
	}
}
