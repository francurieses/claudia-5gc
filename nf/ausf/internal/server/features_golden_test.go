package server

// features_golden_test.go - byte-identity goldens for the AUSF SBI wire output
// (REL19-2.7 slice 2). They were captured against the pre-change code (git
// worktree at HEAD) and must keep passing UNCHANGED under the rel17 /
// no-profile configuration (decisions D1/D2, dev/REL19_PROGRAM.md section 2).
// Only the random authCtxId UUID is normalised.

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/aka"
)

const goldenAuthCtxID = "<AUTHCTXID>"

var uuidRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// fixedUDM returns a deterministic 5G-AKA HE AV so the 201 body is stable.
type fixedUDM struct{ lastReq *UDMAuthDataRequest }

func (m *fixedUDM) GenerateAuthData(_ context.Context, supi string, req *UDMAuthDataRequest) (*UDMAuthDataResponse, error) {
	m.lastReq = req
	return &UDMAuthDataResponse{
		AuthType:  "5G_AKA",
		Rand:      "00112233445566778899aabbccddeeff",
		Autn:      "ffeeddccbbaa99887766554433221100",
		XresStar:  "0f0e0d0c0b0a09080706050403020100",
		HxresStar: "000102030405060708090a0b0c0d0e0f",
		Kausf:     "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
		Supi:      "imsi-001010000000001",
	}, nil
}

// checkGolden compares got with testdata/<name>. UPDATE_GOLDEN=1 rewrites the
// file instead; it is only ever used on the pre-change tree (git worktree at
// HEAD) to capture the legacy bytes.
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

// initAuthSnapshot renders status, Location, Content-Type and body of the
// POST /ue-authentications response with the UUID normalised.
func initAuthSnapshot(t *testing.T, srv *Server, body string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/nausf-auth/v1/ue-authentications", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	return "status: " + http.StatusText(resp.StatusCode) + "\n" +
		"Location: " + resp.Header.Get("Location") + "\n" +
		"Content-Type: " + resp.Header.Get("Content-Type") + "\n\n" + string(raw)
}

func newGoldenAuthServer(t *testing.T, udm UDMClient) *Server {
	t.Helper()
	srv, err := New(Config{NFInstanceID: "11111111-2222-3333-4444-555555555555", ServingNetworkName: "5G:mnc001.mcc001.3gppnetwork.org"},
		udm, aka.NewStore(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func TestGolden_InitAuth201(t *testing.T) {
	const reqBody = `{"supiOrSuci":"suci-0-001-01-0000-0-0-0000000001","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}`
	// A consumer that sent supportedFeatures got the same answer before REL19-2.7
	// (the attribute was ignored); UEAuthenticationCtx has no supportedFeatures.
	const reqBodySF = `{"supiOrSuci":"suci-0-001-01-0000-0-0-0000000001","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org","supportedFeatures":"3"}`
	for name, body := range map[string]string{"without": reqBody, "with_supportedFeatures": reqBodySF} {
		t.Run(name, func(t *testing.T) {
			srv := newGoldenAuthServer(t, &fixedUDM{})
			got := uuidRE.ReplaceAllString(initAuthSnapshot(t, srv, body), goldenAuthCtxID)
			checkGolden(t, "golden_init_auth_201.txt", got)
		})
	}
}
