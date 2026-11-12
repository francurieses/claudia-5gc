package server

// nssaa_golden_test.go - byte-identity goldens for the legacy AUSF-hosted NSSAA
// relay answer (REL19-3.5 slice E). The legacy files were captured on the
// pre-change code (git worktree at HEAD) and must pass UNCHANGED in every
// profile. The 29.526 201 golden was written on the new code with the random
// authCtxId masked.
// Ref: TS 29.526 §5.2.2.2

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
)

func nssaaLegacySnapshot(t *testing.T, srv *Server, identity string) string {
	t.Helper()
	pkt := base64.StdEncoding.EncodeToString(eap.BuildIdentityResponse(7, identity))
	body := `{"supi":"imsi-001010000000003","gpsi":"msisdn-12025550100","snssai":{"sst":1,"sd":"000003"},"eapPayload":"` + pkt + `"}`
	r := httptest.NewRequest(http.MethodPost, "/nausf-nssaa/v1/imsi-001010000000003/authenticate", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	return "status: " + http.StatusText(resp.StatusCode) + "\nContent-Type: " +
		resp.Header.Get("Content-Type") + "\n\n" + string(raw)
}

func TestGolden_NSSAALegacy(t *testing.T) {
	for name, identity := range map[string]string{
		"success": "alice@nssaa.example.com",
		"reject":  "mallory@reject.example.com",
	} {
		t.Run(name, func(t *testing.T) {
			srv := newGoldenAuthServer(t, &fixedUDM{})
			checkGolden(t, "golden_nssaa_legacy_"+name+".txt", nssaaLegacySnapshot(t, srv, identity))
		})
	}
}

func TestGolden_SliceAuthCreate201(t *testing.T) {
	srv := newGoldenAuthServer(t, &fixedUDM{})
	r := httptest.NewRequest(http.MethodPost, "/nnssaaf-nssaa/v1/slice-authentications",
		bytes.NewBufferString(createBody("alice@nssaa.example.com")))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	got := "status: " + http.StatusText(resp.StatusCode) + "\nLocation: " + resp.Header.Get("Location") +
		"\nContent-Type: " + resp.Header.Get("Content-Type") + "\n\n" + string(raw)
	checkGolden(t, "golden_nssaa_slice_auth_201_rel19.txt", uuidRE.ReplaceAllString(got, goldenAuthCtxID))
}
