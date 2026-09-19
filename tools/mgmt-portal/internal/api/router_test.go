package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIndexHTML is the SPA shell served by the fallback; the marker is what the
// deep-link test looks for to prove index.html (not a file listing) came back.
const fakeIndexHTML = `<!doctype html><html><body><div id="root"></div></body></html>`

// browserAccept is what Chrome/Firefox send for a top-level navigation.
const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

// newFakeRouter builds a router over a temp filesystem containing index.html
// and one hashed asset, mirroring the embedded `static/` layout.
func newFakeRouter(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(fakeIndexHTML), 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatalf("mkdir assets: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app-abc123.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}
	return NewRouter(Deps{}, http.FS(os.DirFS(dir)))
}

// do issues a request against the router and returns the recorder.
func do(t *testing.T, h http.Handler, method, path, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestSPAFallback_DeepLink: a browser navigation to a client-side route that has
// no file on disk must return the SPA shell (PRD problem #1 — F5/deep links).
func TestSPAFallback_DeepLink(t *testing.T) {
	rec := do(t, newFakeRouter(t), http.MethodGet, "/qos", browserAccept)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /qos: want 200, got %d (body %q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET /qos: want text/html, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Errorf("GET /qos: body is not the SPA shell: %q", rec.Body.String())
	}
}

// TestSPAFallback_Root: the SPA root keeps working through the file server.
func TestSPAFallback_Root(t *testing.T) {
	rec := do(t, newFakeRouter(t), http.MethodGet, "/", browserAccept)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Errorf("GET /: body is not the SPA shell: %q", rec.Body.String())
	}
}

// TestSPAFallback_UnknownAPIIsJSON404: unknown API endpoints must stay a
// machine-readable 404 even when the caller sends an HTML Accept header.
func TestSPAFallback_UnknownAPIIsJSON404(t *testing.T) {
	rec := do(t, newFakeRouter(t), http.MethodGet, "/api/v1/unknown", browserAccept)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/v1/unknown: want 404, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("GET /api/v1/unknown: want application/json, got %q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET /api/v1/unknown: body is not JSON: %v (%q)", err, rec.Body.String())
	}
	if body["error"] == "" {
		t.Errorf("GET /api/v1/unknown: JSON 404 has no error field: %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `id="root"`) {
		t.Error("GET /api/v1/unknown: API 404 leaked the SPA shell")
	}
}

// TestSPAFallback_ReservedNamespacesNeverServeSPA covers the namespaces that
// must never receive the HTML fallback, whatever the Accept header says.
func TestSPAFallback_ReservedNamespacesNeverServeSPA(t *testing.T) {
	h := newFakeRouter(t)
	for _, path := range []string{"/api/v1/nope", "/api/nope", "/api", "/ws/bad", "/ws"} {
		rec := do(t, h, http.MethodGet, path, browserAccept)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: want 404, got %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("GET %s: want application/json, got %q", path, ct)
		}
		if strings.Contains(rec.Body.String(), `id="root"`) {
			t.Errorf("GET %s: reserved namespace served the SPA shell", path)
		}
	}
}

// TestSPAFallback_StaticAssetServed: a real hashed asset wins over the shell.
func TestSPAFallback_StaticAssetServed(t *testing.T) {
	rec := do(t, newFakeRouter(t), http.MethodGet, "/assets/app-abc123.js", "*/*")

	if rec.Code != http.StatusOK {
		t.Fatalf("GET asset: want 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET asset: served HTML for a JS file (%q)", ct)
	}
	if got := rec.Body.String(); got != "console.log(1)" {
		t.Errorf("GET asset: want asset bytes, got %q", got)
	}
}

// TestSPAFallback_NonHTMLClient404: a non-navigation client hitting an unknown
// client-side path gets a JSON 404, not the shell.
func TestSPAFallback_NonHTMLClient404(t *testing.T) {
	rec := do(t, newFakeRouter(t), http.MethodGet, "/qos", "application/json")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /qos (json accept): want 404, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("GET /qos (json accept): want application/json, got %q", ct)
	}
}

// TestSPAFallback_MissingIndexHTML: an unbuilt bundle must not emit an empty
// 200 for a deep link — it degrades to a JSON 404.
func TestSPAFallback_MissingIndexHTML(t *testing.T) {
	dir := t.TempDir() // no index.html
	h := NewRouter(Deps{}, http.FS(os.DirFS(dir)))

	rec := do(t, h, http.MethodGet, "/qos", browserAccept)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /qos without index.html: want 404, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("GET /qos without index.html: want application/json, got %q", ct)
	}
}

// TestAcceptsHTML documents the Accept parsing used by the fallback.
func TestAcceptsHTML(t *testing.T) {
	cases := []struct {
		accept string
		want   bool
	}{
		{"", false},
		{"application/json", false},
		{"text/html", true},
		{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", true},
		{"application/xhtml+xml", true},
		{"*/*", true},
		{"text/*", false},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/qos", nil)
		if tc.accept != "" {
			req.Header.Set("Accept", tc.accept)
		}
		if got := acceptsHTML(req); got != tc.want {
			t.Errorf("acceptsHTML(%q) = %v, want %v", tc.accept, got, tc.want)
		}
	}
}
