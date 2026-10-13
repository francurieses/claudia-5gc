package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func status(t *testing.T, srv *http.Server, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func textHandler(s string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(s)) })
}

func TestMetricsServerWithAdminRoutes(t *testing.T) {
	logLevel := textHandler("loglevel")
	srv := MetricsServerWithAdmin(":0", logLevel,
		AdminRoute{Pattern: "/admin/v1/n4-sessions", Handler: textHandler("n4-first")},
		AdminRoute{Pattern: "/admin/v1/n4-sessions", Handler: textHandler("n4-dup")},
		AdminRoute{Pattern: "/admin/v1/log-level", Handler: textHandler("shadow")},
		AdminRoute{Pattern: "/internal/x", Handler: textHandler("outside")},
		AdminRoute{Pattern: "/admin/v1/nilh", Handler: nil},
		AdminRoute{Pattern: "/admin/{bad", Handler: textHandler("bad")},
	)
	cases := []struct {
		path string
		code int
		body string
	}{
		{"/admin/v1/n4-sessions", 200, "n4-first"},
		{"/admin/v1/log-level", 200, "loglevel"},
		{"/internal/x", 404, ""},
		{"/admin/v1/nilh", 404, ""},
		{"/metrics", 200, ""},
		{"/healthz", 200, `{"status":"UP"}`},
	}
	for _, c := range cases {
		code, body := status(t, srv, c.path)
		if code != c.code || (c.body != "" && body != c.body) {
			t.Errorf("%s: got %d %q want %d %q", c.path, code, body, c.code, c.body)
		}
	}
}

func TestMetricsServerWithAdminNoRoutes(t *testing.T) {
	srv := MetricsServerWithAdmin(":0", nil)
	if code, _ := status(t, srv, "/admin/v1/log-level"); code != 404 {
		t.Fatalf("log-level without handler: %d", code)
	}
	if code, _ := status(t, MetricsServer(":0"), "/healthz"); code != 200 {
		t.Fatalf("healthz: %d", code)
	}
}
