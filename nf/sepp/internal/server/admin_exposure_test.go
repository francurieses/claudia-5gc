package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
)

// PORTAL-UI-22 / SEPP-005: the unauthenticated N32 admin routes (contexts, partners) live on the metrics port
// only; neither the SBI nor the N32 listener may serve them.
func TestAdminRoutesNotOnSBIOrN32(t *testing.T) {
	t.Setenv(config.PartnersFileEnv, t.TempDir()+"/absent.yaml")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, slog.Default())
	for name, h := range map[string]http.Handler{"SBI": s.Handler(), "N32": s.N32Handler()} {
		for _, req := range []*http.Request{
			httptest.NewRequest(http.MethodGet, "/admin/v1/n32/contexts", nil),
			httptest.NewRequest(http.MethodPost, "/admin/v1/n32/contexts/001-02/handshake", nil),
		} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "local_plmn") || strings.Contains(w.Body.String(), `"partners"`) {
				t.Errorf("%s listener served %s %s (%d)", name, req.Method, req.URL.Path, w.Code)
			}
		}
	}
}
