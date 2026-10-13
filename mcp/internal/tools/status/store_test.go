package status

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
)

// storePortal answers /health with health (empty = empty body, like an older portal)
// and the store routes with listStatus/listBody.
func storePortal(t *testing.T, health string, listStatus int, listBody string) Deps {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/health":
			_, _ = w.Write([]byte(health))
		case strings.HasPrefix(r.URL.Path, "/api/v1/subscribers") || strings.HasPrefix(r.URL.Path, "/api/v1/policy-templates"):
			w.WriteHeader(listStatus)
			_, _ = w.Write([]byte(listBody))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	t.Cleanup(srv.Close)
	return Deps{Portal: clients.NewPortal(srv.URL, http.DefaultClient)}
}

func wantStoreUnavailable(t *testing.T, out any, err error) {
	t.Helper()
	var me *mcperr.Error
	if !errors.As(err, &me) || me.Message != "PORTAL_STORE_UNAVAILABLE" || me.Code != mcperr.CodeToolError {
		t.Fatalf("want PORTAL_STORE_UNAVAILABLE tool error, got out=%v err=%v", out, err)
	}
	if me.Data["reason"] == nil || me.Data["hint"] == nil {
		t.Errorf("data: %v", me.Data)
	}
}

func TestSubscriberListStoreDown(t *testing.T) {
	tests := []struct {
		name       string
		health     string
		status     int
		body       string
		wantErr    bool
		wantResult string
	}{
		{"store down", `{"status":"ok","store":"down"}`, 200, `[]`, true, ""},
		{"store up", `{"status":"ok","store":"up"}`, 200, `[{"supi":"imsi-1"}]`, false, "imsi-1"},
		{"unknown (empty body) and 503", ``, 503, `database unavailable`, true, ""},
		{"unknown (no store field) and 200", `{"status":"ok"}`, 200, `[]`, false, "[]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := storePortal(t, tc.health, tc.status, tc.body)
			out, err := subscriberListTool{d}.Invoke(context.Background(), nil)
			if tc.wantErr {
				wantStoreUnavailable(t, out, err)
				return
			}
			if err != nil {
				t.Fatalf("invoke: %v", err)
			}
			raw, _ := json.Marshal(out)
			if !strings.Contains(string(raw), tc.wantResult) {
				t.Errorf("result %s", raw)
			}
		})
	}
}

func TestSubscriberGetStoreDown(t *testing.T) {
	d := storePortal(t, `{"status":"ok","store":"down"}`, 200, `{}`)
	out, err := subscriberGetTool{d}.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	wantStoreUnavailable(t, out, err)
	d = storePortal(t, ``, 503, `database unavailable`)
	out, err = subscriberGetTool{d}.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	wantStoreUnavailable(t, out, err)
}

func TestConfigViewStoreDownOnlyAffectsTemplates(t *testing.T) {
	d := storePortal(t, `{"status":"ok","store":"down"}`, 200, `[]`)
	out, err := configViewTool{d}.Invoke(context.Background(), nil)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	secs := out.(map[string]any)["sections"].(map[string]any)
	pt := secs["policy_templates"].(map[string]any)
	if pt["error"] != "PORTAL_STORE_UNAVAILABLE" || pt["value"] != nil {
		t.Errorf("policy_templates: %v", pt)
	}
	if secs["slices"].(map[string]any)["value"] == nil {
		t.Errorf("slices must stay readable: %v", secs["slices"])
	}
}

func TestCoreHealthReportsDependencies(t *testing.T) {
	d := coreFixture(t, true)
	dep := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer dep.Close()
	d.Probes = []Probe{{Name: "loki", URL: dep.URL + "/ready"}, {Name: "jaeger", URL: "http://127.0.0.1:1/"}}
	out, err := coreHealthTool{d}.Invoke(context.Background(), nil)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	deps := out.(map[string]any)["dependencies"].(map[string]any)
	if deps["loki"].(map[string]any)["reachable"] != true || deps["jaeger"].(map[string]any)["reachable"] != false {
		t.Errorf("dependencies: %v", deps)
	}
	if deps["portal"].(map[string]any)["store"] != "unknown" || deps["prometheus"].(map[string]any)["reachable"] != true {
		t.Errorf("dependencies: %v", deps)
	}
}
