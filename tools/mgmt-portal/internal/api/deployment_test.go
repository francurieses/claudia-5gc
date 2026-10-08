package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/deployment"
	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
)

type stubLister struct{ svcs []dockerclient.Service }

func (s stubLister) List(context.Context) ([]dockerclient.Service, error) { return s.svcs, nil }

// emptyFS is an empty static root for routers whose SPA shell is irrelevant.
func emptyFS(t *testing.T) fs.FS {
	t.Helper()
	return os.DirFS(t.TempDir())
}

func routerWithDeployment(t *testing.T, svcs ...dockerclient.Service) http.Handler {
	t.Helper()
	det := deployment.NewDetector(stubLister{svcs: svcs}, "")
	return NewRouter(Deps{Deployment: det}, http.FS(emptyFS(t)))
}

func postJSON(h http.Handler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDeployment_Endpoint(t *testing.T) {
	h := routerWithDeployment(t, dockerclient.Service{Name: "ueransim-gnb", State: "running"})
	rec := do(t, h, http.MethodGet, "/api/v1/deployment", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var c deployment.Capabilities
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if c.Mode != deployment.ModeUERANSIM || !c.UERANSIM.Deployed || c.PacketRusher.Deployed {
		t.Errorf("caps = %+v", c)
	}
}

func TestDeployment_EndpointWithoutDetector(t *testing.T) {
	rec := do(t, newFakeRouter(t), http.MethodGet, "/api/v1/deployment", "")
	var c deployment.Capabilities
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Code != http.StatusOK || c.Mode != deployment.ModeStandalone || c.Source != deployment.SourceUnavailable {
		t.Errorf("status=%d caps=%+v", rec.Code, c)
	}
}

func TestRequireRANTool_Standalone409(t *testing.T) {
	h := routerWithDeployment(t)
	cases := map[string]string{
		"/api/v1/ueransim/nr-cli":                "ueransim",
		"/api/v1/ueransim/ping":                  "ueransim",
		"/api/v1/ueransim/scenarios/multi/start": "ueransim",
		"/api/v1/qos/nw-sessions":                "ueransim",
		"/api/v1/packetrusher/xn/start":          "packetrusher",
		"/api/v1/packetrusher/n2/stop":           "packetrusher",
	}
	for path, tool := range cases {
		rec := postJSON(h, path)
		if rec.Code != http.StatusConflict {
			t.Errorf("POST %s: status = %d, want 409", path, rec.Code)
			continue
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("POST %s: body not JSON: %v", path, err)
			continue
		}
		if body["code"] != "RAN_TOOL_NOT_DEPLOYED" || body["tool"] != tool || body["hint"] != "make up RAN="+tool {
			t.Errorf("POST %s: body = %v", path, body)
		}
	}
}

func TestRequireRANTool_StatusGETsStayAvailable(t *testing.T) {
	h := routerWithDeployment(t)
	for _, path := range []string{"/api/v1/ueransim/status", "/api/v1/packetrusher/status"} {
		if rec := do(t, h, http.MethodGet, path, ""); rec.Code == http.StatusConflict {
			t.Errorf("GET %s: got 409, status endpoints must stay available", path)
		}
	}
}

func TestRequireRANTool_DeployedPassesThrough(t *testing.T) {
	h := routerWithDeployment(t, dockerclient.Service{Name: "packetrusher", State: "created"})
	// packetrusher is deployed: the gate must not answer 409 for it.
	if rec := postJSON(h, "/api/v1/packetrusher/xn/pause"); rec.Code == http.StatusConflict {
		t.Errorf("deployed tool was blocked: %d %s", rec.Code, rec.Body.String())
	}
	// ueransim is not deployed: still blocked.
	if rec := postJSON(h, "/api/v1/ueransim/ping"); rec.Code != http.StatusConflict {
		t.Errorf("undeployed tool was not blocked: %d", rec.Code)
	}
}

func TestRequireRANTool_NoDetectorFailsOpen(t *testing.T) {
	rec := postJSON(newFakeRouter(t), "/api/v1/ueransim/ping")
	if rec.Code == http.StatusConflict {
		t.Errorf("no detector wired: got 409, want pass-through")
	}
}
