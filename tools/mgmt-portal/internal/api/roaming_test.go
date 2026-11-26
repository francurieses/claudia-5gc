package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
)

func view(local string, partners ...N32Partner) *N32View {
	return &N32View{LocalPLMN: local, Partners: partners}
}

func TestLinkState(t *testing.T) {
	est := func(p string) N32Partner { return N32Partner{PLMN: p, State: "ESTABLISHED"} }
	none := func(p string) N32Partner { return N32Partner{PLMN: p, State: "NONE"} }
	v := func(p N32Partner) RoamingSEPP { return RoamingSEPP{Side: sideLocal, N32: view("001/001", p)} }
	h := func(p N32Partner) RoamingSEPP { return RoamingSEPP{Side: sidePartner, N32: view("001/002", p)} }
	for _, tc := range []struct {
		name     string
		deployed bool
		sepps    []RoamingSEPP
		want     string
	}{
		{"not deployed", false, []RoamingSEPP{v(none("001/002"))}, linkNotDeployed},
		{"both established", true, []RoamingSEPP{v(est("001/002")), h(est("001/001"))}, linkUp},
		{"one side", true, []RoamingSEPP{v(est("001/002")), h(none("001/001"))}, linkDegraded},
		{"none", true, []RoamingSEPP{v(none("001/002")), h(none("001/001"))}, linkDown},
		{"hsepp unreachable", true, []RoamingSEPP{v(est("001/002")), {Side: sidePartner, Error: "x"}}, linkDown},
	} {
		got := linkState(tc.deployed, tc.sepps)
		if got.State != tc.want {
			t.Errorf("%s: state %s, want %s (%s)", tc.name, got.State, tc.want, got.Reason)
		}
	}
}

func TestParseErrorLines(t *testing.T) {
	text := `{"time":"2026-11-23T10:00:00Z","level":"INFO","msg":"ok"}
not json
{"time":"2026-11-23T10:00:01Z","level":"WARN","msg":"n32 initiator exchange failed","procedure":"N32cExchangeCapability","cause":"dial tcp"}
{"time":"2026-11-23T10:00:02Z","level":"ERROR","msg":"boom"}`
	got := parseErrorLines("sepp", text)
	if len(got) != 2 || got[0].Level != "warn" || got[0].Cause != "dial tcp" || got[1].Level != "error" || got[0].Container != "sepp" {
		t.Fatalf("got %+v", got)
	}
}

func TestSideOf(t *testing.T) {
	for name, want := range map[string]string{"hsepp": sidePartner, "hnrf": sidePartner, "sepp": sideLocal, "amf": sideLocal} {
		if got := sideOf(name); got != want {
			t.Errorf("sideOf(%s)=%s want %s", name, got, want)
		}
	}
}

func TestRoamingN32ActionValidation(t *testing.T) {
	h := NewRouter(Deps{}, http.Dir("."))
	for _, tc := range []struct{ path string }{
		{"/api/v1/roaming/sepp/amf/n32/001-02/handshake"},
		{"/api/v1/roaming/sepp/sepp/n32/1-2/handshake"},
		{"/api/v1/roaming/sepp/sepp/n32/001-02/reboot"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, tc.path, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", tc.path, w.Code)
		}
	}
}

func TestRoamingLifecycleValidation(t *testing.T) {
	h := NewRouter(Deps{}, http.Dir("."))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/roaming/destroy", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad action = %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/roaming/start", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no docker = %d", w.Code)
	}
}

// Without Docker the status still answers, reports NOT_DEPLOYED and the deploy hint.
func TestRoamingStatusWithoutDocker(t *testing.T) {
	h := NewRouter(Deps{}, http.Dir("."))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/roaming/status", nil))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var st RoamingStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Deployed || st.Link.State != linkNotDeployed || !strings.Contains(st.DeployHint, "--profile roaming") ||
		len(st.NFs) != len(roamingTopology) || st.Traffic.Available {
		t.Fatalf("status %+v", st)
	}
}

func TestHealthFromStatus(t *testing.T) {
	for in, want := range map[string]string{
		"Up 5 minutes (healthy)":         "healthy",
		"Up 1 second (health: starting)": "starting",
		"Up 2 hours (unhealthy)":         "unhealthy",
		"Exited (0) 3 minutes ago":       "",
	} {
		if got := dockerclient.HealthFromStatus(in); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}
