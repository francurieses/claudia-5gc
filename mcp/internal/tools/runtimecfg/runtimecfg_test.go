package runtimecfg

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// portalStub records every call as "METHOD path" with its body, and answers the
// service list with the names in services.
type portalStub struct {
	mu       sync.Mutex
	calls    []string
	bodies   []string
	services []string
	reply    map[string]int
}

func (p *portalStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	p.mu.Lock()
	key := r.Method + " " + r.URL.Path
	p.calls = append(p.calls, key)
	p.bodies = append(p.bodies, string(b))
	status, ok := p.reply[key]
	p.mu.Unlock()
	if r.URL.Path == "/api/v1/services" {
		var parts []string
		for _, s := range p.services {
			parts = append(parts, `{"name":"`+s+`"}`)
		}
		_, _ = w.Write([]byte("[" + strings.Join(parts, ",") + "]"))
		return
	}
	if !ok {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (p *portalStub) saw(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.calls {
		if c == key {
			return true
		}
	}
	return false
}

func setup(t *testing.T, allowService bool, services ...string) (map[string]registry.Tool, *portalStub, *guard.Guard) {
	t.Helper()
	stub := &portalStub{services: services, reply: map[string]int{}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	g := guard.New(guard.Options{Mode: guard.ModeLab}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	tools := map[string]registry.Tool{}
	for _, tl := range All(Deps{Portal: clients.NewPortal(srv.URL, http.DefaultClient), Guard: g,
		AllowServiceControl: allowService}) {
		tools[tl.Name()] = tl
	}
	return tools, stub, g
}

func code(t *testing.T, err error) int {
	t.Helper()
	var e *mcperr.Error
	if !errors.As(err, &e) {
		t.Fatalf("want *mcperr.Error, got %T %v", err, err)
	}
	return e.Code
}

func ctx() context.Context { return guard.WithRole(context.Background(), guard.RoleAdmin) }

func TestSliceAMBRRiskDependsOnApply(t *testing.T) {
	tools, _, _ := setup(t, false)
	tl := tools["slice_session_ambr_set"].(registry.ArgRisker)
	if got := tl.RiskFor(json.RawMessage(`{"sst":1}`)); got != registry.Mutating {
		t.Errorf("stored change: %s, want MUTATING", got)
	}
	if got := tl.RiskFor(json.RawMessage(`{"apply_to_active":true}`)); got != registry.Disruptive {
		t.Errorf("apply_to_active: %s, want DISRUPTIVE", got)
	}
}

func TestSliceAMBRRejectsBadBitRate(t *testing.T) {
	tools, _, _ := setup(t, false)
	for _, rate := range []string{"100", "100 mbps", "1.5 Mbps", "-1 Mbps", "100Mbps"} {
		args := `{"sst":1,"sd":"000001","dnn":"internet","uplink":"` + rate + `","downlink":"100 Mbps"}`
		if _, err := tools["slice_session_ambr_set"].Invoke(ctx(), json.RawMessage(args)); code(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("uplink %q: want -32602", rate)
		}
	}
}

func TestSliceAMBRSetsThenAppliesToActive(t *testing.T) {
	tools, stub, g := setup(t, false)
	args := json.RawMessage(`{"sst":1,"sd":"000001","dnn":"internet","uplink":"50 Mbps","downlink":"200 Mbps","apply_to_active":true,"confirm":true}`)
	d := g.Check(ctx(), tools["slice_session_ambr_set"], args)
	if d.Verdict != guard.Proceed {
		t.Fatalf("confirmed apply must proceed: %v %v", d.Verdict, d.Err)
	}
	if _, err := tools["slice_session_ambr_set"].Invoke(ctx(), args); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !stub.saw("PUT /api/v1/slices/qos/1/000001/internet") || !stub.saw("POST /api/v1/slices/qos/1/000001/internet/apply") {
		t.Errorf("calls: %v", stub.calls)
	}
	if !strings.Contains(stub.bodies[0], `"downlink":"200 Mbps"`) {
		t.Errorf("body: %s", stub.bodies[0])
	}
}

func TestSliceAMBRRevertUsesDELETE(t *testing.T) {
	tools, stub, _ := setup(t, false)
	if _, err := tools["slice_session_ambr_set"].Invoke(ctx(), json.RawMessage(
		`{"sst":1,"sd":"000001","dnn":"internet","revert":true}`)); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if !stub.saw("DELETE /api/v1/slices/qos/1/000001/internet") {
		t.Errorf("revert must DELETE: %v", stub.calls)
	}
}

func TestRFSPRange(t *testing.T) {
	tools, _, _ := setup(t, false)
	for _, args := range []string{`{"supi":"imsi-001010000000001","rfsp":0}`, `{"supi":"imsi-001010000000001","rfsp":257}`} {
		if _, err := tools["rfsp_override_set"].Invoke(ctx(), json.RawMessage(args)); code(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("%s: want -32602", args)
		}
	}
}

func TestRFSPDryRunSaysUEIsDeregistered(t *testing.T) {
	tools, stub, g := setup(t, false)
	d := g.Check(ctx(), tools["rfsp_override_set"], json.RawMessage(`{"supi":"imsi-001010000000001","rfsp":5}`))
	if d.Verdict != guard.DryRun {
		t.Fatalf("verdict: %v", d.Verdict)
	}
	raw, _ := json.Marshal(d.Result)
	if !strings.Contains(string(raw), "deregistered") {
		t.Errorf("dry-run must say the UE is deregistered: %s", raw)
	}
	if len(stub.calls) != 1 || stub.calls[0] != "GET /api/v1/subscribers/imsi-001010000000001/rfsp" {
		t.Errorf("dry-run may only read: %v", stub.calls)
	}
}

func TestServiceControlRefusedWithoutAllowFlag(t *testing.T) {
	tools, _, _ := setup(t, false, "smf")
	_, err := tools["nf_service_control"].Invoke(ctx(), json.RawMessage(`{"name":"smf","action":"restart"}`))
	if err == nil || !strings.Contains(err.Error(), "allow_service_control") {
		t.Errorf("must be refused without allow_service_control: %v", err)
	}
}

func TestServiceControlProtectedNeedsForce(t *testing.T) {
	tools, _, _ := setup(t, true, "nrf", "smf")
	_, err := tools["nf_service_control"].Invoke(ctx(), json.RawMessage(`{"name":"nrf","action":"stop"}`))
	if err == nil || !strings.Contains(err.Error(), "force:true") {
		t.Errorf("stopping nrf without force must be refused: %v", err)
	}
}

func TestServiceControlUnknownNameRefused(t *testing.T) {
	tools, _, _ := setup(t, true, "smf")
	_, err := tools["nf_service_control"].Invoke(ctx(), json.RawMessage(`{"name":"ghost","action":"start"}`))
	if err == nil || !strings.Contains(err.Error(), "not a service the portal lists") {
		t.Errorf("unknown service must be refused: %v", err)
	}
}

func TestServiceControlRestartsListedService(t *testing.T) {
	tools, stub, _ := setup(t, true, "smf")
	if _, err := tools["nf_service_control"].Invoke(ctx(), json.RawMessage(`{"name":"smf","action":"restart"}`)); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !stub.saw("POST /api/v1/services/smf/restart") {
		t.Errorf("restart not sent: %v", stub.calls)
	}
}

func TestServiceControlIsAdmin(t *testing.T) {
	tools, _, _ := setup(t, true)
	if tools["nf_service_control"].Risk() != registry.Admin {
		t.Errorf("risk %s, want ADMIN", tools["nf_service_control"].Risk())
	}
}

func TestAuditLogReadsGuardRing(t *testing.T) {
	tools, _, g := setup(t, false)
	g.Audit().Add(guard.Entry{Tool: "ue_page", Outcome: "executed"})
	out, err := tools["mcp_audit_log"].Invoke(ctx(), json.RawMessage(`{"n":5}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	entries := out.(map[string]any)["entries"].([]guard.Entry)
	if len(entries) != 1 || entries[0].Tool != "ue_page" {
		t.Errorf("entries: %+v", entries)
	}
	if _, err := tools["mcp_audit_log"].Invoke(ctx(), json.RawMessage(`{"n":300}`)); code(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("n above 256 must be refused")
	}
}

func TestURSPTemplateIDRejectsPathCharacters(t *testing.T) {
	tools, _, _ := setup(t, false)
	if _, err := tools["ursp_template_apply"].Invoke(ctx(), json.RawMessage(`{"template_id":"a/b","supi":"imsi-001010000000001"}`)); code(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("slash in template id must be refused")
	}
}

func TestURSPTemplateRefusesWhenStoreDown(t *testing.T) {
	for _, health := range []struct{ name, body string }{
		{"store down", `{"status":"ok","store":"down"}`},
	} {
		t.Run(health.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/health" {
					_, _ = w.Write([]byte(health.body))
					return
				}
				t.Errorf("no store route may be called: %s %s", r.Method, r.URL.Path)
			}))
			defer srv.Close()
			g := guard.New(guard.Options{Mode: guard.ModeLab}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			var tl registry.Tool
			for _, c := range All(Deps{Portal: clients.NewPortal(srv.URL, http.DefaultClient), Guard: g}) {
				if c.Name() == "ursp_template_apply" {
					tl = c
				}
			}
			args := json.RawMessage(`{"template_id":"t1","supi":"imsi-001010000000001"}`)
			_, perr := tl.(registry.Planner).Plan(ctx(), args)
			var me *mcperr.Error
			if !errors.As(perr, &me) || me.Message != "PORTAL_STORE_UNAVAILABLE" {
				t.Fatalf("plan: %v", perr)
			}
			_, ierr := tl.Invoke(ctx(), args)
			if !errors.As(ierr, &me) || me.Message != "PORTAL_STORE_UNAVAILABLE" {
				t.Fatalf("invoke: %v", ierr)
			}
		})
	}
}

func TestURSPTemplatePlan503IsStoreUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	g := guard.New(guard.Options{Mode: guard.ModeLab}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, c := range All(Deps{Portal: clients.NewPortal(srv.URL, http.DefaultClient), Guard: g}) {
		if c.Name() != "ursp_template_apply" {
			continue
		}
		_, err := c.(registry.Planner).Plan(ctx(), json.RawMessage(`{"template_id":"t1","supi":"imsi-001010000000001"}`))
		var me *mcperr.Error
		if !errors.As(err, &me) || me.Message != "PORTAL_STORE_UNAVAILABLE" {
			t.Fatalf("plan: %v", err)
		}
	}
}
