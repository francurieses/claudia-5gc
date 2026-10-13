package guard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

type stub struct {
	name  string
	risk  registry.Risk
	calls int
}

func (s *stub) Name() string                  { return s.name }
func (s *stub) Description() string           { return "stub" }
func (s *stub) InputSchema() json.RawMessage  { return json.RawMessage(`{"type":"object"}`) }
func (s *stub) OutputSchema() json.RawMessage { return json.RawMessage(`{}`) }
func (s *stub) Risk() registry.Risk           { return s.risk }
func (s *stub) Invoke(context.Context, json.RawMessage) (any, error) {
	s.calls++
	return map[string]any{"ok": true}, nil
}

// planner adds a Plan method so the dry-run carries a tool-specific description.
type planner struct {
	stub
	plan any
	perr error
}

func (p *planner) Plan(context.Context, json.RawMessage) (any, error) {
	if p.perr != nil {
		return nil, p.perr
	}
	return p.plan, nil
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fixedClock returns a Guard whose clock the test controls.
func fixedClock(g *Guard) *time.Time {
	t := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return t }
	return &t
}

func ctxWith(r Role) context.Context { return WithRole(context.Background(), r) }

func TestParseModeAndRole(t *testing.T) {
	if _, err := ParseAccessMode("lab"); err != nil {
		t.Errorf("lab: %v", err)
	}
	if _, err := ParseAccessMode("root"); err == nil {
		t.Error("expected error for unknown access mode")
	}
	if _, err := ParseRole("admin"); err != nil {
		t.Errorf("admin: %v", err)
	}
	if _, err := ParseRole("god"); err == nil {
		t.Error("expected error for unknown role")
	}
}

func TestRoleFailsClosedToViewer(t *testing.T) {
	if got := RoleFrom(context.Background()); got != RoleViewer {
		t.Errorf("no role in ctx: got %q, want viewer", got)
	}
}

// TestModeRoleMatrix covers every access mode × role × risk combination for a
// confirmed call, which is the case that must run whenever both caps allow it.
func TestModeRoleMatrix(t *testing.T) {
	modes := []AccessMode{ModeReadOnly, ModeOperator, ModeLab}
	roles := []Role{RoleViewer, RoleOperator, RoleAdmin}
	risks := []registry.Risk{registry.ReadOnly, registry.Mutating, registry.Disruptive, registry.Admin}
	confirmed := json.RawMessage(`{"confirm":true}`)

	for _, m := range modes {
		for _, r := range roles {
			for _, k := range risks {
				g := New(Options{Mode: m, MinInterval: time.Nanosecond}, quiet())
				fixedClock(g)
				tool := &stub{name: "t", risk: k}
				d := g.Check(ctxWith(r), tool, confirmed)

				wantRun := k <= m.Ceiling() && k <= r.Max()
				gotRun := d.Verdict == Proceed
				if gotRun != wantRun {
					t.Errorf("mode=%s role=%s risk=%s: proceed=%v, want %v (err=%v)",
						m, r, k, gotRun, wantRun, d.Err)
				}
			}
		}
	}
}

func TestDisruptiveWithoutConfirmIsDryRun(t *testing.T) {
	g := New(Options{Mode: ModeOperator}, quiet())
	fixedClock(g)
	tool := &planner{stub: stub{name: "ue_deregister_nw", risk: registry.Disruptive},
		plan: map[string]any{"supi": "imsi-001010000000001"}}
	d := g.Check(ctxWith(RoleOperator), tool, json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	if d.Verdict != DryRun {
		t.Fatalf("verdict: got %v, want DryRun", d.Verdict)
	}
	m, ok := d.Result.(map[string]any)
	if !ok || m["dry_run"] != true {
		t.Fatalf("result lacks dry_run:true: %#v", d.Result)
	}
	if _, ok := m["plan"]; !ok {
		t.Error("planner output missing from dry-run")
	}
	if tool.calls != 0 {
		t.Errorf("dry-run must not invoke the tool, got %d calls", tool.calls)
	}
	if got := g.Audit().Recent(10); len(got) != 1 || got[0].Outcome != "dry_run" {
		t.Errorf("dry-run not audited: %+v", got)
	}
}

func TestPlannerErrorIsRefused(t *testing.T) {
	g := New(Options{Mode: ModeOperator}, quiet())
	tool := &planner{stub: stub{name: "x", risk: registry.Disruptive}, perr: errors.New("upstream down")}
	d := g.Check(ctxWith(RoleOperator), tool, json.RawMessage(`{}`))
	if d.Verdict != Refused || d.Err == nil {
		t.Fatalf("planner failure must refuse, got %v", d.Verdict)
	}
}

func TestViewerRefusedForDisruptiveWithExactMessage(t *testing.T) {
	g := New(Options{Mode: ModeOperator}, quiet())
	tool := &stub{name: "pdu_session_release_nw", risk: registry.Disruptive}
	d := g.Check(ctxWith(RoleViewer), tool, json.RawMessage(`{"confirm":true}`))
	if d.Verdict != Refused {
		t.Fatalf("verdict: got %v, want Refused", d.Verdict)
	}
	if d.Err.Code != -32000 {
		t.Errorf("code: got %d, want -32000", d.Err.Code)
	}
	if want := "role viewer may not call DISRUPTIVE tool pdu_session_release_nw"; d.Err.Message != want {
		t.Errorf("message: got %q, want %q", d.Err.Message, want)
	}
}

func TestReadOnlyNeverNeedsConfirmOrAudit(t *testing.T) {
	g := New(Options{Mode: ModeReadOnly}, quiet())
	tool := &stub{name: "ue_list", risk: registry.ReadOnly}
	d := g.Check(ctxWith(RoleViewer), tool, json.RawMessage(`{}`))
	if d.Verdict != Proceed {
		t.Fatalf("read-only call: got %v, want Proceed", d.Verdict)
	}
	g.Record(ctxWith(RoleViewer), tool, json.RawMessage(`{}`), nil)
	if n := len(g.Audit().Recent(10)); n != 0 {
		t.Errorf("read-only call audited: %d entries", n)
	}
}

func TestRateLimitAcrossDisruptiveTools(t *testing.T) {
	g := New(Options{Mode: ModeOperator, MinInterval: 2 * time.Second}, quiet())
	clock := fixedClock(g)
	ctx := ctxWith(RoleOperator)
	confirmed := json.RawMessage(`{"confirm":true}`)

	first := g.Check(ctx, &stub{name: "a", risk: registry.Disruptive}, confirmed)
	if first.Verdict != Proceed {
		t.Fatalf("first confirmed call: got %v", first.Verdict)
	}
	// A different disruptive tool inside the window is still refused.
	second := g.Check(ctx, &stub{name: "b", risk: registry.Disruptive}, confirmed)
	if second.Verdict != Refused || second.Err == nil {
		t.Fatalf("second confirmed call inside 2s: got %v", second.Verdict)
	}
	*clock = clock.Add(2 * time.Second)
	third := g.Check(ctx, &stub{name: "b", risk: registry.Disruptive}, confirmed)
	if third.Verdict != Proceed {
		t.Fatalf("call after the interval: got %v", third.Verdict)
	}
}

func TestDryRunDoesNotConsumeRateLimit(t *testing.T) {
	g := New(Options{Mode: ModeOperator, MinInterval: time.Minute}, quiet())
	fixedClock(g)
	ctx := ctxWith(RoleOperator)
	if d := g.Check(ctx, &stub{name: "a", risk: registry.Disruptive}, json.RawMessage(`{}`)); d.Verdict != DryRun {
		t.Fatalf("dry run: got %v", d.Verdict)
	}
	if d := g.Check(ctx, &stub{name: "a", risk: registry.Disruptive}, json.RawMessage(`{"confirm":true}`)); d.Verdict != Proceed {
		t.Fatalf("confirmed call after a dry run must proceed, got %v", d.Verdict)
	}
}

func TestRecordAuditsStateChangeWithHashNotInput(t *testing.T) {
	g := New(Options{Mode: ModeOperator}, quiet())
	fixedClock(g)
	ctx := session.WithID(ctxWith(RoleOperator), "sess-1")
	tool := &stub{name: "qos_policy_set", risk: registry.Mutating}
	args := json.RawMessage(`{"supi":"imsi-001010000000001","5qi":9}`)
	g.Check(ctx, tool, args)
	g.Record(ctx, tool, args, errors.New("pcf 500"))

	got := g.Audit().Recent(10)
	if len(got) != 1 {
		t.Fatalf("audit entries: got %d, want 1", len(got))
	}
	e := got[0]
	if e.Outcome != "failed" || e.Error != "pcf 500" || e.Session != "sess-1" || e.Role != "operator" {
		t.Errorf("entry: %+v", e)
	}
	if e.InputHash != InputHash(args) || len(e.InputHash) != 16 {
		t.Errorf("input hash: got %q", e.InputHash)
	}
	raw, _ := json.Marshal(e)
	if containsSUPI(string(raw)) {
		t.Errorf("audit entry leaks SUPI: %s", raw)
	}
}

func containsSUPI(s string) bool {
	for i := 0; i+5 <= len(s); i++ {
		if s[i:i+5] == "imsi-" {
			return true
		}
	}
	return false
}

func TestAuditRingKeepsNewestInOrder(t *testing.T) {
	a := NewAudit(3)
	for i := 0; i < 5; i++ {
		a.Add(Entry{Tool: string(rune('a' + i))})
	}
	got := a.Recent(10)
	if len(got) != 3 || got[0].Tool != "c" || got[1].Tool != "d" || got[2].Tool != "e" {
		t.Errorf("ring order: got %+v", got)
	}
	if n := len(a.Recent(2)); n != 2 {
		t.Errorf("Recent(2): got %d", n)
	}
}

func TestAuditEmpty(t *testing.T) {
	if n := len(NewAudit(4).Recent(10)); n != 0 {
		t.Errorf("empty ring: got %d entries", n)
	}
}

func TestAuditSessionLabel(t *testing.T) {
	tests := []struct {
		name         string
		sid, remote  string
		wantSession  string
		wantRemoteIP string
	}{
		{"stdio when nothing known", "", "", "stdio", ""},
		{"stateless http uses remote ip", "", "10.1.2.3", "http:10.1.2.3", "10.1.2.3"},
		{"session id wins and keeps remote", "sess-9", "10.1.2.3", "sess-9", "10.1.2.3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := New(Options{Mode: ModeOperator}, quiet())
			ctx := ctxWith(RoleOperator)
			if tc.sid != "" {
				ctx = session.WithID(ctx, tc.sid)
			}
			if tc.remote != "" {
				ctx = session.WithRemoteAddr(ctx, tc.remote)
			}
			tool := &stub{name: "qos_policy_set", risk: registry.Mutating}
			g.Check(ctx, tool, json.RawMessage(`{}`))
			g.Record(ctx, tool, json.RawMessage(`{}`), nil)
			got := g.Audit().Recent(1)
			if len(got) != 1 || got[0].Session != tc.wantSession || got[0].RemoteAddr != tc.wantRemoteIP {
				t.Fatalf("entry: %+v", got)
			}
		})
	}
}

// redactingStub redacts the "k" argument, as the subscriber tools do.
type redactingStub struct{ stub }

func (redactingStub) RedactArgs(a json.RawMessage) json.RawMessage {
	return registry.RedactJSONFields(a, "k")
}

func TestHashForUsesRedactedArgs(t *testing.T) {
	tool := &redactingStub{stub{name: "r", risk: registry.Mutating}}
	a1 := json.RawMessage(`{"supi":"imsi-1","k":"00112233445566778899aabbccddeeff"}`)
	a2 := json.RawMessage(`{"supi":"imsi-1","k":"ffffffffffffffffffffffffffffffff"}`)
	if HashFor(tool, a1) != HashFor(tool, a2) {
		t.Error("hash of a redacting tool must not depend on the secret value")
	}
	plain := &stub{name: "p", risk: registry.Mutating}
	if HashFor(plain, a1) != InputHash(a1) {
		t.Error("a tool without Redactor keeps the plain input hash")
	}
	if HashFor(tool, json.RawMessage(`{"k":"00`)) == InputHash(json.RawMessage(`{"k":"00`)) {
		t.Error("unparseable args of a redacting tool must be replaced")
	}
}
