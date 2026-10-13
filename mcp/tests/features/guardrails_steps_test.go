//go:build functional

package features

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
	"github.com/francurieses/claudia-5gc/mcp/internal/server/transport"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	nastools "github.com/francurieses/claudia-5gc/mcp/internal/tools/nas"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// probeTool is a test-only tool at a fixed risk level. Every real Invoke bumps
// upstream, which stands in for the upstream mutation the guard must prevent.
type probeTool struct {
	name     string
	risk     registry.Risk
	upstream *int32
}

func (p probeTool) Name() string        { return p.name }
func (p probeTool) Description() string { return "guardrail probe " + p.name }
func (p probeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"supi":{"type":"string"}}}`)
}
func (p probeTool) OutputSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (p probeTool) Risk() registry.Risk           { return p.risk }
func (p probeTool) Invoke(context.Context, json.RawMessage) (any, error) {
	atomic.AddInt32(p.upstream, 1)
	return map[string]any{"executed": true}, nil
}
func (p probeTool) Plan(context.Context, json.RawMessage) (any, error) {
	return map[string]any{"would": "change core state"}, nil
}

// guardCtx holds the state of the guardrail scenarios.
type guardCtx struct {
	c        *mcpCtx
	guard    *guard.Guard
	upstream int32
	header   string // Authorization header sent with the next call
	listed   []string
	lastCode float64
	lastErr  string
	rawText  string // text of the last tool result, whatever its JSON shape
}

const (
	operatorToken = "op-token"
	viewerToken   = "view-token"
)

// startGuardServer replaces the scenario server with one that has the probe
// tools registered and the requested access mode. authOn adds bearer tokens.
func (g *guardCtx) startGuardServer(mode string, authOn bool) error {
	if g.c.srv != nil {
		g.c.srv.Close()
	}
	if g.c.cancel != nil {
		g.c.cancel()
	}
	atomic.StoreInt32(&g.upstream, 0)

	m, err := guard.ParseAccessMode(mode)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// The 2 s interval is the production default, so the rate-limit scenario is real.
	g.guard = guard.New(guard.Options{Mode: m, MinInterval: 2 * time.Second}, logger)

	reg := registry.New()
	if err := reg.RegisterAll(nastools.All()...); err != nil {
		return err
	}
	if err := reg.RegisterAll(
		probeTool{name: "probe_read", risk: registry.ReadOnly, upstream: &g.upstream},
		probeTool{name: "probe_mutate", risk: registry.Mutating, upstream: &g.upstream},
		probeTool{name: "probe_disrupt", risk: registry.Disruptive, upstream: &g.upstream},
		probeTool{name: "probe_admin", risk: registry.Admin, upstream: &g.upstream},
	); err != nil {
		return err
	}

	cfg := &config.Config{Transport: config.TransportSSE, SSE: config.SSE{Debug: true}}
	if authOn {
		cfg.Auth = config.Auth{BearerToken: operatorToken,
			Tokens: []config.AuthToken{{Token: viewerToken, Role: "viewer"}}}
	}
	disp := server.NewDispatcher(reg, g.guard, logger)
	sse := transport.NewSSE(disp, reg, session.NewManager(logger), cfg, logger)
	g.c.srv = httptest.NewServer(sse.Handler())
	return nil
}

// do sends one JSON-RPC request with the scenario's Authorization header and
// returns the decoded response envelope.
func (g *guardCtx) do(body string) (map[string]any, error) {
	req, _ := http.NewRequest(http.MethodPost, g.c.srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if g.header != "" {
		req.Header.Set("Authorization", g.header)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

func (g *guardCtx) listTools() error {
	req, _ := http.NewRequest(http.MethodGet, g.c.srv.URL+"/mcp/tools", nil)
	if g.header != "" {
		req.Header.Set("Authorization", g.header)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	g.listed = g.listed[:0]
	for _, t := range out.Tools {
		g.listed = append(g.listed, t.Name)
	}
	return nil
}

func (g *guardCtx) call(name, args string) error {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, name, args)
	env, err := g.do(body)
	if err != nil {
		return err
	}
	res, _ := env["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		return fmt.Errorf("no content in response: %v", env)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	g.rawText = text
	g.c.content = map[string]any{}
	// A tool may return a JSON array (subscriber_list): content stays empty then
	// and rawText carries the document.
	var anyDoc any
	if err := json.Unmarshal([]byte(text), &anyDoc); err != nil {
		return fmt.Errorf("decode tool content: %w", err)
	}
	if obj, ok := anyDoc.(map[string]any); ok {
		g.c.content = obj
	}
	g.c.isError, _ = res["isError"].(bool)
	g.lastCode, _ = g.c.content["code"].(float64)
	g.lastErr, _ = g.c.content["error"].(string)
	return nil
}

func (g *guardCtx) theServerRunsWithMode(mode string) error {
	return g.startGuardServer(mode, false)
}

func (g *guardCtx) theServerRunsWithModeAndTokens(mode string) error {
	return g.startGuardServer(mode, true)
}

func (g *guardCtx) iSendTheOperatorToken() error { g.header = "Bearer " + operatorToken; return nil }
func (g *guardCtx) iSendTheViewerToken() error   { g.header = "Bearer " + viewerToken; return nil }

func (g *guardCtx) theToolListContains(name string) error {
	for _, n := range g.listed {
		if n == name {
			return nil
		}
	}
	return fmt.Errorf("tool list %v lacks %q", g.listed, name)
}

func (g *guardCtx) theToolListDoesNotContain(name string) error {
	for _, n := range g.listed {
		if n == name {
			return fmt.Errorf("tool list %v must not contain %q", g.listed, name)
		}
	}
	return nil
}

func (g *guardCtx) theResultIsADryRun() error {
	if g.c.isError {
		return fmt.Errorf("expected a dry run, got error: %s", g.lastErr)
	}
	if g.c.content["dry_run"] != true {
		return fmt.Errorf("expected dry_run:true, got %v", g.c.content)
	}
	return nil
}

func (g *guardCtx) theCallIsRefused(code int, msg string) error {
	if !g.c.isError {
		return fmt.Errorf("expected a refusal, call succeeded: %v", g.c.content)
	}
	if int(g.lastCode) != code {
		return fmt.Errorf("code: got %v, want %d", g.lastCode, code)
	}
	if !strings.Contains(g.lastErr, msg) {
		return fmt.Errorf("message %q lacks %q", g.lastErr, msg)
	}
	return nil
}

func (g *guardCtx) theUpstreamWasCalled(n int) error {
	if got := atomic.LoadInt32(&g.upstream); int(got) != n {
		return fmt.Errorf("upstream calls: got %d, want %d", got, n)
	}
	return nil
}

func (g *guardCtx) theAuditLogHasOutcome(tool, outcome string) error {
	for _, e := range g.guard.Audit().Recent(0) {
		if e.Tool == tool && e.Outcome == outcome {
			return nil
		}
	}
	return fmt.Errorf("no audit entry for %s with outcome %s: %+v", tool, outcome, g.guard.Audit().Recent(0))
}

// registerGuardrailSteps wires the guardrail steps into the suite.
func registerGuardrailSteps(sc *godog.ScenarioContext, c *mcpCtx) *guardCtx {
	g := &guardCtx{c: c}
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		g.header, g.listed = "", nil
		return ctx, nil
	})
	sc.Step(`^the MCP server runs with access mode "([^"]+)"$`, g.theServerRunsWithMode)
	sc.Step(`^the MCP server runs with access mode "([^"]+)" and bearer authentication$`, g.theServerRunsWithModeAndTokens)
	sc.Step(`^I send the operator token$`, g.iSendTheOperatorToken)
	sc.Step(`^I send the viewer token$`, g.iSendTheViewerToken)
	sc.Step(`^I list the tools$`, g.listTools)
	sc.Step(`^the tool list contains "([^"]+)"$`, g.theToolListContains)
	sc.Step(`^the tool list does not contain "([^"]+)"$`, g.theToolListDoesNotContain)
	sc.Step(`^I call "([^"]+)" with arguments (\{.*\})$`, g.call)
	sc.Step(`^the result is a dry run$`, g.theResultIsADryRun)
	sc.Step(`^the call is refused with code (-?\d+) and message "([^"]+)"$`, g.theCallIsRefused)
	sc.Step(`^the upstream was called (\d+) times?$`, g.theUpstreamWasCalled)
	sc.Step(`^the audit log has an entry for "([^"]+)" with outcome "([^"]+)"$`, g.theAuditLogHasOutcome)
	return g
}
