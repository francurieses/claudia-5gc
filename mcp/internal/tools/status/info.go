package status

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// upstreamProbeTimeout bounds each mcp_info upstream probe.
const upstreamProbeTimeout = 2 * time.Second

// Upstream is one service mcp_info probes. MTLS selects the SBI client for the
// NF SBIs (NRF, SMF, UDM, PCF, BSF); the others are plain HTTP.
type Upstream struct {
	Name string
	Addr string
	MTLS bool
}

// mcpInfoTool describes this MCP server: build, mode, caller, tool counts and
// the reachability of each upstream. An upstream that is down never fails the call.
type mcpInfoTool struct{ d Deps }

func (mcpInfoTool) Name() string        { return "mcp_info" }
func (mcpInfoTool) Risk() registry.Risk { return registry.ReadOnly }
func (mcpInfoTool) Description() string {
	return "About this MCP server: version, build_commit, access_mode, caller_role, tool_count and " +
		"alias_count (as listed by tools/list for this access mode; hidden_by_access_mode counts the rest), " +
		"and the upstreams (nrf, amf, smf, udm, pcf, bsf, portal, prometheus, loki, jaeger) with their address, " +
		"reachable flag and latency_ms. Reachable means any HTTP answer arrived within 2 s. Use it first to learn " +
		"what this server can do and what is down."
}
func (mcpInfoTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{}}`)
}
func (mcpInfoTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"version":{"type":"string"},"build_commit":{"type":"string"},"access_mode":{"type":"string"},"caller_role":{"type":"string"},"tool_count":{"type":"integer"},"alias_count":{"type":"integer"},"upstreams":{"type":"array"}}}`)
}

func (t mcpInfoTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	commit := t.d.BuildCommit
	if commit == "" {
		commit = "unknown"
	}
	out := map[string]any{
		"version":      t.d.Version,
		"build_commit": commit,
		"caller_role":  string(guard.RoleFrom(ctx)),
		"access_mode":  nil,
		"tool_count":   nil,
		"alias_count":  nil,
	}
	if t.d.Guard != nil {
		out["access_mode"] = string(t.d.Guard.Mode())
	}
	if t.d.Registry != nil {
		ceiling := registry.Admin
		if t.d.Guard != nil {
			ceiling = t.d.Guard.Ceiling()
		}
		all := t.d.Registry.List()
		tools, aliases, visible := 0, 0, 0
		for _, tl := range all {
			if tl.Risk() > ceiling {
				continue
			}
			visible++
			if registry.IsAlias(tl) {
				aliases++
			} else {
				tools++
			}
		}
		out["tool_count"], out["alias_count"], out["hidden_by_access_mode"] = tools, aliases, len(all)-visible
	}

	rows := make([]map[string]any, len(t.d.Upstreams))
	var wg sync.WaitGroup
	for i, u := range t.d.Upstreams {
		wg.Add(1)
		go func(i int, u Upstream) {
			defer wg.Done()
			rows[i] = t.probe(ctx, u)
		}(i, u)
	}
	wg.Wait()
	out["upstreams"] = rows
	return out, nil
}

// probe does one cheap GET. Any HTTP answer, even 4xx, means the upstream is reachable.
func (t mcpInfoTool) probe(ctx context.Context, u Upstream) map[string]any {
	row := map[string]any{"name": u.Name, "addr": u.Addr, "reachable": false, "latency_ms": nil}
	client := t.d.HTTP
	if u.MTLS && t.d.SBI != nil {
		client = t.d.SBI
	}
	if client == nil {
		return row
	}
	pctx, cancel := context.WithTimeout(ctx, upstreamProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, strings.TrimRight(u.Addr, "/")+"/", nil)
	if err != nil {
		return row
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return row
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	_ = resp.Body.Close()
	row["reachable"] = true
	row["latency_ms"] = time.Since(start).Milliseconds()
	return row
}
