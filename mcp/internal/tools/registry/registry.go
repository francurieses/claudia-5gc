// Package registry holds the single, transport-agnostic catalogue of MCP tools.
// Every tool is registered exactly once at startup and served identically over
// both transports (stdio and HTTP SSE) — there is one Registry instance shared
// by the one Dispatcher, which structurally guarantees no capability divergence.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// Tool is the contract every MCP tool implements. Name is the wire identifier;
// Description references the governing 3GPP TS clause; InputSchema/OutputSchema
// are JSON Schema documents; Invoke executes the tool. Invoke must never panic —
// malformed input is reported as a structured *mcperr.Error.
type Tool interface {
	Name() string
	Description() string
	InputSchema() json.RawMessage
	OutputSchema() json.RawMessage
	Invoke(ctx context.Context, in json.RawMessage) (any, error)
}

// Registry is a concurrency-safe map of tools keyed by name.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{tools: make(map[string]Tool)}
}

// Register adds a tool. A duplicate name is an error (never a panic).
func (r *Registry) Register(t Tool) error {
	if t == nil {
		return fmt.Errorf("registry: nil tool")
	}
	name := t.Name()
	if name == "" {
		return fmt.Errorf("registry: tool has empty name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("registry: duplicate tool %q", name)
	}
	r.tools[name] = t
	return nil
}

// MustRegister registers each tool and returns the first error encountered.
// Convenience for startup wiring where a single call registers many tools.
func (r *Registry) RegisterAll(tools ...Tool) error {
	for _, t := range tools {
		if err := r.Register(t); err != nil {
			return err
		}
	}
	return nil
}

// Get returns the tool registered under name.
func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// List returns all tools sorted by name (stable output for clients/tests).
func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// ManifestEntry is the per-tool descriptor in the MCP tools/list result and the
// GET /mcp/tools manifest. Field names follow MCP 2024-11-05 schema.
// outputSchema is intentionally omitted: it was introduced in MCP 2025-03-26 and
// when present requires structuredContent in every tools/call result. Sending it
// while negotiating 2024-11-05 causes Claude Desktop to mark every tool call as
// failed because structuredContent is absent.
type ManifestEntry struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Manifest returns the descriptor list for every registered tool, sorted by name.
func (r *Registry) Manifest() []ManifestEntry {
	tools := r.List()
	out := make([]ManifestEntry, 0, len(tools))
	for _, t := range tools {
		out = append(out, ManifestEntry{
			Name:        t.Name(),
			Description: t.Description(),
			InputSchema: t.InputSchema(),
		})
	}
	return out
}
