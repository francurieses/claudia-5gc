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
	"strings"
	"sync"
)

// Risk classifies what a tool may do to the running core. The guard uses it to
// hide tools above the access mode, to refuse calls above the caller's role, and
// to decide whether a call needs confirm:true (see mcp/internal/guard).
type Risk int

const (
	// ReadOnly tools query state and never change it.
	ReadOnly Risk = iota
	// Mutating tools change a stored setting (e.g. a PCF override) without
	// disturbing live traffic or registrations.
	Mutating
	// Disruptive tools change live state: they release sessions, deregister UEs,
	// page, or broadcast. They need confirm:true.
	Disruptive
	// Admin tools control NF processes themselves. They need confirm:true and the
	// lab access mode.
	Admin
)

// String returns the wire name of the risk level.
func (r Risk) String() string {
	switch r {
	case ReadOnly:
		return "READ_ONLY"
	case Mutating:
		return "MUTATING"
	case Disruptive:
		return "DISRUPTIVE"
	case Admin:
		return "ADMIN"
	default:
		return fmt.Sprintf("RISK(%d)", int(r))
	}
}

// NeedsConfirm reports whether a call at this risk level requires confirm:true.
func (r Risk) NeedsConfirm() bool { return r >= Disruptive }

// Tool is the contract every MCP tool implements. Name is the wire identifier;
// Description references the governing 3GPP TS clause; InputSchema/OutputSchema
// are JSON Schema documents; Risk classifies the tool; Invoke executes the tool.
// Invoke must never panic — malformed input is reported as a structured
// *mcperr.Error.
type Tool interface {
	Name() string
	Description() string
	InputSchema() json.RawMessage
	OutputSchema() json.RawMessage
	Risk() Risk
	Invoke(ctx context.Context, in json.RawMessage) (any, error)
}

// Planner is an optional interface for tools whose dry-run needs more than the
// generic message: the tool describes what the confirmed call would change. It
// may read upstream state but must not change it.
type Planner interface {
	Plan(ctx context.Context, in json.RawMessage) (any, error)
}

// ArgRisker is an optional interface for tools whose risk depends on the call:
// the static Risk() is the highest level the tool can reach, and RiskFor gives
// the level of one call. The guard enforces RiskFor. A tool that does not
// implement it always runs at Risk().
type ArgRisker interface {
	RiskFor(args json.RawMessage) Risk
}

// Redactor is an optional interface for tools whose arguments carry secrets (for
// example subscriber keys). The guard and the dispatcher hash and log the redacted
// form returned by RedactArgs instead of the raw arguments, so a secret never
// reaches the audit ring or the logs, not even through a hash preimage. The
// returned document must keep the same shape with every secret value replaced.
type Redactor interface {
	RedactArgs(args json.RawMessage) json.RawMessage
}

// RedactedValue replaces a secret in a redacted argument document.
const RedactedValue = "<redacted>"

// RedactJSONFields returns args with the value of every object key named in names
// (matched case-insensitively, at any depth) replaced by RedactedValue. Args that
// are not valid JSON are replaced by a fixed placeholder, because malformed text
// could still contain the secret.
func RedactJSONFields(args json.RawMessage, names ...string) json.RawMessage {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[strings.ToLower(n)] = true
	}
	var v any
	if err := json.Unmarshal(args, &v); err != nil {
		return json.RawMessage(`{"redacted":"unparseable arguments"}`)
	}
	out, err := json.Marshal(redactWalk(v, set))
	if err != nil {
		return json.RawMessage(`{"redacted":"unmarshalable arguments"}`)
	}
	return out
}

func redactWalk(v any, set map[string]bool) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if set[strings.ToLower(k)] {
				t[k] = RedactedValue
				continue
			}
			t[k] = redactWalk(val, set)
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactWalk(t[i], set)
		}
		return t
	default:
		return v
	}
}

// Alias is implemented by a deprecated tool name that forwards to another tool.
// AliasOf returns the name of the tool it forwards to.
type Alias interface {
	AliasOf() string
}

// IsAlias reports whether t is a deprecated alias of another tool.
func IsAlias(t Tool) bool {
	_, ok := t.(Alias)
	return ok
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

// RegisterAll registers each tool and returns the first error encountered.
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

// ManifestFor returns the descriptors of every tool whose risk is at or below
// ceiling, sorted by name. Tools above the ceiling are hidden. Tools that need
// confirmation get a confirm property in their schema and a risk prefix in
// their description, so an LLM sees the guard before it calls.
func (r *Registry) ManifestFor(ceiling Risk) []ManifestEntry {
	tools := r.List()
	out := make([]ManifestEntry, 0, len(tools))
	for _, t := range tools {
		if t.Risk() > ceiling {
			continue
		}
		out = append(out, ManifestEntry{
			Name:        t.Name(),
			Description: riskPrefix(t.Risk()) + t.Description(),
			InputSchema: withConfirm(t.Risk(), t.InputSchema()),
		})
	}
	return out
}

// riskPrefix tags a description with its risk level. ReadOnly tools carry no tag.
func riskPrefix(r Risk) string {
	switch r {
	case Mutating:
		return "[MUTATING] "
	case Disruptive:
		return "[DISRUPTIVE: needs confirm:true, otherwise returns a dry-run] "
	case Admin:
		return "[ADMIN: needs confirm:true and access_mode lab, otherwise returns a dry-run] "
	default:
		return ""
	}
}

// withConfirm adds the confirm property to an object schema for tools that need
// confirmation. Other schemas are returned unchanged.
func withConfirm(r Risk, schema json.RawMessage) json.RawMessage {
	if !r.NeedsConfirm() || len(schema) == 0 {
		return schema
	}
	var doc map[string]any
	if err := json.Unmarshal(schema, &doc); err != nil || doc == nil {
		return schema
	}
	props, _ := doc["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
	}
	props["confirm"] = map[string]any{
		"type":        "boolean",
		"description": "Set true to execute. Omitted or false returns a dry-run that changes nothing.",
	}
	doc["properties"] = props
	out, err := json.Marshal(doc)
	if err != nil {
		return schema
	}
	return out
}
