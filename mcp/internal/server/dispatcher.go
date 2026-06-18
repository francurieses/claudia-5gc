// Package server contains the transport-agnostic MCP JSON-RPC dispatcher and the
// stdio/SSE transport adapters. The Dispatcher is pure: it maps a parsed request
// to a response by consulting the shared tool Registry and performs no socket
// I/O, which guarantees both transports expose an identical tool surface.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/jsonrpc"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// protocolVersion is the MCP protocol revision this server implements.
const protocolVersion = "2024-11-05"

// serverName / serverVersion identify this implementation in the initialize result.
const (
	serverName    = "5gc-rel17-mcp"
	serverVersion = "0.1.0"
)

// Dispatcher routes JSON-RPC methods to the tool registry.
type Dispatcher struct {
	reg    *registry.Registry
	logger *slog.Logger
}

// NewDispatcher returns a Dispatcher over the given registry.
func NewDispatcher(reg *registry.Registry, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{reg: reg, logger: logger.With("component", "dispatcher")}
}

// Dispatch handles a single request and returns the response. For notifications
// (no id) it returns the zero Response; callers must not write it to the wire.
func (d *Dispatcher) Dispatch(ctx context.Context, req *jsonrpc.Request) jsonrpc.Response {
	switch req.Method {
	case "initialize":
		return jsonrpc.NewResult(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		})
	case "notifications/initialized", "initialized":
		// Client acknowledgement; no response.
		return jsonrpc.Response{}
	case "ping":
		return jsonrpc.NewResult(req.ID, map[string]any{})
	case "tools/list":
		return jsonrpc.NewResult(req.ID, map[string]any{"tools": d.reg.Manifest()})
	case "tools/call":
		return d.callTool(ctx, req)
	default:
		if req.IsNotification() {
			return jsonrpc.Response{}
		}
		return jsonrpc.NewError(req.ID, mcperr.Newf(mcperr.CodeMethodNotFound,
			map[string]any{"method": req.Method}, "method not found: %s", req.Method))
	}
}

// callTool executes a tools/call request, wrapping the result in MCP content.
func (d *Dispatcher) callTool(ctx context.Context, req *jsonrpc.Request) jsonrpc.Response {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonrpc.NewError(req.ID, mcperr.Newf(mcperr.CodeInvalidParams, nil,
			"tools/call params: %v", err))
	}
	if params.Name == "" {
		return jsonrpc.NewError(req.ID, mcperr.New(mcperr.CodeInvalidParams,
			"tools/call requires a tool name", nil))
	}
	tool, ok := d.reg.Get(params.Name)
	if !ok {
		return jsonrpc.NewError(req.ID, mcperr.Newf(mcperr.CodeMethodNotFound,
			map[string]any{"tool": params.Name}, "tool not found: %s", params.Name))
	}
	if len(params.Arguments) == 0 {
		params.Arguments = json.RawMessage("{}")
	}

	sid := session.IDFrom(ctx)
	if sid == "" {
		sid = "stdio"
	}
	start := time.Now()
	result, err := tool.Invoke(ctx, params.Arguments)
	latency := time.Since(start).Milliseconds()

	logArgs := []any{
		"tool_name", params.Name,
		"session_id", sid,
		"input_hash", inputHash(params.Arguments),
		"latency_ms", latency,
	}
	if err != nil {
		e := mcperr.From(err)
		d.logger.Warn("tool invocation failed", append(logArgs, "error", e.Message)...)
		// Tool errors are returned as a successful JSON-RPC response with
		// isError=true so the model sees the diagnostic, per MCP convention.
		return jsonrpc.NewResult(req.ID, toolErrorContent(e))
	}
	d.logger.Info("tool invocation ok", append(logArgs, "error", "")...)
	return jsonrpc.NewResult(req.ID, toolContent(result))
}

// toolContent wraps a successful tool result as MCP tool content.
func toolContent(result any) map[string]any {
	text, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return toolErrorContent(mcperr.Newf(mcperr.CodeInternal, nil,
			"marshal tool result: %v", err))
	}
	// isError is omitted on success; per MCP spec it defaults to false when absent.
	// Some Claude Desktop versions misinterpret isError:false as an error state.
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(text)}},
	}
}

// toolErrorContent wraps a structured error as MCP tool content with isError set.
func toolErrorContent(e *mcperr.Error) map[string]any {
	text, _ := json.MarshalIndent(map[string]any{
		"error": e.Message, "code": e.Code, "data": e.Data,
	}, "", "  ")
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(text)}},
		"isError": true,
	}
}

// inputHash returns the first 8 bytes of the SHA-256 of the raw input as hex.
// Hashing avoids logging PII (SUPI, keys) while still correlating identical calls.
func inputHash(in json.RawMessage) string {
	sum := sha256.Sum256(in)
	return fmt.Sprintf("%x", sum[:8])
}
