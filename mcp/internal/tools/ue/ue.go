// Package ue implements MCP Group C tools: UE context introspection backed by
// the AMF management API. Reference: 3GPP TS 23.502 / TS 24.501.
package ue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// All returns the Group C tools bound to an AMF client.
func All(amf *clients.AMF) []registry.Tool {
	return []registry.Tool{
		listTool{amf}, getTool{amf}, gmmTool{amf},
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// ---- ue_list --------------------------------------------------------------

type listTool struct{ amf *clients.AMF }

func (listTool) Name() string { return "ue_list" }
func (listTool) Description() string {
	return "List all active UE contexts held by the AMF: SUPI, GUTI, 5GMM state, CM state and " +
		"last activity. Per 3GPP TS 23.502 (registration management)."
}
func (listTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{}}`)
}
func (listTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"ue_contexts":{"type":"array","items":{"type":"object"}}}}`)
}
func (t listTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	raw, err := t.amf.ListContexts(ctx)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_list: %w", err), nil)
	}
	return map[string]any{"ue_contexts": raw}, nil
}

// ---- ue_context_get -------------------------------------------------------

type getTool struct{ amf *clients.AMF }

func (getTool) Name() string { return "ue_context_get" }
func (getTool) Description() string {
	return "Retrieve the full UE context for a SUPI: identifiers, 5GMM/CM state, PDU sessions " +
		"and timestamps. Per 3GPP TS 23.502."
}
func (getTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string","description":"e.g. imsi-001010000000001"}},"required":["supi"]}`)
}
func (getTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object"}`)
}
func (t getTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	supi, perr := requireSUPI(in)
	if perr != nil {
		return nil, perr
	}
	raw, err := t.amf.GetContext(ctx, supi)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_context_get: %w", err), nil)
	}
	if raw == nil {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"supi": supi},
			"UE context not found: %s", supi)
	}
	return raw, nil
}

// ---- gmm_state_get --------------------------------------------------------

type gmmTool struct{ amf *clients.AMF }

func (gmmTool) Name() string { return "gmm_state_get" }
func (gmmTool) Description() string {
	return "Get the current 5GMM state for a SUPI, with CM state and last activity, projected " +
		"from the UE context. Per 3GPP TS 24.501 §5 (5GMM state machine)."
}
func (gmmTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string"}},"required":["supi"]}`)
}
func (gmmTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string"},"gmm_state":{"type":"string"},"cm_state":{"type":"string"},"last_activity":{"type":"string"}}}`)
}
func (t gmmTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	supi, perr := requireSUPI(in)
	if perr != nil {
		return nil, perr
	}
	raw, err := t.amf.GetContext(ctx, supi)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("gmm_state_get: %w", err), nil)
	}
	if raw == nil {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"supi": supi},
			"UE context not found: %s", supi)
	}
	// Project the state fields from the AMF snapshot.
	var snap struct {
		SUPI         string `json:"supi"`
		GMMState     string `json:"gmm_state"`
		CMState      string `json:"cm_state"`
		LastActivity string `json:"last_activity"`
	}
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("gmm_state_get: parse snapshot: %w", err), nil)
	}
	return snap, nil
}

func requireSUPI(in json.RawMessage) (string, *mcperr.Error) {
	var a struct {
		SUPI string `json:"supi"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return "", mcperr.Newf(mcperr.CodeInvalidParams, nil, "args: %v", err)
	}
	if a.SUPI == "" {
		return "", mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}
	return a.SUPI, nil
}
