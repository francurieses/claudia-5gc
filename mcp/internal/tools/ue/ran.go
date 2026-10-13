package ue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// ---- ran_gnb_list ---------------------------------------------------------

type ranGNBListTool struct{ amf *clients.AMF }

func (ranGNBListTool) Name() string        { return "ran_gnb_list" }
func (ranGNBListTool) Risk() registry.Risk { return registry.ReadOnly }
func (ranGNBListTool) Description() string {
	return "List the gNBs known to the AMF over N2: Global gNB ID, RAN node name, PLMN, supported " +
		"TAs and slices, SCTP remote address, state (SCTP_UP, NG_READY, DISCONNECTED with reason), " +
		"connected-since and UE counts. Works in every deployment mode (standalone core or with " +
		"UERANSIM/PacketRusher). Per 3GPP TS 38.413 §8.7.1 (NG Setup)."
}
func (ranGNBListTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{}}`)
}
func (ranGNBListTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"amf":{"type":"object"},"gnbs":{"type":"array","items":{"type":"object"}}}}`)
}
func (t ranGNBListTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	raw, err := t.amf.ListGNBs(ctx)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ran_gnb_list: %w", err), nil)
	}
	return raw, nil
}
