// Package nf implements MCP Group B tools: NF lifecycle introspection backed by
// the NRF SBI. Reference: 3GPP TS 29.510.
package nf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// All returns the Group B tools bound to an NRF client.
func All(nrf *clients.NRF) []registry.Tool {
	return []registry.Tool{
		discoverTool{nrf}, listTool{nrf}, statusTool{nrf},
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// ---- nf_discover ----------------------------------------------------------

type discoverTool struct{ nrf *clients.NRF }

func (discoverTool) Name() string { return "nf_discover" }
func (discoverTool) Description() string {
	return "Discover NF instances of a given type via Nnrf_NFDiscovery. Filters by target NF " +
		"type, optional service names, DNN and S-NSSAIs. Per 3GPP TS 29.510 §5.3.2.2."
}
func (discoverTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"target_nf_type":{"type":"string","description":"e.g. SMF, UDM, AUSF"},"requester_nf_type":{"type":"string","description":"defaults to AMF"},"service_names":{"type":"string"},"dnn":{"type":"string"},"snssais":{"type":"string","description":"JSON array, e.g. [{\"sst\":1,\"sd\":\"000001\"}]"}},"required":["target_nf_type"]}`)
}
func (discoverTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"nfInstances":{"type":"array"}}}`)
}
func (t discoverTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		TargetNFType    string `json:"target_nf_type"`
		RequesterNFType string `json:"requester_nf_type"`
		ServiceNames    string `json:"service_names"`
		DNN             string `json:"dnn"`
		SNSSAIs         string `json:"snssais"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "nf_discover args: %v", err)
	}
	if a.TargetNFType == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "target_nf_type is required", nil)
	}
	if a.RequesterNFType == "" {
		a.RequesterNFType = "AMF"
	}
	q := url.Values{}
	q.Set("target-nf-type", a.TargetNFType)
	q.Set("requester-nf-type", a.RequesterNFType)
	if a.ServiceNames != "" {
		q.Set("service-names", a.ServiceNames)
	}
	if a.DNN != "" {
		q.Set("dnn", a.DNN)
	}
	if a.SNSSAIs != "" {
		q.Set("snssais", a.SNSSAIs)
	}
	raw, err := t.nrf.Discover(ctx, q)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nf_discover: %w", err), nil)
	}
	return raw, nil
}

// ---- nf_list --------------------------------------------------------------

type listTool struct{ nrf *clients.NRF }

func (listTool) Name() string { return "nf_list" }
func (listTool) Description() string {
	return "List all NF instances currently registered with the NRF (NFListRetrieval). " +
		"Per 3GPP TS 29.510 §5.2.2.6."
}
func (listTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"detail":{"type":"boolean","description":"inline full NF profiles instead of ids"}}}`)
}
func (listTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"nfInstances":{"type":"array"}}}`)
}
func (t listTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		Detail bool `json:"detail"`
	}
	_ = json.Unmarshal(in, &a) // all fields optional
	raw, err := t.nrf.List(ctx, a.Detail)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nf_list: %w", err), nil)
	}
	return raw, nil
}

// ---- nf_status ------------------------------------------------------------

type statusTool struct{ nrf *clients.NRF }

func (statusTool) Name() string { return "nf_status" }
func (statusTool) Description() string {
	return "Retrieve a single NF profile by nfInstanceId, including registration status and " +
		"heartbeat timer (NFProfileRetrieve). Per 3GPP TS 29.510 §5.2.2.5."
}
func (statusTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"nf_instance_id":{"type":"string"}},"required":["nf_instance_id"]}`)
}
func (statusTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"nfInstanceId":{"type":"string"},"nfStatus":{"type":"string"},"heartBeatTimer":{"type":"integer"}}}`)
}
func (t statusTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		ID string `json:"nf_instance_id"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "nf_status args: %v", err)
	}
	if a.ID == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "nf_instance_id is required", nil)
	}
	raw, err := t.nrf.GetByID(ctx, a.ID)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nf_status: %w", err), nil)
	}
	if raw == nil {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"nf_instance_id": a.ID},
			"NF instance not found: %s", a.ID)
	}
	return raw, nil
}
