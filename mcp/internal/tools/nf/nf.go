// Package nf implements MCP Group B tools: NF lifecycle introspection backed by
// the NRF SBI. Reference: 3GPP TS 29.510.
package nf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"

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

func (discoverTool) Name() string        { return "nf_discover" }
func (discoverTool) Risk() registry.Risk { return registry.ReadOnly }
func (discoverTool) Description() string {
	return "Discover NF instances of a given type via Nnrf_NFDiscovery. Filters by target NF " +
		"type, optional service names, DNN and S-NSSAIs. Per 3GPP TS 29.510 §5.3.2.2."
}
func (discoverTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"target_nf_type":{"type":"string","description":"e.g. SMF, UDM, AUSF"},"requester_nf_type":{"type":"string","description":"defaults to AMF"},"service_names":{"type":"string"},"dnn":{"type":"string"},"snssais":{"description":"S-NSSAI filter: a JSON array, e.g. [{\"sst\":1,\"sd\":\"000001\"}] (preferred), or the same array as a string."}},"required":["target_nf_type"]}`)
}
func (discoverTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"nfInstances":{"type":"array"}}}`)
}
func (t discoverTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		TargetNFType    string          `json:"target_nf_type"`
		RequesterNFType string          `json:"requester_nf_type"`
		ServiceNames    string          `json:"service_names"`
		DNN             string          `json:"dnn"`
		SNSSAIs         json.RawMessage `json:"snssais"`
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
	snssais, perr := normaliseSNSSAIs(a.SNSSAIs)
	if perr != nil {
		return nil, perr
	}
	if snssais != "" {
		q.Set("snssais", snssais)
	}
	raw, err := t.nrf.Discover(ctx, q)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nf_discover: %w", err), nil)
	}
	return raw, nil
}

// ---- nf_list --------------------------------------------------------------

type listTool struct{ nrf *clients.NRF }

func (listTool) Name() string        { return "nf_list" }
func (listTool) Risk() registry.Risk { return registry.ReadOnly }
func (listTool) Description() string {
	return "List the NF instances currently registered with the NRF (NFListRetrieval). By default " +
		"(detail:false) each row is a summary {instance_id, nf_type, nf_status, services[]}; with " +
		"detail:true the full NF profiles are returned unchanged. Per 3GPP TS 29.510 §5.2.2.6."
}
func (listTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"detail":{"type":"boolean","description":"return full NF profiles instead of summary rows (default false)"}}}`)
}
func (listTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"count":{"type":"integer","description":"summary mode only"},` +
		`"nfInstances":{"type":"array","description":"summary rows {instance_id, nf_type, nf_status, services[]}, or full NF profiles when detail:true"}}}`)
}

// maxProfileFetch bounds the per-instance profile fetches used when the NRF
// answers a list with bare instance ids.
const maxProfileFetch = 200

// summaryRow is one nf_list row in summary mode.
type summaryRow struct {
	InstanceID string   `json:"instance_id"`
	NFType     string   `json:"nf_type"`
	NFStatus   string   `json:"nf_status"`
	Services   []string `json:"services"`
}

func (t listTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		Detail bool `json:"detail"`
	}
	_ = json.Unmarshal(in, &a) // all fields optional
	// Summary rows need the profiles, so both modes ask the NRF for them inline.
	raw, err := t.nrf.List(ctx, true)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nf_list: %w", err), nil)
	}
	if a.Detail {
		return raw, nil
	}
	var res struct {
		NFInstances []json.RawMessage `json:"nfInstances"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nf_list: decode NRF list: %w", err), nil)
	}
	rows := make([]summaryRow, 0, len(res.NFInstances))
	for _, item := range res.NFInstances {
		var id string
		if json.Unmarshal(item, &id) == nil { // bare id: fetch the profile
			if len(rows) >= maxProfileFetch {
				break
			}
			prof, err := t.nrf.GetByID(ctx, id)
			if err != nil || prof == nil {
				rows = append(rows, summaryRow{InstanceID: id, Services: []string{}})
				continue
			}
			item = prof
		}
		rows = append(rows, summarise(item))
	}
	return map[string]any{"count": len(rows), "nfInstances": rows}, nil
}

// summarise reduces an NF profile (TS 29.510 §6.1.6.2.2) to a summary row. The
// nfServices attribute is a list in the spec and a map in older profiles; both
// are accepted.
func summarise(profile json.RawMessage) summaryRow {
	var p struct {
		ID       string          `json:"nfInstanceId"`
		Type     string          `json:"nfType"`
		Status   string          `json:"nfStatus"`
		Services json.RawMessage `json:"nfServices"`
	}
	_ = json.Unmarshal(profile, &p)
	row := summaryRow{InstanceID: p.ID, NFType: p.Type, NFStatus: p.Status, Services: []string{}}
	type svc struct {
		Name string `json:"serviceName"`
	}
	var list []svc
	if json.Unmarshal(p.Services, &list) == nil {
		for _, s := range list {
			if s.Name != "" {
				row.Services = append(row.Services, s.Name)
			}
		}
		return row
	}
	var m map[string]svc
	if json.Unmarshal(p.Services, &m) == nil {
		for k, s := range m {
			if s.Name != "" {
				k = s.Name
			}
			row.Services = append(row.Services, k)
		}
		sort.Strings(row.Services)
	}
	return row
}

// ---- nf_status ------------------------------------------------------------

type statusTool struct{ nrf *clients.NRF }

func (statusTool) Name() string        { return "nf_status" }
func (statusTool) Risk() registry.Risk { return registry.ReadOnly }
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

// normaliseSNSSAIs accepts snssais as a JSON array or as a string holding one,
// and returns the compact array the NRF expects. Empty input means no filter.
func normaliseSNSSAIs(raw json.RawMessage) (string, *mcperr.Error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		raw = json.RawMessage(asString)
	}
	var arr []struct {
		SST int    `json:"sst"`
		SD  string `json:"sd,omitempty"`
	}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return "", mcperr.Newf(mcperr.CodeInvalidParams, nil,
			"snssais must be a JSON array of {sst, sd}: %v", err)
	}
	for _, sn := range arr {
		if sn.SST < 0 || sn.SST > 255 {
			return "", mcperr.Newf(mcperr.CodeInvalidParams, nil,
				"snssais sst must be 0-255, got %d", sn.SST)
		}
	}
	out, err := json.Marshal(arr)
	if err != nil {
		return "", mcperr.ToolError(err, nil)
	}
	return string(out), nil
}
