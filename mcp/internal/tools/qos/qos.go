// Package qos implements the MCP QoS tools: per-subscriber SM policy overrides in
// the PCF (this file) and PDU session QoS state in the SMF and UDM (sessions.go).
// The policy tools configure 5QI and AMBR per subscriber, optionally scoped to a
// DNN, so the next PDU session establishment picks them up.
//
// 3GPP references:
//   - TS 23.501 §5.7 — QoS model (5QI table, non-GBR / GBR flows)
//   - TS 29.512 §5.2.2.2 — Npcf_SMPolicyControl_Create response (qosDecs + sessRules)
//   - TS 23.502 §4.3.2.2 — PDU Session Establishment procedure
package qos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

// All returns the PCF-backed policy tools.
func All(pcf *clients.PCF) []registry.Tool {
	return []registry.Tool{
		setPolicyTool{pcf},
		getPolicyTool{pcf},
		deletePolicyTool{pcf},
		listPolicyTool{pcf},
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// optionalDNN validates a DNN argument that may be absent. Empty means "all DNNs".
func optionalDNN(dnn string) *mcperr.Error {
	if dnn == "" {
		return nil
	}
	return toolutil.ValidDNN(dnn)
}

// ---- qos_policy_set ---------------------------------------------------------

type setPolicyTool struct{ pcf *clients.PCF }

func (setPolicyTool) Name() string        { return "qos_policy_set" }
func (setPolicyTool) Risk() registry.Risk { return registry.Mutating }
func (setPolicyTool) Description() string {
	return "Set a per-subscriber SM policy QoS override in the PCF. " +
		"The configured 5QI and AMBR apply the next time this SUPI establishes a PDU session " +
		"(an active session keeps its QoS until pdu_session_qos_set). Optional dnn limits the override to one DNN. " +
		"Common 5QI values: 1 (voice), 7 (real-time streaming), 8 (video), 9 (best-effort internet). " +
		"Ref: TS 29.512 §5.2.2.2 (qosDecs), TS 23.501 §5.7 (QoS model)."
}
func (setPolicyTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "supi":             {"type":"string","description":"Subscriber SUPI, e.g. imsi-001010000000001"},
  "dnn":              {"type":"string","description":"Optional DNN the override applies to (e.g. internet). Omit for all DNNs."},
  "5qi":              {"type":"integer","description":"5QI value: standardised (TS 23.501 Table 5.7.4-1) or operator-defined 128-254."},
  "ambr_uplink":      {"type":"string","description":"Session AMBR uplink, e.g. '50 Mbps'. Omit to keep the subscription default."},
  "ambr_downlink":    {"type":"string","description":"Session AMBR downlink, e.g. '200 Mbps'. Omit to keep the subscription default."},
  "arp_priority_level":{"type":"integer","description":"ARP priority level 1-15 (lower = higher priority). Default 8."}
},
"required":["supi","5qi"]}`)
}
func (setPolicyTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"applied":{"type":"boolean"},"supi":{},"dnn":{},"5qi":{},"ambr_uplink":{},"ambr_downlink":{}}}`)
}

func (t setPolicyTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI             string `json:"supi"`
		DNN              string `json:"dnn"`
		FiveQI           int    `json:"5qi"`
		AMBRUplink       string `json:"ambr_uplink"`
		AMBRDownlink     string `json:"ambr_downlink"`
		ARPPriorityLevel int    `json:"arp_priority_level"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "qos_policy_set args: %v", err)
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return nil, perr
	}
	if perr := optionalDNN(a.DNN); perr != nil {
		return nil, perr
	}
	if !toolutil.ValidFiveQI(a.FiveQI) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil,
			"5qi %d is neither standardised (TS 23.501 Table 5.7.4-1) nor operator-defined (128-254)", a.FiveQI)
	}
	if a.ARPPriorityLevel != 0 && (a.ARPPriorityLevel < 1 || a.ARPPriorityLevel > 15) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil,
			"arp_priority_level must be 1-15, got %d", a.ARPPriorityLevel)
	}

	p := clients.PCFQoSPolicy{
		DNN:              a.DNN,
		FiveQI:           a.FiveQI,
		AMBRUplink:       a.AMBRUplink,
		AMBRDownlink:     a.AMBRDownlink,
		ARPPriorityLevel: a.ARPPriorityLevel,
	}
	if err := t.pcf.SetQoSPolicy(ctx, a.SUPI, p); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("qos_policy_set: %w", err), nil)
	}

	slog.InfoContext(ctx, "QoS policy set",
		"tool_name", "qos_policy_set",
		"supi_hash", toolutil.HashSUPI(a.SUPI),
		"dnn", a.DNN,
		"5qi", a.FiveQI,
	)
	return map[string]any{
		"applied":       true,
		"supi":          a.SUPI,
		"dnn":           a.DNN,
		"5qi":           a.FiveQI,
		"ambr_uplink":   a.AMBRUplink,
		"ambr_downlink": a.AMBRDownlink,
	}, nil
}

// ---- qos_policy_get ---------------------------------------------------------

type getPolicyTool struct{ pcf *clients.PCF }

func (getPolicyTool) Name() string        { return "qos_policy_get" }
func (getPolicyTool) Risk() registry.Risk { return registry.ReadOnly }
func (getPolicyTool) Description() string {
	return "Get the PCF QoS override for a SUPI (and optional DNN). Returns the override's 5QI and AMBR, " +
		"or is_override:false when none is set. It never invents a default: for the subscription " +
		"values use subscription_qos_get. Ref: TS 29.512 §5.2.2.2."
}
func (getPolicyTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string"},"dnn":{"type":"string","description":"Optional DNN scope."}},"required":["supi"]}`)
}
func (getPolicyTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{},"dnn":{},"5qi":{},"ambr_uplink":{},"ambr_downlink":{},"is_override":{"type":"boolean"},"hint":{}}}`)
}

func (t getPolicyTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
		DNN  string `json:"dnn"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "qos_policy_get args: %v", err)
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return nil, perr
	}
	if perr := optionalDNN(a.DNN); perr != nil {
		return nil, perr
	}

	p, err := t.pcf.GetQoSPolicy(ctx, a.SUPI, a.DNN)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("qos_policy_get: %w", err), nil)
	}
	if p == nil {
		return map[string]any{
			"supi":        a.SUPI,
			"dnn":         a.DNN,
			"is_override": false,
			"hint":        "no PCF override for this scope; the subscription QoS applies (see subscription_qos_get)",
		}, nil
	}
	return map[string]any{
		"supi":          a.SUPI,
		"dnn":           p.DNN,
		"5qi":           p.FiveQI,
		"ambr_uplink":   p.AMBRUplink,
		"ambr_downlink": p.AMBRDownlink,
		"is_override":   true,
	}, nil
}

// ---- qos_policy_delete ------------------------------------------------------

type deletePolicyTool struct{ pcf *clients.PCF }

func (deletePolicyTool) Name() string        { return "qos_policy_delete" }
func (deletePolicyTool) Risk() registry.Risk { return registry.Mutating }
func (deletePolicyTool) Description() string {
	return "Remove the PCF QoS override for a SUPI (and optional DNN). Later PDU sessions use the " +
		"subscription QoS. Idempotent: no error if no override exists."
}
func (deletePolicyTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string"},"dnn":{"type":"string","description":"Optional DNN scope."}},"required":["supi"]}`)
}
func (deletePolicyTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"cleared":{"type":"boolean"},"supi":{},"dnn":{}}}`)
}

func (t deletePolicyTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
		DNN  string `json:"dnn"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "qos_policy_delete args: %v", err)
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return nil, perr
	}
	if perr := optionalDNN(a.DNN); perr != nil {
		return nil, perr
	}

	if err := t.pcf.DeleteQoSPolicy(ctx, a.SUPI, a.DNN); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("qos_policy_delete: %w", err), nil)
	}
	slog.InfoContext(ctx, "QoS policy deleted", "tool_name", "qos_policy_delete",
		"supi_hash", toolutil.HashSUPI(a.SUPI), "dnn", a.DNN)
	return map[string]any{"cleared": true, "supi": a.SUPI, "dnn": a.DNN}, nil
}

// ---- qos_policy_list --------------------------------------------------------

type listPolicyTool struct{ pcf *clients.PCF }

func (listPolicyTool) Name() string        { return "qos_policy_list" }
func (listPolicyTool) Risk() registry.Risk { return registry.ReadOnly }
func (listPolicyTool) Description() string {
	return "List every per-subscriber SM policy QoS override the PCF holds (optionally only one SUPI). " +
		"Each entry has supi, dnn (when the override is DNN-scoped), 5qi, arp, ambr_ul and ambr_dl; arp and the " +
		"AMBRs are null when the override does not set them. An empty list means no override exists. " +
		"Overrides are created with qos_policy_set. Ref: TS 29.512 §5.2.2.2 (qosDecs, sessRules)."
}
func (listPolicyTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string","description":"Optional filter, e.g. imsi-001010000000001"}},"additionalProperties":false}`)
}
func (listPolicyTool) OutputSchema() json.RawMessage { return schema(`{"type":"array"}`) }

func (t listPolicyTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
	}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &a); err != nil {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "qos_policy_list args: %v", err)
		}
	}
	if a.SUPI != "" {
		if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
			return nil, perr
		}
	}
	list, err := t.pcf.ListQoSOverrides(ctx, a.SUPI)
	if err != nil {
		data := map[string]any{}
		var se *clients.PCFStatusError
		if errors.As(err, &se) {
			data["status"] = se.Status
		}
		return nil, mcperr.ToolError(fmt.Errorf("qos_policy_list: %w", err), data)
	}
	out := make([]map[string]any, 0, len(list))
	for _, o := range list {
		e := map[string]any{"supi": o.SUPI, "5qi": o.FiveQI, "arp": nil, "ambr_ul": nil, "ambr_dl": nil}
		if o.DNN != "" {
			e["dnn"] = o.DNN
		}
		if o.ARPPriorityLevel != nil {
			e["arp"] = *o.ARPPriorityLevel
		}
		if o.AMBRUplink != "" {
			e["ambr_ul"] = o.AMBRUplink
		}
		if o.AMBRDownlink != "" {
			e["ambr_dl"] = o.AMBRDownlink
		}
		out = append(out, e)
	}
	slog.InfoContext(ctx, "QoS policy overrides listed", "nf", "MCP", "procedure", "QosPolicyList",
		"interface", "Npcf", "direction", "OUT", "spec_ref", "TS 29.512 §5.2.2.2",
		"tool_name", "qos_policy_list", "supi_hash", toolutil.HashSUPI(a.SUPI), "count", len(out))
	return out, nil
}
