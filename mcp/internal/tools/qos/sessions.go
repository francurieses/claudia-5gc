// sessions.go — MCP tools backed by the SMF session store and the UDM SDM
// service: pdu_session_list, pdu_session_qos_get, pdu_session_qos_set,
// subscription_qos_get.
//
// 3GPP references:
//   - TS 23.501 §5.7 / Table 5.7.4-1 — 5QI characteristics
//   - TS 23.502 §4.3.3.2 — NW-initiated PDU Session Modification
//   - TS 29.503 §6.1.6.2.7 — SessionManagementSubscriptionData (sm-data)
package qos

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// Sessions returns the SMF/UDM-backed PDU session QoS tools.
func Sessions(smf *clients.SMF, udm *clients.UDM) []registry.Tool {
	return []registry.Tool{
		sessionListTool{smf},
		sessionQoSGetTool{smf},
		sessionQoSSetTool{smf},
		subscriptionQoSGetTool{udm},
	}
}

// validFiveQI mirrors the SMF-side validation: standardised 5QIs per
// TS 23.501 Table 5.7.4-1 plus the operator-defined range 128-254.
func validFiveQI(v int) bool {
	switch v {
	case 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		65, 66, 67, 69, 70, 71, 72, 73, 74, 75, 76,
		79, 80, 82, 83, 84, 85, 86, 87, 88, 89, 90:
		return true
	}
	return v >= 128 && v <= 254
}

// ---- pdu_session_list -------------------------------------------------------

type sessionListTool struct{ smf *clients.SMF }

func (sessionListTool) Name() string { return "pdu_session_list" }
func (sessionListTool) Description() string {
	return "List all active PDU sessions held by the SMF session store. " +
		"Returns supi, pduSessionId, dnn, sNssai, current5qi, qosSource, session AMBR, " +
		"UPF TEID and session state for each session."
}
func (sessionListTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{}}`)
}
func (sessionListTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"count":{"type":"integer"},"sessions":{"type":"array"}}}`)
}

func (t sessionListTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	raw, err := t.smf.ListSessions(ctx)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pdu_session_list: %w", err), nil)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pdu_session_list: decode SMF response: %w", err), nil)
	}
	slog.InfoContext(ctx, "PDU sessions listed", "tool_name", "pdu_session_list", "count", out["count"])
	return out, nil
}

// ---- pdu_session_qos_get ----------------------------------------------------

type sessionQoSGetTool struct{ smf *clients.SMF }

func (sessionQoSGetTool) Name() string { return "pdu_session_qos_get" }
func (sessionQoSGetTool) Description() string {
	return "Get the QoS state of an active PDU session: current 5QI, ARP, session AMBR, " +
		"QoS flow list, SMF-side PFCP QER state, and the source of the 5QI " +
		"(UDM subscription, PCF policy/override, or manual override). " +
		"Identify the session by supi and/or pdu_session_id."
}
func (sessionQoSGetTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "supi":           {"type":"string","description":"Subscriber SUPI, e.g. imsi-001010000000001"},
  "pdu_session_id": {"type":"integer","description":"PDU session ID (1-15). Optional if supi uniquely identifies the session."}
}}`)
}
func (sessionQoSGetTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"session":{},"qosFlows":{},"pfcpQer":{}}}`)
}

func (t sessionQoSGetTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI         string `json:"supi"`
		PDUSessionID int    `json:"pdu_session_id"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pdu_session_qos_get args: %v", err)
	}
	if a.SUPI == "" && a.PDUSessionID == 0 {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi or pdu_session_id is required", nil)
	}

	psi := a.PDUSessionID
	if psi == 0 {
		// Resolve the PSI from the session list by SUPI.
		raw, err := t.smf.ListSessions(ctx)
		if err != nil {
			return nil, mcperr.ToolError(fmt.Errorf("pdu_session_qos_get: %w", err), nil)
		}
		var list struct {
			Sessions []struct {
				SUPI         string `json:"supi"`
				PDUSessionID int    `json:"pduSessionId"`
			} `json:"sessions"`
		}
		_ = json.Unmarshal(raw, &list)
		for _, s := range list.Sessions {
			if s.SUPI == a.SUPI {
				psi = s.PDUSessionID
				break
			}
		}
		if psi == 0 {
			return map[string]any{"found": false, "note": "no active PDU session for " + a.SUPI}, nil
		}
	}

	raw, err := t.smf.GetSession(ctx, psi, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pdu_session_qos_get: %w", err), nil)
	}
	if raw == nil {
		return map[string]any{"found": false, "note": fmt.Sprintf("no session with pduSessionId %d", psi)}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pdu_session_qos_get: decode SMF response: %w", err), nil)
	}
	out["found"] = true
	slog.InfoContext(ctx, "PDU session QoS read",
		"tool_name", "pdu_session_qos_get", "supi_hash", hashSUPI(a.SUPI), "pdu_session_id", psi)
	return out, nil
}

// ---- pdu_session_qos_set ----------------------------------------------------

type sessionQoSSetTool struct{ smf *clients.SMF }

func (sessionQoSSetTool) Name() string { return "pdu_session_qos_set" }
func (sessionQoSSetTool) Description() string {
	return "Change the 5QI of an ACTIVE PDU session via the SMF management endpoint " +
		"(POST /nsmf-management/v1/sessions/{id}/qos). Triggers the full NW-initiated " +
		"PDU Session Modification: PFCP QER update to the UPF (N4), then N2 PDU Session " +
		"Resource Modify Request and NAS PDU Session Modification Command to the UE. " +
		"The UE must be CM-CONNECTED. Spec: TS 23.502 §4.3.3.2."
}
func (sessionQoSSetTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "pdu_session_id": {"type":"integer","description":"PDU session ID to modify (1-15)."},
  "new5qi":         {"type":"integer","description":"New 5QI: standardised (TS 23.501 Table 5.7.4-1, e.g. 1=voice, 7=streaming, 9=best-effort) or operator-defined (128-254)."},
  "reason":         {"type":"string","description":"Operator reason for the change (required, logged)."},
  "supi":           {"type":"string","description":"Optional SUPI to disambiguate when several UEs share the PDU session ID."},
  "ambr_dl_mbps":   {"type":"integer","description":"Optional new session AMBR downlink in Mbps."},
  "ambr_ul_mbps":   {"type":"integer","description":"Optional new session AMBR uplink in Mbps."}
},
"required":["pdu_session_id","new5qi","reason"]}`)
}
func (sessionQoSSetTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"result":{},"previous5qi":{},"new5qi":{},"modifiedAt":{}}}`)
}

func (t sessionQoSSetTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		PDUSessionID int    `json:"pdu_session_id"`
		New5QI       int    `json:"new5qi"`
		Reason       string `json:"reason"`
		SUPI         string `json:"supi"`
		AMBRDLMbps   int    `json:"ambr_dl_mbps"`
		AMBRULMbps   int    `json:"ambr_ul_mbps"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pdu_session_qos_set args: %v", err)
	}
	if a.PDUSessionID <= 0 || a.PDUSessionID > 255 {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pdu_session_id must be 1-255, got %d", a.PDUSessionID)
	}
	if !validFiveQI(a.New5QI) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil,
			"new5qi %d is neither standardised (TS 23.501 Table 5.7.4-1) nor operator-defined (128-254)", a.New5QI)
	}
	if a.Reason == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "reason is required", nil)
	}

	raw, err := t.smf.SetSessionQoS(ctx, a.PDUSessionID, a.New5QI, a.Reason, a.SUPI, a.AMBRDLMbps, a.AMBRULMbps)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pdu_session_qos_set: %w", err), nil)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pdu_session_qos_set: decode SMF response: %w", err), nil)
	}
	slog.InfoContext(ctx, "PDU session QoS modified",
		"tool_name", "pdu_session_qos_set",
		"supi_hash", hashSUPI(a.SUPI),
		"pdu_session_id", a.PDUSessionID,
		"new_5qi", a.New5QI,
	)
	return out, nil
}

// ---- subscription_qos_get ---------------------------------------------------

type subscriptionQoSGetTool struct{ udm *clients.UDM }

func (subscriptionQoSGetTool) Name() string { return "subscription_qos_get" }
func (subscriptionQoSGetTool) Description() string {
	return "Get the subscriber's default QoS from the UDM (GET /nudm-sdm/v2/{supi}/sm-data): " +
		"per-slice default 5QI, ARP (priority, preemption capability/vulnerability) and " +
		"session AMBR. Ref: TS 29.503 §6.1.6.2.7."
}
func (subscriptionQoSGetTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string","description":"Subscriber SUPI, e.g. imsi-001010000000001"}},"required":["supi"]}`)
}
func (subscriptionQoSGetTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{},"subscriptions":{"type":"array"}}}`)
}

func (t subscriptionQoSGetTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "subscription_qos_get args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}

	raw, err := t.udm.GetSMData(ctx, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("subscription_qos_get: %w", err), nil)
	}
	if raw == nil {
		return map[string]any{"supi": a.SUPI, "found": false, "note": "no SM subscription provisioned"}, nil
	}

	var entries []struct {
		SingleNSSAI struct {
			SST int    `json:"sst"`
			SD  string `json:"sd"`
		} `json:"singleNssai"`
		DNNConfigurations map[string]struct {
			QoSProfile struct {
				FiveQI int `json:"5qi"`
				ARP    struct {
					PriorityLevel int    `json:"priorityLevel"`
					PreemptCap    string `json:"preemptCap"`
					PreemptVuln   string `json:"preemptVuln"`
				} `json:"arp"`
			} `json:"5gQosProfile"`
			SessionAMBR struct {
				Uplink   string `json:"uplink"`
				Downlink string `json:"downlink"`
			} `json:"sessionAmbr"`
		} `json:"dnnConfigurations"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("subscription_qos_get: decode sm-data: %w", err), nil)
	}

	subs := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		for dnn, cfg := range e.DNNConfigurations {
			subs = append(subs, map[string]any{
				"snssai":        map[string]any{"sst": e.SingleNSSAI.SST, "sd": e.SingleNSSAI.SD},
				"dnn":           dnn,
				"default5qi":    cfg.QoSProfile.FiveQI,
				"arp":           map[string]any{"priorityLevel": cfg.QoSProfile.ARP.PriorityLevel, "preemptCap": cfg.QoSProfile.ARP.PreemptCap, "preemptVuln": cfg.QoSProfile.ARP.PreemptVuln},
				"sessionAmbrUl": cfg.SessionAMBR.Uplink,
				"sessionAmbrDl": cfg.SessionAMBR.Downlink,
			})
		}
	}
	slog.InfoContext(ctx, "subscription QoS read",
		"tool_name", "subscription_qos_get", "supi_hash", hashSUPI(a.SUPI), "entries", len(subs))
	return map[string]any{"supi": a.SUPI, "found": true, "subscriptions": subs}, nil
}
