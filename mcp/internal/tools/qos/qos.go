// Package qos implements MCP Group H tools: per-subscriber QoS policy write operations.
// These tools allow an LLM or operator to configure 5QI + AMBR per subscriber in the PCF
// and orchestrate new PDU session establishment that carries those QoS parameters end-to-end.
//
// 3GPP references:
//   - TS 23.501 §5.7 — QoS model (5QI table, non-GBR / GBR flows)
//   - TS 29.512 §5.2.2.2 — Npcf_SMPolicyControl_Create response (qosDecs + sessRules)
//   - TS 23.502 §4.3.2.2 — PDU Session Establishment procedure
package qos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	ueclient "github.com/francurieses/claudia-5gc/mcp/internal/ueransim"
)

// All returns the five Group H tools bound to a PCF client, AMF client, and UERANSIM client.
func All(pcf *clients.PCF, amf *clients.AMF, ue ueclient.Client) []registry.Tool {
	return []registry.Tool{
		setPolicyTool{pcf},
		getPolicyTool{pcf},
		deletePolicyTool{pcf},
		establishWithQoSTool{pcf: pcf, ue: ue},
		modifyQoSTool{pcf: pcf, amf: amf},
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

func hashSUPI(supi string) string {
	h := sha256.Sum256([]byte(supi))
	return hex.EncodeToString(h[:4])
}

// ---- qos_policy_set ---------------------------------------------------------

type setPolicyTool struct{ pcf *clients.PCF }

func (setPolicyTool) Name() string { return "qos_policy_set" }
func (setPolicyTool) Description() string {
	return "Set a per-subscriber SM policy QoS override in the PCF. " +
		"The configured 5QI and AMBR will be applied the next time this SUPI establishes a PDU session. " +
		"Common 5QI values: 1 (voice), 7 (real-time streaming), 8 (video), 9 (best-effort internet). " +
		"Ref: TS 29.512 §5.2.2.2 (qosDecs), TS 23.501 §5.7 (QoS model)."
}
func (setPolicyTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "supi":             {"type":"string","description":"Subscriber SUPI, e.g. imsi-001010000000001"},
  "5qi":              {"type":"integer","description":"5QI value (1-86). Standard non-GBR: 5,7,8,9. GBR voice: 1."},
  "ambr_uplink":      {"type":"string","description":"Session AMBR uplink, e.g. '50 Mbps'. Omit to keep default (100 Mbps)."},
  "ambr_downlink":    {"type":"string","description":"Session AMBR downlink, e.g. '200 Mbps'. Omit to keep default (100 Mbps)."},
  "arp_priority_level":{"type":"integer","description":"ARP priority level 1-15 (lower = higher priority). Default 8."}
},
"required":["supi","5qi"]}`)
}
func (setPolicyTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"applied":{"type":"boolean"},"supi":{},"5qi":{},"ambr_uplink":{},"ambr_downlink":{}}}`)
}

func (t setPolicyTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI             string `json:"supi"`
		FiveQI           int    `json:"5qi"`
		AMBRUplink       string `json:"ambr_uplink"`
		AMBRDownlink     string `json:"ambr_downlink"`
		ARPPriorityLevel int    `json:"arp_priority_level"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "qos_policy_set args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}
	if a.FiveQI <= 0 || a.FiveQI > 86 {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "5qi must be 1-86, got %d", a.FiveQI)
	}

	p := clients.PCFQoSPolicy{
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
		"supi_hash", hashSUPI(a.SUPI),
		"5qi", a.FiveQI,
	)
	return map[string]any{
		"applied":       true,
		"supi":          a.SUPI,
		"5qi":           a.FiveQI,
		"ambr_uplink":   strOrDefault(a.AMBRUplink, "100 Mbps (default)"),
		"ambr_downlink": strOrDefault(a.AMBRDownlink, "100 Mbps (default)"),
	}, nil
}

// ---- qos_policy_get ---------------------------------------------------------

type getPolicyTool struct{ pcf *clients.PCF }

func (getPolicyTool) Name() string { return "qos_policy_get" }
func (getPolicyTool) Description() string {
	return "Get the active per-subscriber SM policy QoS override for a SUPI. " +
		"Returns the configured 5QI and AMBR, or indicates that the operator default (5QI=9) is in use. " +
		"Ref: TS 29.512 §5.2.2.2."
}
func (getPolicyTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string"}},"required":["supi"]}`)
}
func (getPolicyTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{},"5qi":{},"ambr_uplink":{},"ambr_downlink":{},"is_override":{"type":"boolean"}}}`)
}

func (t getPolicyTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "qos_policy_get args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}

	p, err := t.pcf.GetQoSPolicy(ctx, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("qos_policy_get: %w", err), nil)
	}
	if p == nil {
		return map[string]any{
			"supi":          a.SUPI,
			"5qi":           9,
			"ambr_uplink":   "100 Mbps",
			"ambr_downlink": "100 Mbps",
			"is_override":   false,
			"note":          "No per-subscriber override; operator default (5QI=9) will be applied.",
		}, nil
	}
	return map[string]any{
		"supi":          a.SUPI,
		"5qi":           p.FiveQI,
		"ambr_uplink":   strOrDefault(p.AMBRUplink, "100 Mbps (default)"),
		"ambr_downlink": strOrDefault(p.AMBRDownlink, "100 Mbps (default)"),
		"is_override":   true,
	}, nil
}

// ---- qos_policy_delete ------------------------------------------------------

type deletePolicyTool struct{ pcf *clients.PCF }

func (deletePolicyTool) Name() string { return "qos_policy_delete" }
func (deletePolicyTool) Description() string {
	return "Remove the per-subscriber QoS override for a SUPI. " +
		"Subsequent PDU sessions will use the operator default (5QI=9, 100 Mbps). " +
		"Idempotent: no error if no override exists."
}
func (deletePolicyTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string"}},"required":["supi"]}`)
}
func (deletePolicyTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"cleared":{"type":"boolean"},"supi":{}}}`)
}

func (t deletePolicyTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "qos_policy_delete args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}

	if err := t.pcf.DeleteQoSPolicy(ctx, a.SUPI); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("qos_policy_delete: %w", err), nil)
	}
	slog.InfoContext(ctx, "QoS policy deleted", "tool_name", "qos_policy_delete", "supi_hash", hashSUPI(a.SUPI))
	return map[string]any{"cleared": true, "supi": a.SUPI}, nil
}

// ---- pdu_session_establish_with_qos -----------------------------------------

type establishWithQoSTool struct {
	pcf *clients.PCF
	ue  ueclient.Client
}

func (establishWithQoSTool) Name() string { return "pdu_session_establish_with_qos" }
func (establishWithQoSTool) Description() string {
	return "Orchestrates end-to-end QoS-aware PDU session establishment: " +
		"(1) sets a per-subscriber 5QI + AMBR override in the PCF, " +
		"(2) triggers UERANSIM to establish a new PDU session, " +
		"(3) returns the result with the configured QoS parameters. " +
		"The SMF reads the 5QI from the PCF response and encodes it in N1SM (QoS Rules) and N2SM (NGAP QoS Flow). " +
		"Spec: TS 23.502 §4.3.2.2, TS 29.512 §5.2.2.2, TS 23.501 §5.7."
}
func (establishWithQoSTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "supi":          {"type":"string","description":"Subscriber SUPI, e.g. imsi-001010000000001"},
  "5qi":           {"type":"integer","description":"5QI for the new session (1-86). 1=voice, 7=streaming, 9=internet."},
  "dnn":           {"type":"string","description":"Data Network Name. Defaults to 'internet'."},
  "ambr_uplink":   {"type":"string","description":"Session AMBR UL e.g. '50 Mbps'. Default: 100 Mbps."},
  "ambr_downlink": {"type":"string","description":"Session AMBR DL e.g. '200 Mbps'. Default: 100 Mbps."}
},
"required":["supi","5qi"]}`)
}
func (establishWithQoSTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"success":{},"pdu_session_id":{},"ue_ip":{},"5qi_configured":{},"ambr_uplink":{},"ambr_downlink":{},"establish_time_ms":{},"steps":{},"error":{}}}`)
}

func (t establishWithQoSTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		SUPI         string `json:"supi"`
		FiveQI       int    `json:"5qi"`
		DNN          string `json:"dnn"`
		AMBRUplink   string `json:"ambr_uplink"`
		AMBRDownlink string `json:"ambr_downlink"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pdu_session_establish_with_qos args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}
	if a.FiveQI <= 0 || a.FiveQI > 86 {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "5qi must be 1-86, got %d", a.FiveQI)
	}
	if a.DNN == "" {
		a.DNN = "internet"
	}

	steps := make([]map[string]any, 0, 2)

	// Step 1: Set QoS policy override in PCF.
	t1 := time.Now()
	policy := clients.PCFQoSPolicy{
		FiveQI:       a.FiveQI,
		AMBRUplink:   a.AMBRUplink,
		AMBRDownlink: a.AMBRDownlink,
	}
	if err := t.pcf.SetQoSPolicy(ctx, a.SUPI, policy); err != nil {
		steps = append(steps, stepResult("set_qos_policy", false, time.Since(t1), err.Error()))
		return map[string]any{"success": false, "steps": steps, "error": err.Error()}, nil
	}
	steps = append(steps, stepResult("set_qos_policy", true, time.Since(t1), ""))

	// Step 2: Trigger UERANSIM PDU session establishment.
	t2 := time.Now()
	sess, err := t.ue.PDUSessionEstablish(ctx, a.SUPI, a.DNN)
	if err != nil {
		steps = append(steps, stepResult("pdu_session_establish", false, time.Since(t2), err.Error()))
		return map[string]any{"success": false, "steps": steps, "error": err.Error()}, nil
	}
	steps = append(steps, stepResult("pdu_session_establish", true, time.Since(t2), ""))

	slog.InfoContext(ctx, "PDU session with QoS established",
		"tool_name", "pdu_session_establish_with_qos",
		"supi_hash", hashSUPI(a.SUPI),
		"5qi", a.FiveQI,
		"dnn", a.DNN,
		"session_id", sess.SessionID,
		"establish_time_ms", time.Since(start).Milliseconds(),
	)

	return map[string]any{
		"success":           true,
		"pdu_session_id":    sess.SessionID,
		"ue_ip":             sess.UEAddr,
		"5qi_configured":    a.FiveQI,
		"ambr_uplink":       strOrDefault(a.AMBRUplink, "100 Mbps (default)"),
		"ambr_downlink":     strOrDefault(a.AMBRDownlink, "100 Mbps (default)"),
		"establish_time_ms": time.Since(start).Milliseconds(),
		"steps":             steps,
	}, nil
}

// ---- pdu_session_qos_modify -------------------------------------------------

type modifyQoSTool struct {
	pcf *clients.PCF
	amf *clients.AMF
}

func (modifyQoSTool) Name() string { return "pdu_session_qos_modify" }
func (modifyQoSTool) Description() string {
	return "Triggers a NW-initiated QoS modification on an active PDU session: " +
		"(1) sets a per-subscriber 5QI + AMBR override in the PCF, " +
		"(2) triggers the AMF to issue a PDU Session Modification Command to the UE and gNB. " +
		"The UE must be CM-CONNECTED. " +
		"Spec: TS 23.502 §4.3.3.2 (NW-initiated PDU Session Modification)."
}
func (modifyQoSTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "supi":            {"type":"string","description":"Subscriber SUPI, e.g. imsi-001010000000001"},
  "pdu_session_id":  {"type":"integer","description":"PDU session ID to modify (1-15). Default: 1."},
  "5qi":             {"type":"integer","description":"New 5QI value (1-86). 1=voice, 7=streaming, 9=internet."},
  "ambr_dl_mbps":    {"type":"integer","description":"New Session AMBR downlink in Mbps. Default: 100."},
  "ambr_ul_mbps":    {"type":"integer","description":"New Session AMBR uplink in Mbps. Default: 100."}
},
"required":["supi","5qi"]}`)
}
func (modifyQoSTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"success":{},"supi":{},"pdu_session_id":{},"5qi_applied":{},"ambr_dl_mbps":{},"ambr_ul_mbps":{},"modify_time_ms":{},"steps":{},"error":{}}}`)
}

func (t modifyQoSTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		SUPI         string `json:"supi"`
		PDUSessionID int    `json:"pdu_session_id"`
		FiveQI       int    `json:"5qi"`
		AMBRDLMbps   int    `json:"ambr_dl_mbps"`
		AMBRULMbps   int    `json:"ambr_ul_mbps"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pdu_session_qos_modify args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}
	if a.FiveQI <= 0 || a.FiveQI > 86 {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "5qi must be 1-86, got %d", a.FiveQI)
	}
	if a.PDUSessionID == 0 {
		a.PDUSessionID = 1
	}
	if a.AMBRDLMbps <= 0 {
		a.AMBRDLMbps = 100
	}
	if a.AMBRULMbps <= 0 {
		a.AMBRULMbps = 100
	}

	steps := make([]map[string]any, 0, 2)

	// Step 1: Set QoS policy override in PCF.
	t1 := time.Now()
	policy := clients.PCFQoSPolicy{
		FiveQI:       a.FiveQI,
		AMBRDownlink: fmt.Sprintf("%d Mbps", a.AMBRDLMbps),
		AMBRUplink:   fmt.Sprintf("%d Mbps", a.AMBRULMbps),
	}
	if err := t.pcf.SetQoSPolicy(ctx, a.SUPI, policy); err != nil {
		steps = append(steps, stepResult("set_qos_policy", false, time.Since(t1), err.Error()))
		return map[string]any{"success": false, "steps": steps, "error": err.Error()}, nil
	}
	steps = append(steps, stepResult("set_qos_policy", true, time.Since(t1), ""))

	// Step 2: Trigger NW-initiated modification via AMF management API.
	t2 := time.Now()
	_, err := t.amf.ModifyPDUSessionQoS(ctx, a.SUPI, a.PDUSessionID, a.FiveQI, a.AMBRDLMbps, a.AMBRULMbps)
	if err != nil {
		steps = append(steps, stepResult("amf_qos_modify", false, time.Since(t2), err.Error()))
		return map[string]any{"success": false, "steps": steps, "error": err.Error()}, nil
	}
	steps = append(steps, stepResult("amf_qos_modify", true, time.Since(t2), ""))

	slog.InfoContext(ctx, "NW QoS modification triggered",
		"tool_name", "pdu_session_qos_modify",
		"supi_hash", hashSUPI(a.SUPI),
		"pdu_session_id", a.PDUSessionID,
		"5qi", a.FiveQI,
		"ambr_dl_mbps", a.AMBRDLMbps,
		"ambr_ul_mbps", a.AMBRULMbps,
		"modify_time_ms", time.Since(start).Milliseconds(),
	)
	return map[string]any{
		"success":        true,
		"supi":           a.SUPI,
		"pdu_session_id": a.PDUSessionID,
		"5qi_applied":    a.FiveQI,
		"ambr_dl_mbps":   a.AMBRDLMbps,
		"ambr_ul_mbps":   a.AMBRULMbps,
		"modify_time_ms": time.Since(start).Milliseconds(),
		"steps":          steps,
	}, nil
}

// ---- helpers ----------------------------------------------------------------

func stepResult(name string, ok bool, d time.Duration, errMsg string) map[string]any {
	m := map[string]any{
		"step":        name,
		"success":     ok,
		"duration_ms": d.Milliseconds(),
	}
	if errMsg != "" {
		m["error"] = errMsg
	}
	return m
}

func strOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
