// Package control implements the core-side control tools: operations that change
// live UE, session and broadcast state. Every tool is Disruptive, so the guard
// returns a dry-run unless the call carries confirm:true. Each dry-run (Plan)
// reads the current state and describes the effect, but never changes it.
//
// 3GPP references are on each tool. The RAN side is not driven here: the core
// signals as it would for a real network, and the UE or gNB reacts.
package control

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

// Deps are the upstreams the control tools call.
type Deps struct {
	AMF    *clients.AMF
	SMF    *clients.SMF
	Portal *clients.Portal
	NEF    *clients.NEF
	SMSF   *clients.SMSF
}

// All returns the core-side control tools.
func All(d Deps) []registry.Tool {
	return append([]registry.Tool{
		deregisterTool{d}, releaseSessionTool{d}, policyPushTool{d}, pageTool{d},
		nssaaTool{d}, pwsBroadcastTool{d}, pwsCancelTool{d},
	}, netctlTools(d)...)
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// supiArgs is the common input: a SUPI, validated before anything is sent.
type supiArgs struct {
	SUPI string `json:"supi"`
}

func parseSUPI(in json.RawMessage, tool string) (supiArgs, *mcperr.Error) {
	var a supiArgs
	if err := json.Unmarshal(in, &a); err != nil {
		return a, mcperr.Newf(mcperr.CodeInvalidParams, nil, "%s args: %v", tool, err)
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return a, perr
	}
	return a, nil
}

// psiArg validates a PDU session ID argument for the tools that take one.
func psiArg(psi int) *mcperr.Error { return toolutil.ValidPSI(psi) }

// amfStatus maps an AMF management status to a tool result. 404 means the UE is
// unknown to the AMF, which is an error the caller must see.
func amfStatus(tool string, status int, body []byte, supi string) *mcperr.Error {
	switch {
	case status == http.StatusNotFound:
		return mcperr.Newf(mcperr.CodeToolError, map[string]any{"supi": supi, "status": status},
			"%s: UE not found in the AMF: %s", tool, supi)
	case status >= 200 && status < 300:
		return nil
	default:
		return mcperr.Newf(mcperr.CodeToolError, map[string]any{"status": status},
			"%s: AMF returned %d: %s", tool, status, strings.TrimSpace(string(body)))
	}
}

// ---- ue_deregister_nw -------------------------------------------------------

type deregisterTool struct{ d Deps }

func (deregisterTool) Name() string        { return "ue_deregister_nw" }
func (deregisterTool) Risk() registry.Risk { return registry.Disruptive }
func (deregisterTool) Description() string {
	return "Network-initiated deregistration of a UE with re-registration required (cause 0, the UE " +
		"re-fetches its subscription). The UE drops its PDU sessions and must register again. " +
		"Spec: TS 23.502 §4.2.2.3.3, TS 24.501 §5.5.2.3."
}
func (deregisterTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string","description":"e.g. imsi-001010000000001"}},"required":["supi"]}`)
}
func (deregisterTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t deregisterTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSUPI(in, "ue_deregister_nw")
	if perr != nil {
		return nil, perr
	}
	ue, err := t.d.AMF.GetContext(ctx, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_deregister_nw plan: %w", err), nil)
	}
	if ue == nil {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"supi": a.SUPI},
			"UE not found in the AMF: %s", a.SUPI)
	}
	return map[string]any{
		"supi":   a.SUPI,
		"ue":     json.RawMessage(ue),
		"effect": "UE is deregistered; all its PDU sessions are released; it must re-register",
	}, nil
}

func (t deregisterTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSUPI(in, "ue_deregister_nw")
	if perr != nil {
		return nil, perr
	}
	status, body, err := t.d.AMF.DeregisterUE(ctx, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_deregister_nw: %w", err), nil)
	}
	if perr := amfStatus("ue_deregister_nw", status, body, a.SUPI); perr != nil {
		return nil, perr
	}
	slog.InfoContext(ctx, "NW deregistration triggered", "tool_name", "ue_deregister_nw",
		"procedure", "NetworkDeregistration", "spec_ref", "TS 23.502 §4.2.2.3.3")
	return map[string]any{"accepted": true, "supi": a.SUPI, "spec_ref": "TS 23.502 §4.2.2.3.3"}, nil
}

// ---- pdu_session_release_nw -------------------------------------------------

type releaseSessionTool struct{ d Deps }

type sessionArgs struct {
	SUPI         string `json:"supi"`
	PDUSessionID int    `json:"pdu_session_id"`
}

func parseSession(in json.RawMessage, tool string) (sessionArgs, *mcperr.Error) {
	var a sessionArgs
	if err := json.Unmarshal(in, &a); err != nil {
		return a, mcperr.Newf(mcperr.CodeInvalidParams, nil, "%s args: %v", tool, err)
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return a, perr
	}
	if perr := psiArg(a.PDUSessionID); perr != nil {
		return a, perr
	}
	return a, nil
}

func (releaseSessionTool) Name() string        { return "pdu_session_release_nw" }
func (releaseSessionTool) Risk() registry.Risk { return registry.Disruptive }
func (releaseSessionTool) Description() string {
	return "Network-initiated release of one PDU session: the SMF releases the UPF tunnel over N4 and " +
		"the AMF sends the PDU Session Release Command to the UE. The UE is not deregistered. " +
		"Spec: TS 23.502 §4.3.4.3."
}
func (releaseSessionTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"supi":{"type":"string"},
"pdu_session_id":{"type":"integer","description":"PDU session ID (1-15)"}},"required":["supi","pdu_session_id"]}`)
}
func (releaseSessionTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t releaseSessionTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSession(in, "pdu_session_release_nw")
	if perr != nil {
		return nil, perr
	}
	sess, err := t.d.SMF.GetSession(ctx, a.PDUSessionID, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pdu_session_release_nw plan: %w", err), nil)
	}
	return map[string]any{
		"supi":           a.SUPI,
		"pdu_session_id": a.PDUSessionID,
		"session":        json.RawMessage(sess),
		"effect":         "PDU session released: UPF tunnel removed (N4), UE sent PDU Session Release Command",
	}, nil
}

func (t releaseSessionTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSession(in, "pdu_session_release_nw")
	if perr != nil {
		return nil, perr
	}
	status, body, err := t.d.AMF.ReleasePDUSession(ctx, a.SUPI, a.PDUSessionID)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pdu_session_release_nw: %w", err), nil)
	}
	if perr := amfStatus("pdu_session_release_nw", status, body, a.SUPI); perr != nil {
		return nil, perr
	}
	return map[string]any{"accepted": true, "supi": a.SUPI, "pdu_session_id": a.PDUSessionID,
		"spec_ref": "TS 23.502 §4.3.4.3"}, nil
}

// ---- ue_policy_push ---------------------------------------------------------

type policyPushTool struct{ d Deps }

func (policyPushTool) Name() string        { return "ue_policy_push" }
func (policyPushTool) Risk() registry.Risk { return registry.Disruptive }
func (policyPushTool) Description() string {
	return "Push the current URSP (UE route selection policy) from the PCF to a registered UE, through a " +
		"UE Configuration Update. A CM-IDLE UE is not reachable: the result says deferred:true instead of failing. " +
		"Spec: TS 23.502 §4.2.4.3, TS 24.526."
}
func (policyPushTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string"}},"required":["supi"]}`)
}
func (policyPushTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t policyPushTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSUPI(in, "ue_policy_push")
	if perr != nil {
		return nil, perr
	}
	ue, err := t.d.AMF.GetContext(ctx, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_policy_push plan: %w", err), nil)
	}
	if ue == nil {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"supi": a.SUPI}, "UE not found in the AMF: %s", a.SUPI)
	}
	return map[string]any{
		"supi":   a.SUPI,
		"ue":     json.RawMessage(ue),
		"effect": "UE Configuration Update carrying the URSP; deferred if the UE is CM-IDLE",
	}, nil
}

func (t policyPushTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSUPI(in, "ue_policy_push")
	if perr != nil {
		return nil, perr
	}
	status, body, err := t.d.AMF.PushPolicies(ctx, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_policy_push: %w", err), nil)
	}
	switch {
	case status == http.StatusConflict:
		return map[string]any{"pushed": false, "deferred": true, "supi": a.SUPI,
			"reason": "UE is CM-IDLE: delivery deferred until the UE connects"}, nil
	case status == http.StatusNotFound:
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"supi": a.SUPI}, "UE not found in the AMF: %s", a.SUPI)
	case status >= 200 && status < 300:
		return map[string]any{"pushed": true, "supi": a.SUPI, "spec_ref": "TS 23.502 §4.2.4.3"}, nil
	default:
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"status": status},
			"ue_policy_push: AMF returned %d: %s", status, strings.TrimSpace(string(body)))
	}
}

// ---- ue_page ----------------------------------------------------------------

type pageTool struct{ d Deps }

func (pageTool) Name() string        { return "ue_page" }
func (pageTool) Risk() registry.Risk { return registry.Disruptive }
func (pageTool) Description() string {
	return "Page a CM-IDLE UE for one PDU session: the SMF raises a downlink data notification, the AMF " +
		"sends N2 Paging to the gNBs and the UE answers with a Service Request. Use it before a network-initiated " +
		"QoS or release on an IDLE UE. Spec: TS 23.502 §4.2.3.3."
}
func (pageTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"pdu_session_id":{"type":"integer","description":"PDU session to page for (1-15)"},
"supi":{"type":"string","description":"needed when several UEs share the PDU session ID"}},"required":["pdu_session_id"]}`)
}
func (pageTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t pageTool) Plan(_ context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
		PSI  int    `json:"pdu_session_id"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ue_page args: %v", err)
	}
	if perr := psiArg(a.PSI); perr != nil {
		return nil, perr
	}
	return map[string]any{
		"pdu_session_id": a.PSI,
		"supi":           a.SUPI,
		"effect":         "N2 Paging to the gNBs of the UE's tracking area; the UE answers with a Service Request",
	}, nil
}

func (t pageTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
		PSI  int    `json:"pdu_session_id"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ue_page args: %v", err)
	}
	if perr := psiArg(a.PSI); perr != nil {
		return nil, perr
	}
	if a.SUPI != "" {
		if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
			return nil, perr
		}
	}
	status, body, err := t.d.SMF.DLDataNotify(ctx, a.PSI, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_page: %w", err), nil)
	}
	switch {
	case status >= 200 && status < 300:
		return map[string]any{"paging": "triggered", "pdu_session_id": a.PSI, "spec_ref": "TS 23.502 §4.2.3.3"}, nil
	case status == http.StatusNotFound:
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"pdu_session_id": a.PSI, "smf_code": "CONTEXT_NOT_FOUND"},
			"ue_page: no SMF session with pdu_session_id %d", a.PSI)
	case status == http.StatusConflict:
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"pdu_session_id": a.PSI, "smf_code": "AMBIGUOUS_SESSION"},
			"ue_page: several sessions match pdu_session_id %d; pass supi", a.PSI)
	default:
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"status": status},
			"ue_page: SMF returned %d: %s", status, strings.TrimSpace(string(body)))
	}
}

// ---- nssaa_trigger ----------------------------------------------------------

type nssaaTool struct{ d Deps }

func (nssaaTool) Name() string        { return "nssaa_trigger" }
func (nssaaTool) Risk() registry.Risk { return registry.Disruptive }
func (nssaaTool) Description() string {
	return "Trigger slice-specific authentication (NSSAA) for a UE on one S-NSSAI: reauth runs EAP " +
		"re-authentication with the AAA server, revoke withdraws the slice. Spec: TS 23.502 §4.2.9.3 (re-auth), " +
		"§4.2.9.4 (revoke)."
}
func (nssaaTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"supi":{"type":"string"},
"action":{"type":"string","enum":["reauth","revoke"]},
"sst":{"type":"integer","description":"Slice/Service Type 0-255"},
"sd":{"type":"string","description":"Slice Differentiator, 6 hex digits, optional"}},"required":["supi","action","sst"]}`)
}
func (nssaaTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t nssaaTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, sst, sd, perr := parseNSSAA(in)
	if perr != nil {
		return nil, perr
	}
	ue, err := t.d.AMF.GetContext(ctx, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nssaa_trigger plan: %w", err), nil)
	}
	return map[string]any{
		"supi": a.SUPI, "action": a.Action, "sst": sst, "sd": sd,
		"ue_found": ue != nil,
		"effect":   nssaaEffect(a.Action),
	}, nil
}

func (t nssaaTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, sst, sd, perr := parseNSSAA(in)
	if perr != nil {
		return nil, perr
	}
	status, body, err := t.d.AMF.NSSAA(ctx, a.SUPI, a.Action, sst, sd)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nssaa_trigger: %w", err), nil)
	}
	if status == http.StatusNotFound {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"supi": a.SUPI},
			"nssaa_trigger: UE not found, or the slice is not in its Allowed NSSAI")
	}
	if perr := amfStatus("nssaa_trigger", status, body, a.SUPI); perr != nil {
		return nil, perr
	}
	return map[string]any{"accepted": true, "supi": a.SUPI, "action": a.Action, "sst": sst, "sd": sd,
		"spec_ref": nssaaSpec(a.Action)}, nil
}

type nssaaArgs struct {
	SUPI   string `json:"supi"`
	Action string `json:"action"`
}

func parseNSSAA(in json.RawMessage) (nssaaArgs, int, string, *mcperr.Error) {
	var raw struct {
		SUPI   string `json:"supi"`
		Action string `json:"action"`
		SST    int    `json:"sst"`
		SD     string `json:"sd"`
	}
	if err := json.Unmarshal(in, &raw); err != nil {
		return nssaaArgs{}, 0, "", mcperr.Newf(mcperr.CodeInvalidParams, nil, "nssaa_trigger args: %v", err)
	}
	if perr := toolutil.ValidSUPI(raw.SUPI); perr != nil {
		return nssaaArgs{}, 0, "", perr
	}
	if raw.Action != "reauth" && raw.Action != "revoke" {
		return nssaaArgs{}, 0, "", mcperr.Newf(mcperr.CodeInvalidParams, nil, "action must be reauth or revoke, got %q", raw.Action)
	}
	if raw.SST < 0 || raw.SST > 255 {
		return nssaaArgs{}, 0, "", mcperr.Newf(mcperr.CodeInvalidParams, nil, "sst must be 0-255, got %d", raw.SST)
	}
	if raw.SD != "" && !isHex6(raw.SD) {
		return nssaaArgs{}, 0, "", mcperr.Newf(mcperr.CodeInvalidParams, nil, "sd must be 6 hex digits, got %q", raw.SD)
	}
	return nssaaArgs{SUPI: raw.SUPI, Action: raw.Action}, raw.SST, raw.SD, nil
}

func isHex6(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

func nssaaSpec(action string) string {
	if action == "revoke" {
		return "TS 23.502 §4.2.9.4"
	}
	return "TS 23.502 §4.2.9.3"
}

func nssaaEffect(action string) string {
	if action == "revoke" {
		return "the slice is withdrawn from the UE and its sessions on that slice are released"
	}
	return "EAP re-authentication with the AAA server for the slice"
}

// ---- pws_broadcast / pws_cancel --------------------------------------------

type pwsBroadcastTool struct{ d Deps }

func (pwsBroadcastTool) Name() string        { return "pws_broadcast" }
func (pwsBroadcastTool) Risk() registry.Risk { return registry.Disruptive }
func (pwsBroadcastTool) Description() string {
	return "Start a Public Warning System broadcast to the gNBs (Write-Replace Warning over NGAP). The portal " +
		"keeps the CBC store in step with the AMF. Spec: TS 38.413 §8.9.1 (Write-Replace Warning), TS 23.041."
}
func (pwsBroadcastTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"messageIdentifier":{"type":"integer"},
"serialNumber":{"type":"integer"},
"repetitionPeriod":{"type":"integer"},
"numberOfBroadcastsRequested":{"type":"integer"},
"warningType":{"type":"string"},
"dataCodingScheme":{"type":"integer"},
"language":{"type":"string"},
"messageText":{"type":"string"},
"warningAreaTacs":{"type":"array","items":{"type":"integer"}}},"required":["messageIdentifier","serialNumber"]}`)
}
func (pwsBroadcastTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t pwsBroadcastTool) Plan(_ context.Context, in json.RawMessage) (any, error) {
	return map[string]any{"request": json.RawMessage(in),
		"effect": "warning message broadcast to every gNB of the AMF's PWS area until cancelled"}, nil
}

func (t pwsBroadcastTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		MessageIdentifier *int `json:"messageIdentifier"`
		SerialNumber      *int `json:"serialNumber"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pws_broadcast args: %v", err)
	}
	if a.MessageIdentifier == nil || a.SerialNumber == nil {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "messageIdentifier and serialNumber are required", nil)
	}
	out, status, err := t.d.Portal.Post(ctx, "/pws/broadcast", json.RawMessage(in))
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pws_broadcast: %w", err), nil)
	}
	if status < 200 || status > 299 {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"status": status},
			"pws_broadcast: portal returned %d: %s", status, out)
	}
	return map[string]any{"broadcast": true, "result": out}, nil
}

type pwsCancelTool struct{ d Deps }

func (pwsCancelTool) Name() string        { return "pws_cancel" }
func (pwsCancelTool) Risk() registry.Risk { return registry.Disruptive }
func (pwsCancelTool) Description() string {
	return "Cancel an active PWS broadcast identified by message identifier and serial number " +
		"(PWS Cancel over NGAP). Spec: TS 38.413 §8.9.2 (PWS Cancel)."
}
func (pwsCancelTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"messageIdentifier":{"type":"integer"},"serialNumber":{"type":"integer"}},"required":["messageIdentifier","serialNumber"]}`)
}
func (pwsCancelTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t pwsCancelTool) Plan(_ context.Context, in json.RawMessage) (any, error) {
	return map[string]any{"request": json.RawMessage(in), "effect": "the broadcast stops at every gNB"}, nil
}

func (t pwsCancelTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		MessageIdentifier *int `json:"messageIdentifier"`
		SerialNumber      *int `json:"serialNumber"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pws_cancel args: %v", err)
	}
	if a.MessageIdentifier == nil || a.SerialNumber == nil {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "messageIdentifier and serialNumber are required", nil)
	}
	out, status, err := t.d.Portal.Post(ctx, "/pws/cancel", json.RawMessage(in))
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pws_cancel: %w", err), nil)
	}
	if status < 200 || status > 299 {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"status": status},
			"pws_cancel: portal returned %d: %s", status, out)
	}
	return map[string]any{"cancelled": true, "result": out}, nil
}
