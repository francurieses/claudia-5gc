// Package runtimecfg implements the tools that change operator configuration while
// the core runs: the per-slice session AMBR, the RFSP index
// of a subscriber, the URSP policy template of a UE, NF service lifecycle (admin
// only), the runtime NF log level, and the reader for the guard's audit log.
//
// Each tool says which settings apply live and which need an NF restart; see the
// config_view tool for the same classification.
//
// 3GPP references: BitRate TS 29.571 §5.5.2; RFSP TS 38.413 §9.3.1.27 and
// TS 23.501 §5.3.3.4.3; URSP TS 24.526 and TS 23.503 §6.6.2.
package runtimecfg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

// Deps are the upstreams and settings the runtime tools use.
type Deps struct {
	Portal *clients.Portal
	// AMF serves amf_timer_config (the AMF management API, plain HTTP).
	AMF   *clients.AMF
	Guard *guard.Guard
	// Prom finds each NF's metrics address (the scrape target instance label), which
	// is where the runtime log-level endpoint is served. HTTP calls it.
	Prom *promclient.Client
	// Targets is the shared scrape-target resolver (with metrics_host_override). When
	// nil, one is built from Prom with no override.
	Targets *clients.Targets
	HTTP    *http.Client
	// AllowServiceControl mirrors the allow_service_control config flag. nf_service_control
	// refuses to run without it, in every access mode.
	AllowServiceControl bool
}

// targets returns the scrape-target resolver.
func (d Deps) targets() *clients.Targets {
	if d.Targets != nil {
		return d.Targets
	}
	return clients.NewTargets(d.Prom, "")
}

// All returns the runtime-config tools.
func All(d Deps) []registry.Tool {
	return []registry.Tool{
		sliceAMBRTool{d}, rfspTool{d}, ursTemplateTool{d}, serviceControlTool{d},
		auditLogTool{d}, logLevelTool{d}, timerConfigTool{d},
		subscriberProfileUpdateTool{d}, subscriberProvisionTool{d}, subscriberDeleteTool{d},
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// bitRateRe is the TS 29.571 §5.5.2 BitRate string: an integer and a unit.
var bitRateRe = regexp.MustCompile(`^[0-9]+ (bps|Kbps|Mbps|Gbps|Tbps)$`)

var hex6Re = regexp.MustCompile(`^[0-9a-fA-F]{6}$`)

// protectedServices are the containers whose stop or restart breaks the whole
// core or the control plane itself. They need force:true as well.
var protectedServices = map[string]bool{
	"postgres": true, "redis": true, "nrf": true, "mgmt-portal": true, "mcp": true,
}

// sliceArgs identifies one slice QoS entry: S-NSSAI plus DNN.
type sliceArgs struct {
	SST int    `json:"sst"`
	SD  string `json:"sd"`
	DNN string `json:"dnn"`
}

func (a sliceArgs) validate() *mcperr.Error {
	if a.SST < 0 || a.SST > 255 {
		return mcperr.Newf(mcperr.CodeInvalidParams, nil, "sst must be 0-255, got %d", a.SST)
	}
	if !hex6Re.MatchString(a.SD) {
		return mcperr.Newf(mcperr.CodeInvalidParams, nil, "sd must be 6 hex digits, got %q", a.SD)
	}
	return toolutil.ValidDNN(a.DNN)
}

func (a sliceArgs) path() string {
	return fmt.Sprintf("/slices/qos/%d/%s/%s", a.SST, url.PathEscape(a.SD), url.PathEscape(a.DNN))
}

// ---- slice_session_ambr_set -------------------------------------------------

type sliceAMBRTool struct{ d Deps }

func (sliceAMBRTool) Name() string        { return "slice_session_ambr_set" }
func (sliceAMBRTool) Risk() registry.Risk { return registry.Disruptive }

// RiskFor: a stored change is Mutating. Applying it to the sessions that are
// already up (apply_to_active) renegotiates live PDU sessions, which is Disruptive.
func (sliceAMBRTool) RiskFor(in json.RawMessage) registry.Risk {
	var a struct {
		Apply bool `json:"apply_to_active"`
	}
	_ = json.Unmarshal(in, &a)
	if a.Apply {
		return registry.Disruptive
	}
	return registry.Mutating
}

func (sliceAMBRTool) Description() string {
	return "Set the session AMBR (uplink, downlink) of a slice and DNN, or revert it. The stored value applies " +
		"to PDU sessions established afterwards. With apply_to_active:true the SMF also renegotiates the " +
		"sessions that are up now (Disruptive). Values are BitRate strings such as \"200 Mbps\" (TS 29.571 §5.5.2). " +
		"Spec: TS 23.501 §5.7.2.6 (session-AMBR), TS 23.503 §6.4.2."
}
func (sliceAMBRTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"sst":{"type":"integer","description":"Slice/Service Type 0-255"},
"sd":{"type":"string","description":"Slice Differentiator, 6 hex digits"},
"dnn":{"type":"string","description":"DNN, e.g. internet"},
"uplink":{"type":"string","description":"session AMBR uplink, BitRate e.g. \"100 Mbps\""},
"downlink":{"type":"string","description":"session AMBR downlink, BitRate e.g. \"200 Mbps\""},
"revert":{"type":"boolean","description":"remove the stored value instead of setting it"},
"apply_to_active":{"type":"boolean","description":"also renegotiate the sessions up now (Disruptive)"}},
"required":["sst","sd","dnn"]}`)
}
func (sliceAMBRTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

type sliceAMBRArgs struct {
	sliceArgs
	Uplink   string `json:"uplink"`
	Downlink string `json:"downlink"`
	Revert   bool   `json:"revert"`
	Apply    bool   `json:"apply_to_active"`
}

func parseSliceAMBR(in json.RawMessage) (sliceAMBRArgs, *mcperr.Error) {
	var a sliceAMBRArgs
	if err := json.Unmarshal(in, &a); err != nil {
		return a, mcperr.Newf(mcperr.CodeInvalidParams, nil, "slice_session_ambr_set args: %v", err)
	}
	if perr := a.validate(); perr != nil {
		return a, perr
	}
	if !a.Revert {
		if !bitRateRe.MatchString(a.Uplink) {
			return a, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"uplink": a.Uplink},
				"uplink must be a BitRate such as \"100 Mbps\" (TS 29.571 §5.5.2), got %q", a.Uplink)
		}
		if !bitRateRe.MatchString(a.Downlink) {
			return a, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"downlink": a.Downlink},
				"downlink must be a BitRate such as \"200 Mbps\" (TS 29.571 §5.5.2), got %q", a.Downlink)
		}
	}
	return a, nil
}

func (t sliceAMBRTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSliceAMBR(in)
	if perr != nil {
		return nil, perr
	}
	current, err := t.d.Portal.Get(ctx, "/slices/qos", nil)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("slice_session_ambr_set plan: %w", err), nil)
	}
	return map[string]any{
		"sst": a.SST, "sd": a.SD, "dnn": a.DNN,
		"requested":         map[string]any{"uplink": a.Uplink, "downlink": a.Downlink, "revert": a.Revert},
		"apply_to_active":   a.Apply,
		"current_slice_qos": json.RawMessage(current),
	}, nil
}

func (t sliceAMBRTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSliceAMBR(in)
	if perr != nil {
		return nil, perr
	}
	var status int
	var body json.RawMessage
	var err error
	if a.Revert {
		body, status, err = t.d.Portal.Send(ctx, "DELETE", a.path(), nil)
	} else {
		body, status, err = t.d.Portal.Send(ctx, "PUT", a.path(),
			map[string]any{"sessionAmbr": map[string]string{"uplink": a.Uplink, "downlink": a.Downlink}})
	}
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("slice_session_ambr_set: %w", err), nil)
	}
	if status < 200 || status > 299 {
		return nil, portalError("slice_session_ambr_set", status, body)
	}
	out := map[string]any{"stored": true, "result": body}
	if a.Revert {
		out["stored"] = false
		out["reverted"] = true
	}
	if a.Apply {
		applied, st, err := t.d.Portal.Send(ctx, "POST", a.path()+"/apply",
			map[string]any{"include_overridden": false})
		if err != nil {
			return nil, mcperr.ToolError(fmt.Errorf("slice_session_ambr_set apply: %w", err), nil)
		}
		if st < 200 || st > 299 {
			return nil, portalError("slice_session_ambr_set apply", st, applied)
		}
		out["applied_to_active"] = applied
	}
	return out, nil
}

// ---- rfsp_override_set ------------------------------------------------------

type rfspTool struct{ d Deps }

func (rfspTool) Name() string        { return "rfsp_override_set" }
func (rfspTool) Risk() registry.Risk { return registry.Disruptive }
func (rfspTool) Description() string {
	return "Set the RFSP index override of a subscriber (1-256), or clear it. The portal applies it by " +
		"deregistering the UE, so it re-registers with the new index. The dry-run says so. " +
		"Spec: TS 38.413 §9.3.1.27 (RFSP index), TS 23.501 §5.3.3.4.3."
}
func (rfspTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"supi":{"type":"string"},
"rfsp":{"type":"integer","description":"RFSP index 1-256"},
"clear":{"type":"boolean","description":"remove the override instead of setting it"}},"required":["supi"]}`)
}
func (rfspTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func parseRFSP(in json.RawMessage) (string, int, bool, *mcperr.Error) {
	var a struct {
		SUPI  string `json:"supi"`
		RFSP  int    `json:"rfsp"`
		Clear bool   `json:"clear"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return "", 0, false, mcperr.Newf(mcperr.CodeInvalidParams, nil, "rfsp_override_set args: %v", err)
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return "", 0, false, perr
	}
	if !a.Clear && (a.RFSP < 1 || a.RFSP > 256) {
		return "", 0, false, mcperr.Newf(mcperr.CodeInvalidParams, nil, "rfsp must be 1-256, got %d", a.RFSP)
	}
	return a.SUPI, a.RFSP, a.Clear, nil
}

func (t rfspTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	supi, rfsp, clear, perr := parseRFSP(in)
	if perr != nil {
		return nil, perr
	}
	current, err := t.d.Portal.Get(ctx, "/subscribers/"+url.PathEscape(supi)+"/rfsp", nil)
	if err != nil {
		current = json.RawMessage(`null`)
	}
	return map[string]any{
		"supi": supi, "rfsp": rfsp, "clear": clear,
		"current_override": json.RawMessage(current),
		"effect":           "the UE is deregistered so it re-registers with the new RFSP index",
	}, nil
}

func (t rfspTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	supi, rfsp, clear, perr := parseRFSP(in)
	if perr != nil {
		return nil, perr
	}
	p := "/subscribers/" + url.PathEscape(supi) + "/rfsp"
	var body json.RawMessage
	var status int
	var err error
	if clear {
		body, status, err = t.d.Portal.Send(ctx, "DELETE", p, nil)
	} else {
		body, status, err = t.d.Portal.Send(ctx, "PUT", p, map[string]int{"rfsp": rfsp})
	}
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("rfsp_override_set: %w", err), nil)
	}
	if status < 200 || status > 299 {
		return nil, portalError("rfsp_override_set", status, body)
	}
	return map[string]any{"supi": supi, "clear": clear, "rfsp": rfsp, "result": body}, nil
}

// ---- ursp_template_apply ----------------------------------------------------

type ursTemplateTool struct{ d Deps }

func (ursTemplateTool) Name() string        { return "ursp_template_apply" }
func (ursTemplateTool) Risk() registry.Risk { return registry.Disruptive }
func (ursTemplateTool) Description() string {
	return "Apply a stored URSP policy template to one subscriber. The template is written to the subscriber's " +
		"policy and pushed to the UE with a UE Configuration Update (deferred if the UE is CM-IDLE). " +
		"Spec: TS 24.526 (URSP), TS 23.503 §6.6.2."
}
func (ursTemplateTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"template_id":{"type":"string","description":"policy template id, from config_view"},
"supi":{"type":"string"}},"required":["template_id","supi"]}`)
}
func (ursTemplateTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func parseTemplate(in json.RawMessage) (string, string, *mcperr.Error) {
	var a struct {
		ID   string `json:"template_id"`
		SUPI string `json:"supi"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return "", "", mcperr.Newf(mcperr.CodeInvalidParams, nil, "ursp_template_apply args: %v", err)
	}
	if a.ID == "" || strings.ContainsAny(a.ID, "/?# ") {
		return "", "", mcperr.Newf(mcperr.CodeInvalidParams, nil, "template_id is required and must not contain / ? # or spaces")
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return "", "", perr
	}
	return a.ID, a.SUPI, nil
}

func (t ursTemplateTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	id, supi, perr := parseTemplate(in)
	if perr != nil {
		return nil, perr
	}
	// The planner reads the store: a store that is down refuses the call.
	if perr := t.d.Portal.RequireStore(ctx); perr != nil {
		return nil, perr
	}
	tpl, err := t.d.Portal.Get(ctx, "/policy-templates/"+url.PathEscape(id), nil)
	if err != nil {
		if mapped, ok := clients.StoreErr(err).(*mcperr.Error); ok {
			return nil, mapped
		}
		return nil, mcperr.ToolError(fmt.Errorf("ursp_template_apply plan: %w", err), nil)
	}
	return map[string]any{"template_id": id, "supi": supi, "template": json.RawMessage(tpl),
		"effect": "subscriber policy replaced; UE Configuration Update carries the URSP"}, nil
}

func (t ursTemplateTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	id, supi, perr := parseTemplate(in)
	if perr != nil {
		return nil, perr
	}
	if perr := t.d.Portal.RequireStore(ctx); perr != nil {
		return nil, perr
	}
	body, status, err := t.d.Portal.Send(ctx, "POST", "/policy-templates/"+url.PathEscape(id)+"/apply",
		map[string]string{"supi": supi})
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ursp_template_apply: %w", err), nil)
	}
	if status == http.StatusServiceUnavailable {
		return nil, clients.StoreUnavailableError()
	}
	if status < 200 || status > 299 {
		return nil, portalError("ursp_template_apply", status, body)
	}
	return map[string]any{"applied": true, "template_id": id, "supi": supi, "result": body}, nil
}

// ---- nf_service_control -----------------------------------------------------

type serviceControlTool struct{ d Deps }

func (serviceControlTool) Name() string        { return "nf_service_control" }
func (serviceControlTool) Risk() registry.Risk { return registry.Admin }
func (serviceControlTool) Description() string {
	return "Start, stop or restart an NF container through the portal. Admin only: needs access_mode lab, " +
		"allow_service_control true and an admin token. Stopping or restarting postgres, redis, nrf, " +
		"mgmt-portal or mcp needs force:true. The name must be a service the portal lists."
}
func (serviceControlTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"name":{"type":"string","description":"service name, e.g. smf"},
"action":{"type":"string","enum":["start","stop","restart"]},
"force":{"type":"boolean","description":"required to act on postgres, redis, nrf, mgmt-portal or mcp"}},"required":["name","action"]}`)
}
func (serviceControlTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func parseService(in json.RawMessage) (string, string, bool, *mcperr.Error) {
	var a struct {
		Name   string `json:"name"`
		Action string `json:"action"`
		Force  bool   `json:"force"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return "", "", false, mcperr.Newf(mcperr.CodeInvalidParams, nil, "nf_service_control args: %v", err)
	}
	if !nameOK(a.Name) {
		return "", "", false, mcperr.Newf(mcperr.CodeInvalidParams, nil, "name must be a container name, got %q", a.Name)
	}
	switch a.Action {
	case "start", "stop", "restart":
	default:
		return "", "", false, mcperr.Newf(mcperr.CodeInvalidParams, nil, "action must be start|stop|restart, got %q", a.Action)
	}
	return a.Name, a.Action, a.Force, nil
}

func nameOK(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789-_", c) {
			return false
		}
	}
	return true
}

// checkService applies the guards that hold in every mode: the config flag, the
// protected list, and the portal's own service list.
func (t serviceControlTool) checkService(ctx context.Context, name, action string, force bool) *mcperr.Error {
	if !t.d.AllowServiceControl {
		return mcperr.New(mcperr.CodeToolError,
			"nf_service_control is disabled: set allow_service_control: true in the MCP config", nil)
	}
	if protectedServices[name] && !force && action != "start" {
		return mcperr.Newf(mcperr.CodeToolError, map[string]any{"service": name},
			"%s is a protected service: pass force:true to %s it", name, action)
	}
	raw, err := t.d.Portal.Get(ctx, "/services", nil)
	if err != nil {
		return mcperr.ToolError(fmt.Errorf("nf_service_control: list services: %w", err), nil)
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return mcperr.ToolError(fmt.Errorf("nf_service_control: decode services: %w", err), nil)
	}
	for _, s := range list {
		if s.Name == name {
			return nil
		}
	}
	return mcperr.Newf(mcperr.CodeToolError, map[string]any{"service": name},
		"%s is not a service the portal lists", name)
}

func (t serviceControlTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	name, action, force, perr := parseService(in)
	if perr != nil {
		return nil, perr
	}
	if perr := t.checkService(ctx, name, action, force); perr != nil {
		return nil, perr
	}
	return map[string]any{"service": name, "action": action, "force": force,
		"effect": "the container is " + action + "ed; dependent NFs reconnect when it is back"}, nil
}

func (t serviceControlTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	name, action, force, perr := parseService(in)
	if perr != nil {
		return nil, perr
	}
	if perr := t.checkService(ctx, name, action, force); perr != nil {
		return nil, perr
	}
	body, status, err := t.d.Portal.Send(ctx, "POST", "/services/"+name+"/"+action, nil)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nf_service_control: %w", err), nil)
	}
	if status < 200 || status > 299 {
		return nil, portalError("nf_service_control", status, body)
	}
	return map[string]any{"service": name, "action": action, "result": body}, nil
}

// ---- mcp_audit_log ----------------------------------------------------------

type auditLogTool struct{ d Deps }

func (auditLogTool) Name() string        { return "mcp_audit_log" }
func (auditLogTool) Risk() registry.Risk { return registry.ReadOnly }
func (auditLogTool) Description() string {
	return "The newest audit entries of this MCP server: every state-changing call with its tool, risk, " +
		"role, session, outcome (executed, failed, dry_run or refused) and input hash. Inputs are never " +
		"logged in clear. Kept in memory (audit_size entries)."
}
func (auditLogTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"n":{"type":"integer","description":"newest entries to return, 1-256 (default 50)"}}}`)
}
func (auditLogTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"entries":{"type":"array"}}}`)
}

func (t auditLogTool) Invoke(_ context.Context, in json.RawMessage) (any, error) {
	var a struct {
		N int `json:"n"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "mcp_audit_log args: %v", err)
	}
	if a.N == 0 {
		a.N = 50
	}
	if a.N < 1 || a.N > 256 {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "n must be 1-256, got %d", a.N)
	}
	return map[string]any{"entries": t.d.Guard.Audit().Recent(a.N)}, nil
}

// portalError maps a non-2xx portal reply to a tool error with its status.
func portalError(tool string, status int, body json.RawMessage) *mcperr.Error {
	return mcperr.Newf(mcperr.CodeToolError, map[string]any{"status": status},
		"%s: portal returned %d: %s", tool, status, body)
}

// ---- nf_log_level -----------------------------------------------------------

type logLevelTool struct{ d Deps }

func (logLevelTool) Name() string        { return "nf_log_level" }
func (logLevelTool) Risk() registry.Risk { return registry.Mutating }

// RiskFor: reading the level (no level argument) changes nothing; setting it is
// Mutating. Changes revert on their own after ttl_s.
func (logLevelTool) RiskFor(in json.RawMessage) registry.Risk {
	var a struct {
		Level string `json:"level"`
	}
	_ = json.Unmarshal(in, &a)
	if a.Level == "" {
		return registry.ReadOnly
	}
	return registry.Mutating
}

func (logLevelTool) Description() string {
	return "Read or change the log level of a running NF without a restart. Without level it returns the " +
		"current level; with level (debug|info|warn|error) it sets the level for ttl_s seconds (default 900, " +
		"max 3600), after which the NF reverts to its startup level. The endpoint is internal (the NF's " +
		"metrics port); the NF is found from its Prometheus scrape target."
}
func (logLevelTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"nf":{"type":"string","description":"NF name as Prometheus labels it, e.g. AMF"},
"level":{"type":"string","enum":["debug","info","warn","error"],"description":"omit to read the current level"},
"ttl_s":{"type":"integer","description":"seconds before the level reverts, 1-3600 (default 900)"}},"required":["nf"]}`)
}
func (logLevelTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

var (
	nfLabelRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{1,31}$`)
	logLevelSet = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
)

func (t logLevelTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		NF    string `json:"nf"`
		Level string `json:"level"`
		TTLs  int    `json:"ttl_s"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "nf_log_level args: %v", err)
	}
	if !nfLabelRe.MatchString(a.NF) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "nf must be a NF name such as AMF, got %q", a.NF)
	}
	if a.Level != "" && !logLevelSet[a.Level] {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "level must be debug|info|warn|error, got %q", a.Level)
	}
	if a.TTLs != 0 && (a.TTLs < 1 || a.TTLs > 3600) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ttl_s must be 1-3600, got %d", a.TTLs)
	}
	addr, err := t.d.targets().Addr(ctx, a.NF)
	if err != nil {
		if errors.Is(err, clients.ErrNoTarget) {
			return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"nf": a.NF},
				"no Prometheus scrape target for NF %s: it is not running or not scraped", a.NF)
		}
		return nil, mcperr.ToolError(fmt.Errorf("nf_log_level: find %s: %w", a.NF, err), nil)
	}
	target := "http://" + addr + "/admin/v1/log-level"

	method := http.MethodGet
	var body io.Reader
	if a.Level != "" {
		method = http.MethodPut
		payload := map[string]any{"level": a.Level}
		if a.TTLs != 0 {
			payload["ttl_s"] = a.TTLs
		}
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nf_log_level: build request: %w", err), nil)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := t.d.HTTP.Do(req)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nf_log_level: %s: %w", a.NF, err), nil)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"status": resp.StatusCode},
			"nf_log_level: %s returned %d: %s", a.NF, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var state json.RawMessage
	if json.Unmarshal(raw, &state) != nil {
		state = json.RawMessage(`null`)
	}
	return map[string]any{"nf": a.NF, "endpoint": target, "state": state}, nil
}
