package runtimecfg

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// Bounds of the AMF timers the tool accepts. They mirror the AMF endpoint, so a
// value the tool lets through is one the AMF accepts.
const (
	// minT3512Secs is the lab lower bound of T3512. The TS default is 54 min
	// (TS 24.501 §10.2 Table 10.2.1).
	minT3512Secs = 60
	// maxT3512Secs caps T3512 at 24 h (project choice; GPRS timer 3 reaches further).
	maxT3512Secs = 86400
	// minGuardSecs and maxGuardSecs bound the guard added to T3512 to get the mobile
	// reachable timer (TS 24.501 §5.3.7: by default 4 min longer than T3512).
	minGuardSecs = 0
	maxGuardSecs = 3600
	// minImplicitDetachSecs and maxImplicitDetachSecs bound the implicit
	// de-registration timer, which is network dependent (TS 24.501 §5.3.7).
	minImplicitDetachSecs = 60
	maxImplicitDetachSecs = 86400
)

// timerAppliesTo says when a change takes effect (TS 24.501 §5.3.7).
const timerAppliesTo = "Registration Accepts sent after the change; running timers keep their value"

// gprsTimer3Units are the GPRS timer 3 units (TS 24.008 §10.5.7.4a) that the AMF
// encoder shared/nas.EncodeGPRSTimer3 uses to encode a value exactly: 1 h, 10 min,
// 1 min, 30 s and 2 s, each with a value of 1..31. The 10 h and 320 h units are
// never produced by the encoder, so they are not accepted.
var gprsTimer3Units = []int{2, 30, 60, 600, 3600}

const gprsTimer3MaxValue = 31

// t3512Representable reports whether secs is v*unit for one encoder unit, v in 1..31.
func t3512Representable(secs int) bool {
	for _, u := range gprsTimer3Units {
		if secs%u == 0 && secs/u >= 1 && secs/u <= gprsTimer3MaxValue {
			return true
		}
	}
	return false
}

// t3512Neighbours returns the closest representable values below and above secs
// inside the T3512 bounds (0 when there is none).
func t3512Neighbours(secs int) (lower, higher int) {
	var all []int
	for _, u := range gprsTimer3Units {
		for v := 1; v <= gprsTimer3MaxValue; v++ {
			if x := u * v; x >= minT3512Secs && x <= maxT3512Secs {
				all = append(all, x)
			}
		}
	}
	sort.Ints(all)
	for _, x := range all {
		if x < secs {
			lower = x
		}
		if x > secs {
			return lower, x
		}
	}
	return lower, 0
}

type timerConfigTool struct{ d Deps }

func (timerConfigTool) Name() string        { return "amf_timer_config" }
func (timerConfigTool) Risk() registry.Risk { return registry.Mutating }

// timerValueKeys are the keys that make a call a change.
var timerValueKeys = []string{"t3512_secs", "mobile_reachable_guard_secs", "implicit_detach_secs"}

// RiskFor: without values and reset the call is a GET (ReadOnly); with any value
// key, or reset:true, it is a PUT (Mutating). A value key present but malformed
// still counts as a change, so the guard errs on the safe side.
func (timerConfigTool) RiskFor(in json.RawMessage) registry.Risk {
	var m map[string]json.RawMessage
	if json.Unmarshal(in, &m) != nil {
		return registry.ReadOnly
	}
	for _, k := range timerValueKeys {
		if _, ok := m[k]; ok {
			return registry.Mutating
		}
	}
	if raw, ok := m["reset"]; ok && strings.TrimSpace(string(raw)) != "false" {
		return registry.Mutating
	}
	return registry.ReadOnly
}

func (timerConfigTool) Description() string {
	return "Read or change the AMF NAS timers at runtime, without a restart. Without arguments it reads the effective " +
		"and base values. With t3512_secs (periodic registration update timer, 60-86400 s, exactly representable " +
		"in GPRS timer 3: a multiple of 2 s up to 62 s, 30 s up to 930 s, 1 min up to 31 min, 10 min up to 310 min " +
		"or 1 h up to 31 h), mobile_reachable_guard_secs (0-3600) and/or implicit_detach_secs (60-86400) it changes " +
		"them; reset:true restores the YAML base values. Mobile reachable = T3512 + guard. The change is runtime " +
		"only (persisted:false) and is lost on an AMF restart. A UE learns the new T3512 only in its next " +
		"Registration Accept, and timers already running keep their value. When T3512 is lowered, the AMF arms " +
		"the mobile reachable timer from max(T3512 sent to the UE, effective T3512) so a UE that holds the older, " +
		"longer T3512 is not implicitly de-registered early. " +
		"mobile_reachable_guard_secs 0 is a lab-only setting: TS 24.501 §5.3.7 says the mobile reachable timer is longer than T3512, keep the guard >= 1 in operation. " +
		"Spec: TS 24.501 §5.3.7; T3512 is in §10.2 Table 10.2.1, the AMF-side mobile reachable and implicit de-registration timers are in Table 10.2.2; TS 23.501 §5.4.1.1."
}

func (timerConfigTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"t3512_secs":{"type":"integer","minimum":60,"maximum":86400,"description":"T3512 in seconds; must be exactly representable in GPRS timer 3 (e.g. 120, 600, 1800, 3600)"},
"mobile_reachable_guard_secs":{"type":"integer","minimum":0,"maximum":3600,"description":"guard added to T3512 to get the mobile reachable timer"},
"implicit_detach_secs":{"type":"integer","minimum":60,"maximum":86400,"description":"implicit de-registration timer"},
"reset":{"type":"boolean","description":"restore the YAML base values; cannot be combined with values"}},
"additionalProperties":false}`)
}
func (timerConfigTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"effective":{"type":"object"},"base":{"type":"object"},"applies_to":{"type":"string"},"persisted":{"type":"boolean"}}}`)
}

type timerRequest struct {
	values map[string]int
	reset  bool
}

func (r timerRequest) isChange() bool { return r.reset || len(r.values) > 0 }

func timerBounds(key string) (lo, hi int) {
	switch key {
	case "t3512_secs":
		return minT3512Secs, maxT3512Secs
	case "mobile_reachable_guard_secs":
		return minGuardSecs, maxGuardSecs
	default:
		return minImplicitDetachSecs, maxImplicitDetachSecs
	}
}

func parseTimerArgs(in json.RawMessage) (timerRequest, *mcperr.Error) {
	req := timerRequest{values: map[string]int{}}
	var m map[string]json.RawMessage
	if len(in) > 0 {
		if err := json.Unmarshal(in, &m); err != nil {
			return req, mcperr.Newf(mcperr.CodeInvalidParams, nil, "amf_timer_config args: %v", err)
		}
	}
	for k, raw := range m {
		switch k {
		case "confirm":
		case "reset":
			if err := json.Unmarshal(raw, &req.reset); err != nil {
				return req, mcperr.Newf(mcperr.CodeInvalidParams, nil, "reset must be a boolean")
			}
		case "t3512_secs", "mobile_reachable_guard_secs", "implicit_detach_secs":
			v, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil {
				return req, mcperr.Newf(mcperr.CodeInvalidParams, nil, "%s must be an integer number of seconds", k)
			}
			lo, hi := timerBounds(k)
			if v < lo || v > hi {
				return req, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"min": lo, "max": hi},
					"%s must be %d-%d seconds, got %d", k, lo, hi, v)
			}
			req.values[k] = v
		default:
			return req, mcperr.Newf(mcperr.CodeInvalidParams, nil,
				"unknown argument %q: allowed are t3512_secs, mobile_reachable_guard_secs, implicit_detach_secs, reset", k)
		}
	}
	if req.reset && len(req.values) > 0 {
		return req, mcperr.New(mcperr.CodeInvalidParams, "reset cannot be combined with timer values", nil)
	}
	if v, ok := req.values["t3512_secs"]; ok && !t3512Representable(v) {
		lo, hi := t3512Neighbours(v)
		return req, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"nearest_lower": lo, "nearest_higher": hi},
			"t3512_secs %d is not exactly representable in GPRS timer 3 (TS 24.008 §10.5.7.4a); nearest values are %d and %d",
			v, lo, hi)
	}
	return req, nil
}

func (t timerConfigTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	req, perr := parseTimerArgs(in)
	if perr != nil {
		return nil, perr
	}
	method := "GET"
	var status int
	var body []byte
	var err error
	if req.isChange() {
		method = "PUT"
		payload := map[string]any{}
		if req.reset {
			payload["reset"] = true
		}
		for k, v := range req.values {
			payload[k] = v
		}
		status, body, err = t.d.AMF.PutTimerConfig(ctx, payload)
	} else {
		status, body, err = t.d.AMF.GetTimerConfig(ctx)
	}
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("amf_timer_config: %w", err), nil)
	}
	if status < 200 || status > 299 {
		return nil, amfTimerError(method, status, body)
	}
	out := map[string]any{}
	if json.Unmarshal(body, &out) != nil || out == nil {
		out = map[string]any{"raw": strings.TrimSpace(string(body))}
	}
	out["applies_to"] = timerAppliesTo
	out["persisted"] = false
	out["spec_ref"] = "TS 24.501 §5.3.7, §10.2 Table 10.2.1; TS 23.501 §5.4.1.1"
	if method == "PUT" {
		slog.InfoContext(ctx, "AMF timer config changed",
			"nf", "MCP", "procedure", "AmfTimerConfig", "interface", "OAM", "direction", "OUT",
			"spec_ref", "TS 24.501 §5.3.7, §10.2 Table 10.2.1", "tool_name", "amf_timer_config",
			"reset", req.reset, "result", "OK")
	}
	return out, nil
}

// amfTimerError maps a non-2xx AMF reply to a tool error that carries the status
// and, when the body is application/problem+json, its cause and detail.
func amfTimerError(method string, status int, body []byte) *mcperr.Error {
	var p struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
		Cause  string `json:"cause"`
	}
	data := map[string]any{"status": status}
	msg := fmt.Sprintf("amf_timer_config: AMF %s %s returned %d", method, clients.TimerConfigPath, status)
	if json.Unmarshal(body, &p) == nil {
		if p.Cause != "" {
			data["cause"] = p.Cause
			msg += " cause " + p.Cause
		}
		if p.Detail != "" {
			msg += ": " + p.Detail
		} else if p.Title != "" {
			msg += ": " + p.Title
		}
	}
	return mcperr.New(mcperr.CodeToolError, msg, data)
}
