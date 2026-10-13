// Package ue implements the UE context tools: introspection of the AMF's UE
// contexts through the AMF management API. Reference: 3GPP TS 23.502 / TS 24.501.
package ue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

// All returns the UE context tools bound to an AMF client: ue_list, ue_context_get,
// ran_gnb_list, and the deprecated gmm_state_get alias of ue_context_get.
func All(amf *clients.AMF) []registry.Tool {
	get := getTool{amf}
	return []registry.Tool{
		listTool{amf},
		get,
		ranGNBListTool{amf},
		toolutil.Deprecated("gmm_state_get", supiSchema, get, passThrough),
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

var supiSchema = schema(`{"type":"object","properties":{"supi":{"type":"string","description":"e.g. imsi-001010000000001"}},"required":["supi"]}`)

// passThrough is used by an alias whose arguments carry over unchanged.
func passThrough(in json.RawMessage) (json.RawMessage, error) { return in, nil }

// ---- ue_list --------------------------------------------------------------

type listTool struct{ amf *clients.AMF }

func (listTool) Name() string        { return "ue_list" }
func (listTool) Risk() registry.Risk { return registry.ReadOnly }
func (listTool) Description() string {
	return "List the UE contexts held by the AMF: SUPI, GUTI, 5GMM state, CM state and last activity. " +
		"pdu_session_ids is an int array and an unset registration_time is null. " +
		"The AMF reports 5GMM-REGISTERED, 5GMM-DEREGISTERED, ... and CM-CONNECTED, CM-IDLE. " +
		"Optional gmm_state and cm_state filters (case-insensitive; the 5GMM- / CM- prefix is optional, " +
		"so REGISTERED and 5GMM-REGISTERED are equivalent). " +
		"Per 3GPP TS 23.502 (registration management)."
}
func (listTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"gmm_state":{"type":"string","description":"Only UEs in this 5GMM state: 5GMM-REGISTERED or 5GMM-DEREGISTERED (prefix optional)."},
"cm_state":{"type":"string","description":"Only UEs in this CM state: CM-CONNECTED or CM-IDLE (prefix optional)."}}}`)
}
func (listTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"count":{"type":"integer"},"ue_contexts":{"type":"array","items":{"type":"object"}}}}`)
}

func (t listTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		GMMState string `json:"gmm_state"`
		CMState  string `json:"cm_state"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ue_list args: %v", err)
	}
	raw, err := t.amf.ListContexts(ctx)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_list: %w", err), nil)
	}
	var all []json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_list: decode AMF list: %w", err), nil)
	}
	out := make([]json.RawMessage, 0, len(all))
	for _, item := range all {
		var s struct {
			GMMState string `json:"gmm_state"`
			CMState  string `json:"cm_state"`
		}
		if err := json.Unmarshal(item, &s); err != nil {
			continue
		}
		if a.GMMState != "" && bareState(s.GMMState, "5GMM-") != bareState(a.GMMState, "5GMM-") {
			continue
		}
		if a.CMState != "" && bareState(s.CMState, "CM-") != bareState(a.CMState, "CM-") {
			continue
		}
		out = append(out, normalize(item))
	}
	return map[string]any{"count": len(out), "ue_contexts": out}, nil
}

// bareState upper-cases a state name and strips the given prefix, so the AMF's
// "5GMM-REGISTERED" / "CM-IDLE" and the bare "REGISTERED" / "IDLE" compare equal.
func bareState(s, prefix string) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), prefix)
}

// ---- ue_context_get -------------------------------------------------------

type getTool struct{ amf *clients.AMF }

func (getTool) Name() string        { return "ue_context_get" }
func (getTool) Risk() registry.Risk { return registry.ReadOnly }
func (getTool) Description() string {
	return "Retrieve the full UE context for a SUPI, or for a 5G-GUTI (the guti string exactly as ue_list " +
		"shows it): identifiers, 5GMM/CM state, PDU sessions and timestamps. Per 3GPP TS 23.502."
}
func (getTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"supi":{"type":"string","description":"e.g. imsi-001010000000001"},
"guti":{"type":"string","description":"5G-GUTI as reported by ue_list, e.g. mcc=001 mnc=01 amf=01 set=1 id=01 tmsi=00000001"}}}`)
}
func (getTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object"}`)
}

func (t getTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
		GUTI string `json:"guti"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ue_context_get args: %v", err)
	}
	if (a.SUPI == "") == (a.GUTI == "") {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "exactly one of supi or guti is required", nil)
	}
	supi := a.SUPI
	if supi == "" {
		resolved, err := t.resolveGUTI(ctx, a.GUTI)
		if err != nil {
			return nil, err
		}
		supi = resolved
	}
	if perr := toolutil.ValidSUPI(supi); perr != nil {
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
	return normalize(raw), nil
}

// zeroTime is Go's zero time.Time as the AMF serialises an unset timestamp.
const zeroTime = "0001-01-01T00:00:00Z"

// normalize cleans the two AMF snapshot quirks in one UE object: pdu_session_ids
// arrives as a base64 string (Go marshals []uint8 that way) and is returned as an
// int array; an unset registration_time (Go zero time) is returned as null.
// Input that is not a JSON object is returned unchanged.
func normalize(raw json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return raw
	}
	if v, ok := obj["pdu_session_ids"]; ok {
		if ids, ok := ParsePSIs(v); ok {
			valid, invalid := splitPSIs(ids)
			b, _ := json.Marshal(valid)
			obj["pdu_session_ids"] = b
			if len(invalid) > 0 {
				ib, _ := json.Marshal(invalid)
				obj["pdu_session_ids_invalid"] = ib
			}
		}
	}
	if v, ok := obj["registration_time"]; ok {
		var ts *string
		if json.Unmarshal(v, &ts) == nil && (ts == nil || *ts == "" || isZeroTime(*ts)) {
			obj["registration_time"] = json.RawMessage("null")
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return out
}

// isZeroTime reports whether an RFC 3339 timestamp is the zero time.
func isZeroTime(s string) bool {
	if s == zeroTime {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && t.IsZero()
}

// splitPSIs separates PDU session IDs in the TS 24.007 §11.2.3.1b range 1-15
// from out-of-range values, which are reported rather than shown as sessions.
func splitPSIs(ids []int) (valid, invalid []int) {
	valid = []int{}
	for _, id := range ids {
		if toolutil.ValidPSI(id) != nil {
			invalid = append(invalid, id)
			continue
		}
		valid = append(valid, id)
	}
	return valid, invalid
}

// ParsePSIs reads pdu_session_ids as a base64 string (one byte per PSI) or as an
// int array. null and "" give an empty list. ok is false for any other shape.
func ParsePSIs(v json.RawMessage) (ids []int, ok bool) {
	ids = []int{}
	if string(v) == "null" {
		return ids, true
	}
	var str string
	if json.Unmarshal(v, &str) == nil {
		if strings.TrimSpace(str) == "" {
			return ids, true
		}
		b, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, false
		}
		for _, c := range b {
			ids = append(ids, int(c))
		}
		return ids, true
	}
	var arr []int
	if json.Unmarshal(v, &arr) == nil {
		if arr == nil {
			arr = []int{}
		}
		return arr, true
	}
	return nil, false
}

// resolveGUTI maps a 5G-GUTI to its SUPI by scanning the AMF list. The AMF has
// no GUTI index in its management API, so the list is the source of truth.
func (t getTool) resolveGUTI(ctx context.Context, guti string) (string, *mcperr.Error) {
	raw, err := t.amf.ListContexts(ctx)
	if err != nil {
		return "", mcperr.ToolError(fmt.Errorf("ue_context_get: resolve guti: %w", err), nil)
	}
	var all []struct {
		SUPI string `json:"supi"`
		GUTI string `json:"guti"`
	}
	if err := json.Unmarshal(raw, &all); err != nil {
		return "", mcperr.ToolError(fmt.Errorf("ue_context_get: decode AMF list: %w", err), nil)
	}
	for _, u := range all {
		if u.GUTI == guti {
			return u.SUPI, nil
		}
	}
	return "", mcperr.Newf(mcperr.CodeToolError, map[string]any{"guti": guti},
		"no UE context holds GUTI %q", guti)
}
