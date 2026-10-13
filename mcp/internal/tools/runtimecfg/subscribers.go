package runtimecfg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

// Subscriber provisioning tools: subscriber_profile_update, subscriber_provision,
// subscriber_delete. They talk to the portal subscriber API. The long-term keys
// K and OPc (TS 33.501 §6.2.1 (K); TS 35.206 (OPc)) are never returned, logged, put in an error or in
// the audit hash preimage: the tools that receive them implement registry.Redactor
// and every error text is built without them.

const (
	// maxProfileSlices bounds the slices list of one subscriber profile.
	maxProfileSlices = 8
	// subscriberSpecRef is the spec reference of the subscription data these tools edit.
	subscriberSpecRef = "TS 23.502 §4.2.2.3.3; TS 29.505 (subscription data)"
)

var (
	hex32Re = regexp.MustCompile(`^[0-9a-fA-F]{32}$`) // K, OPc: 128 bits (TS 33.501 §6.2.1 (K); TS 35.206 (OPc))
	hex12Re = regexp.MustCompile(`^[0-9a-fA-F]{12}$`) // SQN: 48 bits (TS 33.102 §6.3)
	hex4Re  = regexp.MustCompile(`^[0-9a-fA-F]{4}$`)  // AMF: 16 bits (TS 33.102 §6.3)
)

// secretKeys are the argument names the Redactor strips from audit hashes.
var secretKeys = []string{"k", "opc", "op", "sqn"}

// keyFieldNames may not be set through subscriber_profile_update at all.
var keyFieldNames = map[string]bool{"k": true, "opc": true, "op": true, "sqn": true, "amf": true, "supi": true}

// bitRateKbpsRe is the TS 29.571 §5.5.2 BitRate pattern: "<number>[.<frac>] <unit>".
var bitRateKbpsRe = regexp.MustCompile(`^([0-9]+)(?:\.([0-9]{1,12}))? (bps|Kbps|Mbps|Gbps|Tbps)$`)

// bitRateUnitBps maps a TS 29.571 §5.5.2 BitRate unit to bits per second. The
// spec uses SI decimal multiples: 1 Kbps = 1000 bps.
var bitRateUnitBps = map[string]int64{
	"bps": 1, "Kbps": 1e3, "Mbps": 1e6, "Gbps": 1e9, "Tbps": 1e12,
}

// bitRateToKbps converts a TS 29.571 §5.5.2 BitRate string to the integer kbps
// that the portal subscriber record stores (ambr_ul, ambr_dl, UE-AMBR, TS 29.571
// §5.5.2 / TS 23.501 §5.7.2.6). The result must be a whole, non-zero number of
// kbps: "1.5 Mbps" gives 1500, "500 bps", "1.5 Kbps" and "0 Mbps" are errors.
func bitRateToKbps(s string) (uint64, error) {
	m := bitRateKbpsRe.FindStringSubmatch(s)
	if m == nil {
		return 0, errors.New("not a BitRate")
	}
	digits := m[1] + m[2]
	num, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return 0, errors.New("not a BitRate")
	}
	// bps = num * unit / 10^len(frac); kbps = bps / 1000.
	num.Mul(num, big.NewInt(bitRateUnitBps[m[3]]))
	div := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(len(m[2]))+3), nil)
	q, r := new(big.Int).QuoRem(num, div, new(big.Int))
	if r.Sign() != 0 {
		return 0, errors.New("not a whole number of kbps")
	}
	if q.Sign() == 0 {
		return 0, errors.New("must be greater than zero")
	}
	if !q.IsUint64() || q.Uint64() > math.MaxInt64 {
		return 0, errors.New("too large")
	}
	return q.Uint64(), nil
}

// profileSlice is one S-NSSAI and DNN entry of a subscriber record.
type profileSlice struct {
	SST int    `json:"sst"`
	SD  string `json:"sd,omitempty"`
	DNN string `json:"dnn,omitempty"`
}

// profile is the non-key part of a subscriber record that the tools may set.
type profile struct {
	AmbrUL string // BitRate string as received
	AmbrDL string
	ulKbps uint64 // converted by validate, written to the portal record
	dlKbps uint64
	Slices []profileSlice
	hasUL  bool
	hasDL  bool
	hasSl  bool
}

// validate checks a profile and returns -32602 errors that carry no secrets.
func (p *profile) validate() *mcperr.Error {
	if p.hasUL {
		v, err := bitRateToKbps(p.AmbrUL)
		if err != nil {
			return mcperr.Newf(mcperr.CodeInvalidParams, nil,
				"ambr_ul must be a BitRate such as \"100 Mbps\" that is a whole, non-zero number of kbps (TS 29.571 §5.5.2)")
		}
		p.ulKbps = v
	}
	if p.hasDL {
		v, err := bitRateToKbps(p.AmbrDL)
		if err != nil {
			return mcperr.Newf(mcperr.CodeInvalidParams, nil,
				"ambr_dl must be a BitRate such as \"200 Mbps\" that is a whole, non-zero number of kbps (TS 29.571 §5.5.2)")
		}
		p.dlKbps = v
	}
	if p.hasSl {
		if len(p.Slices) < 1 || len(p.Slices) > maxProfileSlices {
			return mcperr.Newf(mcperr.CodeInvalidParams, nil, "slices must hold 1-%d entries", maxProfileSlices)
		}
		for i, s := range p.Slices {
			if s.SST < 0 || s.SST > 255 {
				return mcperr.Newf(mcperr.CodeInvalidParams, nil, "slices[%d].sst must be 0-255", i)
			}
			if s.SD != "" && !hex6Re.MatchString(s.SD) {
				return mcperr.Newf(mcperr.CodeInvalidParams, nil, "slices[%d].sd must be 6 hex digits", i)
			}
			if s.DNN != "" {
				if perr := toolutil.ValidDNN(s.DNN); perr != nil {
					return mcperr.Newf(mcperr.CodeInvalidParams, nil, "slices[%d].dnn is not a valid DNN", i)
				}
			}
		}
	}
	return nil
}

// decodeProfile reads ambr_ul, ambr_dl and slices from a key-to-raw map. Any other
// key is rejected. The caller decides which maps are allowed to hold more keys.
func decodeProfile(m map[string]json.RawMessage, where string) (profile, *mcperr.Error) {
	var p profile
	for k, raw := range m {
		switch k {
		case "ambr_ul":
			if json.Unmarshal(raw, &p.AmbrUL) != nil {
				return p, mcperr.Newf(mcperr.CodeInvalidParams, nil, "%s.ambr_ul must be a string", where)
			}
			p.hasUL = true
		case "ambr_dl":
			if json.Unmarshal(raw, &p.AmbrDL) != nil {
				return p, mcperr.Newf(mcperr.CodeInvalidParams, nil, "%s.ambr_dl must be a string", where)
			}
			p.hasDL = true
		case "slices":
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if dec.Decode(&p.Slices) != nil {
				return p, mcperr.Newf(mcperr.CodeInvalidParams, nil,
					"%s.slices must be a list of {sst, sd, dnn}", where)
			}
			p.hasSl = true
		default:
			if keyFieldNames[strings.ToLower(k)] {
				return p, mcperr.Newf(mcperr.CodeInvalidParams, nil,
					"%s: subscriber keys and identity (k, opc, op, sqn, amf, supi) cannot be set here", where)
			}
			return p, mcperr.Newf(mcperr.CodeInvalidParams, nil,
				"%s: unsupported entry; allowed are ambr_ul, ambr_dl, slices", where)
		}
	}
	perr := p.validate() // sets the converted kbps values; evaluate before returning p
	return p, perr
}

func (p profile) empty() bool { return !p.hasUL && !p.hasDL && !p.hasSl }

// apply merges the profile into a subscriber record map. The portal stores
// ambr_ul and ambr_dl as integer kbps, not as BitRate strings.
func (p profile) apply(rec map[string]any) {
	if p.hasUL {
		rec["ambr_ul"] = p.ulKbps
	}
	if p.hasDL {
		rec["ambr_dl"] = p.dlKbps
	}
	if p.hasSl {
		rec["slices"] = p.Slices
	}
}

// scrub removes every occurrence of the given secrets from s.
func scrub(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, registry.RedactedValue)
		}
	}
	return s
}

// portalFailure builds the -32000 error for a non-2xx portal reply. It names the
// status and a scrubbed, redacted excerpt of the body, never a secret.
func portalFailure(tool string, status int, body json.RawMessage, secrets ...string) *mcperr.Error {
	msg := fmt.Sprintf("%s: portal returned %d", tool, status)
	if t := strings.TrimSpace(string(body)); t != "" && t != "null" {
		msg += ": " + scrub(t, secrets...)
	}
	return mcperr.New(mcperr.CodeToolError, msg, map[string]any{"status": status})
}

// identRe matches an argument name that is safe to echo in an error.
var identRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,40}$`)

// rejectUnknownArgs returns -32602 for any top-level key not in allowed. The guard
// leaves confirm and dry_run in the arguments, so every tool allows them. The error
// names the key only if it is identifier-like and not a secret-looking key.
func rejectUnknownArgs(top map[string]json.RawMessage, allowed ...string) *mcperr.Error {
	ok := map[string]bool{"confirm": true, "dry_run": true}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range top {
		if ok[k] {
			continue
		}
		lk := strings.ToLower(k)
		if keyFieldNames[lk] || !identRe.MatchString(k) {
			return mcperr.New(mcperr.CodeInvalidParams, "unsupported argument", nil)
		}
		return mcperr.Newf(mcperr.CodeInvalidParams, nil, "unsupported argument %q", k)
	}
	return nil
}

// recordSecrets returns the secret field values (k, opc, op, sqn) of a portal record.
func recordSecrets(rec map[string]any) []string {
	var out []string
	for key, v := range rec {
		lk := strings.ToLower(key)
		for _, sk := range secretKeys {
			if lk == sk {
				if sv, ok := v.(string); ok && sv != "" {
					out = append(out, sv)
				}
			}
		}
	}
	return out
}

// errSubscriberExists is the refusal of subscriber_provision for a known SUPI. The
// portal POST is an upsert that would replace K/OPc and rewind SQN, which breaks
// 5G-AKA for a registered UE (TS 33.501 §6.1.3.2; TS 33.102 §6.3.5).
func errSubscriberExists() *mcperr.Error {
	return mcperr.New(mcperr.CodeToolError,
		"subscriber already exists; use subscriber_profile_update for non-key fields, or subscriber_delete first",
		map[string]any{"exists": true})
}

// subscriberExists reads the redacted portal record. A 404 is (false, nil, nil);
// any other failure is an error and the caller must refuse the call.
func subscriberExists(ctx context.Context, d Deps, tool, supi string) (bool, json.RawMessage, error) {
	prev, err := d.Portal.Get(ctx, subscriberPath(supi), nil)
	if err != nil {
		var se *clients.PortalStatusError
		if errors.As(err, &se) && se.Status == http.StatusNotFound {
			return false, nil, nil
		}
		return false, nil, mcperr.ToolError(fmt.Errorf("%s: read subscriber: %w", tool, err), nil)
	}
	return true, prev, nil
}

// subscriberPath is the portal path of one subscriber.
func subscriberPath(supi string) string { return "/subscribers/" + url.PathEscape(supi) }

// ---- subscriber_profile_update ----------------------------------------------

type subscriberProfileUpdateTool struct{ d Deps }

func (subscriberProfileUpdateTool) Name() string        { return "subscriber_profile_update" }
func (subscriberProfileUpdateTool) Risk() registry.Risk { return registry.Disruptive }
func (subscriberProfileUpdateTool) Description() string {
	return "Change the non-key profile of one subscriber: ambr_ul, ambr_dl (BitRate strings such as \"100 Mbps\") " +
		"and/or slices ([{sst, sd, dnn}]). The keys and identity (k, opc, op, sqn, amf) cannot be changed here: " +
		"they are carried through unchanged and never shown. The portal writes the whole record and then deregisters " +
		"the UE, which must re-register (network-initiated deregistration with re-registration required). The " +
		"dry-run shows the redacted current record and the changes. " +
		"Spec: TS 23.502 §4.2.2.3.3, TS 29.505 (subscription data), TS 29.571 §5.5.2."
}
func (subscriberProfileUpdateTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"supi":{"type":"string","description":"e.g. imsi-001010000000001"},
"fields":{"type":"object","properties":{
 "ambr_ul":{"type":"string","description":"subscribed UE-AMBR uplink, BitRate e.g. \"50 Mbps\" (stored as whole kbps)"},
 "ambr_dl":{"type":"string","description":"subscribed UE-AMBR downlink, BitRate e.g. \"100 Mbps\""},
 "slices":{"type":"array","items":{"type":"object","properties":{"sst":{"type":"integer"},"sd":{"type":"string","description":"6 hex digits"},"dnn":{"type":"string"}},"required":["sst"],"additionalProperties":false}}},
 "additionalProperties":false,"minProperties":1}},
"required":["supi","fields"],"additionalProperties":false}`)
}
func (subscriberProfileUpdateTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

// RedactArgs implements registry.Redactor.
func (subscriberProfileUpdateTool) RedactArgs(a json.RawMessage) json.RawMessage {
	return registry.RedactJSONFields(a, secretKeys...)
}

type profileUpdateArgs struct {
	supi string
	prof profile
}

func parseProfileUpdate(in json.RawMessage) (profileUpdateArgs, *mcperr.Error) {
	var out profileUpdateArgs
	var top map[string]json.RawMessage
	if err := json.Unmarshal(in, &top); err != nil {
		return out, mcperr.Newf(mcperr.CodeInvalidParams, nil, "subscriber_profile_update args are not a JSON object")
	}
	for k := range top {
		if keyFieldNames[strings.ToLower(k)] && strings.ToLower(k) != "supi" {
			return out, mcperr.New(mcperr.CodeInvalidParams,
				"subscriber keys (k, opc, op, sqn, amf) cannot be set; use fields with ambr_ul, ambr_dl, slices", nil)
		}
	}
	if perr := rejectUnknownArgs(top, "supi", "fields"); perr != nil {
		return out, perr
	}
	if raw, ok := top["supi"]; ok {
		_ = json.Unmarshal(raw, &out.supi)
	}
	if perr := toolutil.ValidSUPI(out.supi); perr != nil {
		return out, perr
	}
	rawFields, ok := top["fields"]
	if !ok {
		return out, mcperr.New(mcperr.CodeInvalidParams, "fields is required: ambr_ul, ambr_dl and/or slices", nil)
	}
	var fm map[string]json.RawMessage
	if err := json.Unmarshal(rawFields, &fm); err != nil || len(fm) == 0 {
		return out, mcperr.New(mcperr.CodeInvalidParams, "fields must be a non-empty object", nil)
	}
	p, perr := decodeProfile(fm, "fields")
	if perr != nil {
		return out, perr
	}
	out.prof = p
	return out, nil
}

func (t subscriberProfileUpdateTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseProfileUpdate(in)
	if perr != nil {
		return nil, perr
	}
	prev, err := t.d.Portal.Get(ctx, subscriberPath(a.supi), nil)
	if err != nil {
		var se *clients.PortalStatusError
		if errors.As(err, &se) && se.Status == http.StatusNotFound {
			return nil, mcperr.New(mcperr.CodeToolError, "subscriber_profile_update: portal returned 404: subscriber not found",
				map[string]any{"status": http.StatusNotFound})
		}
		return nil, mcperr.ToolError(fmt.Errorf("subscriber_profile_update plan: %w", err), nil)
	}
	var cur map[string]any
	_ = json.Unmarshal(prev, &cur)
	changes := map[string]any{}
	if a.prof.hasUL {
		changes["ambr_ul"] = map[string]any{"from": cur["ambr_ul"], "to": a.prof.ulKbps,
			"to_bitrate": a.prof.AmbrUL, "unit": "kbps"}
	}
	if a.prof.hasDL {
		changes["ambr_dl"] = map[string]any{"from": cur["ambr_dl"], "to": a.prof.dlKbps,
			"to_bitrate": a.prof.AmbrDL, "unit": "kbps"}
	}
	if a.prof.hasSl {
		changes["slices"] = map[string]any{"from": cur["slices"], "to": a.prof.Slices}
	}
	return map[string]any{
		"supi":                    a.supi,
		"previous":                json.RawMessage(prev),
		"changes":                 changes,
		"ue_will_be_deregistered": true,
		"note":                    "the portal deregisters the UE (re-registration required, TS 23.502 §4.2.2.3.3)",
	}, nil
}

func (t subscriberProfileUpdateTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseProfileUpdate(in)
	if perr != nil {
		return nil, perr
	}
	raw, status, err := t.d.Portal.GetUnredacted(ctx, subscriberPath(a.supi))
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("subscriber_profile_update: %w", err), nil)
	}
	if status < 200 || status > 299 {
		// The body of a failed read is not echoed: it is unredacted portal output.
		return nil, portalFailure("subscriber_profile_update", status, nil)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil || rec == nil {
		return nil, mcperr.New(mcperr.CodeToolError, "subscriber_profile_update: portal record is not a JSON object", nil)
	}
	k, _ := rec["k"].(string)
	opc, _ := rec["opc"].(string)
	if k == "" || opc == "" {
		return nil, mcperr.New(mcperr.CodeToolError,
			"subscriber_profile_update: the portal record has no k/opc, the whole-record update cannot be sent", nil)
	}
	secrets := recordSecrets(rec)
	previous, rerr := clients.Redact(raw)
	if rerr != nil {
		return nil, mcperr.New(mcperr.CodeToolError, "subscriber_profile_update: cannot redact the portal record", nil)
	}
	a.prof.apply(rec)
	body, status, err := t.d.Portal.Send(ctx, http.MethodPut, subscriberPath(a.supi), rec)
	if err != nil {
		return nil, mcperr.ToolError(errors.New(scrub(fmt.Sprintf("subscriber_profile_update: %v", err), secrets...)), nil)
	}
	if status < 200 || status > 299 {
		return nil, portalFailure("subscriber_profile_update", status, body, secrets...)
	}
	var resp map[string]any
	_ = json.Unmarshal(body, &resp)
	slog.InfoContext(ctx, "subscriber profile updated",
		"nf", "MCP", "procedure", "SubscriberProfileUpdate", "interface", "portal", "direction", "OUT",
		"spec_ref", subscriberSpecRef, "tool_name", "subscriber_profile_update",
		"supi_hash", toolutil.HashSUPI(a.supi), "result", "OK")
	return map[string]any{
		"updated":        true,
		"supi":           a.supi,
		"deregistered":   resp["deregistered"],
		"sm_data_synced": resp["sm_data_synced"],
		"previous":       previous,
	}, nil
}

// ---- subscriber_provision ---------------------------------------------------

type subscriberProvisionTool struct{ d Deps }

func (subscriberProvisionTool) Name() string        { return "subscriber_provision" }
func (subscriberProvisionTool) Risk() registry.Risk { return registry.Admin }
func (subscriberProvisionTool) Description() string {
	return "Create a NEW subscriber in the UDR through the portal (an existing SUPI is refused, never overwritten): supi, k (32 hex), opc (32 hex), optional sqn (12 hex), " +
		"amf (4 hex) and a profile {ambr_ul, ambr_dl, slices}. The keys are sent to the portal and are never echoed, " +
		"logged or kept in the audit log; the dry-run shows them as <redacted>. subscriber_get shows the new record " +
		"with the keys redacted. Admin only: needs access_mode lab and an admin token. " +
		"Spec: TS 33.501 §6.2.1 (K); TS 35.206 (OPc), TS 33.102 §6.3 (SQN, AMF), TS 29.505 (subscription data)."
}
func (subscriberProvisionTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"supi":{"type":"string","description":"e.g. imsi-001010000000077"},
"k":{"type":"string","description":"permanent key K, 32 hex digits"},
"opc":{"type":"string","description":"operator code OPc, 32 hex digits"},
"sqn":{"type":"string","description":"optional initial SQN, 12 hex digits"},
"amf":{"type":"string","description":"optional authentication management field, 4 hex digits"},
"profile":{"type":"object","properties":{
 "ambr_ul":{"type":"string"},"ambr_dl":{"type":"string"},
 "slices":{"type":"array","items":{"type":"object","properties":{"sst":{"type":"integer"},"sd":{"type":"string"},"dnn":{"type":"string"}},"required":["sst"],"additionalProperties":false}}},
 "additionalProperties":false}},
"required":["supi","k","opc"],"additionalProperties":false}`)
}
func (subscriberProvisionTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

// RedactArgs implements registry.Redactor.
func (subscriberProvisionTool) RedactArgs(a json.RawMessage) json.RawMessage {
	return registry.RedactJSONFields(a, secretKeys...)
}

type provisionArgs struct {
	supi, k, opc, sqn, amf string
	prof                   profile
}

func parseProvision(in json.RawMessage) (provisionArgs, *mcperr.Error) {
	var out provisionArgs
	var top map[string]json.RawMessage
	if err := json.Unmarshal(in, &top); err != nil {
		return out, mcperr.New(mcperr.CodeInvalidParams, "subscriber_provision args are not a JSON object", nil)
	}
	str := func(key string) (string, bool) {
		raw, ok := top[key]
		if !ok {
			return "", false
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return "", true
		}
		return s, true
	}
	if perr := rejectUnknownArgs(top, "supi", "k", "opc", "sqn", "amf", "profile"); perr != nil {
		return out, perr
	}
	out.supi, _ = str("supi")
	if perr := toolutil.ValidSUPI(out.supi); perr != nil {
		return out, perr
	}
	// Error texts below never include the received values.
	out.k, _ = str("k")
	if !hex32Re.MatchString(out.k) {
		return out, mcperr.New(mcperr.CodeInvalidParams, "k must be exactly 32 hex digits (128 bits)", nil)
	}
	out.opc, _ = str("opc")
	if !hex32Re.MatchString(out.opc) {
		return out, mcperr.New(mcperr.CodeInvalidParams, "opc must be exactly 32 hex digits (128 bits)", nil)
	}
	if v, ok := str("sqn"); ok {
		if !hex12Re.MatchString(v) {
			return out, mcperr.New(mcperr.CodeInvalidParams, "sqn must be exactly 12 hex digits (48 bits)", nil)
		}
		out.sqn = v
	}
	if v, ok := str("amf"); ok {
		if !hex4Re.MatchString(v) {
			return out, mcperr.New(mcperr.CodeInvalidParams, "amf must be exactly 4 hex digits (16 bits)", nil)
		}
		out.amf = v
	}
	if raw, ok := top["profile"]; ok {
		var pm map[string]json.RawMessage
		if err := json.Unmarshal(raw, &pm); err != nil {
			return out, mcperr.New(mcperr.CodeInvalidParams, "profile must be an object", nil)
		}
		p, perr := decodeProfile(pm, "profile")
		if perr != nil {
			return out, perr
		}
		out.prof = p
	}
	return out, nil
}

func (a provisionArgs) profileView() map[string]any {
	v := map[string]any{}
	a.prof.apply(v)
	return v
}

func (t subscriberProvisionTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseProvision(in)
	if perr != nil {
		return nil, perr
	}
	exists, _, err := subscriberExists(ctx, t.d, "subscriber_provision plan", a.supi)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errSubscriberExists()
	}
	plan := map[string]any{
		"supi":    a.supi,
		"exists":  false,
		"k":       "<redacted>",
		"opc":     "<redacted>",
		"profile": a.profileView(),
		"effect":  "the subscriber is created in the UDR through the portal; the keys are sent once and never shown",
	}
	if a.sqn != "" {
		plan["sqn"] = "<redacted>"
	}
	if a.amf != "" {
		plan["amf"] = a.amf
	}
	return plan, nil
}

func (t subscriberProvisionTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseProvision(in)
	if perr != nil {
		return nil, perr
	}
	// TOCTOU guard: re-read immediately before the POST (an upsert on the portal).
	exists, _, err := subscriberExists(ctx, t.d, "subscriber_provision", a.supi)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errSubscriberExists()
	}
	rec := map[string]any{"supi": a.supi, "k": a.k, "opc": a.opc}
	if a.sqn != "" {
		rec["sqn"] = a.sqn
	}
	if a.amf != "" {
		rec["amf"] = a.amf
	}
	a.prof.apply(rec)
	body, status, err := t.d.Portal.Send(ctx, http.MethodPost, "/subscribers", rec)
	if err != nil {
		return nil, mcperr.ToolError(errors.New(scrub(fmt.Sprintf("subscriber_provision: %v", err), a.k, a.opc, a.sqn)), nil)
	}
	if status < 200 || status > 299 {
		return nil, portalFailure("subscriber_provision", status, body, a.k, a.opc, a.sqn)
	}
	slog.InfoContext(ctx, "subscriber provisioned",
		"nf", "MCP", "procedure", "SubscriberProvision", "interface", "portal", "direction", "OUT",
		"spec_ref", "TS 33.501 §6.2.1 (K); TS 35.206 (OPc); TS 29.505", "tool_name", "subscriber_provision",
		"supi_hash", toolutil.HashSUPI(a.supi), "result", "OK")
	return map[string]any{"created": true, "supi": a.supi}, nil
}

// ---- subscriber_delete ------------------------------------------------------

type subscriberDeleteTool struct{ d Deps }

func (subscriberDeleteTool) Name() string        { return "subscriber_delete" }
func (subscriberDeleteTool) Risk() registry.Risk { return registry.Admin }
func (subscriberDeleteTool) Description() string {
	return "Delete a subscriber from the UDR through the portal. The portal does not deregister a UE that is " +
		"registered now: it keeps its AMF context until its next authentication or registration. The dry-run shows " +
		"the redacted record; an unknown SUPI is refused (subscriber not found). Admin only: needs access_mode lab and an admin token. " +
		"Spec: TS 29.505 (subscription data), TS 23.502 §4.2.2.3.3."
}
func (subscriberDeleteTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string","description":"e.g. imsi-001010000000077"}},"required":["supi"],"additionalProperties":false}`)
}
func (subscriberDeleteTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func parseSupiOnly(tool string, in json.RawMessage) (string, *mcperr.Error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(in, &top); err != nil {
		return "", mcperr.Newf(mcperr.CodeInvalidParams, nil, "%s args are not a JSON object", tool)
	}
	if perr := rejectUnknownArgs(top, "supi"); perr != nil {
		return "", perr
	}
	var a struct {
		SUPI string `json:"supi"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return "", mcperr.Newf(mcperr.CodeInvalidParams, nil, "%s args: %v", tool, err)
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return "", perr
	}
	return a.SUPI, nil
}

func errSubscriberNotFound() *mcperr.Error {
	return mcperr.New(mcperr.CodeToolError, "subscriber not found", map[string]any{"status": http.StatusNotFound})
}

func (t subscriberDeleteTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	supi, perr := parseSupiOnly("subscriber_delete", in)
	if perr != nil {
		return nil, perr
	}
	exists, prev, err := subscriberExists(ctx, t.d, "subscriber_delete plan", supi)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errSubscriberNotFound()
	}
	return map[string]any{"supi": supi, "exists": true, "current": json.RawMessage(prev),
		"effect": "the subscriber is removed from the UDR; a UE registered now keeps its AMF context until its next authentication or registration"}, nil
}

func (t subscriberDeleteTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	supi, perr := parseSupiOnly("subscriber_delete", in)
	if perr != nil {
		return nil, perr
	}
	// The portal answers 204 for an unknown SUPI, so read first.
	exists, _, err := subscriberExists(ctx, t.d, "subscriber_delete", supi)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errSubscriberNotFound()
	}
	body, status, err := t.d.Portal.Send(ctx, http.MethodDelete, subscriberPath(supi), nil)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("subscriber_delete: %w", err), nil)
	}
	if status < 200 || status > 299 {
		return nil, portalFailure("subscriber_delete", status, body)
	}
	slog.InfoContext(ctx, "subscriber deleted",
		"nf", "MCP", "procedure", "SubscriberDelete", "interface", "portal", "direction", "OUT",
		"spec_ref", "TS 29.505", "tool_name", "subscriber_delete",
		"supi_hash", toolutil.HashSUPI(supi), "result", "OK")
	return map[string]any{"deleted": true, "supi": supi}, nil
}
