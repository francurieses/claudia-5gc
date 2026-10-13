// netctl.go — control tools for AN release, UE location, AF QoS sessions (NEF),
// PWS resend and MT-SMS (backlog MCP-010). Same rules as control.go: every
// signalling tool is Disruptive with a Planner that only reads, and a call
// without confirm:true never reaches the mutating upstream.
package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

const (
	// smsPayloadMaxBytes is the largest decoded SMS payload the sms_send_mt tool
	// accepts: an RP-DATA TPDU carries at most 140 bytes of user data, and the
	// RPDU with its headers stays under one octet of length (TS 24.011 §8.2.5.3).
	smsPayloadMaxBytes = 255
	// pwsIDMax is the maximum of the 16-bit Message Identifier and Serial Number
	// (TS 38.413 §9.3.1.35, §9.3.1.36).
	pwsIDMax = 65535
	// specANRelease is the spec reference reported by ue_an_release_nw.
	specANRelease = "TS 23.502 §4.2.6; TS 38.413 §8.3.3"
	// specLocation is the spec reference reported by ue_location_get.
	specLocation = "TS 23.273 §6.10.1; TS 38.413 §8.12"
	// specAFQoS is the spec reference of the af_qos_session_* tools.
	specAFQoS = "TS 29.522 §4.4.13; TS 23.502 §4.15.6.6"
	// specPWSResend is the spec reference of pws_resend.
	specPWSResend = "TS 38.413 §8.9.1"
	// specMTSMS is the spec reference of sms_send_mt.
	specMTSMS = "TS 23.502 §4.13.3"
)

// scsAsIDRe limits the AF/SCS identifier to a safe single path segment.
var scsAsIDRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)

func netctlTools(d Deps) []registry.Tool {
	return []registry.Tool{
		anReleaseTool{d}, locationTool{d},
		afCreateTool{d}, afGetTool{d}, afDeleteTool{d},
		pwsResendTool{d}, smsMTTool{d},
	}
}

func notFoundUE(supi string) *mcperr.Error {
	return mcperr.Newf(mcperr.CodeToolError, map[string]any{"supi": supi},
		"UE not found in the AMF: %s", supi)
}

// problemCause reads the "cause" of a ProblemDetails body (TS 29.571 §5.2.4.1).
func problemCause(body []byte) string {
	var p struct {
		Cause string `json:"cause"`
	}
	_ = json.Unmarshal(body, &p)
	return p.Cause
}

// ueSnapshot is the part of the AMF UE context the tools read.
type ueSnapshot struct {
	CMState       string `json:"cm_state"`
	PDUSessionIDs []int  `json:"pdu_session_ids"`
}

// readUE fetches the UE context from the AMF and refuses an unknown UE.
func readUE(ctx context.Context, d Deps, tool, supi string) (ueSnapshot, *mcperr.Error) {
	var snap ueSnapshot
	raw, err := d.AMF.GetContext(ctx, supi)
	if err != nil {
		return snap, mcperr.ToolError(fmt.Errorf("%s: read ue context: %w", tool, err), nil)
	}
	if raw == nil {
		return snap, notFoundUE(supi)
	}
	_ = json.Unmarshal(raw, &snap)
	return snap, nil
}

// cmStateKind classifies an AMF cm_state string.
func cmStateKind(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CM-IDLE", "IDLE":
		return "idle"
	case "CM-CONNECTED", "CONNECTED":
		return "connected"
	default:
		return "unknown"
	}
}

// ---- ue_an_release_nw -------------------------------------------------------

type anReleaseTool struct{ d Deps }

func (anReleaseTool) Name() string        { return "ue_an_release_nw" }
func (anReleaseTool) Risk() registry.Risk { return registry.Disruptive }
func (anReleaseTool) Description() string {
	return "AMF-initiated AN release of a CM-CONNECTED UE (UE Context Release Command, cause O&M intervention). " +
		"The UE becomes CM-IDLE and stays registered; the user plane of its PDU sessions is deactivated. " +
		"Refused for a CM-IDLE or unknown UE. Spec: TS 23.502 §4.2.6, TS 38.413 §8.3.3."
}
func (anReleaseTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string","description":"e.g. imsi-001010000000001"}},"required":["supi"]}`)
}
func (anReleaseTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

// target reads the UE and refuses unless it is CM-CONNECTED.
func (t anReleaseTool) target(ctx context.Context, supi string) (ueSnapshot, *mcperr.Error) {
	snap, perr := readUE(ctx, t.d, "ue_an_release_nw", supi)
	if perr != nil {
		return snap, perr
	}
	switch cmStateKind(snap.CMState) {
	case "connected":
		return snap, nil
	case "idle":
		return snap, mcperr.Newf(mcperr.CodeToolError, map[string]any{"supi": supi, "cm_state": snap.CMState},
			"ue_an_release_nw: UE is CM-IDLE, it has no AN connection to release")
	default:
		return snap, mcperr.Newf(mcperr.CodeToolError, map[string]any{"supi": supi, "cm_state": snap.CMState},
			"ue_an_release_nw: UE CM state is unknown (%q), refusing to release", snap.CMState)
	}
}

func (t anReleaseTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSUPI(in, "ue_an_release_nw")
	if perr != nil {
		return nil, perr
	}
	snap, perr := t.target(ctx, a.SUPI)
	if perr != nil {
		return nil, perr
	}
	return map[string]any{
		"supi":                  a.SUPI,
		"previous_cm_state":     snap.CMState,
		"affected_pdu_sessions": nonNil(snap.PDUSessionIDs),
		"effect":                "N2 UE Context Release Command (cause O&M intervention); UE goes CM-IDLE, stays registered, user plane of its sessions deactivated",
		"spec_ref":              specANRelease,
	}, nil
}

func (t anReleaseTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSUPI(in, "ue_an_release_nw")
	if perr != nil {
		return nil, perr
	}
	snap, perr := t.target(ctx, a.SUPI)
	if perr != nil {
		return nil, perr
	}
	status, body, err := t.d.AMF.ANRelease(ctx, a.SUPI)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_an_release_nw: %w", err), nil)
	}
	if perr := amfStatus("ue_an_release_nw", status, body, a.SUPI); perr != nil {
		return nil, perr
	}
	prev, sessions := snap.CMState, snap.PDUSessionIDs
	var resp struct {
		Previous string `json:"previous_cm_state"`
		Affected []int  `json:"affected_pdu_sessions"`
	}
	if json.Unmarshal(body, &resp) == nil {
		if resp.Previous != "" {
			prev = resp.Previous
		}
		if resp.Affected != nil {
			sessions = resp.Affected
		}
	}
	return map[string]any{"accepted": true, "supi": a.SUPI, "previous_cm_state": prev,
		"affected_pdu_sessions": nonNil(sessions), "spec_ref": specANRelease}, nil
}

func nonNil(v []int) []int {
	if v == nil {
		return []int{}
	}
	return v
}

// ---- ue_location_get --------------------------------------------------------

type locationTool struct{ d Deps }

func (locationTool) Name() string        { return "ue_location_get" }
func (locationTool) Risk() registry.Risk { return registry.Disruptive }
func (locationTool) Description() string {
	return "Locate a UE through the portal and the LMF. This triggers NGAP Location Reporting towards the gNB " +
		"and reveals the UE position (LCS privacy), so it needs confirm. Returns reachable, latitude, longitude, " +
		"accuracy_m, nr_cell_id, tac and, when unreachable, a cause. Spec: TS 23.273 §6.10.1, TS 38.413 §8.12."
}
func (locationTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string"}},"required":["supi"]}`)
}
func (locationTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t locationTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSUPI(in, "ue_location_get")
	if perr != nil {
		return nil, perr
	}
	snap, perr := readUE(ctx, t.d, "ue_location_get", a.SUPI)
	if perr != nil {
		return nil, perr
	}
	return map[string]any{
		"supi":     a.SUPI,
		"cm_state": snap.CMState,
		"effect":   "the LMF asks the AMF to start NGAP Location Reporting for the UE and returns its position",
		"spec_ref": specLocation,
	}, nil
}

func (t locationTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseSUPI(in, "ue_location_get")
	if perr != nil {
		return nil, perr
	}
	raw, err := t.d.Portal.UELocation(ctx, a.SUPI)
	if err != nil {
		var pse *clients.PortalStatusError
		if errors.As(err, &pse) {
			return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"status": pse.Status},
				"ue_location_get: portal returned %d: %s", pse.Status, pse.Body)
		}
		return nil, mcperr.ToolError(fmt.Errorf("ue_location_get: %w", err), nil)
	}
	var loc struct {
		Reachable bool    `json:"reachable"`
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
		AccuracyM float64 `json:"accuracy_m"`
		NRCellID  string  `json:"nr_cell_id"`
		TAC       string  `json:"tac"`
		Cause     string  `json:"cause"`
	}
	if err := json.Unmarshal(raw, &loc); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ue_location_get: decode portal reply: %w", err), nil)
	}
	out := map[string]any{"supi": a.SUPI, "reachable": loc.Reachable, "latitude": loc.Latitude,
		"longitude": loc.Longitude, "accuracy_m": loc.AccuracyM, "nr_cell_id": loc.NRCellID,
		"tac": loc.TAC, "spec_ref": specLocation}
	if loc.Cause != "" {
		out["cause"] = loc.Cause
	}
	return out, nil
}

// ---- af_qos_session_* (NEF, TS 29.522 §4.4.13) ------------------------------

// nefStatus maps a NEF reply to a tool error. 2xx is nil.
func nefStatus(tool string, status int, body []byte) *mcperr.Error {
	if status >= 200 && status < 300 {
		return nil
	}
	data := map[string]any{"status": status}
	if c := problemCause(body); c != "" {
		data["cause"] = c
	}
	return mcperr.Newf(mcperr.CodeToolError, data, "%s: NEF returned %d: %s", tool, status,
		strings.TrimSpace(string(body)))
}

func validSCS(id string) *mcperr.Error {
	if !scsAsIDRe.MatchString(id) {
		return mcperr.Newf(mcperr.CodeInvalidParams, nil, "scs_as_id must match %s, got %q", scsAsIDRe, id)
	}
	return nil
}

type afCreateArgs struct {
	SCSAsID                 string   `json:"scs_as_id"`
	UEIPv4                  string   `json:"ue_ipv4"`
	QoSReference            string   `json:"qos_reference"`
	FlowDescriptions        []string `json:"flow_descriptions"`
	NotificationDestination string   `json:"notification_destination"`
}

func parseAFCreate(in json.RawMessage) (afCreateArgs, *mcperr.Error) {
	var a afCreateArgs
	if err := json.Unmarshal(in, &a); err != nil {
		return a, mcperr.Newf(mcperr.CodeInvalidParams, nil, "af_qos_session_create args: %v", err)
	}
	if perr := validSCS(a.SCSAsID); perr != nil {
		return a, perr
	}
	if ip, err := parseIPv4(a.UEIPv4); err != nil {
		return a, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ue_ipv4 must be a dotted IPv4 address, got %q", ip)
	}
	if a.QoSReference == "" || len(a.QoSReference) > 128 {
		return a, mcperr.New(mcperr.CodeInvalidParams, "qos_reference is required (1-128 characters)", nil)
	}
	if a.NotificationDestination != "" {
		u, err := url.Parse(a.NotificationDestination)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return a, mcperr.Newf(mcperr.CodeInvalidParams, nil,
				"notification_destination must be an http(s) URL, got %q", a.NotificationDestination)
		}
	}
	return a, nil
}

func parseIPv4(s string) (string, error) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil || strings.Contains(s, ":") {
		return s, errors.New("not an IPv4 address")
	}
	return s, nil
}

// requireSMFSession refuses unless ue_ipv4 belongs to a session in the SMF store.
func requireSMFSession(ctx context.Context, d Deps, tool, ip string) *mcperr.Error {
	raw, err := d.SMF.ListSessions(ctx)
	if err != nil {
		return mcperr.ToolError(fmt.Errorf("%s: list SMF sessions: %w", tool, err), nil)
	}
	var list struct {
		Sessions []struct {
			UEIP string `json:"ueIp"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return mcperr.ToolError(fmt.Errorf("%s: decode SMF sessions: %w", tool, err), nil)
	}
	for _, s := range list.Sessions {
		if s.UEIP == ip {
			return nil
		}
	}
	return mcperr.Newf(mcperr.CodeToolError, map[string]any{"ue_ipv4": ip},
		"%s: no SMF PDU session has UE address %s", tool, ip)
}

func (a afCreateArgs) body() map[string]any {
	b := map[string]any{"ueIpv4Addr": a.UEIPv4, "qosReference": a.QoSReference}
	if len(a.FlowDescriptions) > 0 {
		b["flowInfo"] = []map[string]any{{"flowId": 1, "flowDescriptions": a.FlowDescriptions}}
	}
	if a.NotificationDestination != "" {
		b["notificationDestination"] = a.NotificationDestination
	}
	return b
}

type afCreateTool struct{ d Deps }

func (afCreateTool) Name() string        { return "af_qos_session_create" }
func (afCreateTool) Risk() registry.Risk { return registry.Disruptive }
func (afCreateTool) Description() string {
	return "Create an AF session with required QoS at the NEF (Nnef_AFsessionWithQoS): the NEF finds the PCF through " +
		"the BSF and the PCF installs the QoS rule on the UE's PDU session. The tool gets an NRF access token " +
		"(scope nnef-afsessionwithqos) first. The UE IPv4 must belong to a live SMF session. " +
		"Spec: TS 29.522 §4.4.13, TS 23.502 §4.15.6.6."
}
func (afCreateTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"scs_as_id":{"type":"string","description":"AF/SCS identifier (path segment)"},
"ue_ipv4":{"type":"string","description":"UE IPv4 address of a live PDU session"},
"qos_reference":{"type":"string","description":"pre-provisioned QoS reference"},
"flow_descriptions":{"type":"array","items":{"type":"string"},"description":"IPFilterRule strings (optional)"},
"notification_destination":{"type":"string","description":"AF callback URL (optional)"}},
"required":["scs_as_id","ue_ipv4","qos_reference"]}`)
}
func (afCreateTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t afCreateTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseAFCreate(in)
	if perr != nil {
		return nil, perr
	}
	if perr := requireSMFSession(ctx, t.d, "af_qos_session_create", a.UEIPv4); perr != nil {
		return nil, perr
	}
	return map[string]any{
		"scs_as_id": a.SCSAsID, "request": a.body(),
		"effect":   "NRF token request, then POST of the subscription to the NEF; the PCF installs the QoS rule on the UE's session",
		"spec_ref": specAFQoS,
	}, nil
}

func (t afCreateTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseAFCreate(in)
	if perr != nil {
		return nil, perr
	}
	if perr := requireSMFSession(ctx, t.d, "af_qos_session_create", a.UEIPv4); perr != nil {
		return nil, perr
	}
	status, body, loc, err := t.d.NEF.CreateSubscription(ctx, a.SCSAsID, a.body())
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("af_qos_session_create: %w", err), nil)
	}
	if perr := nefStatus("af_qos_session_create", status, body); perr != nil {
		return nil, perr
	}
	var resp struct {
		SubscriptionID string `json:"subscriptionId"`
	}
	_ = json.Unmarshal(body, &resp)
	if resp.SubscriptionID == "" && loc != "" {
		resp.SubscriptionID = path.Base(loc)
	}
	return map[string]any{"subscription_id": resp.SubscriptionID, "self_link": loc, "accepted": true,
		"scs_as_id": a.SCSAsID, "spec_ref": specAFQoS}, nil
}

type afRefArgs struct {
	SCSAsID        string `json:"scs_as_id"`
	SubscriptionID string `json:"subscription_id"`
}

func parseAFRef(in json.RawMessage, tool string) (afRefArgs, *mcperr.Error) {
	var a afRefArgs
	if err := json.Unmarshal(in, &a); err != nil {
		return a, mcperr.Newf(mcperr.CodeInvalidParams, nil, "%s args: %v", tool, err)
	}
	if perr := validSCS(a.SCSAsID); perr != nil {
		return a, perr
	}
	if !scsAsIDRe.MatchString(a.SubscriptionID) {
		return a, mcperr.Newf(mcperr.CodeInvalidParams, nil, "subscription_id must match %s, got %q",
			scsAsIDRe, a.SubscriptionID)
	}
	return a, nil
}

const afRefSchema = `{"type":"object","properties":{"scs_as_id":{"type":"string"},"subscription_id":{"type":"string"}},"required":["scs_as_id","subscription_id"]}`

type afGetTool struct{ d Deps }

func (afGetTool) Name() string        { return "af_qos_session_get" }
func (afGetTool) Risk() registry.Risk { return registry.ReadOnly }
func (afGetTool) Description() string {
	return "Read one AF session with required QoS from the NEF. Spec: TS 29.522 §4.4.13, TS 23.502 §4.15.6.6."
}
func (afGetTool) InputSchema() json.RawMessage  { return schema(afRefSchema) }
func (afGetTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t afGetTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseAFRef(in, "af_qos_session_get")
	if perr != nil {
		return nil, perr
	}
	status, body, err := t.d.NEF.GetSubscription(ctx, a.SCSAsID, a.SubscriptionID)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("af_qos_session_get: %w", err), nil)
	}
	if perr := nefStatus("af_qos_session_get", status, body); perr != nil {
		return nil, perr
	}
	return json.RawMessage(body), nil
}

type afDeleteTool struct{ d Deps }

func (afDeleteTool) Name() string        { return "af_qos_session_delete" }
func (afDeleteTool) Risk() registry.Risk { return registry.Disruptive }
func (afDeleteTool) Description() string {
	return "Delete an AF session with required QoS at the NEF; the PCF removes the QoS rule from the UE's session. " +
		"Spec: TS 29.522 §4.4.13, TS 23.502 §4.15.6.6."
}
func (afDeleteTool) InputSchema() json.RawMessage  { return schema(afRefSchema) }
func (afDeleteTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t afDeleteTool) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseAFRef(in, "af_qos_session_delete")
	if perr != nil {
		return nil, perr
	}
	status, body, err := t.d.NEF.GetSubscription(ctx, a.SCSAsID, a.SubscriptionID)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("af_qos_session_delete plan: %w", err), nil)
	}
	if perr := nefStatus("af_qos_session_delete", status, body); perr != nil {
		return nil, perr
	}
	return map[string]any{"scs_as_id": a.SCSAsID, "subscription_id": a.SubscriptionID,
		"subscription": json.RawMessage(body),
		"effect":       "the subscription is deleted at the NEF and the PCF removes its QoS rule",
		"spec_ref":     specAFQoS}, nil
}

func (t afDeleteTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, perr := parseAFRef(in, "af_qos_session_delete")
	if perr != nil {
		return nil, perr
	}
	status, body, err := t.d.NEF.DeleteSubscription(ctx, a.SCSAsID, a.SubscriptionID)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("af_qos_session_delete: %w", err), nil)
	}
	if perr := nefStatus("af_qos_session_delete", status, body); perr != nil {
		return nil, perr
	}
	return map[string]any{"deleted": true, "scs_as_id": a.SCSAsID, "subscription_id": a.SubscriptionID,
		"spec_ref": specAFQoS}, nil
}

// ---- pws_resend -------------------------------------------------------------

type pwsResendTool struct{ d Deps }

type pwsResendArgs struct {
	MessageIdentifier *int `json:"message_identifier"`
	SerialNumber      *int `json:"serial_number"`
}

func parsePWSResend(in json.RawMessage) (int, int, *mcperr.Error) {
	var a pwsResendArgs
	if err := json.Unmarshal(in, &a); err != nil {
		return 0, 0, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pws_resend args: %v", err)
	}
	if a.MessageIdentifier == nil || a.SerialNumber == nil {
		return 0, 0, mcperr.New(mcperr.CodeInvalidParams, "message_identifier and serial_number are required", nil)
	}
	for name, v := range map[string]int{"message_identifier": *a.MessageIdentifier, "serial_number": *a.SerialNumber} {
		if v < 0 || v > pwsIDMax {
			return 0, 0, mcperr.Newf(mcperr.CodeInvalidParams, nil, "%s must be 0-%d, got %d", name, pwsIDMax, v)
		}
	}
	return *a.MessageIdentifier, *a.SerialNumber, nil
}

func (pwsResendTool) Name() string        { return "pws_resend" }
func (pwsResendTool) Risk() registry.Risk { return registry.Disruptive }
func (pwsResendTool) Description() string {
	return "Re-send a stored Public Warning System broadcast to the gNBs (Write-Replace Warning), as a CBC does " +
		"after a restoration event. Needs the message identifier and serial number of a stored broadcast. " +
		"Spec: TS 38.413 §8.9.1."
}
func (pwsResendTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"message_identifier":{"type":"integer","minimum":0,"maximum":65535},
"serial_number":{"type":"integer","minimum":0,"maximum":65535}},"required":["message_identifier","serial_number"]}`)
}
func (pwsResendTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t pwsResendTool) Plan(_ context.Context, in json.RawMessage) (any, error) {
	mid, sn, perr := parsePWSResend(in)
	if perr != nil {
		return nil, perr
	}
	return map[string]any{"message_identifier": mid, "serial_number": sn,
		"effect":   "the stored warning is written again to every gNB of the AMF's PWS area",
		"spec_ref": specPWSResend}, nil
}

func (t pwsResendTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	mid, sn, perr := parsePWSResend(in)
	if perr != nil {
		return nil, perr
	}
	out, status, err := t.d.Portal.PWSResend(ctx, mid, sn)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pws_resend: %w", err), nil)
	}
	if status < 200 || status > 299 {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"status": status},
			"pws_resend: portal returned %d: %s", status, out)
	}
	return map[string]any{"resent": true, "message_identifier": mid, "serial_number": sn,
		"result": out, "spec_ref": specPWSResend}, nil
}

// ---- sms_send_mt ------------------------------------------------------------

type smsMTTool struct{ d Deps }

type smsMTArgs struct {
	SUPI       string `json:"supi"`
	PayloadB64 string `json:"payload_b64"`
}

func parseSMSMT(in json.RawMessage) (smsMTArgs, int, *mcperr.Error) {
	var a smsMTArgs
	if err := json.Unmarshal(in, &a); err != nil {
		return a, 0, mcperr.Newf(mcperr.CodeInvalidParams, nil, "sms_send_mt args: %v", err)
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return a, 0, perr
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(a.PayloadB64)
	if err != nil {
		return a, 0, mcperr.Newf(mcperr.CodeInvalidParams, nil, "payload_b64 is not valid base64: %v", err)
	}
	if len(raw) < 1 || len(raw) > smsPayloadMaxBytes {
		return a, 0, mcperr.Newf(mcperr.CodeInvalidParams, nil,
			"payload_b64 must decode to 1-%d bytes, got %d", smsPayloadMaxBytes, len(raw))
	}
	return a, len(raw), nil
}

func (smsMTTool) Name() string        { return "sms_send_mt" }
func (smsMTTool) Risk() registry.Risk { return registry.Disruptive }
func (smsMTTool) Description() string {
	return "Originate a mobile-terminated SMS to a UE through the SMSF: the raw payload (base64, 1-255 bytes, sent as-is) " +
		"is carried to the AMF as an N1N2 message and delivered over NAS. The UE needs an active SMS context at the SMSF. " +
		"Spec: TS 23.502 §4.13.3."
}
func (smsMTTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"supi":{"type":"string"},
"payload_b64":{"type":"string","description":"raw SMS payload, standard base64, 1-255 decoded bytes"}},
"required":["supi","payload_b64"]}`)
}
func (smsMTTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }

func (t smsMTTool) Plan(_ context.Context, in json.RawMessage) (any, error) {
	a, n, perr := parseSMSMT(in)
	if perr != nil {
		return nil, perr
	}
	return map[string]any{"supi": a.SUPI, "payload_bytes": n,
		"effect":   "the SMSF sends the payload to the UE through the AMF as a NAS message; a UE with no SMS context is refused",
		"spec_ref": specMTSMS}, nil
}

func (t smsMTTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	a, _, perr := parseSMSMT(in)
	if perr != nil {
		return nil, perr
	}
	status, body, err := t.d.SMSF.SendMT(ctx, a.SUPI, a.PayloadB64)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("sms_send_mt: %w", err), nil)
	}
	if status < 200 || status > 299 {
		cause := problemCause(body)
		if cause == "" && status == http.StatusNotFound {
			cause = "CONTEXT_NOT_FOUND"
		}
		data := map[string]any{"status": status, "supi": a.SUPI}
		if cause != "" {
			data["cause"] = cause
		}
		return nil, mcperr.Newf(mcperr.CodeToolError, data, "sms_send_mt: SMSF returned %d %s: %s",
			status, cause, strings.TrimSpace(string(body)))
	}
	var resp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(body, &resp)
	if resp.Status == "" {
		resp.Status = "accepted"
	}
	return map[string]any{"status": resp.Status, "supi": a.SUPI, "spec_ref": specMTSMS}, nil
}
