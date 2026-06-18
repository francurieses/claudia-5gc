package api

// nwsessions.go — Network-triggered additional PDU session orchestration.
//
// 3GPP has no NW-initiated PDU Session Establishment: the standard mechanism is
// URSP steering (TS 23.503 §6.6.2) — the PCF delivers a URSP rule matching the
// newly detected application, and the UE reacts with a UE-requested PDU Session
// Establishment for an additional PSI (TS 23.502 §4.3.2.2.1, TS 24.501 §6.4.1.2).
// This handler simulates the app-detection event (operator acting as AF) and
// orchestrates the network-side flow; the UE-side URSP evaluation is simulated
// by driving nr-cli, since UERANSIM v3.2.8 has no URSP support.
//
// See docs/procedures/nw-triggered-pdu-session.md.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/store"
)

// nwSessionRequest is the body for POST /api/v1/qos/nw-sessions.
type nwSessionRequest struct {
	SUPI         string   `json:"supi"`
	App          string   `json:"app"`        // application label (for the URSP rule / audit trail)
	AppFQDNs     []string `json:"app_fqdns"`  // optional destination FQDNs identifying the app traffic
	DNN          string   `json:"dnn"`        // target DNN for the additional session
	SST          int      `json:"sst"`        // S-NSSAI SST
	SD           string   `json:"sd"`         // S-NSSAI SD, 6 hex chars (e.g. "000001"); optional
	FiveQI       int      `json:"5qi"`        // QoS for the new session
	AMBRUplink   string   `json:"ambr_uplink"`   // e.g. "50 Mbps"; optional
	AMBRDownlink string   `json:"ambr_downlink"` // e.g. "200 Mbps"; optional
}

// nwSessionStep records the outcome of one orchestration step.
type nwSessionStep struct {
	Step       string `json:"step"`
	Success    bool   `json:"success"`
	DurationMs int64  `json:"duration_ms"`
	Detail     string `json:"detail,omitempty"`
}

// nwSessionResponse is the orchestration result.
type nwSessionResponse struct {
	Success      bool            `json:"success"`
	Steps        []nwSessionStep `json:"steps"`
	PDUSessionID int             `json:"pdu_session_id,omitempty"`
	UEIP         string          `json:"ue_ip,omitempty"`
	FiveQI       int             `json:"5qi,omitempty"`
	QoSSource    string          `json:"qos_source,omitempty"`
	Error        string          `json:"error,omitempty"`
}

// smfSessionView mirrors the SMF /nsmf-management/v1/sessions entry fields the
// orchestration needs (see nf/smf/internal/server/qos.go sessionView).
type smfSessionView struct {
	SmContextRef string `json:"smContextRef"`
	SUPI         string `json:"supi"`
	PDUSessionID int    `json:"pduSessionId"`
	DNN          string `json:"dnn"`
	FiveQI       int    `json:"current5qi"`
	QoSSource    string `json:"qosSource"`
	UEIP         string `json:"ueIp"`
	State        string `json:"sessionState"`
}

// handleNWSessionTrigger implements POST /api/v1/qos/nw-sessions.
//
// Steps (each reported individually):
//  1. pcf_qos_override — DNN-scoped 5QI/AMBR override in the PCF, so the
//     upcoming Npcf_SMPolicyControl_Create returns the requested QoS.
//  2. ursp_rule_store  — per-subscriber URSP rule in subscription_policy
//     (UDR-shared table) steering the app traffic to the target DNN/S-NSSAI.
//  3. ursp_push        — AMF UE Policy delivery (DL NAS, container 0x05).
//  4. ue_establish     — simulated URSP evaluation: nr-cli ps-establish.
//  5. verify           — poll SMF for the additional PSI with the requested 5QI.
func (d Deps) handleNWSessionTrigger(w http.ResponseWriter, r *http.Request) {
	var req nwSessionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.SUPI == "" || req.DNN == "" {
		writeError(w, http.StatusBadRequest, "supi and dnn are required")
		return
	}
	if req.FiveQI <= 0 || req.FiveQI > 86 {
		writeError(w, http.StatusBadRequest, "5qi must be 1-86")
		return
	}
	if req.SST <= 0 {
		req.SST = 1
	}
	if req.App == "" {
		req.App = req.DNN
	}

	ctx := r.Context()
	resp := nwSessionResponse{Steps: []nwSessionStep{}}

	// Baseline: existing SMF sessions, so the verify step can detect the new one.
	baseline, _ := d.fetchSMFSessions(ctx)
	known := make(map[string]bool, len(baseline))
	for _, s := range baseline {
		known[s.SmContextRef] = true
	}

	// Step 1 — PCF DNN-scoped QoS override.
	step := d.stepPCFOverride(ctx, req)
	resp.Steps = append(resp.Steps, step)
	if !step.Success {
		resp.Error = step.Detail
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Step 2 — store the URSP rule (best-effort: establishment works without it,
	// but policy delivery on next registration needs the UDR row).
	resp.Steps = append(resp.Steps, d.stepStoreURSPRule(ctx, req))

	// Step 3 — push UE policy via AMF (UCU / DL NAS Transport).
	step = d.stepPushPolicies(ctx, req.SUPI)
	resp.Steps = append(resp.Steps, step)
	if strings.Contains(step.Detail, "not registered") {
		resp.Error = "UE not registered — register the UE before triggering a session"
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Step 4 — simulated UE URSP evaluation: trigger the additional establishment.
	step = d.stepUEEstablish(ctx, req)
	resp.Steps = append(resp.Steps, step)
	if !step.Success {
		resp.Error = step.Detail
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Step 5 — verify the additional session appears in the SMF with the QoS.
	step, sess := d.stepVerify(ctx, req, known)
	resp.Steps = append(resp.Steps, step)
	if sess != nil {
		resp.PDUSessionID = sess.PDUSessionID
		resp.UEIP = sess.UEIP
		resp.FiveQI = sess.FiveQI
		resp.QoSSource = sess.QoSSource
	}
	resp.Success = step.Success
	if !step.Success {
		resp.Error = step.Detail
	}
	writeJSON(w, http.StatusOK, resp)
}

// stepPCFOverride PUTs the DNN-scoped SM policy override into the PCF.
func (d Deps) stepPCFOverride(ctx context.Context, req nwSessionRequest) nwSessionStep {
	start := time.Now()
	step := nwSessionStep{Step: "pcf_qos_override"}
	if d.PCFBaseURL == "" {
		step.Detail = "PCF_URL not configured"
		step.DurationMs = time.Since(start).Milliseconds()
		return step
	}
	body, _ := json.Marshal(map[string]any{
		"5qi":           req.FiveQI,
		"dnn":           req.DNN,
		"ambr_uplink":   req.AMBRUplink,
		"ambr_downlink": req.AMBRDownlink,
	})
	u := strings.TrimRight(d.PCFBaseURL, "/") +
		"/pcf-internal/v1/subscribers/" + url.PathEscape(req.SUPI) + "/sm-policy-override"
	hr, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(body))
	if err != nil {
		step.Detail = err.Error()
		step.DurationMs = time.Since(start).Milliseconds()
		return step
	}
	hr.Header.Set("Content-Type", "application/json")
	res, err := d.MTLSClient.Do(hr)
	step.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		step.Detail = "PCF unreachable: " + err.Error()
		return step
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		step.Detail = fmt.Sprintf("PCF returned %d: %s", res.StatusCode, string(b))
		return step
	}
	step.Success = true
	step.Detail = fmt.Sprintf("5QI %d scoped to DNN %q for %s", req.FiveQI, req.DNN, req.SUPI)
	return step
}

// stepStoreURSPRule upserts a per-subscriber URSP rule steering the app's
// traffic to the target DNN/S-NSSAI (TS 24.526 §5.2/§5.3 component types).
func (d Deps) stepStoreURSPRule(ctx context.Context, req nwSessionRequest) nwSessionStep {
	start := time.Now()
	step := nwSessionStep{Step: "ursp_rule_store"}
	if d.Store == nil {
		step.Detail = "store unavailable — URSP rule not persisted (delivery on next registration disabled)"
		step.DurationMs = time.Since(start).Milliseconds()
		return step
	}

	td := map[string]any{"dnns": []string{req.DNN}}
	if len(req.AppFQDNs) > 0 {
		td["fqdns"] = req.AppFQDNs
	}
	rsd := map[string]any{
		"precedence":       1,
		"ssc_mode":         1,
		"snssai":           map[string]any{"sst": req.SST, "sd": req.SD},
		"dnn":              req.DNN,
		"pdu_session_type": 1,
	}
	rules, _ := json.Marshal([]map[string]any{{
		"precedence":            10,
		"app":                   req.App, // audit-trail label; ignored by the URSP codec
		"traffic_descriptor":    td,
		"route_sel_descriptors": []map[string]any{rsd},
	}})

	err := d.Store.UpsertPolicy(ctx, store.PolicySubscription{
		SUPI:       req.SUPI,
		Precedence: 10,
		Rules:      rules,
	})
	step.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		step.Detail = "store policy: " + err.Error()
		return step
	}
	step.Success = true
	step.Detail = fmt.Sprintf("URSP rule for app %q → DNN %s, S-NSSAI %d:%s", req.App, req.DNN, req.SST, req.SD)
	return step
}

// stepPushPolicies triggers the AMF UE Policy delivery (TS 23.502 §4.2.4.3).
// 409 (CM-IDLE) is non-fatal: the establishment trigger implicitly brings the
// UE back to CM-CONNECTED via Service Request.
func (d Deps) stepPushPolicies(ctx context.Context, supi string) nwSessionStep {
	start := time.Now()
	step := nwSessionStep{Step: "ursp_push"}
	if d.AMFBaseURL == "" {
		step.Detail = "AMF base URL not configured"
		step.DurationMs = time.Since(start).Milliseconds()
		return step
	}
	u := fmt.Sprintf("%s/amf/v1/ue-contexts/%s/push-policies", d.AMFBaseURL, url.PathEscape(supi))
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		step.Detail = err.Error()
		step.DurationMs = time.Since(start).Milliseconds()
		return step
	}
	res, err := http.DefaultClient.Do(hr)
	step.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		step.Detail = "AMF unreachable: " + err.Error()
		return step
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusNoContent:
		step.Success = true
		step.Detail = "MANAGE UE POLICY COMMAND sent (DL NAS, payload container 0x05)"
	case http.StatusConflict:
		step.Success = true
		step.Detail = "UE is CM-IDLE — URSP delivery deferred; continuing (establishment triggers Service Request)"
	case http.StatusNotFound:
		step.Detail = "UE not registered in AMF"
	default:
		step.Detail = fmt.Sprintf("AMF returned %d", res.StatusCode)
	}
	return step
}

// stepUEEstablish simulates the UE-side URSP evaluation by driving nr-cli:
// ps-establish IPv4 [--sst N --sd N] --dnn <dnn>  (UERANSIM v3.2.8 syntax).
func (d Deps) stepUEEstablish(ctx context.Context, req nwSessionRequest) nwSessionStep {
	start := time.Now()
	step := nwSessionStep{Step: "ue_establish"}
	if d.Docker == nil {
		step.Detail = "docker unavailable"
		step.DurationMs = time.Since(start).Milliseconds()
		return step
	}

	// Locate the UE container for this SUPI among running ueransim-ue* containers.
	var running []string
	if svcs, err := d.Docker.List(ctx); err == nil {
		for _, s := range svcs {
			if strings.HasPrefix(s.Name, "ueransim-ue") && s.State == "running" {
				running = append(running, s.Name)
			}
		}
	}
	container := guessUEContainer(req.SUPI, running)
	if container == "" {
		step.Detail = "no running ueransim-ue* container — start a UERANSIM scenario first"
		step.DurationMs = time.Since(start).Milliseconds()
		return step
	}

	cmd := "ps-establish IPv4"
	if req.SST > 0 {
		cmd += fmt.Sprintf(" --sst %d", req.SST)
		if req.SD != "" {
			// nr-cli takes SD as a decimal integer; portal API uses 6-hex-char strings.
			if sd, err := strconv.ParseUint(strings.TrimPrefix(req.SD, "0x"), 16, 32); err == nil {
				cmd += fmt.Sprintf(" --sd %d", sd)
			} else {
				step.Detail = fmt.Sprintf("invalid sd %q: expected 6 hex chars", req.SD)
				step.DurationMs = time.Since(start).Milliseconds()
				return step
			}
		}
	}
	cmd += " --dnn " + req.DNN

	res, err := d.Docker.Exec(ctx, container, []string{"nr-cli", req.SUPI, "-e", cmd})
	step.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		step.Detail = fmt.Sprintf("exec in %s: %v", container, err)
		return step
	}
	out := strings.TrimSpace(res.Output)
	if res.ExitCode != 0 || strings.Contains(strings.ToLower(out), "error") {
		step.Detail = fmt.Sprintf("nr-cli (%s): %s", container, out)
		return step
	}
	step.Success = true
	step.Detail = fmt.Sprintf("%s in %s (simulated URSP evaluation — UERANSIM has no URSP support)", cmd, container)
	return step
}

// stepVerify polls the SMF management API until the additional session appears
// (new smContextRef for this SUPI+DNN) and validates its 5QI.
func (d Deps) stepVerify(ctx context.Context, req nwSessionRequest, known map[string]bool) (nwSessionStep, *smfSessionView) {
	start := time.Now()
	step := nwSessionStep{Step: "verify"}

	// UERANSIM quirk: an nr-cli ps-establish is often locally barred by a UAC
	// timing race ("No response from RRC from UAC checks") and only goes out on
	// the T3580 retransmission 16 s later. 30 s covers retransmit + N1/N2/N4 setup.
	deadline := time.Now().Add(30 * time.Second)
	for {
		sessions, err := d.fetchSMFSessions(ctx)
		if err == nil {
			for i := range sessions {
				s := &sessions[i]
				if s.SUPI != req.SUPI || s.DNN != req.DNN || known[s.SmContextRef] {
					continue
				}
				if s.State != "ACTIVE" && s.UEIP == "" {
					continue // still establishing
				}
				step.DurationMs = time.Since(start).Milliseconds()
				if s.FiveQI != req.FiveQI {
					step.Detail = fmt.Sprintf(
						"additional PSI %d established but 5QI is %d (wanted %d, source %s)",
						s.PDUSessionID, s.FiveQI, req.FiveQI, s.QoSSource)
					return step, s
				}
				step.Success = true
				step.Detail = fmt.Sprintf("additional PSI %d ACTIVE: 5QI %d, source %s, UE IP %s",
					s.PDUSessionID, s.FiveQI, s.QoSSource, s.UEIP)
				return step, s
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			step.DurationMs = time.Since(start).Milliseconds()
			step.Detail = "no additional session appeared in the SMF within 30s — check SMF/AMF logs"
			return step, nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(800 * time.Millisecond):
		}
	}
}

// fetchSMFSessions GETs the SMF management session list over mTLS.
func (d Deps) fetchSMFSessions(ctx context.Context) ([]smfSessionView, error) {
	u := strings.TrimRight(d.SMFBaseURL, "/") + "/nsmf-management/v1/sessions"
	hr, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := d.MTLSClient.Do(hr)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SMF returned %d", res.StatusCode)
	}
	var out struct {
		Sessions []smfSessionView `json:"sessions"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Sessions, nil
}
