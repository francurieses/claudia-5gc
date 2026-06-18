// Package ueransim implements MCP Group F tools: UERANSIM test orchestration.
// All docker exec calls are isolated behind the ueransim.Client interface so
// unit tests run without a live container. Spec refs: 3GPP TS 23.502.
package ueransim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	ueclient "github.com/francurieses/claudia-5gc/mcp/internal/ueransim"
)

// All returns the five Group F tools bound to a UERANSIM client.
func All(client ueclient.Client) []registry.Tool {
	return []registry.Tool{
		registerTool{client},
		establishTool{client},
		deregisterTool{client},
		scenarioTool{client},
		statusTool{client},
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// hashSUPI produces a short non-reversible tag for log fields.
func hashSUPI(supi string) string {
	h := sha256.Sum256([]byte(supi))
	return hex.EncodeToString(h[:4])
}

func logInvoke(ctx context.Context, toolName, supi string, start time.Time, err error) {
	attrs := []any{
		"tool_name", toolName,
		"supi_hash", hashSUPI(supi),
		"latency_ms", time.Since(start).Milliseconds(),
	}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	slog.InfoContext(ctx, "tool invoked", attrs...)
}

// ---- ueransim_ue_register --------------------------------------------------

type registerTool struct{ c ueclient.Client }

func (registerTool) Name() string { return "ueransim_ue_register" }
func (registerTool) Description() string {
	return "Check the registration state of a running UERANSIM UE identified by SUPI. " +
		"Returns MM state (MM-REGISTERED / MM-DEREGISTERED) and GUTI if available. " +
		"The UE must be running in the ueransim-ue container. " +
		"Spec: 3GPP TS 23.502 §4.2.2.2."
}
func (registerTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "supi":  {"type":"string","description":"UE SUPI, e.g. 'imsi-001010000000001'"},
  "plmn":  {"type":"object","description":"Optional PLMN hint (not used for state query)"},
  "slice": {"type":"object","description":"Optional slice hint (not used for state query)"}
},
"required":["supi"]}`)
}
func (registerTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"success":{},"mm_state":{},"registered":{},"registration_time_ms":{},"error":{}}}`)
}
func (t registerTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		SUPI string `json:"supi"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ueransim_ue_register args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}

	st, err := t.c.UEStatus(ctx, a.SUPI)
	logInvoke(ctx, t.Name(), a.SUPI, start, err)
	if err != nil {
		return map[string]any{
			"success": false,
			"error":   err.Error(),
		}, nil
	}

	return map[string]any{
		"success":             st.Registered,
		"mm_state":            st.MMState,
		"registered":          st.Registered,
		"registration_time_ms": time.Since(start).Milliseconds(),
		"error":               nil,
	}, nil
}

// ---- ueransim_pdu_session_establish ----------------------------------------

type establishTool struct{ c ueclient.Client }

func (establishTool) Name() string { return "ueransim_pdu_session_establish" }
func (establishTool) Description() string {
	return "Establish a PDU session for a running UERANSIM UE. Returns session ID and UE IP. " +
		"Spec: 3GPP TS 23.502 §4.3.2."
}
func (establishTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "supi":  {"type":"string","description":"UE SUPI"},
  "dnn":   {"type":"string","description":"Data Network Name, e.g. 'internet'"},
  "slice": {"type":"object","description":"Optional slice hint (sst, sd)"}
},
"required":["supi","dnn"]}`)
}
func (establishTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"success":{},"pdu_session_id":{},"ue_ip":{},"establish_time_ms":{},"error":{}}}`)
}
func (t establishTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		SUPI string `json:"supi"`
		DNN  string `json:"dnn"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ueransim_pdu_session_establish args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}
	if a.DNN == "" {
		a.DNN = "internet"
	}

	slog.InfoContext(ctx, "establishing PDU session",
		"tool_name", t.Name(),
		"supi_hash", hashSUPI(a.SUPI),
		"dnn", a.DNN,
		"scenario_step", "pdu_establish",
	)

	sess, err := t.c.PDUSessionEstablish(ctx, a.SUPI, a.DNN)
	logInvoke(ctx, t.Name(), a.SUPI, start, err)
	if err != nil {
		return map[string]any{
			"success": false,
			"error":   err.Error(),
		}, nil
	}

	return map[string]any{
		"success":          true,
		"pdu_session_id":   sess.SessionID,
		"ue_ip":            sess.UEAddr,
		"establish_time_ms": time.Since(start).Milliseconds(),
		"error":            nil,
	}, nil
}

// ---- ueransim_ue_deregister ------------------------------------------------

type deregisterTool struct{ c ueclient.Client }

func (deregisterTool) Name() string { return "ueransim_ue_deregister" }
func (deregisterTool) Description() string {
	return "Trigger UE-initiated normal deregistration for a running UERANSIM UE. " +
		"Spec: 3GPP TS 23.502 §4.2.2.3."
}
func (deregisterTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string"}},"required":["supi"]}`)
}
func (deregisterTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"success":{},"deregister_time_ms":{},"error":{}}}`)
}
func (t deregisterTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		SUPI string `json:"supi"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ueransim_ue_deregister args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}

	err := t.c.Deregister(ctx, a.SUPI)
	logInvoke(ctx, t.Name(), a.SUPI, start, err)
	if err != nil {
		return map[string]any{"success": false, "error": err.Error()}, nil
	}
	return map[string]any{
		"success":           true,
		"deregister_time_ms": time.Since(start).Milliseconds(),
		"error":             nil,
	}, nil
}

// ---- ueransim_run_scenario -------------------------------------------------

type scenarioTool struct{ c ueclient.Client }

func (scenarioTool) Name() string { return "ueransim_run_scenario" }
func (scenarioTool) Description() string {
	return "Execute a full UE lifecycle smoke test: register check → PDU session establish → " +
		"PDU session release → deregister. All steps are executed in sequence; failure of any " +
		"step is reported but remaining steps are skipped. Use this as the primary end-to-end " +
		"validation tool. Spec: 3GPP TS 23.502 §4.2.2.2, §4.3.2, §4.3.4, §4.2.2.3."
}
func (scenarioTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "supi":  {"type":"string","description":"UE SUPI"},
  "dnn":   {"type":"string","description":"DNN for PDU session, default 'internet'"},
  "plmn":  {"type":"object"},
  "slice": {"type":"object"}
},
"required":["supi"]}`)
}
func (scenarioTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"steps":{"type":"array"},"total_duration_ms":{},"all_passed":{}}}`)
}
func (t scenarioTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		SUPI string `json:"supi"`
		DNN  string `json:"dnn"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ueransim_run_scenario args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}
	if a.DNN == "" {
		a.DNN = "internet"
	}

	type stepResult struct {
		Name       string `json:"name"`
		Success    bool   `json:"success"`
		DurationMS int64  `json:"duration_ms"`
		Error      any    `json:"error"`
	}
	steps := make([]stepResult, 0, 4)
	allPassed := true
	var sessionID int

	runStep := func(name string, fn func() error) bool {
		t0 := time.Now()
		err := fn()
		sr := stepResult{
			Name:       name,
			Success:    err == nil,
			DurationMS: time.Since(t0).Milliseconds(),
		}
		if err != nil {
			sr.Error = err.Error()
			allPassed = false
		}
		steps = append(steps, sr)
		slog.InfoContext(ctx, "scenario step",
			"tool_name", "ueransim_run_scenario",
			"supi_hash", hashSUPI(a.SUPI),
			"scenario_step", name,
			"success", sr.Success,
			"duration_ms", sr.DurationMS,
		)
		return err == nil
	}

	// Step 1: verify registration
	runStep("check_registered", func() error {
		st, err := t.c.UEStatus(ctx, a.SUPI)
		if err != nil {
			return err
		}
		if !st.Registered {
			return fmt.Errorf("UE %s is not registered (MM state: %s)", a.SUPI, st.MMState)
		}
		return nil
	})

	// Step 2: PDU session establish (only if registered)
	if steps[0].Success {
		runStep("pdu_session_establish", func() error {
			sess, err := t.c.PDUSessionEstablish(ctx, a.SUPI, a.DNN)
			if err != nil {
				return err
			}
			if sess.SessionID == 0 {
				return fmt.Errorf("PDU session established but no session ID returned")
			}
			sessionID = sess.SessionID
			return nil
		})
	}

	// Step 3: PDU session release
	if len(steps) >= 2 && steps[1].Success && sessionID > 0 {
		runStep("pdu_session_release", func() error {
			return t.c.PDUSessionRelease(ctx, a.SUPI, sessionID)
		})
	}

	// Step 4: deregister
	runStep("deregister", func() error {
		return t.c.Deregister(ctx, a.SUPI)
	})

	slog.InfoContext(ctx, "tool invoked",
		"tool_name", t.Name(),
		"supi_hash", hashSUPI(a.SUPI),
		"latency_ms", time.Since(start).Milliseconds(),
		"all_passed", allPassed,
	)
	return map[string]any{
		"steps":            steps,
		"total_duration_ms": time.Since(start).Milliseconds(),
		"all_passed":       allPassed,
	}, nil
}

// ---- ueransim_status -------------------------------------------------------

type statusTool struct{ c ueclient.Client }

func (statusTool) Name() string { return "ueransim_status" }
func (statusTool) Description() string {
	return "Return the operational status of the UERANSIM container: whether it is running, " +
		"which UEs are registered, active session count, and container uptime."
}
func (statusTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{}}`)
}
func (statusTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"container_running":{},"registered_ues":{"type":"array"},"active_sessions":{},"uptime_seconds":{}}}`)
}
func (t statusTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	start := time.Now()
	info, err := t.c.ContainerInfo(ctx)
	slog.InfoContext(ctx, "tool invoked",
		"tool_name", t.Name(),
		"latency_ms", time.Since(start).Milliseconds(),
	)
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInternal, nil, "ueransim_status: %v", err)
	}
	regUEs := info.RegisteredSUPIs
	if regUEs == nil {
		regUEs = []string{}
	}
	return map[string]any{
		"container_running": info.Running,
		"registered_ues":    regUEs,
		"active_sessions":   info.ActiveSessions,
		"uptime_seconds":    info.UptimeSeconds,
	}, nil
}
