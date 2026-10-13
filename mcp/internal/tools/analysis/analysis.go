// Package analysis implements the read-only analysis tools that join logs, traces,
// metrics and NF state into answers: log_query, procedure_timeline, ue_diagnose
// and procedure_stats. It also carries the PCAP tools, which control the capture
// sidecars through the portal.
//
// 3GPP references: procedure flow TS 23.502 §4.2 (registration), §4.3 (PDU
// session); the diagnostic findings cite the clause they check.
package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/trace"
)

// Deps are the upstreams the analysis tools read from.
type Deps struct {
	Loki   *clients.Loki
	Obs    *clients.Obs
	Prom   *promclient.Client
	AMF    *clients.AMF
	SMF    *clients.SMF
	PCF    *clients.PCF
	UDM    *clients.UDM
	Portal *clients.Portal
	// Targets resolves the Prometheus scrape targets for core_consistency_check.
	// When nil, a resolver over Prom without host override is used.
	Targets *clients.Targets
	// HTTP is the plain-HTTP client for the UPF admin endpoint on the metrics port
	// (n4_session_get). When nil, http.DefaultClient is used.
	HTTP *http.Client
}

// upstreamTimeout bounds each fan-out call in ue_diagnose, so one slow NF returns
// partial results instead of stalling the whole diagnosis.
const upstreamTimeout = 3 * time.Second

const (
	// diagnoseLokiLimit is the number of REJECT/FAILURE log lines ue_diagnose
	// asks Loki for, newest first, before grouping them.
	diagnoseLokiLimit = 200
	// diagnoseLogWindow is how far back ue_diagnose looks for REJECT/FAILURE logs.
	diagnoseLogWindow = 15 * time.Minute
	// recentErrorsTopN is the number of grouped error kinds ue_diagnose returns.
	recentErrorsTopN = 10
)

// All returns the analysis and PCAP tools, including the deprecated procedure_summary alias.
func All(d Deps) []registry.Tool {
	stats := procedureStatsTool{d}
	return []registry.Tool{
		logQueryTool{d}, procedureTimelineTool{d}, ueDiagnoseTool{d}, stats,
		toolutil.Deprecated("procedure_summary", summaryLegacySchema, stats, mapSummaryLegacy),
		pcapListTool{d}, pcapControlTool{d},
		consistencyTool{d}, errorSummaryTool{d}, n4SessionTool{d},
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

var (
	idRe   = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)
	nameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)
)

// parseWindow reads a duration argument, applying def when empty and rejecting
// anything above max.
func parseWindow(s string, def, max time.Duration) (time.Duration, *mcperr.Error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"window": s},
			"window must be a positive duration such as 15m, got %q", s)
	}
	if d > max {
		return 0, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"window": s},
			"window %s is above the %s maximum", s, max)
	}
	return d, nil
}

// ---- log_query --------------------------------------------------------------

type logQueryTool struct{ d Deps }

func (logQueryTool) Name() string        { return "log_query" }
func (logQueryTool) Risk() registry.Risk { return registry.ReadOnly }
func (logQueryTool) Description() string {
	return "Query the NF logs in Loki with LogQL, for a window of at most 1 hour (default 15m) and at most " +
		"500 lines. Example: {nf=\"AMF\"} |= \"REJECT\". Log records are JSON with nf, procedure, " +
		"spec_ref, result and correlation_id fields."
}
func (logQueryTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"query":{"type":"string","description":"LogQL selector and filters, e.g. {nf=\"SMF\"} |= \"PduSession\""},
"window":{"type":"string","description":"look-back window, e.g. 15m or 1h (default 15m, max 1h)"},
"limit":{"type":"integer","description":"max lines, 1-500 (default 100)"}},"required":["query"]}`)
}
func (logQueryTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"count":{"type":"integer"},"lines":{"type":"array"}}}`)
}

func (t logQueryTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		Query  string `json:"query"`
		Window string `json:"window"`
		Limit  int    `json:"limit"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "log_query args: %v", err)
	}
	if strings.TrimSpace(a.Query) == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "query is required", nil)
	}
	window, perr := parseWindow(a.Window, 15*time.Minute, time.Hour)
	if perr != nil {
		return nil, perr
	}
	if a.Limit == 0 {
		a.Limit = 100
	}
	if a.Limit < 1 || a.Limit > 500 {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "limit must be 1-500, got %d", a.Limit)
	}
	now := time.Now()
	lines, err := t.d.Loki.QueryRange(ctx, a.Query, now.Add(-window), now, a.Limit)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("log_query: %w", err), nil)
	}
	return map[string]any{"count": len(lines), "lines": lines}, nil
}

// ---- procedure_timeline -----------------------------------------------------

type procedureTimelineTool struct{ d Deps }

func (procedureTimelineTool) Name() string        { return "procedure_timeline" }
func (procedureTimelineTool) Risk() registry.Risk { return registry.ReadOnly }
func (procedureTimelineTool) Description() string {
	return "Reconstruct one procedure run from its logs and traces: every log record with the given " +
		"correlation_id (or SUPI) ordered by time, the Jaeger spans of the same correlation_id, and the " +
		"first REJECT or FAILURE. Window at most 1 hour (default 15m)."
}
func (procedureTimelineTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"correlation_id":{"type":"string","description":"X-Correlation-Id of the run (ULID)"},
"supi":{"type":"string","description":"alternative to correlation_id: all runs for this SUPI in the window"},
"window":{"type":"string","description":"look-back window (default 15m, max 1h)"}}}`)
}
func (procedureTimelineTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"entries":{"type":"array"},"first_failure":{},"traces":{}}}`)
}

// logRecord is the subset of an NF log line the timeline reads.
type logRecord struct {
	NF            string `json:"nf"`
	Procedure     string `json:"procedure"`
	Interface     string `json:"interface"`
	Direction     string `json:"direction"`
	SpecRef       string `json:"spec_ref"`
	Result        string `json:"result"`
	CorrelationID string `json:"correlation_id"`
	SUPI          string `json:"supi"`
	Msg           string `json:"msg"`
}

func (t procedureTimelineTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		CorrelationID string `json:"correlation_id"`
		SUPI          string `json:"supi"`
		Window        string `json:"window"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "procedure_timeline args: %v", err)
	}
	if (a.CorrelationID == "") == (a.SUPI == "") {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "exactly one of correlation_id or supi is required", nil)
	}
	if a.CorrelationID != "" && !idRe.MatchString(a.CorrelationID) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "correlation_id must be alphanumeric, got %q", a.CorrelationID)
	}
	if a.SUPI != "" {
		if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
			return nil, perr
		}
	}
	window, perr := parseWindow(a.Window, 15*time.Minute, time.Hour)
	if perr != nil {
		return nil, perr
	}

	key, field := a.CorrelationID, "correlation_id"
	if a.SUPI != "" {
		key, field = a.SUPI, "supi"
	}
	now := time.Now()
	lines, err := t.d.Loki.QueryRange(ctx, `{nf=~".+"} |= "`+key+`"`, now.Add(-window), now, 500)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("procedure_timeline: %w", err), nil)
	}

	var entries []timelineEntry
	var firstFailure *timelineEntry
	for _, l := range lines {
		var r logRecord
		if err := json.Unmarshal([]byte(l.Line), &r); err != nil {
			continue
		}
		if fieldValue(r, field) != key {
			continue
		}
		e := timelineEntry{Time: l.Time, NF: r.NF, Proc: r.Procedure, Iface: r.Interface,
			Dir: r.Direction, Spec: r.SpecRef, Res: r.Result, Msg: r.Msg}
		entries = append(entries, e)
		if firstFailure == nil && (r.Result == "REJECT" || r.Result == "FAILURE") {
			ec := e
			firstFailure = &ec
		}
	}

	out := map[string]any{"entries": entries, "first_failure": firstFailure}
	if a.CorrelationID != "" {
		traces, err := t.traces(ctx, a.CorrelationID)
		if err != nil {
			out["traces_error"] = err.Error()
		} else {
			out["traces"] = traces
		}
	}
	return out, nil
}

// timelineEntry is one step of a procedure run, from one log record.
type timelineEntry struct {
	Time  time.Time `json:"time"`
	NF    string    `json:"nf"`
	Proc  string    `json:"procedure,omitempty"`
	Iface string    `json:"interface,omitempty"`
	Dir   string    `json:"direction,omitempty"`
	Spec  string    `json:"spec_ref,omitempty"`
	Res   string    `json:"result,omitempty"`
	Msg   string    `json:"msg,omitempty"`
}

func fieldValue(r logRecord, name string) string {
	if name == "supi" {
		return r.SUPI
	}
	return r.CorrelationID
}

// traces fetches the AMF's Jaeger traces for a correlation id and reshapes them
// with the same timeline the trace tool uses.
func (t procedureTimelineTool) traces(ctx context.Context, id string) (any, error) {
	cctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	raw, err := t.d.Obs.JaegerTraces(cctx, "AMF", map[string]string{"correlation_id": id}, 5)
	if err != nil {
		return nil, err
	}
	return trace.Timeline(raw)
}

// ---- ue_diagnose ------------------------------------------------------------

type ueDiagnoseTool struct{ d Deps }

func (ueDiagnoseTool) Name() string        { return "ue_diagnose" }
func (ueDiagnoseTool) Risk() registry.Risk { return registry.ReadOnly }
func (ueDiagnoseTool) Description() string {
	return "Diagnose one UE in a single call: AMF context (5GMM and CM state), SMF PDU sessions, the PCF QoS " +
		"override, the UDM subscription QoS and the recent REJECT/FAILURE logs. Returns findings that name " +
		"the spec clause each check comes from. Upstream failures are reported in errors[], not hidden."
}
func (ueDiagnoseTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string","description":"e.g. imsi-001010000000001"}},"required":["supi"]}`)
}
func (ueDiagnoseTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"findings":{"type":"array"},"errors":{"type":"array"}}}`)
}

type diagnosis struct {
	mu       sync.Mutex
	errs     []map[string]string
	amf      json.RawMessage
	sessions []json.RawMessage
	pcf      *clients.PCFQoSPolicy // nil when no override is set
	udm      json.RawMessage
	logs     []logEntry
	// truncated is set when Loki returned diagnoseLokiLimit lines: older ones were cut.
	truncated bool
}

type logEntry struct {
	Time time.Time `json:"time"`
	NF   string    `json:"nf"`
	Proc string    `json:"procedure,omitempty"`
	Res  string    `json:"result,omitempty"`
	Spec string    `json:"spec_ref,omitempty"`
	Msg  string    `json:"msg,omitempty"`
}

func (d *diagnosis) fail(source string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.errs = append(d.errs, map[string]string{"source": source, "error": err.Error()})
}

func (t ueDiagnoseTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ue_diagnose args: %v", err)
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return nil, perr
	}

	dg := &diagnosis{}
	var wg sync.WaitGroup
	call := func(source string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
			defer cancel()
			if err := fn(cctx); err != nil {
				dg.fail(source, err)
			}
		}()
	}
	call("amf", func(c context.Context) error {
		raw, err := t.d.AMF.GetContext(c, a.SUPI)
		dg.mu.Lock()
		dg.amf = raw
		dg.mu.Unlock()
		return err
	})
	call("smf", func(c context.Context) error {
		raw, err := t.d.SMF.ListSessions(c)
		if err != nil {
			return err
		}
		mine, err := sessionsOf(raw, a.SUPI)
		if err != nil {
			return fmt.Errorf("ue_diagnose: decode SMF sessions: %w", err)
		}
		dg.mu.Lock()
		defer dg.mu.Unlock()
		dg.sessions = append(dg.sessions, mine...)
		return nil
	})
	call("pcf", func(c context.Context) error {
		p, err := t.d.PCF.GetQoSPolicy(c, a.SUPI, "")
		dg.mu.Lock()
		dg.pcf = p
		dg.mu.Unlock()
		return err
	})
	call("udm", func(c context.Context) error {
		raw, err := t.d.UDM.GetSMData(c, a.SUPI)
		dg.mu.Lock()
		dg.udm = raw
		dg.mu.Unlock()
		return err
	})
	call("loki", func(c context.Context) error {
		now := time.Now()
		lines, err := t.d.Loki.QueryRange(c, `{nf=~".+"} |= "`+a.SUPI+`" | json | result=~"REJECT|FAILURE"`,
			now.Add(-diagnoseLogWindow), now, diagnoseLokiLimit)
		if err != nil {
			return err
		}
		dg.mu.Lock()
		defer dg.mu.Unlock()
		dg.truncated = len(lines) >= diagnoseLokiLimit
		for _, l := range lines {
			var r logRecord
			if json.Unmarshal([]byte(l.Line), &r) != nil {
				continue
			}
			if r.Result != "REJECT" && r.Result != "FAILURE" {
				continue // the line filter is a substring match; keep only real outcomes
			}
			dg.logs = append(dg.logs, logEntry{Time: l.Time, NF: r.NF, Proc: r.Procedure,
				Res: r.Result, Spec: r.SpecRef, Msg: r.Msg})
		}
		return nil
	})
	wg.Wait()

	// Newest first, whatever order the Loki client returned the lines in.
	sort.SliceStable(dg.logs, func(i, j int) bool { return dg.logs[i].Time.After(dg.logs[j].Time) })
	findings := buildFindings(dg)
	var amfView map[string]any
	if dg.amf != nil {
		var snap struct {
			GMMState string `json:"gmm_state"`
			CMState  string `json:"cm_state"`
			GUTI     string `json:"guti"`
		}
		_ = json.Unmarshal(dg.amf, &snap)
		amfView = map[string]any{"gmm_state": snap.GMMState, "cm_state": snap.CMState, "guti": snap.GUTI}
	}
	return map[string]any{
		"supi":                 a.SUPI,
		"logs_truncated":       dg.truncated,
		"amf":                  amfView,
		"smf_sessions":         dg.sessions,
		"pcf_override":         dg.pcf,
		"subscription_sm_data": dg.udm,
		"recent_errors":        groupErrors(dg.logs, recentErrorsTopN),
		"findings":             findings,
		"errors":               dg.errs,
	}, nil
}

// buildFindings turns the collected state into checks. Each finding names the
// clause it tests, so the reader can go to the spec.
func buildFindings(dg *diagnosis) []map[string]string {
	var out []map[string]string
	add := func(sev, msg, spec string) {
		out = append(out, map[string]string{"severity": sev, "message": msg, "spec_ref": spec})
	}
	var snap struct {
		GMMState string `json:"gmm_state"`
		CMState  string `json:"cm_state"`
	}
	if dg.amf == nil {
		add("error", "UE context not found in the AMF: the UE is not registered", "TS 23.502 §4.2.2.2")
	} else {
		_ = json.Unmarshal(dg.amf, &snap)
		if !registeredState(snap.GMMState) {
			add("warning", "5GMM state is "+snap.GMMState+", not REGISTERED", "TS 24.501 §5.1.3")
		}
	}
	if len(dg.sessions) > 0 && cmIdle(snap.CMState) {
		add("warning", "UE is CM-IDLE: this AMF does not page for NW-initiated PDU session modification "+
			"(TS 23.502 §4.3.3.2 step 3b expects a network-triggered Service Request, §4.2.3.3); page the UE first (ue_page)",
			"TS 23.502 §4.3.3.2")
	}
	if dg.pcf != nil {
		add("info", "a PCF QoS override is set for this UE; new sessions use it", "TS 29.512 §5.2.2.2")
	}
	if n := len(dg.logs); n > 0 {
		last := dg.logs[0] // newest: dg.logs is sorted newest first
		count := strconv.Itoa(n)
		if dg.truncated {
			count = fmt.Sprintf("at least %d (capped at the query limit)", diagnoseLokiLimit)
		}
		msg := fmt.Sprintf("%s REJECT/FAILURE log records in the last %s; latest %s %s",
			count, strings.TrimSuffix(diagnoseLogWindow.String(), "0s"), last.NF, last.Proc)
		if last.Msg != "" {
			msg += ": " + last.Msg
		}
		add("warning", msg, last.Spec)
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i]["severity"]) < severityRank(out[j]["severity"]) })
	return out
}

// sessionsOf returns the SMF sessions of supi from a GET /nsmf-management/v1/sessions
// body. The SMF answers {"count":n,"sessions":[...]}; a bare array is also accepted.
func sessionsOf(raw []byte, supi string) ([]json.RawMessage, error) {
	var wrapped struct {
		Sessions []json.RawMessage `json:"sessions"`
	}
	all := []json.RawMessage(nil)
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		all = wrapped.Sessions
	} else if err := json.Unmarshal(raw, &all); err != nil {
		return nil, err
	}
	var out []json.RawMessage
	for _, s := range all {
		var row struct {
			SUPI string `json:"supi"`
		}
		if err := json.Unmarshal(s, &row); err != nil {
			return nil, err
		}
		if row.SUPI == supi {
			out = append(out, s)
		}
	}
	return out, nil
}

// cmIdle reports whether a CM state is CM-IDLE. The AMF reports the TS 23.501
// §5.3.3 names ("CM-IDLE", "CM-CONNECTED"); the bare "IDLE" form is accepted too.
func cmIdle(state string) bool {
	return strings.TrimPrefix(state, "CM-") == "IDLE"
}

// errorGroup is one row of recent_errors: identical (nf, procedure, result, msg)
// log lines collapsed into a count with their first and last timestamps.
type errorGroup struct {
	NF    string    `json:"nf"`
	Proc  string    `json:"procedure"`
	Res   string    `json:"result"`
	Msg   string    `json:"msg"`
	Spec  string    `json:"spec_ref"`
	Count int       `json:"count"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// groupErrors groups log entries by (nf, procedure, result, msg), orders the
// groups by count descending (ties: most recent first) and keeps the top n.
func groupErrors(logs []logEntry, n int) []errorGroup {
	idx := map[[4]string]int{}
	groups := []errorGroup{}
	for _, l := range logs {
		k := [4]string{l.NF, l.Proc, l.Res, l.Msg}
		i, ok := idx[k]
		if !ok {
			idx[k] = len(groups)
			groups = append(groups, errorGroup{NF: l.NF, Proc: l.Proc, Res: l.Res, Msg: l.Msg,
				Spec: l.Spec, Count: 1, First: l.Time, Last: l.Time})
			continue
		}
		g := &groups[i]
		g.Count++
		if l.Time.Before(g.First) {
			g.First = l.Time
		}
		if l.Time.After(g.Last) {
			g.Last = l.Time
			if l.Spec != "" {
				g.Spec = l.Spec
			}
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].Last.After(groups[j].Last)
	})
	if len(groups) > n {
		groups = groups[:n]
	}
	return groups
}

// registeredState reports whether a 5GMM state is REGISTERED. The AMF reports the
// TS 24.501 names with a "5GMM-" prefix (for example 5GMM-REGISTERED), so both forms count.
func registeredState(state string) bool {
	return strings.TrimPrefix(state, "5GMM-") == "REGISTERED"
}

func severityRank(s string) int {
	switch s {
	case "error":
		return 0
	case "warning":
		return 1
	default:
		return 2
	}
}

// ---- procedure_stats --------------------------------------------------------

type procedureStatsTool struct{ d Deps }

func (procedureStatsTool) Name() string        { return "procedure_stats" }
func (procedureStatsTool) Risk() registry.Risk { return registry.ReadOnly }
func (procedureStatsTool) Description() string {
	return "Procedure outcomes over a window from fivegc_procedure_total: per NF and procedure, the OK, " +
		"REJECT and FAILURE counts, the success percentage and the rate per minute. Optional nf and " +
		"procedure filters. Window at most 7 days (default 1h). Rows whose counts are all 0 are omitted " +
		"unless include_zero is true (every NF exports every shared counter)."
}
func (procedureStatsTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"nf":{"type":"string","description":"NF name, e.g. AMF"},
"procedure":{"type":"string","description":"procedure name, e.g. InitialRegistration"},
"window":{"type":"string","description":"window, e.g. 1h or 24h (default 1h, max 7d)"},
"include_zero":{"type":"boolean","description":"also return rows whose OK, REJECT and FAILURE counts are all 0 (default false)"}}}`)
}
func (procedureStatsTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"window":{},"rows":{"type":"array"}}}`)
}

func (t procedureStatsTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		NF          string `json:"nf"`
		Procedure   string `json:"procedure"`
		Window      string `json:"window"`
		IncludeZero bool   `json:"include_zero"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "procedure_stats args: %v", err)
	}
	if a.NF != "" && !nameRe.MatchString(a.NF) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "nf must be a NF name, got %q", a.NF)
	}
	if a.Procedure != "" && !nameRe.MatchString(a.Procedure) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "procedure must be a CamelCase name, got %q", a.Procedure)
	}
	window, perr := parseWindow(a.Window, time.Hour, 7*24*time.Hour)
	if perr != nil {
		return nil, perr
	}

	var sel []string
	if a.NF != "" {
		sel = append(sel, `nf="`+a.NF+`"`)
	}
	if a.Procedure != "" {
		sel = append(sel, `procedure="`+a.Procedure+`"`)
	}
	q := fmt.Sprintf(`sum by (nf, procedure, result) (increase(fivegc_procedure_total{%s}[%s]))`,
		strings.Join(sel, ","), promDuration(window))
	res, err := t.d.Prom.Query(ctx, q, time.Time{})
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("procedure_stats: %w", err), nil)
	}

	type acc struct{ ok, reject, failure float64 }
	groups := map[string]*acc{}
	keys := []string{}
	for _, s := range res.Data.Result {
		k := s.Metric["nf"] + "\x00" + s.Metric["procedure"]
		g, ok := groups[k]
		if !ok {
			g = &acc{}
			groups[k] = g
			keys = append(keys, k)
		}
		v := s.Float64()
		switch s.Metric["result"] {
		case "OK":
			g.ok += v
		case "REJECT":
			g.reject += v
		case "FAILURE":
			g.failure += v
		}
	}
	sort.Strings(keys)
	rows := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		parts := strings.SplitN(k, "\x00", 2)
		g := groups[k]
		total := g.ok + g.reject + g.failure
		if !a.IncludeZero && math.Round(g.ok) == 0 && math.Round(g.reject) == 0 && math.Round(g.failure) == 0 {
			continue
		}
		pct := 0.0
		if total > 0 {
			pct = math.Round(g.ok/total*1000) / 10
		}
		rows = append(rows, map[string]any{
			"nf":          parts[0],
			"procedure":   parts[1],
			"ok":          math.Round(g.ok),
			"reject":      math.Round(g.reject),
			"failure":     math.Round(g.failure),
			"success_pct": pct,
			"per_minute":  math.Round(total/window.Minutes()*100) / 100,
		})
	}
	return map[string]any{"window": window.String(), "rows": rows}, nil
}

// promDuration renders a Go duration as a PromQL range, e.g. 90m -> 5400s.
func promDuration(d time.Duration) string {
	return fmt.Sprintf("%ds", int64(d.Seconds()))
}

// summaryLegacySchema is the input schema of the deprecated procedure_summary.
var summaryLegacySchema = schema(`{"type":"object","properties":{
"metric":{"type":"string","description":"metric name, only fivegc_procedure_total is supported now"},
"query":{"type":"string","description":"removed: use metric_query for raw PromQL"}}}`)

// mapSummaryLegacy turns procedure_summary arguments into procedure_stats
// arguments. Raw PromQL has no equivalent here and is refused with a pointer to
// metric_query, so the change is never silent.
func mapSummaryLegacy(in json.RawMessage) (json.RawMessage, error) {
	var old struct {
		Metric string `json:"metric"`
		Query  string `json:"query"`
	}
	if err := json.Unmarshal(in, &old); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "procedure_summary args: %v", err)
	}
	if old.Query != "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams,
			"procedure_summary raw query mode was removed: run the PromQL with metric_query", nil)
	}
	if old.Metric != "" && old.Metric != "fivegc_procedure_total" {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"metric": old.Metric},
			"procedure_summary now reports fivegc_procedure_total only; use metric_query for %s", old.Metric)
	}
	return json.RawMessage("{}"), nil
}

// ---- pcap_list / pcap_control ----------------------------------------------

// pcapNF maps an NF name to the portal's sidecar key. The portal keys its
// sidecars in lower case (amf, smf, …), so "AMF" and "amf" are the same NF.
func pcapNF(name string) (string, *mcperr.Error) {
	if !nameRe.MatchString(name) {
		return "", mcperr.Newf(mcperr.CodeInvalidParams, nil, "nf must be a NF name, got %q", name)
	}
	return strings.ToLower(name), nil
}

type pcapListTool struct{ d Deps }

func (pcapListTool) Name() string        { return "pcap_list" }
func (pcapListTool) Risk() registry.Risk { return registry.ReadOnly }
func (pcapListTool) Description() string {
	return "PCAP capture state of each NF sidecar (capturing, paused, file count). With nf, also the capture " +
		"files of that NF. Read-only. Use the captures with pcap-analyzer."
}
func (pcapListTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"nf":{"type":"string","description":"optional NF, e.g. AMF"}}}`)
}
func (pcapListTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }
func (t pcapListTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		NF string `json:"nf"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pcap_list args: %v", err)
	}
	status, err := t.d.Portal.Get(ctx, "/pcap/status", nil)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pcap_list: %w", err), nil)
	}
	out := map[string]any{"status": status}
	if a.NF != "" {
		nf, perr := pcapNF(a.NF)
		if perr != nil {
			return nil, perr
		}
		files, err := t.d.Portal.Get(ctx, "/pcap/"+nf+"/files", nil)
		if err != nil {
			return nil, mcperr.ToolError(fmt.Errorf("pcap_list: %w", err), nil)
		}
		out["files"] = files
	}
	return out, nil
}

type pcapControlTool struct{ d Deps }

func (pcapControlTool) Name() string        { return "pcap_control" }
func (pcapControlTool) Risk() registry.Risk { return registry.Mutating }
func (pcapControlTool) Description() string {
	return "Start, stop, pause, resume or rotate the tcpdump capture of one NF sidecar. Changes only the " +
		"capture state (no core procedure), so it runs without confirm. Pause suspends tcpdump (SIGSTOP)."
}
func (pcapControlTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"nf":{"type":"string","description":"NF whose sidecar to control, e.g. AMF (case does not matter)"},
"action":{"type":"string","enum":["start","stop","pause","resume","rotate"]}},"required":["nf","action"]}`)
}
func (pcapControlTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }
func (t pcapControlTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		NF     string `json:"nf"`
		Action string `json:"action"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pcap_control args: %v", err)
	}
	nf, perr := pcapNF(a.NF)
	if perr != nil {
		return nil, perr
	}
	switch a.Action {
	case "start", "stop", "pause", "resume", "rotate":
	default:
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "action must be start|stop|pause|resume|rotate, got %q", a.Action)
	}
	body, status, err := t.d.Portal.Post(ctx, "/pcap/"+nf+"/"+a.Action, nil)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pcap_control: %w", err), nil)
	}
	if status < 200 || status > 299 {
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"status": status},
			"portal refused pcap %s on %s: %s", a.Action, nf, body)
	}
	return map[string]any{"nf": nf, "action": a.Action, "result": body}, nil
}
