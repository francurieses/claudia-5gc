package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

const (
	// errorSummaryDefaultWindow is the look-back when window is omitted.
	errorSummaryDefaultWindow = 15 * time.Minute
	// errorSummaryMaxWindow is the largest accepted window.
	errorSummaryMaxWindow = time.Hour
	// errorSummaryDefaultTop and errorSummaryMaxTop bound the number of rows.
	errorSummaryDefaultTop = 10
	errorSummaryMaxTop     = 50
	// errorExampleTimeout bounds the best-effort example lookups as a whole.
	errorExampleTimeout = 5 * time.Second
	// errorExampleParallel is the number of example lookups in flight at once.
	errorExampleParallel = 5
)

var nfUpperRe = regexp.MustCompile(`^[A-Z]{2,16}$`)

// errorSummaryTool groups the REJECT and FAILURE log records of a window by NF,
// procedure, result, cause and spec clause, with one example per group.
type errorSummaryTool struct{ d Deps }

func (errorSummaryTool) Name() string        { return "error_summary" }
func (errorSummaryTool) Risk() registry.Risk { return registry.ReadOnly }
func (errorSummaryTool) Description() string {
	return "Top error groups in the NF logs: REJECT and FAILURE records of the window counted by " +
		"(nf, procedure, result, cause, spec_ref), highest count first, each with an example_correlation_id " +
		"(feed it to procedure_timeline) and the last_seen time. Window up to 1h (default 15m); top 1-50 (default 10). " +
		"Backend: a Loki metric query over the JSON log fields. Each row cites the spec_ref the NF logged."
}
func (errorSummaryTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"window":{"type":"string","description":"look-back window, e.g. 15m or 1h (default 15m, max 1h)"},
"nf":{"type":"string","description":"only this NF, uppercase, e.g. AMF or SMF"},
"top":{"type":"integer","description":"number of groups, 1-50 (default 10)"}}}`)
}
func (errorSummaryTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"window":{"type":"string"},"rows":{"type":"array"}}}`)
}

// logRange renders a duration as a LogQL range: 15m, 1h, 90s.
func logRange(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", int64(d/time.Minute))
	default:
		return fmt.Sprintf("%ds", int64(d.Seconds()))
	}
}

type errorRow struct {
	NF        string  `json:"nf"`
	Procedure string  `json:"procedure"`
	Result    string  `json:"result"`
	Cause     string  `json:"cause"`
	SpecRef   string  `json:"spec_ref"`
	Count     int64   `json:"count"`
	Example   string  `json:"example_correlation_id"`
	LastSeen  string  `json:"last_seen"`
	raw       float64 `json:"-"`
}

func (t errorSummaryTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		Window string `json:"window"`
		NF     string `json:"nf"`
		Top    *int   `json:"top"`
	}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &a); err != nil {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "error_summary args: %v", err)
		}
	}
	window, perr := parseWindow(a.Window, errorSummaryDefaultWindow, errorSummaryMaxWindow)
	if perr != nil {
		return nil, perr
	}
	top := errorSummaryDefaultTop
	if a.Top != nil {
		top = *a.Top
	}
	if top < 1 || top > errorSummaryMaxTop {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"top": top},
			"top must be 1-%d, got %d", errorSummaryMaxTop, top)
	}
	if a.NF != "" && !nfUpperRe.MatchString(a.NF) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"nf": a.NF},
			"nf must be an upper-case NF name such as AMF, got %q", a.NF)
	}

	sel := `{nf=~".+"}`
	if a.NF != "" {
		sel = `{nf="` + a.NF + `"}`
	}
	logql := fmt.Sprintf(`sum by (nf,procedure,result,cause,spec_ref) (count_over_time(%s | json | result=~"REJECT|FAILURE" [%s]))`,
		sel, logRange(window))
	now := time.Now()
	samples, err := t.d.Loki.QueryMetric(ctx, logql, now)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("error_summary: %w", err), nil)
	}
	rows := make([]errorRow, 0, len(samples))
	for _, s := range samples {
		rows = append(rows, errorRow{
			NF: s.Labels["nf"], Procedure: s.Labels["procedure"], Result: s.Labels["result"],
			Cause: s.Labels["cause"], SpecRef: s.Labels["spec_ref"],
			Count: int64(math.Round(s.Value)), raw: s.Value,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].raw != rows[j].raw {
			return rows[i].raw > rows[j].raw
		}
		if rows[i].NF != rows[j].NF {
			return rows[i].NF < rows[j].NF
		}
		return rows[i].Procedure < rows[j].Procedure
	})
	if len(rows) > top {
		rows = rows[:top]
	}
	t.fillExamples(ctx, rows, now, window)

	slog.InfoContext(ctx, "error summary built", "nf", "MCP", "procedure", "McpStatusAnalysisWave2",
		"tool_name", "error_summary", "interface", "Loki", "direction", "OUT",
		"spec_ref", "n/a (operational)", "rows", len(rows), "latency_ms", time.Since(start).Milliseconds())
	return map[string]any{"window": window.String(), "rows": rows}, nil
}

// fillExamples sets example_correlation_id and last_seen from the newest log line
// of each group. It is best effort: a failed lookup leaves the fields empty. The
// number of extra queries is the number of rows (at most top).
func (t errorSummaryTool) fillExamples(ctx context.Context, rows []errorRow, now time.Time, window time.Duration) {
	ectx, cancel := context.WithTimeout(ctx, errorExampleTimeout)
	defer cancel()
	sem := make(chan struct{}, errorExampleParallel)
	var wg sync.WaitGroup
	for i := range rows {
		wg.Add(1)
		sem <- struct{}{}
		go func(r *errorRow) {
			defer wg.Done()
			defer func() { <-sem }()
			q := exampleQuery(r)
			lines, err := t.d.Loki.QueryRange(ectx, q, now.Add(-window), now, 1)
			if err != nil || len(lines) == 0 {
				return
			}
			var rec struct {
				CorrelationID string `json:"correlation_id"`
			}
			if json.Unmarshal([]byte(lines[0].Line), &rec) == nil {
				r.Example = rec.CorrelationID
			}
			r.LastSeen = lines[0].Time.UTC().Format(time.RFC3339Nano)
		}(&rows[i])
	}
	wg.Wait()
}

// exampleQuery selects the log lines of one error group. Label values are
// quoted with strconv.Quote so a cause or procedure cannot break out of the filter.
func exampleQuery(r *errorRow) string {
	sel := `{nf=~".+"}`
	if r.NF != "" {
		sel = `{nf=` + strconv.Quote(r.NF) + `}`
	}
	q := sel + ` | json | result=` + strconv.Quote(r.Result)
	if r.Procedure != "" {
		q += ` | procedure=` + strconv.Quote(r.Procedure)
	}
	q += ` | cause=` + strconv.Quote(r.Cause)
	return q
}
