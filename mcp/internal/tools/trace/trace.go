// Package trace implements MCP Group D tools: SBI trace and metric queries over
// the Jaeger and Prometheus HTTP APIs.
package trace

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// All returns the Group D tools bound to an observability client.
func All(obs *clients.Obs) []registry.Tool {
	return []registry.Tool{queryTool{obs}}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// ---- trace_query ----------------------------------------------------------

type queryTool struct{ obs *clients.Obs }

func (queryTool) Name() string        { return "trace_query" }
func (queryTool) Risk() registry.Risk { return registry.ReadOnly }
func (queryTool) Description() string {
	return "Query distributed traces from Jaeger for a service, optionally filtered by a tag " +
		"such as correlation_id or supi. format:timeline (default) returns, per trace, the spans " +
		"ordered by start with service, operation, offset and duration in ms, and marks errors. " +
		"format:raw returns the Jaeger response unchanged. limit is at most 50 traces. " +
		"Spans come from the OTel instrumentation on every NF SBI handler."
}
func (queryTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"trace_id":{"type":"string","description":"fetch a single trace by id"},
"service":{"type":"string","description":"NF service name, e.g. AMF"},
"correlation_id":{"type":"string"},
"supi":{"type":"string"},
"limit":{"type":"integer","description":"max traces, 1-50 (default 20)"},
"format":{"type":"string","enum":["timeline","raw"],"description":"timeline (default) or raw Jaeger JSON"}}}`)
}
func (queryTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"mode":{"type":"string"},"traces":{"type":"array"}}}`)
}

const (
	defaultTraceLimit = 20
	maxTraceLimit     = 50
)

func (t queryTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		TraceID       string `json:"trace_id"`
		Service       string `json:"service"`
		CorrelationID string `json:"correlation_id"`
		SUPI          string `json:"supi"`
		Limit         int    `json:"limit"`
		Format        string `json:"format"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "trace_query args: %v", err)
	}
	if a.Format == "" {
		a.Format = "timeline"
	}
	if a.Format != "timeline" && a.Format != "raw" {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "format must be timeline or raw, got %q", a.Format)
	}
	if a.Limit == 0 {
		a.Limit = defaultTraceLimit
	}
	if a.Limit < 1 || a.Limit > maxTraceLimit {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "limit must be 1-%d, got %d", maxTraceLimit, a.Limit)
	}

	var raw json.RawMessage
	var err error
	switch {
	case a.TraceID != "":
		raw, err = t.obs.JaegerTrace(ctx, a.TraceID)
	case a.Service == "":
		return nil, mcperr.New(mcperr.CodeInvalidParams,
			"either trace_id or service is required", nil)
	default:
		tags := map[string]string{}
		if a.CorrelationID != "" {
			tags["correlation_id"] = a.CorrelationID
		}
		if a.SUPI != "" {
			tags["supi"] = a.SUPI
		}
		raw, err = t.obs.JaegerTraces(ctx, a.Service, tags, a.Limit)
	}
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("trace_query: %w", err), nil)
	}
	if a.Format == "raw" {
		return raw, nil
	}
	return Timeline(raw)
}

// jaegerResponse is the subset of the Jaeger query API response the timeline needs.
type jaegerResponse struct {
	Data []struct {
		TraceID   string `json:"traceID"`
		Processes map[string]struct {
			ServiceName string `json:"serviceName"`
		} `json:"processes"`
		Spans []struct {
			SpanID        string `json:"spanID"`
			OperationName string `json:"operationName"`
			ProcessID     string `json:"processID"`
			StartTime     int64  `json:"startTime"` // microseconds
			Duration      int64  `json:"duration"`  // microseconds
			Tags          []struct {
				Key   string `json:"key"`
				Value any    `json:"value"`
			} `json:"tags"`
		} `json:"spans"`
	} `json:"data"`
}

// Timeline reshapes a Jaeger response into per-trace span lists ordered by start
// time, with offsets relative to the trace's first span.
func Timeline(raw json.RawMessage) (any, error) {
	var jr jaegerResponse
	if err := json.Unmarshal(raw, &jr); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("trace_query: decode Jaeger response: %w", err), nil)
	}
	type span struct {
		Service    string  `json:"service"`
		Operation  string  `json:"operation"`
		SpanID     string  `json:"span_id"`
		OffsetMs   float64 `json:"start_offset_ms"`
		DurationMs float64 `json:"duration_ms"`
		Error      bool    `json:"error"`
	}
	type trace struct {
		TraceID string  `json:"trace_id"`
		TotalMs float64 `json:"total_ms"`
		Spans   []span  `json:"spans"`
	}
	traces := make([]trace, 0, len(jr.Data))
	for _, d := range jr.Data {
		if len(d.Spans) == 0 {
			continue
		}
		first := d.Spans[0].StartTime
		var last int64
		for _, sp := range d.Spans {
			if sp.StartTime < first {
				first = sp.StartTime
			}
		}
		spans := make([]span, 0, len(d.Spans))
		for _, sp := range d.Spans {
			if end := sp.StartTime + sp.Duration; end > last {
				last = end
			}
			spans = append(spans, span{
				Service:    d.Processes[sp.ProcessID].ServiceName,
				Operation:  sp.OperationName,
				SpanID:     sp.SpanID,
				OffsetMs:   float64(sp.StartTime-first) / 1000,
				DurationMs: float64(sp.Duration) / 1000,
				Error:      isError(sp.Tags),
			})
		}
		sort.SliceStable(spans, func(i, j int) bool { return spans[i].OffsetMs < spans[j].OffsetMs })
		traces = append(traces, trace{
			TraceID: d.TraceID,
			TotalMs: float64(last-first) / 1000,
			Spans:   spans,
		})
	}
	return map[string]any{"mode": "timeline", "traces": traces}, nil
}

// isError reports whether a span carries an error marker: the OTel error tag or
// a status code of ERROR.
func isError(tags []struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}) bool {
	for _, t := range tags {
		switch t.Key {
		case "error":
			if b, ok := t.Value.(bool); ok && b {
				return true
			}
		case "otel.status_code":
			if s, ok := t.Value.(string); ok && s == "ERROR" {
				return true
			}
		}
	}
	return false
}
