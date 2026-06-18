// Package trace implements MCP Group D tools: SBI trace and metric queries over
// the Jaeger and Prometheus HTTP APIs.
package trace

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// All returns the Group D tools bound to an observability client.
func All(obs *clients.Obs) []registry.Tool {
	return []registry.Tool{queryTool{obs}, summaryTool{obs}}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// ---- trace_query ----------------------------------------------------------

type queryTool struct{ obs *clients.Obs }

func (queryTool) Name() string { return "trace_query" }
func (queryTool) Description() string {
	return "Query distributed traces from Jaeger for a service, optionally filtered by a tag " +
		"such as correlation_id or supi, returning the matching spans as a timeline. Spans are " +
		"produced by the OTel instrumentation on every NF SBI handler."
}
func (queryTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"trace_id":{"type":"string","description":"fetch a single trace by id"},"service":{"type":"string","description":"NF service name, e.g. AMF"},"correlation_id":{"type":"string"},"supi":{"type":"string"},"limit":{"type":"integer","description":"max traces (default 20)"}}}`)
}
func (queryTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","description":"raw Jaeger API response (data: array of traces with spans)"}`)
}
func (t queryTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		TraceID       string `json:"trace_id"`
		Service       string `json:"service"`
		CorrelationID string `json:"correlation_id"`
		SUPI          string `json:"supi"`
		Limit         int    `json:"limit"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "trace_query args: %v", err)
	}
	if a.TraceID != "" {
		raw, err := t.obs.JaegerTrace(ctx, a.TraceID)
		if err != nil {
			return nil, mcperr.ToolError(fmt.Errorf("trace_query: %w", err), nil)
		}
		return raw, nil
	}
	if a.Service == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams,
			"either trace_id or service is required", nil)
	}
	tags := map[string]string{}
	if a.CorrelationID != "" {
		tags["correlation_id"] = a.CorrelationID
	}
	if a.SUPI != "" {
		tags["supi"] = a.SUPI
	}
	if a.Limit == 0 {
		a.Limit = 20
	}
	raw, err := t.obs.JaegerTraces(ctx, a.Service, tags, a.Limit)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("trace_query: %w", err), nil)
	}
	return raw, nil
}

// ---- procedure_summary ----------------------------------------------------

type summaryTool struct{ obs *clients.Obs }

func (summaryTool) Name() string { return "procedure_summary" }
func (summaryTool) Description() string {
	return "Summarise success/failure counts for a procedure from Prometheus. Accepts a raw " +
		"PromQL query, or a metric name to aggregate. Backed by the NF /metrics endpoints."
}
func (summaryTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"query":{"type":"string","description":"raw PromQL; takes precedence"},"metric":{"type":"string","description":"metric name to sum by result label"}},"required":[]}`)
}
func (summaryTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","description":"raw Prometheus query API response"}`)
}
func (t summaryTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		Query  string `json:"query"`
		Metric string `json:"metric"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "procedure_summary args: %v", err)
	}
	q := a.Query
	if q == "" {
		if a.Metric == "" {
			return nil, mcperr.New(mcperr.CodeInvalidParams,
				"either query or metric is required", nil)
		}
		// Aggregate the metric by its result label (OK/REJECT/FAILURE).
		q = fmt.Sprintf("sum by (result) (%s)", a.Metric)
	}
	raw, err := t.obs.PromQuery(ctx, q)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("procedure_summary: %w", err), nil)
	}
	return raw, nil
}
