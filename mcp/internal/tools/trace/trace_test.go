package trace

import (
	"context"
	"encoding/json"
	"testing"
)

// jaegerFixture is two spans of one trace, delivered out of start order, the
// second marked as an error. Times are microseconds as Jaeger reports them.
const jaegerFixture = `{"data":[{"traceID":"t1",
 "processes":{"p1":{"serviceName":"AMF"},"p2":{"serviceName":"SMF"}},
 "spans":[
  {"spanID":"s2","operationName":"POST /nsmf-pdusession","processID":"p2","startTime":1500,"duration":4000,
   "tags":[{"key":"error","type":"bool","value":true}]},
  {"spanID":"s1","operationName":"POST /namf-comm","processID":"p1","startTime":1000,"duration":9000,"tags":[]}
 ]}]}`

func TestTimelineOrdersSpansAndMarksErrors(t *testing.T) {
	out, err := Timeline(json.RawMessage(jaegerFixture))
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	raw, _ := json.Marshal(out)
	var got struct {
		Mode   string `json:"mode"`
		Traces []struct {
			TraceID string  `json:"trace_id"`
			TotalMs float64 `json:"total_ms"`
			Spans   []struct {
				Service  string  `json:"service"`
				Offset   float64 `json:"start_offset_ms"`
				Duration float64 `json:"duration_ms"`
				Error    bool    `json:"error"`
			} `json:"spans"`
		} `json:"traces"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Mode != "timeline" || len(got.Traces) != 1 {
		t.Fatalf("shape: %s", raw)
	}
	tr := got.Traces[0]
	if tr.TotalMs != 9 {
		t.Errorf("total_ms: got %v, want 9 (first start 1000us to last end 10000us)", tr.TotalMs)
	}
	if len(tr.Spans) != 2 || tr.Spans[0].Service != "AMF" || tr.Spans[1].Service != "SMF" {
		t.Fatalf("span order: %s", raw)
	}
	if tr.Spans[1].Offset != 0.5 || tr.Spans[1].Duration != 4 {
		t.Errorf("offset/duration: %+v", tr.Spans[1])
	}
	if tr.Spans[0].Error || !tr.Spans[1].Error {
		t.Errorf("error flags: %+v", tr.Spans)
	}
}

func TestTimelineErrorStatusCode(t *testing.T) {
	fixture := `{"data":[{"traceID":"t","processes":{"p":{"serviceName":"PCF"}},"spans":[
	 {"spanID":"s","operationName":"op","processID":"p","startTime":1,"duration":1,
	  "tags":[{"key":"otel.status_code","type":"string","value":"ERROR"}]}]}]}`
	out, err := Timeline(json.RawMessage(fixture))
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	raw, _ := json.Marshal(out)
	if want := `"error":true`; !contains(string(raw), want) {
		t.Errorf("otel.status_code ERROR not flagged: %s", raw)
	}
}

func TestTimelineRejectsGarbage(t *testing.T) {
	if _, err := Timeline(json.RawMessage(`not json`)); err == nil {
		t.Error("garbage input must be an error")
	}
}

func TestQueryLimitCapIs50(t *testing.T) {
	tool := queryTool{}
	for _, args := range []string{`{"service":"AMF","limit":51}`, `{"service":"AMF","limit":0,"format":"x"}`} {
		if _, err := tool.Invoke(context.Background(), json.RawMessage(args)); err == nil {
			t.Errorf("%s: want validation error", args)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
