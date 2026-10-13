package qos

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

func listTool(t *testing.T, handler http.HandlerFunc) (registry.Tool, *call) {
	t.Helper()
	rec := &call{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return listPolicyTool{clients.NewPCF(srv.URL, http.DefaultClient)}, rec
}

func TestQoSPolicyListNormalisesEntries(t *testing.T) {
	tl, rec := listTool(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"supi":"imsi-001010000000001","5qi":7,"dnn":"internet","arp_priority_level":8,"ambr_uplink":"50 Mbps","ambr_downlink":"100 Mbps"},` +
			`{"supi":"imsi-001010000000002","5qi":9}]`))
	})
	if tl.Risk() != registry.ReadOnly {
		t.Errorf("risk %s", tl.Risk())
	}
	out, err := tl.Invoke(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	var list []map[string]any
	if err := json.Unmarshal(b, &list); err != nil || len(list) != 2 {
		t.Fatalf("result: %s %v", b, err)
	}
	e := list[0]
	if e["supi"] != "imsi-001010000000001" || e["dnn"] != "internet" || e["5qi"] != float64(7) ||
		e["arp"] != float64(8) || e["ambr_ul"] != "50 Mbps" || e["ambr_dl"] != "100 Mbps" {
		t.Errorf("entry 0: %v", e)
	}
	for _, k := range []string{"supi", "5qi", "arp", "ambr_ul", "ambr_dl"} {
		if _, ok := list[1][k]; !ok {
			t.Errorf("entry 1 misses key %s: %v", k, list[1])
		}
	}
	if _, ok := list[1]["dnn"]; ok {
		t.Error("dnn must be omitted when the override is not DNN-scoped")
	}
	if !rec.has("GET /pcf-internal/v1/sm-policy-overrides") || len(rec.calls) != 1 {
		t.Errorf("calls: %v", rec.calls)
	}
}

func TestQoSPolicyListEmptyIsArrayNotNull(t *testing.T) {
	tl, _ := listTool(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	out, err := tl.Invoke(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(out); string(b) != "[]" {
		t.Errorf("empty list must marshal to [], got %s", b)
	}
	// A PCF that answers JSON null also yields [].
	tl, _ = listTool(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`null`)) })
	out, _ = tl.Invoke(context.Background(), json.RawMessage(`{}`))
	if b, _ := json.Marshal(out); string(b) != "[]" {
		t.Errorf("null must marshal to [], got %s", b)
	}
}

func TestQoSPolicyListSupiFilterAndValidation(t *testing.T) {
	tl, rec := listTool(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	if _, err := tl.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`)); err != nil {
		t.Fatal(err)
	}
	if !rec.has("GET /pcf-internal/v1/sm-policy-overrides?supi=imsi-001010000000001") {
		t.Errorf("filter not sent: %v", rec.calls)
	}
	n := len(rec.calls)
	_, err := tl.Invoke(context.Background(), json.RawMessage(`{"supi":"not-a-supi"}`))
	if e, ok := err.(*mcperr.Error); !ok || e.Code != mcperr.CodeInvalidParams {
		t.Errorf("want -32602, got %v", err)
	}
	if len(rec.calls) != n {
		t.Error("the PCF must not be called for an invalid supi")
	}
}

func TestQoSPolicyListUpstreamError(t *testing.T) {
	tl, _ := listTool(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	_, err := tl.Invoke(context.Background(), json.RawMessage(`{}`))
	e, ok := err.(*mcperr.Error)
	if !ok || e.Code != mcperr.CodeToolError || !strings.Contains(e.Message, "500") || e.Data["status"] != 500 {
		t.Errorf("want -32000 with status 500, got %#v", err)
	}
}
