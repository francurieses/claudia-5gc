package status

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

func okTool(name string, r registry.Risk) registry.Tool { return stubTool{name, r} }

type stubTool struct {
	name string
	risk registry.Risk
}

func (s stubTool) Name() string                                         { return s.name }
func (s stubTool) Description() string                                  { return "stub" }
func (s stubTool) InputSchema() json.RawMessage                         { return json.RawMessage(`{"type":"object"}`) }
func (s stubTool) OutputSchema() json.RawMessage                        { return json.RawMessage(`{}`) }
func (s stubTool) Risk() registry.Risk                                  { return s.risk }
func (s stubTool) Invoke(context.Context, json.RawMessage) (any, error) { return nil, nil }

func srv(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

func asCode(t *testing.T, err error) int {
	t.Helper()
	var me *mcperr.Error
	if !errors.As(err, &me) {
		t.Fatalf("want *mcperr.Error, got %v", err)
	}
	return me.Code
}

func TestMCPInfo(t *testing.T) {
	up := srv(t, func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	reg := registry.New()
	target := okTool("real", registry.ReadOnly)
	_ = reg.RegisterAll(target, okTool("other", registry.ReadOnly), okTool("danger", registry.Disruptive),
		toolutil.Deprecated("old_real", json.RawMessage(`{"type":"object"}`), target,
			func(in json.RawMessage) (json.RawMessage, error) { return in, nil }))
	g := guard.New(guard.Options{Mode: guard.ModeReadOnly}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d := Deps{
		HTTP: http.DefaultClient, Registry: reg, Guard: g, Version: "0.1.0", BuildCommit: "abc1234",
		Upstreams: []Upstream{{Name: "prometheus", Addr: up.URL}, {Name: "amf", Addr: downURL}},
	}
	ctx := guard.WithRole(context.Background(), guard.RoleAdmin)
	out, err := mcpInfoTool{d}.Invoke(ctx, nil)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	m := out.(map[string]any)
	if m["build_commit"] != "abc1234" || m["version"] != "0.1.0" || m["access_mode"] != "read-only" || m["caller_role"] != "admin" {
		t.Errorf("identity fields: %v", m)
	}
	// read-only mode hides "danger": 2 real tools + 1 alias visible, as tools/list shows.
	if m["tool_count"] != 2 || m["alias_count"] != 1 || m["hidden_by_access_mode"] != 1 {
		t.Errorf("counts: tool=%v alias=%v hidden=%v", m["tool_count"], m["alias_count"], m["hidden_by_access_mode"])
	}
	ups := m["upstreams"].([]map[string]any)
	if ups[0]["reachable"] != true || ups[0]["latency_ms"] == nil {
		t.Errorf("prometheus (any HTTP answer, even 404) must be reachable: %v", ups[0])
	}
	if ups[1]["reachable"] != false || ups[1]["latency_ms"] != nil {
		t.Errorf("dead amf must be unreachable, call must still succeed: %v", ups[1])
	}

	d.BuildCommit = ""
	out, _ = mcpInfoTool{d}.Invoke(context.Background(), nil)
	if out.(map[string]any)["build_commit"] != "unknown" || out.(map[string]any)["caller_role"] != "viewer" {
		t.Errorf("defaults: %v", out)
	}
}

func sliceFixture(t *testing.T, failSMF bool) Deps {
	t.Helper()
	prom := srv(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
		 {"metric":{"nf":"AMF","sst":"1","sd":"000001","exported_nf":"AMF"},"value":[1,"2"]},
		 {"metric":{"nf":"SMF","sst":"1","sd":"000001"},"value":[1,"0"]}]}}`))
	})
	smf := srv(t, func(w http.ResponseWriter, _ *http.Request) {
		if failSMF {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"count":3,"sessions":[
		 {"supi":"imsi-1","dnn":"internet","sNssai":{"sst":1,"sd":"000001"},"sessionState":"ACTIVE"},
		 {"supi":"imsi-2","dnn":"internet","sNssai":{"sst":1,"sd":"000001"},"sessionState":"ACTIVE"},
		 {"supi":"imsi-3","dnn":"ims","sNssai":{"sst":2,"sd":"000002"},"sessionState":"ACTIVE"}]}`))
	})
	portal := srv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/slices/qos" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"snssai":{"sst":1,"sd":"000001"},"dnn":"internet","sessionAmbr":{"uplink":"100 Mbps","downlink":"200 Mbps"},"source":"config"}]}`))
	})
	amf := srv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"gnbs":[{"state":"NG_READY","supported_tas":[{"tac":1,"broadcast_plmns":[{"slices":[{"sst":1,"sd":"000001"}]}]}]},
		 {"state":"DISCONNECTED","supported_tas":[{"tac":1,"broadcast_plmns":[{"slices":[{"sst":1,"sd":"000001"}]}]}]}]}`))
	})
	return Deps{
		Prom:   promclient.New(prom.URL, prom.Client(), 0),
		SMF:    clients.NewSMF(smf.URL, http.DefaultClient),
		Portal: clients.NewPortal(portal.URL, http.DefaultClient),
		AMF:    clients.NewAMF(amf.URL, http.DefaultClient),
	}
}

func TestSliceStatus(t *testing.T) {
	d := sliceFixture(t, false)
	out, err := sliceStatusTool{d}.Invoke(context.Background(), json.RawMessage(`{"sst":1,"sd":"000001"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	es := out.([]sliceEntry)
	if len(es) != 1 {
		t.Fatalf("want 1 entry, got %d", len(es))
	}
	e := es[0]
	if e.RegisteredUE != 2 || e.GNBs != 1 || e.Unavailable != nil {
		t.Errorf("entry: ues=%v gnbs=%v unavailable=%v", e.RegisteredUE, e.GNBs, e.Unavailable)
	}
	if e.Sessions.(map[string]int)["internet"] != 2 {
		t.Errorf("sessions: %v", e.Sessions)
	}
	if l := e.AMBR.([]map[string]any); len(l) != 1 || l[0]["dnn"] != "internet" {
		t.Errorf("ambr: %v", e.AMBR)
	}

	// No filter: union of slices from every source (sst 1 and sst 2).
	out, _ = sliceStatusTool{d}.Invoke(context.Background(), nil)
	if es := out.([]sliceEntry); len(es) != 2 || es[0].Snssai["sst"] != 1 || es[1].Snssai["sst"] != 2 {
		t.Errorf("union: %+v", es)
	}

	// A failing source gives null + reason, not 0.
	d = sliceFixture(t, true)
	out, err = sliceStatusTool{d}.Invoke(context.Background(), json.RawMessage(`{"sst":1}`))
	if err != nil {
		t.Fatal(err)
	}
	e = out.([]sliceEntry)[0]
	if e.Sessions != nil || e.Unavailable["active_sessions_by_dnn"] == "" || e.RegisteredUE != 2 {
		t.Errorf("partial failure: %+v", e)
	}
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), `"active_sessions_by_dnn":null`) {
		t.Errorf("must serialise null: %s", b)
	}
}

func TestSliceStatusRejectsBadInput(t *testing.T) {
	d := sliceFixture(t, false)
	for _, args := range []string{`{"sd":"0001"}`, `{"sd":"00000g"}`, `{"sst":256}`, `{"sst":-1}`} {
		_, err := sliceStatusTool{d}.Invoke(context.Background(), json.RawMessage(args))
		if err == nil || asCode(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("%s: want -32602, got %v", args, err)
		}
	}
}

func bindingFixture(t *testing.T) (Deps, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var queries []string
	bsf := srv(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.RawQuery)
		mu.Unlock()
		q := r.URL.Query()
		switch {
		case q.Get("supi") == "imsi-001010000000099":
			http.NotFound(w, r)
		case q.Get("ipv4Addr") == "10.60.0.9":
			http.NotFound(w, r)
		case q.Get("ipv4Addr") != "":
			_, _ = w.Write([]byte(`{"bindingId":"b-` + q.Get("ipv4Addr") + `","ipv4Addr":"` + q.Get("ipv4Addr") + `","dnn":"internet"}`))
		default:
			_, _ = w.Write([]byte(`{"bindingId":"b-supi","supi":"` + q.Get("supi") + `","ipv4Addr":"10.60.0.1","dnn":"internet","pcfId":"pcf-1"}`))
		}
	})
	smf := srv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sessions":[{"supi":"imsi-1","ueIp":"10.60.0.1"},{"supi":"imsi-2","ueIp":"10.60.0.2"},{"supi":"imsi-3","ueIp":"10.60.0.2"},{"supi":"imsi-4"}]}`))
	})
	prom := srv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"nf":"BSF"},"value":[1,"2"]}]}}`))
	})
	return Deps{
		BSF:  clients.NewBSF(bsf.URL, http.DefaultClient),
		SMF:  clients.NewSMF(smf.URL, http.DefaultClient),
		Prom: promclient.New(prom.URL, prom.Client(), 0),
	}, &queries
}

func TestPCFBindingList(t *testing.T) {
	tests := []struct {
		name         string
		args         string
		wantBindings int
		wantQueried  int
		wantQuery    string
	}{
		{"supi filter", `{"supi":"imsi-001010000000001"}`, 1, 1, "supi=imsi-001010000000001"},
		{"ue_ip maps to ipv4Addr", `{"ue_ip":"10.60.0.1","dnn":"internet"}`, 1, 1, "dnn=internet&ipv4Addr=10.60.0.1"},
		{"404 is an empty list", `{"supi":"imsi-001010000000099"}`, 0, 1, ""},
		{"no filter: one per distinct session ueIp", `{}`, 2, 2, "ipv4Addr="},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, queries := bindingFixture(t)
			out, err := pcfBindingListTool{d}.Invoke(context.Background(), json.RawMessage(tc.args))
			if err != nil {
				t.Fatalf("invoke: %v", err)
			}
			m := out.(map[string]any)
			if got := len(m["bindings"].([]json.RawMessage)); got != tc.wantBindings {
				t.Errorf("bindings = %d, want %d", got, tc.wantBindings)
			}
			if m["queried"] != tc.wantQueried || m["bindings_active"] != 2 {
				t.Errorf("queried=%v active=%v", m["queried"], m["bindings_active"])
			}
			for _, q := range *queries {
				if tc.wantQuery != "" && !strings.Contains(q, tc.wantQuery) {
					t.Errorf("query %q lacks %q", q, tc.wantQuery)
				}
			}
		})
	}
}

func TestPCFBindingListRejectsBadInput(t *testing.T) {
	d, queries := bindingFixture(t)
	for _, args := range []string{`{"ue_ip":"999.1.1.1"}`, `{"ue_ip":"::1"}`, `{"supi":"bad"}`, `{"dnn":"bad dnn!"}`} {
		_, err := pcfBindingListTool{d}.Invoke(context.Background(), json.RawMessage(args))
		if err == nil || asCode(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("%s: want -32602, got %v", args, err)
		}
	}
	if len(*queries) != 0 {
		t.Errorf("BSF must not be contacted on invalid input, got %v", *queries)
	}
}

func TestPCFBindingListBSFDown(t *testing.T) {
	d, _ := bindingFixture(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	u := dead.URL
	dead.Close()
	d.BSF = clients.NewBSF(u, http.DefaultClient)
	_, err := pcfBindingListTool{d}.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	if err == nil || asCode(t, err) != mcperr.CodeToolError {
		t.Errorf("want -32000, got %v", err)
	}
}
