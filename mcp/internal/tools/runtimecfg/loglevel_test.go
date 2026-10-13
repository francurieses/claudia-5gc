package runtimecfg

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// nfAdmin stands in for an NF's metrics port. It records the PUT body and answers
// with a level state.
type nfAdmin struct {
	puts []string
}

func (n *nfAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/v1/log-level" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodPut {
		b, _ := io.ReadAll(r.Body)
		n.puts = append(n.puts, string(b))
	}
	_, _ = w.Write([]byte(`{"level":"DEBUG","base_level":"INFO","revert_in_s":900}`))
}

// promTarget answers the up{nf="..."} query with one scrape target at instance.
func promTarget(t *testing.T, instance string) *promclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("query"), `up{nf="`) {
			t.Errorf("unexpected query %q", r.URL.Query().Get("query"))
		}
		if instance == "" {
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
		 {"metric":{"instance":"` + instance + `","nf":"AMF"},"value":[1,"1"]}]}}`))
	}))
	t.Cleanup(srv.Close)
	return promclient.New(srv.URL, http.DefaultClient, 0)
}

func logLevelSetup(t *testing.T) (registry.Tool, *nfAdmin) {
	t.Helper()
	nf := &nfAdmin{}
	srv := httptest.NewServer(nf)
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	inst := host + ":" + port
	g := guard.New(guard.Options{Mode: guard.ModeLab}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, tl := range All(Deps{Guard: g, Prom: promTarget(t, inst), HTTP: http.DefaultClient}) {
		if tl.Name() == "nf_log_level" {
			return tl, nf
		}
	}
	t.Fatal("nf_log_level not registered")
	return nil, nil
}

func TestLogLevelReadIsReadOnly(t *testing.T) {
	tl, _ := logLevelSetup(t)
	if r := tl.(registry.ArgRisker).RiskFor(json.RawMessage(`{"nf":"AMF"}`)); r != registry.ReadOnly {
		t.Errorf("read without level: %s, want READ_ONLY", r)
	}
	if r := tl.(registry.ArgRisker).RiskFor(json.RawMessage(`{"nf":"AMF","level":"debug"}`)); r != registry.Mutating {
		t.Errorf("set level: %s, want MUTATING", r)
	}
}

func TestLogLevelSetSendsPUTToScrapeTarget(t *testing.T) {
	tl, nf := logLevelSetup(t)
	out, err := tl.Invoke(context.Background(), json.RawMessage(`{"nf":"AMF","level":"debug","ttl_s":300}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if len(nf.puts) != 1 || !strings.Contains(nf.puts[0], `"level":"debug"`) || !strings.Contains(nf.puts[0], `"ttl_s":300`) {
		t.Errorf("PUT body: %v", nf.puts)
	}
	if out.(map[string]any)["nf"] != "AMF" {
		t.Errorf("result: %v", out)
	}
}

func TestLogLevelReadDoesNotPUT(t *testing.T) {
	tl, nf := logLevelSetup(t)
	if _, err := tl.Invoke(context.Background(), json.RawMessage(`{"nf":"AMF"}`)); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if len(nf.puts) != 0 {
		t.Errorf("a read must not PUT: %v", nf.puts)
	}
}

func TestLogLevelNoScrapeTargetIsAnError(t *testing.T) {
	g := guard.New(guard.Options{Mode: guard.ModeLab}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var tl registry.Tool
	for _, c := range All(Deps{Guard: g, Prom: promTarget(t, ""), HTTP: http.DefaultClient}) {
		if c.Name() == "nf_log_level" {
			tl = c
		}
	}
	_, err := tl.Invoke(context.Background(), json.RawMessage(`{"nf":"GHOST","level":"info"}`))
	if err == nil || !strings.Contains(err.Error(), "no Prometheus scrape target") {
		t.Errorf("missing target must be a clear error: %v", err)
	}
}

func TestLogLevelRejectsBadInput(t *testing.T) {
	tl, _ := logLevelSetup(t)
	for _, args := range []string{
		`{"nf":"AMF}or{x"}`,
		`{"nf":"AMF","level":"trace"}`,
		`{"nf":"AMF","level":"info","ttl_s":7200}`,
	} {
		if _, err := tl.Invoke(context.Background(), json.RawMessage(args)); err == nil {
			t.Errorf("%s: want validation error", args)
		}
	}
}
