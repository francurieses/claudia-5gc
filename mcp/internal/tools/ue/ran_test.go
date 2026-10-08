package ue

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
)

func TestRanGnbList_Registered(t *testing.T) {
	for _, tool := range All(clients.NewAMF("http://amf:9002", http.DefaultClient)) {
		if tool.Name() == "ran_gnb_list" {
			if !json.Valid(tool.InputSchema()) || !json.Valid(tool.OutputSchema()) {
				t.Fatal("ran_gnb_list schemas are not valid JSON")
			}
			return
		}
	}
	t.Fatal("ran_gnb_list not registered in ue.All")
}

func TestRanGnbList_Invoke(t *testing.T) {
	const body = `{"amf":{"name":"5GC-AMF"},"gnbs":[{"ran_node_name":"gnb-a","state":"NG_READY"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/amf/v1/ran/gnbs" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	out, err := ranGNBListTool{clients.NewAMF(srv.URL, srv.Client())}.Invoke(context.Background(), nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	raw, ok := out.(json.RawMessage)
	if !ok || !strings.Contains(string(raw), `"gnb-a"`) {
		t.Fatalf("out = %T %v", out, out)
	}
}

func TestRanGnbList_AMFError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := (ranGNBListTool{clients.NewAMF(srv.URL, srv.Client())}).Invoke(context.Background(), nil); err == nil {
		t.Fatal("want error on AMF 500")
	}
}
