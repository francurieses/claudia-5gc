package nf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
)

func TestNormaliseSNSSAIsAcceptsArrayAndString(t *testing.T) {
	cases := map[string]string{
		`[{"sst":1,"sd":"000001"}]`:         `[{"sst":1,"sd":"000001"}]`,
		`"[{\"sst\":1,\"sd\":\"000001\"}]"`: `[{"sst":1,"sd":"000001"}]`,
		`[{"sst":2}]`:                       `[{"sst":2}]`,
	}
	for in, want := range cases {
		got, perr := normaliseSNSSAIs(json.RawMessage(in))
		if perr != nil {
			t.Errorf("%s: %v", in, perr)
			continue
		}
		if got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

func TestNormaliseSNSSAIsEmptyMeansNoFilter(t *testing.T) {
	for _, in := range []string{"", "null"} {
		got, perr := normaliseSNSSAIs(json.RawMessage(in))
		if perr != nil || got != "" {
			t.Errorf("%q: got (%q,%v), want no filter", in, got, perr)
		}
	}
}

func TestNormaliseSNSSAIsRejectsBadInput(t *testing.T) {
	for _, in := range []string{`{"sst":1}`, `[{"sst":300}]`, `[{"sst":"one"}]`} {
		_, perr := normaliseSNSSAIs(json.RawMessage(in))
		if perr == nil || perr.Code != mcperr.CodeInvalidParams {
			t.Errorf("%s: want -32602, got %v", in, perr)
		}
	}
}

func nrfServer(t *testing.T, listBody string) *clients.NRF {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nnrf-nfm/v1/nf-instances":
			_, _ = w.Write([]byte(listBody))
		case "/nnrf-nfm/v1/nf-instances/id-2":
			_, _ = w.Write([]byte(`{"nfInstanceId":"id-2","nfType":"UDM","nfStatus":"REGISTERED","nfServices":{"0":{"serviceName":"nudm-sdm"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return clients.NewNRF(srv.URL, http.DefaultClient)
}

func TestListSummaryRows(t *testing.T) {
	body := `{"nfInstances":[
	 {"nfInstanceId":"id-1","nfType":"AMF","nfStatus":"REGISTERED","nfServices":[{"serviceName":"namf-comm"},{"serviceName":"namf-mt"}]},
	 "id-2"]}`
	out, err := listTool{nrfServer(t, body)}.Invoke(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	raw, _ := json.Marshal(out)
	want := `{"count":2,"nfInstances":[` +
		`{"instance_id":"id-1","nf_type":"AMF","nf_status":"REGISTERED","services":["namf-comm","namf-mt"]},` +
		`{"instance_id":"id-2","nf_type":"UDM","nf_status":"REGISTERED","services":["nudm-sdm"]}]}`
	if string(raw) != want {
		t.Errorf("got  %s\nwant %s", raw, want)
	}
}

func TestListDetailKeepsFullProfiles(t *testing.T) {
	body := `{"nfInstances":[{"nfInstanceId":"id-1","nfType":"AMF","heartBeatTimer":60}]}`
	out, err := listTool{nrfServer(t, body)}.Invoke(context.Background(), json.RawMessage(`{"detail":true}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), `"heartBeatTimer":60`) {
		t.Errorf("full profile lost: %s", raw)
	}
}
