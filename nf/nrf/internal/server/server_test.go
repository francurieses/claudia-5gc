package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/nrf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/nrf/internal/registry"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.Metrics.Address = "127.0.0.1:0"
	cfg.OAuth2Secret = "test"
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(cfg, registry.NewInMemory(lg), lg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s
}

func do(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.sbiSrv.Handler.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return v
}

const rel19Profile = `{
  "nfInstanceId": "aaaaaaaa-0000-0000-0000-000000000001",
  "nfType": "SMF",
  "smfInfo": {"sNssaiSmfInfoList": [{"sNssai": {"sst": 1}, "dnnSmfInfoList": [{"dnn": "internet"}]}]},
  "nfSetIdList": ["set1.smfset.5gc.mnc001.mcc001"],
  "fooRel19Attr": {"nested": [1, 2, {"x": true}]},
  "sNssais": [{"sst": 1, "sd": "000001", "futureSnssaiAttr": "z"}],
  "nfServices": [{
    "serviceInstanceId": "s1", "serviceName": "nsmf-pdusession",
    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
    "scheme": "https", "nfServiceStatus": "REGISTERED",
    "allowedPlmns": [{"mcc": "001", "mnc": "01"}],
    "ipEndPoints": [{"ipv4Address": "10.0.0.1", "port": 8080, "transport": "TCP"}]
  }],
  "nfServiceList": {"s2": {
    "serviceInstanceId": "s2", "serviceName": "nsmf-event-exposure",
    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
    "scheme": "https", "nfServiceStatus": "REGISTERED", "newServiceAttr": 7
  }}
}`

func TestRegisterPreservesUnknownAttributes(t *testing.T) {
	s := newTestServer(t)
	const id = "aaaaaaaa-0000-0000-0000-000000000001"
	rec := do(t, s, http.MethodPut, "/nnrf-nfm/v1/nf-instances/"+id, rel19Profile)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}

	want := decode(t, []byte(rel19Profile)).(map[string]any)
	want["nfStatus"] = "REGISTERED"
	want["heartBeatTimer"] = float64(registry.DefaultHeartbeatTimer)

	check := func(name string, got any) {
		t.Helper()
		if !reflect.DeepEqual(got, any(want)) {
			t.Errorf("%s: profile mismatch\n got: %v\nwant: %v", name, got, want)
		}
	}
	check("PUT response", decode(t, rec.Body.Bytes()))

	rec = do(t, s, http.MethodGet, "/nnrf-nfm/v1/nf-instances/"+id, "")
	check("GET", decode(t, rec.Body.Bytes()))

	rec = do(t, s, http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF", "")
	res := decode(t, rec.Body.Bytes()).(map[string]any)["nfInstances"].([]any)
	if len(res) != 1 {
		t.Fatalf("discover: %d results", len(res))
	}
	check("discover", res[0])

	rec = do(t, s, http.MethodGet, "/nnrf-nfm/v1/nf-instances?detail=true", "")
	res = decode(t, rec.Body.Bytes()).(map[string]any)["nfInstances"].([]any)
	check("list detail", res[0])

	// Heartbeat leaves the raw untouched; full replace swaps it.
	if rec = do(t, s, http.MethodPatch, "/nnrf-nfm/v1/nf-instances/"+id, `[]`); rec.Code != http.StatusNoContent {
		t.Fatalf("heartbeat: %d", rec.Code)
	}
	rec = do(t, s, http.MethodGet, "/nnrf-nfm/v1/nf-instances/"+id, "")
	check("GET after heartbeat", decode(t, rec.Body.Bytes()))

	repl := `{"nfType":"SMF","nfStatus":"REGISTERED","replacedAttr":1}`
	if rec = do(t, s, http.MethodPatch, "/nnrf-nfm/v1/nf-instances/"+id, repl); rec.Code != http.StatusNoContent {
		t.Fatalf("replace: %d", rec.Code)
	}
	rec = do(t, s, http.MethodGet, "/nnrf-nfm/v1/nf-instances/"+id, "")
	got := decode(t, rec.Body.Bytes()).(map[string]any)
	if got["replacedAttr"] != float64(1) || got["fooRel19Attr"] != nil || got["nfInstanceId"] != id {
		t.Errorf("replace did not swap raw: %v", got)
	}

	if rec = do(t, s, http.MethodPut, "/nnrf-nfm/v1/nf-instances/x", `{not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed body: %d", rec.Code)
	}
}

func TestDiscoverBySupportedFeatures(t *testing.T) {
	s := newTestServer(t)
	svc := func(name, sf string) string {
		f := ""
		if sf != "" {
			f = `,"supportedFeatures":"` + sf + `"`
		}
		return `{"serviceInstanceId":"i","serviceName":"` + name + `","scheme":"https","nfServiceStatus":"REGISTERED"` + f + `}`
	}
	reg := func(id, body string) {
		if rec := do(t, s, http.MethodPut, "/nnrf-nfm/v1/nf-instances/"+id, body); rec.Code != http.StatusCreated {
			t.Fatalf("register %s: %d %s", id, rec.Code, rec.Body)
		}
	}
	reg("A", `{"nfType":"SMF","nfServices":[`+svc("nsmf-pdusession", "0f")+`]}`)
	reg("B", `{"nfType":"SMF","nfServices":[`+svc("nsmf-pdusession", "1")+`]}`)
	reg("C", `{"nfType":"SMF","nfServices":[`+svc("nsmf-pdusession", "")+`]}`)
	reg("D", `{"nfType":"SMF","nfServiceList":{"i":`+svc("nsmf-pdusession", "8")+`}}`)

	const base = "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF"
	ids := func(q string) []string {
		t.Helper()
		rec := do(t, s, http.MethodGet, base+q, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", q, rec.Code, rec.Body)
		}
		var out []string
		for _, n := range decode(t, rec.Body.Bytes()).(map[string]any)["nfInstances"].([]any) {
			out = append(out, n.(map[string]any)["nfInstanceId"].(string))
		}
		sort.Strings(out)
		return out
	}
	all := []string{"A", "B", "C", "D"}
	tests := []struct {
		name, q string
		want    []string
	}{
		{"feature 4 (0x8)", "&service-names=nsmf-pdusession&supported-features=8", []string{"A", "D"}},
		{"feature 1", "&service-names=nsmf-pdusession&supported-features=1", []string{"A", "B"}},
		{"zero matches all", "&service-names=nsmf-pdusession&supported-features=0", all},
		{"no service-names ignored", "&supported-features=8", all},
		{"two service-names OR, features ignored", "&service-names=nsmf-pdusession,nsmf-event-exposure&supported-features=8", all},
		{"over-long, leading zeros only", "&service-names=nsmf-pdusession&supported-features=" + strings.Repeat("0", 299) + "8", []string{"A", "D"}},
		{"over-long, non-zero high digit", "&service-names=nsmf-pdusession&supported-features=1" + strings.Repeat("0", 299), nil},
		{"unsatisfiable", "&service-names=nsmf-pdusession&supported-features=ff", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ids(tc.q); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}

	// Two names: OR over service names (TS 29.510 Table 6.2.3.2.3.1-1) and the
	// supported-features parameter is ignored.
	reg("E", `{"nfType":"SMF","nfServices":[`+svc("nsmf-pdusession", "")+`,`+svc("nsmf-event-exposure", "")+`]}`)
	if got := ids("&service-names=nsmf-pdusession,nsmf-event-exposure&supported-features=8"); !reflect.DeepEqual(got, []string{"A", "B", "C", "D", "E"}) {
		t.Errorf("two names: got %v", got)
	}

	rec := do(t, s, http.MethodGet, base+"&service-names=nsmf-pdusession&supported-features=zz", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid: %d", rec.Code)
	}
	pd := decode(t, rec.Body.Bytes()).(map[string]any)
	if pd["cause"] != "OPTIONAL_QUERY_PARAM_INCORRECT" {
		t.Errorf("cause = %v", pd["cause"])
	}
	ip, _ := pd["invalidParams"].([]any)
	if len(ip) != 1 || ip[0].(map[string]any)["param"] != "query supported-features" {
		t.Errorf("invalidParams = %v", pd["invalidParams"])
	}
	// Invalid value is ignored (no 400) without a single service-name.
	if rec := do(t, s, http.MethodGet, base+"&supported-features=zz", ""); rec.Code != http.StatusOK {
		t.Errorf("ignored invalid: %d", rec.Code)
	}
}
