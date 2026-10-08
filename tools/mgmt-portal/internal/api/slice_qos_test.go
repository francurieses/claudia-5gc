package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// newSliceQoSRouter wires a router to fake UDR and SMF servers.
func newSliceQoSRouter(t *testing.T, udr, smf http.Handler) http.Handler {
	t.Helper()
	u := httptest.NewServer(udr)
	t.Cleanup(u.Close)
	s := httptest.NewServer(smf)
	t.Cleanup(s.Close)
	return NewRouter(Deps{UDRBaseURL: u.URL, SMFBaseURL: s.URL, MTLSClient: http.DefaultClient},
		http.Dir(t.TempDir()))
}

func call(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBitRateToKbps(t *testing.T) {
	tests := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{"20 Mbps", 20000, false},
		{"0.125 Gbps", 125000, false},
		{"125000 Kbps", 125000, false},
		{"1 bps", 1, false}, // rounds up to 1 kbps
		{"1500 Kbps", 1500, false},
		{"1 Pbps", 0, true},
		{"1000 Tbps", 1_000_000_000_000, false},
		{"1001 Tbps", 0, true},
		{"20Mbps", 0, true},
		{"20 mbps", 0, true},
		{"20 MB", 0, true},
		{"-5 Mbps", 0, true},
		{"0 Mbps", 0, true},
		{"0.0 Gbps", 0, true},
		{"", 0, true},
	}
	for _, tc := range tests {
		got, err := bitRateToKbps(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("bitRateToKbps(%q) = %d, %v; want %d, err=%v", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestKbpsToMbpsCeil(t *testing.T) {
	for in, want := range map[uint64]int{1: 1, 999: 1, 1000: 1, 1001: 2, 1500: 2, 20000: 20} {
		if got := kbpsToMbpsCeil(in); got != want {
			t.Errorf("kbpsToMbpsCeil(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestSliceQoS_Validation400(t *testing.T) {
	hit := false
	h := newSliceQoSRouter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }),
		http.NotFoundHandler())
	good := `{"sessionAmbr":{"uplink":"20 Mbps","downlink":"30 Mbps"}}`
	tests := []struct{ name, method, path, body string }{
		{"bad sst", "PUT", "/api/v1/slices/qos/256/000001/internet", good},
		{"non-numeric sst", "PUT", "/api/v1/slices/qos/x/000001/internet", good},
		{"bad sd", "PUT", "/api/v1/slices/qos/1/0001/internet", good},
		{"bad dnn", "PUT", "/api/v1/slices/qos/1/000001/bad%20dnn", good},
		{"bad json", "PUT", "/api/v1/slices/qos/1/000001/internet", "{"},
		{"missing ambr", "PUT", "/api/v1/slices/qos/1/000001/internet", `{}`},
		{"missing uplink", "PUT", "/api/v1/slices/qos/1/000001/internet", `{"sessionAmbr":{"downlink":"30 Mbps"}}`},
		{"no space", "PUT", "/api/v1/slices/qos/1/000001/internet", `{"sessionAmbr":{"uplink":"20Mbps","downlink":"30 Mbps"}}`},
		{"lowercase unit", "PUT", "/api/v1/slices/qos/1/000001/internet", `{"sessionAmbr":{"uplink":"20 Mbps","downlink":"30 mbps"}}`},
		{"zero", "PUT", "/api/v1/slices/qos/1/000001/internet", `{"sessionAmbr":{"uplink":"0 Mbps","downlink":"30 Mbps"}}`},
		{"too big", "PUT", "/api/v1/slices/qos/1/000001/internet", `{"sessionAmbr":{"uplink":"2000 Tbps","downlink":"30 Mbps"}}`},
		{"delete bad sst", "DELETE", "/api/v1/slices/qos/300/-/internet", ""},
		{"apply bad sd", "POST", "/api/v1/slices/qos/1/zz/internet/apply", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := call(h, tc.method, tc.path, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
	if hit {
		t.Fatal("UDR must not be called when validation fails")
	}
}

func TestSliceQoS_RelayStatuses(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotBody, gotMethod string
	status := http.StatusOK
	udr := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotPath, gotBody, gotMethod = r.URL.Path, string(b), r.Method
		st := status
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_, _ = w.Write([]byte(`{"relayed":true}`))
	})
	h := newSliceQoSRouter(t, udr, http.NotFoundHandler())

	for _, st := range []int{200, 201, 400, 404, 500} {
		mu.Lock()
		status = st
		mu.Unlock()
		rec := call(h, "PUT", "/api/v1/slices/qos/1/-/Internet", `{"sessionAmbr":{"uplink":" 20 Mbps","downlink":"30 Mbps"}}`)
		if rec.Code != st || !strings.Contains(rec.Body.String(), "relayed") {
			t.Fatalf("PUT status %d: got %d %s", st, rec.Code, rec.Body.String())
		}
	}
	if gotMethod != "PUT" || gotPath != "/nudr-internal/v1/slice-dnn-qos/1/-/Internet" {
		t.Errorf("upstream = %s %s", gotMethod, gotPath)
	}
	if !strings.Contains(gotBody, `"uplink":"20 Mbps"`) {
		t.Errorf("body not canonicalised: %s", gotBody)
	}

	rec := call(h, "DELETE", "/api/v1/slices/qos/1/000AbC/internet", "")
	if gotMethod != "DELETE" || gotPath != "/nudr-internal/v1/slice-dnn-qos/1/000abc/internet" || rec.Code != 500 {
		t.Errorf("delete: %s %s -> %d", gotMethod, gotPath, rec.Code)
	}
	rec = call(h, "GET", "/api/v1/slices/qos", "")
	if gotPath != "/nudr-internal/v1/slice-dnn-qos" || rec.Code != 500 {
		t.Errorf("list: %s -> %d", gotPath, rec.Code)
	}
}

func TestSliceQoS_UDRUnreachable502(t *testing.T) {
	u := httptest.NewServer(http.NotFoundHandler())
	url := u.URL
	u.Close()
	h := NewRouter(Deps{UDRBaseURL: url, MTLSClient: http.DefaultClient}, http.Dir(t.TempDir()))
	for _, c := range [][2]string{{"GET", "/api/v1/slices/qos"}, {"DELETE", "/api/v1/slices/qos/1/-/internet"}, {"POST", "/api/v1/slices/qos/1/-/internet/apply"}} {
		if rec := call(h, c[0], c[1], ""); rec.Code != http.StatusBadGateway {
			t.Errorf("%s %s: want 502, got %d", c[0], c[1], rec.Code)
		}
	}
}

type smfCall struct {
	Path string
	Body map[string]any
}

// applyFixture returns a router with a UDR item of 20 Mbps / 1500 Kbps and a
// SMF with a mixed session list; calls records each POST .../qos.
func applyFixture(t *testing.T, udrStatus int) (http.Handler, *[]smfCall) {
	t.Helper()
	var mu sync.Mutex
	calls := &[]smfCall{}
	udr := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(udrStatus)
		if udrStatus == 200 {
			_, _ = w.Write([]byte(`{"sessionAmbr":{"uplink":"20 Mbps","downlink":"1500 Kbps"},"source":"edited"}`))
		} else {
			_, _ = w.Write([]byte(`{"status":404,"cause":"DATA_NOT_FOUND"}`))
		}
	})
	sessions := `{"count":8,"sessions":[
	 {"supi":"imsi-1","pduSessionId":1,"dnn":"internet","sNssai":{"sst":1,"sd":"000001"},"current5qi":9,"qosSource":"UDM_SUBSCRIPTION"},
	 {"supi":"imsi-2","pduSessionId":1,"dnn":"INTERNET","sNssai":{"sst":1,"sd":"000001"},"current5qi":9,"qosSource":"OPERATOR_DEFAULT"},
	 {"supi":"imsi-3","pduSessionId":1,"dnn":"internet","sNssai":{"sst":1,"sd":"000001"},"current5qi":9,"qosSource":"PCF_OVERRIDE"},
	 {"supi":"imsi-4","pduSessionId":2,"dnn":"internet","sNssai":{"sst":1,"sd":"000001"},"current5qi":9,"qosSource":"UDM_SUBSCRIPTION"},
	 {"supi":"imsi-5","pduSessionId":3,"dnn":"internet","sNssai":{"sst":1,"sd":"000001"},"current5qi":9,"qosSource":"UDM_SUBSCRIPTION"},
	 {"supi":"imsi-6","pduSessionId":1,"dnn":"ims","sNssai":{"sst":1,"sd":"000001"},"current5qi":9,"qosSource":"UDM_SUBSCRIPTION"},
	 {"supi":"imsi-7","pduSessionId":1,"dnn":"internet","sNssai":{"sst":2,"sd":"000001"},"current5qi":9,"qosSource":"UDM_SUBSCRIPTION"},
	 {"supi":"imsi-8","pduSessionId":1,"dnn":"internet","sNssai":{"sst":1},"current5qi":9,"qosSource":"UDM_SUBSCRIPTION"}]}`
	smf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(sessions))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		*calls = append(*calls, smfCall{r.URL.Path, body})
		mu.Unlock()
		switch body["supi"] {
		case "imsi-4":
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"cause":"CONTEXT_NOT_FOUND","detail":"gone"}`))
		case "imsi-5":
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"cause":"AMBIGUOUS_SESSION","detail":"dup"}`))
		default:
			_, _ = w.Write([]byte(`{"result":"success"}`))
		}
	})
	return newSliceQoSRouter(t, udr, smf), calls
}

func TestApplySliceQoS(t *testing.T) {
	h, calls := applyFixture(t, 200)
	rec := call(h, "POST", "/api/v1/slices/qos/1/000001/internet/apply", "")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp applyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Matched != 5 || len(resp.Applied) != 2 || len(resp.Skipped) != 2 || len(resp.Failed) != 1 {
		t.Fatalf("matched=%d applied=%d skipped=%d failed=%d (%s)", resp.Matched,
			len(resp.Applied), len(resp.Skipped), len(resp.Failed), rec.Body.String())
	}
	if resp.AppliedMbps.UL != 20 || resp.AppliedMbps.DL != 2 {
		t.Errorf("applied_mbps = %+v, want ul 20 dl 2 (1500 Kbps rounds up)", resp.AppliedMbps)
	}
	reasons := map[string]string{}
	for _, s := range resp.Skipped {
		reasons[s.SUPI] = s.Reason
	}
	if reasons["imsi-3"] != "higher-precedence source" || reasons["imsi-4"] != "gone" {
		t.Errorf("skipped reasons = %v", reasons)
	}
	if resp.Failed[0].SUPI != "imsi-5" || resp.Failed[0].Status != 409 || resp.Failed[0].Cause != "AMBIGUOUS_SESSION" {
		t.Errorf("failed = %+v", resp.Failed[0])
	}
	if len(*calls) != 4 { // imsi-1,2,4,5 (3 skipped)
		t.Fatalf("SMF POSTs = %d, want 4", len(*calls))
	}
	c := (*calls)[0]
	if c.Path != "/nsmf-management/v1/sessions/1/qos" || c.Body["5qi"].(float64) != 9 ||
		c.Body["supi"] != "imsi-1" || c.Body["ambr_ul_mbps"].(float64) != 20 ||
		c.Body["ambr_dl_mbps"].(float64) != 2 || c.Body["reason"] != sliceQoSReason {
		t.Errorf("SMF request = %+v", c)
	}
}

func TestApplySliceQoS_IncludeOverridden(t *testing.T) {
	h, calls := applyFixture(t, 200)
	rec := call(h, "POST", "/api/v1/slices/qos/1/000001/internet/apply", `{"include_overridden":true}`)
	var resp applyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != 200 || len(resp.Applied) != 3 || len(*calls) != 5 {
		t.Fatalf("code=%d applied=%d calls=%d", rec.Code, len(resp.Applied), len(*calls))
	}
}

func TestApplySliceQoS_NoSDKey(t *testing.T) {
	h, calls := applyFixture(t, 200)
	rec := call(h, "POST", "/api/v1/slices/qos/1/-/internet/apply", "")
	var resp applyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != 200 || resp.Matched != 1 || len(*calls) != 1 || (*calls)[0].Body["supi"] != "imsi-8" {
		t.Fatalf("code=%d matched=%d calls=%d", rec.Code, resp.Matched, len(*calls))
	}
}

func TestApplySliceQoS_UDR404Relayed(t *testing.T) {
	h, calls := applyFixture(t, 404)
	rec := call(h, "POST", "/api/v1/slices/qos/1/000001/internet/apply", "")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "DATA_NOT_FOUND") || len(*calls) != 0 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestApplySliceQoS_SMFListFails502(t *testing.T) {
	udr := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sessionAmbr":{"uplink":"20 Mbps","downlink":"20 Mbps"}}`))
	})
	smf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	h := newSliceQoSRouter(t, udr, smf)
	if rec := call(h, "POST", "/api/v1/slices/qos/1/-/internet/apply", ""); rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", rec.Code)
	}
}
