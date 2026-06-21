package server

// policy_data_test.go — UDR SM Policy Data + UE Policy Set PATCH resources.
// Ref: UDR-001, TS 29.504 §5.2.13 / TS 29.519 §5.6.2.4.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
)

func newTestUDR(t *testing.T) *httptest.Server {
	t.Helper()
	st := store.NewInMemory()
	srv, err := New(":0", TLSConfig{}, st, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("New UDR: %v", err)
	}
	return httptest.NewServer(srv.Handler())
}

func do(t *testing.T, ts *httptest.Server, method, path, body string) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestSmPolicyDataPutGet(t *testing.T) {
	ts := newTestUDR(t)
	defer ts.Close()

	put := `{"smPolicySnssaiData":{"1-000001":{"snssai":{"sst":1,"sd":"000001"},` +
		`"smPolicyDnnData":{"internet":{"dnn":"internet","5qi":7}}}}}`
	if code, _ := do(t, ts, http.MethodPut,
		"/nudr-dr/v2/policy-data/imsi-001010000000001/sm-data", put); code != http.StatusNoContent {
		t.Fatalf("PUT sm-data: got %d", code)
	}

	code, body := do(t, ts, http.MethodGet,
		"/nudr-dr/v2/policy-data/imsi-001010000000001/sm-data", "")
	if code != http.StatusOK {
		t.Fatalf("GET sm-data: got %d", code)
	}
	var data store.SmPolicyData
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := data.SmPolicySnssaiData["1-000001"].SmPolicyDnnData["internet"].FiveQI; got != 7 {
		t.Errorf("5qi: got %d want 7", got)
	}
}

func TestSmPolicyDataPatchMerges(t *testing.T) {
	ts := newTestUDR(t)
	defer ts.Close()

	base := `{"smPolicySnssaiData":{"1-000001":{"snssai":{"sst":1,"sd":"000001"},` +
		`"smPolicyDnnData":{"internet":{"dnn":"internet","5qi":7}}}}}`
	do(t, ts, http.MethodPut, "/nudr-dr/v2/policy-data/imsi-001010000000001/sm-data", base)

	patch := `{"smPolicySnssaiData":{"2-000001":{"snssai":{"sst":2,"sd":"000001"},` +
		`"smPolicyDnnData":{"ims":{"dnn":"ims","5qi":1}}}}}`
	if code, _ := do(t, ts, http.MethodPatch,
		"/nudr-dr/v2/policy-data/imsi-001010000000001/sm-data", patch); code != http.StatusNoContent {
		t.Fatalf("PATCH sm-data: got %d", code)
	}

	_, body := do(t, ts, http.MethodGet,
		"/nudr-dr/v2/policy-data/imsi-001010000000001/sm-data", "")
	var data store.SmPolicyData
	_ = json.Unmarshal(body, &data)
	if got := data.SmPolicySnssaiData["1-000001"].SmPolicyDnnData["internet"].FiveQI; got != 7 {
		t.Errorf("existing slice dropped: internet 5qi got %d want 7", got)
	}
	if got := data.SmPolicySnssaiData["2-000001"].SmPolicyDnnData["ims"].FiveQI; got != 1 {
		t.Errorf("patched slice: ims 5qi got %d want 1", got)
	}
}

func TestSmPolicyDataGetNotFound(t *testing.T) {
	ts := newTestUDR(t)
	defer ts.Close()
	if code, _ := do(t, ts, http.MethodGet,
		"/nudr-dr/v2/policy-data/imsi-001019999999999/sm-data", ""); code != http.StatusNotFound {
		t.Fatalf("GET unprovisioned: got %d want 404", code)
	}
}

func TestSmPolicyDataPatchNotFound(t *testing.T) {
	ts := newTestUDR(t)
	defer ts.Close()
	patch := `{"smPolicySnssaiData":{"1":{"snssai":{"sst":1}}}}`
	if code, _ := do(t, ts, http.MethodPatch,
		"/nudr-dr/v2/policy-data/imsi-001019999999999/sm-data", patch); code != http.StatusNotFound {
		t.Fatalf("PATCH unprovisioned: got %d want 404", code)
	}
}

func TestUEPolicySetPatch(t *testing.T) {
	ts := newTestUDR(t)
	defer ts.Close()

	put := `{"precedence":10,"rules":[]}`
	if code, _ := do(t, ts, http.MethodPut,
		"/nudr-dr/v2/policy-data/imsi-001010000000001/ue-policy-set", put); code != http.StatusNoContent {
		t.Fatalf("PUT ue-policy-set: got %d", code)
	}
	if code, _ := do(t, ts, http.MethodPatch,
		"/nudr-dr/v2/policy-data/imsi-001010000000001/ue-policy-set", `{"precedence":5}`); code != http.StatusNoContent {
		t.Fatalf("PATCH ue-policy-set: got %d", code)
	}
	_, body := do(t, ts, http.MethodGet,
		"/nudr-dr/v2/policy-data/imsi-001010000000001/ue-policy-set", "")
	var sub store.PolicySubscription
	_ = json.Unmarshal(body, &sub)
	if sub.Precedence != 5 {
		t.Errorf("precedence: got %d want 5", sub.Precedence)
	}
}

func TestUEPolicySetPatchNotFound(t *testing.T) {
	ts := newTestUDR(t)
	defer ts.Close()
	if code, _ := do(t, ts, http.MethodPatch,
		"/nudr-dr/v2/policy-data/imsi-001019999999999/ue-policy-set", `{"precedence":5}`); code != http.StatusNotFound {
		t.Fatalf("PATCH unprovisioned ue-policy-set: got %d want 404", code)
	}
}
