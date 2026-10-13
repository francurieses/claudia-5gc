package status

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
)

// coreFixture stands up what core_health reads: the NRF list (identity only, as the
// real NRF returns it), the Prometheus scrape targets, and one metrics port per NF.
// AMF answers /healthz with 503 when amfHealthy is false. SMF answers 200. NRF has no
// /healthz (404) and is judged by its scrape state. UDM has a target that refuses connections.
func coreFixture(t *testing.T, amfHealthy bool) Deps {
	t.Helper()
	amf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !amfHealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(amf.Close)
	smf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(smf.Close)
	nrfMetrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(nrfMetrics.Close)
	dead := httptest.NewServer(http.NotFoundHandler())
	deadAddr := strings.TrimPrefix(dead.URL, "http://")
	dead.Close()

	nrf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"nfInstances":[
		 {"nfInstanceId":"a","nfType":"AMF","nfStatus":"REGISTERED","nfServices":[{"serviceName":"namf-comm"}]},
		 {"nfInstanceId":"s","nfType":"SMF","nfStatus":"REGISTERED"},
		 {"nfInstanceId":"n","nfType":"NRF","nfStatus":"REGISTERED"},
		 {"nfInstanceId":"x","nfType":"UDM","nfStatus":"REGISTERED"}]}`))
	}))
	t.Cleanup(nrf.Close)

	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"supi":"imsi-001010000000001","k":"465b5ce8b199b49faa5f0a2ee238a6bc","dnn":"internet"}`))
	}))
	t.Cleanup(portal.Close)

	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
		 {"metric":{"nf":"AMF","instance":"` + strings.TrimPrefix(amf.URL, "http://") + `"},"value":[1,"1"]},
		 {"metric":{"nf":"SMF","instance":"` + strings.TrimPrefix(smf.URL, "http://") + `"},"value":[1,"1"]},
		 {"metric":{"nf":"NRF","instance":"` + strings.TrimPrefix(nrfMetrics.URL, "http://") + `"},"value":[1,"1"]},
		 {"metric":{"nf":"UDM","instance":"` + deadAddr + `"},"value":[1,"0"]}]}}`))
	}))
	t.Cleanup(prom.Close)

	return Deps{
		NRF:    clients.NewNRF(nrf.URL, http.DefaultClient),
		Portal: clients.NewPortal(portal.URL, http.DefaultClient),
		Prom:   promclient.New(prom.URL, http.DefaultClient, 0),
		HTTP:   http.DefaultClient,
	}
}

func TestCoreHealthReportsEachNFWithoutHidingOthers(t *testing.T) {
	deps := coreFixture(t, false) // AMF /healthz returns 503
	out, err := coreHealthTool{deps}.Invoke(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	m := out.(map[string]any)
	byType := map[string]map[string]any{}
	for _, r := range m["nfs"].([]map[string]any) {
		byType[r["nf_type"].(string)] = r
	}
	if byType["AMF"]["healthy"] != false || byType["AMF"]["http_status"] != 503 {
		t.Errorf("AMF must be unhealthy with 503: %v", byType["AMF"])
	}
	if byType["SMF"]["healthy"] != true || byType["SMF"]["http_status"] != 200 {
		t.Errorf("SMF must still be reported healthy: %v", byType["SMF"])
	}
	if byType["NRF"]["healthy"] != true || byType["NRF"]["note"] == nil {
		t.Errorf("NRF without /healthz must be judged by its scrape state with a note: %v", byType["NRF"])
	}
	if byType["UDM"]["healthy"] != false || byType["UDM"]["error"] == nil {
		t.Errorf("UDM unreachable must be unhealthy with the error: %v", byType["UDM"])
	}
	if byType["AMF"]["scrape_up"] != true || byType["UDM"]["scrape_up"] != false {
		t.Errorf("scrape_up: AMF=%v UDM=%v", byType["AMF"]["scrape_up"], byType["UDM"]["scrape_up"])
	}
	sum := m["summary"].(map[string]any)
	if sum["registered"] != 4 || sum["healthy"] != 2 || sum["unhealthy"] != 2 || sum["unknown"] != 0 {
		t.Errorf("summary: %v", sum)
	}
}

func TestSubscriberGetRedactsSecrets(t *testing.T) {
	deps := coreFixture(t, true)
	out, err := subscriberGetTool{deps}.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "465b5ce8") {
		t.Fatalf("subscriber key leaked: %s", raw)
	}
	if !strings.Contains(string(raw), "redacted") {
		t.Errorf("redaction marker missing: %s", raw)
	}
}

func TestSubscriberGetValidatesSUPI(t *testing.T) {
	deps := coreFixture(t, true)
	if _, err := (subscriberGetTool{deps}).Invoke(context.Background(), json.RawMessage(`{"supi":"001010000000001"}`)); err == nil {
		t.Error("a SUPI without the imsi- prefix must be rejected")
	}
}

func TestConfigViewTagsRuntimeAndRestart(t *testing.T) {
	deps := coreFixture(t, true)
	out, err := configViewTool{deps}.Invoke(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	sections := out.(map[string]any)["sections"].(map[string]any)
	for key, want := range map[string]string{"slices": "restart_required", "dnns": "restart_required",
		"slice_qos": "runtime", "policy_templates": "runtime"} {
		got := sections[key].(map[string]any)["change"]
		if got != want {
			t.Errorf("%s: change %v, want %s", key, got, want)
		}
	}
}

func TestPortalFailureIsAToolErrorNotAPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	deps := Deps{Portal: clients.NewPortal(srv.URL, http.DefaultClient)}
	if _, err := (deploymentTool{deps}).Invoke(context.Background(), json.RawMessage(`{}`)); err == nil {
		t.Fatal("portal 502 must surface as an error")
	}
}
