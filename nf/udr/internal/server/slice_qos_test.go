package server

// slice_qos_test.go — /nudr-internal/v1/slice-dnn-qos endpoints (UDR-003).
// Error cases per docs/procedures/SliceSessionAmbrConfig.md.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
)

const qosBase = "/nudr-internal/v1/slice-dnn-qos"

func newQoSUDR(t *testing.T, slices ...store.SNSSAISubscribed) (*httptest.Server, *Server, *store.InMemory) {
	t.Helper()
	st := store.NewInMemory()
	if _, err := store.SeedSliceDNNQoSFromEntries(t.Context(), st, slices, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv, err := New(":0", TLSConfig{}, st, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv, st
}

var defSlices = []store.SNSSAISubscribed{{SST: 1, SD: "000001"}, {SST: 2, SD: "000001"}}

func putBody(ul, dl string) string {
	return fmt.Sprintf(`{"sessionAmbr":{"uplink":%q,"downlink":%q}}`, ul, dl)
}

type problem struct {
	Status        int            `json:"status"`
	Cause         string         `json:"cause"`
	InvalidParams []invalidParam `json:"invalidParams"`
}

type writeResp struct {
	Item    sliceQoSView `json:"item"`
	Changed bool         `json:"changed"`
	Resync  resyncView   `json:"resync"`
}

func TestSliceQoS_ListSortedAndFiltered(t *testing.T) {
	ts, _, _ := newQoSUDR(t, defSlices...)
	code, b := do(t, ts, "GET", qosBase, "")
	var l struct{ Items []sliceQoSView }
	_ = json.Unmarshal(b, &l)
	if code != 200 || len(l.Items) != 2 || l.Items[0].Snssai.SST != 1 || l.Items[1].Snssai.SST != 2 ||
		l.Items[0].Source != "default" || l.Items[0].SessionAMBR.Uplink != "100 Mbps" {
		t.Fatalf("list: %d %s", code, b)
	}
	_, b = do(t, ts, "GET", qosBase+"?sst=2", "")
	_ = json.Unmarshal(b, &l)
	if len(l.Items) != 1 || l.Items[0].Snssai.SST != 2 {
		t.Errorf("filter: %s", b)
	}
	if code, _ = do(t, ts, "GET", qosBase+"?sst=999", ""); code != 400 {
		t.Errorf("bad filter: %d", code)
	}
}

func TestSliceQoS_PutCreatedVsOKAndSMDataResync(t *testing.T) {
	ts, _, st := newQoSUDR(t, defSlices...)
	if err := store.SeedTestSubscriber(st, "imsi-001010000000001", "00", "00", "8000", "000000000001"); err != nil {
		t.Fatal(err)
	}
	if err := store.SeedTestSubscriberWithNSSAI(st, "imsi-001010000000002", "00", "00", "8000", "000000000001",
		[]store.SNSSAISubscribed{{SST: 2, SD: "000001"}}); err != nil {
		t.Fatal(err)
	}
	code, b := do(t, ts, "PUT", qosBase+"/1/000001/internet", putBody("20 Mbps", "30 Mbps"))
	var w writeResp
	_ = json.Unmarshal(b, &w)
	if code != 200 || !w.Changed || w.Item.Source != "edited" || w.Item.SessionAMBR.Downlink != "30 Mbps" ||
		w.Item.DefaultSessionAMBR.Uplink != "100 Mbps" || w.Resync.AffectedSubscribers != 1 || w.Resync.Synced != 1 ||
		w.Resync.Failed == nil || len(w.Resync.Failed) != 0 {
		t.Fatalf("put existing: %d %s", code, b)
	}
	subs, _ := st.GetSMSubscriptions("imsi-001010000000001")
	if a := subs[0].DNNConfigurations["internet"].SessionAMBR; a.Uplink != "20 Mbps" || a.Downlink != "30 Mbps" {
		t.Errorf("sm-data: %+v", a)
	}
	other, _ := st.GetSMSubscriptions("imsi-001010000000002")
	if a := other[0].DNNConfigurations["internet"].SessionAMBR; a.Uplink != "100 Mbps" {
		t.Errorf("other slice touched: %+v", a)
	}

	// Same body again: 200, changed=false, resync still runs (repair retry).
	code, b = do(t, ts, "PUT", qosBase+"/1/000001/internet", putBody("20 Mbps", "30 Mbps"))
	_ = json.Unmarshal(b, &w)
	if code != 200 || w.Changed || w.Resync.Synced != 1 {
		t.Errorf("idempotent put: %d %s", code, b)
	}

	// Unseeded key: 201, no subscribers; GET afterwards 200.
	code, b = do(t, ts, "PUT", qosBase+"/3/00000A/ims", putBody("5 Mbps", "8 Mbps"))
	_ = json.Unmarshal(b, &w)
	if code != 201 || w.Item.Snssai.SD != "00000a" || w.Resync.AffectedSubscribers != 0 || w.Item.DefaultSessionAMBR.Uplink != "50 Mbps" {
		t.Fatalf("put unseeded: %d %s", code, b)
	}
	if code, _ = do(t, ts, "GET", qosBase+"/3/00000a/ims", ""); code != 200 {
		t.Errorf("get after create: %d", code)
	}
}

func TestSliceQoS_NoSDHyphen(t *testing.T) {
	ts, _, _ := newQoSUDR(t, defSlices...)
	code, b := do(t, ts, "PUT", qosBase+"/1/-/internet", putBody("10 Mbps", "10 Mbps"))
	var w struct {
		Item map[string]any `json:"item"`
	}
	_ = json.Unmarshal(b, &w)
	sn := w.Item["snssai"].(map[string]any)
	if _, has := sn["sd"]; code != 201 || has || sn["sst"].(float64) != 1 {
		t.Fatalf("%d %s", code, b)
	}
	_, b = do(t, ts, "GET", qosBase+"/1/000001/internet", "")
	var v sliceQoSView
	_ = json.Unmarshal(b, &v)
	if v.Source != "default" {
		t.Errorf("1/000001 touched: %s", b)
	}
}

func TestSliceQoS_PutErrors(t *testing.T) {
	ts, _, _ := newQoSUDR(t, defSlices...)
	cases := []struct {
		name, path, body, cause, param string
	}{
		{"no space", "1/000001/internet", putBody("20Mbps", "30 Mbps"), "MANDATORY_IE_INCORRECT", "sessionAmbr.uplink"},
		{"lower unit", "1/000001/internet", putBody("20 mbps", "30 Mbps"), "MANDATORY_IE_INCORRECT", "sessionAmbr.uplink"},
		{"bad unit", "1/000001/internet", putBody("20 MB", "30 Mbps"), "MANDATORY_IE_INCORRECT", "sessionAmbr.uplink"},
		{"negative", "1/000001/internet", putBody("-5 Mbps", "30 Mbps"), "MANDATORY_IE_INCORRECT", "sessionAmbr.uplink"},
		{"zero ul", "1/000001/internet", putBody("0 Mbps", "30 Mbps"), "MANDATORY_IE_INCORRECT", "sessionAmbr.uplink"},
		{"zero dl", "1/000001/internet", putBody("20 Mbps", "0 Kbps"), "MANDATORY_IE_INCORRECT", "sessionAmbr.downlink"},
		{"too big", "1/000001/internet", putBody("2000 Tbps", "30 Mbps"), "MANDATORY_IE_INCORRECT", "sessionAmbr.uplink"},
		{"empty ul", "1/000001/internet", `{"sessionAmbr":{"uplink":"","downlink":"30 Mbps"}}`, "MANDATORY_IE_MISSING", "sessionAmbr.uplink"},
		{"absent dl", "1/000001/internet", `{"sessionAmbr":{"uplink":"20 Mbps"}}`, "MANDATORY_IE_MISSING", "sessionAmbr.downlink"},
		{"no ambr", "1/000001/internet", `{}`, "MANDATORY_IE_MISSING", "sessionAmbr"},
		{"bad json", "1/000001/internet", `{"sessionAmbr": not-json`, "INVALID_MSG_FORMAT", ""},
		{"wrong shape", "1/000001/internet", `{"sessionAmbr":"x"}`, "INVALID_MSG_FORMAT", ""},
		{"sst 300", "300/000001/internet", putBody("20 Mbps", "30 Mbps"), "MANDATORY_IE_INCORRECT", "sst"},
		{"sd zz", "1/zz/internet", putBody("20 Mbps", "30 Mbps"), "MANDATORY_IE_INCORRECT", "sd"},
		{"sd short", "1/00001/internet", putBody("20 Mbps", "30 Mbps"), "MANDATORY_IE_INCORRECT", "sd"},
		{"sd long", "1/0000011/internet", putBody("20 Mbps", "30 Mbps"), "MANDATORY_IE_INCORRECT", "sd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, b := do(t, ts, "PUT", qosBase+"/"+c.path, c.body)
			var p problem
			_ = json.Unmarshal(b, &p)
			if code != 400 || p.Cause != c.cause || p.Status != 400 {
				t.Fatalf("got %d %s", code, b)
			}
			if c.param != "" {
				found := false
				for _, ip := range p.InvalidParams {
					found = found || ip.Param == c.param
				}
				if !found {
					t.Errorf("invalidParams lacks %q: %s", c.param, b)
				}
			}
			_, g := do(t, ts, "GET", qosBase+"/1/000001/internet", "")
			var v sliceQoSView
			_ = json.Unmarshal(g, &v)
			if v.Source != "default" || v.SessionAMBR.Uplink != "100 Mbps" {
				t.Errorf("stored value changed by rejected PUT: %s", g)
			}
		})
	}
}

func TestSliceQoS_UnknownDNNRejectedWhenConfigured(t *testing.T) {
	ts, srv, _ := newQoSUDR(t, defSlices...)
	srv.SetKnownDNNs([]string{"internet", "IMS"})
	if code, _ := do(t, ts, "PUT", qosBase+"/1/000001/gaming", putBody("1 Mbps", "1 Mbps")); code != 400 {
		t.Errorf("unknown dnn: %d", code)
	}
	if code, _ := do(t, ts, "PUT", qosBase+"/1/000001/ims", putBody("1 Mbps", "1 Mbps")); code != 201 {
		t.Errorf("case-insensitive known dnn: %d", code)
	}
}

func TestSliceQoS_PutUnseededUsesOperatorSeedAsRevertTarget(t *testing.T) {
	ts, srv, _ := newQoSUDR(t, defSlices...)
	srv.SetSliceQoSSeed([]store.OperatorSeedEntry{{Key: store.NewSliceKey(3, "00000a", "ims"), AMBR: store.AMBR{Uplink: "7 Mbps", Downlink: "9 Mbps"}}})
	_, b := do(t, ts, "PUT", qosBase+"/3/00000a/ims", putBody("1 Mbps", "1 Mbps"))
	var w writeResp
	_ = json.Unmarshal(b, &w)
	if w.Item.DefaultSource != "operator" || w.Item.DefaultSessionAMBR.Downlink != "9 Mbps" {
		t.Errorf("%s", b)
	}
}

func TestSliceQoS_DeleteRevertAndIdempotence(t *testing.T) {
	ts, _, st := newQoSUDR(t, defSlices...)
	if err := store.SeedTestSubscriber(st, "imsi-001010000000001", "00", "00", "8000", "000000000001"); err != nil {
		t.Fatal(err)
	}
	do(t, ts, "PUT", qosBase+"/1/000001/internet", putBody("20 Mbps", "30 Mbps"))
	code, b := do(t, ts, "DELETE", qosBase+"/1/000001/internet", "")
	var w writeResp
	_ = json.Unmarshal(b, &w)
	if code != 200 || !w.Changed || w.Item.Source != "default" || w.Item.SessionAMBR.Uplink != "100 Mbps" ||
		w.Resync.AffectedSubscribers != 1 || w.Resync.Synced != 1 {
		t.Fatalf("revert: %d %s", code, b)
	}
	subs, _ := st.GetSMSubscriptions("imsi-001010000000001")
	if a := subs[0].DNNConfigurations["internet"].SessionAMBR; a.Uplink != "100 Mbps" {
		t.Errorf("sm-data after revert: %+v", a)
	}
	code, b = do(t, ts, "DELETE", qosBase+"/1/000001/internet", "")
	_ = json.Unmarshal(b, &w)
	if code != 200 || w.Changed || w.Resync.AffectedSubscribers != 0 || w.Resync.Synced != 0 {
		t.Errorf("second delete: %d %s", code, b)
	}
}

func TestSliceQoS_NotFound(t *testing.T) {
	ts, _, _ := newQoSUDR(t, defSlices...)
	for _, m := range []string{"GET", "DELETE"} {
		code, b := do(t, ts, m, qosBase+"/9/ffffff/nonexistent", "")
		var p problem
		_ = json.Unmarshal(b, &p)
		if code != 404 || p.Cause != "DATA_NOT_FOUND" {
			t.Errorf("%s: %d %s", m, code, b)
		}
	}
	if code, _ := do(t, ts, "DELETE", qosBase+"/1/zz/internet", ""); code != http.StatusBadRequest {
		t.Errorf("bad path on delete: %d", code)
	}
}

func TestSliceQoS_SyncEndpointUsesTable(t *testing.T) {
	ts, _, st := newQoSUDR(t, defSlices...)
	_ = st.PutAMSubscription(&store.AccessAndMobilitySubscriptionData{SUPI: "imsi-001010000000001",
		NSSAI: store.AllowedNSSAI{SNSSAIs: []store.SNSSAISubscribed{{SST: 1, SD: "000001"}}}})
	do(t, ts, "PUT", qosBase+"/1/000001/internet", putBody("20 Mbps", "30 Mbps"))
	if code, _ := do(t, ts, "POST", "/nudr-internal/v1/subscribers/imsi-001010000000001/sync-sm-data", ""); code != 200 {
		t.Fatal(code)
	}
	subs, _ := st.GetSMSubscriptions("imsi-001010000000001")
	if a := subs[0].DNNConfigurations["internet"].SessionAMBR; a.Uplink != "20 Mbps" {
		t.Errorf("%+v", a)
	}
}
