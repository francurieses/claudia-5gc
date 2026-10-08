package mgmt

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
)

type fakeLister struct{ snaps []ngap.GNBSnapshot }

func (f fakeLister) GNBSnapshots() []ngap.GNBSnapshot { return f.snaps }
func (f fakeLister) N2ListenAddr() string             { return "0.0.0.0:38412" }

func serve(t *testing.T, l GNBLister) (*httptest.ResponseRecorder, string) {
	t.Helper()
	h := GNBListHandler(l, AMFInfo{Name: "5GC-AMF", MCC: "001", MNC: "01", RegionID: 1, SetID: 1},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/amf/v1/ran/gnbs", nil))
	return rec, rec.Body.String()
}

func TestGNBListHandler_EmptyIsArrayNotNull(t *testing.T) {
	rec, body := serve(t, fakeLister{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(body, `"gnbs":[]`) {
		t.Errorf("body = %s, want gnbs:[]", body)
	}
}

func TestGNBListHandler_Shape(t *testing.T) {
	now := time.Now()
	snaps := []ngap.GNBSnapshot{
		{ID: "172.30.1.20:1", State: ngap.GNBStateNGReady, RANNodeName: "gnb-a", ConnectedAt: now,
			RANNode: ngap.RANNodeJSON{Type: "gNB", GNBID: 1, GNBIDHex: "00000001", GNBIDBitLen: 32},
			SCTP:    ngap.SCTPJSON{RemoteAddrs: []string{"172.30.1.20"}, RemotePort: 1}},
		{ID: "172.30.1.21:2", State: ngap.GNBStateDisconnected, DisconnectReason: ngap.GNBDisconnectSCTPClosed, DisconnectedAt: &now},
	}
	rec, body := serve(t, fakeLister{snaps: snaps})

	var got struct {
		AMF  map[string]any   `json:"amf"`
		GNBs []map[string]any `json:"gnbs"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	if rec.Code != http.StatusOK || len(got.GNBs) != 2 {
		t.Fatalf("status=%d gnbs=%d", rec.Code, len(got.GNBs))
	}
	if got.AMF["n2_addr"] != "0.0.0.0:38412" || got.AMF["name"] != "5GC-AMF" {
		t.Errorf("amf = %v", got.AMF)
	}
	if got.GNBs[0]["state"] != "NG_READY" || got.GNBs[1]["disconnect_reason"] != "sctp_closed" {
		t.Errorf("gnbs = %v", got.GNBs)
	}
}
