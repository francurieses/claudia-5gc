package main

// smf_update_test.go — AMF-012: HTTPSMFClient UpdateSMContext legs of the Xn / N2
// handover decode SmContextUpdatedData / SmContextUpdateError into an SMFUpdateResult.
// Ref: TS 29.502 §5.2.2.3.3-4, §6.1.6.2; TS 23.502 §4.9.1.2.2 steps 2-6

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestDecodeSMFUpdateResponse(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	tests := []struct {
		name       string
		status     int
		body       string
		wantType   string
		wantInfo   []byte
		wantHo     string
		wantCause  string
		wantOKFlag bool
	}{
		{"200 SmContextUpdatedData", 200, `{"n2SmInfo":"` + b64(payload) + `","n2SmInfoType":"PATH_SWITCH_REQ_ACK"}`,
			"PATH_SWITCH_REQ_ACK", payload, "", "", true},
		{"200 hoState + HANDOVER_CMD", 200, `{"hoState":"PREPARED","n2SmInfo":"` + b64(payload) + `","n2SmInfoType":"HANDOVER_CMD"}`,
			"HANDOVER_CMD", payload, "PREPARED", "", true},
		{"200 empty body", 200, ``, "", nil, "", "", true},
		{"204", 204, ``, "", nil, "", "", true},
		{"500 SmContextUpdateError with n2SmInfo", 500,
			`{"error":{"cause":"SYSTEM_FAILURE"},"n2SmInfo":"` + b64(payload) + `","n2SmInfoType":"PATH_SWITCH_REQ_FAIL"}`,
			"PATH_SWITCH_REQ_FAIL", payload, "", "SYSTEM_FAILURE", false},
		{"404 plain ProblemDetails", 404, `{"title":"x","status":404,"cause":"CONTEXT_NOT_FOUND"}`, "", nil, "", "CONTEXT_NOT_FOUND", false},
		{"422 non-JSON body", 422, `not json`, "", nil, "", "", false},
		{"200 invalid base64 kept as raw bytes", 200, `{"n2SmInfo":"@@@","n2SmInfoType":"HANDOVER_CMD"}`, "HANDOVER_CMD", []byte("@@@"), "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeSMFUpdateResponse(tc.status, []byte(tc.body))
			if got.HTTPStatus != tc.status || got.N2SmInfoType != tc.wantType || string(got.N2SmInfo) != string(tc.wantInfo) ||
				got.HoState != tc.wantHo || got.Cause != tc.wantCause || got.OK() != tc.wantOKFlag || got.Err != nil {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

// smfServer records the last request and answers with the given status/body.
func smfServer(t *testing.T, status int, body string, last *map[string]any, path *string, corr *string) *HTTPSMFClient {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		m := map[string]any{}
		_ = json.Unmarshal(raw, &m)
		*last, *path, *corr = m, r.URL.Path, r.Header.Get("X-Correlation-Id")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &HTTPSMFClient{address: strings.TrimPrefix(srv.URL, "https://"), client: srv.Client()}
}

func TestHTTPSMFClient_HandoverUpdateLegs(t *testing.T) {
	transfer := []byte{0xAB, 0xCD}
	reply := `{"n2SmInfo":"` + b64([]byte{9}) + `","n2SmInfoType":"X"}`
	ctx := logging.WithCorrelationID(context.Background(), "01TESTCORRELATION")
	tests := []struct {
		name string
		call func(c *HTTPSMFClient) (status int, info []byte)
		want map[string]any
	}{
		{"PATH_SWITCH_REQ", func(c *HTTPSMFClient) (int, []byte) {
			r := c.UpdatePathSwitch(ctx, "ref1", transfer)
			return r.HTTPStatus, r.N2SmInfo
		}, map[string]any{"n2SmInfoType": "PATH_SWITCH_REQ", "toBeSwitched": true}},
		{"PATH_SWITCH_SETUP_FAIL", func(c *HTTPSMFClient) (int, []byte) {
			r := c.UpdatePathSwitchSetupFail(ctx, "ref1", transfer)
			return r.HTTPStatus, r.N2SmInfo
		}, map[string]any{"n2SmInfoType": "PATH_SWITCH_SETUP_FAIL", "failedToBeSwitched": true}},
		{"HANDOVER_REQ_ACK", func(c *HTTPSMFClient) (int, []byte) {
			r := c.PrepareHandover(ctx, "ref1", transfer)
			return r.HTTPStatus, r.N2SmInfo
		}, map[string]any{"n2SmInfoType": "HANDOVER_REQ_ACK", "hoState": "PREPARED"}},
		{"HANDOVER_RES_ALLOC_FAIL", func(c *HTTPSMFClient) (int, []byte) {
			r := c.HandoverResourceAllocationFailed(ctx, "ref1", transfer)
			return r.HTTPStatus, r.N2SmInfo
		}, map[string]any{"n2SmInfoType": "HANDOVER_RES_ALLOC_FAIL", "hoState": "PREPARED"}},
		{"HANDOVER_REQUIRED (PREPARING)", func(c *HTTPSMFClient) (int, []byte) {
			r := c.PrepareHandoverRequired(ctx, "ref1", transfer, ngap.HOTargetID{})
			return r.HTTPStatus, r.N2SmInfo
		}, map[string]any{"n2SmInfoType": "HANDOVER_REQUIRED", "hoState": "PREPARING"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var last map[string]any
			var path, corr string
			c := smfServer(t, 200, reply, &last, &path, &corr)
			status, info := tc.call(c)
			if status != 200 || string(info) != string([]byte{9}) {
				t.Fatalf("status=%d info=%x", status, info)
			}
			if path != "/nsmf-pdusession/v1/sm-contexts/ref1/modify" {
				t.Fatalf("path = %s", path)
			}
			if corr != "01TESTCORRELATION" {
				t.Fatalf("X-Correlation-Id = %q", corr)
			}
			if last["n2SmInfo"] != b64(transfer) {
				t.Fatalf("n2SmInfo = %v, want the base64 of the relayed transfer", last["n2SmInfo"])
			}
			for k, v := range tc.want {
				if last[k] != v {
					t.Fatalf("field %s = %v, want %v (body %v)", k, last[k], v, last)
				}
			}
		})
	}
}

func TestHTTPSMFClient_UpdateTransportError(t *testing.T) {
	var last map[string]any
	var path, corr string
	c := smfServer(t, 200, ``, &last, &path, &corr)
	c.address = "127.0.0.1:1" // nothing listens
	r := c.UpdatePathSwitch(context.Background(), "ref1", []byte{1})
	if r.Err == nil || r.OK() || r.HTTPStatus != 0 {
		t.Fatalf("expected a transport error, got %+v", r)
	}
}

func TestHTTPSMFClient_ErrorResponseKeepsN2SmInfo(t *testing.T) {
	var last map[string]any
	var path, corr string
	c := smfServer(t, 500, `{"error":{"cause":"UPF_FAIL"},"n2SmInfo":"`+b64([]byte{7})+`","n2SmInfoType":"PATH_SWITCH_REQ_FAIL"}`, &last, &path, &corr)
	r := c.UpdatePathSwitch(context.Background(), "ref1", []byte{1})
	if r.OK() || r.HTTPStatus != 500 || r.Cause != "UPF_FAIL" || r.N2SmInfoType != "PATH_SWITCH_REQ_FAIL" || string(r.N2SmInfo) != string([]byte{7}) {
		t.Fatalf("got %+v", r)
	}
}

// TestHTTPSMFClient_NotifyANReleaseSendsCorrelationID checks the X-Correlation-Id header.
func TestHTTPSMFClient_NotifyANReleaseSendsCorrelationID(t *testing.T) {
	var last map[string]any
	var path, corr string
	c := smfServer(t, 204, ``, &last, &path, &corr)
	ctx := logging.WithCorrelationID(context.Background(), "01NOTIFYCORR")
	if err := c.NotifyANRelease(ctx, "ref-1"); err != nil {
		t.Fatalf("NotifyANRelease: %v", err)
	}
	if corr != "01NOTIFYCORR" || last["upCnxState"] != "DEACTIVATED" {
		t.Fatalf("corr=%q body=%v", corr, last)
	}
}

// TestHTTPSMFClient_PrepareHandoverRequiredTargetID checks the PREPARING request body: the
// NgRanTargetId (TS 29.571) and the optional n2SmInfo.
func TestHTTPSMFClient_PrepareHandoverRequiredTargetID(t *testing.T) {
	target := ngap.HOTargetID{
		Node: ngap.GlobalRANNode{Type: ngap.RANNodeTypeGNB, MCC: "001", MNC: "01", GNBID: 0x1234, GNBIDBitLen: 22},
		TAI:  &ngap.HOTargetTAI{MCC: "001", MNC: "01", TAC: "000007"},
	}
	var last map[string]any
	var path, corr string
	c := smfServer(t, 200, `{"hoState":"PREPARING","n2SmInfoType":"PDU_RES_SETUP_REQ","n2SmInfo":"`+b64([]byte{5})+`"}`, &last, &path, &corr)
	ctx := logging.WithCorrelationID(context.Background(), "01PREPCORR")

	r := c.PrepareHandoverRequired(ctx, "ref1", []byte{0xAB}, target)
	if !r.OK() || r.HoState != "PREPARING" || r.N2SmInfoType != "PDU_RES_SETUP_REQ" || string(r.N2SmInfo) != string([]byte{5}) {
		t.Fatalf("decoded response = %+v", r)
	}
	if corr != "01PREPCORR" || path != "/nsmf-pdusession/v1/sm-contexts/ref1/modify" {
		t.Fatalf("corr=%q path=%q", corr, path)
	}
	if last["n2SmInfo"] != b64([]byte{0xAB}) {
		t.Fatalf("n2SmInfo = %v", last["n2SmInfo"])
	}
	tid, _ := last["targetId"].(map[string]any)
	node, _ := tid["ranNodeId"].(map[string]any)
	gnb, _ := node["gNbId"].(map[string]any)
	plmn, _ := node["plmnId"].(map[string]any)
	tai, _ := tid["tai"].(map[string]any)
	taiPlmn, _ := tai["plmnId"].(map[string]any)
	// 22-bit gNB ID -> ceil(22/4)=6 hex digits, right-aligned value.
	if gnb["bitLength"] != float64(22) || gnb["gNBValue"] != "001234" || plmn["mcc"] != "001" || plmn["mnc"] != "01" ||
		tai["tac"] != "000007" || taiPlmn["mcc"] != "001" {
		t.Fatalf("targetId = %v", tid)
	}

	// No HandoverRequiredTransfer and no target: both fields are omitted.
	c.PrepareHandoverRequired(ctx, "ref1", nil, ngap.HOTargetID{})
	if _, has := last["n2SmInfo"]; has {
		t.Fatalf("n2SmInfo must be omitted when the source sent none: %v", last)
	}
	if _, has := last["targetId"]; has {
		t.Fatalf("targetId must be omitted when absent: %v", last)
	}
}

func TestNgRanTargetID_PartsOmitted(t *testing.T) {
	if got := ngRanTargetID(ngap.HOTargetID{}); len(got) != 0 {
		t.Fatalf("empty target -> %v", got)
	}
	only := ngRanTargetID(ngap.HOTargetID{TAI: &ngap.HOTargetTAI{MCC: "001", MNC: "01", TAC: "000001"}})
	if _, has := only["ranNodeId"]; has || only["tai"] == nil {
		t.Fatalf("TAI only -> %v", only)
	}
	// 32-bit gNB ID -> 8 digits.
	full := ngRanTargetID(ngap.HOTargetID{Node: ngap.GlobalRANNode{Type: ngap.RANNodeTypeGNB, MCC: "001", MNC: "01", GNBID: 0xDEADBEEF, GNBIDBitLen: 32}})
	gnb := full["ranNodeId"].(map[string]any)["gNbId"].(map[string]any)
	if gnb["gNBValue"] != "deadbeef" {
		t.Fatalf("gNBValue = %v", gnb["gNBValue"])
	}
}

// TestHTTPSMFClient_CompleteHandover checks the COMPLETED request (no n2SmInfo) and the
// decoding of the hoState answer / SmContextUpdateError.
func TestHTTPSMFClient_CompleteHandover(t *testing.T) {
	var last map[string]any
	var path, corr string
	c := smfServer(t, 200, `{"hoState":"COMPLETED"}`, &last, &path, &corr)
	ctx := logging.WithCorrelationID(context.Background(), "01COMPLCORR")
	r := c.CompleteHandover(ctx, "ref1")
	if !r.OK() || r.HoState != "COMPLETED" {
		t.Fatalf("got %+v", r)
	}
	if len(last) != 1 || last["hoState"] != "COMPLETED" || corr != "01COMPLCORR" {
		t.Fatalf("body = %v corr = %q", last, corr)
	}

	c = smfServer(t, 404, `{"error":{"status":404,"cause":"CONTEXT_NOT_FOUND"}}`, &last, &path, &corr)
	r = c.CompleteHandover(ctx, "ref1")
	if r.OK() || r.HTTPStatus != 404 || r.Cause != "CONTEXT_NOT_FOUND" {
		t.Fatalf("got %+v", r)
	}
}

func TestHTTPSMFClient_ResAllocFailCancelledIsA2xx(t *testing.T) {
	var last map[string]any
	var path, corr string
	c := smfServer(t, 200, `{"hoState":"CANCELLED"}`, &last, &path, &corr)
	r := c.HandoverResourceAllocationFailed(context.Background(), "ref1", []byte{1})
	if !r.OK() || r.HoState != "CANCELLED" || last["n2SmInfo"] != b64([]byte{1}) {
		t.Fatalf("got %+v body %v", r, last)
	}
}
