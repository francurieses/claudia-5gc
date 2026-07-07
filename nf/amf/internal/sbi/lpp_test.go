package sbi

// lpp_test.go — unit tests for the Namf_Location dl-lpp-info handler (LMF-005).
//
// Tests: happy path (200), UE not found (404), missing lppPdu field (400),
// invalid base64 body (400), UE CM-IDLE returns 504, relay send error returns
// 504, relay not wired returns 503, relay timeout returns 504.
//
// Ref: TS 29.518 §5.2.2.6; TS 24.501 §8.7.4; TS 23.273 §7.2.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
)

// fakeLPPRelay is a test double for the LPPRelay interface.
type fakeLPPRelay struct {
	result        nasmsg.LPPResult
	sendErr       error // returned directly from SendDownlinkLPP / SendDownlinkLPPNoWait
	noSend        bool  // if true, nothing is sent (simulate timeout)
	called        int
	noWaitCalled  int
	lastPDU       []byte
	lastNoWaitPDU []byte
}

func (f *fakeLPPRelay) SendDownlinkLPP(_ *amfctx.UEContext, lppPDU []byte) (<-chan nasmsg.LPPResult, error) {
	f.called++
	f.lastPDU = lppPDU
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	ch := make(chan nasmsg.LPPResult, 1)
	if !f.noSend {
		ch <- f.result
	}
	return ch, nil
}

func (f *fakeLPPRelay) SendDownlinkLPPNoWait(_ *amfctx.UEContext, lppPDU []byte) error {
	f.noWaitCalled++
	f.lastNoWaitPDU = lppPDU
	return f.sendErr
}

// testLPPPayload is a sample DL LPP PDU body (arbitrary bytes, base64-encoded).
var testLPPPayload = []byte{0x00, 0x01, 0x80} // matches a real BuildRequestCapabilities shape

// postDLLPP posts to the namf-loc dl-lpp-info endpoint.
func postDLLPP(t *testing.T, srv *Server, ueContextID string, body []byte) (*http.Response, []byte) {
	t.Helper()
	ts := httptest.NewServer(srv.httpSrv.Handler)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/namf-loc/v1/ue-contexts/"+ueContextID+"/dl-lpp-info",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

// TestDLLPPInfo_HappyPath verifies that a CM-CONNECTED UE with a wired LPPRelay
// returns 200 with the UL LPP PDU base64-encoded in the response body.
// Ref: TS 29.518 §5.2.2.6; TS 24.501 §8.7.4.
func TestDLLPPInfo_HappyPath(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")

	ulPDU := []byte{0x80, 0x00, 0x80, 0x3e, 0x20} // simulated UL LPP PDU

	relay := &fakeLPPRelay{result: nasmsg.LPPResult{LPPPDU: ulPDU}}
	srv.SetLPPRelay(relay)

	reqBody, _ := json.Marshal(DLLPPInfoReq{
		LppPdu: base64.StdEncoding.EncodeToString(testLPPPayload),
	})
	resp, raw := postDLLPP(t, srv, "imsi-001010000000001", reqBody)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}
	var rsp DLLPPInfoRsp
	if err := json.Unmarshal(raw, &rsp); err != nil {
		t.Fatalf("decode DLLPPInfoRsp: %v", err)
	}
	gotPDU, err := base64.StdEncoding.DecodeString(rsp.LppPdu)
	if err != nil {
		t.Fatalf("base64 decode lppPdu in response: %v", err)
	}
	if string(gotPDU) != string(ulPDU) {
		t.Errorf("UL LPP PDU = %v, want %v", gotPDU, ulPDU)
	}
	if relay.called != 1 {
		t.Errorf("SendDownlinkLPP called %d times, want 1", relay.called)
	}
	if string(relay.lastPDU) != string(testLPPPayload) {
		t.Errorf("relayed DL LPP PDU mismatch")
	}
}

// TestDLLPPInfo_UENotFound verifies that a request for an unknown UE returns 404.
func TestDLLPPInfo_UENotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	relay := &fakeLPPRelay{}
	srv.SetLPPRelay(relay)

	reqBody, _ := json.Marshal(DLLPPInfoReq{
		LppPdu: base64.StdEncoding.EncodeToString(testLPPPayload),
	})
	resp, raw := postDLLPP(t, srv, "imsi-999990000000001", reqBody)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body=%s", resp.StatusCode, raw)
	}
	if relay.called != 0 {
		t.Error("SendDownlinkLPP should not be called for unknown UE")
	}
}

// TestDLLPPInfo_MissingLppPdu verifies that a missing lppPdu field returns 400.
func TestDLLPPInfo_MissingLppPdu(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")
	srv.SetLPPRelay(&fakeLPPRelay{})

	reqBody, _ := json.Marshal(map[string]string{})
	resp, raw := postDLLPP(t, srv, "imsi-001010000000001", reqBody)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, raw)
	}
}

// TestDLLPPInfo_InvalidBase64 verifies that an invalid base64 lppPdu returns 400.
func TestDLLPPInfo_InvalidBase64(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")
	srv.SetLPPRelay(&fakeLPPRelay{})

	reqBody, _ := json.Marshal(DLLPPInfoReq{LppPdu: "not!valid@base64$"})
	resp, raw := postDLLPP(t, srv, "imsi-001010000000001", reqBody)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, raw)
	}
}

// TestDLLPPInfo_CMIdle verifies that a CM-IDLE UE returns 504 (LPP relay
// requires an active N1/N2 connection).
// Ref: TS 24.501 §8.7.4 (DL NAS Transport requires CM-CONNECTED).
func TestDLLPPInfo_CMIdle(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedRegisteredUE(mgr, "imsi-001010000000001") // CMState is CMIdle by default
	srv.SetLPPRelay(&fakeLPPRelay{})

	reqBody, _ := json.Marshal(DLLPPInfoReq{
		LppPdu: base64.StdEncoding.EncodeToString(testLPPPayload),
	})
	resp, raw := postDLLPP(t, srv, "imsi-001010000000001", reqBody)

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504; body=%s", resp.StatusCode, raw)
	}
}

// TestDLLPPInfo_SendError verifies that an error from SendDownlinkLPP returns 504.
func TestDLLPPInfo_SendError(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")

	relay := &fakeLPPRelay{sendErr: fmt.Errorf("nasmsg: send downlink lpp: connection refused")}
	srv.SetLPPRelay(relay)

	reqBody, _ := json.Marshal(DLLPPInfoReq{
		LppPdu: base64.StdEncoding.EncodeToString(testLPPPayload),
	})
	resp, raw := postDLLPP(t, srv, "imsi-001010000000001", reqBody)

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504; body=%s", resp.StatusCode, raw)
	}
}

// TestDLLPPInfo_RelayNotWired verifies the 503 code path when no LPPRelay is wired.
func TestDLLPPInfo_RelayNotWired(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")
	// Intentionally do NOT call srv.SetLPPRelay — relay remains nil.

	reqBody, _ := json.Marshal(DLLPPInfoReq{
		LppPdu: base64.StdEncoding.EncodeToString(testLPPPayload),
	})
	resp, raw := postDLLPP(t, srv, "imsi-001010000000001", reqBody)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (relay not wired); body=%s", resp.StatusCode, raw)
	}
}

// boolPtr returns a pointer to b (for the DLLPPInfoReq.ExpectUlResponse field).
func boolPtr(b bool) *bool { return &b }

// TestDLLPPInfo_ExpectUlResponseFalseReturns204 verifies the LMF-009 DL-only
// leg: expectUlResponse=false → the AMF sends via SendDownlinkLPPNoWait
// (registering no waiter) and returns 204 No Content with an empty body.
// Ref: docs/procedures/LPPRelay.md §Endpoints; TS 37.355 §6.5.2.
func TestDLLPPInfo_ExpectUlResponseFalseReturns204(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")

	relay := &fakeLPPRelay{}
	srv.SetLPPRelay(relay)

	reqBody, _ := json.Marshal(DLLPPInfoReq{
		LppPdu:           base64.StdEncoding.EncodeToString(testLPPPayload),
		ExpectUlResponse: boolPtr(false),
	})
	resp, raw := postDLLPP(t, srv, "imsi-001010000000001", reqBody)

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", resp.StatusCode, raw)
	}
	if len(raw) != 0 {
		t.Errorf("204 body = %q, want empty", raw)
	}
	if relay.noWaitCalled != 1 {
		t.Errorf("SendDownlinkLPPNoWait called %d times, want 1", relay.noWaitCalled)
	}
	if relay.called != 0 {
		t.Errorf("SendDownlinkLPP (waiter path) called %d times, want 0", relay.called)
	}
	if string(relay.lastNoWaitPDU) != string(testLPPPayload) {
		t.Errorf("relayed DL LPP PDU mismatch on the no-wait path")
	}
}

// TestDLLPPInfo_ExpectUlResponseTrueExplicit verifies that an explicit
// expectUlResponse=true behaves exactly like the absent-field default (200
// with the UL LPP PDU).
func TestDLLPPInfo_ExpectUlResponseTrueExplicit(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")

	ulPDU := []byte{0x90, 0x03, 0x08, 0x21, 0x00, 0x00, 0xe4, 0x08, 0x00}
	relay := &fakeLPPRelay{result: nasmsg.LPPResult{LPPPDU: ulPDU}}
	srv.SetLPPRelay(relay)

	reqBody, _ := json.Marshal(DLLPPInfoReq{
		LppPdu:           base64.StdEncoding.EncodeToString(testLPPPayload),
		ExpectUlResponse: boolPtr(true),
	})
	resp, raw := postDLLPP(t, srv, "imsi-001010000000001", reqBody)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}
	if relay.called != 1 || relay.noWaitCalled != 0 {
		t.Errorf("relay calls = (wait %d, no-wait %d), want (1, 0)", relay.called, relay.noWaitCalled)
	}
}

// TestDLLPPInfo_ExpectUlResponseFalseSendError verifies a no-wait send
// failure still maps to 504 LPP_RELAY_FAILURE.
func TestDLLPPInfo_ExpectUlResponseFalseSendError(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")

	relay := &fakeLPPRelay{sendErr: fmt.Errorf("nasmsg: send downlink lpp (no-wait): connection refused")}
	srv.SetLPPRelay(relay)

	reqBody, _ := json.Marshal(DLLPPInfoReq{
		LppPdu:           base64.StdEncoding.EncodeToString(testLPPPayload),
		ExpectUlResponse: boolPtr(false),
	})
	resp, raw := postDLLPP(t, srv, "imsi-001010000000001", reqBody)

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504; body=%s", resp.StatusCode, raw)
	}
}

// TestDLLPPInfo_WithTransactionID verifies that an lppTransactionId in the
// request is accepted without error (optional correlation aid, not used for
// AMF-side correlation — that keys on AMF-UE-NGAP-ID).
func TestDLLPPInfo_WithTransactionID(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedConnectedUE(mgr, "imsi-001010000000001")

	ulPDU := []byte{0x40, 0x01, 0xa0}
	relay := &fakeLPPRelay{result: nasmsg.LPPResult{LPPPDU: ulPDU}}
	srv.SetLPPRelay(relay)

	reqBody, _ := json.Marshal(DLLPPInfoReq{
		LppPdu:           base64.StdEncoding.EncodeToString(testLPPPayload),
		LppTransactionId: 7,
	})
	resp, raw := postDLLPP(t, srv, "imsi-001010000000001", reqBody)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}
}
