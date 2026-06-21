package sbi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// newTestServer builds an SBI server with no TLS (H2C handler) for in-process tests.
func newTestServer(t *testing.T) (*Server, *amfctx.Manager) {
	t.Helper()
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	s, err := New(Config{Address: "127.0.0.1:0"}, mgr, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, mgr
}

// seedRegisteredUE creates a UE with an active security context, an assigned
// 5G-GUTI (registered in the manager's TMSI index), and one PDU session.
func seedRegisteredUE(mgr *amfctx.Manager, supi string) *amfctx.UEContext {
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, supi)
	mgr.AssignGUTI(context.Background(), ue)
	ue.SecurityCtx = amfctx.SecurityContext{
		Active:         true,
		IntegrityAlgID: 2, // NIA2
		CipheringAlgID: 2, // NEA2
		KAMF:           bytes.Repeat([]byte{0xAB}, 32),
		UplinkCount:    3,
		DownlinkCount:  4,
	}
	ue.PDUSessions[1] = &amfctx.PDUSession{
		PDUSessionID:  1,
		DNN:           "internet",
		SMFInstanceID: "smf-ctx-ref-1",
		SNSSAI:        amfctx.SNSSAISubscribed{SST: 1, SD: "000001"},
	}
	return ue
}

func post(t *testing.T, srv *Server, ueContextID string, body []byte) (*http.Response, []byte) {
	t.Helper()
	ts := httptest.NewServer(srv.httpSrv.Handler)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/namf-comm/v1/ue-contexts/"+ueContextID+"/transfer",
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

func TestUEContextTransfer_HappyPath_BySUPI(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedRegisteredUE(mgr, "imsi-001010000000001")

	body, _ := json.Marshal(UeContextTransferReqData{Reason: ReasonMobiReg, AccessType: "3GPP_ACCESS"})
	resp, raw := post(t, srv, "imsi-001010000000001", body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}
	var rsp UeContextTransferRspData
	if err := json.Unmarshal(raw, &rsp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rsp.UeContext.Supi != "imsi-001010000000001" {
		t.Errorf("supi = %q", rsp.UeContext.Supi)
	}
	if len(rsp.UeContext.MmContextList) != 1 {
		t.Fatalf("mmContextList len = %d, want 1", len(rsp.UeContext.MmContextList))
	}
	sm := rsp.UeContext.MmContextList[0].NasSecurityMode
	if sm == nil || sm.IntegrityAlgorithm != "NIA2" || sm.CipheringAlgorithm != "NEA2" {
		t.Errorf("nasSecurityMode = %+v, want NIA2/NEA2", sm)
	}
	if rsp.UeContext.MmContextList[0].KAmf == "" {
		t.Error("kamf not carried")
	}
	if len(rsp.UeContext.SessionContextList) != 1 || rsp.UeContext.SessionContextList[0].Dnn != "internet" {
		t.Errorf("sessionContextList = %+v", rsp.UeContext.SessionContextList)
	}

	ue, _ := mgr.GetBySUPI("imsi-001010000000001")
	ue.Lock()
	transferred := ue.Transferred
	ue.Unlock()
	if !transferred {
		t.Error("UE context not marked transferred")
	}
}

func TestUEContextTransfer_ByGUTI(t *testing.T) {
	srv, mgr := newTestServer(t)
	ue := seedRegisteredUE(mgr, "imsi-001010000000001")

	body, _ := json.Marshal(UeContextTransferReqData{Reason: ReasonMobiReg})
	// 5g-guti: trailing 8 hex digits carry the assigned 5G-TMSI.
	id := fmt.Sprintf("5g-guti-00101000020%08x", ue.GUTI.TMSI)
	resp, raw := post(t, srv, id, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}
}

func TestUEContextTransfer_NotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	body, _ := json.Marshal(UeContextTransferReqData{Reason: ReasonMobiReg})
	resp, raw := post(t, srv, "imsi-999999999999999", body)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", resp.StatusCode, raw)
	}
	var pd ProblemDetails
	_ = json.Unmarshal(raw, &pd)
	if pd.Cause != "CONTEXT_NOT_FOUND" {
		t.Errorf("cause = %q, want CONTEXT_NOT_FOUND", pd.Cause)
	}
}

// fakePager records SendPaging calls for assertions.
type fakePager struct{ paged int }

func (f *fakePager) SendPaging(_ *amfctx.UEContext) error { f.paged++; return nil }

func postN1N2(t *testing.T, srv *Server, ueContextID string, body []byte) (*http.Response, []byte) {
	t.Helper()
	ts := httptest.NewServer(srv.httpSrv.Handler)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/namf-comm/v1/ue-contexts/"+ueContextID+"/n1-n2-messages",
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

func TestN1N2MessageTransfer_IdleUEPaged(t *testing.T) {
	srv, mgr := newTestServer(t)
	fp := &fakePager{}
	srv.SetPager(fp)
	ue := seedRegisteredUE(mgr, "imsi-001010000000001")
	ue.CMState = amfctx.CMIdle

	psi := uint8(1)
	body, _ := json.Marshal(N1N2MessageTransferReqData{PduSessionID: &psi})
	resp, raw := postN1N2(t, srv, "imsi-001010000000001", body)

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", resp.StatusCode, raw)
	}
	var rsp N1N2MessageTransferRspData
	_ = json.Unmarshal(raw, &rsp)
	if rsp.Cause != CauseAttemptingToReachUE {
		t.Errorf("cause = %q, want %q", rsp.Cause, CauseAttemptingToReachUE)
	}
	if fp.paged != 1 {
		t.Errorf("SendPaging called %d times, want 1", fp.paged)
	}
	ue.Lock()
	pending := ue.PendingN1N2
	ue.Unlock()
	if !pending {
		t.Error("PendingN1N2 not set")
	}
}

func TestN1N2MessageTransfer_ConnectedUENoPaging(t *testing.T) {
	srv, mgr := newTestServer(t)
	fp := &fakePager{}
	srv.SetPager(fp)
	ue := seedRegisteredUE(mgr, "imsi-001010000000001")
	ue.CMState = amfctx.CMConnected

	psi := uint8(1)
	body, _ := json.Marshal(N1N2MessageTransferReqData{PduSessionID: &psi})
	resp, raw := postN1N2(t, srv, "imsi-001010000000001", body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}
	var rsp N1N2MessageTransferRspData
	_ = json.Unmarshal(raw, &rsp)
	if rsp.Cause != CauseN1N2TransferInitiated {
		t.Errorf("cause = %q, want %q", rsp.Cause, CauseN1N2TransferInitiated)
	}
	if fp.paged != 0 {
		t.Errorf("SendPaging called %d times, want 0 (UE connected)", fp.paged)
	}
}

func TestN1N2MessageTransfer_NotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.SetPager(&fakePager{})
	psi := uint8(1)
	body, _ := json.Marshal(N1N2MessageTransferReqData{PduSessionID: &psi})
	resp, raw := postN1N2(t, srv, "imsi-999999999999999", body)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", resp.StatusCode, raw)
	}
	var pd ProblemDetails
	_ = json.Unmarshal(raw, &pd)
	if pd.Cause != "CONTEXT_NOT_FOUND" {
		t.Errorf("cause = %q, want CONTEXT_NOT_FOUND", pd.Cause)
	}
}

func TestUEContextTransfer_MissingReason(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedRegisteredUE(mgr, "imsi-001010000000001")
	body, _ := json.Marshal(UeContextTransferReqData{}) // no reason
	resp, raw := post(t, srv, "imsi-001010000000001", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, raw)
	}
	var pd ProblemDetails
	_ = json.Unmarshal(raw, &pd)
	if pd.Cause != "MANDATORY_IE_MISSING" {
		t.Errorf("cause = %q, want MANDATORY_IE_MISSING", pd.Cause)
	}
}
