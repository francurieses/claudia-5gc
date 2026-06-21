//go:build functional

// Unified in-process step definitions for the AMF inbound SBI server features:
//   - ue_context_transfer.feature           (TS 29.518 §5.3.2)
//   - network_triggered_service_request.feature (TS 23.502 §4.2.3.3)
//
// Both features drive the real internal/sbi server in-process (no UERANSIM), so
// they share one world and one set of step definitions to avoid duplicate-step
// registration and to keep per-scenario state coherent.
package features_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/cucumber/godog"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfsbi "github.com/francurieses/claudia-5gc/nf/amf/internal/sbi"
)

// pagingSpy records SendPaging invocations for the paging assertions.
type pagingSpy struct{ count int }

func (p *pagingSpy) SendPaging(_ *amfctx.UEContext) error { p.count++; return nil }

// sbiWorld holds per-scenario state for the AMF inbound SBI features.
type sbiWorld struct {
	mgr  *amfctx.Manager
	ts   *httptest.Server
	pgr  *pagingSpy
	ue   *amfctx.UEContext
	resp *http.Response
	body []byte
}

func (w *sbiWorld) reset() {
	if w.ts != nil {
		w.ts.Close()
	}
	w.mgr = amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	srv, err := amfsbi.New(amfsbi.Config{Address: "127.0.0.1:0"}, w.mgr, nil)
	if err != nil {
		panic(err)
	}
	w.pgr = &pagingSpy{}
	srv.SetPager(w.pgr)
	w.ts = httptest.NewServer(srv.HTTPHandler())
	w.ue, w.resp, w.body = nil, nil, nil
}

func (w *sbiWorld) serverRunning() error { return nil }

func (w *sbiWorld) ueRegistered(supi string) error {
	ue := w.mgr.AllocateUEContext(1)
	w.mgr.SetSUPI(ue, supi)
	w.mgr.AssignGUTI(context.Background(), ue)
	ue.SecurityCtx = amfctx.SecurityContext{
		Active: true, IntegrityAlgID: 2, CipheringAlgID: 2,
		KAMF: bytes.Repeat([]byte{0xAB}, 32), UplinkCount: 3, DownlinkCount: 4,
	}
	w.ue = ue
	return nil
}

func (w *sbiWorld) ueHasSession(psi int, dnn string) error {
	if w.ue == nil {
		return fmt.Errorf("no UE seeded")
	}
	w.ue.PDUSessions[uint8(psi)] = &amfctx.PDUSession{
		PDUSessionID: uint8(psi), DNN: dnn, SMFInstanceID: "smf-ctx-ref-1",
		SNSSAI: amfctx.SNSSAISubscribed{SST: 1, SD: "000001"},
	}
	return nil
}

func (w *sbiWorld) ueIsIdle() error      { w.ue.CMState = amfctx.CMIdle; return nil }
func (w *sbiWorld) ueIsConnected() error { w.ue.CMState = amfctx.CMConnected; return nil }

// ---- transport helpers ----------------------------------------------------

func (w *sbiWorld) do(method, path string, body []byte) error {
	req, _ := http.NewRequest(method, w.ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.ts.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	w.resp, w.body = resp, buf.Bytes()
	return nil
}

// ---- UEContextTransfer steps ----------------------------------------------

func (w *sbiWorld) transferForUE(reason string) error {
	body, _ := json.Marshal(amfsbi.UeContextTransferReqData{Reason: reason})
	return w.do(http.MethodPost, "/namf-comm/v1/ue-contexts/"+w.ue.SUPI+"/transfer", body)
}

func (w *sbiWorld) transferUnknownUE() error {
	body, _ := json.Marshal(amfsbi.UeContextTransferReqData{Reason: amfsbi.ReasonMobiReg})
	return w.do(http.MethodPost, "/namf-comm/v1/ue-contexts/imsi-999999999999999/transfer", body)
}

func (w *sbiWorld) transferNoReason() error {
	body, _ := json.Marshal(amfsbi.UeContextTransferReqData{})
	return w.do(http.MethodPost, "/namf-comm/v1/ue-contexts/"+w.ue.SUPI+"/transfer", body)
}

func (w *sbiWorld) responseHasSecurityContext() error {
	var rsp amfsbi.UeContextTransferRspData
	if err := json.Unmarshal(w.body, &rsp); err != nil {
		return err
	}
	if len(rsp.UeContext.MmContextList) != 1 || rsp.UeContext.MmContextList[0].NasSecurityMode == nil {
		return fmt.Errorf("missing mmContext/nasSecurityMode: %+v", rsp.UeContext)
	}
	sm := rsp.UeContext.MmContextList[0].NasSecurityMode
	if sm.IntegrityAlgorithm == "" || sm.CipheringAlgorithm == "" {
		return fmt.Errorf("algorithms not set: %+v", sm)
	}
	return nil
}

func (w *sbiWorld) responseListsSession(psi int, dnn string) error {
	var rsp amfsbi.UeContextTransferRspData
	if err := json.Unmarshal(w.body, &rsp); err != nil {
		return err
	}
	for _, sc := range rsp.UeContext.SessionContextList {
		if sc.PduSessionID == uint8(psi) && sc.Dnn == dnn {
			return nil
		}
	}
	return fmt.Errorf("session %d on %q not found in %+v", psi, dnn, rsp.UeContext.SessionContextList)
}

func (w *sbiWorld) contextMarkedTransferred() error {
	w.ue.Lock()
	defer w.ue.Unlock()
	if !w.ue.Transferred {
		return fmt.Errorf("UE context not marked transferred")
	}
	return nil
}

// ---- N1N2MessageTransfer steps --------------------------------------------

func (w *sbiWorld) smfPostsForSession(psi int) error {
	p := uint8(psi)
	body, _ := json.Marshal(amfsbi.N1N2MessageTransferReqData{PduSessionID: &p})
	return w.do(http.MethodPost, "/namf-comm/v1/ue-contexts/"+w.ue.SUPI+"/n1-n2-messages", body)
}

func (w *sbiWorld) smfPostsUnknownUE() error {
	p := uint8(1)
	body, _ := json.Marshal(amfsbi.N1N2MessageTransferReqData{PduSessionID: &p})
	return w.do(http.MethodPost, "/namf-comm/v1/ue-contexts/imsi-999999999999999/n1-n2-messages", body)
}

func (w *sbiWorld) transferCauseIs(cause string) error {
	var rsp amfsbi.N1N2MessageTransferRspData
	if err := json.Unmarshal(w.body, &rsp); err != nil {
		return err
	}
	if rsp.Cause != cause {
		return fmt.Errorf("cause = %q, want %q", rsp.Cause, cause)
	}
	return nil
}

func (w *sbiWorld) pagingEmitted() error {
	if w.pgr.count < 1 {
		return fmt.Errorf("expected paging, SendPaging called %d times", w.pgr.count)
	}
	return nil
}

func (w *sbiWorld) pagingNotEmitted() error {
	if w.pgr.count != 0 {
		return fmt.Errorf("expected no paging, SendPaging called %d times", w.pgr.count)
	}
	return nil
}

// ---- shared assertions ----------------------------------------------------

func (w *sbiWorld) statusIs(code int) error {
	if w.resp.StatusCode != code {
		return fmt.Errorf("status = %d, want %d; body=%s", w.resp.StatusCode, code, w.body)
	}
	return nil
}

func (w *sbiWorld) problemCauseIs(cause string) error {
	var pd amfsbi.ProblemDetails
	if err := json.Unmarshal(w.body, &pd); err != nil {
		return err
	}
	if pd.Cause != cause {
		return fmt.Errorf("cause = %q, want %q", pd.Cause, cause)
	}
	return nil
}

// initAMFSBISteps registers all in-process AMF SBI steps. Called from
// InitializeScenario in steps_test.go.
func initAMFSBISteps(sc *godog.ScenarioContext) {
	w := &sbiWorld{}
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})

	// Background (shared by both features)
	sc.Step(`^the AMF inbound namf-comm SBI server is running$`, w.serverRunning)
	sc.Step(`^a UE "([^"]+)" is registered with an active NAS security context$`, w.ueRegistered)
	sc.Step(`^the UE has an established PDU session (\d+) on DNN "([^"]+)"$`, w.ueHasSession)
	sc.Step(`^the UE is CM-IDLE$`, w.ueIsIdle)
	sc.Step(`^the UE is CM-CONNECTED$`, w.ueIsConnected)

	// UEContextTransfer
	sc.Step(`^a new AMF POSTs a UEContextTransfer request for the UE with reason "([^"]+)"$`, w.transferForUE)
	sc.Step(`^a new AMF POSTs a UEContextTransfer request for an unknown UE$`, w.transferUnknownUE)
	sc.Step(`^a new AMF POSTs a UEContextTransfer request with no reason$`, w.transferNoReason)
	sc.Step(`^the response carries the UE security context with the selected NAS algorithms$`, w.responseHasSecurityContext)
	sc.Step(`^the response lists PDU session context (\d+) with DNN "([^"]+)"$`, w.responseListsSession)
	sc.Step(`^the old AMF marks the UE context as transferred$`, w.contextMarkedTransferred)

	// N1N2MessageTransfer
	sc.Step(`^the SMF POSTs an N1N2MessageTransfer for PDU session (\d+)$`, w.smfPostsForSession)
	sc.Step(`^the SMF POSTs an N1N2MessageTransfer for an unknown UE$`, w.smfPostsUnknownUE)
	sc.Step(`^the N1N2 transfer cause is "([^"]+)"$`, w.transferCauseIs)
	sc.Step(`^the AMF emits an NGAP Paging for the UE$`, w.pagingEmitted)
	sc.Step(`^the AMF does not emit a Paging$`, w.pagingNotEmitted)

	// Shared assertions
	sc.Step(`^the response status is (\d+)$`, w.statusIs)
	sc.Step(`^the problem detail cause is "([^"]+)"$`, w.problemCauseIs)
}
