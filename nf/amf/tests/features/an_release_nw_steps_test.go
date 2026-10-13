//go:build functional

// an_release_nw_steps_test.go -- in-process godog steps for an_release_nw.feature
// (O&M-triggered AN release, TS 23.502 §4.2.6; TS 38.413 §8.3.3; TS 38.412 §7).
//
// The real mgmt.RegisterANRelease routes (plus a method-less catch-all like
// cmd/amf) are served by an httptest server in front of the real *ngap.Server
// (sbiW.mgr is the UE store). The gNB is a GNBContext with the fake SCTP
// transport seam (SetTransportForTest) that captures the written NGAP PDUs and
// the SndRcvInfo PPID. The Release Complete is fed through the server's
// dispatch path when the DispatchNGAPForTest seam exists (see anDispatcher);
// the SMF notification is the callback cmd/amf wires with SetANReleaseHandler,
// mirrored here against the shared httptest SMF of ntsrW (so the shared
// "AMF requests upCnxState ... exactly once" step asserts on it).
// The last scenario drives the real NAS handler with an integrity-protected
// Registration Complete and reads the snapshot over the mgmt GET route.
package features_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/mgmt"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

const anGNBAddr = "172.30.1.10:48211"

// anDispatcher is the exported seam needed to feed a gNB-originated NGAP PDU
// through ngap.Server.dispatch (decode + route) from this external package. It
// is absent today: the Release Complete step reports pending until the seam
// exists. Proposed (gnb_registry_seams.go style):
//
//	func (s *Server) DispatchNGAPForTest(ctx context.Context, gnb *GNBContext, pdu []byte) {
//		s.dispatch(ctx, gnb, pdu)
//	}
type anDispatcher interface {
	DispatchNGAPForTest(ctx context.Context, gnb *amfngap.GNBContext, pdu []byte)
}

type anWrite struct {
	pdu  []byte
	ppid uint32
}

type anWorld struct {
	srv  *amfngap.Server
	gnb  *amfngap.GNBContext
	api  *httptest.Server
	mu   sync.Mutex
	sent []anWrite

	ranID    int64
	resp     *http.Response
	body     []byte
	respBody map[string]json.RawMessage
}

var anW = &anWorld{}

func (w *anWorld) reset() {
	if w.api != nil {
		w.api.Close()
		w.api = nil
	}
	w.sent, w.gnb, w.resp, w.body, w.respBody = nil, nil, nil, nil, nil
	w.ranID = 0
	w.srv = amfngap.NewServer("", sbiW.mgr, nil, amfngap.AMFConfig{MCC: "001", MNC: "01"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func (w *anWorld) writes() []anWrite {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]anWrite(nil), w.sent...)
}

// ---- Background -----------------------------------------------------------

// mgmtRunning serves the AN release routes exactly as cmd/amf registers them,
// next to the method-less subtree catch-all (the routing pitfall) and the
// read-only UE snapshot route.
func (w *anWorld) mgmtRunning() error {
	if sbiW.ue == nil {
		return fmt.Errorf("no UE seeded")
	}
	// The Background UE is registered (RM-REGISTERED, TS 23.502 §4.2.2.2.2).
	sbiW.ue.Lock()
	sbiW.ue.State = amfctx.GMMRegistered
	sbiW.ue.Unlock()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /amf/v1/ue-contexts/{supi}", func(rw http.ResponseWriter, r *http.Request) {
		ue, ok := sbiW.mgr.GetBySUPI(r.PathValue("supi"))
		if !ok {
			http.Error(rw, "UE not found", http.StatusNotFound)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(ue.Snapshot())
	})
	mgmt.RegisterANRelease(mux, sbiW.mgr, w.srv, logger)
	mux.HandleFunc("/amf/v1/ue-contexts/", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rw.WriteHeader(http.StatusNotFound)
	})
	w.api = httptest.NewServer(mux)
	return nil
}

// smfMockRecords arms the shared httptest SMF of ntsrW so a DEACTIVATED
// UpdateSMContext answers 200 (the mock answers 500 without an N2SM body).
func (w *anWorld) smfMockRecords() error {
	sbiW.ue.Lock()
	defer sbiW.ue.Unlock()
	ntsrW.mu.Lock()
	defer ntsrW.mu.Unlock()
	for psi := range sbiW.ue.PDUSessions {
		ntsrW.n2sm[ntsrRef(int(psi))] = []byte{0xA0, psi, 0x01}
	}
	// Sessions added after the Background (PDU session 2) are armed on demand.
	return nil
}

// ---- Given ----------------------------------------------------------------

func (w *anWorld) servedByGNB() error {
	ue := sbiW.ue
	g := &amfngap.GNBContext{
		Name:    "gnb-an-release",
		UEs:     map[int64]*amfctx.UEContext{},
		IdleUEs: map[int64]*amfctx.UEContext{},
	}
	g.SetTransportForTest(anGNBAddr, func(pdu []byte, info *sctp.SndRcvInfo) (int, error) {
		var ppid uint32
		if info != nil {
			ppid = info.PPID
		}
		w.mu.Lock()
		w.sent = append(w.sent, anWrite{pdu: append([]byte(nil), pdu...), ppid: ppid})
		w.mu.Unlock()
		return len(pdu), nil
	})
	w.srv.AddGNBForTest(anGNBAddr, g)
	w.srv.CompleteNGSetupForTest(g)

	ue.Lock()
	w.ranID = ue.RANUENGAPId
	ue.GNBAddr = anGNBAddr
	ue.Unlock()
	g.UEs[w.ranID] = ue
	w.gnb = g
	return nil
}

func (w *anWorld) noGNBAssociation() error {
	sbiW.ue.Lock()
	sbiW.ue.GNBAddr = ""
	sbiW.ue.Unlock()
	return nil
}

func (w *anWorld) deregistrationPending() error {
	sbiW.ue.Lock()
	sbiW.ue.PendingRemoval = true
	sbiW.ue.Unlock()
	return nil
}

func (w *anWorld) registrationComplete() error {
	ue := sbiW.ue
	ue.SecurityCtx.KNASint = bytes.Repeat([]byte{0x11}, 16)
	ue.SecurityCtx.KNASenc = bytes.Repeat([]byte{0x22}, 16)
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := procedures.NewRegistrationHandler(sbiW.mgr, nil, nil, nil, "nf", "001", "01", lg)
	h := nasmsg.NewHandler(&ntsrSender{w: ntsrW}, reg, lg)
	plain := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationComplete)}
	pdu, err := protectUL(ue, plain)
	if err != nil {
		return err
	}
	if err := h.HandleNASMessage(context.Background(), ue, pdu); err != nil {
		return fmt.Errorf("Registration Complete handling failed: %w", err)
	}
	return nil
}

// ---- When -----------------------------------------------------------------

func (w *anWorld) call(method, path string) error {
	if w.api == nil {
		return fmt.Errorf("AMF management API not running")
	}
	req, err := http.NewRequest(method, w.api.URL+path, nil)
	if err != nil {
		return err
	}
	resp, err := w.api.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	w.resp, w.body, w.respBody = resp, buf.Bytes(), nil
	// The shared "the response status is" step reads sbiW.resp.
	sbiW.resp, sbiW.body = resp, buf.Bytes()
	_ = json.Unmarshal(w.body, &w.respBody)
	return nil
}

func (w *anWorld) postRelease(supi string) error {
	return w.call(http.MethodPost, "/amf/v1/ue-contexts/"+supi+"/an-release")
}

func (w *anWorld) methodRelease(method, supi string) error {
	return w.call(method, "/amf/v1/ue-contexts/"+supi+"/an-release")
}

func (w *anWorld) requestSnapshot(supi string) error {
	return w.call(http.MethodGet, "/amf/v1/ue-contexts/"+supi)
}

// buildReleaseComplete encodes a gNB UEContextReleaseComplete (TS 38.413 §9.2.2.6).
func buildReleaseComplete(amfID, ranID int64) ([]byte, error) {
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeUEContextRelease},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentUEContextReleaseComplete,
				UEContextReleaseComplete: &ngapType.UEContextReleaseComplete{
					ProtocolIEs: ngapType.ProtocolIEContainerUEContextReleaseCompleteIEs{
						List: []ngapType.UEContextReleaseCompleteIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.UEContextReleaseCompleteIEsValue{
									Present:     ngapType.UEContextReleaseCompleteIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.UEContextReleaseCompleteIEsValue{
									Present:     ngapType.UEContextReleaseCompleteIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
								},
							},
						},
					},
				},
			},
		},
	}
	return libngap.Encoder(pdu)
}

// wireSMFNotify installs the callback cmd/amf registers with SetANReleaseHandler:
// one Nsmf_PDUSession_UpdateSMContext {upCnxState: DEACTIVATED} per PDU session
// (HTTPSMFClient.NotifyANRelease wire contract, TS 29.502 §5.2.2.3.2).
func (w *anWorld) wireSMFNotify() {
	smfURL := ntsrW.smf.URL
	w.srv.SetANReleaseHandler(func(ctx context.Context, ue *amfctx.UEContext) {
		ue.Lock()
		refs := make([]string, 0, len(ue.PDUSessions))
		for _, s := range ue.PDUSessions {
			if s.SMFInstanceID != "" {
				refs = append(refs, s.SMFInstanceID)
			}
		}
		ue.Unlock()
		for _, ref := range refs {
			body, _ := json.Marshal(map[string]string{"upCnxState": "DEACTIVATED"})
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
				smfURL+"/nsmf-pdusession/v1/sm-contexts/"+ref+"/modify", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	})
}

func (w *anWorld) gnbAnswersReleaseComplete() error {
	d, ok := any(w.srv).(anDispatcher)
	if !ok {
		// Seam missing: scenario cannot reach the Release Complete handler.
		return godog.ErrPending
	}
	if w.gnb == nil {
		return fmt.Errorf("no serving gNB")
	}
	ntsrW.active = true
	// Arm the SMF mock for every session, including ones added after the Background.
	if err := w.smfMockRecords(); err != nil {
		return err
	}
	w.wireSMFNotify()
	ue := sbiW.ue
	ue.Lock()
	amfID := ue.AMFUENGAPId
	ue.Unlock()
	pdu, err := buildReleaseComplete(amfID, w.ranID)
	if err != nil {
		return err
	}
	d.DispatchNGAPForTest(context.Background(), w.gnb, pdu)
	w.srv.WaitUESerialForTest(amfID)
	return nil
}

// ---- Then -----------------------------------------------------------------

func (w *anWorld) bodyField(name string, into any) error {
	raw, ok := w.respBody[name]
	if !ok {
		return fmt.Errorf("response has no %q field: %s", name, w.body)
	}
	return json.Unmarshal(raw, into)
}

func (w *anWorld) acceptedTrueAndPrevState(state string) error {
	var acc bool
	if err := w.bodyField("accepted", &acc); err != nil || !acc {
		return fmt.Errorf("accepted = %v (err %v), want true; body=%s", acc, err, w.body)
	}
	var cm string
	if err := w.bodyField("previous_cm_state", &cm); err != nil || cm != state {
		return fmt.Errorf("previous_cm_state = %q (err %v), want %q", cm, err, state)
	}
	return nil
}

// jsonNumbers decodes a JSON array and fails if any element is not a number.
func jsonNumbers(raw json.RawMessage) ([]int, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("not a JSON array: %s", raw)
	}
	out := make([]int, 0, len(items))
	for _, it := range items {
		s := strings.TrimSpace(string(it))
		if strings.HasPrefix(s, `"`) {
			return nil, fmt.Errorf("element %s is a JSON string, want number", s)
		}
		var n int
		if err := json.Unmarshal(it, &n); err != nil {
			return nil, fmt.Errorf("element %s is not an integer: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func (w *anWorld) affectedPDUSessions(n int) error {
	raw, ok := w.respBody["affected_pdu_sessions"]
	if !ok {
		return fmt.Errorf("no affected_pdu_sessions in %s", w.body)
	}
	got, err := jsonNumbers(raw)
	if err != nil {
		return err
	}
	if len(got) != 1 || got[0] != n {
		return fmt.Errorf("affected_pdu_sessions = %v, want [%d]", got, n)
	}
	return nil
}

func (w *anWorld) specRefNonEmpty() error {
	var s string
	if err := w.bodyField("spec_ref", &s); err != nil || s == "" {
		return fmt.Errorf("spec_ref = %q (err %v), want non-empty", s, err)
	}
	return nil
}

// pollWrites waits (short deadline) for at least n captured NGAP writes.
func (w *anWorld) pollWrites(n int) []anWrite {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := w.writes(); len(got) >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (w *anWorld) releaseCommand() (*ngapType.UEContextReleaseCommand, anWrite, error) {
	got := w.pollWrites(1)
	if len(got) != 1 {
		return nil, anWrite{}, fmt.Errorf("gNB received %d NGAP PDUs, want exactly 1", len(got))
	}
	pdu, err := libngap.Decoder(got[0].pdu)
	if err != nil {
		return nil, anWrite{}, fmt.Errorf("decode NGAP PDU: %w", err)
	}
	if pdu.Present != ngapType.NGAPPDUPresentInitiatingMessage || pdu.InitiatingMessage == nil {
		return nil, anWrite{}, fmt.Errorf("PDU is not an InitiatingMessage")
	}
	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeUEContextRelease {
		return nil, anWrite{}, fmt.Errorf("procedure code = %d, want 41",
			pdu.InitiatingMessage.ProcedureCode.Value)
	}
	cmd := pdu.InitiatingMessage.Value.UEContextReleaseCommand
	if cmd == nil {
		return nil, anWrite{}, fmt.Errorf("InitiatingMessage is not a UEContextReleaseCommand")
	}
	return cmd, got[0], nil
}

func (w *anWorld) sendsCommandProcCode(code int) error {
	cmd, _, err := w.releaseCommand()
	if err != nil {
		return err
	}
	_ = cmd
	if code != int(ngapType.ProcedureCodeUEContextRelease) {
		return fmt.Errorf("feature expects procedure code %d, TS 38.413 Table 9.1-1 gives 41", code)
	}
	return nil
}

func (w *anWorld) commandCarriesPairAndCause(label string, value int) error {
	cmd, _, err := w.releaseCommand()
	if err != nil {
		return err
	}
	list := cmd.ProtocolIEs.List
	if len(list) != 2 {
		return fmt.Errorf("UEContextReleaseCommand has %d IEs, want 2", len(list))
	}
	if list[0].Id.Value != ngapType.ProtocolIEIDUENGAPIDs || list[1].Id.Value != ngapType.ProtocolIEIDCause {
		return fmt.Errorf("IE order = %d,%d; want UE-NGAP-IDs (%d) then Cause (%d)",
			list[0].Id.Value, list[1].Id.Value, ngapType.ProtocolIEIDUENGAPIDs, ngapType.ProtocolIEIDCause)
	}
	ids := list[0].Value.UENGAPIDs
	if ids == nil || ids.Present != ngapType.UENGAPIDsPresentUENGAPIDPair || ids.UENGAPIDPair == nil {
		return fmt.Errorf("UE NGAP IDs is not the UENGAPIDPair choice")
	}
	ue := sbiW.ue
	ue.Lock()
	wantAMF, wantRAN := ue.AMFUENGAPId, ue.RANUENGAPId
	ue.Unlock()
	if ids.UENGAPIDPair.AMFUENGAPID.Value != wantAMF || ids.UENGAPIDPair.RANUENGAPID.Value != wantRAN {
		return fmt.Errorf("UE NGAP ID pair = (%d,%d), want (%d,%d)",
			ids.UENGAPIDPair.AMFUENGAPID.Value, ids.UENGAPIDPair.RANUENGAPID.Value, wantAMF, wantRAN)
	}
	c := list[1].Value.Cause
	if c == nil || c.Present != ngapType.CausePresentMisc || c.Misc == nil {
		return fmt.Errorf("Cause is not the misc group: %+v", c)
	}
	if label != "om-intervention" || int(c.Misc.Value) != value ||
		c.Misc.Value != ngapType.CauseMiscPresentOmIntervention {
		return fmt.Errorf("Cause misc = %d, want %q (%d)", c.Misc.Value, label, value)
	}
	return nil
}

func (w *anWorld) commandPPID(ppid int) error {
	_, wr, err := w.releaseCommand()
	if err != nil {
		return err
	}
	if wr.ppid != uint32(ppid) {
		return fmt.Errorf("SCTP PPID = %d, want %d", wr.ppid, ppid)
	}
	return nil
}

func (w *anWorld) notMarkedForRemoval() error {
	sbiW.ue.Lock()
	defer sbiW.ue.Unlock()
	if sbiW.ue.PendingRemoval {
		return fmt.Errorf("UE is marked PendingRemoval")
	}
	return nil
}

func (w *anWorld) becomesCMIdle() error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		sbiW.ue.Lock()
		cm := sbiW.ue.CMState
		sbiW.ue.Unlock()
		if cm == amfctx.CMIdle {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("UE CM state = %s, want CM-IDLE", cm)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (w *anWorld) stillCM(want amfctx.CMState) error {
	sbiW.ue.Lock()
	defer sbiW.ue.Unlock()
	if sbiW.ue.CMState != want {
		return fmt.Errorf("UE CM state = %s, want %s", sbiW.ue.CMState, want)
	}
	return nil
}

func (w *anWorld) contextPresentRegistered() error {
	ue, ok := sbiW.mgr.GetBySUPI(sbiW.ue.SUPI)
	if !ok {
		return fmt.Errorf("UE context for %s no longer present", sbiW.ue.SUPI)
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.State != amfctx.GMMRegistered {
		return fmt.Errorf("UE RM state = %v, want RM-REGISTERED", ue.State)
	}
	return nil
}

func (w *anWorld) noCommand() error {
	// No async path may emit one: give a late writer a short chance, then assert.
	time.Sleep(50 * time.Millisecond)
	if got := w.writes(); len(got) != 0 {
		return fmt.Errorf("gNB received %d NGAP PDU(s), want none", len(got))
	}
	return nil
}

func (w *anWorld) noDeactivatedRequest(state string) error {
	ntsrW.mu.Lock()
	defer ntsrW.mu.Unlock()
	for ref, states := range ntsrW.requests {
		for _, s := range states {
			if s == state {
				return fmt.Errorf("SMF received upCnxState=%s for %s", state, ref)
			}
		}
	}
	return nil
}

func (w *anWorld) allowHeader(want string) error {
	if got := w.resp.Header.Get("Allow"); got != want {
		return fmt.Errorf("Allow header = %q, want %q", got, want)
	}
	return nil
}

func (w *anWorld) snapshotRegistrationTime() error {
	var s string
	if err := w.bodyField("registration_time", &s); err != nil {
		return err
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return fmt.Errorf("registration_time %q: %w", s, err)
	}
	if t.IsZero() {
		return fmt.Errorf("registration_time is the zero time (%s)", s)
	}
	return nil
}

func (w *anWorld) snapshotPDUSessionIDs(n int) error {
	raw, ok := w.respBody["pdu_session_ids"]
	if !ok {
		return fmt.Errorf("no pdu_session_ids in %s", w.body)
	}
	got, err := jsonNumbers(raw)
	if err != nil {
		return err
	}
	if len(got) != 1 || got[0] != n {
		return fmt.Errorf("pdu_session_ids = %v, want [%d]", got, n)
	}
	return nil
}

func initANReleaseNwSteps(sc *godog.ScenarioContext) {
	w := anW
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if w.api != nil {
			w.api.Close()
			w.api = nil
		}
		return ctx, nil
	})

	sc.Step(`^the AMF management API is running$`, w.mgmtRunning)
	sc.Step(`^an SMF mock records Nsmf UpdateSMContext requests$`, w.smfMockRecords)

	sc.Step(`^the UE is served by a connected gNB$`, w.servedByGNB)
	sc.Step(`^no gNB association exists for the UE$`, w.noGNBAssociation)
	sc.Step(`^a deregistration is pending for the UE$`, w.deregistrationPending)
	sc.Step(`^the UE completed registration with a Registration Complete$`, w.registrationComplete)

	sc.Step(`^O&M POSTs an AN release for SUPI "([^"]+)"$`, w.postRelease)
	sc.Step(`^O&M sends an HTTP (\w+) to the AN release path of SUPI "([^"]+)"$`, w.methodRelease)
	sc.Step(`^O&M requests the UE snapshot for SUPI "([^"]+)"$`, w.requestSnapshot)
	sc.Step(`^the gNB answers with a UE CONTEXT RELEASE COMPLETE for the UE$`, w.gnbAnswersReleaseComplete)

	sc.Step(`^the AN release response has accepted true and previous_cm_state "([^"]+)"$`, w.acceptedTrueAndPrevState)
	sc.Step(`^the AN release response lists affected_pdu_sessions as the JSON numbers (\d+)$`, w.affectedPDUSessions)
	sc.Step(`^the AN release response carries a non-empty spec_ref$`, w.specRefNonEmpty)
	sc.Step(`^the AMF sends a UE CONTEXT RELEASE COMMAND to the serving gNB with procedure code (\d+)$`, w.sendsCommandProcCode)
	sc.Step(`^the UE CONTEXT RELEASE COMMAND carries the UE NGAP ID pair of the UE followed by Cause misc "([^"]+)" \((\d+)\)$`, w.commandCarriesPairAndCause)
	sc.Step(`^the UE CONTEXT RELEASE COMMAND is sent with SCTP PPID (\d+)$`, w.commandPPID)
	sc.Step(`^the UE is not marked for removal$`, w.notMarkedForRemoval)
	sc.Step(`^the UE becomes CM-IDLE within the test deadline$`, w.becomesCMIdle)
	sc.Step(`^the UE context is still present and RM-REGISTERED$`, w.contextPresentRegistered)
	sc.Step(`^the UE is still CM-CONNECTED$`, func() error { return w.stillCM(amfctx.CMConnected) })
	sc.Step(`^the UE is still CM-IDLE$`, func() error { return w.stillCM(amfctx.CMIdle) })
	sc.Step(`^the AMF sends no UE CONTEXT RELEASE COMMAND$`, w.noCommand)
	sc.Step(`^the AMF sends no upCnxState "([^"]+)" request to the SMF$`, w.noDeactivatedRequest)
	sc.Step(`^the response Allow header is "([^"]+)"$`, w.allowHeader)
	sc.Step(`^the UE snapshot registration_time is not the zero time$`, w.snapshotRegistrationTime)
	sc.Step(`^the UE snapshot pdu_session_ids is a JSON array of numbers equal to (\d+)$`, w.snapshotPDUSessionIDs)
}
