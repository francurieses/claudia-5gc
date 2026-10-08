//go:build functional

// network_triggered_sr_steps_test.go -- in-process godog steps for the paged
// Service Request scenarios of network_triggered_service_request.feature
// (TS 23.502 §4.2.3.3 step 6 -> §4.2.3.2 steps 4/12; TS 24.501 §5.6.1.4.1).
//
// The real nasmsg.Handler.HandleNASMessage is driven with a hand-encoded,
// NIA2 integrity-protected Service Request (SHT=0x01). The paged PDU session
// set is populated by the real namf-comm N1N2MessageTransfer server (sbiW).
// The SMF is an httptest server speaking the Nsmf_PDUSession_UpdateSMContext
// wire contract used by the AMF's HTTPSMFClient.ActivateSMContext; the N2
// sender is an in-memory fake that records the InitialContextSetupRequest.
// The live scenario (@e2e) is covered by the shared pendingIfNoE2E steps.
package features_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// ntsrSender fakes the AMF N2/SMF sender: it records the ICS Request and
// performs ActivateSMContext against the httptest SMF over HTTP.
type ntsrSender struct {
	w *ntsrWorld
}

func (s *ntsrSender) SendDownlinkNASTransport(*amfctx.UEContext, []byte) error { return nil }
func (s *ntsrSender) SendPDUSessionResourceSetupRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (s *ntsrSender) SendPDUSessionResourceReleaseCommand(*amfctx.UEContext, uint8, []byte) error {
	return nil
}
func (s *ntsrSender) SendPDUSessionResourceModifyRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (s *ntsrSender) SendUEContextReleaseCommandForUE(*amfctx.UEContext, int, int64) error {
	return nil
}

func (s *ntsrSender) SendInitialContextSetupRequest(_ *amfctx.UEContext, nasPDU []byte,
	_ [32]byte, _, _ byte, _, _ uint16, pduSessions []ngap.PDUSessionSetupItemCxtReq) error {
	s.w.icsCount++
	s.w.icsNAS = nasPDU
	s.w.icsItems = pduSessions
	return nil
}

// DeleteSMContext mirrors cmd/amf HTTPSMFClient.DeleteSMContext (SM context
// release, TS 29.502 §5.2.2.4) against the in-process SMF.
func (s *ntsrSender) DeleteSMContext(ctx context.Context, ref string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
		s.w.smf.URL+"/nsmf-pdusession/v1/sm-contexts/"+ref, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("smf: delete sm context: status %d", resp.StatusCode)
	}
	return nil
}

// ActivateSMContext mirrors cmd/amf HTTPSMFClient.ActivateSMContext
// (TS 29.502 §5.2.2.3.2.2) against the in-process SMF.
func (s *ntsrSender) ActivateSMContext(ctx context.Context, ref string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"upCnxState": "ACTIVATING"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		s.w.smf.URL+"/nsmf-pdusession/v1/sm-contexts/"+ref+"/modify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("smf: activate sm context: status %d", resp.StatusCode)
	}
	var out struct {
		N2SmInfo string `json:"n2SmInfo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(out.N2SmInfo)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("smf: empty or invalid n2SmInfo")
	}
	return b, nil
}

type ntsrWorld struct {
	// active is set once a Service Request has been driven in-process; it lets
	// the ICS assertion steps shared with service_request.feature (E2E-gated)
	// tell the two apart.
	active bool

	smf      *httptest.Server
	mu       sync.Mutex
	n2sm     map[string][]byte // smContextRef -> N2SM to return
	failRef  map[string]bool
	requests map[string][]string // smContextRef -> upCnxState values received
	released []string            // smContextRefs released (DELETE sm-contexts/{ref})
	relCh    chan string         // signalled on every SM context release

	logs *bytes.Buffer

	srErr    error
	icsCount int
	icsNAS   []byte
	icsItems []ngap.PDUSessionSetupItemCxtReq
	preDL    uint32
}

var ntsrW = &ntsrWorld{}

func (w *ntsrWorld) reset() {
	if w.smf != nil {
		w.smf.Close()
	}
	w.active = false
	w.n2sm = map[string][]byte{}
	w.failRef = map[string]bool{}
	w.requests = map[string][]string{}
	w.released = nil
	w.relCh = make(chan string, 16)
	w.logs = &bytes.Buffer{}
	w.srErr, w.icsCount, w.icsNAS, w.icsItems, w.preDL = nil, 0, nil, nil, 0
	w.smf = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// /nsmf-pdusession/v1/sm-contexts/{ref}/modify
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		// SM context release: DELETE /nsmf-pdusession/v1/sm-contexts/{ref}
		// (the AMF HTTPSMFClient.DeleteSMContext wire contract).
		if r.Method == http.MethodDelete && len(parts) == 4 && parts[2] == "sm-contexts" {
			w.mu.Lock()
			w.released = append(w.released, parts[3])
			w.mu.Unlock()
			w.relCh <- parts[3]
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		if len(parts) != 5 || parts[4] != "modify" {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		ref := parts[3]
		var body struct {
			UpCnxState string `json:"upCnxState"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.mu.Lock()
		w.requests[ref] = append(w.requests[ref], body.UpCnxState)
		fail := w.failRef[ref]
		n2 := w.n2sm[ref]
		w.mu.Unlock()
		if fail || len(n2) == 0 {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]string{"n2SmInfo": base64.StdEncoding.EncodeToString(n2)})
	}))
}

func ntsrRef(psi int) string { return fmt.Sprintf("smf-ctx-ref-%d", psi) }

// ---- Given ----------------------------------------------------------------

func (w *ntsrWorld) smfReturnsN2SM(psi int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.n2sm[ntsrRef(psi)] = []byte{0xA0, byte(psi), 0x01}
	return nil
}

func (w *ntsrWorld) smfFails(psi int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.failRef[ntsrRef(psi)] = true
	return nil
}

func (w *ntsrWorld) pduSessionReleased(psi int) error {
	ue := sbiW.ue
	ue.Lock()
	defer ue.Unlock()
	if _, ok := ue.PDUSessions[uint8(psi)]; !ok {
		return fmt.Errorf("PDU session %d not in UE context", psi)
	}
	delete(ue.PDUSessions, uint8(psi))
	return nil
}

func (w *ntsrWorld) nothingPaged() error {
	if p := sbiW.ue.PagedPDUSessions(); len(p) != 0 {
		return fmt.Errorf("expected no paged PDU sessions, have %v", p)
	}
	return nil
}

// ---- When -----------------------------------------------------------------

var ntsrServiceTypes = map[string]byte{
	"signalling":                 nas.ServiceTypeSignalling,
	"data":                       nas.ServiceTypeData,
	"mobile terminated services": nas.ServiceTypeMobileTerminated,
}

// buildServiceRequest encodes a plain Service Request (TS 24.501 §8.2.16):
// ngKSI|service type, 5G-S-TMSI (LV-E), optional Uplink data status (IEI 0x40).
func buildServiceRequest(svcType byte, tmsi uint32, uplinkPSIs []uint8) []byte {
	pdu := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeServiceRequest), svcType << 4}
	pdu = append(pdu, 0x00, 0x07, 0xF4, 0x00, 0x41,
		byte(tmsi>>24), byte(tmsi>>16), byte(tmsi>>8), byte(tmsi))
	if len(uplinkPSIs) > 0 {
		var m uint16
		for _, p := range uplinkPSIs {
			m |= 1 << (8 + p)
		}
		pdu = append(pdu, 0x40, 0x02, byte(m>>8), byte(m))
	}
	return pdu
}

// protectUL wraps inner with integrity protection (SHT=0x01): MAC over
// SQN||inner with NIA2, COUNT=UplinkCount, BEARER=1, DIR=0 (TS 33.501 §D.3).
func protectUL(ue *amfctx.UEContext, inner []byte) ([]byte, error) {
	count := ue.SecurityCtx.UplinkCount
	sqn := byte(count & 0xFF)
	mac, err := nia.NIA2(ue.SecurityCtx.KNASint, count, 0x01, 0x00, append([]byte{sqn}, inner...))
	if err != nil {
		return nil, err
	}
	pdu := []byte{nas.PDMobilityManagement, byte(nas.SecurityHeaderIntegrityProtected)}
	pdu = append(pdu, mac...)
	pdu = append(pdu, sqn)
	return append(pdu, inner...), nil
}

func (w *ntsrWorld) sendServiceRequest(svcName string, ulds []uint8) error {
	st, ok := ntsrServiceTypes[svcName]
	if !ok {
		return fmt.Errorf("unknown service type %q", svcName)
	}
	ue := sbiW.ue
	if ue == nil || ue.GUTI == nil {
		return fmt.Errorf("UE not seeded with a GUTI")
	}
	return w.sendRawServiceRequest(buildServiceRequest(st, ue.GUTI.TMSI, ulds))
}

// sendRawServiceRequest integrity-protects a plain Service Request and drives
// it through the real NAS handler.
func (w *ntsrWorld) sendRawServiceRequest(plain []byte) error {
	ue := sbiW.ue
	if ue == nil || ue.GUTI == nil {
		return fmt.Errorf("UE not seeded with a GUTI")
	}
	ue.SecurityCtx.KNASint = bytes.Repeat([]byte{0x11}, 16)
	ue.SecurityCtx.KNASenc = bytes.Repeat([]byte{0x22}, 16)
	ue.UESecCapEA[2], ue.UESecCapIA[2] = true, true
	w.preDL = ue.SecurityCtx.DownlinkCount

	pdu, err := protectUL(ue, plain)
	if err != nil {
		return err
	}
	h := nasmsg.NewHandler(&ntsrSender{w: w}, nil, slog.New(slog.NewJSONHandler(w.logs, nil)))
	w.active = true
	w.srErr = h.HandleNASMessage(context.Background(), ue, pdu)
	return nil
}

func (w *ntsrWorld) srNoULDS(svc string) error { return w.sendServiceRequest(svc, nil) }

func (w *ntsrWorld) srULDS(svc string, a, b int) error {
	return w.sendServiceRequest(svc, []uint8{uint8(a), uint8(b)})
}

// ---- Then -----------------------------------------------------------------

func (w *ntsrWorld) requireSR() error {
	if !w.active {
		return fmt.Errorf("no Service Request was driven in this scenario")
	}
	if w.srErr != nil {
		return fmt.Errorf("Service Request handling failed: %w", w.srErr)
	}
	if bytes.Contains(w.logs.Bytes(), []byte("NAS MAC mismatch")) ||
		bytes.Contains(w.logs.Bytes(), []byte("NAS MAC verification error")) {
		return fmt.Errorf("uplink Service Request failed NIA2 verification: %s", w.logs.String())
	}
	return nil
}

func (w *ntsrWorld) requestCount(psi int, state string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, s := range w.requests[ntsrRef(psi)] {
		if s == state {
			n++
		}
	}
	return n
}

func (w *ntsrWorld) smfRequestedExactlyOnce(state string, psi int) error {
	if err := w.requireSR(); err != nil {
		return err
	}
	if n := w.requestCount(psi, state); n != 1 {
		return fmt.Errorf("SMF received %d upCnxState=%s requests for PDU session %d, want exactly 1 (all: %v)",
			n, state, psi, w.requests)
	}
	return nil
}

func (w *ntsrWorld) noActivationRequest(psi int) error {
	if err := w.requireSR(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if got := w.requests[ntsrRef(psi)]; len(got) != 0 {
		return fmt.Errorf("SMF received unexpected requests for PDU session %d: %v", psi, got)
	}
	return nil
}

// icsCarries asserts the PDUSessionResourceSetupListCxtReq of the recorded ICS
// Request equals the comma-separated PSI list (empty = no list). Items must be
// ascending and carry the N2SM transfer the SMF returned.
func (w *ntsrWorld) icsCarries(psis string) error {
	if err := w.requireSR(); err != nil {
		return err
	}
	if w.icsCount != 1 {
		return fmt.Errorf("InitialContextSetupRequest sent %d times, want 1", w.icsCount)
	}
	var want []uint8
	for _, f := range strings.Split(psis, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			return err
		}
		want = append(want, uint8(n))
	}
	var got []uint8
	for _, it := range w.icsItems {
		got = append(got, it.PDUSessionID)
		w.mu.Lock()
		exp := w.n2sm[ntsrRef(int(it.PDUSessionID))]
		w.mu.Unlock()
		if !bytes.Equal(it.Transfer, exp) {
			return fmt.Errorf("PDU session %d transfer = %x, want SMF-provided %x", it.PDUSessionID, it.Transfer, exp)
		}
	}
	if len(got) != len(want) {
		return fmt.Errorf("ICS PDUSessionResourceSetupListCxtReq PSIs = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			return fmt.Errorf("ICS PDUSessionResourceSetupListCxtReq PSIs = %v, want %v", got, want)
		}
	}
	return nil
}

func (w *ntsrWorld) serviceAccept() error {
	if err := w.requireSR(); err != nil {
		return err
	}
	if w.icsCount != 1 || len(w.icsNAS) < 8 {
		return fmt.Errorf("no Service Accept NAS-PDU in ICS Request (ics=%d len=%d)", w.icsCount, len(w.icsNAS))
	}
	pdu := w.icsNAS
	if pdu[1] != byte(nas.SecurityHeaderIntegrityProtectedAndCiphered) {
		return fmt.Errorf("Service Accept SHT = %#x, want 0x02", pdu[1])
	}
	ue := sbiW.ue
	count := w.preDL // DL COUNT consumed by the Service Accept
	if ue.SecurityCtx.DownlinkCount != count+1 {
		return fmt.Errorf("DL COUNT advanced %d -> %d, want exactly one NAS message", count, ue.SecurityCtx.DownlinkCount)
	}
	ok, err := nia.Verify(ue.SecurityCtx.KNASint, count, 0x01, 0x01, pdu[6:], pdu[2:6])
	if err != nil || !ok {
		return fmt.Errorf("Service Accept NIA2 MAC invalid (ok=%v err=%v)", ok, err)
	}
	inner, err := nea.NEA2(ue.SecurityCtx.KNASenc, count, 0x01, 0x01, pdu[7:])
	if err != nil {
		return err
	}
	if len(inner) < 3 || inner[0] != nas.PDMobilityManagement || nas.MessageType(inner[2]) != nas.MsgTypeServiceAccept {
		return fmt.Errorf("inner NAS message = %x, want Service Accept (0x4E)", inner)
	}
	return nil
}

func (w *ntsrWorld) noPagedPending() error {
	if p := sbiW.ue.PagedPDUSessions(); len(p) != 0 {
		return fmt.Errorf("paged PDU sessions still pending after Service Request: %v", p)
	}
	return nil
}

func initNTSRSteps(sc *godog.ScenarioContext) {
	w := ntsrW
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, err error) (context.Context, error) {
		if w.smf != nil {
			w.smf.Close()
			w.smf = nil
		}
		return ctx, nil
	})

	sc.Step(`^the SMF will return an N2SM PDUSessionResourceSetupRequestTransfer for PDU session (\d+) on activation$`, w.smfReturnsN2SM)
	sc.Step(`^the SMF will fail the activation of PDU session (\d+)$`, w.smfFails)
	sc.Step(`^PDU session (\d+) is released from the UE context before the Service Request$`, w.pduSessionReleased)
	sc.Step(`^no PDU session is pending as paged for the UE$`, w.nothingPaged)

	sc.Step(`^the UE sends a Service Request with service type "([^"]+)" and no Uplink Data Status$`, w.srNoULDS)
	sc.Step(`^the UE sends a Service Request with service type "([^"]+)" and Uplink Data Status flagging PDU sessions (\d+) and (\d+)$`, w.srULDS)

	sc.Step(`^the AMF requests upCnxState "([^"]+)" from the SMF for PDU session (\d+) exactly once$`, w.smfRequestedExactlyOnce)
	sc.Step(`^the AMF sends no activation request to the SMF for PDU session (\d+)$`, w.noActivationRequest)
	sc.Step(`^the InitialContextSetupRequest carries PDU sessions ([\d,]+) in ascending order in the PDUSessionResourceSetupListCxtReq$`, w.icsCarries)
	sc.Step(`^the AMF sends a Service Accept$`, w.serviceAccept)
	sc.Step(`^the UE has no paged PDU sessions pending$`, w.noPagedPending)

	// @e2e scenario: live UERANSIM stack only (pending unless E2E_TEST=1).
	// Validated by docs/validation-commands.md §15 (CN Paging recipe).
	sc.Step(`^the SMF triggers a dl-data-notification for PDU session (\d+)$`,
		func(int) error { return pendingIfNoE2E() })
	sc.Step(`^the UE logs "([^"]+)" and sends a Service Request due to IDLE-PAGING$`,
		func(string) error { return pendingIfNoE2E() })
}
