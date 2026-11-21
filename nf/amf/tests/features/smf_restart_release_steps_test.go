//go:build functional

// smf_restart_release_steps_test.go -- in-process godog steps for
// smf_restart_release.feature (SMF-012): O&M release of PDU sessions orphaned
// by an SMF restart with 5GSM cause #39 "reactivation requested".
// Ref: TS 23.502 §4.3.4.2; TS 24.501 §6.3.3.2, §6.3.3.3, §5.6.1.4; TS 38.413 §8.4.2;
// docs/procedures/SmfRestartRecovery.md §4.1, §4.4, §5, §7.2, §8.2.
//
// The real mgmt route logic (mgmt.SplitPDUSessionPath + HandlePDUSessionRelease,
// wired exactly as cmd/amf does) runs behind an httptest server in front of a
// real nasmsg.Handler. The N2/N1 sender is an in-memory fake that records the
// ciphered DL NAS PDUs (MAC verified and deciphered by the assertions), the NGAP
// PDU Session Resource Release Commands and the ICS Request carrying the Service
// Accept; the SMF is an httptest server speaking the Nsmf SM-context contract
// (DELETE sm-contexts/{ref}, POST .../modify) with per-ref status overrides.
// The paging trigger is the shared sbiW pagingSpy. The shared Background / CM
// state / paging steps live in sbi_steps_test.go (sbiW holds the UE).
//
// Timing: no sleeps for ordering. Asynchronous work (serial queue, paging
// guard) is awaited by polling with a deadline or by a serial-queue barrier;
// the paging guard is shortened per scenario with SetReleaseGuardsForTest.
package features_test

import (
	"bytes"
	"context"
	"encoding/base64"
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

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/mgmt"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

const (
	// smrWait bounds every poll on asynchronous AMF work.
	smrWait = 5 * time.Second
	// smrPagingGuard is the shortened paging guard of the guard-expiry scenario.
	smrPagingGuard = 100 * time.Millisecond
	// smrLongGuard keeps the paging guard and T3592 out of the way elsewhere.
	smrLongGuard = 10 * time.Minute
	// cause5GSMReactivationRequested is 5GSM cause #39 (TS 24.501 Table 9.11.4.2.1).
	smrCause39Octet = 0x27
)

// smrDL is one recorded DL NAS PDU: bytes, the DL COUNT it was sent with and a
// global send sequence number (orders it against the ICS carrying the Accept).
type smrDL struct {
	pdu   []byte
	count uint32
	seq   int
}

type smrNGAPRel struct {
	psi uint8
	smrDL
}

// smrSender fakes the N1/N2 sender and the Nsmf client of the AMF.
type smrSender struct {
	ntsrSender // unused no-op N2 methods
	w          *smrWorld
}

func (s *smrSender) stamp(ue *amfctx.UEContext, pdu []byte) smrDL {
	ue.Lock()
	count := ue.SecurityCtx.DownlinkCount - 1 // already advanced by sendNASSecured
	ue.Unlock()
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	s.w.seq++
	return smrDL{pdu: append([]byte(nil), pdu...), count: count, seq: s.w.seq}
}

func (s *smrSender) SendDownlinkNASTransport(ue *amfctx.UEContext, pdu []byte) error {
	d := s.stamp(ue, pdu)
	s.w.mu.Lock()
	s.w.dl = append(s.w.dl, d)
	s.w.mu.Unlock()
	return nil
}

func (s *smrSender) SendPDUSessionResourceReleaseCommand(ue *amfctx.UEContext, psi uint8, pdu []byte) error {
	d := s.stamp(ue, pdu)
	s.w.mu.Lock()
	s.w.ngapRel = append(s.w.ngapRel, smrNGAPRel{psi: psi, smrDL: d})
	s.w.mu.Unlock()
	return nil
}

func (s *smrSender) SendInitialContextSetupRequest(ue *amfctx.UEContext, pdu []byte,
	_ [32]byte, _, _ byte, _, _ uint16, _ []ngap.PDUSessionSetupItemCxtReq) error {
	d := s.stamp(ue, pdu)
	s.w.mu.Lock()
	s.w.ics = append(s.w.ics, d)
	s.w.mu.Unlock()
	return nil
}

// ActivateSMContext mirrors cmd/amf HTTPSMFClient.ActivateSMContext: 404 is
// wrapped in nasmsg.ErrSMContextNotFound (SMF restart orphan).
func (s *smrSender) ActivateSMContext(ctx context.Context, ref string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"upCnxState": "ACTIVATING"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		s.w.smfURL+"/nsmf-pdusession/v1/sm-contexts/"+ref+"/modify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("smf: activate sm context: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("smf: activate sm context: status %d: %w", resp.StatusCode, nasmsg.ErrSMContextNotFound)
	}
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

// DeleteSMContext mirrors cmd/amf HTTPSMFClient.DeleteSMContext.
func (s *smrSender) DeleteSMContext(ctx context.Context, ref string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
		s.w.smfURL+"/nsmf-pdusession/v1/sm-contexts/"+ref, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("smf: delete sm context: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("smf: delete sm context: status %d: %w", resp.StatusCode, nasmsg.ErrSMContextNotFound)
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("smf: delete sm context: status %d", resp.StatusCode)
	}
	return nil
}

type smrWorld struct {
	// active is set by the Background step; it makes the shared steps
	// ("the AMF sends a Service Accept", "the SMF is not reachable") delegate here.
	active   bool
	scenario string

	mu      sync.Mutex
	seq     int
	dl      []smrDL
	ics     []smrDL
	ngapRel []smrNGAPRel

	smf        *httptest.Server
	smfURL     string
	relStatus  map[string]int      // ref -> status of DELETE sm-contexts/{ref}
	modStatus  map[string]int      // ref -> status of POST .../modify
	deletes    []string            // refs DELETEd
	activation map[string][]string // ref -> upCnxState values received

	mgmtTS   *httptest.Server
	handler  *nasmsg.Handler
	logs     *tcLockedBuf
	statuses []int
	srErr    error
	srDone   bool
	preDL    uint32
}

var smrW = &smrWorld{}

func (w *smrWorld) reset(scenario string) {
	w.closeServers()
	w.active, w.scenario = false, scenario
	w.seq, w.dl, w.ics, w.ngapRel = 0, nil, nil, nil
	w.relStatus, w.modStatus = map[string]int{}, map[string]int{}
	w.deletes, w.activation = nil, map[string][]string{}
	w.handler, w.logs = nil, &tcLockedBuf{}
	w.statuses, w.srErr, w.srDone, w.preDL = nil, nil, false, 0
	w.smf = httptest.NewServer(http.HandlerFunc(w.serveSMF))
	w.smfURL = w.smf.URL
}

func (w *smrWorld) closeServers() {
	if w.mgmtTS != nil {
		w.mgmtTS.Close()
		w.mgmtTS = nil
	}
	if w.smf != nil {
		w.smf.Close()
		w.smf = nil
	}
}

func (w *smrWorld) serveSMF(rw http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// /nsmf-pdusession/v1/sm-contexts/{ref}[/modify]
	if len(parts) < 4 || parts[2] != "sm-contexts" {
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	ref := parts[3]
	switch {
	case r.Method == http.MethodDelete && len(parts) == 4:
		w.mu.Lock()
		w.deletes = append(w.deletes, ref)
		st := w.relStatus[ref]
		w.mu.Unlock()
		if st == 0 {
			st = http.StatusNoContent
		}
		rw.WriteHeader(st)
	case r.Method == http.MethodPost && len(parts) == 5 && parts[4] == "modify":
		var body struct {
			UpCnxState string `json:"upCnxState"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.mu.Lock()
		w.activation[ref] = append(w.activation[ref], body.UpCnxState)
		st := w.modStatus[ref]
		w.mu.Unlock()
		if st == 0 || st == http.StatusOK {
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]string{
				"n2SmInfo": base64.StdEncoding.EncodeToString([]byte{0xA0, 0x01, 0x01})})
			return
		}
		rw.Header().Set("Content-Type", "application/problem+json")
		rw.WriteHeader(st)
		_, _ = io.WriteString(rw, `{"cause":"CONTEXT_NOT_FOUND"}`)
	default:
		rw.WriteHeader(http.StatusNotFound)
	}
}

// prepareUE completes the sbiW UE into a UE with an active NAS security
// context that the real handler can protect/verify for (idempotent).
func (w *smrWorld) prepareUE() (*amfctx.UEContext, error) {
	ue := sbiW.ue
	if ue == nil {
		return nil, fmt.Errorf("no UE seeded")
	}
	ue.Lock()
	ue.SecurityCtx.KNASint = bytes.Repeat([]byte{0x11}, 16)
	ue.SecurityCtx.KNASenc = bytes.Repeat([]byte{0x22}, 16)
	ue.UESecCapEA[2], ue.UESecCapIA[2] = true, true
	if len(ue.AllowedNSSAI) == 0 {
		ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	}
	ue.Unlock()
	ue.TransitionTo(amfctx.GMMRegistered)
	return ue, nil
}

// ---- Given ----------------------------------------------------------------

func (w *smrWorld) mgmtRunning() error {
	w.active = true
	logger := slog.New(slog.NewJSONHandler(w.logs, nil))
	reg := procedures.NewRegistrationHandler(sbiW.mgr, nil, nil, nil, "nf", "001", "01", logger)
	w.handler = nasmsg.NewHandler(&smrSender{w: w}, reg, logger)
	w.handler.SetPager(sbiW.pgr)
	paging := smrLongGuard
	if strings.Contains(w.scenario, "paging guard") {
		paging = smrPagingGuard
	}
	w.handler.SetReleaseGuardsForTest(paging, smrLongGuard)

	mux := http.NewServeMux()
	// Same routing as cmd/amf: /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}[?cause=].
	mux.HandleFunc("/amf/v1/ue-contexts/", func(rw http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/amf/v1/ue-contexts/"):]
		if r.Method != http.MethodDelete {
			http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		supi, psiText, ok := mgmt.SplitPDUSessionPath(path)
		if !ok {
			http.Error(rw, "not a pdu-sessions path", http.StatusNotFound)
			return
		}
		mgmt.HandlePDUSessionRelease(rw, r, sbiW.mgr, w.handler, supi, psiText, logger)
	})
	w.mgmtTS = httptest.NewServer(mux)
	return nil
}

func (w *smrWorld) smfAnswersRelease(psi, status int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.relStatus[ntsrRef(psi)] = status
	return nil
}

func (w *smrWorld) smfAnswersActivation404(psi int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.modStatus[ntsrRef(psi)] = http.StatusNotFound
	return nil
}

// smfDown shuts the SMF down (connection refused afterwards). Called through
// ngrWorld.smfUnreachable, which owns the shared step text.
func (w *smrWorld) smfDown() error {
	if w.smf == nil {
		return fmt.Errorf("SMF mock not running")
	}
	w.smf.Close()
	return nil
}

// ---- When: mgmt DELETE ----------------------------------------------------

func (w *smrWorld) deleteReq(supi string, psi int, query string) error {
	if _, err := w.prepareUE(); err != nil {
		return err
	}
	if w.mgmtTS == nil {
		return fmt.Errorf("mgmt server not running")
	}
	url := fmt.Sprintf("%s/amf/v1/ue-contexts/%s/pdu-sessions/%d%s", w.mgmtTS.URL, supi, psi, query)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := w.mgmtTS.Client().Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	w.statuses = append(w.statuses, resp.StatusCode)
	return nil
}

func (w *smrWorld) deleteWithCause(psi, cause int) error {
	return w.deleteReq(sbiW.ue.SUPI, psi, fmt.Sprintf("?cause=%d", cause))
}

func (w *smrWorld) deleteWithoutCause(psi int) error {
	return w.deleteReq(sbiW.ue.SUPI, psi, "")
}

func (w *smrWorld) deleteUnknownUE(supi string, psi, cause int) error {
	return w.deleteReq(supi, psi, fmt.Sprintf("?cause=%d", cause))
}

// ---- When: UE uplink ------------------------------------------------------

// sendUL integrity-protects a plain UL NAS message and drives the real handler.
func (w *smrWorld) sendUL(plain []byte) error {
	ue, err := w.prepareUE()
	if err != nil {
		return err
	}
	ue.Lock()
	w.preDL = ue.SecurityCtx.DownlinkCount
	ue.Unlock()
	pdu, err := protectUL(ue, plain)
	if err != nil {
		return err
	}
	w.srErr = w.handler.HandleNASMessage(context.Background(), ue, pdu)
	w.srDone = true
	return nil
}

func (w *smrWorld) serviceRequest(svc byte, ulds []uint8) error {
	ue := sbiW.ue
	if ue == nil || ue.GUTI == nil {
		return fmt.Errorf("UE not seeded with a GUTI")
	}
	return w.sendUL(buildServiceRequest(svc, ue.GUTI.TMSI, ulds))
}

func (w *smrWorld) srMTWithULDS(svc string, psi int) error {
	st, ok := ntsrServiceTypes[svc]
	if !ok {
		return fmt.Errorf("unknown service type %q", svc)
	}
	return w.serviceRequest(st, []uint8{uint8(psi)})
}

func (w *smrWorld) srDataWithULDS(psi int) error {
	return w.serviceRequest(nas.ServiceTypeData, []uint8{uint8(psi)})
}

// releaseComplete sends UL NAS Transport carrying the 5GSM PDU SESSION RELEASE
// COMPLETE (TS 24.501 §8.3.10) for psi.
func (w *smrWorld) releaseComplete(psi int) error {
	id := uint8(psi)
	body, err := nas.EncodeULNASTransport(&nas.ULNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     []byte{0x2E, id, 0x00, byte(nas.MsgTypePDUSessionReleaseComplete)},
		PDUSessionID:         &id,
	})
	if err != nil {
		return err
	}
	plain := append([]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeULNASTransport)}, body...)
	if err := w.sendUL(plain); err != nil {
		return err
	}
	if w.srErr != nil {
		return fmt.Errorf("UL NAS Transport (Release Complete) failed: %w", w.srErr)
	}
	return nil
}

func (w *smrWorld) gnbResponseThenComplete() error {
	// TS 23.502 §4.3.4.2: the SM context is released only after the UE's
	// Release Complete, never alongside the Release Command.
	w.mu.Lock()
	n := len(w.deletes)
	w.mu.Unlock()
	if n != 0 {
		return fmt.Errorf("SM context released at the SMF before the PDU SESSION RELEASE COMPLETE: %v", w.deletes)
	}
	// The PDU Session Resource Release Response is a gNB -> AMF NGAP message
	// with no AMF-side effect on the PSI in this procedure.
	return w.releaseComplete(1)
}

func (w *smrWorld) ueSendsReleaseComplete(psi int) error { return w.releaseComplete(psi) }

func (w *smrWorld) pagingGuardExpires() error {
	return w.waitFor("PDU session 1 released after the paging guard", func() bool { return !hasSession(1) })
}

// ---- helpers --------------------------------------------------------------

func hasSession(psi uint8) bool {
	ue := sbiW.ue
	ue.Lock()
	defer ue.Unlock()
	_, ok := ue.PDUSessions[psi]
	return ok
}

func (w *smrWorld) waitFor(what string, cond func() bool) error {
	deadline := time.Now().Add(smrWait)
	for !cond() {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s", smrWait, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// drainSerial returns once everything queued on the UE serial queue before the
// call has run (FIFO barrier), so absence assertions are not vacuous.
func (w *smrWorld) drainSerial() error {
	done := make(chan struct{})
	sbiW.ue.EnqueueSerial(func() { close(done) })
	select {
	case <-done:
		return nil
	case <-time.After(smrWait):
		return fmt.Errorf("UE serial queue did not drain within %s", smrWait)
	}
}

func (w *smrWorld) snapshot() (dl, ics []smrDL, rel []smrNGAPRel) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]smrDL(nil), w.dl...), append([]smrDL(nil), w.ics...),
		append([]smrNGAPRel(nil), w.ngapRel...)
}

// deciphered verifies SHT 0x02, the NIA2 MAC and deciphers a DL PDU (NEA2).
func deciphered(ue *amfctx.UEContext, d smrDL) ([]byte, error) {
	pdu := d.pdu
	if len(pdu) < 8 || pdu[0] != nas.PDMobilityManagement {
		return nil, fmt.Errorf("DL PDU too short or not 5GMM: %x", pdu)
	}
	if pdu[1] != byte(nas.SecurityHeaderIntegrityProtectedAndCiphered) {
		return nil, fmt.Errorf("DL NAS SHT = %#x, want 0x02 (integrity protected and ciphered)", pdu[1])
	}
	ok, err := nia.Verify(ue.SecurityCtx.KNASint, d.count, 0x01, 0x01, pdu[6:], pdu[2:6])
	if err != nil || !ok {
		return nil, fmt.Errorf("DL NAS NIA2 MAC invalid (ok=%v err=%v)", ok, err)
	}
	return nea.NEA2(ue.SecurityCtx.KNASenc, d.count, 0x01, 0x01, pdu[7:])
}

// releaseCommandOf asserts d is a ciphered DL NAS Transport carrying the
// 5GSM PDU SESSION RELEASE COMMAND for psi with the given cause octet:
// payload 2E psi PTI=0 D3 cause (cause as value octet, no IEI), PDU session ID IE.
func releaseCommandOf(d smrDL, psi, cause uint8) error {
	inner, err := deciphered(sbiW.ue, d)
	if err != nil {
		return err
	}
	if len(inner) < 6 || inner[2] != byte(nas.MsgTypeDLNASTransport) {
		return fmt.Errorf("inner NAS = %x, want DL NAS TRANSPORT (0x68)", inner)
	}
	if inner[3]&0x0F != nas.PayloadContainerTypeN1SM {
		return fmt.Errorf("payload container type = %#x, want N1 SM information (0x01)", inner[3]&0x0F)
	}
	n := int(inner[4])<<8 | int(inner[5])
	if len(inner) < 6+n {
		return fmt.Errorf("truncated payload container in %x", inner)
	}
	want := []byte{0x2E, psi, 0x00, byte(nas.MsgTypePDUSessionReleaseCommand), cause}
	if got := inner[6 : 6+n]; !bytes.Equal(got, want) {
		return fmt.Errorf("5GSM payload = %x, want PDU SESSION RELEASE COMMAND %x (PTI 0, 5GSM cause %#x)", got, want, cause)
	}
	rest := inner[6+n:]
	if len(rest) < 2 || rest[0] != nas.IEIPDUSessionID || rest[1] != psi {
		return fmt.Errorf("DL NAS Transport PDU session ID IE = %x, want 12 %02x", rest, psi)
	}
	return nil
}

// ---- Then: mgmt response --------------------------------------------------

func (w *smrWorld) statusIs(code int) error {
	if len(w.statuses) == 0 {
		return fmt.Errorf("no mgmt DELETE was sent")
	}
	if got := w.statuses[len(w.statuses)-1]; got != code {
		return fmt.Errorf("mgmt response status = %d, want %d (all: %v)", got, code, w.statuses)
	}
	return nil
}

// ---- Then: NGAP / NAS -----------------------------------------------------

func (w *smrWorld) ngapReleaseSent(psi int) error {
	_, _, rel := w.snapshot()
	if len(rel) != 1 || rel[0].psi != uint8(psi) {
		return fmt.Errorf("NGAP PDU Session Resource Release Commands = %v, want exactly one for PDU session %d", relPSIs(rel), psi)
	}
	return nil
}

func relPSIs(rel []smrNGAPRel) []uint8 {
	var out []uint8
	for _, r := range rel {
		out = append(out, r.psi)
	}
	return out
}

func (w *smrWorld) noNGAPRelease() error {
	if err := w.drainSerial(); err != nil {
		return err
	}
	if _, _, rel := w.snapshot(); len(rel) != 0 {
		return fmt.Errorf("unexpected NGAP PDU Session Resource Release Command(s) for PDU sessions %v", relPSIs(rel))
	}
	return nil
}

func (w *smrWorld) exactlyOneNGAPRelease(psi int) error { return w.ngapReleaseSent(psi) }

func (w *smrWorld) nasCarriesCause39() error {
	_, _, rel := w.snapshot()
	if len(rel) != 1 {
		return fmt.Errorf("want one NGAP release command, have %d", len(rel))
	}
	return releaseCommandOf(rel[0].smrDL, uint8(rel[0].psi), smrCause39Octet)
}

func (w *smrWorld) nasDeliveredCiphered(psi int) error {
	_, _, rel := w.snapshot()
	if len(rel) != 1 {
		return fmt.Errorf("want one NGAP release command, have %d", len(rel))
	}
	// releaseCommandOf checks SHT 0x02, MAC, DL NAS Transport type and PSI IE.
	return releaseCommandOf(rel[0].smrDL, uint8(psi), smrCause39Octet)
}

func (w *smrWorld) callsReleaseSMContext404Tolerated(psi int) error {
	ref := ntsrRef(psi)
	if err := w.waitFor("ReleaseSMContext for PDU session", func() bool { return w.deleteCount(ref) >= 1 }); err != nil {
		return err
	}
	if n := w.deleteCount(ref); n != 1 {
		return fmt.Errorf("SMF received %d ReleaseSMContext for %s, want exactly 1", n, ref)
	}
	if w.srErr != nil {
		return fmt.Errorf("Release Complete handling failed: %w", w.srErr)
	}
	// 404 tolerated: logged at INFO as already released, never WARN/ERROR.
	var info bool
	for _, line := range strings.Split(strings.TrimSpace(w.logs.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["cause"] == "ALREADY_RELEASED" && rec["level"] == "INFO" {
			info = true
		}
		if msg, _ := rec["msg"].(string); strings.Contains(msg, "DeleteSMContext failed") {
			return fmt.Errorf("SMF 404 not tolerated: %s", line)
		}
	}
	if !info {
		return fmt.Errorf("no INFO ALREADY_RELEASED record for the SMF 404 in the AMF log")
	}
	return nil
}

func (w *smrWorld) deleteCount(ref string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, d := range w.deletes {
		if d == ref {
			n++
		}
	}
	return n
}

func (w *smrWorld) sessionRemoved(psi int) error {
	if err := w.waitFor(fmt.Sprintf("PDU session %d removed from the UE context", psi),
		func() bool { return !hasSession(uint8(psi)) }); err != nil {
		return err
	}
	return sessionGone(psi)
}

func (w *smrWorld) sessionKept(psi int) error { return sessionStill(psi) }

// ---- Then: Service Request / Service Accept -------------------------------

func (w *smrWorld) requireSR() error {
	if !w.srDone {
		return fmt.Errorf("no Service Request was driven in this scenario")
	}
	if w.srErr != nil {
		return fmt.Errorf("Service Request handling failed: %w", w.srErr)
	}
	if s := w.logs.String(); strings.Contains(s, "NAS MAC mismatch") || strings.Contains(s, "NAS MAC verification error") {
		return fmt.Errorf("uplink NAS failed NIA2 verification: %s", s)
	}
	return nil
}

// serviceAccept is the body of the shared step "the AMF sends a Service Accept"
// for this feature: the Accept is the NAS-PDU of the single ICS Request,
// ciphered with the DL COUNT the UE context held before the Service Request.
func (w *smrWorld) serviceAccept() error {
	if err := w.requireSR(); err != nil {
		return err
	}
	_, ics, _ := w.snapshot()
	if len(ics) != 1 {
		return fmt.Errorf("InitialContextSetupRequest sent %d times, want 1 (carrying the Service Accept)", len(ics))
	}
	if ics[0].count != w.preDL {
		return fmt.Errorf("Service Accept DL COUNT = %d, want %d", ics[0].count, w.preDL)
	}
	inner, err := deciphered(sbiW.ue, ics[0])
	if err != nil {
		return err
	}
	if len(inner) < 3 || nas.MessageType(inner[2]) != nas.MsgTypeServiceAccept {
		return fmt.Errorf("inner NAS message = %x, want Service Accept (0x4E)", inner)
	}
	return nil
}

func (w *smrWorld) noActivatingRequest(psi int) error {
	if err := w.requireSR(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, st := range w.activation[ntsrRef(psi)] {
		if st == "ACTIVATING" {
			return fmt.Errorf("AMF requested upCnxState ACTIVATING for PDU session %d: %v", psi, w.activation[ntsrRef(psi)])
		}
	}
	return nil
}

func (w *smrWorld) afterAcceptReleaseCommand(psi int, cause string) error {
	if cause != "0x27" {
		return fmt.Errorf("unsupported cause literal %q", cause)
	}
	if err := w.waitFor("DL NAS Transport with PDU SESSION RELEASE COMMAND", func() bool {
		dl, _, _ := w.snapshot()
		return len(dl) >= 1
	}); err != nil {
		return err
	}
	dl, ics, _ := w.snapshot()
	if len(dl) != 1 || len(ics) != 1 {
		return fmt.Errorf("DL NAS Transports = %d, ICS = %d; want exactly one each", len(dl), len(ics))
	}
	if dl[0].seq <= ics[0].seq {
		return fmt.Errorf("Release Command (seq %d) was not sent after the Service Accept (seq %d)", dl[0].seq, ics[0].seq)
	}
	if dl[0].count != ics[0].count+1 {
		return fmt.Errorf("Release Command DL COUNT = %d, want Service Accept COUNT+1 = %d", dl[0].count, ics[0].count+1)
	}
	return releaseCommandOf(dl[0], uint8(psi), smrCause39Octet)
}

func (w *smrWorld) reportedNotReactivated(psi int) error {
	if err := w.serviceAccept(); err != nil {
		return err
	}
	_, ics, _ := w.snapshot()
	inner, err := deciphered(sbiW.ue, ics[0])
	if err != nil {
		return err
	}
	sa, err := nas.DecodeServiceAccept(inner[3:])
	if err != nil {
		return fmt.Errorf("decode Service Accept: %w", err)
	}
	if sa.PDUSessionReactivationResult == nil {
		return fmt.Errorf("Service Accept has no PDU session reactivation result IE (0x26)")
	}
	if got, want := *sa.PDUSessionReactivationResult, nas.PSIMask(uint8(psi)); got != want {
		return fmt.Errorf("PDU session reactivation result = %s, want %s", maskString(got), maskString(want))
	}
	return nil
}

func (w *smrWorld) startsReleaseCause39(psi int) error {
	// The release is started during the Service Request; its evidence is the
	// Release Command that follows the Accept (pending entry is consumed then).
	if err := w.waitFor("release of the orphaned PDU session to start", func() bool {
		dl, _, _ := w.snapshot()
		if len(dl) > 0 {
			return true
		}
		c, ok := sbiW.ue.PendingSMReleaseCause(uint8(psi))
		return ok && c == 39
	}); err != nil {
		return err
	}
	if c, ok := sbiW.ue.PendingSMReleaseCause(uint8(psi)); ok && c != 39 {
		return fmt.Errorf("pending release cause = %d, want 39", c)
	}
	return nil
}

func (w *smrWorld) deliveredCmd(psi int, cause string) error {
	if cause != "0x27" {
		return fmt.Errorf("unsupported cause literal %q", cause)
	}
	if err := w.waitFor("PDU SESSION RELEASE COMMAND delivery", func() bool {
		dl, _, _ := w.snapshot()
		return len(dl) >= 1
	}); err != nil {
		return err
	}
	dl, _, rel := w.snapshot()
	if len(dl) != 1 || len(rel) != 0 {
		return fmt.Errorf("DL NAS Transports = %d, NGAP release commands = %d; want 1 and 0", len(dl), len(rel))
	}
	return releaseCommandOf(dl[0], uint8(psi), smrCause39Octet)
}

func (w *smrWorld) startsNoRelease(psi int) error {
	if err := w.requireSR(); err != nil {
		return err
	}
	if err := w.drainSerial(); err != nil {
		return err
	}
	dl, _, rel := w.snapshot()
	if len(dl) != 0 || len(rel) != 0 {
		return fmt.Errorf("release started: DL NAS Transports=%d, NGAP release commands=%v", len(dl), relPSIs(rel))
	}
	if c, ok := sbiW.ue.PendingSMReleaseCause(uint8(psi)); ok {
		return fmt.Errorf("pending release recorded for PDU session %d (cause %d)", psi, c)
	}
	if n := w.deleteCount(ntsrRef(psi)); n != 0 {
		return fmt.Errorf("SM context of PDU session %d released at the SMF %d time(s)", psi, n)
	}
	return nil
}

func (w *smrWorld) noDLForPSI(psi int) error {
	if err := w.drainSerial(); err != nil {
		return err
	}
	if dl, _, _ := w.snapshot(); len(dl) != 0 {
		return fmt.Errorf("AMF sent %d DL NAS Transport(s) for PDU session %d, want none", len(dl), psi)
	}
	return nil
}

func initSMFRestartReleaseSteps(sc *godog.ScenarioContext) {
	w := smrW
	sc.Before(func(ctx context.Context, s *godog.Scenario) (context.Context, error) {
		w.reset(s.Name)
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if sbiW.ue != nil {
			sbiW.ue.StopPendingSMReleaseGuards()
		}
		w.active = false
		w.closeServers()
		return ctx, nil
	})

	sc.Step(`^the AMF mgmt server is running$`, w.mgmtRunning)
	sc.Step(`^the SMF answers ReleaseSMContext for PDU session (\d+) with (\d+)(?: "CONTEXT_NOT_FOUND")?$`, w.smfAnswersRelease)
	sc.Step(`^the SMF answers UpdateSMContext and ActivateSMContext for PDU session (\d+) with 404 "CONTEXT_NOT_FOUND"$`, w.smfAnswersActivation404)

	sc.Step(`^the SMF sends DELETE for PDU session (\d+) with cause (\d+)$`, w.deleteWithCause)
	sc.Step(`^the SMF sends DELETE for PDU session (\d+) with cause (\d+) again$`, w.deleteWithCause)
	sc.Step(`^the SMF sends DELETE for PDU session (\d+) without a cause$`, w.deleteWithoutCause)
	sc.Step(`^the SMF sends DELETE for unknown UE "([^"]+)" PDU session (\d+) with cause (\d+)$`, w.deleteUnknownUE)
	sc.Step(`^the mgmt response status is (\d+)$`, w.statusIs)

	sc.Step(`^the AMF sends an NGAP PDU Session Resource Release Command for PDU session (\d+)$`, w.ngapReleaseSent)
	sc.Step(`^the AMF sends no NGAP PDU Session Resource Release Command$`, w.noNGAPRelease)
	sc.Step(`^the AMF sent exactly one NGAP PDU Session Resource Release Command for PDU session (\d+)$`, w.exactlyOneNGAPRelease)
	sc.Step(`^the NAS PDU SESSION RELEASE COMMAND carries 5GSM cause 0x27 and PTI 0$`, w.nasCarriesCause39)
	sc.Step(`^the PDU SESSION RELEASE COMMAND is delivered in a ciphered DL NAS Transport with PDU session ID (\d+)$`, w.nasDeliveredCiphered)
	sc.Step(`^the gNB returns the PDU Session Resource Release Response and the UE sends a PDU SESSION RELEASE COMPLETE$`, w.gnbResponseThenComplete)
	sc.Step(`^the AMF calls ReleaseSMContext for PDU session (\d+) and the 404 is tolerated$`, w.callsReleaseSMContext404Tolerated)
	sc.Step(`^the UE sends a PDU SESSION RELEASE COMPLETE for PDU session (\d+)$`, w.ueSendsReleaseComplete)
	sc.Step(`^PDU session (\d+) is removed from the UE context$`, w.sessionRemoved)
	sc.Step(`^PDU session (\d+) is kept in the UE context$`, w.sessionKept)

	sc.Step(`^the UE answers with a Service Request with service type "([^"]+)" and Uplink Data Status for PDU session (\d+)$`, w.srMTWithULDS)
	sc.Step(`^the UE sends a Service Request with Uplink Data Status for PDU session (\d+)$`, w.srDataWithULDS)
	sc.Step(`^the AMF does not request upCnxState "ACTIVATING" from the SMF for PDU session (\d+)$`, w.noActivatingRequest)
	sc.Step(`^after the Service Accept the AMF sends a DL NAS Transport with PDU SESSION RELEASE COMMAND for PDU session (\d+) with 5GSM cause (0x[0-9a-fA-F]+)$`, w.afterAcceptReleaseCommand)
	sc.Step(`^the paging guard expires without a Service Request$`, w.pagingGuardExpires)
	sc.Step(`^the AMF sends no DL NAS Transport for PDU session (\d+)$`, w.noDLForPSI)
	sc.Step(`^the AMF reports PDU session (\d+) as not re-activated in the Service Accept$`, w.reportedNotReactivated)
	sc.Step(`^the AMF starts a release of PDU session (\d+) with 5GSM cause 39$`, w.startsReleaseCause39)
	sc.Step(`^a PDU SESSION RELEASE COMMAND with 5GSM cause (0x[0-9a-fA-F]+) is delivered for PDU session (\d+)$`,
		func(cause string, psi int) error { return w.deliveredCmd(psi, cause) })
	sc.Step(`^the AMF starts no release of PDU session (\d+)$`, w.startsNoRelease)
}
