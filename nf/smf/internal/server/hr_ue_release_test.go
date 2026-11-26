package server

// hr_ue_release_test.go — UE-initiated release of a home-routed PDU session (V-SMF 0xD1 branch, H-SMF
// Update UE_REQ_PDU_SES_REL), the serving-network release order (#13), the origin refusals (#17) and
// the vcnTunnelInfo address guard (ROAM-002). Ref: TS 23.502 §4.3.4.3; TS 29.502 §5.2.2.8.2.3, §5.2.2.9;
// TS 29.500 Table 5.2.7.2-1; TS 24.501 §8.3.12, §8.3.14.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	pfcpie "github.com/wmnsk/go-pfcp/ie"

	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// releaseRequestN1 is a PDU SESSION RELEASE REQUEST: EPD | PSI | PTI | 0xD1.
func releaseRequestN1(psi, pti uint8) []byte {
	return []byte{nas.PDGroupSessionManagement, psi, pti, byte(nas.MsgTypePDUSessionReleaseRequest)}
}

func (f *vsmfFixture) updateSMContext(ref string, body map[string]any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/"+ref+"/modify", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("smContextRef", ref)
	w := httptest.NewRecorder()
	f.s.handleUpdateSMContext(w, r)
	return w
}

func releaseBody(n1 []byte) map[string]any {
	return map[string]any{"n1SmMsg": base64.StdEncoding.EncodeToString(n1), "pduSessionId": testPSI}
}

// ueReleaseSEPP answers create 201 and /modify with modStatus; at the moment the Update arrives it
// records how many PFCP modifications / deletions the V-UPF stub has seen (ordering proof).
type ueReleaseProbe struct {
	mu            sync.Mutex
	modAtN16      int
	delAtN16      int
	updateSeen    bool
	fillFromStub  func() (mod, del int)
	modifyStatus  int
	releaseStatus int
	block         chan struct{} // when set, /modify waits for it to be closed before answering
	blockRelease  chan struct{} // when set, /release waits for it to be closed before answering
	releaseJSON   string        // body of a non-2xx /release answer
}

func (p *ueReleaseProbe) handler() func(http.ResponseWriter, *http.Request, seppRecord) {
	create := answerCreated(createdJSON(nil), testHRefPath)
	return func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
		switch {
		case strings.HasSuffix(rec.Path, "/modify") || strings.HasSuffix(rec.Path, "/release"):
			p.mu.Lock()
			p.updateSeen = true
			if p.fillFromStub != nil {
				p.modAtN16, p.delAtN16 = p.fillFromStub()
			}
			st := p.modifyStatus
			if strings.HasSuffix(rec.Path, "/release") {
				st = p.releaseStatus
			}
			p.mu.Unlock()
			if p.block != nil && strings.HasSuffix(rec.Path, "/modify") {
				<-p.block
			}
			if p.blockRelease != nil && strings.HasSuffix(rec.Path, "/release") {
				<-p.blockRelease
			}
			if st == 0 {
				st = http.StatusNoContent
			}
			if strings.HasSuffix(rec.Path, "/release") && p.releaseJSON != "" && st >= 400 {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(st)
				_, _ = w.Write([]byte(p.releaseJSON))
				return
			}
			w.WriteHeader(st)
		default:
			create(w, r, rec)
		}
	}
}

func newUEReleaseVSMF(t *testing.T) (*vsmfFixture, string, *ueReleaseProbe) {
	t.Helper()
	p := &ueReleaseProbe{}
	f, ref := establishedVSMF(t, p.handler())
	p.fillFromStub = func() (int, int) { _, m, d := f.upf.counts(); return m, d }
	return f, ref, p
}

func TestVSMFUERelease_HappyPath(t *testing.T) {
	f, ref, p := newUEReleaseVSMF(t)
	metric := func() float64 {
		return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"UeRelease", "OK"))
	}
	before := metric()
	w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, 9)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d %s", w.Code, w.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	cmd, _ := base64.StdEncoding.DecodeString(out["n1SmMsg"])
	if want := []byte{0x2E, testPSI, 9, 0xD3, 0x24}; !bytes.Equal(cmd, want) {
		t.Errorf("Release Command = %x, want %x", cmd, want)
	}
	// Ordering: UL FAR DROP (2nd modification after the step-13a update) -> N16 Update -> V-UPF deletion.
	p.mu.Lock()
	if !p.updateSeen || p.modAtN16 != 2 || p.delAtN16 != 0 {
		t.Errorf("at N16 Update: modifications=%d deletions=%d seen=%v, want 2 / 0 (DROP before N16, deletion after)",
			p.modAtN16, p.delAtN16, p.updateSeen)
	}
	p.mu.Unlock()
	if _, mod, del := f.upf.counts(); mod != 2 || del != 1 {
		t.Errorf("V-UPF modifications/deletions = %d/%d, want 2/1", mod, del)
	}
	uf, _ := f.upf.modAt(1).UpdateFAR[0].UpdateFAR()
	if id, _ := hrChild(t, uf, pfcpie.FARID).FARID(); id != ulFARID {
		t.Errorf("Update FAR id = %d, want UL FAR", id)
	}
	if aa, _ := hrChild(t, uf, pfcpie.ApplyAction).ApplyAction(); aa != applyActionDROP {
		t.Errorf("apply action = %#x, want DROP", aa)
	}
	recs := f.sepp.records()
	if len(recs) != 2 {
		t.Fatalf("SEPP requests = %d, want create + update", len(recs))
	}
	up := recs[1]
	if up.Method != http.MethodPost || up.Path != testHRefPath+"/modify" || up.Host != f.sepp.addr() {
		t.Errorf("update = %s %s host %s", up.Method, up.Path, up.Host)
	}
	if up.Header.Get(hdrTargetAPIRoot) != testHSMFRoot || up.Header.Get(hdrOriginatingNetworkID) != "001-01" ||
		up.ContentType != mediaTypeJSON {
		t.Errorf("update headers = %v ct=%q", up.Header, up.ContentType)
	}
	if string(up.Body) != `{"requestIndication":"UE_REQ_PDU_SES_REL","pti":9}` {
		t.Errorf("HsmfUpdateData = %s", up.Body)
	}
	if f.sessionCount() != 1 {
		t.Error("SM context must stay until DeleteSMContext (TS 29.502 §5.2.2.8.3.3 NOTE)")
	}
	if metric()-before != 1 {
		t.Errorf("UeRelease OK metric delta = %v, want 1", metric()-before)
	}
	logs := f.logs.String()
	for _, want := range []string{"Nsmf_PDUSession_Update", "UE_REQ_PDU_SES_REL"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q", want)
		}
	}
	assertNoDuplicateKeys(t, "UE release", logs)

	// The later DeleteSMContext frees local state only: no N16, no N4.
	if w := f.deleteSMContext(ref); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", w.Code)
	}
	if len(f.sepp.records()) != 2 {
		t.Errorf("DELETE sent an N16 request: %d records", len(f.sepp.records()))
	}
	if _, mod, del := f.upf.counts(); mod != 2 || del != 1 {
		t.Errorf("after DELETE V-UPF modifications/deletions = %d/%d, want 2/1 (no further N4)", mod, del)
	}
	if f.sessionCount() != 0 {
		t.Error("session not freed by DELETE")
	}
	assertNoDuplicateKeys(t, "UE release", f.logs.String())
}

// A retransmitted request is answered again without a second N16 Update or N4 message.
func TestVSMFUERelease_Retransmission(t *testing.T) {
	f, ref, _ := newUEReleaseVSMF(t)
	for i := 0; i < 2; i++ {
		if w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, 9))); w.Code != http.StatusOK {
			t.Fatalf("request %d = %d", i, w.Code)
		}
	}
	if len(f.sepp.records()) != 2 {
		t.Errorf("SEPP requests = %d, want 2", len(f.sepp.records()))
	}
	if _, mod, del := f.upf.counts(); mod != 2 || del != 1 {
		t.Errorf("V-UPF modifications/deletions = %d/%d, want 2/1", mod, del)
	}
}

func TestVSMFUERelease_N16FailureStillReleases(t *testing.T) {
	for name, status := range map[string]int{"500": 500, "503": 503, "404": 404} {
		t.Run(name, func(t *testing.T) {
			f, ref, p := newUEReleaseVSMF(t)
			p.modifyStatus = status
			w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, testPTI)))
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "n1SmMsg") {
				t.Fatalf("status = %d %s, want 200 + command", w.Code, w.Body.String())
			}
			if _, _, del := f.upf.counts(); del != 1 {
				t.Errorf("V-UPF deletions = %d, want 1", del)
			}
			if !strings.Contains(f.logs.String(), `"msg":"hsmf_update_failed"`) {
				t.Errorf("no WARN hsmf_update_failed: %s", f.logs.String())
			}
			if w := f.deleteSMContext(ref); w.Code != http.StatusNoContent || f.sessionCount() != 0 {
				t.Errorf("delete = %d sessions=%d", w.Code, f.sessionCount())
			}
			assertNoDuplicateKeys(t, "UE release", f.logs.String())
		})
	}
}

// releaseSMContextBudgetAMF mirrors the AMF's releaseSMContextTimeout (nf/amf): the V-SMF must answer sooner.
const releaseSMContextBudgetAMF = 10 * time.Second

func (p *ueReleaseProbe) set(f func()) { p.mu.Lock(); f(); p.mu.Unlock() }

func (f *vsmfFixture) sepp2xxPaths(suffix string) int {
	n := 0
	for _, r := range f.sepp.records() {
		if strings.HasSuffix(r.Path, suffix) {
			n++
		}
	}
	return n
}

// A failed N16 Update leaves HomeN16Done false: the later DELETE sends the N16 Release (and only that:
// the V-UPF was already deleted), and the failure is counted.
func TestVSMFUERelease_N16FailureThenDeleteRetriesN16Only(t *testing.T) {
	f, ref, p := newUEReleaseVSMF(t)
	p.set(func() { p.modifyStatus = 503 })
	fail := func() float64 {
		return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"UeRelease", "FAILURE"))
	}
	before := fail()
	if w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, 4))); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if fail() != before+1 {
		t.Error("N16 failure not counted as UeRelease FAILURE")
	}
	if !strings.Contains(f.logs.String(), `"cause"`) {
		t.Error("no cause logged")
	}
	if f.sepp2xxPaths("/release") != 0 {
		t.Fatal("N16 Release sent before the DELETE")
	}
	if w := f.deleteSMContext(ref); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", w.Code)
	}
	if got := f.sepp2xxPaths("/release"); got != 1 {
		t.Errorf("N16 Release at DELETE = %d, want 1", got)
	}
	if _, _, del := f.upf.counts(); del != 1 {
		t.Errorf("V-UPF deletions = %d, want 1 (no second N4 deletion)", del)
	}
}

// A failed V-UPF deletion leaves VUPFDeleted false: the DELETE retries only the N4 deletion.
func TestVSMFUERelease_N4FailureThenDeleteRetriesN4Only(t *testing.T) {
	f, ref, _ := newUEReleaseVSMF(t)
	retxBefore := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"UeRelease", hrResultRetxAfterFailure))
	f.upf.mu.Lock()
	f.upf.delCause = pfcpie.CauseRequestRejected
	f.upf.mu.Unlock()
	if w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, 4))); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Retransmission after completion: same command, no new legs, real (FAILURE) result in the log.
	f.logs.Reset()
	if w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, 4))); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "n1SmMsg") {
		t.Fatalf("retransmission = %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(f.logs.String(), `"level":"WARN","msg":"UE-initiated HR release retransmitted after a failed release, answering again"`) ||
		!strings.Contains(f.logs.String(), `"result":"FAILURE"`) {
		t.Errorf("retransmission log lacks the WARN with the earlier FAILURE result: %s", f.logs.String())
	}
	if got := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"UeRelease", hrResultRetxAfterFailure)); got != retxBefore+1 {
		t.Errorf("RETX_AFTER_FAILURE = %v, want %v", got, retxBefore+1)
	}
	f.upf.mu.Lock()
	f.upf.delCause = pfcpie.CauseRequestAccepted
	f.upf.mu.Unlock()
	if w := f.deleteSMContext(ref); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", w.Code)
	}
	if _, _, del := f.upf.counts(); del != 2 {
		t.Errorf("V-UPF deletions = %d, want 2 (retry at DELETE)", del)
	}
	if got := f.sepp2xxPaths("/release"); got != 0 {
		t.Errorf("N16 Release = %d, want 0 (N16 Update succeeded)", got)
	}
}

// A request retransmitted while the first is still running gets 409, not an early Release Command; a
// DELETE arriving meanwhile is deferred to the running release (no duplicated legs).
func TestVSMFUERelease_ConcurrentRetransmission(t *testing.T) {
	f, ref, p := newUEReleaseVSMF(t)
	p.block = make(chan struct{})
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, 4))) }()
	for i := 0; ; i++ {
		p.mu.Lock()
		seen := p.updateSeen
		p.mu.Unlock()
		if seen {
			break
		}
		if i > 500 {
			t.Fatal("N16 Update never sent")
		}
		time.Sleep(10 * time.Millisecond)
	}
	w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, 4)))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), causeSessionReleasing) {
		t.Errorf("concurrent retransmission = %d %s, want 409", w.Code, w.Body.String())
	}
	if w := f.deleteSMContext(ref); w.Code != http.StatusNoContent {
		t.Errorf("delete = %d", w.Code)
	}
	close(p.block)
	if r := <-first; r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "n1SmMsg") {
		t.Fatalf("first = %d %s", r.Code, r.Body.String())
	}
	f.s.WaitHRCleanup()
	if _, _, del := f.upf.counts(); del != 1 {
		t.Errorf("V-UPF deletions = %d, want exactly 1", del)
	}
	if got := f.sepp2xxPaths("/release") + f.sepp2xxPaths("/modify"); got != 1 {
		t.Errorf("N16 requests after create = %d, want only the Update", got)
	}
}

func TestDetachedTimeoutAndBudget(t *testing.T) {
	if hrUEReleaseBudget >= releaseSMContextBudgetAMF {
		t.Errorf("UE release budget %v must stay below the AMF wait %v", hrUEReleaseBudget, releaseSMContextBudgetAMF)
	}
	if hrUEReleaseN4Leg*2+hrUEReleaseN16Leg > hrUEReleaseBudget {
		t.Error("legs do not fit the shared budget")
	}
	parent, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c, c2 := detachedTimeout(parent, 8*time.Second)
	defer c2()
	if dl, _ := c.Deadline(); time.Until(dl) > time.Second {
		t.Error("detachedTimeout ignored the parent deadline")
	}
	cancel()
	if c.Err() != nil && errors.Is(c.Err(), context.Canceled) {
		t.Error("detachedTimeout must not follow parent cancellation")
	}
}

func TestSanitizeLogValue(t *testing.T) {
	if got := sanitizeLogValue("001-01\r\n\x00x"); got != "001-01x" {
		t.Errorf("got %q", got)
	}
	if got := sanitizeLogValue(strings.Repeat("a", 500)); len(got) != maxLoggedHeaderLen {
		t.Errorf("len = %d", len(got))
	}
}

func TestVSMFUERelease_BadN1WarnsAndFallsBack(t *testing.T) {
	f, ref, _ := newUEReleaseVSMF(t)
	for name, b64 := range map[string]string{"bad base64": "!!!", "short": base64.StdEncoding.EncodeToString([]byte{0x2E, 5})} {
		f.logs.Reset()
		f.updateSMContext(ref, map[string]any{"n1SmMsg": b64, "pduSessionId": testPSI})
		if !strings.Contains(f.logs.String(), `"reason"`) {
			t.Errorf("%s: no WARN with reason: %s", name, f.logs.String())
		}
	}
	if len(f.sepp.records()) != 1 {
		t.Error("a malformed n1SmMsg started an N16 release")
	}
}

func TestVSMFUERelease_SEPPUnreachable(t *testing.T) {
	f, ref, _ := newUEReleaseVSMF(t)
	f.sepp.srv.Close()
	w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, testPTI)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if _, _, del := f.upf.counts(); del != 1 {
		t.Errorf("V-UPF deletions = %d, want 1", del)
	}
	if !strings.Contains(f.logs.String(), `"msg":"hsmf_update_failed"`) {
		t.Error("no WARN hsmf_update_failed")
	}
}

// A failed UL FAR DROP does not stop the release.
func TestVSMFUERelease_DropFailureContinues(t *testing.T) {
	f, ref, _ := newUEReleaseVSMF(t)
	f.upf.setCauses(pfcpie.CauseRequestAccepted, pfcpie.CauseRequestRejected)
	if w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, testPTI))); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if recs := f.sepp.records(); len(recs) != 2 {
		t.Errorf("SEPP requests = %d, want the N16 Update to be sent", len(recs))
	}
	if _, _, del := f.upf.counts(); del != 1 {
		t.Errorf("V-UPF deletions = %d, want 1", del)
	}
}

func TestVSMFUERelease_UnknownRefAndReleasing(t *testing.T) {
	f, ref, _ := newUEReleaseVSMF(t)
	// Unknown ref: falls through to the pre-existing behaviour (no N16, no N4).
	if w := f.updateSMContext("nope", releaseBody(releaseRequestN1(testPSI, 1))); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Errorf("unknown ref = %d %q, want the unchanged empty 200", w.Code, w.Body.String())
	}
	f.s.sessionMu.Lock()
	f.s.sessions[ref].State = sessionStateReleasing
	f.s.sessionMu.Unlock()
	w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, 1)))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), causeSessionReleasing) {
		t.Errorf("RELEASING = %d %s, want 409", w.Code, w.Body.String())
	}
	if len(f.sepp.records()) != 1 {
		t.Error("N16 request sent for a RELEASING session")
	}
	assertNoDuplicateKeys(t, "UE release", f.logs.String())
}

// Non-HR sessions: 0xD1 keeps the unchanged behaviour (no N16, no N4, empty 200).
func TestVSMFUERelease_NonHRUnchanged(t *testing.T) {
	f, _, _ := newUEReleaseVSMF(t)
	f.s.sessionMu.Lock()
	f.s.sessions["plain"] = &Session{SUPI: "imsi-x", DNN: "internet", PDUSessionID: 5}
	f.s.sessionMu.Unlock()
	_, mod0, del0 := f.upf.counts()
	w := f.updateSMContext("plain", releaseBody(releaseRequestN1(5, 7)))
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Errorf("non-HR 0xD1 = %d %q, want the unchanged empty 200", w.Code, w.Body.String())
	}
	if len(f.sepp.records()) != 1 {
		t.Error("non-HR session produced an N16 request")
	}
	if _, mod, del := f.upf.counts(); mod != mod0 || del != del0 {
		t.Error("non-HR session produced N4 traffic")
	}
}

// #13: the serving-network release (DELETE sm-context) sends the UL FAR DROP before the N16 Release.
func TestVSMFRelease_DropBeforeN16Release(t *testing.T) {
	f, ref, p := newUEReleaseVSMF(t)
	if w := f.deleteSMContext(ref); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", w.Code)
	}
	p.mu.Lock()
	if p.modAtN16 != 2 || p.delAtN16 != 0 {
		t.Errorf("at N16 Release: modifications=%d deletions=%d, want 2 / 0", p.modAtN16, p.delAtN16)
	}
	p.mu.Unlock()
	if _, mod, del := f.upf.counts(); mod != 2 || del != 1 {
		t.Errorf("V-UPF modifications/deletions = %d/%d, want 2/1", mod, del)
	}
	// DROP failure: still released.
	f2, ref2, _ := newUEReleaseVSMF(t)
	f2.upf.setCauses(pfcpie.CauseRequestAccepted, pfcpie.CauseRequestRejected)
	if w := f2.deleteSMContext(ref2); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", w.Code)
	}
	if recs := f2.sepp.records(); len(recs) != 2 || !strings.HasSuffix(recs[1].Path, "/release") {
		t.Errorf("N16 release not sent after a failed DROP: %+v", recs)
	}
	// N4Stale: no DROP.
	f3, ref3, _ := newUEReleaseVSMF(t)
	f3.s.sessionMu.Lock()
	f3.s.sessions[ref3].N4Stale = true
	f3.s.sessionMu.Unlock()
	if w := f3.deleteSMContext(ref3); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", w.Code)
	}
	if _, mod, del := f3.upf.counts(); mod != 1 || del != 0 {
		t.Errorf("N4Stale V-UPF modifications/deletions = %d/%d, want 1/0 (no DROP, no deletion)", mod, del)
	}
}

// H-SMF side -------------------------------------------------------------------------------------

func (f *hrFixture) update(ref, nid, body string) *httptest.ResponseRecorder {
	return f.updateReader(ref, nid, strings.NewReader(body))
}

func (f *hrFixture) updateReader(ref, nid string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/pdu-sessions/"+ref+"/modify", body)
	r.Header.Set("Content-Type", "application/json")
	if nid != "" {
		r.Header.Set(hdrOriginatingNetworkID, nid)
	}
	r.SetPathValue("pduSessionRef", ref)
	w := httptest.NewRecorder()
	f.s.handleHsmfUpdatePduSession(w, r)
	return w
}

func (f *hrFixture) hasSession(ref string) bool {
	f.s.sessionMu.Lock()
	defer f.s.sessionMu.Unlock()
	_, ok := f.s.sessions[ref]
	return ok
}

func TestHSMFUpdate(t *testing.T) {
	f := newHRFixture(t, udmSubscribed)
	f.s.cfg.PLMN.MCC, f.s.cfg.PLMN.MNC = "001", "02"
	mk := func(psi int) string {
		d := validCreateData()
		d["pduSessionId"] = psi
		w := f.post(t, d, nil)
		if w.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", w.Code, w.Body.String())
		}
		return refFromLocation(w.Header().Get("Location"))
	}
	ref := mk(5)
	const ue = `{"requestIndication":"UE_REQ_PDU_SES_REL","pti":9}`

	t.Run("refusals leave the session untouched", func(t *testing.T) {
		unknown := f.update("no-such-ref", "001-01", ue)
		cases := []struct {
			name, ref, nid, body string
			status               int
			cause                string
		}{
			{"unknown ref", "no-such-ref", "001-01", ue, 404, causeContextNotFound},
			{"missing requestIndication", ref, "001-01", `{"pti":9}`, 400, causeMandatoryIEMissing},
			{"missing header", ref, "", ue, 403, causeSubscriptionDenied},
			{"foreign PLMN", ref, "310-260", ue, 404, causeContextNotFound},
			{"own PLMN", ref, "001-02", ue, 404, causeContextNotFound},
			{"bad JSON", ref, "001-01", `{`, 400, causeInvalidMsgFormat},
		}
		for _, c := range cases {
			w := f.update(c.ref, c.nid, c.body)
			if w.Code != c.status || !strings.Contains(w.Body.String(), c.cause) {
				t.Errorf("%s = %d %s, want %d %s", c.name, w.Code, w.Body.String(), c.status, c.cause)
			}
			var he HsmfUpdateError
			if json.Unmarshal(w.Body.Bytes(), &he) != nil || he.Error.Cause != c.cause || he.Error.Status != c.status ||
				w.Header().Get("Content-Type") != mediaTypeJSON {
				t.Errorf("%s: not an HsmfUpdateError (ct=%q): %s", c.name, w.Header().Get("Content-Type"), w.Body.String())
			}
			if c.status == 404 && w.Body.String() != unknown.Body.String() {
				t.Errorf("%s body differs from the unknown-ref body (existence oracle)", c.name)
			}
		}
		if w := f.update(ref, "001-01", `{"pti":9}`); !strings.Contains(w.Body.String(), `"/requestIndication"`) {
			t.Errorf("400 lacks invalidParams /requestIndication: %s", w.Body.String())
		}
		if !f.hasSession(ref) || f.upf.deletionCount() != 0 {
			t.Error("a refused Update changed the session or reached the H-UPF")
		}
	})
	t.Run("oversize body 413", func(t *testing.T) {
		big := `{"requestIndication":"UE_REQ_PDU_SES_REL","pad":"` + strings.Repeat("a", maxHRRequestBody) + `"}`
		w := f.update(ref, "001-01", big)
		var pd HRProblemDetails
		if w.Code != http.StatusRequestEntityTooLarge || json.Unmarshal(w.Body.Bytes(), &pd) != nil ||
			pd.Cause != causeMaxJSONSizeExceeded || strings.Contains(w.Body.String(), `"error"`) {
			t.Errorf("oversize = %d %s, want plain ProblemDetails", w.Code, w.Body.String())
		}
	})
	t.Run("unsupported requestIndication", func(t *testing.T) {
		w := f.update(ref, "001-01", `{"requestIndication":"UE_REQ_PDU_SES_MOD","pti":3}`)
		var e HsmfUpdateError
		if w.Code != http.StatusInternalServerError || json.Unmarshal(w.Body.Bytes(), &e) != nil ||
			e.Error.Cause != causeSystemFailure || e.PTI == nil || *e.PTI != 3 {
			t.Errorf("got %d %s", w.Code, w.Body.String())
		}
		if !f.hasSession(ref) {
			t.Error("session released by an unsupported indication")
		}
	})
	t.Run("UE_REQ_PDU_SES_REL releases", func(t *testing.T) {
		w := f.update(ref, "001-01", ue)
		if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
			t.Fatalf("got %d %s", w.Code, w.Body.String())
		}
		if f.upf.deletionCount() != 1 || f.hasSession(ref) {
			t.Errorf("H-UPF deletions=%d session present=%v", f.upf.deletionCount(), f.hasSession(ref))
		}
		if w := f.update(ref, "001-01", ue); w.Code != http.StatusNotFound {
			t.Errorf("second Update = %d, want 404", w.Code)
		}
	})
	t.Run("log lines", func(t *testing.T) {
		logs := &syncBuffer{}
		f.s.logger = slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "SMF")
		ref := mk(6)
		if w := f.update(ref, "001-01", ue); w.Code != http.StatusNoContent {
			t.Fatalf("got %d", w.Code)
		}
		for _, want := range []string{"Nsmf_PDUSession_Update", "UE_REQ_PDU_SES_REL", `"direction":"IN"`} {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("logs lack %q", want)
			}
		}
		assertNoDuplicateKeys(t, "UE release", logs.String())
	})
}

// vcnTunnelInfo guard -----------------------------------------------------------------------------

func TestCheckVcnAddress(t *testing.T) {
	_, allow, _ := net.ParseCIDR("192.0.2.0/24")
	for _, c := range []struct {
		name    string
		t       *HRTunnelInfo
		allowed []*net.IPNet
		param   string // "" = accepted
		reason  string
	}{
		{"routable", &HRTunnelInfo{IPv4Addr: "10.1.0.7"}, nil, "", ""},
		{"loopback", &HRTunnelInfo{IPv4Addr: "127.0.0.1"}, nil, "/vcnTunnelInfo/ipv4Addr", "loopback"},
		{"link-local", &HRTunnelInfo{IPv4Addr: "169.254.1.1"}, nil, "/vcnTunnelInfo/ipv4Addr", "link-local"},
		{"link-local multicast", &HRTunnelInfo{IPv4Addr: "224.0.0.1"}, nil, "/vcnTunnelInfo/ipv4Addr", "link-local multicast"},
		{"multicast", &HRTunnelInfo{IPv4Addr: "239.1.1.1"}, nil, "/vcnTunnelInfo/ipv4Addr", "multicast"},
		{"unspecified", &HRTunnelInfo{IPv4Addr: "0.0.0.0"}, nil, "/vcnTunnelInfo/ipv4Addr", "unspecified"},
		{"broadcast", &HRTunnelInfo{IPv4Addr: "255.255.255.255"}, nil, "/vcnTunnelInfo/ipv4Addr", "limited broadcast"},
		{"v6 loopback", &HRTunnelInfo{IPv4Addr: "10.1.0.7", IPv6Addr: "::1"}, nil, "/vcnTunnelInfo/ipv6Addr", "loopback"},
		{"v6 link-local", &HRTunnelInfo{IPv6Addr: "fe80::1"}, nil, "/vcnTunnelInfo/ipv6Addr", "link-local"},
		{"v6 multicast", &HRTunnelInfo{IPv6Addr: "ff02::1"}, nil, "/vcnTunnelInfo/ipv6Addr", "multicast"},
		{"v6 unspecified", &HRTunnelInfo{IPv6Addr: "::"}, nil, "/vcnTunnelInfo/ipv6Addr", "unspecified"},
		{"v6 unparsed rejected", &HRTunnelInfo{IPv4Addr: "10.1.0.7", IPv6Addr: "zz"}, nil, "/vcnTunnelInfo/ipv6Addr", "not a valid IP"},
		{"v4 unparsed rejected", &HRTunnelInfo{IPv4Addr: "999.1.1.1"}, nil, "/vcnTunnelInfo/ipv4Addr", "not a valid IP"},
		{"this-network", &HRTunnelInfo{IPv4Addr: "0.1.2.3"}, nil, "/vcnTunnelInfo/ipv4Addr", "0.0.0.0/8"},
		{"reserved class E", &HRTunnelInfo{IPv4Addr: "250.1.1.1"}, nil, "/vcnTunnelInfo/ipv4Addr", "240.0.0.0/4"},
		{"mapped loopback", &HRTunnelInfo{IPv6Addr: "::ffff:127.0.0.1"}, nil, "/vcnTunnelInfo/ipv6Addr", "loopback"},
		{"mapped broadcast", &HRTunnelInfo{IPv6Addr: "::ffff:255.255.255.255"}, nil, "/vcnTunnelInfo/ipv6Addr", "limited broadcast"},
		{"mapped this-network", &HRTunnelInfo{IPv6Addr: "::ffff:0.1.2.3"}, nil, "/vcnTunnelInfo/ipv6Addr", "0.0.0.0/8"},
		{"CIDR allow", &HRTunnelInfo{IPv4Addr: "192.0.2.10"}, []*net.IPNet{allow}, "", ""},
		{"CIDR deny", &HRTunnelInfo{IPv4Addr: "198.51.100.10"}, []*net.IPNet{allow}, "/vcnTunnelInfo/ipv4Addr", "not in the allowed"},
		{"CIDR does not excuse loopback", &HRTunnelInfo{IPv4Addr: "127.0.0.1"}, []*net.IPNet{allow}, "/vcnTunnelInfo/ipv4Addr", "loopback"},
		{"nil tunnel", nil, nil, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := checkVcnAddress(c.t, c.allowed)
			if c.param == "" {
				if len(bad) != 0 {
					t.Fatalf("rejected: %+v", bad)
				}
				return
			}
			if len(bad) != 1 || bad[0].Param != c.param || !strings.Contains(bad[0].Reason, c.reason) {
				t.Fatalf("got %+v, want %s containing %q", bad, c.param, c.reason)
			}
		})
	}
}

func TestHSMFCreate_VcnAddressGuard(t *testing.T) {
	f := newHRFixture(t, udmSubscribed)
	for _, addr := range []string{"127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255"} {
		d := validCreateData()
		d["vcnTunnelInfo"] = map[string]any{"ipv4Addr": addr, "gtpTeid": "0000ABCD"}
		w := f.post(t, d, nil)
		e := decodeCreateError(t, w)
		if w.Code != http.StatusBadRequest || e.Error.Cause != causeMandatoryIEIncorrect ||
			len(e.Error.InvalidParams) != 1 || e.Error.InvalidParams[0].Param != "/vcnTunnelInfo/ipv4Addr" {
			t.Errorf("%s = %d %s", addr, w.Code, w.Body.String())
		}
	}
	if len(f.upf.establishments()) != 0 {
		t.Error("a rejected vcnTunnelInfo reached the H-UPF")
	}
	// CIDR allow-list.
	_, cn, _ := net.ParseCIDR("192.0.2.0/24")
	f.s.vupfN9Allowed = []*net.IPNet{cn}
	d := validCreateData()
	d["vcnTunnelInfo"] = map[string]any{"ipv4Addr": "198.51.100.10", "gtpTeid": "0000ABCD"}
	if w := f.post(t, d, nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "/vcnTunnelInfo/ipv4Addr") {
		t.Errorf("outside CIDR = %d %s", w.Code, w.Body.String())
	}
	d = validCreateData()
	d["vcnTunnelInfo"] = map[string]any{"ipv4Addr": "192.0.2.10", "gtpTeid": "0000ABCD"}
	if w := f.post(t, d, nil); w.Code != http.StatusCreated {
		t.Errorf("inside CIDR = %d %s", w.Code, w.Body.String())
	}
}

// An invalid vupf_n9_allowed_cidrs entry stops the SMF at construction.
func TestNew_InvalidVUPFN9CIDR(t *testing.T) {
	s := newTestSMFServer(t)
	cfg := *s.cfg
	cfg.VUPFN9AllowedCIDRs = []string{"192.0.2.0/99"}
	if _, err := New(&cfg, s.logger, nil); err == nil {
		t.Fatal("New accepted an invalid vupf_n9_allowed_cidrs")
	}
}

// With a deferred DELETE the 200 Release Command is written before the deferred N16 Release is sent
// (the AMF must not wait for the cleanup); the cleanup then runs on the tracked goroutine.
func TestVSMFUERelease_DeferredDeleteAnswersBeforeCleanup(t *testing.T) {
	f, ref, p := newUEReleaseVSMF(t)
	p.set(func() { p.modifyStatus = 503 }) // N16 Update fails: the deferred cleanup owes the N16 Release
	p.block = make(chan struct{})
	p.blockRelease = make(chan struct{})
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, 4))) }()
	for i := 0; ; i++ {
		p.mu.Lock()
		seen := p.updateSeen
		p.mu.Unlock()
		if seen {
			break
		}
		if i > 500 {
			t.Fatal("N16 Update never sent")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if w := f.deleteSMContext(ref); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", w.Code)
	}
	close(p.block)
	select {
	case r := <-first:
		if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "n1SmMsg") {
			t.Fatalf("first = %d %s", r.Code, r.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Release Command not written while the deferred N16 Release is still pending")
	}
	if got := f.sepp2xxPaths("/release"); got != 0 {
		t.Errorf("N16 Release answered before the unblock: %d", got)
	}
	close(p.blockRelease)
	f.s.WaitHRCleanup()
	if got := f.sepp2xxPaths("/release"); got != 1 {
		t.Errorf("deferred N16 Release = %d, want 1", got)
	}
}

// A DELETE whose caller did not ask for N4 (sendN4=false) is not deferred to a running UE release.
func TestReleaseSessionLocal_NoDeferWithoutN4(t *testing.T) {
	f, ref, _ := newUEReleaseVSMF(t)
	f.s.sessionMu.Lock()
	sess := f.s.sessions[ref]
	sess.HR.UEReleaseInProgress = true
	f.s.sessionMu.Unlock()
	if !f.s.releaseSessionLocal(context.Background(), ref, sess, false) {
		t.Fatal("releaseSessionLocal returned false")
	}
	f.s.sessionMu.Lock()
	deferred := sess.HR.DeleteDeferred
	f.s.sessionMu.Unlock()
	if deferred {
		t.Error("DeleteDeferred set although the caller asked for no N4")
	}
	if _, _, del := f.upf.counts(); del != 0 {
		t.Errorf("V-UPF deletions = %d, want 0", del)
	}
}

// A panic in a leg must not leave UEReleaseInProgress set.
func TestVSMFUERelease_PanicClearsInProgress(t *testing.T) {
	f, ref, _ := newUEReleaseVSMF(t)
	f.s.sessionMu.Lock()
	sess := f.s.sessions[ref]
	sess.HR.UEReleaseInProgress = true
	f.s.sessionMu.Unlock()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected the leg panic to propagate")
			}
		}()
		f.s.runVSMFUERelease(context.Background(), nil, sess, "https://x.example/ref", 1, true) // nil logger panics in the N16 leg
	}()
	f.s.sessionMu.Lock()
	inProg, done := sess.HR.UEReleaseInProgress, sess.HR.UEReleaseDone
	f.s.sessionMu.Unlock()
	if inProg || done {
		t.Errorf("after panic inProgress=%v done=%v, want false/false", inProg, done)
	}
}

// 404 CONTEXT_NOT_FOUND on the N16 Release retried after an unanswered Update counts as released; on a
// first-time release it stays a failure.
func TestVSMFN16Release_404AfterUnknownUpdate(t *testing.T) {
	notFound := string(problemBody(http.StatusNotFound, causeContextNotFound))
	relMetric := func(res string) float64 {
		return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"Release", res))
	}
	t.Run("after unanswered Update", func(t *testing.T) {
		f, ref, p := newUEReleaseVSMF(t)
		p.set(func() { p.modifyStatus = 503; p.releaseStatus = 404; p.releaseJSON = notFound })
		if w := f.updateSMContext(ref, releaseBody(releaseRequestN1(testPSI, 4))); w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
		okBefore, failBefore := relMetric("OK"), relMetric("FAILURE")
		f.logs.Reset()
		if w := f.deleteSMContext(ref); w.Code != http.StatusNoContent {
			t.Fatalf("delete = %d", w.Code)
		}
		if relMetric("OK") != okBefore+1 || relMetric("FAILURE") != failBefore {
			t.Errorf("Release metric OK/FAILURE moved %v/%v, want +1/+0", relMetric("OK")-okBefore, relMetric("FAILURE")-failBefore)
		}
		if strings.Contains(f.logs.String(), "hsmf_release_failed") || !strings.Contains(f.logs.String(), "counted as released") {
			t.Errorf("404 after an unanswered Update not logged as released: %s", f.logs.String())
		}
	})
	t.Run("first-time release", func(t *testing.T) {
		f, ref, p := newUEReleaseVSMF(t)
		p.set(func() { p.releaseStatus = 404; p.releaseJSON = notFound })
		failBefore := relMetric("FAILURE")
		f.logs.Reset()
		if w := f.deleteSMContext(ref); w.Code != http.StatusNoContent {
			t.Fatalf("delete = %d", w.Code)
		}
		if relMetric("FAILURE") != failBefore+1 || !strings.Contains(f.logs.String(), "hsmf_release_failed") {
			t.Errorf("first-time 404 must stay a FAILURE: %s", f.logs.String())
		}
	})
}

// Graceful shutdown releases a home-routed V-SMF session towards the H-SMF (N16) and the V-UPF; a
// non-HR session still only gets its PFCP deletion (exactly one, no N16).
func TestCleanupAllSessions_HRVSMFSendsN16Release(t *testing.T) {
	f, _, _ := newUEReleaseVSMF(t)
	f.s.sessionMu.Lock()
	f.s.sessions["plain"] = &Session{SUPI: "imsi-x", DNN: "internet", PDUSessionID: 5}
	f.s.sessionMu.Unlock()
	_, _, delBefore := f.upf.counts()
	f.s.cleanupAllSessions(context.Background())
	if n := f.sepp2xxPaths("/release"); n != 1 {
		t.Errorf("N16 releases = %d, want 1 (HR session only)", n)
	}
	// One V-UPF deletion for the HR session + exactly one PFCP deletion for the plain session.
	if _, _, del := f.upf.counts(); del-delBefore != 2 {
		t.Errorf("PFCP deletions = %d, want 2 (HR V-UPF + plain)", del-delBefore)
	}
	if !strings.Contains(f.logs.String(), "home-routed PDU session released on shutdown") ||
		!strings.Contains(f.logs.String(), `"result":"OK"`) {
		t.Errorf("no OK shutdown release line: %s", f.logs.String())
	}
}

// An N16 Release that never answers is cut at its own sub-budget: the V-UPF deletion still happens, the
// shutdown line reports the failed leg, and the whole cleanup stays inside hrShutdownBudget.
func TestCleanupAllSessions_HRN16TimeoutBounded(t *testing.T) {
	f, _, p := newUEReleaseVSMF(t)
	block := make(chan struct{})
	p.set(func() { p.blockRelease = block })
	t.Cleanup(func() { close(block) })
	if hrShutdownBudget >= 5*time.Second {
		t.Fatalf("hrShutdownBudget %v must be below the 5 s shutdown window", hrShutdownBudget)
	}
	_, _, delBefore := f.upf.counts()
	start := time.Now()
	f.s.cleanupAllSessions(context.Background())
	if el := time.Since(start); el > hrShutdownBudget+500*time.Millisecond {
		t.Errorf("shutdown took %v, budget %v", el, hrShutdownBudget)
	}
	if _, _, del := f.upf.counts(); del-delBefore != 1 {
		t.Errorf("V-UPF deletions = %d, want 1 despite the hung N16", del-delBefore)
	}
	var done, n16Done bool
	f.s.sessionMu.Lock()
	for _, sess := range f.s.sessions {
		if sess.HR != nil {
			done, n16Done = sess.HR.VUPFDeleted, sess.HR.HomeN16Done
		}
	}
	f.s.sessionMu.Unlock()
	if !done || n16Done {
		t.Errorf("flags VUPFDeleted=%v HomeN16Done=%v, want true/false", done, n16Done)
	}
	out := f.logs.String()
	if !strings.Contains(out, "home-routed PDU session released on shutdown") || !strings.Contains(out, `"result":"FAILURE"`) ||
		!strings.Contains(out, "n16_release") || strings.Contains(out, "vupf_deletion") {
		t.Errorf("shutdown line must be FAILURE with only n16_release failed: %s", out)
	}
}
