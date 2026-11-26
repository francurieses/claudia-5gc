//go:build functional

// godog step definitions for home_routed_pdu_session_release.feature (ROAM-002: UE-initiated and
// serving-network release of a home-routed PDU session, H-SMF Update/Release refusals and the
// vcnTunnelInfo guard; TS 23.502 §4.3.4.3, TS 29.502 §5.2.2.8.2.3 / §5.2.2.9 / §5.2.2.7,
// TS 29.500 Table 5.2.7.2-1, TS 24.501 §8.3.12 / §8.3.14 / §9.11.4.2).
//
// The steps drive the real handlers in-process: the V-SMF through handleUpdateSMContext /
// handleDeleteSMContext, the H-SMF through its routed http.Handler (so the /modify and /release
// routes are exercised). The local SEPP is an httptest mock, the V-UPF / H-UPF are PFCP stubs
// (vupfStub / hrFakeUPF, reused). Nothing needs the live stack, so nothing is E2E-gated.
//
// Run with: go test -tags=functional ./nf/smf/...  (see Makefile test-functional)
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cucumber/godog"
	pfcpie "github.com/wmnsk/go-pfcp/ie"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

const (
	hrrVPLMNOrigin = "001-01" // 3gpp-Sbi-Originating-Network-Id inserted by the vSEPP
	hrrHPLMNOrigin = "001-02"
	hrrForeignNID  = "310-260"
	hrrRefToken    = "{pduSessionRef}"
)

// hrrWorld is the state of one scenario.
type hrrWorld struct {
	t *testing.T

	// V-SMF side.
	vf        *vsmfFixture
	mu        sync.Mutex
	modStatus int // answer to POST .../modify (0 = 204)
	relStatus int // answer to POST .../release (0 = 204)
	n16Seen   bool
	modAtN16  int // V-UPF PFCP modifications when the first N16 Update/Release arrived
	delAtN16  int // V-UPF PFCP deletions at that moment
	smRef     string
	rec       *httptest.ResponseRecorder

	baseSEPP, baseMod, baseDel int // counters after the UE-initiated release completed

	// H-SMF side.
	hf        *hrFixture
	hRef      string
	hRec      *httptest.ResponseRecorder
	hUnk      *httptest.ResponseRecorder // answer to an unknown pduSessionRef on /modify (existence-oracle baseline)
	hUnkRel   *httptest.ResponseRecorder // same on /release (plain ProblemDetails)
	hOnModify bool                       // the last request under test went to the /modify route
	createVcn map[string]any
}

// ---- V-SMF fixture -----------------------------------------------------------

func (w *hrrWorld) seppHandler(rw http.ResponseWriter, r *http.Request, rec seppRecord) {
	if strings.HasSuffix(rec.Path, "/modify") || strings.HasSuffix(rec.Path, "/release") {
		w.mu.Lock()
		if !w.n16Seen {
			w.n16Seen = true
			_, w.modAtN16, w.delAtN16 = w.vf.upf.counts()
		}
		st := w.modStatus
		if strings.HasSuffix(rec.Path, "/release") {
			st = w.relStatus
		}
		w.mu.Unlock()
		if st == 0 || st == http.StatusNoContent {
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		rw.Header().Set("Content-Type", "application/problem+json")
		rw.WriteHeader(st)
		cause := "SYSTEM_FAILURE"
		if st == http.StatusServiceUnavailable {
			cause = "UNSPECIFIED"
		}
		_, _ = rw.Write(problemBody(st, cause))
		return
	}
	answerCreated(createdJSON(nil), testHRefPath)(rw, r, rec)
}

func (w *hrrWorld) smfRunsInProcess() error {
	w.vf = newVSMFFixture(w.t, w.seppHandler)
	return nil
}

func (w *hrrWorld) plmns(vm, vn, hm, hn string) error {
	cfg := w.vf.s.cfg.PLMN
	if cfg.MCC != vm || cfg.MNC != vn {
		return fmt.Errorf("V-SMF PLMN is %s/%s, feature expects VPLMN %s/%s", cfg.MCC, cfg.MNC, vm, vn)
	}
	if hm+"/"+hn != "001/02" || hrrHPLMNOrigin != hm+"-"+hn {
		return fmt.Errorf("unexpected HPLMN %s/%s", hm, hn)
	}
	return nil
}

func (w *hrrWorld) establishedHR(psi int) error {
	if psi != testPSI {
		return fmt.Errorf("PSI %d: the fixture establishes PSI %d", psi, testPSI)
	}
	rec := w.vf.createSMContext(w.t, smContextCreateData(nil))
	if rec.Code != http.StatusCreated {
		return fmt.Errorf("home-routed establishment failed: %d %s", rec.Code, rec.Body.String())
	}
	var r createResp
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		return err
	}
	w.smRef = r.SMContextRef
	w.vf.s.sessionMu.Lock()
	sess := w.vf.s.sessions[w.smRef]
	w.vf.s.sessionMu.Unlock()
	if sess == nil || sess.HR == nil || sess.HR.HSmfPduSessionRef == "" {
		return fmt.Errorf("no home-routed session for smContextRef %q", w.smRef)
	}
	if want := strings.TrimPrefix(testHSMFRoot+testHRefPath, testHSMFRoot); !strings.HasSuffix(sess.HR.HSmfPduSessionRef, want) {
		return fmt.Errorf("HSmfPduSessionRef = %q, want one ending in %q", sess.HR.HSmfPduSessionRef, want)
	}
	// Establishment sent 1 Update FAR (step 13a hcn tunnel): the DROP must be the second.
	if _, mod, _ := w.vf.upf.counts(); mod != 1 {
		return fmt.Errorf("V-UPF modifications after establishment = %d, want 1", mod)
	}
	return nil
}

func (w *hrrWorld) establishedNonRoaming(psi int) error {
	w.smRef = "plain"
	w.vf.s.sessionMu.Lock()
	w.vf.s.sessions[w.smRef] = &Session{SUPI: "imsi-x", DNN: "internet", PDUSessionID: uint8(psi)}
	w.vf.s.sessionMu.Unlock()
	_, w.baseMod, w.baseDel = w.vf.upf.counts()
	return nil
}

func (w *hrrWorld) hsmfAnswers204To(suffix string) error {
	switch suffix {
	case "{pduSessionRef}/modify":
		w.modStatus = http.StatusNoContent
	case "{pduSessionRef}/release":
		w.relStatus = http.StatusNoContent
	default:
		return fmt.Errorf("unknown N16 operation %q", suffix)
	}
	return nil
}

func (w *hrrWorld) hsmfBehaves(b string) error {
	switch b {
	case "is not reachable (connection refused)":
		w.vf.sepp.srv.Close()
	case "answers 500 SYSTEM_FAILURE":
		w.modStatus = http.StatusInternalServerError
	case "answers 503 UNSPECIFIED":
		w.modStatus = http.StatusServiceUnavailable
	default:
		return fmt.Errorf("unknown H-SMF behaviour %q", b)
	}
	return nil
}

func (w *hrrWorld) amfSendsRelease(msg string, pti int) error {
	if msg != "0xD1" || byte(nas.MsgTypePDUSessionReleaseRequest) != 0xD1 {
		return fmt.Errorf("message type %q is not PDU SESSION RELEASE REQUEST 0xD1", msg)
	}
	w.rec = w.vf.updateSMContext(w.smRef, releaseBody(releaseRequestN1(testPSI, uint8(pti))))
	return nil
}

func (w *hrrWorld) amfDeletes() error {
	w.rec = w.vf.deleteSMContext(w.smRef)
	return nil
}

func (w *hrrWorld) amfDeletesFor(string) error { return w.amfDeletes() }

func (w *hrrWorld) completedUEReleased() error {
	if err := w.establishedHR(testPSI); err != nil {
		return err
	}
	if err := w.amfSendsRelease("0xD1", testPTI); err != nil {
		return err
	}
	if w.rec.Code != http.StatusOK {
		return fmt.Errorf("UE-initiated release = %d %s, want 200", w.rec.Code, w.rec.Body.String())
	}
	if err := w.releaseCommand(testPSI, testPTI, 36); err != nil {
		return err
	}
	w.baseSEPP = len(w.vf.sepp.records())
	_, w.baseMod, w.baseDel = w.vf.upf.counts()
	return nil
}

func (w *hrrWorld) ulFarDrop() error {
	if _, mod, _ := w.vf.upf.counts(); mod != 2 {
		return fmt.Errorf("V-UPF Session Modification Requests = %d, want 2 (step 13a + UL FAR DROP)", mod)
	}
	mod := w.vf.upf.modAt(1)
	if len(mod.UpdateFAR) != 1 {
		return fmt.Errorf("Update FARs = %d, want 1", len(mod.UpdateFAR))
	}
	uf, err := mod.UpdateFAR[0].UpdateFAR()
	if err != nil {
		return err
	}
	idIE := hrChildOf(uf, pfcpie.FARID)
	aaIE := hrChildOf(uf, pfcpie.ApplyAction)
	if idIE == nil || aaIE == nil {
		return fmt.Errorf("Update FAR lacks FAR ID or Apply Action")
	}
	if id, _ := idIE.FARID(); id != ulFARID {
		return fmt.Errorf("Update FAR id = %d, want UL FAR %d", id, ulFARID)
	}
	if aa, _ := aaIE.ApplyAction(); aa != applyActionDROP {
		return fmt.Errorf("Apply Action = %#x, want DROP %#x", aa, applyActionDROP)
	}
	return nil
}

func (w *hrrWorld) n16Record(suffix string) (seppRecord, error) {
	want := testHRefPath + suffix
	for _, r := range w.vf.sepp.records() {
		if r.Method == http.MethodPost && r.Path == want {
			return r, nil
		}
	}
	return seppRecord{}, fmt.Errorf("local SEPP saw no POST %s (%d requests)", want, len(w.vf.sepp.records()))
}

func (w *hrrWorld) seppReceivesModify(path, indication string, pti int) error {
	if want := "/nsmf-pdusession/v1/pdu-sessions/" + hrrRefToken + "/modify"; path != want {
		return fmt.Errorf("unexpected template %q", path)
	}
	r, err := w.n16Record("/modify")
	if err != nil {
		return err
	}
	if got := r.Header.Get(hdrTargetAPIRoot); got != testHSMFRoot {
		return fmt.Errorf("%s = %q, want %q", hdrTargetAPIRoot, got, testHSMFRoot)
	}
	if got := r.Header.Get(hdrOriginatingNetworkID); got != hrrVPLMNOrigin {
		return fmt.Errorf("%s = %q, want %q", hdrOriginatingNetworkID, got, hrrVPLMNOrigin)
	}
	if r.ContentType != mediaTypeJSON {
		return fmt.Errorf("Content-Type = %q, want %q", r.ContentType, mediaTypeJSON)
	}
	var body map[string]any
	if err := json.Unmarshal(r.Body, &body); err != nil {
		return fmt.Errorf("HsmfUpdateData %q: %w", r.Body, err)
	}
	if len(body) != 2 || body["requestIndication"] != indication || body["pti"] != float64(pti) {
		return fmt.Errorf("HsmfUpdateData = %s, want exactly requestIndication %q and pti %d", r.Body, indication, pti)
	}
	return nil
}

func (w *hrrWorld) dropBeforeN16(kind string) error {
	suffix := "/modify"
	if kind == "Release" {
		suffix = "/release"
	}
	if _, err := w.n16Record(suffix); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.n16Seen || w.modAtN16 != 2 || w.delAtN16 != 0 {
		return fmt.Errorf("at the N16 %s request: V-UPF modifications=%d deletions=%d seen=%v, want 2 / 0 (UL FAR DROP before N16, deletion after)",
			kind, w.modAtN16, w.delAtN16, w.n16Seen)
	}
	return nil
}

func (w *hrrWorld) vupfDeletes() error {
	if !hrWaitUntil(func() bool { _, _, d := w.vf.upf.counts(); return d == 1 }) {
		_, _, d := w.vf.upf.counts()
		return fmt.Errorf("V-UPF N4 session deletions = %d, want 1", d)
	}
	return nil
}

func (w *hrrWorld) vupfDeletesAfter204() error {
	if err := w.vupfDeletes(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.delAtN16 != 0 {
		return fmt.Errorf("V-UPF deletion preceded the N16 answer (deletions at N16 = %d)", w.delAtN16)
	}
	return nil
}

func (w *hrrWorld) releaseCommand(psi, pti, cause int) error {
	if w.rec.Code != http.StatusOK {
		return fmt.Errorf("answer = %d %s, want 200", w.rec.Code, w.rec.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(w.rec.Body.Bytes(), &out); err != nil {
		return fmt.Errorf("UpdateSMContext answer: %w: %s", err, w.rec.Body.String())
	}
	cmd, err := base64.StdEncoding.DecodeString(out["n1SmMsg"])
	if err != nil {
		return err
	}
	want := []byte{0x2E, byte(psi), byte(pti), 0xD3, byte(cause)}
	if !bytes.Equal(cmd, want) {
		return fmt.Errorf("PDU SESSION RELEASE COMMAND = %x, want %x", cmd, want)
	}
	return nil
}

func (w *hrrWorld) vsmfFreesContext() error {
	if w.rec.Code != http.StatusNoContent {
		return fmt.Errorf("DeleteSMContext answer = %d, want 204", w.rec.Code)
	}
	if n := w.vf.sessionCount(); n != 0 {
		return fmt.Errorf("%d SM context(s) left", n)
	}
	return nil
}

func (w *hrrWorld) noFurtherSEPP() error {
	if n := len(w.vf.sepp.records()); n != w.baseSEPP {
		return fmt.Errorf("local SEPP received %d request(s) after the release, want %d (no N16 on DELETE)", n, w.baseSEPP)
	}
	return nil
}

func (w *hrrWorld) noFurtherPFCP() error {
	if _, mod, del := w.vf.upf.counts(); mod != w.baseMod || del != w.baseDel {
		return fmt.Errorf("V-UPF modifications/deletions = %d/%d, want %d/%d (no further N4)", mod, del, w.baseMod, w.baseDel)
	}
	return nil
}

func (w *hrrWorld) seppNoRequest() error {
	if n := len(w.vf.sepp.records()); n != 0 {
		return fmt.Errorf("local SEPP received %d request(s), want none", n)
	}
	return nil
}

func (w *hrrWorld) nonRoamingUnchanged() error {
	if w.rec.Code != http.StatusOK || w.rec.Body.Len() != 0 {
		return fmt.Errorf("non-roaming 0xD1 = %d %q, want the unchanged empty 200", w.rec.Code, w.rec.Body.String())
	}
	if _, mod, del := w.vf.upf.counts(); mod != w.baseMod || del != w.baseDel {
		return fmt.Errorf("non-roaming release produced N4 traffic: %d/%d, want %d/%d", mod, del, w.baseMod, w.baseDel)
	}
	return nil
}

func (w *hrrWorld) servingNetworkRelease() error {
	if w.rec.Code != http.StatusNoContent {
		return fmt.Errorf("DeleteSMContext answer = %d, want 204", w.rec.Code)
	}
	r, err := w.n16Record("/release")
	if err != nil {
		return err
	}
	if got := r.Header.Get(hdrTargetAPIRoot); got != testHSMFRoot {
		return fmt.Errorf("%s = %q, want %q", hdrTargetAPIRoot, got, testHSMFRoot)
	}
	return nil
}

func (w *hrrWorld) vsmfAnswersRelease(code int, msg string, psi, pti, cause int) error {
	if code != 200 || msg != "0xD3" || byte(nas.MsgTypePDUSessionReleaseCommand) != 0xD3 {
		return fmt.Errorf("unexpected answer expectation %d %s", code, msg)
	}
	return w.releaseCommand(psi, pti, cause)
}

// ---- H-SMF fixture -----------------------------------------------------------

func (w *hrrWorld) home() *hrFixture {
	if w.hf == nil {
		w.hf = newHRFixture(w.t, udmSubscribed)
		w.hf.s.cfg.PLMN.MCC, w.hf.s.cfg.PLMN.MNC = "001", "02"
	}
	return w.hf
}

func (w *hrrWorld) hsmfServe(method, path, nid, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if nid != "" {
		r.Header.Set(hdrOriginatingNetworkID, nid)
	}
	rr := httptest.NewRecorder()
	w.home().s.httpSrv.Handler.ServeHTTP(rr, r)
	return rr
}

func (w *hrrWorld) hsmfSession(ueIP string) error {
	hf := w.home()
	rec := hf.post(w.t, validCreateData(), hrN1SmInfoIPv4)
	if rec.Code != http.StatusCreated {
		return fmt.Errorf("H-SMF establishment = %d %s", rec.Code, rec.Body.String())
	}
	w.hRef = refFromLocation(rec.Header().Get("Location"))
	hf.s.sessionMu.Lock()
	sess := hf.s.sessions[w.hRef]
	hf.s.sessionMu.Unlock()
	if sess == nil {
		return fmt.Errorf("no H-SMF session for %q", w.hRef)
	}
	if ueIP != "" && (sess.UEIP == nil || sess.UEIP.String() != ueIP) {
		return fmt.Errorf("UE IPv4 address = %v, want %s from the HPLMN pool", sess.UEIP, ueIP)
	}
	// Baseline for the existence-oracle check: the answer to an unknown reference.
	w.hUnk = w.hsmfServe(http.MethodPost, hrCreatePath+"/no-such-ref/modify", hrrVPLMNOrigin,
		`{"requestIndication":"UE_REQ_PDU_SES_REL","pti":9}`)
	w.hUnkRel = w.hsmfServe(http.MethodPost, hrCreatePath+"/no-such-ref/release", hrrVPLMNOrigin, "{}")
	return nil
}

func (w *hrrWorld) hsmfSessionPlain() error { return w.hsmfSession("") }

func (w *hrrWorld) modifyPath(ref string) string { return hrCreatePath + "/" + ref + "/modify" }

func (w *hrrWorld) vsmfPostsModify(indication string) error {
	body := fmt.Sprintf(`{"requestIndication":%q,"pti":9}`, indication)
	w.hRec = w.hsmfServe(http.MethodPost, w.modifyPath(w.hRef), hrrVPLMNOrigin, body)
	return nil
}

func (w *hrrWorld) hsmfDeletesHUPF() error {
	if !hrWaitUntil(func() bool { return w.home().upf.deletionCount() == 1 }) {
		return fmt.Errorf("H-UPF N4 session deletions = %d, want 1", w.home().upf.deletionCount())
	}
	hs := w.home().s
	hs.sessionMu.Lock()
	_, ok := hs.sessions[w.hRef]
	hs.sessionMu.Unlock()
	if ok {
		return fmt.Errorf("H-SMF still holds session %q", w.hRef)
	}
	return nil
}

func (w *hrrWorld) hsmfFreesIP(ip string) error {
	got, err := w.home().s.ipPools["internet"].Allocate()
	if err != nil {
		return err
	}
	if got.String() != ip {
		return fmt.Errorf("next pool address = %s, want the released %s", got, ip)
	}
	return nil
}

func (w *hrrWorld) hsmfResponds204() error {
	if w.hRec.Code != http.StatusNoContent || w.hRec.Body.Len() != 0 {
		return fmt.Errorf("H-SMF answer = %d %q, want an empty 204", w.hRec.Code, w.hRec.Body.String())
	}
	return nil
}

func (w *hrrWorld) updateWhere(condition string) error {
	const ue = `{"requestIndication":"UE_REQ_PDU_SES_REL","pti":9}`
	w.hOnModify = true
	switch condition {
	case "the pduSessionRef is unknown":
		w.hRec = w.hsmfServe(http.MethodPost, w.modifyPath("unknown-ref"), hrrVPLMNOrigin, ue)
	case "requestIndication is missing":
		w.hRec = w.hsmfServe(http.MethodPost, w.modifyPath(w.hRef), hrrVPLMNOrigin, `{"pti":9}`)
	case "header 3gpp-Sbi-Originating-Network-Id is missing":
		w.hRec = w.hsmfServe(http.MethodPost, w.modifyPath(w.hRef), "", ue)
	case "the originating network is a foreign PLMN not owning the ref":
		w.hRec = w.hsmfServe(http.MethodPost, w.modifyPath(w.hRef), hrrForeignNID, ue)
	default:
		return fmt.Errorf("unknown condition %q", condition)
	}
	return nil
}

func (w *hrrWorld) releaseWhere(path, condition string) error {
	if path != "/nsmf-pdusession/v1/pdu-sessions/"+hrrRefToken+"/release" {
		return fmt.Errorf("unexpected template %q", path)
	}
	p := hrCreatePath + "/" + w.hRef + "/release"
	w.hOnModify = false
	nid := ""
	switch condition {
	case "header 3gpp-Sbi-Originating-Network-Id is missing":
	case "the originating network is a foreign PLMN":
		nid = hrrForeignNID
	case "the originating network is the H-SMF's own PLMN":
		nid = hrrHPLMNOrigin
	default:
		return fmt.Errorf("unknown condition %q", condition)
	}
	w.hRec = w.hsmfServe(http.MethodPost, p, nid, "{}")
	return nil
}

// hsmfProblem asserts the refusal body: the /modify route answers an HsmfUpdateError
// ({"error": ProblemDetails}, application/json, TS 29.502 Table 6.1.3.6.4.2.2-2), the /release route a
// plain ProblemDetails (Table 6.1.3.6.3.2-2).
func (w *hrrWorld) hsmfProblem(status int, cause string) error {
	var pd HRProblemDetails
	unk := w.hUnkRel
	if w.hOnModify {
		unk = w.hUnk
		var he HsmfUpdateError
		if err := json.Unmarshal(w.hRec.Body.Bytes(), &he); err != nil || he.Error.Status == 0 {
			return fmt.Errorf("/modify refusal is not an HsmfUpdateError: %v: %s", err, w.hRec.Body.String())
		}
		if ct := w.hRec.Header().Get("Content-Type"); ct != mediaTypeJSON {
			return fmt.Errorf("/modify refusal content-type = %q, want %q", ct, mediaTypeJSON)
		}
		pd = he.Error
	} else if err := json.Unmarshal(w.hRec.Body.Bytes(), &pd); err != nil {
		return fmt.Errorf("ProblemDetails: %w: %s", err, w.hRec.Body.String())
	}
	if w.hRec.Code != status || pd.Cause != cause || pd.Status != status {
		return fmt.Errorf("H-SMF answer = %d (status %d) cause %q, want %d %q: %s", w.hRec.Code, pd.Status, pd.Cause, status, cause, w.hRec.Body.String())
	}
	switch cause {
	case causeMandatoryIEMissing:
		if len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != "/requestIndication" {
			return fmt.Errorf("invalidParams = %+v, want one entry /requestIndication", pd.InvalidParams)
		}
	case causeContextNotFound:
		// 404 must be indistinguishable from an unknown reference (no existence oracle).
		if unk != nil && unk.Body.String() != w.hRec.Body.String() {
			return fmt.Errorf("404 body %q differs from the unknown-ref body %q", w.hRec.Body.String(), unk.Body.String())
		}
	}
	return nil
}

func (w *hrrWorld) hsmfUnchanged() error {
	hs := w.home().s
	hs.sessionMu.Lock()
	sess, ok := hs.sessions[w.hRef]
	hs.sessionMu.Unlock()
	if !ok || sess.UEIP == nil {
		return fmt.Errorf("H-SMF session %q was removed or lost its UE IP", w.hRef)
	}
	if n := w.home().upf.deletionCount(); n != 0 {
		return fmt.Errorf("H-UPF N4 session deletions = %d, want 0", n)
	}
	return nil
}

// ---- vcnTunnelInfo guard -----------------------------------------------------

func (w *hrrWorld) cidrs(list string) error {
	var nets []*net.IPNet
	for _, c := range strings.Split(list, ",") {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return err
		}
		nets = append(nets, n)
	}
	w.home().s.vupfN9Allowed = nets
	return nil
}

func (w *hrrWorld) createDataVcn(addr string) error {
	w.home()
	w.hRef = ""
	vcn := map[string]any{"ipv4Addr": addr, "gtpTeid": "0000ABCD"}
	w.hRec = nil
	w.createVcn = vcn
	return nil
}

func (w *hrrWorld) vsmfPostsCreate(path string) error {
	if path != hrCreatePath {
		return fmt.Errorf("unexpected path %q", path)
	}
	d := validCreateData()
	d["vcnTunnelInfo"] = w.createVcn
	w.hRec = w.home().post(w.t, d, hrN1SmInfoIPv4)
	return nil
}

func (w *hrrWorld) hupfAccepts() error {
	hf := w.home()
	hf.upf.mu.Lock()
	hf.upf.estCause = pfcpie.CauseRequestAccepted
	hf.upf.mu.Unlock()
	return nil
}

func (w *hrrWorld) hsmfResponds400Vcn(cause, param string) error {
	var e PduSessionCreateError
	if err := json.Unmarshal(w.hRec.Body.Bytes(), &e); err != nil {
		return fmt.Errorf("PduSessionCreateError: %w: %s", err, w.hRec.Body.String())
	}
	if w.hRec.Code != http.StatusBadRequest || e.Error.Cause != cause ||
		len(e.Error.InvalidParams) != 1 || e.Error.InvalidParams[0].Param != param {
		return fmt.Errorf("H-SMF answer = %d cause %q invalidParams %+v, want 400 %q [%s]: %s",
			w.hRec.Code, e.Error.Cause, e.Error.InvalidParams, cause, param, w.hRec.Body.String())
	}
	return nil
}

func (w *hrrWorld) noPFCPEstablishment() error {
	if n := len(w.home().upf.establishments()); n != 0 {
		return fmt.Errorf("H-UPF Session Establishment Requests = %d, want none", n)
	}
	return nil
}

func (w *hrrWorld) noUEIP() error {
	hs := w.home().s
	hs.sessionMu.Lock()
	n := len(hs.sessions)
	hs.sessionMu.Unlock()
	if n != 0 {
		return fmt.Errorf("%d H-SMF session(s) stored", n)
	}
	ip, err := hs.ipPools["internet"].Allocate()
	if err != nil || ip.String() != "10.60.0.2" {
		return fmt.Errorf("first pool address = %v (err %v), want 10.60.0.2: an address was allocated", ip, err)
	}
	return nil
}

func (w *hrrWorld) hsmfResponds201() error {
	if w.hRec.Code != http.StatusCreated {
		return fmt.Errorf("H-SMF status = %d, want 201: %s", w.hRec.Code, w.hRec.Body.String())
	}
	var got PduSessionCreatedData
	if err := json.Unmarshal(w.hRec.Body.Bytes(), &got); err != nil {
		return err
	}
	if got.HcnTunnelInfo == nil || got.UeIPv4Address == "" {
		return fmt.Errorf("PduSessionCreatedData incomplete: %s", w.hRec.Body.String())
	}
	return nil
}

func (w *hrrWorld) hupfDLFARTowards(addr string) error {
	reqs := w.home().upf.establishments()
	if len(reqs) != 1 {
		return fmt.Errorf("H-UPF establishments = %d, want 1", len(reqs))
	}
	ohc, err := farOHC(reqs[0], dlFARID)
	if err != nil {
		return err
	}
	if net.ParseIP(addr) == nil || ohc.IPv4Address.String() != addr || ohc.TEID != 0xABCD {
		return fmt.Errorf("DL FAR OHC = %s/%#x, want %s/0xabcd", ohc.IPv4Address, ohc.TEID, addr)
	}
	return nil
}

// ---- registration ------------------------------------------------------------

// InitializeHRReleaseScenario wires the steps of home_routed_pdu_session_release.feature.
func InitializeHRReleaseScenario(t *testing.T) func(*godog.ScenarioContext) {
	return func(ctx *godog.ScenarioContext) {
		w := &hrrWorld{t: t}
		ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
			*w = hrrWorld{t: t}
			return c, nil
		})

		ctx.Step(`^the SMF runs in-process with a PFCP stub V-UPF and a mock local SEPP$`, w.smfRunsInProcess)
		ctx.Step(`^the VPLMN is "(\d{3})/(\d{2})" and the HPLMN is "(\d{3})/(\d{2})"$`, w.plmns)

		// V-SMF
		ctx.Step(`^an established home-routed PDU session with PSI (\d+) and a pduSessionRef at the H-SMF$`, w.establishedHR)
		ctx.Step(`^an established non-roaming PDU session with PSI (\d+)$`, w.establishedNonRoaming)
		ctx.Step(`^the mock H-SMF answers 204 to POST "([^"]+)"$`, w.hsmfAnswers204To)
		ctx.Step(`^the mock H-SMF "([^"]+)"$`, w.hsmfBehaves)
		ctx.Step(`^the AMF sends UpdateSMContext with n1SmMsg PDU SESSION RELEASE REQUEST "([^"]+)" with PTI (\d+)$`, w.amfSendsRelease)
		ctx.Step(`^the AMF sends DELETE on the sm-context$`, w.amfDeletes)
		ctx.Step(`^the AMF sends DELETE on the sm-context, for example on (.+)$`, w.amfDeletesFor)
		ctx.Step(`^a home-routed PDU session in which the UE-initiated release has completed with a PDU SESSION RELEASE COMMAND$`, w.completedUEReleased)
		ctx.Step(`^the V-SMF sends a PFCP Session Modification Request to the V-UPF updating the UL FAR with Apply Action DROP$`, w.ulFarDrop)
		ctx.Step(`^the local SEPP receives POST "([^"]+)" with requestIndication "([^"]+)" and pti (\d+)$`, w.seppReceivesModify)
		ctx.Step(`^the V-SMF sends the N4 Update FAR DROP before the N16 (modify|Release) request$`, w.dropBeforeN16)
		ctx.Step(`^the V-SMF deletes the V-UPF N4 session after the H-SMF answers 204$`, w.vupfDeletesAfter204)
		ctx.Step(`^the V-SMF deletes the V-UPF N4 session$`, w.vupfDeletes)
		ctx.Step(`^the V-SMF answers the AMF (\d+) with n1SmMsg PDU SESSION RELEASE COMMAND "([^"]+)" with PSI (\d+), PTI (\d+) and 5GSM cause (\d+)$`, w.vsmfAnswersRelease)
		ctx.Step(`^the V-SMF frees the SM context$`, w.vsmfFreesContext)
		ctx.Step(`^the local SEPP receives no further request$`, w.noFurtherSEPP)
		ctx.Step(`^the V-UPF stub receives no further PFCP message$`, w.noFurtherPFCP)
		ctx.Step(`^the local SEPP receives no request$`, w.seppNoRequest)
		ctx.Step(`^the SMF follows the existing non-roaming release behaviour$`, w.nonRoamingUnchanged)

		// H-SMF
		ctx.Step(`^a home-routed PDU session at the H-SMF with UE IPv4 address "([^"]+)" allocated from the HPLMN pool$`, w.hsmfSession)
		ctx.Step(`^a home-routed PDU session at the H-SMF$`, w.hsmfSessionPlain)
		ctx.Step(`^the V-SMF sends POST "/nsmf-pdusession/v1/pdu-sessions/\{pduSessionRef\}/modify" with requestIndication "([^"]+)", header "3gpp-Sbi-Originating-Network-Id" of the VPLMN$`, w.vsmfPostsModify)
		ctx.Step(`^the H-SMF deletes the H-UPF N4 session$`, w.hsmfDeletesHUPF)
		ctx.Step(`^the H-SMF frees UE IPv4 address "([^"]+)" back to the pool$`, w.hsmfFreesIP)
		ctx.Step(`^the H-SMF responds 204$`, w.hsmfResponds204)
		ctx.Step(`^the V-SMF sends an Update release request where "([^"]+)"$`, w.updateWhere)
		ctx.Step(`^the V-SMF sends POST "([^"]+)" where "([^"]+)"$`, w.releaseWhere)
		ctx.Step(`^the H-SMF responds (\d+) with ProblemDetails cause "([^"]+)"$`, w.hsmfProblem)
		ctx.Step(`^the H-SMF session and H-UPF N4 session are unchanged$`, w.hsmfUnchanged)

		// vcnTunnelInfo guard
		ctx.Step(`^the H-SMF is configured with the allowed V-UPF N9 CIDR list "([^"]+)"$`, w.cidrs)
		ctx.Step(`^a valid PduSessionCreateData whose vcnTunnelInfo ipv4Addr is "([^"]+)"$`, w.createDataVcn)
		ctx.Step(`^the PFCP stub H-UPF accepts the Session Establishment Request$`, w.hupfAccepts)
		ctx.Step(`^the V-SMF sends POST "([^"]+)" to the H-SMF$`, w.vsmfPostsCreate)
		ctx.Step(`^the H-SMF responds 400 with ProblemDetails cause "([^"]+)" and invalidParams param "([^"]+)"$`, w.hsmfResponds400Vcn)
		ctx.Step(`^the H-SMF sends no PFCP Session Establishment Request to the H-UPF$`, w.noPFCPEstablishment)
		ctx.Step(`^the H-SMF allocates no UE IP address$`, w.noUEIP)
		ctx.Step(`^the H-SMF responds 201 with a PduSessionCreatedData$`, w.hsmfResponds201)
		ctx.Step(`^the H-UPF DL FAR has Outer Header Creation towards "([^"]+)"$`, w.hupfDLFARTowards)
	}
}

// TestHomeRoutedPduSessionReleaseFeatures runs home_routed_pdu_session_release.feature against
// the real V-SMF / H-SMF handlers (TS 23.502 §4.3.4.3, TS 29.502 §5.2.2.8.2.3, §5.2.2.9).
func TestHomeRoutedPduSessionReleaseFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeHRReleaseScenario(t),
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/home_routed_pdu_session_release.feature"},
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
