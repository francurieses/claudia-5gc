//go:build functional

// godog step definitions for home_routed_pdu_session.feature (ROAM-002 phase 1:
// V-SMF / H-SMF over N16, TS 23.502 §4.3.2.2.2 establishment and §4.3.4.3 release,
// TS 29.502 §5.2.2.7 / §5.2.2.9, TS 23.501 §4.2.4, TS 29.500 §6.1.4.3.3,
// TS 24.501 §9.11.4.2 5GSM cause).
//
// The steps drive the real production handlers (handleCreateSMContext,
// handleDeleteSMContext, handleHsmfCreatePduSession, handleHsmfReleasePduSession)
// in-process: the SEPP, the visited/home UDM and the PCF are httptest mocks, the
// V-UPF / H-UPF are PFCP stubs (vupfStub / hrFakeUPF from hr_vsmf_test.go and
// hr_hsmf_test.go, reused). Scenarios that exercise both roles chain the V-SMF
// through the mock SEPP straight into a second in-process SMF (the H-SMF).
// No live UERANSIM stack is needed, so nothing is E2E-gated.
//
// Run with: go test -tags=functional ./nf/smf/...  (see Makefile test-functional)
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/nrf"
)

const (
	hrCreatePath = "/nsmf-pdusession/v1/pdu-sessions"
	hrWaitFor    = 3 * time.Second
)

// hrRelay is one request the mock SEPP handed to the in-process H-SMF and the answer it got.
type hrRelay struct {
	path string
	code int
	body []byte
}

// hrWorld is the state of one scenario. Every scenario builds its own fixtures.
type hrWorld struct {
	t *testing.T

	profile      string
	vplmn, hplmn string

	// V-SMF side.
	vf         *vsmfFixture
	pcfMu      sync.Mutex
	pcfHits    int
	pcfSrv     *httptest.Server
	stop       chan struct{}
	mu         sync.Mutex
	seppH      func(http.ResponseWriter, *http.Request, seppRecord)
	failRel    bool
	relays     []hrRelay
	createData map[string]any
	rec        *httptest.ResponseRecorder
	smRef      string
	hRef       string

	wantUEIP   string
	wantQoS    []byte
	wantHcnIP  string
	wantHcnTID uint32

	// Home (H-SMF) side.
	hf      *hrFixture
	udmMu   sync.Mutex
	udmH    http.HandlerFunc
	hData   map[string]any
	hN1     []byte
	hRec    *httptest.ResponseRecorder
	hRelRef string

	// Non-roaming golden scenarios.
	nr      *hrFixture
	nrSEPP  *mockSEPP
	nrPaths []string
	nrLogs  *syncBuffer
	nrRec   *httptest.ResponseRecorder

	// NF profile scenarios.
	cfg       *config.Config
	profBytes []byte
	nfp       *hrProfileView
}

// ---- generic helpers ---------------------------------------------------------

func hrWaitUntil(cond func() bool) bool {
	deadline := time.Now().Add(hrWaitFor)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func hrPostSMContext(s *Server, m map[string]any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(m)
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateSMContext(w, r)
	return w
}

func hrLogLines(buf *syncBuffer) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func hrChildOf(parent []*pfcpie.IE, typ uint16) *pfcpie.IE {
	for _, x := range parent {
		if x.Type == typ {
			return x
		}
	}
	return nil
}

// pdrTunnel returns the Source Interface and F-TEID of the idx-th Create PDR.
func pdrTunnel(req *pfcpmsg.SessionEstablishmentRequest, idx int) (src uint8, ip string, teid uint32, err error) {
	if idx >= len(req.CreatePDR) {
		return 0, "", 0, fmt.Errorf("Create PDR #%d missing (%d PDRs)", idx, len(req.CreatePDR))
	}
	pdr, err := req.CreatePDR[idx].CreatePDR()
	if err != nil {
		return 0, "", 0, err
	}
	pie := hrChildOf(pdr, pfcpie.PDI)
	if pie == nil {
		return 0, "", 0, fmt.Errorf("PDR #%d has no PDI", idx)
	}
	pdi, err := pie.PDI()
	if err != nil {
		return 0, "", 0, err
	}
	si := hrChildOf(pdi, pfcpie.SourceInterface)
	if si == nil {
		return 0, "", 0, fmt.Errorf("PDR #%d has no Source Interface", idx)
	}
	if src, err = si.SourceInterface(); err != nil {
		return 0, "", 0, err
	}
	fi := hrChildOf(pdi, pfcpie.FTEID)
	if fi == nil {
		return src, "", 0, fmt.Errorf("PDR #%d has no F-TEID", idx)
	}
	ft, err := fi.FTEID()
	if err != nil {
		return src, "", 0, err
	}
	return src, ft.IPv4Address.String(), ft.TEID, nil
}

// farOHC returns the Outer Header Creation of the Create FAR with the given id.
func farOHC(req *pfcpmsg.SessionEstablishmentRequest, farID uint32) (*pfcpie.OuterHeaderCreationFields, error) {
	for _, far := range req.CreateFAR {
		ies, err := far.CreateFAR()
		if err != nil {
			return nil, err
		}
		id, err := hrChildOf(ies, pfcpie.FARID).FARID()
		if err != nil || id != farID {
			continue
		}
		fpie := hrChildOf(ies, pfcpie.ForwardingParameters)
		if fpie == nil {
			return nil, fmt.Errorf("FAR %d has no Forwarding Parameters", farID)
		}
		fp, err := fpie.ForwardingParameters()
		if err != nil {
			return nil, err
		}
		o := hrChildOf(fp, pfcpie.OuterHeaderCreation)
		if o == nil {
			return nil, fmt.Errorf("FAR %d has no Outer Header Creation", farID)
		}
		return o.OuterHeaderCreation()
	}
	return nil, fmt.Errorf("Create FAR %d not found", farID)
}

// ---- fixtures ----------------------------------------------------------------

// seppDispatch is the handler installed in the mock local SEPP; the scenario swaps w.seppH.
func (w *hrWorld) seppDispatch(wr http.ResponseWriter, r *http.Request, rec seppRecord) {
	w.mu.Lock()
	h := w.seppH
	w.mu.Unlock()
	h(wr, r, rec)
}

func (w *hrWorld) setSEPP(h func(http.ResponseWriter, *http.Request, seppRecord)) {
	w.mu.Lock()
	w.seppH = h
	w.mu.Unlock()
}

func (w *hrWorld) udmDispatch(wr http.ResponseWriter, r *http.Request) {
	w.udmMu.Lock()
	h := w.udmH
	w.udmMu.Unlock()
	h(wr, r)
}

func (w *hrWorld) setUDM(h http.HandlerFunc) {
	w.udmMu.Lock()
	w.udmH = h
	w.udmMu.Unlock()
}

// home returns the H-SMF fixture (own UDM mock, H-UPF PFCP stub, IP pool), created on first use.
func (w *hrWorld) home() *hrFixture {
	if w.hf == nil {
		if w.udmH == nil {
			w.setUDM(udmSubscribed)
		}
		w.hf = newHRFixture(w.t, w.udmDispatch)
		w.hf.s.cfg.UPFN9Addr = "10.0.0.9"
		// The H-SMF builds its absolute Location from sbi.fqdn + port: the authority of hSmfUri.
		w.hf.s.cfg.SBI.Address, w.hf.s.cfg.SBI.FQDN = ":8004", "smf.5gc.mnc002.mcc001.3gppnetwork.org"
		w.hf.s.cfg.PLMN.MCC, w.hf.s.cfg.PLMN.MNC = "001", "02"
	}
	return w.hf
}

// passthrough relays every SEPP request into the in-process H-SMF handler and records the answer.
func (w *hrWorld) passthrough(wr http.ResponseWriter, r *http.Request, rec seppRecord) {
	if w.failRel && strings.HasSuffix(rec.Path, "/release") {
		wr.WriteHeader(http.StatusBadGateway)
		return
	}
	rr := httptest.NewRecorder()
	w.home().s.httpSrv.Handler.ServeHTTP(rr, r)
	w.mu.Lock()
	w.relays = append(w.relays, hrRelay{path: rec.Path, code: rr.Code, body: rr.Body.Bytes()})
	w.mu.Unlock()
	for k, v := range rr.Header() {
		wr.Header()[k] = v
	}
	wr.WriteHeader(rr.Code)
	_, _ = wr.Write(rr.Body.Bytes())
}

func (w *hrWorld) usePassthrough() {
	w.home()
	w.setSEPP(w.passthrough)
}

func (w *hrWorld) lastRelay(match func(string) bool) (hrRelay, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := len(w.relays) - 1; i >= 0; i-- {
		if match(w.relays[i].path) {
			return w.relays[i], true
		}
	}
	return hrRelay{}, false
}

// ---- Background --------------------------------------------------------------

func (w *hrWorld) smfRunsInProcess() error {
	w.stop = make(chan struct{})
	w.setSEPP(answerCreated(createdJSON(nil), testHRefPath))
	w.vf = newVSMFFixture(w.t, w.seppDispatch)
	w.wantHcnIP, w.wantHcnTID = "10.0.0.99", 0xCAFE
	w.wantQoS = testQoSRules
	w.wantUEIP = "10.60.0.2"
	// The visited-side PCF must never be asked on the home-routed path.
	w.pcfSrv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		w.pcfMu.Lock()
		w.pcfHits++
		w.pcfMu.Unlock()
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	w.t.Cleanup(w.pcfSrv.Close)
	w.vf.s.cfg.Peers.PCF = strings.TrimPrefix(w.pcfSrv.URL, "https://")
	w.createData = smContextCreateData(nil)
	return nil
}

func (w *hrWorld) plmns(vm, vn, hm, hn string) error {
	cfg := w.vf.s.cfg.PLMN
	if cfg.MCC != vm || cfg.MNC != vn {
		return fmt.Errorf("V-SMF PLMN is %s/%s, feature expects VPLMN %s/%s", cfg.MCC, cfg.MNC, vm, vn)
	}
	w.vplmn, w.hplmn = vm+"/"+vn, hm+"/"+hn
	if !strings.Contains(testHSMFURI, "mnc"+"0"+hn+".mcc"+hm) {
		return fmt.Errorf("H-SMF URI %q is not in the HPLMN %s/%s", testHSMFURI, hm, hn)
	}
	return nil
}

// ---- V-SMF Givens ------------------------------------------------------------

func (w *hrWorld) createDataWith(uri, dnn string) error {
	w.createData = smContextCreateData(func(m map[string]any) {
		m["hSmfUri"] = uri
		m["dnn"] = dnn
	})
	if _, ok := w.createData["hplmnSnssai"]; !ok {
		return fmt.Errorf("SmContextCreateData has no hplmnSnssai")
	}
	return nil
}

func (w *hrWorld) hsmfAnswers201(ueIP, qosHex string) error {
	rules, err := hex.DecodeString(strings.TrimPrefix(qosHex, "0x"))
	if err != nil {
		return fmt.Errorf("qosRules octets %q: %w", qosHex, err)
	}
	w.wantUEIP, w.wantQoS = ueIP, rules
	body := createdJSON(func(m map[string]any) {
		m["ueIpv4Address"] = ueIP
		m["qosFlowsSetupList"].([]map[string]any)[0]["qosRules"] = base64.StdEncoding.EncodeToString(rules)
	})
	w.setSEPP(answerCreated(body, testHRefPath))
	return nil
}

func hrRespond(status int, body []byte) func(http.ResponseWriter, *http.Request, seppRecord) {
	return func(rw http.ResponseWriter, _ *http.Request, rec seppRecord) {
		if strings.HasSuffix(rec.Path, "/release") {
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(status)
		_, _ = rw.Write(body)
	}
}

func (w *hrWorld) hsmfAnswers403(cause string) error {
	w.setSEPP(hrRespond(403, createErrorBody(403, cause, "")))
	return nil
}

func (w *hrWorld) seppAnswersProblem(cause string) error {
	w.setSEPP(hrRespond(504, problemBody(504, cause)))
	return nil
}

func (w *hrWorld) hsmfAnswersWithoutHcn() error {
	w.setSEPP(answerCreated(createdJSON(func(m map[string]any) { delete(m, "hcnTunnelInfo") }), testHRefPath))
	return nil
}

func (w *hrWorld) vupfRejects() error {
	w.vf.upf.setCauses(pfcpie.CauseRequestRejected, pfcpie.CauseRequestAccepted)
	return nil
}

func (w *hrWorld) pathFails(reason string) error {
	switch reason {
	case "the local SEPP is unreachable":
		w.vf.sepp.srv.Close()
	case "the local SEPP answers 500":
		w.setSEPP(func(rw http.ResponseWriter, _ *http.Request, _ seppRecord) {
			rw.WriteHeader(http.StatusInternalServerError)
		})
	case "the H-SMF does not answer within the timeout":
		w.vf.s.n16Timeout = 150 * time.Millisecond
		w.setSEPP(func(_ http.ResponseWriter, r *http.Request, _ seppRecord) {
			select { // hold the answer back until the V-SMF gives up (bounded, never a bare sleep)
			case <-r.Context().Done():
			case <-w.stop:
			case <-time.After(5 * time.Second):
			}
		})
	default:
		return fmt.Errorf("unknown failure %q", reason)
	}
	return nil
}

// ---- V-SMF When / Then -------------------------------------------------------

func (w *hrWorld) amfCreates() error {
	w.rec = hrPostSMContext(w.vf.s, w.createData)
	return nil
}

func (w *hrWorld) noVisitedUDM() error {
	if q := w.vf.udm.seen(); len(q) != 0 {
		return fmt.Errorf("visited UDM was asked: %v", q)
	}
	return nil
}

func (w *hrWorld) noPCF() error {
	w.pcfMu.Lock()
	defer w.pcfMu.Unlock()
	if w.pcfHits != 0 {
		return fmt.Errorf("PCF received %d Npcf_SMPolicyControl request(s)", w.pcfHits)
	}
	return nil
}

func (w *hrWorld) n4N3AndN9() error {
	if est, _, _ := w.vf.upf.counts(); est != 1 {
		return fmt.Errorf("V-UPF Session Establishment Requests = %d, want 1", est)
	}
	req := w.vf.upf.estAt(0)
	for i, tc := range []struct {
		src  uint8
		addr string
		name string
	}{{pfcpie.SrcInterfaceAccess, "10.0.0.1", "N3 UL"}, {pfcpie.SrcInterfaceCore, "10.0.0.9", "N9 DL"}} {
		src, ip, teid, err := pdrTunnel(req, i)
		if err != nil {
			return fmt.Errorf("%s PDR: %w", tc.name, err)
		}
		if src != tc.src || ip != tc.addr || teid == 0 {
			return fmt.Errorf("%s PDR: source interface %d F-TEID %s/%d, want %d %s/non-zero TEID", tc.name, src, ip, teid, tc.src, tc.addr)
		}
	}
	return nil
}

func (w *hrWorld) seppReceivesPost(path, header, want string) error {
	for _, r := range w.vf.sepp.records() {
		if r.Method == http.MethodPost && r.Path == path {
			if got := r.Header.Get(header); got != want {
				return fmt.Errorf("header %s = %q, want %q", header, got, want)
			}
			return nil
		}
	}
	return fmt.Errorf("local SEPP saw no POST %s (%d requests)", path, len(w.vf.sepp.records()))
}

func (w *hrWorld) createDataCarries() error {
	for _, r := range w.vf.sepp.records() {
		if r.Method != http.MethodPost || r.Path != hrCreatePath {
			continue
		}
		mp, err := readHRBody(r.ContentType, bytes.NewReader(r.Body))
		if err != nil {
			return fmt.Errorf("decode PduSessionCreateData body: %w", err)
		}
		var d PduSessionCreateData
		if err := json.Unmarshal(mp.JSON, &d); err != nil {
			return err
		}
		switch {
		case d.VcnTunnelInfo == nil || d.VcnTunnelInfo.IPv4Addr == "" || d.VcnTunnelInfo.GtpTeid == "":
			return fmt.Errorf("vcnTunnelInfo missing or empty: %+v", d.VcnTunnelInfo)
		case d.ChargingID == "":
			return fmt.Errorf("chargingId missing")
		case d.N1SmInfoFromUe == nil || len(mp.Parts[d.N1SmInfoFromUe.ContentID]) == 0:
			return fmt.Errorf("n1SmInfoFromUe missing or its binary part is empty")
		case d.VsmfID == "":
			return fmt.Errorf("vsmfId missing")
		case d.VsmfPduSessionURI == "":
			return fmt.Errorf("vsmfPduSessionUri missing")
		}
		return nil
	}
	return fmt.Errorf("no PduSessionCreateData POST seen by the SEPP")
}

func (w *hrWorld) ulFARUpdated() error {
	if _, mod, _ := w.vf.upf.counts(); mod != 1 {
		return fmt.Errorf("V-UPF Session Modification Requests = %d, want 1", mod)
	}
	mod := w.vf.upf.modAt(0)
	if len(mod.UpdateFAR) != 1 {
		return fmt.Errorf("Update FARs = %d, want 1", len(mod.UpdateFAR))
	}
	uf, err := mod.UpdateFAR[0].UpdateFAR()
	if err != nil {
		return err
	}
	if id, _ := hrChildOf(uf, pfcpie.FARID).FARID(); id != ulFARID {
		return fmt.Errorf("Update FAR id = %d, want UL FAR %d", id, ulFARID)
	}
	ufp := hrChildOf(uf, pfcpie.UpdateForwardingParameters)
	if ufp == nil {
		return fmt.Errorf("Update FAR lacks Update Forwarding Parameters")
	}
	upd, err := ufp.UpdateForwardingParameters()
	if err != nil {
		return err
	}
	oie := hrChildOf(upd, pfcpie.OuterHeaderCreation)
	if oie == nil {
		return fmt.Errorf("Update FAR lacks Outer Header Creation")
	}
	ohc, err := oie.OuterHeaderCreation()
	if err != nil {
		return err
	}
	if ohc.TEID != w.wantHcnTID || ohc.IPv4Address.String() != w.wantHcnIP {
		return fmt.Errorf("UL FAR OHC = %s/%#x, want hcnTunnelInfo %s/%#x", ohc.IPv4Address, ohc.TEID, w.wantHcnIP, w.wantHcnTID)
	}
	return nil
}

func (w *hrWorld) createdBody() (createResp, []byte, error) {
	var r createResp
	if err := json.Unmarshal(w.rec.Body.Bytes(), &r); err != nil {
		return r, nil, fmt.Errorf("decode CreateSMContext answer: %w: %s", err, w.rec.Body.String())
	}
	n1, _ := base64.StdEncoding.DecodeString(r.N1SmMsg)
	return r, n1, nil
}

func (w *hrWorld) answersAccept(ip string) error {
	if w.rec.Code != http.StatusCreated {
		return fmt.Errorf("CreateSMContext status = %d, want 201: %s", w.rec.Code, w.rec.Body.String())
	}
	r, n1, err := w.createdBody()
	if err != nil {
		return err
	}
	if r.N2SmInfoType != "PDU_RES_SETUP_REQ" || r.SMContextRef == "" {
		return fmt.Errorf("answer = %+v, want PDU_RES_SETUP_REQ with an smContextRef", r)
	}
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return fmt.Errorf("bad UE IP %q", ip)
	}
	if !bytes.Contains(n1, append([]byte{0x29, 0x05, 0x01}, v4...)) {
		return fmt.Errorf("PDU address IE with %s missing in Accept body %x", ip, n1)
	}
	return nil
}

func (w *hrWorld) qosRulesUnchanged() error {
	_, n1, err := w.createdBody()
	if err != nil {
		return err
	}
	if len(n1) < 3 {
		return fmt.Errorf("Accept body too short: %x", n1)
	}
	ln := int(n1[1])<<8 | int(n1[2])
	if 3+ln > len(n1) || !bytes.Equal(n1[3:3+ln], w.wantQoS) {
		return fmt.Errorf("Authorized QoS rules = %x, want the H-SMF octets %x unchanged", n1[3:min(3+ln, len(n1))], w.wantQoS)
	}
	return nil
}

func (w *hrWorld) answersReject(cause int) error {
	if w.rec.Code < 400 {
		return fmt.Errorf("status = %d, want an error answer: %s", w.rec.Code, w.rec.Body.String())
	}
	var body struct {
		N1SmMsg string `json:"n1SmMsg"`
	}
	if err := json.Unmarshal(w.rec.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("SmContextCreateError: %w: %s", err, w.rec.Body.String())
	}
	n1, _ := base64.StdEncoding.DecodeString(body.N1SmMsg)
	want := []byte{nas.PDGroupSessionManagement, testPSI, testPTI, byte(nas.MsgTypePDUSessionEstablishmentReject), byte(cause)}
	if !bytes.Equal(n1, want) {
		return fmt.Errorf("PDU SESSION ESTABLISHMENT REJECT = %x, want %x (5GSM cause %d)", n1, want, cause)
	}
	return nil
}

func (w *hrWorld) vupfDeleted() error {
	if !hrWaitUntil(func() bool { _, _, del := w.vf.upf.counts(); return del == 1 }) {
		est, _, del := w.vf.upf.counts()
		return fmt.Errorf("V-UPF N4 session deletions = %d (establishments %d), want 1", del, est)
	}
	if est, _, _ := w.vf.upf.counts(); est < 1 {
		return fmt.Errorf("V-UPF never established an N4 session")
	}
	return nil
}

func (w *hrWorld) seppNoRequest() error {
	if n := len(w.vf.sepp.records()); n != 0 {
		return fmt.Errorf("local SEPP received %d request(s), want none", n)
	}
	return nil
}

func (w *hrWorld) releasePostedTo(ref, header string) error {
	want := testHRefPath + "/release"
	if w.hRef != "" {
		want = strings.TrimPrefix(w.hRef, testHSMFRoot) + "/release"
	}
	for _, r := range w.vf.sepp.records() {
		if r.Method == http.MethodPost && r.Path == want {
			if got := r.Header.Get(header); got != testHSMFRoot {
				return fmt.Errorf("%s = %q, want %q", header, got, testHSMFRoot)
			}
			return nil
		}
	}
	return fmt.Errorf("local SEPP saw no POST %s (placeholder %s)", want, ref)
}

func (w *hrWorld) releaseViaSEPPNoHeader(ref string) error {
	return w.releasePostedTo(ref, "3gpp-Sbi-Target-apiRoot")
}

func (w *hrWorld) logsResult(result, iface, role string) error {
	for _, l := range hrLogLines(w.vf.logs) {
		if l["result"] == result && l["interface"] == iface && l["smf_role"] == role {
			return nil
		}
	}
	return fmt.Errorf("no log line with result=%s interface=%s smf_role=%s in: %s", result, iface, role, w.vf.logs.String())
}

func (w *hrWorld) logsWarn(msg string) error {
	for _, l := range hrLogLines(w.vf.logs) {
		if l["msg"] == msg && l["level"] == "WARN" {
			return nil
		}
	}
	return fmt.Errorf("no WARN %q in: %s", msg, w.vf.logs.String())
}

// ---- Release scenarios -------------------------------------------------------

func (w *hrWorld) establishedSession(_ string) error {
	w.usePassthrough()
	rec := hrPostSMContext(w.vf.s, w.createData)
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
		return fmt.Errorf("no home-routed session stored for smContextRef %q", w.smRef)
	}
	w.hRef = sess.HR.HSmfPduSessionRef
	return nil
}

func (w *hrWorld) n16ReleaseFails() error {
	w.mu.Lock()
	w.failRel = true
	w.mu.Unlock()
	return nil
}

func (w *hrWorld) amfReleases() error {
	w.rec = w.vf.deleteSMContext(w.smRef)
	return nil
}

func (w *hrWorld) hsmfDeletesHUPF() error {
	if !hrWaitUntil(func() bool { return w.home().upf.deletionCount() == 1 }) {
		return fmt.Errorf("H-UPF N4 session deletions = %d, want 1", w.home().upf.deletionCount())
	}
	return nil
}

func (w *hrWorld) hsmfAnswers204() error {
	r, ok := w.lastRelay(func(p string) bool { return strings.HasSuffix(p, "/release") })
	if !ok {
		return fmt.Errorf("the H-SMF never answered a release request")
	}
	if r.code != http.StatusNoContent {
		return fmt.Errorf("H-SMF release answer = %d, want 204", r.code)
	}
	return nil
}

func (w *hrWorld) amfAnswers204() error {
	if w.rec.Code != http.StatusNoContent {
		return fmt.Errorf("ReleaseSMContext answer = %d, want 204", w.rec.Code)
	}
	return nil
}

func (w *hrWorld) hsmfHasNoSession(ref string) error {
	hf := w.home()
	hf.s.sessionMu.Lock()
	_, ok := hf.s.sessions[ref]
	hf.s.sessionMu.Unlock()
	if ok {
		return fmt.Errorf("H-SMF has a session for %q", ref)
	}
	w.hRelRef = ref
	return nil
}

func (w *hrWorld) vsmfPostsReleaseToHSMF(path string) error {
	ref := strings.TrimSuffix(strings.TrimPrefix(path, hrCreatePath+"/"), "/release")
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(hdrOriginatingNetworkID, "001-01") // the hSEPP inserts the VPLMN (TS 29.500 §5.2.3.2.15)
	r.SetPathValue("pduSessionRef", ref)
	rw := httptest.NewRecorder()
	w.home().s.handleHsmfReleasePduSession(rw, r)
	w.mu.Lock()
	w.relays = append(w.relays, hrRelay{path: path, code: rw.Code, body: rw.Body.Bytes()})
	w.mu.Unlock()
	return nil
}

func (w *hrWorld) hsmfProblem404(cause string) error {
	r, ok := w.lastRelay(func(p string) bool { return strings.HasSuffix(p, "/release") })
	if !ok {
		return fmt.Errorf("no H-SMF answer recorded")
	}
	var pd HRProblemDetails
	if err := json.Unmarshal(r.body, &pd); err != nil {
		return fmt.Errorf("ProblemDetails: %w: %s", err, r.body)
	}
	if r.code != http.StatusNotFound || pd.Cause != cause {
		return fmt.Errorf("H-SMF answer = %d cause %q, want 404 %q", r.code, pd.Cause, cause)
	}
	return nil
}

// ---- H-SMF scenarios ---------------------------------------------------------

func (w *hrWorld) createDataFull(dnn string) error {
	if dnn != "internet.mnc002.mcc001.gprs" {
		return fmt.Errorf("unexpected full DNN %q", dnn)
	}
	w.hData = validCreateData()
	w.hN1 = hrN1SmInfoIPv4
	for _, k := range []string{"dnn", "sNssai", "vcnTunnelInfo", "vsmfId", "vsmfPduSessionUri"} {
		if _, ok := w.hData[k]; !ok {
			return fmt.Errorf("PduSessionCreateData lacks %s", k)
		}
	}
	w.home()
	return nil
}

func (w *hrWorld) hudmHolds(dnn string) error {
	w.setUDM(udmSubscribed)
	if dnn != "internet" {
		return fmt.Errorf("unexpected DNN %q", dnn)
	}
	return nil
}

func (w *hrWorld) hupfAccepts() error {
	hf := w.home()
	hf.upf.mu.Lock()
	hf.upf.estCause = pfcpie.CauseRequestAccepted
	hf.upf.mu.Unlock()
	return nil
}

func (w *hrWorld) vsmfPostsToHSMF() error {
	w.hRec = w.home().post(w.t, w.hData, w.hN1)
	return nil
}

func (w *hrWorld) createdFromRec() (*PduSessionCreatedData, string, error) {
	if w.hRec.Code != http.StatusCreated {
		return nil, "", fmt.Errorf("H-SMF status = %d, want 201: %s", w.hRec.Code, w.hRec.Body.String())
	}
	var got PduSessionCreatedData
	if err := json.Unmarshal(w.hRec.Body.Bytes(), &got); err != nil {
		return nil, "", err
	}
	return &got, w.hRec.Header().Get("Location"), nil
}

func (w *hrWorld) hsmfFetchesSmData() error {
	qs := w.home().udm.seen()
	if len(qs) == 0 {
		return fmt.Errorf("the H-SMF made no sm-data request to its own UDM")
	}
	v, err := url.ParseQuery(qs[0])
	if err != nil {
		return err
	}
	sn := v.Get("single-nssai")
	if !strings.Contains(sn, `"sst":1`) || !strings.Contains(sn, `"sd":"000001"`) {
		return fmt.Errorf("single-nssai = %q, want the HPLMN S-NSSAI sst 1 sd 000001", sn)
	}
	return nil
}

func (w *hrWorld) dnnStripped(dnn string) error {
	qs := w.home().udm.seen()
	if len(qs) == 0 {
		return fmt.Errorf("no sm-data request seen")
	}
	v, _ := url.ParseQuery(qs[0])
	if got := v.Get("dnn"); got != dnn {
		return fmt.Errorf("sm-data dnn = %q, want %q (Operator Identifier stripped)", got, dnn)
	}
	return nil
}

func (w *hrWorld) ueIPFromHomePool() error {
	got, _, err := w.createdFromRec()
	if err != nil {
		return err
	}
	_, pool, _ := net.ParseCIDR("10.60.0.0/24")
	if ip := net.ParseIP(got.UeIPv4Address); ip == nil || !pool.Contains(ip) {
		return fmt.Errorf("ueIpv4Address = %q, want an address of the H-SMF pool %s", got.UeIPv4Address, pool)
	}
	return nil
}

func (w *hrWorld) hupfULPDR() error {
	reqs := w.home().upf.establishments()
	if len(reqs) != 1 {
		return fmt.Errorf("H-UPF establishments = %d, want 1", len(reqs))
	}
	_, loc, err := w.createdFromRec()
	if err != nil {
		return err
	}
	ref := loc[strings.LastIndex(loc, "/")+1:]
	hs := w.home().s
	hs.sessionMu.Lock()
	sess := hs.sessions[ref]
	hs.sessionMu.Unlock()
	if sess == nil {
		return fmt.Errorf("no H-SMF session %q", ref)
	}
	src, ip, teid, err := pdrTunnel(reqs[0], 0)
	if err != nil {
		return err
	}
	if src != pfcpie.SrcInterfaceAccess || ip != "10.0.0.9" || teid != sess.ULTEID || teid == 0 {
		return fmt.Errorf("UL PDR: source interface %d F-TEID %s/%d, want Access (0) N9 10.0.0.9/%d", src, ip, teid, sess.ULTEID)
	}
	return nil
}

func (w *hrWorld) hupfDLFAR() error {
	reqs := w.home().upf.establishments()
	if len(reqs) != 1 {
		return fmt.Errorf("H-UPF establishments = %d, want 1", len(reqs))
	}
	ohc, err := farOHC(reqs[0], dlFARID)
	if err != nil {
		return err
	}
	if ohc.TEID != 0xABCD || ohc.IPv4Address.String() != "10.1.0.7" {
		return fmt.Errorf("DL FAR OHC = %s/%#x, want vcnTunnelInfo 10.1.0.7/0xABCD", ohc.IPv4Address, ohc.TEID)
	}
	return nil
}

func (w *hrWorld) locationEndsWith(suffix string) error {
	_, loc, err := w.createdFromRec()
	if err != nil {
		return err
	}
	const pre = "/nsmf-pdusession/v1/pdu-sessions/"
	// The Location is an absolute URI on the H-SMF apiRoot (TS 29.502 Table 6.1.3.5.3.1-4).
	if !strings.HasPrefix(loc, testHSMFRoot+pre) {
		return fmt.Errorf("Location = %q, want an absolute %s%s{pduSessionRef}", loc, testHSMFRoot, pre)
	}
	loc = strings.TrimPrefix(loc, testHSMFRoot)
	if strings.Contains(loc[len(pre):], "/") || len(loc) == len(pre) {
		return fmt.Errorf("Location = %q, want %s{pduSessionRef}", loc, pre)
	}
	if !strings.HasPrefix(suffix, "/pdu-sessions/") {
		return fmt.Errorf("unexpected suffix %q", suffix)
	}
	hs := w.home().s
	hs.sessionMu.Lock()
	_, ok := hs.sessions[loc[len(pre):]]
	hs.sessionMu.Unlock()
	if !ok {
		return fmt.Errorf("Location ref %q does not name an H-SMF session", loc[len(pre):])
	}
	return nil
}

func (w *hrWorld) createdCarries() error {
	got, _, err := w.createdFromRec()
	if err != nil {
		return err
	}
	switch {
	case got.HcnTunnelInfo == nil || got.HcnTunnelInfo.IPv4Addr == "" || got.HcnTunnelInfo.GtpTeid == "":
		return fmt.Errorf("hcnTunnelInfo missing: %+v", got.HcnTunnelInfo)
	case got.UeIPv4Address == "":
		return fmt.Errorf("ueIpv4Address missing")
	case got.SessionAmbr == nil || got.SessionAmbr.Uplink == "" || got.SessionAmbr.Downlink == "":
		return fmt.Errorf("sessionAmbr missing: %+v", got.SessionAmbr)
	case len(got.QosFlowsSetupList) == 0:
		return fmt.Errorf("qosFlowsSetupList missing")
	}
	return nil
}

// ---- H-SMF rejection outline -------------------------------------------------

func (w *hrWorld) createDataWhose(condition string) error {
	switch condition {
	case "DNN is not subscribed in the hUDM":
		w.setUDM(func(rw http.ResponseWriter, r *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("dnn") != "" {
				_, _ = rw.Write([]byte("[]"))
				return
			}
			_, _ = rw.Write([]byte(strings.ReplaceAll(hrSmData, `"internet"`, `"ims"`)))
		})
	case "HPLMN S-NSSAI is not subscribed":
		w.setUDM(func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte("[]"))
		})
	case "no sm-data exists for the SUPI":
		w.setUDM(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusNotFound) })
	case "H-UPF N4 establishment fails":
		w.setUDM(udmSubscribed)
		hf := w.home()
		hf.upf.mu.Lock()
		hf.upf.estCause = pfcpie.CauseRequestRejected
		hf.upf.mu.Unlock()
	default:
		return fmt.Errorf("unknown condition %q", condition)
	}
	w.usePassthrough()
	return nil
}

func (w *hrWorld) hsmfProcesses(path string) error {
	if path != hrCreatePath {
		return fmt.Errorf("unexpected path %q", path)
	}
	w.rec = hrPostSMContext(w.vf.s, w.createData)
	return nil
}

func (w *hrWorld) createRelay() (hrRelay, bool) {
	return w.lastRelay(func(p string) bool { return p == hrCreatePath })
}

func (w *hrWorld) hsmfRespondsError(status int, cause string) error {
	var code int
	var body []byte
	if w.hRec != nil && w.hRec.Code != 0 {
		code, body = w.hRec.Code, w.hRec.Body.Bytes()
	} else if r, ok := w.createRelay(); ok {
		code, body = r.code, r.body
	} else {
		return fmt.Errorf("the H-SMF answered no PostPduSessions request")
	}
	var e PduSessionCreateError
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("PduSessionCreateError: %w: %s", err, body)
	}
	if code != status || e.Error.Cause != cause {
		return fmt.Errorf("H-SMF answer = %d cause %q, want %d %q", code, e.Error.Cause, status, cause)
	}
	return nil
}

func (w *hrWorld) hsmfN1smCause(cause string) error {
	r, ok := w.createRelay()
	if !ok {
		return fmt.Errorf("the H-SMF answered no PostPduSessions request")
	}
	var e PduSessionCreateError
	if err := json.Unmarshal(r.body, &e); err != nil {
		return err
	}
	if e.N1smCause != cause {
		return fmt.Errorf("n1smCause = %q, want %q", e.N1smCause, cause)
	}
	return nil
}

func (w *hrWorld) vupfEstablishedFirst() error {
	// Precondition of the flow: the V-SMF always installs the V-UPF N4 session before step 3a.
	// It is verified for real once the flow ran (establishment count and deletion count).
	return nil
}

// ---- H-SMF mandatory attribute outline ---------------------------------------

func (w *hrWorld) createDataWithout(attr string) error {
	w.hData = validCreateData()
	if _, ok := w.hData[attr]; !ok {
		return fmt.Errorf("PduSessionCreateData has no %s to remove", attr)
	}
	delete(w.hData, attr)
	w.hN1 = nil
	w.home()
	return nil
}

func (w *hrWorld) noHUPFN4() error {
	if n := len(w.home().upf.establishments()); n != 0 {
		return fmt.Errorf("H-UPF establishments = %d, want none", n)
	}
	return nil
}

func (w *hrWorld) noUEIPAllocated() error {
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

// ---- Legacy / golden ---------------------------------------------------------

func (w *hrWorld) releaseProfile(p string) error { w.profile = p; return nil }

func (w *hrWorld) createDataWithoutHSmfURI() error {
	w.createData = smContextCreateData(func(m map[string]any) {
		delete(m, "hSmfUri")
		delete(m, "hplmnSnssai")
		m["dnn"] = "internet"
	})
	return nil
}

func (w *hrWorld) amfCreatesOnPlainSMF() error {
	w.nrSEPP = newMockSEPP(w.t, func(rw http.ResponseWriter, _ *http.Request, _ seppRecord) {
		rw.WriteHeader(http.StatusInternalServerError)
	})
	w.nr = newHRFixture(w.t, func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.nrPaths = append(w.nrPaths, r.URL.Path)
		w.mu.Unlock()
		udmSubscribed(rw, r)
	})
	w.nr.s.profile = profileFor(w.t, w.profile)
	w.nr.s.cfg.Peers.SEPP = w.nrSEPP.addr()
	w.nrLogs = &syncBuffer{}
	w.nr.s.logger = slog.New(slog.NewJSONHandler(w.nrLogs, nil)).With("nf", "SMF")
	w.nrRec = hrPostSMContext(w.nr.s, w.createData)
	if w.nrRec.Code != http.StatusCreated {
		return fmt.Errorf("non-roaming CreateSMContext = %d: %s", w.nrRec.Code, w.nrRec.Body.String())
	}
	return nil
}

func (w *hrWorld) fetchesLocalSmData() error {
	if !hrWaitUntil(func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		for _, p := range w.nrPaths {
			if strings.Contains(p, "sm-data") {
				return true
			}
		}
		return false
	}) {
		return fmt.Errorf("the SMF made no sm-data request to the local UDM (paths %v)", w.nrPaths)
	}
	return nil
}

func (w *hrWorld) noSEPPRequest() error {
	if n := len(w.nrSEPP.records()); n != 0 {
		return fmt.Errorf("SEPP received %d request(s), want none", n)
	}
	return nil
}

func (w *hrWorld) n4Golden(name string) error {
	if !hrWaitUntil(func() bool { return len(w.nr.upf.establishments()) == 1 }) {
		return fmt.Errorf("UPF establishments = %d, want 1", len(w.nr.upf.establishments()))
	}
	b, err := w.nr.upf.establishments()[0].Marshal()
	if err != nil {
		return err
	}
	got := []byte(hex.EncodeToString(b) + "\n")
	path := filepath.Join("testdata", "golden_"+name+".hex")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			return err
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read golden %s: %w", path, err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("PFCP Session Establishment bytes changed:\n got: %s\nwant: %s", got, want)
	}
	return nil
}

func (w *hrWorld) neitherRole() error {
	s := w.nr.s
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if len(s.sessions) != 1 {
		return fmt.Errorf("sessions = %d, want 1", len(s.sessions))
	}
	for _, sess := range s.sessions {
		if sess.HR != nil {
			return fmt.Errorf("non-roaming session carries HR state: %+v", sess.HR)
		}
	}
	for _, l := range hrLogLines(w.nrLogs) {
		if _, ok := l["smf_role"]; ok {
			return fmt.Errorf("non-roaming log line carries smf_role: %v", l)
		}
	}
	return nil
}

// ---- NRF NFProfile -----------------------------------------------------------

// hrProfileView is the part of the NFProfile JSON the feature asserts on.
type hrProfileView struct {
	FQDN       string `json:"fqdn"`
	NFServices []struct {
		ServiceName string `json:"serviceName"`
	} `json:"nfServices"`
}

func hrProfileConfig() *config.Config {
	return &config.Config{
		NFInstanceID: "11111111-2222-3333-4444-555555555555",
		SNSSAIs: []struct {
			SST int    `yaml:"sst"`
			SD  string `yaml:"sd"`
		}{{SST: 1, SD: "000001"}, {SST: 2, SD: "000002"}},
		DNNs: []config.DNNConfig{{Name: "internet"}, {Name: "ims"}},
	}
}

func (w *hrWorld) configNoFQDN() error {
	w.cfg = hrProfileConfig()
	return nil
}

func (w *hrWorld) configFQDN(fqdn string) error {
	w.cfg = hrProfileConfig()
	w.cfg.SBI.Address = "0.0.0.0:8004"
	w.cfg.PLMN.MCC, w.cfg.PLMN.MNC = "001", "02"
	w.cfg.SBI.FQDN = fqdn
	return nil
}

func (w *hrWorld) buildProfile() error {
	p := BuildNFProfile(w.cfg, nil)
	// Same wiring as cmd/smf/main.go before NRF registration (no-op without sbi.fqdn).
	if err := nrf.ApplyFQDNIdentity(p, w.cfg.SBI.FQDN, w.cfg.SBI.Address, w.cfg.PLMN.MCC, w.cfg.PLMN.MNC); err != nil {
		return fmt.Errorf("ApplyFQDNIdentity: %w", err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	w.profBytes = b
	return json.Unmarshal(b, &w.nfp)
}

func (w *hrWorld) profileGolden(name string) error {
	want, err := os.ReadFile(filepath.Join("testdata", "golden_"+name+".json"))
	if err != nil {
		return err
	}
	if !bytes.Equal(w.profBytes, want) {
		return fmt.Errorf("NFProfile bytes changed:\n got: %s\nwant: %s", w.profBytes, want)
	}
	return nil
}

func (w *hrWorld) profileNoFQDN() error {
	if bytes.Contains(w.profBytes, []byte(`"fqdn"`)) {
		return fmt.Errorf("NFProfile carries an fqdn attribute: %s", w.profBytes)
	}
	return nil
}

func (w *hrWorld) profileFQDN(fqdn string) error {
	if w.nfp == nil || w.nfp.FQDN != fqdn {
		return fmt.Errorf("NFProfile fqdn = %v, want %q: %s", w.nfp, fqdn, w.profBytes)
	}
	return nil
}

func (w *hrWorld) profileService(name string) error {
	if w.nfp != nil {
		for _, s := range w.nfp.NFServices {
			if s.ServiceName == name {
				return nil
			}
		}
	}
	return fmt.Errorf("NFProfile lists no service %q: %s", name, w.profBytes)
}

// ---- registration ------------------------------------------------------------

// InitializeHomeRoutedScenario wires the steps of home_routed_pdu_session.feature.
func InitializeHomeRoutedScenario(t *testing.T) func(*godog.ScenarioContext) {
	return func(ctx *godog.ScenarioContext) {
		w := &hrWorld{t: t}
		ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
			*w = hrWorld{t: t}
			return c, nil
		})
		ctx.After(func(c context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
			if w.stop != nil {
				close(w.stop)
			}
			return c, nil
		})

		// Background
		ctx.Step(`^the SMF runs in-process with a PFCP stub V-UPF and a mock local SEPP$`, w.smfRunsInProcess)
		ctx.Step(`^the VPLMN is "(\d{3})/(\d{2})" and the HPLMN is "(\d{3})/(\d{2})"$`, w.plmns)

		// V-SMF
		ctx.Step(`^an SmContextCreateData with hSmfUri "([^"]+)", hplmnSnssai and full DNN "([^"]+)"$`, w.createDataWith)
		ctx.Step(`^the mock H-SMF answers 201 with PduSessionCreatedData carrying ueIpv4Address "([^"]+)", hcnTunnelInfo and qosRules octets "([^"]+)" in qosFlowsSetupList$`, w.hsmfAnswers201)
		ctx.Step(`^the mock H-SMF answers 403 with a PduSessionCreateError cause "([^"]+)" without n1smCause$`, w.hsmfAnswers403)
		ctx.Step(`^the mock local SEPP answers 504 with a plain ProblemDetails cause "([^"]+)"$`, w.seppAnswersProblem)
		ctx.Step(`^the mock H-SMF answers 201 with PduSessionCreatedData lacking hcnTunnelInfo$`, w.hsmfAnswersWithoutHcn)
		ctx.Step(`^the PFCP stub V-UPF rejects the Session Establishment Request$`, w.vupfRejects)
		ctx.Step(`^the home-routed path fails because "([^"]+)"$`, w.pathFails)
		ctx.Step(`^the AMF sends the Nsmf_PDUSession CreateSMContext request to the V-SMF$`, w.amfCreates)
		ctx.Step(`^the V-SMF does not send any Nudm_SDM sm-data request to the visited UDM$`, w.noVisitedUDM)
		ctx.Step(`^the V-SMF does not send any Npcf_SMPolicyControl request$`, w.noPCF)
		ctx.Step(`^the V-SMF establishes the N4 session on the V-UPF with an N3 F-TEID and an N9 F-TEID$`, w.n4N3AndN9)
		ctx.Step(`^the local SEPP receives POST "([^"]+)" with header "([^"]+)" equal to "([^"]+)"$`, w.seppReceivesPost)
		ctx.Step(`^the PduSessionCreateData carries vcnTunnelInfo, chargingId, n1SmInfoFromUe, vsmfId and vsmfPduSessionUri$`, w.createDataCarries)
		ctx.Step(`^the V-SMF updates the V-UPF UL FAR with Outer Header Creation towards the hcnTunnelInfo$`, w.ulFARUpdated)
		ctx.Step(`^the V-SMF answers the AMF with a PDU SESSION ESTABLISHMENT ACCEPT carrying UE IP "([^"]+)"$`, w.answersAccept)
		ctx.Step(`^the qosRules in the PDU SESSION ESTABLISHMENT ACCEPT equal the H-SMF qosRules octets unchanged$`, w.qosRulesUnchanged)
		ctx.Step(`^the V-SMF answers the AMF with a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause (\d+)$`, func(c int) error { return w.answersReject(c) })
		ctx.Step(`^the V-SMF deletes its V-UPF N4 session$`, w.vupfDeleted)
		ctx.Step(`^the local SEPP receives no request$`, w.seppNoRequest)
		ctx.Step(`^the V-SMF sends POST "([^"]+)/release" to the H-SMF via the local SEPP$`, w.releaseViaSEPPNoHeader)
		ctx.Step(`^the V-SMF logs result "([^"]+)" with interface "([^"]+)" and smf_role "([^"]+)"$`, w.logsResult)
		ctx.Step(`^the V-SMF logs a WARN "([^"]+)"$`, w.logsWarn)

		// Release
		ctx.Step(`^an established home-routed PDU session with hSmfPduSessionRef "([^"]+)"$`, w.establishedSession)
		ctx.Step(`^the N16 release request fails with a 5xx$`, w.n16ReleaseFails)
		ctx.Step(`^the AMF sends the Nsmf_PDUSession ReleaseSMContext request to the V-SMF$`, w.amfReleases)
		ctx.Step(`^the V-SMF sends POST "([^"]+)/release" via the local SEPP with header "([^"]+)"$`, func(ref, h string) error { return w.releasePostedTo(ref, h) })
		ctx.Step(`^the H-SMF deletes the H-UPF N4 session$`, w.hsmfDeletesHUPF)
		ctx.Step(`^the H-SMF answers 204$`, w.hsmfAnswers204)
		ctx.Step(`^the V-SMF answers the AMF with 204$`, w.amfAnswers204)
		ctx.Step(`^the H-SMF has no session for pduSessionRef "([^"]+)"$`, w.hsmfHasNoSession)
		ctx.Step(`^the V-SMF sends POST "(/nsmf-pdusession/v1/pdu-sessions/[^"]+/release)" to the H-SMF$`, w.vsmfPostsReleaseToHSMF)
		ctx.Step(`^the H-SMF responds 404 with ProblemDetails cause "([^"]+)"$`, w.hsmfProblem404)

		// H-SMF
		ctx.Step(`^a PduSessionCreateData with full DNN "([^"]+)", HPLMN sNssai, vcnTunnelInfo, vsmfId, vsmfPduSessionUri and n1SmInfoFromUe$`, w.createDataFull)
		ctx.Step(`^the mock hUDM holds sm-data for the HPLMN S-NSSAI and DNN "([^"]+)"$`, w.hudmHolds)
		ctx.Step(`^the PFCP stub H-UPF accepts the Session Establishment Request$`, w.hupfAccepts)
		ctx.Step(`^the V-SMF sends POST "(/nsmf-pdusession/v1/pdu-sessions)" to the H-SMF$`, func(string) error { return w.vsmfPostsToHSMF() })
		ctx.Step(`^the H-SMF fetches sm-data from its own UDM with the HPLMN S-NSSAI$`, w.hsmfFetchesSmData)
		ctx.Step(`^the DNN used for the sm-data lookup has the Operator Identifier stripped, "([^"]+)"$`, w.dnnStripped)
		ctx.Step(`^the H-SMF allocates the UE IPv4 address from its own pool$`, w.ueIPFromHomePool)
		ctx.Step(`^the H-UPF UL PDR has Source Interface "Access" and the N9 F-TEID$`, w.hupfULPDR)
		ctx.Step(`^the H-UPF DL FAR has Outer Header Creation towards the vcnTunnelInfo$`, w.hupfDLFAR)
		ctx.Step(`^the H-SMF responds 201 with a Location header ending in "([^"]+)"$`, w.locationEndsWith)
		ctx.Step(`^the PduSessionCreatedData carries hcnTunnelInfo, ueIpv4Address, sessionAmbr and qosFlowsSetupList$`, w.createdCarries)

		// H-SMF rejections
		ctx.Step(`^a PduSessionCreateData whose "([^"]+)"$`, w.createDataWhose)
		ctx.Step(`^the V-SMF has established the N4 session on the V-UPF$`, w.vupfEstablishedFirst)
		ctx.Step(`^the H-SMF processes POST "([^"]+)"$`, w.hsmfProcesses)
		ctx.Step(`^the H-SMF responds (\d+) with a PduSessionCreateError whose ProblemDetails cause is "([^"]+)"$`, func(s int, c string) error { return w.hsmfRespondsError(s, c) })
		ctx.Step(`^the PduSessionCreateError carries n1smCause "([^"]+)"$`, w.hsmfN1smCause)
		ctx.Step(`^a PduSessionCreateData without "([^"]+)"$`, w.createDataWithout)
		ctx.Step(`^no N4 session is established on the H-UPF$`, w.noHUPFN4)
		ctx.Step(`^no UE IP address is allocated from the H-SMF pool$`, w.noUEIPAllocated)

		// Legacy / golden
		ctx.Step(`^the release profile is "([^"]+)"$`, w.releaseProfile)
		ctx.Step(`^an SmContextCreateData without hSmfUri$`, w.createDataWithoutHSmfURI)
		ctx.Step(`^the AMF sends the Nsmf_PDUSession CreateSMContext request to the SMF$`, w.amfCreatesOnPlainSMF)
		ctx.Step(`^the SMF fetches sm-data from the local UDM$`, w.fetchesLocalSmData)
		ctx.Step(`^the SMF sends no request to a SEPP$`, w.noSEPPRequest)
		ctx.Step(`^the PFCP Session Establishment Request bytes equal the golden "([^"]+)"$`, w.n4Golden)
		ctx.Step(`^the SMF behaves as neither V-SMF nor H-SMF$`, w.neitherRole)
		ctx.Step(`^the SMF config has no sbi.fqdn$`, w.configNoFQDN)
		ctx.Step(`^the SMF config has sbi.fqdn "([^"]+)"$`, w.configFQDN)
		ctx.Step(`^the SMF builds its NRF NFProfile$`, w.buildProfile)
		ctx.Step(`^the NFProfile bytes equal the golden "([^"]+)"$`, w.profileGolden)
		ctx.Step(`^the NFProfile has no fqdn attribute$`, w.profileNoFQDN)
		ctx.Step(`^the NFProfile carries fqdn "([^"]+)"$`, w.profileFQDN)
		ctx.Step(`^the NFProfile lists service "([^"]+)"$`, w.profileService)
	}
}

// TestHomeRoutedPduSessionFeatures runs home_routed_pdu_session.feature against the real
// V-SMF / H-SMF handlers (TS 23.502 §4.3.2.2.2, §4.3.4.3).
func TestHomeRoutedPduSessionFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeHomeRoutedScenario(t),
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/home_routed_pdu_session.feature"},
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
