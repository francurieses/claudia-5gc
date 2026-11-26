package server

// hr_vsmf_test.go — V-SMF role of the home-routed PDU session (ROAM-002): CreateSMContext with
// hSmfUri against an httptest SEPP and a PFCP stub V-UPF, the HR PFCP rule set, the Accept/N2 built
// from PduSessionCreatedData, every error mapping, the serving-network release, the PduSessionCreateData
// golden and an in-process V-SMF -> SEPP passthrough -> H-SMF run.
// Behaviour contract: tests/features/home_routed_pdu_session.feature (@vsmf, @release).

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
	"github.com/free5gc/aper"
)

const (
	testHSMFRoot = "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004"
	testHSMFURI  = testHSMFRoot + "/nsmf-pdusession/v1"
	testFullDNN  = "internet.mnc002.mcc001.gprs"
	testHRefPath = "/nsmf-pdusession/v1/pdu-sessions/ref-1234"
)

// vupfStub is a PFCP stub V-UPF: records Establishment / Modification / Deletion, causes configurable.
type vupfStub struct {
	conn *net.UDPConn

	mu       sync.Mutex
	estCause uint8
	modCause uint8
	delCause uint8 // Cause of the Session Deletion Response
	est      []*pfcpmsg.SessionEstablishmentRequest
	mod      []*pfcpmsg.SessionModificationRequest
	dels     int
}

func newVUPFStub(t *testing.T) *vupfStub {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen stub V-UPF: %v", err)
	}
	f := &vupfStub{conn: conn, estCause: pfcpie.CauseRequestAccepted, modCause: pfcpie.CauseRequestAccepted, delCause: pfcpie.CauseRequestAccepted}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 8192)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, err := pfcpmsg.Parse(append([]byte(nil), buf[:n]...)) // IEs alias the buffer
			if err != nil {
				continue
			}
			f.mu.Lock()
			ec, mc := f.estCause, f.modCause
			var rsp interface{ Marshal() ([]byte, error) }
			switch m := msg.(type) {
			case *pfcpmsg.SessionEstablishmentRequest:
				f.est = append(f.est, m)
				rsp = pfcpmsg.NewSessionEstablishmentResponse(0, 0, 1, m.Sequence(), 0, pfcpie.NewCause(ec), pfcpie.NewNodeID("", "", "upf"))
			case *pfcpmsg.SessionModificationRequest:
				f.mod = append(f.mod, m)
				rsp = pfcpmsg.NewSessionModificationResponse(0, 0, m.SEID(), m.Sequence(), 0, pfcpie.NewCause(mc))
			case *pfcpmsg.SessionDeletionRequest:
				f.dels++
				rsp = pfcpmsg.NewSessionDeletionResponse(0, 0, m.SEID(), m.Sequence(), 0, pfcpie.NewCause(f.delCause))
			}
			f.mu.Unlock()
			if rsp != nil {
				if b, err := rsp.Marshal(); err == nil {
					_, _ = conn.WriteToUDP(b, raddr)
				}
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return f
}

func (f *vupfStub) setCauses(est, mod uint8) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.estCause, f.modCause = est, mod
}

func (f *vupfStub) estAt(i int) *pfcpmsg.SessionEstablishmentRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.est[i]
}

func (f *vupfStub) modAt(i int) *pfcpmsg.SessionModificationRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mod[i]
}

func (f *vupfStub) counts() (est, mod, del int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.est), len(f.mod), f.dels
}

// seppRecord is one request seen by the mock SEPP.
type seppRecord struct {
	Host        string
	Method      string
	Path        string
	Header      http.Header
	ContentType string
	Body        []byte
}

// mockSEPP is the local SEPP: records requests, answers through handler.
type mockSEPP struct {
	srv *httptest.Server
	mu  sync.Mutex
	rec []seppRecord
}

func newMockSEPP(t *testing.T, h func(w http.ResponseWriter, r *http.Request, rec seppRecord)) *mockSEPP {
	t.Helper()
	m := &mockSEPP{}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec := seppRecord{Host: r.Host, Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(),
			ContentType: r.Header.Get("Content-Type"), Body: b}
		m.mu.Lock()
		m.rec = append(m.rec, rec)
		m.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(b)) // let a passthrough handler read it again
		h(w, r, rec)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockSEPP) addr() string { return strings.TrimPrefix(m.srv.URL, "https://") }

func (m *mockSEPP) records() []seppRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]seppRecord(nil), m.rec...)
}

var testQoSRules = []byte{0x01, 0x00}

// createdJSON is a valid PduSessionCreatedData answer (optionally mutated).
func createdJSON(mutate func(m map[string]any)) []byte {
	m := map[string]any{
		"pduSessionType": "IPV4", "sscMode": "1", "ueIpv4Address": "10.60.0.2",
		"hcnTunnelInfo":  map[string]any{"ipv4Addr": "10.0.0.99", "gtpTeid": "0000CAFE"},
		"sessionAmbr":    map[string]any{"uplink": "50000 Kbps", "downlink": "200000 Kbps"},
		"hSmfInstanceId": "00000000-0000-4005-8000-0000000000bb",
		"qosFlowsSetupList": []map[string]any{{
			"qfi": 1, "qosRules": base64.StdEncoding.EncodeToString(testQoSRules), "defaultQosRuleInd": true,
			"qosFlowProfile": map[string]any{"5qi": 8, "arp": map[string]any{"priorityLevel": 5, "preemptCap": "NOT_PREEMPT", "preemptVuln": "NOT_PREEMPTABLE"}},
		}},
	}
	if mutate != nil {
		mutate(m)
	}
	b, _ := json.Marshal(m)
	return b
}

// answerCreated replies 201 with Location + created.
func answerCreated(body []byte, loc string) func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
	return func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
		if strings.HasSuffix(rec.Path, "/release") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}
}

type vsmfFixture struct {
	s    *Server
	upf  *vupfStub
	sepp *mockSEPP
	udm  *hrUDM
	logs *syncBuffer
}

func newVSMFFixture(t *testing.T, h func(w http.ResponseWriter, r *http.Request, rec seppRecord)) *vsmfFixture {
	t.Helper()
	f := newHRFixture(t, func(w http.ResponseWriter, r *http.Request) { // visited UDM: must never be asked
		w.WriteHeader(http.StatusInternalServerError)
	})
	upf := newVUPFStub(t)
	f.s.cfg.Peers.UPF = upf.conn.LocalAddr().String()
	f.s.cfg.PLMN.MCC, f.s.cfg.PLMN.MNC = "001", "01"
	f.s.cfg.SBI.Address, f.s.cfg.SBI.FQDN = ":8004", "smf.5gc.mnc001.mcc001.3gppnetwork.org"
	logs := &syncBuffer{}
	f.s.logger = slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "SMF")
	sepp := newMockSEPP(t, h)
	f.s.httpClient = sepp.srv.Client()
	f.s.cfg.Peers.SEPP = sepp.addr()
	return &vsmfFixture{s: f.s, upf: upf, sepp: sepp, udm: f.udm, logs: logs}
}

const testPSI, testPTI = 5, 7

// n1EstRequest is a PDU SESSION ESTABLISHMENT REQUEST: IPMDR 0xFF/0xFF, PDU session type IPv4, SSC mode 1.
func n1EstRequest() []byte {
	return []byte{nas.PDGroupSessionManagement, testPSI, testPTI, 0xC1, 0xFF, 0xFF, 0x91, 0xA1}
}

func smContextCreateData(mutate func(m map[string]any)) map[string]any {
	m := map[string]any{
		"supi": "imsi-001020000000001", "dnn": testFullDNN, "pduSessionId": testPSI, "anType": "3GPP_ACCESS",
		"requestType": "INITIAL_REQUEST", "servingNfId": "amf-001",
		"n1SmMsg":     base64.StdEncoding.EncodeToString(n1EstRequest()),
		"snssai":      map[string]any{"sst": 1, "sd": "000001"},
		"hplmnSnssai": map[string]any{"sst": 1, "sd": "000001"},
		"hSmfUri":     testHSMFURI,
	}
	if mutate != nil {
		mutate(m)
	}
	return m
}

func (f *vsmfFixture) createSMContext(t *testing.T, m map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(m)
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.s.handleCreateSMContext(w, r)
	return w
}

func (f *vsmfFixture) deleteSMContext(ref string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodDelete, "/nsmf-pdusession/v1/sm-contexts/"+ref, nil)
	r.SetPathValue("smContextRef", ref)
	w := httptest.NewRecorder()
	f.s.handleDeleteSMContext(w, r)
	return w
}

type createResp struct {
	SMContextRef string `json:"smContextRef"`
	N1SmMsg      string `json:"n1SmMsg"`
	N2SmInfo     string `json:"n2SmInfo"`
	N2SmInfoType string `json:"n2SmInfoType"`
}

func decodeCreateResp(t *testing.T, w *httptest.ResponseRecorder) (createResp, []byte, []byte) {
	t.Helper()
	var r createResp
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode CreateSMContext answer: %v: %s", err, w.Body.String())
	}
	n1, _ := base64.StdEncoding.DecodeString(r.N1SmMsg)
	n2, _ := base64.StdEncoding.DecodeString(r.N2SmInfo)
	return r, n1, n2
}

func (f *vsmfFixture) sessionCount() int {
	f.s.sessionMu.Lock()
	defer f.s.sessionMu.Unlock()
	return len(f.s.sessions)
}

// Happy path -------------------------------------------------------------------------------------

func TestVSMFCreate_HappyPath(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	resp, n1, n2 := decodeCreateResp(t, w)
	if resp.N2SmInfoType != "PDU_RES_SETUP_REQ" || resp.SMContextRef == "" {
		t.Fatalf("answer = %+v", resp)
	}

	// No visited UDM / PCF access.
	if q := f.udm.seen(); len(q) != 0 {
		t.Errorf("visited UDM was asked: %v", q)
	}

	// N16: exactly one POST to the SEPP (TCP target), home FQDN only in the header.
	recs := f.sepp.records()
	if len(recs) != 1 {
		t.Fatalf("SEPP requests = %d, want 1", len(recs))
	}
	rq := recs[0]
	if rq.Host != f.sepp.addr() {
		t.Errorf("TCP target %q, want the SEPP %q", rq.Host, f.sepp.addr())
	}
	if rq.Method != http.MethodPost || rq.Path != "/nsmf-pdusession/v1/pdu-sessions" {
		t.Errorf("request = %s %s", rq.Method, rq.Path)
	}
	if got := rq.Header.Get("3gpp-Sbi-Target-apiRoot"); got != testHSMFRoot {
		t.Errorf("target-apiRoot = %q, want %q", got, testHSMFRoot)
	}
	if got := rq.Header.Get("3gpp-Sbi-Originating-Network-Id"); got != "001-01" {
		t.Errorf("originating network id = %q", got)
	}
	if !strings.HasPrefix(rq.ContentType, "multipart/related") {
		t.Fatalf("content-type = %q, want multipart/related", rq.ContentType)
	}
	mp, err := readHRBody(rq.ContentType, bytes.NewReader(rq.Body))
	if err != nil {
		t.Fatalf("readHRBody: %v", err)
	}
	var data PduSessionCreateData
	if err := json.Unmarshal(mp.JSON, &data); err != nil {
		t.Fatal(err)
	}
	// The H-SMF validator must accept exactly what the V-SMF sends.
	if missing, incorrect := validatePduSessionCreateData(&data); len(missing)+len(incorrect) > 0 {
		t.Errorf("PduSessionCreateData fails the H-SMF validation: missing=%v incorrect=%v", missing, incorrect)
	}
	if data.DNN != testFullDNN || data.SNSSAI == nil || data.SNSSAI.SST != 1 || data.SNSSAI.SD != "000001" {
		t.Errorf("dnn/sNssai = %q %+v", data.DNN, data.SNSSAI)
	}
	if data.ServingNetwork == nil || data.ServingNetwork.MCC != "001" || data.ServingNetwork.MNC != "01" {
		t.Errorf("servingNetwork = %+v", data.ServingNetwork)
	}
	if data.VsmfID != f.s.cfg.NFInstanceID || !strings.HasPrefix(data.VsmfPduSessionURI, "https://smf.5gc.mnc001.mcc001.3gppnetwork.org:8004/nsmf-pdusession/v1/vsmf-pdu-sessions/") {
		t.Errorf("vsmfId/vsmfPduSessionUri = %q %q", data.VsmfID, data.VsmfPduSessionURI)
	}
	if data.AnType != "3GPP_ACCESS" || data.RequestType != "INITIAL_REQUEST" || !chargingIDRe.MatchString(data.ChargingID) {
		t.Errorf("anType/requestType/chargingId = %q %q %q", data.AnType, data.RequestType, data.ChargingID)
	}
	if data.MaxIntegrityProtectedDataRateUl != "MAX_UE_RATE" || data.MaxIntegrityProtectedDataRateDl != "MAX_UE_RATE" {
		t.Errorf("max integrity protected data rate = %q/%q", data.MaxIntegrityProtectedDataRateUl, data.MaxIntegrityProtectedDataRateDl)
	}
	if data.N1SmInfoFromUe == nil || !bytes.Equal(mp.Parts[data.N1SmInfoFromUe.ContentID], []byte{0x91, 0xA1}) {
		t.Errorf("n1SmInfoFromUe = %+v parts=%v", data.N1SmInfoFromUe, mp.Parts)
	}

	// V-UPF N4 Establishment: N3 UL F-TEID and N9 DL F-TEID; vcnTunnelInfo = the N9 endpoint.
	if est, mod, del := f.upf.counts(); est != 1 || mod != 1 || del != 0 {
		t.Fatalf("V-UPF est/mod/del = %d/%d/%d", est, mod, del)
	}
	vcn, err := parseHRTunnel(data.VcnTunnelInfo)
	if err != nil || !vcn.IP.Equal(net.ParseIP("10.0.0.9")) {
		t.Errorf("vcnTunnelInfo = %+v err=%v, want the upf_n9_addr", data.VcnTunnelInfo, err)
	}
	checkVSMFEstablishment(t, f.upf.estAt(0), vcn.TEID)

	// Step 13a: Update FAR 2 = FORW + OHC to hcnTunnelInfo.
	mod := f.upf.modAt(0)
	if len(mod.UpdateFAR) != 1 {
		t.Fatalf("Update FARs = %d", len(mod.UpdateFAR))
	}
	uf, _ := mod.UpdateFAR[0].UpdateFAR()
	if id, _ := hrChild(t, uf, pfcpie.FARID).FARID(); id != ulFARID {
		t.Errorf("Update FAR id = %d, want UL FAR %d", id, ulFARID)
	}
	if aa, _ := hrChild(t, uf, pfcpie.ApplyAction).ApplyAction(); aa != 0x02 {
		t.Errorf("apply action = %#x, want FORW", aa)
	}
	upd, _ := hrChild(t, uf, pfcpie.UpdateForwardingParameters).UpdateForwardingParameters()
	dst, _ := hrChild(t, upd, pfcpie.DestinationInterface).DestinationInterface()
	ohc, err := hrChild(t, upd, pfcpie.OuterHeaderCreation).OuterHeaderCreation()
	if err != nil || ohc.TEID != 0xCAFE || ohc.IPv4Address.String() != "10.0.0.99" || dst != pfcpie.DstInterfaceCore {
		t.Errorf("UL FAR update: ohc=%+v err=%v dst=%d", ohc, err, dst)
	}

	// N1 Accept body: H-SMF qosRules unchanged, UE IP, requested DNN, S-NSSAI.
	if n1[0] != (nas.SSCMode1<<4)|nas.PDUSessionTypeIPv4 {
		t.Errorf("selected type/SSC octet = %#x", n1[0])
	}
	ln := int(n1[1])<<8 | int(n1[2])
	if !bytes.Equal(n1[3:3+ln], testQoSRules) {
		t.Errorf("qosRules = %x, want %x unchanged", n1[3:3+ln], testQoSRules)
	}
	rest := n1[3+ln:]
	if !bytes.Contains(rest, []byte{0x29, 0x05, 0x01, 10, 60, 0, 2}) {
		t.Errorf("PDU address IE with 10.60.0.2 missing in %x", rest)
	}
	if !bytes.Contains(rest, []byte{0x25, 9, 8, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't'}) {
		t.Errorf("DNN IE (requested DNN, no operator id) missing in %x", rest)
	}
	if !bytes.Contains(rest, []byte{0x22, 4, 1, 0, 0, 1}) {
		t.Errorf("S-NSSAI IE (VPLMN value) missing in %x", rest)
	}

	// N2: UL NG-U = V-UPF N3 F-TEID (upf_n3_addr, session ULTEID), 5QI/AMBR from the H-SMF.
	var tr ngapType.PDUSessionResourceSetupRequestTransfer
	if err := aper.UnmarshalWithParams(n2, &tr, "valueExt"); err != nil {
		t.Fatalf("decode N2 transfer: %v", err)
	}
	f.s.sessionMu.Lock()
	sess := f.s.sessions[resp.SMContextRef]
	f.s.sessionMu.Unlock()
	if sess == nil || sess.HR == nil || sess.HR.Role != HRRoleVSMF || sess.State != "ACTIVE" {
		t.Fatalf("session = %+v", sess)
	}
	var sawTunnel bool
	for _, ie := range tr.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDULNGUUPTNLInformation {
			g := ie.Value.ULNGUUPTNLInformation.GTPTunnel
			sawTunnel = net.IP(g.TransportLayerAddress.Value.Bytes).Equal(net.ParseIP("10.0.0.1")) &&
				binary.BigEndian.Uint32(g.GTPTEID.Value) == sess.ULTEID
		}
	}
	if !sawTunnel {
		t.Error("N2 UL NG-U tunnel is not the V-UPF N3 F-TEID")
	}
	if sess.HR.HSmfPduSessionRef != testHSMFRoot+testHRefPath || sess.HR.PeerTunnel.TEID != 0xCAFE ||
		sess.UEIP != nil || !sess.HR.UEIPv4.Equal(net.ParseIP("10.60.0.2")) || sess.FiveQI != 8 || sess.AMBRDLKbps != 200000 {
		t.Errorf("HR session = %+v / %+v", sess, sess.HR)
	}
	for _, want := range []string{`"procedure":"HomeRoutedPduSession"`, `"smf_role":"V-SMF"`, `"interface":"N16"`, `"interface":"N4"`, `"spec_ref"`} {
		if !strings.Contains(f.logs.String(), want) {
			t.Errorf("log lacks %s", want)
		}
	}
}

// checkVSMFEstablishment asserts the V-UPF rule layout of HomeRoutedPduSession.md §4.
func checkVSMFEstablishment(t *testing.T, req *pfcpmsg.SessionEstablishmentRequest, n9TEID uint32) {
	t.Helper()
	if len(req.CreatePDR) != 2 || len(req.CreateFAR) != 2 {
		t.Fatalf("PDRs=%d FARs=%d", len(req.CreatePDR), len(req.CreateFAR))
	}
	for i, tc := range []struct {
		src   uint8
		addr  string
		label string
	}{
		{pfcpie.SrcInterfaceAccess, "10.0.0.1", "UL"},
		{pfcpie.SrcInterfaceCore, "10.0.0.9", "DL"},
	} {
		pdr, _ := req.CreatePDR[i].CreatePDR()
		pdi, _ := hrChild(t, pdr, pfcpie.PDI).PDI()
		src, _ := hrChild(t, pdi, pfcpie.SourceInterface).SourceInterface()
		ft, err := hrChild(t, pdi, pfcpie.FTEID).FTEID()
		if err != nil || src != tc.src || ft.IPv4Address.String() != tc.addr || ft.TEID == 0 {
			t.Errorf("%s PDR: src=%d fteid=%+v err=%v", tc.label, src, ft, err)
		}
		if hrChild(t, pdi, pfcpie.UEIPAddress) != nil || hrChild(t, pdi, pfcpie.NetworkInstance) != nil {
			t.Errorf("%s PDR carries a UE IP / network instance", tc.label)
		}
		if hrChild(t, pdr, pfcpie.OuterHeaderRemoval) == nil {
			t.Errorf("%s PDR lacks Outer Header Removal", tc.label)
		}
		if i == 1 && ft != nil && ft.TEID != n9TEID {
			t.Errorf("DL PDR TEID %d != vcnTunnelInfo TEID %d", ft.TEID, n9TEID)
		}
	}
	for _, far := range req.CreateFAR {
		ies, _ := far.CreateFAR()
		id, _ := hrChild(t, ies, pfcpie.FARID).FARID()
		fp, _ := hrChild(t, ies, pfcpie.ForwardingParameters).ForwardingParameters()
		dst, _ := hrChild(t, fp, pfcpie.DestinationInterface).DestinationInterface()
		if hrChild(t, fp, pfcpie.OuterHeaderCreation) != nil {
			t.Errorf("FAR %d carries an OHC at establishment", id)
		}
		want := pfcpie.DstInterfaceAccess
		if id == ulFARID {
			want = pfcpie.DstInterfaceCore
		}
		if dst != want {
			t.Errorf("FAR %d destination = %d, want %d", id, dst, want)
		}
	}
}

// Error mapping ---------------------------------------------------------------------------------

func problemBody(status int, cause string) []byte {
	b, _ := json.Marshal(map[string]any{"status": status, "cause": cause})
	return b
}

func createErrorBody(status int, cause, n1sm string) []byte {
	m := map[string]any{"error": map[string]any{"status": status, "cause": cause}}
	if n1sm != "" {
		m["n1smCause"] = n1sm
	}
	b, _ := json.Marshal(m)
	return b
}

func TestVSMFCreate_ErrorMapping(t *testing.T) {
	respond := func(status int, body []byte) func(http.ResponseWriter, *http.Request, seppRecord) {
		return func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
			if strings.HasSuffix(rec.Path, "/release") {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}
	}
	tests := []struct {
		name        string
		h           func(http.ResponseWriter, *http.Request, seppRecord)
		timeout     time.Duration
		closeSEPP   bool
		wantCause   uint8
		wantRelease bool // an N16 release POST is expected after the create
	}{
		{"n1smCause relayed (#27)", respond(403, createErrorBody(403, "DNN_DENIED", "1B")), 0, false, 27, false},
		{"n1smCause relayed over fallback (#67)", respond(403, createErrorBody(403, "SNSSAI_DENIED", "43")), 0, false, 67, false},
		{"no n1smCause N1_SM_ERROR (#111)", respond(403, createErrorBody(403, "N1_SM_ERROR", "")), 0, false, 111, false},
		{"no n1smCause DNN_DENIED (#27)", respond(403, createErrorBody(403, "DNN_DENIED", "")), 0, false, 27, false},
		{"no n1smCause SNSSAI_DENIED (#33)", respond(403, createErrorBody(403, "SNSSAI_DENIED", "")), 0, false, 33, false},
		{"no n1smCause SYSTEM_FAILURE (#26)", respond(500, createErrorBody(500, "SYSTEM_FAILURE", "")), 0, false, 26, false},
		{"no n1smCause pool exhausted (#67)", respond(500, createErrorBody(500, "INSUFFICIENT_RESOURCES_SLICE_DNN", "")), 0, false, 67, false},
		{"no n1smCause NOT_SUPPORTED_WITH_ISMF (#38)", respond(403, createErrorBody(403, "NOT_SUPPORTED_WITH_ISMF", "")), 0, false, 38, false},
		{"bad n1smCause falls back", respond(403, createErrorBody(403, "DNN_DENIED", "ZZ")), 0, false, 27, false},
		{"SEPP plain ProblemDetails 504 (#38)", respond(504, problemBody(504, "TARGET_NF_NOT_REACHABLE")), 0, false, 38, false},
		{"SEPP 500 empty body (#38)", respond(500, nil), 0, false, 38, false},
		{"SEPP 500 plain SYSTEM_FAILURE (#38, path failure)", respond(500, problemBody(500, "SYSTEM_FAILURE")), 0, false, 38, false},
		{"SEPP unreachable (#38)", respond(500, nil), 0, true, 38, false},
		{"H-SMF does not answer within the timeout (#38)", func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
			time.Sleep(600 * time.Millisecond)
		}, 150 * time.Millisecond, false, 38, false},
		{"201 without hcnTunnelInfo (#38 + release)", answerCreated(createdJSON(func(m map[string]any) { delete(m, "hcnTunnelInfo") }), testHRefPath), 0, false, 38, true},
		{"201 without sscMode (#38 + release)", answerCreated(createdJSON(func(m map[string]any) { delete(m, "sscMode") }), testHRefPath), 0, false, 38, true},
		{"201 without UE address (#38 + release)", answerCreated(createdJSON(func(m map[string]any) { delete(m, "ueIpv4Address") }), testHRefPath), 0, false, 38, true},
		{"201 without Location (#38)", answerCreated(createdJSON(nil), ""), 0, false, 38, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newVSMFFixture(t, tc.h)
			if tc.timeout > 0 {
				f.s.n16Timeout = tc.timeout
			}
			if tc.closeSEPP {
				f.sepp.srv.Close()
			}
			w := f.createSMContext(t, smContextCreateData(nil))
			if w.Code < 400 {
				t.Fatalf("status = %d, want an error: %s", w.Code, w.Body.String())
			}
			var body struct {
				Error   map[string]any `json:"error"`
				N1SmMsg string         `json:"n1SmMsg"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("SmContextCreateError: %v: %s", err, w.Body.String())
			}
			n1, _ := base64.StdEncoding.DecodeString(body.N1SmMsg)
			want := []byte{nas.PDGroupSessionManagement, testPSI, testPTI, byte(nas.MsgTypePDUSessionEstablishmentReject), tc.wantCause}
			if !bytes.Equal(n1, want) {
				t.Errorf("REJECT = %x, want %x", n1, want)
			}
			if _, _, del := f.upf.counts(); del != 1 {
				t.Errorf("V-UPF deletions = %d, want 1", del)
			}
			if f.sessionCount() != 0 {
				t.Errorf("session left behind: %d", f.sessionCount())
			}
			if !tc.closeSEPP {
				rel := 0
				for _, r := range f.sepp.records() {
					if strings.HasSuffix(r.Path, "/release") {
						rel++
					}
				}
				if tc.wantRelease && rel != 1 || !tc.wantRelease && rel != 0 {
					t.Errorf("N16 release requests = %d, want release=%v", rel, tc.wantRelease)
				}
			}
			if !strings.Contains(f.logs.String(), `"smf_role":"V-SMF"`) || !strings.Contains(f.logs.String(), `"result":"`) {
				t.Errorf("rejection not logged canonically: %s", f.logs.String())
			}
		})
	}
}

func TestVSMFCreate_FailureLogsN16(t *testing.T) {
	f := newVSMFFixture(t, func(w http.ResponseWriter, r *http.Request, rec seppRecord) { w.WriteHeader(500) })
	f.createSMContext(t, smContextCreateData(nil))
	out := f.logs.String()
	if !strings.Contains(out, `"interface":"N16"`) || !strings.Contains(out, `"result":"FAILURE"`) {
		t.Errorf("no N16 FAILURE log: %s", out)
	}
}

func TestVSMFCreate_N4EstablishmentRejected(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	f.upf.setCauses(pfcpie.CauseRequestRejected, pfcpie.CauseRequestAccepted)
	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code < 400 {
		t.Fatalf("status = %d", w.Code)
	}
	var body struct {
		N1SmMsg string `json:"n1SmMsg"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	n1, _ := base64.StdEncoding.DecodeString(body.N1SmMsg)
	if len(n1) != 5 || n1[4] != 26 {
		t.Errorf("REJECT = %x, want cause 26", n1)
	}
	if len(f.sepp.records()) != 0 {
		t.Error("N16 call after a V-UPF N4 rejection")
	}
	if f.sessionCount() != 0 {
		t.Error("session left behind")
	}
}

func TestVSMFCreate_ULFARUpdateRejected(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	f.upf.setCauses(pfcpie.CauseRequestAccepted, pfcpie.CauseRequestRejected)
	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code < 400 {
		t.Fatalf("status = %d", w.Code)
	}
	rel := 0
	for _, r := range f.sepp.records() {
		if strings.HasSuffix(r.Path, "/release") {
			rel++
		}
	}
	if rel != 1 {
		t.Errorf("H-SMF release requests = %d, want 1", rel)
	}
	if _, _, del := f.upf.counts(); del != 1 {
		t.Errorf("V-UPF deletions = %d", del)
	}
}

func TestVSMFCreate_NoSEPPConfigured(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	f.s.cfg.Peers.SEPP = ""
	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code < 400 || len(f.sepp.records()) != 0 {
		t.Fatalf("status=%d requests=%d", w.Code, len(f.sepp.records()))
	}
	if est, _, _ := f.upf.counts(); est != 0 {
		t.Error("N4 session created without a SEPP")
	}
}

// Without hSmfUri the non-roaming path runs: no SEPP traffic, local IP allocation.
func TestVSMFCreate_NoHSmfURIIsNonRoaming(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	m := smContextCreateData(func(m map[string]any) {
		delete(m, "hSmfUri")
		delete(m, "hplmnSnssai")
		m["dnn"] = "internet"
	})
	w := f.createSMContext(t, m)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if len(f.sepp.records()) != 0 {
		t.Error("non-roaming request reached the SEPP")
	}
	f.s.sessionMu.Lock()
	defer f.s.sessionMu.Unlock()
	for _, s := range f.s.sessions {
		if s.HR != nil {
			t.Error("non-roaming session carries HR state")
		}
	}
}

// Release ---------------------------------------------------------------------------------------

func establishedVSMF(t *testing.T, h func(http.ResponseWriter, *http.Request, seppRecord)) (*vsmfFixture, string) {
	t.Helper()
	f := newVSMFFixture(t, h)
	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	r, _, _ := decodeCreateResp(t, w)
	return f, r.SMContextRef
}

func TestVSMFRelease_N16ThenN4(t *testing.T) {
	f, ref := establishedVSMF(t, answerCreated(createdJSON(nil), testHRefPath))
	w := f.deleteSMContext(ref)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	recs := f.sepp.records()
	if len(recs) != 2 {
		t.Fatalf("SEPP requests = %d", len(recs))
	}
	rel := recs[1]
	if rel.Method != http.MethodPost || rel.Path != testHRefPath+"/release" || rel.Host != f.sepp.addr() {
		t.Errorf("release = %s %s host %s", rel.Method, rel.Path, rel.Host)
	}
	if got := rel.Header.Get("3gpp-Sbi-Target-apiRoot"); got != testHSMFRoot {
		t.Errorf("target-apiRoot = %q", got)
	}
	var rd ReleaseData
	if err := json.Unmarshal(rel.Body, &rd); err != nil {
		t.Errorf("ReleaseData: %v", err)
	}
	if _, _, del := f.upf.counts(); del != 1 {
		t.Errorf("V-UPF deletions = %d", del)
	}
	if f.sessionCount() != 0 {
		t.Error("session not removed")
	}
}

func TestVSMFRelease_N16FailureStillCleansUp(t *testing.T) {
	for name, sepp5xx := range map[string]bool{"5xx": true, "timeout": false} {
		t.Run(name, func(t *testing.T) {
			var fail bool
			var mu sync.Mutex
			f, ref := establishedVSMF(t, func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
				mu.Lock()
				f := fail
				mu.Unlock()
				if strings.HasSuffix(rec.Path, "/release") && f {
					if sepp5xx {
						w.WriteHeader(http.StatusBadGateway)
					} else {
						time.Sleep(600 * time.Millisecond)
					}
					return
				}
				answerCreated(createdJSON(nil), testHRefPath)(w, r, rec)
			})
			mu.Lock()
			fail = true
			mu.Unlock()
			f.s.n16Timeout = 150 * time.Millisecond
			w := f.deleteSMContext(ref)
			if w.Code != http.StatusNoContent {
				t.Fatalf("status = %d", w.Code)
			}
			if _, _, del := f.upf.counts(); del != 1 {
				t.Errorf("V-UPF deletions = %d, want 1", del)
			}
			if f.sessionCount() != 0 {
				t.Error("session not removed")
			}
			if !strings.Contains(f.logs.String(), `"msg":"hsmf_release_failed"`) || !strings.Contains(f.logs.String(), `"level":"WARN"`) {
				t.Errorf("no WARN hsmf_release_failed: %s", f.logs.String())
			}
		})
	}
}

// Replacing an existing HR session for the same PSI releases it over N16 first.
func TestVSMFCreate_StaleHRSessionReleasedOverN16(t *testing.T) {
	f, _ := establishedVSMF(t, answerCreated(createdJSON(nil), testHRefPath))
	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("second create: %d", w.Code)
	}
	rel := 0
	for _, r := range f.sepp.records() {
		if strings.HasSuffix(r.Path, "/release") {
			rel++
		}
	}
	if rel != 1 {
		t.Errorf("release requests = %d, want 1 (stale session)", rel)
	}
}

// Golden ----------------------------------------------------------------------------------------

// TestVSMFPduSessionCreateDataGolden freezes the PostPduSessions JSON of a fixed HR session.
// Regenerate deliberately with UPDATE_GOLDEN=1 after a reviewed wire change.
func TestVSMFPduSessionCreateDataGolden(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	f.s.cfg.NFInstanceID = "00000000-0000-4005-8000-0000000000aa"
	sess := &Session{SUPI: "imsi-001020000000001", PDUSessionID: 5, HR: &HRSession{
		HplmnSnssai: SliceID{SST: 1, SD: "000001"}, ChargingID: "4242", N9DLTEID: 0xABCD}}
	in := &vsmfCreateIn{
		req: map[string]interface{}{"anType": "3GPP_ACCESS", "ratType": "NR"}, dnn: testFullDNN,
		n1SmMsg: n1EstRequest(), pduReq: &nas.PDUSessionEstablishmentRequest{IntegrityProtectionMaxDataRate: [2]byte{0xFF, 0x00}},
	}
	d := f.s.buildPduSessionCreateData(sess, in, "fixed-ref")
	d.N1SmInfoFromUe = &HRRefToBinaryData{ContentID: partNameN1Ue}
	got, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "golden_hr_pdusessioncreatedata.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want := readGolden(t, "golden_hr_pdusessioncreatedata.json")
	if !bytes.Equal(got, want) {
		t.Errorf("PduSessionCreateData changed:\n got: %s\nwant: %s", got, want)
	}
}

// TestVSMFEstablishmentRequestGolden freezes the V-UPF PFCP Session Establishment bytes of a fixed session.
func TestVSMFEstablishmentRequestGolden(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	f.s.cfg.N4.VolumeThresholdBytes, f.s.cfg.N4.MeasurementPeriodSeconds = 1000000, 60
	sess := &Session{SEID: 77, ULTEID: 0x11, HR: &HRSession{Role: HRRoleVSMF, N9DLTEID: 0x22}}
	req, err := f.s.buildVSMFEstablishmentRequest(sess, 9)
	if err != nil {
		t.Fatal(err)
	}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got := []byte(hex.EncodeToString(b) + "\n")
	path := filepath.Join("testdata", "golden_hr_vupf_establishment.hex")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want := readGolden(t, "golden_hr_vupf_establishment.hex"); !bytes.Equal(got, want) {
		t.Errorf("V-UPF establishment bytes changed:\n got: %s\nwant: %s", got, want)
	}
}

// End to end -------------------------------------------------------------------------------------

// TestHomeRouted_VSMFToHSMF runs both roles of this package against each other: the V-SMF talks to a
// mock SEPP that passes every request straight into the H-SMF handler.
func TestHomeRouted_VSMFToHSMF(t *testing.T) {
	// Home side: H-SMF with its own H-UPF stub, home UDM and IP pool.
	home := newHRFixture(t, udmSubscribed)
	hupf := home.upf
	home.s.cfg.UPFN9Addr = "10.0.1.9"
	// The H-SMF builds its Location from sbi.fqdn + port: it must name the hSmfUri authority.
	home.s.cfg.SBI.Address, home.s.cfg.SBI.FQDN = ":8004", "smf.5gc.mnc002.mcc001.3gppnetwork.org"
	home.s.cfg.PLMN.MCC, home.s.cfg.PLMN.MNC = "001", "02"
	var viaSEPP []string
	var mu sync.Mutex
	f := newVSMFFixture(t, func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
		mu.Lock()
		viaSEPP = append(viaSEPP, rec.Method+" "+rec.Path+" -> "+rec.Header.Get("3gpp-Sbi-Target-apiRoot"))
		mu.Unlock()
		home.s.httpSrv.Handler.ServeHTTP(w, r)
	})

	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	resp, n1, _ := decodeCreateResp(t, w)

	// The UE address comes from the H-SMF pool; the qosRules are the H-SMF's octets, unchanged.
	if !bytes.Contains(n1, []byte{0x29, 0x05, 0x01, 10, 60, 0}) {
		t.Errorf("Accept lacks an H-SMF pool UE address: %x", n1)
	}
	if want := nas.BuildDefaultQoSRules(1); !bytes.Contains(n1, want) {
		t.Errorf("Accept lacks the H-SMF qosRules %x: %x", want, n1)
	}
	if est := hupf.establishments(); len(est) != 1 {
		t.Fatalf("H-UPF establishments = %d", len(est))
	}
	// V-UPF UL FAR OHC = H-UPF N9 endpoint (H-SMF UL TEID); H-UPF DL FAR OHC = V-UPF N9 DL endpoint.
	f.s.sessionMu.Lock()
	vs := f.s.sessions[resp.SMContextRef]
	f.s.sessionMu.Unlock()
	if vs == nil || vs.HR.PeerTunnel.IP.String() != "10.0.1.9" || vs.HR.PeerTunnel.TEID == 0 {
		t.Fatalf("V-SMF peer tunnel = %+v", vs.HR)
	}
	var hs *Session
	home.s.sessionMu.Lock()
	for _, x := range home.s.sessions {
		hs = x
	}
	home.s.sessionMu.Unlock()
	if hs == nil || hs.HR.Role != HRRoleHSMF || hs.ULTEID != vs.HR.PeerTunnel.TEID {
		t.Fatalf("H-SMF session = %+v", hs)
	}
	if hs.HR.PeerTunnel.TEID != vs.HR.N9DLTEID || hs.HR.PeerTunnel.IP.String() != "10.0.0.9" {
		t.Errorf("H-SMF vcn = %+v, want V-UPF N9 10.0.0.9/%d", hs.HR.PeerTunnel, vs.HR.N9DLTEID)
	}
	if hs.HR.ChargingID != vs.HR.ChargingID {
		t.Errorf("chargingId %q vs %q", hs.HR.ChargingID, vs.HR.ChargingID)
	}

	// Release: V-SMF -> SEPP -> H-SMF; both N4 sessions deleted, both session tables empty.
	if w := f.deleteSMContext(resp.SMContextRef); w.Code != http.StatusNoContent {
		t.Fatalf("release: %d", w.Code)
	}
	if hupf.deletionCount() != 1 {
		t.Errorf("H-UPF deletions = %d", hupf.deletionCount())
	}
	if _, _, del := f.upf.counts(); del != 1 {
		t.Errorf("V-UPF deletions = %d", del)
	}
	home.s.sessionMu.Lock()
	left := len(home.s.sessions)
	home.s.sessionMu.Unlock()
	if left != 0 || f.sessionCount() != 0 {
		t.Errorf("sessions left: H=%d V=%d", left, f.sessionCount())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(viaSEPP) != 2 || !strings.HasSuffix(viaSEPP[1], "/release -> "+testHSMFRoot) {
		t.Errorf("SEPP traffic = %v", viaSEPP)
	}
}
