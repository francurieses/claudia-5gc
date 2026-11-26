package server

// hr_hsmf_test.go — H-SMF role of the home-routed PDU session (ROAM-002 phase 1): body validation,
// the H-UPF PFCP rule set, error mapping, release and the NRF profile with/without sbi.fqdn.
// Behaviour contract: tests/features/home_routed_pdu_session.feature (@hsmf, @legacy).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/nrf"
)

// hrFakeUPF is a PFCP stub H-UPF answering Session Establishment and Deletion.
type hrFakeUPF struct {
	conn *net.UDPConn

	mu         sync.Mutex
	estCause   uint8
	silent     bool
	est        []*pfcpmsg.SessionEstablishmentRequest
	deletions  int
	delCause   uint8
	deleteSEID []uint64
}

func newHRFakeUPF(t *testing.T) *hrFakeUPF {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen fake H-UPF: %v", err)
	}
	f := &hrFakeUPF{conn: conn, estCause: pfcpie.CauseRequestAccepted, delCause: pfcpie.CauseRequestAccepted}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 8192)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, err := pfcpmsg.Parse(buf[:n])
			if err != nil {
				continue
			}
			f.mu.Lock()
			silent, ec, dc := f.silent, f.estCause, f.delCause
			f.mu.Unlock()
			switch m := msg.(type) {
			case *pfcpmsg.SessionEstablishmentRequest:
				f.mu.Lock()
				f.est = append(f.est, m)
				f.mu.Unlock()
				if silent {
					continue
				}
				rsp := pfcpmsg.NewSessionEstablishmentResponse(0, 0, 1, m.Sequence(), 0,
					pfcpie.NewCause(ec), pfcpie.NewNodeID("", "", "upf"))
				if b, err := rsp.Marshal(); err == nil {
					_, _ = conn.WriteToUDP(b, raddr)
				}
			case *pfcpmsg.SessionDeletionRequest:
				f.mu.Lock()
				f.deletions++
				f.deleteSEID = append(f.deleteSEID, m.SEID())
				f.mu.Unlock()
				rsp := pfcpmsg.NewSessionDeletionResponse(0, 0, m.SEID(), m.Sequence(), 0, pfcpie.NewCause(dc))
				if b, err := rsp.Marshal(); err == nil {
					_, _ = conn.WriteToUDP(b, raddr)
				}
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return f
}

func (f *hrFakeUPF) establishments() []*pfcpmsg.SessionEstablishmentRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pfcpmsg.SessionEstablishmentRequest(nil), f.est...)
}

func (f *hrFakeUPF) deletionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deletions
}

// hrUDM is a mock home UDM; handler decides per request.
type hrUDM struct {
	srv     *httptest.Server
	mu      sync.Mutex
	queries []string
}

func (u *hrUDM) seen() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.queries...)
}

const hrSmData = `[{"singleNssai":{"sst":1,"sd":"000001"},"dnnConfigurations":{"internet":{"5gQosProfile":{"5qi":8,"arp":{"priorityLevel":5,"preemptCap":"NOT_PREEMPT","preemptVuln":"NOT_PREEMPTABLE"}},"sessionAmbr":{"uplink":"50 Mbps","downlink":"200 Mbps"}}}}]`

// udmSubscribed answers sm-data with hrSmData when the filters match it, [] otherwise.
func udmSubscribed(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	w.Header().Set("Content-Type", "application/json")
	if q.Get("dnn") != "" && q.Get("dnn") != "internet" {
		_, _ = w.Write([]byte("[]"))
		return
	}
	if sn := q.Get("single-nssai"); !strings.Contains(sn, `"sd":"000001"`) {
		_, _ = w.Write([]byte("[]"))
		return
	}
	_, _ = w.Write([]byte(hrSmData))
}

type hrFixture struct {
	s   *Server
	upf *hrFakeUPF
	udm *hrUDM
}

func newHRFixture(t *testing.T, udmHandler http.HandlerFunc) *hrFixture {
	t.Helper()
	upf := newHRFakeUPF(t)
	s := newTestSMFServer(t)
	s.cfg.Peers.UPF = upf.conn.LocalAddr().String()
	s.cfg.UPFN3Addr = "10.0.0.1"
	s.cfg.UPFN9Addr = "10.0.0.9"
	s.cfg.NFInstanceID = "00000000-0000-4005-8000-0000000000aa"
	s.pfcpTimers = pfcpNodeTimers{t1: 200 * time.Millisecond, n1: 1,
		heartbeatInterval: time.Hour, assocRetryInitial: time.Hour, assocRetryMax: time.Hour}
	u := &hrUDM{}
	if udmHandler != nil {
		u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u.mu.Lock()
			u.queries = append(u.queries, r.URL.RawQuery)
			u.mu.Unlock()
			udmHandler(w, r)
		}))
		t.Cleanup(u.srv.Close)
		s.cfg.Peers.UDM = strings.TrimPrefix(u.srv.URL, "https://")
		s.httpClient = u.srv.Client()
	}
	return &hrFixture{s: s, upf: upf, udm: u}
}

// ptype/sscmode IEs of the 5GSM Establishment Request, TS 24.501 §8.3.1 (nibble IEIs 0x9- / 0xA-).
var hrN1SmInfoIPv4 = []byte{0x91, 0xA1}

func validCreateData() map[string]any {
	return map[string]any{
		"supi": "imsi-001020000000001", "pduSessionId": 5, "dnn": "internet.mnc002.mcc001.gprs",
		"sNssai":         map[string]any{"sst": 1, "sd": "000001"},
		"servingNetwork": map[string]any{"mcc": "001", "mnc": "01"}, "anType": "3GPP_ACCESS",
		"vsmfId": "11111111-1111-4111-8111-111111111111", "vsmfPduSessionUri": "https://smf.visited:8004/nsmf-pdusession/v1/vsmf-pdu-sessions/abc",
		"vcnTunnelInfo": map[string]any{"ipv4Addr": "10.1.0.7", "gtpTeid": "0000ABCD"},
		"chargingId":    "42",
	}
}

// post sends a PostPduSessions request; n1 (nil = none) is sent as the binary multipart part.
func (f *hrFixture) post(t *testing.T, data map[string]any, n1 []byte) *httptest.ResponseRecorder {
	t.Helper()
	// The hSEPP inserts the originating PLMN: mirror servingNetwork (TS 29.500 §5.2.3.2.15).
	nid := ""
	if sn, ok := data["servingNetwork"].(map[string]any); ok {
		nid = fmt.Sprintf("%v-%v", sn["mcc"], sn["mnc"])
	}
	return f.postNID(t, data, n1, nid)
}

// postNID is post with an explicit 3gpp-Sbi-Originating-Network-Id ("" = header absent).
func (f *hrFixture) postNID(t *testing.T, data map[string]any, n1 []byte, nid string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	ct := "application/json"
	if n1 != nil {
		data["n1SmInfoFromUe"] = map[string]any{"contentId": "n1SmInfoFromUe"}
		mw := multipart.NewWriter(&body)
		jh := textproto.MIMEHeader{"Content-Type": {"application/json"}}
		jp, _ := mw.CreatePart(jh)
		_ = json.NewEncoder(jp).Encode(data)
		bh := textproto.MIMEHeader{"Content-Type": {"application/vnd.3gpp.5gnas"}, "Content-Id": {"n1SmInfoFromUe"}}
		bp, _ := mw.CreatePart(bh)
		_, _ = bp.Write(n1)
		_ = mw.Close()
		ct = `multipart/related; boundary=` + mw.Boundary() + `; type="application/json"`
	} else {
		_ = json.NewEncoder(&body).Encode(data)
	}
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/pdu-sessions", &body)
	r.Header.Set("Content-Type", ct)
	if nid != "" {
		r.Header.Set(hdrOriginatingNetworkID, nid)
	}
	w := httptest.NewRecorder()
	f.s.handleHsmfCreatePduSession(w, r)
	return w
}

func decodeCreateError(t *testing.T, w *httptest.ResponseRecorder) PduSessionCreateError {
	t.Helper()
	var e PduSessionCreateError
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode PduSessionCreateError: %v: %s", err, w.Body.String())
	}
	return e
}

func hrChild(t *testing.T, parent []*pfcpie.IE, typ uint16) *pfcpie.IE {
	t.Helper()
	for _, x := range parent {
		if x.Type == typ {
			return x
		}
	}
	return nil
}

func TestHSMFCreate_Validation(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(m map[string]any)
		wantCause string
		wantParam string
	}{
		{"missing vcnTunnelInfo", func(m map[string]any) { delete(m, "vcnTunnelInfo") }, causeMandatoryIEMissing, "/vcnTunnelInfo"},
		{"missing vsmfId", func(m map[string]any) { delete(m, "vsmfId") }, causeMandatoryIEMissing, "/vsmfId"},
		{"missing vsmfPduSessionUri", func(m map[string]any) { delete(m, "vsmfPduSessionUri") }, causeMandatoryIEMissing, "/vsmfPduSessionUri"},
		{"missing dnn", func(m map[string]any) { delete(m, "dnn") }, causeMandatoryIEMissing, "/dnn"},
		{"missing servingNetwork", func(m map[string]any) { delete(m, "servingNetwork") }, causeMandatoryIEMissing, "/servingNetwork"},
		{"missing anType", func(m map[string]any) { delete(m, "anType") }, causeMandatoryIEMissing, "/anType"},
		{"missing supi", func(m map[string]any) { delete(m, "supi") }, causeMandatoryIEMissing, "/supi"},
		{"missing sNssai", func(m map[string]any) { delete(m, "sNssai") }, causeMandatoryIEMissing, "/sNssai"},
		{"bad gtpTeid", func(m map[string]any) { m["vcnTunnelInfo"] = map[string]any{"ipv4Addr": "10.1.0.7", "gtpTeid": "XYZ"} }, causeMandatoryIEIncorrect, "/vcnTunnelInfo"},
		{"vcn without ipv4", func(m map[string]any) { m["vcnTunnelInfo"] = map[string]any{"gtpTeid": "0000ABCD"} }, causeMandatoryIEIncorrect, "/vcnTunnelInfo"},
		{"bad chargingId", func(m map[string]any) { m["chargingId"] = "007" }, causeMandatoryIEIncorrect, "/chargingId"},
		{"psi out of range", func(m map[string]any) { m["pduSessionId"] = 16 }, causeMandatoryIEIncorrect, "/pduSessionId"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newHRFixture(t, udmSubscribed)
			m := validCreateData()
			tc.mutate(m)
			w := f.post(t, m, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
			}
			e := decodeCreateError(t, w)
			if e.Error.Cause != tc.wantCause {
				t.Errorf("cause = %q, want %q", e.Error.Cause, tc.wantCause)
			}
			found := false
			for _, p := range e.Error.InvalidParams {
				found = found || p.Param == tc.wantParam
			}
			if !found {
				t.Errorf("invalidParams %+v lack %s", e.Error.InvalidParams, tc.wantParam)
			}
			if got := len(f.upf.establishments()); got != 0 {
				t.Errorf("%d N4 establishments, want none", got)
			}
			if len(f.udm.seen()) != 0 {
				t.Errorf("UDM queried on an invalid request")
			}
			f.s.sessionMu.Lock()
			n := len(f.s.sessions)
			f.s.sessionMu.Unlock()
			if n != 0 {
				t.Errorf("%d sessions stored", n)
			}
		})
	}
	t.Run("undecodable JSON", func(t *testing.T) {
		f := newHRFixture(t, udmSubscribed)
		r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/pdu-sessions", strings.NewReader("{"))
		w := httptest.NewRecorder()
		f.s.handleHsmfCreatePduSession(w, r)
		if w.Code != http.StatusBadRequest || decodeCreateError(t, w).Error.Cause != causeInvalidMsgFormat {
			t.Fatalf("got %d %s", w.Code, w.Body.String())
		}
	})
}

// refFromLocation returns the pduSessionRef of an H-SMF Location header.
func refFromLocation(loc string) string {
	return loc[strings.LastIndex(loc, "/")+1:]
}

func TestHSMFCreate_HappyPath(t *testing.T) {
	f := newHRFixture(t, udmSubscribed)
	w := f.post(t, validCreateData(), hrN1SmInfoIPv4)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://example.com/nsmf-pdusession/v1/pdu-sessions/") { // absolute URI, request Host (no sbi.fqdn)
		t.Fatalf("Location = %q", loc)
	}
	ref := refFromLocation(loc)

	var got PduSessionCreatedData
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.UeIPv4Address == "" || !strings.HasPrefix(got.UeIPv4Address, "10.60.0.") {
		t.Errorf("ueIpv4Address = %q, want from the H-SMF pool", got.UeIPv4Address)
	}
	if got.PduSessionType != "IPV4" || got.SscMode != "SSC_MODE_1" {
		t.Errorf("type/ssc = %q/%q", got.PduSessionType, got.SscMode)
	}
	if got.HcnTunnelInfo == nil || got.HcnTunnelInfo.IPv4Addr != "10.0.0.9" || len(got.HcnTunnelInfo.GtpTeid) != 8 {
		t.Errorf("hcnTunnelInfo = %+v", got.HcnTunnelInfo)
	}
	// subscribed AMBR 50/200 Mbps wins over the operator default (no PCF configured).
	if got.SessionAmbr == nil || got.SessionAmbr.Uplink != "50000 Kbps" || got.SessionAmbr.Downlink != "200000 Kbps" {
		t.Errorf("sessionAmbr = %+v", got.SessionAmbr)
	}
	if len(got.QosFlowsSetupList) != 1 {
		t.Fatalf("qosFlowsSetupList = %+v", got.QosFlowsSetupList)
	}
	item := got.QosFlowsSetupList[0]
	rules, err := base64.StdEncoding.DecodeString(item.QosRules)
	if err != nil || !bytes.Equal(rules, nas.BuildDefaultQoSRules(1)) {
		t.Errorf("qosRules = %x, want the TS 24.501 §9.11.4.13 default rule %x", rules, nas.BuildDefaultQoSRules(1))
	}
	if item.QFI != 1 || !item.DefaultQosRuleInd || item.QosFlowProfile == nil || item.QosFlowProfile.FiveQI != 8 {
		t.Errorf("qos flow item = %+v", item)
	}
	if got.HSmfInstanceID == "" {
		t.Error("hSmfInstanceId missing")
	}

	// sm-data lookup: own UDM, Operator Identifier stripped, HPLMN S-NSSAI.
	qs := f.udm.seen()
	if len(qs) == 0 || !strings.Contains(qs[0], "dnn=internet&") && !strings.HasSuffix(qs[0], "dnn=internet") {
		t.Errorf("UDM query %v lacks the stripped dnn", qs)
	}
	if len(qs) == 0 || !strings.Contains(qs[0], "single-nssai=") {
		t.Errorf("UDM query %v lacks the HPLMN S-NSSAI", qs)
	}

	// Session model.
	f.s.sessionMu.Lock()
	sess := f.s.sessions[ref]
	f.s.sessionMu.Unlock()
	if sess == nil || sess.HR == nil || sess.HR.Role != HRRoleHSMF || sess.State != "ACTIVE" {
		t.Fatalf("session = %+v", sess)
	}
	if sess.HR.PeerTunnel.TEID != 0xABCD || sess.HR.PeerTunnel.IP.String() != "10.1.0.7" || sess.HR.ChargingID != "42" {
		t.Errorf("HR fields = %+v", sess.HR)
	}

	// H-UPF rules.
	reqs := f.upf.establishments()
	if len(reqs) != 1 {
		t.Fatalf("%d establishments", len(reqs))
	}
	checkHSMFRules(t, reqs[0], sess)
}

// checkHSMFRules asserts the H-UPF rule layout of docs/procedures/HomeRoutedPduSession.md §4.
func checkHSMFRules(t *testing.T, req *pfcpmsg.SessionEstablishmentRequest, sess *Session) {
	t.Helper()
	if len(req.CreatePDR) != 2 || len(req.CreateFAR) != 2 {
		t.Fatalf("PDRs=%d FARs=%d", len(req.CreatePDR), len(req.CreateFAR))
	}
	// UL PDR.
	ul, _ := req.CreatePDR[0].CreatePDR()
	pdi, _ := hrChild(t, ul, pfcpie.PDI).PDI()
	if si, _ := hrChild(t, pdi, pfcpie.SourceInterface).SourceInterface(); si != pfcpie.SrcInterfaceAccess {
		t.Errorf("UL PDR Source Interface = %d, want Access (0)", si)
	}
	ft, err := hrChild(t, pdi, pfcpie.FTEID).FTEID()
	if err != nil || ft.TEID != sess.ULTEID || ft.IPv4Address.String() != "10.0.0.9" {
		t.Errorf("UL PDR F-TEID = %+v err=%v, want N9 10.0.0.9 teid %d", ft, err, sess.ULTEID)
	}
	if hrChild(t, pdi, pfcpie.NetworkInstance) == nil || hrChild(t, ul, pfcpie.OuterHeaderRemoval) == nil {
		t.Error("UL PDR lacks Network Instance / Outer Header Removal")
	}
	// DL PDR.
	dl, _ := req.CreatePDR[1].CreatePDR()
	dpdi, _ := hrChild(t, dl, pfcpie.PDI).PDI()
	if si, _ := hrChild(t, dpdi, pfcpie.SourceInterface).SourceInterface(); si != pfcpie.SrcInterfaceCore {
		t.Errorf("DL PDR Source Interface = %d, want Core (1)", si)
	}
	if hrChild(t, dpdi, pfcpie.FTEID) != nil {
		t.Error("DL PDR must match on the UE IP, not an F-TEID")
	}
	// DL FAR: FORW + OHC to vcnTunnelInfo, no BAR.
	var dlFAR, ulFAR []*pfcpie.IE
	for _, far := range req.CreateFAR {
		ies, _ := far.CreateFAR()
		id, _ := hrChild(t, ies, pfcpie.FARID).FARID()
		switch id {
		case dlFARID:
			dlFAR = ies
		case ulFARID:
			ulFAR = ies
		}
	}
	aa, _ := hrChild(t, dlFAR, pfcpie.ApplyAction).ApplyAction()
	if aa != 0x02 {
		t.Errorf("DL FAR apply action = %#x, want FORW", aa)
	}
	fp, _ := hrChild(t, dlFAR, pfcpie.ForwardingParameters).ForwardingParameters()
	if di, _ := hrChild(t, fp, pfcpie.DestinationInterface).DestinationInterface(); di != pfcpie.DstInterfaceAccess {
		t.Errorf("DL FAR destination interface = %d", di)
	}
	ohc, err := hrChild(t, fp, pfcpie.OuterHeaderCreation).OuterHeaderCreation()
	if err != nil || ohc.TEID != 0xABCD || ohc.IPv4Address.String() != "10.1.0.7" || ohc.OuterHeaderCreationDescription != ohcGTPUUDPIPv4 {
		t.Errorf("DL FAR OHC = %+v err=%v", ohc, err)
	}
	if hrChild(t, dlFAR, pfcpie.BARID) != nil || req.CreateBAR != nil {
		t.Error("H-UPF DL FAR must not carry a BAR")
	}
	ufp, _ := hrChild(t, ulFAR, pfcpie.ForwardingParameters).ForwardingParameters()
	if di, _ := hrChild(t, ufp, pfcpie.DestinationInterface).DestinationInterface(); di != pfcpie.DstInterfaceCore {
		t.Errorf("UL FAR destination interface = %d, want Core (N6)", di)
	}
}

func TestHSMFCreate_N9AddressDefaultsToN3(t *testing.T) {
	f := newHRFixture(t, nil)
	f.s.cfg.UPFN9Addr = ""
	if got := f.s.n9Addr().String(); got != "10.0.0.1" {
		t.Errorf("n9Addr = %s, want the N3 address", got)
	}
}

func TestHSMFCreate_ErrorMapping(t *testing.T) {
	udmStatus := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
	}
	// slice subscribed, other DNN only: DNN_DENIED. No entry for the slice at all: SNSSAI_DENIED.
	otherDNN := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("dnn") != "" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write([]byte(strings.ReplaceAll(hrSmData, `"internet"`, `"ims"`)))
	}
	noSlice := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}

	tests := []struct {
		name       string
		udm        http.HandlerFunc
		upfCause   uint8
		upfSilent  bool
		mutate     func(m map[string]any)
		wantStatus int
		wantCause  string
		wantN1sm   string
	}{
		{name: "DNN not subscribed", udm: otherDNN, wantStatus: 403, wantCause: "DNN_DENIED", wantN1sm: "1B"},
		{name: "S-NSSAI not subscribed", udm: noSlice, wantStatus: 403, wantCause: "SNSSAI_DENIED", wantN1sm: "21"},
		{name: "no sm-data", udm: udmStatus(404), wantStatus: 403, wantCause: "SUBSCRIPTION_DENIED", wantN1sm: "21"},
		{name: "UDM 500 is not swallowed", udm: udmStatus(500), wantStatus: 500, wantCause: "SYSTEM_FAILURE", wantN1sm: "1A"},
		{name: "H-UPF rejects", udm: udmSubscribed, upfCause: pfcpie.CauseRequestRejected, wantStatus: 500, wantCause: "SYSTEM_FAILURE", wantN1sm: "1A"},
		{name: "H-UPF silent is SYSTEM_FAILURE, never UPF_NOT_RESPONDING", udm: udmSubscribed, upfSilent: true, wantStatus: 500, wantCause: "SYSTEM_FAILURE", wantN1sm: "1A"},
		{name: "DNN not served", udm: udmSubscribed, mutate: func(m map[string]any) { m["dnn"] = "private.mnc002.mcc001.gprs" }, wantStatus: 403, wantCause: "DNN_NOT_SUPPORTED", wantN1sm: "1B"},
		{name: "I-SMF pair unsupported", udm: udmSubscribed, mutate: func(m map[string]any) { m["ismfId"] = "x" }, wantStatus: 403, wantCause: "NOT_SUPPORTED_WITH_ISMF", wantN1sm: "26"},
	}
	for _, tc := range tests {
		for _, withN1 := range []bool{true, false} {
			name := tc.name + "/n1SmInfoFromUe"
			if !withN1 {
				name = tc.name + "/no-n1"
			}
			t.Run(name, func(t *testing.T) {
				f := newHRFixture(t, tc.udm)
				if tc.upfCause != 0 {
					f.upf.mu.Lock()
					f.upf.estCause = tc.upfCause
					f.upf.mu.Unlock()
				}
				if tc.upfSilent {
					f.upf.mu.Lock()
					f.upf.silent = true
					f.upf.mu.Unlock()
				}
				m := validCreateData()
				if tc.mutate != nil {
					tc.mutate(m)
				}
				var n1 []byte
				if withN1 {
					n1 = hrN1SmInfoIPv4
				}
				w := f.post(t, m, n1)
				if w.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
				}
				e := decodeCreateError(t, w)
				if e.Error.Cause != tc.wantCause {
					t.Errorf("cause = %q, want %q", e.Error.Cause, tc.wantCause)
				}
				if e.Error.Cause == "UPF_NOT_RESPONDING" {
					t.Error("UPF_NOT_RESPONDING is not allowed on PostPduSessions")
				}
				if withN1 && e.N1smCause != tc.wantN1sm {
					t.Errorf("n1smCause = %q, want %q", e.N1smCause, tc.wantN1sm)
				}
				if !withN1 && e.N1smCause != "" {
					t.Errorf("n1smCause = %q without n1SmInfoFromUe, want none", e.N1smCause)
				}
				// nothing is left behind: no session, the UE IP is back in the pool.
				f.s.sessionMu.Lock()
				n := len(f.s.sessions)
				f.s.sessionMu.Unlock()
				if n != 0 {
					t.Errorf("%d sessions left", n)
				}
				ip, err := f.s.ipPools["internet"].Allocate()
				if err != nil || ip.String() != "10.60.0.2" {
					t.Errorf("first pool address = %v err=%v, want the first pool address 10.60.0.2 (IP leaked)", ip, err)
				}
			})
		}
	}
}

func TestHSMFRelease(t *testing.T) {
	f := newHRFixture(t, udmSubscribed)
	w := f.post(t, validCreateData(), nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	ref := refFromLocation(w.Header().Get("Location"))

	rel := func(ref string, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/pdu-sessions/"+ref+"/release", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(hdrOriginatingNetworkID, "001-01")
		r.SetPathValue("pduSessionRef", ref)
		rw := httptest.NewRecorder()
		f.s.handleHsmfReleasePduSession(rw, r)
		return rw
	}

	t.Run("unknown ref", func(t *testing.T) {
		rw := rel("unknown-ref", "{}")
		if rw.Code != http.StatusNotFound || !strings.Contains(rw.Body.String(), causeContextNotFound) {
			t.Fatalf("got %d %s", rw.Code, rw.Body.String())
		}
	})
	t.Run("non-HR session is not releasable here", func(t *testing.T) {
		f.s.sessionMu.Lock()
		f.s.sessions["plain"] = &Session{SUPI: "imsi-x", DNN: "internet"}
		f.s.sessionMu.Unlock()
		if rw := rel("plain", "{}"); rw.Code != http.StatusNotFound {
			t.Fatalf("got %d", rw.Code)
		}
	})
	t.Run("release", func(t *testing.T) {
		rw := rel(ref, `{"cause":"REL_DUE_TO_HO"}`)
		if rw.Code != http.StatusNoContent {
			t.Fatalf("got %d %s", rw.Code, rw.Body.String())
		}
		if f.upf.deletionCount() != 1 {
			t.Errorf("H-UPF deletions = %d, want 1", f.upf.deletionCount())
		}
		f.s.sessionMu.Lock()
		_, still := f.s.sessions[ref]
		f.s.sessionMu.Unlock()
		if still {
			t.Error("session still present")
		}
		if rw := rel(ref, "{}"); rw.Code != http.StatusNotFound {
			t.Errorf("second release = %d, want 404", rw.Code)
		}
	})
	t.Run("empty body", func(t *testing.T) {
		w := f.post(t, func() map[string]any { m := validCreateData(); m["pduSessionId"] = 6; return m }(), nil)
		ref := refFromLocation(w.Header().Get("Location"))
		if rw := rel(ref, ""); rw.Code != http.StatusNoContent {
			t.Fatalf("got %d", rw.Code)
		}
	})
}

func TestStripDNNOperatorID(t *testing.T) {
	tests := map[string]string{
		"internet.mnc002.mcc001.gprs": "internet",
		"INTERNET.MNC002.MCC001.GPRS": "INTERNET",
		"internet":                    "internet",
		"ims.corp.mnc002.mcc001.gprs": "ims.corp",
		"internet.mnc02.mcc001.gprs":  "internet.mnc02.mcc001.gprs", // MNC must be 3 digits
	}
	for in, want := range tests {
		if got := stripDNNOperatorID(in); got != want {
			t.Errorf("stripDNNOperatorID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSMFNFProfile_FQDN(t *testing.T) {
	cfg := &config.Config{NFInstanceID: "00000000-0000-4005-8000-000000000001"}
	cfg.SBI.Address = "0.0.0.0:8004"
	cfg.PLMN.MCC, cfg.PLMN.MNC = "001", "02"

	base := BuildNFProfile(cfg, nil)
	baseJSON, _ := json.Marshal(base)

	t.Run("empty fqdn is a no-op (byte-identical profile)", func(t *testing.T) {
		p := BuildNFProfile(cfg, nil)
		if err := nrf.ApplyFQDNIdentity(p, cfg.SBI.FQDN, cfg.SBI.Address, cfg.PLMN.MCC, cfg.PLMN.MNC); err != nil {
			t.Fatal(err)
		}
		got, _ := json.Marshal(p)
		if !bytes.Equal(got, baseJSON) || bytes.Contains(got, []byte(`"fqdn"`)) {
			t.Errorf("profile changed:\n%s\n%s", baseJSON, got)
		}
	})
	t.Run("fqdn is advertised with the nsmf-pdusession service", func(t *testing.T) {
		const fqdn = "smf.5gc.mnc002.mcc001.3gppnetwork.org"
		p := BuildNFProfile(cfg, nil)
		if err := nrf.ApplyFQDNIdentity(p, fqdn, cfg.SBI.Address, cfg.PLMN.MCC, cfg.PLMN.MNC); err != nil {
			t.Fatal(err)
		}
		if p.FQDN != fqdn {
			t.Errorf("FQDN = %q", p.FQDN)
		}
		if len(p.NFServices) != 1 || p.NFServices[0].ServiceName != "nsmf-pdusession" {
			t.Errorf("services = %+v", p.NFServices)
		}
	})
	t.Run("invalid fqdn is rejected", func(t *testing.T) {
		p := BuildNFProfile(cfg, nil)
		if err := nrf.ApplyFQDNIdentity(p, "http://bad", cfg.SBI.Address, "001", "02"); err == nil {
			t.Error("want error")
		}
	})
}
