//go:build functional

// godog step definitions for downlink_data_report.feature (SMF-011): PFCP Downlink Data Report
// (DLDR) -> N1N2MessageTransfer. The real SMF runs in-process: its PFCP receiver
// (StartPFCPReceiver) takes Session Report Requests injected by a fake UPF on loopback UDP, the
// real consumer answers them and pages through an httptest TLS AMF; Session Establishment /
// Modification Requests of the SMF are captured by the same fake UPF. Detached work (paging,
// Update FAR DROP) is awaited by polling with a deadline or by WaitHandoverTasks.
// Run with: go test -tags=functional ./nf/smf/...
// Ref: TS 23.502 §4.2.3.3 steps 2a-3c; TS 29.244 §7.5.2.6, §7.5.8.2, §7.5.9, §8.2.21.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cucumber/godog"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

const (
	dldrSUPI    = "imsi-001010000000001"
	dldrRef     = "sm-ctx-dldr-1"
	dldrSEID    = uint64(42)
	dldrWithin  = 6 * time.Second
	dldrGNBTEID = uint32(0x2002)
)

var dldrGNBIP = [4]byte{10, 0, 0, 9}

// ---- fake UPF -----------------------------------------------------------------------------------

// dldrUPF records every PFCP message the SMF sends, answers Session Establishment and
// Modification Requests with Cause 1 and records Session Report Responses.
type dldrUPF struct {
	conn *net.UDPConn
	done chan struct{}

	mu   sync.Mutex
	msgs []pfcpmsg.Message
	seq  uint32
}

func newDLDRUPF() (*dldrUPF, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, fmt.Errorf("listen fake UPF: %w", err)
	}
	u := &dldrUPF{conn: conn, done: make(chan struct{})}
	go u.serve()
	return u, nil
}

func (u *dldrUPF) addr() string { return u.conn.LocalAddr().String() }

func (u *dldrUPF) close() {
	_ = u.conn.Close()
	<-u.done
}

func (u *dldrUPF) serve() {
	defer close(u.done)
	buf := make([]byte, 4096)
	for {
		n, raddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Parse keeps references into its input: give every message its own copy.
		msg, err := pfcpmsg.Parse(append([]byte(nil), buf[:n]...))
		if err != nil {
			continue
		}
		u.mu.Lock()
		u.msgs = append(u.msgs, msg)
		u.mu.Unlock()
		var rsp pfcpmsg.Message
		switch m := msg.(type) {
		case *pfcpmsg.SessionEstablishmentRequest:
			rsp = pfcpmsg.NewSessionEstablishmentResponse(0, 0, 0, m.Sequence(), 0, pfcpie.NewCause(pfcpie.CauseRequestAccepted))
		case *pfcpmsg.SessionModificationRequest:
			rsp = pfcpmsg.NewSessionModificationResponse(0, 0, m.SEID(), m.Sequence(), 0, pfcpie.NewCause(pfcpie.CauseRequestAccepted))
		default:
			continue
		}
		b := make([]byte, rsp.MarshalLen())
		if err := rsp.MarshalTo(b); err == nil {
			_, _ = u.conn.WriteToUDP(b, raddr)
		}
	}
}

// sendSRR injects a Session Report Request with Report Type DLDR towards the SMF receiver and
// returns its sequence number.
func (u *dldrUPF) sendSRR(smf *net.UDPAddr, seid uint64, ies ...*pfcpie.IE) (uint32, error) {
	u.mu.Lock()
	u.seq++
	seq := u.seq
	u.mu.Unlock()
	req := pfcpmsg.NewSessionReportRequest(0, 0, seid, seq, 0,
		append([]*pfcpie.IE{pfcpie.NewReportType(0, 0, 0, 1)}, ies...)...)
	b, err := req.Marshal()
	if err != nil {
		return 0, fmt.Errorf("marshal Session Report Request: %w", err)
	}
	if _, err := u.conn.WriteToUDP(b, smf); err != nil {
		return 0, fmt.Errorf("send Session Report Request: %w", err)
	}
	return seq, nil
}

func (u *dldrUPF) snapshot() []pfcpmsg.Message {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]pfcpmsg.Message(nil), u.msgs...)
}

func (u *dldrUPF) response(seq uint32) *pfcpmsg.SessionReportResponse {
	for _, m := range u.snapshot() {
		if r, ok := m.(*pfcpmsg.SessionReportResponse); ok && r.Sequence() == seq {
			return r
		}
	}
	return nil
}

// ---- recording AMF ------------------------------------------------------------------------------

type dldrAMFCall struct {
	path string
	psi  int
}

type dldrStepAMF struct {
	srv    *httptest.Server
	status atomic.Int32
	cause  atomic.Value // string

	mu    sync.Mutex
	calls []dldrAMFCall
}

func newDLDRStepAMF() *dldrStepAMF {
	a := &dldrStepAMF{}
	a.status.Store(http.StatusAccepted)
	a.cause.Store("")
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body struct {
			PduSessionID int `json:"pduSessionId"`
		}
		_ = json.Unmarshal(b, &body)
		a.mu.Lock()
		a.calls = append(a.calls, dldrAMFCall{path: r.Method + " " + r.URL.Path, psi: body.PduSessionID})
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		st := int(a.status.Load())
		w.WriteHeader(st)
		if st >= 400 {
			_, _ = w.Write([]byte(`{"cause":"` + a.cause.Load().(string) + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"cause":"ATTEMPTING_TO_REACH_UE"}`))
	}))
	return a
}

func (a *dldrStepAMF) snapshot() []dldrAMFCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]dldrAMFCall(nil), a.calls...)
}

// ---- world --------------------------------------------------------------------------------------

type dldrWorld struct {
	upf  *dldrUPF
	amf  *dldrStepAMF
	srv  *Server
	logs *hoLogStore
	sess *Session

	smfAddr *net.UDPAddr
	cancel  context.CancelFunc
	rxDone  chan struct{}
	lastSeq uint32
	estab   *pfcpmsg.SessionEstablishmentRequest
}

func (w *dldrWorld) teardown() {
	if w.sess != nil && w.srv != nil {
		w.srv.clearDLPagingPending(w.sess) // stop the 20 s guard timer
	}
	if w.cancel != nil {
		w.cancel()
		<-w.rxDone
	}
	if w.srv != nil {
		w.srv.WaitHandoverTasks()
	}
	if w.upf != nil {
		w.upf.close()
	}
	if w.amf != nil {
		w.amf.srv.Close()
	}
	*w = dldrWorld{}
}

func (w *dldrWorld) startUPF() error {
	upf, err := newDLDRUPF()
	if err != nil {
		return err
	}
	w.upf = upf
	return nil
}

func (w *dldrWorld) startAMF() error {
	w.amf = newDLDRStepAMF()
	return nil
}

func (w *dldrWorld) startSMF() error {
	if w.upf == nil || w.amf == nil {
		return fmt.Errorf("fake UPF and httptest AMF must be started first")
	}
	// Reserve a free loopback UDP port for the SMF PFCP receiver.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return err
	}
	w.smfAddr = probe.LocalAddr().(*net.UDPAddr)
	_ = probe.Close()

	cfg := &config.Config{UEIPPool: "10.60.0.0/24", UPFN3Addr: "10.0.0.250"}
	cfg.Peers.UPF = w.upf.addr()
	cfg.N4.ReportListen = w.smfAddr.String()
	w.logs = &hoLogStore{}
	srv, err := New(cfg, slog.New(hoLogHandler{store: w.logs}), nil)
	if err != nil {
		return fmt.Errorf("new SMF server: %w", err)
	}
	srv.pfcpTimers.t1, srv.pfcpTimers.n1 = 2*time.Second, 1
	pointAtAMF(srv, w.amf.srv)
	w.srv = srv

	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.rxDone = make(chan struct{})
	go func() { defer close(w.rxDone); _ = srv.StartPFCPReceiver(ctx) }()
	return hoStepsPoll(dldrWithin, func() error {
		if _, ok := w.logs.find(func(r hoRec) bool { return r.msg == "SMF: PFCP receiver listening" }); !ok {
			return fmt.Errorf("SMF PFCP receiver not listening")
		}
		return nil
	})
}

func (w *dldrWorld) idleSession(supi string, psi int) error {
	if w.srv == nil {
		return fmt.Errorf("SMF not started")
	}
	w.sess = &Session{SUPI: supi, PDUSessionID: uint8(psi), DNN: "internet", SEID: dldrSEID, State: "IDLE",
		ULTEID: 0x1001, FiveQI: 9, AMBRULMbps: 100, AMBRDLMbps: 200}
	w.srv.sessionMu.Lock()
	w.srv.sessions[dldrRef] = w.sess
	w.srv.sessionMu.Unlock()
	return nil
}

func dldrReportIE(pdrID uint16, qfi uint8) *pfcpie.IE {
	return pfcpie.NewDownlinkDataReport(pfcpie.NewPDRID(pdrID),
		pfcpie.NewDownlinkDataServiceInformation(false, true, 0, qfi))
}

func (w *dldrWorld) sendDLDR(seid uint64, ies ...*pfcpie.IE) error {
	seq, err := w.upf.sendSRR(w.smfAddr, seid, ies...)
	w.lastSeq = seq
	return err
}

func (w *dldrWorld) dldrPDR2() error {
	return w.sendDLDR(dldrSEID, dldrReportIE(dlPDRID, 1))
}
func (w *dldrWorld) dldrUnknownSEID(seid uint64) error {
	return w.sendDLDR(seid, dldrReportIE(dlPDRID, 1))
}
func (w *dldrWorld) dldrNoIE() error { return w.sendDLDR(dldrSEID) }

// awaitResponse polls for the Session Report Response of the last request.
func (w *dldrWorld) awaitResponse() (*pfcpmsg.SessionReportResponse, error) {
	var rsp *pfcpmsg.SessionReportResponse
	err := hoStepsPoll(dldrWithin, func() error {
		if rsp = w.upf.response(w.lastSeq); rsp == nil {
			return fmt.Errorf("no Session Report Response for sequence %d within %s", w.lastSeq, dldrWithin)
		}
		return nil
	})
	return rsp, err
}

func (w *dldrWorld) amfCalls() []dldrAMFCall { return w.amf.snapshot() }

func (w *dldrWorld) alreadyPaged() error {
	if err := w.dldrPDR2(); err != nil {
		return err
	}
	if _, err := w.awaitResponse(); err != nil {
		return err
	}
	if err := hoStepsPoll(dldrWithin, func() error {
		if n := len(w.amfCalls()); n != 1 {
			return fmt.Errorf("AMF received %d N1N2MessageTransfer, want 1", n)
		}
		return nil
	}); err != nil {
		return err
	}
	if !w.srv.dlPagingPending(w.sess) {
		return fmt.Errorf("paging-pending flag not set after the first DLDR")
	}
	return nil
}

func (w *dldrWorld) amfAnswers404(cause string) error {
	w.amf.status.Store(http.StatusNotFound)
	w.amf.cause.Store(cause)
	return nil
}

// ---- establishment ------------------------------------------------------------------------------

func (w *dldrWorld) establish(supi string, psi int) error {
	sess := &Session{SUPI: supi, PDUSessionID: uint8(psi), DNN: "internet", SEID: 77, UEIP: net.ParseIP("10.60.0.10"),
		ULTEID: 5, AMBRULMbps: 50, AMBRDLMbps: 100}
	w.srv.sendPFCPSessionEstablishment(context.Background(), sess)
	return hoStepsPoll(dldrWithin, func() error {
		for _, m := range w.upf.snapshot() {
			if r, ok := m.(*pfcpmsg.SessionEstablishmentRequest); ok {
				w.estab = r
				return nil
			}
		}
		return fmt.Errorf("no Session Establishment Request reached the fake UPF")
	})
}

func (w *dldrWorld) oneCreateBAR() error {
	if w.estab == nil || w.estab.CreateBAR == nil {
		return fmt.Errorf("Session Establishment Request carries no Create BAR")
	}
	kids, err := w.estab.CreateBAR.CreateBAR()
	if err != nil {
		return err
	}
	for _, k := range kids {
		if k.Type == pfcpie.BARID {
			if id, _ := k.BARID(); id != 1 {
				return fmt.Errorf("Create BAR BAR ID = %d, want 1", id)
			}
			return nil
		}
	}
	return fmt.Errorf("Create BAR has no BAR ID")
}

func (w *dldrWorld) barNoSuggested() error {
	kids, err := w.estab.CreateBAR.CreateBAR()
	if err != nil {
		return err
	}
	for _, k := range kids {
		if k.Type != pfcpie.BARID {
			return fmt.Errorf("Create BAR carries IE type %d besides BAR ID (Suggested Buffering Packets Count not allowed)", k.Type)
		}
	}
	return nil
}

func (w *dldrWorld) createPDR(id uint16) (src uint8, far uint32, err error) {
	for _, c := range w.estab.CreatePDR {
		kids, perr := c.CreatePDR()
		if perr != nil {
			return 0, 0, perr
		}
		var got uint16
		var s uint8
		var f uint32
		for _, k := range kids {
			switch k.Type {
			case pfcpie.PDRID:
				got, _ = k.PDRID()
			case pfcpie.FARID:
				f, _ = k.FARID()
			case pfcpie.PDI:
				pk, _ := k.PDI()
				for _, x := range pk {
					if x.Type == pfcpie.SourceInterface {
						s, _ = x.SourceInterface()
					}
				}
			}
		}
		if got == id {
			return s, f, nil
		}
	}
	return 0, 0, fmt.Errorf("no Create PDR with PDR ID %d", id)
}

func (w *dldrWorld) pdrRefs(id int, srcName string, farID int) error {
	want := map[string]uint8{"Core": pfcpie.SrcInterfaceCore, "Access": pfcpie.SrcInterfaceAccess}[srcName]
	src, far, err := w.createPDR(uint16(id))
	if err != nil {
		return err
	}
	if src != want || far != uint32(farID) {
		return fmt.Errorf("PDR %d: Source Interface %d FAR ID %d, want %s (%d) FAR ID %d", id, src, far, srcName, want, farID)
	}
	return nil
}

func (w *dldrWorld) createFAR(id uint32) (aa byte, bar uint8, dest uint8, err error) {
	dest = 0xFF
	for _, c := range w.estab.CreateFAR {
		kids, ferr := c.CreateFAR()
		if ferr != nil {
			return 0, 0, 0, ferr
		}
		var got uint32
		var a byte
		var b uint8
		d := uint8(0xFF)
		for _, k := range kids {
			switch k.Type {
			case pfcpie.FARID:
				got, _ = k.FARID()
			case pfcpie.ApplyAction:
				a = k.Payload[0]
			case pfcpie.BARID:
				b, _ = k.BARID()
			case pfcpie.ForwardingParameters:
				fk, _ := k.ForwardingParameters()
				for _, x := range fk {
					if x.Type == pfcpie.DestinationInterface {
						d, _ = x.DestinationInterface()
					}
				}
			}
		}
		if got == id {
			return a, b, d, nil
		}
	}
	return 0, 0, 0, fmt.Errorf("no Create FAR with FAR ID %d", id)
}

func (w *dldrWorld) farCarriesBAR(id, bar int) error {
	_, got, _, err := w.createFAR(uint32(id))
	if err != nil {
		return err
	}
	if int(got) != bar {
		return fmt.Errorf("FAR %d BAR ID = %d, want %d", id, got, bar)
	}
	return nil
}

func (w *dldrWorld) farForwCore(id int) error {
	aa, _, dest, err := w.createFAR(uint32(id))
	if err != nil {
		return err
	}
	if aa != 0x02 || dest != pfcpie.DstInterfaceCore {
		return fmt.Errorf("FAR %d Apply Action %#x Destination Interface %d, want FORW (0x02) / Core", id, aa, dest)
	}
	return nil
}

// ---- Thens: PFCP / AMF --------------------------------------------------------------------------

func (w *dldrWorld) responseCause(want int, _ string) error {
	rsp, err := w.awaitResponse()
	if err != nil {
		return err
	}
	c, err := rsp.Cause.Cause()
	if err != nil {
		return err
	}
	if int(c) != want {
		return fmt.Errorf("Session Report Response Cause = %d, want %d", c, want)
	}
	return nil
}

func (w *dldrWorld) responseHeaderSEID(want uint64) error {
	rsp, err := w.awaitResponse()
	if err != nil {
		return err
	}
	if rsp.SEID() != want {
		return fmt.Errorf("Session Report Response header SEID = %#x, want %#x", rsp.SEID(), want)
	}
	return nil
}

func (w *dldrWorld) responseOffending(want int) error {
	rsp, err := w.awaitResponse()
	if err != nil {
		return err
	}
	if rsp.OffendingIE == nil {
		return fmt.Errorf("Session Report Response carries no Offending IE")
	}
	if o, _ := rsp.OffendingIE.OffendingIE(); int(o) != want {
		return fmt.Errorf("Offending IE = %d, want %d", o, want)
	}
	return nil
}

func (w *dldrWorld) amfExactlyOneFor(supi string, psi int) error {
	if err := hoStepsPoll(dldrWithin, func() error {
		if n := len(w.amfCalls()); n < 1 {
			return fmt.Errorf("AMF received no N1N2MessageTransfer within %s", dldrWithin)
		}
		return nil
	}); err != nil {
		return err
	}
	w.srv.WaitHandoverTasks()
	calls := w.amfCalls()
	if len(calls) != 1 {
		return fmt.Errorf("AMF received %d N1N2MessageTransfer, want exactly 1", len(calls))
	}
	if want := "POST /namf-comm/v1/ue-contexts/" + supi + "/n1-n2-messages"; calls[0].path != want {
		return fmt.Errorf("N1N2MessageTransfer = %q, want %q", calls[0].path, want)
	}
	if calls[0].psi != psi {
		return fmt.Errorf("N1N2MessageTransfer pduSessionId = %d, want %d", calls[0].psi, psi)
	}
	return nil
}

func (w *dldrWorld) amfTotal(want int) error {
	if _, err := w.awaitResponse(); err != nil {
		return err
	}
	w.srv.WaitHandoverTasks()
	if n := len(w.amfCalls()); n != want {
		return fmt.Errorf("AMF received %d N1N2MessageTransfer in total, want %d", n, want)
	}
	return nil
}

func (w *dldrWorld) amfNone() error { return w.amfTotal(0) }
func (w *dldrWorld) amfOne() error  { return w.amfTotal(1) }

// ---- Thens: logs --------------------------------------------------------------------------------

func (w *dldrWorld) logsFlow(proc, iface, dir, spec string) error {
	return hoStepsPoll(dldrWithin, func() error {
		if _, ok := w.logs.find(func(r hoRec) bool {
			return r.attrs["procedure"] == proc && r.attrs["interface"] == iface &&
				r.attrs["direction"] == dir && r.attrs["spec_ref"] == spec
		}); !ok {
			return fmt.Errorf("no log with procedure %s interface %s direction %s spec_ref %q", proc, iface, dir, spec)
		}
		return nil
	})
}

func (w *dldrWorld) logsResult(proc, iface, result, cause string) error {
	return hoStepsPoll(dldrWithin, func() error {
		if _, ok := w.logs.find(func(r hoRec) bool {
			return r.attrs["procedure"] == proc && r.attrs["interface"] == iface &&
				r.attrs["result"] == result && r.attrs["cause"] == cause
		}); !ok {
			return fmt.Errorf("no log with procedure %s interface %s result %s cause %s", proc, iface, result, cause)
		}
		return nil
	})
}

// ---- Service Request re-activation --------------------------------------------------------------

func (w *dldrWorld) post(body map[string]interface{}) (*httptest.ResponseRecorder, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/"+dldrRef+"/modify", strings.NewReader(string(b)))
	r.SetPathValue("smContextRef", dldrRef)
	rec := httptest.NewRecorder()
	w.srv.handleUpdateSMContext(rec, r)
	return rec, nil
}

// activate follows the Service Request loop of TS 23.502 §4.2.3.2: ACTIVATING fetches the
// N2SM setup transfer (step 12 of the 4.2.3.2 flow), then the gNB's PDU Session Resource Setup
// Response Transfer (N3 tunnel) is relayed and re-activates the DL FAR.
func (w *dldrWorld) activate() error {
	rec, err := w.post(map[string]interface{}{"upCnxState": "ACTIVATING"})
	if err != nil {
		return err
	}
	if rec.Code != http.StatusOK {
		return fmt.Errorf("UpdateSMContext ACTIVATING = HTTP %d, want 200", rec.Code)
	}
	tr, err := hoStepsMarshal(ngapType.PDUSessionResourceSetupResponseTransfer{
		DLQosFlowPerTNLInformation: ngapType.QosFlowPerTNLInformation{
			UPTransportLayerInformation: hoStepsGTP(dldrGNBIP, dldrGNBTEID),
			AssociatedQosFlowList: ngapType.AssociatedQosFlowList{List: []ngapType.AssociatedQosFlowItem{
				{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}}}},
		},
	})
	if err != nil {
		return err
	}
	rec, err = w.post(map[string]interface{}{"n2SmInfo": b64(tr), "n2SmInfoType": "PDU_RES_SETUP_RSP"})
	if err != nil {
		return err
	}
	if rec.Code != http.StatusOK {
		return fmt.Errorf("UpdateSMContext with gNB N3 tunnel = HTTP %d, want 200", rec.Code)
	}
	return nil
}

// modWith polls for a Session Modification Request whose single Update FAR satisfies pred.
func (w *dldrWorld) modWith(desc string, pred func(aa byte, kids []*pfcpie.IE) bool) error {
	return hoStepsPoll(dldrWithin, func() error {
		for _, m := range w.upf.snapshot() {
			req, ok := m.(*pfcpmsg.SessionModificationRequest)
			if !ok || len(req.UpdateFAR) != 1 {
				continue
			}
			kids, err := req.UpdateFAR[0].UpdateFAR()
			if err != nil {
				continue
			}
			var farID uint32
			var aa byte
			for _, k := range kids {
				switch k.Type {
				case pfcpie.FARID:
					farID, _ = k.FARID()
				case pfcpie.ApplyAction:
					aa = k.Payload[0]
				}
			}
			if farID == 1 && pred(aa, kids) {
				return nil
			}
		}
		return fmt.Errorf("fake UPF received no Session Modification Request with %s", desc)
	})
}

func (w *dldrWorld) modForwOHC() error {
	return w.modWith("Update FAR 1 Apply Action FORW and an Outer Header Creation", func(aa byte, kids []*pfcpie.IE) bool {
		if aa != 0x02 {
			return false
		}
		for _, k := range kids {
			if k.Type != pfcpie.UpdateForwardingParameters {
				continue
			}
			fk, _ := k.UpdateForwardingParameters()
			for _, x := range fk {
				if x.Type == pfcpie.OuterHeaderCreation {
					return true
				}
			}
		}
		return false
	})
}

func (w *dldrWorld) modDrop() error {
	return w.modWith("Update FAR 1 Apply Action DROP", func(aa byte, _ []*pfcpie.IE) bool { return aa == 0x01 })
}

func (w *dldrWorld) stateIs(want string) error {
	return hoStepsPoll(dldrWithin, func() error {
		w.srv.sessionMu.Lock()
		got := w.sess.State
		w.srv.sessionMu.Unlock()
		if got != want {
			return fmt.Errorf("PDU session state = %q, want %q", got, want)
		}
		return nil
	})
}

func (w *dldrWorld) noPending() error {
	return hoStepsPoll(dldrWithin, func() error {
		if w.srv.dlPagingPending(w.sess) {
			return fmt.Errorf("pending-paging flag still set")
		}
		return nil
	})
}

// InitializeDownlinkDataReportScenario wires downlink_data_report.feature.
func InitializeDownlinkDataReportScenario(ctx *godog.ScenarioContext) {
	w := &dldrWorld{}
	ctx.After(func(c context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.teardown()
		return c, nil
	})

	ctx.Step(`^a fake UPF PFCP peer listening on a loopback UDP socket$`, w.startUPF)
	ctx.Step(`^an httptest AMF recording N1N2MessageTransfer requests$`, w.startAMF)
	ctx.Step(`^the SMF is running in-process with the fake UPF as N4 peer and the httptest AMF as Namf-comm$`, w.startSMF)
	ctx.Step(`^the SMF holds an IDLE PDU session "([^"]+)" PSI (\d+) whose DL FAR 1 is BUFF\+NOCP$`, w.idleSession)
	ctx.Step(`^the SMF has already sent one N1N2MessageTransfer for the session and paging is pending$`, w.alreadyPaged)
	ctx.Step(`^the httptest AMF answers N1N2MessageTransfer with HTTP 404 and ProblemDetails cause "([^"]+)"$`, w.amfAnswers404)

	ctx.Step(`^a new PDU session "([^"]+)" PSI (\d+) is established through the SMF$`, w.establish)
	ctx.Step(`^the fake UPF sends a Session Report Request with Report Type DLDR and Downlink Data Report PDR ID 2 with QFI 1 for the session$`, w.dldrPDR2)
	ctx.Step(`^the fake UPF sends a Session Report Request with Report Type DLDR for SEID 0xDEAD that matches no session$`,
		func() error { return w.dldrUnknownSEID(0xDEAD) })
	ctx.Step(`^the fake UPF sends a Session Report Request with Report Type DLDR and no Downlink Data Report IE for the session$`, w.dldrNoIE)
	ctx.Step(`^the AMF sends Nsmf_PDUSession_UpdateSMContext with upCnxState "ACTIVATING" and the gNB N3 tunnel for the session$`, w.activate)

	ctx.Step(`^the fake UPF receives a PFCP Session Establishment Request containing exactly one Create BAR with BAR ID 1$`, w.oneCreateBAR)
	ctx.Step(`^the Create BAR contains no Suggested Buffering Packets Count$`, w.barNoSuggested)
	ctx.Step(`^the Create PDR with PDR ID (\d+) has Source Interface "([^"]+)" and references FAR ID (\d+)$`, w.pdrRefs)
	ctx.Step(`^the Create FAR with FAR ID (\d+) carries BAR ID (\d+)$`, w.farCarriesBAR)
	ctx.Step(`^the Create FAR with FAR ID (\d+) has Apply Action FORW with Destination Interface "Core"$`, w.farForwCore)

	ctx.Step(`^the fake UPF receives a Session Report Response with Cause (\d+) "([^"]+)"$`, w.responseCause)
	ctx.Step(`^the fake UPF receives a Session Report Response with Cause (\d+) "([^"]+)" and header SEID (\d+)$`,
		func(c int, s string, seid int) error {
			if err := w.responseCause(c, s); err != nil {
				return err
			}
			return w.responseHeaderSEID(uint64(seid))
		})
	ctx.Step(`^the fake UPF receives a Session Report Response with Cause (\d+) "([^"]+)" and Offending IE (\d+)$`,
		func(c int, s string, ie int) error {
			if err := w.responseCause(c, s); err != nil {
				return err
			}
			return w.responseOffending(ie)
		})
	ctx.Step(`^the httptest AMF receives exactly one N1N2MessageTransfer for "([^"]+)" with pduSessionId (\d+)$`, w.amfExactlyOneFor)
	ctx.Step(`^the httptest AMF has received exactly one N1N2MessageTransfer in total$`, w.amfOne)
	ctx.Step(`^the httptest AMF has received no N1N2MessageTransfer$`, w.amfNone)

	ctx.Step(`^the SMF logs procedure "([^"]+)" interface "([^"]+)" direction "([^"]+)" with spec_ref "([^"]+)"$`, w.logsFlow)
	ctx.Step(`^the SMF logs procedure "([^"]+)" interface "([^"]+)" with result "([^"]+)" and cause "([^"]+)"$`, w.logsResult)

	ctx.Step(`^the fake UPF receives a PFCP Session Modification Request with Update FAR 1 Apply Action FORW and an Outer Header Creation$`, w.modForwOHC)
	ctx.Step(`^the fake UPF receives a PFCP Session Modification Request with Update FAR 1 Apply Action DROP$`, w.modDrop)
	ctx.Step(`^the SMF PDU session state is "([A-Z]+)"$`, w.stateIs)
	ctx.Step(`^the SMF no longer holds a pending-paging flag for the session$`, w.noPending)
}

// TestDownlinkDataReportFeatures runs downlink_data_report.feature against the in-process SMF.
func TestDownlinkDataReportFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeDownlinkDataReportScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/downlink_data_report.feature"},
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
