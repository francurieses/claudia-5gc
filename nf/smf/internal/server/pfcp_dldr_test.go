package server

// pfcp_dldr_test.go — unit tests for the SMF-011 N4 trigger: Create BAR / DL PDR layout of the
// Session Establishment Request and the Downlink Data Report (DLDR) consumer.
// Ref: TS 29.244 §7.5.2, §7.5.8.2, §7.5.9; TS 23.502 §4.2.3.3.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

// dldrAMF counts N1N2MessageTransfer requests and answers status/cause.
type dldrAMF struct {
	ts    *httptest.Server
	calls atomic.Int32
}

func newDLDRAMF(t *testing.T, status int, problemCause string) *dldrAMF {
	t.Helper()
	a := &dldrAMF{}
	a.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status >= 400 {
			_, _ = w.Write([]byte(`{"cause":"` + problemCause + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"cause":"ATTEMPTING_TO_REACH_UE"}`))
	}))
	t.Cleanup(a.ts.Close)
	return a
}

// dldrFixture is an IDLE session (SEID 42) with a responding fake UPF and AMF.
func dldrFixture(t *testing.T, amfStatus int, amfCause string) (*Server, *Session, *hoFakeUPF, *dldrAMF) {
	t.Helper()
	s, sess, upf := hoRespFixture(t)
	sess.State = "IDLE"
	amf := newDLDRAMF(t, amfStatus, amfCause)
	pointAtAMF(s, amf.ts)
	return s, sess, upf, amf
}

func dldrRequest(seid uint64, ies ...*pfcpie.IE) *pfcpmsg.SessionReportRequest {
	return pfcpmsg.NewSessionReportRequest(0, 0, seid, 1, 0,
		append([]*pfcpie.IE{pfcpie.NewReportType(0, 0, 0, 1)}, ies...)...)
}

func dldrIE(pdrID uint16, qfi uint8) *pfcpie.IE {
	return pfcpie.NewDownlinkDataReport(pfcpie.NewPDRID(pdrID),
		pfcpie.NewDownlinkDataServiceInformation(false, true, 0, qfi))
}

// TestDLDRAcceptedTriggersOneN1N2: Cause 1, pending set, exactly one N1N2; duplicate while
// pending is acknowledged with no second call.
func TestDLDRAcceptedTriggersOneN1N2(t *testing.T) {
	s, sess, _, amf := dldrFixture(t, http.StatusAccepted, "")
	cause, _, post := s.consumeSessionReportDeferred(t.Context(), dldrRequest(42, dldrIE(dlPDRID, 1)))
	if cause != pfcpie.CauseRequestAccepted || post == nil {
		t.Fatalf("cause=%d post=%v, want 1 and non-nil", cause, post != nil)
	}
	if !s.dlPagingPending(sess) {
		t.Fatal("paging flag not set")
	}
	post()
	s.WaitHandoverTasks()
	if n := amf.calls.Load(); n != 1 {
		t.Fatalf("N1N2 calls = %d, want 1", n)
	}

	cause, _, post = s.consumeSessionReportDeferred(t.Context(), dldrRequest(42, dldrIE(dlPDRID, 1)))
	if cause != pfcpie.CauseRequestAccepted || post != nil {
		t.Fatalf("duplicate: cause=%d post=%v, want 1 and nil", cause, post != nil)
	}
	s.WaitHandoverTasks()
	if n := amf.calls.Load(); n != 1 {
		t.Fatalf("N1N2 calls after duplicate = %d, want 1", n)
	}

	// UP re-activation clears the flag.
	if !s.markSessionActive(sess) || s.dlPagingPending(sess) {
		t.Fatal("pending flag not cleared by UP re-activation")
	}
}

func TestDLDRUnknownSEIDAndMissingIE(t *testing.T) {
	s, _, _, amf := dldrFixture(t, http.StatusAccepted, "")
	if cause, _, post := s.consumeSessionReportDeferred(t.Context(), dldrRequest(0xDEAD, dldrIE(dlPDRID, 1))); cause != pfcpie.CauseSessionContextNotFound || post != nil {
		t.Fatalf("unknown SEID: cause=%d, want 65", cause)
	}
	if cause, _, post := s.consumeSessionReportDeferred(t.Context(), dldrRequest(42)); cause != pfcpie.CauseConditionalIEMissing || post != nil {
		t.Fatalf("missing DLDR IE: cause=%d, want 67", cause)
	}
	if cause, off, post := s.consumeDownlinkDataReport(t.Context(), dldrRequest(42)); cause != 67 || off != 83 || post != nil {
		t.Fatalf("missing DLDR IE: cause=%d offending=%d, want 67/83", cause, off)
	}
	noPDR := dldrRequest(42, pfcpie.NewDownlinkDataReport())
	if cause, off, post := s.consumeDownlinkDataReport(t.Context(), noPDR); cause != 67 || off != 56 || post != nil {
		t.Fatalf("missing PDR ID: cause=%d offending=%d, want 67/56", cause, off)
	}
	if n := amf.calls.Load(); n != 0 {
		t.Fatalf("N1N2 calls = %d, want 0", n)
	}
}

// TestDLDRResponseWire: Cause 65 answers with header SEID 0, Cause 67 with Offending IE 83 / 56.
func TestDLDRResponseWire(t *testing.T) {
	s, _, _, _ := dldrFixture(t, http.StatusAccepted, "")
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	read := func() *pfcpmsg.SessionReportResponse {
		buf := make([]byte, 1500)
		n, _, err := cli.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no response: %v", err)
		}
		m, err := pfcpmsg.Parse(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		return m.(*pfcpmsg.SessionReportResponse)
	}
	raddr := cli.LocalAddr().(*net.UDPAddr)

	s.handleSessionReport(t.Context(), srv, raddr, dldrRequest(0xDEAD, dldrIE(dlPDRID, 1)))
	r := read()
	if c, _ := r.Cause.Cause(); c != 65 || r.SEID() != 0 {
		t.Fatalf("unknown: cause=%d seid=%#x, want 65 / 0", c, r.SEID())
	}
	s.handleSessionReport(t.Context(), srv, raddr, dldrRequest(42))
	r = read()
	if c, _ := r.Cause.Cause(); c != 67 || r.OffendingIE == nil {
		t.Fatalf("missing IE: cause=%d offending=%v", c, r.OffendingIE)
	}
	if o, _ := r.OffendingIE.OffendingIE(); o != 83 {
		t.Fatalf("offending IE = %d, want 83", o)
	}
	s.handleSessionReport(t.Context(), srv, raddr, dldrRequest(42, pfcpie.NewDownlinkDataReport()))
	r = read()
	if c, _ := r.Cause.Cause(); c != 67 || r.OffendingIE == nil {
		t.Fatalf("missing PDR ID: cause=%d offending=%v", c, r.OffendingIE)
	}
	if o, _ := r.OffendingIE.OffendingIE(); o != 56 {
		t.Fatalf("offending IE = %d, want 56", o)
	}
}

// TestDLDRAMFFailureSendsDrop: AMF 404 CONTEXT_NOT_FOUND clears the flag and sends Update FAR 1 DROP.
func TestDLDRAMFFailureSendsDrop(t *testing.T) {
	s, sess, upf, amf := dldrFixture(t, http.StatusNotFound, "CONTEXT_NOT_FOUND")
	_, _, post := s.consumeSessionReportDeferred(t.Context(), dldrRequest(42, dldrIE(dlPDRID, 1)))
	post()
	s.WaitHandoverTasks()
	if n := amf.calls.Load(); n != 1 {
		t.Fatalf("N1N2 calls = %d, want 1", n)
	}
	if s.dlPagingPending(sess) {
		t.Fatal("pending flag not cleared after AMF failure")
	}
	reqs := upf.requests()
	if len(reqs) != 1 {
		t.Fatalf("UPF modifications = %d, want 1", len(reqs))
	}
	if aa, _, _ := applyActionOf(t, reqs[0].far); aa != 0x01 {
		t.Fatalf("apply action = %#x, want DROP 0x01", aa)
	}
}

// dldrDropCase runs one DLDR against an AMF answering status/cause and expects exactly one
// N1N2 call followed by Update FAR 1 DROP and a cleared pending flag.
func dldrExpectDrop(t *testing.T, s *Server, sess *Session, upf *hoFakeUPF, amf *dldrAMF) {
	t.Helper()
	_, _, post := s.consumeSessionReportDeferred(t.Context(), dldrRequest(42, dldrIE(dlPDRID, 1)))
	post()
	s.WaitHandoverTasks()
	if n := amf.calls.Load(); n < 1 {
		t.Fatalf("N1N2 calls = %d, want >= 1", n)
	}
	if s.dlPagingPending(sess) {
		t.Fatal("pending flag not cleared after AMF failure")
	}
	reqs := upf.requests()
	if len(reqs) != 1 {
		t.Fatalf("UPF modifications = %d, want 1", len(reqs))
	}
	if aa, _, _ := applyActionOf(t, reqs[0].far); aa != 0x01 {
		t.Fatalf("apply action = %#x, want DROP 0x01", aa)
	}
}

// TestDLDRAMF5xxSendsDrop: AMF 503 -> failure -> DROP.
func TestDLDRAMF5xxSendsDrop(t *testing.T) {
	s, sess, upf, amf := dldrFixture(t, http.StatusServiceUnavailable, "SYSTEM_FAILURE")
	dldrExpectDrop(t, s, sess, upf, amf)
}

// TestDLDRAMFUnexpected2xxSendsDrop: AMF 200 with a cause that does not mean "paging" -> DROP.
func TestDLDRAMFUnexpected2xxSendsDrop(t *testing.T) {
	s, sess, upf, amf := dldrFixture(t, http.StatusOK, "")
	amf.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		amf.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"cause":"UE_NOT_RESPONDING"}`))
	})
	dldrExpectDrop(t, s, sess, upf, amf)
}

// TestDLDRAMFTimeoutStillSendsDrop: an AMF that never answers within the N1N2 deadline must
// not starve the DROP (it runs on a detached context).
func TestDLDRAMFTimeoutStillSendsDrop(t *testing.T) {
	s, sess, upf, amf := dldrFixture(t, http.StatusAccepted, "")
	release := make(chan struct{})
	amf.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		amf.calls.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(release) })
	dldrExpectDrop(t, s, sess, upf, amf)
}

// TestDLDRConcurrentOneN1N2: two concurrent DLDRs trigger exactly one N1N2MessageTransfer.
func TestDLDRConcurrentOneN1N2(t *testing.T) {
	s, _, _, amf := dldrFixture(t, http.StatusAccepted, "")
	var wg sync.WaitGroup
	var posts atomic.Int32
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, post := s.consumeSessionReportDeferred(t.Context(), dldrRequest(42, dldrIE(dlPDRID, 1)))
			if post != nil {
				posts.Add(1)
				post()
			}
		}()
	}
	wg.Wait()
	s.WaitHandoverTasks()
	if posts.Load() != 1 || amf.calls.Load() != 1 {
		t.Fatalf("posts=%d N1N2 calls=%d, want 1/1", posts.Load(), amf.calls.Load())
	}
}

// TestDLDRNoPagingForActiveOrReleasing: DLDR for an ACTIVE or RELEASING session is acknowledged only.
func TestDLDRNoPagingForActiveOrReleasing(t *testing.T) {
	for _, st := range []string{"ACTIVE", sessionStateReleasing} {
		s, sess, _, amf := dldrFixture(t, http.StatusAccepted, "")
		sess.State = st
		cause, _, post := s.consumeSessionReportDeferred(t.Context(), dldrRequest(42, dldrIE(dlPDRID, 1)))
		if cause != pfcpie.CauseRequestAccepted || post != nil || amf.calls.Load() != 0 || s.dlPagingPending(sess) {
			t.Fatalf("state %s: cause=%d post=%v calls=%d", st, cause, post != nil, amf.calls.Load())
		}
	}
}

func TestParseDownlinkDataReport(t *testing.T) {
	rep, ok := parseDownlinkDataReport(dldrIE(2, 5))
	if !ok || rep.PDRID != 2 || !rep.HasQFI || rep.QFI != 5 {
		t.Fatalf("got %+v ok=%v", rep, ok)
	}
	rep, ok = parseDownlinkDataReport(pfcpie.NewDownlinkDataReport(pfcpie.NewPDRID(2)))
	if !ok || rep.HasQFI {
		t.Fatalf("no-QFI: %+v ok=%v", rep, ok)
	}
	if _, ok = parseDownlinkDataReport(pfcpie.NewDownlinkDataReport()); ok {
		t.Fatal("empty report must lack the mandatory PDR ID")
	}
}

// TestEstablishmentCarriesBARAndDLPDR pins the SMF-011 rule layout: Create BAR 1; DL PDR 2
// (Core, UE IP as destination) -> FAR 1 (BAR ID 1); UL PDR 1 (Access) -> FAR 2 (Core).
func TestEstablishmentCarriesBARAndDLPDR(t *testing.T) {
	upfConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer upfConn.Close()
	s := newTestSMFServer(t)
	s.cfg.Peers.UPF = upfConn.LocalAddr().String()
	sess := &Session{SUPI: "imsi-001010000000042", DNN: "internet", UEIP: net.ParseIP("10.60.0.10"),
		ULTEID: 5, SEID: 77, AMBRULMbps: 50, AMBRDLMbps: 100}
	go s.sendPFCPSessionEstablishment(t.Context(), sess)

	buf := make([]byte, 2048)
	_ = upfConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := upfConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no establishment request: %v", err)
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	req := msg.(*pfcpmsg.SessionEstablishmentRequest)

	if req.CreateBAR == nil {
		t.Fatal("no Create BAR")
	}
	barIEs, _ := req.CreateBAR.CreateBAR()
	if len(barIEs) != 1 || barIEs[0].Type != pfcpie.BARID {
		t.Fatalf("Create BAR children = %d, want only BAR ID (no Suggested Buffering Packets Count)", len(barIEs))
	}
	if id, _ := barIEs[0].BARID(); id != defaultBARID {
		t.Fatalf("BAR ID = %d", id)
	}

	if len(req.CreatePDR) != 2 || len(req.CreateFAR) != 2 {
		t.Fatalf("PDRs=%d FARs=%d, want 2/2", len(req.CreatePDR), len(req.CreateFAR))
	}
	type pdr struct {
		src    uint8
		far    uint32
		urr    bool
		qers   int
		ueFlag uint8
	}
	pdrs := map[uint16]pdr{}
	for _, c := range req.CreatePDR {
		kids, _ := c.CreatePDR()
		var id uint16
		var p pdr
		for _, k := range kids {
			switch k.Type {
			case pfcpie.PDRID:
				id, _ = k.PDRID()
			case pfcpie.FARID:
				p.far, _ = k.FARID()
			case pfcpie.URRID:
				p.urr = true
			case pfcpie.QERID:
				p.qers++
			case pfcpie.PDI:
				pk, _ := k.PDI()
				for _, x := range pk {
					switch x.Type {
					case pfcpie.SourceInterface:
						p.src, _ = x.SourceInterface()
					case pfcpie.UEIPAddress:
						p.ueFlag = x.Payload[0]
					}
				}
			}
		}
		pdrs[id] = p
	}
	if p := pdrs[ulPDRID]; p.src != pfcpie.SrcInterfaceAccess || p.far != ulFARID || p.ueFlag != 0x02 {
		t.Fatalf("UL PDR = %+v", p)
	}
	if p := pdrs[dlPDRID]; p.src != pfcpie.SrcInterfaceCore || p.far != dlFARID || !p.urr || p.qers != 2 || p.ueFlag != 0x06 {
		t.Fatalf("DL PDR = %+v (want Core, FAR 1, URR, 2 QERs, UE IP flags 0x06 = V4|dest)", p)
	}

	for _, c := range req.CreateFAR {
		kids, _ := c.CreateFAR()
		var id uint32
		var bar uint8
		var dest uint8 = 0xFF
		var aa byte
		for _, k := range kids {
			switch k.Type {
			case pfcpie.FARID:
				id, _ = k.FARID()
			case pfcpie.BARID:
				bar, _ = k.BARID()
			case pfcpie.ApplyAction:
				aa = k.Payload[0]
			case pfcpie.ForwardingParameters:
				fk, _ := k.ForwardingParameters()
				for _, x := range fk {
					if x.Type == pfcpie.DestinationInterface {
						dest, _ = x.DestinationInterface()
					}
				}
			}
		}
		switch id {
		case dlFARID:
			if bar != defaultBARID || aa != 0x02 || dest != pfcpie.DstInterfaceAccess {
				t.Fatalf("DL FAR: bar=%d aa=%#x dest=%d", bar, aa, dest)
			}
		case ulFARID:
			if bar != 0 || aa != 0x02 || dest != pfcpie.DstInterfaceCore {
				t.Fatalf("UL FAR: bar=%d aa=%#x dest=%d", bar, aa, dest)
			}
		default:
			t.Fatalf("unexpected FAR %d", id)
		}
	}
}
