package pfcp

// dlbuffer_test.go - DL buffering and Downlink Data Report (SMF-011, UPF side)
// over real PFCP/UDP round trips. Ref: TS 29.244 §5.2.3.1, §7.5.2.6, §7.5.4.3,
// §7.5.8.

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

type recFlusher struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (f *recFlusher) SendBuffered(_ *Session, p []byte) bool {
	f.mu.Lock()
	f.pkts = append(f.pkts, append([]byte(nil), p...))
	f.mu.Unlock()
	return true
}

func (f *recFlusher) got() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.pkts...)
}

// fakeSMF is a loopback PFCP peer recording Session Report Requests.
type fakeSMF struct {
	conn  *net.UDPConn
	cause uint8
	mu    sync.Mutex
	reqs  []*pfcpmsg.SessionReportRequest
	// mute suppresses the Session Report Response (retransmission tests).
	mute atomic.Bool
	// seen receives one token per Session Report Request (quiet-window checks).
	seen chan struct{}
}

func newFakeSMF(t *testing.T, cause uint8) *fakeSMF {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMF{conn: c, cause: cause, seen: make(chan struct{}, 64)}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			m, err := pfcpmsg.Parse(buf[:n])
			if err != nil {
				continue
			}
			if r, ok := m.(*pfcpmsg.SessionReportRequest); ok {
				f.mu.Lock()
				f.reqs = append(f.reqs, r)
				f.mu.Unlock()
				select {
				case f.seen <- struct{}{}:
				default:
				}
				if f.mute.Load() {
					continue
				}
				resp := pfcpmsg.NewSessionReportResponse(0, 0, r.SEID(), r.Sequence(), 0, pfcpie.NewCause(f.cause))
				b := make([]byte, resp.MarshalLen())
				_ = resp.MarshalTo(b)
				_, _ = c.WriteToUDP(b, from)
			}
		}
	}()
	return f
}

func (f *fakeSMF) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

// quiet fails if the SMF receives another Session Report Request within window
// of the call (quiet-window check; returns when the window elapses).
func (f *fakeSMF) quiet(t *testing.T, window time.Duration) {
	t.Helper()
	n := f.count()
	deadline := time.After(window)
	for {
		select {
		case <-f.seen:
			if got := f.count(); got != n {
				t.Fatalf("unexpected Session Report Request: %d -> %d", n, got)
			}
		case <-deadline:
			return
		}
	}
}

func (s *Server) dldrPendingLen() int {
	s.dldrMu.Lock()
	defer s.dldrMu.Unlock()
	return len(s.dldrPending)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// quietWindow is how long a "no (further) report" assertion observes the SMF.
const quietWindow = 100 * time.Millisecond

const (
	bufSEID   = uint64(501)
	bufULTEID = uint32(0x501)
)

// establishBuf installs PDR 2 (Core, UE IP) -> FAR 1 (BAR 1) and PDR 1 -> FAR 2.
func establishBuf(t *testing.T, addr *net.UDPAddr, suggested int, legacy bool) {
	t.Helper()
	bar := []*pfcpie.IE{pfcpie.NewBARID(1)}
	if suggested > 0 {
		bar = append(bar, pfcpie.NewSuggestedBufferingPacketsCount(uint8(suggested)))
	}
	var ies []*pfcpie.IE
	ies = append(ies, pfcpie.NewNodeID("", "", "smf"), pfcpie.NewFSEID(bufSEID, net.ParseIP("127.0.0.1"), nil))
	if legacy {
		ies = append(ies,
			pfcpie.NewCreatePDR(pfcpie.NewPDRID(1), pfcpie.NewPrecedence(100),
				pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
					pfcpie.NewFTEID(0x01, bufULTEID, net.ParseIP("127.0.0.1"), nil, 0),
					pfcpie.NewUEIPAddress(0x02, "10.60.0.7", "", 0, 0)),
				pfcpie.NewFARID(1)),
			pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02)))
	} else {
		ies = append(ies,
			pfcpie.NewCreatePDR(pfcpie.NewPDRID(1), pfcpie.NewPrecedence(100),
				pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
					pfcpie.NewFTEID(0x01, bufULTEID, net.ParseIP("127.0.0.1"), nil, 0)),
				pfcpie.NewFARID(2)),
			pfcpie.NewCreatePDR(pfcpie.NewPDRID(2), pfcpie.NewPrecedence(100),
				pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceCore),
					pfcpie.NewUEIPAddress(0x02, "10.60.0.7", "", 0, 0)),
				pfcpie.NewFARID(1)),
			pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02), pfcpie.NewBARID(1)),
			pfcpie.NewCreateFAR(pfcpie.NewFARID(2), pfcpie.NewApplyAction(0x02)),
			pfcpie.NewCreateBAR(bar...))
	}
	est := pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, 1, 0, ies...)
	if _, ok := sendAndRecv(t, addr, est).(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatal("expected SessionEstablishmentResponse")
	}
}

func modFAR(t *testing.T, addr *net.UDPAddr, farID uint32, aa uint8, ohcTEID uint32) {
	t.Helper()
	ies := []*pfcpie.IE{pfcpie.NewFARID(farID), pfcpie.NewApplyAction(aa)}
	if ohcTEID != 0 {
		ies = append(ies, pfcpie.NewUpdateForwardingParameters(
			pfcpie.NewDestinationInterface(pfcpie.DstInterfaceAccess),
			pfcpie.NewOuterHeaderCreation(0x0100, ohcTEID, "127.0.0.1", "", 0, 0, 0)))
	}
	req := pfcpmsg.NewSessionModificationRequest(0, 0, bufSEID, 2, 0, pfcpie.NewUpdateFAR(ies...))
	if _, ok := sendAndRecv(t, addr, req).(*pfcpmsg.SessionModificationResponse); !ok {
		t.Fatal("expected SessionModificationResponse")
	}
}

func dropped(reason string) float64 {
	return testutil.ToFloat64(UPFDLBufferDroppedTotal.WithLabelValues(reason))
}

func setup(t *testing.T, limit int, cause uint8, suggested int, legacy bool) (*Server, *Session, *fakeSMF, *recFlusher, *net.UDPAddr) {
	t.Helper()
	srv, table, addr, stop := startTestUPFWith(t, Config{DLBufferDefaultPackets: limit})
	t.Cleanup(stop)
	fl := &recFlusher{}
	srv.SetDLFlusher(fl)
	smf := newFakeSMF(t, cause)
	establishBuf(t, addr, suggested, legacy)
	sess := table.GetByULTEID(bufULTEID)
	if sess == nil {
		t.Fatal("session not stored")
	}
	sess.SMFAddr = smf.conn.LocalAddr().(*net.UDPAddr)
	return srv, sess, smf, fl, addr
}

func TestDLBufferEstablishmentRecordsLinkage(t *testing.T) {
	_, sess, _, _, _ := setup(t, 3, 1, 0, false)
	if sess.DLPDRID != 2 || sess.DLFARID != 1 || sess.BARID != 1 {
		t.Errorf("DL pdr/far/bar = %d/%d/%d, want 2/1/1", sess.DLPDRID, sess.DLFARID, sess.BARID)
	}
}

func TestDLBufferLegacyLayout(t *testing.T) {
	srv, sess, smf, _, addr := setup(t, 3, 1, 0, true)
	if sess.DLPDRID != 1 || sess.DLFARID != 1 || sess.BARID != 0 {
		t.Errorf("legacy DL pdr/far/bar = %d/%d/%d, want 1/1/0", sess.DLPDRID, sess.DLFARID, sess.BARID)
	}
	modFAR(t, addr, 1, 0x0C, 0)
	if sess.DLBuf.Offer([]byte("P1")) != OfferQueuedReport {
		t.Fatal("first packet must request the report")
	}
	srv.NotifyDownlinkData(t.Context(), sess)
	waitFor(t, "legacy DLDR", func() bool { return smf.count() == 1 })
	smf.mu.Lock()
	ies, _ := smf.reqs[0].DownlinkDataReport.DownlinkDataReport()
	smf.mu.Unlock()
	if len(ies) == 0 || ies[0].Type != pfcpie.PDRID {
		t.Fatal("DLDR must start with PDR ID")
	}
	if id, _ := ies[0].PDRID(); id != 1 {
		t.Errorf("legacy DLDR PDR ID = %d, want 1", id)
	}
}

func fillN(sess *Session, n int) []OfferResult {
	var out []OfferResult
	for i := 1; i <= n; i++ {
		out = append(out, sess.DLBuf.Offer([]byte(fmt.Sprintf("P%d", i))))
	}
	return out
}

func TestDLBufferSuggestedCountHonouredAndCapped(t *testing.T) {
	// BAR suggests 2 although the default is 5: limit 2.
	_, sess, _, _, addr := setup(t, 5, 1, 2, false)
	modFAR(t, addr, 1, 0x04, 0) // BUFF without NOCP
	res := fillN(sess, 3)
	if res[0] != OfferQueued || res[1] != OfferQueued || res[2] != OfferFull {
		t.Errorf("results = %v, want queued, queued, full (limit 2)", res)
	}
}

func TestDLBufferCapAppliesToSuggested(t *testing.T) {
	srv, _, _, _ := startTestUPFWith(t, Config{DLBufferDefaultPackets: 10, DLBufferMaxPackets: 4})
	if got := srv.effectiveDLBufferLimit(200); got != 4 {
		t.Errorf("limit = %d, want 4 (capped)", got)
	}
	if got := srv.effectiveDLBufferLimit(0); got != 4 {
		t.Errorf("default limit = %d, want 4 (default capped)", got)
	}
}

func TestDLBufferFirstPacketSingleDLDR(t *testing.T) {
	_, sess, _, _, addr := setup(t, 3, 1, 0, false)
	before := testutil.ToFloat64(UPFDLBufferedPacketsTotal)
	modFAR(t, addr, 1, 0x0C, 0) // BUFF+NOCP
	res := fillN(sess, 3)
	if res[0] != OfferQueuedReport || res[1] != OfferQueued || res[2] != OfferQueued {
		t.Fatalf("results = %v", res)
	}
	if got := testutil.ToFloat64(UPFDLBufferedPacketsTotal) - before; got != 3 {
		t.Errorf("buffered counter delta = %v, want 3", got)
	}
}

func TestDLBufferDLDRContent(t *testing.T) {
	srv, sess, smf, _, addr := setup(t, 3, 1, 0, false)
	modFAR(t, addr, 1, 0x0C, 0)
	if sess.DLBuf.Offer([]byte("P1")) != OfferQueuedReport {
		t.Fatal("want report")
	}
	srv.NotifyDownlinkData(t.Context(), sess)
	waitFor(t, "DLDR", func() bool { return smf.count() == 1 })
	smf.mu.Lock()
	r := smf.reqs[0]
	smf.mu.Unlock()
	if r.SEID() != bufSEID {
		t.Errorf("header SEID = %d, want CP SEID %d", r.SEID(), bufSEID)
	}
	if !r.ReportType.HasDLDR() || r.ReportType.HasUSAR() {
		t.Error("Report Type must be DLDR only")
	}
	ies, err := r.DownlinkDataReport.DownlinkDataReport()
	if err != nil {
		t.Fatal(err)
	}
	var pdr uint16
	for _, c := range ies {
		if c.Type == pfcpie.PDRID {
			pdr, _ = c.PDRID()
		}
	}
	if pdr != 2 {
		t.Errorf("DLDR PDR ID = %d, want 2", pdr)
	}
	for _, c := range ies {
		if c.Type == pfcpie.DownlinkDataServiceInformation {
			t.Error("no QFI is known: DL Data Service Information must be absent")
		}
	}
	smf.quiet(t, quietWindow)
	if smf.count() != 1 {
		t.Errorf("reports = %d, want exactly 1", smf.count())
	}
}

func TestDLBufferNoReportWithoutNOCP(t *testing.T) {
	_, sess, smf, _, addr := setup(t, 3, 1, 0, false)
	modFAR(t, addr, 1, 0x04, 0)
	if sess.DLBuf.Offer([]byte("P1")) != OfferQueued {
		t.Fatal("BUFF without NOCP must queue silently")
	}
	smf.quiet(t, quietWindow)
	if smf.count() != 0 {
		t.Error("no Session Report Request expected")
	}
}

func TestDLBufferFlushFIFOOnForw(t *testing.T) {
	_, sess, _, fl, addr := setup(t, 3, 1, 0, false)
	modFAR(t, addr, 1, 0x0C, 0)
	fillN(sess, 4) // P4 over the limit
	modFAR(t, addr, 1, 0x02, 0x1234)
	got := fl.got()
	if len(got) != 3 || !bytes.Equal(got[0], []byte("P1")) || !bytes.Equal(got[1], []byte("P2")) || !bytes.Equal(got[2], []byte("P3")) {
		t.Fatalf("flushed %q, want P1 P2 P3", got)
	}
	if sess.DLBuf.Len() != 0 || sess.DLBuf.Active() {
		t.Error("buffer must be empty and inactive after the flush")
	}
	if sess.DLBuf.Offer([]byte("P5")) != OfferNotBuffering {
		t.Error("after the flush packets bypass the buffer")
	}
	if sess.DLTEID != 0x1234 {
		t.Errorf("DL TEID = %#x, want 0x1234", sess.DLTEID)
	}
}

func TestDLBufferDropAndDeletionDiscard(t *testing.T) {
	_, sess, _, fl, addr := setup(t, 3, 1, 0, false)
	modFAR(t, addr, 1, 0x04, 0)
	fillN(sess, 2)
	d0 := dropped(DLDropFARDrop)
	modFAR(t, addr, 1, 0x01, 0) // DROP
	if dropped(DLDropFARDrop)-d0 != 2 || sess.DLBuf.Len() != 0 || sess.DLBuf.Active() {
		t.Error("DROP must discard 2 packets and stop buffering")
	}
	modFAR(t, addr, 1, 0x04, 0)
	fillN(sess, 2)
	s0 := dropped(DLDropSessionDeleted)
	del := pfcpmsg.NewSessionDeletionRequest(0, 0, bufSEID, 3, 0)
	if _, ok := sendAndRecv(t, addr, del).(*pfcpmsg.SessionDeletionResponse); !ok {
		t.Fatal("expected deletion response")
	}
	if dropped(DLDropSessionDeleted)-s0 != 2 {
		t.Error("deletion must count 2 discarded packets")
	}
	if len(fl.got()) != 0 {
		t.Error("nothing may be flushed")
	}
}

func TestDLBufferCPRejectDiscards(t *testing.T) {
	srv, sess, smf, _, addr := setup(t, 3, 65, 0, false)
	modFAR(t, addr, 1, 0x0C, 0)
	c0 := dropped(DLDropCPRejected)
	if sess.DLBuf.Offer([]byte("P1")) != OfferQueuedReport {
		t.Fatal("want report")
	}
	srv.NotifyDownlinkData(t.Context(), sess)
	waitFor(t, "DLDR", func() bool { return smf.count() == 1 })
	waitFor(t, "cp_rejected", func() bool { return dropped(DLDropCPRejected)-c0 == 1 })
	if sess.DLBuf.Len() != 0 {
		t.Error("buffer must be empty after a rejected DLDR")
	}
}

func TestDLBufferFlushOrderWithConcurrentArrivals(t *testing.T) {
	var b DLBuffer
	b.SetLimit(1000)
	b.Arm(false)
	for i := 0; i < 10; i++ {
		b.Offer([]byte{byte(i)})
	}
	if !b.BeginFlush() {
		t.Fatal("flush expected")
	}
	// Arrivals during the flush queue behind the backlog.
	if b.Offer([]byte{10}) != OfferQueued {
		t.Fatal("arrival during flush must queue")
	}
	var out []byte
	for {
		batch, done := b.NextBatch()
		if done {
			break
		}
		for _, p := range batch {
			out = append(out, p[0])
			if p[0] == 3 {
				b.Offer([]byte{11})
			}
		}
	}
	want := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	if !bytes.Equal(out, want) {
		t.Errorf("order %v, want %v", out, want)
	}
	if b.Offer([]byte{12}) != OfferNotBuffering {
		t.Error("buffer must be inactive after the flush")
	}
}

func TestDLBufferOfferCopies(t *testing.T) {
	var b DLBuffer
	b.Arm(false)
	p := []byte("abc")
	b.Offer(p)
	p[0] = 'X'
	if got := b.Packets()[0]; string(got) != "abc" {
		t.Errorf("buffer aliases the caller slice: %q", got)
	}
}

func TestDLBufferDLDRCarriesQFI(t *testing.T) {
	srv, sess, smf, _, addr := setup(t, 3, 1, 0, false)
	sess.qos.Store(&qosView{dlQFI: 9, hasQFI: true})
	modFAR(t, addr, 1, 0x0C, 0)
	if sess.DLBuf.Offer([]byte("P1")) != OfferQueuedReport {
		t.Fatal("want report")
	}
	srv.NotifyDownlinkData(t.Context(), sess)
	waitFor(t, "DLDR", func() bool { return smf.count() == 1 })
	smf.mu.Lock()
	r := smf.reqs[0]
	smf.mu.Unlock()
	ies, err := r.DownlinkDataReport.DownlinkDataReport()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range ies {
		if c.Type != pfcpie.DownlinkDataServiceInformation {
			continue
		}
		found = true
		pl, err := c.DownlinkDataServiceInformation()
		if err != nil || len(pl) < 2 {
			t.Fatalf("DL Data Service Information payload %x err %v", pl, err)
		}
		if pl[0]&0x02 == 0 {
			t.Errorf("QFII flag not set: %#x", pl[0])
		}
		if pl[len(pl)-1] != 9 {
			t.Errorf("QFI = %d, want 9", pl[len(pl)-1])
		}
	}
	if !found {
		t.Fatal("DL Data Service Information missing")
	}
}

// shortT1 makes DLDR retransmission fast for tests.
func shortT1(srv *Server, n1 int) {
	srv.dldrT1, srv.dldrN1 = 20*time.Millisecond, n1
}

func TestDLBufferDLDRRetransmitAndExpiry(t *testing.T) {
	srv, sess, smf, _, addr := setup(t, 3, 1, 0, false)
	shortT1(srv, 2)
	smf.mute.Store(true)
	modFAR(t, addr, 1, 0x0C, 0)
	f0 := testutil.ToFloat64(dldrFailure)
	if sess.DLBuf.Offer([]byte("P1")) != OfferQueuedReport {
		t.Fatal("want report")
	}
	srv.NotifyDownlinkData(t.Context(), sess)
	waitFor(t, "initial DLDR + N1 retransmissions", func() bool { return smf.count() == 3 })
	waitFor(t, "pending cleared on expiry", func() bool { return srv.dldrPendingLen() == 0 })
	waitFor(t, "failure counted", func() bool { return testutil.ToFloat64(dldrFailure)-f0 == 1 })
	smf.mu.Lock()
	seq := smf.reqs[0].Sequence()
	for i, r := range smf.reqs {
		if r.Sequence() != seq {
			t.Errorf("retransmission %d changed the sequence number", i)
		}
	}
	smf.mu.Unlock()
	smf.quiet(t, quietWindow)
	if sess.DLBuf.Len() != 1 || !sess.DLBuf.Active() {
		t.Error("buffering must continue after DLDR expiry")
	}
}

func TestDLBufferDLDRRetransmitStopsOnResponse(t *testing.T) {
	srv, sess, smf, _, addr := setup(t, 3, 1, 0, false)
	shortT1(srv, 5)
	smf.mute.Store(true)
	modFAR(t, addr, 1, 0x0C, 0)
	sess.DLBuf.Offer([]byte("P1"))
	srv.NotifyDownlinkData(t.Context(), sess)
	waitFor(t, "one retransmission", func() bool { return smf.count() >= 2 })
	smf.mute.Store(false)
	waitFor(t, "response clears pending", func() bool { return srv.dldrPendingLen() == 0 })
	smf.quiet(t, quietWindow)
	if smf.count() > 5 {
		t.Errorf("retransmissions continued after the response: %d", smf.count())
	}
}

func TestDLBufferDLDRTimerStopsOnDiscard(t *testing.T) {
	srv, sess, smf, _, addr := setup(t, 3, 1, 0, false)
	shortT1(srv, 5)
	smf.mute.Store(true)
	modFAR(t, addr, 1, 0x0C, 0)
	sess.DLBuf.Offer([]byte("P1"))
	srv.NotifyDownlinkData(t.Context(), sess)
	waitFor(t, "DLDR", func() bool { return smf.count() >= 1 })
	modFAR(t, addr, 1, 0x01, 0) // DROP discards the buffer and the pending DLDR
	if srv.dldrPendingLen() != 0 {
		t.Fatal("pending DLDR must be cleared on discard")
	}
	smf.quiet(t, quietWindow)
}

func TestDLBufferNotifyAfterDiscardRegistersNothing(t *testing.T) {
	srv, sess, smf, _, addr := setup(t, 3, 1, 0, false)
	modFAR(t, addr, 1, 0x0C, 0)
	sess.DLBuf.Offer([]byte("P1"))
	srv.discardDLBuffer(t.Context(), sess, DLDropSessionDeleted)
	srv.NotifyDownlinkData(t.Context(), sess)
	if srv.dldrPendingLen() != 0 {
		t.Error("a DLDR racing a discard must not leave a pending entry")
	}
	smf.quiet(t, quietWindow)
}

func TestDLBufferRearmAfterFlush(t *testing.T) {
	srv, sess, smf, fl, addr := setup(t, 3, 1, 0, false)
	for cycle := 1; cycle <= 2; cycle++ {
		modFAR(t, addr, 1, 0x0C, 0)
		if r := sess.DLBuf.Offer([]byte{byte(cycle)}); r != OfferQueuedReport {
			t.Fatalf("cycle %d: first packet result %v, want report", cycle, r)
		}
		srv.NotifyDownlinkData(t.Context(), sess)
		waitFor(t, "DLDR", func() bool { return smf.count() == cycle })
		modFAR(t, addr, 1, 0x02, 0x1234)
		if got := len(fl.got()); got != cycle {
			t.Fatalf("cycle %d: flushed %d packets total, want %d", cycle, got, cycle)
		}
		if sess.DLBuf.Active() {
			t.Fatalf("cycle %d: buffer must be inactive after the flush", cycle)
		}
	}
}

func TestDLBufferArmDuringFlushStopsDrain(t *testing.T) {
	var b DLBuffer
	b.SetLimit(100)
	b.Arm(false)
	for i := 0; i < 5; i++ {
		b.Offer([]byte{byte(i)})
	}
	if !b.BeginFlush() {
		t.Fatal("flush expected")
	}
	batch, done := b.NextBatch()
	if done || len(batch) != 5 {
		t.Fatalf("batch %d done %v", len(batch), done)
	}
	if st, _ := b.StopFlushIfBuffering(batch[2:]); st {
		t.Fatal("not buffering yet: the drain must continue")
	}
	b.Arm(true) // BUFF+NOCP arrives mid-flush
	// Re-armed NOCP: the arrival during the flush triggers the DLDR itself.
	if r := b.Offer([]byte{5}); r != OfferQueuedReport {
		t.Fatalf("arrival after re-arm = %v, want report", r)
	}
	stopped, report := b.StopFlushIfBuffering(batch[2:])
	if !stopped || report {
		t.Fatalf("stopped=%v report=%v, want true/false (DLDR already armed by the arrival)", stopped, report)
	}
	var got []byte
	for _, p := range b.Packets() {
		got = append(got, p[0])
	}
	if !bytes.Equal(got, []byte{2, 3, 4, 5}) {
		t.Errorf("buffer %v, want [2 3 4 5] in order", got)
	}
	if !b.Active() || !b.Buffering() {
		t.Error("buffer must stay active and buffering")
	}
}
