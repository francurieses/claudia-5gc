//go:build functional

// Step definitions for dl_buffering.feature (SMF-011, UPF side): a real
// pfcp.Server and gtpu.Server in-process on loopback, a fake SMF PFCP peer
// recording Session Report Requests, the DNN TUN as a socketpair and the gNB
// N3 endpoint as a loopback UDP socket. Metrics are read as before/after deltas
// from the real Prometheus registry.
// Ref: TS 29.244 §5.2.3.1, §7.5.2.6, §7.5.4.3, §7.5.8; TS 23.501 §5.8.2.19.2.
package features

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/gtpu"
	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
)

const (
	dlUEIP    = "10.60.0.7"
	dlSEID    = uint64(0x5A1)
	dlULTEID  = uint32(0x5A2)
	dlGNBTEID = uint32(0x1234)
	dlWait    = 3 * time.Second
	dlQuiet   = 200 * time.Millisecond
)

var dlReasons = []string{pfcp.DLDropBufferFull, pfcp.DLDropFARDrop, pfcp.DLDropSessionDeleted,
	pfcp.DLDropCPRejected, pfcp.DLDropFlushUnavailable}

// dlSMF is the fake SMF PFCP peer.
type dlSMF struct {
	conn  *net.UDPConn
	mu    sync.Mutex
	cause uint8
	reqs  []*pfcpmsg.SessionReportRequest
}

func (f *dlSMF) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		m, err := pfcpmsg.Parse(buf[:n])
		if err != nil {
			continue
		}
		r, ok := m.(*pfcpmsg.SessionReportRequest)
		if !ok {
			continue
		}
		f.mu.Lock()
		f.reqs = append(f.reqs, r)
		c := f.cause
		f.mu.Unlock()
		resp := pfcpmsg.NewSessionReportResponse(0, 0, r.SEID(), r.Sequence(), 0, pfcpie.NewCause(c))
		b := make([]byte, resp.MarshalLen())
		if resp.MarshalTo(b) == nil {
			_, _ = f.conn.WriteToUDP(b, from)
		}
	}
}

func (f *dlSMF) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

type dlWorld struct {
	started bool
	limit   int
	cancel  context.CancelFunc
	psrv    *pfcp.Server
	gsrv    *gtpu.Server
	table   *pfcp.SessionTable
	sess    *pfcp.Session
	smf     *dlSMF
	gnb     *net.UDPConn
	tunR    *os.File
	tunW    *os.File
	pfcpAdr string
	seq     uint32

	bufBase  float64
	dropBase map[string]float64
}

func dlPoll(what string, d time.Duration, cond func() bool) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		<-time.After(5 * time.Millisecond)
	}
	if cond() {
		return nil
	}
	return fmt.Errorf("timeout waiting for %s", what)
}

// quiet reports whether cond stays false for the whole quiet window.
func dlQuietFor(cond func() bool) bool {
	deadline := time.Now().Add(dlQuiet)
	for time.Now().Before(deadline) {
		if cond() {
			return false
		}
		<-time.After(5 * time.Millisecond)
	}
	return !cond()
}

func (w *dlWorld) reset() {
	if w.cancel != nil {
		w.cancel()
	}
	if w.psrv != nil {
		_ = w.psrv.Close()
	}
	if w.smf != nil {
		_ = w.smf.conn.Close()
	}
	for _, f := range []*os.File{w.tunW, w.tunR} {
		if f != nil {
			_ = f.Close()
		}
	}
	if w.gnb != nil {
		_ = w.gnb.Close()
	}
	*w = dlWorld{}
}

func (w *dlWorld) givenUPF() error {
	*w = dlWorld{limit: 3}
	return nil
}

func (w *dlWorld) givenLimit(n int) error {
	w.limit = n
	return nil
}

func (w *dlWorld) givenSession(pdr int, ue string, far, bar, ulpdr, ulfar int) error {
	if pdr != 2 || far != 1 || bar != 1 || ulpdr != 1 || ulfar != 2 {
		return fmt.Errorf("unsupported fixture %d/%d/%d/%d/%d", pdr, far, bar, ulpdr, ulfar)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("127.0.0.1:%d", gnbPort))
	if err != nil {
		return fmt.Errorf("bind gNB listener: %w", err)
	}
	w.gnb = pc.(*net.UDPConn)

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	for _, fd := range fds {
		_ = syscall.SetNonblock(fd, true)
	}
	w.tunR = os.NewFile(uintptr(fds[0]), "tun-upf")
	w.tunW = os.NewFile(uintptr(fds[1]), "tun-peer")

	smfConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	w.smf = &dlSMF{conn: smfConn, cause: pfcpie.CauseRequestAccepted}
	go w.smf.serve()

	w.table = pfcp.NewSessionTable()
	n3, err := freeUDPAddr()
	if err != nil {
		return err
	}
	if w.pfcpAdr, err = freeUDPAddr(); err != nil {
		return err
	}
	if w.gsrv, err = gtpu.New(gtpu.Config{Address: n3, N3IP: n3IP}, log, w.table,
		[]gtpu.TUNEntry{{DNN: "internet", Subnet: "10.60.0.0/24", TunFile: w.tunR}}); err != nil {
		return err
	}
	if w.psrv, err = pfcp.New(pfcp.Config{Address: w.pfcpAdr, NodeIP: "127.0.0.1", RAInterval: time.Hour,
		DLBufferDefaultPackets: w.limit}, log, w.table); err != nil {
		return err
	}
	w.psrv.SetDLFlusher(w.gsrv)
	w.gsrv.SetPFCPServer(w.psrv)
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	go func() { _ = w.psrv.Start(ctx) }()
	go func() { _ = w.gsrv.Start(ctx) }()

	est := pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, w.nextSeq(), 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(dlSEID, net.ParseIP("127.0.0.1"), nil),
		pfcpie.NewCreatePDR(pfcpie.NewPDRID(1), pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, dlULTEID, net.ParseIP("127.0.0.1"), nil, 0)),
			pfcpie.NewFARID(2)),
		pfcpie.NewCreatePDR(pfcpie.NewPDRID(2), pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceCore),
				pfcpie.NewUEIPAddress(0x02, ue, "", 0, 0)),
			pfcpie.NewFARID(1)),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02), pfcpie.NewBARID(1)),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(2), pfcpie.NewApplyAction(0x02)),
		pfcpie.NewCreateBAR(pfcpie.NewBARID(1)))
	resp, err := pfcpExchange(w.pfcpAdr, est)
	if err != nil {
		return err
	}
	if _, ok := resp.(*pfcpmsg.SessionEstablishmentResponse); !ok {
		return fmt.Errorf("expected Session Establishment Response, got %s", resp.MessageTypeName())
	}
	if w.sess = w.table.GetByULTEID(dlULTEID); w.sess == nil {
		return fmt.Errorf("session not stored in the UPF")
	}
	w.sess.SMFAddr = smfConn.LocalAddr().(*net.UDPAddr)

	w.bufBase = testutil.ToFloat64(pfcp.UPFDLBufferedPacketsTotal)
	w.dropBase = map[string]float64{}
	for _, r := range dlReasons {
		w.dropBase[r] = testutil.ToFloat64(pfcp.UPFDLBufferDroppedTotal.WithLabelValues(r))
	}
	return nil
}

func (w *dlWorld) nextSeq() uint32 { w.seq++; return w.seq }

func (w *dlWorld) modifyFAR(aa uint8, forw bool) error {
	ies := []*pfcpie.IE{pfcpie.NewFARID(1), pfcpie.NewApplyAction(aa)}
	if forw {
		ies = append(ies, pfcpie.NewUpdateForwardingParameters(
			pfcpie.NewDestinationInterface(pfcpie.DstInterfaceAccess),
			pfcpie.NewOuterHeaderCreation(0x0100, dlGNBTEID, "127.0.0.1", "", 0, 0, 0)))
	}
	resp, err := pfcpExchange(w.pfcpAdr,
		pfcpmsg.NewSessionModificationRequest(0, 0, dlSEID, w.nextSeq(), 0, pfcpie.NewUpdateFAR(ies...)))
	if err != nil {
		return err
	}
	if r, ok := resp.(*pfcpmsg.SessionModificationResponse); !ok {
		return fmt.Errorf("expected Session Modification Response, got %s", resp.MessageTypeName())
	} else if c, _ := r.Cause.Cause(); c != pfcpie.CauseRequestAccepted {
		return fmt.Errorf("Session Modification Response Cause %d, want 1", c)
	}
	return nil
}

func (w *dlWorld) givenFAR(aa string) error {
	switch aa {
	case "BUFF+NOCP":
		return w.modifyFAR(0x0C, false)
	case "BUFF without NOCP":
		return w.modifyFAR(0x04, false)
	}
	return fmt.Errorf("unsupported Apply Action %q", aa)
}

// dlPacket builds an IPv4/UDP packet to ue whose UDP payload is name.
func dlPacket(ue, name string) []byte {
	pl := []byte(name)
	n := 28 + len(pl)
	p := make([]byte, n)
	p[0] = 0x45
	p[2], p[3] = byte(n>>8), byte(n)
	p[8], p[9] = 64, 17
	copy(p[12:16], net.IPv4(8, 8, 8, 8).To4())
	copy(p[16:20], net.ParseIP(ue).To4())
	p[20], p[21], p[22], p[23] = 0x13, 0x88, 0x13, 0x89
	l := 8 + len(pl)
	p[24], p[25] = byte(l>>8), byte(l)
	copy(p[28:], pl)
	return p
}

func (w *dlWorld) inject(name string) {
	w.gsrv.InjectDownlink("internet", dlPacket(dlUEIP, name))
}

func (w *dlWorld) whenPacket(name string) error {
	w.inject(name)
	return nil
}

func (w *dlWorld) whenPackets(a, b string) error {
	w.inject(a)
	w.inject(b)
	return nil
}

func (w *dlWorld) givenBuffered(list string) error {
	names := quoted(list)
	for _, n := range names {
		w.inject(n)
	}
	return w.bufferIs(names)
}

func (w *dlWorld) givenBufferedReported(name string) error {
	w.inject(name)
	return w.reportCount(1)
}

var quotedRE = regexp.MustCompile(`"([^"]*)"`)

func quoted(s string) []string {
	var out []string
	for _, m := range quotedRE.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

func (w *dlWorld) payloads() []string {
	var out []string
	for _, p := range w.sess.DLBuf.Packets() {
		out = append(out, string(p[28:]))
	}
	return out
}

func (w *dlWorld) bufferIs(names []string) error {
	if err := dlPoll("buffer contents", dlWait, func() bool {
		return strings.Join(w.payloads(), ",") == strings.Join(names, ",")
	}); err != nil {
		return fmt.Errorf("buffer holds %v, want %v: %w", w.payloads(), names, err)
	}
	return nil
}

func (w *dlWorld) thenBufferHolds(list string) error { return w.bufferIs(quoted(list)) }

func (w *dlWorld) thenDiscarded(p4, list string) error {
	return w.bufferIs(quoted(list))
}

func (w *dlWorld) bufferedNotDropped() error {
	if w.sess.DLBuf.Len() != 1 {
		return fmt.Errorf("buffer holds %d packets, want 1", w.sess.DLBuf.Len())
	}
	for _, r := range dlReasons {
		if d := testutil.ToFloat64(pfcp.UPFDLBufferDroppedTotal.WithLabelValues(r)) - w.dropBase[r]; d != 0 {
			return fmt.Errorf("drop counter %q moved by %v, want 0", r, d)
		}
	}
	return nil
}

func (w *dlWorld) thenBuffered() error {
	if w.sess.DLBuf.Len() != 1 {
		return fmt.Errorf("buffer holds %d packets, want 1", w.sess.DLBuf.Len())
	}
	return nil
}

func (w *dlWorld) reportCount(n int) error {
	if err := dlPoll(fmt.Sprintf("%d Session Report Request(s)", n), dlWait, func() bool { return w.smf.count() >= n }); err != nil {
		return fmt.Errorf("fake SMF has %d Session Report Requests: %w", w.smf.count(), err)
	}
	if !dlQuietFor(func() bool { return w.smf.count() != n }) {
		return fmt.Errorf("fake SMF received %d Session Report Requests, want exactly %d", w.smf.count(), n)
	}
	return nil
}

func (w *dlWorld) thenExactlyOneDLDR() error {
	if err := w.reportCount(1); err != nil {
		return err
	}
	w.smf.mu.Lock()
	defer w.smf.mu.Unlock()
	if !w.smf.reqs[0].ReportType.HasDLDR() || w.smf.reqs[0].ReportType.HasUSAR() {
		return fmt.Errorf("Report Type is not DLDR only")
	}
	return nil
}

func (w *dlWorld) thenDLDRPDR(id int) error {
	w.smf.mu.Lock()
	defer w.smf.mu.Unlock()
	if len(w.smf.reqs) == 0 || w.smf.reqs[0].DownlinkDataReport == nil {
		return fmt.Errorf("no Downlink Data Report received")
	}
	ies, err := w.smf.reqs[0].DownlinkDataReport.DownlinkDataReport()
	if err != nil {
		return err
	}
	for _, c := range ies {
		if c.Type == pfcpie.PDRID {
			got, _ := c.PDRID()
			if int(got) != id {
				return fmt.Errorf("Downlink Data Report PDR ID %d, want %d", got, id)
			}
			return nil
		}
	}
	return fmt.Errorf("Downlink Data Report carries no PDR ID")
}

func (w *dlWorld) thenNoReport() error {
	if !dlQuietFor(func() bool { return w.smf.count() != 0 }) {
		return fmt.Errorf("fake SMF received %d Session Report Requests, want none", w.smf.count())
	}
	return nil
}

func (w *dlWorld) thenTotalReports(n int) error { return w.reportCount(n) }

func (w *dlWorld) thenMetric(name string, want float64) error {
	if name != "fivegc_upf_dl_buffered_packets_total" {
		return fmt.Errorf("unsupported metric %q", name)
	}
	var got float64
	if err := dlPoll(name, dlWait, func() bool {
		got = testutil.ToFloat64(pfcp.UPFDLBufferedPacketsTotal) - w.bufBase
		return got == want
	}); err != nil {
		return fmt.Errorf("%s delta = %v, want %v", name, got, want)
	}
	return nil
}

func (w *dlWorld) thenDropMetric(reason string, want float64) error {
	var got float64
	if err := dlPoll("drop counter", dlWait, func() bool {
		got = testutil.ToFloat64(pfcp.UPFDLBufferDroppedTotal.WithLabelValues(reason)) - w.dropBase[reason]
		return got == want
	}); err != nil {
		return fmt.Errorf("fivegc_upf_dl_buffer_dropped_total{reason=%q} delta = %v, want %v", reason, got, want)
	}
	return nil
}

func (w *dlWorld) whenForw() error { return w.modifyFAR(0x02, true) }
func (w *dlWorld) whenDrop() error { return w.modifyFAR(0x01, false) }

func (w *dlWorld) whenDelete() error {
	resp, err := pfcpExchange(w.pfcpAdr, pfcpmsg.NewSessionDeletionRequest(0, 0, dlSEID, w.nextSeq(), 0))
	if err != nil {
		return err
	}
	if _, ok := resp.(*pfcpmsg.SessionDeletionResponse); !ok {
		return fmt.Errorf("expected Session Deletion Response, got %s", resp.MessageTypeName())
	}
	return nil
}

func (w *dlWorld) givenCause(c int) error {
	w.smf.mu.Lock()
	w.smf.cause = uint8(c)
	w.smf.mu.Unlock()
	return nil
}

// recvPayloads reads n GTP-U datagrams at the gNB endpoint and returns the UDP
// payload of each inner IPv4 packet (GTP-U header 8 + extension 8 octets).
func (w *dlWorld) recvPayloads(n int) ([]string, error) {
	var out []string
	buf := make([]byte, 4096)
	for i := 0; i < n; i++ {
		_ = w.gnb.SetReadDeadline(time.Now().Add(dlWait))
		l, _, err := w.gnb.ReadFromUDP(buf)
		if err != nil {
			return out, fmt.Errorf("gNB received %d of %d GTP-U packets: %w", i, n, err)
		}
		d := buf[:l]
		if l < 8+gtpuExtOctets+28 {
			return out, fmt.Errorf("short GTP-U datagram (%d octets)", l)
		}
		if teid := uint32(d[4])<<24 | uint32(d[5])<<16 | uint32(d[6])<<8 | uint32(d[7]); teid != dlGNBTEID {
			return out, fmt.Errorf("GTP-U TEID %#x, want %#x", teid, dlGNBTEID)
		}
		out = append(out, string(d[8+gtpuExtOctets+28:]))
	}
	return out, nil
}

func (w *dlWorld) thenGNBReceives(list string) error {
	want := quoted(list)
	got, err := w.recvPayloads(len(want))
	if err != nil {
		return err
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		return fmt.Errorf("gNB received %v, want %v in that order", got, want)
	}
	return nil
}

func (w *dlWorld) thenBufferEmpty() error {
	return dlPoll("empty buffer", dlWait, func() bool { return w.sess.DLBuf.Len() == 0 })
}

func (w *dlWorld) thenFirstNoDrop(first string) error {
	for _, r := range dlReasons {
		if d := testutil.ToFloat64(pfcp.UPFDLBufferDroppedTotal.WithLabelValues(r)) - w.dropBase[r]; d != 0 {
			return fmt.Errorf("drop counter %q moved by %v, want 0", r, d)
		}
	}
	return nil
}

func (w *dlWorld) thenNothingForwarded() error {
	_ = w.gnb.SetReadDeadline(time.Now().Add(dlQuiet))
	buf := make([]byte, 4096)
	if _, _, err := w.gnb.ReadFromUDP(buf); err == nil {
		return fmt.Errorf("a GTP-U packet reached the gNB tunnel endpoint, want none")
	}
	return nil
}

func (w *dlWorld) thenBufferEmptyNothingForwarded() error {
	if err := w.thenBufferEmpty(); err != nil {
		return err
	}
	return w.thenNothingForwarded()
}

func (w *dlWorld) thenBufferGone() error {
	if err := dlPoll("buffer discard", dlWait, func() bool { return w.sess.DLBuf.Len() == 0 }); err != nil {
		return err
	}
	if w.table.GetByULTEID(dlULTEID) != nil {
		return fmt.Errorf("session still present in the UPF after deletion")
	}
	return w.thenNothingForwarded()
}

var dlScrape string

func (w *dlWorld) whenScrape() error {
	rec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		return fmt.Errorf("/metrics returned %d", rec.Code)
	}
	dlScrape = rec.Body.String()
	return nil
}

func (w *dlWorld) thenExposesCounter(name string) error {
	if !strings.Contains(dlScrape, "# TYPE "+name+" counter") {
		return fmt.Errorf("exposition lacks counter %s", name)
	}
	return nil
}

func (w *dlWorld) thenGauge(name string, want int) error {
	for _, l := range strings.Split(dlScrape, "\n") {
		if strings.HasPrefix(l, name+" ") {
			v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(l, name)), 64)
			if err != nil {
				return err
			}
			if int(v) != want {
				return fmt.Errorf("gauge %s = %v, want %d", name, v, want)
			}
			return nil
		}
	}
	return fmt.Errorf("exposition lacks gauge %s", name)
}

func registerDLBufferSteps(sc *godog.ScenarioContext) {
	w := &dlWorld{}
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.reset()
		return ctx, nil
	})
	sc.Step(`^an in-process UPF with a PFCP server and a fake SMF PFCP peer recording Session Report Requests$`, w.givenUPF)
	sc.Step(`^the UPF DL buffer limit is (\d+) packets$`, w.givenLimit)
	sc.Step(`^a PFCP session with DL PDR (\d+) for UE IP (\S+) referencing FAR (\d+) with BAR ID (\d+) and UL PDR (\d+) referencing FAR (\d+)$`,
		func(pdr int, ue string, far, bar, ulpdr, ulfar int) error {
			return w.givenSession(pdr, ue, far, bar, ulpdr, ulfar)
		})
	sc.Step(`^FAR 1 has Apply Action (BUFF\+NOCP|BUFF without NOCP)$`, w.givenFAR)
	sc.Step(`^a DL packet ("P\d+") for UE IP 10\.60\.0\.7 arrives from the N6 side$`,
		func(p string) error { return w.whenPacket(strings.Trim(p, `"`)) })
	sc.Step(`^a DL packet ("P\d+") arrives for UE IP 10\.60\.0\.7$`,
		func(p string) error { return w.whenPacket(strings.Trim(p, `"`)) })
	sc.Step(`^DL packets ("P\d+") and ("P\d+") arrive for UE IP 10\.60\.0\.7$`,
		func(a, b string) error { return w.whenPackets(strings.Trim(a, `"`), strings.Trim(b, `"`)) })
	sc.Step(`^a DL packet ("P\d+") for UE IP 10\.60\.0\.7 was buffered and reported$`,
		func(p string) error { return w.givenBufferedReported(strings.Trim(p, `"`)) })
	sc.Step(`^DL packets (.+) are buffered$`, w.givenBuffered)
	sc.Step(`^the packet is buffered and not counted as dropped$`, w.bufferedNotDropped)
	sc.Step(`^the packet is buffered$`, w.thenBuffered)
	sc.Step(`^the fake SMF receives exactly one Session Report Request with Report Type DLDR$`, w.thenExactlyOneDLDR)
	sc.Step(`^the Downlink Data Report names PDR ID (\d+)$`, w.thenDLDRPDR)
	sc.Step(`^the fake SMF has received exactly one Session Report Request in total$`,
		func() error { return w.thenTotalReports(1) })
	sc.Step(`^the fake SMF receives no Session Report Request$`, w.thenNoReport)
	sc.Step(`^the metric "([^"]*)" is (\d+)$`, func(n string, v int) error { return w.thenMetric(n, float64(v)) })
	sc.Step(`^the metric "fivegc_upf_dl_buffer_dropped_total" with reason "([^"]*)" is (\d+)$`,
		func(r string, v int) error { return w.thenDropMetric(r, float64(v)) })
	sc.Step(`^the buffer holds (.+) in that order$`, w.thenBufferHolds)
	sc.Step(`^("P\d+") is discarded and the buffer still holds (.+) in that order$`, w.thenDiscarded)
	sc.Step(`^the SMF sends a PFCP Session Modification Request with Update FAR 1 Apply Action FORW and Outer Header Creation to the gNB N3 tunnel$`, w.whenForw)
	sc.Step(`^the SMF sends a PFCP Session Modification Request with Update FAR 1 Apply Action DROP$`, w.whenDrop)
	sc.Step(`^the SMF sends a PFCP Session Deletion Request for the session$`, w.whenDelete)
	sc.Step(`^the gNB tunnel endpoint receives GTP-U packets carrying (.+) in that order$`, w.thenGNBReceives)
	sc.Step(`^the buffer is empty$`, w.thenBufferEmpty)
	sc.Step(`^("P\d+") is received first and no buffered packet is dropped$`, w.thenFirstNoDrop)
	sc.Step(`^the buffer is empty and nothing is forwarded to the gNB tunnel endpoint$`, w.thenBufferEmptyNothingForwarded)
	sc.Step(`^the buffer is gone and nothing is forwarded to the gNB tunnel endpoint$`, w.thenBufferGone)
	sc.Step(`^the fake SMF answers Session Report Requests with Cause (\d+) "[^"]*"$`, w.givenCause)
	sc.Step(`^the UPF metrics endpoint is scraped$`, w.whenScrape)
	sc.Step(`^the exposition contains the counter "([^"]*)"$`, w.thenExposesCounter)
	sc.Step(`^the gauge "([^"]*)" equals (\d+)$`, w.thenGauge)
}
