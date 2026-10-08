//go:build functional

// Package features contains godog BDD step definitions for the UPF.
// Run with: make -C nf/upf test-functional
//
// The DownlinkChecksum suite (task UPF-003) drives the REAL downlink path
// in-process, no root and no real network:
//
//   - a pfcp.Server on loopback UDP establishes the PDU session (Session
//     Establishment + Session Modification carrying the DL TEID / gNB IP);
//   - the DNN "TUN" is one end of an AF_UNIX SOCK_DGRAM socketpair, so each
//     packet written is exactly one read in gtpu.startTUNReader (message
//     boundaries preserved, unlike a pipe);
//   - the gNB is a UDP listener on 127.0.0.1:2152 (sendGTPU hard-codes
//     gtpuPort and macOS only has 127.0.0.1 on loopback, so 127.0.0.2 is not
//     an option). The GTP-U server itself listens on 127.0.0.1:0, so there is
//     no clash (an ephemeral port picked up front). Scenarios run sequentially and release the port in After.
//   - the repair counter is the real Prometheus counter, wired exactly as in
//     cmd/upf/main.go via SetL4RepairHook, and read as a before/after delta.
//
// Scenarios tagged @e2e @manual need the live UERANSIM stack and are skipped
// (godog.ErrSkip) unless E2E_TEST=1; with E2E_TEST=1 they report pending
// because the live assertions are driven through the MCP tools (procedure
// doc recipe), not from Go.
//
// Checksum math here is an independent RFC 1071 implementation, never the
// l4csum package under test.
package features

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus/testutil"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/gtpu"
	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	n3IP          = "172.30.3.100"
	ueV6Addr      = "2001:db8:60::3"
	ulTEID        = uint32(0x2001)
	cpSEID        = uint64(0x77)
	gnbPort       = 2152 // gtpu.gtpuPort (unexported)
	recvTimeout   = 3 * time.Second
	extraWait     = 250 * time.Millisecond
	gtpuExtOctets = 8 // seq(2)+npdu(1)+next(1)+PDU Session Container(4)
)

var repairLabels = [][2]string{{"tcp", "v4"}, {"udp", "v4"}, {"tcp", "v6"}, {"udp", "v6"}}

// ---------- world ----------

type world struct {
	// background parameters
	ueAddr string
	dlTEID uint32
	qfi    uint8
	gnbLbl string
	repair bool

	// runtime
	started bool
	cancel  context.CancelFunc
	tunW    *os.File
	tunR    *os.File
	gnb     *net.UDPConn
	pfcpSrv *pfcp.Server
	n3Addr  string
	table   *pfcp.SessionTable
	base    map[[2]string]float64

	// scenario data
	pkt        []byte // packet injected into the TUN
	l4Off      int    // offset of the L4 header inside pkt
	proto      string // "TCP"/"UDP"
	ipv6       bool
	noSession  bool
	padding    int
	dgram      []byte // captured GTP-U datagram
	sentinel   []byte
	sentinelRx bool
	built      string // "icmp" | "ra"
}

func counts() map[[2]string]float64 {
	m := map[[2]string]float64{}
	for _, l := range repairLabels {
		m[l] = testutil.ToFloat64(metrics.UPFL4ChecksumRepairedTotal.WithLabelValues(l[0], l[1]))
	}
	return m
}

func (w *world) delta(proto, ip string) float64 {
	return testutil.ToFloat64(metrics.UPFL4ChecksumRepairedTotal.WithLabelValues(proto, ip)) - w.base[[2]string{proto, ip}]
}

func freeUDPAddr() (string, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.LocalAddr().String(), nil
}

func pfcpExchange(addr string, msg pfcpmsg.Message) (pfcpmsg.Message, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	b := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(b); err != nil {
		return nil, err
	}
	if _, err := conn.Write(b); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(recvTimeout))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("no PFCP response: %w", err)
	}
	return pfcpmsg.Parse(buf[:n])
}

// ensure builds and starts the in-process UPF the first time it is needed, so
// that the knob step can still change the configuration after the Background.
func (w *world) ensure() error {
	if w.started {
		return nil
	}
	w.started = true
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// SO_REUSEADDR lets this specific 127.0.0.1:2152 bind coexist with a wildcard
	// *:2152 socket (e.g. Docker Desktop publishing the live UPF's N3 port); the
	// kernel delivers to the most specific match, so the gNB listener wins.
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
	var gnb *net.UDPConn
	if err == nil {
		gnb = pc.(*net.UDPConn)
	}
	if err != nil {
		return fmt.Errorf("bind gNB listener 127.0.0.1:%d (needed: sendGTPU hard-codes the port): %w", gnbPort, err)
	}
	w.gnb = gnb

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	for _, fd := range fds {
		_ = syscall.SetNonblock(fd, true)
	}
	w.tunR = os.NewFile(uintptr(fds[0]), "tun-upf")
	w.tunW = os.NewFile(uintptr(fds[1]), "tun-peer")

	w.table = pfcp.NewSessionTable()
	if w.n3Addr, err = freeUDPAddr(); err != nil {
		return err
	}
	gtpuSrv, err := gtpu.New(gtpu.Config{Address: w.n3Addr, N3IP: n3IP, L4ChecksumRepair: w.repair},
		log, w.table, []gtpu.TUNEntry{{DNN: "internet", Subnet: "10.60.0.0/24", Subnet6: "2001:db8:60::/56", TunFile: w.tunR}})
	if err != nil {
		return err
	}
	// Same wiring as cmd/upf/main.go.
	gtpuSrv.SetL4RepairHook(func(proto, ipver string) {
		metrics.UPFL4ChecksumRepairedTotal.WithLabelValues(proto, ipver).Inc()
	})

	pfcpAddr, err := freeUDPAddr()
	if err != nil {
		return err
	}
	psrv, err := pfcp.New(pfcp.Config{Address: pfcpAddr, NodeIP: "127.0.0.1", RAInterval: time.Hour}, log, w.table)
	if err != nil {
		return err
	}
	psrv.SetRASender(gtpuSrv)
	w.pfcpSrv = psrv
	gtpuSrv.SetPFCPServer(psrv)

	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	go func() { _ = psrv.Start(ctx) }()
	go func() { _ = gtpuSrv.Start(ctx) }()

	// PFCP Session Establishment (dual-stack UE address) + Modification (DL tunnel).
	est := pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(cpSEID, net.ParseIP("127.0.0.1"), nil),
		pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(1), pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(
				pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, ulTEID, net.ParseIP("127.0.0.1"), nil, 0),
				pfcpie.NewUEIPAddress(0x03, w.ueAddr, ueV6Addr, 0, 0),
				pfcpie.NewNetworkInstance("internet"),
			),
			pfcpie.NewOuterHeaderRemoval(0, 0), pfcpie.NewFARID(1), pfcpie.NewQERID(1)),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02)),
		pfcpie.NewCreateQER(pfcpie.NewQERID(1), pfcpie.NewGateStatus(0, 0), pfcpie.NewMBR(100_000, 100_000), pfcpie.NewQFI(w.qfi)),
	)
	resp, err := pfcpExchange(pfcpAddr, est)
	if err != nil {
		return err
	}
	if _, ok := resp.(*pfcpmsg.SessionEstablishmentResponse); !ok {
		return fmt.Errorf("expected Session Establishment Response, got %s", resp.MessageTypeName())
	}
	mod := pfcpmsg.NewSessionModificationRequest(0, 0, cpSEID, 2, 0,
		pfcpie.NewUpdateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02),
			pfcpie.NewUpdateForwardingParameters(
				pfcpie.NewOuterHeaderCreation(0x0100, w.dlTEID, "127.0.0.1", "", 0, 0, 0))))
	resp, err = pfcpExchange(pfcpAddr, mod)
	if err != nil {
		return err
	}
	if _, ok := resp.(*pfcpmsg.SessionModificationResponse); !ok {
		return fmt.Errorf("expected Session Modification Response, got %s", resp.MessageTypeName())
	}
	w.base = counts()
	return nil
}

func (w *world) teardown() {
	if w.cancel != nil {
		w.cancel()
	}
	if w.pfcpSrv != nil {
		_ = w.pfcpSrv.Close()
	}
	if w.tunW != nil {
		_ = w.tunW.Close()
	}
	if w.tunR != nil {
		_ = w.tunR.Close()
	}
	if w.gnb != nil {
		_ = w.gnb.Close()
	}
}

// recv returns the next GTP-U datagram sent to the gNB within d.
func (w *world) recv(d time.Duration) ([]byte, error) {
	_ = w.gnb.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	n, _, err := w.gnb.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (w *world) inner() ([]byte, error) {
	if len(w.dgram) < 8+gtpuExtOctets+1 {
		return nil, errors.New("no GTP-U datagram captured")
	}
	return w.dgram[8+gtpuExtOctets:], nil
}

// ---------- RFC 1071 helpers (independent of l4csum) ----------

func sum16(b []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return uint16(s)
}

func pseudo(ip []byte, nh byte, l4len int) []byte {
	var p []byte
	if ip[0]>>4 == 4 {
		p = append(p, ip[12:20]...)
		p = append(p, 0, nh, byte(l4len>>8), byte(l4len))
	} else {
		p = append(p, ip[8:40]...)
		p = append(p, 0, 0, byte(l4len>>8), byte(l4len), 0, 0, 0, nh)
	}
	return p
}

// l4Sum is the folded (uncomplemented) sum over pseudo-header + segment as stored.
func l4Sum(ip []byte, nh byte, l4 []byte) uint16 {
	return fold(sum16(pseudo(ip, nh, len(l4))) + sum16(l4))
}

// rawCsum is the correct checksum for ip/l4 with the checksum field zeroed.
func rawCsum(ip []byte, nh byte, l4 []byte, csumOff int) uint16 {
	c := make([]byte, len(l4))
	copy(c, l4)
	c[csumOff], c[csumOff+1] = 0, 0
	return ^l4Sum(ip, nh, c)
}

func ipv4Hdr(b []byte) {
	b[10], b[11] = 0, 0
	c := ^fold(sum16(b[:20]))
	binary.BigEndian.PutUint16(b[10:], c)
}

// ---------- packet builders ----------

func buildV4(nh byte, src, dst string, l4 []byte, fragField uint16) []byte {
	p := make([]byte, 20+len(l4))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[6:], fragField)
	p[8], p[9] = 64, nh
	copy(p[12:], net.ParseIP(src).To4())
	copy(p[16:], net.ParseIP(dst).To4())
	copy(p[20:], l4)
	ipv4Hdr(p)
	return p
}

func buildV6(nh byte, src, dst string, l4 []byte) []byte {
	p := make([]byte, 40+len(l4))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], uint16(len(l4)))
	p[6], p[7] = nh, 64
	copy(p[8:], net.ParseIP(src).To16())
	copy(p[24:], net.ParseIP(dst).To16())
	copy(p[40:], l4)
	return p
}

func tcpSeg(window uint16) []byte {
	s := make([]byte, 24)
	binary.BigEndian.PutUint16(s[0:], 80)
	binary.BigEndian.PutUint16(s[2:], 58924)
	binary.BigEndian.PutUint32(s[4:], 0x01020304)
	binary.BigEndian.PutUint32(s[8:], 0x0a0b0c0d)
	s[12] = 5 << 4
	s[13] = 0x12 // SYN,ACK
	binary.BigEndian.PutUint16(s[14:], window)
	copy(s[20:], "data")
	return s
}

func udpDgram(tail uint16) []byte {
	d := make([]byte, 14) // 8 header + 6 payload; last 2 octets are the tunable word
	binary.BigEndian.PutUint16(d[0:], 5000)
	binary.BigEndian.PutUint16(d[2:], 4000)
	binary.BigEndian.PutUint16(d[4:], uint16(len(d)))
	copy(d[8:], "abcd")
	binary.BigEndian.PutUint16(d[12:], tail)
	return d
}

// solve returns the 16-bit value f for the field at l4[pos:pos+2] such that the
// correct checksum of the segment equals want (raw, before any RFC 768 mapping).
func solve(ip []byte, nh byte, l4 []byte, pos int, want uint16) (uint16, error) {
	c := make([]byte, len(l4))
	copy(c, l4)
	c[pos], c[pos+1] = 0, 0
	csumOff := 16
	if nh == 17 {
		csumOff = 6
	}
	c[csumOff], c[csumOff+1] = 0, 0
	s := uint32(l4Sum(ip, nh, c))
	t := uint32(^want)
	var f uint32
	if t >= s {
		f = t - s
	} else {
		f = t + 0xFFFF - s
	}
	binary.BigEndian.PutUint16(c[pos:], uint16(f))
	if got := rawCsum(ip, nh, c, csumOff); got != want {
		return 0, fmt.Errorf("could not tune field: want checksum 0x%04x got 0x%04x", want, got)
	}
	return uint16(f), nil
}

func put16(b []byte, off int, v uint16) { binary.BigEndian.PutUint16(b[off:], v) }

// mkV4 builds an IPv4 packet around a fully valid L4 segment (window tuned if
// wantRaw != nil) and stores `stored` as the checksum (nil = valid checksum).
func (w *world) mkV4(proto string, src, dst string, stored *uint16, wantRaw *uint16) error {
	var l4 []byte
	var nh byte
	var off, tune int
	if proto == "TCP" {
		l4, nh, off, tune = tcpSeg(0x7210), 6, 16, 14
	} else {
		l4, nh, off, tune = udpDgram(0), 17, 6, 12
	}
	ip := buildV4(nh, src, dst, l4, 0)
	if wantRaw != nil {
		f, err := solve(ip, nh, l4, tune, *wantRaw)
		if err != nil {
			return err
		}
		put16(l4, tune, f)
		ip = buildV4(nh, src, dst, l4, 0)
	}
	cs := rawCsum(ip, nh, ip[20:], off)
	if stored != nil {
		cs = *stored
	}
	put16(ip, 20+off, cs)
	w.pkt, w.l4Off, w.proto, w.ipv6 = ip, 20, proto, false
	return nil
}

func (w *world) mkV6(proto, dst string, stored uint16, valid bool) {
	var l4 []byte
	var nh byte
	var off int
	if proto == "TCP" {
		l4, nh, off = tcpSeg(0x7210), 6, 16
	} else {
		l4, nh, off = udpDgram(0x1111), 17, 6
	}
	ip := buildV6(nh, "2001:db8:ffff::1", dst, l4)
	cs := stored
	if valid {
		cs = rawCsum(ip, nh, ip[40:], off)
	}
	put16(ip, 40+off, cs)
	w.pkt, w.l4Off, w.proto, w.ipv6 = ip, 40, proto, true
}

// ---------- steps: Background ----------

func (w *world) aUPFWithSession(ue, teid, qfi, gnb string) error {
	t, err := strconv.ParseUint(teid, 0, 32)
	if err != nil {
		return err
	}
	q, err := strconv.ParseUint(qfi, 10, 8)
	if err != nil {
		return err
	}
	w.ueAddr, w.dlTEID, w.qfi, w.gnbLbl = ue, uint32(t), uint8(q), gnb
	return nil
}

func (w *world) knob(v string) error { w.repair = v == "true"; return nil }
func (w *world) counterRead() error  { return nil } // baseline is snapshotted when the UPF starts

// ---------- steps: Given (packets) ----------

func u16(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 0, 16)
	return uint16(v), err
}

func (w *world) givenSynAck(src, dst, stored, correct string) error {
	st, err := u16(stored)
	if err != nil {
		return err
	}
	want, err := u16(correct)
	if err != nil {
		return err
	}
	return w.mkV4("TCP", src, dst, &st, &want)
}

func (w *world) givenTCPZeroInvalid(dst string) error {
	z := uint16(0)
	if err := w.mkV4("TCP", "1.1.1.1", dst, &z, nil); err != nil {
		return err
	}
	if l4Sum(w.pkt, 6, w.pkt[20:]) == 0xFFFF {
		return errors.New("test packet unexpectedly verifies with checksum 0")
	}
	return nil
}

func (w *world) givenTCPValid(dst string) error { return w.mkV4("TCP", "1.1.1.1", dst, nil, nil) }

func (w *world) givenUDPZero(dst string) error {
	z := uint16(0)
	return w.mkV4("UDP", "1.1.1.1", dst, &z, nil)
}

func (w *world) givenUDPValid(dst string) error { return w.mkV4("UDP", "1.1.1.1", dst, nil, nil) }

func (w *world) givenUDPInvalid(dst string) error {
	if err := w.mkV4("UDP", "1.1.1.1", dst, nil, nil); err != nil {
		return err
	}
	bad := binary.BigEndian.Uint16(w.pkt[26:]) + 1
	if bad == 0 {
		bad = 2
	}
	put16(w.pkt, 26, bad)
	return nil
}

func (w *world) givenUDPComputesZero(dst, stored string) error {
	st, err := u16(stored)
	if err != nil {
		return err
	}
	zero := uint16(0)
	return w.mkV4("UDP", "1.1.1.1", dst, &st, &zero)
}

func (w *world) givenV6Invalid(proto, dst, _ string) error {
	w.mkV6(proto, dst, 0xBEEF, false)
	if rawCsum(w.pkt, map[string]byte{"TCP": 6, "UDP": 17}[proto], w.pkt[40:], map[string]int{"TCP": 16, "UDP": 6}[proto]) == 0xBEEF {
		return errors.New("test packet checksum collision")
	}
	return nil
}

func (w *world) givenV6UDPZero(dst string) error {
	w.mkV6("UDP", dst, 0, false)
	return nil
}

func (w *world) givenKind(kind, _ string) error {
	const bad = 0xBEEF
	v6dst := ueV6Addr
	switch kind {
	case "IPv4 fragment with MF=1", "IPv4 fragment with non-zero offset":
		frag := uint16(0x2000)
		if kind == "IPv4 fragment with non-zero offset" {
			frag = 0x0001
		}
		l4 := tcpSeg(1)
		put16(l4, 16, bad)
		w.pkt = buildV4(6, "1.1.1.1", w.ueAddr, l4, frag)
	case "truncated TCP header (less than 20 octets)":
		w.pkt = buildV4(6, "1.1.1.1", w.ueAddr, make([]byte, 10), 0)
		put16(w.pkt, 20+8, bad)
	case "truncated UDP header (less than 8 octets)":
		w.pkt = buildV4(17, "1.1.1.1", w.ueAddr, make([]byte, 4), 0)
	case "IPv4 Total Length greater than read size":
		l4 := tcpSeg(1)
		put16(l4, 16, bad)
		w.pkt = buildV4(6, "1.1.1.1", w.ueAddr, l4, 0)
		put16(w.pkt, 2, uint16(len(w.pkt)+60))
		ipv4Hdr(w.pkt)
	case "IPv6 Payload Length beyond read size":
		l4 := tcpSeg(1)
		put16(l4, 16, bad)
		w.pkt = buildV6(6, "2001:db8:ffff::1", v6dst, l4)
		put16(w.pkt, 4, uint16(len(l4)+200))
	case "UDP Length not equal to IP-derived length":
		l4 := udpDgram(1)
		put16(l4, 4, uint16(len(l4)+16))
		put16(l4, 6, bad)
		w.pkt = buildV4(17, "1.1.1.1", w.ueAddr, l4, 0)
	case "IPv6 with Hop-by-Hop extension header", "IPv6 with Fragment extension header":
		nh := byte(0)
		if kind == "IPv6 with Fragment extension header" {
			nh = 44
		}
		l4 := tcpSeg(1)
		put16(l4, 16, bad)
		ext := make([]byte, 8)
		ext[0] = 6 // next header = TCP
		w.pkt = buildV6(nh, "2001:db8:ffff::1", v6dst, append(ext, l4...))
	case "ICMP echo reply":
		icmp := []byte{0, 0, 0xBE, 0xEF, 0, 1, 0, 1}
		w.pkt = buildV4(1, "1.1.1.1", w.ueAddr, icmp, 0)
	case "ICMPv6 echo reply":
		icmp := []byte{129, 0, 0xBE, 0xEF, 0, 1, 0, 1}
		w.pkt = buildV6(58, "2001:db8:ffff::1", v6dst, icmp)
	default:
		return fmt.Errorf("unknown packet kind %q", kind)
	}
	return nil
}

func (w *world) givenPadding(dst string, n int) error {
	if err := w.mkV4("TCP", "1.1.1.1", dst, nil, nil); err != nil {
		return err
	}
	put16(w.pkt, 20+16, binary.BigEndian.Uint16(w.pkt[36:])+1) // now invalid
	w.padding = n
	for i := 0; i < n; i++ {
		w.pkt = append(w.pkt, 0xA5)
	}
	return nil
}

func (w *world) givenNoSession(dst string) error {
	bad := uint16(0xBEEF)
	if err := w.mkV4("TCP", "1.1.1.1", dst, &bad, nil); err != nil {
		return err
	}
	w.noSession = true
	return nil
}

// ---------- steps: When ----------

func (w *world) validSentinel() []byte {
	l4 := tcpSeg(0x0001)
	l4[0], l4[1] = 0x27, 0x0F
	ip := buildV4(6, "1.1.1.1", w.ueAddr, l4, 0)
	put16(ip, 36, rawCsum(ip, 6, ip[20:], 16))
	return ip
}

func (w *world) whenReadFromTUN() error {
	if err := w.ensure(); err != nil {
		return err
	}
	w.base = counts()
	if _, err := w.tunW.Write(w.pkt); err != nil {
		return fmt.Errorf("inject into TUN: %w", err)
	}
	if w.noSession {
		// The packet must be dropped. A valid follow-up packet proves the reader
		// processed (and discarded) the first one: socketpair order is preserved.
		w.sentinel = w.validSentinel()
		if _, err := w.tunW.Write(w.sentinel); err != nil {
			return err
		}
	}
	d, err := w.recv(recvTimeout)
	if err != nil {
		return fmt.Errorf("no GTP-U datagram sent to the gNB: %w", err)
	}
	w.dgram = d
	return nil
}

func (w *world) whenUPFAnswersICMP(ue string) error {
	if err := w.ensure(); err != nil {
		return err
	}
	w.base = counts()
	icmp := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 7, 'p', 'i', 'n', 'g'}
	put16(icmp, 2, ^fold(sum16(icmp)))
	inner := buildV4(1, ue, n3IP, icmp, 0)
	ext := []byte{0, 0, 0, 0x85, 1, 0x10, 1, 0} // UL PDU Session Container
	hdr := make([]byte, 8)
	hdr[0], hdr[1] = 0x34, 0xFF
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(ext)+len(inner)))
	binary.BigEndian.PutUint32(hdr[4:], ulTEID)
	pkt := append(append(hdr, ext...), inner...)
	// UL GTP-U toward the UPF N3 socket.
	up, err := net.ResolveUDPAddr("udp", w.n3Addr)
	if err != nil {
		return err
	}
	c, err := net.DialUDP("udp", nil, up)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write(pkt); err != nil {
		return err
	}
	w.built = "icmp"
	d, err := w.recv(recvTimeout)
	if err != nil {
		return fmt.Errorf("no ICMP echo reply sent to the gNB: %w", err)
	}
	w.dgram = d
	return nil
}

func (w *world) whenUPFSendsRA() error {
	if err := w.ensure(); err != nil {
		return err
	}
	w.base = counts()
	sess := w.table.GetByULTEID(ulTEID)
	if sess == nil {
		return errors.New("session not found")
	}
	w.pfcpSrv.TriggerSolicitedRA(context.Background(), sess, net.ParseIP("fe80::1234"))
	w.built = "ra"
	d, err := w.recv(recvTimeout)
	if err != nil {
		return fmt.Errorf("no Router Advertisement sent to the gNB: %w", err)
	}
	w.dgram = d
	return nil
}

// ---------- steps: Then ----------

func (w *world) thenExactlyOne() error {
	if len(w.dgram) == 0 {
		return errors.New("no datagram")
	}
	if d, err := w.recv(extraWait); err == nil {
		return fmt.Errorf("a second GTP-U datagram was sent (%d octets)", len(d))
	}
	return nil
}

func (w *world) l4Stored() (uint16, error) {
	in, err := w.inner()
	if err != nil {
		return 0, err
	}
	off := w.l4Off + 16
	if w.proto == "UDP" {
		off = w.l4Off + 6
	}
	if len(in) < off+2 {
		return 0, errors.New("inner packet too short")
	}
	return binary.BigEndian.Uint16(in[off:]), nil
}

func (w *world) thenInnerCsumIs(proto, want string) error {
	w.proto = proto
	v, err := u16(want)
	if err != nil {
		return err
	}
	got, err := w.l4Stored()
	if err != nil {
		return err
	}
	if got != v {
		return fmt.Errorf("inner %s checksum = 0x%04x, want 0x%04x", proto, got, v)
	}
	return nil
}

func (w *world) thenTEIDQFI(teid, qfi string) error {
	t, _ := strconv.ParseUint(teid, 0, 32)
	q, _ := strconv.ParseUint(qfi, 10, 8)
	d := w.dgram
	if len(d) < 16 {
		return errors.New("datagram too short")
	}
	if d[0] != 0x34 || d[1] != 0xFF {
		return fmt.Errorf("GTP-U flags/type = %02x/%02x, want 34/ff", d[0], d[1])
	}
	if got := binary.BigEndian.Uint32(d[4:]); got != uint32(t) {
		return fmt.Errorf("TEID = 0x%x, want 0x%x", got, t)
	}
	if d[11] != 0x85 || d[12] != 1 || d[14]&0x3F != byte(q) || d[15] != 0 {
		return fmt.Errorf("PDU Session Container wrong: ext=% x (want next=0x85 len=1 QFI=%d end=0)", d[8:16], q)
	}
	return nil
}

func (w *world) thenGTPLength() error {
	in, err := w.inner()
	if err != nil {
		return err
	}
	if got, want := int(binary.BigEndian.Uint16(w.dgram[2:])), len(in)+gtpuExtOctets; got != want {
		return fmt.Errorf("GTP-U Length = %d, want %d (inner %d + ext %d)", got, want, len(in), gtpuExtOctets)
	}
	if int(binary.BigEndian.Uint16(w.dgram[2:])) != len(w.dgram)-8 {
		return errors.New("GTP-U Length does not match datagram size")
	}
	return nil
}

func (w *world) thenIdenticalExceptCsum(proto string) error {
	in, err := w.inner()
	if err != nil {
		return err
	}
	if len(in) != len(w.pkt) {
		return fmt.Errorf("inner length %d != TUN packet length %d", len(in), len(w.pkt))
	}
	off := w.l4Off + 16
	if proto == "UDP" {
		off = w.l4Off + 6
	}
	for i := range in {
		if (i == off || i == off+1) && proto != "" {
			continue
		}
		if in[i] != w.pkt[i] {
			return fmt.Errorf("inner byte %d differs: 0x%02x vs TUN 0x%02x", i, in[i], w.pkt[i])
		}
	}
	return nil
}

func (w *world) thenCounterInc(proto, ip string, n int) error {
	if got := w.delta(proto, ip); got != float64(n) {
		return fmt.Errorf("counter proto=%s ip=%s delta = %v, want %d", proto, ip, got, n)
	}
	var total float64
	for _, l := range repairLabels {
		total += w.delta(l[0], l[1])
	}
	if total != float64(n) {
		return fmt.Errorf("total counter delta = %v, want exactly %d", total, n)
	}
	return nil
}

func (w *world) thenNoCounterChange(string) error {
	for _, l := range repairLabels {
		if d := w.delta(l[0], l[1]); d != 0 {
			return fmt.Errorf("counter proto=%s ip=%s changed by %v, want 0", l[0], l[1], d)
		}
	}
	return nil
}

func (w *world) thenIdenticalToTUN() error {
	in, err := w.inner()
	if err != nil {
		return err
	}
	if string(in) != string(w.pkt) {
		return fmt.Errorf("inner packet differs from TUN packet:\n got % x\nwant % x", in, w.pkt)
	}
	return nil
}

func (w *world) thenVerifies(proto string, v6 bool) error {
	in, err := w.inner()
	if err != nil {
		return err
	}
	w.proto = proto
	nh := byte(6)
	if proto == "UDP" {
		nh = 17
	}
	var l4 []byte
	if v6 {
		l4 = in[40 : 40+int(binary.BigEndian.Uint16(in[4:]))]
	} else {
		l4 = in[20:int(binary.BigEndian.Uint16(in[2:]))]
	}
	if got := l4Sum(in, nh, l4); got != 0xFFFF {
		return fmt.Errorf("inner %s checksum does not verify (folded sum 0x%04x, want 0xffff)", proto, got)
	}
	return nil
}

func (w *world) thenV6UDPNonZeroVerifies() error {
	got, err := w.l4StoredAt(40, 6)
	if err != nil {
		return err
	}
	if got == 0 {
		return errors.New("IPv6 UDP checksum is still zero")
	}
	return w.thenVerifies("UDP", true)
}

func (w *world) l4StoredAt(l4, off int) (uint16, error) {
	in, err := w.inner()
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(in[l4+off:]), nil
}

func (w *world) thenRepairedWithinTotalLength() error {
	in, err := w.inner()
	if err != nil {
		return err
	}
	if len(in) != len(w.pkt) {
		return fmt.Errorf("forwarded length %d != %d", len(in), len(w.pkt))
	}
	total := int(binary.BigEndian.Uint16(in[2:]))
	if total+w.padding != len(in) {
		return fmt.Errorf("Total Length %d + padding %d != packet %d", total, w.padding, len(in))
	}
	if err := w.thenVerifies("TCP", false); err != nil {
		return err
	}
	for i := total; i < len(in); i++ {
		if in[i] != 0xA5 {
			return fmt.Errorf("trailing padding octet %d was modified", i)
		}
	}
	return nil
}

func (w *world) thenNoDatagram() error {
	if w.sentinel == nil {
		return errors.New("scenario did not arm the drop check")
	}
	in, err := w.inner()
	if err != nil {
		return err
	}
	if string(in) != string(w.sentinel) {
		return errors.New("a GTP-U datagram for the unknown-UE packet was sent; first datagram is not the sentinel")
	}
	return nil
}

func (w *world) thenNoPanic() error {
	// If the UPF goroutine had panicked the process would have died; additionally
	// prove the downlink path is still alive with a valid follow-up packet.
	if err := w.ensure(); err != nil {
		return err
	}
	if d, err := w.recv(extraWait); err == nil {
		return fmt.Errorf("unexpected extra datagram (%d octets)", len(d))
	}
	s := w.validSentinel()
	if _, err := w.tunW.Write(s); err != nil {
		return err
	}
	d, err := w.recv(recvTimeout)
	if err != nil {
		return fmt.Errorf("downlink path dead after ineligible packet: %w", err)
	}
	if string(d[8+gtpuExtOctets:]) != string(s) {
		return errors.New("sentinel mismatch after ineligible packet")
	}
	return nil
}

func (w *world) thenBuiltICMP() error {
	in, err := w.inner()
	if err != nil {
		return err
	}
	if len(in) < 28 || in[0] != 0x45 || in[9] != 1 {
		return fmt.Errorf("not an IPv4 ICMP packet: % x", in)
	}
	if !net.IP(in[12:16]).Equal(net.ParseIP(n3IP)) || !net.IP(in[16:20]).Equal(net.ParseIP(w.ueAddr)) {
		return fmt.Errorf("echo reply addresses wrong: %s -> %s", net.IP(in[12:16]), net.IP(in[16:20]))
	}
	if in[20] != 0 {
		return fmt.Errorf("ICMP type = %d, want 0 (echo reply)", in[20])
	}
	if fold(sum16(in[:20])) != 0xFFFF || fold(sum16(in[20:])) != 0xFFFF {
		return errors.New("echo reply IP/ICMP checksum invalid")
	}
	if string(in[28:]) != "ping" || binary.BigEndian.Uint16(in[24:]) != 0x1234 {
		return errors.New("echo reply does not echo identifier/payload")
	}
	return w.thenTEIDQFI(fmt.Sprint(w.dlTEID), fmt.Sprint(w.qfi))
}

func (w *world) thenBuiltRA() error {
	in, err := w.inner()
	if err != nil {
		return err
	}
	if len(in) < 48 || in[0]>>4 != 6 || in[6] != 58 || in[40] != 134 {
		return fmt.Errorf("not an ICMPv6 Router Advertisement: % x", in)
	}
	if l4Sum(in, 58, in[40:40+int(binary.BigEndian.Uint16(in[4:]))]) != 0xFFFF {
		return errors.New("RA ICMPv6 checksum invalid")
	}
	return nil
}

// ---------- E2E gating ----------

func e2e1(string) error { return e2e() }

func e2e() error {
	if os.Getenv("E2E_TEST") != "1" {
		return godog.ErrSkip
	}
	// Live assertions are driven through the MCP tools (ueransim_status,
	// ueransim_ue_register, ueransim_pdu_session_establish, procedure_summary)
	// per docs/procedures/DownlinkChecksum.md, not from Go.
	return godog.ErrPending
}

// ---------- wiring ----------

func InitializeScenario(sc *godog.ScenarioContext) {
	w := &world{repair: true}
	a := &ambrWorld{}
	registerAmbrSteps(sc, a) // AmbrEnforcement (UPF-005) steps, ambr_enforcement_steps_test.go
	sc.After(func(ctx context.Context, _ *godog.Scenario, err error) (context.Context, error) {
		w.teardown()
		*w = world{repair: true}
		return ctx, nil
	})

	sc.Step(`^a UPF with an established PDU session for UE address "([^"]*)" with DL TEID (0x[0-9a-fA-F]+), QFI (\d+) and gNB address "([^"]*)"$`, w.aUPFWithSession)
	sc.Step(`^the UPF knob "n6\.l4_checksum_repair" is (true|false)$`, w.knob)
	sc.Step(`^the counter "fivegc_upf_l4_checksum_repaired_total" is read for all proto and ip labels$`, w.counterRead)

	sc.Step(`^a downlink IPv4 TCP SYN-ACK from "([^"]*)" to "([^"]*)" with TCP checksum (0x[0-9a-fA-F]+) but correct value (0x[0-9a-fA-F]+)$`, w.givenSynAck)
	sc.Step(`^a downlink IPv4 TCP segment to "([^"]*)" with TCP checksum 0x0000 that does not verify$`, w.givenTCPZeroInvalid)
	sc.Step(`^a downlink IPv4 TCP segment to "([^"]*)" with a valid TCP checksum$`, w.givenTCPValid)
	sc.Step(`^a downlink IPv4 UDP datagram to "([^"]*)" with UDP checksum 0x0000$`, w.givenUDPZero)
	sc.Step(`^a downlink IPv4 UDP datagram to "([^"]*)" with a valid UDP checksum$`, w.givenUDPValid)
	sc.Step(`^a downlink IPv4 UDP datagram to "([^"]*)" with a non-zero UDP checksum that does not verify$`, w.givenUDPInvalid)
	sc.Step(`^a downlink IPv4 UDP datagram to "([^"]*)" whose correct checksum computes to 0x0000 and whose stored checksum is (0x[0-9a-fA-F]+)$`, w.givenUDPComputesZero)
	sc.Step(`^a downlink IPv6 (TCP|UDP) packet to UE IPv6 prefix address "([^"]*)" with an invalid (TCP|UDP) checksum$`, w.givenV6Invalid)
	sc.Step(`^a downlink IPv6 UDP packet to UE IPv6 prefix address "([^"]*)" with UDP checksum 0x0000$`, w.givenV6UDPZero)
	sc.Step(`^a downlink packet of kind "([^"]*)" to "([^"]*)" carrying an invalid L4 checksum$`, w.givenKind)
	sc.Step(`^a downlink IPv4 TCP segment to "([^"]*)" with an invalid checksum followed by (\d+) trailing padding octets after Total Length$`,
		func(dst string, n int) error { return w.givenPadding(dst, n) })
	sc.Step(`^a downlink IPv4 TCP segment to "([^"]*)" with an invalid TCP checksum and no session for that address$`, w.givenNoSession)
	sc.Step(`^the UPF answers an ICMP echo request from UE "([^"]*)" to the gateway with its own echo reply via sendGTPU$`, w.whenUPFAnswersICMP)
	// Shared with ambr_enforcement.feature: dispatched on the active feature.
	sc.Step(`^the UPF sends an ICMPv6 Router Advertisement to the UE via sendGTPU$`, func() error {
		if a.active {
			return a.sendRA()
		}
		return w.whenUPFSendsRA()
	})

	sc.Step(`^the packet is read from the TUN$`, w.whenReadFromTUN)

	sc.Step(`^exactly one GTP-U datagram is sent to the gNB$`, w.thenExactlyOne)
	sc.Step(`^the inner (TCP|UDP) checksum in the datagram is (0x[0-9a-fA-F]+)$`, w.thenInnerCsumIs)
	sc.Step(`^the inner (UDP) checksum in the sent datagram is (0x[0-9a-fA-F]+)$`, w.thenInnerCsumIs)
	sc.Step(`^the GTP-U TEID is (0x[0-9a-fA-F]+) and the PDU Session Container carries QFI (\d+)$`, func(teid, qfi string) error {
		if a.active {
			return a.thenTEIDQFI(teid, qfi)
		}
		return w.thenTEIDQFI(teid, qfi)
	})
	sc.Step(`^the GTP-U Length equals the inner packet length plus the extension header octets$`, w.thenGTPLength)
	sc.Step(`^all inner bytes except the (TCP) checksum are identical to the TUN packet$`, w.thenIdenticalExceptCsum)
	sc.Step(`^the counter with proto "([^"]*)" and ip "([^"]*)" has increased by (\d+)$`, w.thenCounterInc)
	sc.Step(`^no counter with name "(fivegc_upf_l4_checksum_repaired_total)" has changed$`, w.thenNoCounterChange)
	sc.Step(`^the inner packet in the sent GTP-U datagram is byte-identical to the TUN packet$`, w.thenIdenticalToTUN)
	sc.Step(`^the inner (TCP) checksum in the sent datagram verifies over the pseudo-header and segment$`,
		func(p string) error { return w.thenVerifies(p, false) })
	sc.Step(`^the inner (UDP) checksum in the sent datagram verifies over the pseudo-header and datagram$`,
		func(p string) error { return w.thenVerifies(p, false) })
	sc.Step(`^the inner (TCP|UDP) checksum in the sent datagram verifies over the IPv6 pseudo-header and segment$`,
		func(p string) error { return w.thenVerifies(p, true) })
	sc.Step(`^the inner UDP checksum in the sent datagram is non-zero and verifies over the IPv6 pseudo-header$`, w.thenV6UDPNonZeroVerifies)
	sc.Step(`^the inner TCP checksum is repaired using only the octets within Total Length$`, w.thenRepairedWithinTotalLength)
	sc.Step(`^no GTP-U datagram is sent$`, w.thenNoDatagram)
	sc.Step(`^the UPF does not panic$`, w.thenNoPanic)
	sc.Step(`^the echo reply in the sent GTP-U datagram is exactly the packet the UPF built$`, w.thenBuiltICMP)
	sc.Step(`^the Router Advertisement in the sent GTP-U datagram is exactly the packet the UPF built$`, w.thenBuiltRA)

	// @e2e @manual — skipped unless E2E_TEST=1 (then pending: driven via MCP tools).
	sc.Step(`^E2E_TEST is set to "1" and (.+)$`, e2e1)
	for _, re := range []string{
		`^a TCP server is listening on the Mac LAN address$`,
		`^the UE runs curl bound to "uesimtun0" against that server$`,
		`^the HTTP response is received before the timeout$`,
		`^the UE runs "([^"]*)"$`,
		`^an HTTP response is received$`,
		`^the UE /proc/net/snmp Tcp and Udp InCsumErrors are recorded$`,
		`^the UE completes an external TCP transfer and an external UDP transfer through the PDU session$`,
		`^the Tcp InCsumErrors and Udp InCsumErrors values are unchanged$`,
		`^the UPF counter "([^"]*)" has increased on Docker Desktop$`,
		`^"make ueransim-iperf" is run with the repair enabled$`,
		`^TCP UL, TCP DL, UDP UL and UDP DL throughput show no material regression against the baseline$`,
		`^the repair counter stays 0 for N6-bridge-only traffic$`,
		`^iperf3 is listening on a LAN or Mac host address$`,
		`^the portal iperf3 test is started with that custom server IP$`,
		`^the test completes with a non-zero throughput result$`,
		`^the request times out$`,
		`^the UE Tcp InCsumErrors value increases$`,
	} {
		if strings.Contains(re, `"([^"]*)"`) {
			sc.Step(re, e2e1)
		} else {
			sc.Step(re, e2e)
		}
	}
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"./"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }
