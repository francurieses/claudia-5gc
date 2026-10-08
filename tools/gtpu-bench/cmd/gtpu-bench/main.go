// Command gtpu-bench is a UERANSIM-bypass user-plane load generator for the UPF.
//
//	ran: fake SMF (PFCP/N4) + fake gNB (GTP-U/N3). Installs K synthetic sessions, sends
//	     uplink T-PDUs at a paced rate and receives/validates downlink T-PDUs.
//	dn:  data-network side (N6). UDP sink counting uplink arrivals, and a paced downlink
//	     sender toward the synthetic UE addresses via the UPF.
//
// Each invocation is one measurement step; both sides print one JSON result at the end.
// See tools/gtpu-bench/CLAUDE.md for the reserved SEID/TEID/UE-IP ranges.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/francurieses/claudia-5gc/tools/gtpu-bench/internal/gtp"
	"github.com/francurieses/claudia-5gc/tools/gtpu-bench/internal/pace"
	"github.com/francurieses/claudia-5gc/tools/gtpu-bench/internal/pfcpcp"
)

// Result is the JSON document printed by both modes.
type Result struct {
	Mode       string  `json:"mode"`
	Sessions   int     `json:"sessions"`
	InnerSize  int     `json:"inner_size"`
	Seconds    float64 `json:"seconds"`
	TargetPPS  float64 `json:"target_pps"`
	SentPkts   uint64  `json:"sent_pkts"`
	SentPPS    float64 `json:"sent_pps"`
	SentMbps   float64 `json:"sent_mbps"`
	RecvPkts   uint64  `json:"recv_pkts"`
	RecvPPS    float64 `json:"recv_pps"`
	RecvMbps   float64 `json:"recv_mbps"`
	Reordered  uint64  `json:"reordered"`
	BadFormat  uint64  `json:"bad_format"`
	SendErrors uint64  `json:"send_errors"`
}

type config struct {
	mode     string
	sessions int
	size     int
	pps      float64
	duration time.Duration
	startAt  int64
	workers  int

	// ran
	upf, upfN3, gnbN3, dnn, ueBase string
	dnSink                         string
	sendUL, recvDL                 bool
	// dn
	listen string
	ueDst  string
	sendDL bool
}

func main() {
	var c config
	flag.StringVar(&c.mode, "mode", "", "ran | dn")
	flag.IntVar(&c.sessions, "sessions", 1, "synthetic sessions (K)")
	flag.IntVar(&c.size, "size", 1400, "inner IPv4 packet size in bytes (min 44)")
	flag.Float64Var(&c.pps, "pps", 10000, "target packets/s, total across sessions (0 = receive only)")
	flag.DurationVar(&c.duration, "duration", 10*time.Second, "send duration")
	flag.Int64Var(&c.startAt, "start-at", 0, "unix epoch seconds at which to start sending (sync ran/dn)")
	flag.IntVar(&c.workers, "workers", 1, "sender goroutines")
	flag.StringVar(&c.upf, "upf", "upf-n4.5gc.local:8805", "ran: UPF PFCP address")
	flag.StringVar(&c.upfN3, "upf-n3", "172.30.3.100", "ran: UPF N3 IP (F-TEID address, GTP-U destination)")
	flag.StringVar(&c.gnbN3, "gnb-n3", "", "ran: local N3 IP announced as the gNB DL address")
	flag.StringVar(&c.dnn, "dnn", "internet", "ran: DNN (Network Instance)")
	flag.StringVar(&c.ueBase, "ue-base", "10.60.0.200", "first synthetic UE IP (reserved 10.60.0.200-249)")
	flag.StringVar(&c.dnSink, "dn-sink", "172.30.6.51:9000", "ran: uplink inner destination host:port (the dn sink)")
	flag.BoolVar(&c.sendUL, "ul", true, "ran: send uplink")
	flag.BoolVar(&c.recvDL, "dl", true, "ran: receive downlink")
	flag.StringVar(&c.listen, "listen", ":9000", "dn: UDP sink listen address")
	flag.BoolVar(&c.sendDL, "send-dl", true, "dn: send downlink to the synthetic UEs")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("tool", "gtpu-bench", "mode", c.mode)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var (
		res Result
		err error
	)
	switch c.mode {
	case "ran":
		res, err = runRAN(ctx, log, c)
	case "dn":
		res, err = runDN(ctx, log, c)
	default:
		fmt.Fprintln(os.Stderr, "gtpu-bench: -mode ran|dn required")
		os.Exit(2)
	}
	if err != nil {
		log.Error("run failed", "error", err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(res)
}

// counters is the shared receive/send accounting.
type counters struct {
	sent, sentBytes, recv, recvBytes, bad, errs, reorder atomic.Uint64
}

func (k *counters) result(c config, dur time.Duration) Result {
	s := dur.Seconds()
	return Result{
		Mode: c.mode, Sessions: c.sessions, InnerSize: c.size, Seconds: s, TargetPPS: c.pps,
		SentPkts: k.sent.Load(), SentPPS: float64(k.sent.Load()) / s, SentMbps: float64(k.sentBytes.Load()) * 8 / s / 1e6,
		RecvPkts: k.recv.Load(), RecvPPS: float64(k.recv.Load()) / s, RecvMbps: float64(k.recvBytes.Load()) * 8 / s / 1e6,
		Reordered: k.reorder.Load(), BadFormat: k.bad.Load(), SendErrors: k.errs.Load(),
	}
}

// seqTracker detects reordering per flow: a sequence number lower than the highest seen.
type seqTracker struct {
	mu   sync.Mutex
	last map[uint16]uint64
}

func (t *seqTracker) observe(flow uint16, seq uint64) (reordered bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.last == nil {
		t.last = map[uint16]uint64{}
	}
	if l, ok := t.last[flow]; ok && seq < l {
		return true
	}
	t.last[flow] = seq
	return false
}

func waitStart(ctx context.Context, at int64) time.Time {
	t := time.Unix(at, 0)
	if at == 0 || time.Until(t) <= 0 {
		return time.Now()
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Until(t)):
	}
	return t
}

func splitHostPort(s string) (net.IP, uint16, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, err
	}
	ips, err := net.LookupIP(h)
	if err != nil || len(ips) == 0 {
		return nil, 0, fmt.Errorf("resolve %q: %v", h, err)
	}
	var port int
	if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
		return nil, 0, err
	}
	return ips[0], uint16(port), nil
}

// runRAN: install sessions, send paced UL T-PDUs, receive DL T-PDUs, delete sessions.
func runRAN(ctx context.Context, log *slog.Logger, c config) (Result, error) {
	upfN3 := net.ParseIP(c.upfN3)
	gnb := net.ParseIP(c.gnbN3)
	if upfN3 == nil || gnb == nil {
		return Result{}, fmt.Errorf("gtpu-bench: -upf-n3 and -gnb-n3 must be IPs")
	}
	dstIP, dstPort, err := splitHostPort(c.dnSink)
	if err != nil {
		return Result{}, fmt.Errorf("gtpu-bench: -dn-sink: %w", err)
	}
	cli, err := pfcpcp.Dial(ctx, c.upf)
	if err != nil {
		return Result{}, err
	}
	defer cli.Close()

	ues := net.ParseIP(c.ueBase)
	sessions := make([]pfcpcp.Session, c.sessions)
	installed := 0
	defer func() { // always restore the UPF table
		for i := 0; i < installed; i++ {
			if err := cli.Delete(sessions[i]); err != nil {
				log.Warn("session delete failed", "seid", sessions[i].SEID, "error", err)
			}
		}
	}()
	for i := range sessions {
		sessions[i] = pfcpcp.NewSession(i, ues)
		if err := cli.Establish(sessions[i], upfN3, gnb, c.dnn); err != nil {
			installed = i
			return Result{}, err
		}
	}
	installed = len(sessions)
	log.Info("sessions installed", "count", installed, "first_ue", sessions[0].UEIP)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: gnb, Port: gtp.Port})
	if err != nil {
		return Result{}, fmt.Errorf("gtpu-bench: listen N3: %w", err)
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(16 << 20)
	_ = conn.SetWriteBuffer(16 << 20)

	var k counters
	var tr seqTracker
	// Receiver: validates every DL T-PDU (PDU Session Container, DL type, TEID of a known session).
	known := map[uint32]bool{}
	for _, s := range sessions {
		known[s.DLTEID] = true
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			tp, err := gtp.ParseTPDU(buf[:n])
			if err != nil || !tp.HasPDU || tp.PDUType != gtp.PDUTypeDL || !known[tp.TEID] {
				k.bad.Add(1)
				continue
			}
			flow, seq, ok := gtp.GetPayload(gtp.UDPPayload(tp.Inner))
			if !ok {
				k.bad.Add(1)
				continue
			}
			k.recv.Add(1)
			k.recvBytes.Add(uint64(len(tp.Inner)))
			if tr.observe(flow, seq) {
				k.reorder.Add(1)
			}
		}
	}()

	start := waitStart(ctx, c.startAt)
	end := start.Add(c.duration)
	if c.sendUL && c.pps > 0 {
		var wg sync.WaitGroup
		for w := 0; w < c.workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				ulSender(ctx, c, w, sessions, upfN3, dstIP, dstPort, conn, &k, start, end)
			}(w)
		}
		wg.Wait()
	} else {
		select {
		case <-ctx.Done():
		case <-time.After(time.Until(end)):
		}
	}
	// Grace period for in-flight DL packets.
	time.Sleep(500 * time.Millisecond)
	conn.Close()
	<-done
	return k.result(c, c.duration), nil
}

func ulSender(ctx context.Context, c config, w int, ss []pfcpcp.Session, upfN3, dst net.IP, dport uint16,
	conn *net.UDPConn, k *counters, start, end time.Time) {
	p := pace.New(c.pps/float64(c.workers), start)
	addr := &net.UDPAddr{IP: upfN3, Port: gtp.Port}
	inner := make([]byte, c.size)
	pkt := make([]byte, 0, c.size+gtp.Overhead)
	seq := make([]uint64, len(ss))
	rr := w
	for ctx.Err() == nil {
		now := time.Now()
		if now.After(end) {
			return
		}
		n := p.Due(now, 4096)
		if n == 0 {
			time.Sleep(50 * time.Microsecond)
			continue
		}
		for ; n > 0; n-- {
			i := rr % len(ss)
			rr += c.workers
			s := ss[i]
			frame := gtp.BuildInnerUDP(inner, s.UEIP, dst, uint16(20000+i), dport, c.size, uint16(i*256+w), seq[i])
			seq[i]++
			pkt = gtp.BuildTPDU(pkt[:0], s.ULTEID, pfcpcp.QFI, gtp.PDUTypeUL, frame)
			if _, err := conn.WriteToUDP(pkt, addr); err != nil {
				k.errs.Add(1)
				continue
			}
			k.sent.Add(1)
			k.sentBytes.Add(uint64(c.size))
		}
	}
}

// runDN: UDP sink for uplink + paced downlink sender toward the synthetic UEs.
func runDN(ctx context.Context, log *slog.Logger, c config) (Result, error) {
	laddr, err := net.ResolveUDPAddr("udp", c.listen)
	if err != nil {
		return Result{}, fmt.Errorf("gtpu-bench: -listen: %w", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return Result{}, fmt.Errorf("gtpu-bench: listen sink: %w", err)
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(16 << 20)

	var k counters
	var tr seqTracker
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Uplink inner packets arrive as plain UDP: payload = bench header (+padding).
			// Wire size seen here is inner minus IPv4+UDP headers; count the inner size.
			flow, seq, ok := gtp.GetPayload(buf[:n])
			if !ok {
				k.bad.Add(1)
				continue
			}
			k.recv.Add(1)
			k.recvBytes.Add(uint64(n + 28))
			if tr.observe(flow, seq) {
				k.reorder.Add(1)
			}
		}
	}()

	start := waitStart(ctx, c.startAt)
	end := start.Add(c.duration)
	if c.sendDL && c.pps > 0 {
		ues := net.ParseIP(c.ueDstBase())
		var wg sync.WaitGroup
		for w := 0; w < c.workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				dlSender(ctx, c, w, ues, &k, start, end)
			}(w)
		}
		wg.Wait()
	} else {
		select {
		case <-ctx.Done():
		case <-time.After(time.Until(end)):
		}
	}
	time.Sleep(500 * time.Millisecond)
	conn.Close()
	<-done
	log.Info("dn step finished")
	return k.result(c, c.duration), nil
}

func (c config) ueDstBase() string {
	if c.ueDst != "" {
		return c.ueDst
	}
	return c.ueBase
}

func dlSender(ctx context.Context, c config, w int, ueBase net.IP, k *counters, start, end time.Time) {
	p := pace.New(c.pps/float64(c.workers), start)
	conns := make([]*net.UDPConn, c.sessions)
	for i := range conns {
		ip := make(net.IP, 4)
		copy(ip, ueBase.To4())
		ip[3] += byte(i)
		cn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: 30000 + i})
		if err != nil {
			k.errs.Add(1)
			return
		}
		defer cn.Close()
		conns[i] = cn
	}
	payload := make([]byte, c.size-28)
	seq := make([]uint64, c.sessions)
	rr := w
	for ctx.Err() == nil {
		now := time.Now()
		if now.After(end) {
			return
		}
		n := p.Due(now, 4096)
		if n == 0 {
			time.Sleep(50 * time.Microsecond)
			continue
		}
		for ; n > 0; n-- {
			i := rr % c.sessions
			rr += c.workers
			gtp.PutPayload(payload, uint16(i*256+w), seq[i])
			seq[i]++
			if _, err := conns[i].Write(payload); err != nil {
				k.errs.Add(1)
				continue
			}
			k.sent.Add(1)
			k.sentBytes.Add(uint64(c.size))
		}
	}
}
