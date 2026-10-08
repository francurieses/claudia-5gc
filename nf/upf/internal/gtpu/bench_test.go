package gtpu

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
)

// benchLogger discards output but keeps the handler enabled at lvl, so the
// benchmark pays the real per-record cost of INFO (or DEBUG) logging.
func benchLogger(lvl slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: lvl}))
}

// benchInnerUDP builds an IPv4/UDP packet of total length n from ueIP to 8.8.8.8.
func benchInnerUDP(ueIP net.IP, n int) []byte {
	p := make([]byte, n)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(n))
	p[8], p[9] = 64, 17
	copy(p[12:16], ueIP.To4())
	copy(p[16:20], net.IPv4(8, 8, 8, 8).To4())
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], 5201)
	binary.BigEndian.PutUint16(p[24:26], uint16(n-20))
	return p
}

// benchGTPU wraps inner in the UERANSIM-shaped UL header: flags 0x34, E=1,
// PDU Session Container (type 0x85, UL PDU Session Information).
func benchGTPU(teid uint32, inner []byte) []byte {
	ext := []byte{0x00, 0x00, 0x00, extHdrTypePDUSessionContainer, 0x01, 0x10, 0x01, 0x00}
	h := make([]byte, 8, 8+len(ext)+len(inner))
	h[0], h[1] = 0x34, msgTypeTPDU
	binary.BigEndian.PutUint16(h[2:4], uint16(len(ext)+len(inner)))
	binary.BigEndian.PutUint32(h[4:8], teid)
	return append(append(h, ext...), inner...)
}

func benchServer(b testing.TB, lvl slog.Level) (*Server, *pfcp.Session, *os.File, *net.UDPConn) {
	b.Helper()
	ueIP := net.IPv4(10, 60, 0, 3)
	tab := pfcp.NewSessionTable()

	// DL sink: a loopback UDP socket drained by a goroutine, standing in for the gNB.
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := sink.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()
	// sendGTPU always targets gtpuPort on sess.GNBIP, so bind the server socket
	// to loopback and send to 127.0.0.1:2152 is not possible without privileges
	// on every host; the benchmark instead points GNBIP at 127.0.0.1 and relies
	// on the port being closed (ICMP unreachable is ignored on an unconnected
	// socket) while still exercising the full encap + syscall cost.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		b.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, pr) }()

	_, subnet, _ := net.ParseCIDR("10.60.0.0/24")
	sess := &pfcp.Session{
		CPSEID: 1, UPSEID: 1, ULTEID: 0xB0000001, DLTEID: 0xB0000002,
		UEIP: ueIP, GNBIP: net.IPv4(127, 0, 0, 1),
		QERs: map[uint32]*pfcp.QERState{1: {QERID: 1, QFI: 1, HasQFI: true, HasMBR: true,
			MBRULKbps: 0xFFFFFFFF, MBRDLKbps: 0xFFFFFFFF}},
		PDRs: map[uint16]*pfcp.PDRState{1: {PDRID: 1, QERIDs: []uint32{1}}},
	}
	sess.RebuildQoS(pfcp.QoSConfig{})
	tab.Add(sess)
	rt := tunRoute{dnn: "internet", subnet: subnet, file: pw}
	rt.resolveCounters()
	s := &Server{
		cfg: Config{}, logger: benchLogger(lvl), conn: conn, sessions: tab,
		n3IP: net.IPv4(172, 30, 3, 100).To4(),
		tuns: []tunRoute{rt},
	}
	s.initCounters()
	b.Cleanup(func() { sink.Close(); conn.Close(); pw.Close(); pr.Close() })
	return s, sess, pw, sink
}

func benchUplink(b *testing.B, lvl slog.Level, size int) {
	s, sess, _, _ := benchServer(b, lvl)
	pkt := benchGTPU(sess.ULTEID, benchInnerUDP(sess.UEIP, size))
	b.ReportAllocs()
	b.SetBytes(int64(size))
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		// Start() hands its reusable receive buffer to handlePacket (no copy).
		s.handlePacket(pkt)
	}
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "pps")
}

func benchDownlink(b *testing.B, lvl slog.Level, size int) {
	s, sess, _, _ := benchServer(b, lvl)
	inner := benchInnerUDP(sess.UEIP, size)
	frame := make([]byte, dlHeadroom+size)
	b.ReportAllocs()
	b.SetBytes(int64(size))
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		// Mirrors one startTUNReader iteration: the TUN read fills frame[dlHeadroom:],
		// the header is written in place, then one sendto.
		copy(frame[dlHeadroom:], inner)
		putDLHeader(frame[:dlHeadroom], sess.DLTEID, sess.DLQFI(), size)
		s.sendFrame(sess, frame, size)
	}
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "pps")
}

func BenchmarkUplink1400Info(b *testing.B)    { benchUplink(b, slog.LevelInfo, 1400) }
func BenchmarkUplink1400Debug(b *testing.B)   { benchUplink(b, slog.LevelDebug, 1400) }
func BenchmarkUplink64Info(b *testing.B)      { benchUplink(b, slog.LevelInfo, 64) }
func BenchmarkDownlink1400Info(b *testing.B)  { benchDownlink(b, slog.LevelInfo, 1400) }
func BenchmarkDownlink1400Debug(b *testing.B) { benchDownlink(b, slog.LevelDebug, 1400) }
func BenchmarkDownlink64Info(b *testing.B)    { benchDownlink(b, slog.LevelInfo, 64) }

// benchServer2 returns a ready server at INFO for ordinary tests.
func benchServer2(t testing.TB) (*Server, *pfcp.Session, *os.File, *net.UDPConn) {
	return benchServer(t, slog.LevelInfo)
}
