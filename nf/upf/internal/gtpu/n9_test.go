package gtpu

// n9_test.go — V-UPF relay (UL N3 -> N9, DL N9 -> N3), H-UPF DL OHC towards the
// V-UPF and the non-roaming byte-identity goldens. Peers are loopback sockets on
// the GTP-U port (frames always go to port 2152); tests skip when it is taken.
// Ref: TS 23.501 §4.2.4; TS 29.281 §5.1, §5.2.2.7; TS 38.415 §5.5.2.

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
)

// peerSink opens the receiving GTP-U peer and points peerPort at it.
func peerSink(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	old := peerPort
	peerPort = uint16(c.LocalAddr().(*net.UDPAddr).Port)
	t.Cleanup(func() { peerPort = old; c.Close() })
	return c
}

func recvFrame(t *testing.T, c *net.UDPConn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no GTP-U frame received: %v", err)
	}
	return buf[:n]
}

// n9Server builds a server whose TUN is a pipe the test can read (TUN writes).
func n9Server(t *testing.T, sess *pfcp.Session) (*Server, *os.File) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	tab := pfcp.NewSessionTable()
	sess.QERs = map[uint32]*pfcp.QERState{1: {QERID: 1, QFI: 5, HasQFI: true}}
	sess.PDRs = map[uint16]*pfcp.PDRState{1: {PDRID: 1, QERIDs: []uint32{1}}, 2: {PDRID: 2, SourceInterface: 1, QERIDs: []uint32{1}}}
	sess.RebuildQoS(pfcp.QoSConfig{})
	tab.Add(sess)
	_, subnet, _ := net.ParseCIDR("10.70.0.0/24")
	rt := tunRoute{dnn: "internet", subnet: subnet, file: pw}
	rt.resolveCounters()
	s := &Server{logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), conn: conn, sessions: tab,
		n3IP: net.IPv4(172, 30, 3, 100).To4(), tuns: []tunRoute{rt}}
	s.initCounters()
	t.Cleanup(func() { conn.Close(); pw.Close(); pr.Close() })
	return s, pr
}

// gtpuIn builds an inbound T-PDU with a PDU Session Container of the given PDU
// type nibble and QFI.
func gtpuIn(teid uint32, pduType, qfi byte, inner []byte) []byte {
	p := benchGTPU(teid, inner)
	p[8+5], p[8+6] = pduType, qfi
	return p
}

func wantFrame(teid uint32, pduType, qfi byte, inner []byte) []byte {
	h := make([]byte, 16, 16+len(inner))
	h[0], h[1] = 0x34, msgTypeTPDU
	h[2], h[3] = 0, byte(8+len(inner))
	h[4], h[5], h[6], h[7] = byte(teid>>24), byte(teid>>16), byte(teid>>8), byte(teid)
	h[11], h[12], h[13], h[14] = 0x85, 0x01, pduType, qfi
	return append(h, inner...)
}

// TestVUPFUplinkRelay: UL from N3 leaves as GTP-U to the H-UPF N9 peer (UL PDU
// Session Container, inbound QFI kept) and never reaches the TUN; before the peer
// is known it is dropped and counted.
func TestVUPFUplinkRelay(t *testing.T) {
	sink := peerSink(t)
	sess := &pfcp.Session{CPSEID: 1, UPSEID: 1, ULTEID: 0x31, N9TEID: 0x91, ULRelay: true}
	s, tun := n9Server(t, sess)
	inner := benchInnerUDP(net.IPv4(10, 70, 0, 5), 64)

	before := counterValue(t, s.dropULNotReady)
	s.handlePacket(gtpuIn(0x31, 0x10, 7, inner))
	if got := counterValue(t, s.dropULNotReady) - before; got != 1 {
		t.Fatalf("ul_tunnel_not_ready delta = %v, want 1", got)
	}

	sess.SetULPeer(&pfcp.GTPUPeer{TEID: 0xAB, Addr: netip.MustParseAddr("127.0.0.1")})
	s.handlePacket(gtpuIn(0x31, 0x10, 7, inner))
	if got, want := recvFrame(t, sink), wantFrame(0xAB, 0x10, 7, inner); !bytes.Equal(got, want) {
		t.Fatalf("N9 UL frame\n got % X\nwant % X", got, want)
	}
	_ = tun.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if n, _ := tun.Read(make([]byte, 2048)); n != 0 {
		t.Fatalf("relayed UL leaked to the N6 TUN (%d bytes)", n)
	}
}

// TestVUPFDownlinkFromN9: GTP-U on the N9 F-TEID is re-encapsulated to the gNB with
// the DL TEID and the inbound QFI; a missing gNB tunnel drops and counts.
func TestVUPFDownlinkFromN9(t *testing.T) {
	sink := peerSink(t)
	sess := &pfcp.Session{CPSEID: 2, UPSEID: 2, ULTEID: 0x32, N9TEID: 0x92, ULRelay: true}
	s, _ := n9Server(t, sess)
	inner := benchInnerUDP(net.IPv4(10, 70, 0, 5), 80)

	before := counterValue(t, s.dropDLNotReady)
	s.handlePacket(gtpuIn(0x92, 0x00, 5, inner))
	if got := counterValue(t, s.dropDLNotReady) - before; got != 1 {
		t.Fatalf("dl_tunnel_not_ready delta = %v, want 1", got)
	}

	sess.DLTEID, sess.GNBIP = 0xCD, net.IPv4(127, 0, 0, 1)
	s.handlePacket(gtpuIn(0x92, 0x00, 5, inner))
	if got, want := recvFrame(t, sink), wantFrame(0xCD, 0x00, 5, inner); !bytes.Equal(got, want) {
		t.Fatalf("N3 DL frame\n got % X\nwant % X", got, want)
	}
}

// TestHUPFDownlinkToN9: the H-UPF's DL FAR OHC (the V-UPF N9 F-TEID) makes the
// ordinary TUN downlink path send GTP-U to the V-UPF.
func TestHUPFDownlinkToN9(t *testing.T) {
	sink := peerSink(t)
	ue := net.IPv4(10, 70, 0, 5)
	sess := &pfcp.Session{CPSEID: 3, UPSEID: 3, ULTEID: 0x33, UEIP: ue, DLTEID: 0x91, GNBIP: net.IPv4(127, 0, 0, 1)}
	s, _ := n9Server(t, sess)
	inner := benchInnerUDP(ue, 100)
	// dst must be the UE: swap src/dst of the helper packet.
	copy(inner[12:16], net.IPv4(8, 8, 8, 8).To4())
	copy(inner[16:20], ue.To4())

	buf := make([]byte, dlHeadroom+len(inner))
	copy(buf[dlHeadroom:], inner)
	if !s.handleTUNPacket(&s.tuns[0], buf, len(inner)) {
		t.Fatal("DL packet not sent")
	}
	got := recvFrame(t, sink)
	if want := wantFrame(0x91, 0x00, 5, inner); !bytes.Equal(got[:16], want[:16]) {
		t.Fatalf("H-UPF DL header\n got % X\nwant % X", got[:16], want[:16])
	}
}

// TestNonHRGolden: a plain N3 session still writes the UL inner packet to the TUN,
// emits nothing on the network, and the DL GTP-U frame is byte-identical to the
// pre-N9 encoding (fixed vector).
func TestNonHRGolden(t *testing.T) {
	sink := peerSink(t)
	ue := net.IPv4(10, 70, 0, 5)
	sess := &pfcp.Session{CPSEID: 4, UPSEID: 4, ULTEID: 0x34, UEIP: ue, DLTEID: 0xDEADBEEF, GNBIP: net.IPv4(127, 0, 0, 1)}
	s, tun := n9Server(t, sess)

	ul := benchInnerUDP(ue, 48)
	s.handlePacket(gtpuIn(0x34, 0x10, 5, ul))
	_ = tun.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 2048)
	n, err := tun.Read(got)
	if err != nil || !bytes.Equal(got[:n], ul) {
		t.Fatalf("UL to TUN = % X (%v), want inner packet", got[:n], err)
	}
	_ = sink.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if n, _, err := sink.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Fatalf("non-HR UL produced %d bytes of GTP-U", n)
	}

	s.sendGTPU(sess, []byte{0x45, 0x00, 0x00, 0x14})
	want := []byte{0x34, 0xFF, 0x00, 0x0C, 0xDE, 0xAD, 0xBE, 0xEF,
		0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x05, 0x00, 0x45, 0x00, 0x00, 0x14}
	if got := recvFrame(t, sink); !bytes.Equal(got, want) {
		t.Fatalf("non-HR DL frame\n got % X\nwant % X", got, want)
	}
}
