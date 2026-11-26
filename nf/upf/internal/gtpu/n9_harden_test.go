package gtpu

// n9_harden_test.go — N9 relay review fixes: UL volume counts forwarded packets
// only, DL buffer-full drop is counted and logged, DL from a non-peer source is
// dropped, and N9 log lines carry each JSON key once.
// Ref: TS 29.244 §5.2.2.4, §5.2.3.1; TS 29.281 §4.4.2; TS 23.502 §4.3.2.2.2.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
)

func TestN9ULVolumeCountsForwardedOnly(t *testing.T) {
	sink := peerSink(t)
	sess := &pfcp.Session{CPSEID: 3, UPSEID: 3, ULTEID: 0x33, N9TEID: 0x93, ULRelay: true}
	sess.URRState.Installed = true
	s, _ := n9Server(t, sess)
	inner := benchInnerUDP(net.IPv4(10, 70, 0, 5), 64)

	s.handlePacket(gtpuIn(0x33, 0x10, 7, inner)) // peer not set: dropped
	if got := sess.URRState.ULVolume.Load(); got != 0 {
		t.Fatalf("UL volume counted for a dropped packet: %d", got)
	}
	sess.SetULPeer(&pfcp.GTPUPeer{TEID: 0xAB, Addr: netip.MustParseAddr("127.0.0.1")})
	s.handlePacket(gtpuIn(0x33, 0x10, 7, inner))
	recvFrame(t, sink)
	if got := sess.URRState.ULVolume.Load(); got != uint64(len(inner)) {
		t.Fatalf("UL volume = %d, want %d", got, len(inner))
	}
}

func TestN9DLBufferFullCountedAndLogged(t *testing.T) {
	sess := &pfcp.Session{CPSEID: 4, UPSEID: 4, ULTEID: 0x34, N9TEID: 0x94, ULRelay: true}
	s, _ := n9Server(t, sess)
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	sess.DLBuf.SetLimit(1)
	sess.DLBuf.Arm(false)
	inner := benchInnerUDP(net.IPv4(10, 70, 0, 5), 64)

	before := pfcp.UPFDLBufferDroppedTotal.WithLabelValues(pfcp.DLDropBufferFull)
	b0 := counterValue(t, before)
	s.handlePacket(gtpuIn(0x94, 0x00, 5, inner)) // queued
	s.handlePacket(gtpuIn(0x94, 0x00, 5, inner)) // full
	s.handlePacket(gtpuIn(0x94, 0x00, 5, inner)) // full, log suppressed
	if d := counterValue(t, before) - b0; d != 2 {
		t.Fatalf("buffer_full delta = %v, want 2", d)
	}
	if n := strings.Count(logs.String(), "N9 DL buffer full"); n != 1 {
		t.Fatalf("buffer-full log lines = %d, want 1 (rate-limited)", n)
	}
	assertUniqueKeys(t, logs.Bytes())
}

func TestN9DLSourceCheck(t *testing.T) {
	sink := peerSink(t)
	sess := &pfcp.Session{CPSEID: 5, UPSEID: 5, ULTEID: 0x35, N9TEID: 0x95, ULRelay: true,
		DLTEID: 0xCD, GNBIP: net.IPv4(127, 0, 0, 1)}
	s, _ := n9Server(t, sess)
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewJSONHandler(&logs, nil).WithAttrs([]slog.Attr{slog.String("nf", "UPF")}))
	inner := benchInnerUDP(net.IPv4(10, 70, 0, 5), 80)
	pkt := gtpuIn(0x95, 0x00, 5, inner)
	good, bad := netip.MustParseAddr("172.30.20.200"), netip.MustParseAddr("172.30.20.201")

	// Peer not set yet: legacy behaviour, any source is relayed.
	s.handlePacketFrom(pkt, bad)
	recvFrame(t, sink)

	sess.SetULPeer(&pfcp.GTPUPeer{TEID: 0xAB, Addr: good})
	before := counterValue(t, s.dropN9SrcMismatch)
	s.handlePacketFrom(pkt, bad)
	s.handlePacketFrom(pkt, bad)
	if d := counterValue(t, s.dropN9SrcMismatch) - before; d != 2 {
		t.Fatalf("n9_source_mismatch delta = %v, want 2", d)
	}
	if n := strings.Count(logs.String(), "not the session N9 peer"); n != 1 {
		t.Fatalf("mismatch log lines = %d, want 1 (rate-limited)", n)
	}
	assertUniqueKeys(t, logs.Bytes())

	// Matching source (also as 4-in-6) is relayed.
	s.handlePacketFrom(pkt, good)
	recvFrame(t, sink)
	s.handlePacketFrom(pkt, netip.AddrFrom16(good.As16()))
	recvFrame(t, sink)
}

// assertUniqueKeys fails when any top-level JSON key repeats within a log line.
func assertUniqueKeys(t *testing.T, b []byte) {
	t.Helper()
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		if _, err := dec.Token(); err != nil {
			t.Fatalf("log line is not JSON: %s", line)
		}
		seen := map[string]bool{}
		for dec.More() {
			k, _ := dec.Token()
			key := k.(string)
			if seen[key] {
				t.Errorf("duplicate JSON key %q in %s", key, line)
			}
			seen[key] = true
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				t.Fatal(err)
			}
		}
	}
}
