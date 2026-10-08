package gtpu

// qos_test.go — datapath QoS enforcement (UPF-005): UL/DL admission before the
// URR count and the TUN/N3 send, drop counters, QFI from the snapshot, the
// exemption of UPF-originated downlink, and the no-INFO-log rule.
// Ref: TS 23.501 §5.7.1.8; TS 29.244 §5.4.3, §5.4.4.

import (
	"bytes"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
)

type testClock struct{ ns atomic.Int64 }

func (c *testClock) Now() int64 { return c.ns.Load() }

// qosServer returns a bench server whose session carries QER 1 (Session-AMBR,
// no QFI, ul/dl kbps) + QER 2 (QFI 7, no MBR) on PDR 1, a URR, and burst 10 ms.
func qosServer(t *testing.T, ulKbps, dlKbps uint64, cfg pfcp.QoSConfig) (*Server, *pfcp.Session, *testClock) {
	t.Helper()
	s, sess, _, _ := benchServer(t, slog.LevelInfo)
	clk := &testClock{}
	cfg.Clock = clk.Now
	cfg.BurstMs = 10
	sess.QERs = map[uint32]*pfcp.QERState{
		1: {QERID: 1, HasMBR: true, MBRULKbps: ulKbps, MBRDLKbps: dlKbps},
		2: {QERID: 2, HasQFI: true, QFI: 7},
	}
	sess.PDRs = map[uint16]*pfcp.PDRState{1: {PDRID: 1, QERIDs: []uint32{1, 2}}}
	sess.RebuildQoS(cfg)
	sess.URRState.Installed = true
	return s, sess, clk
}

func delta(t *testing.T, s *Server, r pfcp.DropReason, f func()) float64 {
	t.Helper()
	before := counterValue(t, s.dropQER[r])
	f()
	return counterValue(t, s.dropQER[r]) - before
}

func TestUplinkPolicedBeforeURRAndTUN(t *testing.T) {
	s, sess, _ := qosServer(t, 8000, 8000, pfcp.QoSConfig{}) // depth 10000 B
	pkt := benchGTPU(sess.ULTEID, benchInnerUDP(sess.UEIP, 1000))
	var drops float64
	drops = delta(t, s, pfcp.DropMBRExceeded, func() {
		for i := 0; i < 15; i++ {
			s.handlePacket(pkt)
		}
	})
	if drops != 5 {
		t.Errorf("qer_mbr_exceeded delta = %v, want 5", drops)
	}
	if got := sess.URRState.ULVolume.Load(); got != 10000 {
		t.Errorf("UL volume = %d, want 10000 (policed packets are not measured)", got)
	}
}

func TestUplinkGateClosed(t *testing.T) {
	s, sess, _ := qosServer(t, 8000, 8000, pfcp.QoSConfig{})
	sess.QERs[2].GateUL = 1
	sess.RebuildQoS(pfcp.QoSConfig{})
	pkt := benchGTPU(sess.ULTEID, benchInnerUDP(sess.UEIP, 1000))
	var gate, mbr float64
	mbr = delta(t, s, pfcp.DropMBRExceeded, func() {
		gate = delta(t, s, pfcp.DropGateClosed, func() {
			for i := 0; i < 4; i++ {
				s.handlePacket(pkt)
			}
		})
	})
	if gate != 4 || mbr != 0 {
		t.Errorf("gate delta=%v mbr delta=%v, want 4 and 0", gate, mbr)
	}
	if sess.URRState.ULVolume.Load() != 0 {
		t.Error("gate-closed packets must not be measured")
	}
}

func TestDownlinkPolicedAndQFIFromSnapshot(t *testing.T) {
	s, sess, _ := qosServer(t, 8000, 4000, pfcp.QoSConfig{}) // DL depth 5000 B
	pkt := benchInnerUDP(sess.UEIP, 1000)
	copy(pkt[12:16], []byte{8, 8, 8, 8}) // downlink: from the DN ...
	copy(pkt[16:20], sess.UEIP.To4())    // ... to the UE
	sent := 0
	drops := delta(t, s, pfcp.DropMBRExceeded, func() {
		for i := 0; i < 10; i++ {
			if s.InjectDownlink("internet", pkt) {
				sent++
			}
		}
	})
	if sent != 5 || drops != 5 {
		t.Errorf("sent=%d drops=%v, want 5 and 5", sent, drops)
	}
	if got := sess.URRState.DLVolume.Load(); got != 5000 {
		t.Errorf("DL volume = %d, want 5000", got)
	}
	if sess.DLQFI() != 7 {
		t.Errorf("DLQFI = %d, want 7 (QER 2)", sess.DLQFI())
	}
	if s.InjectDownlink("nope", pkt) {
		t.Error("unknown DNN must not send")
	}
}

func TestUPFOriginatedDownlinkIsExempt(t *testing.T) {
	s, sess, _ := qosServer(t, 2000, 2000, pfcp.QoSConfig{}) // depth 4500 B
	for ok, _ := sess.AdmitDL(1500); ok; ok, _ = sess.AdmitDL(1500) {
	}
	drops := delta(t, s, pfcp.DropMBRExceeded, func() {
		s.SendDownlink(sess, make([]byte, 100)) // RA / ICMP reply path (sendGTPU)
	})
	if drops != 0 {
		t.Errorf("exempt path counted %v policing drops", drops)
	}
	if got := sess.URRState.DLVolume.Load(); got != 100 {
		t.Errorf("DL volume = %d, want 100 (the exempt datagram was sent)", got)
	}
}

func TestMBRKnobOffStillGates(t *testing.T) {
	s, sess, _ := qosServer(t, 8000, 8000, pfcp.QoSConfig{MBRDisabled: true})
	pkt := benchGTPU(sess.ULTEID, benchInnerUDP(sess.UEIP, 1000))
	if d := delta(t, s, pfcp.DropMBRExceeded, func() {
		for i := 0; i < 100; i++ {
			s.handlePacket(pkt)
		}
	}); d != 0 {
		t.Errorf("knob off but %v packets policed", d)
	}
}

func TestNoInfoLogPerPolicedPacket(t *testing.T) {
	var buf bytes.Buffer
	s, sess, _ := qosServer(t, 8000, 8000, pfcp.QoSConfig{})
	s.logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	s.initCounters()
	pkt := benchGTPU(sess.ULTEID, benchInnerUDP(sess.UEIP, 1000))
	for i := 0; i < 1000; i++ {
		s.handlePacket(pkt)
	}
	if buf.Len() != 0 {
		t.Errorf("INFO+ log output during policing: %s", buf.String())
	}
}

func TestDebugDropLogRateLimited(t *testing.T) {
	var buf bytes.Buffer
	s, sess, _ := qosServer(t, 8000, 8000, pfcp.QoSConfig{})
	s.logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s.initCounters()
	pkt := benchGTPU(sess.ULTEID, benchInnerUDP(sess.UEIP, 1000))
	for i := 0; i < 1000; i++ {
		s.handlePacket(pkt)
	}
	if n := bytes.Count(buf.Bytes(), []byte("QER policing drop")); n != 1 {
		t.Errorf("policing event logged %d times, want 1 (rate limited per SEID)", n)
	}
}

func benchAdmit(b *testing.B, ulKbps uint64) {
	s, sess, _, _ := benchServer(b, slog.LevelInfo)
	sess.QERs = map[uint32]*pfcp.QERState{
		1: {QERID: 1, HasMBR: true, MBRULKbps: ulKbps, MBRDLKbps: ulKbps},
		2: {QERID: 2, HasQFI: true, QFI: 1},
	}
	sess.PDRs = map[uint16]*pfcp.PDRState{1: {PDRID: 1, QERIDs: []uint32{1, 2}}}
	sess.RebuildQoS(pfcp.QoSConfig{})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.AdmitUL(sess, 1400)
	}
}

// BenchmarkAdmitUnlimited: the gtpu-bench shape (MBR 0xFFFFFFFF): nil buckets.
func BenchmarkAdmitUnlimited(b *testing.B) { benchAdmit(b, 0xFFFFFFFF) }

// BenchmarkAdmitLimitedPass: a real bucket with the real clock, always conforming.
func BenchmarkAdmitLimitedPass(b *testing.B) { benchAdmit(b, 100_000_000) }
