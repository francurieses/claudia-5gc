package gtpu

// dlbuffer_test.go - datapath side of DL buffering (SMF-011): a buffering
// session queues instead of dropping as dl_tunnel_not_ready, over-limit packets
// are counted buffer_full, and the flush goes through the normal DL send path.
// Ref: TS 29.244 §5.2.3.1.

import (
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
)

func TestBufferingSessionQueuesInsteadOfDropping(t *testing.T) {
	s, sess, _, _ := benchServer(t, slog.LevelInfo)
	sess.DLTEID, sess.GNBIP = 0, nil // AN released: tunnel cleared
	sess.DLBuf.SetLimit(2)
	sess.DLBuf.Arm(false)

	pkt := benchInnerUDP(sess.UEIP, 100)
	copy(pkt[12:16], []byte{8, 8, 8, 8})
	copy(pkt[16:20], sess.UEIP.To4())

	notReady := counterValue(t, s.dropDLNotReady)
	full := testutil.ToFloat64(pfcp.UPFDLBufferDroppedTotal.WithLabelValues(pfcp.DLDropBufferFull))
	for i := 0; i < 3; i++ {
		pkt[28] = byte(i + 1) // distinct payload; the TUN buffer is reused by the caller
		if s.InjectDownlink("internet", pkt) {
			t.Fatal("a buffered packet must not be reported as sent")
		}
	}
	if d := counterValue(t, s.dropDLNotReady) - notReady; d != 0 {
		t.Errorf("dl_tunnel_not_ready delta = %v, want 0", d)
	}
	if d := testutil.ToFloat64(pfcp.UPFDLBufferDroppedTotal.WithLabelValues(pfcp.DLDropBufferFull)) - full; d != 1 {
		t.Errorf("buffer_full delta = %v, want 1", d)
	}
	got := sess.DLBuf.Packets()
	if len(got) != 2 || got[0][28] != 1 || got[1][28] != 2 {
		t.Fatalf("buffer = %d packets, want P1,P2 in order", len(got))
	}
}

func TestSendBufferedUsesNormalDownlinkPath(t *testing.T) {
	s, sess, _, _ := benchServer(t, slog.LevelInfo)
	sess.URRState.Installed = true
	pkt := benchInnerUDP(sess.UEIP, 100)
	if !s.SendBuffered(sess, pkt) {
		t.Error("SendBuffered must report true for a sent packet")
	}
	if got := sess.URRState.DLVolume.Load(); got != 100 {
		t.Errorf("DL volume = %d, want 100 (flush is measured by the URR)", got)
	}
	sess.DLTEID, sess.GNBIP = 0, nil
	before := counterValue(t, s.dropDLNotReady)
	if s.SendBuffered(sess, pkt) {
		t.Error("SendBuffered must report false without a tunnel")
	}
	if counterValue(t, s.dropDLNotReady)-before != 1 {
		t.Error("flush without a tunnel must count dl_tunnel_not_ready")
	}
}
