package gtpu

// N9 relay of a home-routed PDU session (ROAM-002 phase 2): the V-UPF forwards UL
// from N3 to the H-UPF and DL from N9 to the gNB, re-encapsulating GTP-U in both
// directions. The H-UPF needs no code here: its UL goes to the N6 TUN and its DL
// (FAR OHC to the V-UPF N9 F-TEID) takes the ordinary TUN -> GTP-U path.
// Ref: TS 23.501 §4.2.4, TS 23.502 §4.3.2.2.2, TS 29.281 §5.1/§5.2.2.7, TS 38.415 §5.5.2.

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

const (
	// pduSessionContainerUL is the PDU Type nibble of "UL PDU SESSION
	// INFORMATION" (type 1, bits 8-5), TS 38.415 Table 5.5.2.1-2. N9 carries the
	// PDU Session Container in both directions (TS 29.281 §5.2.2.7).
	pduSessionContainerUL = 0x10
	// relayBufSize is the pooled relay frame size (headroom + a 1500 B MTU packet).
	relayBufSize = dlHeadroom + 2048
)

// peerPort is the UDP destination port of every GTP-U frame sent to a peer
// (gNB or N9 peer, TS 29.281 §4.4.2.1: 2152). A variable only so tests can
// target an unprivileged loopback socket.
var peerPort uint16 = gtpuPort

// relayPool recycles relay frames: the UDP write copies, so a frame is free to
// reuse as soon as sendRelay returns (zero allocation per packet).
var relayPool = sync.Pool{New: func() any { b := make([]byte, relayBufSize); return &b }}

// putULHeader writes the 16-octet UL encapsulation into h: GTP-U header (v1,
// PT=1, E=1, T-PDU) and the PDU Session Container carrying the UL PDU type and
// QFI (same layout as putDLHeader, PDU Type = 1). Ref: TS 29.281 §5.1, §5.2.1.
func putULHeader(h []byte, teid uint32, qfi uint8, innerLen int) {
	h[0] = 0x34
	h[1] = msgTypeTPDU
	binary.BigEndian.PutUint16(h[2:4], uint16(8+innerLen))
	binary.BigEndian.PutUint32(h[4:8], teid)
	h[8], h[9], h[10] = 0x00, 0x00, 0x00
	h[11] = extHdrTypePDUSessionContainer
	h[12] = 0x01
	h[13] = pduSessionContainerUL
	h[14] = qfi & 0x3F
	h[15] = 0x00
}

// containerQFI returns the QFI of the PDU Session Container in the extension
// chain of pkt (E flag set, validated by handlePacket). Relay paths only.
func containerQFI(pkt []byte) (uint8, bool) {
	if pkt[0]&0x07 == 0 || len(pkt) < gtpuExtHdr {
		return 0, false
	}
	next, off := pkt[gtpuExtHdr-1], gtpuExtHdr
	for next != 0 && off+4 <= len(pkt) {
		l := int(pkt[off]) * 4
		if l < 4 || off+l > len(pkt) {
			return 0, false
		}
		if next == extHdrTypePDUSessionContainer {
			return pkt[off+2] & 0x3F, true
		}
		next = pkt[off+l-1]
		off += l
	}
	return 0, false
}

// relayUplinkN9 forwards one admitted UL packet to the H-UPF (N9). Until the
// Session Modification installed the peer OHC the packet is dropped (counted).
func (s *Server) relayUplinkN9(sess *pfcp.Session, pkt, inner []byte) {
	peer := sess.ULPeer()
	if peer == nil {
		if s.limiter.allow(sess.ULTEID) {
			s.logger.Warn("N9 UL peer not ready (repeats suppressed 10s)", "procedure", "HomeRoutedPduSession",
				"interface", "N9", "direction", "OUT", "ul_teid", sess.ULTEID,
				"spec_ref", "TS 29.244 §5.2.1", "result", "REJECT")
		}
		s.dropULNotReady.Inc()
		return
	}
	sess.AddULVolume(len(inner)) // forwarded packets only (TS 29.244 §5.2.2.4)
	qfi, ok := containerQFI(pkt)
	if !ok {
		qfi = sess.DLQFI()
	}
	bp := relayPool.Get().(*[]byte)
	frame := bufFor(bp, len(inner))
	copy(frame[dlHeadroom:], inner)
	putULHeader(frame, peer.TEID, qfi, len(inner))
	s.sendRelay(frame, peer.Addr, "ul")
	relayPool.Put(bp)
}

// handleN9Downlink forwards one DL packet received on the N9 F-TEID to the gNB
// (DL FAR Destination Access + OHC), through the same buffering, QoS and volume
// accounting as the ordinary DL path. The L4 checksum repair is an N6 matter and
// stays at the H-UPF. When the N9 peer is known and src is valid, a datagram whose
// source IP is not the peer's is dropped (n9_source_mismatch): the N9 TEID alone
// is not an authenticator. Ref: TS 29.244 §5.2.3.1, §5.4.3; TS 29.281 §4.4.2.
func (s *Server) handleN9Downlink(sess *pfcp.Session, pkt, inner []byte, src netip.Addr) {
	if peer := sess.ULPeer(); peer != nil && src.IsValid() && src.Unmap() != peer.Addr.Unmap() {
		if s.limiter.allow("n9src") {
			s.logger.Warn("N9 DL source is not the session N9 peer (repeats suppressed 10s)",
				"procedure", "HomeRoutedPduSession", "interface", "N9", "direction", "IN",
				"n9_teid", sess.N9TEID, "src", src.String(), "peer", peer.Addr.String(),
				"spec_ref", "TS 29.281 §4.4.2; TS 23.502 §4.3.2.2.2", "result", "REJECT")
		}
		s.dropN9SrcMismatch.Inc()
		return
	}
	n := len(inner)
	if sess.DLBuf.Active() {
		switch sess.DLBuf.Offer(inner) {
		case pfcp.OfferQueued:
			return
		case pfcp.OfferQueuedReport:
			if s.pfcpSrv != nil {
				go s.pfcpSrv.NotifyDownlinkData(logging.WithCorrelationID(context.Background(), ""), sess)
			}
			return
		case pfcp.OfferFull:
			// Counted by DLBuf.Offer (fivegc_upf_dl_buffer_dropped_total{buffer_full}),
			// like the TUN DL path; log is rate-limited.
			if s.limiter.allow("dlbuf_full") {
				s.logger.Warn("N9 DL buffer full, packet dropped (repeats suppressed 10s)",
					"procedure", "HomeRoutedPduSession", "interface", "N9", "direction", "IN",
					"n9_teid", sess.N9TEID, "reason", pfcp.DLDropBufferFull,
					"spec_ref", "TS 29.244 §5.2.3.1", "result", "REJECT")
			}
			return
		}
	}
	if sess.DLTEID == 0 || sess.GNBIP == nil {
		if s.limiter.allow(sess.DLTEID) {
			s.logger.Warn("N9 DL tunnel not ready (repeats suppressed 10s)", "procedure", "HomeRoutedPduSession",
				"interface", "N9", "direction", "IN", "n9_teid", sess.N9TEID,
				"spec_ref", "TS 29.244 §5.2.1", "result", "REJECT")
		}
		s.dropDLNotReady.Inc()
		return
	}
	if !s.AdmitDL(sess, n) {
		return
	}
	qfi, ok := containerQFI(pkt)
	if !ok {
		qfi = sess.DLQFI()
	}
	bp := relayPool.Get().(*[]byte)
	frame := bufFor(bp, n)
	copy(frame[dlHeadroom:], inner)
	putDLHeader(frame, sess.DLTEID, qfi, n)
	s.sendFrame(sess, frame, n)
	relayPool.Put(bp)
}

// bufFor returns a frame of dlHeadroom+n octets from the pooled buffer,
// growing the pooled buffer (once) for oversized packets.
func bufFor(bp *[]byte, n int) []byte {
	if need := dlHeadroom + n; need > cap(*bp) {
		*bp = make([]byte, need)
	}
	return (*bp)[:dlHeadroom+n]
}

// sendRelay writes an encapsulated frame to a GTP-U peer on port 2152.
func (s *Server) sendRelay(frame []byte, peer netip.Addr, dir string) {
	if _, err := s.conn.WriteToUDPAddrPort(frame, netip.AddrPortFrom(peer, peerPort)); err != nil {
		if s.limiter.allow("n9send") {
			s.logger.Error("N9 GTP-U send (repeats suppressed 10s)", "error", err, "peer", peer.String(),
				"procedure", "HomeRoutedPduSession", "interface", "N9", "direction", "OUT", "dir", dir,
				"spec_ref", "TS 29.281 §5.1")
		}
		s.dropSend.Inc()
		return
	}
	if s.debug {
		s.logger.Debug("N9 GTP-U sent", "procedure", "HomeRoutedPduSession", "interface", "N9",
			"direction", "OUT", "spec_ref", "TS 29.281 §5.1", "peer", peer.String(), "dir", dir)
	}
}
