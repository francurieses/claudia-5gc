package pfcp

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// Downlink buffering and Downlink Data Report (SMF-011, UPF side).
// Ref: TS 23.501 §5.8.2.19.2; TS 23.502 §4.2.3.3 step 2a; TS 29.244 §5.2.3.1,
// §5.2.4.1, §7.5.2.6 (Create BAR), §7.5.8 (Session Report Request, DLDR).

// Apply Action IE bits (TS 29.244 §8.2.26, octet 5).
const (
	// applyActionBUFF is bit 3: buffer the packet.
	applyActionBUFF uint8 = 0x04
	// applyActionNOCP is bit 4: notify the CP function of the first buffered
	// DL packet (Downlink Data Report).
	applyActionNOCP uint8 = 0x08
)

const (
	// defaultDLBufferPackets is the per-session DL buffer limit when the BAR
	// carries no Suggested Buffering Packets Count. No 3GPP-mandated default
	// exists (TS 29.244 §5.2.3.1: "implementation specific"); config key
	// n4.dl_buffer.default_max_packets overrides it.
	defaultDLBufferPackets = 64
	// maxDLBufferPackets caps both the default and a BAR-suggested count
	// (config key n4.dl_buffer.max_packets_cap). TS 29.244 §8.2.118 limits the
	// suggested count to one octet (0-255); 256 keeps headroom for the default.
	maxDLBufferPackets = 256
	// legacyDLPDRID is the DL PDR ID reported in the DLDR for SMFs that install
	// a single PDR 1 -> FAR 1 (pre SMF-011 layout). TS 29.244 §7.5.8.2.
	legacyDLPDRID uint16 = 1
	// legacyDLFARID is the DL FAR ID of that legacy layout.
	legacyDLFARID uint32 = 1
	// dldrT1 is the retransmission timer T1 of the DLDR Session Report Request:
	// the UPF waits this long for the Session Report Response before resending
	// (TS 29.244 §6.4, §7.2.2.4.1; value implementation specific, 3 s as for the
	// other PFCP request retransmissions).
	dldrT1 = 3 * time.Second
	// dldrN1 is the maximum number of retransmissions of the DLDR after the
	// initial transmission (TS 29.244 §6.4, §7.2.2.4.1).
	dldrN1 = 3
	// procDownlinkDataReport is the procedure label of the DLDR counter.
	procDownlinkDataReport = "DownlinkDataReport"
	// procNetworkTriggeredServiceRequest is the canonical procedure name used
	// in the DL buffering logs.
	procNetworkTriggeredServiceRequest = "NetworkTriggeredServiceRequest"
)

// Drop / discard reasons of fivegc_upf_dl_buffer_dropped_total.
const (
	// DLDropBufferFull: tail drop at the per-session limit.
	DLDropBufferFull = "buffer_full"
	// DLDropFARDrop: Update FAR with DROP discarded the buffer.
	DLDropFARDrop = "far_drop"
	// DLDropSessionDeleted: Session Deletion (or CP restart purge).
	DLDropSessionDeleted = "session_deleted"
	// DLDropCPRejected: the CP answered the DLDR with Cause != 1.
	DLDropCPRejected = "cp_rejected"
	// DLDropFlushUnavailable: FORW arrived but no datapath flusher is wired.
	DLDropFlushUnavailable = "flush_unavailable"
)

var (
	// UPFDLBufferedPacketsTotal counts DL packets queued in a session buffer.
	UPFDLBufferedPacketsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fivegc_upf_dl_buffered_packets_total",
		Help: "Total downlink packets buffered by the UPF while the FAR Apply Action is BUFF (TS 29.244 §5.2.3.1).",
	})
	// UPFDLBufferDroppedTotal counts buffered or would-be-buffered DL packets
	// that were discarded, by reason.
	UPFDLBufferDroppedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_upf_dl_buffer_dropped_total",
		Help: "Total downlink packets dropped from the UPF DL buffer, labeled by reason.",
	}, []string{"reason"})
	// UPFDLBufferLimitPackets exposes the configured default per-session limit.
	UPFDLBufferLimitPackets = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "fivegc_upf_dl_buffer_limit_packets",
		Help: "Configured default per-session downlink buffer limit in packets.",
	})

	dldrOK      = metrics.ProcedureTotal.WithLabelValues("UPF", procDownlinkDataReport, "OK")
	dldrFailure = metrics.ProcedureTotal.WithLabelValues("UPF", procDownlinkDataReport, "FAILURE")
	dldrReject  = metrics.ProcedureTotal.WithLabelValues("UPF", procDownlinkDataReport, "REJECT")
)

func init() {
	// Materialise every reason so the exposition carries the series at 0.
	for _, r := range []string{DLDropBufferFull, DLDropFARDrop, DLDropSessionDeleted,
		DLDropCPRejected, DLDropFlushUnavailable} {
		UPFDLBufferDroppedTotal.WithLabelValues(r)
	}
}

// OfferResult is the outcome of DLBuffer.Offer.
type OfferResult uint8

const (
	// OfferNotBuffering: the FAR is not buffering; forward/drop as usual.
	OfferNotBuffering OfferResult = iota
	// OfferQueued: the packet was copied into the buffer.
	OfferQueued
	// OfferQueuedReport: queued, and it is the first packet of the buffering
	// period with NOCP armed - the caller must send the DLDR.
	OfferQueuedReport
	// OfferFull: the buffer is at its limit; the packet was counted as dropped.
	OfferFull
)

// DLBuffer is the bounded per-session FIFO of downlink packets held while the
// DL FAR has Apply Action BUFF. The zero value is ready (not buffering).
// Ref: TS 29.244 §5.2.3.1.
type DLBuffer struct {
	// active mirrors (buffering || flushing) for a lock-free fast path.
	active atomic.Bool

	mu        sync.Mutex
	buffering bool // FAR Apply Action has BUFF
	flushing  bool // flush in progress: new packets queue behind the backlog
	notify    bool // NOCP armed
	reported  bool // DLDR already sent in this period
	limit     int
	pkts      [][]byte
	reportSeq uint32
}

// Active reports (lock-free) whether packets must go through Offer.
func (b *DLBuffer) Active() bool { return b.active.Load() }

func (b *DLBuffer) refreshLocked() { b.active.Store(b.buffering || b.flushing) }

// SetLimit sets the maximum queued packets (<=0 selects the default).
func (b *DLBuffer) SetLimit(n int) {
	b.mu.Lock()
	b.limit = n
	b.mu.Unlock()
}

// Len returns the number of queued packets.
func (b *DLBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pkts)
}

// Packets returns a copy of the queued packets in FIFO order (tests, admin).
func (b *DLBuffer) Packets() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([][]byte, len(b.pkts))
	for i, p := range b.pkts {
		out[i] = append([]byte(nil), p...)
	}
	return out
}

// Offer queues a copy of the downlink IP packet pkt when the FAR is buffering
// (or a flush is draining). pkt is not retained (the TUN read buffer is reused).
func (b *DLBuffer) Offer(pkt []byte) OfferResult {
	if !b.active.Load() {
		return OfferNotBuffering
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.buffering && !b.flushing {
		return OfferNotBuffering
	}
	limit := b.limit
	if limit <= 0 {
		limit = defaultDLBufferPackets
	}
	if len(b.pkts) >= limit {
		UPFDLBufferDroppedTotal.WithLabelValues(DLDropBufferFull).Inc()
		return OfferFull
	}
	b.pkts = append(b.pkts, append([]byte(nil), pkt...))
	UPFDLBufferedPacketsTotal.Inc()
	if b.buffering && b.notify && !b.reported {
		b.reported = true
		return OfferQueuedReport
	}
	return OfferQueued
}

// Arm starts (or re-arms) buffering for an Update FAR with BUFF. notify is the
// NOCP bit; a fresh BUFF+NOCP re-arms the single DLDR. It returns true when
// packets are already queued and a DLDR is due now.
func (b *DLBuffer) Arm(notify bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buffering = true
	b.notify = notify
	b.reported = false
	b.refreshLocked()
	if notify && len(b.pkts) > 0 && !b.flushing {
		b.reported = true
		return true
	}
	return false
}

// BeginReport records the sequence number of the outstanding DLDR. It returns
// false when the report is no longer armed (a Discard / FORW raced in), in which
// case the caller must not send the DLDR.
func (b *DLBuffer) BeginReport(seq uint32) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.reported {
		return false
	}
	b.reportSeq = seq
	return true
}

// Buffering reports whether the FAR Apply Action currently has BUFF.
func (b *DLBuffer) Buffering() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffering
}

// StopFlushIfBuffering is called by a draining flush before sending rest (the
// packets of the current batch not yet sent). When a BUFF arrived mid-flush it
// puts rest back at the head of the queue (order preserved), ends the flush and
// returns stopped=true; report=true when NOCP is armed and a DLDR is now due.
func (b *DLBuffer) StopFlushIfBuffering(rest [][]byte) (stopped, report bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.buffering {
		return false, false
	}
	if len(rest) > 0 {
		b.pkts = append(append(make([][]byte, 0, len(rest)+len(b.pkts)), rest...), b.pkts...)
	}
	b.flushing = false
	b.refreshLocked()
	if b.notify && !b.reported && len(b.pkts) > 0 {
		b.reported = true
		report = true
	}
	return true, report
}

// ReportSeq returns the sequence number of the outstanding DLDR (0 = none).
func (b *DLBuffer) ReportSeq() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reportSeq
}

// DisarmReport lets the next buffered packet trigger a new DLDR (send failed).
func (b *DLBuffer) DisarmReport() {
	b.mu.Lock()
	b.reported = false
	b.reportSeq = 0
	b.mu.Unlock()
}

// Discard drops every queued packet, leaves buffering state, and counts the
// packets under reason. It returns the number discarded.
func (b *DLBuffer) Discard(reason string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.pkts)
	b.pkts = nil
	b.buffering, b.flushing, b.notify, b.reported, b.reportSeq = false, false, false, false, 0
	b.refreshLocked()
	if n > 0 {
		UPFDLBufferDroppedTotal.WithLabelValues(reason).Add(float64(n))
	}
	return n
}

// DiscardKeepBuffering drops the queued packets (counted under reason) but
// keeps the FAR in buffering state (CP rejected the DLDR).
func (b *DLBuffer) DiscardKeepBuffering(reason string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.pkts)
	b.pkts = nil
	b.reportSeq = 0
	if n > 0 {
		UPFDLBufferDroppedTotal.WithLabelValues(reason).Add(float64(n))
	}
	return n
}

// BeginFlush leaves buffering state because the FAR now forwards. It returns
// true when packets are queued: the caller must then drain with NextBatch.
// Until NextBatch reports done, new packets keep queueing behind the backlog
// so FIFO order is preserved.
func (b *DLBuffer) BeginFlush() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buffering, b.notify, b.reported, b.reportSeq = false, false, false, 0
	b.flushing = len(b.pkts) > 0
	b.refreshLocked()
	return b.flushing
}

// NextBatch hands the caller everything queued so far. When nothing is queued
// the flush ends atomically (done=true) and later packets bypass the buffer.
func (b *DLBuffer) NextBatch() (batch [][]byte, done bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.pkts) == 0 || b.buffering {
		// Empty, or a BUFF arrived mid-flush: stop draining, keep the rest.
		b.flushing = false
		b.refreshLocked()
		return nil, true
	}
	batch, b.pkts = b.pkts, nil
	return batch, false
}

// DLFlusher sends one buffered downlink IP packet through the normal DL path
// (QoS/AMBR admission, L4 checksum repair, GTP-U encapsulation, URR volume).
// Implemented by the GTP-U server; the seam keeps pfcp from importing gtpu.
type DLFlusher interface {
	// SendBuffered reports whether the packet was handed to the N3 socket.
	SendBuffered(sess *Session, ipPkt []byte) bool
}

// SetDLFlusher wires the GTP-U server used to flush buffered packets.
func (s *Server) SetDLFlusher(f DLFlusher) { s.dlFlusher = f }

// effectiveDLBufferLimit applies the BAR suggestion (if any) and the config cap.
func (s *Server) effectiveDLBufferLimit(suggested int) int {
	limit := s.dlBufDefault
	if suggested > 0 {
		limit = suggested
	}
	if limit > s.dlBufCap {
		limit = s.dlBufCap
	}
	return limit
}

// flushDLBuffer drains the session buffer in FIFO order through the flusher.
// Packets that arrive meanwhile queue behind the backlog (BeginFlush contract).
// A BUFF arriving mid-flush stops the drain and keeps the rest buffered.
func (s *Server) flushDLBuffer(ctx context.Context, sess *Session) {
	if !sess.DLBuf.BeginFlush() {
		return
	}
	logger := logging.NewProcedureLogger(ctx, s.logger, procNetworkTriggeredServiceRequest)
	if s.dlFlusher == nil {
		logger.Warn("DL buffer flush: no datapath flusher wired, buffered packets dropped",
			"nf", "UPF", "interface", "N3", "direction", "OUT",
			"spec_ref", "TS 29.244 §5.2.3.1", "seid", sess.UPSEID, "result", "FAILURE")
	}
	sent, failed := 0, 0
	reportDue := false
drain:
	for {
		batch, done := sess.DLBuf.NextBatch()
		if done {
			break
		}
		for i, p := range batch {
			if stopped, report := sess.DLBuf.StopFlushIfBuffering(batch[i:]); stopped {
				reportDue = report
				break drain
			}
			if s.dlFlusher == nil {
				UPFDLBufferDroppedTotal.WithLabelValues(DLDropFlushUnavailable).Inc()
				failed++
				continue
			}
			if s.dlFlusher.SendBuffered(sess, p) {
				sent++
			} else {
				failed++
			}
		}
	}
	result := "OK"
	if failed > 0 {
		result = "FAILURE"
	}
	logger.Info("DL buffer flushed",
		"nf", "UPF", "interface", "N3", "direction", "OUT",
		"spec_ref", "TS 29.244 §5.2.3.1; TS 23.502 §4.2.3.3 step 7",
		"seid", sess.UPSEID, "sent", sent, "failed", failed, "result", result)
	if reportDue {
		s.NotifyDownlinkData(ctx, sess)
	}
}

// discardDLBuffer discards the buffer with a log line when anything was lost.
// The pending DLDR is dropped under dldrMu together with the buffer reset so a
// concurrent NotifyDownlinkData cannot register an orphan entry.
func (s *Server) discardDLBuffer(ctx context.Context, sess *Session, reason string) {
	s.dldrMu.Lock()
	s.removeDLDRLocked(sess.DLBuf.ReportSeq())
	n := sess.DLBuf.Discard(reason)
	s.dldrMu.Unlock()
	if n == 0 {
		return
	}
	logging.NewProcedureLogger(ctx, s.logger, procNetworkTriggeredServiceRequest).Info("DL buffer discarded",
		"nf", "UPF", "interface", "N4", "direction", "IN",
		"spec_ref", "TS 29.244 §5.2.3.1, §7.5.4.3", "seid", sess.UPSEID,
		"packets", n, "reason", reason)
}

// dldrEntry is one outstanding DLDR Session Report Request awaiting its
// response, retransmitted on T1 up to N1 times (TS 29.244 §6.4, §7.2.2.4.1).
type dldrEntry struct {
	sess  *Session
	msg   []byte
	cid   string
	timer *time.Timer
	// retx counts the retransmissions already sent (guarded by Server.dldrMu).
	retx int
}

// removeDLDRLocked forgets the outstanding DLDR with sequence seq and stops its
// timer. dldrMu must be held. It returns the entry (nil when none).
func (s *Server) removeDLDRLocked(seq uint32) *dldrEntry {
	if seq == 0 {
		return nil
	}
	e := s.dldrPending[seq]
	if e != nil {
		e.timer.Stop()
		delete(s.dldrPending, seq)
	}
	return e
}

// stopDLDRTimers stops every outstanding DLDR timer (server shutdown).
func (s *Server) stopDLDRTimers() {
	s.dldrMu.Lock()
	defer s.dldrMu.Unlock()
	for seq := range s.dldrPending {
		s.removeDLDRLocked(seq)
	}
}

// dldrTimeout runs on T1 expiry: retransmit, or give up after N1 retransmissions.
func (s *Server) dldrTimeout(seq uint32) {
	s.dldrMu.Lock()
	e := s.dldrPending[seq]
	if e == nil {
		s.dldrMu.Unlock()
		return
	}
	ctx := logging.WithCorrelationID(context.Background(), e.cid)
	logger := logging.NewProcedureLogger(ctx, s.logger, procNetworkTriggeredServiceRequest)
	sess := e.sess
	if e.retx >= s.dldrN1 {
		s.removeDLDRLocked(seq)
		// Keep buffering; let the next packet trigger a fresh DLDR.
		sess.DLBuf.DisarmReport()
		s.dldrMu.Unlock()
		dldrFailure.Inc()
		logger.Warn("DLDR not acknowledged after N1 retransmissions, giving up",
			"nf", "UPF", "interface", "N4", "direction", "OUT",
			"spec_ref", "TS 29.244 §6.4, §7.2.2.4.1", "seid", sess.CPSEID,
			"sequence", seq, "retransmissions", e.retx, "result", "FAILURE")
		return
	}
	e.retx++
	retx := e.retx
	e.timer.Reset(s.dldrT1)
	msg, addr := e.msg, sess.SMFAddr
	s.dldrMu.Unlock()
	if _, err := s.conn.WriteToUDP(msg, addr); err != nil {
		logger.Warn("DLDR retransmission send failed", "error", fmt.Errorf("upf: downlink data report: %w", err),
			"nf", "UPF", "interface", "N4", "direction", "OUT", "spec_ref", "TS 29.244 §6.4",
			"seid", sess.CPSEID, "sequence", seq, "result", "FAILURE")
		return
	}
	logger.Info("PFCP Session Report Request (DLDR) retransmitted",
		"nf", "UPF", "interface", "N4", "direction", "OUT",
		"spec_ref", "TS 29.244 §6.4, §7.2.2.4.1", "seid", sess.CPSEID,
		"sequence", seq, "retransmission", retx, "message_type", "SessionReportRequest")
}

// NotifyDownlinkData sends one PFCP Session Report Request with Report Type
// DLDR and a Downlink Data Report (PDR ID of the DL PDR, QFI when known) to the
// CP function. Called once per buffering period when NOCP is set. The request is
// retransmitted on T1 up to N1 times until the response arrives; on a send
// failure the report is re-armed.
// Ref: TS 29.244 §5.2.3.1, §6.4, §7.5.8.1, §7.5.8.2.
func (s *Server) NotifyDownlinkData(ctx context.Context, sess *Session) {
	logger := logging.NewProcedureLogger(ctx, s.logger, procNetworkTriggeredServiceRequest)
	if sess.SMFAddr == nil {
		logger.Warn("DLDR not sent: no SMF address", "nf", "UPF", "interface", "N4", "direction", "OUT",
			"spec_ref", "TS 29.244 §7.5.8", "seid", sess.CPSEID, "result", "FAILURE")
		sess.DLBuf.DisarmReport()
		dldrFailure.Inc()
		return
	}
	pdrID := sess.DLPDRID
	if pdrID == 0 {
		pdrID = legacyDLPDRID
	}
	dlIEs := []*pfcpie.IE{pfcpie.NewPDRID(pdrID)}
	qfi := sess.DLQFI()
	if qfi != 0 {
		dlIEs = append(dlIEs, pfcpie.NewDownlinkDataServiceInformation(false, true, 0, qfi))
	}
	seq := s.reportSeq.Add(1)
	report := pfcpmsg.NewSessionReportRequest(0, 0, sess.CPSEID, seq, 0,
		pfcpie.NewReportType(0, 0, 0, 1), // DLDR=1, TS 29.244 §8.2.21
		pfcpie.NewDownlinkDataReport(dlIEs...),
	)
	b := make([]byte, report.MarshalLen())
	if err := report.MarshalTo(b); err != nil {
		logger.Error("DLDR marshal failed", "error", fmt.Errorf("upf: downlink data report: %w", err),
			"nf", "UPF", "interface", "N4", "direction", "OUT", "spec_ref", "TS 29.244 §7.5.8",
			"seid", sess.CPSEID, "result", "FAILURE")
		sess.DLBuf.DisarmReport()
		dldrFailure.Inc()
		return
	}
	e := &dldrEntry{sess: sess, msg: b, cid: logging.CorrelationID(ctx)}
	// Register atomically with the buffer state: a Discard / FORW that raced in
	// has cleared "reported" and BeginReport refuses (no orphan entry).
	s.dldrMu.Lock()
	if !sess.DLBuf.BeginReport(seq) {
		s.dldrMu.Unlock()
		return
	}
	e.timer = time.AfterFunc(s.dldrT1, func() { s.dldrTimeout(seq) })
	s.dldrPending[seq] = e
	s.dldrMu.Unlock()
	if _, err := s.conn.WriteToUDP(b, sess.SMFAddr); err != nil {
		s.dldrMu.Lock()
		s.removeDLDRLocked(seq)
		s.dldrMu.Unlock()
		sess.DLBuf.DisarmReport()
		dldrFailure.Inc()
		logger.Warn("DLDR send failed", "error", fmt.Errorf("upf: downlink data report: %w", err),
			"nf", "UPF", "interface", "N4", "direction", "OUT", "spec_ref", "TS 29.244 §7.5.8",
			"seid", sess.CPSEID, "smf", sess.SMFAddr, "result", "FAILURE")
		return
	}
	logger.Info("PFCP Session Report Request (DLDR) sent",
		"nf", "UPF", "interface", "N4", "direction", "OUT",
		"spec_ref", "TS 29.244 §5.2.3.1, §7.5.8.2",
		"seid", sess.CPSEID, "pdr_id", pdrID, "qfi", qfi, "sequence", seq,
		"message_type", "SessionReportRequest", "result", "OK")
}

// handleDLDRResponse processes the Session Report Response of a DLDR. It
// returns false when seq belongs to no outstanding DLDR.
func (s *Server) handleDLDRResponse(ctx context.Context, seq uint32, cause uint8) bool {
	s.dldrMu.Lock()
	e := s.removeDLDRLocked(seq)
	s.dldrMu.Unlock()
	if e == nil {
		return false
	}
	sess := e.sess
	logger := logging.NewProcedureLogger(ctx, s.logger, procNetworkTriggeredServiceRequest)
	if cause == pfcpie.CauseRequestAccepted {
		dldrOK.Inc()
		logger.Info("PFCP Session Report Response (DLDR) accepted",
			"nf", "UPF", "interface", "N4", "direction", "IN",
			"spec_ref", "TS 29.244 §7.5.9", "seid", sess.CPSEID, "cause", cause, "result", "OK")
		return true
	}
	dldrReject.Inc()
	n := sess.DLBuf.DiscardKeepBuffering(DLDropCPRejected)
	logger.Warn("PFCP Session Report Response (DLDR) rejected, buffer discarded",
		"nf", "UPF", "interface", "N4", "direction", "IN",
		"spec_ref", "TS 29.244 §7.5.9", "seid", sess.CPSEID, "cause", cause,
		"packets", n, "reason", DLDropCPRejected, "result", "REJECT")
	return true
}

// setupDLBuffering records the DL PDR / FAR / BAR linkage of a new session and
// sizes its DL buffer. The DL PDR is the first PDR with Source Interface Core;
// a legacy SMF layout (single PDR 1 -> FAR 1, no Core PDR) falls back to
// PDR 1 / its FAR. The BAR's Suggested Buffering Packets Count, if present and
// the BAR is the one linked to the DL FAR, sets the limit (capped by config).
// Ref: TS 29.244 §7.5.2.2, §7.5.2.3, §7.5.2.6, §8.2.118.
func (s *Server) setupDLBuffering(sess *Session, req *pfcpmsg.SessionEstablishmentRequest,
	pdrs []*PDRState, pdrFAR map[uint16]uint32) {
	sess.DLPDRID, sess.DLFARID = legacyDLPDRID, legacyDLFARID
	if far, ok := pdrFAR[legacyDLPDRID]; ok {
		sess.DLFARID = far
	}
	for _, p := range pdrs {
		if p.SourceInterface == srcInterfaceCore {
			sess.DLPDRID = p.PDRID
			if far, ok := pdrFAR[p.PDRID]; ok {
				sess.DLFARID = far
			}
			break
		}
	}

	// FAR -> BAR link of the DL FAR (Create FAR BAR ID, §7.5.2.3).
	for _, far := range req.CreateFAR {
		children, err := far.CreateFAR()
		if err != nil {
			continue
		}
		var farID uint32
		var barID uint8
		for _, c := range children {
			switch c.Type {
			case pfcpie.FARID:
				farID, _ = c.FARID()
			case pfcpie.BARID:
				barID, _ = c.BARID()
			}
		}
		if farID == sess.DLFARID {
			sess.BARID = barID
		}
	}

	suggested := 0
	if req.CreateBAR != nil && sess.BARID != 0 {
		if children, err := req.CreateBAR.CreateBAR(); err == nil {
			var id uint8
			var cnt uint8
			for _, c := range children {
				switch c.Type {
				case pfcpie.BARID:
					id, _ = c.BARID()
				case pfcpie.SuggestedBufferingPacketsCount:
					cnt, _ = c.SuggestedBufferingPacketsCount()
				}
			}
			if id == sess.BARID {
				suggested = int(cnt)
			}
		}
	}
	sess.DLBuf.SetLimit(s.effectiveDLBufferLimit(suggested))
}

// applyDLBufferAction applies an Update FAR Apply Action (without FORW) of the
// DL FAR to the session buffer: BUFF starts buffering (NOCP arms one DLDR),
// anything else (DROP, none) discards what was buffered.
// Ref: TS 29.244 §5.2.3.1, §7.5.4.3, §8.2.26.
func (s *Server) applyDLBufferAction(ctx context.Context, sess *Session, aa uint8) {
	logger := logging.NewProcedureLogger(ctx, s.logger, procNetworkTriggeredServiceRequest)
	if aa&applyActionBUFF != 0 {
		notify := aa&applyActionNOCP != 0
		reportNow := sess.DLBuf.Arm(notify)
		logger.Info("DL buffering enabled",
			"nf", "UPF", "interface", "N4", "direction", "IN",
			"spec_ref", "TS 29.244 §5.2.3.1, §8.2.26", "seid", sess.UPSEID,
			"apply_action", aa, "nocp", notify, "queued", sess.DLBuf.Len())
		if reportNow {
			s.NotifyDownlinkData(ctx, sess)
		}
		return
	}
	s.discardDLBuffer(ctx, sess, DLDropFARDrop)
}
