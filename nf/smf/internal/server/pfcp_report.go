// Package server: this file implements the SMF-side of PFCP Usage Reporting
// (UPF-001, TS 29.244 §5.2.2.4, §7.5.5, §7.5.8, §7.5.9). The SMF is normally
// a PFCP CLIENT ONLY (ephemeral net.DialUDP per establishment/modification/
// deletion). This file adds an ADDITIVE, persistent PFCP receiver bound to
// the well-known N4 UDP port so the UPF can send node-initiated Session
// Report Requests carrying Usage Reports (volume-threshold / periodic
// triggers). The receiver does not touch the existing client sockets.
//
// Consumption is split into a pure, side-effect-light seam
// (consumeSessionReport) and the UDP transport loop (StartPFCPReceiver) so
// functional/godog tests can drive the real production logic in-process
// without opening a socket.
package server

import (
	"context"
	"fmt"
	"net"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// pfcpReceiveBufferSize bounds a single inbound PFCP UDP datagram. PFCP
// messages are small (a handful of TLV IEs); 2048 bytes matches the UPF's
// receiver buffer and comfortably exceeds a Session Report Request.
const pfcpReceiveBufferSize = 2048

// pfcpReceiveReadTimeout bounds each ReadFromUDP call so the receive loop can
// observe ctx cancellation promptly without busy-looping. Mirrors the UPF
// GTP-U server's receive-loop pattern.
const pfcpReceiveReadTimeout = 1 * time.Second

// usageReportTriggerUnknown labels a Usage Report Trigger IE that carries
// neither VOLTH nor PERIO (e.g. a spec-defined trigger this MVP does not yet
// distinguish). Ref: TS 29.244 §8.2.44.
const usageReportTriggerUnknown = "UNKNOWN"

// UsageSummary carries the parsed contents of a single Usage Report IE
// (TS 29.244 §7.5.8), independent of the PFCP transport. It is the testable
// seam's return value: godog steps assert against it without needing a real
// UDP round-trip.
type UsageSummary struct {
	SEID            uint64
	URRID           uint32
	URSeqn          uint32
	Trigger         string // VOLTH | PERIO | UNKNOWN
	TotalVolume     uint64
	ULVolume        uint64
	DLVolume        uint64
	DurationSeconds float64
	KnownURR        bool // false when URRID does not match the session's installed URR
}

// StartPFCPReceiver runs the SMF's persistent PFCP receiver on the N4
// well-known UDP port, dispatching inbound Session Report Requests (msg type
// 56, node-initiated Usage Reporting) to consumeSessionReport and replying
// with a Session Report Response (msg type 57). Blocks until ctx is
// cancelled. Ref: TS 29.244 §6.2.1, §7.5.5, §7.5.9.
func (s *Server) StartPFCPReceiver(ctx context.Context) error {
	addr := s.cfg.N4.ReportListen
	if addr == "" {
		addr = "0.0.0.0:8805"
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("smf: pfcp receiver resolve %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("smf: pfcp receiver listen %q: %w", addr, err)
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	s.logger.Info("SMF: PFCP receiver listening",
		"nf", "SMF", "interface", "N4", "direction", "IN",
		"spec_ref", "TS 29.244 §6.2.1", "addr", addr)

	buf := make([]byte, pfcpReceiveBufferSize)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(pfcpReceiveReadTimeout))
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			s.logger.Warn("SMF: PFCP receiver read error",
				"nf", "SMF", "interface", "N4", "direction", "IN", "error", err)
			continue
		}

		msg, err := pfcpmsg.Parse(buf[:n])
		if err != nil {
			s.logger.Warn("SMF: PFCP receiver parse error",
				"nf", "SMF", "interface", "N4", "direction", "IN",
				"error", err, "bytes", n, "remote", raddr)
			continue
		}

		switch m := msg.(type) {
		case *pfcpmsg.SessionReportRequest:
			s.handleSessionReport(ctx, conn, raddr, m)
		default:
			s.logger.Info("SMF: PFCP receiver: unhandled message type",
				"nf", "SMF", "interface", "N4", "direction", "IN",
				"type", msg.MessageTypeName(), "remote", raddr)
		}
	}
}

// handleSessionReport consumes an inbound Session Report Request via the
// pure consumeSessionReport seam, then marshals and sends the Session Report
// Response back to raddr on the receiver socket. Never panics: any parse
// anomaly is logged and answered best-effort. Ref: TS 29.244 §7.5.5, §7.5.9.
func (s *Server) handleSessionReport(ctx context.Context, conn *net.UDPConn, raddr *net.UDPAddr, req *pfcpmsg.SessionReportRequest) {
	cause, _ := s.consumeSessionReport(ctx, req)

	resp := pfcpmsg.NewSessionReportResponse(
		0, 0, req.SEID(), req.Sequence(), 0,
		pfcpie.NewCause(cause),
	)

	b := make([]byte, resp.MarshalLen())
	if err := resp.MarshalTo(b); err != nil {
		s.logger.Error("SMF: PFCP Session Report Response marshal",
			"nf", "SMF", "interface", "N4", "direction", "OUT",
			"error", fmt.Errorf("smf: usage report: %w", err), "seid", req.SEID())
		return
	}
	if _, err := conn.WriteToUDP(b, raddr); err != nil {
		s.logger.Warn("SMF: PFCP Session Report Response send failed",
			"nf", "SMF", "interface", "N4", "direction", "OUT",
			"error", fmt.Errorf("smf: usage report: %w", err), "seid", req.SEID(), "remote", raddr)
	}
}

// consumeSessionReport is the testable production seam: it looks up the
// session by CP F-SEID, parses every Usage Report IE (URR ID, UR-SEQN,
// trigger, volume/duration measurement), logs it, and decides the PFCP Cause
// to answer with. No UDP I/O happens here, so godog steps can call it
// in-process. Returns the last UsageSummary parsed (the feature scenarios
// exercise one Usage Report per request; multiple reports are each logged
// individually). Ref: TS 29.244 §5.2.2.4, §7.5.5, §7.5.8.
func (s *Server) consumeSessionReport(ctx context.Context, req *pfcpmsg.SessionReportRequest) (uint8, UsageSummary) {
	seid := req.SEID()
	logger := logging.NewProcedureLogger(ctx, s.logger, "UsageReporting")

	sess := s.sessionBySEID(seid)
	if sess == nil {
		logger.Warn("PFCP Session Report: session not found",
			"nf", "SMF", "interface", "N4", "direction", "IN",
			"spec_ref", "TS 29.244 §5.2.2.4",
			"seid", seid, "result", "REJECT", "cause", "SessionContextNotFound")
		return pfcpie.CauseSessionContextNotFound, UsageSummary{SEID: seid}
	}

	var summary UsageSummary
	summary.SEID = seid

	for _, ur := range req.UsageReport {
		summary = parseUsageReport(seid, ur)

		if summary.URRID != usageReportingURRID {
			summary.KnownURR = false
			logger.Warn("PFCP Session Report: unknown URR ID",
				"nf", "SMF", "interface", "N4", "direction", "IN",
				"spec_ref", "TS 29.244 §7.5.9",
				"seid", seid, "urr_id", summary.URRID)
		} else {
			summary.KnownURR = true
		}

		logger.Info("PFCP Usage Report consumed",
			"nf", "SMF", "interface", "N4", "direction", "IN",
			"spec_ref", "TS 29.244 §5.2.2.4",
			"seid", seid, "urr_id", summary.URRID, "ur_seqn", summary.URSeqn,
			"trigger", summary.Trigger,
			"total_volume", summary.TotalVolume, "ul_volume", summary.ULVolume, "dl_volume", summary.DLVolume,
			"duration_s", summary.DurationSeconds, "result", "OK")

		metrics.ProcedureTotal.WithLabelValues("SMF", "UsageReporting", "OK").Inc()

		// Charging integration point (out of scope for UPF-001): this is
		// where a downstream Nchf_ConvergedCharging usage report (TS 32.290 /
		// TS 32.255) would be triggered from the consumed volume/duration.
	}

	return pfcpie.CauseRequestAccepted, summary
}

// parseUsageReport decodes a single Usage Report IE (TS 29.244 §7.5.8) into a
// UsageSummary. Never panics on malformed/partial input — missing child IEs
// simply leave the corresponding field at its zero value.
func parseUsageReport(seid uint64, ur *pfcpie.IE) UsageSummary {
	summary := UsageSummary{SEID: seid, Trigger: usageReportTriggerUnknown}

	if v, err := ur.URRID(); err == nil {
		summary.URRID = v
	}

	// UR-SEQN and Usage Report Trigger: go-pfcp's URSEQN()/HasVOLTH()/
	// HasPERIO() accessors have no case for the UsageReport group IE, so reach
	// the child IEs directly via UsageReport().
	if children, err := ur.UsageReport(); err == nil {
		for _, child := range children {
			switch child.Type {
			case pfcpie.URSEQN:
				if v, err := child.URSEQN(); err == nil {
					summary.URSeqn = v
				}
			case pfcpie.UsageReportTrigger:
				switch {
				case child.HasVOLTH():
					summary.Trigger = "VOLTH"
				case child.HasPERIO():
					summary.Trigger = "PERIO"
				}
			}
		}
	}

	if vm, err := ur.VolumeMeasurement(); err == nil {
		summary.TotalVolume = vm.TotalVolume
		summary.ULVolume = vm.UplinkVolume
		summary.DLVolume = vm.DownlinkVolume
	}

	if d, err := ur.DurationMeasurement(); err == nil {
		summary.DurationSeconds = d.Seconds()
	}

	return summary
}

// sessionBySEID scans the session table for a session whose CP F-SEID
// matches seid. A linear scan is acceptable for the MVP session counts; a
// dedicated SEID index can be added if this becomes a hot path.
// Ref: TS 29.244 §7.5.5 (the UPF addresses Session Report Requests by SEID).
func (s *Server) sessionBySEID(seid uint64) *Session {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	for _, sess := range s.sessions {
		if sess.SEID == seid {
			return sess
		}
	}
	return nil
}
