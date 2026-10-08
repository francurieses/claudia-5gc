// Package gtpu implements GTP-U (N3 interface) packet processing for UPF.
// Uplink: decapsulates inner IP and writes to the DNN-specific TUN for N6 forwarding.
// Downlink: reads from each TUN and re-encapsulates for gNB.
// Ref: 3GPP TS 29.281
package gtpu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/l4csum"
	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
	"github.com/francurieses/claudia-5gc/nf/upf/internal/ra"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// GTP-U header constants (TS 29.281 §5.1)
const (
	gtpuPort    = 2152
	gtpuMinHdr  = 8  // flags(1) + msgType(1) + length(2) + TEID(4)
	gtpuExtHdr  = 12 // + seqNum(2) + nPDUNum(1) + extHdrType(1) when E/S/PN flags set
	msgTypeTPDU = 0xFF

	// extHdrTypePDUSessionContainer is the Next Extension Header Type value
	// for the PDU Session Container (TS 38.415 §5.5.2.1, TS 29.281 §5.2.1
	// Table 5.2.1-3). NG-U (N3) requires this on EVERY GTP-U packet, both
	// directions, so the receiving gNB/UPF can map the flow to a QoS Flow
	// (QFI) and, for DL, know which DRB to schedule it on.
	extHdrTypePDUSessionContainer = 0x85
	// pduSessionContainerDL is the PDU Type nibble for "DL PDU SESSION
	// INFORMATION" (TS 38.415 Table 5.5.2.1-2): upper nibble of the
	// container's first content octet, low nibble carries PPP/RQI/spare (all
	// 0 here — no paging policy, no reflective QoS).
	pduSessionContainerDL = 0x00
)

// TUNEntry associates a DNN name and its UE subnet CIDR with an open TUN device.
// The GTP-U server selects the correct TUN by matching the UE IP against each subnet.
// Ref: TS 23.501 §5.6.5, TS 29.244 §6.3.3.14
type TUNEntry struct {
	DNN     string
	Subnet  string // IPv4 UE pool CIDR, e.g. "10.60.0.0/24"
	Subnet6 string // IPv6 delegated base prefix CIDR, e.g. "2001:db8:60::/56" (empty = IPv4-only DNN)
	TunFile *os.File
}

// tunRoute is the pre-parsed form of TUNEntry used at runtime.
type tunRoute struct {
	dnn     string
	subnet  *net.IPNet
	subnet6 *net.IPNet // nil for IPv4-only DNNs
	file    *os.File

	// Pre-resolved Prometheus children: resolving WithLabelValues per packet
	// hashes the label set on the hot path.
	ulPkts, ulBytes, dlPkts, dlBytes prometheus.Counter
}

// Config holds GTP-U server configuration.
type Config struct {
	Address string // "0.0.0.0:2152"
	N3IP    string // UPF N3 interface IP (e.g. "172.30.3.100")

	// SocketBufferBytes sizes the GTP-U UDP socket buffers (0 = kernel default).
	SocketBufferBytes int

	// L4ChecksumRepair enables recomputing a wrong TCP/UDP checksum on
	// downlink packets read from the TUN (UPF-003; config n6.l4_checksum_repair).
	L4ChecksumRepair bool
}

// Server is the UPF GTP-U server (N3 interface).
type Server struct {
	cfg      Config
	logger   *slog.Logger
	conn     *net.UDPConn
	sessions *pfcp.SessionTable
	n3IP     net.IP
	tuns     []tunRoute // per-DNN TUN entries; empty = N6 disabled

	// debug is true when the logger emits DEBUG records. Per-packet logging
	// is guarded by it so the disabled case costs neither a record nor the
	// boxing of the log arguments.
	debug bool
	// drop* are the pre-resolved fivegc_upf_packet_drops_total children.
	dropNoSession, dropNoRoute, dropTunWrite, dropSend, dropDLNoSession, dropDLNotReady prometheus.Counter
	// dropQER holds the QoS enforcement drop counters, indexed by
	// pfcp.DropReason (qer_gate_closed, qer_mbr_exceeded).
	dropQER [pfcp.NumDropReasons]prometheus.Counter
	// limiter rate-limits event-driven INFO/WARN logs that a packet flood
	// would otherwise repeat per packet (one record per key per interval).
	limiter logLimiter

	// pfcpSrv is used only to trigger an immediate solicited Router
	// Advertisement (TS 23.501 §5.8.2.2.2, RFC 4861 §6.2.6) when a Router
	// Solicitation is decapsulated from the uplink. Nil disables that path
	// without affecting normal GTP-U forwarding. Wired at startup via
	// SetPFCPServer — the seam between the N3 (GTP-U) and N4 (PFCP)
	// packages so pfcp need not import gtpu.
	pfcpSrv *pfcp.Server

	// onL4Repair, when non-nil, is invoked once per repaired downlink packet
	// (proto "tcp"|"udp", ipver "v4"|"v6"); lets observability attach a counter.
	onL4Repair func(proto, ipver string)
}

// SetL4RepairHook registers a callback invoked for every downlink packet whose
// L4 checksum was repaired. Call before Start; nil disables it.
func (s *Server) SetL4RepairHook(f func(proto, ipver string)) {
	s.onL4Repair = f
}

// repairDownlinkChecksum verifies/repairs the TCP/UDP checksum of a downlink
// IP packet in place when enabled. A T-PDU must reach the UE with a valid L4
// checksum, but a userspace-proxied TUN host (Docker Desktop for macOS) may hand
// over segments with a complete but incorrect checksum. Only the TUN reader path calls this; UPF-built
// packets (ICMP replies, Router Advertisements) already carry correct sums.
// Ref: RFC 1071, RFC 793 §3.1, RFC 768, RFC 8200 §8.1, TS 29.281 §5.
func (s *Server) repairDownlinkChecksum(pkt []byte, dst net.IP, dnn string) {
	if !s.cfg.L4ChecksumRepair {
		return
	}
	res, ok := l4csum.Repair(pkt)
	if !ok {
		return
	}
	s.logger.Debug("downlink L4 checksum repaired",
		"procedure", "DownlinkChecksum",
		"interface", "N6",
		"direction", "IN",
		"spec_ref", "RFC 1071; RFC 793 §3.1; RFC 768; RFC 8200 §8.1",
		"proto", res.Proto, "ip", res.IP, "dst", dst, "dnn", dnn,
		"src", srcIP(pkt), "old_cksum", int(res.Old), "new_cksum", int(res.New))
	if s.onL4Repair != nil {
		s.onL4Repair(res.Proto, res.IP)
	}
}

// New creates a GTP-U server with per-DNN TUN entries for N6 forwarding.
// tunEntries may be empty when N6 forwarding is disabled.
func New(cfg Config, logger *slog.Logger, sessions *pfcp.SessionTable, tunEntries []TUNEntry) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("gtpu: resolve address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("gtpu: listen: %w", err)
	}

	rcvBuf, sndBuf, err := setSocketBuffers(conn, cfg.SocketBufferBytes)
	if err != nil {
		logger.Warn("GTP-U socket buffer sizing failed", "error", err)
	} else if cfg.SocketBufferBytes > 0 {
		logger.Info("GTP-U socket buffers", "requested", cfg.SocketBufferBytes, "rcvbuf", rcvBuf, "sndbuf", sndBuf)
	}

	var tuns []tunRoute
	for _, e := range tunEntries {
		_, subnet, err := net.ParseCIDR(e.Subnet)
		if err != nil {
			return nil, fmt.Errorf("gtpu: DNN %q subnet %q: %w", e.DNN, e.Subnet, err)
		}
		rt := tunRoute{dnn: e.DNN, subnet: subnet, file: e.TunFile}
		rt.resolveCounters()
		if e.Subnet6 != "" {
			_, subnet6, err := net.ParseCIDR(e.Subnet6)
			if err != nil {
				return nil, fmt.Errorf("gtpu: DNN %q IPv6 subnet %q: %w", e.DNN, e.Subnet6, err)
			}
			rt.subnet6 = subnet6
		}
		tuns = append(tuns, rt)
	}

	srv := &Server{
		cfg:      cfg,
		logger:   logger.With("nf", "UPF", "component", "gtpu"),
		conn:     conn,
		sessions: sessions,
		n3IP:     net.ParseIP(cfg.N3IP).To4(),
		tuns:     tuns,
	}
	srv.initCounters()
	return srv, nil
}

// resolveCounters pre-resolves the per-DNN Prometheus children.
func (r *tunRoute) resolveCounters() {
	r.ulPkts = metrics.UPFGTPPacketsTotal.WithLabelValues("uplink")
	r.dlPkts = metrics.UPFGTPPacketsTotal.WithLabelValues("downlink")
	r.ulBytes = metrics.UPFGTPBytesTotal.WithLabelValues("uplink", r.dnn)
	r.dlBytes = metrics.UPFGTPBytesTotal.WithLabelValues("downlink", r.dnn)
}

// initCounters pre-resolves the drop-reason children and caches whether the
// logger emits DEBUG, so the datapath does no label lookup or log work per packet.
func (s *Server) initCounters() {
	s.debug = s.logger.Enabled(context.Background(), slog.LevelDebug)
	s.dropNoSession = metrics.UPFPacketDropsTotal.WithLabelValues("no_session")
	s.dropNoRoute = metrics.UPFPacketDropsTotal.WithLabelValues("no_route")
	s.dropTunWrite = metrics.UPFPacketDropsTotal.WithLabelValues("tun_write_error")
	s.dropSend = metrics.UPFPacketDropsTotal.WithLabelValues("gtpu_send_error")
	s.dropDLNoSession = metrics.UPFPacketDropsTotal.WithLabelValues("dl_no_session")
	s.dropDLNotReady = metrics.UPFPacketDropsTotal.WithLabelValues("dl_tunnel_not_ready")
	for r := pfcp.DropGateClosed; r < pfcp.NumDropReasons; r++ {
		s.dropQER[r] = metrics.UPFPacketDropsTotal.WithLabelValues(r.String())
	}
}

// logLimitInterval bounds how often an event-driven datapath log repeats for
// the same key (e.g. a TEID with no session under a packet flood).
const logLimitInterval = 10 * time.Second

// logLimiter allows one log record per key per logLimitInterval.
type logLimiter struct{ last sync.Map } // key -> time.Time

func (l *logLimiter) allow(key any) bool {
	now := time.Now()
	if v, ok := l.last.Load(key); ok && now.Sub(v.(time.Time)) < logLimitInterval {
		return false
	}
	l.last.Store(key, now)
	return true
}

// qosDrop counts a packet refused by QoS enforcement and emits the
// rate-limited (1 per 10 s per SEID and direction) DEBUG event log. It never
// logs at INFO and never per packet unguarded.
// Ref: TS 29.244 §5.4.3 (gating), §5.4.4 (MBR), TS 23.501 §5.7.1.8.
func (s *Server) qosDrop(sess *pfcp.Session, reason pfcp.DropReason, uplink bool) {
	s.dropQER[reason].Inc()
	if !s.debug {
		return
	}
	dir := "DL"
	if uplink {
		dir = "UL"
	}
	if s.limiter.allow(qosLogKey{seid: sess.UPSEID, uplink: uplink}) {
		specRef := specQERMBR
		if reason == pfcp.DropGateClosed {
			specRef = specQERGate
		}
		s.logger.Debug("QER policing drop (repeats suppressed 10s)",
			"procedure", "AmbrEnforcement", "interface", "N3", "direction", dir,
			"spec_ref", specRef, "seid", sess.UPSEID, "reason", reason.String(),
			"result", "REJECT")
	}
}

// Spec references of the policing-drop log, chosen by drop reason without
// allocating. Ref: TS 29.244 §5.4.3 (gating), §5.4.4 (MBR).
const (
	specQERGate = "TS 29.244 §5.4.3"
	specQERMBR  = "TS 29.244 §5.4.4"
)

// qosLogKey keys the policing-drop log limiter.
type qosLogKey struct {
	seid   uint64
	uplink bool
}

// AdmitUL polices an uplink inner IP packet of n octets against the session's
// QERs (gate + MBR + Session-AMBR) and counts the drop. It is the hook
// handlePacket uses before the URR volume count, the TUN write and the
// ICMP-to-self reply. Zero allocations.
// Ref: TS 23.501 §5.7.1.8, TS 29.244 §5.4.3, §5.4.4.
func (s *Server) AdmitUL(sess *pfcp.Session, n int) bool {
	ok, reason := sess.AdmitUL(n)
	if !ok {
		s.qosDrop(sess, reason, true)
	}
	return ok
}

// AdmitDL polices a downlink inner IP packet of n octets read from the N6 TUN,
// counting the drop. UPF-originated downlink traffic (Router Advertisements,
// ICMP echo replies via sendGTPU) does not pass through it and is exempt.
func (s *Server) AdmitDL(sess *pfcp.Session, n int) bool {
	ok, reason := sess.AdmitDL(n)
	if !ok {
		s.qosDrop(sess, reason, false)
	}
	return ok
}

// SetPFCPServer wires the PFCP server so a decapsulated Router Solicitation
// can immediately trigger a unicast solicited Router Advertisement.
// Ref: TS 23.501 §5.8.2.2.2.
func (s *Server) SetPFCPServer(p *pfcp.Server) {
	s.pfcpSrv = p
}

// SendDownlink implements pfcp.RASender: it encapsulates ipPkt (a Router
// Advertisement built by the PFCP server) in GTP-U and sends it to sess's
// gNB, reusing the same downlink path as ordinary user-plane traffic.
// Ref: TS 23.501 §5.8.2.2.2.
func (s *Server) SendDownlink(sess *pfcp.Session, ipPkt []byte) {
	s.sendGTPU(sess, ipPkt)
}

// tunRouteForIP returns the tunRoute whose IPv4 subnet contains ip, or nil.
func (s *Server) tunRouteForIP(ip net.IP) *tunRoute {
	for i := range s.tuns {
		if s.tuns[i].subnet.Contains(ip) {
			return &s.tuns[i]
		}
	}
	return nil
}

// tunRouteForIPv6 returns the tunRoute whose delegated IPv6 prefix contains ip,
// or nil if none matches (or the matching DNN is IPv4-only).
func (s *Server) tunRouteForIPv6(ip net.IP) *tunRoute {
	for i := range s.tuns {
		if s.tuns[i].subnet6 != nil && s.tuns[i].subnet6.Contains(ip) {
			return &s.tuns[i]
		}
	}
	return nil
}

// Start runs the GTP-U uplink loop (N3 → TUN) until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("GTP-U server listening", "addr", s.cfg.Address, "n3ip", s.cfg.N3IP,
		"n6_tuns", len(s.tuns))

	for _, t := range s.tuns {
		go s.startTUNReader(ctx, t)
	}

	// A watcher closes the socket on shutdown, which unblocks the read below;
	// a per-packet SetReadDeadline would cost a syscall-sized timer reset per datagram.
	go func() {
		<-ctx.Done()
		s.conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, _, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Error("GTP-U read error", "error", err)
			continue
		}

		// handlePacket is synchronous and nothing it calls retains pkt (the RS
		// path copies the source address), so the receive buffer is reused.
		s.handlePacket(buf[:n])
	}
}

func (s *Server) handlePacket(pkt []byte) {
	if len(pkt) < gtpuMinHdr {
		return
	}

	flags := pkt[0]
	msgType := pkt[1]
	teid := binary.BigEndian.Uint32(pkt[4:8])

	if msgType != msgTypeTPDU {
		if s.debug {
			s.logger.Debug("GTP-U non-TPDU message", "type", msgType)
		}
		return
	}

	// Skip optional fields and extension headers (TS 29.281 §5.2).
	// When E|S|PN flags are set, a 4-byte block follows the mandatory header:
	// seqNum(2) | N-PDU(1) | nextExtHdrType(1). If nextExtHdrType != 0, one
	// or more extension headers follow; each starts with a 1-byte length in
	// 4-octet units (inclusive). 5G gNBs typically add a PDU Session Container
	// extension header (type 0x85, TS 38.415) which must be skipped.
	hdrLen := gtpuMinHdr
	if flags&0x07 != 0 { // E | S | PN bits
		if len(pkt) < gtpuExtHdr {
			return
		}
		hdrLen = gtpuExtHdr
		for pkt[hdrLen-1] != 0 {
			if len(pkt) <= hdrLen {
				return
			}
			extLen := int(pkt[hdrLen]) * 4
			if extLen < 4 || hdrLen+extLen > len(pkt) {
				return
			}
			hdrLen += extLen
		}
	}
	if len(pkt) <= hdrLen {
		return
	}
	inner := pkt[hdrLen:]

	sess := s.sessions.GetByULTEID(teid)
	if sess == nil {
		if s.limiter.allow(teid) {
			s.logger.Info("GTP-U no session for TEID (repeats suppressed 10s)", "teid", teid,
				"procedure", "GtpuForwarding", "interface", "N3", "direction", "IN",
				"spec_ref", "TS 29.281 §5.1", "result", "REJECT")
		}
		s.dropNoSession.Inc()
		return
	}

	if s.debug {
		s.logger.Debug("GTP-U T-PDU received",
			"procedure", "GtpuForwarding", "interface", "N3", "direction", "IN",
			"spec_ref", "TS 29.281 §5.1",
			"ulTEID", teid, "ueIP", sess.UEIP, "innerLen", len(inner))
	}

	// QoS enforcement (gating + MBR + Session-AMBR) comes first: a policed
	// packet is neither forwarded nor measured. Ref: TS 29.244 §5.4.3, §5.4.4.
	if !s.AdmitUL(sess, len(inner)) {
		return
	}

	// Uplink usage measurement (TS 29.244 §5.2.2.4, VOLUM method). Counts
	// every admitted uplink T-PDU regardless of downstream path (TUN-forwarded
	// or ICMP-to-self both originate on N3 as uplink traffic).
	sess.AddULVolume(len(inner))

	// Branch by IP version. IPv6 (TS 23.501 §5.8.2.2): RS → Router
	// Advertisement, echo-to-fe80::1 → inline reply, everything else → N6 TUN
	// forwarding (handleInnerIPv6). IPv4 keeps its original decap/route path.
	if len(inner) > 0 && inner[0]>>4 == 6 {
		s.handleInnerIPv6(sess, inner)
		return
	}

	s.processInnerIP(sess, inner)
}

// icmpv6TypeEchoRequest / icmpv6TypeEchoReply (RFC 4443 §4.1/§4.2) — the
// ping test's message types. Not Neighbor Discovery, so kept local to gtpu
// rather than in the ra package (which is scoped to RFC 4861 ND messages).
const (
	icmpv6TypeEchoRequest uint8 = 128
	icmpv6TypeEchoReply   uint8 = 129
)

// handleInnerIPv6 routes a decapsulated uplink IPv6 packet:
//   - ICMPv6 Router Solicitation (RFC 4861 §4.1) → immediate unicast Router
//     Advertisement (§6.2.6)
//   - ICMPv6 Echo Request to the RA's router address (fe80::1) → inline reply
//     (the IPv6 equivalent of the IPv4 echo-to-N3-IP fast path; works even when
//     N6 egress is not configured)
//   - everything else → write to the DNN-specific TUN for kernel N6 forwarding
//   - ip6tables MASQUERADE, mirroring processInnerIP for IPv4
func (s *Server) handleInnerIPv6(sess *pfcp.Session, inner []byte) {
	if ok, srcLL := ra.ParseRouterSolicitation(inner); ok {
		s.logger.Info("Router Solicitation received", "ueIPv6", sess.UEIPv6, "src", srcLL,
			"spec_ref", "RFC 4861 §4.1")
		if s.pfcpSrv != nil {
			s.pfcpSrv.TriggerSolicitedRA(context.Background(), sess, srcLL)
		}
		return
	}

	if len(inner) < 40 {
		return
	}
	srcIP := net.IP(inner[8:24])
	dstIP := net.IP(inner[24:40])

	// ICMPv6 Echo Request to our own router address: reply inline.
	if inner[6] == ra.NextHeaderICMPv6 && len(inner) >= 48 {
		icmp := inner[40:]
		if icmp[0] == icmpv6TypeEchoRequest && dstIP.Equal(ra.LinkLocalRouterAddr) {
			s.logger.Info("ICMPv6 Echo Request received (router address)",
				"ueIPv6", sess.UEIPv6, "src", srcIP,
				"id", binary.BigEndian.Uint16(icmp[4:6]), "seq", binary.BigEndian.Uint16(icmp[6:8]))
			if sess.DLTEID == 0 || sess.GNBIP == nil {
				s.logger.Warn("GTP-U: DL tunnel not ready, dropping ICMPv6 reply", "ueIPv6", sess.UEIPv6)
				return
			}
			s.sendGTPU(sess, s.buildICMPv6EchoReply(srcIP, dstIP, icmp))
			return
		}
	}

	// General IPv6 forwarding to N6: route to the TUN whose delegated prefix
	// contains the UE source address (selecting by source keeps the lookup O(1)
	// and needs no DNN string on the packet). The kernel then forwards out the
	// N6 bridge and ip6tables MASQUERADEs the source. Ref: TS 23.501 §5.8.2.2.
	rt := s.tunRouteForIPv6(srcIP)
	if rt == nil {
		if s.debug {
			s.logger.Debug("GTP-U no IPv6 TUN for UE prefix, dropping", "src", srcIP, "dst", dstIP,
				"ueIPv6", sess.UEIPv6)
		}
		s.dropNoRoute.Inc()
		return
	}
	if _, err := rt.file.Write(inner); err != nil {
		if s.limiter.allow("tunwrite6") {
			s.logger.Error("GTP-U IPv6 TUN write (repeats suppressed 10s)", "error", err, "src", srcIP, "dst", dstIP)
		}
		s.dropTunWrite.Inc()
	} else {
		if s.debug {
			s.logger.Debug("GTP-U → TUN (IPv6)", "src", srcIP, "dst", dstIP, "len", len(inner))
		}
		rt.ulPkts.Inc()
		rt.ulBytes.Add(float64(len(inner)))
	}
}

// buildICMPv6EchoReply crafts an ICMPv6 Echo Reply (RFC 4443 §4.2) for the
// given Echo Request, swapping source/destination and copying the
// identifier/sequence/data verbatim. Ref: RFC 4443 §2.3 (checksum).
func (s *Server) buildICMPv6EchoReply(reqSrc, reqDst net.IP, icmpReq []byte) []byte {
	reply := make([]byte, len(icmpReq))
	copy(reply, icmpReq)
	reply[0] = icmpv6TypeEchoReply
	reply[1] = 0 // code
	binary.BigEndian.PutUint16(reply[2:4], ra.ICMPv6Checksum(reqDst, reqSrc, reply))
	return ra.BuildIPv6Packet(reqDst, reqSrc, ra.NextHeaderICMPv6, ra.DefaultCurHopLimit, reply)
}

// processInnerIP routes the decapsulated inner IPv4 packet:
//   - ICMP echo to UPF N3 IP → inline reply (no TUN required)
//   - everything else → write to the DNN-specific TUN for kernel N6 forwarding
func (s *Server) processInnerIP(sess *pfcp.Session, inner []byte) {
	if len(inner) < 20 || inner[0]>>4 != 4 {
		return // not IPv4
	}

	dstIP := net.IP(inner[16:20])

	// ICMP to our own N3 IP: reply inline (preserves existing ping test)
	if dstIP.Equal(s.n3IP) {
		s.handleICMPToSelf(sess, inner)
		return
	}

	// Route to the TUN whose subnet contains the UE source IP.
	// Selecting by source (UE) IP rather than DNN name keeps the lookup O(1)
	// and avoids needing the DNN string in every PFCP session.
	srcIP := net.IP(inner[12:16])
	rt := s.tunRouteForIP(srcIP)
	if rt == nil {
		if s.debug {
			s.logger.Debug("GTP-U no TUN for UE subnet, dropping", "src", srcIP, "dst", dstIP)
		}
		s.dropNoRoute.Inc()
		return
	}
	if _, err := rt.file.Write(inner); err != nil {
		if s.limiter.allow("tunwrite4") {
			s.logger.Error("GTP-U TUN write (repeats suppressed 10s)", "error", err, "src", srcIP, "dst", dstIP)
		}
		s.dropTunWrite.Inc()
	} else {
		if s.debug {
			s.logger.Debug("GTP-U → TUN", "src", srcIP, "dst", dstIP, "len", len(inner))
		}
		rt.ulPkts.Inc()
		rt.ulBytes.Add(float64(len(inner)))
	}
}

// dlHeadroom is the room left in front of each TUN read for the DL GTP-U
// header (8 octets) and the NG-U extension block (8 octets), so the packet is
// encapsulated in place without a copy. Ref: TS 29.281 §5.1, §5.2.1.
const dlHeadroom = gtpuMinHdr + 8

// startTUNReader reads IP packets from a DNN TUN (N6 downlink) and encapsulates
// them in GTP-U. Each DNN runs its own goroutine.
func (s *Server) startTUNReader(ctx context.Context, t tunRoute) {
	go func() {
		<-ctx.Done()
		t.file.Close()
	}()

	buf := make([]byte, dlHeadroom+4096)
	s.logger.Info("GTP-U TUN reader started (N6 downlink)", "dnn", t.dnn)
	for {
		n, err := t.file.Read(buf[dlHeadroom:])
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Error("TUN read error", "dnn", t.dnn, "error", err)
			return
		}
		if n < 1 {
			continue
		}
		s.handleTUNPacket(&t, buf, n)
	}
}

// InjectDownlink feeds one downlink IP packet through exactly the path a packet
// read from the DNN's N6 TUN takes (session lookup, QoS admission, checksum
// repair, GTP-U encapsulation, send) and reports whether a datagram went to the
// gNB. It allocates and exists for tests and tools; the TUN reader calls
// handleTUNPacket directly. An unknown dnn returns false.
func (s *Server) InjectDownlink(dnn string, ipPkt []byte) bool {
	for i := range s.tuns {
		if s.tuns[i].dnn != dnn {
			continue
		}
		buf := make([]byte, dlHeadroom+len(ipPkt))
		copy(buf[dlHeadroom:], ipPkt)
		return s.handleTUNPacket(&s.tuns[i], buf, len(ipPkt))
	}
	return false
}

// handleTUNPacket processes one downlink IP packet of n octets that the TUN
// reader left at buf[dlHeadroom:dlHeadroom+n]: session lookup, QoS admission,
// checksum repair and in-place GTP-U encapsulation. It reports whether the
// packet was sent to the gNB.
func (s *Server) handleTUNPacket(t *tunRoute, buf []byte, n int) bool {
	pkt := buf[dlHeadroom : dlHeadroom+n]

	// Look up the session by the packet's destination UE address (after
	// conntrack un-DNAT): IPv4 dst at [16:20] matched exactly; IPv6 dst at
	// [24:40] matched by delegated /64 (the UE's SLAAC IID is its own).
	var sess *pfcp.Session
	var dstIP net.IP
	switch pkt[0] >> 4 {
	case 4:
		if n < 20 {
			return false
		}
		dstIP = net.IP(pkt[16:20])
		sess = s.sessions.GetByUEIP(dstIP)
	case 6:
		if n < 40 {
			return false
		}
		dstIP = net.IP(pkt[24:40])
		sess = s.sessions.GetByUEIPv6Prefix(dstIP)
	default:
		return false
	}
	if sess == nil {
		if s.debug {
			s.logger.Debug("TUN: no session for dst", "dnn", t.dnn, "dst", dstIP)
		}
		s.dropDLNoSession.Inc()
		return false
	}
	if sess.DLTEID == 0 || sess.GNBIP == nil {
		if s.limiter.allow(sess.DLTEID) {
			s.logger.Warn("TUN: DL tunnel not ready (repeats suppressed 10s)", "dnn", t.dnn, "ueIP", dstIP.String())
		}
		s.dropDLNotReady.Inc()
		return false
	}

	// QoS enforcement (gating + MBR + Session-AMBR) before any rewriting or
	// sending, so a policed packet costs nothing and is not measured by the URR
	// (AddDLVolume lives in sendFrame). Ref: TS 29.244 §5.4.3, §5.4.4.
	if !s.AdmitDL(sess, n) {
		return false
	}

	s.repairDownlinkChecksum(pkt, dstIP, t.dnn)
	putDLHeader(buf[:dlHeadroom], sess.DLTEID, sess.DLQFI(), n)
	if !s.sendFrame(sess, buf[:dlHeadroom+n], n) {
		return false
	}
	t.dlPkts.Inc()
	t.dlBytes.Add(float64(n))
	if s.debug {
		s.logger.Debug("TUN → GTP-U", "dnn", t.dnn, "dst", dstIP,
			"dlTEID", sess.DLTEID, "gnb", sess.GNBIP)
	}
	return true
}

// handleICMPToSelf replies to ICMP echo requests addressed to the UPF's N3 IP.
func (s *Server) handleICMPToSelf(sess *pfcp.Session, inner []byte) {
	proto := inner[9]
	if proto != 1 { // ICMP
		s.logger.Debug("GTP-U non-ICMP to UPF N3 IP", "proto", proto)
		return
	}

	ihl := int(inner[0]&0x0F) * 4
	if len(inner) < ihl+8 {
		return
	}
	icmp := inner[ihl:]
	if icmp[0] != 8 { // type 8 = Echo Request
		return
	}

	s.logger.Info("ICMP Echo Request received",
		"src", net.IP(inner[12:16]).String(),
		"dst", net.IP(inner[16:20]).String(),
		"id", binary.BigEndian.Uint16(icmp[4:6]),
		"seq", binary.BigEndian.Uint16(icmp[6:8]))

	if sess.DLTEID == 0 || sess.GNBIP == nil {
		s.logger.Warn("GTP-U: DL tunnel not ready, dropping ICMP reply", "ueIP", sess.UEIP)
		return
	}

	reply := s.buildICMPReply(inner, ihl, icmp)
	s.sendGTPU(sess, reply)
}

// buildICMPReply crafts an ICMP Echo Reply for the given Echo Request.
func (s *Server) buildICMPReply(ipPkt []byte, ihl int, icmpReq []byte) []byte {
	icmpLen := len(icmpReq)
	reply := make([]byte, ihl+icmpLen)

	copy(reply, ipPkt[:ihl])
	copy(reply[12:16], ipPkt[16:20]) // src = UPF N3 IP
	copy(reply[16:20], ipPkt[12:16]) // dst = UE IP
	reply[10], reply[11] = 0, 0
	cs := ipChecksum(reply[:ihl])
	reply[10], reply[11] = cs[0], cs[1]

	copy(reply[ihl:], icmpReq)
	reply[ihl] = 0   // Echo Reply
	reply[ihl+1] = 0 // code = 0
	reply[ihl+2], reply[ihl+3] = 0, 0
	cs = ipChecksum(reply[ihl:])
	reply[ihl+2], reply[ihl+3] = cs[0], cs[1]

	return reply
}

// buildDLPDUSessionContainer builds the mandatory NG-U extension block that
// must follow the 8-byte mandatory GTP-U header on every DL packet: seqNum(2,
// unused=0) | N-PDU(1, unused=0) | nextExtHdrType(1) | ext-len(1, 4-octet
// units) | PDU Session Container content(2) | next-ext-hdr-type(1, end=0).
// Ref: TS 29.281 §5.2.1, TS 38.415 §5.5.2.1.
//
// Without this, the packet is well-formed GTP-U (TS 29.281) but incomplete
// NG-U (TS 38.415) — reproduced against a live gNB 2026-09-03: every DL
// packet the UPF sent was logged and accepted at the UDP/GTP-U layer, then
// dropped by the gNB with "Incomplete PDU at NG-U interface: missing or
// invalid PDU session container", so no reply ever reached the UE despite the
// PDU session, PFCP rules, and UL path all being correct.
func buildDLPDUSessionContainer(qfi uint8) []byte {
	return []byte{
		0x00, 0x00, // Sequence Number (unused for T-PDU on N3, TS 29.281 §5.2.1 NOTE 1)
		0x00,                          // N-PDU Number (unused)
		extHdrTypePDUSessionContainer, // Next Extension Header Type
		0x01,                          // this extension header's length: 1 * 4 = 4 octets
		pduSessionContainerDL,         // PDU Type (DL, bits 8-5) | spare/PPP/RQI (bits 4-1) = 0
		qfi & 0x3F,                    // spare(2 bits)=0 | QFI (6 bits)
		0x00,                          // Next Extension Header Type = no more extensions
	}
}

// putDLHeader writes the 16-octet DL encapsulation into h: the mandatory GTP-U
// header (flags 0x34 = v1, PT=1, E=1; T-PDU; length; DL TEID) followed by the
// NG-U PDU Session Container block of buildDLPDUSessionContainer, byte for byte.
// Ref: TS 29.281 §5.1, §5.2.1; TS 38.415 §5.5.2.1.
func putDLHeader(h []byte, dlTEID uint32, qfi uint8, innerLen int) {
	h[0] = 0x34
	h[1] = msgTypeTPDU
	binary.BigEndian.PutUint16(h[2:4], uint16(8+innerLen)) // ext block (8) + inner
	binary.BigEndian.PutUint32(h[4:8], dlTEID)
	h[8], h[9], h[10] = 0x00, 0x00, 0x00 // seq (unused), N-PDU (unused)
	h[11] = extHdrTypePDUSessionContainer
	h[12] = 0x01 // ext length: 1 * 4 octets
	h[13] = pduSessionContainerDL
	h[14] = qfi & 0x3F
	h[15] = 0x00 // no further extension
}

// sendGTPU encapsulates innerIP in a GTP-U T-PDU and sends it to the gNB. It
// copies innerIP once; the TUN reader avoids that copy via sendFrame.
func (s *Server) sendGTPU(sess *pfcp.Session, innerIP []byte) {
	frame := make([]byte, dlHeadroom+len(innerIP))
	copy(frame[dlHeadroom:], innerIP)
	putDLHeader(frame, sess.DLTEID, sess.DLQFI(), len(innerIP))
	s.sendFrame(sess, frame, len(innerIP))
}

// sendFrame sends an already encapsulated DL frame (innerLen inner octets) to
// the session's gNB and accounts the DL usage volume. It reports success.
func (s *Server) sendFrame(sess *pfcp.Session, frame []byte, innerLen int) bool {
	gnb, ok := netip.AddrFromSlice(sess.GNBIP)
	if !ok {
		s.dropSend.Inc()
		return false
	}
	if _, err := s.conn.WriteToUDPAddrPort(frame, netip.AddrPortFrom(gnb.Unmap(), gtpuPort)); err != nil {
		if s.limiter.allow("send") {
			s.logger.Error("GTP-U send (repeats suppressed 10s)", "error", err, "gnb", sess.GNBIP.String())
		}
		s.dropSend.Inc()
		return false
	}

	// Downlink usage measurement (TS 29.244 §5.2.2.4, VOLUM method). This is
	// the single choke point for all DL sends (TUN reader + ICMP responder),
	// so counting here avoids double-counting session volume.
	sess.AddDLVolume(innerLen)

	if s.debug {
		s.logger.Debug("GTP-U DL sent",
			"procedure", "GtpuForwarding", "interface", "N3", "direction", "OUT",
			"spec_ref", "TS 29.281 §5.1",
			"dlTEID", sess.DLTEID, "gnbIP", sess.GNBIP, "qfi", sess.DLQFI(), "len", innerLen)
	}
	return true
}

// ipChecksum computes the one's complement checksum over data.
func ipChecksum(data []byte) [2]byte {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	s := uint16(^sum)
	return [2]byte{byte(s >> 8), byte(s)}
}

// srcIP returns the source address of an IPv4/IPv6 packet (aliasing pkt);
// only called on the rare repair path. Callers guarantee a validated header.
func srcIP(pkt []byte) net.IP {
	if pkt[0]>>4 == 6 {
		return net.IP(pkt[8:24])
	}
	return net.IP(pkt[12:16])
}
