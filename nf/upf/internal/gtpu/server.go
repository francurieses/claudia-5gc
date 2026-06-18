// Package gtpu implements GTP-U (N3 interface) packet processing for UPF.
// Uplink: decapsulates inner IP and writes to the DNN-specific TUN for N6 forwarding.
// Downlink: reads from each TUN and re-encapsulates for gNB.
// Ref: 3GPP TS 29.281
package gtpu

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// GTP-U header constants (TS 29.281 §5.1)
const (
	gtpuPort    = 2152
	gtpuMinHdr  = 8  // flags(1) + msgType(1) + length(2) + TEID(4)
	gtpuExtHdr  = 12 // + seqNum(2) + nPDUNum(1) + extHdrType(1) when E/S/PN flags set
	msgTypeTPDU = 0xFF
)

// TUNEntry associates a DNN name and its UE subnet CIDR with an open TUN device.
// The GTP-U server selects the correct TUN by matching the UE IP against each subnet.
// Ref: TS 23.501 §5.6.5, TS 29.244 §6.3.3.14
type TUNEntry struct {
	DNN     string
	Subnet  string // CIDR, e.g. "10.60.0.0/24"
	TunFile *os.File
}

// tunRoute is the pre-parsed form of TUNEntry used at runtime.
type tunRoute struct {
	dnn    string
	subnet *net.IPNet
	file   *os.File
}

// Config holds GTP-U server configuration.
type Config struct {
	Address string // "0.0.0.0:2152"
	N3IP    string // UPF N3 interface IP (e.g. "172.30.3.100")
}

// Server is the UPF GTP-U server (N3 interface).
type Server struct {
	cfg      Config
	logger   *slog.Logger
	conn     *net.UDPConn
	sessions *pfcp.SessionTable
	n3IP     net.IP
	tuns     []tunRoute // per-DNN TUN entries; empty = N6 disabled
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

	var tuns []tunRoute
	for _, e := range tunEntries {
		_, subnet, err := net.ParseCIDR(e.Subnet)
		if err != nil {
			return nil, fmt.Errorf("gtpu: DNN %q subnet %q: %w", e.DNN, e.Subnet, err)
		}
		tuns = append(tuns, tunRoute{dnn: e.DNN, subnet: subnet, file: e.TunFile})
	}

	return &Server{
		cfg:      cfg,
		logger:   logger.With("nf", "UPF", "component", "gtpu"),
		conn:     conn,
		sessions: sessions,
		n3IP:     net.ParseIP(cfg.N3IP).To4(),
		tuns:     tuns,
	}, nil
}

// tunRouteForIP returns the tunRoute whose subnet contains ip, or nil if none matches.
func (s *Server) tunRouteForIP(ip net.IP) *tunRoute {
	for i := range s.tuns {
		if s.tuns[i].subnet.Contains(ip) {
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

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return s.conn.Close()
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, raddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			s.logger.Error("GTP-U read error", "error", err)
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.handlePacket(raddr, pkt)
	}
}

func (s *Server) handlePacket(raddr *net.UDPAddr, pkt []byte) {
	if len(pkt) < gtpuMinHdr {
		return
	}

	flags := pkt[0]
	msgType := pkt[1]
	teid := binary.BigEndian.Uint32(pkt[4:8])

	if msgType != msgTypeTPDU {
		s.logger.Debug("GTP-U non-TPDU message", "type", msgType)
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
		s.logger.Info("GTP-U no session for TEID", "teid", teid)
		metrics.UPFPacketDropsTotal.WithLabelValues("no_session").Inc()
		return
	}

	s.logger.Info("GTP-U T-PDU received",
		"ulTEID", teid, "ueIP", sess.UEIP, "innerLen", len(inner))

	s.processInnerIP(sess, inner)
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
		s.logger.Debug("GTP-U no TUN for UE subnet, dropping", "src", srcIP, "dst", dstIP)
		metrics.UPFPacketDropsTotal.WithLabelValues("no_route").Inc()
		return
	}
	if _, err := rt.file.Write(inner); err != nil {
		s.logger.Error("GTP-U TUN write", "error", err, "src", srcIP, "dst", dstIP)
	} else {
		s.logger.Debug("GTP-U → TUN", "src", srcIP, "dst", dstIP, "len", len(inner))
		metrics.UPFGTPPacketsTotal.WithLabelValues("uplink").Inc()
		metrics.UPFGTPBytesTotal.WithLabelValues("uplink", rt.dnn).Add(float64(len(inner)))
	}
}

// startTUNReader reads IP packets from a DNN TUN (N6 downlink) and encapsulates
// them in GTP-U. Each DNN runs its own goroutine.
func (s *Server) startTUNReader(ctx context.Context, t tunRoute) {
	go func() {
		<-ctx.Done()
		t.file.Close()
	}()

	buf := make([]byte, 4096)
	s.logger.Info("GTP-U TUN reader started (N6 downlink)", "dnn", t.dnn)
	for {
		n, err := t.file.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Error("TUN read error", "dnn", t.dnn, "error", err)
			return
		}
		if n < 20 || buf[0]>>4 != 4 {
			continue // not IPv4
		}

		// buf[16:20] is dst IP — the UE IP after iptables conntrack DNAT
		dstIP := net.IP(buf[16:20])
		sess := s.sessions.GetByUEIP(dstIP)
		if sess == nil {
			s.logger.Debug("TUN: no session for dst", "dnn", t.dnn, "dst", dstIP)
			continue
		}
		if sess.DLTEID == 0 || sess.GNBIP == nil {
			s.logger.Warn("TUN: DL tunnel not ready", "dnn", t.dnn, "ueIP", dstIP)
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.sendGTPU(sess, pkt)
		metrics.UPFGTPPacketsTotal.WithLabelValues("downlink").Inc()
		metrics.UPFGTPBytesTotal.WithLabelValues("downlink", t.dnn).Add(float64(n))
		s.logger.Debug("TUN → GTP-U", "dnn", t.dnn, "dst", dstIP,
			"dlTEID", sess.DLTEID, "gnb", sess.GNBIP)
	}
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

// sendGTPU encapsulates innerIP in a GTP-U T-PDU and sends it to the gNB.
func (s *Server) sendGTPU(sess *pfcp.Session, innerIP []byte) {
	gnbAddr := &net.UDPAddr{IP: sess.GNBIP, Port: gtpuPort}

	hdr := make([]byte, gtpuMinHdr)
	hdr[0] = 0x30 // version=1, PT=1, E=0, S=0, PN=0
	hdr[1] = msgTypeTPDU
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(innerIP)))
	binary.BigEndian.PutUint32(hdr[4:8], sess.DLTEID)

	pkt := append(hdr, innerIP...)
	if _, err := s.conn.WriteToUDP(pkt, gnbAddr); err != nil {
		s.logger.Error("GTP-U send", "error", err, "gnb", gnbAddr)
		return
	}
	s.logger.Info("GTP-U DL sent", "dlTEID", sess.DLTEID, "gnbIP", sess.GNBIP, "len", len(innerIP))
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
