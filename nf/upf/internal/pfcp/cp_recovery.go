package pfcp

// cp_recovery.go — UPF-side detection of a restarted CP function (SMF).
//
// The UPF remembers the Recovery Time Stamp (RTS) each CP peer advertised in
// its last Association Setup Request / Heartbeat Request. When a later message
// from the same peer carries a *later* RTS, the CP function has restarted and
// has lost every PFCP session it owned, so the UPF deletes all sessions of that
// peer (otherwise they stay orphaned forever). An equal RTS keeps the sessions;
// an older RTS is a stale/reordered message and is ignored.
// Ref: TS 29.244 §6.2.6 (Heartbeat Procedure / restart detection), §7.4.4.1,
// TS 23.007 §19A (restoration procedures).

import (
	"net"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/pfcpx"
)

const specCPRestart = "TS 29.244 §6.2.6, §7.4.4.1"

// cpPeerKey identifies a CP function: its Node ID when known, else the
// source IP of the PFCP message.
func cpPeerKey(nodeID *pfcpie.IE, raddr *net.UDPAddr) string {
	if nodeID != nil {
		if v, err := nodeID.NodeID(); err == nil && v != "" {
			return v
		}
	}
	if raddr != nil {
		return raddr.IP.String()
	}
	return ""
}

// observeCPPeerRTS records the RTS advertised by a CP peer and, when it is
// later than the stored one, deletes every session owned by that peer. It
// returns the number of sessions purged.
func (s *Server) observeCPPeerRTS(peer string, rtsIE *pfcpie.IE, source string) int {
	if peer == "" || rtsIE == nil {
		return 0
	}
	rts, err := rtsIE.RecoveryTimeStamp()
	if err != nil {
		return 0
	}
	rts = rts.UTC().Truncate(time.Second)

	s.cpMu.Lock()
	old, known := s.cpPeerRTS[peer]
	if !known || rts.After(old) {
		s.cpPeerRTS[peer] = rts
	}
	s.cpMu.Unlock()

	switch {
	case !known:
		s.logger.Info("PFCP CP peer RTS baseline", "peer", peer, "rts", rts.Format(time.RFC3339),
			"source", source, "spec_ref", specCPRestart)
		return 0
	case rts.After(old):
		n := s.purgeCPSessions(peer)
		s.logger.Warn("PFCP CP peer restart detected, sessions deleted",
			"procedure", "PfcpNodeRecovery", "interface", "N4", "direction", "IN",
			"peer", peer, "old_rts", old.Format(time.RFC3339), "new_rts", rts.Format(time.RFC3339),
			"sessions_deleted", n, "source", source, "result", "OK", "spec_ref", specCPRestart)
		return n
	case rts.Before(old):
		s.logger.Warn("PFCP CP peer sent older RTS, ignored", "peer", peer,
			"old_rts", old.Format(time.RFC3339), "rts", rts.Format(time.RFC3339),
			"source", source, "spec_ref", specCPRestart)
	}
	return 0
}

// purgeCPSessions deletes every session owned by the CP peer.
func (s *Server) purgeCPSessions(peer string) int {
	s.sessions.mu.RLock()
	var seids []uint64
	for id, sess := range s.sessions.bySEID {
		if sess.CPNodeID == peer {
			seids = append(seids, id)
		}
	}
	s.sessions.mu.RUnlock()

	n := 0
	for _, id := range seids {
		s.sessions.mu.Lock()
		sess, ok := s.sessions.bySEID[id]
		if ok && sess.raCancel != nil {
			sess.raCancel()
		}
		s.sessions.mu.Unlock()
		if !ok {
			continue
		}
		sess.qos.Store(nil)
		s.sessions.delete(id)
		metrics.UPFPFCPSessionsActive.Dec()
		n++
	}
	return n
}

// learnCPAddr remembers which CP peer a source IP belongs to, so Heartbeat
// Requests (which carry no Node ID) can be attributed to it.
func (s *Server) learnCPAddr(raddr *net.UDPAddr, peer string) {
	if raddr == nil || peer == "" {
		return
	}
	s.cpMu.Lock()
	s.cpAddrPeer[raddr.IP.String()] = peer
	s.cpMu.Unlock()
}

// cpPeerForAddr returns the CP peer key for a source address.
func (s *Server) cpPeerForAddr(raddr *net.UDPAddr) string {
	s.cpMu.Lock()
	defer s.cpMu.Unlock()
	if p, ok := s.cpAddrPeer[raddr.IP.String()]; ok {
		return p
	}
	return raddr.IP.String()
}

// cpPeerFeatures is the CP Function Features a CP peer announced in its last
// Association Setup Request. Raw keeps every octet, including those beyond the
// bit table known to shared/pfcpx (extended octets); Names are the decoded
// known bits. Ref: TS 29.244 §8.2.58, §6.2.6.
type cpPeerFeatures struct {
	Raw   []byte
	Names []string
}

// recordCPFeatures stores (replacing any previous value) the CP Function
// Features of peer. A nil IE (conditional IE absent) clears the stored value.
// The payload is copied: go-pfcp IEs alias the reused receive buffer.
func (s *Server) recordCPFeatures(peer string, i *pfcpie.IE) cpPeerFeatures {
	var f cpPeerFeatures
	if i != nil {
		f.Raw = make([]byte, len(i.Payload))
		copy(f.Raw, i.Payload)
		f.Names = pfcpx.SetCPFeatures(i)
	}
	if peer != "" {
		s.cpMu.Lock()
		s.cpFeatures[peer] = f
		s.cpMu.Unlock()
	}
	return f
}

// cpPeerFeaturesFor returns the stored CP Function Features of peer.
func (s *Server) cpPeerFeaturesFor(peer string) cpPeerFeatures {
	s.cpMu.Lock()
	defer s.cpMu.Unlock()
	return s.cpFeatures[peer]
}
