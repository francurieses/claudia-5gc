package pfcp

// N9 user plane of a home-routed PDU session (ROAM-002 phase 2).
//
// V-UPF: UL PDR (Source Access, F-TEID N3) -> UL FAR (Destination Core, Outer
// Header Creation to the H-UPF N9 F-TEID, installed by a later Session
// Modification); DL PDR (Source Core, F-TEID = N9 address + TEID) -> DL FAR
// (Destination Access, OHC to the gNB). H-UPF: UL PDR (Source Access, F-TEID on its
// N9 address) -> UL FAR Core without OHC (N6 TUN as today); DL FAR (Destination
// Access) carries the OHC to the V-UPF N9 F-TEID at establishment.
// Ref: TS 23.502 §4.3.2.2.2 steps 11-13a; TS 23.501 §4.2.4; TS 29.244 §5.2.1,
// §7.5.2.3, §7.5.4.3, §8.2.2 NOTE 1, §8.2.56.

import (
	"context"
	"net"
	"net/netip"

	"github.com/francurieses/claudia-5gc/shared/logging"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

// procHomeRoutedPduSession is the canonical procedure name of the N9 log lines.
const procHomeRoutedPduSession = "HomeRoutedPduSession"

// ohcPeer extracts a GTP-U/UDP/IPv4 Outer Header Creation from the children of
// a (Update) Forwarding Parameters IE; nil when absent or without an IPv4 address.
// The address is copied: go-pfcp aliases the server's UDP read buffer.
func ohcPeer(params []*pfcpie.IE) *GTPUPeer {
	for _, c := range params {
		if c.Type != pfcpie.OuterHeaderCreation {
			continue
		}
		ohc, err := c.OuterHeaderCreation()
		if err != nil || ohc.IPv4Address == nil {
			return nil
		}
		a, ok := netip.AddrFromSlice(append(net.IP(nil), ohc.IPv4Address...))
		if !ok {
			return nil
		}
		return &GTPUPeer{TEID: ohc.TEID, Addr: a.Unmap()}
	}
	return nil
}

// setupN9 derives the home-routed fields of sess from the Create PDR / Create
// FAR set (after setupDLBuffering has resolved DLFARID). A plain N3 session
// (no N9 DL F-TEID, no OHC on the UL FAR) is left untouched. Called once at
// establishment, before the session is published.
func setupN9(sess *Session, req *pfcpmsg.SessionEstablishmentRequest, pdrs []*PDRState, pdrFAR map[uint16]uint32) {
	for _, p := range pdrs {
		if p.SourceInterface != srcInterfaceAccess {
			continue
		}
		if far, ok := pdrFAR[p.PDRID]; ok {
			sess.ULFARID = far
			break
		}
	}
	sess.ULRelay = sess.N9TEID != 0
	for _, far := range req.CreateFAR {
		children, err := far.CreateFAR()
		if err != nil {
			continue
		}
		var farID uint32
		var peer *GTPUPeer
		for _, c := range children {
			switch c.Type {
			case pfcpie.FARID:
				farID, _ = c.FARID()
			case pfcpie.ForwardingParameters:
				if fp, err := c.ForwardingParameters(); err == nil {
					peer = ohcPeer(fp)
				}
			}
		}
		if peer == nil || farID == 0 || sess.ULFARID == sess.DLFARID {
			continue
		}
		switch farID {
		case sess.ULFARID:
			sess.ULRelay = true
			sess.SetULPeer(peer)
		case sess.DLFARID:
			// H-UPF: the V-UPF N9 tunnel is known at establishment (no step-19 update).
			sess.DLTEID = peer.TEID
			sess.GNBIP = net.IP(peer.Addr.AsSlice())
		}
	}
}

// updateULRelayFAR applies an Update FAR to the UL FAR of a relaying (V-UPF)
// session: FORW + Outer Header Creation installs the H-UPF N9 peer, an Apply Action
// without FORW clears it (UL is then dropped). The DL tunnel is never touched.
// Ref: TS 23.502 §4.3.2.2.2 step 13a; TS 29.244 §7.5.4.3.
func (s *Server) updateULRelayFAR(ctx context.Context, sess *Session, ufarIEs []*pfcpie.IE, haveAA bool, aa uint8) {
	lg := logging.NewProcedureLogger(ctx, s.logger, procHomeRoutedPduSession)
	if haveAA && aa&applyActionFORW == 0 {
		sess.SetULPeer(nil)
		lg.Info("N9 UL peer cleared", "interface", "N4", "direction", "IN",
			"seid", sess.UPSEID, "apply_action", aa, "spec_ref", "TS 29.244 §7.5.4.3")
		return
	}
	for _, c := range ufarIEs {
		if c.Type != pfcpie.UpdateForwardingParameters {
			continue
		}
		fp, err := c.UpdateForwardingParameters()
		if err != nil {
			continue
		}
		if peer := ohcPeer(fp); peer != nil {
			sess.SetULPeer(peer)
			lg.Info("N9 UL peer set", "interface", "N4", "direction", "IN",
				"seid", sess.UPSEID, "peer_ip", peer.Addr.String(), "peer_teid", peer.TEID,
				"spec_ref", "TS 23.502 §4.3.2.2.2 step 13a; TS 29.244 §8.2.56")
		}
	}
}
