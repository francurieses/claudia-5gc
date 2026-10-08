package ngap

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/ishidawataru/sctp"
)

// gnbHistoryMax is the maximum number of disconnected gNBs kept for the
// management view. Lab UX constant, not a 3GPP value.
const gnbHistoryMax = 32

// gnbHistoryRetention is how long a disconnected gNB stays listed. Lab UX
// constant, not a 3GPP timer.
const gnbHistoryRetention = 15 * time.Minute

// RAN node types reported in GlobalRANNode.Type.
const (
	RANNodeTypeGNB   = "gNB"
	RANNodeTypeNgENB = "ng-eNB"
	RANNodeTypeN3IWF = "N3IWF"
)

// GNBState is the lifecycle state of a gNB as seen by the AMF.
// Ref: TS 38.413 §8.7.1 (NG Setup), TS 38.412 §7 (SCTP association).
type GNBState string

// gNB lifecycle states.
const (
	// GNBStateSCTPUp: association is up, NG Setup not yet completed.
	GNBStateSCTPUp GNBState = "SCTP_UP"
	// GNBStateNGReady: NG Setup Response was sent successfully.
	GNBStateNGReady GNBState = "NG_READY"
	// GNBStateDisconnected: association closed; entry kept in the history.
	GNBStateDisconnected GNBState = "DISCONNECTED"
)

// Reasons an association ended, reported as disconnect_reason.
const (
	GNBDisconnectSCTPClosed  = "sctp_closed"
	GNBDisconnectReadError   = "read_error"
	GNBDisconnectAMFShutdown = "amf_shutdown"
)

// GlobalRANNode is the decoded Global RAN Node ID of an NG Setup Request.
// Ref: TS 38.413 §9.3.1.5 (Global RAN Node ID), §9.3.1.6 (Global gNB ID).
type GlobalRANNode struct {
	Type        string // gNB | ng-eNB | N3IWF ("" when unknown)
	MCC, MNC    string
	GNBID       uint32
	GNBIDBitLen uint8 // 22..32 for a gNB
}

// IDString renders "<hex>/<bits>" for logs, or "" when there is no gNB ID.
func (n GlobalRANNode) IDString() string {
	if n.Type != RANNodeTypeGNB || n.GNBIDBitLen == 0 {
		return ""
	}
	return fmt.Sprintf("%s/%d", n.hex(), n.GNBIDBitLen)
}

// hex renders the gNB ID zero-padded to its bit length.
func (n GlobalRANNode) hex() string {
	digits := (int(n.GNBIDBitLen) + 3) / 4
	return fmt.Sprintf("%0*x", digits, n.GNBID)
}

// gnbHistoryEntry is a disconnected gNB kept for the management view.
type gnbHistoryEntry struct {
	snap GNBSnapshot
}

// ---- JSON snapshot types (contract: docs/procedures/ng-setup-gnb-registry.md)

// PLMNJSON is a PLMN in the management API.
type PLMNJSON struct {
	MCC string `json:"mcc"`
	MNC string `json:"mnc"`
}

// RANNodeJSON is the Global RAN Node ID in the management API.
type RANNodeJSON struct {
	Type        string   `json:"type"`
	PLMN        PLMNJSON `json:"plmn"`
	GNBID       uint32   `json:"gnb_id"`
	GNBIDHex    string   `json:"gnb_id_hex"`
	GNBIDBitLen uint8    `json:"gnb_id_bit_length"`
}

// SCTPJSON is the SCTP peer of a gNB in the management API.
type SCTPJSON struct {
	RemoteAddrs []string `json:"remote_addrs"`
	RemotePort  int      `json:"remote_port"`
}

// SliceJSON is an S-NSSAI in the management API.
type SliceJSON struct {
	SST uint8  `json:"sst"`
	SD  string `json:"sd"`
}

// BroadcastPLMNJSON is a broadcast PLMN with its slices.
type BroadcastPLMNJSON struct {
	MCC    string      `json:"mcc"`
	MNC    string      `json:"mnc"`
	Slices []SliceJSON `json:"slices"`
}

// SupportedTAJSON is a supported tracking area of a gNB.
type SupportedTAJSON struct {
	TAC            uint32              `json:"tac"`
	BroadcastPLMNs []BroadcastPLMNJSON `json:"broadcast_plmns"`
}

// UECountsJSON counts the UEs associated with a gNB.
type UECountsJSON struct {
	Connected int `json:"connected"`
	Idle      int `json:"idle"`
}

// GNBSnapshot is the read-only view of one gNB served by
// GET /amf/v1/ran/gnbs.
type GNBSnapshot struct {
	ID               string            `json:"id"`
	AMFName          string            `json:"amf_name"`
	RANNode          RANNodeJSON       `json:"ran_node"`
	RANNodeName      string            `json:"ran_node_name"`
	SCTP             SCTPJSON          `json:"sctp"`
	State            GNBState          `json:"state"`
	ConnectedAt      time.Time         `json:"connected_at"`
	NGSetupAt        *time.Time        `json:"ng_setup_at,omitempty"`
	DisconnectedAt   *time.Time        `json:"disconnected_at,omitempty"`
	DisconnectReason string            `json:"disconnect_reason,omitempty"`
	SupportedTAs     []SupportedTAJSON `json:"supported_tas"`
	UEs              UECountsJSON      `json:"ues"`
	LastNGResetAt    *time.Time        `json:"last_ng_reset_at,omitempty"`
	NGResetCount     int               `json:"ng_reset_count"`
}

// clock returns the registry time, tolerating Server literals built in tests.
func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// N2ListenAddr returns the configured NGAP listen address.
func (s *Server) N2ListenAddr() string { return s.addr }

// remoteAddrParts extracts the peer IPs and port from an SCTP remote address
// (multi-homing aware), falling back to the textual form.
func remoteAddrParts(a net.Addr) ([]string, int) {
	if sa, ok := a.(*sctp.SCTPAddr); ok && sa != nil {
		ips := make([]string, 0, len(sa.IPAddrs))
		for _, ip := range sa.IPAddrs {
			ips = append(ips, ip.String())
		}
		return ips, sa.Port
	}
	host, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return []string{a.String()}, 0
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return []string{host}, port
}

// markGNBReady moves a gNB to NG_READY after a successful NG Setup Response and
// drops any history entry of the same Global gNB ID (reconnect → one row).
func (s *Server) markGNBReady(gnb *GNBContext) {
	now := s.clock()
	gnb.mu.Lock()
	gnb.State = GNBStateNGReady
	gnb.NGSetupAt = now
	node := gnb.RANNode
	gnb.mu.Unlock()

	if node.Type != RANNodeTypeGNB {
		return
	}
	s.mu.Lock()
	kept := s.gnbHistory[:0]
	for _, h := range s.gnbHistory {
		if h.snap.RANNode.Type == node.Type && h.snap.RANNode.GNBID == node.GNBID &&
			h.snap.RANNode.GNBIDBitLen == node.GNBIDBitLen &&
			h.snap.RANNode.PLMN == (PLMNJSON{MCC: node.MCC, MNC: node.MNC}) {
			continue
		}
		kept = append(kept, h)
	}
	s.gnbHistory = kept
	s.mu.Unlock()
}

// observeNGReset records an NG Reset from the gNB. Observe-only: no NG Reset
// Acknowledge is sent and the state does not change.
// Ref: TS 38.413 §8.7.4.
func (s *Server) observeNGReset(gnb *GNBContext) {
	gnb.mu.Lock()
	gnb.LastNGResetAt = s.clock()
	gnb.NGResetCount++
	name := gnb.Name
	gnb.mu.Unlock()
	s.logger.Warn("NG Reset received",
		"procedure", "NGReset",
		"interface", "N2",
		"direction", "IN",
		"spec_ref", "TS 38.413 §8.7.4",
		"gnb_name", name,
		"result", "FAILURE",
		"cause", "not implemented — no NG Reset Acknowledge sent",
	)
}

// recordGNBDisconnectLocked appends a DISCONNECTED snapshot to the history.
// The caller must hold s.mu for writing and must not hold gnb.mu.
func (s *Server) recordGNBDisconnectLocked(gnb *GNBContext, id, reason string) {
	now := s.clock()
	snap := s.snapshotLocked(gnb, id)
	snap.State = GNBStateDisconnected
	snap.DisconnectedAt = &now
	snap.DisconnectReason = reason
	snap.UEs = UECountsJSON{}
	s.pruneHistoryLocked(now)
	s.gnbHistory = append(s.gnbHistory, gnbHistoryEntry{snap: snap})
	if over := len(s.gnbHistory) - gnbHistoryMax; over > 0 {
		s.gnbHistory = append([]gnbHistoryEntry(nil), s.gnbHistory[over:]...)
	}
}

// pruneHistoryLocked drops history entries older than gnbHistoryRetention.
func (s *Server) pruneHistoryLocked(now time.Time) {
	kept := s.gnbHistory[:0]
	for _, h := range s.gnbHistory {
		if h.snap.DisconnectedAt != nil && now.Sub(*h.snap.DisconnectedAt) > gnbHistoryRetention {
			continue
		}
		kept = append(kept, h)
	}
	s.gnbHistory = kept
}

// snapshotLocked builds the snapshot of a live gNB. The caller holds s.mu
// (read or write). It never dereferences gnb.Conn.
func (s *Server) snapshotLocked(gnb *GNBContext, id string) GNBSnapshot {
	gnb.mu.Lock()
	defer gnb.mu.Unlock()

	snap := GNBSnapshot{
		ID:      id,
		AMFName: s.cfg.Name,
		RANNode: RANNodeJSON{
			Type:        gnb.RANNode.Type,
			PLMN:        PLMNJSON{MCC: gnb.RANNode.MCC, MNC: gnb.RANNode.MNC},
			GNBID:       gnb.RANNode.GNBID,
			GNBIDHex:    gnb.RANNode.hex(),
			GNBIDBitLen: gnb.RANNode.GNBIDBitLen,
		},
		RANNodeName: gnb.Name,
		SCTP: SCTPJSON{
			RemoteAddrs: append([]string{}, gnb.RemoteAddrs...),
			RemotePort:  gnb.RemotePort,
		},
		State:        gnb.State,
		ConnectedAt:  gnb.ConnectedAt,
		SupportedTAs: make([]SupportedTAJSON, 0, len(gnb.SupportedTAs)),
		UEs:          UECountsJSON{Connected: len(gnb.UEs), Idle: len(gnb.IdleUEs)},
		NGResetCount: gnb.NGResetCount,
	}
	if snap.State == "" {
		snap.State = GNBStateSCTPUp
	}
	if gnb.RANNode.Type != RANNodeTypeGNB {
		snap.RANNode.GNBIDHex = ""
	}
	if !gnb.NGSetupAt.IsZero() {
		t := gnb.NGSetupAt
		snap.NGSetupAt = &t
	}
	if !gnb.LastNGResetAt.IsZero() {
		t := gnb.LastNGResetAt
		snap.LastNGResetAt = &t
	}
	for _, ta := range gnb.SupportedTAs {
		tj := SupportedTAJSON{TAC: ta.TAC, BroadcastPLMNs: make([]BroadcastPLMNJSON, 0, len(ta.BroadcastPLMNs))}
		for _, p := range ta.BroadcastPLMNs {
			pj := BroadcastPLMNJSON{MCC: p.MCC, MNC: p.MNC, Slices: make([]SliceJSON, 0, len(p.SliceSupport))}
			for _, sl := range p.SliceSupport {
				pj.Slices = append(pj.Slices, SliceJSON{SST: sl.SST, SD: sl.SD})
			}
			tj.BroadcastPLMNs = append(tj.BroadcastPLMNs, pj)
		}
		snap.SupportedTAs = append(snap.SupportedTAs, tj)
	}
	return snap
}

// GNBSnapshots returns the live gNBs followed by recently disconnected ones.
// Order: NG_READY, SCTP_UP, DISCONNECTED; then by ID for stability.
func (s *Server) GNBSnapshots() []GNBSnapshot {
	s.mu.Lock()
	s.pruneHistoryLocked(s.clock())
	out := make([]GNBSnapshot, 0, len(s.gnbs)+len(s.gnbHistory))
	for id, gnb := range s.gnbs {
		out = append(out, s.snapshotLocked(gnb, id))
	}
	for _, h := range s.gnbHistory {
		out = append(out, h.snap)
	}
	s.mu.Unlock()

	rank := func(st GNBState) int {
		switch st {
		case GNBStateNGReady:
			return 0
		case GNBStateSCTPUp:
			return 1
		}
		return 2
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := rank(out[i].State), rank(out[j].State); ri != rj {
			return ri < rj
		}
		return out[i].ID < out[j].ID
	})
	return out
}
