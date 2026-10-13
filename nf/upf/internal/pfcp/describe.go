package pfcp

// Read-only deep-copy view of the PFCP SessionTable for the UPF admin
// endpoint (GET /admin/v1/n4-sessions, task MCP-012). This is an O&M read
// path, not a 3GPP procedure: it sends no PFCP message and never writes to the
// table. The data shown is the packet-forwarding-model state the SMF installed
// with PFCP Session Establishment / Modification.
//
// Design: docs/procedures/n4-session-inspection.md §4.3, §7.1, §7.2.
// Ref: TS 29.244 §5.2 (Packet Forwarding Model), §5.2.1A (PDR handling),
// §5.2.2 (URR handling), §5.2.5 (QER handling), §7.5.2.

import (
	"fmt"
	"net"
	"slices"
	"time"
)

// Textual values of the Gate Status (TS 29.244 §8.2.7) and Source Interface
// (TS 29.244 §8.2.2) IEs as rendered by Describe.
const (
	gateOpenText       = "OPEN"
	gateClosedText     = "CLOSED"
	srcInterfaceAccTxt = "ACCESS"
	srcInterfaceCorTxt = "CORE"
)

// DescribeFilter selects the sessions Describe returns. The zero value
// matches every session; set fields are AND-combined.
type DescribeFilter struct {
	// SEID, when non-zero, matches a session whose CP SEID or UP SEID equals it.
	SEID uint64
	// UEIP, when non-nil, matches a session by UE address: exact for IPv4
	// (TS 29.244 §8.2.62), inside the session's delegated /64 for IPv6
	// (TS 23.501 §5.8.2.2.2, same rule as the downlink fast path).
	UEIP net.IP
}

// SessionDescription is the JSON-serialisable deep copy of one PFCP session.
// It shares no memory with the live Session.
type SessionDescription struct {
	CPSEID  uint64           `json:"cp_seid"`
	UPSEID  uint64           `json:"up_seid"`
	UEIPv4  string           `json:"ue_ipv4,omitempty"`
	UEIPv6  string           `json:"ue_ipv6,omitempty"`
	DNN     string           `json:"dnn"`
	ULTEID  uint32           `json:"ul_teid"`
	DLTEID  uint32           `json:"dl_teid"`
	GNBN3IP string           `json:"gnb_n3_ip,omitempty"`
	SMFAddr string           `json:"smf_addr,omitempty"`
	PDRs    []PDRDescription `json:"pdrs"`
	QERs    []QERDescription `json:"qers"`
	URR     URRDescription   `json:"urr"`
}

// PDRDescription is the deep copy of one Packet Detection Rule (TS 29.244 §8.2.36).
type PDRDescription struct {
	PDRID           uint16   `json:"pdr_id"`
	SourceInterface string   `json:"source_interface"`
	Precedence      *uint32  `json:"precedence,omitempty"`
	QERIDs          []uint32 `json:"qer_ids"`
}

// QERDescription is the deep copy of one QoS Enforcement Rule
// (TS 29.244 §7.5.2.5, §8.2.7, §8.2.8, §8.2.89).
type QERDescription struct {
	QERID     uint32 `json:"qer_id"`
	QFI       *uint8 `json:"qfi,omitempty"`
	GateUL    string `json:"gate_ul"`
	GateDL    string `json:"gate_dl"`
	HasMBR    bool   `json:"has_mbr"`
	MBRULKbps uint64 `json:"mbr_ul_kbps"`
	MBRDLKbps uint64 `json:"mbr_dl_kbps"`
}

// URRDescription is the deep copy of the Usage Reporting Rule configuration
// and its cumulative counters (TS 29.244 §5.2.2, §7.5.2.4). When Installed is
// false every other field is zero.
type URRDescription struct {
	Installed             bool   `json:"installed"`
	URRID                 uint32 `json:"urr_id"`
	MeasureVolume         bool   `json:"measure_volume"`
	MeasureDuration       bool   `json:"measure_duration"`
	TriggerVOLTH          bool   `json:"trigger_volth"`
	TriggerPERIO          bool   `json:"trigger_perio"`
	VolumeThresholdBytes  uint64 `json:"volume_threshold_bytes"`
	MeasurementPeriodSecs uint64 `json:"measurement_period_secs"`
	ULVolumeBytes         uint64 `json:"ul_volume_bytes"`
	DLVolumeBytes         uint64 `json:"dl_volume_bytes"`
	ULPackets             uint64 `json:"ul_packets"`
	DLPackets             uint64 `json:"dl_packets"`
	URSeqn                uint32 `json:"ur_seqn"`
}

// Describe returns deep copies of the sessions matching f, sorted by UP SEID
// ascending. It never returns nil. The table lock is held only while copying
// (no sorting, encoding or I/O under the lock); URR counters are read with
// atomic loads so the datapath is never blocked. It does not use Snapshot():
// that returns live pointers whose fields would be read after unlock.
func (t *SessionTable) Describe(f DescribeFilter) []SessionDescription {
	out := make([]SessionDescription, 0, 4)
	t.mu.RLock()
	for _, s := range t.bySEID {
		if describeMatches(s, f) {
			out = append(out, describeSession(s))
		}
	}
	t.mu.RUnlock()

	slices.SortFunc(out, func(a, b SessionDescription) int {
		switch {
		case a.UPSEID < b.UPSEID:
			return -1
		case a.UPSEID > b.UPSEID:
			return 1
		}
		return 0
	})
	for i := range out {
		slices.SortFunc(out[i].PDRs, func(a, b PDRDescription) int { return int(a.PDRID) - int(b.PDRID) })
		slices.SortFunc(out[i].QERs, func(a, b QERDescription) int {
			switch {
			case a.QERID < b.QERID:
				return -1
			case a.QERID > b.QERID:
				return 1
			}
			return 0
		})
	}
	return out
}

// describeMatches applies the filter; the caller holds t.mu.RLock.
func describeMatches(s *Session, f DescribeFilter) bool {
	if f.SEID != 0 && s.CPSEID != f.SEID && s.UPSEID != f.SEID {
		return false
	}
	if f.UEIP == nil {
		return true
	}
	if v4 := f.UEIP.To4(); v4 != nil {
		want, ok := ueAddr(v4)
		if !ok || len(s.UEIP) == 0 {
			return false
		}
		have, ok := ueAddr(s.UEIP)
		return ok && have == want
	}
	prefix := ueV6Prefix(s.UEIPv6)
	return prefix != nil && prefix.Contains(f.UEIP)
}

// describeSession deep-copies one session; the caller holds t.mu.RLock. PDR and
// QER slices are returned unsorted (sorted by Describe after unlock).
func describeSession(s *Session) SessionDescription {
	d := SessionDescription{
		CPSEID: s.CPSEID,
		UPSEID: s.UPSEID,
		DNN:    s.DNN,
		ULTEID: s.ULTEID,
		DLTEID: s.DLTEID,
		PDRs:   make([]PDRDescription, 0, len(s.PDRs)),
		QERs:   make([]QERDescription, 0, len(s.QERs)),
	}
	if len(s.UEIP) > 0 {
		d.UEIPv4 = net.IP(append([]byte(nil), s.UEIP...)).String()
	}
	if len(s.UEIPv6) > 0 {
		d.UEIPv6 = net.IP(append([]byte(nil), s.UEIPv6...)).String()
	}
	if len(s.GNBIP) > 0 {
		d.GNBN3IP = net.IP(append([]byte(nil), s.GNBIP...)).String()
	}
	if s.SMFAddr != nil {
		d.SMFAddr = s.SMFAddr.String()
	}
	for _, p := range s.PDRs {
		pd := PDRDescription{
			PDRID:           p.PDRID,
			SourceInterface: sourceInterfaceText(p.SourceInterface),
			QERIDs:          append([]uint32{}, p.QERIDs...),
		}
		if p.Precedence != noPrecedence {
			v := p.Precedence
			pd.Precedence = &v
		}
		d.PDRs = append(d.PDRs, pd)
	}
	for _, q := range s.QERs {
		qd := QERDescription{
			QERID:     q.QERID,
			GateUL:    gateText(q.GateUL),
			GateDL:    gateText(q.GateDL),
			HasMBR:    q.HasMBR,
			MBRULKbps: q.MBRULKbps,
			MBRDLKbps: q.MBRDLKbps,
		}
		if q.HasQFI {
			v := q.QFI
			qd.QFI = &v
		}
		d.QERs = append(d.QERs, qd)
	}
	d.URR = describeURR(&s.URRState)
	return d
}

// describeURR copies the URR. Config fields are written once before the
// session is stored; counters are atomics; Installed is read under the URR's
// own mutex (order t.mu -> URRState.mu, same as nothing else holds them in
// the reverse order).
func describeURR(u *URRState) URRDescription {
	u.mu.Lock()
	installed := u.Installed
	u.mu.Unlock()
	if !installed {
		return URRDescription{}
	}
	return URRDescription{
		Installed:             true,
		URRID:                 u.URRID,
		MeasureVolume:         u.MeasureVolume,
		MeasureDuration:       u.MeasureDuration,
		TriggerVOLTH:          u.TriggerVOLTH,
		TriggerPERIO:          u.TriggerPERIO,
		VolumeThresholdBytes:  u.VolumeThreshold,
		MeasurementPeriodSecs: uint64(u.MeasurementPeriod / time.Second),
		ULVolumeBytes:         u.ULVolume.Load(),
		DLVolumeBytes:         u.DLVolume.Load(),
		ULPackets:             u.ULPackets.Load(),
		DLPackets:             u.DLPackets.Load(),
		URSeqn:                u.URSeqn.Load(),
	}
}

// gateText renders a Gate Status value; spare values count as CLOSED
// (TS 29.244 §8.2.7).
func gateText(g uint8) string {
	if g == gateOpen {
		return gateOpenText
	}
	return gateClosedText
}

// sourceInterfaceText renders the PDI Source Interface (TS 29.244 §8.2.2).
func sourceInterfaceText(v uint8) string {
	switch v {
	case srcInterfaceAccess:
		return srcInterfaceAccTxt
	case srcInterfaceCore:
		return srcInterfaceCorTxt
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)
}
