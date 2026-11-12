package pfcpx

import (
	"math/bits"

	"github.com/wmnsk/go-pfcp/ie"
)

// Feature is one bit of the UP Function Features (TS 29.244 §8.2.25) or CP
// Function Features (§8.2.58) IE.
//
// Octet, bit and name of every entry follow TS 29.244 V19.6.0 Table 8.2.25-1
// and Table 8.2.58-1. Octet is the zero-based payload index (0 is octet 5 for
// both IEs). Names of the bits go-pfcp v0.0.14 exposes as HasXXX() agree with
// this table (see TestFeaturesMatchGoPFCP). Desc is a short paraphrase.
type Feature struct {
	Name  string // abbreviation used by the spec
	Octet int    // zero-based payload octet index
	Mask  uint8  // bit mask inside the octet (bit 1 = 0x01)
	Desc  string // short description (Wireshark blurb)
}

// Set reports whether f is set in payload (UP or CP Function Features).
// Payloads shorter than the feature's octet read as "not set".
func (f Feature) Set(payload []byte) bool {
	return f.Octet < len(payload) && payload[f.Octet]&f.Mask != 0
}

// Apply returns payload with the feature bit set, extending it with zero
// octets as needed. The input slice is not modified.
func (f Feature) Apply(payload []byte) []byte {
	out := make([]byte, max(len(payload), f.Octet+1))
	copy(out, payload)
	out[f.Octet] |= f.Mask
	return out
}

// Bit returns the 1-based bit number (1..8) of the feature inside its octet.
func (f Feature) Bit() int { return bits.TrailingZeros8(f.Mask) + 1 }

// UPFeatures lists every UP Function Features bit, in octet/bit order.
var UPFeatures = []Feature{
	{Name: "BUCP", Octet: 0, Mask: 0x01, Desc: "Downlink Data Buffering in CP function"},
	{Name: "DDND", Octet: 0, Mask: 0x02, Desc: "Buffering parameter 'Downlink Data Notification Delay'"},
	{Name: "DLBD", Octet: 0, Mask: 0x04, Desc: "Buffering parameter 'DL Buffering Duration' in PFCP Session Report Response"},
	{Name: "TRST", Octet: 0, Mask: 0x08, Desc: "Traffic Steering"},
	{Name: "FTUP", Octet: 0, Mask: 0x10, Desc: "F-TEID allocation / release in the UP function"},
	{Name: "PFDM", Octet: 0, Mask: 0x20, Desc: "PFD Management procedure"},
	{Name: "HEEU", Octet: 0, Mask: 0x40, Desc: "Header Enrichment of Uplink traffic"},
	{Name: "TREU", Octet: 0, Mask: 0x80, Desc: "Traffic Redirection Enforcement in the UP function"},
	{Name: "EMPU", Octet: 1, Mask: 0x01, Desc: "Sending of End Marker packets"},
	{Name: "PDIU", Octet: 1, Mask: 0x02, Desc: "Support of PDI optimised signalling"},
	{Name: "UDBC", Octet: 1, Mask: 0x04, Desc: "Support of UL/DL Buffering Control"},
	{Name: "QUOAC", Octet: 1, Mask: 0x08, Desc: "The UP function supports being provisioned with the Quota Action to apply when reaching quotas"},
	{Name: "TRACE", Octet: 1, Mask: 0x10, Desc: "The UP function supports Trace"},
	{Name: "FRRT", Octet: 1, Mask: 0x20, Desc: "The UP function supports Framed Routing"},
	{Name: "PFDE", Octet: 1, Mask: 0x40, Desc: "The UP function supports a PFD Contents including a property with multiple values"},
	{Name: "EPFAR", Octet: 1, Mask: 0x80, Desc: "The UP function supports the Enhanced PFCP Association Release feature"},
	{Name: "DPDRA", Octet: 2, Mask: 0x01, Desc: "The UP function supports Deferred PDR Activation or Deactivation"},
	{Name: "ADPDP", Octet: 2, Mask: 0x02, Desc: "The UP function supports the Activation and Deactivation of Pre-defined PDRs"},
	{Name: "UEIP", Octet: 2, Mask: 0x04, Desc: "The UP function supports allocating UE IP addresses or prefixes"},
	{Name: "SSET", Octet: 2, Mask: 0x08, Desc: "UP function support of PFCP sessions successively controlled by different SMFs of a same SMF Set"},
	{Name: "MNOP", Octet: 2, Mask: 0x10, Desc: "UPF supports measurement of number of packets which is instructed with the flag 'Measurement of Number of Packets' in a URR"},
	{Name: "MTE", Octet: 2, Mask: 0x20, Desc: "UPF supports multiple instances of Traffic Endpoint IDs in a PDI"},
	{Name: "BUNDL", Octet: 2, Mask: 0x40, Desc: "PFCP messages bundling"},
	{Name: "GCOM", Octet: 2, Mask: 0x80, Desc: "UPF support of 5G VN Group Communication"},
	{Name: "MPAS", Octet: 3, Mask: 0x01, Desc: "UPF support for multiple PFCP associations to the SMFs in an SMF set"},
	{Name: "RTTL", Octet: 3, Mask: 0x02, Desc: "The UP function supports redundant transmission at transport layer"},
	{Name: "VTIME", Octet: 3, Mask: 0x04, Desc: "UPF support of quota validity time feature"},
	{Name: "NORP", Octet: 3, Mask: 0x08, Desc: "UP function support of Number of Reports"},
	{Name: "IPTV", Octet: 3, Mask: 0x10, Desc: "UPF support of IPTV service"},
	{Name: "IP6PL", Octet: 3, Mask: 0x20, Desc: "UPF supports UE IPv6 address(es) allocation with IPv6 prefix length other than default /64"},
	{Name: "TSN", Octet: 3, Mask: 0x40, Desc: "Integration of 5GS into a TSN data network is supported by the UPF"},
	{Name: "MPTCP", Octet: 3, Mask: 0x80, Desc: "UPF support of MPTCP Proxy functionality"},
	{Name: "ATSSS-LL", Octet: 4, Mask: 0x01, Desc: "UPF support of ATSSS-LL steering functionality"},
	{Name: "QFQM", Octet: 4, Mask: 0x02, Desc: "UPF support of per QoS flow per UE QoS monitoring for packet delay"},
	{Name: "GPQM", Octet: 4, Mask: 0x04, Desc: "UPF support of per GTP-U Path QoS monitoring"},
	{Name: "MT-EDT", Octet: 4, Mask: 0x08, Desc: "SGW-U support of reporting the size of DL Data Packets"},
	{Name: "CIOT", Octet: 4, Mask: 0x10, Desc: "UPF support of CIoT feature"},
	{Name: "ETHAR", Octet: 4, Mask: 0x20, Desc: "UPF support of Ethernet PDU Session Anchor Relocation"},
	{Name: "DDDS", Octet: 4, Mask: 0x40, Desc: "UPF support of reporting of the first buffered / discarded data for downlink"},
	{Name: "RDS", Octet: 4, Mask: 0x80, Desc: "UP function support of Reliable Data Service"},
	{Name: "RTTWP", Octet: 5, Mask: 0x01, Desc: "UPF support of RTT measurement towards the UE without PMF"},
	{Name: "QUASF", Octet: 5, Mask: 0x02, Desc: "The UP function supports being provisioned in a URR with an Exempted Application ID for Quota Action or an Exempted SDF Filter for Quota Action which is to be used when the quota is exhausted"},
	{Name: "NSPOC", Octet: 5, Mask: 0x04, Desc: "UP function supports notifying start of Pause of Charging via user plane"},
	{Name: "L2TP", Octet: 5, Mask: 0x08, Desc: "UP function supports L2TP"},
	{Name: "UPBER", Octet: 5, Mask: 0x10, Desc: "UP function supports the uplink packet buffering during EAS relocation"},
	{Name: "RESPS", Octet: 5, Mask: 0x20, Desc: "UP function supports Restoration of PFCP Session association"},
	{Name: "IPREP", Octet: 5, Mask: 0x40, Desc: "UP function supports IP Address and Port number replacement"},
	{Name: "DNSTS", Octet: 5, Mask: 0x80, Desc: "UP function support DNS Traffic Steering based on FQDN in the DNS Query message"},
	{Name: "DRQOS", Octet: 6, Mask: 0x01, Desc: "UP function supports Direct Reporting of QoS monitoring events to Local NEF or AF"},
	{Name: "MBSN4", Octet: 6, Mask: 0x02, Desc: "UPF supports sending MBS multicast session data to associated PDU sessions using 5GC individual delivery"},
	{Name: "PSUPRM", Octet: 6, Mask: 0x04, Desc: "UP function supports Per Slice UP Resource Management"},
	{Name: "EPPPI", Octet: 6, Mask: 0x08, Desc: "UP function supports Enhanced Provisioning of Paging Policy Indicator"},
	{Name: "RATP", Octet: 6, Mask: 0x10, Desc: "UP function supports Redirection Address Types set to Port, IPv4 address and Port, IPv6 address and Port, or IPv4 and IPv6 addresses and Port"},
	{Name: "UPIDP", Octet: 6, Mask: 0x20, Desc: "UP function supports User Plane Inactivity Detection and reporting per PDR"},
	{Name: "AFSFC", Octet: 6, Mask: 0x40, Desc: "UP function supports inserting metadata when Application Function influence on Service Function Chaining"},
	{Name: "MPQUIC-UDP", Octet: 6, Mask: 0x80, Desc: "UPF support of MPQUIC-UDP Proxy functionality"},
	{Name: "REDSM", Octet: 7, Mask: 0x01, Desc: "UP function supports the Redundant Steering Mode"},
	{Name: "DBDM", Octet: 7, Mask: 0x02, Desc: "The buffering parameters 'DL Buffering Duration' and 'DL Buffering Suggested Packet Count' in PFCP Session Modification Request are supported by the UP function"},
	{Name: "TSCTS", Octet: 7, Mask: 0x04, Desc: "AF requested support of Time Synchronization and/or Time Sensitive Communication is supported by the UP function"},
	{Name: "DRTSC", Octet: 7, Mask: 0x08, Desc: "UP function supports Direct Reporting of TSC management information events to TSN AF or TSCTSF"},
	{Name: "N6JEDB", Octet: 7, Mask: 0x10, Desc: "UPF support of N6 Jitter, DL Periodicity and UL Periodicity Measurement and Reporting, and End of Data Burst marking"},
	{Name: "QMCON", Octet: 7, Mask: 0x20, Desc: "UPF support of QoS monitoring of Congestion information"},
	{Name: "DETNET", Octet: 7, Mask: 0x40, Desc: "Deterministic Networking is supported by the UP function"},
	{Name: "EML4S", Octet: 7, Mask: 0x80, Desc: "UP function supports ECN Marking for L4S"},
	{Name: "PDUSM", Octet: 8, Mask: 0x01, Desc: "UP function supports PDU Set Marking"},
	{Name: "CN-TL", Octet: 8, Mask: 0x02, Desc: "UPF support of the TSN Talker and Listener (TL) functionality"},
	{Name: "QMDRM", Octet: 8, Mask: 0x04, Desc: "UPF support of QoS monitoring of Data Rate Measurement"},
	{Name: "EDBNC", Octet: 8, Mask: 0x08, Desc: "UP function supports Extended DL Buffering Notification Control"},
	{Name: "MT-SDT", Octet: 8, Mask: 0x10, Desc: "UPF support of reporting the size of DL Data Packets per QoS flow"},
	{Name: "UPSBIES", Octet: 8, Mask: 0x20, Desc: "UPF support of event subscription via Service Based Interface"},
	{Name: "UMN6IP", Octet: 8, Mask: 0x40, Desc: "UPF supports to allocate a mapped N6 IP address and perform IP replacement"},
	{Name: "UN6TU", Octet: 8, Mask: 0x80, Desc: "UPF supports N6 tunnelling using N6 routing information"},
	{Name: "MBSCH", Octet: 9, Mask: 0x01, Desc: "MB-UPF support of MBS charging"},
	{Name: "UN6DM", Octet: 9, Mask: 0x02, Desc: "UPF support of N6 Delay Measurement and Reporting"},
	{Name: "NATPUB", Octet: 9, Mask: 0x04, Desc: "UPF supports NAT information exposure of the public IP address and port for a PDU Session"},
	{Name: "USHPH", Octet: 9, Mask: 0x08, Desc: "UPF support of Handling of Payload Headers"},
	{Name: "MPQUIC-IP", Octet: 9, Mask: 0x10, Desc: "UPF support of MPQUIC-IP Proxy functionality"},
	{Name: "MPQUIC-E", Octet: 9, Mask: 0x20, Desc: "UPF support of MPQUIC-E Proxy functionality"},
	{Name: "DYNTR", Octet: 9, Mask: 0x40, Desc: "UPF support of dynamically changing traffic characteristics via the User Plane"},
	{Name: "MUXMF", Octet: 9, Mask: 0x80, Desc: "UPF support of traffic identification and differentiated QoS for multiplexed media flows"},
	{Name: "CONUDP", Octet: 10, Mask: 0x01, Desc: "UPF support of transferring media related information over N6 using connect-UDP"},
	{Name: "MOQ", Octet: 10, Mask: 0x02, Desc: "UP function supports MoQ relay functionality"},
	{Name: "ULM", Octet: 10, Mask: 0x04, Desc: "UE Level measurement"},
	{Name: "PSITLM", Octet: 10, Mask: 0x08, Desc: "UP function supports PDU Set Importance based transport level packet marking"},
	{Name: "UDPOPT", Octet: 10, Mask: 0x10, Desc: "UPF support of transferring media related information over N6 using UDP Option"},
	{Name: "QMABR", Octet: 10, Mask: 0x20, Desc: "UPF support of QoS monitoring of Available Bitrate measurement"},
	{Name: "PAPFD", Octet: 10, Mask: 0x40, Desc: "UP function supports partial acceptance of provisioning of the Application ID's PFDs"},
}

// CPFeatures lists every CP Function Features bit, in octet/bit order.
var CPFeatures = []Feature{
	{Name: "LOAD", Octet: 0, Mask: 0x01, Desc: "Load Control"},
	{Name: "OVRL", Octet: 0, Mask: 0x02, Desc: "Overload Control"},
	{Name: "EPFAR", Octet: 0, Mask: 0x04, Desc: "The CP function supports the Enhanced PFCP Association Release feature"},
	{Name: "SSET", Octet: 0, Mask: 0x08, Desc: "SMF support of PFCP sessions successively controlled by different SMFs of a same SMF Set"},
	{Name: "BUNDL", Octet: 0, Mask: 0x10, Desc: "PFCP messages bundling"},
	{Name: "MPAS", Octet: 0, Mask: 0x20, Desc: "SMF support for multiple PFCP associations from an SMF set to a single UPF"},
	{Name: "ARDR", Octet: 0, Mask: 0x40, Desc: "CP function supports Additional Usage Reports in the PFCP Session Deletion Response"},
	{Name: "UIAUR", Octet: 0, Mask: 0x80, Desc: "CP function supports the UE IP Address Usage Reporting feature"},
	{Name: "PSUCC", Octet: 1, Mask: 0x01, Desc: "CP function supports PFCP session establishment or modification with Partial Success"},
	{Name: "RPGUR", Octet: 1, Mask: 0x02, Desc: "CP function supports the Peer GTP-U Entity Restart Reporting"},
	{Name: "PAPFD", Octet: 1, Mask: 0x04, Desc: "CP function supports partial acceptance of provisioning of the Application ID's PFDs"},
}

// UPFeature returns the UP Function Features bit named name (case-sensitive).
func UPFeature(name string) (Feature, bool) { return lookup(UPFeatures, name) }

// CPFeature returns the CP Function Features bit named name (case-sensitive).
func CPFeature(name string) (Feature, bool) { return lookup(CPFeatures, name) }

func lookup(tab []Feature, name string) (Feature, bool) {
	for _, f := range tab {
		if f.Name == name {
			return f, true
		}
	}
	return Feature{}, false
}

// SetUPFeatures returns the names of all UP Function Features bits set in the
// IE payload, in table order. Bits not in UPFeatures (future releases) are
// ignored; use the raw payload to preserve them.
func SetUPFeatures(i *ie.IE) []string { return setNames(UPFeatures, i, ie.UPFunctionFeatures) }

// SetCPFeatures is the CP Function Features counterpart of SetUPFeatures.
func SetCPFeatures(i *ie.IE) []string { return setNames(CPFeatures, i, ie.CPFunctionFeatures) }

func setNames(tab []Feature, i *ie.IE, typ uint16) []string {
	if i == nil || i.Type != typ {
		return nil
	}
	var out []string
	for _, f := range tab {
		if f.Set(i.Payload) {
			out = append(out, f.Name)
		}
	}
	return out
}

// NewUPFunctionFeatures builds a UP Function Features IE from named bits,
// emitting as many octets as the highest set bit needs (minimum 2, as
// go-pfcp's ie.NewUPFunctionFeatures does). Unknown names are returned in the
// second result and ignored.
func NewUPFunctionFeatures(names ...string) (*ie.IE, []string) {
	return buildFeatures(ie.UPFunctionFeatures, UPFeatures, 2, names)
}

// NewCPFunctionFeatures builds a CP Function Features IE from named bits
// (minimum 1 octet, as go-pfcp). Unknown names are returned and ignored.
func NewCPFunctionFeatures(names ...string) (*ie.IE, []string) {
	return buildFeatures(ie.CPFunctionFeatures, CPFeatures, 1, names)
}

func buildFeatures(typ uint16, tab []Feature, minLen int, names []string) (*ie.IE, []string) {
	p := make([]byte, minLen)
	var unknown []string
	for _, n := range names {
		f, ok := lookup(tab, n)
		if !ok {
			unknown = append(unknown, n)
			continue
		}
		p = f.Apply(p)
	}
	return ie.New(typ, p), unknown
}
