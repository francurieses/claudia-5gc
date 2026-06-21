// Package types defines shared data types used across multiple 5GC NFs.
package types

import "fmt"

// ---- URSP Policy Types (TS 24.526 / TS 29.525) --------------------------

// URSPRule is a single UE Route Selection Policy rule.
// Ref: TS 24.526 §4.2
type URSPRule struct {
	Precedence          uint8                      `json:"precedence"`
	TrafficDescriptor   TrafficDescriptor          `json:"traffic_descriptor"`
	RouteSelDescriptors []RouteSelectionDescriptor `json:"route_sel_descriptors"`
}

// TrafficDescriptor specifies what traffic a URSP rule matches.
// Ref: TS 24.526 §5.2
type TrafficDescriptor struct {
	MatchAll         bool        `json:"match_all,omitempty"`
	DNNs             []string    `json:"dnns,omitempty"`
	FQDNs            []string    `json:"fqdns,omitempty"`
	IPv4Addrs        []string    `json:"ipv4_addrs,omitempty"`
	ProtocolIDs      []uint8     `json:"protocol_ids,omitempty"`
	PortRanges       []PortRange `json:"port_ranges,omitempty"`
	ConnCapabilities []uint8     `json:"conn_capabilities,omitempty"`
}

// PortRange is an inclusive destination port range in a Traffic Descriptor.
type PortRange struct {
	Low  uint16 `json:"low"`
	High uint16 `json:"high"`
}

// RouteSelectionDescriptor specifies how to route traffic matched by a URSP rule.
// Ref: TS 24.526 §5.3
type RouteSelectionDescriptor struct {
	Precedence     uint8   `json:"precedence"`
	SSCMode        *uint8  `json:"ssc_mode,omitempty"`
	SNSSAI         *SNSSAI `json:"snssai,omitempty"`
	DNN            *string `json:"dnn,omitempty"`
	PDUSessionType *uint8  `json:"pdu_session_type,omitempty"`
}

// SNSSAI is a Single Network Slice Selection Assistance Information value.
type SNSSAI struct {
	SST uint8  `json:"sst"`
	SD  string `json:"sd,omitempty"` // 6-hex-char string, e.g. "000001"
}

// PolicySubscription holds the URSP rule set for a subscriber (or the operator default).
type PolicySubscription struct {
	ID         string     `json:"id"`
	SUPI       string     `json:"supi"` // empty = operator default
	Precedence int        `json:"precedence"`
	Rules      []URSPRule `json:"rules"`
}

// ---- SM Policy Data (TS 29.519 §5.6.2 — UDR policy-data/{supi}/sm-data) --

// SmPolicyData is the SM Policy Data resource stored in the UDR under
// /nudr-dr/v2/policy-data/{supi}/sm-data. The PCF retrieves it over N36 to
// source per-subscriber/per-DNN authorized QoS at SmPolicyControl_Create.
// Ref: TS 29.519 §5.6.2.4 (SmPolicyData).
type SmPolicyData struct {
	SUPI string `json:"supi,omitempty"`
	// SmPolicySnssaiData is keyed by S-NSSAI string: "sst" or "sst-sd"
	// (e.g. "1" or "1-000001").
	SmPolicySnssaiData map[string]SmPolicySnssaiData `json:"smPolicySnssaiData,omitempty"`
}

// SmPolicySnssaiData groups the per-DNN policy data for one S-NSSAI.
// Ref: TS 29.519 §5.6.2.5 (SmPolicySnssaiData).
type SmPolicySnssaiData struct {
	SNSSAI SNSSAI `json:"snssai"`
	// SmPolicyDnnData is keyed by DNN.
	SmPolicyDnnData map[string]SmPolicyDnnData `json:"smPolicyDnnData,omitempty"`
}

// SmPolicyDnnData holds the authorized SM policy QoS for one DNN. This is a
// pragmatic subset of TS 29.519 §5.6.2.6 (SmPolicyDnnData) carrying the fields
// the PCF applies as the authorized default 5QI / ARP / Session-AMBR.
type SmPolicyDnnData struct {
	DNN          string `json:"dnn,omitempty"`
	FiveQI       int    `json:"5qi,omitempty"`
	ARPPriority  int    `json:"arpPriorityLevel,omitempty"`
	AMBRUplink   string `json:"ambrUplink,omitempty"`
	AMBRDownlink string `json:"ambrDownlink,omitempty"`
}

// SnssaiKey builds the SmPolicySnssaiData map key from an S-NSSAI: "sst" when
// no SD is set, otherwise "sst-sd" (e.g. "1-000001"). Shared by the UDR store
// and the PCF so writes and reads agree on the key format.
func SnssaiKey(sst uint8, sd string) string {
	if sd == "" {
		return fmt.Sprintf("%d", sst)
	}
	return fmt.Sprintf("%d-%s", sst, sd)
}
