// Package types defines shared data types used across multiple 5GC NFs.
package types

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
	ID         string      `json:"id"`
	SUPI       string      `json:"supi"` // empty = operator default
	Precedence int         `json:"precedence"`
	Rules      []URSPRule  `json:"rules"`
}
