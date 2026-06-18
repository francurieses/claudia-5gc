// Package policy implements URSP (UE Route Selection Policy) encoding for the PCF.
//
// URSP rules are encoded into a UE policy container per the 3GPP UE policy delivery
// service. The bytes produced here are the value of the "Payload container" IE of a
// DL NAS TRANSPORT message with payload container type = "UE policy container" (0x05).
// The AMF wraps them; it does not interpret them.
//
// Wire structure (verified against TS 24.501 Annex D + TS 24.526 §5.2 and the
// Wireshark NAS-5GS dissector / free5GC nas codec):
//
//	MANAGE UE POLICY COMMAND (UE policy delivery service message, TS 24.501 §D.5.1)
//	  PTI                              (1 octet)   — PCF-assigned, 0x80–0xFE
//	  message type = 0x01              (1 octet)   — MANAGE UE POLICY COMMAND
//	  UE policy section management list            — LV-E (2-octet length + value)
//	    └─ sublist (TS 24.501 §D.6.2):
//	         sublist length            (2 octets)  = 3 + len(instructions)
//	         PLMN ID                   (3 octets)  — packed BCD, TS 24.008 §10.5.1.13
//	         instruction(s):
//	           instruction length      (2 octets)  = 2 + len(UE policy parts)
//	           UPSC                     (2 octets)  — PCF-assigned section code
//	           UE policy part(s):
//	             UE policy part length  (2 octets)  = 1 + len(URSP rules)
//	             UE policy part type    (1 octet)   = 0x01 (URSP)
//	             URSP rules                          — TS 24.526 §5.2
//
//	URSP rule (TS 24.526 §5.2), repeated:
//	  URSP rule length                 (2 octets)  = bytes after this field
//	  precedence                       (1 octet)
//	  traffic descriptor length        (2 octets)
//	  traffic descriptor                           — one+ components, no per-component length
//	  route selection descriptor list length (2 octets)
//	  route selection descriptor list              — one+ RSDs
//
//	Route selection descriptor (TS 24.526 §5.3), repeated:
//	  RSD length                       (2 octets)  = bytes after this field
//	  precedence                       (1 octet)
//	  RSD contents length              (2 octets)
//	  RSD contents                                 — one+ components
//
// Spec references:
//   - TS 24.501 Annex D — UE policy delivery service, MANAGE UE POLICY COMMAND
//   - TS 24.526 §5.2     — URSP rule + traffic descriptor component types
//   - TS 24.526 §5.3     — route selection descriptor component types
package policy

import (
	"fmt"

	"github.com/francurieses/claudia-5gc/shared/types"
)

// UE policy delivery service message types (TS 24.501 §D.6.1).
const (
	updsMsgManageUEPolicyCommand byte = 0x01
)

// UE policy part type (TS 24.526 §5.1).
const uePolicyPartTypeURSP byte = 0x01

// DefaultPTI is the procedure transaction identity the PCF assigns to a
// network-requested UE policy management procedure. The valid range for the
// network is 0x80–0xFE (TS 24.501 §D.3). DefaultUPSC is the UE policy section code.
const (
	DefaultPTI  byte   = 0x80
	DefaultUPSC uint16 = 0x0001
)

// Traffic descriptor component type identifiers (TS 24.526 §5.2, Table 5.2.1).
// Each component is a 1-octet type identifier followed by a type-specific value
// field — there is no generic per-component length octet.
const (
	tdMatchAll       = 0x01 // no value
	tdIPv4RemoteAddr = 0x10 // 4-octet address + 4-octet mask
	tdIPv6RemoteAddr = 0x21 // 16-octet address + 1-octet prefix length
	tdProtocolID     = 0x30 // 1 octet (IPv4 protocol / IPv6 next header)
	tdSingleRemPort  = 0x50 // 2 octets
	tdRemotePortRng  = 0x51 // 2-octet low + 2-octet high
	tdConnCapability = 0x90 // 1-octet count + count octets
	tdDestFQDN       = 0x91 // 1-octet length + FQDN (RFC 1035 label format)
)

// Route selection descriptor component type identifiers (TS 24.526 §5.3, Table 5.3.1).
const (
	rsdSSCMode        = 0x01 // 1 octet (no length field)
	rsdSNSSAI         = 0x02 // 1-octet length + S-NSSAI value
	rsdDNN            = 0x04 // 1-octet length + DNN (APN label format)
	rsdPDUSessionType = 0x08 // 1 octet (no length field)
	rsdPreferredAcc   = 0x10 // 1 octet (no length field)
)

// EncodeURSPRules encodes URSP rules into a UE policy container, returned as the
// value bytes of the DL NAS TRANSPORT payload container (payload container
// type 0x05). The result is a complete MANAGE UE POLICY COMMAND message.
//
// plmn is the PLMN identity of the PCF (5 or 6 digits, e.g. "00101" or "001010").
// Returns nil when there are no rules to deliver.
func EncodeURSPRules(rules []types.URSPRule, plmn string) ([]byte, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	urspRules, err := encodeURSPRuleList(rules)
	if err != nil {
		return nil, fmt.Errorf("policy: encode URSP rules: %w", err)
	}

	// UE policy part: length(2) | type(1=URSP) | URSP rules.
	// The length covers the type octet plus the URSP rule bytes.
	part := appendUint16(nil, uint16(1+len(urspRules)))
	part = append(part, uePolicyPartTypeURSP)
	part = append(part, urspRules...)

	// Instruction: length(2) | UPSC(2) | UE policy part(s).
	// The length covers the UPSC plus the policy-part bytes.
	instruction := appendUint16(nil, uint16(2+len(part)))
	instruction = appendUint16(instruction, DefaultUPSC)
	instruction = append(instruction, part...)

	// Sublist: length(2) | PLMN(3) | instruction(s).
	// The length covers the 3 PLMN octets plus the instruction bytes.
	plmnBytes := encodePLMNID(plmn)
	sublistBody := append(append([]byte{}, plmnBytes[:]...), instruction...)
	sublist := appendUint16(nil, uint16(len(sublistBody)))
	sublist = append(sublist, sublistBody...)

	// MANAGE UE POLICY COMMAND: PTI(1) | msg type(1) |
	// UE policy section management list LV-E: length(2) | value(sublists).
	out := []byte{DefaultPTI, updsMsgManageUEPolicyCommand}
	out = appendUint16(out, uint16(len(sublist)))
	out = append(out, sublist...)
	return out, nil
}

// encodeURSPRuleList encodes the ordered URSP rule list per TS 24.526 §5.2.
func encodeURSPRuleList(rules []types.URSPRule) ([]byte, error) {
	var out []byte
	for _, r := range rules {
		td, err := encodeTrafficDescriptor(r.TrafficDescriptor)
		if err != nil {
			return nil, fmt.Errorf("rule precedence %d: %w", r.Precedence, err)
		}
		rsd, err := encodeRouteSelectionDescriptorList(r.RouteSelDescriptors)
		if err != nil {
			return nil, fmt.Errorf("rule precedence %d RSD: %w", r.Precedence, err)
		}

		// Rule body: precedence(1) | TD length(2) | TD | RSD list length(2) | RSD list.
		body := []byte{r.Precedence}
		body = appendUint16(body, uint16(len(td)))
		body = append(body, td...)
		body = appendUint16(body, uint16(len(rsd)))
		body = append(body, rsd...)

		// Prepend the URSP rule length (covers the whole body).
		out = appendUint16(out, uint16(len(body)))
		out = append(out, body...)
	}
	return out, nil
}

// encodeTrafficDescriptor encodes the traffic descriptor components (TS 24.526 §5.2).
// Components carry no generic length octet; each type has a fixed or self-describing
// value field. A traffic descriptor must contain at least one component, so an empty
// or DNN-only descriptor falls back to match-all (DNN is a route-selection component,
// not a traffic-descriptor component).
func encodeTrafficDescriptor(td types.TrafficDescriptor) ([]byte, error) {
	if td.MatchAll {
		return []byte{tdMatchAll}, nil
	}

	var out []byte

	for _, fqdn := range td.FQDNs {
		v := encodeAPNLabels(fqdn)
		if len(v) > 255 {
			return nil, fmt.Errorf("FQDN too long: %q", fqdn)
		}
		out = append(out, tdDestFQDN, byte(len(v)))
		out = append(out, v...)
	}

	for _, ipv4 := range td.IPv4Addrs {
		b, err := encodeIPv4Prefix(ipv4)
		if err != nil {
			return nil, err
		}
		out = append(out, tdIPv4RemoteAddr)
		out = append(out, b...) // 4-octet address + 4-octet mask
	}

	for _, proto := range td.ProtocolIDs {
		out = append(out, tdProtocolID, proto)
	}

	for _, pr := range td.PortRanges {
		out = append(out, tdRemotePortRng,
			byte(pr.Low>>8), byte(pr.Low),
			byte(pr.High>>8), byte(pr.High))
	}

	if len(td.ConnCapabilities) > 0 {
		out = append(out, tdConnCapability, byte(len(td.ConnCapabilities)))
		out = append(out, td.ConnCapabilities...)
	}

	if len(out) == 0 {
		// No encodable traffic-descriptor component (e.g. only DNNs were set).
		out = append(out, tdMatchAll)
	}
	return out, nil
}

// encodeRouteSelectionDescriptorList encodes an ordered RSD list (TS 24.526 §5.3).
func encodeRouteSelectionDescriptorList(rsds []types.RouteSelectionDescriptor) ([]byte, error) {
	var out []byte
	for _, rsd := range rsds {
		contents := encodeRSDContents(rsd)

		// RSD: length(2) | precedence(1) | contents length(2) | contents.
		// The RSD length covers everything after it (precedence + contents-len + contents).
		body := []byte{rsd.Precedence}
		body = appendUint16(body, uint16(len(contents)))
		body = append(body, contents...)

		out = appendUint16(out, uint16(len(body)))
		out = append(out, body...)
	}
	return out, nil
}

// encodeRSDContents encodes the components of one route selection descriptor.
func encodeRSDContents(rsd types.RouteSelectionDescriptor) []byte {
	var c []byte

	if rsd.SSCMode != nil {
		// SSC mode: type + 1-octet value (bits 3-1), no length octet.
		c = append(c, rsdSSCMode, *rsd.SSCMode&0x07)
	}

	if rsd.SNSSAI != nil {
		v := encodeSnssai(rsd.SNSSAI)
		c = append(c, rsdSNSSAI, byte(len(v)))
		c = append(c, v...)
	}

	if rsd.DNN != nil {
		v := encodeAPNLabels(*rsd.DNN)
		c = append(c, rsdDNN, byte(len(v)))
		c = append(c, v...)
	}

	if rsd.PDUSessionType != nil {
		// PDU session type: type + 1-octet value (bits 3-1), no length octet.
		c = append(c, rsdPDUSessionType, *rsd.PDUSessionType&0x07)
	}

	return c
}

// encodePLMNID encodes a PLMN string (5 or 6 digits) as 3 octets per TS 24.008 §10.5.1.13.
// Example: "00101" (MCC=001, MNC=01) → [0x00, 0xF1, 0x10].
func encodePLMNID(plmn string) [3]byte {
	if len(plmn) < 5 {
		return [3]byte{}
	}
	mcc := plmn[:3]
	mnc := plmn[3:]

	mccD1 := mcc[0] - '0'
	mccD2 := mcc[1] - '0'
	mccD3 := mcc[2] - '0'
	mncD1 := mnc[0] - '0'
	mncD2 := mnc[1] - '0'
	var mncD3 byte = 0xF // fill nibble for 2-digit MNC
	if len(mnc) >= 3 {
		mncD3 = mnc[2] - '0'
	}

	return [3]byte{
		(mccD2 << 4) | mccD1,
		(mncD3 << 4) | mccD3,
		(mncD2 << 4) | mncD1,
	}
}

// encodeAPNLabels encodes a DNN/FQDN string into the APN label format (TS 23.003 §9.1):
// each dot-separated label is prefixed by its length octet. "internet" → 08 "internet".
func encodeAPNLabels(s string) []byte {
	if s == "" {
		return []byte{0x00}
	}
	var out []byte
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			label := s[start:i]
			out = append(out, byte(len(label)))
			out = append(out, label...)
			start = i + 1
		}
	}
	return out
}

// encodeSnssai encodes an S-NSSAI value field: 1-octet SST [+ 3-octet SD] (TS 24.501 §9.11.2.8
// value part, without mapped HPLMN fields).
func encodeSnssai(s *types.SNSSAI) []byte {
	if s.SD == "" {
		return []byte{s.SST}
	}
	var sd [3]byte
	_, _ = fmt.Sscanf(s.SD, "%02x%02x%02x", &sd[0], &sd[1], &sd[2])
	return []byte{s.SST, sd[0], sd[1], sd[2]}
}

// encodeIPv4Prefix encodes a CIDR or plain IPv4 address as 4-octet address + 4-octet mask.
func encodeIPv4Prefix(cidr string) ([]byte, error) {
	var a, b, c, d, mask int
	if n, _ := fmt.Sscanf(cidr, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &mask); n == 5 {
		m := ^(uint32(0xFFFFFFFF) >> mask)
		return []byte{byte(a), byte(b), byte(c), byte(d),
			byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)}, nil
	}
	if n, _ := fmt.Sscanf(cidr, "%d.%d.%d.%d", &a, &b, &c, &d); n == 4 {
		return []byte{byte(a), byte(b), byte(c), byte(d), 0xFF, 0xFF, 0xFF, 0xFF}, nil
	}
	return nil, fmt.Errorf("policy: invalid IPv4 address: %s", cidr)
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
