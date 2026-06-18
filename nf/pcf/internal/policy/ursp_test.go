package policy_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/policy"
	"github.com/francurieses/claudia-5gc/shared/types"
)

func ptr[T any](v T) *T { return &v }

// ---- structural decoder -------------------------------------------------
//
// parseContainer walks a UE policy container (MANAGE UE POLICY COMMAND) exactly
// as the Wireshark NAS-5GS dissector does, verifying every length field is
// self-consistent. It fails the test on any framing error and returns the
// decoded URSP rules so individual fields can be asserted.

type urspRule struct {
	precedence byte
	td         []byte // traffic descriptor bytes
	rsdList    []byte // route selection descriptor list bytes
}

func be16(b []byte) int { return int(binary.BigEndian.Uint16(b)) }

// parseContainer returns (pti, msgType, urspRules).
func parseContainer(t *testing.T, c []byte) (byte, byte, []urspRule) {
	t.Helper()
	if len(c) < 4 {
		t.Fatalf("container too short: %d bytes", len(c))
	}
	pti := c[0]
	msgType := c[1]
	listLen := be16(c[2:4])
	off := 4
	if off+listLen != len(c) {
		t.Fatalf("section management list length %d != remaining %d", listLen, len(c)-off)
	}
	list := c[off : off+listLen]

	var rules []urspRule
	// sublists
	for p := 0; p < len(list); {
		if p+2 > len(list) {
			t.Fatalf("sublist length field truncated at %d", p)
		}
		subLen := be16(list[p : p+2])
		p += 2
		if p+subLen > len(list) {
			t.Fatalf("sublist length %d overruns list", subLen)
		}
		sub := list[p : p+subLen]
		p += subLen

		if len(sub) < 3 {
			t.Fatalf("sublist shorter than PLMN(3): %d", len(sub))
		}
		instr := sub[3:] // skip PLMN

		// instructions
		for q := 0; q < len(instr); {
			if q+2 > len(instr) {
				t.Fatalf("instruction length field truncated")
			}
			insLen := be16(instr[q : q+2])
			q += 2
			if q+insLen > len(instr) {
				t.Fatalf("instruction length %d overruns sublist", insLen)
			}
			ins := instr[q : q+insLen]
			q += insLen

			if len(ins) < 2 {
				t.Fatalf("instruction shorter than UPSC(2)")
			}
			parts := ins[2:] // skip UPSC

			// UE policy parts
			for r := 0; r < len(parts); {
				if r+2 > len(parts) {
					t.Fatalf("policy part length field truncated")
				}
				partLen := be16(parts[r : r+2])
				r += 2
				if r+partLen > len(parts) {
					t.Fatalf("policy part length %d overruns instruction", partLen)
				}
				part := parts[r : r+partLen]
				r += partLen

				if len(part) < 1 {
					t.Fatalf("policy part empty")
				}
				if part[0] != 0x01 {
					t.Fatalf("UE policy part type: got %#x, want 0x01 (URSP)", part[0])
				}
				rules = append(rules, parseURSPRules(t, part[1:])...)
			}
		}
	}
	return pti, msgType, rules
}

func parseURSPRules(t *testing.T, b []byte) []urspRule {
	t.Helper()
	var out []urspRule
	for i := 0; i < len(b); {
		if i+2 > len(b) {
			t.Fatalf("URSP rule length field truncated")
		}
		ruleLen := be16(b[i : i+2])
		i += 2
		if i+ruleLen > len(b) {
			t.Fatalf("URSP rule length %d overruns", ruleLen)
		}
		rule := b[i : i+ruleLen]
		i += ruleLen

		// precedence(1) | td_len(2) | td | rsd_list_len(2) | rsd_list
		if len(rule) < 5 {
			t.Fatalf("URSP rule too short: %d", len(rule))
		}
		prec := rule[0]
		tdLen := be16(rule[1:3])
		j := 3
		if j+tdLen > len(rule) {
			t.Fatalf("traffic descriptor length %d overruns rule", tdLen)
		}
		td := rule[j : j+tdLen]
		j += tdLen
		if j+2 > len(rule) {
			t.Fatalf("rsd list length field truncated")
		}
		rsdLen := be16(rule[j : j+2])
		j += 2
		if j+rsdLen != len(rule) {
			t.Fatalf("rsd list length %d != remaining %d", rsdLen, len(rule)-j)
		}
		out = append(out, urspRule{precedence: prec, td: td, rsdList: rule[j : j+rsdLen]})
	}
	return out
}

// ---- tests --------------------------------------------------------------

func TestEncodeURSPRules_Empty(t *testing.T) {
	for _, in := range [][]types.URSPRule{nil, {}} {
		result, err := policy.EncodeURSPRules(in, "00101")
		if err != nil {
			t.Fatalf("EncodeURSPRules(%v): %v", in, err)
		}
		if result != nil {
			t.Errorf("EncodeURSPRules(%v): got %x, want nil", in, result)
		}
	}
}

func TestEncodeURSPRules_Header(t *testing.T) {
	rules := []types.URSPRule{{
		Precedence:          255,
		TrafficDescriptor:   types.TrafficDescriptor{MatchAll: true},
		RouteSelDescriptors: []types.RouteSelectionDescriptor{{Precedence: 1, SSCMode: ptr(uint8(1))}},
	}}
	c, err := policy.EncodeURSPRules(rules, "00101")
	if err != nil {
		t.Fatalf("EncodeURSPRules: %v", err)
	}
	pti, msgType, parsed := parseContainer(t, c)
	if pti != policy.DefaultPTI {
		t.Errorf("PTI: got %#x, want %#x", pti, policy.DefaultPTI)
	}
	if msgType != 0x01 {
		t.Errorf("message type: got %#x, want 0x01 (MANAGE UE POLICY COMMAND)", msgType)
	}
	if len(parsed) != 1 {
		t.Fatalf("rule count: got %d, want 1", len(parsed))
	}
	if parsed[0].precedence != 255 {
		t.Errorf("rule precedence: got %d, want 255", parsed[0].precedence)
	}
}

func TestEncodeURSPRules_PLMN(t *testing.T) {
	// PLMN "00101" → MCC=001 MNC=01 → [0x00, 0xF1, 0x10] (TS 24.008 §10.5.1.13)
	rules := []types.URSPRule{{
		Precedence:          255,
		TrafficDescriptor:   types.TrafficDescriptor{MatchAll: true},
		RouteSelDescriptors: []types.RouteSelectionDescriptor{{Precedence: 1, SSCMode: ptr(uint8(1))}},
	}}
	c, err := policy.EncodeURSPRules(rules, "00101")
	if err != nil {
		t.Fatalf("EncodeURSPRules: %v", err)
	}
	parseContainer(t, c) // validates framing
	// PLMN sits at: PTI(1)+msgType(1)+listLen(2)+sublistLen(2) = offset 6
	plmn := c[6:9]
	if want := []byte{0x00, 0xF1, 0x10}; !bytes.Equal(plmn, want) {
		t.Errorf("PLMN: got %x, want %x", plmn, want)
	}
}

func TestEncodeURSPRules_MatchAllTrafficDescriptor(t *testing.T) {
	rules := []types.URSPRule{{
		Precedence:          255,
		TrafficDescriptor:   types.TrafficDescriptor{MatchAll: true},
		RouteSelDescriptors: []types.RouteSelectionDescriptor{{Precedence: 1, SSCMode: ptr(uint8(1))}},
	}}
	c, err := policy.EncodeURSPRules(rules, "00101")
	if err != nil {
		t.Fatalf("EncodeURSPRules: %v", err)
	}
	_, _, parsed := parseContainer(t, c)
	if want := []byte{0x01}; !bytes.Equal(parsed[0].td, want) {
		t.Errorf("match-all TD: got %x, want %x", parsed[0].td, want)
	}
}

func TestEncodeURSPRules_RSDComponents(t *testing.T) {
	// One RSD with SSC mode, S-NSSAI (SST=1 SD=000001), DNN "internet", PDU session type 1.
	rules := []types.URSPRule{{
		Precedence:        255,
		TrafficDescriptor: types.TrafficDescriptor{MatchAll: true},
		RouteSelDescriptors: []types.RouteSelectionDescriptor{{
			Precedence:     1,
			SSCMode:        ptr(uint8(1)),
			SNSSAI:         &types.SNSSAI{SST: 1, SD: "000001"},
			DNN:            ptr("internet"),
			PDUSessionType: ptr(uint8(1)),
		}},
	}}
	c, err := policy.EncodeURSPRules(rules, "00101")
	if err != nil {
		t.Fatalf("EncodeURSPRules: %v", err)
	}
	_, _, parsed := parseContainer(t, c)
	rsdList := parsed[0].rsdList

	// RSD: len(2) | prec(1) | contentsLen(2) | contents
	rsdLen := be16(rsdList[0:2])
	if 2+rsdLen != len(rsdList) {
		t.Fatalf("single RSD expected; rsdLen=%d total=%d", rsdLen, len(rsdList))
	}
	if rsdList[2] != 1 {
		t.Errorf("RSD precedence: got %d, want 1", rsdList[2])
	}
	contentsLen := be16(rsdList[3:5])
	contents := rsdList[5 : 5+contentsLen]

	// Expected component encodings (TS 24.526 §5.3):
	//   SSC mode (0x01):           01 01
	//   S-NSSAI (0x02):            02 04 01 00 00 01
	//   DNN (0x04):                04 09 08 "internet"
	//   PDU session type (0x08):   08 01
	want := []byte{
		0x01, 0x01,
		0x02, 0x04, 0x01, 0x00, 0x00, 0x01,
		0x04, 0x09, 0x08, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't',
		0x08, 0x01,
	}
	if !bytes.Equal(contents, want) {
		t.Errorf("RSD contents:\n  got  %x\n  want %x", contents, want)
	}
}

func TestEncodeURSPRules_SNSSAIWithoutSD(t *testing.T) {
	rules := []types.URSPRule{{
		Precedence:        100,
		TrafficDescriptor: types.TrafficDescriptor{MatchAll: true},
		RouteSelDescriptors: []types.RouteSelectionDescriptor{
			{Precedence: 1, SNSSAI: &types.SNSSAI{SST: 1, SD: ""}},
		},
	}}
	c, err := policy.EncodeURSPRules(rules, "00101")
	if err != nil {
		t.Fatalf("EncodeURSPRules: %v", err)
	}
	_, _, parsed := parseContainer(t, c)
	// S-NSSAI component, SST only: 02 01 01
	if !bytes.Contains(parsed[0].rsdList, []byte{0x02, 0x01, 0x01}) {
		t.Errorf("S-NSSAI-only component 02 01 01 not found in %x", parsed[0].rsdList)
	}
}

func TestEncodeURSPRules_TrafficDescriptorComponents(t *testing.T) {
	rules := []types.URSPRule{{
		Precedence: 50,
		TrafficDescriptor: types.TrafficDescriptor{
			IPv4Addrs:        []string{"10.0.0.0/8"},
			ProtocolIDs:      []uint8{6},
			PortRanges:       []types.PortRange{{Low: 80, High: 443}},
			ConnCapabilities: []uint8{0x08}, // Internet
			FQDNs:            []string{"example.com"},
		},
		RouteSelDescriptors: []types.RouteSelectionDescriptor{{Precedence: 1, SSCMode: ptr(uint8(1))}},
	}}
	c, err := policy.EncodeURSPRules(rules, "00101")
	if err != nil {
		t.Fatalf("EncodeURSPRules: %v", err)
	}
	_, _, parsed := parseContainer(t, c)
	td := parsed[0].td

	// IPv4 remote address (0x10): 10.0.0.0 mask /8 = FF 00 00 00
	if !bytes.Contains(td, []byte{0x10, 10, 0, 0, 0, 0xFF, 0x00, 0x00, 0x00}) {
		t.Errorf("IPv4 component (0x10) not found in TD: %x", td)
	}
	// Protocol id (0x30): 30 06
	if !bytes.Contains(td, []byte{0x30, 0x06}) {
		t.Errorf("protocol-id component (0x30) not found in TD: %x", td)
	}
	// Remote port range (0x51): 51 00 50 01 BB  (80..443)
	if !bytes.Contains(td, []byte{0x51, 0x00, 0x50, 0x01, 0xBB}) {
		t.Errorf("port-range component (0x51) not found in TD: %x", td)
	}
	// Connection capability (0x90): 90 01 08
	if !bytes.Contains(td, []byte{0x90, 0x01, 0x08}) {
		t.Errorf("conn-capability component (0x90) not found in TD: %x", td)
	}
	// Destination FQDN (0x91): 91 0C 07 "example" 03 "com"  (len = 1+7+1+3 = 12)
	if !bytes.Contains(td, []byte{0x91, 0x0C, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm'}) {
		t.Errorf("destination FQDN component (0x91) not found in TD: %x", td)
	}
}

func TestEncodeURSPRules_MultipleRulesOrdered(t *testing.T) {
	rules := []types.URSPRule{
		{
			Precedence:          10,
			TrafficDescriptor:   types.TrafficDescriptor{FQDNs: []string{"ims.example"}},
			RouteSelDescriptors: []types.RouteSelectionDescriptor{{Precedence: 1, SNSSAI: &types.SNSSAI{SST: 1, SD: "000002"}}},
		},
		{
			Precedence:          255,
			TrafficDescriptor:   types.TrafficDescriptor{MatchAll: true},
			RouteSelDescriptors: []types.RouteSelectionDescriptor{{Precedence: 1, SNSSAI: &types.SNSSAI{SST: 1, SD: "000001"}}},
		},
	}
	c, err := policy.EncodeURSPRules(rules, "00101")
	if err != nil {
		t.Fatalf("EncodeURSPRules: %v", err)
	}
	_, _, parsed := parseContainer(t, c)
	if len(parsed) != 2 {
		t.Fatalf("rule count: got %d, want 2", len(parsed))
	}
	if parsed[0].precedence != 10 || parsed[1].precedence != 255 {
		t.Errorf("rule order: got [%d, %d], want [10, 255]", parsed[0].precedence, parsed[1].precedence)
	}
}

// TestEncodeURSPRules_GoldenVector pins the complete byte output of a known rule
// set so any change to the wire format is caught. Computed by hand from
// TS 24.501 Annex D + TS 24.526 §5.2/§5.3.
func TestEncodeURSPRules_GoldenVector(t *testing.T) {
	rules := []types.URSPRule{{
		Precedence:        255,
		TrafficDescriptor: types.TrafficDescriptor{MatchAll: true},
		RouteSelDescriptors: []types.RouteSelectionDescriptor{{
			Precedence:     1,
			SSCMode:        ptr(uint8(1)),
			SNSSAI:         &types.SNSSAI{SST: 1, SD: "000001"},
			DNN:            ptr("internet"),
			PDUSessionType: ptr(uint8(1)),
		}},
	}}
	c, err := policy.EncodeURSPRules(rules, "00101")
	if err != nil {
		t.Fatalf("EncodeURSPRules: %v", err)
	}

	want := []byte{
		0x80, 0x01, // PTI, MANAGE UE POLICY COMMAND
		0x00, 0x2E, // section management list length = 46
		0x00, 0x2C, // sublist length = 44
		0x00, 0xF1, 0x10, // PLMN 00101
		0x00, 0x27, // instruction length = 39
		0x00, 0x01, // UPSC
		0x00, 0x23, // UE policy part length = 35
		0x01,       // UE policy part type = URSP
		0x00, 0x20, // URSP rule length = 32
		0xFF,       // precedence 255
		0x00, 0x01, // traffic descriptor length = 1
		0x01,       // match-all
		0x00, 0x1A, // route selection descriptor list length = 26
		0x00, 0x18, // RSD length = 24
		0x01,       // RSD precedence 1
		0x00, 0x15, // RSD contents length = 21
		0x01, 0x01, // SSC mode 1
		0x02, 0x04, 0x01, 0x00, 0x00, 0x01, // S-NSSAI SST=1 SD=000001
		0x04, 0x09, 0x08, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't', // DNN internet
		0x08, 0x01, // PDU session type 1
	}
	if !bytes.Equal(c, want) {
		t.Errorf("golden vector mismatch:\n  got  %x\n  want %x", c, want)
	}
}
