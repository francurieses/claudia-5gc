// 5GMM capability (TS 24.501 §9.11.3.1) and 5GSM capability (§9.11.4.1)
// information elements decoded into bit structs (REL19-5.4).

package nas

import (
	"encoding/hex"
	"fmt"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// IEIPDUSessionEstReq5GSMCapability is the 5GSM capability IEI in PDU SESSION
// ESTABLISHMENT REQUEST (optional TLV, TS 24.501 §8.3.1, §9.11.4.1).
const IEIPDUSessionEstReq5GSMCapability uint8 = 0x28

// 5GMM / 5GSM capability value limits. Both IEs are type 4 with a total length
// of at most 15 octets (IEI + length + 13 value octets), TS 24.501 §9.11.3.1,
// §9.11.4.1. Octet 3 (first value octet) is mandatory, later ones optional.
const (
	// capabilityMinValueLen is the minimum value length (octet 3 only).
	capabilityMinValueLen = 1
	// capabilityMaxValueLen is the maximum value length defined by the spec
	// (octets 3..15). Longer values are tolerated and preserved in Raw.
	capabilityMaxValueLen = 13

	// atsssSTShift/atsssSTMask: ATSSS-ST is octet 3, bits 4 to 7 (§9.11.4.1).
	atsssSTShift = 3
	atsssSTMask  = 0x0F
	// atsssLLShift/atsssLLMask: ATSSS-LL is octet 4, bits 4 and 5 (§9.11.4.1).
	atsssLLShift = 3
	atsssLLMask  = 0x03
)

// FiveGMMCapability is the decoded 5GMM capability IE value (TS 24.501
// §9.11.3.1, Figure/Table 9.11.3.1.1, V19.8.0). Each bool is the raw wire bit
// (true = bit set); octets absent from a short IE decode as false. Spare bits
// and octets beyond the known layout survive in Raw.
type FiveGMMCapability struct {
	// Raw holds the value octets verbatim (without IEI/length). Encode returns
	// it unchanged when non-nil, so unknown bits round-trip byte-identically.
	// WARNING: while Raw is non-nil, edits to the bool fields are IGNORED by
	// Encode; set Raw to nil to re-encode from the bool fields.
	Raw []byte

	// EPC NAS supported (S1 mode). Octet 3, bit 1; introduced Rel-15.
	S1Mode bool
	// ATTACH REQUEST with PDN CONNECTIVITY REQUEST for handover (HO attach). Octet 3, bit 2; introduced Rel-15.
	HOAttach bool
	// LTE Positioning Protocol capability (LPP). Octet 3, bit 3; introduced Rel-15.
	LPP bool
	// Restriction on use of enhanced coverage (RestrictEC). Octet 3, bit 4; introduced Rel-16.
	RestrictEC bool
	// Control plane CIoT 5GS optimization (5G-CP CIoT). Octet 3, bit 5; introduced Rel-16.
	CPCIoT bool
	// N3 data transfer (N3 data); INVERTED: 1 = not supported. Octet 3, bit 6; introduced Rel-16.
	N3DataNotSupported bool
	// IP header compression for CP CIoT (5G-IPHC-CP CIoT). Octet 3, bit 7; introduced Rel-16.
	IPHCCPCIoT bool
	// Service gap control (SGC). Octet 3, bit 8; introduced Rel-16.
	SGC bool
	// 5G-SRVCC from NG-RAN to UTRAN (5GSRVCC). Octet 4, bit 1; introduced Rel-16.
	SRVCC5G bool
	// User plane CIoT 5GS optimization (5G-UP CIoT). Octet 4, bit 2; introduced Rel-16.
	UPCIoT bool
	// V2X-Uu capability. Octet 4, bit 3; introduced Rel-16.
	V2XUu bool
	// V2X communication over E-UTRA-PC5. Octet 4, bit 4; introduced Rel-16.
	V2XCEPC5 bool
	// V2X communication over NR-PC5. Octet 4, bit 5; introduced Rel-16.
	V2XCNPC5 bool
	// 5G-LCS notification mechanisms. Octet 4, bit 6; introduced Rel-16.
	LCS5G bool
	// Network slice-specific authentication and authorization (NSSAA). Octet 4, bit 7; introduced Rel-16.
	NSSAA bool
	// Radio capability signalling optimisation (RACS). Octet 4, bit 8; introduced Rel-16.
	RACS bool
	// Closed Access Group (CAG). Octet 5, bit 1; introduced Rel-16.
	CAG bool
	// WUS assistance information reception (WUSA). Octet 5, bit 2; introduced Rel-16.
	WUSA bool
	// Multiple user-plane resources support (multipleUP). Octet 5, bit 3; introduced Rel-16.
	MultipleUP bool
	// Ethernet header compression for CP CIoT (5G-EHC-CP CIoT). Octet 5, bit 4; introduced Rel-16.
	EHCCPCIoT bool
	// Extended rejected NSSAI support (ER-NSSAI). Octet 5, bit 5; introduced Rel-17.
	ERNSSAI bool
	// 5G ProSe direct discovery (5G ProSe-dd). Octet 5, bit 6; introduced Rel-17.
	ProSeDD bool
	// 5G ProSe direct communication (5G ProSe-dc). Octet 5, bit 7; introduced Rel-17.
	ProSeDC bool
	// 5G ProSe layer-2 UE-to-network relay (5G ProSe-l2relay). Octet 5, bit 8; introduced Rel-17.
	ProSeL2Relay bool
	// 5G ProSe layer-3 UE-to-network relay (5G ProSe-l3relay). Octet 6, bit 1; introduced Rel-17.
	ProSeL3Relay bool
	// 5G ProSe layer-2 UE-to-network remote (5G ProSe-l2rmt). Octet 6, bit 2; introduced Rel-17.
	ProSeL2Rmt bool
	// 5G ProSe layer-3 UE-to-network remote (5G ProSe-l3rmt). Octet 6, bit 3; introduced Rel-17.
	ProSeL3Rmt bool
	// NR paging subgroup support indication (NR-PSSI). Octet 6, bit 4; introduced Rel-17.
	NRPSSI bool
	// N1 NAS signalling connection release (NCR). Octet 6, bit 5; introduced Rel-17.
	NCR bool
	// Paging indication for voice services (PIV). Octet 6, bit 6; introduced Rel-17.
	PIV bool
	// Reject paging request (RPR). Octet 6, bit 7; introduced Rel-17.
	RPR bool
	// Paging restriction (PR). Octet 6, bit 8; introduced Rel-17.
	PR bool
	// NSSRG. Octet 7, bit 1; introduced Rel-17.
	NSSRG bool
	// Minimization of service interruption (MINT). Octet 7, bit 2; introduced Rel-17.
	MINT bool
	// Event notification. Octet 7, bit 3; introduced Rel-17.
	EventNotification bool
	// SOR-SNPN-SI. Octet 7, bit 4; introduced Rel-17.
	SSNPNSI bool
	// Extended CAG information list support (Ex-CAG). Octet 7, bit 5; introduced Rel-17.
	ExCAG bool
	// NSAG. Octet 7, bit 6; introduced Rel-17.
	NSAG bool
	// UAS. Octet 7, bit 7; introduced Rel-17.
	UAS bool
	// MPS indicator update (MPSIU). Octet 7, bit 8; introduced Rel-17.
	MPSIU bool
	// Registration complete for acknowledging PEIPS assistance information (RCMAP). Octet 8, bit 1; introduced Rel-17.
	RCMAP bool
	// Registration complete for acknowledging NSAG information (RCMAN). Octet 8, bit 2; introduced Rel-17.
	RCMAN bool
	// Equivalent SNPNs indicator (ESI). Octet 8, bit 3; introduced Rel-18.
	ESI bool
	// Enhanced CAG information (ECI). Octet 8, bit 4; introduced Rel-18.
	ECI bool
	// Reconnection due to RAN timing synchronization status change (RANtiming). Octet 8, bit 5; introduced Rel-18.
	RANTiming bool
	// LADN per DNN and S-NSSAI support (LADN-DS). Octet 8, bit 6; introduced Rel-18.
	LADNDS bool
	// Network slice replacement (NSR). Octet 8, bit 7; introduced Rel-18.
	NSR bool
	// Slice-based TNGF selection support (SBTS). Octet 8, bit 8; introduced Rel-18.
	SBTS bool
	// A2X over E-UTRA-PC5. Octet 9, bit 1; introduced Rel-18.
	A2XEPC5 bool
	// A2X over NR-PC5. Octet 9, bit 2; introduced Rel-18.
	A2XNPC5 bool
	// Unavailability period (UN-PER). Octet 9, bit 3; introduced Rel-18.
	UNPER bool
	// Slice-based N3IWF selection support (SBNS). Octet 9, bit 4; introduced Rel-18.
	SBNS bool
	// SL positioning server UE (RSLPS). Octet 9, bit 5; introduced Rel-18.
	RSLPS bool
	// 5G ProSe layer-2 UE-to-UE relay. Octet 9, bit 6; introduced Rel-18.
	ProSeL2U2URelay bool
	// 5G ProSe layer-3 UE-to-UE relay. Octet 9, bit 7; introduced Rel-18.
	ProSeL3U2URelay bool
	// 5G ProSe layer-2 end UE. Octet 9, bit 8; introduced Rel-18.
	ProSeL2End bool
	// 5G ProSe layer-3 end UE. Octet 10, bit 1; introduced Rel-18.
	ProSeL3End bool
	// Ranging and sidelink positioning support (RSLP). Octet 10, bit 2; introduced Rel-18.
	RSLP bool
	// Partial network slice (PNS). Octet 10, bit 3; introduced Rel-18.
	PNS bool
	// LCS-UPP user plane positioning. Octet 10, bit 4; introduced Rel-18.
	LCSUPP bool
	// SUPL user plane positioning. Octet 10, bit 5; introduced Rel-18.
	SUPL bool
	// S-NSSAI time validity information (TempNS). Octet 10, bit 6; introduced Rel-18.
	TempNS bool
	// S-NSSAI location validity information (SLVI). Octet 10, bit 7; introduced Rel-18.
	SLVI bool
	// A2X over Uu capability. Octet 10, bit 8; introduced Rel-18.
	A2XUu bool
	// MCS indicator update (MCSIU). Octet 11, bit 1; introduced Rel-18.
	MCSIU bool
	// Network verified UE location over satellite NG-RAN (NVL-SATNR). Octet 11, bit 2; introduced Rel-18.
	NVLSATNR bool
	// Ranging and sidelink positioning over PC5 for located UE (RSLPL). Octet 11, bit 3; introduced Rel-18.
	RSLPL bool
	// Network slice usage control (NSUC). Octet 11, bit 4; introduced Rel-18.
	NSUC bool
	// Ranging and sidelink positioning with V2X capable UE (RSLPVU). Octet 11, bit 5; introduced Rel-19.
	RSLPVU bool
	// Ranging and sidelink positioning with 5G ProSe capable UE (RSLPPU). Octet 11, bit 6; introduced Rel-19.
	RSLPPU bool
	// Access technology utilization control (ATUC). Octet 11, bit 7; introduced Rel-19.
	ATUC bool
	// LP-WUSPS assistance information support indication (LP-WUSPSAI-SI). Octet 11, bit 8; introduced Rel-19.
	LPWUSPSAISI bool
	// Operator policy for high priority access exemptions (OPHPAE). Octet 12, bit 1; introduced Rel-19.
	OPHPAE bool
	// 5G ProSe Multi-hop relay communication indication (5G ProSe-MCI). Octet 12, bit 2; introduced Rel-19.
	ProSeMCI bool
	// Multiple LCS secured user plane connections (MLCSUP). Octet 12, bit 3; introduced Rel-19.
	MLCSUP bool
	// 5G ProSe layer-3 intermediate UE-to-network relay UE. Octet 12, bit 4; introduced Rel-19.
	ProSeL3IMRelay bool
	// 5G ProSe layer-2 intermediate UE-to-network relay UE. Octet 12, bit 5; introduced Rel-19.
	ProSeL2IMRelay bool
	// Minimization of service interruption support in EPS (MINT-EPS). Octet 12, bit 6; introduced Rel-19.
	MINTEPS bool
	// ExtendedFacility IE for 5G LCS (EF5L). Octet 12, bit 7; introduced Rel-19.
	EF5L bool
	// LP-WUS disabling (LWD). Octet 12, bit 8; introduced Rel-19.
	LWD bool
	// Non satellite lower PLMN selection (NonSATLSP). Octet 13, bit 1; introduced Rel-19.
	NonSATLSP bool
	// Location service continuity between 5GS and EPS for deferred location (LCSCDL). Octet 13, bit 4; introduced Rel-19.
	LCSCDL bool
}

// FiveGSMCapability is the decoded 5GSM capability IE value (TS 24.501
// §9.11.4.1, Figure/Table 9.11.4.1.1, V19.8.0). Bool fields are raw wire bits;
// ATSSSST and ATSSSLL are multi-bit fields.
type FiveGSMCapability struct {
	// Raw holds the value octets verbatim (without IEI/length); see
	// FiveGMMCapability.Raw.
	Raw []byte

	// ATSSSST is the supported ATSSS steering functionalities and steering
	// modes, octet 3 bits 4 to 7 (0 = ATSSS not supported, 1 = ATSSS-LL any
	// mode, 2 = MPTCP any + ATSSS-LL active-standby, 3 = MPTCP any +
	// ATSSS-LL any; others reserved). Introduced Rel-16.
	ATSSSST uint8
	// ATSSSLL is ATSSS-LL functionality support, octet 4 bits 5 and 4
	// (0 = not supported, 1 = active-standby only, 2 = any steering mode,
	// 3 = spare). Introduced Rel-18.
	ATSSSLL uint8

	// Reflective QoS (RQoS). Octet 3, bit 1; introduced Rel-15.
	RQoS bool
	// Multi-homed IPv6 PDU session (MH6-PDU). Octet 3, bit 2; introduced Rel-15.
	MH6PDU bool
	// Ethernet PDN type in S1 mode (EPT-S1). Octet 3, bit 3; introduced Rel-16.
	EPTS1 bool
	// Transfer of port management information containers (TPMIC). Octet 3, bit 8; introduced Rel-16.
	TPMIC bool
	// Access performance measurements per QoS flow rule (APMQF). Octet 4, bit 1; introduced Rel-17.
	APMQF bool
	// Secondary DN authentication and authorization over EPC (SDNAEPC). Octet 4, bit 2; introduced Rel-18.
	SDNAEPC bool
	// (S)RTP multiplexed media identification information (RTPMMII). Octet 4, bit 3; introduced Rel-19.
	RTPMMII bool
	// MPTCP functionality with any steering mode (MPTCP). Octet 4, bit 6; introduced Rel-18.
	MPTCP bool
	// MPQUIC-UDP functionality with any steering mode. Octet 4, bit 7; introduced Rel-18.
	MPQUICUDP bool
	// MPQUIC-IP functionality with any steering mode. Octet 4, bit 8; introduced Rel-19.
	MPQUICIP bool
	// MPQUIC-E functionality with any steering mode. Octet 5, bit 1; introduced Rel-19.
	MPQUICE bool
	// Extended 802.1Q C-TAG/S-TAG PCP/DEI packet filter component (E8PCPDEI). Octet 5, bit 2; introduced Rel-19.
	E8PCPDEI bool
}

// capabilityBit describes one single-bit field of a capability IE.
type capabilityBit[T any] struct {
	octet      int // octet number as in the spec figure (3 = first value octet)
	bit        int // bit number 1..8 (1 = LSB)
	name       string
	introduced capability.Release
	field      func(*T) *bool
}

// fiveGMMCapabilityBits lists every 5GMM capability bit (Table 9.11.3.1.1).
// Introduced is taken from the first TS 24.501 version (V15.7.0, V16.15.0,
// V17.18.1, V18.14.0, V19.8.0) whose table defines the bit.
var fiveGMMCapabilityBits = []capabilityBit[FiveGMMCapability]{
	{octet: 3, bit: 1, name: "S1Mode", introduced: capability.Rel15, field: func(c *FiveGMMCapability) *bool { return &c.S1Mode }},
	{octet: 3, bit: 2, name: "HOAttach", introduced: capability.Rel15, field: func(c *FiveGMMCapability) *bool { return &c.HOAttach }},
	{octet: 3, bit: 3, name: "LPP", introduced: capability.Rel15, field: func(c *FiveGMMCapability) *bool { return &c.LPP }},
	{octet: 3, bit: 4, name: "RestrictEC", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.RestrictEC }},
	{octet: 3, bit: 5, name: "CPCIoT", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.CPCIoT }},
	{octet: 3, bit: 6, name: "N3DataNotSupported", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.N3DataNotSupported }},
	{octet: 3, bit: 7, name: "IPHCCPCIoT", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.IPHCCPCIoT }},
	{octet: 3, bit: 8, name: "SGC", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.SGC }},
	{octet: 4, bit: 1, name: "SRVCC5G", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.SRVCC5G }},
	{octet: 4, bit: 2, name: "UPCIoT", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.UPCIoT }},
	{octet: 4, bit: 3, name: "V2XUu", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.V2XUu }},
	{octet: 4, bit: 4, name: "V2XCEPC5", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.V2XCEPC5 }},
	{octet: 4, bit: 5, name: "V2XCNPC5", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.V2XCNPC5 }},
	{octet: 4, bit: 6, name: "LCS5G", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.LCS5G }},
	{octet: 4, bit: 7, name: "NSSAA", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.NSSAA }},
	{octet: 4, bit: 8, name: "RACS", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.RACS }},
	{octet: 5, bit: 1, name: "CAG", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.CAG }},
	{octet: 5, bit: 2, name: "WUSA", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.WUSA }},
	{octet: 5, bit: 3, name: "MultipleUP", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.MultipleUP }},
	{octet: 5, bit: 4, name: "EHCCPCIoT", introduced: capability.Rel16, field: func(c *FiveGMMCapability) *bool { return &c.EHCCPCIoT }},
	{octet: 5, bit: 5, name: "ERNSSAI", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.ERNSSAI }},
	{octet: 5, bit: 6, name: "ProSeDD", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.ProSeDD }},
	{octet: 5, bit: 7, name: "ProSeDC", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.ProSeDC }},
	{octet: 5, bit: 8, name: "ProSeL2Relay", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.ProSeL2Relay }},
	{octet: 6, bit: 1, name: "ProSeL3Relay", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.ProSeL3Relay }},
	{octet: 6, bit: 2, name: "ProSeL2Rmt", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.ProSeL2Rmt }},
	{octet: 6, bit: 3, name: "ProSeL3Rmt", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.ProSeL3Rmt }},
	{octet: 6, bit: 4, name: "NRPSSI", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.NRPSSI }},
	{octet: 6, bit: 5, name: "NCR", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.NCR }},
	{octet: 6, bit: 6, name: "PIV", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.PIV }},
	{octet: 6, bit: 7, name: "RPR", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.RPR }},
	{octet: 6, bit: 8, name: "PR", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.PR }},
	{octet: 7, bit: 1, name: "NSSRG", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.NSSRG }},
	{octet: 7, bit: 2, name: "MINT", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.MINT }},
	{octet: 7, bit: 3, name: "EventNotification", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.EventNotification }},
	{octet: 7, bit: 4, name: "SSNPNSI", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.SSNPNSI }},
	{octet: 7, bit: 5, name: "ExCAG", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.ExCAG }},
	{octet: 7, bit: 6, name: "NSAG", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.NSAG }},
	{octet: 7, bit: 7, name: "UAS", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.UAS }},
	{octet: 7, bit: 8, name: "MPSIU", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.MPSIU }},
	{octet: 8, bit: 1, name: "RCMAP", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.RCMAP }},
	{octet: 8, bit: 2, name: "RCMAN", introduced: capability.Rel17, field: func(c *FiveGMMCapability) *bool { return &c.RCMAN }},
	{octet: 8, bit: 3, name: "ESI", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.ESI }},
	{octet: 8, bit: 4, name: "ECI", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.ECI }},
	{octet: 8, bit: 5, name: "RANTiming", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.RANTiming }},
	{octet: 8, bit: 6, name: "LADNDS", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.LADNDS }},
	{octet: 8, bit: 7, name: "NSR", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.NSR }},
	{octet: 8, bit: 8, name: "SBTS", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.SBTS }},
	{octet: 9, bit: 1, name: "A2XEPC5", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.A2XEPC5 }},
	{octet: 9, bit: 2, name: "A2XNPC5", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.A2XNPC5 }},
	{octet: 9, bit: 3, name: "UNPER", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.UNPER }},
	{octet: 9, bit: 4, name: "SBNS", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.SBNS }},
	{octet: 9, bit: 5, name: "RSLPS", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.RSLPS }},
	{octet: 9, bit: 6, name: "ProSeL2U2URelay", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.ProSeL2U2URelay }},
	{octet: 9, bit: 7, name: "ProSeL3U2URelay", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.ProSeL3U2URelay }},
	{octet: 9, bit: 8, name: "ProSeL2End", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.ProSeL2End }},
	{octet: 10, bit: 1, name: "ProSeL3End", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.ProSeL3End }},
	{octet: 10, bit: 2, name: "RSLP", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.RSLP }},
	{octet: 10, bit: 3, name: "PNS", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.PNS }},
	{octet: 10, bit: 4, name: "LCSUPP", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.LCSUPP }},
	{octet: 10, bit: 5, name: "SUPL", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.SUPL }},
	{octet: 10, bit: 6, name: "TempNS", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.TempNS }},
	{octet: 10, bit: 7, name: "SLVI", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.SLVI }},
	{octet: 10, bit: 8, name: "A2XUu", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.A2XUu }},
	{octet: 11, bit: 1, name: "MCSIU", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.MCSIU }},
	{octet: 11, bit: 2, name: "NVLSATNR", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.NVLSATNR }},
	{octet: 11, bit: 3, name: "RSLPL", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.RSLPL }},
	{octet: 11, bit: 4, name: "NSUC", introduced: capability.Rel18, field: func(c *FiveGMMCapability) *bool { return &c.NSUC }},
	{octet: 11, bit: 5, name: "RSLPVU", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.RSLPVU }},
	{octet: 11, bit: 6, name: "RSLPPU", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.RSLPPU }},
	{octet: 11, bit: 7, name: "ATUC", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.ATUC }},
	{octet: 11, bit: 8, name: "LPWUSPSAISI", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.LPWUSPSAISI }},
	{octet: 12, bit: 1, name: "OPHPAE", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.OPHPAE }},
	{octet: 12, bit: 2, name: "ProSeMCI", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.ProSeMCI }},
	{octet: 12, bit: 3, name: "MLCSUP", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.MLCSUP }},
	{octet: 12, bit: 4, name: "ProSeL3IMRelay", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.ProSeL3IMRelay }},
	{octet: 12, bit: 5, name: "ProSeL2IMRelay", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.ProSeL2IMRelay }},
	{octet: 12, bit: 6, name: "MINTEPS", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.MINTEPS }},
	{octet: 12, bit: 7, name: "EF5L", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.EF5L }},
	{octet: 12, bit: 8, name: "LWD", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.LWD }},
	{octet: 13, bit: 1, name: "NonSATLSP", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.NonSATLSP }},
	{octet: 13, bit: 4, name: "LCSCDL", introduced: capability.Rel19, field: func(c *FiveGMMCapability) *bool { return &c.LCSCDL }},
}

// fiveGSMCapabilityBits lists every single-bit 5GSM capability field
// (Table 9.11.4.1.1); ATSSS-ST and ATSSS-LL are handled separately.
var fiveGSMCapabilityBits = []capabilityBit[FiveGSMCapability]{
	{octet: 3, bit: 1, name: "RQoS", introduced: capability.Rel15, field: func(c *FiveGSMCapability) *bool { return &c.RQoS }},
	{octet: 3, bit: 2, name: "MH6PDU", introduced: capability.Rel15, field: func(c *FiveGSMCapability) *bool { return &c.MH6PDU }},
	{octet: 3, bit: 3, name: "EPTS1", introduced: capability.Rel16, field: func(c *FiveGSMCapability) *bool { return &c.EPTS1 }},
	{octet: 3, bit: 8, name: "TPMIC", introduced: capability.Rel16, field: func(c *FiveGSMCapability) *bool { return &c.TPMIC }},
	{octet: 4, bit: 1, name: "APMQF", introduced: capability.Rel17, field: func(c *FiveGSMCapability) *bool { return &c.APMQF }},
	{octet: 4, bit: 2, name: "SDNAEPC", introduced: capability.Rel18, field: func(c *FiveGSMCapability) *bool { return &c.SDNAEPC }},
	{octet: 4, bit: 3, name: "RTPMMII", introduced: capability.Rel19, field: func(c *FiveGSMCapability) *bool { return &c.RTPMMII }},
	{octet: 4, bit: 6, name: "MPTCP", introduced: capability.Rel18, field: func(c *FiveGSMCapability) *bool { return &c.MPTCP }},
	{octet: 4, bit: 7, name: "MPQUICUDP", introduced: capability.Rel18, field: func(c *FiveGSMCapability) *bool { return &c.MPQUICUDP }},
	{octet: 4, bit: 8, name: "MPQUICIP", introduced: capability.Rel19, field: func(c *FiveGSMCapability) *bool { return &c.MPQUICIP }},
	{octet: 5, bit: 1, name: "MPQUICE", introduced: capability.Rel19, field: func(c *FiveGSMCapability) *bool { return &c.MPQUICE }},
	{octet: 5, bit: 2, name: "E8PCPDEI", introduced: capability.Rel19, field: func(c *FiveGSMCapability) *bool { return &c.E8PCPDEI }},
}

// bitAt reports whether bit (1..8) of spec octet n is set in the value octets
// (octet 3 = index 0). Octets beyond len(v) read as 0.
func bitAt(v []byte, octet, bit int) bool {
	i := octet - 3
	return i >= 0 && i < len(v) && v[i]&(1<<(bit-1)) != 0
}

// Decode5GMMCapability decodes the 5GMM capability IE value octets (without
// IEI and length). Zero length is an error; any length >= 1 is accepted and
// preserved in Raw. Ref: TS 24.501 §9.11.3.1
func Decode5GMMCapability(b []byte) (*FiveGMMCapability, error) {
	if len(b) < capabilityMinValueLen {
		return nil, fmt.Errorf("nas: 5GMM capability: length %d < %d", len(b), capabilityMinValueLen)
	}
	c := &FiveGMMCapability{Raw: append([]byte(nil), b...)}
	for _, d := range fiveGMMCapabilityBits {
		*d.field(c) = bitAt(b, d.octet, d.bit)
	}
	return c, nil
}

// Encode5GMMCapability returns the IE value octets (without IEI and length).
// When c.Raw is set it is returned verbatim (edited bool fields with a stale
// Raw are ignored - clear Raw to re-encode from them); otherwise the value is built from
// the bit fields, trimmed to the highest octet with a bit set (minimum one
// octet). Ref: TS 24.501 §9.11.3.1
func Encode5GMMCapability(c *FiveGMMCapability) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("nas: 5GMM capability: nil")
	}
	if c.Raw != nil {
		if len(c.Raw) < capabilityMinValueLen {
			return nil, fmt.Errorf("nas: 5GMM capability: empty Raw")
		}
		return append([]byte(nil), c.Raw...), nil
	}
	out := make([]byte, capabilityMaxValueLen)
	n := capabilityMinValueLen
	for _, d := range fiveGMMCapabilityBits {
		if *d.field(c) {
			out[d.octet-3] |= 1 << (d.bit - 1)
			n = max(n, d.octet-2)
		}
	}
	return out[:n], nil
}

// Decode5GSMCapability decodes the 5GSM capability IE value octets (without
// IEI and length). Zero length is an error; any length >= 1 is accepted and
// preserved in Raw. Ref: TS 24.501 §9.11.4.1
func Decode5GSMCapability(b []byte) (*FiveGSMCapability, error) {
	if len(b) < capabilityMinValueLen {
		return nil, fmt.Errorf("nas: 5GSM capability: length %d < %d", len(b), capabilityMinValueLen)
	}
	c := &FiveGSMCapability{Raw: append([]byte(nil), b...)}
	c.ATSSSST = (b[0] >> atsssSTShift) & atsssSTMask
	if len(b) > 1 {
		c.ATSSSLL = (b[1] >> atsssLLShift) & atsssLLMask
	}
	for _, d := range fiveGSMCapabilityBits {
		*d.field(c) = bitAt(b, d.octet, d.bit)
	}
	return c, nil
}

// Encode5GSMCapability returns the IE value octets (without IEI and length);
// Raw semantics as Encode5GMMCapability: a non-nil Raw is returned verbatim and
// edited fields are ignored until Raw is cleared. Ref: TS 24.501 §9.11.4.1
func Encode5GSMCapability(c *FiveGSMCapability) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("nas: 5GSM capability: nil")
	}
	if c.Raw != nil {
		if len(c.Raw) < capabilityMinValueLen {
			return nil, fmt.Errorf("nas: 5GSM capability: empty Raw")
		}
		return append([]byte(nil), c.Raw...), nil
	}
	out := make([]byte, capabilityMaxValueLen)
	n := capabilityMinValueLen
	out[0] |= (c.ATSSSST & atsssSTMask) << atsssSTShift
	out[1] |= (c.ATSSSLL & atsssLLMask) << atsssLLShift
	if c.ATSSSLL != 0 {
		n = 2
	}
	for _, d := range fiveGSMCapabilityBits {
		if *d.field(c) {
			out[d.octet-3] |= 1 << (d.bit - 1)
			n = max(n, d.octet-2)
		}
	}
	return out[:n], nil
}

// PeerUE adapts the decoded 5GMM capability to a capability.PeerUE. bits maps
// a capability.Feature.ID to the predicate reading its bit; features without
// an entry are not supported (REL19-5.4, ADR-5). shared/capability stays a
// leaf package, so the mapping lives here.
func (c FiveGMMCapability) PeerUE(bits map[string]func(FiveGMMCapability) bool) capability.PeerUE {
	return capability.PeerUE{Supports: func(f capability.Feature) bool {
		p, ok := bits[f.ID]
		return ok && p(c)
	}}
}

// PeerUE is the 5GSM counterpart of FiveGMMCapability.PeerUE.
func (c FiveGSMCapability) PeerUE(bits map[string]func(FiveGSMCapability) bool) capability.PeerUE {
	return capability.PeerUE{Supports: func(f capability.Feature) bool {
		p, ok := bits[f.ID]
		return ok && p(c)
	}}
}

// SetBitNames returns the names of the 5GMM capability bits that are set on
// the wire, in spec octet/bit order (table order). N3DataNotSupported is
// reported under its spec name "N3data" only when the wire bit is 1, i.e. the
// INVERTED sense is not applied: the list is the raw set bits. Used for
// observability (canonical log field capability_5gmm_bits). Ref: TS 24.501 §9.11.3.1
func (c *FiveGMMCapability) SetBitNames() []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, d := range fiveGMMCapabilityBits {
		if *d.field(c) {
			out = append(out, d.name)
		}
	}
	return out
}

// SetBitNames returns the names of the 5GSM capability bits that are set,
// followed by "ATSSS-ST=<n>" / "ATSSS-LL=<n>" when those multi-bit fields are
// non-zero. Ref: TS 24.501 §9.11.4.1
func (c *FiveGSMCapability) SetBitNames() []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, d := range fiveGSMCapabilityBits {
		if *d.field(c) {
			out = append(out, d.name)
		}
	}
	if c.ATSSSST != 0 {
		out = append(out, fmt.Sprintf("ATSSS-ST=%d", c.ATSSSST))
	}
	if c.ATSSSLL != 0 {
		out = append(out, fmt.Sprintf("ATSSS-LL=%d", c.ATSSSLL))
	}
	return out
}

// RawHex returns the IE value octets as lowercase hex ("" for nil/empty), for
// the canonical log field capability_5gmm. Ref: TS 24.501 §9.11.3.1
func (c *FiveGMMCapability) RawHex() string {
	if c == nil {
		return ""
	}
	return hex.EncodeToString(c.Raw)
}

// RawHex is the 5GSM counterpart of FiveGMMCapability.RawHex (log field
// capability_5gsm). Ref: TS 24.501 §9.11.4.1
func (c *FiveGSMCapability) RawHex() string {
	if c == nil {
		return ""
	}
	return hex.EncodeToString(c.Raw)
}
