// Package nas — ietable.go: per-message optional-IE tables and the generic
// unknown-IE skipper for the non-imperative part of 5GMM/5GSM messages.
//
// The tables are transcribed from the message-content tables of
// TS 24.501 V19.8.0 clause 8 (Tables 8.2.1.1.1, 8.2.2.1.1, 8.2.6.1.1, 8.2.7.1.1,
// 8.2.10.1.1, 8.2.11.1.1, 8.2.16.1.1, 8.2.17.1.1, 8.2.19.1.1, 8.2.25.1.1,
// 8.2.26.1.1, 8.3.1.1.1). They
// give, for each IEI that is "known" in a message, the IE format (TS 24.007
// §11.2.1.1.4 categories) and the release that introduced it. A decoder that
// meets an IEI it does not handle calls skipIE, which uses the table when the
// IEI is known and the TS 24.007 §11.2.4 rule when it is not, so one
// unrecognised IE never desynchronises the rest of the message.
//
// Ref: TS 24.007 §11.2.4, TS 24.501 §7.6.1.
package nas

import (
	"errors"
	"fmt"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// IEFormat is the TS 24.007 §11.2.1.1.4 format of an information element in
// the non-imperative part of a message.
type IEFormat uint8

// IE formats. Ref: TS 24.007 §11.2.1.1.4 (categories type 1, 2, 3, 4, 6).
const (
	// IEFormatTV1 is a type 1 TV IE: half-octet IEI in bits 8-5, half-octet
	// value in bits 4-1 of the same octet (one octet in total).
	IEFormatTV1 IEFormat = iota + 1
	// IEFormatT is a type 2 IE: one-octet IEI, empty value.
	IEFormatT
	// IEFormatTV is a type 3 IE: one-octet IEI followed by a fixed-length
	// value (IEDef.Len is the total length including the IEI).
	IEFormatTV
	// IEFormatTLV is a type 4 IE: IEI, one-octet length, value.
	IEFormatTLV
	// IEFormatTLVE is a type 6 IE: IEI, two-octet big-endian length, value.
	IEFormatTLVE
)

// String returns the TS 24.501 table spelling of the format.
func (f IEFormat) String() string {
	switch f {
	case IEFormatTV1:
		return "TV(1/2)"
	case IEFormatT:
		return "T"
	case IEFormatTV:
		return "TV"
	case IEFormatTLV:
		return "TLV"
	case IEFormatTLVE:
		return "TLV-E"
	}
	return fmt.Sprintf("IEFormat(%d)", uint8(f))
}

// IEDef describes one optional IE of a message.
type IEDef struct {
	// IEI is the IE identifier. For IEFormatTV1 it is the half-octet IEI in
	// the high nibble (for example 0xB0 for "B-").
	IEI byte
	// Name is the IE name as written in the message-content table.
	Name string
	// Format is the IE format column of the table.
	Format IEFormat
	// Len is the total length (IEI included) of an IEFormatTV IE, else 0.
	Len int
	// Introduced is the release whose final TS 24.501 version first lists
	// the IE in the message-content table: V15.7.0 -> Rel15, V16.15.0 ->
	// Rel16, V17.18.1 -> Rel17, V18.14.0 -> Rel18, V19.8.0 -> Rel19.
	// Verified by diffing the per-message tables of those versions
	// (REL19-5.1 follow-up). The spec does not mark the introducing release
	// per IE, so an IE added and listed within one release carries that
	// release; it is exact at release granularity only. Nothing gates on it
	// yet.
	Introduced capability.Release
	// Ref is the clause defining the IE value part.
	Ref string
}

// IEMessage identifies a message whose optional-IE table is registered.
type IEMessage string

// Messages with a registered IE table.
const (
	// IEMsgRegistrationRequest — TS 24.501 Table 8.2.6.1.1.
	IEMsgRegistrationRequest IEMessage = "RegistrationRequest"
	// IEMsgRegistrationAccept — TS 24.501 Table 8.2.7.1.1.
	IEMsgRegistrationAccept IEMessage = "RegistrationAccept"
	// IEMsgPDUSessionEstablishmentRequest — TS 24.501 Table 8.3.1.1.1.
	IEMsgPDUSessionEstablishmentRequest IEMessage = "PDUSessionEstablishmentRequest"
	// IEMsgServiceRequest — TS 24.501 Table 8.2.16.1.1 (SERVICE REQUEST).
	IEMsgServiceRequest IEMessage = "ServiceRequest"
	// IEMsgServiceAccept — TS 24.501 Table 8.2.17.1.1 (SERVICE ACCEPT).
	IEMsgServiceAccept IEMessage = "ServiceAccept"
	// IEMsgConfigurationUpdateCommand — TS 24.501 Table 8.2.19.1.1 (CONFIGURATION UPDATE COMMAND).
	IEMsgConfigurationUpdateCommand IEMessage = "ConfigurationUpdateCommand"
	// IEMsgULNASTransport — TS 24.501 Table 8.2.10.1.1 (UL NAS TRANSPORT).
	IEMsgULNASTransport IEMessage = "ULNASTransport"
	// IEMsgDLNASTransport — TS 24.501 Table 8.2.11.1.1 (DL NAS TRANSPORT).
	IEMsgDLNASTransport IEMessage = "DLNASTransport"
	// IEMsgAuthenticationRequest — TS 24.501 Table 8.2.1.1.1 (AUTHENTICATION REQUEST).
	IEMsgAuthenticationRequest IEMessage = "AuthenticationRequest"
	// IEMsgAuthenticationResponse — TS 24.501 Table 8.2.2.1.1 (AUTHENTICATION RESPONSE).
	IEMsgAuthenticationResponse IEMessage = "AuthenticationResponse"
	// IEMsgSecurityModeCommand — TS 24.501 Table 8.2.25.1.1 (SECURITY MODE COMMAND).
	IEMsgSecurityModeCommand IEMessage = "SecurityModeCommand"
	// IEMsgSecurityModeComplete — TS 24.501 Table 8.2.26.1.1 (SECURITY MODE COMPLETE).
	IEMsgSecurityModeComplete IEMessage = "SecurityModeComplete"
)

// ieTables holds the optional IEs of each message in spec table order.
var ieTables = map[IEMessage][]IEDef{
	IEMsgRegistrationRequest: {
		{IEI: 0xC0, Name: "Non-current native NAS key set identifier", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.32"},
		{IEI: 0x10, Name: "5GMM capability", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.1"},
		{IEI: 0x2E, Name: "UE security capability", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.54"},
		{IEI: 0x2F, Name: "Requested NSSAI", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.37"},
		{IEI: 0x52, Name: "Last visited registered TAI", Format: IEFormatTV, Len: 7, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.8"},
		{IEI: 0x17, Name: "S1 UE network capability", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.48"},
		{IEI: 0x40, Name: "Uplink data status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.57"},
		{IEI: 0x50, Name: "PDU session status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.44"},
		{IEI: 0xB0, Name: "MICO indication", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.31"},
		{IEI: 0x2B, Name: "UE status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.56"},
		{IEI: 0x77, Name: "Additional GUTI", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.4"},
		{IEI: 0x25, Name: "Allowed PDU session status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.13"},
		{IEI: 0x18, Name: "UE's usage setting", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.55"},
		{IEI: 0x51, Name: "Requested DRX parameters", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.2A"},
		{IEI: 0x70, Name: "EPS NAS message container", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.24"},
		{IEI: 0x74, Name: "LADN indication", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.29"},
		{IEI: 0x80, Name: "Payload container type", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.40"},
		{IEI: 0x7B, Name: "Payload container", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.39"},
		{IEI: 0x90, Name: "Network slicing indication", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.36"},
		{IEI: 0x53, Name: "5GS update type", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.9A"},
		{IEI: 0x41, Name: "Mobile station classmark 2", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.31C"},
		{IEI: 0x42, Name: "Supported codecs", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.51A"},
		{IEI: 0x71, Name: "NAS message container", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.33"},
		{IEI: 0x60, Name: "EPS bearer context status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.23A"},
		{IEI: 0x6E, Name: "Requested extended DRX parameters", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.26A"},
		{IEI: 0x6A, Name: "T3324 value", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.2.5"},
		{IEI: 0x67, Name: "UE radio capability ID", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.68"},
		{IEI: 0x35, Name: "Requested mapped NSSAI", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.31B"},
		{IEI: 0x48, Name: "Additional information requested", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.12A"},
		{IEI: 0x1A, Name: "Requested WUS assistance information", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.71"},
		{IEI: 0xA0, Name: "N5GC indication", Format: IEFormatTV1, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.72"},
		{IEI: 0x30, Name: "Requested NB-N1 mode DRX parameters", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.73"},
		{IEI: 0x29, Name: "UE request type", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.76"},
		{IEI: 0x28, Name: "Paging restriction", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.77"},
		{IEI: 0x72, Name: "Service-level-AA container", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.2.10"},
		{IEI: 0x32, Name: "NID", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.79"},
		{IEI: 0x16, Name: "UE determined PLMN with disaster condition", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.85"},
		{IEI: 0x2A, Name: "Requested PEIPS assistance information", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.80"},
		{IEI: 0x3B, Name: "Requested T3512 value", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.2.5"},
		{IEI: 0x3C, Name: "Unavailability information", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.2.20"},
		{IEI: 0x3F, Name: "Non-3GPP path switching information", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.102"},
		{IEI: 0x56, Name: "AUN3 indication", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.104"},
		{IEI: 0x64, Name: "Requested LP-WUSPS assistance information", Format: IEFormatTLV, Introduced: capability.Rel19, Ref: "TS 24.501 §9.11.3.111"},
	},
	IEMsgRegistrationAccept: {
		{IEI: 0x77, Name: "5G-GUTI", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.4"},
		{IEI: 0x4A, Name: "Equivalent PLMNs", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.45"},
		{IEI: 0x54, Name: "TAI list", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.9"},
		{IEI: 0x15, Name: "Allowed NSSAI", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.37"},
		{IEI: 0x11, Name: "Rejected NSSAI", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.46"},
		{IEI: 0x31, Name: "Configured NSSAI", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.37"},
		{IEI: 0x21, Name: "5GS network feature support", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.5"},
		{IEI: 0x50, Name: "PDU session status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.44"},
		{IEI: 0x26, Name: "PDU session reactivation result", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.42"},
		{IEI: 0x72, Name: "PDU session reactivation result error cause", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.43"},
		{IEI: 0x79, Name: "LADN information", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.30"},
		{IEI: 0xB0, Name: "MICO indication", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.31"},
		{IEI: 0x90, Name: "Network slicing indication", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.36"},
		{IEI: 0x27, Name: "Service area list", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.49"},
		{IEI: 0x5E, Name: "T3512 value", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.5"},
		{IEI: 0x5D, Name: "Non-3GPP de-registration timer value", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.4"},
		{IEI: 0x16, Name: "T3502 value", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.4"},
		{IEI: 0x34, Name: "Emergency number list", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.23"},
		{IEI: 0x7A, Name: "Extended emergency number list", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.26"},
		{IEI: 0x73, Name: "SOR transparent container", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.51"},
		{IEI: 0x78, Name: "EAP message", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.2"},
		{IEI: 0xA0, Name: "NSSAI inclusion mode", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.37A"},
		{IEI: 0x76, Name: "Operator-defined access category definitions", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.38"},
		{IEI: 0x51, Name: "Negotiated DRX parameters", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.2A"},
		{IEI: 0xD0, Name: "Non-3GPP NW policies", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.36A"},
		{IEI: 0x60, Name: "EPS bearer context status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.23A"},
		{IEI: 0x6E, Name: "Negotiated extended DRX parameters", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.26A"},
		{IEI: 0x6C, Name: "T3447 value", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.2.5"},
		{IEI: 0x6B, Name: "T3448 value", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.2.4"},
		{IEI: 0x6A, Name: "T3324 value", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.2.5"},
		{IEI: 0x67, Name: "UE radio capability ID", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.68"},
		{IEI: 0xE0, Name: "UE radio capability ID deletion indication", Format: IEFormatTV1, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.69"},
		{IEI: 0x39, Name: "Pending NSSAI", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.37"},
		{IEI: 0x74, Name: "Ciphering key data", Format: IEFormatTLVE, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.18C"},
		{IEI: 0x75, Name: "CAG information list", Format: IEFormatTLVE, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.18A"},
		{IEI: 0x1B, Name: "Truncated 5G-S-TMSI configuration", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.70"},
		{IEI: 0x1C, Name: "Negotiated WUS assistance information", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.71"},
		{IEI: 0x29, Name: "Negotiated NB-N1 mode DRX parameters", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.73"},
		{IEI: 0x68, Name: "Extended rejected NSSAI", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.75"},
		{IEI: 0x7B, Name: "Service-level-AA container", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.2.10"},
		{IEI: 0x33, Name: "Negotiated PEIPS assistance information", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.80"},
		{IEI: 0x35, Name: "5GS additional request result", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.81"},
		{IEI: 0x70, Name: "NSSRG information", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.82"},
		{IEI: 0x14, Name: "Disaster roaming wait range", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.84"},
		{IEI: 0x2C, Name: "Disaster return wait range", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.84"},
		{IEI: 0x13, Name: "List of PLMNs to be used in disaster condition", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.83"},
		{IEI: 0x1D, Name: "Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for roaming\"", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.9"},
		{IEI: 0x1E, Name: "Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for regional provision of service\"", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.9"},
		{IEI: 0x71, Name: "Extended CAG information list", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.86"},
		{IEI: 0x7C, Name: "NSAG information", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.87"},
		{IEI: 0x3D, Name: "Equivalent SNPNs", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.92"},
		{IEI: 0x32, Name: "NID", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.79"},
		{IEI: 0x7D, Name: "Registration accept type 6 IE container", Format: IEFormatTLVE, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.98"},
		{IEI: 0x4B, Name: "RAN timing synchronization", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.95"},
		{IEI: 0x4C, Name: "Alternative NSSAI", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.97"},
		{IEI: 0x4F, Name: "Discontinuous coverage maximum time offset", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.2.5"},
		{IEI: 0x5B, Name: "S-NSSAI time validity information", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.101"},
		{IEI: 0x3C, Name: "Unavailability configuration", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.2.21"},
		{IEI: 0x5C, Name: "Feature authorization indication", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.105"},
		{IEI: 0x61, Name: "On-demand NSSAI", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.108"},
		{IEI: 0x63, Name: "Access technology utilization control", Format: IEFormatTLV, Introduced: capability.Rel19, Ref: "TS 24.501 §9.11.3.110"},
		{IEI: 0x64, Name: "Negotiated LP-WUSPS assistance information", Format: IEFormatTLV, Introduced: capability.Rel19, Ref: "TS 24.501 §9.11.3.111"},
		{IEI: 0x80, Name: "LP-WUS status", Format: IEFormatTV1, Introduced: capability.Rel19, Ref: "TS 24.501 §9.11.3.112"},
	},
	IEMsgPDUSessionEstablishmentRequest: {
		{IEI: 0x90, Name: "PDU session type", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.4.11"},
		{IEI: 0xA0, Name: "SSC mode", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.4.16"},
		{IEI: 0x28, Name: "5GSM capability", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.4.1"},
		{IEI: 0x55, Name: "Maximum number of supported packet filters", Format: IEFormatTV, Len: 3, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.4.9"},
		{IEI: 0xB0, Name: "Always-on PDU session requested", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.4.4"},
		{IEI: 0x39, Name: "SM PDU DN request container", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.4.15"},
		{IEI: 0x7B, Name: "Extended protocol configuration options", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.4.6"},
		{IEI: 0x66, Name: "IP header compression configuration", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.4.24"},
		{IEI: 0x6E, Name: "DS-TT Ethernet port MAC address", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.4.25"},
		{IEI: 0x6F, Name: "UE-DS-TT residence time", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.4.26"},
		{IEI: 0x74, Name: "Port management information container", Format: IEFormatTLVE, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.4.27"},
		{IEI: 0x1F, Name: "Ethernet header compression configuration", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.4.28"},
		{IEI: 0x29, Name: "Suggested interface identifier", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.4.10"},
		{IEI: 0x72, Name: "Service-level-AA container", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.2.10"},
		{IEI: 0x70, Name: "Requested MBS container", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.4.30"},
		{IEI: 0x34, Name: "PDU session pair ID", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.4.32"},
		{IEI: 0x35, Name: "RSN", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.4.33"},
		{IEI: 0x36, Name: "URSP rule enforcement reports", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.4.38"},
	},
	IEMsgServiceRequest: {
		{IEI: 0x40, Name: "Uplink data status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.57"},
		{IEI: 0x50, Name: "PDU session status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.44"},
		{IEI: 0x25, Name: "Allowed PDU session status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.13"},
		{IEI: 0x71, Name: "NAS message container", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.33"},
		{IEI: 0x29, Name: "UE request type", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.76"},
		{IEI: 0x28, Name: "Paging restriction", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.77"},
	},
	IEMsgServiceAccept: {
		{IEI: 0x50, Name: "PDU session status", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.44"},
		{IEI: 0x26, Name: "PDU session reactivation result", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.42"},
		{IEI: 0x72, Name: "PDU session reactivation result error cause", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.43"},
		{IEI: 0x78, Name: "EAP message", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.2"},
		{IEI: 0x6B, Name: "T3448 value", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.2.4"},
		{IEI: 0x34, Name: "5GS additional request result", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.81"},
		{IEI: 0x1D, Name: "Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for roaming\"", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.9"},
		{IEI: 0x1E, Name: "Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for regional provision of service\"", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.9"},
	},
	IEMsgConfigurationUpdateCommand: {
		{IEI: 0xD0, Name: "Configuration update indication", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.18"},
		{IEI: 0x77, Name: "5G-GUTI", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.4"},
		{IEI: 0x54, Name: "TAI list", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.9"},
		{IEI: 0x15, Name: "Allowed NSSAI", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.37"},
		{IEI: 0x27, Name: "Service area list", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.49"},
		{IEI: 0x43, Name: "Full name for network", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.35"},
		{IEI: 0x45, Name: "Short name for network", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.35"},
		{IEI: 0x46, Name: "Local time zone", Format: IEFormatTV, Len: 2, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.52"},
		{IEI: 0x47, Name: "Universal time and local time zone", Format: IEFormatTV, Len: 8, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.53"},
		{IEI: 0x49, Name: "Network daylight saving time", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.19"},
		{IEI: 0x79, Name: "LADN information", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.30"},
		{IEI: 0xB0, Name: "MICO indication", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.31"},
		{IEI: 0x90, Name: "Network slicing indication", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.36"},
		{IEI: 0x31, Name: "Configured NSSAI", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.37"},
		{IEI: 0x11, Name: "Rejected NSSAI", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.46"},
		{IEI: 0x76, Name: "Operator-defined access category definitions", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.38"},
		{IEI: 0xF0, Name: "SMS indication", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.50A"},
		{IEI: 0x6C, Name: "T3447 value", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.2.5"},
		{IEI: 0x75, Name: "CAG information list", Format: IEFormatTLVE, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.18A"},
		{IEI: 0x67, Name: "UE radio capability ID", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.68"},
		{IEI: 0xA0, Name: "UE radio capability ID deletion indication", Format: IEFormatTV1, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.69"},
		{IEI: 0x44, Name: "5GS registration result", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.6"},
		{IEI: 0x1B, Name: "Truncated 5G-S-TMSI configuration", Format: IEFormatTLV, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.70"},
		{IEI: 0xC0, Name: "Additional configuration indication", Format: IEFormatTV1, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.74"},
		{IEI: 0x68, Name: "Extended rejected NSSAI", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.75"},
		{IEI: 0x72, Name: "Service-level-AA container", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.2.10"},
		{IEI: 0x70, Name: "NSSRG information", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.82"},
		{IEI: 0x14, Name: "Disaster roaming wait range", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.84"},
		{IEI: 0x2C, Name: "Disaster return wait range", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.84"},
		{IEI: 0x13, Name: "List of PLMNs to be used in disaster condition", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.83"},
		{IEI: 0x71, Name: "Extended CAG information list", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.86"},
		{IEI: 0x1F, Name: "Updated PEIPS assistance information", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.80"},
		{IEI: 0x73, Name: "NSAG information", Format: IEFormatTLVE, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.87"},
		{IEI: 0xE0, Name: "Priority indicator", Format: IEFormatTV1, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.3.91"},
		{IEI: 0x4B, Name: "RAN timing synchronization", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.95"},
		{IEI: 0x78, Name: "Extended LADN information", Format: IEFormatTLVE, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.96"},
		{IEI: 0x4C, Name: "Alternative NSSAI", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.97"},
		{IEI: 0x7B, Name: "S-NSSAI location validity information", Format: IEFormatTLVE, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.100"},
		{IEI: 0x5B, Name: "S-NSSAI time validity information", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.101"},
		{IEI: 0x4F, Name: "Discontinuous coverage maximum time offset", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.2.5"},
		{IEI: 0x74, Name: "Partially allowed NSSAI", Format: IEFormatTLVE, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.103"},
		{IEI: 0x7A, Name: "Partially rejected NSSAI", Format: IEFormatTLVE, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.103"},
		{IEI: 0x5C, Name: "Feature authorization indication", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.105"},
		{IEI: 0x61, Name: "On-demand NSSAI", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.108"},
		{IEI: 0x63, Name: "Access technology utilization control", Format: IEFormatTLV, Introduced: capability.Rel19, Ref: "TS 24.501 §9.11.3.110"},
		{IEI: 0x64, Name: "Updated LP-WUSPS assistance information", Format: IEFormatTLV, Introduced: capability.Rel19, Ref: "TS 24.501 §9.11.3.111"},
		{IEI: 0x80, Name: "LP-WUS status", Format: IEFormatTV1, Introduced: capability.Rel19, Ref: "TS 24.501 §9.11.3.112"},
	},
	IEMsgULNASTransport: {
		{IEI: 0x12, Name: "PDU session ID", Format: IEFormatTV, Len: 2, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.41"},
		{IEI: 0x59, Name: "Old PDU session ID", Format: IEFormatTV, Len: 2, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.41"},
		{IEI: 0x80, Name: "Request type", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.47"},
		{IEI: 0x22, Name: "S-NSSAI", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.8"},
		{IEI: 0x25, Name: "DNN", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.1B"},
		{IEI: 0x24, Name: "Additional information", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.1"},
		{IEI: 0xA0, Name: "MA PDU session information", Format: IEFormatTV1, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.31A"},
		{IEI: 0xF0, Name: "Release assistance indication", Format: IEFormatTV1, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.46A"},
		{IEI: 0x4E, Name: "Non-3GPP access path switching indication", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.99"},
		{IEI: 0x5A, Name: "Alternative S-NSSAI", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.2.8"},
		{IEI: 0x90, Name: "Payload container information", Format: IEFormatTV1, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.106"},
	},
	IEMsgDLNASTransport: {
		{IEI: 0x12, Name: "PDU session ID", Format: IEFormatTV, Len: 2, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.41"},
		{IEI: 0x24, Name: "Additional information", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.1"},
		{IEI: 0x58, Name: "5GMM cause", Format: IEFormatTV, Len: 2, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.2"},
		{IEI: 0x37, Name: "Back-off timer value", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.5"},
		{IEI: 0x3A, Name: "Lower bound timer value", Format: IEFormatTLV, Introduced: capability.Rel17, Ref: "TS 24.501 §9.11.2.5"},
	},
	IEMsgAuthenticationRequest: {
		{IEI: 0x21, Name: "Authentication parameter RAND (5G authentication challenge)", Format: IEFormatTV, Len: 17, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.16"},
		{IEI: 0x20, Name: "Authentication parameter AUTN (5G authentication challenge)", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.15"},
		{IEI: 0x78, Name: "EAP message", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.2"},
	},
	IEMsgAuthenticationResponse: {
		{IEI: 0x2D, Name: "Authentication response parameter", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.17"},
		{IEI: 0x78, Name: "EAP message", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.2"},
	},
	IEMsgSecurityModeCommand: {
		{IEI: 0xE0, Name: "IMEISV request", Format: IEFormatTV1, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.28"},
		{IEI: 0x57, Name: "Selected EPS NAS security algorithms", Format: IEFormatTV, Len: 2, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.25"},
		{IEI: 0x36, Name: "Additional 5G security information", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.12"},
		{IEI: 0x78, Name: "EAP message", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.2.2"},
		{IEI: 0x38, Name: "ABBA", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.10"},
		{IEI: 0x19, Name: "Replayed S1 UE security capabilities", Format: IEFormatTLV, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.48A"},
		{IEI: 0x55, Name: "AUN3 device security key", Format: IEFormatTLV, Introduced: capability.Rel18, Ref: "TS 24.501 §9.11.3.107"},
	},
	IEMsgSecurityModeComplete: {
		{IEI: 0x77, Name: "IMEISV", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.4"},
		{IEI: 0x71, Name: "NAS message container", Format: IEFormatTLVE, Introduced: capability.Rel15, Ref: "TS 24.501 §9.11.3.33"},
		{IEI: 0x78, Name: "non-IMEISV PEI", Format: IEFormatTLVE, Introduced: capability.Rel16, Ref: "TS 24.501 §9.11.3.4"},
	},
}

// IETable returns a copy of the optional-IE table of msg in spec order (nil if
// the message has none registered). Modifying the result does not affect the
// registered table.
func IETable(msg IEMessage) []IEDef {
	t := ieTables[msg]
	if t == nil {
		return nil
	}
	return append([]IEDef(nil), t...)
}

// LookupIE returns the definition of iei in msg. For type 1 IEs (high bit
// set, IEI in the high nibble) the low nibble of iei is ignored.
func LookupIE(msg IEMessage, iei byte) (IEDef, bool) {
	for _, d := range ieTables[msg] {
		if d.Format == IEFormatTV1 {
			if iei&0xF0 == d.IEI {
				return d, true
			}
			continue
		}
		if d.IEI == iei {
			return d, true
		}
	}
	return IEDef{}, false
}

// ieFormatByRule returns the format that TS 24.007 §11.2.4 assumes for an IE
// with unknown IEI in the 5GS protocols 5GMM and 5GSM: bit 8 set means a
// one-octet type 1 / type 2 IE; IEI 0x70-0x7F is TLV-E (type 6); 0x00-0x6F
// is TLV (type 4).
func ieFormatByRule(iei byte) IEFormat {
	switch {
	case iei&0x80 != 0:
		return IEFormatTV1 // type 1 or type 2: whole IE is one octet
	case iei&0xF0 == 0x70:
		return IEFormatTLVE
	default:
		return IEFormatTLV
	}
}

// ErrIETruncated reports an IE whose declared length overruns the message.
var ErrIETruncated = errors.New("nas: IE truncated")

// errNoIEIConsumed reports Reader.skipIE called before any IEI was read.
var errNoIEIConsumed = errors.New("nas: skip IE: no IEI consumed")

// skipIEOfFormat returns the offset just past the IE that starts at buf[off]
// given its format. Truncation yields an error, never a panic.
func skipIEOfFormat(buf []byte, off int, f IEFormat, fixedLen int) (int, error) {
	if off < 0 || off >= len(buf) {
		return off, fmt.Errorf("nas: skip IE: offset %d outside %d-byte buffer: %w", off, len(buf), ErrIETruncated)
	}
	iei := buf[off]
	var end int
	switch f {
	case IEFormatTV1, IEFormatT:
		end = off + 1
	case IEFormatTV:
		if fixedLen < 1 {
			return off, fmt.Errorf("nas: skip IE 0x%02X: TV IE without fixed length", iei)
		}
		end = off + fixedLen
	case IEFormatTLV:
		if off+2 > len(buf) {
			return off, fmt.Errorf("nas: skip IE 0x%02X: missing length octet: %w", iei, ErrIETruncated)
		}
		end = off + 2 + int(buf[off+1])
	case IEFormatTLVE:
		if off+3 > len(buf) {
			return off, fmt.Errorf("nas: skip IE 0x%02X: missing 2-octet length: %w", iei, ErrIETruncated)
		}
		end = off + 3 + (int(buf[off+1])<<8 | int(buf[off+2]))
	default:
		return off, fmt.Errorf("nas: skip IE 0x%02X: unknown format %v", iei, f)
	}
	if end > len(buf) {
		return off, fmt.Errorf("nas: skip IE 0x%02X (%v): needs %d octets, have %d: %w",
			iei, f, end-off, len(buf)-off, ErrIETruncated)
	}
	return end, nil
}

// skipUnknownIE skips the IE starting at buf[off] using only the TS 24.007
// §11.2.4 rule for unknown IEIs and returns the offset of the next IE. Unknown
// IEs in the non-imperative part are ignored (TS 24.501 §7.6.1, TS 24.007
// §11.2.5).
func skipUnknownIE(buf []byte, off int) (int, error) {
	if off < 0 || off >= len(buf) {
		return off, fmt.Errorf("nas: skip IE: offset %d outside %d-byte buffer: %w", off, len(buf), ErrIETruncated)
	}
	return skipIEOfFormat(buf, off, ieFormatByRule(buf[off]), 0)
}

// skipIE skips the IE starting at buf[off] in message msg. A known IEI uses
// the format (and fixed length) from the table, so type 3 TV IEs such as
// "Last visited registered TAI" are consumed correctly; an unknown IEI falls
// back to skipUnknownIE. Ref: TS 24.007 §11.2.4.
func skipIE(msg IEMessage, buf []byte, off int) (int, error) {
	if off < 0 || off >= len(buf) {
		return off, fmt.Errorf("nas: skip IE: offset %d outside %d-byte buffer: %w", off, len(buf), ErrIETruncated)
	}
	if d, ok := LookupIE(msg, buf[off]); ok {
		return skipIEOfFormat(buf, off, d.Format, d.Len)
	}
	return skipUnknownIE(buf, off)
}

// skipIE skips the IE whose IEI byte the reader has just consumed.
func (r *Reader) skipIE(msg IEMessage) error {
	if r.pos < 1 {
		return fmt.Errorf("nas: skip IE: %w", errNoIEIConsumed)
	}
	end, err := skipIE(msg, r.data, r.pos-1)
	if err != nil {
		return err
	}
	r.pos = end
	return nil
}
