// Package n32c implements the SEPP N32-c Security Capability Negotiation
// (exchange-capability) for TLS security mode: wire types, the per-PLMN N32
// context store, the responder handler and the initiator client.
//
// Wire types are hand-written from TS29573_N32_Handshake.yaml (Rel-17 and
// Rel-19, no codegen). PRINS is out of scope: this SEPP only offers and
// selects TLS. Rel-19-only IEs are decoded for tolerance but ignored; they
// are never stored and never emitted.
//
// Ref: TS 29.573 §5.2.2, §6.1.4.2, §6.1.5.2, §6.1.6.3, §6.1.7.
package n32c

import (
	"fmt"
	"strings"
)

// SecurityCapability is the extensible enum of TS 29.573 §6.1.6.3.3
// (anyOf enum | free string): unknown values must be tolerated.
type SecurityCapability string

// Known SecurityCapability values.
const (
	// CapTLS selects TLS protection of N32-f. Ref: TS 29.573 §6.1.6.3.3.
	CapTLS SecurityCapability = "TLS"
	// CapPRINS selects application-layer protection (out of scope here).
	CapPRINS SecurityCapability = "PRINS"
	// CapNone requests N32-f TLS teardown; valid only with feature NFTLST.
	// Ref: TS 29.573 §5.2.2, §6.1.5.3.3.
	CapNone SecurityCapability = "NONE"
)

// N32Purpose is the extensible N32 usage purpose enum. Ref: TS 29.573 §6.1.6.3.
type N32Purpose string

// PurposeRoaming is the only purpose this NF sends. Ref: TS 29.573 §6.1.6.3.
const PurposeRoaming N32Purpose = "ROAMING"

// IntendedN32Purpose is the purpose container. Ref: TS 29.573 §6.1.5.3.9.
// oapi: TS29573_N32_Handshake.yaml#/components/schemas/IntendedN32Purpose
type IntendedN32Purpose struct {
	UsagePurpose   N32Purpose `json:"usagePurpose"`
	AdditionalInfo string     `json:"additionalInfo,omitempty"`
	Cause          string     `json:"cause,omitempty"`
}

// PlmnId is the TS 29.571 §5.4.4.3 PlmnId (mcc 3 digits, mnc 2 or 3 digits).
// oapi: TS29571_CommonData.yaml#/components/schemas/PlmnId
type PlmnId struct {
	Mcc string `json:"mcc"`
	Mnc string `json:"mnc"`
}

// Canonical returns the PLMN with the MNC left-padded to three digits, the
// form used in the Home Network Domain label (TS 23.003 §28.2), so that
// "01" and "001" compare equal.
func (p PlmnId) Canonical() PlmnId {
	mnc := p.Mnc
	for len(mnc) < 3 {
		mnc = "0" + mnc
	}
	return PlmnId{Mcc: p.Mcc, Mnc: mnc}
}

// Key returns the canonical "mcc-mnc" string (TS 29.571 §5.4.4.3 note).
func (p PlmnId) Key() string { c := p.Canonical(); return c.Mcc + "-" + c.Mnc }

// String renders the canonical PLMN as "mcc/mnc" for logs, so the same PLMN
// is logged identically whether it came from config ("02") or from a peer
// FQDN label ("mnc002", TS 23.003 §28.2).
func (p PlmnId) String() string { c := p.Canonical(); return c.Mcc + "/" + c.Mnc }

// Valid reports whether mcc is 3 digits and mnc 2 or 3 digits.
func (p PlmnId) Valid() bool {
	return allDigits(p.Mcc, 3, 3) && allDigits(p.Mnc, 2, 3)
}

func allDigits(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// SecNegotiateReqData is the exchange-capability request body.
// Ref: TS 29.573 §6.1.5.2.2 and TS29573_N32_Handshake.yaml.
// oapi: TS29573_N32_Handshake.yaml#/components/schemas/SecNegotiateReqData
type SecNegotiateReqData struct {
	Sender string `json:"sender"`
	// SupportedSecCapabilityList is nil when absent and non-nil-empty for
	// "[]", so the handler can tell MANDATORY_IE_MISSING from _INCORRECT.
	SupportedSecCapabilityList []SecurityCapability `json:"supportedSecCapabilityList"`
	// TargetAPIRootSupported is IE "3GppSbiTargetApiRootSupported" (the name
	// breaks TS 29.501 naming on purpose); default false.
	TargetAPIRootSupported bool                 `json:"3GppSbiTargetApiRootSupported,omitempty"`
	PlmnIDList             []PlmnId             `json:"plmnIdList,omitempty"`
	TargetPlmnID           *PlmnId              `json:"targetPlmnId,omitempty"`
	IntendedUsagePurpose   []IntendedN32Purpose `json:"intendedUsagePurpose,omitempty"`
	SupportedFeatures      string               `json:"supportedFeatures,omitempty"`

	// Rel-19-only IEs: decoded, ignored, never stored, never emitted by this
	// NF (the Rel-17 profile must not carry them).
	N32HandshakeID     string `json:"n32HandshakeId,omitempty"`
	SenderN32fFqdn     string `json:"senderN32fFqdn,omitempty"`
	SenderN32fPortList []int  `json:"senderN32fPortList,omitempty"`
	N32KeepaliveTimer  *int   `json:"n32KeepaliveTimer,omitempty"`
}

// SecNegotiateRspData is the exchange-capability 200 response body.
// Ref: TS 29.573 §6.1.5.2.3.
// oapi: TS29573_N32_Handshake.yaml#/components/schemas/SecNegotiateRspData
type SecNegotiateRspData struct {
	Sender                 string               `json:"sender"`
	SelectedSecCapability  SecurityCapability   `json:"selectedSecCapability"`
	TargetAPIRootSupported bool                 `json:"3GppSbiTargetApiRootSupported,omitempty"`
	PlmnIDList             []PlmnId             `json:"plmnIdList,omitempty"`
	AllowedUsagePurpose    []IntendedN32Purpose `json:"allowedUsagePurpose,omitempty"`
	RejectedUsagePurpose   []IntendedN32Purpose `json:"rejectedUsagePurpose,omitempty"`
	SupportedFeatures      string               `json:"supportedFeatures,omitempty"`

	// Rel-19-only IEs: decoded for tolerance, never emitted by this NF.
	// n32HandshakeId is deliberately not echoed: SEPP-001 does not support
	// the N32 handshake identifier (TS 29.573 §5.2.2 step 2a makes echoing
	// conditional on support; support is optional).
	N32HandshakeID    string `json:"n32HandshakeId,omitempty"`
	SenderN32fFqdn    string `json:"senderN32fFqdn,omitempty"`
	SenderN32fPort    *int   `json:"senderN32fPort,omitempty"`
	N32KeepaliveTimer *int   `json:"n32KeepaliveTimer,omitempty"`
}

// ProblemDetails is the TS 29.571 §5.2.4.1 error body (TS 29.500 §5.2.7).
// oapi: TS29571_CommonData.yaml#/components/schemas/ProblemDetails
type ProblemDetails struct {
	Title  string `json:"title,omitempty"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Cause  string `json:"cause,omitempty"`
	// InvalidParams lists the offending attributes of a 400 reply.
	// Ref: TS 29.500 Table 5.2.7.2-1 NOTE 1; TS 29.571 §5.2.4.1.
	InvalidParams []InvalidParam `json:"invalidParams,omitempty"`
}

// InvalidParam names one invalid attribute and why. Ref: TS 29.571 §5.2.4.1.
type InvalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason,omitempty"`
}

// Application and generic error causes.
const (
	// CauseNegotiationNotAllowed: TS 29.573 §6.1.4.2.2 Table 6.1.4.2.2-2, §6.1.6.3 (403).
	CauseNegotiationNotAllowed = "NEGOTIATION_NOT_ALLOWED"
	// CauseExchangeOngoing: TS 29.573 §5.2.2 step 2b, §6.1.6.3 Table 6.1.6.3-1 (409, Rel-19).
	CauseExchangeOngoing = "N32C_EXCHANGE_CAPABILITY_ONGOING"
	// CauseMandatoryIEMissing: TS 29.500 Table 5.2.7.2-1 (400).
	CauseMandatoryIEMissing = "MANDATORY_IE_MISSING"
	// CauseMandatoryIEIncorrect: TS 29.500 Table 5.2.7.2-1 (400).
	CauseMandatoryIEIncorrect = "MANDATORY_IE_INCORRECT"
	// CauseInvalidMsgFormat: TS 29.500 Table 5.2.7.2-1 (400).
	CauseInvalidMsgFormat = "INVALID_MSG_FORMAT"
)

// Home Network Domain handling for SEPP FQDNs.
// Ref: TS 23.003 §28.5.1, §28.2; TS 29.510 §6.1.6.2.72.
const homeNetworkDomainSuffix = "3gppnetwork.org"

// ParsePLMNFromFQDN extracts the PLMN from the trailing
// "mnc<MNC>.mcc<MCC>.3gppnetwork.org" of a SEPP FQDN (the check is on the
// trailing Home Network Domain, not the first label). A 2- or 3-digit MNC is
// accepted. Ref: TS 23.003 §28.5.1.
func ParsePLMNFromFQDN(fqdn string) (PlmnId, error) {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(fqdn), "."), ".")
	n := len(labels)
	if n < 4 || strings.Join(labels[n-2:], ".") != homeNetworkDomainSuffix {
		return PlmnId{}, fmt.Errorf("n32c: parse fqdn %q: not under %s", fqdn, homeNetworkDomainSuffix)
	}
	mncL, mccL := labels[n-4], labels[n-3]
	if !strings.HasPrefix(mncL, "mnc") || !strings.HasPrefix(mccL, "mcc") {
		return PlmnId{}, fmt.Errorf("n32c: parse fqdn %q: missing mnc/mcc labels", fqdn)
	}
	p := PlmnId{Mcc: strings.TrimPrefix(mccL, "mcc"), Mnc: strings.TrimPrefix(mncL, "mnc")}
	if !p.Valid() {
		return PlmnId{}, fmt.Errorf("n32c: parse fqdn %q: invalid mcc/mnc", fqdn)
	}
	return p, nil
}

// N32fContextInfo is the N32-f context information body.
// It carries the PRINS-only n32fContextId, so this TLS-only SEPP never
// produces or stores one; the type exists for wire completeness.
// Ref: TS 29.573 §6.1.5.2.10.
//
// oapi: TS29573_N32_Handshake.yaml#/components/schemas/N32fContextInfo
type N32fContextInfo struct {
	// N32fContextID matches ^[A-Fa-f0-9]{16}$.
	N32fContextID string `json:"n32fContextId"`
}
