// Package apiversion holds the hand-maintained table mapping each SBI service
// to its (apiVersionInUri, apiFullVersion) pair for the rel17 and rel19
// profiles. These are the values an NF advertises in NFServiceVersion when it
// registers with the NRF [TS 29.510 §6.1.6.2.19 NFServiceVersion; the
// apiVersionInUri/apiFullVersion semantics follow TS 29.501 §4.3.1 API
// version numbers].
//
// Full versions are transcribed from the `info.version` field of the 3GPP
// OpenAPI YAML of the Rel-17 and Rel-19 branches of the 5G_APIs repository;
// the URI major version comes from the `servers:` URL. Step 3.2 of the Rel-19
// plan (tools/openapi-drift) validates this table against the YAMLs, which is
// why every entry records its TS and YAML name and the whole table is
// exported through [All].
//
// The package is a leaf: it must not import shared/nrf (which will import sbi
// packages), only shared/capability.
package apiversion

import (
	"sort"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// Service is the SBI service name as used in the TS 29.510 ServiceName enum
// (the standard key), e.g. "namf-comm".
type Service string

// Services covered by the table.
const (
	NamfComm            Service = "namf-comm"
	NausfAuth           Service = "nausf-auth"
	NbsfManagement      Service = "nbsf-management"
	NlmfLoc             Service = "nlmf-loc"
	AsSessionWithQoS    Service = "3gpp-as-session-with-qos"
	NnssfNSSelection    Service = "nnssf-nsselection"
	NpcfAMPolicyControl Service = "npcf-am-policy-control"
	NpcfSMPolicyControl Service = "npcf-smpolicycontrol"
	NpcfUEPolicyControl Service = "npcf-ue-policy-control"
	NpcfPolicyAuth      Service = "npcf-policyauthorization"
	NsmfPDUSession      Service = "nsmf-pdusession"
	NsmsfSMS            Service = "nsmsf-sms"
	NudmUEAU            Service = "nudm-ueau"
	NudmSDM             Service = "nudm-sdm"
	NudmUECM            Service = "nudm-uecm"
	NudrDR              Service = "nudr-dr"
	NnrfNFManagement    Service = "nnrf-nfm"
	NnrfNFDiscovery     Service = "nnrf-disc"
	N32cHandshake       Service = "n32c-handshake"
)

// Profile names understood by [ProfileName].
const (
	ProfileRel17 = "rel17"
	ProfileRel19 = "rel19"
)

// Version is the API version pair advertised for a service.
type Version struct {
	// InURI is apiVersionInUri, e.g. "v1".
	InURI string
	// Full is apiFullVersion (semver), e.g. "1.2.8".
	Full string
}

// Entry is one row of the table.
type Entry struct {
	Service Service
	// Spec is the owning TS, e.g. "TS 29.518".
	Spec string
	// YAML is the OpenAPI file base name in specs/3gpp-openapi/<Rel-NN>/.
	YAML string
	// InURI is apiVersionInUri (identical in both profiles).
	InURI string
	// Rel17 and Rel19 are apiFullVersion per profile (YAML info.version).
	Rel17, Rel19 string
}

// Version returns the entry's Version for the given profile name.
func (e Entry) Version(profile string) Version {
	if profile == ProfileRel19 {
		return Version{InURI: e.InURI, Full: e.Rel19}
	}
	return Version{InURI: e.InURI, Full: e.Rel17}
}

var table = []Entry{
	{NamfComm, "TS 29.518", "TS29518_Namf_Communication", "v1", "1.2.8", "1.4.3"},
	{NausfAuth, "TS 29.509", "TS29509_Nausf_UEAuthentication", "v1", "1.2.3", "1.4.0"},
	{NbsfManagement, "TS 29.521", "TS29521_Nbsf_Management", "v1", "1.3.2", "1.5.0"},
	{NlmfLoc, "TS 29.572", "TS29572_Nlmf_Location", "v1", "1.2.7", "1.4.2"},
	{AsSessionWithQoS, "TS 29.122", "TS29122_AsSessionWithQoS", "v1", "1.2.3", "1.4.2"},
	{NnssfNSSelection, "TS 29.531", "TS29531_Nnssf_NSSelection", "v2", "2.2.2", "2.4.0"},
	{NpcfAMPolicyControl, "TS 29.507", "TS29507_Npcf_AMPolicyControl", "v1", "1.2.2", "1.4.2"},
	{NpcfSMPolicyControl, "TS 29.512", "TS29512_Npcf_SMPolicyControl", "v1", "1.2.6", "1.4.2"},
	{NpcfUEPolicyControl, "TS 29.525", "TS29525_Npcf_UEPolicyControl", "v1", "1.2.2", "1.4.2"},
	{NpcfPolicyAuth, "TS 29.514", "TS29514_Npcf_PolicyAuthorization", "v1", "1.2.3", "1.4.2"},
	{NsmfPDUSession, "TS 29.502", "TS29502_Nsmf_PDUSession", "v1", "1.2.8", "1.4.2"},
	{NsmsfSMS, "TS 29.540", "TS29540_Nsmsf_SMService", "v2", "2.2.1", "2.4.1"},
	{NudmUEAU, "TS 29.503", "TS29503_Nudm_UEAU", "v1", "1.2.2", "1.4.0"},
	{NudmSDM, "TS 29.503", "TS29503_Nudm_SDM", "v2", "2.2.12", "2.4.2"},
	{NudmUECM, "TS 29.503", "TS29503_Nudm_UECM", "v1", "1.2.7", "1.4.2"},
	{NudrDR, "TS 29.504", "TS29504_Nudr_DR", "v2", "2.2.12", "2.4.2"},
	{NnrfNFManagement, "TS 29.510", "TS29510_Nnrf_NFManagement", "v1", "1.2.9", "1.4.2"},
	{NnrfNFDiscovery, "TS 29.510", "TS29510_Nnrf_NFDiscovery", "v1", "1.2.8", "1.4.2"},
	{N32cHandshake, "TS 29.573", "TS29573_N32_Handshake", "v1", "1.2.1", "1.4.1"},
}

// ProfileName resolves a release profile to the table column: Rel-19 and
// above map to "rel19", everything else (including a nil profile) to "rel17".
func ProfileName(p *capability.Profile) string {
	if p != nil && p.Release() >= capability.Rel19 {
		return ProfileRel19
	}
	return ProfileRel17
}

// Lookup returns the Version of svc for profile p (nil means rel17).
func Lookup(p *capability.Profile, svc Service) (Version, bool) {
	for _, e := range table {
		if e.Service == svc {
			return e.Version(ProfileName(p)), true
		}
	}
	return Version{}, false
}

// Of is Lookup without the found flag, for registration code. Every Service
// constant in this package is present in the table (enforced by
// TestEveryConstantInTable), so it only returns the zero Version for a
// Service value made up by the caller.
func Of(p *capability.Profile, svc Service) Version {
	v, _ := Lookup(p, svc)
	return v
}

// All returns a copy of the whole table sorted by service name, for
// programmatic consumers such as the OpenAPI drift checker. Use
// [Entry.Version] or the Rel17/Rel19 fields to read a column.
func All() []Entry {
	out := make([]Entry, len(table))
	copy(out, table)
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}
