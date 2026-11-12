// Per-gNB release capability (REL19-4.8): inference from the NG Setup Request
// and the operator override ngap.ran_profiles.

package ngap

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// DefaultRANRelease is the release assumed for a gNB that gives no evidence of
// a newer one (plan REL19-4.8: "an unknown gNB is Rel-17"). It is also the
// floor of the inference.
const DefaultRANRelease = capability.Rel17

// maxRANRelease caps inference and override: the newest release this AMF
// knows the NGAP ASN.1 of (shared/ngap is generated from TS 38.413 Rel-19).
const maxRANRelease = capability.Rel19

// ngSetupIERelease classifies each top-level NG SETUP REQUEST IE by the
// release that introduced it. Verified by diffing the NGSetupRequestIEs
// object set of TS 38.413 V17.15.0, V18.11.0 and V19.4.0 (ASN.1 section 9.4.4):
//   - ids 27, 82, 102, 21, 147, 204 and 273 (Extended RAN Node Name) are all
//     present in V17.15.0, so they sit at the Rel-17 floor;
//   - id 475 (AIoT-Support) and 483 (AdditionalULI) are absent from V18.11.0
//     and present in V19.4.0, hence Rel-19.
//
// An id missing from this table is treated as the newest known release.
var ngSetupIERelease = map[int64]capability.Release{
	ngapType.ProtocolIEIDGlobalRANNodeID:        capability.Rel17,
	ngapType.ProtocolIEIDRANNodeName:            capability.Rel17,
	ngapType.ProtocolIEIDSupportedTAList:        capability.Rel17,
	ngapType.ProtocolIEIDDefaultPagingDRX:       capability.Rel17,
	ngapType.ProtocolIEIDUERetentionInformation: capability.Rel17,
	ngapType.ProtocolIEIDNBIoTDefaultPagingDRX:  capability.Rel17,
	ngapType.ProtocolIEIDExtendedRANNodeName:    capability.Rel17,
	ngapType.ProtocolIEIDAIoTSupport:            capability.Rel19,
	ngapType.ProtocolIEIDAdditionalULI:          capability.Rel19,
}

// ngSetupExtIERelease classifies the extension IEs of SupportedTAItem
// (ConfiguredTACIndication 272, RAT-Information 179) and BroadcastPLMNItem
// (NPN-Support 258, ExtendedTAISliceSupportList 271, TAINSAGSupportList 353).
// Same extension sets in TS 38.413 V17.15.0, V18.11.0 and V19.4.0
// (SupportedTAItem-ExtIEs, BroadcastPLMNItem-ExtIEs), so all are at the
// Rel-17 floor; any other extension id is treated as the newest release.
var ngSetupExtIERelease = map[int64]capability.Release{
	ngapType.ProtocolIEIDConfiguredTACIndication:     capability.Rel17,
	ngapType.ProtocolIEIDRATInformation:              capability.Rel17,
	ngapType.ProtocolIEIDNPNSupport:                  capability.Rel17,
	ngapType.ProtocolIEIDExtendedTAISliceSupportList: capability.Rel17,
	ngapType.ProtocolIEIDTAINSAGSupportList:          capability.Rel17,
}

func releaseOf(table map[int64]capability.Release, id int64) capability.Release {
	if r, ok := table[id]; ok {
		return r
	}
	return maxRANRelease
}

func clampRANRelease(r capability.Release) capability.Release {
	if r < DefaultRANRelease {
		return DefaultRANRelease
	}
	if r > maxRANRelease {
		return maxRANRelease
	}
	return r
}

// InferRANRelease returns the release evidenced by an NG SETUP REQUEST: the
// maximum release over its IEs (top level and the Supported TA / Broadcast
// PLMN extension IEs), floored at DefaultRANRelease and capped at Rel-19.
// A nil request yields the default. It never panics on partial decodes.
// Ref: TS 38.413 §9.2.6.1, §9.4.4.
func InferRANRelease(req *ngapType.NGSetupRequest) capability.Release {
	rel := DefaultRANRelease
	if req == nil {
		return rel
	}
	bump := func(r capability.Release) {
		if r > rel {
			rel = r
		}
	}
	for _, ie := range req.ProtocolIEs.List {
		bump(releaseOf(ngSetupIERelease, ie.Id.Value))
		if ie.Value.SupportedTAList == nil {
			continue
		}
		for _, ta := range ie.Value.SupportedTAList.List {
			if ta.IEExtensions != nil {
				for _, x := range ta.IEExtensions.List {
					bump(releaseOf(ngSetupExtIERelease, x.Id.Value))
				}
			}
			for _, bp := range ta.BroadcastPLMNList.List {
				if bp.IEExtensions == nil {
					continue
				}
				for _, x := range bp.IEExtensions.List {
					bump(releaseOf(ngSetupExtIERelease, x.Id.Value))
				}
			}
		}
	}
	return clampRANRelease(rel)
}

// RANProfileConfig is one ngap.ran_profiles entry. Exactly one of
// GlobalRANNodeID / GNBName selects the gNB.
type RANProfileConfig struct {
	// GlobalRANNodeID is the gNB ID as GlobalRANNode.IDString() renders it
	// ("<hex>/<bit length>", e.g. "000001/24"); compared case-insensitively.
	GlobalRANNodeID string `yaml:"global_ran_node_id"`
	// GNBName is a path.Match glob over the RAN Node Name IE.
	GNBName string `yaml:"gnb_name"`
	// MaxRelease is "Rel-17", "Rel-18" or "Rel-19" ("rel18" and "18" also work).
	MaxRelease string `yaml:"max_release"`
}

type ranProfile struct {
	id      string
	name    string
	max     capability.Release
	hasName bool
}

// RANProfiles is the validated operator override table. The zero value (and
// nil) matches nothing.
type RANProfiles struct {
	profiles []ranProfile
}

// ParseRANRelease accepts "Rel-17", "rel17", "Rel17" or "17" for 17..19.
func ParseRANRelease(s string) (capability.Release, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	v = strings.TrimPrefix(v, "rel")
	v = strings.TrimPrefix(v, "-")
	n, err := strconv.Atoi(v)
	if err != nil || n < int(DefaultRANRelease) || n > int(maxRANRelease) {
		return 0, fmt.Errorf("ngap: ran release %q: want Rel-17, Rel-18 or Rel-19", s)
	}
	return capability.Release(n), nil
}

// NewRANProfiles validates cfg: each entry needs exactly one selector, a valid
// glob and a valid max_release.
func NewRANProfiles(cfg []RANProfileConfig) (*RANProfiles, error) {
	out := &RANProfiles{}
	seen := make(map[string]int, len(cfg))
	for i, c := range cfg {
		id := strings.ToLower(strings.TrimSpace(c.GlobalRANNodeID))
		name := strings.TrimSpace(c.GNBName)
		if (id == "") == (name == "") {
			return nil, fmt.Errorf("ngap: ran_profiles[%d]: exactly one of global_ran_node_id and gnb_name is required", i)
		}
		key := "id:" + id
		if name != "" {
			key = "name:" + name
		}
		if j, dup := seen[key]; dup {
			return nil, fmt.Errorf("ngap: ran_profiles[%d]: duplicate selector of ran_profiles[%d]", i, j)
		}
		seen[key] = i
		max, err := ParseRANRelease(c.MaxRelease)
		if err != nil {
			return nil, fmt.Errorf("ngap: ran_profiles[%d]: %w", i, err)
		}
		if name != "" {
			if _, err := path.Match(name, ""); err != nil {
				return nil, fmt.Errorf("ngap: ran_profiles[%d]: gnb_name pattern %q: %w", i, name, err)
			}
		}
		out.profiles = append(out.profiles, ranProfile{id: id, name: name, max: max, hasName: name != ""})
	}
	return out, nil
}

// Resolve returns the effective release of a gNB and whether an override
// matched. An ID match beats a name match; within each kind the first entry
// wins. max_release only caps: effective = min(inferred, max_release); it never
// raises a gNB above what its NG Setup Request evidences.
func (p *RANProfiles) Resolve(node GlobalRANNode, name string, inferred capability.Release) (capability.Release, bool) {
	inferred = clampRANRelease(inferred)
	if p == nil {
		return inferred, false
	}
	idStr := strings.ToLower(node.IDString())
	var byName *ranProfile
	for i := range p.profiles {
		pr := &p.profiles[i]
		if !pr.hasName {
			if idStr != "" && pr.id == idStr {
				return min(inferred, pr.max), true
			}
			continue
		}
		if byName == nil && name != "" {
			if ok, _ := path.Match(pr.name, name); ok {
				byName = pr
			}
		}
	}
	if byName != nil {
		return min(inferred, byName.max), true
	}
	return inferred, false
}

// PeerRAN returns the gNB's recorded release capability for the Gate API
// (capability.Gate). A gNB that has not completed NG Setup is Rel-17.
func (g *GNBContext) PeerRAN() capability.PeerRAN {
	g.mu.Lock()
	defer g.mu.Unlock()
	return capability.PeerRAN{Release: clampRANRelease(g.release)}
}

// appendICSRel18PlusIEs is the capability.Gate point for IEs that Rel-18+ added
// to INITIAL CONTEXT SETUP REQUEST (TS 38.413 §9.2.2.1). No such IE is emitted
// today, so it returns ieList unchanged for every gNB; a future step appends
// them here, in spec order after the Rel-17 IEs, only when
// capability.Gate(ctx, featureID, ranCap) allows. Rel-17 bytes stay frozen
// (TestLegacyGNBByteIdentical).
func appendICSRel18PlusIEs(ieList []ngapType.InitialContextSetupRequestIEs, ranCap capability.PeerRAN) []ngapType.InitialContextSetupRequestIEs {
	_ = ranCap
	return ieList
}

// appendPSRRel18PlusIEs is the capability.Gate point for Rel-18+ IEs of PDU
// SESSION RESOURCE SETUP REQUEST (TS 38.413 §9.2.1.1); a no-op today, see
// appendICSRel18PlusIEs.
func appendPSRRel18PlusIEs(ies *ngapType.ProtocolIEContainerPDUSessionResourceSetupRequestIEs, ranCap capability.PeerRAN) {
	_, _ = ies, ranCap
}
