package procedures

// nfs_config.go — operator YAML model for the optional bits of the 5GS network
// feature support IE (IEI 0x21, TS 24.501 §9.11.3.5) beyond IMS-VoPS-3GPP
// (REL19-5.5). Every field defaults to false, which keeps the Registration
// Accept byte-identical to the legacy 2-octet form.

import "github.com/francurieses/claudia-5gc/shared/nas"

// NetworkFeatureSupportConfig lists the 5GS network feature support bits the
// operator wants the AMF to advertise. A bit reaches the wire only if (1) it
// is set here, (2) the UE set the matching 5GMM capability bit in its
// REGISTRATION REQUEST (TS 24.501 §5.5.1.2.4) and (3) for bits introduced after
// Rel-17 (un_per, lcs_upp, supl, rslp, mlcsup, ef5l) the capability feature
// NAS-NFS-EXT is enabled through the release profile (release.profile: rel19
// and release.features.NAS-NFS-EXT: true).
//
// YAML (under operator.network_feature_support):
//
//	ncr: true      # octet 5 bit 4, N1 NAS signalling connection release (Rel-17)
//	piv: true      # octet 5 bit 5, paging indication for voice services (Rel-17)
//	rpr: true      # octet 5 bit 6, reject paging request (Rel-17)
//	pr: true       # octet 5 bit 7, paging restriction (Rel-17)
//	un_per: true   # octet 5 bit 8 (Rel-18)
//	lcs_upp: true  # octet 6 bit 2 (Rel-18)
//	supl: true     # octet 6 bit 3 (Rel-18)
//	rslp: true     # octet 6 bit 4 (Rel-18)
//	mlcsup: true   # octet 6 bit 5 (Rel-19), needs lcs_upp
//	ef5l: true     # octet 6 bit 6 (Rel-19)
//
// Ref: TS 24.501 §9.11.3.5, §5.5.1.2.4.
type NetworkFeatureSupportConfig struct {
	NCR    bool `yaml:"ncr"`
	PIV    bool `yaml:"piv"`
	RPR    bool `yaml:"rpr"`
	PR     bool `yaml:"pr"`
	UNPER  bool `yaml:"un_per"`
	LCSUPP bool `yaml:"lcs_upp"`
	SUPL   bool `yaml:"supl"`
	RSLP   bool `yaml:"rslp"`
	MLCSUP bool `yaml:"mlcsup"`
	EF5L   bool `yaml:"ef5l"`
}

// Bits converts the configuration to the typed IE model. A nil receiver (block
// absent from the YAML) yields the zero value, i.e. the legacy form.
func (c *NetworkFeatureSupportConfig) Bits() nas.NetworkFeatureSupport {
	if c == nil {
		return nas.NetworkFeatureSupport{}
	}
	return nas.NetworkFeatureSupport{
		NCR: c.NCR, PIV: c.PIV, RPR: c.RPR, PR: c.PR, UNPER: c.UNPER,
		LCSUPP: c.LCSUPP, SUPL: c.SUPL, RSLP: c.RSLP, MLCSUP: c.MLCSUP, EF5L: c.EF5L,
	}
}
