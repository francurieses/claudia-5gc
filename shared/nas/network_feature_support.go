package nas

// network_feature_support.go — typed model of the "5GS network feature
// support" information element (IEI 0x21, TLV, TS 24.501 §9.11.3.5) with a
// release-bounded encoder (REL19-5.5).
//
// The IE has 2..4 content octets in TS 24.501 V19.8.0 (type 4, total length
// 3..6; V17.18.1 allowed 3 content octets). A receiver reads missing trailing
// octets as zero, so the encoder never emits a trailing zero octet beyond the
// legacy 2-octet form: a legacy UE therefore sees byte-identical output unless
// the caller both allows the extended form and sets a bit in it.
//
// Content octet n is "octet n+2" in the TS figure. Bit release table
// (vs V17.18.1 / V18.14.0 / V19.8.0 text):
//
//	octet 3 (content 1) and octet 4 (content 2) all bits      Rel-15/16/17
//	octet 5 (content 3) bits 1-3 LCS, ATS-IND, EHC-CP CIoT     Rel-16/17
//	octet 5 bits 4-7 NCR, PIV, RPR, PR                         Rel-17 (in V17.18.1)
//	octet 5 bit 8 UN-PER                                       Rel-18
//	octet 6 (content 4) bits 1-4 NAPS, LCS-UPP, SUPL, RSLP     Rel-18
//	octet 6 bits 5-6 MLCSUP, EF5L                              Rel-19
//
// Ref: TS 24.501 §9.11.3.5 Figure 9.11.3.5.1, Table 9.11.3.5.1.

import "fmt"

// Content-octet counts of the 5GS network feature support IE.
const (
	// NFSLegacyOctets is the content length the AMF has always emitted
	// (octets 3 and 4 of the IE); it is also the Rel-17 baseline form.
	NFSLegacyOctets = 2
	// NFSMaxOctets is the maximum content length in TS 24.501 V19.8.0
	// (IE length 6 minus IEI and length octets).
	// Ref: TS 24.501 §9.11.3.5.
	NFSMaxOctets = 4
)

// NetworkFeatureSupport holds the bits of the 5GS network feature support IE.
// Two-bit fields (EMC, EMF, RestrictEC) carry the raw 0..3 value.
type NetworkFeatureSupport struct {
	// --- content octet 1 (octet 3) ---

	IMSVoPS3GPP  bool  // bit 1, IMS-VoPS-3GPP
	IMSVoPSN3GPP bool  // bit 2, IMS-VoPS-N3GPP
	EMC          uint8 // bits 4-3, emergency services support (3GPP access)
	EMF          uint8 // bits 6-5, emergency services fallback (3GPP access)
	IWKN26       bool  // bit 7, 1 = interworking without N26 interface supported
	MPSI         bool  // bit 8, MPS indicator

	// --- content octet 2 (octet 4) ---

	EMCN3      bool  // bit 1, emergency services over non-3GPP access
	MCSI       bool  // bit 2, MCS indicator
	RestrictEC uint8 // bits 4-3, restriction on enhanced coverage
	CPCIoT     bool  // bit 5, 5G-CP CIoT
	// N3DataNotSupported is bit 6, INVERTED: 1 = N3 data transfer NOT supported.
	N3DataNotSupported bool
	IPHCCPCIoT         bool // bit 7, 5G-IPHC-CP CIoT
	UPCIoT             bool // bit 8, 5G-UP CIoT

	// --- content octet 3 (octet 5) ---

	LCS       bool // bit 1, 5G-LCS (Rel-16)
	ATSInd    bool // bit 2, ATSSS support (Rel-16)
	EHCCPCIoT bool // bit 3, 5G-EHC-CP CIoT (Rel-16)
	NCR       bool // bit 4, N1 NAS signalling connection release (Rel-17)
	PIV       bool // bit 5, paging indication for voice services (Rel-17)
	RPR       bool // bit 6, reject paging request (Rel-17)
	PR        bool // bit 7, paging restriction (Rel-17)
	UNPER     bool // bit 8, UN-PER (Rel-18)

	// --- content octet 4 (octet 6) ---

	NAPS   bool // bit 1, non-3GPP access path switching (Rel-18)
	LCSUPP bool // bit 2, LCS-UPP user plane positioning (Rel-18)
	SUPL   bool // bit 3, SUPL user plane positioning (Rel-18)
	RSLP   bool // bit 4, ranging and sidelink positioning (Rel-18)
	MLCSUP bool // bit 5, multiple LCS secured UP connections (Rel-19)
	EF5L   bool // bit 6, ExtendedFacility IE for 5G LCS (Rel-19)
	// bits 7-8 of octet 6 are spare (0).
}

func nfsBit(b bool, bit uint) byte {
	if b {
		return 1 << (bit - 1)
	}
	return 0
}

// octets returns the full 4 content octets.
func (n NetworkFeatureSupport) octets() [NFSMaxOctets]byte {
	return [NFSMaxOctets]byte{
		nfsBit(n.IMSVoPS3GPP, 1) | nfsBit(n.IMSVoPSN3GPP, 2) | (n.EMC&0x03)<<2 |
			(n.EMF&0x03)<<4 | nfsBit(n.IWKN26, 7) | nfsBit(n.MPSI, 8),
		nfsBit(n.EMCN3, 1) | nfsBit(n.MCSI, 2) | (n.RestrictEC&0x03)<<2 |
			nfsBit(n.CPCIoT, 5) | nfsBit(n.N3DataNotSupported, 6) | nfsBit(n.IPHCCPCIoT, 7) | nfsBit(n.UPCIoT, 8),
		nfsBit(n.LCS, 1) | nfsBit(n.ATSInd, 2) | nfsBit(n.EHCCPCIoT, 3) | nfsBit(n.NCR, 4) |
			nfsBit(n.PIV, 5) | nfsBit(n.RPR, 6) | nfsBit(n.PR, 7) | nfsBit(n.UNPER, 8),
		nfsBit(n.NAPS, 1) | nfsBit(n.LCSUPP, 2) | nfsBit(n.SUPL, 3) | nfsBit(n.RSLP, 4) |
			nfsBit(n.MLCSUP, 5) | nfsBit(n.EF5L, 6),
	}
}

// HasExtendedBits reports whether any bit beyond the legacy 2 content octets
// (octets 5 and 6 of the TS figure) is set.
func (n NetworkFeatureSupport) HasExtendedBits() bool {
	o := n.octets()
	return o[2] != 0 || o[3] != 0
}

// Encode returns the IE content (without IEI/length). The first
// NFSLegacyOctets octets are always emitted. Octets 3..maxOctets are emitted
// only up to the last non-zero one, so trailing zero octets are never sent
// beyond the legacy length. maxOctets is clamped to
// [NFSLegacyOctets, NFSMaxOctets]; pass NFSLegacyOctets for the byte-identical
// legacy form (extended bits are dropped).
// Ref: TS 24.501 §9.11.3.5 (missing trailing octets are interpreted as 0).
func (n NetworkFeatureSupport) Encode(maxOctets int) []byte {
	maxOctets = min(max(maxOctets, NFSLegacyOctets), NFSMaxOctets)
	o := n.octets()
	last := NFSLegacyOctets
	for i := NFSLegacyOctets; i < maxOctets; i++ {
		if o[i] != 0 {
			last = i + 1
		}
	}
	return append([]byte(nil), o[:last]...)
}

// DecodeNetworkFeatureSupport parses the IE content. Receivers are tolerant:
// 1..NFSMaxOctets octets are accepted with missing octets read as zero, and
// octets beyond NFSMaxOctets (future releases) are ignored. An empty content
// is an error.
// Ref: TS 24.501 §9.11.3.5, §7.7.1.
func DecodeNetworkFeatureSupport(b []byte) (*NetworkFeatureSupport, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("nas: decode 5gs network feature support: empty content")
	}
	var o [NFSMaxOctets]byte
	copy(o[:], b)
	bit := func(v byte, n uint) bool { return v&(1<<(n-1)) != 0 }
	return &NetworkFeatureSupport{
		IMSVoPS3GPP: bit(o[0], 1), IMSVoPSN3GPP: bit(o[0], 2),
		EMC: o[0] >> 2 & 3, EMF: o[0] >> 4 & 3,
		IWKN26: bit(o[0], 7), MPSI: bit(o[0], 8),
		EMCN3: bit(o[1], 1), MCSI: bit(o[1], 2), RestrictEC: o[1] >> 2 & 3,
		CPCIoT: bit(o[1], 5), N3DataNotSupported: bit(o[1], 6), IPHCCPCIoT: bit(o[1], 7), UPCIoT: bit(o[1], 8),
		LCS: bit(o[2], 1), ATSInd: bit(o[2], 2), EHCCPCIoT: bit(o[2], 3), NCR: bit(o[2], 4),
		PIV: bit(o[2], 5), RPR: bit(o[2], 6), PR: bit(o[2], 7), UNPER: bit(o[2], 8),
		NAPS: bit(o[3], 1), LCSUPP: bit(o[3], 2), SUPL: bit(o[3], 3), RSLP: bit(o[3], 4),
		MLCSUP: bit(o[3], 5), EF5L: bit(o[3], 6),
	}, nil
}

// LimitToUECapability returns n with every bit that TS 24.501 §5.5.1.2.4 /
// §5.5.1.3.4 allows only when the UE indicated the matching 5GMM capability
// bit in the REGISTRATION REQUEST cleared unless the UE set it. Mapping
// (NFS bit <- 5GMM capability bit, same name): NCR, PIV, RPR, PR, UN-PER,
// LCS-UPP, SUPL, MLCSUP, EF5L, RSLP. MLCSUP also requires LCS-UPP to be set
// (§5.5.1.2.4) and PR requires RPR and/or NCR (§5.5.1.2.4). A nil capability (no 5GMM capability IE) clears all of them.
// Bits not tied to a UE capability bit are left untouched.
// Ref: TS 24.501 §5.5.1.2.4, §5.5.1.3.4, §9.11.3.1, §9.11.3.5.
func (n NetworkFeatureSupport) LimitToUECapability(c *FiveGMMCapability) NetworkFeatureSupport {
	if c == nil {
		c = &FiveGMMCapability{}
	}
	n.NCR = n.NCR && c.NCR
	n.PIV = n.PIV && c.PIV
	n.RPR = n.RPR && c.RPR
	// PR only together with RPR and/or NCR (§5.5.1.2.4), after those are limited.
	n.PR = n.PR && c.PR && (n.RPR || n.NCR)
	n.UNPER = n.UNPER && c.UNPER
	n.LCSUPP = n.LCSUPP && c.LCSUPP
	n.SUPL = n.SUPL && c.SUPL
	n.RSLP = n.RSLP && c.RSLP
	n.EF5L = n.EF5L && c.EF5L
	n.MLCSUP = n.MLCSUP && c.MLCSUP && n.LCSUPP
	return n
}

// DropAfterRel17 returns n with the bits introduced after Rel-17 cleared
// (UN-PER and all of octet 6), leaving the Rel-16/17 bits of octets 3-5.
// Ref: TS 24.501 §9.11.3.5 (release table above).
func (n NetworkFeatureSupport) DropAfterRel17() NetworkFeatureSupport {
	n.UNPER = false
	n.NAPS, n.LCSUPP, n.SUPL, n.RSLP, n.MLCSUP, n.EF5L = false, false, false, false, false, false
	return n
}
