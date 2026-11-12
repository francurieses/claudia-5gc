package nas

import (
	"fmt"
	"time"
)

// ---- Registration Request (TS 24.501 §8.2.6.1) ---------------------------

// RegistrationRequest is the decoded form of a 5GMM Registration Request message.
// Mandatory IEs are always present; optional IEs are pointer fields (nil = absent).
type RegistrationRequest struct {
	// Mandatory IEs (TS 24.501 §8.2.6.1)
	RegistrationType RegistrationType
	FollowOnRequest  FollowOnRequest
	NGKSI            NGKSI
	MobileIdentity   MobileIdentity

	// Optional IEs (type-value coded, presence indicated by IEI)
	// IEI 0x17 — Non-current native NAS key set identifier
	NonCurrentNGKSI *NGKSI
	// IEI 0x10 — 5GMM capability
	FiveGMMCapability []byte
	// IEI 0x2E — UE security capability
	UESecurityCapability *UESecurityCapability
	// IEI 0x2F — Requested NSSAI
	RequestedNSSAI *NSSAI
	// IEI 0x52 — Last visited registered TAI
	LastVisitedTAI []byte
	// IEI 0x55 — S1 UE network capability (EPS legacy)
	S1UENetworkCapability []byte
	// IEI 0x40 — Uplink data status
	UplinkDataStatus []byte
	// IEI 0x50 — PDU session status
	PDUSessionStatus []byte
	// IEI 0xB- — MICO indication
	MICOIndication *byte
	// IEI 0x2B — UE status
	UEStatus *byte
	// IEI 0x77 — Additional GUTI
	AdditionalGUTI *MobileIdentity
	// IEI 0x53 — 5GS update type value octets (TS 24.501 §9.11.3.9A)
	FiveGSUpdateType []byte
	// IEI 0x71 — NAS message container (TLV-E, TS 24.501 §9.11.3.33): raw value
	// part (the ciphered/plain inner NAS message), without IEI and length.
	NASMessageContainer []byte
}

// IEI codes for RegistrationRequest optional IEs (TS 24.501 §8.2.6.1 Table 8.2.6.1.1)
const (
	IEI5GMMCapability        = 0x10
	IEIUESecurityCapability  = 0x2E
	IEIRequestedNSSAI        = 0x2F // TS 24.501 Table 8.2.6.1.1 (was wrongly 0x6D — never matched)
	IEILastVisitedTAI        = 0x52
	IEIS1UENetworkCapability = 0x17
	IEIUplinkDataStatus      = 0x40
	IEIPDUSessionStatus      = 0x50
	IEIUEStatus              = 0x2B
	IEIAdditionalGUTI        = 0x77
	IEIAllowedPDUSessStatus  = 0x25
	IEIUEUsageSetting        = 0x18
	IEIRequestedDRX          = 0x51
	IEIEPSNASMsgContainer    = 0x70
	IEILADNIndication        = 0x74 // TLV-E (TS 24.501 §9.11.3.29); UERANSIM fork emits 0x7E
	IEIPayloadContainerReg   = 0x7B
	IEI5GSUpdateType         = 0x53
	IEINASMessageContainer   = 0x71
	IEIMICOIndication        = 0xB0 // type 1 half-octet IEI 0xB (TS 24.501 §9.11.3.31)
)

// DecodeRegistrationRequest parses the body bytes after the message type.
// Ref: TS 24.501 §8.2.6.1
func DecodeRegistrationRequest(b []byte) (*RegistrationRequest, error) {
	if len(b) < 3 {
		return nil, fmt.Errorf("nas: RegistrationRequest too short: %d", len(b))
	}
	r := &RegistrationRequest{}
	rdr := NewReader(b)

	// Octet 4 (one byte shared by two ½-octet IEs per TS 24.501 §9.6.2):
	//   upper nibble (bits 8-5): spare(1) | TSC(1) | NAS key set identifier(3)
	//   lower nibble (bits 4-1): Follow-on request(1) | 5GS registration type(3)
	combined, err := rdr.ReadByte()
	if err != nil {
		return nil, err
	}
	r.NGKSI = NGKSI{
		Type:             (combined >> 7) & 0x01,
		KeySetIdentifier: (combined >> 4) & 0x07,
	}
	r.FollowOnRequest = FollowOnRequest((combined>>3)&0x01 == 1)
	r.RegistrationType = RegistrationType(combined & 0x07)

	// 5GS Mobile Identity: mandatory LV-E (2-byte length) per TS 24.501 §8.2.6.1 Table 8.2.6.1.1.
	miHi, err := rdr.ReadByte()
	if err != nil {
		return nil, err
	}
	miLo, err := rdr.ReadByte()
	if err != nil {
		return nil, err
	}
	miBytes, err := rdr.ReadBytes(int(miHi)<<8 | int(miLo))
	if err != nil {
		return nil, fmt.Errorf("nas: mobile identity: %w", err)
	}
	mi, err := DecodeMobileIdentity(miBytes)
	if err != nil {
		return nil, err
	}
	r.MobileIdentity = *mi

	// Optional IEs. Two non-imperative error rules apply to every IE below:
	//   - TS 24.501 §7.6.3: a repeated IE whose repetition is not specified is
	//     handled only on its first occurrence; later repetitions are skipped.
	//   - TS 24.501 §7.7.1: a syntactically incorrect optional IE is treated as
	//     not present. When its length octet is intact the IE is skipped and
	//     decoding continues; when the length overruns the message the parser
	//     cannot resynchronise, so optional-IE parsing stops (same rule as the
	//     generic Reader.skipIE path).
	seen := make(map[byte]bool, 4)
	for rdr.Len() > 0 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}
		repeated := seen[iei]
		seen[iei] = true
		switch {
		case repeated:
			if err := rdr.skipIE(IEMsgRegistrationRequest); err != nil {
				return r, nil
			}
		case iei == IEI5GMMCapability:
			v, ok := readOptionalTLVValue(rdr)
			if !ok {
				return r, nil
			}
			r.FiveGMMCapability = v
		case iei == IEIUESecurityCapability:
			v, ok := readOptionalTLVValue(rdr)
			if !ok {
				return r, nil
			}
			if cap, err := DecodeUESecurityCapability(v); err == nil {
				r.UESecurityCapability = &cap
			}
		case iei == IEIRequestedNSSAI:
			v, ok := readOptionalTLVValue(rdr)
			if !ok {
				return r, nil
			}
			if nssai, err := DecodeNSSAI(v); err == nil {
				r.RequestedNSSAI = &nssai
			}
		case iei == IEIUplinkDataStatus, iei == IEIPDUSessionStatus, iei == IEI5GSUpdateType, iei == IEIUEStatus:
			// TS 24.501 §9.11.3.57, §9.11.3.44, §9.11.3.9A, §9.11.3.56 (all TLV).
			v, ok := readOptionalTLVValue(rdr)
			if !ok {
				return r, nil
			}
			switch iei {
			case IEIUplinkDataStatus:
				r.UplinkDataStatus = v
			case IEIPDUSessionStatus:
				r.PDUSessionStatus = v
			case IEI5GSUpdateType:
				r.FiveGSUpdateType = v
			case IEIUEStatus:
				if len(v) == 1 {
					b := v[0]
					r.UEStatus = &b
				}
			}
		case iei&0xF0 == IEIMICOIndication:
			// Type 1 TV: IEI in the high nibble, value in the low nibble
			// (TS 24.501 §9.11.3.31).
			b := iei & 0x0F
			r.MICOIndication = &b
		case iei == IEINASMessageContainer:
			// TLV-E: 2-byte length (TS 24.501 §9.11.3.33). Overrun = syntactically
			// incorrect: treated as absent, parsing stops (§7.7.1).
			hi, err1 := rdr.ReadByte()
			lo, err2 := rdr.ReadByte()
			if err1 != nil || err2 != nil {
				return r, nil
			}
			v, err := rdr.ReadBytes(int(hi)<<8 | int(lo))
			if err != nil {
				return r, nil
			}
			r.NASMessageContainer = append([]byte(nil), v...)
		default:
			// IEs without a dedicated case (including the TLV-E ones: NAS message
			// container 0x71, EPS NAS message container 0x70, Additional GUTI 0x77,
			// Payload container 0x7B, LADN indication 0x74, and 0x7E emitted by the
			// UERANSIM fork) are skipped by the IE table / TS 24.007 §11.2.4 rule.
			// A 1-byte length for a TLV-E IE would shift every later IE.
			// Ref: TS 24.501 §7.6.1, Table 8.2.6.1.1
			if err := rdr.skipIE(IEMsgRegistrationRequest); err != nil {
				// Syntactically incorrect optional IE: treat as not present and
				// stop optional-IE parsing. Ref: TS 24.501 §7.7.1
				return r, nil
			}
		}
	}
	return r, nil
}

// readOptionalTLVValue reads the length octet and value of a type 4 (TLV)
// optional IE whose IEI the reader has just consumed. ok is false when the
// length octet is missing or overruns the message: the IE is then syntactically
// incorrect and the remaining octets cannot be parsed (TS 24.501 §7.7.1,
// TS 24.007 §11.2.4). The returned slice aliases the message buffer.
func readOptionalTLVValue(rdr *Reader) ([]byte, bool) {
	l, err := rdr.ReadByte()
	if err != nil {
		return nil, false
	}
	v, err := rdr.ReadBytes(int(l))
	if err != nil {
		return nil, false
	}
	return v, true
}

// ---- Registration Accept (TS 24.501 §8.2.7.1) ---------------------------

// RegistrationAccept is the 5GMM Registration Accept message.
type RegistrationAccept struct {
	// Mandatory
	RegistrationResult byte

	// Optional — listed in spec order
	// IEI 0x77 — 5G-GUTI
	FiveGGUTI *MobileIdentity
	// IEI 0x4A — Equivalent PLMNs
	EquivalentPLMNs []byte
	// IEI 0x54 — TAI list
	TAIList []byte
	// IEI 0x15 — Allowed NSSAI (UERANSIM uses 0x15; TS 24.501 §8.2.7.1 uses 0x15 too)
	AllowedNSSAI *NSSAI
	// IEI 0x11 — Rejected NSSAI value (TLV, TS 24.501 §9.11.3.46). Raw value
	// octets; build with RejectedNSSAIValue. nil/empty = IE absent.
	RejectedNSSAI []byte
	// IEI 0x31 — Configured NSSAI
	ConfiguredNSSAI *NSSAI
	// IEI 0x21 — 5GS network feature support (TS 24.501 §9.11.3.5). TLV, 1-3
	// content octets. Only the first octet is populated by this encoder today
	// (IMS VoPS-3GPP bit, bit 1); see NewNetworkFeatureSupport.
	NetworkFeatureSupport []byte
	// IEI 0x50 — PDU session status
	PDUSessionStatus []byte
	// IEI 0x26 — PDU session reactivation result
	PDUSessionReactivationResult []byte
	// IEI 0x72 — PDU session reactivation result error cause (TLV-E, TS 24.501
	// §9.11.3.43). Encoded right after IEI 0x26. nil/empty = IE absent.
	PDUSessionReactivationResultErrorCause []PDUSessionErrorCause
	// IEI 0x79 — LADN information (TS 24.501 §9.11.3.30; was wrongly commented
	// 0x72 — that IEI is unassigned in Table 8.2.7.1.1). Not yet encoded.
	LADNInformation []byte
	// IEI 0x27 — Service area list (TS 24.501 §9.11.3.49; was wrongly commented
	// 0x2C — that IEI is "Disaster return wait range" in Rel-17+).
	// nil = IE absent; encoded between PDU session reactivation result and T3512.
	ServiceAreaList *ServiceAreaList
	// T3512 timer value
	T3512Value *byte
	// IEI 0x39 — Pending NSSAI (TLV, 1-byte length; TS 24.501 Table 8.2.7.1.1,
	// §9.11.3.37). nil/empty = IE absent. Sent while NSSAA is still pending.
	PendingNSSAI *NSSAI
	// IEI 0x68 — Extended rejected NSSAI (TLV, TS 24.501 §9.11.3.75, Table
	// 8.2.7.1.1: after Pending NSSAI 0x39 and the NB-N1 mode DRX IE). Only for
	// UEs with the ER-NSSAI bit set (RegistrationRequest.ERNSSAISupported). nil = absent.
	ExtendedRejectedNSSAI *ExtendedRejectedNSSAI
	// IEI 0x5D — Non-3GPP deregistration timer (TS 24.501 §9.11.2.9; was wrongly
	// commented 0x6A — that IEI is T3324 in Table 8.2.7.1.1). Not yet encoded.
	Non3GPPDeregTimer *byte
	// T3502 value
	T3502Value *byte
	// Emergency number list
	EmergencyNumberList []byte
	// IEI 0x7A — Extended emergency number list (TS 24.501 §9.11.3.65; was
	// wrongly commented 0x35 — that IEI is "5GS additional request result" in
	// Rel-17+ Table 8.2.7.1.1). Not yet encoded.
	ExtendedEmergencyNumberList []byte
	// IEI 0x90 (TV, half-octet) — Network slicing indication (TS 24.501
	// §9.11.3.36; was wrongly commented 0x9A). Not yet encoded.
	NetworkSlicingIndication *byte
}

// EncodeGPRSTimer3 encodes a duration in seconds into the GPRS Timer 3 1-byte format.
// Ref: TS 24.008 §10.5.7.4a (adopted by TS 24.501 for T3512, T3502, etc.)
// Bit layout: bits 7-5 = unit, bits 4-0 = value (0–31).
// Units are tried from coarsest to finest so that human-readable values are preferred
// (e.g. 3600 s → 1 hour, not 60 minutes).
func EncodeGPRSTimer3(seconds int) byte {
	if seconds == 0 {
		return 0x00 // timer deactivated
	}
	// unit 001: multiples of 1 h (value 1–31 → 1h–31h)
	if seconds%3600 == 0 && seconds/3600 >= 1 && seconds/3600 <= 31 {
		return byte(1<<5) | byte(seconds/3600)
	}
	// unit 000: multiples of 10 min (value 1–31 → 10min–310min)
	if seconds%(10*60) == 0 && seconds/(10*60) >= 1 && seconds/(10*60) <= 31 {
		return byte(0<<5) | byte(seconds/(10*60))
	}
	// unit 101: multiples of 1 min (value 1–31 → 1min–31min)
	if seconds%60 == 0 && seconds/60 >= 1 && seconds/60 <= 31 {
		return byte(5<<5) | byte(seconds/60)
	}
	// unit 100: multiples of 30 s (value 1–31 → 30s–930s)
	if seconds%30 == 0 && seconds/30 >= 1 && seconds/30 <= 31 {
		return byte(4<<5) | byte(seconds/30)
	}
	// unit 011: multiples of 2 s (value 1–31 → 2s–62s)
	if seconds%2 == 0 && seconds/2 >= 1 && seconds/2 <= 31 {
		return byte(3<<5) | byte(seconds/2)
	}
	// Best-effort: round to nearest minute, clamped to 31 min.
	mins := seconds / 60
	if mins > 31 {
		mins = 31
	}
	if mins == 0 {
		mins = 1
	}
	return byte(5<<5) | byte(mins)
}

// NewNetworkFeatureSupport builds the 2-octet content of the "5GS network
// feature support" IE (IEI 0x21) with only the IMS VoPS-3GPP-access bit set
// (bit 1 of the first content octet), mirroring Open5GS's default builder
// (src/amf/gmm-build.c gmm_build_registration_accept, which sets this bit to 1
// unless the operator has configured no_ims). All other bits (MPS indicator,
// IWK-without-N26, emergency service indicators, IMS VoPS over non-3GPP, and
// the second octet's CIoT/coverage bits) are left at 0 — ClaudIA does not
// implement those features.
// Ref: TS 24.501 §9.11.3.5, §8.2.7.1 Table 8.2.7.1.1 (IEI 0x21)
func NewNetworkFeatureSupport(imsVoPS3GPP bool) []byte {
	return NetworkFeatureSupport{IMSVoPS3GPP: imsVoPS3GPP}.Encode(NFSLegacyOctets)
}

// EncodeTAIList encodes a 5GS tracking area identity list containing a single
// type-00 partial list ("list of TACs belonging to one PLMN, with
// non-consecutive TAC values"). This is the registration area the UE stores;
// a UE will not send a Service Request from a TAI outside this list.
//
// Layout (TS 24.501 §9.11.3.9):
//
//	octet 1:   bit 8 spare (0) | bits 7-6 type of list (00) | bits 5-1 number of elements - 1
//	octets 2-4: MCC/MNC in BCD
//	then 3 octets per TAC (big-endian 24-bit)
//
// A type-00 partial list holds at most 16 TACs (TS 24.501 §9.11.3.9);
// extra entries are truncated. Returns nil for an empty TAC set.
func EncodeTAIList(mcc, mnc string, tacs []uint32) []byte {
	if len(tacs) == 0 {
		return nil
	}
	if len(tacs) > 16 {
		tacs = tacs[:16]
	}
	out := []byte{byte(len(tacs)-1) & 0x1F} // type of list 00 + element count
	out = append(out, encodeMCCMNC(mcc, mnc)...)
	for _, tac := range tacs {
		out = append(out, byte(tac>>16), byte(tac>>8), byte(tac))
	}
	return out
}

// EncodeRegistrationAccept serialises a RegistrationAccept into wire bytes.
// Ref: TS 24.501 §8.2.7.1
// IEI alignment validated against UERANSIM v3.2.8 RegistrationAccept::onBuild.
func EncodeRegistrationAccept(ra *RegistrationAccept) ([]byte, error) {
	// 5GS Registration Result: mandatory IE4 (LV) — length byte + value byte.
	// UERANSIM reads length byte first (DecodeIe4), then 1 byte of value.
	out := []byte{0x01, ra.RegistrationResult}

	// IEI 0x77 — 5G-GUTI (optional, IE6 = 2-byte length)
	if ra.FiveGGUTI != nil && ra.FiveGGUTI.GUTI != nil {
		gutiBytes := Encode5GGUTI(ra.FiveGGUTI.GUTI)
		length := len(gutiBytes)
		out = append(out, 0x77, byte(length>>8), byte(length))
		out = append(out, gutiBytes...)
	}

	// IEI 0x54 — TAI list (IE4 = 1-byte length)
	if len(ra.TAIList) > 0 {
		out = append(out, 0x54, byte(len(ra.TAIList)))
		out = append(out, ra.TAIList...)
	}

	// IEI 0x15 — Allowed NSSAI (IE4 = 1-byte length)
	// UERANSIM uses 0x15, not 0x70 (which is unregistered and throws Bad constructed NAS message)
	if ra.AllowedNSSAI != nil {
		nssaiBytes := EncodeNSSAI(*ra.AllowedNSSAI)
		out = append(out, 0x15, byte(len(nssaiBytes)))
		out = append(out, nssaiBytes...)
	}

	// IEI 0x11 — Rejected NSSAI (TLV, 1-byte length), between Allowed and Configured
	// NSSAI per TS 24.501 Table 8.2.7.1.1.
	if len(ra.RejectedNSSAI) > 0 {
		out = append(out, 0x11, byte(len(ra.RejectedNSSAI)))
		out = append(out, ra.RejectedNSSAI...)
	}

	// IEI 0x31 — Configured NSSAI (IE4 = 1-byte length)
	if ra.ConfiguredNSSAI != nil {
		nssaiBytes := EncodeNSSAI(*ra.ConfiguredNSSAI)
		out = append(out, 0x31, byte(len(nssaiBytes)))
		out = append(out, nssaiBytes...)
	}

	// IEI 0x21 — 5GS network feature support (TLV, 1-4 content octets, TS 24.501 V19.8.0).
	// Ref: TS 24.501 §8.2.7.1 Table 8.2.7.1.1, §9.11.3.5
	if len(ra.NetworkFeatureSupport) > 0 {
		out = append(out, 0x21, byte(len(ra.NetworkFeatureSupport)))
		out = append(out, ra.NetworkFeatureSupport...)
	}

	// IEI 0x50 — PDU session status, IEI 0x26 — PDU session reactivation result
	// (TLV), after 5GS network feature support and before T3512 value per
	// TS 24.501 Table 8.2.7.1.1; §9.11.3.44, §9.11.3.42.
	if len(ra.PDUSessionStatus) > 0 {
		out = append(out, IEIPDUSessionStatus, byte(len(ra.PDUSessionStatus)))
		out = append(out, ra.PDUSessionStatus...)
	}
	if len(ra.PDUSessionReactivationResult) > 0 {
		out = append(out, IEIPDUSessionReactivationResult, byte(len(ra.PDUSessionReactivationResult)))
		out = append(out, ra.PDUSessionReactivationResult...)
	}
	out = append(out, EncodePDUSessionReactivationResultErrorCause(ra.PDUSessionReactivationResultErrorCause)...)

	// IEI 0x27 — Service area list (TLV), after PDU session reactivation result
	// (and LADN info / MICO / NSSAI inclusion mode) and before T3512 value
	// per TS 24.501 Table 8.2.7.1.1; §9.11.3.49.
	if ra.ServiceAreaList != nil {
		tlv, err := EncodeServiceAreaList(ra.ServiceAreaList)
		if err != nil {
			return nil, err
		}
		out = append(out, tlv...)
	}

	// IEI 0x5E — T3512 value (TLV: IEI + 1-byte length + 1-byte GPRS Timer 3 value)
	// Spec says TV (length=2) but UERANSIM v3.2.8 decodes it as TLV (reads length byte first).
	// Ref: TS 24.501 §8.2.7.1 Table 8.2.7.1.1, §9.11.3.48
	if ra.T3512Value != nil {
		out = append(out, 0x5E, 0x01, *ra.T3512Value)
	}

	// IEI 0x39 — Pending NSSAI (TLV, 1-byte length). Last in Table 8.2.7.1.1 among the
	// IEs this encoder emits (follows T3512 value).
	if ra.PendingNSSAI != nil {
		if nssaiBytes := EncodeNSSAI(*ra.PendingNSSAI); len(nssaiBytes) > 0 {
			out = append(out, 0x39, byte(len(nssaiBytes)))
			out = append(out, nssaiBytes...)
		}
	}

	// IEI 0x68 — Extended rejected NSSAI (TLV), Table 8.2.7.1.1: after Pending NSSAI.
	if ra.ExtendedRejectedNSSAI != nil {
		tlv, err := encodeExtendedRejectedNSSAITLV(ra.ExtendedRejectedNSSAI)
		if err != nil {
			return nil, err
		}
		out = append(out, tlv...)
	}

	// NOTE: URSP / UE policies are NOT carried in Registration Accept. They are
	// delivered via the UE policy delivery service over DL NAS TRANSPORT after
	// registration (payload container type "UE policy container", 0x05).
	// Ref: TS 23.502 §4.2.4.3, TS 24.501 Annex D

	return out, nil
}

// DecodeRegistrationAccept parses a RegistrationAccept body.
func DecodeRegistrationAccept(b []byte) (*RegistrationAccept, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("nas: RegistrationAccept too short")
	}
	ra := &RegistrationAccept{}
	rdr := NewReader(b)
	// IE4 (mandatory LV): length byte + value byte
	l, _ := rdr.ReadByte()
	valBytes, _ := rdr.ReadBytes(int(l))
	if len(valBytes) > 0 {
		ra.RegistrationResult = valBytes[0]
	}

	for rdr.Len() > 0 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}
		switch iei {
		case 0x77: // 5G-GUTI — IE6 (2-byte length)
			hi, _ := rdr.ReadByte()
			lo, _ := rdr.ReadByte()
			length := int(hi)<<8 | int(lo)
			gutiBytes, _ := rdr.ReadBytes(length)
			mi, _ := DecodeMobileIdentity(gutiBytes)
			ra.FiveGGUTI = mi
		case 0x54: // TAI list — IE4 (1-byte length), raw value kept as-is
			l, _ := rdr.ReadByte()
			taiBytes, _ := rdr.ReadBytes(int(l))
			ra.TAIList = taiBytes
		case 0x15: // Allowed NSSAI — IE4 (1-byte length), UERANSIM uses 0x15
			l, _ := rdr.ReadByte()
			nssaiBytes, _ := rdr.ReadBytes(int(l))
			nssai, _ := DecodeNSSAI(nssaiBytes)
			ra.AllowedNSSAI = &nssai
		case 0x31: // Configured NSSAI — IE4 (1-byte length)
			l, _ := rdr.ReadByte()
			nssaiBytes, _ := rdr.ReadBytes(int(l))
			nssai, _ := DecodeNSSAI(nssaiBytes)
			ra.ConfiguredNSSAI = &nssai
		case 0x11: // Rejected NSSAI — TLV (1-byte length), raw value kept
			l, _ := rdr.ReadByte()
			ra.RejectedNSSAI, _ = rdr.ReadBytes(int(l))
		case IEIExtendedRejectedNSSAI: // Extended rejected NSSAI — TLV (1-byte length)
			l, err := rdr.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("nas: registration accept: extended rejected NSSAI length: %w", err)
			}
			v, err := rdr.ReadBytes(int(l))
			if err != nil {
				return nil, fmt.Errorf("nas: registration accept: extended rejected NSSAI: %w", err)
			}
			if ra.ExtendedRejectedNSSAI, err = DecodeExtendedRejectedNSSAI(v); err != nil {
				return nil, fmt.Errorf("nas: registration accept: %w", err)
			}
		case 0x39: // Pending NSSAI — TLV (1-byte length)
			l, _ := rdr.ReadByte()
			nssaiBytes, _ := rdr.ReadBytes(int(l))
			nssai, _ := DecodeNSSAI(nssaiBytes)
			ra.PendingNSSAI = &nssai
		case IEIPDUSessionReactivationResultErrorCause: // TLV-E (2-byte length)
			lb, err := rdr.ReadBytes(2)
			if err != nil {
				return ra, nil
			}
			v, err := rdr.ReadBytes(int(lb[0])<<8 | int(lb[1]))
			if err != nil {
				return ra, nil
			}
			if list, err := DecodePDUSessionReactivationResultErrorCause(v); err == nil {
				ra.PDUSessionReactivationResultErrorCause = list
			}
		case 0x27: // Service area list — TLV (1-byte length)
			l, _ := rdr.ReadByte()
			v, _ := rdr.ReadBytes(int(l))
			if sal, err := DecodeServiceAreaListValue(v); err == nil {
				ra.ServiceAreaList = sal
			}
		case 0x21: // 5GS network feature support — TLV (1-byte length, 1-4 content octets, TS 24.501 V19.8.0)
			l, _ := rdr.ReadByte()
			nfsBytes, _ := rdr.ReadBytes(int(l))
			ra.NetworkFeatureSupport = nfsBytes
		case 0x5E: // T3512 value — TLV (1-byte length + 1-byte GPRS Timer 3 value)
			l, _ := rdr.ReadByte()
			valB, _ := rdr.ReadBytes(int(l))
			if len(valB) > 0 {
				v := valB[0]
				ra.T3512Value = &v
			}
		default:
			// Unknown / unhandled optional IE: skip per the IE table or the
			// TS 24.007 §11.2.4 rule (TS 24.501 §7.6.1).
			if err := rdr.skipIE(IEMsgRegistrationAccept); err != nil {
				// Syntactically incorrect optional IE: treat as not present and
				// stop optional-IE parsing. Ref: TS 24.501 §7.7.1
				return ra, nil
			}
		}
	}
	return ra, nil
}

// RegistrationComplete is the 5GMM Registration Complete message (no body IEs).
type RegistrationComplete struct{}

// RegistrationReject is the body of a 5GMM Registration Reject (0x44).
// Contains a mandatory 5GMM Cause IE. Ref: TS 24.501 §8.2.9
type RegistrationReject struct {
	// Cause5GMM — TS 24.501 §9.11.3.2.
	// 0x49 = cause 73 = "Serving network not authorized" (Service Area Restriction).
	Cause5GMM byte

	// RejectedNSSAI is the optional Rejected NSSAI IE (IEI 0x69, TLV,
	// TS 24.501 §9.11.3.46), sent with cause #62. Empty = IE absent.
	RejectedNSSAI []RejectedSNSSAI

	// ExtendedRejectedNSSAI is the optional Extended rejected NSSAI IE
	// (IEI 0x68, TLV, TS 24.501 §9.11.3.75). nil = IE absent.
	ExtendedRejectedNSSAI *ExtendedRejectedNSSAI

	// T3346 is the optional T3346 value IE (IEI 0x5F, GPRS timer 2,
	// TS 24.501 §9.11.2.4). nil = IE absent; a zero duration encodes as
	// 0 x 2 s (not "deactivated"). Ref: TS 24.501 §8.2.9.1.
	T3346 *time.Duration
}

// IEIRegistrationRejectT3346 is the T3346 value IEI in REGISTRATION REJECT
// (TS 24.501 §8.2.9.1, Table 8.2.9.1.1).
const IEIRegistrationRejectT3346 = 0x5F

// GPRSTimer2Deactivated is the GPRS timer 2 octet meaning "timer deactivated"
// (unit bits 111). Ref: TS 24.008 §10.5.7.4, TS 24.501 §9.11.2.4.
const GPRSTimer2Deactivated byte = 0xE0

// EncodeGPRSTimer2 encodes d as a GPRS timer 2 value octet (unit in bits 8-6:
// 000 = 2 s, 001 = 1 min, 010 = decihours (6 min); value in bits 5-1).
// It picks the finest unit whose value fits in 5 bits, rounding up to the unit;
// durations above 31 decihours (3 h 6 min) or negative are rejected.
// Ref: TS 24.008 §10.5.7.4, TS 24.501 §9.11.2.4.
func EncodeGPRSTimer2(d time.Duration) (byte, error) {
	if d < 0 {
		return 0, fmt.Errorf("nas: GPRS timer 2: negative duration %s", d)
	}
	units := []struct {
		unit byte
		step time.Duration
	}{{0x00, 2 * time.Second}, {0x20, time.Minute}, {0x40, 6 * time.Minute}}
	for _, u := range units {
		v := (d + u.step - 1) / u.step
		if v <= 31 {
			return u.unit | byte(v), nil
		}
	}
	return 0, fmt.Errorf("nas: GPRS timer 2: duration %s exceeds 31 decihours", d)
}

// IEIRegistrationRejectRejectedNSSAI is the Rejected NSSAI IEI in REGISTRATION
// REJECT (TS 24.501 §8.2.9.1, Table 8.2.9.1.1).
const IEIRegistrationRejectRejectedNSSAI = 0x69

// EncodeRegistrationReject encodes a Registration Reject body: cause, then
// optional IEs in Table 8.2.9.1.1 order (Rejected NSSAI 0x69 precedes Extended
// rejected NSSAI 0x68). With no optional IEs the output is exactly {cause}.
// The common header (EPD + SHT + MsgType) is prepended by the NAS encoder.
// Ref: TS 24.501 §8.2.9
func EncodeRegistrationReject(r *RegistrationReject) ([]byte, error) {
	out := []byte{r.Cause5GMM}
	if r.T3346 != nil {
		t, err := EncodeGPRSTimer2(*r.T3346)
		if err != nil {
			return nil, err
		}
		out = append(out, IEIRegistrationRejectT3346, 0x01, t)
	}
	if len(r.RejectedNSSAI) > 0 {
		rej, err := EncodeRejectedNSSAI(r.RejectedNSSAI)
		if err != nil {
			return nil, err
		}
		out = append(out, IEIRegistrationRejectRejectedNSSAI, byte(len(rej)))
		out = append(out, rej...)
	}
	if r.ExtendedRejectedNSSAI != nil {
		tlv, err := encodeExtendedRejectedNSSAITLV(r.ExtendedRejectedNSSAI)
		if err != nil {
			return nil, err
		}
		out = append(out, tlv...)
	}
	return out, nil
}

// RejectedNSSAIValue builds the RegistrationAccept.RejectedNSSAI value octets
// (TS 24.501 §9.11.3.46) from a typed list.
func RejectedNSSAIValue(list []RejectedSNSSAI) ([]byte, error) {
	return EncodeRejectedNSSAI(list)
}

// Capability5GMM returns the decoded 5GMM capability IE of this REGISTRATION
// REQUEST, or nil when the IE is absent or empty (treated as not present,
// TS 24.501 §7.7.1). FiveGMMCapability keeps the raw value octets.
// Ref: TS 24.501 §9.11.3.1
func (r *RegistrationRequest) Capability5GMM() *FiveGMMCapability {
	if r == nil {
		return nil
	}
	c, err := Decode5GMMCapability(r.FiveGMMCapability)
	if err != nil {
		return nil
	}
	return c
}
