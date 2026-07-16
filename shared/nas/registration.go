package nas

import (
	"fmt"
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

	// Optional IEs (TLV format)
	for rdr.Len() > 0 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}
		switch iei {
		case IEI5GMMCapability:
			l, err := rdr.ReadByte()
			if err != nil {
				return nil, err
			}
			r.FiveGMMCapability, err = rdr.ReadBytes(int(l))
			if err != nil {
				return nil, err
			}
		case IEIUESecurityCapability:
			l, err := rdr.ReadByte()
			if err != nil {
				return nil, err
			}
			capBytes, err := rdr.ReadBytes(int(l))
			if err != nil {
				return nil, err
			}
			cap, err := DecodeUESecurityCapability(capBytes)
			if err != nil {
				return nil, err
			}
			r.UESecurityCapability = &cap
		case IEIRequestedNSSAI:
			l, err := rdr.ReadByte()
			if err != nil {
				return nil, err
			}
			nssaiBytes, err := rdr.ReadBytes(int(l))
			if err != nil {
				return nil, err
			}
			nssai, err := DecodeNSSAI(nssaiBytes)
			if err != nil {
				return nil, err
			}
			r.RequestedNSSAI = &nssai
		case IEINASMessageContainer, IEIEPSNASMsgContainer, IEIAdditionalGUTI,
			IEIPayloadContainerReg, IEILADNIndication, 0x7E:
			// TLV-E IEs (2-byte big-endian length): NAS message container (0x71),
			// EPS NAS message container (0x70), Additional GUTI (0x77), Payload
			// container (0x7B), LADN indication (0x74 per spec; 0x7E in the
			// UERANSIM fork). Skipping these with a 1-byte length would shift
			// the parser and corrupt every subsequent IE.
			// Ref: TS 24.501 Table 8.2.6.1.1, TS 24.007 §11.2.1.1.4
			hi, err := rdr.ReadByte()
			if err != nil {
				break
			}
			lo, err := rdr.ReadByte()
			if err != nil {
				break
			}
			_, _ = rdr.ReadBytes(int(hi)<<8 | int(lo))
		default:
			// Unknown optional IE: skip (TV/TLV)
			// Try TLV format (IEI >= 0x80 are TV with value in low nibble)
			if iei < 0x80 {
				l, err := rdr.ReadByte()
				if err != nil {
					break
				}
				_, _ = rdr.ReadBytes(int(l))
			}
			// TV (1-byte value, IEI >= 0x80): already consumed IEI byte
		}
	}
	return r, nil
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
	// IEI 0x11 — Rejected NSSAI
	RejectedNSSAI []byte
	// IEI 0x31 — Configured NSSAI
	ConfiguredNSSAI *NSSAI
	// IEI 0x21 — Network feature support
	NetworkFeatureSupport []byte
	// IEI 0x50 — PDU session status
	PDUSessionStatus []byte
	// IEI 0x26 — PDU session reactivation result
	PDUSessionReactivationResult []byte
	// IEI 0x72 — LADN information
	LADNInformation []byte
	// IEI 0x2C — Service area list
	ServiceAreaList []byte
	// T3512 timer value
	T3512Value *byte
	// IEI 0x6A — Non-3GPP deregistration timer
	Non3GPPDeregTimer *byte
	// T3502 value
	T3502Value *byte
	// Emergency number list
	EmergencyNumberList []byte
	// IEI 0x35 — Extended emergency number list
	ExtendedEmergencyNumberList []byte
	// IEI 0x9A — Network slicing indication
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

	// IEI 0x31 — Configured NSSAI (IE4 = 1-byte length)
	if ra.ConfiguredNSSAI != nil {
		nssaiBytes := EncodeNSSAI(*ra.ConfiguredNSSAI)
		out = append(out, 0x31, byte(len(nssaiBytes)))
		out = append(out, nssaiBytes...)
	}

	// IEI 0x5E — T3512 value (TLV: IEI + 1-byte length + 1-byte GPRS Timer 3 value)
	// Spec says TV (length=2) but UERANSIM v3.2.8 decodes it as TLV (reads length byte first).
	// Ref: TS 24.501 §8.2.7.1 Table 8.2.7.1.1, §9.11.3.48
	if ra.T3512Value != nil {
		out = append(out, 0x5E, 0x01, *ra.T3512Value)
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
		case 0x5E: // T3512 value — TLV (1-byte length + 1-byte GPRS Timer 3 value)
			l, _ := rdr.ReadByte()
			valB, _ := rdr.ReadBytes(int(l))
			if len(valB) > 0 {
				v := valB[0]
				ra.T3512Value = &v
			}
		default:
			// Skip unknown optional TLV IEs; TV IEs (IEI >= 0x80) have no length byte
			if iei < 0x80 {
				l, err := rdr.ReadByte()
				if err != nil {
					break
				}
				_, _ = rdr.ReadBytes(int(l))
			}
		}
	}
	return ra, nil
}

// RegistrationComplete is the 5GMM Registration Complete message (no body IEs).
type RegistrationComplete struct{}

// RegistrationReject is the body of a 5GMM Registration Reject (0x44).
// Contains a mandatory 5GMM Cause IE. Ref: TS 24.501 §8.2.8.2
type RegistrationReject struct {
	// Cause5GMM — TS 24.501 §9.11.3.2.
	// 0x49 = cause 73 = "Serving network not authorized" (Service Area Restriction).
	Cause5GMM byte
}

// EncodeRegistrationReject encodes a Registration Reject body (1 byte: cause).
// The common header (EPD + SHT + MsgType) is prepended by the NAS encoder.
// Ref: TS 24.501 §8.2.8.2
func EncodeRegistrationReject(r *RegistrationReject) ([]byte, error) {
	return []byte{r.Cause5GMM}, nil
}
