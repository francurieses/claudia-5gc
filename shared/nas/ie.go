// IE (Information Elements) for NAS-5GS messages.
// Ref: 3GPP TS 24.501 §9.11.x
package nas

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// ---- 5GS Mobile Identity (TS 24.501 §9.11.3.4) ---------------------------

// MobileIdentityType per TS 24.501 Table 9.11.3.4.1
type MobileIdentityType byte

const (
	MobileIdentityNoIdentity MobileIdentityType = 0
	MobileIdentitySUCI       MobileIdentityType = 1
	MobileIdentityGUTI       MobileIdentityType = 2
	MobileIdentityIMEI       MobileIdentityType = 4
	MobileIdentityGUTI5G     MobileIdentityType = 2 // alias
	MobileIdentityTMSI       MobileIdentityType = 3
	MobileIdentityIMEISV     MobileIdentityType = 5
	MobileIdentityMAC        MobileIdentityType = 6
	MobileIdentityEUI64      MobileIdentityType = 7
)

// MobileIdentity is the decoded 5GS Mobile Identity IE.
type MobileIdentity struct {
	Type MobileIdentityType

	// SUCI fields (Type == MobileIdentitySUCI)
	SUCI *SUCIMobileIdentity

	// GUTI fields (Type == MobileIdentityGUTI)
	GUTI *GUTIMobileIdentity

	// IMEI/IMEISV (Type == MobileIdentityIMEI or IMEISV)
	IMEISV string
}

// SUCIMobileIdentity holds the decoded SUCI from the mobile identity IE.
type SUCIMobileIdentity struct {
	SUPIFormat             byte   // 0=IMSI, 1=NAI
	MCC                    string // e.g. "001"
	MNC                    string // e.g. "01"
	RoutingIndicator       string // 4-digit BCD
	ProtectionSchemeID     byte   // 0=null, 1=ProfileA, 2=ProfileB
	HomeNetworkPublicKeyID byte
	SchemeOutput           []byte
}

// GUTIMobileIdentity holds a 5G-GUTI.
type GUTIMobileIdentity struct {
	MCC         string
	MNC         string
	AMFRegionID byte
	AMFSetID    uint16 // 10 bits
	AMFID       byte   // 6 bits
	TMSI        uint32
}

// Encode5GGUTI encodes a GUTIMobileIdentity as the 5GS Mobile Identity IE bytes
// (without the IEI byte and length prefix — those are added by the message encoder).
// Ref: TS 24.501 §9.11.3.4, format Figure 9.11.3.4.4
func Encode5GGUTI(g *GUTIMobileIdentity) []byte {
	// Octet 3 per TS 24.501 Figure 9.11.3.4.1 (5G-GUTI): bits 8-5 are spare and
	// shall be coded as "1111", bit 4 = 0 (even), bits 3-1 = type 010 (5G-GUTI)
	// → 0xF2. (Audit fix: previously encoded as 0x02 with zero spare bits;
	// UERANSIM and free5GC-style decoders read only the low 3 bits, so this is
	// wire-compatible, but 0xF2 is the conformant coding.)
	out := []byte{
		0xF0 | byte(MobileIdentityGUTI),
	}
	// MCC (3 digits BCD) + MNC (2 or 3 digits BCD) — 3 bytes total
	out = append(out, encodeMCCMNC(g.MCC, g.MNC)...)
	// AMF Region ID
	out = append(out, g.AMFRegionID)
	// AMF Set ID (10 bits) + AMF ID (6 bits) = 2 bytes
	amfRef := uint16(g.AMFSetID&0x3FF)<<6 | uint16(g.AMFID&0x3F)
	out = append(out, byte(amfRef>>8), byte(amfRef))
	// 5G-TMSI (4 bytes)
	tmsi := make([]byte, 4)
	binary.BigEndian.PutUint32(tmsi, g.TMSI)
	out = append(out, tmsi...)
	return out
}

// DecodeMobileIdentity parses the value bytes of a 5GS Mobile Identity IE.
func DecodeMobileIdentity(b []byte) (*MobileIdentity, error) {
	if len(b) < 1 {
		return nil, errors.New("nas: mobile identity empty")
	}
	mi := &MobileIdentity{}
	idType := MobileIdentityType(b[0] & 0x07)
	mi.Type = idType

	switch idType {
	case MobileIdentitySUCI:
		suci, err := decodeSUCI(b)
		if err != nil {
			return nil, err
		}
		mi.SUCI = suci
	case MobileIdentityGUTI:
		guti, err := decodeGUTI(b)
		if err != nil {
			return nil, err
		}
		mi.GUTI = guti
	}
	return mi, nil
}

func decodeSUCI(b []byte) (*SUCIMobileIdentity, error) {
	if len(b) < 8 {
		return nil, errors.New("nas: SUCI too short")
	}
	suci := &SUCIMobileIdentity{}
	suci.SUPIFormat = (b[0] >> 3) & 0x07 // bits 5-3 of byte 0
	suci.MCC, suci.MNC = decodeMCCMNC(b[1:4])
	// Routing Indicator: up to 4 decimal digits, BCD low-nibble-first with 0xF
	// padding (TS 24.501 §9.11.3.4). Previously decoded with a wrong nibble
	// order, an 8-bit shift that always overflowed to 0, and %04X hex
	// formatting — only RI "0000" survived by luck.
	suci.RoutingIndicator = decodeRoutingIndicator(b[4:6])
	suci.ProtectionSchemeID = b[6] & 0x0F
	suci.HomeNetworkPublicKeyID = b[7]
	suci.SchemeOutput = append([]byte(nil), b[8:]...)
	return suci, nil
}

// decodeRoutingIndicator decodes the 2-byte BCD Routing Indicator field.
// Digits are packed low-nibble-first; a 0xF nibble marks the end of the digit
// string (RIs shorter than 4 digits are padded with 0xF).
func decodeRoutingIndicator(b []byte) string {
	digits := make([]byte, 0, 4)
	for _, byt := range b {
		for _, nib := range [2]byte{byt & 0x0F, (byt >> 4) & 0x0F} {
			if nib == 0x0F {
				if len(digits) == 0 {
					return "0" // RI "absent" (all-F) — treat as default 0 per TS 23.003 §2.7.4.2
				}
				return string(digits)
			}
			digits = append(digits, '0'+nib)
		}
	}
	return string(digits)
}

func decodeGUTI(b []byte) (*GUTIMobileIdentity, error) {
	if len(b) < 11 {
		return nil, fmt.Errorf("nas: GUTI too short: %d", len(b))
	}
	g := &GUTIMobileIdentity{}
	g.MCC, g.MNC = decodeMCCMNC(b[1:4])
	g.AMFRegionID = b[4]
	amfRef := uint16(b[5])<<8 | uint16(b[6])
	g.AMFSetID = amfRef >> 6
	g.AMFID = byte(amfRef & 0x3F)
	g.TMSI = binary.BigEndian.Uint32(b[7:11])
	return g, nil
}

// ---- NSSAI / S-NSSAI (TS 24.501 §9.11.3.37) ------------------------------

// SNSSAI is a Single Network Slice Selection Assistance Information.
type SNSSAI struct {
	SST uint8  // Slice/Service Type (1 byte)
	SD  uint32 // Slice Differentiator (3 bytes, 0xFFFFFF = not set)
}

const SDNotPresent uint32 = 0xFFFFFF

// SDFromString converts a 6-hex-char SD string (e.g. "000001") to uint32.
// Returns SDNotPresent if the string is empty or unparseable.
func SDFromString(sd string) uint32 {
	if len(sd) == 0 {
		return SDNotPresent
	}
	b, err := hex.DecodeString(sd)
	if err != nil || len(b) != 3 {
		return SDNotPresent
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

// NSSAI is a list of S-NSSAIs.
type NSSAI struct {
	SNSSAIs []SNSSAI
}

// EncodeNSSAI encodes an NSSAI IE value (without IEI + length prefix).
func EncodeNSSAI(n NSSAI) []byte {
	var out []byte
	for _, s := range n.SNSSAIs {
		if s.SD == SDNotPresent {
			out = append(out, 1, s.SST)
		} else {
			sd := []byte{byte(s.SD >> 16), byte(s.SD >> 8), byte(s.SD)}
			out = append(out, 4, s.SST)
			out = append(out, sd...)
		}
	}
	return out
}

// DecodeNSSAI parses an NSSAI IE value.
func DecodeNSSAI(b []byte) (NSSAI, error) {
	var n NSSAI
	i := 0
	for i < len(b) {
		if i >= len(b) {
			break
		}
		length := int(b[i])
		i++
		if i+length > len(b) {
			return n, fmt.Errorf("nas: NSSAI truncated")
		}
		s := SNSSAI{SD: SDNotPresent}
		s.SST = b[i]
		if length == 4 {
			s.SD = uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
		}
		n.SNSSAIs = append(n.SNSSAIs, s)
		i += length
	}
	return n, nil
}

// ---- 5GS Registration Type (TS 24.501 §9.11.3.7) -------------------------

type RegistrationType byte

const (
	RegistrationTypeInitial     RegistrationType = 1
	RegistrationTypeMobility    RegistrationType = 2
	RegistrationTypePeriodic    RegistrationType = 3
	RegistrationTypeEmergency   RegistrationType = 4
)

// FollowOnRequestPending bit (bit 4 of octet 1)
type FollowOnRequest bool

const (
	FollowOnPending  FollowOnRequest = true
	FollowOnNoPending FollowOnRequest = false
)

// ---- NAS Key Set Identifier (TS 24.501 §9.11.3.32) -----------------------

// NGKSI identifies the NAS key set.
type NGKSI struct {
	KeySetIdentifier byte  // 0-6; 7 = no key is available
	Type             byte  // 0=native, 1=mapped
}

// ---- NAS Security Algorithms (TS 24.501 §9.11.3.34) ----------------------

// NASSecurityAlgorithms holds the selected ciphering + integrity algorithms.
type NASSecurityAlgorithms struct {
	// CipheringAlgorithmID: 0=NEA0, 1=128-NEA1, 2=128-NEA2, 3=128-NEA3
	CipheringAlgorithmID byte
	// IntegrityAlgorithmID: 0=NIA0, 1=128-NIA1, 2=128-NIA2, 3=128-NIA3
	IntegrityAlgorithmID byte
}

// Encode encodes the security algorithms IE value (1 byte).
func (a NASSecurityAlgorithms) Encode() byte {
	return (a.CipheringAlgorithmID << 4) | (a.IntegrityAlgorithmID & 0x0F)
}

// Decode parses a 1-byte security algorithms IE value.
func DecodeNASSecurityAlgorithms(b byte) NASSecurityAlgorithms {
	return NASSecurityAlgorithms{
		CipheringAlgorithmID: (b >> 4) & 0x0F,
		IntegrityAlgorithmID: b & 0x0F,
	}
}

// ---- UE Security Capability (TS 24.501 §9.11.3.54) -----------------------

// UESecurityCapability lists the security algorithms supported by the UE.
type UESecurityCapability struct {
	// 5G-EA: bits 8..1 = EA0..EA7
	EA0, EA1, EA2, EA3, EA4, EA5, EA6, EA7 bool
	// 5G-IA: bits 8..1 = IA0..IA7
	IA0, IA1, IA2, IA3, IA4, IA5, IA6, IA7 bool
	// Raw preserves the verbatim wire bytes so the AMF can replay them
	// byte-for-byte in the Security Mode Command (TS 24.501 §8.2.25.1).
	// UERANSIM sends 4 bytes (5G-EA, 5G-IA, EPS-EA, EPS-IA); replaying fewer
	// bytes triggers "Replayed UE security capability mismatch".
	Raw []byte
}

// DecodeUESecurityCapability parses 2+ bytes of UE security capability.
func DecodeUESecurityCapability(b []byte) (UESecurityCapability, error) {
	if len(b) < 2 {
		return UESecurityCapability{}, errors.New("nas: UE sec cap too short")
	}
	c := UESecurityCapability{
		EA0: b[0]&0x80 != 0, EA1: b[0]&0x40 != 0,
		EA2: b[0]&0x20 != 0, EA3: b[0]&0x10 != 0,
		IA0: b[1]&0x80 != 0, IA1: b[1]&0x40 != 0,
		IA2: b[1]&0x20 != 0, IA3: b[1]&0x10 != 0,
		Raw: append([]byte(nil), b...), // preserve all bytes for exact replay
	}
	return c, nil
}

// EncodeUESecurityCapability serialises the capability. Returns Raw verbatim
// if present (for exact SMC replay), otherwise encodes from boolean fields.
func EncodeUESecurityCapability(c UESecurityCapability) []byte {
	if len(c.Raw) > 0 {
		return append([]byte(nil), c.Raw...)
	}
	var b [2]byte
	if c.EA0 { b[0] |= 0x80 }
	if c.EA1 { b[0] |= 0x40 }
	if c.EA2 { b[0] |= 0x20 }
	if c.EA3 { b[0] |= 0x10 }
	if c.IA0 { b[1] |= 0x80 }
	if c.IA1 { b[1] |= 0x40 }
	if c.IA2 { b[1] |= 0x20 }
	if c.IA3 { b[1] |= 0x10 }
	return b[:]
}

// ---- ABBA (TS 24.501 §9.11.3.10) ----------------------------------------

// ABBA is the Anti-Bidding-down Between Architectures IE (2 octets minimum).
// For initial registration, AMF sets ABBA to 0x0000.
type ABBA [2]byte

// ---- 5GMM Cause (TS 24.501 §9.11.3.2) -----------------------------------

type Cause5GMM byte

const (
	CauseIllegalUE                   Cause5GMM = 3
	CauseIdentificationNotAccepted   Cause5GMM = 5
	CauseIllegalME                   Cause5GMM = 6
	Cause5GSServicesNotAllowed        Cause5GMM = 7
	CauseUEIdentityNotDerived        Cause5GMM = 9
	CauseImplicitlyDeregistered      Cause5GMM = 10
	CausePLMNNotAllowed              Cause5GMM = 11
	CauseTANotAllowed                Cause5GMM = 12
	CauseRoamingNotAllowed           Cause5GMM = 13
	CauseNoSuitableCellsInTA         Cause5GMM = 15
	CauseMACFailure                  Cause5GMM = 20
	CauseSynchFailure                Cause5GMM = 21
	CauseCongestino                  Cause5GMM = 22
	CauseUnspecified                 Cause5GMM = 111
)

// ---- BCD helpers -----------------------------------------------------------

func encodeMCCMNC(mcc, mnc string) []byte {
	// 3 bytes: MCC digit2 | MCC digit1, MNC digit3 | MCC digit3, MNC digit2 | MNC digit1
	// For 2-digit MNC: MNC digit3 = 0xF
	if len(mcc) != 3 {
		return []byte{0x00, 0x00, 0x00}
	}
	b1 := (bcd(mcc[1]) << 4) | bcd(mcc[0])
	mncD3 := byte(0xF)
	if len(mnc) == 3 {
		mncD3 = bcd(mnc[2])
	}
	b2 := (mncD3 << 4) | bcd(mcc[2])
	b3 := (bcd(mnc[1]) << 4) | bcd(mnc[0])
	return []byte{b1, b2, b3}
}

func decodeMCCMNC(b []byte) (mcc, mnc string) {
	d := [3]byte(b)
	mcc = fmt.Sprintf("%d%d%d", d[0]&0x0F, (d[0]>>4)&0x0F, d[1]&0x0F)
	mncD3 := (d[1] >> 4) & 0x0F
	if mncD3 == 0xF {
		mnc = fmt.Sprintf("%d%d", d[2]&0x0F, (d[2]>>4)&0x0F)
	} else {
		mnc = fmt.Sprintf("%d%d%d", d[2]&0x0F, (d[2]>>4)&0x0F, mncD3)
	}
	return
}

func bcd(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	return 0
}
