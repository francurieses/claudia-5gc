// suci.go holds the standard SUCI text form (SupiOrSuci, suci branch) shared
// by the AMF (which builds it from the NAS 5GS mobile identity), the AUSF and
// the UDM (which parse it from Nausf_UEAuthentication / Nudm_UEAU requests).

package types

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SUCIPattern is the suci branch of the SupiOrSuci schema pattern, copied
// verbatim from TS29571_CommonData.yaml components/schemas/SupiOrSuci
// (TS 29.571 §5.3.2; SUCI text form per TS 23.003 §2.2B, used e.g. by
// TS 29.509 AuthenticationInfo.supiOrSuci). Layout:
//
//	suci-<supiType>-<mcc>-<mnc>-<routingIndicator>-<protectionSchemeId>-<hnPublicKeyId>-<schemeOutput>
//
// For supiType 1..7 the "<mcc>-<mnc>" part is the Home Network Identifier.
const SUCIPattern = `suci-(0-[0-9]{3}-[0-9]{2,3}|[1-7]-.+)-[0-9]{1,4}-(0-0-.*|[a-fA-F1-9]-([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])-[a-fA-F0-9]+)`

// SUCIPrefix is the leading token of the SUCI text form.
const SUCIPrefix = "suci-"

// Protection scheme identifiers (TS 23.003 §2.2B, TS 33.501 Annex C).
const (
	// SUCISchemeNull is the null protection scheme (no concealment).
	SUCISchemeNull uint8 = 0
	// SUCISchemeProfileA is ECIES Profile A (X25519).
	SUCISchemeProfileA uint8 = 1
	// SUCISchemeProfileB is ECIES Profile B (secp256r1).
	SUCISchemeProfileB uint8 = 2
)

// MaxSUCILen caps the accepted SUCI text length before any regexp runs
// (defence against oversized path/body values; a Profile B SUCI is < 300
// characters, NAI-based ones are bounded by the 4 KiB limit here).
const MaxSUCILen = 4096

// SUPITypeIMSI is the SUPI type value for an IMSI (TS 23.003 §2.2B).
const SUPITypeIMSI uint8 = 0

var (
	suciPatternRE = regexp.MustCompile(`^` + SUCIPattern + `$`)
	// Capture groups: 1 mcc, 2 mnc (type 0) | 3 type, 4 home network id
	// (type 1..7), 5 RI, 6/7 null scheme+keyid, 8 null output, 9 scheme,
	// 10 key id, 11 output.
	suciParseRE = regexp.MustCompile(
		`^suci-(?:0-([0-9]{3})-([0-9]{2,3})|([1-7])-(.+?))-([0-9]{1,4})-` +
			`(?:(0)-(0)-(.*)|([a-fA-F1-9])-([0-9]{1,3})-([a-fA-F0-9]+))$`)
	digitsRE = regexp.MustCompile(`^[0-9]+$`)
)

// SUCI is the decoded standard SUCI text form.
type SUCI struct {
	// SUPIType is 0 for IMSI, 1..7 for other types (TS 23.003 §2.2B).
	SUPIType uint8
	// MCC and MNC are set when SUPIType is 0.
	MCC, MNC string
	// HomeNetworkID is set when SUPIType is not 0.
	HomeNetworkID string
	// RoutingIndicator is 1..4 decimal digits, kept as text ("0", "0000").
	RoutingIndicator string
	// ProtectionScheme is the protection scheme identifier (0 null, 1 A, 2 B).
	ProtectionScheme uint8
	// HNPublicKeyID is 0 for the null scheme, else 1..255.
	HNPublicKeyID uint8
	// SchemeOutput is the MSIN digits (null scheme, IMSI) or the hex of the
	// ECIES output (eph pub key || ciphertext || MAC).
	SchemeOutput string
}

// IsSUCI reports whether s starts with the "suci-" prefix.
func IsSUCI(s string) bool { return strings.HasPrefix(s, SUCIPrefix) }

// String returns the standard SUCI text form.
func (s SUCI) String() string {
	var b strings.Builder
	b.WriteString(SUCIPrefix)
	b.WriteString(strconv.Itoa(int(s.SUPIType)))
	b.WriteByte('-')
	if s.SUPIType == SUPITypeIMSI {
		b.WriteString(s.MCC + "-" + s.MNC)
	} else {
		b.WriteString(s.HomeNetworkID)
	}
	b.WriteString("-" + s.RoutingIndicator)
	b.WriteString("-" + strconv.FormatUint(uint64(s.ProtectionScheme), 16))
	b.WriteString("-" + strconv.Itoa(int(s.HNPublicKeyID)))
	b.WriteString("-" + s.SchemeOutput)
	return b.String()
}

// ParseSUCI parses the standard SUCI text form (SUCIPattern). Returned errors
// never embed the input (it may carry the MSIN or concealed scheme output).
func ParseSUCI(s string) (SUCI, error) {
	if len(s) > MaxSUCILen {
		return SUCI{}, fmt.Errorf("types: parse SUCI: input longer than %d bytes", MaxSUCILen)
	}
	if !suciPatternRE.MatchString(s) {
		return SUCI{}, fmt.Errorf("types: parse SUCI: input does not match the SupiOrSuci suci pattern")
	}
	m := suciParseRE.FindStringSubmatch(s)
	if m == nil {
		return SUCI{}, fmt.Errorf("types: parse SUCI: input is not decodable")
	}
	var out SUCI
	if m[3] == "" {
		out.MCC, out.MNC = m[1], m[2]
	} else {
		t, _ := strconv.Atoi(m[3])
		out.SUPIType = uint8(t)
		out.HomeNetworkID = m[4]
	}
	out.RoutingIndicator = m[5]
	if m[6] != "" { // null scheme, key id 0
		out.SchemeOutput = m[8]
		if out.SUPIType == SUPITypeIMSI && !digitsRE.MatchString(out.SchemeOutput) {
			return SUCI{}, fmt.Errorf("types: parse SUCI: null-scheme output is not MSIN digits")
		}
		return out, nil
	}
	sch, err := strconv.ParseUint(m[9], 16, 8)
	if err != nil {
		return SUCI{}, fmt.Errorf("types: parse SUCI: protection scheme is not a valid identifier")
	}
	kid, err := strconv.ParseUint(m[10], 10, 8)
	if err != nil || kid == 0 {
		return SUCI{}, fmt.Errorf("types: parse SUCI: home network public key id out of range 1..255")
	}
	if len(m[11])%2 != 0 {
		return SUCI{}, fmt.Errorf("types: parse SUCI: scheme output has odd hex length %d", len(m[11]))
	}
	out.ProtectionScheme = uint8(sch)
	out.HNPublicKeyID = uint8(kid)
	out.SchemeOutput = m[11]
	return out, nil
}

// SchemeOutputBytes hex-decodes the scheme output of a non-null scheme SUCI.
func (s SUCI) SchemeOutputBytes() ([]byte, error) {
	if s.ProtectionScheme == SUCISchemeNull {
		return nil, fmt.Errorf("types: scheme output bytes: null scheme output is MSIN digits, not hex")
	}
	b, err := hex.DecodeString(s.SchemeOutput)
	if err != nil {
		return nil, fmt.Errorf("types: scheme output bytes: %w", err)
	}
	return b, nil
}

// SUPI returns "imsi-<mcc><mnc><msin>" for a null-scheme IMSI SUCI.
func (s SUCI) SUPI() (string, error) {
	if s.SUPIType != SUPITypeIMSI || s.ProtectionScheme != SUCISchemeNull {
		return "", fmt.Errorf("types: SUPI from SUCI: only null-scheme IMSI SUCI can be de-concealed locally")
	}
	return "imsi-" + s.MCC + s.MNC + s.SchemeOutput, nil
}

// NullSchemeMSIN converts a NAS null-scheme scheme output (packed BCD, low
// nibble first, 0xF filler in the last high nibble; TS 24.501 §9.11.3.4) to
// MSIN decimal digits.
func NullSchemeMSIN(bcd []byte) (string, error) {
	var b strings.Builder
	for i, o := range bcd {
		for j, d := range [2]byte{o & 0x0F, o >> 4} {
			if d == 0x0F && i == len(bcd)-1 && j == 1 {
				continue
			}
			if d > 9 {
				return "", fmt.Errorf("types: null-scheme MSIN: invalid BCD digit 0x%X at octet %d", d, i)
			}
			b.WriteByte('0' + d)
		}
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("types: null-scheme MSIN: empty scheme output")
	}
	return b.String(), nil
}
