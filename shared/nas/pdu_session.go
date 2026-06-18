package nas

import (
	"fmt"
	"net"
)

// PDU Session Establishment Request (5GSM, TS 24.501 §8.3.1)
type PDUSessionEstablishmentRequest struct {
	// IntegrityProtectionMaxDataRate: mandatory V format, 2 octets
	// (max UL octet, max DL octet). Ref: TS 24.501 §9.11.4.7
	IntegrityProtectionMaxDataRate [2]byte
	// PDUSessionType: optional nibble IEI 0x9- (TV ½). Ref: §9.11.4.11
	PDUSessionType *uint8
	// SSCMode: optional nibble IEI 0xA- (TV ½). Ref: §9.11.4.16
	SSCMode *uint8
	// ExtendedProtocolConfigOptions: optional IEI 0x7B (TLV-E, 2-byte length).
	// Ref: §9.11.4.6
	ExtendedProtocolConfigOptions []byte
}

// PDU Session Establishment Accept (5GSM, TS 24.501 §8.3.2)
type PDUSessionEstablishmentAccept struct {
	SelectedPDUSessionType uint8   // Mandatory (4-bit value)
	SelectedSSCMode        uint8   // Mandatory (4-bit value)
	AuthorizedQoSRules     []byte  // Mandatory IEI 0x74
	SessionAMBR            []byte  // Mandatory IEI 0x2C (6 bytes)
	PDUAddress             net.IP  // Optional IEI 0x29
	SNSSAI                 *SNSSAI // Optional IEI 0x22
	DNN                    *string // Optional IEI 0x25
	Cause5GSM              *uint8  // Optional IEI 0x37
}

// 5GSM IE identifiers
const (
	IEIPDUSTI             uint8 = 0x09 // PDU Session Type
	IEIIntProtMaxDataRate uint8 = 0x34
	IEIEPCO               uint8 = 0x7B // Extended Protocol Config Options
	IEIPDUAddress         uint8 = 0x29
	IEISNSSAI5GSM         uint8 = 0x22 // S-NSSAI (TS 24.501 §9.11.4.8, Table 8.3.2.1.1)
	IEIDNN5GSM            uint8 = 0x25
	IEICause5GSM          uint8 = 0x37
	IEISelectedSSCMode    uint8 = 0x0A
	// Modification Command optional IEs (TS 24.501 Table 8.3.7.1.1).
	// Note: in the PDU Session Establishment Accept the QoS rules and Session-AMBR
	// are mandatory LV-E/LV (no IEI); the IEIs below apply to the Modification
	// Command only, where they are TLV-E/TLV.
	IEIAuthorizedQoSRules    uint8 = 0x7A // Authorized QoS rules (TS 24.501 §9.11.4.13)
	IEISessionAMBR           uint8 = 0x2A // Session-AMBR (TS 24.501 §9.11.4.14)
	IEIAuthorizedQoSFlowDesc uint8 = 0x79 // Authorized QoS flow descriptions (TS 24.501 §9.11.4.12)
)

// PDU Session Type values
const (
	PDUSessionTypeIPv4         uint8 = 0x01
	PDUSessionTypeIPv6         uint8 = 0x02
	PDUSessionTypeIPv4v6       uint8 = 0x03
	PDUSessionTypeEthernet     uint8 = 0x04
	PDUSessionTypeUnstructured uint8 = 0x05
)

// SSC Mode values
const (
	SSCMode1 uint8 = 0x01
	SSCMode2 uint8 = 0x02
	SSCMode3 uint8 = 0x03
)

// DecodePDUSessionEstablishmentRequest decodes a 5GSM Establishment Request body.
// b starts AFTER the 5GSM header (EPD|PSI|PTI|MT).
//
// Layout per TS 24.501 §8.3.1 Table 8.3.1.1.1:
//   - Integrity protection maximum data rate — M, V, 2 octets (no IEI)
//   - PDU session type   — O, TV ½, nibble IEI 0x9-
//   - SSC mode           — O, TV ½, nibble IEI 0xA-
//   - 5GSM capability    — O, TLV, IEI 0x28
//   - Max packet filters — O, TV 3, IEI 0x55
//   - Always-on requested— O, TV ½, nibble IEI 0xB-
//   - SM PDU DN request  — O, TLV, IEI 0x39
//   - EPCO               — O, TLV-E (2-byte length), IEI 0x7B
//
// (Audit fix: the previous decoder treated the mandatory V-2 IE as an optional
// IEI 0x34, matched PDU session type on full-byte 0x09 instead of nibble 0x9-,
// and read the TLV-E EPCO with a 1-byte length — none of the fields ever
// decoded correctly against UERANSIM traffic.)
func DecodePDUSessionEstablishmentRequest(b []byte) (*PDUSessionEstablishmentRequest, error) {
	msg := &PDUSessionEstablishmentRequest{}
	if len(b) == 0 {
		return msg, nil
	}

	r := NewReader(b)

	// Mandatory: Integrity protection maximum data rate (V, 2 octets).
	ipmdr, err := r.ReadBytes(2)
	if err != nil {
		return nil, fmt.Errorf("nas: 5GSM EstablishmentRequest: integrity protection max data rate: %w", err)
	}
	copy(msg.IntegrityProtectionMaxDataRate[:], ipmdr)

	// Optional IEs.
	for r.Len() > 0 {
		iei, err := r.ReadByte()
		if err != nil {
			break
		}

		// Nibble (TV ½) IEs: high nibble is the IEI, low nibble the value.
		switch iei >> 4 {
		case 0x9: // PDU session type
			v := iei & 0x0F
			msg.PDUSessionType = &v
			continue
		case 0xA: // SSC mode
			v := iei & 0x0F
			msg.SSCMode = &v
			continue
		case 0xB: // Always-on PDU session requested
			continue
		}

		switch iei {
		case IEIEPCO: // TLV-E: 2-byte big-endian length
			hi, _ := r.ReadByte()
			lo, _ := r.ReadByte()
			l := int(hi)<<8 | int(lo)
			msg.ExtendedProtocolConfigOptions, _ = r.ReadBytes(l)
		case 0x55: // Maximum number of supported packet filters — TV, 3 octets total
			_, _ = r.ReadBytes(2)
		default:
			// Remaining optional IEs (0x28 5GSM capability, 0x39 SM PDU DN
			// request container, ...) are TLV with a 1-byte length.
			l, err := r.ReadByte()
			if err != nil {
				break
			}
			_, _ = r.ReadBytes(int(l))
		}
	}

	return msg, nil
}

// WrapPDUSessionEstablishmentAcceptBody wraps a 5GSM Accept message body with the 5GSM header.
// Takes a pre-encoded body and returns the complete message: EPD | PSI | PTI | MT | body
//
// El header 5GSM ocupa 4 octetos: la PDU session identity y la PTI son cada
// una un OCTETO COMPLETO, no medio octeto. Empaquetarlas en un solo byte
// desplaza el octeto de message type y el UE falla con "invalid NAS message
// type". Ref: TS 24.501 §9.1.1, §8.3.2.
func WrapPDUSessionEstablishmentAcceptBody(pduSessionID uint8, pti uint8, body []byte) []byte {
	// Build complete 5GSM message header + body
	msg := make([]byte, 0, len(body)+4)

	// Octeto 1: EPD = 0x2E (5GS Session Management)
	msg = append(msg, PDGroupSessionManagement)

	// Octeto 2: PDU session identity (octeto completo)
	msg = append(msg, pduSessionID)

	// Octeto 3: Procedure transaction identity (octeto completo)
	msg = append(msg, pti)

	// Octeto 4: Message Type = 0xC2 (PDU Session Establishment Accept)
	msg = append(msg, byte(MsgTypePDUSessionEstablishmentAccept))

	// Body
	msg = append(msg, body...)

	return msg
}

// EncodePDUSessionEstablishmentAccept encodes a complete 5GSM Accept message.
// Returns the full message: EPD | PSI | PTI | MT | body
// Ref: TS 24.501 §8.3.2
func EncodePDUSessionEstablishmentAccept(
	pduSessionID uint8, pti uint8, selectedPDUType uint8, sscMode uint8, ip net.IP, dnn string,
) ([]byte, error) {
	body, err := EncodePDUSessionEstablishmentAcceptBody(selectedPDUType, sscMode, ip, dnn)
	if err != nil {
		return nil, err
	}

	return WrapPDUSessionEstablishmentAcceptBody(pduSessionID, pti, body), nil
}

// EncodePDUSessionEstablishmentAcceptBody encodes a 5GSM Accept message body.
// Returns just the body (after header EPD|PSI|PTI|MT).
// selectedPDUType and sscMode are 4-bit values.
//
// Estructura del body (TS 24.501 §8.3.2, Table 8.3.2.1.1):
//   - Selected SSC mode | Selected PDU session type — V, 1 octeto (half+half)
//   - Authorized QoS rules — M, LV-E (longitud de 2 octetos, SIN IEI)
//   - Session-AMBR — M, LV (longitud de 1 octeto, SIN IEI)
//   - PDU address — O, TLV, IEI 0x29
//   - DNN — O, TLV, IEI 0x25
//
// Las QoS rules y el Session-AMBR son IEs MANDATORIAS: no llevan IEI y su
// longitud no se codifica con un byte arbitrario. Codificarlas como TLV con un
// IEI inventado desplaza el parser del UE (longitud LV-E leída como 0x7407) y
// provoca "readOctetString: out of bounds".
func EncodePDUSessionEstablishmentAcceptBody(
	selectedPDUType uint8, sscMode uint8, ip net.IP, dnn string,
	snssai ...SNSSAI,
) ([]byte, error) {
	out := make([]byte, 0, 100)

	// Octeto 1: Selected SSC mode (bits 8:5) | Selected PDU session type (bits 4:1)
	out = append(out, ((sscMode&0x0F)<<4)|(selectedPDUType&0x0F))

	// Authorized QoS rules — mandatoria, formato LV-E (longitud de 2 octetos).
	qosRules := BuildDefaultQoSRules(1) // QFI=1 for default flow
	out = append(out, byte(len(qosRules)>>8), byte(len(qosRules)&0xFF))
	out = append(out, qosRules...)

	// Session-AMBR — mandatoria, formato LV (longitud de 1 octeto).
	ambr := buildSessionAMBR(100, 100) // Mbps
	out = append(out, byte(len(ambr)))
	out = append(out, ambr...)

	// PDU Address (optional, IEI 0x29)
	if ip != nil {
		pdnAddr := buildPDUAddress(ip)
		out = append(out, IEIPDUAddress)
		out = append(out, byte(len(pdnAddr)))
		out = append(out, pdnAddr...)
	}

	// S-NSSAI (optional, IEI 0x22, TS 24.501 §9.11.4.8)
	// Required by many gNBs (e.g. PacketRusher) to identify the slice for the session.
	if len(snssai) > 0 {
		s := snssai[0]
		if s.SD != SDNotPresent {
			// SST (1B) + SD (3B) = 4 bytes value
			out = append(out, IEISNSSAI5GSM, 4, s.SST,
				byte(s.SD>>16), byte(s.SD>>8), byte(s.SD))
		} else {
			// SST only = 1 byte value
			out = append(out, IEISNSSAI5GSM, 1, s.SST)
		}
	}

	// DNN (optional, IEI 0x25) — value in APN label format (TS 23.003 §9.1).
	if dnn != "" {
		apnBytes := encodeAPN(dnn)
		out = append(out, IEIDNN5GSM)
		out = append(out, byte(len(apnBytes)))
		out = append(out, apnBytes...)
	}

	return out, nil
}

// EncodePDUSessionEstablishmentAcceptBodyWithQoS encodes a 5GSM Accept message body
// with the given QoS parameters from the PCF SM Policy response.
// qfi is the QoS Flow Identifier and fiveQI the authorized 5QI carried in the
// Authorized QoS flow descriptions IE (TS 24.501 §9.11.4.12, IEI 0x79).
// dlMbps/ulMbps are session AMBR values in Mbps.
// Ref: TS 24.501 §8.3.2, TS 29.512 §5.2.2.2.
func EncodePDUSessionEstablishmentAcceptBodyWithQoS(
	selectedPDUType uint8, sscMode uint8, ip net.IP, dnn string,
	qfi, fiveQI uint8, dlMbps, ulMbps int,
	snssai ...SNSSAI,
) ([]byte, error) {
	out := make([]byte, 0, 120)

	out = append(out, ((sscMode&0x0F)<<4)|(selectedPDUType&0x0F))

	qosRules := BuildDefaultQoSRules(qfi)
	out = append(out, byte(len(qosRules)>>8), byte(len(qosRules)&0xFF))
	out = append(out, qosRules...)

	ambr := buildSessionAMBR(dlMbps, ulMbps)
	out = append(out, byte(len(ambr)))
	out = append(out, ambr...)

	if ip != nil {
		pdnAddr := buildPDUAddress(ip)
		out = append(out, IEIPDUAddress)
		out = append(out, byte(len(pdnAddr)))
		out = append(out, pdnAddr...)
	}

	if len(snssai) > 0 {
		s := snssai[0]
		if s.SD != SDNotPresent {
			out = append(out, IEISNSSAI5GSM, 4, s.SST,
				byte(s.SD>>16), byte(s.SD>>8), byte(s.SD))
		} else {
			out = append(out, IEISNSSAI5GSM, 1, s.SST)
		}
	}

	// Authorized QoS flow descriptions (IEI 0x79, TLV-E) — carries the 5QI for QFI.
	// Per Table 8.3.2.1.1 this IE precedes the DNN IE.
	if fiveQI > 0 {
		flowDesc := BuildQoSFlowDescriptions(qfi, fiveQI, ulMbps, dlMbps)
		out = append(out, IEIAuthorizedQoSFlowDesc)
		out = append(out, byte(len(flowDesc)>>8), byte(len(flowDesc)&0xFF))
		out = append(out, flowDesc...)
	}

	// DNN (optional, IEI 0x25) — value in APN label format (TS 23.003 §9.1).
	if dnn != "" {
		apnBytes := encodeAPN(dnn)
		out = append(out, IEIDNN5GSM)
		out = append(out, byte(len(apnBytes)))
		out = append(out, apnBytes...)
	}

	return out, nil
}

// BuildDefaultQoSRules builds a default QoS rule matching all traffic on the given QFI.
// Exported so SMF and tests can call it directly.
//
// Wire format per TS 24.501 §9.11.4.13, Figure 9.11.4.13.3 (create new QoS rule):
//
//	QoS rule identifier (1B)
//	Length of QoS rule (2B)
//	Rule operation code (bits 8-6) | DQR (bit 5) | number of packet filters (bits 4-1)
//	Packet filter list — per filter: spare|direction(bits 6-5)|identifier(bits 4-1),
//	                     length of contents (1B), contents (component list)
//	QoS rule precedence (1B)
//	Spare (bit 8) | Segregation (bit 7) | QFI (bits 6-1)
func BuildDefaultQoSRules(qfi uint8) []byte {
	return buildQoSRule(QoSRuleOpCreateNew, qfi)
}

// BuildModifyQoSRules builds a "modify existing QoS rule and replace all packet
// filters" entry for rule ID 1 — used in the PDU Session Modification Command.
// Ref: TS 24.501 §9.11.4.13, Table 9.11.4.13.1
func BuildModifyQoSRules(qfi uint8) []byte {
	return buildQoSRule(QoSRuleOpModifyReplaceFilters, qfi)
}

// QoS rule operation codes (TS 24.501 Table 9.11.4.13.1).
const (
	QoSRuleOpCreateNew            uint8 = 0x01 // 001 — create new QoS rule
	QoSRuleOpModifyReplaceFilters uint8 = 0x03 // 011 — modify existing, replace all packet filters
)

func buildQoSRule(op, qfi uint8) []byte {
	const (
		dirBidirectional = 0x03
		filterMatchAll   = 0x01 // packet filter component type "match-all" (Table 9.11.4.13.1)
	)
	rule := []byte{
		(op << 5) | (1 << 4) | 0x01,    // operation | DQR=1 (default rule) | 1 packet filter
		(dirBidirectional << 4) | 0x01, // packet filter 1: bidirectional, identifier 1
		0x01,                           // length of packet filter contents
		filterMatchAll,                 // match-all component
		0xFF,                           // QoS rule precedence (255 = lowest priority)
		qfi & 0x3F,                     // spare=0 | segregation=0 | QFI
	}
	out := []byte{0x01} // QoS rule identifier = 1
	out = append(out, byte(len(rule)>>8), byte(len(rule)&0xFF))
	out = append(out, rule...)
	return out
}

// Is5QIGBR reports whether the 5QI denotes a GBR or delay-critical GBR resource type
// per TS 23.501 Table 5.7.4-1.
func Is5QIGBR(fiveQI uint8) bool {
	switch {
	case fiveQI >= 1 && fiveQI <= 4:
		return true
	case fiveQI >= 65 && fiveQI <= 67:
		return true
	case fiveQI >= 71 && fiveQI <= 76:
		return true
	case fiveQI >= 82 && fiveQI <= 85:
		return true
	}
	return false
}

// QoS flow description parameter identifiers (TS 24.501 Table 9.11.4.12.1).
const (
	qosFlowParam5QI    uint8 = 0x01
	qosFlowParamGFBRUL uint8 = 0x02
	qosFlowParamGFBRDL uint8 = 0x03
	qosFlowParamMFBRUL uint8 = 0x04
	qosFlowParamMFBRDL uint8 = 0x05
)

// QoS flow description operation codes (TS 24.501 Table 9.11.4.12.2).
const (
	QoSFlowOpCreateNew      uint8 = 0x01 // 001 — create new QoS flow description
	QoSFlowOpModifyExisting uint8 = 0x03 // 011 — modify existing QoS flow description
)

// BuildQoSFlowDescriptions builds one "create new QoS flow description" entry
// carrying the assigned 5QI (used in the Establishment Accept).
func BuildQoSFlowDescriptions(qfi, fiveQI uint8, ulMbps, dlMbps int) []byte {
	return buildQoSFlowDescription(QoSFlowOpCreateNew, qfi, fiveQI, ulMbps, dlMbps)
}

// BuildModifyQoSFlowDescriptions builds one "modify existing QoS flow description"
// entry with the new 5QI (used in the Modification Command).
func BuildModifyQoSFlowDescriptions(qfi, fiveQI uint8, ulMbps, dlMbps int) []byte {
	return buildQoSFlowDescription(QoSFlowOpModifyExisting, qfi, fiveQI, ulMbps, dlMbps)
}

// buildQoSFlowDescription encodes one QoS flow description entry. For GBR 5QIs
// the GFBR/MFBR parameters are included (set to the session AMBR values — our
// flows are not individually rate-limited).
//
// Wire format per TS 24.501 §9.11.4.12, Figure 9.11.4.12.4:
//
//	QFI (bits 6-1)
//	Operation code (bits 8-6)
//	E bit (bit 7) | number of parameters (bits 6-1)
//	Parameters — per parameter: identifier (1B), length (1B), content
func buildQoSFlowDescription(op, qfi, fiveQI uint8, ulMbps, dlMbps int) []byte {
	type param struct {
		id      uint8
		content []byte
	}
	params := []param{{qosFlowParam5QI, []byte{fiveQI}}}
	if Is5QIGBR(fiveQI) {
		// Bit rate format: unit (1B) + value (2B), same coding as Session-AMBR
		// (TS 24.501 Table 9.11.4.14.1; 0x06 = 1 Mbps granularity).
		rate := func(mbps int) []byte {
			return []byte{0x06, byte(mbps >> 8), byte(mbps & 0xFF)}
		}
		params = append(params,
			param{qosFlowParamGFBRUL, rate(ulMbps)},
			param{qosFlowParamGFBRDL, rate(dlMbps)},
			param{qosFlowParamMFBRUL, rate(ulMbps)},
			param{qosFlowParamMFBRDL, rate(dlMbps)},
		)
	}

	out := make([]byte, 0, 4+len(params)*5)
	out = append(out, qfi&0x3F)
	out = append(out, op<<5)
	out = append(out, (1<<6)|uint8(len(params))) // E=1: parameters list included
	for _, p := range params {
		out = append(out, p.id, byte(len(p.content)))
		out = append(out, p.content...)
	}
	return out
}

// buildSessionAMBR encodes Session AMBR per TS 24.501 §9.11.4.14
// Format: [unit DL (1B)] [value DL (2B)] [unit UL (1B)] [value UL (2B)]
// Unit coding (§9.11.4.14): 0x06 = 1 Mbps. For 100 Mbps: unit=0x06, value=100.
func buildSessionAMBR(dlMbps, ulMbps int) []byte {
	// DL AMBR: unit (1B) | value (2B)
	// UL AMBR: unit (1B) | value (2B)
	const unitMbps = 0x06
	out := make([]byte, 6)

	// DL
	out[0] = unitMbps
	out[1] = byte((dlMbps >> 8) & 0xFF)
	out[2] = byte(dlMbps & 0xFF)

	// UL
	out[3] = unitMbps
	out[4] = byte((ulMbps >> 8) & 0xFF)
	out[5] = byte(ulMbps & 0xFF)

	return out
}

// 5GSM cause values (TS 24.501 §9.11.4.2)
const (
	Cause5GSMRegularDeactivation   uint8 = 0x24 // 36
	Cause5GSMReactivationRequested uint8 = 0x1D // 29
	Cause5GSMNetworkFailure        uint8 = 0x26 // 38
)

// WrapPDUSessionReleaseCommandBody builds a complete 5GSM PDU Session Release Command.
// cause: e.g. Cause5GSMRegularDeactivation (0x24).
//
// UERANSIM v3.2.8 registers smCause as a MANDATORY IE via b.mandatoryIE(&smCause),
// which reads exactly 1 byte as the value with no IEI prefix. Sending the spec-compliant
// T-V format (IEI=0x59 + value) causes UERANSIM to read 0x59 as the cause value and
// the actual cause byte becomes a stray IEI, triggering "Bad constructed NAS message".
// Ref: TS 24.501 §8.3.9, UERANSIM src/lib/nas/msg.cpp
func WrapPDUSessionReleaseCommandBody(pduSessionID, pti, cause uint8) []byte {
	return []byte{
		PDGroupSessionManagement, // EPD 0x2E
		pduSessionID,
		pti,
		byte(MsgTypePDUSessionReleaseCommand),
		cause, // mandatory value only — no IEI prefix (UERANSIM v3.2.8 uses mandatoryIE)
	}
}

// WrapPDUSessionModificationCommandBody wraps a 5GSM Modification Command body with the header.
// Header format: EPD | PDU session identity | PTI | Message type (0xCB)
// Ref: TS 24.501 §9.1.1, §8.3.6
func WrapPDUSessionModificationCommandBody(pduSessionID, pti uint8, body []byte) []byte {
	msg := make([]byte, 0, len(body)+4)
	msg = append(msg, PDGroupSessionManagement) // EPD 0x2E
	msg = append(msg, pduSessionID)
	msg = append(msg, pti)
	msg = append(msg, byte(MsgTypePDUSessionModificationCommand)) // 0xCB
	msg = append(msg, body...)
	return msg
}

// EncodePDUSessionModificationCommandBody encodes a minimal 5GSM Modification Command body.
// All IEs in the command body are optional (TS 24.501 §8.3.6, Table 8.3.6.1.1).
// Returns an empty body — QoS rules and session parameters are unchanged.
func EncodePDUSessionModificationCommandBody() []byte {
	return []byte{}
}

// EncodePDUSessionModificationCommandBodyWithQoS encodes a 5GSM Modification Command body
// that updates the Session AMBR, QoS rules and QoS flow descriptions (new 5QI).
// Used for NW-initiated QoS modification (TS 23.502 §4.3.3.2).
//
// Body IEs in Table 8.3.7.1.1 order (TS 24.501 §8.3.7):
//   - IEI 0x2A: Session-AMBR (TLV, 1-octet length)
//   - IEI 0x7A: Authorized QoS rules (TLV-E, 2-octet length)
//   - IEI 0x79: Authorized QoS flow descriptions (TLV-E) — carries the new 5QI
func EncodePDUSessionModificationCommandBodyWithQoS(qfi, fiveQI uint8, dlMbps, ulMbps int) []byte {
	out := make([]byte, 0, 40)

	ambr := buildSessionAMBR(dlMbps, ulMbps)
	out = append(out, IEISessionAMBR)
	out = append(out, byte(len(ambr)))
	out = append(out, ambr...)

	// "Modify existing" operations: rule ID 1 / QFI were installed at establishment;
	// creating them again with the same identifier would be a semantic error
	// (TS 24.501 §6.4.2.2).
	qosRules := BuildModifyQoSRules(qfi)
	out = append(out, IEIAuthorizedQoSRules)
	out = append(out, byte(len(qosRules)>>8), byte(len(qosRules)&0xFF))
	out = append(out, qosRules...)

	if fiveQI > 0 {
		flowDesc := BuildModifyQoSFlowDescriptions(qfi, fiveQI, ulMbps, dlMbps)
		out = append(out, IEIAuthorizedQoSFlowDesc)
		out = append(out, byte(len(flowDesc)>>8), byte(len(flowDesc)&0xFF))
		out = append(out, flowDesc...)
	}

	return out
}

// buildPDUAddress encodes a PDU Address IE
// Format per TS 24.501 §9.11.4.15:
// [Type (01=IPv4, 02=IPv6, 03=IPv4v6)] [IPv4 address (4 bytes)] or [IPv6 address (8 bytes)]
// For IPv4: 0x01 followed by 4 bytes
func buildPDUAddress(ip net.IP) []byte {
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		return append([]byte{0x01}, ip4...)
	}
	if ip6 := ip.To16(); ip6 != nil {
		// IPv6 (use first 8 bytes for brevity in this impl)
		return append([]byte{0x02}, ip6[:8]...)
	}
	// Fallback: IPv4 zeros
	return []byte{0x01, 0, 0, 0, 0}
}
