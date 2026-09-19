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
	// IPCPRequest is the parsed IPCP (RFC 1332) Configure-Request carried
	// inside the (E)PCO container 0x8021, or nil if that container is absent
	// or is not a Configure-Request. See ParseIPCPFromEPCO.
	IPCPRequest *IPCPConfigureRequest
	// RequestedPCOContainerIDs lists every (E)PCO container ID the UE sent,
	// IN THE EXACT ORDER IT SENT THEM. The Accept must answer the containers
	// it can answer in this same order: Open5GS builds its reply with a
	// single pass over the UE's own list (src/smf/context.c, smf_pco_build,
	// `for (i = 0; i < ue.num_of_id; i++)`), so the reply order mirrors the
	// request order. Confirmed on a real Open5GS Accept captured to a Moto
	// Edge 30 Pro (IPCP first, then DNS, then MTU — the order that phone
	// asked in). See docs/ACCEPT-DIFF-open5gs-vs-claudia-2026-09-04.md §2b.
	RequestedPCOContainerIDs []uint16
	// PCOConfigProtocolOctet is octet 1 of the UE's (E)PCO IE
	// (Ext | spare | configuration protocol, TS 24.008 §10.5.6.3). Open5GS
	// echoes it back verbatim (`smf.ext = ue.ext;
	// smf.configuration_protocol = ue.configuration_protocol`,
	// context.c#L3361-3363) rather than hardcoding 0x80. Zero means the UE
	// sent no (E)PCO.
	PCOConfigProtocolOctet uint8
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
	Cause5GSM              *uint8  // Optional IEI 0x59
}

// 5GSM IE identifiers
const (
	IEIPDUSTI             uint8 = 0x09 // PDU Session Type
	IEIIntProtMaxDataRate uint8 = 0x34
	IEIEPCO               uint8 = 0x7B // Extended Protocol Config Options
	IEIPDUAddress         uint8 = 0x29
	IEISNSSAI5GSM         uint8 = 0x22 // S-NSSAI (TS 24.501 §9.11.4.8, Table 8.3.2.1.1)
	IEIDNN5GSM            uint8 = 0x25
	// IEICause5GSM is the 5GSM cause IE identifier (TV, 2 octets) in the
	// PDU Session Establishment Accept — TS 24.501 Table 8.3.2.1.1, IEI
	// 0x59. (Was 0x37 here, which is wrong and was never emitted; Open5GS
	// encodes it as 0x59, lib/nas/5gs/encoder.c#L3052, and a real captured
	// Open5GS Accept carries `59 32`. See
	// docs/ACCEPT-DIFF-open5gs-vs-claudia-2026-09-04.md §3b.)
	IEICause5GSM       uint8 = 0x59
	IEISelectedSSCMode uint8 = 0x0A
	// Modification Command optional IEs (TS 24.501 Table 8.3.7.1.1).
	// Note: in the PDU Session Establishment Accept the QoS rules and Session-AMBR
	// are mandatory LV-E/LV (no IEI); the IEIs below apply to the Modification
	// Command only, where they are TLV-E/TLV.
	IEIAuthorizedQoSRules    uint8 = 0x7A // Authorized QoS rules (TS 24.501 §9.11.4.13)
	IEISessionAMBR           uint8 = 0x2A // Session-AMBR (TS 24.501 §9.11.4.14)
	IEIAuthorizedQoSFlowDesc uint8 = 0x79 // Authorized QoS flow descriptions (TS 24.501 §9.11.4.12)
)

// 5GSM cause values emitted in the Establishment Accept when the granted PDU
// session type is narrower than the one the UE requested (TS 24.501
// §9.11.4.2, Table 9.11.4.2.1). Open5GS sets exactly these two, and only when
// the UE asked for IPv4v6: src/smf/gsm-build.c#L216-226.
const (
	Cause5GSMPDUSessionTypeIPv4OnlyAllowed uint8 = 0x32 // #50
	Cause5GSMPDUSessionTypeIPv6OnlyAllowed uint8 = 0x33 // #51
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
			msg.IPCPRequest = ParseIPCPFromEPCO(msg.ExtendedProtocolConfigOptions)
			if len(msg.ExtendedProtocolConfigOptions) > 0 {
				msg.PCOConfigProtocolOctet = msg.ExtendedProtocolConfigOptions[0]
			}
			for _, c := range parseEPCOContainerList(msg.ExtendedProtocolConfigOptions) {
				msg.RequestedPCOContainerIDs = append(msg.RequestedPCOContainerIDs, c.ID)
			}
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
	// IPv4 path delegates to the typed encoder; output is byte-identical to the
	// historical encoding (octet 3 = 0x01 followed by the 4 IPv4 octets).
	return EncodePDUSessionEstablishmentAcceptBodyWithQoSAddr(
		PDUAddressInfo{SessionType: selectedPDUType, IPv4: ip},
		sscMode, dnn, qfi, fiveQI, dlMbps, ulMbps, snssai...)
}

// PDUAddressInfo carries the address material for the PDU Address IE
// (TS 24.501 §9.11.4.10). For IPv6 and IPv4v6 the IE conveys ONLY the 64-bit
// interface identifier — never the /64 prefix, which reaches the UE via a
// Router Advertisement on the user plane (UPF). Ref: TS 23.501 §5.8.2.2.
type PDUAddressInfo struct {
	SessionType uint8  // PDUSessionTypeIPv4 | PDUSessionTypeIPv6 | PDUSessionTypeIPv4v6
	IPv4        net.IP // IPv4 / IPv4v6
	IPv6IID     []byte // 8-octet interface identifier — IPv6 / IPv4v6
}

// EncodePDUSessionEstablishmentAcceptBodyWithQoSAddr is the type-aware variant of
// EncodePDUSessionEstablishmentAcceptBodyWithQoS: it encodes the granted PDU
// session type and the matching PDU Address IE (IPv4, IPv6 IID, or IPv4v6
// IID+IPv4) per TS 24.501 §9.11.4.10. The Accept answers the UE's PCO with at
// least the IPv4 Link MTU container (see EncodeEstablishmentAcceptBody).
// Ref: TS 24.501 §8.3.2, TS 29.512 §5.2.2.2.
func EncodePDUSessionEstablishmentAcceptBodyWithQoSAddr(
	addr PDUAddressInfo, sscMode uint8, dnn string,
	qfi, fiveQI uint8, dlMbps, ulMbps int,
	snssai ...SNSSAI,
) ([]byte, error) {
	return EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNS(
		addr, sscMode, dnn, qfi, fiveQI, dlMbps, ulMbps, nil, snssai...)
}

// ContainerIDDNSServerIPv4Address is the (E)PCO container ID for "DNS Server
// IPv4 Address" (TS 24.008 §10.5.6.3, Table 10.5.154 / TS 24.301 Annex D).
// The network echoes this container back in the Accept, filled with the
// resolver address, for each one the UE requested (or unconditionally, which
// every UE tested against — incl. stock Android — accepts).
const ContainerIDDNSServerIPv4Address uint16 = 0x000D

// EncodePCODNSIPv4 builds the (Extended) Protocol Configuration Options
// content carrying one DNS Server IPv4 Address container per address in dns
// (TS 24.008 §10.5.6.3). Non-IPv4 / nil addresses are skipped. Returns nil if
// no valid IPv4 address is given, so callers can skip emitting the EPCO IE.
//
// Kept as its own entry point (DNS-only, no MTU) for callers/tests that want
// the historical byte-for-byte output; EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNS
// itself calls the combined EncodePCODNSAndMTU below.
func EncodePCODNSIPv4(dns ...net.IP) []byte {
	return EncodePCODNSAndMTU(0, dns...)
}

// ContainerIDIPv4LinkMTU is the (E)PCO container ID for "IPv4 Link MTU"
// (TS 24.008 §10.5.6.3, Table 10.5.154). The UE requests it with container
// ID 0x000B ("IPv4 link MTU request", empty value) and the network answers
// with 0x0010 carrying the negotiated 2-octet MTU. Reproduced against a
// Pixel 6a on the live OTA core 2026-09-03: the UE's PDU SESSION
// ESTABLISHMENT REQUEST ePco asked for 0x0010 and the Accept never answered
// it (DNS-only fix landed first, MTU still missing).
const ContainerIDIPv4LinkMTU uint16 = 0x0010

// DefaultIPv4LinkMTU is the MTU (in octets) advertised to the UE via the
// IPv4 Link MTU (E)PCO container. 1400 leaves headroom below the Ethernet
// 1500-byte MTU for GTP-U/UDP/IP encapsulation overhead on the N3 path
// (8 GTP-U + 8 UDP + 20 IP = 36 bytes minimum), matching common practice
// (e.g. Open5GS defaults) — safe even when N3 itself rides another
// encapsulated transport.
const DefaultIPv4LinkMTU uint16 = 1400

// EncodePCODNSAndMTU builds the (Extended) Protocol Configuration Options
// content carrying the IPv4 Link MTU container (when mtu != 0) followed by
// one DNS Server IPv4 Address container per address in dns (TS 24.008
// §10.5.6.3). Non-IPv4 / nil DNS addresses are skipped. Returns nil if
// there is nothing to emit (mtu == 0 and no valid DNS address), so callers
// can skip emitting the EPCO IE entirely.
//
// Per Open5GS (src/smf/gsm-build.c, smf_pco_build): the network answers PCO
// unconditionally rather than gating each container on the UE having
// requested it — the containers a stock UE (including this Pixel 6a) does
// not ask for are simply ignored by it.
func EncodePCODNSAndMTU(mtu uint16, dns ...net.IP) []byte {
	var containers []byte
	if mtu != 0 {
		containers = append(containers,
			byte(ContainerIDIPv4LinkMTU>>8), byte(ContainerIDIPv4LinkMTU&0xFF),
			2, byte(mtu>>8), byte(mtu&0xFF))
	}
	for _, ip := range dns {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		containers = append(containers,
			byte(ContainerIDDNSServerIPv4Address>>8), byte(ContainerIDDNSServerIPv4Address&0xFF),
			byte(len(v4)))
		containers = append(containers, v4...)
	}
	if len(containers) == 0 {
		return nil
	}
	// Octet 1: Ext(bit8)=1 | spare(bits 7-5)=000 | Configuration protocol(bits 4-1)=0000.
	out := append([]byte{0x80}, containers...)
	return out
}

// containerIDIPCP is the (E)PCO container ID for "PPP for use with IP PDP
// type or IP PDN type" (TS 24.008 §10.5.6.3 Table 10.5.154,
// OGS_PCO_PPP_FOR_USE_WITH_IP_PDP_TYPE_OR_IP_PDN_TYPE = 0). RFC 1332 IPCP
// negotiation is carried inside this container. Matches Open5GS
// OGS_PCO_ID_INTERNET_PROTOCOL_CONTROL_PROTOCOL, lib/proto/types.h:676
// (https://github.com/open5gs/open5gs/blob/main/lib/proto/types.h#L676).
const containerIDIPCP uint16 = 0x8021

// IPCP codes we handle (RFC 1661 §5, Configuration Option negotiation).
const (
	ipcpCodeConfigureRequest uint8 = 1 // RFC 1661 §5.1
	ipcpCodeConfigureAck     uint8 = 2 // RFC 1661 §5.2
	ipcpCodeConfigureNak     uint8 = 3 // RFC 1661 §5.3
)

// IPCP option types for DNS delivery (RFC 1877 §1, "PPP IPCP DNS/NBNS Name
// Server Addresses"). Matches Open5GS OGS_IPCP_OPT_PRIMARY_DNS /
// OGS_IPCP_OPT_SECONDARY_DNS, lib/proto/types.h:691-692
// (https://github.com/open5gs/open5gs/blob/main/lib/proto/types.h#L691-L692).
const (
	ipcpOptPrimaryDNS   uint8 = 129 // 0x81
	ipcpOptSecondaryDNS uint8 = 131 // 0x83
)

// IPCPConfigureRequest is the UE's IPCP (RFC 1332) Configure-Request carried
// inside (E)PCO container 0x8021. Populated by ParseIPCPFromEPCO /
// DecodePDUSessionEstablishmentRequest when that container is present with
// IPCP code 1 (Configure-Request, RFC 1661 §5.1).
//
// Reproduced against a Pixel 6a (Shannon modem) on the live OTA core
// 2026-09-03: the phone's PDU SESSION ESTABLISHMENT REQUEST ePco carried a
// 0x8021 container with IPCP Configure-Request options 0x81 (Primary-DNS)
// and 0x83 (Secondary-DNS, RFC 1877 §1), and the phone's DataCallResponse
// showed dnses=[] even though the Accept's plain 0x000D DNS container
// (TS 24.008 §10.5.6.3) was present and correctly formed on the wire — this
// modem appears to source DNS only from an IPCP reply, not from 0x000D.
type IPCPConfigureRequest struct {
	// Identifier is the IPCP identifier (RFC 1661 §5.1) that must be echoed
	// back unchanged in the Configure-Ack.
	Identifier uint8
	// WantsPrimaryDNS/WantsSecondaryDNS report whether the UE's
	// Configure-Request contained IPCP option 129/131 (RFC 1877 §1),
	// regardless of the placeholder value it sent (typically 0.0.0.0).
	WantsPrimaryDNS   bool
	WantsSecondaryDNS bool
}

// parseIPCPConfigureRequest parses one (E)PCO container's raw value as an
// IPCP packet — code(1) identifier(1) length(2, big-endian) + options,
// RFC 1332 §3 / RFC 1661 §5 — and returns the Configure-Request info when
// code == 1. Returns nil (not an error) for any other code, or when the
// value is too short to hold a valid IPCP header.
func parseIPCPConfigureRequest(value []byte) *IPCPConfigureRequest {
	if len(value) < 4 || value[0] != ipcpCodeConfigureRequest {
		return nil
	}
	req := &IPCPConfigureRequest{Identifier: value[1]}
	l := int(value[2])<<8 | int(value[3])
	if l > len(value) {
		l = len(value) // tolerate an overrun declared length
	}
	opts := value[4:l]
	for len(opts) >= 2 {
		optType, optLen := opts[0], int(opts[1])
		if optLen < 2 || optLen > len(opts) {
			break
		}
		switch optType {
		case ipcpOptPrimaryDNS:
			req.WantsPrimaryDNS = true
		case ipcpOptSecondaryDNS:
			req.WantsSecondaryDNS = true
		}
		opts = opts[optLen:]
	}
	return req
}

// epcoContainer is one decoded (E)PCO container: its 2-octet ID and raw value.
type epcoContainer struct {
	ID    uint16
	Value []byte
}

// parseEPCOContainerList walks a decoded (E)PCO IE value (TS 24.008
// §10.5.6.3: one octet of Ext/spare/configuration-protocol, then containers
// of ID(2B big-endian) + length(1B) + value) and returns the containers IN
// THE ORDER THEY APPEAR. Order matters: the Accept answers them in the same
// order (see BuildEPCOReply).
func parseEPCOContainerList(epco []byte) []epcoContainer {
	var out []epcoContainer
	if len(epco) < 1 {
		return out
	}
	b := epco[1:] // skip the Ext/spare/configuration-protocol octet
	for len(b) >= 3 {
		id := uint16(b[0])<<8 | uint16(b[1])
		l := int(b[2])
		if 3+l > len(b) {
			break
		}
		out = append(out, epcoContainer{ID: id, Value: b[3 : 3+l]})
		b = b[3+l:]
	}
	return out
}

// parseEPCOContainers is parseEPCOContainerList keyed by container ID, for
// callers that only need lookup (order is lost — do not use it to build a
// reply).
func parseEPCOContainers(epco []byte) map[uint16][]byte {
	out := make(map[uint16][]byte)
	for _, c := range parseEPCOContainerList(epco) {
		out[c.ID] = c.Value
	}
	return out
}

// ParseIPCPFromEPCO extracts the UE's IPCP Configure-Request (container
// 0x8021) from a decoded (E)PCO value — e.g.
// PDUSessionEstablishmentRequest.ExtendedProtocolConfigOptions — or nil if
// the container is absent or is not a Configure-Request.
func ParseIPCPFromEPCO(epco []byte) *IPCPConfigureRequest {
	value, ok := parseEPCOContainers(epco)[containerIDIPCP]
	if !ok {
		return nil
	}
	return parseIPCPConfigureRequest(value)
}

// EncodeIPCPConfigAckContainer builds the (E)PCO container 0x8021 carrying
// an IPCP Configure-Ack (RFC 1661 §5.2, code 2) in reply to the UE's
// Configure-Request: identifier echoed unchanged, with options 129/131
// (RFC 1877 §1) populated for whichever of primary/secondary DNS the UE
// requested. Returns nil if req is nil or neither DNS option applies (no
// requested option, or no address available for it) — callers then omit the
// container.
//
// Matches verified Open5GS behavior (src/smf/context.c, smf_pco_build,
// case OGS_PCO_ID_INTERNET_PROTOCOL_CONTROL_PROTOCOL, lines ~3404-3460:
// https://github.com/open5gs/open5gs/blob/main/src/smf/context.c#L3404-L3460):
// Open5GS replies with IPCP code 2 (Configure-Ack) — NOT a Configure-Nak
// (code 3) — copying the UE's identifier and substituting the SMF's own DNS
// addresses into whichever of options 129/131 the request contained
// (checked via ipcp_contains_option, same file lines 3300-3326, "stolen
// from osmo-ggsn"). This function reproduces that: Ack, not Nak.
func EncodeIPCPConfigAckContainer(req *IPCPConfigureRequest, primary, secondary net.IP) []byte {
	if req == nil {
		return nil
	}
	var opts []byte
	if req.WantsPrimaryDNS {
		if v4 := primary.To4(); v4 != nil {
			opts = append(opts, ipcpOptPrimaryDNS, 6)
			opts = append(opts, v4...)
		}
	}
	if req.WantsSecondaryDNS {
		if v4 := secondary.To4(); v4 != nil {
			opts = append(opts, ipcpOptSecondaryDNS, 6)
			opts = append(opts, v4...)
		}
	}
	if len(opts) == 0 {
		return nil
	}
	ipcpLen := 4 + len(opts) // code+identifier+length(2) + options
	// Empirically tested against the Pixel 6a on the live OTA core
	// 2026-09-04: both code=2 (Configure-Ack, this line) and code=3
	// (Configure-Nak, RFC 1661 §5.3) were sent — byte-correct on the wire,
	// verified via SMF debug logging (identifier echoed, options 0x81/0x83
	// populated with real DNS addresses) — and produced IDENTICAL results:
	// DataCallResponse.dnses=[] either way. So the IPCP reply code is not
	// the fix; kept as Ack to match verified Open5GS behavior (see doc
	// comment above) since there is no evidence Nak does anything this
	// modem/RIL combination actually uses. See
	// evidence/ota-attach-debug-2026-09-03.md for the negative result.
	ipcp := []byte{ipcpCodeConfigureAck, req.Identifier, byte(ipcpLen >> 8), byte(ipcpLen & 0xFF)}
	ipcp = append(ipcp, opts...)

	container := []byte{byte(containerIDIPCP >> 8), byte(containerIDIPCP & 0xFF), byte(len(ipcp))}
	return append(container, ipcp...)
}

// (E)PCO container IDs this encoder can answer, beyond
// ContainerIDDNSServerIPv4Address (0x000D), ContainerIDIPv4LinkMTU (0x0010)
// and containerIDIPCP (0x8021). Values from TS 24.008 §10.5.6.3
// Table 10.5.154; names/behavior mirror Open5GS lib/proto/types.h#L679-687.
const (
	// ContainerIDDNSServerIPv6Address — "DNS Server IPv6 Address Request".
	// Answered with one 16-octet container per configured IPv6 resolver;
	// omitted entirely when none is configured (Open5GS context.c, case
	// OGS_PCO_ID_DNS_SERVER_IPV6_ADDRESS_REQUEST: gated on smf.dns6[]).
	ContainerIDDNSServerIPv6Address uint16 = 0x0003
	// containerIDMSSupportLocalAddrTFT — "MS support of local address in TFT
	// indicator". Open5GS echoes it back with a ZERO-length value
	// (context.c, case OGS_PCO_ID_MS_SUPPORT_LOCAL_ADDR_TFT_INDICATOR:
	// len = 0, data = 0), so we do the same.
	containerIDMSSupportLocalAddrTFT uint16 = 0x0011
)

// EPCOReplyConfig is everything BuildEPCOReply needs to answer a UE's (E)PCO.
type EPCOReplyConfig struct {
	// ConfigProtocolOctet is octet 1 of the UE's own (E)PCO IE, echoed back
	// (Open5GS context.c#L3361-3363). 0 falls back to 0x80 (Ext=1, config
	// protocol 0000).
	ConfigProtocolOctet uint8
	// RequestedIDs are the container IDs the UE asked for, in ITS order.
	// Empty means the UE sent no (E)PCO — see the legacy fallback below.
	RequestedIDs []uint16
	// IPCP is the UE's IPCP Configure-Request (container 0x8021), or nil.
	IPCP *IPCPConfigureRequest
	// DNSv4/DNSv6 are the resolvers to hand out; MTU is the IPv4 link MTU
	// (0 = not configured, container omitted).
	DNSv4 []net.IP
	DNSv6 []net.IP
	MTU   uint16
}

// BuildEPCOReply builds the (Extended) Protocol Configuration Options IE value
// for a PDU Session Establishment Accept, answering the containers the UE
// requested IN THE UE'S OWN REQUEST ORDER.
//
// This reproduces Open5GS smf_pco_build (src/smf/context.c#L3331-L3573):
// a single pass over the UE's container list, appending one (or more) reply
// containers per recognized ID and skipping the rest. Per-ID semantics, all
// verified against that function:
//
//   - 0x8021 IPCP        — Configure-Ack (code 2), identifier echoed, only the
//     DNS options (0x81/0x83) the UE's own request carried.
//   - 0x000D DNS IPv4    — one flat 4-octet container PER configured resolver
//     (one request → two containers when two are set).
//   - 0x0003 DNS IPv6    — same, 16 octets each; omitted when none configured.
//   - 0x0010 IPv4 MTU    — 2-octet big-endian MTU when configured.
//   - 0x0011 local-addr-in-TFT — echoed back with a zero-length value.
//   - anything else (0x0005 MS-supports-BCM, 0x000A IP-alloc-via-NAS, P-CSCF,
//     ...) — omitted, exactly like Open5GS's `/` TODO `/` + `ogs_warn` arms.
//
// Why order matters: ClaudIA used to emit a FIXED MTU → DNS → DNS → IPCP-last
// list regardless of what the UE asked for. A Pixel 6a (Shannon modem) that
// puts IPCP FIRST in its request got dnses=[] and never validated the network,
// while the same phone works on Open5GS. See
// docs/ACCEPT-DIFF-open5gs-vs-claudia-2026-09-04.md §6 finding #1.
//
// Legacy fallback: when RequestedIDs is empty (caller has no decoded UE
// request — the old DNS/IPCP-only entry points), the historical fixed
// MTU → DNS → IPCP order is emitted so those call sites and their golden-hex
// tests stay byte-identical.
//
// Returns nil when there is nothing to answer, so the caller omits the IE.
func BuildEPCOReply(cfg EPCOReplyConfig) []byte {
	var primary, secondary net.IP
	if len(cfg.DNSv4) > 0 {
		primary = cfg.DNSv4[0]
	}
	if len(cfg.DNSv4) > 1 {
		secondary = cfg.DNSv4[1]
	}

	if len(cfg.RequestedIDs) == 0 {
		return EncodePCODNSMTUAndIPCP(cfg.MTU,
			EncodeIPCPConfigAckContainer(cfg.IPCP, primary, secondary), cfg.DNSv4...)
	}

	appendContainer := func(dst []byte, id uint16, value []byte) []byte {
		dst = append(dst, byte(id>>8), byte(id&0xFF), byte(len(value)))
		return append(dst, value...)
	}

	var containers []byte
	for _, id := range cfg.RequestedIDs {
		switch id {
		case containerIDIPCP:
			// EncodeIPCPConfigAckContainer already emits the full
			// ID+len+value container (or nil when unanswerable).
			if c := EncodeIPCPConfigAckContainer(cfg.IPCP, primary, secondary); c != nil {
				containers = append(containers, c...)
			}
		case ContainerIDDNSServerIPv4Address:
			for _, ip := range cfg.DNSv4 {
				if v4 := ip.To4(); v4 != nil {
					containers = appendContainer(containers, id, v4)
				}
			}
		case ContainerIDDNSServerIPv6Address:
			for _, ip := range cfg.DNSv6 {
				if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
					containers = appendContainer(containers, id, v6)
				}
			}
		case ContainerIDIPv4LinkMTU:
			if cfg.MTU != 0 {
				containers = appendContainer(containers, id,
					[]byte{byte(cfg.MTU >> 8), byte(cfg.MTU & 0xFF)})
			}
		case containerIDMSSupportLocalAddrTFT:
			containers = appendContainer(containers, id, nil)
		default:
			// Unrecognized / unimplemented — omitted, as Open5GS does.
		}
	}
	if len(containers) == 0 {
		return nil
	}
	ext := cfg.ConfigProtocolOctet
	if ext == 0 {
		ext = 0x80
	}
	return append([]byte{ext}, containers...)
}

// EncodePCODNSMTUAndIPCP is EncodePCODNSAndMTU plus an optional pre-built
// (E)PCO container (e.g. from EncodeIPCPConfigAckContainer) appended after
// the MTU/DNS containers. extra may be nil/empty.
func EncodePCODNSMTUAndIPCP(mtu uint16, extra []byte, dns ...net.IP) []byte {
	base := EncodePCODNSAndMTU(mtu, dns...)
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		// No MTU/DNS containers but extra is present: still need the
		// Ext/spare/configuration-protocol octet.
		base = []byte{0x80}
	}
	return append(base, extra...)
}

// EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNS is
// EncodePDUSessionEstablishmentAcceptBodyWithQoSAddr plus an optional list of
// IPv4 DNS resolvers, carried in the EPCO IE (IEI 0x7B, TLV-E) per Table
// 8.3.2.1.1 — placed before the DNN IE. dns may be nil/empty, in which case
// the EPCO still carries the IPv4 Link MTU container.
//
// Without this, a UE that cannot resolve names treats the PDU session as
// having "no internet" even when the IP path itself is healthy — reproduced
// against a Pixel 6a on the live OTA core 2026-09-03 (RIL DataCallResponse
// .dnses = [] with the accept otherwise unchanged).
func EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNS(
	addr PDUAddressInfo, sscMode uint8, dnn string,
	qfi, fiveQI uint8, dlMbps, ulMbps int,
	dns []net.IP,
	snssai ...SNSSAI,
) ([]byte, error) {
	return EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNSIPCP(
		addr, sscMode, dnn, qfi, fiveQI, dlMbps, ulMbps, dns, nil, snssai...)
}

// EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNSIPCP is
// EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNS plus optional IPCP
// (RFC 1332) DNS delivery: when ipcpReq is non-nil (the UE's request carried
// an (E)PCO container 0x8021 IPCP Configure-Request), the EPCO also gets an
// IPCP Configure-Ack container built by EncodeIPCPConfigAckContainer, using
// the same dns[0]/dns[1] as primary/secondary. dns may still be emitted via
// plain container 0x000D as before — some UEs (e.g. this Pixel 6a) need
// both.
func EncodePDUSessionEstablishmentAcceptBodyWithQoSAddrDNSIPCP(
	addr PDUAddressInfo, sscMode uint8, dnn string,
	qfi, fiveQI uint8, dlMbps, ulMbps int,
	dns []net.IP,
	ipcpReq *IPCPConfigureRequest,
	snssai ...SNSSAI,
) ([]byte, error) {
	var req *PDUSessionEstablishmentRequest
	if ipcpReq != nil {
		req = &PDUSessionEstablishmentRequest{IPCPRequest: ipcpReq}
	}
	return EncodeEstablishmentAcceptBody(EstablishmentAcceptParams{
		Addr: addr, SSCMode: sscMode, DNN: dnn,
		QFI: qfi, FiveQI: fiveQI, DLMbps: dlMbps, ULMbps: ulMbps,
		DNSv4: dns, MTU: DefaultIPv4LinkMTU,
		Request: req, SNSSAI: snssai,
	})
}

// EstablishmentAcceptParams is the full input to
// EncodeEstablishmentAcceptBody. Request carries the UE's own decoded
// PDU SESSION ESTABLISHMENT REQUEST (nil when the caller has none) and drives
// two things the older positional entry points could not express: the (E)PCO
// container ORDER (see BuildEPCOReply) and the 5GSM cause emitted when the
// granted PDU session type is narrower than the requested one. EAPMessage is
// the secondary-authentication EAP-Success carried in the EAP message IE
// (IEI 0x78), nil/empty to omit.
type EstablishmentAcceptParams struct {
	Addr           PDUAddressInfo
	SSCMode        uint8
	DNN            string
	QFI, FiveQI    uint8
	DLMbps, ULMbps int
	DNSv4          []net.IP
	DNSv6          []net.IP
	MTU            uint16
	SNSSAI         []SNSSAI
	EAPMessage     []byte
	Request        *PDUSessionEstablishmentRequest
}

// EncodeEstablishmentAcceptBody encodes the 5GSM PDU SESSION
// ESTABLISHMENT ACCEPT body (everything after the EPD|PSI|PTI|MT header) in
// the IE order of TS 24.501 Table 8.3.2.1.1:
//
//	selected PDU session type + SSC mode (V, ½+½)
//	authorized QoS rules                 (LV-E)
//	Session-AMBR                         (LV)
//	5GSM cause            IEI 0x59       (TV)     — on a session-type downgrade
//	PDU address           IEI 0x29       (TLV)
//	S-NSSAI               IEI 0x22       (TLV)
//	EAP message           IEI 0x78       (TLV-E)  — secondary auth only
//	authorized QoS flow descriptions IEI 0x79 (TLV-E)
//	Extended PCO          IEI 0x7B       (TLV-E)
//	DNN                   IEI 0x25       (TLV)
//
// Note EPCO (0x7B) comes BEFORE DNN (0x25). ClaudIA used to emit DNN first
// (and a unit test asserted that EPCO was the last IE in the body, citing
// this same table). Open5GS's encoder (lib/nas/5gs/encoder.c#L3120-3148 and
// the struct order in lib/nas/5gs/message.h), pycrate's independent
// from-spec TS 24.501 codec, and a real captured Open5GS Accept all put EPCO
// before DNN. See docs/ACCEPT-DIFF-open5gs-vs-claudia-2026-09-04.md §2a/§3b
// and finding #2.
func EncodeEstablishmentAcceptBody(p EstablishmentAcceptParams) ([]byte, error) {
	out := make([]byte, 0, 120)

	out = append(out, ((p.SSCMode&0x0F)<<4)|(p.Addr.SessionType&0x0F))

	qosRules := BuildDefaultQoSRules(p.QFI)
	out = append(out, byte(len(qosRules)>>8), byte(len(qosRules)&0xFF))
	out = append(out, qosRules...)

	ambr := buildSessionAMBR(p.DLMbps, p.ULMbps)
	out = append(out, byte(len(ambr)))
	out = append(out, ambr...)

	// 5GSM cause (optional, IEI 0x59, TV 2 octets). Emitted only when the UE
	// asked for IPv4v6 and the network granted a single address family —
	// exactly Open5GS's condition (src/smf/gsm-build.c#L216-226) — so the UE
	// knows the downgrade is deliberate and must not retry the other family.
	if cause := downgradeCause5GSM(p.Request, p.Addr.SessionType); cause != 0 {
		out = append(out, IEICause5GSM, cause)
	}

	if pdnAddr := buildPDUAddressIE(p.Addr); pdnAddr != nil {
		out = append(out, IEIPDUAddress)
		out = append(out, byte(len(pdnAddr)))
		out = append(out, pdnAddr...)
	}

	if len(p.SNSSAI) > 0 {
		s := p.SNSSAI[0]
		if s.SD != SDNotPresent {
			out = append(out, IEISNSSAI5GSM, 4, s.SST,
				byte(s.SD>>16), byte(s.SD>>8), byte(s.SD))
		} else {
			out = append(out, IEISNSSAI5GSM, 1, s.SST)
		}
	}

	// EAP message (IEI 0x78, TLV-E) — secondary authentication only. Per
	// Table 8.3.2.1.1 this IE precedes the Authorized QoS flow descriptions
	// IE (0x79) and the DNN IE (0x25).
	if len(p.EAPMessage) > 0 {
		out = append(out, EncodeEAPMessageTLVE(p.EAPMessage)...)
	}

	// Authorized QoS flow descriptions (IEI 0x79, TLV-E) — carries the 5QI for QFI.
	if p.FiveQI > 0 {
		flowDesc := BuildQoSFlowDescriptions(p.QFI, p.FiveQI, p.ULMbps, p.DLMbps)
		out = append(out, IEIAuthorizedQoSFlowDesc)
		out = append(out, byte(len(flowDesc)>>8), byte(len(flowDesc)&0xFF))
		out = append(out, flowDesc...)
	}

	// EPCO (optional, IEI 0x7B, TLV-E) — answers the UE's own container list
	// in the UE's own order (BuildEPCOReply). Precedes DNN per Table 8.3.2.1.1.
	cfg := EPCOReplyConfig{DNSv4: p.DNSv4, DNSv6: p.DNSv6, MTU: p.MTU}
	if p.Request != nil {
		cfg.ConfigProtocolOctet = p.Request.PCOConfigProtocolOctet
		cfg.RequestedIDs = p.Request.RequestedPCOContainerIDs
		cfg.IPCP = p.Request.IPCPRequest
	}
	if epco := BuildEPCOReply(cfg); epco != nil {
		out = append(out, IEIEPCO)
		out = append(out, byte(len(epco)>>8), byte(len(epco)&0xFF))
		out = append(out, epco...)
	}

	// DNN (optional, IEI 0x25) — value in APN label format (TS 23.003 §9.1).
	if p.DNN != "" {
		apnBytes := encodeAPN(p.DNN)
		out = append(out, IEIDNN5GSM)
		out = append(out, byte(len(apnBytes)))
		out = append(out, apnBytes...)
	}

	return out, nil
}

// downgradeCause5GSM returns the 5GSM cause value to put in the Accept when
// the UE requested an IPv4v6 PDU session and the network granted only one
// address family, or 0 when no cause IE applies. Ref: TS 24.501 §9.11.4.2
// (#50/#51), Open5GS src/smf/gsm-build.c#L216-226.
func downgradeCause5GSM(req *PDUSessionEstablishmentRequest, granted uint8) uint8 {
	if req == nil || req.PDUSessionType == nil || *req.PDUSessionType != PDUSessionTypeIPv4v6 {
		return 0
	}
	switch granted {
	case PDUSessionTypeIPv4:
		return Cause5GSMPDUSessionTypeIPv4OnlyAllowed
	case PDUSessionTypeIPv6:
		return Cause5GSMPDUSessionTypeIPv6OnlyAllowed
	}
	return 0
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

// buildPDUAddressIE encodes the PDU Address IE value (octet 3 onwards) for a
// granted PDU session type. Octet 3 bits 1-3 carry the PDU session type value;
// the address octets are the IPv4 address, the 8-octet IPv6 interface
// identifier, or the IID followed by the IPv4 address. Returns nil when there
// is no address material (so the caller omits the optional IE entirely).
// Ref: TS 24.501 §9.11.4.10, Table 9.11.4.10.1.
func buildPDUAddressIE(addr PDUAddressInfo) []byte {
	switch addr.SessionType {
	case PDUSessionTypeIPv6:
		return append([]byte{0x02}, normalizeIID(addr.IPv6IID)...)
	case PDUSessionTypeIPv4v6:
		out := append([]byte{0x03}, normalizeIID(addr.IPv6IID)...)
		return append(out, normalizeIPv4(addr.IPv4)...)
	default: // IPv4 (001)
		if addr.IPv4 == nil {
			return nil
		}
		return append([]byte{0x01}, normalizeIPv4(addr.IPv4)...)
	}
}

// normalizeIID returns an 8-octet IPv6 interface identifier, zero-padding or
// truncating the input as needed.
func normalizeIID(iid []byte) []byte {
	out := make([]byte, 8)
	copy(out, iid)
	return out
}

// normalizeIPv4 returns the 4-octet form of an IPv4 address (zeros if absent).
func normalizeIPv4(ip net.IP) []byte {
	out := make([]byte, 4)
	if ip4 := ip.To4(); ip4 != nil {
		copy(out, ip4)
	}
	return out
}
