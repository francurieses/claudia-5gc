package ngap

// pws.go — Public Warning System: NGAP Write-Replace Warning (ProcCode 51) and
// PWS Cancel (ProcCode 32) builders + decoders. Both procedures are Class 1,
// non-UE-associated: correlation is by (MessageIdentifier, SerialNumber) only,
// never AMF-UE-NGAP-ID/RAN-UE-NGAP-ID. ASN.1 APER via free5gc/ngap + free5gc/aper,
// following the exact idiom of BuildPaging (see codec.go).
//
// Ref: TS 38.413 §8.9.1 (Write-Replace Warning), §8.9.2 (PWS Cancel);
//
//	TS 23.041 §9.4 (IE value ranges); docs/procedures/PublicWarningSystem.md

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	"github.com/francurieses/claudia-5gc/shared/gsm7"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

// ---- Constants (3GPP magic numbers, named per CLAUDE.md) ------------------

// WarningTypeLength is the fixed size (in octets) of the WarningType IE.
// Ref: TS 23.041 §9.4.1.2.6.
const WarningTypeLength = 2

// WarningSecurityInfoLength is the fixed size (in octets) of the
// WarningSecurityInfo IE. Ref: TS 23.041 §9.4.1.2.7.
const WarningSecurityInfoLength = 50

// DefaultRepetitionPeriod is the MVP default RepetitionPeriod IE value.
// [VERIFY] TS 38.413 §9.3.1.50 states the NGAP unit is seconds; the "1.28 s"
// granularity in some CBS/SBc-AP descriptions is the legacy EPC unit, not NGAP.
// Ref: TS 38.413 §9.3.1.50.
const DefaultRepetitionPeriod int64 = 4096

// DefaultNumberOfBroadcasts is the MVP default NumberOfBroadcastsRequested IE
// value (1 = broadcast once; 0 would mean "until cancelled").
// Ref: TS 38.413 §9.3.1.51.
const DefaultNumberOfBroadcasts int64 = 1

// cbsPageContentLength is the fixed per-page content field size inside the
// WarningMessageContents IE's CBS Message Information Page structure.
// cbsMaxPages is the maximum number of pages the structure carries. A
// dissector (Wireshark's NGAP/CBS decoder included) reads the first octet as
// "Number of Pages" and then walks exactly that many (content[82]+length[1])
// blocks — sending raw, unwrapped text here (as an earlier draft of this file
// did) makes the first text byte misread as a page count and desyncs the
// whole IE, which a live pcap capture confirmed Wireshark flags as a
// Malformed Packet. Ref: TS 23.041 §9.4.2.2.5.
//
// gsm7MaxSeptetsPerPage / ucs2MaxCharsPerPage are the per-page character
// capacities for the two text alphabets: 82 octets pack 93 septets (GSM7,
// 5 padding bits left over) or 41 UCS2 characters (2 octets each).
// Ref: TS 23.038 §5.
const (
	cbsPageContentLength  = 82
	cbsMaxPages           = 15
	gsm7MaxSeptetsPerPage = 93
	ucs2MaxCharsPerPage   = cbsPageContentLength / 2
)

// cbsDCSUcs2WithLanguage is the CBS Data Coding Scheme codepoint for "UCS2;
// message preceded by language indication" (TS 23.038 §5, coding group 0001).
// The page's first ucs2LanguagePrefixLen octets carry the two ISO 639
// characters (GSM7-packed) naming the language, before the UCS2 body.
const (
	cbsDCSUcs2WithLanguage = 0x11
	ucs2LanguagePrefixLen  = 2
)

// encodeWarningMessageContentPages wraps text in the CBS Message Information
// Page structure mandated for the WarningMessageContents IE: a 1-octet
// Number-of-Pages followed by that many (82-octet zero-padded content,
// 1-octet used-length) pages (TS 23.041 §9.4.2.2.5; the length octet is an
// *octet* count per §9.3.20, not a character count, regardless of alphabet).
// The per-page content is encoded according to the alphabet dcs selects
// (TS 23.038 §5): GSM 7-bit default alphabet (septet-packed, up to 93
// characters/page), 8-bit data (raw octets, up to 82/page), or UCS2
// (2 bytes/char big-endian, up to 41 chars/page). text is truncated to
// whatever fits in cbsMaxPages (15) pages for the selected alphabet.
func encodeWarningMessageContentPages(dcs byte, langISO string, text []byte) []byte {
	switch gsm7.AlphabetFromCBSDCS(dcs) {
	case gsm7.AlphabetUCS2:
		var prefix []byte
		if dcs == cbsDCSUcs2WithLanguage && langISO != "" {
			prefix = gsm7.EncodeUCS2LanguagePrefix(langISO)
		}
		return encodeUCS2Pages(text, prefix)
	case gsm7.Alphabet8Bit:
		return encode8BitPages(text)
	default:
		// GSM7 language coding groups (DCS 0x00-0x0F/0x20-0x24) carry the
		// language in the DCS byte itself, so the content is encoded the same
		// regardless of language — no prefix.
		return encodeGSM7Pages(text)
	}
}

// pwsLanguageLabel resolves a human-readable language for logging: the GSM7
// language-coding-group name if the DCS carries one (TS 23.038 §5), else the
// ISO 639 prefix code (UCS2 DCS 0x11), else "unspecified".
func pwsLanguageLabel(dcs byte, langISO string) string {
	if name := gsm7.LanguageNameFromCBSDCS(dcs); name != "" {
		return name
	}
	if langISO != "" {
		return langISO
	}
	return "unspecified"
}

// encode8BitPages is the 8-bit-data alphabet path: raw octets, unpacked,
// cbsPageContentLength (82) octets per page.
func encode8BitPages(text []byte) []byte {
	if len(text) > cbsPageContentLength*cbsMaxPages {
		text = text[:cbsPageContentLength*cbsMaxPages]
	}
	numPages := (len(text) + cbsPageContentLength - 1) / cbsPageContentLength
	if numPages == 0 {
		numPages = 1 // always emit at least one (possibly empty) page
	}
	out := make([]byte, 0, 1+numPages*(cbsPageContentLength+1))
	out = append(out, byte(numPages))
	for i := 0; i < numPages; i++ {
		start := i * cbsPageContentLength
		end := start + cbsPageContentLength
		if end > len(text) {
			end = len(text)
		}
		page := make([]byte, cbsPageContentLength)
		n := copy(page, text[start:end])
		out = append(out, page...)
		out = append(out, byte(n))
	}
	return out
}

// encodeGSM7Pages is the GSM 7-bit default alphabet path (TS 23.038 §6.2.1 +
// §6.1.2.2.1): text is mapped to septets, chunked at gsm7MaxSeptetsPerPage
// (93) character boundaries — packing restarts fresh on every page, so a
// page boundary is also a septet-packing boundary — then each chunk is
// septet-packed into (at most) 82 octets. The trailing length octet is the
// number of *octets* the packed chunk used, per TS 23.041 §9.3.20.
func encodeGSM7Pages(text []byte) []byte {
	septets := gsm7.EncodeText(string(text))
	if len(septets) > gsm7MaxSeptetsPerPage*cbsMaxPages {
		septets = septets[:gsm7MaxSeptetsPerPage*cbsMaxPages]
	}
	numPages := (len(septets) + gsm7MaxSeptetsPerPage - 1) / gsm7MaxSeptetsPerPage
	if numPages == 0 {
		numPages = 1
	}
	out := make([]byte, 0, 1+numPages*(cbsPageContentLength+1))
	out = append(out, byte(numPages))
	for i := 0; i < numPages; i++ {
		start := i * gsm7MaxSeptetsPerPage
		end := start + gsm7MaxSeptetsPerPage
		if end > len(septets) {
			end = len(septets)
		}
		packed := gsm7.PackSeptets(septets[start:end])
		page := make([]byte, cbsPageContentLength)
		n := copy(page, packed)
		out = append(out, page...)
		out = append(out, byte(n))
	}
	return out
}

// encodeUCS2Pages is the UCS2 alphabet path: each rune becomes 2 big-endian
// octets, up to ucs2MaxCharsPerPage (41) characters per page. A non-nil prefix
// (the language-indication octets for DCS 0x11) is placed at the start of the
// first page only, reducing that page's character capacity accordingly
// (TS 23.038 §5 — the language prefix precedes the message).
func encodeUCS2Pages(text []byte, prefix []byte) []byte {
	runes := []rune(string(text))

	// Chunk runes into pages, giving page 0 less room when it carries a prefix.
	var pages [][]rune
	first := true
	for i := 0; i < len(runes) || first; {
		capacity := ucs2MaxCharsPerPage
		if first && len(prefix) > 0 {
			capacity = (cbsPageContentLength - len(prefix)) / 2
		}
		end := i + capacity
		if end > len(runes) {
			end = len(runes)
		}
		pages = append(pages, runes[i:end])
		i = end
		first = false
		if len(pages) >= cbsMaxPages {
			break // truncate anything past the 15-page maximum
		}
	}

	out := make([]byte, 0, 1+len(pages)*(cbsPageContentLength+1))
	out = append(out, byte(len(pages)))
	for i, pageRunes := range pages {
		page := make([]byte, cbsPageContentLength)
		n := 0
		if i == 0 && len(prefix) > 0 {
			n += copy(page, prefix)
		}
		for _, r := range pageRunes {
			page[n] = byte(r >> 8)
			page[n+1] = byte(r)
			n += 2
		}
		out = append(out, page...)
		out = append(out, byte(n))
	}
	return out
}

// DecodeWarningMessageContentPages reverses encodeWarningMessageContentPages
// for the alphabet dcs selects, concatenating every page's decoded text back
// into the original string (as UTF-8 bytes). Exported for tests and for any
// future mgmt-API decode/echo path. Returns nil for a wire value too short to
// contain even the Number-of-Pages octet. Ref: TS 23.041 §9.4.2.2.5.
func DecodeWarningMessageContentPages(dcs byte, wire []byte) []byte {
	switch gsm7.AlphabetFromCBSDCS(dcs) {
	case gsm7.AlphabetUCS2:
		prefixLen := 0
		if dcs == cbsDCSUcs2WithLanguage {
			prefixLen = ucs2LanguagePrefixLen
		}
		return decodeUCS2Pages(wire, prefixLen)
	case gsm7.Alphabet8Bit:
		return decode8BitPages(wire)
	default:
		return decodeGSM7Pages(wire)
	}
}

func decode8BitPages(wire []byte) []byte {
	if len(wire) < 1 {
		return nil
	}
	numPages := int(wire[0])
	var out []byte
	off := 1
	for i := 0; i < numPages; i++ {
		if off+cbsPageContentLength+1 > len(wire) {
			break
		}
		content := wire[off : off+cbsPageContentLength]
		n := int(wire[off+cbsPageContentLength])
		if n > cbsPageContentLength {
			n = cbsPageContentLength
		}
		out = append(out, content[:n]...)
		off += cbsPageContentLength + 1
	}
	return out
}

func decodeGSM7Pages(wire []byte) []byte {
	if len(wire) < 1 {
		return nil
	}
	numPages := int(wire[0])
	var out []byte
	off := 1
	for i := 0; i < numPages; i++ {
		if off+cbsPageContentLength+1 > len(wire) {
			break
		}
		content := wire[off : off+cbsPageContentLength]
		n := int(wire[off+cbsPageContentLength])
		if n > cbsPageContentLength {
			n = cbsPageContentLength
		}
		septetCount := gsm7.SeptetCountForOctets(n)
		if septetCount > gsm7MaxSeptetsPerPage {
			septetCount = gsm7MaxSeptetsPerPage
		}
		septets := gsm7.UnpackSeptets(content[:n], septetCount)
		out = append(out, []byte(gsm7.DecodeSeptets(septets))...)
		off += cbsPageContentLength + 1
	}
	return out
}

// decodeUCS2Pages reverses encodeUCS2Pages. prefixLen (2 for DCS 0x11, else 0)
// is the number of leading octets on page 0 to skip as the language-indication
// prefix rather than decode as UCS2. Use gsm7.DecodeUCS2LanguagePrefix on those
// octets separately to recover the language code.
func decodeUCS2Pages(wire []byte, prefixLen int) []byte {
	if len(wire) < 1 {
		return nil
	}
	numPages := int(wire[0])
	var runes []rune
	off := 1
	for i := 0; i < numPages; i++ {
		if off+cbsPageContentLength+1 > len(wire) {
			break
		}
		content := wire[off : off+cbsPageContentLength]
		n := int(wire[off+cbsPageContentLength])
		if n > cbsPageContentLength {
			n = cbsPageContentLength
		}
		start := 0
		if i == 0 {
			start = prefixLen
		}
		for j := start; j+1 < n; j += 2 {
			runes = append(runes, rune(content[j])<<8|rune(content[j+1]))
		}
		off += cbsPageContentLength + 1
	}
	return []byte(string(runes))
}

// ---- Write-Replace Warning Request (AMF→gNB, InitiatingMessage, ProcCode=51) ----

// WriteReplaceWarningParams carries the Write-Replace Warning Request IEs.
// The mgmt handler (cmd/amf/main.go) fills 3GPP-legal defaults for any IE the
// CBC (management portal) omits before calling BuildWriteReplaceWarningRequest.
// Ref: TS 38.413 §8.9.1, §9.3; TS 23.041 §9.4.
type WriteReplaceWarningParams struct {
	MessageIdentifier      uint16                          // TS 23.041 §9.4.1.2.2
	SerialNumber           uint16                          // TS 23.041 §9.4.1.2.1
	TAIs                   []TAIForPaging                  // WarningAreaList as TAIListForWarning; empty ⇒ IE omitted (whole gNB area)
	RepetitionPeriod       int64                           // TS 38.413 §9.3.1.50, 0..131071
	NumberOfBroadcasts     int64                           // TS 38.413 §9.3.1.51, 0..65535 (0 = until cancelled)
	WarningType            [WarningTypeLength]byte         // TS 23.041 §9.4.1.2.6
	WarningSecurityInfo    [WarningSecurityInfoLength]byte // TS 23.041 §9.4.1.2.7 — dev placeholder, not a real signature
	DataCodingScheme       byte                            // TS 23.038 §5
	LanguageISO639         string                          // 2-char ISO 639 code for the UCS2 language-indication prefix (DCS 0x11); empty ⇒ none. GSM7 coding-group DCS carries the language in the byte itself, ignoring this.
	WarningMessageContents []byte                          // TS 23.041 §9.4.1.2.5 — UTF-8 text, encoded per DataCodingScheme's alphabet (GSM7/8-bit/UCS2)
}

// BuildWriteReplaceWarningRequest builds a non-UE-associated NGAP Write-Replace
// Warning Request (InitiatingMessage, ProcCode 51). Mirrors BuildPaging's idiom.
// Ref: TS 38.413 §8.9.1.
func BuildWriteReplaceWarningRequest(p WriteReplaceWarningParams) []byte {
	var warningAreaList *ngapType.WarningAreaList
	if len(p.TAIs) > 0 {
		warningAreaList = &ngapType.WarningAreaList{
			Present:           ngapType.WarningAreaListPresentTAIListForWarning,
			TAIListForWarning: &ngapType.TAIListForWarning{List: buildTAIListForWarning(p.TAIs)},
		}
	}

	ies := []ngapType.WriteReplaceWarningRequestIEs{
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDMessageIdentifier},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.WriteReplaceWarningRequestIEsValue{
				Present:           ngapType.WriteReplaceWarningRequestIEsPresentMessageIdentifier,
				MessageIdentifier: &ngapType.MessageIdentifier{Value: uint16ToBitString16(p.MessageIdentifier)},
			},
		},
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDSerialNumber},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.WriteReplaceWarningRequestIEsValue{
				Present:      ngapType.WriteReplaceWarningRequestIEsPresentSerialNumber,
				SerialNumber: &ngapType.SerialNumber{Value: uint16ToBitString16(p.SerialNumber)},
			},
		},
	}
	if warningAreaList != nil {
		ies = append(ies, ngapType.WriteReplaceWarningRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDWarningAreaList},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.WriteReplaceWarningRequestIEsValue{
				Present:         ngapType.WriteReplaceWarningRequestIEsPresentWarningAreaList,
				WarningAreaList: warningAreaList,
			},
		})
	}
	ies = append(ies,
		ngapType.WriteReplaceWarningRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRepetitionPeriod},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.WriteReplaceWarningRequestIEsValue{
				Present:          ngapType.WriteReplaceWarningRequestIEsPresentRepetitionPeriod,
				RepetitionPeriod: &ngapType.RepetitionPeriod{Value: p.RepetitionPeriod},
			},
		},
		ngapType.WriteReplaceWarningRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNumberOfBroadcastsRequested},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.WriteReplaceWarningRequestIEsValue{
				Present:                     ngapType.WriteReplaceWarningRequestIEsPresentNumberOfBroadcastsRequested,
				NumberOfBroadcastsRequested: &ngapType.NumberOfBroadcastsRequested{Value: p.NumberOfBroadcasts},
			},
		},
		ngapType.WriteReplaceWarningRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDWarningType},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.WriteReplaceWarningRequestIEsValue{
				Present:     ngapType.WriteReplaceWarningRequestIEsPresentWarningType,
				WarningType: &ngapType.WarningType{Value: aper.OctetString(p.WarningType[:])},
			},
		},
		ngapType.WriteReplaceWarningRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDWarningSecurityInfo},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.WriteReplaceWarningRequestIEsValue{
				Present:             ngapType.WriteReplaceWarningRequestIEsPresentWarningSecurityInfo,
				WarningSecurityInfo: &ngapType.WarningSecurityInfo{Value: aper.OctetString(p.WarningSecurityInfo[:])},
			},
		},
		ngapType.WriteReplaceWarningRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDDataCodingScheme},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.WriteReplaceWarningRequestIEsValue{
				Present:          ngapType.WriteReplaceWarningRequestIEsPresentDataCodingScheme,
				DataCodingScheme: &ngapType.DataCodingScheme{Value: aper.BitString{Bytes: []byte{p.DataCodingScheme}, BitLength: 8}},
			},
		},
	)
	if len(p.WarningMessageContents) > 0 {
		ies = append(ies, ngapType.WriteReplaceWarningRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDWarningMessageContents},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.WriteReplaceWarningRequestIEsValue{
				Present:                ngapType.WriteReplaceWarningRequestIEsPresentWarningMessageContents,
				WarningMessageContents: &ngapType.WarningMessageContents{Value: aper.OctetString(encodeWarningMessageContentPages(p.DataCodingScheme, p.LanguageISO639, p.WarningMessageContents))},
			},
		})
	}

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeWriteReplaceWarning},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentWriteReplaceWarningRequest,
				WriteReplaceWarningRequest: &ngapType.WriteReplaceWarningRequest{
					ProtocolIEs: ngapType.ProtocolIEContainerWriteReplaceWarningRequestIEs{List: ies},
				},
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// PLMNFromMCCMNC encodes MCC+MNC into the 3-byte nibble-encoded PLMN identity
// (TS 24.501 §9.11.3.4). Exported so cmd/amf/main.go can build the default
// WarningAreaList TAIs for the PWS mgmt handler without duplicating the
// nibble-encoding logic.
func PLMNFromMCCMNC(mcc, mnc string) []byte {
	return plmnFromMCCMNC(mcc, mnc)
}

// buildTAIListForWarning converts our TAIForPaging pairs into ngapType.TAI
// entries for a TAIListForWarning (reused for both WriteReplaceWarningRequest
// and PWSCancelRequest's optional WarningAreaList).
func buildTAIListForWarning(tais []TAIForPaging) []ngapType.TAI {
	items := make([]ngapType.TAI, 0, len(tais))
	for _, t := range tais {
		items = append(items, ngapType.TAI{
			PLMNIdentity: ngapType.PLMNIdentity{Value: t.PLMN},
			TAC:          ngapType.TAC{Value: aper.OctetString{byte(t.TAC >> 16), byte(t.TAC >> 8), byte(t.TAC)}},
		})
	}
	return items
}

// ---- Write-Replace Warning Response (gNB→AMF, SuccessfulOutcome, ProcCode=51) ----

// PWSArea is one decoded TAI entry from a BroadcastCompleted/CancelledAreaList.
// Only the TAI-broadcast NR variant is decoded in MVP (our gNBs are NR); other
// CHOICE variants (EUTRA, cell-ID, emergency-area) are counted but not detailed.
// Ref: TS 38.413 §9.3.1.56/.57.
type PWSArea struct {
	MCC string `json:"mcc,omitempty"`
	MNC string `json:"mnc,omitempty"`
	TAC uint32 `json:"tac,omitempty"`
}

// WriteReplaceWarningResponseMsg is the decoded Write-Replace Warning Response.
// Ref: TS 38.413 §8.9.1.
type WriteReplaceWarningResponseMsg struct {
	MessageIdentifier uint16
	SerialNumber      uint16
	Areas             []PWSArea
}

// PWSCancelResponseMsg is the decoded PWS Cancel Response. Ref: TS 38.413 §8.9.2.
type PWSCancelResponseMsg struct {
	MessageIdentifier uint16
	SerialNumber      uint16
	Areas             []PWSArea
}

func extractWriteReplaceWarningResponse(resp *ngapType.WriteReplaceWarningResponse) *WriteReplaceWarningResponseMsg {
	out := &WriteReplaceWarningResponseMsg{}
	for _, ie := range resp.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDMessageIdentifier:
			if ie.Value.MessageIdentifier != nil {
				out.MessageIdentifier = bitString16ToUint16(ie.Value.MessageIdentifier.Value)
			}
		case ngapType.ProtocolIEIDSerialNumber:
			if ie.Value.SerialNumber != nil {
				out.SerialNumber = bitString16ToUint16(ie.Value.SerialNumber.Value)
			}
		case ngapType.ProtocolIEIDBroadcastCompletedAreaList:
			if ie.Value.BroadcastCompletedAreaList != nil {
				out.Areas = extractBroadcastCompletedAreaList(ie.Value.BroadcastCompletedAreaList)
			}
		}
	}
	return out
}

func extractBroadcastCompletedAreaList(list *ngapType.BroadcastCompletedAreaList) []PWSArea {
	var areas []PWSArea
	switch list.Present {
	case ngapType.BroadcastCompletedAreaListPresentTAIBroadcastNR:
		if list.TAIBroadcastNR != nil {
			for _, item := range list.TAIBroadcastNR.List {
				areas = append(areas, PWSArea{
					MCC: plmnToMCC(item.TAI.PLMNIdentity.Value),
					MNC: plmnToMNC(item.TAI.PLMNIdentity.Value),
					TAC: tacToUint32(item.TAI.TAC.Value),
				})
			}
		}
	case ngapType.BroadcastCompletedAreaListPresentTAIBroadcastEUTRA:
		if list.TAIBroadcastEUTRA != nil {
			for _, item := range list.TAIBroadcastEUTRA.List {
				areas = append(areas, PWSArea{
					MCC: plmnToMCC(item.TAI.PLMNIdentity.Value),
					MNC: plmnToMNC(item.TAI.PLMNIdentity.Value),
					TAC: tacToUint32(item.TAI.TAC.Value),
				})
			}
		}
	}
	return areas
}

// ---- PWS Cancel Request (AMF→gNB, InitiatingMessage, ProcCode=32) --------

// BuildPWSCancelRequest builds a non-UE-associated NGAP PWS Cancel Request
// (InitiatingMessage, ProcCode 32). tais is optional (nil/empty ⇒ WarningAreaList
// omitted, meaning "cancel everywhere it was broadcast"); cancelAll sets the
// CancelAllWarningMessages shortcut IE. Ref: TS 38.413 §8.9.2.
func BuildPWSCancelRequest(messageIdentifier, serialNumber uint16, tais []TAIForPaging, cancelAll bool) []byte {
	ies := []ngapType.PWSCancelRequestIEs{
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDMessageIdentifier},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.PWSCancelRequestIEsValue{
				Present:           ngapType.PWSCancelRequestIEsPresentMessageIdentifier,
				MessageIdentifier: &ngapType.MessageIdentifier{Value: uint16ToBitString16(messageIdentifier)},
			},
		},
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDSerialNumber},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.PWSCancelRequestIEsValue{
				Present:      ngapType.PWSCancelRequestIEsPresentSerialNumber,
				SerialNumber: &ngapType.SerialNumber{Value: uint16ToBitString16(serialNumber)},
			},
		},
	}
	if len(tais) > 0 {
		ies = append(ies, ngapType.PWSCancelRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDWarningAreaList},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.PWSCancelRequestIEsValue{
				Present: ngapType.PWSCancelRequestIEsPresentWarningAreaList,
				WarningAreaList: &ngapType.WarningAreaList{
					Present:           ngapType.WarningAreaListPresentTAIListForWarning,
					TAIListForWarning: &ngapType.TAIListForWarning{List: buildTAIListForWarning(tais)},
				},
			},
		})
	}
	if cancelAll {
		ies = append(ies, ngapType.PWSCancelRequestIEs{
			Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDCancelAllWarningMessages},
			// TS 38.413 §9.2.1: the Cancel-All-Warning-Messages IE has criticality "reject".
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.PWSCancelRequestIEsValue{
				Present:                  ngapType.PWSCancelRequestIEsPresentCancelAllWarningMessages,
				CancelAllWarningMessages: &ngapType.CancelAllWarningMessages{Value: ngapType.CancelAllWarningMessagesPresentTrue},
			},
		})
	}

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePWSCancel},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentPWSCancelRequest,
				PWSCancelRequest: &ngapType.PWSCancelRequest{
					ProtocolIEs: ngapType.ProtocolIEContainerPWSCancelRequestIEs{List: ies},
				},
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// ---- PWS Cancel Response (gNB→AMF, SuccessfulOutcome, ProcCode=32) -------

func extractPWSCancelResponse(resp *ngapType.PWSCancelResponse) *PWSCancelResponseMsg {
	out := &PWSCancelResponseMsg{}
	for _, ie := range resp.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDMessageIdentifier:
			if ie.Value.MessageIdentifier != nil {
				out.MessageIdentifier = bitString16ToUint16(ie.Value.MessageIdentifier.Value)
			}
		case ngapType.ProtocolIEIDSerialNumber:
			if ie.Value.SerialNumber != nil {
				out.SerialNumber = bitString16ToUint16(ie.Value.SerialNumber.Value)
			}
		case ngapType.ProtocolIEIDBroadcastCancelledAreaList:
			if ie.Value.BroadcastCancelledAreaList != nil {
				out.Areas = extractBroadcastCancelledAreaList(ie.Value.BroadcastCancelledAreaList)
			}
		}
	}
	return out
}

func extractBroadcastCancelledAreaList(list *ngapType.BroadcastCancelledAreaList) []PWSArea {
	var areas []PWSArea
	switch list.Present {
	case ngapType.BroadcastCancelledAreaListPresentTAICancelledNR:
		if list.TAICancelledNR != nil {
			for _, item := range list.TAICancelledNR.List {
				areas = append(areas, PWSArea{
					MCC: plmnToMCC(item.TAI.PLMNIdentity.Value),
					MNC: plmnToMNC(item.TAI.PLMNIdentity.Value),
					TAC: tacToUint32(item.TAI.TAC.Value),
				})
			}
		}
	case ngapType.BroadcastCancelledAreaListPresentTAICancelledEUTRA:
		if list.TAICancelledEUTRA != nil {
			for _, item := range list.TAICancelledEUTRA.List {
				areas = append(areas, PWSArea{
					MCC: plmnToMCC(item.TAI.PLMNIdentity.Value),
					MNC: plmnToMNC(item.TAI.PLMNIdentity.Value),
					TAC: tacToUint32(item.TAI.TAC.Value),
				})
			}
		}
	}
	return areas
}

// ---- BitString<->uint16 helpers (MessageIdentifier / SerialNumber, both 16-bit) ----

// uint16ToBitString16 encodes v as a big-endian 16-bit aper.BitString, matching
// the encoding already used for NRencryptionAlgorithms etc. in this package.
func uint16ToBitString16(v uint16) aper.BitString {
	return aper.BitString{Bytes: []byte{byte(v >> 8), byte(v)}, BitLength: 16}
}

// bitString16ToUint16 decodes a big-endian 16-bit aper.BitString back to uint16.
func bitString16ToUint16(bs aper.BitString) uint16 {
	if len(bs.Bytes) < 2 {
		return 0
	}
	return uint16(bs.Bytes[0])<<8 | uint16(bs.Bytes[1])
}

// ---- PWS registry + fan-out (Server) --------------------------------------

// ErrPWSBroadcastNotFound is returned by SendPWSCancel when the
// (MessageIdentifier, SerialNumber) key does not match any broadcast the AMF
// has recorded (never sent, or unknown to this AMF instance). The mgmt handler
// maps this to a 404. Ref: TS 23.041 §9.3.2.
var ErrPWSBroadcastNotFound = errors.New("amf: pws: unknown or already-completed broadcast")

// PWSKey correlates a Write-Replace Warning / PWS Cancel exchange by
// (MessageIdentifier, SerialNumber) only — there is no AMF-UE-NGAP-ID /
// RAN-UE-NGAP-ID pair for these non-UE-associated Class 1 procedures.
// Ref: TS 23.041 §9.3.2, TS 38.413 §8.9.
type PWSKey struct {
	MessageIdentifier uint16
	SerialNumber      uint16
}

// PWSGNBStatus is the per-gNB broadcast/cancel completion state for one PWS key.
type PWSGNBStatus struct {
	GNBAddr   string    `json:"gnb_addr"`
	GNBName   string    `json:"gnb_name,omitempty"`
	Completed bool      `json:"completed"`
	Cancelled bool      `json:"cancelled"`
	Failed    bool      `json:"failed,omitempty"`
	Areas     []PWSArea `json:"areas,omitempty"`
}

// PWSBroadcast is one active/completed PWS broadcast tracked by the AMF,
// keyed by (MessageIdentifier, SerialNumber). Guarded by Server.pwsMu.
type PWSBroadcast struct {
	Key          PWSKey
	Params       WriteReplaceWarningParams
	CreatedAt    time.Time
	GNBsTargeted int
	CancelledAt  *time.Time
	PerGNB       map[string]*PWSGNBStatus // key: gNB remoteAddr
}

// PWSBroadcastStatus is a JSON-friendly, lock-free snapshot of a PWSBroadcast
// for the management API status-poll endpoint.
type PWSBroadcastStatus struct {
	MessageIdentifier uint16         `json:"message_identifier"`
	SerialNumber      uint16         `json:"serial_number"`
	GNBsTargeted      int            `json:"gnbs_targeted"`
	GNBsCompleted     int            `json:"gnbs_completed"`
	GNBsCancelled     int            `json:"gnbs_cancelled"`
	Cancelled         bool           `json:"cancelled"`
	CreatedAt         time.Time      `json:"created_at"`
	PerGNB            []PWSGNBStatus `json:"per_gnb"`
}

// SendWriteReplaceWarning builds the Write-Replace Warning Request and fans it
// out to every connected gNB — no TAC filtering, unlike SendPaging: PWS
// broadcasts to the whole configured Warning Area (TS 23.501 §5.20). The
// broadcast is recorded in the PWS registry keyed by (MessageIdentifier,
// SerialNumber) even when zero gNBs are connected, so a later PWS Cancel can
// still resolve it (TS 38.413 §8.9.1 note: Class 1 needs a peer, but the
// request is still accepted). Returns the number of gNBs targeted; per-gNB
// completion is tracked asynchronously by handleWriteReplaceWarningResponse.
// Ref: TS 38.413 §8.9.1.
func (s *Server) SendWriteReplaceWarning(ctx context.Context, params WriteReplaceWarningParams) (int, error) {
	key := PWSKey{MessageIdentifier: params.MessageIdentifier, SerialNumber: params.SerialNumber}

	s.mu.RLock()
	gnbs := make([]*GNBContext, 0, len(s.gnbs))
	for _, g := range s.gnbs {
		gnbs = append(gnbs, g)
	}
	s.mu.RUnlock()

	broadcast := &PWSBroadcast{
		Key:          key,
		Params:       params,
		CreatedAt:    time.Now(),
		GNBsTargeted: len(gnbs),
		PerGNB:       make(map[string]*PWSGNBStatus, len(gnbs)),
	}
	for _, g := range gnbs {
		addr := g.Conn.RemoteAddr().String()
		broadcast.PerGNB[addr] = &PWSGNBStatus{GNBAddr: addr, GNBName: g.Name}
	}
	s.pwsMu.Lock()
	s.pws[key] = broadcast
	s.pwsMu.Unlock()

	log := s.logger.With(
		"nf", "AMF",
		"procedure", "PublicWarningSystem",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "WriteReplaceWarningRequest",
		"message_identifier", params.MessageIdentifier,
		"serial_number", params.SerialNumber,
		"data_coding_scheme", params.DataCodingScheme,
		"language", pwsLanguageLabel(params.DataCodingScheme, params.LanguageISO639),
		"correlation_id", logging.CorrelationID(ctx),
		"spec_ref", "TS 38.413 §8.9.1",
	)

	if len(gnbs) == 0 {
		log.Warn("Write-Replace Warning accepted with no gNB connected", "gnbs_targeted", 0)
		return 0, nil
	}

	pdu := BuildWriteReplaceWarningRequest(params)
	if pdu == nil {
		return 0, fmt.Errorf("amf: pws write-replace warning: encode failed")
	}

	sent := 0
	for _, g := range gnbs {
		if _, err := writeNGAP(g.Conn, pdu); err != nil {
			log.Warn("Write-Replace Warning write failed", "gnb", g.Name, "gnb_addr", g.Conn.RemoteAddr().String(), "error", err)
			continue
		}
		sent++
	}
	log.Info("NGAP Write-Replace Warning Request sent", "gnbs_targeted", len(gnbs), "gnbs_sent", sent)
	return len(gnbs), nil
}

// SendPWSCancel builds a PWS Cancel Request for an existing broadcast keyed by
// (messageIdentifier, serialNumber) and fans it out to every connected gNB.
// Returns ErrPWSBroadcastNotFound if the key is unknown or was never recorded
// by this AMF (the mgmt handler maps that to 404). Ref: TS 38.413 §8.9.2.
func (s *Server) SendPWSCancel(ctx context.Context, messageIdentifier, serialNumber uint16, cancelAll bool) (int, error) {
	key := PWSKey{MessageIdentifier: messageIdentifier, SerialNumber: serialNumber}

	s.pwsMu.Lock()
	broadcast, found := s.pws[key]
	if !found {
		s.pwsMu.Unlock()
		return 0, ErrPWSBroadcastNotFound
	}
	now := time.Now()
	broadcast.CancelledAt = &now
	s.pwsMu.Unlock()

	s.mu.RLock()
	gnbs := make([]*GNBContext, 0, len(s.gnbs))
	for _, g := range s.gnbs {
		gnbs = append(gnbs, g)
	}
	s.mu.RUnlock()

	log := s.logger.With(
		"nf", "AMF",
		"procedure", "PublicWarningSystem",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "PWSCancelRequest",
		"message_identifier", messageIdentifier,
		"serial_number", serialNumber,
		"correlation_id", logging.CorrelationID(ctx),
		"spec_ref", "TS 38.413 §8.9.2",
	)

	if len(gnbs) == 0 {
		log.Warn("PWS Cancel accepted with no gNB connected", "gnbs_targeted", 0)
		return 0, nil
	}

	pdu := BuildPWSCancelRequest(messageIdentifier, serialNumber, nil, cancelAll)
	if pdu == nil {
		return 0, fmt.Errorf("amf: pws cancel: encode failed")
	}

	sent := 0
	for _, g := range gnbs {
		if _, err := writeNGAP(g.Conn, pdu); err != nil {
			log.Warn("PWS Cancel write failed", "gnb", g.Name, "gnb_addr", g.Conn.RemoteAddr().String(), "error", err)
			continue
		}
		sent++
	}
	log.Info("NGAP PWS Cancel Request sent", "gnbs_targeted", len(gnbs), "gnbs_sent", sent)
	return len(gnbs), nil
}

// handleWriteReplaceWarningResponse updates the per-gNB completion status for
// the broadcast identified by (MessageIdentifier, SerialNumber). A response
// with no matching broadcast entry is logged and dropped — correlation is by
// (MessageIdentifier, SerialNumber) only, per TS 23.041 §9.3.2.
func (s *Server) handleWriteReplaceWarningResponse(_ context.Context, gnb *GNBContext, msg *Message) {
	resp, ok := msg.Value.(*WriteReplaceWarningResponseMsg)
	if !ok {
		return
	}
	key := PWSKey{MessageIdentifier: resp.MessageIdentifier, SerialNumber: resp.SerialNumber}
	addr := gnb.Conn.RemoteAddr().String()

	s.pwsMu.Lock()
	broadcast, found := s.pws[key]
	if found {
		st, ok := broadcast.PerGNB[addr]
		if !ok {
			st = &PWSGNBStatus{GNBAddr: addr, GNBName: gnb.Name}
			broadcast.PerGNB[addr] = st
		}
		st.Completed = true
		st.Areas = resp.Areas
	}
	s.pwsMu.Unlock()

	log := s.logger.With(
		"nf", "AMF",
		"procedure", "PublicWarningSystem",
		"interface", "N2",
		"direction", "IN",
		"message_type", "WriteReplaceWarningResponse",
		"message_identifier", resp.MessageIdentifier,
		"serial_number", resp.SerialNumber,
		"gnb_addr", addr,
		"spec_ref", "TS 38.413 §8.9.1",
	)
	if !found {
		log.Warn("Write-Replace Warning Response for unknown broadcast")
		return
	}
	log.Info("Write-Replace Warning Response received", "areas", len(resp.Areas))
}

// handlePWSCancelResponse updates the per-gNB cancellation status for the
// broadcast identified by (MessageIdentifier, SerialNumber).
func (s *Server) handlePWSCancelResponse(_ context.Context, gnb *GNBContext, msg *Message) {
	resp, ok := msg.Value.(*PWSCancelResponseMsg)
	if !ok {
		return
	}
	key := PWSKey{MessageIdentifier: resp.MessageIdentifier, SerialNumber: resp.SerialNumber}
	addr := gnb.Conn.RemoteAddr().String()

	s.pwsMu.Lock()
	broadcast, found := s.pws[key]
	if found {
		st, ok := broadcast.PerGNB[addr]
		if !ok {
			st = &PWSGNBStatus{GNBAddr: addr, GNBName: gnb.Name}
			broadcast.PerGNB[addr] = st
		}
		st.Cancelled = true
		st.Areas = resp.Areas
	}
	s.pwsMu.Unlock()

	log := s.logger.With(
		"nf", "AMF",
		"procedure", "PublicWarningSystem",
		"interface", "N2",
		"direction", "IN",
		"message_type", "PWSCancelResponse",
		"message_identifier", resp.MessageIdentifier,
		"serial_number", resp.SerialNumber,
		"gnb_addr", addr,
		"spec_ref", "TS 38.413 §8.9.2",
	)
	if !found {
		log.Warn("PWS Cancel Response for unknown broadcast")
		return
	}
	log.Info("PWS Cancel Response received", "areas", len(resp.Areas))
}

// markPWSGNBFailed marks every in-flight (not yet completed/cancelled) PWS
// per-gNB entry for gnbAddr as failed. Called from the gNB disconnect cleanup
// path (handleGNBConn's defer) so a dropped SCTP association doesn't leave a
// broadcast entry stuck "pending" forever. Ref: TS 38.412 §7.
func (s *Server) markPWSGNBFailed(gnbAddr string) {
	s.pwsMu.Lock()
	defer s.pwsMu.Unlock()
	for _, b := range s.pws {
		if st, ok := b.PerGNB[gnbAddr]; ok && !st.Completed && !st.Cancelled {
			st.Failed = true
		}
	}
}

// PWSStatus returns a snapshot of one PWS broadcast's per-gNB completion
// status for the management API to poll. ok is false if the key is unknown.
func (s *Server) PWSStatus(messageIdentifier, serialNumber uint16) (PWSBroadcastStatus, bool) {
	key := PWSKey{MessageIdentifier: messageIdentifier, SerialNumber: serialNumber}
	s.pwsMu.Lock()
	defer s.pwsMu.Unlock()
	b, ok := s.pws[key]
	if !ok {
		return PWSBroadcastStatus{}, false
	}
	return snapshotPWSBroadcast(b), true
}

// PWSList returns a snapshot of every PWS broadcast the AMF has recorded
// (active or completed/cancelled). Order is not guaranteed.
func (s *Server) PWSList() []PWSBroadcastStatus {
	s.pwsMu.Lock()
	defer s.pwsMu.Unlock()
	out := make([]PWSBroadcastStatus, 0, len(s.pws))
	for _, b := range s.pws {
		out = append(out, snapshotPWSBroadcast(b))
	}
	return out
}

// snapshotPWSBroadcast must be called with s.pwsMu held.
func snapshotPWSBroadcast(b *PWSBroadcast) PWSBroadcastStatus {
	status := PWSBroadcastStatus{
		MessageIdentifier: b.Key.MessageIdentifier,
		SerialNumber:      b.Key.SerialNumber,
		GNBsTargeted:      b.GNBsTargeted,
		Cancelled:         b.CancelledAt != nil,
		CreatedAt:         b.CreatedAt,
	}
	for _, st := range b.PerGNB {
		status.PerGNB = append(status.PerGNB, *st)
		if st.Completed {
			status.GNBsCompleted++
		}
		if st.Cancelled {
			status.GNBsCancelled++
		}
	}
	return status
}
