package ngap

// pws_test.go — unit tests for the Public Warning System NGAP codec:
// BuildWriteReplaceWarningRequest / BuildPWSCancelRequest (AMF→gNB) and
// extractWriteReplaceWarningResponse / extractPWSCancelResponse (gNB→AMF).
// Ref: 3GPP TS 38.413 §8.9.1, §8.9.2; ProcedureCodes 51 / 32.

import (
	"testing"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	"github.com/francurieses/claudia-5gc/shared/gsm7"
)

// TestBuildWriteReplaceWarningRequest verifies the NGAP Write-Replace Warning
// Request encodes as a valid PDU (ProcedureCode=51, InitiatingMessage) with
// byte-exact MessageIdentifier/SerialNumber/DataCodingScheme/WarningMessageContents,
// and that the WarningAreaList round-trips as a TAIListForWarning.
func TestBuildWriteReplaceWarningRequest(t *testing.T) {
	plmn := plmnFromMCCMNC("001", "01")
	params := WriteReplaceWarningParams{
		MessageIdentifier:      0x1112,
		SerialNumber:           0x0001,
		TAIs:                   []TAIForPaging{{PLMN: plmn, TAC: 0x000001}},
		RepetitionPeriod:       DefaultRepetitionPeriod,
		NumberOfBroadcasts:     DefaultNumberOfBroadcasts,
		WarningType:            [WarningTypeLength]byte{0x10, 0x00},
		WarningSecurityInfo:    [WarningSecurityInfoLength]byte{}, // zero-filled dev placeholder
		DataCodingScheme:       0x00,
		WarningMessageContents: []byte("Tsunami warning: move to higher ground"),
	}

	pdu := BuildWriteReplaceWarningRequest(params)
	if len(pdu) == 0 {
		t.Fatal("BuildWriteReplaceWarningRequest returned nil/empty PDU")
	}

	decoded, err := libngap.Decoder(pdu)
	if err != nil {
		t.Fatalf("re-decode failed: %v", err)
	}
	if decoded.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatalf("expected InitiatingMessage, got %d", decoded.Present)
	}
	im := decoded.InitiatingMessage
	if im.ProcedureCode.Value != ngapType.ProcedureCodeWriteReplaceWarning {
		t.Fatalf("expected ProcedureCodeWriteReplaceWarning (51), got %d", im.ProcedureCode.Value)
	}
	req := im.Value.WriteReplaceWarningRequest
	if req == nil {
		t.Fatal("WriteReplaceWarningRequest is nil in decoded PDU")
	}

	var sawMsgID, sawSerial, sawArea, sawRepPeriod, sawNumBcast, sawWarnType, sawSecInfo, sawDCS, sawContents bool
	for _, ie := range req.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDMessageIdentifier:
			sawMsgID = true
			if ie.Value.MessageIdentifier == nil {
				t.Fatal("MessageIdentifier IE missing value")
			}
			if got := bitString16ToUint16(ie.Value.MessageIdentifier.Value); got != params.MessageIdentifier {
				t.Errorf("MessageIdentifier: want %#04x, got %#04x", params.MessageIdentifier, got)
			}
		case ngapType.ProtocolIEIDSerialNumber:
			sawSerial = true
			if ie.Value.SerialNumber == nil {
				t.Fatal("SerialNumber IE missing value")
			}
			if got := bitString16ToUint16(ie.Value.SerialNumber.Value); got != params.SerialNumber {
				t.Errorf("SerialNumber: want %#04x, got %#04x", params.SerialNumber, got)
			}
		case ngapType.ProtocolIEIDWarningAreaList:
			sawArea = true
			wal := ie.Value.WarningAreaList
			if wal == nil || wal.Present != ngapType.WarningAreaListPresentTAIListForWarning || wal.TAIListForWarning == nil {
				t.Fatalf("WarningAreaList not a TAIListForWarning: %+v", wal)
			}
			if len(wal.TAIListForWarning.List) != 1 {
				t.Fatalf("TAIListForWarning: want 1 item, got %d", len(wal.TAIListForWarning.List))
			}
			tac := wal.TAIListForWarning.List[0].TAC.Value
			if len(tac) != 3 || tac[2] != 0x01 {
				t.Errorf("TAC = %x, want 000001", tac)
			}
		case ngapType.ProtocolIEIDRepetitionPeriod:
			sawRepPeriod = true
			if ie.Value.RepetitionPeriod == nil || ie.Value.RepetitionPeriod.Value != params.RepetitionPeriod {
				t.Errorf("RepetitionPeriod: want %d, got %v", params.RepetitionPeriod, ie.Value.RepetitionPeriod)
			}
		case ngapType.ProtocolIEIDNumberOfBroadcastsRequested:
			sawNumBcast = true
			if ie.Value.NumberOfBroadcastsRequested == nil || ie.Value.NumberOfBroadcastsRequested.Value != params.NumberOfBroadcasts {
				t.Errorf("NumberOfBroadcastsRequested: want %d, got %v", params.NumberOfBroadcasts, ie.Value.NumberOfBroadcastsRequested)
			}
		case ngapType.ProtocolIEIDWarningType:
			sawWarnType = true
			if ie.Value.WarningType == nil || string(ie.Value.WarningType.Value) != string(params.WarningType[:]) {
				t.Errorf("WarningType: want %x, got %v", params.WarningType, ie.Value.WarningType)
			}
		case ngapType.ProtocolIEIDWarningSecurityInfo:
			sawSecInfo = true
			if ie.Value.WarningSecurityInfo == nil || len(ie.Value.WarningSecurityInfo.Value) != WarningSecurityInfoLength {
				t.Errorf("WarningSecurityInfo: want %d octets, got %v", WarningSecurityInfoLength, ie.Value.WarningSecurityInfo)
			}
		case ngapType.ProtocolIEIDDataCodingScheme:
			sawDCS = true
			if ie.Value.DataCodingScheme == nil || len(ie.Value.DataCodingScheme.Value.Bytes) != 1 || ie.Value.DataCodingScheme.Value.Bytes[0] != params.DataCodingScheme {
				t.Errorf("DataCodingScheme: want %#02x, got %v", params.DataCodingScheme, ie.Value.DataCodingScheme)
			}
		case ngapType.ProtocolIEIDWarningMessageContents:
			sawContents = true
			if ie.Value.WarningMessageContents == nil {
				t.Fatal("WarningMessageContents IE missing value")
			}
			wire := []byte(ie.Value.WarningMessageContents.Value)
			if wire[0] != 1 {
				t.Errorf("WarningMessageContents Number-of-Pages: want 1, got %d", wire[0])
			}
			if len(wire) != 1+cbsPageContentLength+1 {
				t.Errorf("WarningMessageContents wire length: want %d (1 page), got %d", 1+cbsPageContentLength+1, len(wire))
			}
			if got := DecodeWarningMessageContentPages(params.DataCodingScheme, wire); string(got) != string(params.WarningMessageContents) {
				t.Errorf("WarningMessageContents round-trip: want %q, got %q", params.WarningMessageContents, got)
			}
		}
	}
	if !sawMsgID || !sawSerial || !sawArea || !sawRepPeriod || !sawNumBcast || !sawWarnType || !sawSecInfo || !sawDCS || !sawContents {
		t.Errorf("missing IEs: msgID=%v serial=%v area=%v repPeriod=%v numBcast=%v warnType=%v secInfo=%v dcs=%v contents=%v",
			sawMsgID, sawSerial, sawArea, sawRepPeriod, sawNumBcast, sawWarnType, sawSecInfo, sawDCS, sawContents)
	}
}

// TestEncodeDecodeWarningMessageContentPages_8Bit verifies the CBS Message
// Information Page framing (TS 23.041 §9.4.2.2.5) round-trips for the empty,
// single-page, multi-page, and truncation-at-15-pages cases under the 8-bit
// data alphabet (DCS 0xF4), and that the wire Number-of-Pages octet matches
// what a real dissector expects.
func TestEncodeDecodeWarningMessageContentPages_8Bit(t *testing.T) {
	const dcs8Bit = 0xF4 // Data coding/message class, 8-bit data, class 0
	cases := []struct {
		name      string
		text      []byte
		wantPages int
	}{
		{"empty", nil, 1},
		{"short", []byte("Tsunami warning: move to higher ground"), 1},
		{"exactly one page", make([]byte, cbsPageContentLength), 1},
		{"spans two pages", make([]byte, cbsPageContentLength+1), 2},
		{"truncated at max pages", make([]byte, cbsPageContentLength*cbsMaxPages+50), cbsMaxPages},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := range tc.text {
				tc.text[i] = byte('a' + i%26)
			}
			wire := encodeWarningMessageContentPages(dcs8Bit, "", tc.text)
			if len(wire) < 1 {
				t.Fatal("encodeWarningMessageContentPages returned empty wire")
			}
			if int(wire[0]) != tc.wantPages {
				t.Errorf("Number-of-Pages: want %d, got %d", tc.wantPages, wire[0])
			}
			wantWireLen := 1 + tc.wantPages*(cbsPageContentLength+1)
			if len(wire) != wantWireLen {
				t.Errorf("wire length: want %d, got %d", wantWireLen, len(wire))
			}
			want := tc.text
			if len(want) > cbsPageContentLength*cbsMaxPages {
				want = want[:cbsPageContentLength*cbsMaxPages]
			}
			if got := DecodeWarningMessageContentPages(dcs8Bit, wire); string(got) != string(want) {
				t.Errorf("round-trip: want %q, got %q", want, got)
			}
		})
	}
}

// TestEncodeDecodeWarningMessageContentPages_GSM7 verifies the GSM 7-bit
// default alphabet path: septet packing (TS 23.038 §6.1.2.2.1), the 93
// septets/page page boundary (TS 23.038 §5), and round-trip decode.
func TestEncodeDecodeWarningMessageContentPages_GSM7(t *testing.T) {
	const dcsGSM7Unspecified = 0x0F // language using GSM7, language unspecified
	cases := []struct {
		name      string
		text      string
		wantPages int
	}{
		{"empty", "", 1},
		{"short", "Tsunami warning: move to higher ground", 1},
		{"exactly one page (93 chars)", stringOfLen(93, 'a'), 1},
		{"spans two pages (94 chars)", stringOfLen(94, 'a'), 2},
		{"extension-table chars", "€ price [bracket] {brace} ~tilde~", 1},
		{"truncated at max pages", stringOfLen(93*cbsMaxPages+50, 'a'), cbsMaxPages},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := encodeWarningMessageContentPages(dcsGSM7Unspecified, "", []byte(tc.text))
			if len(wire) < 1 {
				t.Fatal("encodeWarningMessageContentPages returned empty wire")
			}
			if int(wire[0]) != tc.wantPages {
				t.Errorf("Number-of-Pages: want %d, got %d", tc.wantPages, wire[0])
			}
			// Every page's packed content must fit within the 82-octet page.
			for i := 1; i < len(wire); i += cbsPageContentLength + 1 {
				n := wire[i+cbsPageContentLength]
				if n > cbsPageContentLength {
					t.Errorf("page used-length %d exceeds cbsPageContentLength", n)
				}
			}
			want := tc.text
			if len(want) > 93*cbsMaxPages {
				want = want[:93*cbsMaxPages]
			}
			if got := DecodeWarningMessageContentPages(dcsGSM7Unspecified, wire); string(got) != want {
				t.Errorf("round-trip: want %q, got %q", want, got)
			}
		})
	}
}

// TestEncodeDecodeWarningMessageContentPages_UCS2 verifies the UCS2 alphabet
// path: 2-byte big-endian characters, 41 chars/page boundary (TS 23.038 §5).
func TestEncodeDecodeWarningMessageContentPages_UCS2(t *testing.T) {
	const dcsUCS2 = 0x48 // General Data Coding indication, UCS2 (bits3-2=10)
	cases := []struct {
		name      string
		text      string
		wantPages int
	}{
		{"empty", "", 1},
		{"short unicode", "警報: 高台へ避難してください", 1},
		{"exactly one page (41 chars)", stringOfLen(41, 'a'), 1},
		{"spans two pages (42 chars)", stringOfLen(42, 'a'), 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := encodeWarningMessageContentPages(dcsUCS2, "", []byte(tc.text))
			if len(wire) < 1 {
				t.Fatal("encodeWarningMessageContentPages returned empty wire")
			}
			if int(wire[0]) != tc.wantPages {
				t.Errorf("Number-of-Pages: want %d, got %d", tc.wantPages, wire[0])
			}
			if got := DecodeWarningMessageContentPages(dcsUCS2, wire); string(got) != tc.text {
				t.Errorf("round-trip: want %q, got %q", tc.text, got)
			}
		})
	}
}

// TestEncodeDecodeWarningMessageContentPages_UCS2Language verifies the DCS 0x11
// path: a 2-octet ISO 639 language-indication prefix on page 0, then the UCS2
// body, with the prefix recoverable and the body round-tripping (TS 23.038 §5).
func TestEncodeDecodeWarningMessageContentPages_UCS2Language(t *testing.T) {
	const dcsUCS2Lang = 0x11
	text := "警報: 高台へ避難してください"
	wire := encodeWarningMessageContentPages(dcsUCS2Lang, "ja", []byte(text))

	// Page 0's first 2 octets must decode back to the language code.
	if len(wire) < 1+ucs2LanguagePrefixLen {
		t.Fatalf("wire too short: %d octets", len(wire))
	}
	page0 := wire[1 : 1+cbsPageContentLength]
	if got := gsm7.DecodeUCS2LanguagePrefix(page0[:ucs2LanguagePrefixLen]); got != "ja" {
		t.Errorf("language prefix: want %q, got %q", "ja", got)
	}
	// The body must round-trip with the prefix stripped.
	if got := DecodeWarningMessageContentPages(dcsUCS2Lang, wire); string(got) != text {
		t.Errorf("UCS2+language round-trip: want %q, got %q", text, got)
	}

	// Without a language, DCS 0x48 has no prefix and still round-trips.
	const dcsUCS2NoLang = 0x48
	wireNoLang := encodeWarningMessageContentPages(dcsUCS2NoLang, "", []byte(text))
	if got := DecodeWarningMessageContentPages(dcsUCS2NoLang, wireNoLang); string(got) != text {
		t.Errorf("UCS2 no-language round-trip: want %q, got %q", text, got)
	}
}

// TestPwsLanguageLabel verifies the log-label resolution: GSM7 coding-group DCS
// → name, UCS2 0x11 → ISO code, otherwise "unspecified".
func TestPwsLanguageLabel(t *testing.T) {
	cases := []struct {
		dcs  byte
		iso  string
		want string
	}{
		{0x04, "", "Spanish"},     // GSM7 coding group wins over empty ISO
		{0x04, "en", "Spanish"},   // GSM7 coding group wins over ISO
		{0x11, "ja", "ja"},        // UCS2 prefix language
		{0x48, "", "unspecified"}, // UCS2 general, no language
		{0xF4, "", "unspecified"}, // 8-bit, no language
	}
	for _, tc := range cases {
		if got := pwsLanguageLabel(tc.dcs, tc.iso); got != tc.want {
			t.Errorf("pwsLanguageLabel(%#02x, %q) = %q, want %q", tc.dcs, tc.iso, got, tc.want)
		}
	}
}

func stringOfLen(n int, _ byte) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + byte(i)%26
	}
	return string(b)
}

// TestBuildPWSCancelRequest verifies the NGAP PWS Cancel Request encodes as a
// valid PDU (ProcedureCode=32, InitiatingMessage) with byte-exact
// MessageIdentifier/SerialNumber and the CancelAllWarningMessages shortcut IE.
func TestBuildPWSCancelRequest(t *testing.T) {
	const messageIdentifier uint16 = 0x1112
	const serialNumber uint16 = 0x0001

	pdu := BuildPWSCancelRequest(messageIdentifier, serialNumber, nil, true)
	if len(pdu) == 0 {
		t.Fatal("BuildPWSCancelRequest returned nil/empty PDU")
	}

	decoded, err := libngap.Decoder(pdu)
	if err != nil {
		t.Fatalf("re-decode failed: %v", err)
	}
	if decoded.Present != ngapType.NGAPPDUPresentInitiatingMessage {
		t.Fatalf("expected InitiatingMessage, got %d", decoded.Present)
	}
	im := decoded.InitiatingMessage
	if im.ProcedureCode.Value != ngapType.ProcedureCodePWSCancel {
		t.Fatalf("expected ProcedureCodePWSCancel (32), got %d", im.ProcedureCode.Value)
	}
	req := im.Value.PWSCancelRequest
	if req == nil {
		t.Fatal("PWSCancelRequest is nil in decoded PDU")
	}

	var sawMsgID, sawSerial, sawCancelAll bool
	for _, ie := range req.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDMessageIdentifier:
			sawMsgID = true
			if ie.Value.MessageIdentifier == nil || bitString16ToUint16(ie.Value.MessageIdentifier.Value) != messageIdentifier {
				t.Errorf("MessageIdentifier: want %#04x, got %v", messageIdentifier, ie.Value.MessageIdentifier)
			}
		case ngapType.ProtocolIEIDSerialNumber:
			sawSerial = true
			if ie.Value.SerialNumber == nil || bitString16ToUint16(ie.Value.SerialNumber.Value) != serialNumber {
				t.Errorf("SerialNumber: want %#04x, got %v", serialNumber, ie.Value.SerialNumber)
			}
		case ngapType.ProtocolIEIDCancelAllWarningMessages:
			sawCancelAll = true
			if ie.Value.CancelAllWarningMessages == nil || ie.Value.CancelAllWarningMessages.Value != ngapType.CancelAllWarningMessagesPresentTrue {
				t.Errorf("CancelAllWarningMessages: want true, got %v", ie.Value.CancelAllWarningMessages)
			}
		}
	}
	if !sawMsgID || !sawSerial || !sawCancelAll {
		t.Errorf("missing IEs: msgID=%v serial=%v cancelAll=%v", sawMsgID, sawSerial, sawCancelAll)
	}
}

// TestBuildPWSCancelRequest_WithWarningAreaList verifies the optional
// WarningAreaList round-trips when TAIs are supplied instead of CancelAll.
func TestBuildPWSCancelRequest_WithWarningAreaList(t *testing.T) {
	plmn := plmnFromMCCMNC("001", "01")
	pdu := BuildPWSCancelRequest(0x4370, 0x0001, []TAIForPaging{{PLMN: plmn, TAC: 0x000002}}, false)
	if len(pdu) == 0 {
		t.Fatal("BuildPWSCancelRequest returned nil/empty PDU")
	}
	decoded, err := libngap.Decoder(pdu)
	if err != nil {
		t.Fatalf("re-decode failed: %v", err)
	}
	req := decoded.InitiatingMessage.Value.PWSCancelRequest
	var sawArea bool
	for _, ie := range req.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDWarningAreaList {
			sawArea = true
			wal := ie.Value.WarningAreaList
			if wal == nil || wal.TAIListForWarning == nil || len(wal.TAIListForWarning.List) != 1 {
				t.Fatalf("WarningAreaList not decoded correctly: %+v", wal)
			}
			tac := wal.TAIListForWarning.List[0].TAC.Value
			if len(tac) != 3 || tac[2] != 0x02 {
				t.Errorf("TAC = %x, want 000002", tac)
			}
		}
	}
	if !sawArea {
		t.Error("WarningAreaList IE missing")
	}
}

// TestExtractWriteReplaceWarningResponse verifies that a synthetic gNB
// Write-Replace Warning Response (ProcedureCode=51, SuccessfulOutcome) is
// decoded correctly by DecodeNGAPPDU + extractWriteReplaceWarningResponse,
// including the BroadcastCompletedAreaList (TAIBroadcastNR variant).
func TestExtractWriteReplaceWarningResponse(t *testing.T) {
	const messageIdentifier uint16 = 0x4370
	const serialNumber uint16 = 0x0001
	plmn := plmnFromMCCMNC("001", "01")

	rawPDU := buildSyntheticWriteReplaceWarningResponse(t, messageIdentifier, serialNumber, plmn, 0x000001)

	msg, err := DecodeNGAPPDU(rawPDU)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU: %v", err)
	}
	if msg.Type != 1 { // SuccessfulOutcome
		t.Fatalf("expected SuccessfulOutcome (1), got %d", msg.Type)
	}
	if msg.ProcedureCode != ProcWriteReplaceWarning {
		t.Fatalf("expected ProcWriteReplaceWarning (%d), got %d", ProcWriteReplaceWarning, msg.ProcedureCode)
	}

	result, ok := msg.Value.(*WriteReplaceWarningResponseMsg)
	if !ok || result == nil {
		t.Fatalf("Value is not *WriteReplaceWarningResponseMsg: %T", msg.Value)
	}
	if result.MessageIdentifier != messageIdentifier {
		t.Errorf("MessageIdentifier: want %#04x, got %#04x", messageIdentifier, result.MessageIdentifier)
	}
	if result.SerialNumber != serialNumber {
		t.Errorf("SerialNumber: want %#04x, got %#04x", serialNumber, result.SerialNumber)
	}
	if len(result.Areas) != 1 {
		t.Fatalf("expected 1 completed area, got %d", len(result.Areas))
	}
	if result.Areas[0].TAC != 0x000001 {
		t.Errorf("TAC: want 1, got %d", result.Areas[0].TAC)
	}
}

// TestExtractPWSCancelResponse verifies that a synthetic gNB PWS Cancel
// Response (ProcedureCode=32, SuccessfulOutcome) is decoded correctly,
// including the BroadcastCancelledAreaList (TAICancelledNR variant).
func TestExtractPWSCancelResponse(t *testing.T) {
	const messageIdentifier uint16 = 0x4370
	const serialNumber uint16 = 0x0001
	plmn := plmnFromMCCMNC("001", "01")

	rawPDU := buildSyntheticPWSCancelResponse(t, messageIdentifier, serialNumber, plmn, 0x000002)

	msg, err := DecodeNGAPPDU(rawPDU)
	if err != nil {
		t.Fatalf("DecodeNGAPPDU: %v", err)
	}
	if msg.Type != 1 { // SuccessfulOutcome
		t.Fatalf("expected SuccessfulOutcome (1), got %d", msg.Type)
	}
	if msg.ProcedureCode != ProcPWSCancel {
		t.Fatalf("expected ProcPWSCancel (%d), got %d", ProcPWSCancel, msg.ProcedureCode)
	}

	result, ok := msg.Value.(*PWSCancelResponseMsg)
	if !ok || result == nil {
		t.Fatalf("Value is not *PWSCancelResponseMsg: %T", msg.Value)
	}
	if result.MessageIdentifier != messageIdentifier {
		t.Errorf("MessageIdentifier: want %#04x, got %#04x", messageIdentifier, result.MessageIdentifier)
	}
	if result.SerialNumber != serialNumber {
		t.Errorf("SerialNumber: want %#04x, got %#04x", serialNumber, result.SerialNumber)
	}
	if len(result.Areas) != 1 {
		t.Fatalf("expected 1 cancelled area, got %d", len(result.Areas))
	}
	if result.Areas[0].TAC != 0x000002 {
		t.Errorf("TAC: want 2, got %d", result.Areas[0].TAC)
	}
}

func buildSyntheticWriteReplaceWarningResponse(t *testing.T, messageIdentifier, serialNumber uint16, plmn []byte, tac uint32) []byte {
	t.Helper()
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeWriteReplaceWarning},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentWriteReplaceWarningResponse,
				WriteReplaceWarningResponse: &ngapType.WriteReplaceWarningResponse{
					ProtocolIEs: ngapType.ProtocolIEContainerWriteReplaceWarningResponseIEs{
						List: []ngapType.WriteReplaceWarningResponseIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDMessageIdentifier},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.WriteReplaceWarningResponseIEsValue{
									Present:           ngapType.WriteReplaceWarningResponseIEsPresentMessageIdentifier,
									MessageIdentifier: &ngapType.MessageIdentifier{Value: uint16ToBitString16(messageIdentifier)},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDSerialNumber},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.WriteReplaceWarningResponseIEsValue{
									Present:      ngapType.WriteReplaceWarningResponseIEsPresentSerialNumber,
									SerialNumber: &ngapType.SerialNumber{Value: uint16ToBitString16(serialNumber)},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDBroadcastCompletedAreaList},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.WriteReplaceWarningResponseIEsValue{
									Present: ngapType.WriteReplaceWarningResponseIEsPresentBroadcastCompletedAreaList,
									BroadcastCompletedAreaList: &ngapType.BroadcastCompletedAreaList{
										Present: ngapType.BroadcastCompletedAreaListPresentTAIBroadcastNR,
										TAIBroadcastNR: &ngapType.TAIBroadcastNR{
											List: []ngapType.TAIBroadcastNRItem{
												{
													TAI: ngapType.TAI{
														PLMNIdentity: ngapType.PLMNIdentity{Value: plmn},
														TAC:          ngapType.TAC{Value: aper.OctetString{byte(tac >> 16), byte(tac >> 8), byte(tac)}},
													},
													CompletedCellsInTAINR: ngapType.CompletedCellsInTAINR{
														List: []ngapType.CompletedCellsInTAINRItem{
															{
																NRCGI: ngapType.NRCGI{
																	PLMNIdentity:   ngapType.PLMNIdentity{Value: plmn},
																	NRCellIdentity: ngapType.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0, 0, 0, 0, 0}, BitLength: 36}},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode synthetic WriteReplaceWarningResponse: %v", err)
	}
	return b
}

func buildSyntheticPWSCancelResponse(t *testing.T, messageIdentifier, serialNumber uint16, plmn []byte, tac uint32) []byte {
	t.Helper()
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePWSCancel},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentPWSCancelResponse,
				PWSCancelResponse: &ngapType.PWSCancelResponse{
					ProtocolIEs: ngapType.ProtocolIEContainerPWSCancelResponseIEs{
						List: []ngapType.PWSCancelResponseIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDMessageIdentifier},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PWSCancelResponseIEsValue{
									Present:           ngapType.PWSCancelResponseIEsPresentMessageIdentifier,
									MessageIdentifier: &ngapType.MessageIdentifier{Value: uint16ToBitString16(messageIdentifier)},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDSerialNumber},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PWSCancelResponseIEsValue{
									Present:      ngapType.PWSCancelResponseIEsPresentSerialNumber,
									SerialNumber: &ngapType.SerialNumber{Value: uint16ToBitString16(serialNumber)},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDBroadcastCancelledAreaList},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PWSCancelResponseIEsValue{
									Present: ngapType.PWSCancelResponseIEsPresentBroadcastCancelledAreaList,
									BroadcastCancelledAreaList: &ngapType.BroadcastCancelledAreaList{
										Present: ngapType.BroadcastCancelledAreaListPresentTAICancelledNR,
										TAICancelledNR: &ngapType.TAICancelledNR{
											List: []ngapType.TAICancelledNRItem{
												{
													TAI: ngapType.TAI{
														PLMNIdentity: ngapType.PLMNIdentity{Value: plmn},
														TAC:          ngapType.TAC{Value: aper.OctetString{byte(tac >> 16), byte(tac >> 8), byte(tac)}},
													},
													CancelledCellsInTAINR: ngapType.CancelledCellsInTAINR{
														List: []ngapType.CancelledCellsInTAINRItem{
															{
																NRCGI: ngapType.NRCGI{
																	PLMNIdentity:   ngapType.PLMNIdentity{Value: plmn},
																	NRCellIdentity: ngapType.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0, 0, 0, 0, 0}, BitLength: 36}},
																},
																NumberOfBroadcasts: ngapType.NumberOfBroadcasts{Value: 1},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode synthetic PWSCancelResponse: %v", err)
	}
	return b
}
