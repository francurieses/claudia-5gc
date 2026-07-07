package nas_test

// Tests for the NAS-5GS PDU codec.
// Ref: 3GPP TS 24.501 v17.x.x

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// ---- Reader -----------------------------------------------------------------

func TestReader_Basic(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	r := nas.NewReader(data)

	if r.Len() != 5 {
		t.Errorf("Len: got %d, want 5", r.Len())
	}

	b, err := r.ReadByte()
	if err != nil || b != 0x01 {
		t.Errorf("ReadByte: got %d err %v, want 0x01 nil", b, err)
	}
	if r.Len() != 4 {
		t.Errorf("Len after ReadByte: got %d, want 4", r.Len())
	}

	peek, err := r.PeekByte()
	if err != nil || peek != 0x02 {
		t.Errorf("PeekByte: got %d err %v, want 0x02 nil", peek, err)
	}
	if r.Len() != 4 {
		t.Error("PeekByte should not advance position")
	}

	chunk, err := r.ReadBytes(2)
	if err != nil || !bytes.Equal(chunk, []byte{0x02, 0x03}) {
		t.Errorf("ReadBytes(2): got %x err %v, want 0203 nil", chunk, err)
	}

	rem := r.Remaining()
	if !bytes.Equal(rem, []byte{0x04, 0x05}) {
		t.Errorf("Remaining: got %x, want 0405", rem)
	}
}

func TestReader_EOF(t *testing.T) {
	r := nas.NewReader([]byte{0x01})
	r.ReadByte() // consume the only byte

	_, err := r.ReadByte()
	if err == nil {
		t.Error("ReadByte past end should return error")
	}
	_, err = r.PeekByte()
	if err == nil {
		t.Error("PeekByte past end should return error")
	}
	_, err = r.ReadBytes(1)
	if err == nil {
		t.Error("ReadBytes past end should return error")
	}
}

// ---- Decode -----------------------------------------------------------------

func TestDecode_TooShort(t *testing.T) {
	for _, data := range [][]byte{nil, {}, {0x7E}, {0x7E, 0x00}} {
		_, err := nas.Decode(data)
		if err == nil {
			t.Errorf("Decode(%x): expected error for too-short PDU", data)
		}
	}
}

func TestDecode_PlainNAS_UnknownMsgType(t *testing.T) {
	// Plain NAS PDU with an unrecognised message type → RawBody
	data := []byte{0x7E, 0x00, 0xFF, 0xAA, 0xBB}
	msg, err := nas.Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if msg.Header.ExtendedProtocolDiscriminator != 0x7E {
		t.Errorf("EPD: got %x, want 7E", msg.Header.ExtendedProtocolDiscriminator)
	}
	if msg.Header.SecurityHeaderType != nas.SecurityHeaderPlainNAS {
		t.Errorf("SHT: got %d, want plain", msg.Header.SecurityHeaderType)
	}
	rb, ok := msg.Body.(*nas.RawBody)
	if !ok {
		t.Fatal("expected RawBody for unknown message type")
	}
	if !bytes.Equal(rb.Data, []byte{0xAA, 0xBB}) {
		t.Errorf("RawBody.Data: got %x, want aabb", rb.Data)
	}
}

func TestDecode_SecurityProtected_Header(t *testing.T) {
	// Security-protected PDU:
	// EPD(1) | SHT(1) | MAC(4) | SN(1) | inner EPD(1) | inner SHT(1) | inner MT(1) | body...
	data := []byte{
		0x7E,                   // EPD
		0x02,                   // SHT = IntegrityProtectedAndCiphered
		0xDE, 0xAD, 0xBE, 0xEF, // MAC
		0x42,       // Sequence Number
		0x7E, 0x00, // inner EPD + inner SHT (plain inner)
		0x64,       // inner MsgType = Status5GMM (0x64) → RawBody
		0xCA, 0xFE, // inner body bytes
	}
	msg, err := nas.Decode(data)
	if err != nil {
		t.Fatalf("Decode security-protected: %v", err)
	}
	if msg.Header.SecurityHeaderType != nas.SecurityHeaderIntegrityProtectedAndCiphered {
		t.Errorf("SHT: got %d, want %d", msg.Header.SecurityHeaderType, nas.SecurityHeaderIntegrityProtectedAndCiphered)
	}
	if msg.Header.MessageAuthenticationCode != [4]byte{0xDE, 0xAD, 0xBE, 0xEF} {
		t.Errorf("MAC: got %x, want deadbeef", msg.Header.MessageAuthenticationCode)
	}
	if msg.Header.SequenceNumber != 0x42 {
		t.Errorf("SN: got %x, want 42", msg.Header.SequenceNumber)
	}
	if msg.Header.MessageType != 0x64 {
		t.Errorf("inner MsgType: got %x, want 64", msg.Header.MessageType)
	}
}

// ---- Authentication Request -------------------------------------------------

func buildAuthRequest() *nas.AuthenticationRequest {
	ar := &nas.AuthenticationRequest{
		NGKSI: nas.NGKSI{Type: 0, KeySetIdentifier: 3},
		ABBA:  nas.ABBA{0x00, 0x00},
	}
	for i := range ar.RAND {
		ar.RAND[i] = 0xAA
	}
	for i := range ar.AUTN {
		ar.AUTN[i] = 0xBB
	}
	return ar
}

func TestAuthenticationRequest_EncodeDecodeRoundtrip(t *testing.T) {
	orig := buildAuthRequest()

	pdu := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			SecurityHeaderType:            nas.SecurityHeaderPlainNAS,
			MessageType:                   nas.MsgTypeAuthenticationRequest,
		},
		Body: orig,
	}

	encoded, err := nas.Encode(pdu)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := nas.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Header.MessageType != nas.MsgTypeAuthenticationRequest {
		t.Errorf("MessageType: got %x, want %x", decoded.Header.MessageType, nas.MsgTypeAuthenticationRequest)
	}

	ar, ok := decoded.Body.(*nas.AuthenticationRequest)
	if !ok {
		t.Fatalf("expected *AuthenticationRequest, got %T", decoded.Body)
	}
	if ar.NGKSI.KeySetIdentifier != orig.NGKSI.KeySetIdentifier {
		t.Errorf("NGKSI.KSI: got %d, want %d", ar.NGKSI.KeySetIdentifier, orig.NGKSI.KeySetIdentifier)
	}
	if ar.ABBA != orig.ABBA {
		t.Errorf("ABBA: got %x, want %x", ar.ABBA, orig.ABBA)
	}
	if ar.RAND != orig.RAND {
		t.Errorf("RAND mismatch")
	}
	if ar.AUTN != orig.AUTN {
		t.Errorf("AUTN mismatch")
	}
}

// ---- Authentication Response ------------------------------------------------

func TestDecodeAuthenticationResponse_WithRES(t *testing.T) {
	// Body: IEI 0x2D (RES* TLV) || len || RES* bytes
	resStarBytes := bytes.Repeat([]byte{0xCC}, 16)
	body := append([]byte{0x2D, 0x10}, resStarBytes...)

	pdu := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeAuthenticationResponse)}
	pdu = append(pdu, body...)

	msg, err := nas.Decode(pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ar, ok := msg.Body.(*nas.AuthenticationResponse)
	if !ok {
		t.Fatalf("expected *AuthenticationResponse, got %T", msg.Body)
	}
	if !bytes.Equal(ar.RES, resStarBytes) {
		t.Errorf("RES*: got %x, want %x", ar.RES, resStarBytes)
	}
}

// ---- Authentication Failure -------------------------------------------------

func TestDecodeAuthenticationFailure_MACFailure(t *testing.T) {
	// Body: cause byte
	cause := byte(nas.CauseMACFailure)
	pdu := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeAuthenticationFailure), cause}

	msg, err := nas.Decode(pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	af, ok := msg.Body.(*nas.AuthenticationFailure)
	if !ok {
		t.Fatalf("expected *AuthenticationFailure, got %T", msg.Body)
	}
	if af.Cause5GMM != nas.CauseMACFailure {
		t.Errorf("Cause5GMM: got %d, want %d", af.Cause5GMM, nas.CauseMACFailure)
	}
}

func TestDecodeAuthenticationFailure_SynchWithAUTS(t *testing.T) {
	cause := byte(nas.CauseSynchFailure)
	auts := bytes.Repeat([]byte{0xDD}, 14)
	// IEI 0x30 (AUTS) TLV
	body := append([]byte{cause, 0x30, byte(len(auts))}, auts...)
	pdu := append([]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeAuthenticationFailure)}, body...)

	msg, err := nas.Decode(pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	af, _ := msg.Body.(*nas.AuthenticationFailure)
	if af.Cause5GMM != nas.CauseSynchFailure {
		t.Errorf("Cause5GMM: got %d, want %d", af.Cause5GMM, nas.CauseSynchFailure)
	}
	if !bytes.Equal(af.AUTS, auts) {
		t.Errorf("AUTS: got %x, want %x", af.AUTS, auts)
	}
}

// ---- Security Mode Command --------------------------------------------------

func buildSMC() *nas.SecurityModeCommand {
	return &nas.SecurityModeCommand{
		SelectedNASSecurityAlgorithms: nas.NASSecurityAlgorithms{
			CipheringAlgorithmID: 0x02, // 128-NEA2
			IntegrityAlgorithmID: 0x02, // 128-NIA2
		},
		NGKSI: nas.NGKSI{Type: 0, KeySetIdentifier: 1},
		ReplayedUESecurityCapabilities: nas.UESecurityCapability{
			EA0: true, EA1: true, EA2: true,
			IA0: true, IA1: true, IA2: true,
		},
	}
}

func TestSecurityModeCommand_EncodeDecodeRoundtrip(t *testing.T) {
	orig := buildSMC()

	pdu := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			MessageType:                   nas.MsgTypeSecurityModeCommand,
		},
		Body: orig,
	}

	encoded, err := nas.Encode(pdu)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := nas.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	smc, ok := decoded.Body.(*nas.SecurityModeCommand)
	if !ok {
		t.Fatalf("expected *SecurityModeCommand, got %T", decoded.Body)
	}
	if smc.SelectedNASSecurityAlgorithms != orig.SelectedNASSecurityAlgorithms {
		t.Errorf("NAS sec alg: got %+v, want %+v",
			smc.SelectedNASSecurityAlgorithms, orig.SelectedNASSecurityAlgorithms)
	}
	if smc.NGKSI.KeySetIdentifier != orig.NGKSI.KeySetIdentifier {
		t.Errorf("NGKSI.KSI: got %d, want %d",
			smc.NGKSI.KeySetIdentifier, orig.NGKSI.KeySetIdentifier)
	}
	if smc.ReplayedUESecurityCapabilities.EA2 != true {
		t.Error("EA2 should be supported in replayed caps")
	}
	if smc.ReplayedUESecurityCapabilities.IA2 != true {
		t.Error("IA2 should be supported in replayed caps")
	}
}

// ---- Security Mode Complete -------------------------------------------------

func TestDecodeSecurityModeComplete_WithNASContainer(t *testing.T) {
	container := []byte{0x7E, 0x00, 0x41, 0x01} // inner Registration Request stub
	// IEI 0x71 (NAS message container) LV-E: 2-byte length
	ieiBytes := append([]byte{0x71, 0x00, byte(len(container))}, container...)

	pdu := append([]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeSecurityModeComplete)}, ieiBytes...)

	msg, err := nas.Decode(pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	smc, ok := msg.Body.(*nas.SecurityModeComplete)
	if !ok {
		t.Fatalf("expected *SecurityModeComplete, got %T", msg.Body)
	}
	if !bytes.Equal(smc.NASMessageContainer, container) {
		t.Errorf("NASMessageContainer: got %x, want %x", smc.NASMessageContainer, container)
	}
}

// ---- Identity Request / Response --------------------------------------------

func TestIdentityRequest_EncodeDecodeRoundtrip(t *testing.T) {
	ir := &nas.IdentityRequest{IdentityType: nas.MobileIdentitySUCI}

	pdu := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			MessageType:                   nas.MsgTypeIdentityRequest,
		},
		Body: ir,
	}
	encoded, err := nas.Encode(pdu)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := nas.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	irDec, ok := decoded.Body.(*nas.IdentityRequest)
	if !ok {
		t.Fatalf("expected *IdentityRequest, got %T", decoded.Body)
	}
	if irDec.IdentityType != nas.MobileIdentitySUCI {
		t.Errorf("IdentityType: got %d, want %d", irDec.IdentityType, nas.MobileIdentitySUCI)
	}
}

func TestDecodeIdentityResponse_GUTI(t *testing.T) {
	// Build a GUTI mobile identity: type(1) + MCC/MNC(3) + RegID(1) + AMFRef(2) + TMSI(4) = 11 bytes
	// encodeMCCMNC("208","93") = [0x02, 0xF8, 0x39]
	gutiBytes := []byte{
		0x02,             // type = GUTI (2), SUPIFormat = 0
		0x02, 0xF8, 0x39, // MCC=208, MNC=93
		0xAB,       // AMF Region ID
		0x00, 0x41, // AMFSetID=1 (10 bits), AMFID=1 (6 bits) → (1<<6)|1 = 0x41
		0x12, 0x34, 0x56, 0x78, // TMSI
	}
	// Identity Response body: LV-E (2-byte big-endian length) + MI bytes per TS 24.501 §8.2.14.1 IE type 6
	body := append([]byte{0x00, byte(len(gutiBytes))}, gutiBytes...)
	pdu := append([]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeIdentityResponse)}, body...)

	msg, err := nas.Decode(pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ir, ok := msg.Body.(*nas.IdentityResponse)
	if !ok {
		t.Fatalf("expected *IdentityResponse, got %T", msg.Body)
	}
	if ir.MobileIdentity.Type != nas.MobileIdentityGUTI {
		t.Errorf("Type: got %d, want GUTI(%d)", ir.MobileIdentity.Type, nas.MobileIdentityGUTI)
	}
	g := ir.MobileIdentity.GUTI
	if g == nil {
		t.Fatal("GUTI is nil")
	}
	if g.MCC != "208" || g.MNC != "93" {
		t.Errorf("MCC/MNC: got %s/%s, want 208/93", g.MCC, g.MNC)
	}
	if g.AMFRegionID != 0xAB {
		t.Errorf("AMFRegionID: got %x, want AB", g.AMFRegionID)
	}
	if g.TMSI != 0x12345678 {
		t.Errorf("TMSI: got %x, want 12345678", g.TMSI)
	}
}

// ---- Registration Request ---------------------------------------------------

func TestDecodeRegistrationRequest_Minimal(t *testing.T) {
	// Body layout per TS 24.501 §8.2.6.1:
	//   byte 0 (combined): spare(0)|TSC(0=native)|KSI(001=1) | FOR(0)|reg_type(001=initial)
	//                    = 0b_0001_0001 = 0x11
	//   bytes 1-2: MI length (LV-E 2-byte): 0x00 0x01 = 1 byte
	//   byte 3: MI content — type = 0 (No Identity)
	body := []byte{0x11, 0x00, 0x01, 0x00}
	pdu := append([]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationRequest)}, body...)

	msg, err := nas.Decode(pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rr, ok := msg.Body.(*nas.RegistrationRequest)
	if !ok {
		t.Fatalf("expected *RegistrationRequest, got %T", msg.Body)
	}
	if rr.RegistrationType != nas.RegistrationTypeInitial {
		t.Errorf("RegistrationType: got %d, want Initial(%d)", rr.RegistrationType, nas.RegistrationTypeInitial)
	}
	if bool(rr.FollowOnRequest) {
		t.Error("FollowOnRequest should be false")
	}
	if rr.NGKSI.KeySetIdentifier != 1 {
		t.Errorf("NGKSI.KSI: got %d, want 1", rr.NGKSI.KeySetIdentifier)
	}
	if rr.MobileIdentity.Type != nas.MobileIdentityNoIdentity {
		t.Errorf("MI type: got %d, want NoIdentity", rr.MobileIdentity.Type)
	}
}

func TestDecodeRegistrationRequest_WithNSSAI(t *testing.T) {
	// Same combined byte as minimal + IEI 0x6D (RequestedNSSAI) with SST=0xAB, no SD
	nssaiIE := []byte{0x6D, 0x02, 0x01, 0xAB} // IEI | len | S-NSSAI(len=1, SST=0xAB)
	body := append([]byte{0x11, 0x00, 0x01, 0x00}, nssaiIE...)
	pdu := append([]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationRequest)}, body...)

	msg, err := nas.Decode(pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rr, _ := msg.Body.(*nas.RegistrationRequest)
	if rr.RequestedNSSAI == nil {
		t.Fatal("RequestedNSSAI should not be nil")
	}
	if len(rr.RequestedNSSAI.SNSSAIs) != 1 {
		t.Fatalf("expected 1 S-NSSAI, got %d", len(rr.RequestedNSSAI.SNSSAIs))
	}
	if rr.RequestedNSSAI.SNSSAIs[0].SST != 0xAB {
		t.Errorf("SST: got %x, want AB", rr.RequestedNSSAI.SNSSAIs[0].SST)
	}
	if rr.RequestedNSSAI.SNSSAIs[0].SD != nas.SDNotPresent {
		t.Errorf("SD: got %x, want SDNotPresent", rr.RequestedNSSAI.SNSSAIs[0].SD)
	}
}

// ---- Registration Accept ----------------------------------------------------

func buildRegistrationAccept() *nas.RegistrationAccept {
	return &nas.RegistrationAccept{
		RegistrationResult: 0x01, // 3GPP access
		FiveGGUTI: &nas.MobileIdentity{
			Type: nas.MobileIdentityGUTI,
			GUTI: &nas.GUTIMobileIdentity{
				MCC:         "208",
				MNC:         "93",
				AMFRegionID: 0x01,
				AMFSetID:    0x01,
				AMFID:       0x01,
				TMSI:        0xDEADBEEF,
			},
		},
		AllowedNSSAI: &nas.NSSAI{
			SNSSAIs: []nas.SNSSAI{
				{SST: 0x01, SD: nas.SDNotPresent},
				{SST: 0x02, SD: 0x000003},
			},
		},
	}
}

func TestRegistrationAccept_EncodeDecodeRoundtrip(t *testing.T) {
	orig := buildRegistrationAccept()

	pdu := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			MessageType:                   nas.MsgTypeRegistrationAccept,
		},
		Body: orig,
	}
	encoded, err := nas.Encode(pdu)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := nas.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ra, ok := decoded.Body.(*nas.RegistrationAccept)
	if !ok {
		t.Fatalf("expected *RegistrationAccept, got %T", decoded.Body)
	}
	if ra.RegistrationResult != orig.RegistrationResult {
		t.Errorf("RegistrationResult: got %d, want %d", ra.RegistrationResult, orig.RegistrationResult)
	}
	if ra.FiveGGUTI == nil || ra.FiveGGUTI.GUTI == nil {
		t.Fatal("FiveGGUTI/GUTI is nil after roundtrip")
	}
	if ra.FiveGGUTI.GUTI.MCC != "208" || ra.FiveGGUTI.GUTI.MNC != "93" {
		t.Errorf("GUTI MCC/MNC: got %s/%s, want 208/93",
			ra.FiveGGUTI.GUTI.MCC, ra.FiveGGUTI.GUTI.MNC)
	}
	if ra.FiveGGUTI.GUTI.TMSI != 0xDEADBEEF {
		t.Errorf("GUTI TMSI: got %x, want DEADBEEF", ra.FiveGGUTI.GUTI.TMSI)
	}
	if ra.AllowedNSSAI == nil {
		t.Fatal("AllowedNSSAI is nil after roundtrip")
	}
	if len(ra.AllowedNSSAI.SNSSAIs) != 2 {
		t.Errorf("AllowedNSSAI S-NSSAIs: got %d, want 2", len(ra.AllowedNSSAI.SNSSAIs))
	}
}

// ---- 5G-GUTI encode/decode --------------------------------------------------

func TestEncode5GGUTI_Roundtrip(t *testing.T) {
	want := &nas.GUTIMobileIdentity{
		MCC:         "208",
		MNC:         "93",
		AMFRegionID: 0xFF,
		AMFSetID:    0x3FF, // max 10 bits
		AMFID:       0x3F,  // max 6 bits
		TMSI:        0xCAFEBABE,
	}

	encoded := nas.Encode5GGUTI(want)
	mi, err := nas.DecodeMobileIdentity(encoded)
	if err != nil {
		t.Fatalf("DecodeMobileIdentity: %v", err)
	}
	if mi.Type != nas.MobileIdentityGUTI {
		t.Errorf("Type: got %d, want GUTI", mi.Type)
	}
	g := mi.GUTI
	if g == nil {
		t.Fatal("GUTI is nil")
	}
	if g.MCC != want.MCC || g.MNC != want.MNC {
		t.Errorf("MCC/MNC: got %s/%s, want %s/%s", g.MCC, g.MNC, want.MCC, want.MNC)
	}
	if g.AMFRegionID != want.AMFRegionID {
		t.Errorf("AMFRegionID: got %x, want %x", g.AMFRegionID, want.AMFRegionID)
	}
	if g.AMFSetID != want.AMFSetID {
		t.Errorf("AMFSetID: got %x, want %x", g.AMFSetID, want.AMFSetID)
	}
	if g.AMFID != want.AMFID {
		t.Errorf("AMFID: got %x, want %x", g.AMFID, want.AMFID)
	}
	if g.TMSI != want.TMSI {
		t.Errorf("TMSI: got %x, want %x", g.TMSI, want.TMSI)
	}
}

// ---- NSSAI encode/decode ----------------------------------------------------

func TestEncodeDecodeNSSAI_WithSD(t *testing.T) {
	nssai := nas.NSSAI{
		SNSSAIs: []nas.SNSSAI{
			{SST: 0x01, SD: 0x000002},
			{SST: 0xFF, SD: 0xABCDEF},
		},
	}
	encoded := nas.EncodeNSSAI(nssai)
	decoded, err := nas.DecodeNSSAI(encoded)
	if err != nil {
		t.Fatalf("DecodeNSSAI: %v", err)
	}
	if len(decoded.SNSSAIs) != 2 {
		t.Fatalf("S-NSSAI count: got %d, want 2", len(decoded.SNSSAIs))
	}
	for i, want := range nssai.SNSSAIs {
		got := decoded.SNSSAIs[i]
		if got.SST != want.SST || got.SD != want.SD {
			t.Errorf("S-NSSAI[%d]: got SST=%x SD=%x, want SST=%x SD=%x",
				i, got.SST, got.SD, want.SST, want.SD)
		}
	}
}

func TestEncodeDecodeNSSAI_NoSD(t *testing.T) {
	nssai := nas.NSSAI{
		SNSSAIs: []nas.SNSSAI{
			{SST: 0x02, SD: nas.SDNotPresent},
		},
	}
	encoded := nas.EncodeNSSAI(nssai)
	if len(encoded) != 2 { // S-NSSAI without SD: len(1) + SST(1)
		t.Errorf("encoded length: got %d, want 2", len(encoded))
	}
	decoded, err := nas.DecodeNSSAI(encoded)
	if err != nil {
		t.Fatalf("DecodeNSSAI: %v", err)
	}
	if decoded.SNSSAIs[0].SD != nas.SDNotPresent {
		t.Errorf("SD: got %x, want SDNotPresent", decoded.SNSSAIs[0].SD)
	}
}

func TestEncodeDecodeNSSAI_Mixed(t *testing.T) {
	nssai := nas.NSSAI{
		SNSSAIs: []nas.SNSSAI{
			{SST: 0x01, SD: nas.SDNotPresent}, // 2 bytes
			{SST: 0x02, SD: 0x000006},         // 5 bytes
			{SST: 0x03, SD: nas.SDNotPresent}, // 2 bytes
		},
	}
	encoded := nas.EncodeNSSAI(nssai)
	decoded, err := nas.DecodeNSSAI(encoded)
	if err != nil {
		t.Fatalf("DecodeNSSAI: %v", err)
	}
	if len(decoded.SNSSAIs) != 3 {
		t.Fatalf("S-NSSAI count: got %d, want 3", len(decoded.SNSSAIs))
	}
}

// ---- NAS Security Algorithms ------------------------------------------------

func TestNASSecurityAlgorithms_Encode(t *testing.T) {
	tests := []struct {
		enc, integ, wantByte byte
	}{
		{0, 0, 0x00},
		{2, 2, 0x22},
		{1, 3, 0x13},
		{0xF, 0xF, 0xFF},
	}
	for _, tc := range tests {
		alg := nas.NASSecurityAlgorithms{
			CipheringAlgorithmID: tc.enc,
			IntegrityAlgorithmID: tc.integ,
		}
		got := alg.Encode()
		if got != tc.wantByte {
			t.Errorf("Encode(enc=%x integ=%x): got %02x, want %02x", tc.enc, tc.integ, got, tc.wantByte)
		}
		decoded := nas.DecodeNASSecurityAlgorithms(got)
		if decoded.CipheringAlgorithmID != tc.enc || decoded.IntegrityAlgorithmID != tc.integ {
			t.Errorf("Decode(%02x): got enc=%x integ=%x, want enc=%x integ=%x",
				got, decoded.CipheringAlgorithmID, decoded.IntegrityAlgorithmID, tc.enc, tc.integ)
		}
	}
}

// ---- UE Security Capability -------------------------------------------------

func TestUESecurityCapability_Roundtrip(t *testing.T) {
	original := nas.UESecurityCapability{
		EA0: true, EA2: true,
		IA0: true, IA2: true,
	}

	encoded := nas.EncodeUESecurityCapability(original)

	decoded, err := nas.DecodeUESecurityCapability(encoded[:])
	if err != nil {
		t.Fatalf("DecodeUESecurityCapability: %v", err)
	}
	if decoded.EA0 != original.EA0 || decoded.EA1 != original.EA1 || decoded.EA2 != original.EA2 {
		t.Errorf("EA bits: got EA0=%v EA1=%v EA2=%v, want EA0=%v EA1=%v EA2=%v",
			decoded.EA0, decoded.EA1, decoded.EA2,
			original.EA0, original.EA1, original.EA2)
	}
	if decoded.IA0 != original.IA0 || decoded.IA2 != original.IA2 {
		t.Errorf("IA bits mismatch")
	}
}

func TestDecodeUESecurityCapability_TooShort(t *testing.T) {
	_, err := nas.DecodeUESecurityCapability([]byte{0x01})
	if err == nil {
		t.Error("expected error for 1-byte UE security capability")
	}
}

// ---- Mobile Identity: SUCI --------------------------------------------------

func TestDecodeMobileIdentity_SUCI(t *testing.T) {
	// encodeMCCMNC("208","93") = [0x02, 0xF8, 0x39]
	// RI bytes: 0x00, 0x00 → RI=0000
	// Protection scheme: 0x00 (null), HNPKID: 0x00
	suciBytes := []byte{
		0x01,             // type=SUCI(1), SUPIFormat=IMSI(0) → (0<<3)|1
		0x02, 0xF8, 0x39, // MCC=208, MNC=93
		0x00, 0x00, // Routing Indicator
		0x00,       // Protection Scheme = null
		0x00,       // HN Public Key ID
		0xAA, 0xBB, // Scheme Output (MSIN in plaintext for null scheme)
	}
	mi, err := nas.DecodeMobileIdentity(suciBytes)
	if err != nil {
		t.Fatalf("DecodeMobileIdentity: %v", err)
	}
	if mi.Type != nas.MobileIdentitySUCI {
		t.Errorf("Type: got %d, want SUCI(%d)", mi.Type, nas.MobileIdentitySUCI)
	}
	s := mi.SUCI
	if s == nil {
		t.Fatal("SUCI is nil")
	}
	if s.MCC != "208" || s.MNC != "93" {
		t.Errorf("MCC/MNC: got %s/%s, want 208/93", s.MCC, s.MNC)
	}
	if s.ProtectionSchemeID != 0 {
		t.Errorf("ProtectionSchemeID: got %d, want 0", s.ProtectionSchemeID)
	}
	if !bytes.Equal(s.SchemeOutput, []byte{0xAA, 0xBB}) {
		t.Errorf("SchemeOutput: got %x, want aabb", s.SchemeOutput)
	}
}

// ---- EncodeGPRSTimer3 (T3512) -----------------------------------------------

func TestEncodeGPRSTimer3(t *testing.T) {
	cases := []struct {
		secs int
		want byte
		desc string
	}{
		{0, 0x00, "deactivated"},
		{2, byte(3<<5) | 1, "2 s → unit 011 value 1"},
		{30, byte(4<<5) | 1, "30 s → unit 100 value 1"},
		{60, byte(5<<5) | 1, "60 s (1 min) → unit 101 value 1"},
		{120, byte(5<<5) | 2, "120 s (2 min) → unit 101 value 2"},
		{600, byte(0<<5) | 1, "600 s (10 min) → unit 000 value 1"},
		{3600, byte(1<<5) | 1, "3600 s (1 h) → unit 001 value 1"},
	}
	for _, tc := range cases {
		got := nas.EncodeGPRSTimer3(tc.secs)
		if got != tc.want {
			t.Errorf("EncodeGPRSTimer3(%d) [%s]: got 0x%02x, want 0x%02x",
				tc.secs, tc.desc, got, tc.want)
		}
	}
}

func TestRegistrationAccept_T3512(t *testing.T) {
	t3512 := nas.EncodeGPRSTimer3(60) // 1 min
	ra := &nas.RegistrationAccept{
		RegistrationResult: 0x01,
		T3512Value:         &t3512,
	}
	pdu := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			MessageType:                   nas.MsgTypeRegistrationAccept,
		},
		Body: ra,
	}
	encoded, err := nas.Encode(pdu)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Find IEI 0x5E in encoded bytes. Format is TLV: 0x5E | 0x01 (length) | timer_byte.
	found := false
	for i := 0; i < len(encoded)-2; i++ {
		if encoded[i] == 0x5E {
			if encoded[i+1] != 0x01 {
				t.Errorf("T3512 TLV length: got 0x%02x, want 0x01", encoded[i+1])
			}
			if encoded[i+2] != t3512 {
				t.Errorf("T3512 value: got 0x%02x, want 0x%02x", encoded[i+2], t3512)
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("IEI 0x5E (T3512) not found in encoded Registration Accept: %x", encoded)
	}
}

// ---- TAI list (TS 24.501 §9.11.3.9) -----------------------------------------

func TestEncodeTAIList_Type00Wire(t *testing.T) {
	// PLMN 001/01, single TAC 1 → type-00 partial list:
	// header 0x00 (type 00, 1 element), PLMN BCD 00 F1 10, TAC 00 00 01.
	got := nas.EncodeTAIList("001", "01", []uint32{1})
	want := []byte{0x00, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeTAIList: got %x, want %x", got, want)
	}

	// Two TACs → element count bits = 1 (count-1), 3 bytes per TAC.
	got = nas.EncodeTAIList("001", "01", []uint32{1, 0x000200})
	want = []byte{0x01, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeTAIList 2 TACs: got %x, want %x", got, want)
	}

	if nas.EncodeTAIList("001", "01", nil) != nil {
		t.Fatal("EncodeTAIList with no TACs must return nil")
	}
}

func TestRegistrationAccept_TAIList(t *testing.T) {
	// Regression: Registration Accept must carry the TAI list (IEI 0x54) —
	// without it UERANSIM cancels Service Request from CM-IDLE with
	// "current TAI is not in the TAI list". Ref: TS 24.501 §9.11.3.9, §5.5.1.2.4
	taiList := nas.EncodeTAIList("001", "01", []uint32{1})
	ra := &nas.RegistrationAccept{
		RegistrationResult: 0x01,
		TAIList:            taiList,
	}
	pdu := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			MessageType:                   nas.MsgTypeRegistrationAccept,
		},
		Body: ra,
	}
	encoded, err := nas.Encode(pdu)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// TLV on the wire: 0x54 | length | value.
	wantTLV := append([]byte{0x54, byte(len(taiList))}, taiList...)
	if !bytes.Contains(encoded, wantTLV) {
		t.Fatalf("IEI 0x54 (TAI list) TLV %x not found in encoded Registration Accept: %x",
			wantTLV, encoded)
	}

	decoded, err := nas.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got, ok := decoded.Body.(*nas.RegistrationAccept)
	if !ok {
		t.Fatalf("expected *RegistrationAccept, got %T", decoded.Body)
	}
	if !bytes.Equal(got.TAIList, taiList) {
		t.Fatalf("TAIList roundtrip: got %x, want %x", got.TAIList, taiList)
	}
}
