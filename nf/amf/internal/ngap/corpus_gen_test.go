package ngap

// corpus_gen_test.go — generator of the AMF-built NGAP-PDU vectors of the NGAP equivalence corpus
// (shared/ngap/testdata/corpus/amf-*.hex, REL19-4.4). Skipped unless NGAP_CORPUS_WRITE=1.

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"

	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

const corpusDir = "../../../../shared/ngap/testdata/corpus"

func TestCorpusGenAMF(t *testing.T) {
	if os.Getenv("NGAP_CORPUS_WRITE") != "1" {
		t.Skip("set NGAP_CORPUS_WRITE=1 to regenerate shared/ngap/testdata/corpus/amf-*.hex")
	}
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	w := func(name string, b []byte) {
		t.Helper()
		if len(b) == 0 {
			t.Fatalf("%s: builder returned empty PDU", name)
		}
		if err := os.WriteFile(filepath.Join(corpusDir, "amf-"+name+".hex"), []byte(hex.EncodeToString(b)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	plmn := plmnFromMCCMNC("001", "01")
	nas := []byte{0x7e, 0x00, 0x42, 0x01, 0x02, 0x03} // opaque dummy NAS PDU (no identity)
	s1 := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	s2 := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}, {SST: 2}, {SST: 3, SD: "0000ff"}}
	rn := ngapType.CausePresentRadioNetwork
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	w("NGSetupResponse", BuildNGSetupResponse("amf-test", "001", "01", 0x80, 1, 1, s1))
	w("NGSetupResponse-multislice", BuildNGSetupResponse("amf-test-2", "310", "260", 0x01, 0x3ff, 0x3f, s2))
	w("NGSetupResponse-defaultslice", BuildNGSetupResponse("amf", "001", "01", 0x80, 1, 1, nil))

	w("DownlinkNASTransport", BuildDownlinkNASTransport(1, 2, nas))
	w("DownlinkNASTransport-bigids", BuildDownlinkNASTransport(1<<32-1, 1<<32-1, append(nas, make([]byte, 200)...)))

	w("InitialContextSetupRequest", BuildInitialContextSetupRequest(1, 2, nas, key, 0x8000, 0x8000, "001", "01", 0x80, 1, 1, s1, 0, 0, 0, nil, capability.PeerRAN{}))
	w("InitialContextSetupRequest-rfsp-sessions", BuildInitialContextSetupRequest(3, 4, nas, key, 0xE000, 0xE000, "001", "01", 0x80, 1, 1, s2, 100_000_000, 200_000_000, 7,
		[]PDUSessionSetupItemCxtReq{
			{PDUSessionID: 1, SST: 1, SD: []byte{0, 0, 1}, Transfer: []byte{0x00, 0x01, 0x02}},
			{PDUSessionID: 5, SST: 2, Transfer: []byte{0xAA, 0xBB}},
		}, capability.PeerRAN{}))

	w("PDUSessionResourceSetupRequest", BuildPDUSessionResourceSetupRequest(1, 2, 1, nas, []byte{0x00, 0x01}, 1, []byte{0, 0, 1}, nil, capability.PeerRAN{}))
	w("PDUSessionResourceSetupRequest-ambr-nosd", BuildPDUSessionResourceSetupRequest(5, 6, 9, nil, []byte{0xDE, 0xAD, 0xBE, 0xEF}, 2, nil, &UEAMBR{ULBps: 1_000_000, DLBps: 2_000_000}, capability.PeerRAN{}))

	w("PDUSessionResourceReleaseCommand", BuildPDUSessionResourceReleaseCommand(1, 2, 1, nas))
	w("PDUSessionResourceReleaseCommand-nonas", BuildPDUSessionResourceReleaseCommand(7, 8, 15, nil))

	w("UEContextReleaseCommand-nas", BuildUEContextReleaseCommand(1, 2, ngapType.CausePresentNas, int64(ngapType.CauseNasPresentNormalRelease)))
	w("UEContextReleaseCommand-radio", BuildUEContextReleaseCommand(3, 4, rn, int64(ngapType.CauseRadioNetworkPresentUserInactivity)))
	w("UEContextReleaseCommand-misc", BuildUEContextReleaseCommand(5, 6, ngapType.CausePresentMisc, int64(ngapType.CauseMiscPresentUnspecified)))

	tai := TAIForPaging{PLMN: plmn, TAC: 1}
	w("Paging", BuildPaging(1, 1, 0x12345678, []TAIForPaging{tai}))
	w("Paging-multitai", BuildPaging(0x3ff, 0x3f, 0xFFFFFFFF, []TAIForPaging{tai, {PLMN: plmn, TAC: 0xFFFFFF}, {PLMN: plmnFromMCCMNC("310", "260"), TAC: 0x0100}}))

	w("LocationReportingControl", BuildLocationReportingControl(1, 2))

	hoSess := []PDUSessionHOReqItem{{PDUSessionID: 5, SNSSAI: amfctx.SNSSAISubscribed{SST: 1}, HandoverRequestTransfer: []byte{0xAA}}}
	w("HandoverRequest", BuildHandoverRequest(1, 0, rn, 0, nil, 2, key, 0xE000, 0xE000, hoSess, []amfctx.SNSSAISubscribed{{SST: 1}}, []byte{1, 2, 3}, "001", "01", 1, 1, 1))
	w("HandoverRequest-ambr-multi", BuildHandoverRequest(9, 1, rn, 3, &UEAMBR{ULBps: 5_000_000, DLBps: 6_000_000}, 7, key, 0x8000, 0x4000,
		append(hoSess, PDUSessionHOReqItem{PDUSessionID: 6, SNSSAI: amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}, HandoverRequestTransfer: []byte{0xBB, 0xCC}}),
		s2, make([]byte, 64), "001", "01", 0x80, 3, 2))

	w("HandoverPreparationFailure", BuildHandoverPreparationFailure(1, 2, rn, int64(ngapType.CauseRadioNetworkPresentUnspecified)))
	w("HandoverPreparationFailure-protocol", BuildHandoverPreparationFailure(3, 4, ngapType.CausePresentProtocol, int64(ngapType.CauseProtocolPresentSemanticError)))

	w("HandoverCommand", BuildHandoverCommand(1, 2, 0, []PDUSessionHOCmdItem{{PDUSessionID: 5}}, nil, []byte{1, 2, 3}))
	w("HandoverCommand-transfer-release", BuildHandoverCommand(3, 4, 1,
		[]PDUSessionHOCmdItem{{PDUSessionID: 5, HandoverCommandTransfer: []byte{0x00}}},
		[]PDUSessionHOReleaseItem{{PDUSessionID: 6, CausePresent: rn, CauseValue: 0}, {PDUSessionID: 7, HandoverPreparationUnsuccessfulTransfer: []byte{0x00, 0x01}}},
		make([]byte, 40)))

	w("PDUSessionResourceModifyRequest", BuildPDUSessionResourceModifyRequest(1, 2, 1, nas, []byte{0x00}))
	w("PDUSessionResourceModifyRequest-nonas", BuildPDUSessionResourceModifyRequest(3, 4, 2, nil, []byte{0x01, 0x02, 0x03}))

	w("PathSwitchRequestAcknowledge", BuildPathSwitchRequestAcknowledge(PathSwitchAckParams{
		AMFUENGAPId: 1, RANUENGAPId: 2, NCC: 1, NH: key,
		Switched:     []PDUSessionSwitchItem{{PDUSessionID: 1}},
		AllowedNSSAI: s1,
	}))
	w("PathSwitchRequestAcknowledge-seccap-released", BuildPathSwitchRequestAcknowledge(PathSwitchAckParams{
		AMFUENGAPId: 3, RANUENGAPId: 4, UESecCap: &UESecCapBitmaps{Enc: 0xE000, Int: 0xE000}, NCC: 5, NH: key,
		Switched:     []PDUSessionSwitchItem{{PDUSessionID: 1, AckTransfer: []byte{0x00}}, {PDUSessionID: 2}},
		Released:     []PDUSessionReleasedItem{{PDUSessionID: 3, CausePresent: rn, CauseValue: 0}, {PDUSessionID: 4, Transfer: []byte{0x00, 0x20}}},
		AllowedNSSAI: s2,
	}))

	w("PathSwitchRequestFailure-released", BuildPathSwitchRequestFailure(3, 4, []PDUSessionReleasedItem{{PDUSessionID: 1, CausePresent: rn, CauseValue: 0}}))

	w("DownlinkUEAssociatedNRPPaTransport", BuildDownlinkUEAssociatedNRPPaTransport(1, 2, []byte{0x01, 0x02, 0x03}, []byte{0x00, 0x01}))
	w("DownlinkNonUEAssociatedNRPPaTransport", BuildDownlinkNonUEAssociatedNRPPaTransport([]byte{0x04, 0x05}, []byte{0x00, 0x02}))

	wr := WriteReplaceWarningParams{
		MessageIdentifier: 0x1112, SerialNumber: 1, TAIs: []TAIForPaging{tai},
		RepetitionPeriod: DefaultRepetitionPeriod, NumberOfBroadcasts: DefaultNumberOfBroadcasts,
		WarningType: [WarningTypeLength]byte{0x10, 0x00}, DataCodingScheme: 0x00,
		WarningMessageContents: []byte("Tsunami warning: move to higher ground"),
	}
	w("WriteReplaceWarningRequest", BuildWriteReplaceWarningRequest(wr))
	wr.TAIs = nil
	wr.DataCodingScheme = 0x11
	wr.LanguageISO639 = "en"
	wr.WarningMessageContents = []byte("Test")
	w("WriteReplaceWarningRequest-ucs2-allarea", BuildWriteReplaceWarningRequest(wr))
	w("PWSCancelRequest", BuildPWSCancelRequest(0x1112, 1, []TAIForPaging{tai}, false))
	w("PWSCancelRequest-all", BuildPWSCancelRequest(0x1113, 2, nil, true))
}
