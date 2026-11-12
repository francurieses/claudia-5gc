package server

// corpus_gen_test.go — generator of the SMF N2 SM transfer vectors of the NGAP equivalence corpus
// (shared/ngap/testdata/corpus/smf-*.hex, REL19-4.4). Skipped unless NGAP_CORPUS_WRITE=1.

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
	"github.com/free5gc/aper"
)

const corpusDir = "../../../../shared/ngap/testdata/corpus"

func writeCorpus(t *testing.T, name string, b []byte) {
	t.Helper()
	if len(b) == 0 {
		t.Fatalf("%s: empty encoding", name)
	}
	p := filepath.Join(corpusDir, name+".hex")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(b)+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func mustCorpusMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := aper.MarshalWithParams(v, "valueExt")
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return b
}

func TestCorpusGenSMF(t *testing.T) {
	if os.Getenv("NGAP_CORPUS_WRITE") != "1" {
		t.Skip("set NGAP_CORPUS_WRITE=1 to regenerate shared/ngap/testdata/corpus/smf-*.hex")
	}
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	upf := net.ParseIP("172.30.3.10")

	// PDUSessionResourceSetupRequestTransfer variants (non-GBR / GBR / IPv6 / data-fwd-not-possible).
	for _, c := range []struct {
		name    string
		fiveQI  int64
		typ     aper.Enumerated
		noFwd   bool
		ip      net.IP
		ul, dl  int64
		teid    uint32
		variant string
	}{
		{"nongbr-ipv4", 9, ngapType.PDUSessionTypePresentIpv4, false, upf, 100_000_000, 200_000_000, 0x1001, ""},
		{"gbr-ipv4", 3, ngapType.PDUSessionTypePresentIpv4, false, upf, 30_000_000, 100_000_000, 42, ""},
		{"ipv6", 9, ngapType.PDUSessionTypePresentIpv6, false, upf, 1_000_000_000, 1_000_000_000, 0x01020304, ""},
		{"ipv4v6-nofwd", 5, ngapType.PDUSessionTypePresentIpv4v6, true, upf, 50_000_000, 60_000_000, 7, ""},
		{"ipv6-upf", 9, ngapType.PDUSessionTypePresentIpv4, true, net.ParseIP("2001:db8::10"), 1_000_000, 2_000_000, 0xFFFFFFFF, ""},
	} {
		b, err := buildPDUSessionResourceSetupRequestTransferOpts(c.ip, c.teid, 1, c.fiveQI, c.ul, c.dl, c.typ, c.noFwd)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		writeCorpus(t, "smf-PDUSessionResourceSetupRequestTransfer-"+c.name, b)
	}

	b, err := buildPDUSessionResourceModifyRequestTransfer()
	if err != nil {
		t.Fatal(err)
	}
	writeCorpus(t, "smf-PDUSessionResourceModifyRequestTransfer-empty", b)

	writeCorpus(t, "smf-PathSwitchRequestUnsuccessfulTransfer-radio", pathSwitchUnsuccessfulTransfer(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable))
	writeCorpus(t, "smf-PathSwitchRequestUnsuccessfulTransfer-protocol", pathSwitchUnsuccessfulTransfer(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError))
	writeCorpus(t, "smf-HandoverPreparationUnsuccessfulTransfer-radio", handoverPrepFailTransfer(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnspecified))
	writeCorpus(t, "smf-HandoverPreparationUnsuccessfulTransfer-protocol", handoverPrepFailTransfer(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentUnspecified))
	writeCorpus(t, "smf-HandoverPreparationUnsuccessfulTransfer-misc", handoverPrepFailTransferCause(ngapType.Cause{
		Present: ngapType.CausePresentMisc,
		Misc:    &ngapType.CauseMisc{Value: ngapType.CauseMiscPresentUnspecified},
	}))

	// HandoverRequestAcknowledgeTransfer (as the gNB would send, consumed by the SMF).
	tun := func(ip [4]byte, teid uint32) ngapType.UPTransportLayerInformation {
		return ngapType.UPTransportLayerInformation{
			Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
			GTPTunnel: &ngapType.GTPTunnel{
				TransportLayerAddress: ngapType.TransportLayerAddress{Value: aper.BitString{Bytes: ip[:], BitLength: 32}},
				GTPTEID:               ngapType.GTPTEID{Value: aper.OctetString{byte(teid >> 24), byte(teid >> 16), byte(teid >> 8), byte(teid)}},
			},
		}
	}
	flow := func(qfi int64, fwd bool) ngapType.QosFlowItemWithDataForwarding {
		it := ngapType.QosFlowItemWithDataForwarding{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: qfi}}
		if fwd {
			it.DataForwardingAccepted = &ngapType.DataForwardingAccepted{Value: ngapType.DataForwardingAcceptedPresentDataForwardingAccepted}
		}
		return it
	}
	ackPlain := ngapType.HandoverRequestAcknowledgeTransfer{
		DLNGUUPTNLInformation:    tun([4]byte{10, 0, 0, 7}, 0xABCD),
		QosFlowSetupResponseList: ngapType.QosFlowListWithDataForwarding{List: []ngapType.QosFlowItemWithDataForwarding{flow(1, false)}},
	}
	writeCorpus(t, "smf-HandoverRequestAcknowledgeTransfer-plain", mustCorpusMarshal(t, ackPlain))
	fwdTun := tun([4]byte{10, 0, 0, 8}, 0x77)
	ackFwd := ngapType.HandoverRequestAcknowledgeTransfer{
		DLNGUUPTNLInformation:        tun([4]byte{10, 0, 0, 7}, 0xABCD),
		DLForwardingUPTNLInformation: &fwdTun,
		QosFlowSetupResponseList:     ngapType.QosFlowListWithDataForwarding{List: []ngapType.QosFlowItemWithDataForwarding{flow(1, true), flow(2, false)}},
	}
	writeCorpus(t, "smf-HandoverRequestAcknowledgeTransfer-forwarding", mustCorpusMarshal(t, ackFwd))

	// HandoverCommandTransfer: empty (no direct path), and with direct forwarding.
	empty, _, _ := buildHandoverCommandTransfer(false, &ackPlain) // forwarding mode/reason strings, not errors
	writeCorpus(t, "smf-HandoverCommandTransfer-empty", mustCorpusMarshal(t, empty))
	direct, _, _ := buildHandoverCommandTransfer(true, &ackFwd)
	writeCorpus(t, "smf-HandoverCommandTransfer-direct", mustCorpusMarshal(t, direct))

	// PathSwitchRequestAcknowledgeTransfer (empty, as sent by handover_n2.go) and the gNB-side
	// PathSwitchRequestTransfer / SetupFailedTransfer inputs the SMF decodes.
	writeCorpus(t, "smf-PathSwitchRequestAcknowledgeTransfer-empty", mustCorpusMarshal(t, ngapType.PathSwitchRequestAcknowledgeTransfer{}))
	writeCorpus(t, "smf-PathSwitchRequestTransfer-plain", mustCorpusMarshal(t, hoPathSwitchTransfer([4]byte{10, 0, 0, 5}, 0x1234)))
	writeCorpus(t, "smf-PathSwitchRequestSetupFailedTransfer-radio", mustCorpusMarshal(t, ngapType.PathSwitchRequestSetupFailedTransfer{Cause: ngapCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable)}))
}
