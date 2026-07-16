package server

// gbr_qos_test.go — regression test for the 3GPP conformance audit fix
// (Jul 2026): GBR QoS Flow Information is mandatory for GBR 5QIs in the
// QosFlowSetupRequestList. Ref: TS 38.413 §9.3.1.12

import (
	"net"
	"testing"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
)

// TestBuildQosFlowSetupRequestList_GBR verifies GBRQosInformation is present
// for a GBR 5QI and absent for a non-GBR 5QI. TS 38.413 §9.3.1.12: the GBR QoS
// Flow Information IE "shall be present for GBR QoS flows" — a real gNB
// rejects a GBR flow without it.
func TestBuildQosFlowSetupRequestList_GBR(t *testing.T) {
	const ulBps, dlBps = 30_000_000, 100_000_000

	gbr := buildQosFlowSetupRequestList(1, 3 /* GBR 5QI */, ulBps, dlBps)
	info := gbr.List[0].QosFlowLevelQosParameters.GBRQosInformation
	if info == nil {
		t.Fatal("GBRQosInformation missing for GBR 5QI 3")
	}
	if info.GuaranteedFlowBitRateUL.Value != ulBps || info.MaximumFlowBitRateDL.Value != dlBps {
		t.Errorf("GBR rates: got GFBR-UL=%d MFBR-DL=%d, want %d/%d",
			info.GuaranteedFlowBitRateUL.Value, info.MaximumFlowBitRateDL.Value, ulBps, dlBps)
	}

	nonGBR := buildQosFlowSetupRequestList(1, 9 /* non-GBR 5QI */, ulBps, dlBps)
	if nonGBR.List[0].QosFlowLevelQosParameters.GBRQosInformation != nil {
		t.Error("GBRQosInformation must be absent for non-GBR 5QI 9")
	}
}

// TestBuildPDUSessionResourceSetupRequestTransfer_GBRRoundTrip verifies the
// full N2SM transfer with a GBR flow still encodes/decodes as valid APER.
// Ref: TS 38.413 §9.3.4.1
func TestBuildPDUSessionResourceSetupRequestTransfer_GBRRoundTrip(t *testing.T) {
	b, err := buildPDUSessionResourceSetupRequestTransfer(
		net.ParseIP("172.30.3.10"), 42, 1, 3, 30_000_000, 100_000_000,
		ngapType.PDUSessionTypePresentIpv4)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var decoded ngapType.PDUSessionResourceSetupRequestTransfer
	if err := aper.UnmarshalWithParams(b, &decoded, "valueExt"); err != nil {
		t.Fatalf("APER decode: %v", err)
	}
	var found bool
	for _, ie := range decoded.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDQosFlowSetupRequestList {
			found = true
			if ie.Value.QosFlowSetupRequestList.List[0].QosFlowLevelQosParameters.GBRQosInformation == nil {
				t.Error("GBRQosInformation lost in APER round-trip")
			}
		}
	}
	if !found {
		t.Fatal("QosFlowSetupRequestList IE missing")
	}
}
