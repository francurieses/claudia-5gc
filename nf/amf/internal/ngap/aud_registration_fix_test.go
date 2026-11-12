package ngap

// aud_registration_fix_test.go — regression tests for the registration audit
// findings fixed in AMF-027 (dev/campaigns/results/audit-registration.md
// AUD-registration-18, -22, -23, -25, -26). -19 and -24 are covered by
// aud_registration_test.go.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
	"github.com/free5gc/aper"
	"github.com/ishidawataru/sctp"
)

// audFixNAS records the NAS PDUs handed to the NAS layer and the UE's CM state
// at that moment.
type audFixNAS struct {
	mu      sync.Mutex
	pdus    [][]byte
	cmState []amfctx.CMState
	// newN2 is the UEContext.NASOnNewN2Connection flag seen per PDU.
	newN2 []bool
}

func (n *audFixNAS) HandleNASMessage(_ context.Context, ue *amfctx.UEContext, pdu []byte) error {
	ue.Lock()
	cm := ue.CMState
	newN2 := ue.NASOnNewN2Connection
	ue.Unlock()
	n.mu.Lock()
	n.pdus = append(n.pdus, pdu)
	n.cmState = append(n.cmState, cm)
	n.newN2 = append(n.newN2, newN2)
	n.mu.Unlock()
	return nil
}

type audFixHarness struct {
	srv *Server
	gnb *GNBContext
	nas *audFixNAS
	mu  sync.Mutex
	out [][]byte
}

func newAudFixHarness(t *testing.T) *audFixHarness {
	t.Helper()
	h := &audFixHarness{nas: &audFixNAS{}}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	h.srv = NewServer("", amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil), h.nas, AMFConfig{MCC: "001", MNC: "01"}, lg)
	h.gnb = &GNBContext{UEs: map[int64]*amfctx.UEContext{}, IdleUEs: map[int64]*amfctx.UEContext{}}
	h.gnb.SetTransportForTest("10.0.0.1:38412", func(pdu []byte, _ *sctp.SndRcvInfo) (int, error) {
		h.mu.Lock()
		h.out = append(h.out, append([]byte{}, pdu...))
		h.mu.Unlock()
		return len(pdu), nil
	})
	h.srv.AddGNBForTest("10.0.0.1:38412", h.gnb)
	return h
}

func (h *audFixHarness) sent(t *testing.T) []*ngapType.NGAPPDU {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*ngapType.NGAPPDU
	for _, b := range h.out {
		pdu, err := libngap.Decoder(b)
		if err != nil {
			t.Fatalf("decode sent PDU: %v", err)
		}
		out = append(out, pdu)
	}
	return out
}

// TestAUDRegistration18_ICSCarriesEUTRAAndNRBits4to7: the UE Security
// Capability `2e 04 f0 f0 f0 f0` (EA0-3, IA0-3, EEA0-3, EIA0-3) must give
// E-UTRA bitmaps 0xE000 in the ICS (TS 38.413 §9.3.1.86); NR bits 4-7 come from
// bits 4-1 of octet 3.
func TestAUDRegistration18_ICSCarriesEUTRAAndNRBits4to7(t *testing.T) {
	tests := []struct {
		name                     string
		raw                      []byte
		nrEnc, nrInt, eEnc, eInt uint16
		paramEnc, paramInt       uint16
	}{
		{"EA/IA/EEA/EIA 0-3", []byte{0xf0, 0xf0, 0xf0, 0xf0}, 0xE000, 0xE000, 0xE000, 0xE000, 0xE000, 0xE000},
		{"NR 4-7 carried", []byte{0x7f, 0x60, 0x40, 0x20}, 0xFE00, 0xC000, 0x8000, 0x4000, 0xE000, 0xC000},
		{"no E-UTRA octets", []byte{0x70, 0x70}, 0xE000, 0xE000, 0, 0, 0xE000, 0xE000},
		{"no raw IE: caller bitmaps", nil, 0xC000, 0x4000, 0, 0, 0xC000, 0x4000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newAudFixHarness(t)
			ue := h.srv.mgr.AllocateUEContext(7)
			ue.GNBAddr = "10.0.0.1:38412"
			ue.RawUESecCap = tc.raw
			ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
			if err := h.srv.SendInitialContextSetupRequest(ue, []byte{0x7e, 0x02}, testSecKey, 2, 2,
				tc.paramEnc, tc.paramInt, nil); err != nil {
				t.Fatal(err)
			}
			pdus := h.sent(t)
			if len(pdus) != 1 {
				t.Fatalf("sent %d PDUs, want 1", len(pdus))
			}
			var c *ngapType.UESecurityCapabilities
			for _, ie := range pdus[0].InitiatingMessage.Value.InitialContextSetupRequest.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDUESecurityCapabilities {
					c = ie.Value.UESecurityCapabilities
				}
			}
			if c == nil {
				t.Fatal("no UE Security Capabilities IE")
			}
			got := [4]uint16{bitmap16(c.NRencryptionAlgorithms.Value.Bytes), bitmap16(c.NRintegrityProtectionAlgorithms.Value.Bytes),
				bitmap16(c.EUTRAencryptionAlgorithms.Value.Bytes), bitmap16(c.EUTRAintegrityProtectionAlgorithms.Value.Bytes)}
			want := [4]uint16{tc.nrEnc, tc.nrInt, tc.eEnc, tc.eInt}
			if got != want {
				t.Fatalf("bitmaps NR enc/int, E-UTRA enc/int = %04x, want %04x", got, want)
			}
		})
	}
}

// TestAUDRegistration22_ICSCarriesStoredUERadioCapability: a stored UE Radio
// Capability is sent in the ICS (IE 117, before Index to RFSP; TS 23.501
// §5.4.4.1, TS 38.413 Table 9.2.2.1-1) and omitted when none is stored.
func TestAUDRegistration22_ICSCarriesStoredUERadioCapability(t *testing.T) {
	for _, stored := range [][]byte{nil, {0x01, 0x02}} {
		h := newAudFixHarness(t)
		ue := h.srv.mgr.AllocateUEContext(7)
		ue.GNBAddr = "10.0.0.1:38412"
		ue.UERadioCapability = stored
		ue.RFSP = 1
		ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
		if err := h.srv.SendInitialContextSetupRequest(ue, []byte{0x7e, 0x02}, testSecKey, 2, 2, 0xE000, 0xE000, nil); err != nil {
			t.Fatal(err)
		}
		h.mu.Lock()
		raw := h.out[0]
		h.mu.Unlock()
		ids := icsIEIDs(t, raw)
		has := contains(ids, ngapType.ProtocolIEIDUERadioCapability)
		if has != (stored != nil) {
			t.Fatalf("stored=%x: IE 117 present=%v (ids %v)", stored, has, ids)
		}
		if has {
			var iRC, iRFSP int
			for i, id := range ids {
				switch id {
				case ngapType.ProtocolIEIDUERadioCapability:
					iRC = i
				case ngapType.ProtocolIEIDIndexToRFSP:
					iRFSP = i
				}
			}
			if iRC > iRFSP {
				t.Fatalf("UE Radio Capability after Index to RFSP: %v", ids)
			}
		}
	}
}

// TestAUDRegistration23_InitialUEMessageSetsCMConnected: the INITIAL UE
// MESSAGE moves the fresh context to CM-CONNECTED before any NAS processing
// (TS 23.501 §5.3.3.2.2).
func TestAUDRegistration23_InitialUEMessageSetsCMConnected(t *testing.T) {
	h := newAudFixHarness(t)
	h.srv.handleInitialUEMessage(context.Background(), h.gnb, &Message{Value: &InitialUEMessage{
		RANUENGAPId: 9, NASPdu: []byte{0x7e, 0x00, 0x41, 0x01},
	}})
	ue, ok := h.srv.mgr.GetByNGAPId(1)
	if !ok {
		t.Fatal("no context allocated")
	}
	h.srv.WaitUESerialForTest(ue.AMFUENGAPId)
	h.nas.mu.Lock()
	defer h.nas.mu.Unlock()
	if len(h.nas.cmState) != 1 || h.nas.cmState[0] != amfctx.CMConnected {
		t.Fatalf("CM state at NAS processing = %v, want [CM-CONNECTED]", h.nas.cmState)
	}
}

// initialUEMessagePDU encodes an INITIAL UE MESSAGE; withNAS=false leaves out
// the mandatory NAS-PDU IE (criticality reject, TS 38.413 §9.2.5.1).
func initialUEMessagePDU(t *testing.T, withNAS bool) []byte {
	t.Helper()
	ies := []ngapType.InitialUEMessageIEs{{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.InitialUEMessageIEsValue{Present: ngapType.InitialUEMessageIEsPresentRANUENGAPID,
			RANUENGAPID: &ngapType.RANUENGAPID{Value: 9}},
	}}
	if withNAS {
		ies = append(ies, ngapType.InitialUEMessageIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNASPDU},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialUEMessageIEsValue{Present: ngapType.InitialUEMessageIEsPresentNASPDU,
				NASPDU: &ngapType.NASPDU{Value: aper.OctetString{0x7e, 0x00, 0x41, 0x01}}},
		})
	}
	plmn := plmnFromMCCMNC("001", "01")
	ies = append(ies,
		ngapType.InitialUEMessageIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUserLocationInformation},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialUEMessageIEsValue{Present: ngapType.InitialUEMessageIEsPresentUserLocationInformation,
				UserLocationInformation: &ngapType.UserLocationInformation{
					Present: ngapType.UserLocationInformationPresentUserLocationInformationNR,
					UserLocationInformationNR: &ngapType.UserLocationInformationNR{
						NRCGI: ngapType.NRCGI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmn},
							NRCellIdentity: ngapType.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0, 0, 0, 0, 0x10}, BitLength: 36}}},
						TAI: ngapType.TAI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmn}, TAC: ngapType.TAC{Value: aper.OctetString{0, 0, 1}}},
					}}},
		},
		ngapType.InitialUEMessageIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRRCEstablishmentCause},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitialUEMessageIEsValue{Present: ngapType.InitialUEMessageIEsPresentRRCEstablishmentCause,
				RRCEstablishmentCause: &ngapType.RRCEstablishmentCause{Value: ngapType.RRCEstablishmentCausePresentMoSignalling}},
		})
	b, err := libngap.Encoder(ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeInitialUEMessage},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{Present: ngapType.InitiatingMessagePresentInitialUEMessage,
				InitialUEMessage: &ngapType.InitialUEMessage{ProtocolIEs: ngapType.ProtocolIEContainerInitialUEMessageIEs{List: ies}}},
		},
	})
	if err != nil {
		t.Fatalf("encode InitialUEMessage: %v", err)
	}
	return b
}

// TestAUDRegistration25_InitialUEMessageMissingMandatoryIE: an INITIAL UE
// MESSAGE without the NAS-PDU (M, reject) is answered with an ERROR INDICATION
// and allocates no context (TS 38.413 §9.2.5.1, §10.3.5); a complete one is
// processed.
func TestAUDRegistration25_InitialUEMessageMissingMandatoryIE(t *testing.T) {
	h := newAudFixHarness(t)
	h.srv.DispatchNGAPForTest(context.Background(), h.gnb, initialUEMessagePDU(t, false))
	if _, ok := h.srv.mgr.GetByNGAPId(1); ok {
		t.Fatal("UE context allocated for an INITIAL UE MESSAGE without NAS-PDU")
	}
	pdus := h.sent(t)
	if len(pdus) != 1 || pdus[0].InitiatingMessage == nil ||
		pdus[0].InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeErrorIndication {
		t.Fatalf("want exactly one ERROR INDICATION, got %d PDUs", len(pdus))
	}

	h2 := newAudFixHarness(t)
	h2.srv.DispatchNGAPForTest(context.Background(), h2.gnb, initialUEMessagePDU(t, true))
	if _, ok := h2.srv.mgr.GetByNGAPId(1); !ok {
		t.Fatal("complete INITIAL UE MESSAGE not processed")
	}
	h2.srv.WaitUESerialForTest(1)
}

// TestAUDRegistration25_ServiceRequestWithout5GSTMSI: a Service Request /
// Control Plane Service Request whose INITIAL UE MESSAGE has no 5G-S-TMSI is a
// failed procedure (TS 38.413 §8.6.1.3): SERVICE REJECT #9 + UE Context Release
// Command, never handed to the NAS layer.
func TestAUDRegistration25_ServiceRequestWithout5GSTMSI(t *testing.T) {
	for _, mt := range []nas.MessageType{nas.MsgTypeServiceRequest, nas.MsgTypeControlPlaneServiceRequest} {
		h := newAudFixHarness(t)
		h.srv.handleInitialUEMessage(context.Background(), h.gnb, &Message{Value: &InitialUEMessage{
			RANUENGAPId: 9,
			NASPdu:      []byte{0x7e, 0x00, byte(mt), 0x00, 0x00, 0x07, 0xf4, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01},
		}})
		h.nas.mu.Lock()
		delivered := len(h.nas.pdus)
		h.nas.mu.Unlock()
		if delivered != 0 {
			t.Fatalf("type %#x: Service Request without 5G-S-TMSI handed to NAS", byte(mt))
		}
		pdus := h.sent(t)
		if len(pdus) != 2 {
			t.Fatalf("type %#x: sent %d PDUs, want DL NAS Transport + UE Context Release Command", byte(mt), len(pdus))
		}
		dl := pdus[0].InitiatingMessage
		if dl.ProcedureCode.Value != ngapType.ProcedureCodeDownlinkNASTransport {
			t.Fatalf("first PDU procedure %d, want DownlinkNASTransport", dl.ProcedureCode.Value)
		}
		var nasPDU []byte
		for _, ie := range dl.Value.DownlinkNASTransport.ProtocolIEs.List {
			if ie.Value.NASPDU != nil {
				nasPDU = ie.Value.NASPDU.Value
			}
		}
		if len(nasPDU) != 4 || nasPDU[2] != byte(nas.MsgTypeServiceReject) || nasPDU[3] != byte(nas.CauseUEIdentityNotDerived) {
			t.Fatalf("NAS %x, want SERVICE REJECT #9", nasPDU)
		}
		if pdus[1].InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeUEContextRelease {
			t.Fatalf("second PDU procedure %d, want UEContextRelease", pdus[1].InitiatingMessage.ProcedureCode.Value)
		}
	}
}

// TestAUDRegistration26_ReleaseCompleteDropsNeverRegisteredContext: a
// 5GMM-DEREGISTERED context without PDU sessions is removed at N2 release,
// no Mobile Reachable timer (TS 24.501 §5.3.7 supervises registered UEs).
func TestAUDRegistration26_ReleaseCompleteDropsNeverRegisteredContext(t *testing.T) {
	h := newAudFixHarness(t)
	ue := h.srv.mgr.AllocateUEContext(3)
	ue.GNBAddr = "10.0.0.1:38412"
	h.gnb.UEs[3] = ue
	h.srv.handleUEContextReleaseComplete(context.Background(), h.gnb, &Message{
		Value: &UEContextReleaseCompleteMsg{AMFUENGAPId: ue.AMFUENGAPId, RANUENGAPId: 3}})
	if _, ok := h.srv.mgr.GetByNGAPId(ue.AMFUENGAPId); ok {
		t.Fatal("never-registered context kept after N2 release")
	}
	ue.Lock()
	armed := ue.MobileReachableTimer != nil
	ue.Unlock()
	if armed {
		t.Fatal("Mobile Reachable timer armed for a never-registered context")
	}
	if len(h.gnb.IdleUEs) != 0 {
		t.Fatal("never-registered context left in IdleUEs")
	}
}

// TestAUDRegistration28_ICSEncodeFailureNotReportedSent: nine Allowed S-NSSAIs
// exceed the NGAP SIZE(1..8) bound so the ICS encode fails; the AMF must return
// an error, write nothing and not mark the UE-AMBR as sent (TS 38.413 §9.2.2.1).
func TestAUDRegistration28_ICSEncodeFailureNotReportedSent(t *testing.T) {
	h := newAudFixHarness(t)
	ue := h.srv.mgr.AllocateUEContext(7)
	ue.GNBAddr = "10.0.0.1:38412"
	for i := 1; i <= 9; i++ {
		ue.AllowedNSSAI = append(ue.AllowedNSSAI, amfctx.SNSSAISubscribed{SST: uint8(i)})
	}
	err := h.srv.SendInitialContextSetupRequest(ue, []byte{0x7e, 0x02}, testSecKey, 2, 2, 0xE000, 0xE000,
		[]PDUSessionSetupItemCxtReq{{PDUSessionID: 1, SST: 1}})
	if !errors.Is(err, errICSEncodeFailed) {
		t.Fatalf("SendInitialContextSetupRequest err = %v, want errors.Is errICSEncodeFailed", err)
	}
	if n := len(h.sent(t)); n != 0 {
		t.Fatalf("%d PDUs written, want 0", n)
	}
	ue.Lock()
	sent := ue.UEAMBRSentToRAN
	ue.Unlock()
	if sent {
		t.Fatal("UEAMBRSentToRAN set after a failed encode")
	}
}
