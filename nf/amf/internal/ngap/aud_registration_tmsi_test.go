package ngap

// aud_registration_tmsi_test.go — AMF-035 / AUD-registration-14: the 5G-S-TMSI of
// an INITIAL UE MESSAGE resolves a UE context only when its AMF Set ID and AMF
// Pointer identify this AMF. Ref: TS 38.413 §9.3.3.20, TS 23.003 §2.10.1.

import (
	"context"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

func TestAUDRegistration14_5GSTMSIEncodeDecodeRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		set uint16
		ptr byte
	}{{0, 0}, {1, 1}, {0x3FF, 0x3F}, {0x155, 0x2A}} {
		raw := BuildPaging(tc.set, tc.ptr, 0xDEADBEEF, []TAIForPaging{{PLMN: []byte{0x00, 0xf1, 0x10}, TAC: 1}})
		pdu, err := libngap.Decoder(raw)
		if err != nil {
			t.Fatal(err)
		}
		var id *ngapType.FiveGSTMSI
		for _, ie := range pdu.InitiatingMessage.Value.Paging.ProtocolIEs.List {
			if ie.Value.UEPagingIdentity != nil {
				id = ie.Value.UEPagingIdentity.FiveGSTMSI
			}
		}
		if id == nil {
			t.Fatal("no 5G-S-TMSI")
		}
		set, ptr := decodeAMFSetIDPointer(id.AMFSetID.Value, id.AMFPointer.Value)
		if set != tc.set || ptr != tc.ptr {
			t.Fatalf("round trip got set=%#x ptr=%#x, want %#x %#x", set, ptr, tc.set, tc.ptr)
		}
	}
}

func TestAUDRegistration14_ForeignAMFIdentityNotResolvedByTMSI(t *testing.T) {
	srvSet, srvPtr := uint16(5), byte(3)
	svcReq := []byte{0x7e, 0x00, byte(nas.MsgTypeServiceRequest), 0x00, 0x00, 0x07, 0xf4, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01}
	regReq := []byte{0x7e, 0x00, 0x41, 0x01}
	for _, tc := range []struct {
		name      string
		set       uint16
		ptr       byte
		nasPDU    []byte
		attaches  bool
		wantFresh bool
	}{
		{"matching identity attaches", srvSet, srvPtr, svcReq, true, false},
		{"different set id: service request rejected", srvSet + 1, srvPtr, svcReq, false, false},
		{"different pointer: service request rejected", srvSet, srvPtr + 1, svcReq, false, false},
		{"plain registration with foreign id: fresh context", srvSet + 1, srvPtr, regReq, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAudFixHarness(t)
			h.srv.mgr.AMFID = amfctx.AMFIdentity{MCC: "001", MNC: "01", AMFSetID: srvSet, AMFID: srvPtr}
			ue := h.srv.mgr.AllocateUEContext(1)
			ue.GNBAddr = "10.0.0.1:38412"
			ue.SUPI = "imsi-001010000000001"
			tm := h.srv.mgr.AssignGUTI(context.Background(), ue).TMSI
			h.srv.handleInitialUEMessage(context.Background(), h.gnb, &Message{Value: &InitialUEMessage{
				RANUENGAPId: 9, NASPdu: tc.nasPDU, FiveGSTMSI: &tm,
				FiveGSTMSISetID: tc.set, FiveGSTMSIPointer: tc.ptr,
			}})
			h.srv.WaitUESerialForTest(ue.AMFUENGAPId)
			ue.Lock()
			ran := ue.RANUENGAPId
			ue.Unlock()
			if attached := ran == 9; attached != tc.attaches {
				t.Fatalf("existing UE attached=%v (RANUENGAPId %d), want %v", attached, ran, tc.attaches)
			}
			h.nas.mu.Lock()
			delivered := len(h.nas.pdus)
			h.nas.mu.Unlock()
			switch {
			case tc.attaches && delivered != 1:
				t.Fatalf("NAS deliveries = %d, want 1", delivered)
			case tc.wantFresh:
				if _, ok := h.srv.mgr.GetByNGAPId(2); !ok {
					t.Fatal("no fresh context allocated")
				}
			case !tc.attaches:
				if delivered != 0 {
					t.Fatalf("foreign-identity Service Request handed to NAS")
				}
				if n := len(h.sent(t)); n != 2 {
					t.Fatalf("sent %d PDUs, want SERVICE REJECT + release", n)
				}
			}
		})
	}
}

// TestAUDRegistration22_ICSAfterNGRANRCUHasNoRadioCapability: after NG-RAN-RCU
// cleared the stored capability the ICS carries no UE Radio Capability IE.
func TestAUDRegistration22_ICSAfterNGRANRCUHasNoRadioCapability(t *testing.T) {
	h := newAudFixHarness(t)
	ue := h.srv.mgr.AllocateUEContext(7)
	ue.GNBAddr = "10.0.0.1:38412"
	ue.UERadioCapability = []byte{0x01, 0x02}
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	if !ue.ApplyNGRANRCU([]byte{0x02}) {
		t.Fatal("NG-RAN-RCU not applied")
	}
	if err := h.srv.SendInitialContextSetupRequest(ue, []byte{0x7e, 0x02}, testSecKey, 2, 2, 0xE000, 0xE000, nil); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	raw := h.out[0]
	h.mu.Unlock()
	if contains(icsIEIDs(t, raw), ngapType.ProtocolIEIDUERadioCapability) {
		t.Fatal("ICS carries IE 117 after NG-RAN-RCU")
	}
}
