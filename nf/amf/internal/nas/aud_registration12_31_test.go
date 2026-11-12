package nasmsg

// AUD-registration-12 (NAS message container + PDU session IEs of a registration
// update) and AUD-registration-31 (SECURITY MODE REJECT keeps the context in use).
// Ref: TS 24.501 §4.4.6, §5.5.1.3.4, §5.4.2.5

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// reactSender records the ICS items, PDU Session Resource Setup Requests, and the SM
// contexts released/activated.
type reactSender struct {
	regAudSender
	mu       sync.Mutex
	items    []ngap.PDUSessionSetupItemCxtReq
	psrSetup []uint8
	deleted  chan string
}

func (s *reactSender) SendInitialContextSetupRequest(_ *amfctx.UEContext, nasPDU []byte,
	_ [32]byte, _, _ byte, _, _ uint16, items []ngap.PDUSessionSetupItemCxtReq) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ics = append(s.ics, append([]byte(nil), nasPDU...))
	s.items = append(s.items, items...)
	return nil
}
func (s *reactSender) SendPDUSessionResourceSetupRequest(_ *amfctx.UEContext, psi uint8, _ []byte, _ []byte) error {
	s.mu.Lock()
	s.psrSetup = append(s.psrSetup, psi)
	s.mu.Unlock()
	return nil
}
func (s *reactSender) ActivateSMContext(_ context.Context, ref string) ([]byte, error) {
	return []byte("n2sm-" + ref), nil
}
func (s *reactSender) DeleteSMContext(_ context.Context, ref string) error {
	s.deleted <- ref
	return nil
}

// updateWithContainer builds a mobility REGISTRATION REQUEST whose non-cleartext IEs
// are in a NAS message container ciphered with the UE's current context (the NAS
// COUNT of the outer message), as TS 24.501 §4.4.6 requires.
func updateWithContainer(t *testing.T, ue *amfctx.UEContext, innerIEs []byte) []byte {
	t.Helper()
	inner := append(regReqWithCap(t, 2, ""), innerIEs...)
	ciph, err := nea.NEA2(ue.SecurityCtx.KNASenc, ue.SecurityCtx.UplinkCount, 0x01, 0x00, inner)
	if err != nil {
		t.Fatal(err)
	}
	body := regReqWithCap(t, 2, "")[3:]
	body[0] = 0x12
	body = append(body, 0x71, byte(len(ciph)>>8), byte(len(ciph)))
	body = append(body, ciph...)
	return buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, body)
}

// TestAUDRegistration12_ContainerPDUSessionIEs: the PDU session status and Uplink data
// status IEs, and the Requested NSSAI, are read from the ciphered NAS message
// container; PSI 6 (reported inactive) is released locally and at the SMF, PSI 5
// (uplink data) is re-established (N2 SM info in the ICS when the update opens the N2
// connection, a PDU SESSION RESOURCE SETUP REQUEST otherwise) and the Accept carries
// the PDU session status and PDU session reactivation result IEs.
func TestAUDRegistration12_ContainerPDUSessionIEs(t *testing.T) {
	for _, onNewN2 := range []bool{true, false} {
		h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
		s := &reactSender{deleted: make(chan string, 4)}
		h.sender = s
		ue.TransitionTo(amfctx.GMMRegistered)
		ue.NASOnNewN2Connection = onNewN2
		ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
		ue.SubscribedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}, {SST: 2}}
		ue.PDUSessions = map[uint8]*amfctx.PDUSession{
			5: {PDUSessionID: 5, SMFInstanceID: "ref5", SNSSAI: amfctx.SNSSAISubscribed{SST: 1}},
			6: {PDUSessionID: 6, SMFInstanceID: "ref6", SNSSAI: amfctx.SNSSAISubscribed{SST: 1}},
		}
		pdu := updateWithContainer(t, ue, []byte{
			0x2f, 0x02, 0x01, 0x02, // Requested NSSAI: SST 2
			0x50, 0x02, 0x20, 0x00, // PDU session status: only PSI 5 active at the UE
			0x40, 0x02, 0x20, 0x00}) // Uplink data status: PSI 5

		if err := h.HandleNASMessage(context.Background(), ue, pdu); err != nil {
			t.Fatalf("onNewN2=%v: %v", onNewN2, err)
		}
		select {
		case ref := <-s.deleted:
			if ref != "ref6" {
				t.Errorf("onNewN2=%v: SMF release of %q, want ref6", onNewN2, ref)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("onNewN2=%v: no SM context release for the inactive PDU session", onNewN2)
		}
		ue.Lock()
		_, has6 := ue.PDUSessions[6]
		_, has5 := ue.PDUSessions[5]
		ue.Unlock()
		if has6 || !has5 {
			t.Errorf("onNewN2=%v: sessions after release: 5=%v 6=%v, want 5 kept, 6 released", onNewN2, has5, has6)
		}
		if len(ue.AllowedNSSAI) != 1 || ue.AllowedNSSAI[0].SST != 2 {
			t.Errorf("onNewN2=%v: Allowed NSSAI %v, want re-evaluated to SST 2", onNewN2, ue.AllowedNSSAI)
		}
		var accept []byte
		if onNewN2 {
			if len(s.ics) != 1 || len(s.items) != 1 || s.items[0].PDUSessionID != 5 ||
				!bytes.Equal(s.items[0].Transfer, []byte("n2sm-ref5")) {
				t.Fatalf("ICS %d items %+v, want one item PSI 5 with the SMF N2 SM info", len(s.ics), s.items)
			}
			accept = s.ics[0]
		} else {
			if len(s.psrSetup) != 1 || s.psrSetup[0] != 5 || len(s.dl) != 1 {
				t.Fatalf("PSI setups %v, DL NAS %d; want PSI 5 re-established over the existing N2 connection", s.psrSetup, len(s.dl))
			}
			accept = s.dl[0]
		}
		plain := decipherDLPDU(t, ue, 0, accept)
		if !bytes.Contains(plain, []byte{0x50, 0x02, 0x20, 0x00}) {
			t.Errorf("onNewN2=%v: Accept %x lacks PDU session status (PSI 5 only)", onNewN2, plain)
		}
		if !bytes.Contains(plain, []byte{0x26, 0x02, 0x00, 0x00}) {
			t.Errorf("onNewN2=%v: Accept %x lacks PDU session reactivation result (no failure)", onNewN2, plain)
		}
	}
}

// TestAUDRegistration31_ContextKeptThroughSMC: the context in use before the
// SECURITY MODE COMMAND survives a SECURITY MODE REJECT protected with it, a
// superseded procedure and a T3560 abort (lost SMC); a COMPLETE promotes the new one.
func TestAUDRegistration31_ContextKeptThroughSMC(t *testing.T) {
	newCtx := amfctx.SecurityContext{Active: true, NGKSI: 2, IntegrityAlgID: 2, CipheringAlgID: 2,
		KNASint: bytes.Repeat([]byte{0x77}, 16), KNASenc: bytes.Repeat([]byte{0x88}, 16),
		KAMF: bytes.Repeat([]byte{0x99}, 32)}
	begin := func(ue *amfctx.UEContext) amfctx.SecurityContext {
		old := ue.SecurityCtx
		ue.BeginSecurityCtxChange()
		ue.SecurityCtx = newCtx // what Phase2 does, counts restarted at 0
		ue.SetRegStage(amfctx.RegStageSMC)
		return old
	}
	t.Run("reject protected with the old context", func(t *testing.T) {
		h, ue := newEntryHandler(t)
		old := ue.SecurityCtx
		pdu := buildULSecuredPDU(t, ue, nas.MsgTypeSecurityModeReject, []byte{byte(nas.CauseSecurityModeRejectedUnspecified)})
		begin(ue)
		if err := h.HandleNASMessage(context.Background(), ue, pdu); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ue.SecurityCtx.KNASint, old.KNASint) || ue.SecurityCtx.NGKSI != old.NGKSI || !ue.SecurityCtx.Active {
			t.Fatal("SECURITY MODE REJECT did not leave the context in use")
		}
		if ue.SecurityCtx.UplinkCount != 1 {
			t.Errorf("UL COUNT %d, want 1 (the REJECT was verified with the old context)", ue.SecurityCtx.UplinkCount)
		}
		if ue.SecurityCtxChangePending() {
			t.Error("security context change still pending after the REJECT")
		}
	})
	t.Run("lost SMC, T3560 fifth expiry", func(t *testing.T) {
		h, ue := newEntryHandler(t)
		old := begin(ue)
		h.abortRegProc(ue, h.logger)
		if !bytes.Equal(ue.SecurityCtx.KNASenc, old.KNASenc) || !ue.SecurityCtx.Active {
			t.Fatal("aborted SECURITY MODE COMMAND procedure dropped the context in use")
		}
	})
	t.Run("first registration, reject drops the only context", func(t *testing.T) {
		h, ue := newEntryHandler(t)
		ue.SecurityCtx = amfctx.SecurityContext{}
		begin(ue)
		_ = h.HandleNASMessage(context.Background(), ue,
			[]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeSecurityModeReject), byte(nas.CauseSecurityModeRejectedUnspecified)})
		if ue.SecurityCtx.Active {
			t.Error("unconfirmed context of a first registration kept after SECURITY MODE REJECT")
		}
	})
	t.Run("complete promotes the new context", func(t *testing.T) {
		h, ue := newEntryHandler(t)
		begin(ue)
		_ = h.handleSecurityModeComplete(context.Background(), ue, &nas.Message{Body: &nas.SecurityModeComplete{}})
		if ue.SecurityCtxChangePending() || !bytes.Equal(ue.SecurityCtx.KNASint, newCtx.KNASint) {
			t.Error("SECURITY MODE COMPLETE did not promote the new context")
		}
		if _, restored := ue.RollbackSecurityCtxChange(); restored {
			t.Error("old context still restorable after COMPLETE")
		}
	})
}
