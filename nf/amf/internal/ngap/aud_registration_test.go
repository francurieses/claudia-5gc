package ngap

// aud_registration_test.go — failing-by-design reproductions for the
// registration spec audit (dev/campaigns/results/audit-registration.md).
// Every test is skipped; run them to see today's deviation:
//
//	GOWORK=off go test ./nf/amf/internal/ngap/ -run TestAUDRegistration -v -args -aud-registration-repro
//	GOWORK=off go test -race ./nf/amf/internal/ngap/ -run TestAUDRegistration24 -v -args -aud-registration-repro
//
// Ref: TS 24.501 §5.5.1.2.5, §5.5.1.2.7, §5.5.1.3.8; TS 38.413 §8.3.1, §9.2.2.1

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// regAudRepro opts in to the AUD-registration reproductions below; without it
// they are skipped (command in the file header).
var regAudRepro = flag.Bool("aud-registration-repro", false, "run the AUD-registration failing-by-design reproductions")

func newRegAudServer(t *testing.T) *Server {
	t.Helper()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer("", amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil), nil, AMFConfig{}, lg)
}

func regAudICSFailure(ue *amfctx.UEContext) *Message {
	return &Message{
		Type:          2, // UnsuccessfulOutcome
		ProcedureCode: ProcInitialContextSetup,
		Value: &InitialContextSetupFailureMsg{
			AMFUENGAPId: ue.AMFUENGAPId, RANUENGAPId: ue.RANUENGAPId,
			CausePresent: 1, CauseValue: 26, // radioNetwork: failure-in-radio-interface-procedure
		},
	}
}

// TestAUDRegistration01_UnknownTMSIInitialRegistrationNotCause10: a security
// protected REGISTRATION REQUEST with 5GS registration type "initial
// registration" and an unknown 5G-S-TMSI is answered with REGISTRATION REJECT
// #10. Over 3GPP access #10 is an abnormal case for an initial registration
// (TS 24.501 §5.5.1.2.5, §5.5.1.2.7 d)): the UE retries with the same 5G-GUTI,
// is rejected again, and only after the 5th attempt deletes the 5G-GUTI and
// waits T3502. The AMF should request the SUCI (TS 23.502 §4.2.2.2.2 step 6).
func TestAUDRegistration01_UnknownTMSIInitialRegistrationNotCause10(t *testing.T) {
	// Inner (plain) REGISTRATION REQUEST: ngKSI 0, type 1 (initial), 5G-GUTI.
	inner := []byte{0x7e, 0x00, 0x41, 0x01, 0x00, 0x0b, 0xf2,
		0x00, 0xf1, 0x10, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}
	// Integrity protected initial NAS message (SHT=1), TS 24.501 §4.4.5.
	pdu := append([]byte{0x7e, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00}, inner...)

	// Same decision handleInitialUEMessage takes for an unknown 5G-S-TMSI (ngap.go:1518).
	if !unknownTMSIStartsFreshRegistration(pdu) {
		t.Fatal("initial registration with an unknown 5G-GUTI must take the fresh-context path (IDENTITY REQUEST), not REGISTRATION REJECT #10")
	}
	// Periodic (type 3) and mobility (type 2) updates keep #10 (TS 24.501 §5.5.1.3.8).
	for _, rt := range []byte{0x02, 0x03} {
		in := append([]byte(nil), inner...)
		in[3] = rt
		p := append([]byte{0x7e, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00}, in...)
		if unknownTMSIStartsFreshRegistration(p) {
			t.Fatalf("registration type %d with unknown GUTI must keep reject #10", rt)
		}
		mt, known := nas.PeekMessageType(p)
		r, name, _ := rejectForUnknownTMSI(mt, known)
		if name != "RegistrationReject" || r[3] != byte(nas.CauseImplicitlyDeregistered) {
			t.Fatalf("type %d: got %s %x, want RegistrationReject #10", rt, name, r)
		}
	}
	// Plain emergency registration (type 4) is also fresh.
	if !unknownTMSIStartsFreshRegistration(append([]byte{0x7e, 0x00}, append([]byte{0x41, 0x04}, inner[4:]...)...)) {
		t.Fatal("emergency registration must take the fresh path")
	}
}

// TestAUDRegistration02_ICSCarriesMandatoryAllowedNSSAI: with an empty Allowed
// NSSAI the builder leaves out the mandatory (criticality reject) Allowed NSSAI
// IE and still emits the PDU (TS 38.413 §9.2.2.1); a strict gNB rejects it.
func TestAUDRegistration02_ICSCarriesMandatoryAllowedNSSAI(t *testing.T) {
	raw := BuildInitialContextSetupRequest(1, 2, []byte{0x7e, 0x02}, testSecKey,
		0x8000, 0x8000, "001", "01", 0x80, 1, 0x01,
		nil, // empty Allowed NSSAI (e.g. no requested slice subscribed, or all pending NSSAA)
		0, 0, 0, nil, capability.PeerRAN{})
	if len(raw) > 0 && !contains(icsIEIDs(t, raw), ngapType.ProtocolIEIDAllowedNSSAI) {
		t.Fatal("INITIAL CONTEXT SETUP REQUEST emitted without the mandatory Allowed NSSAI IE (TS 38.413 §9.2.2.1)")
	}
}

// TestAUDRegistration05_ICSFailureKeepsRegisteredContext: an INITIAL CONTEXT
// SETUP FAILURE for a 5GMM-REGISTERED UE (Service Request or periodic update
// ICS) de-registers it and schedules removal of the whole context, orphaning
// its PDU sessions at the SMF. TS 38.413 §8.3.1.3 only asks the AMF to relay the
// per-PDU-session Unsuccessful Transfer and to consider the NAS-PDU undelivered;
// TS 24.501 §5.5.1.3.8 a) keeps both 5G-GUTIs valid and enters 5GMM-IDLE.
func TestAUDRegistration05_ICSFailureKeepsRegisteredContext(t *testing.T) {
	s := newRegAudServer(t)
	ue := s.mgr.AllocateUEContext(7)
	s.mgr.SetSUPI(ue, "imsi-001010000000001")
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.CMState = amfctx.CMConnected
	ue.PDUSessions[5] = &amfctx.PDUSession{PDUSessionID: 5, SMFInstanceID: "sm-ctx-5"}

	s.handleInitialContextSetupFailure(context.Background(), newReleaseGNB("10.0.0.1:38412"), regAudICSFailure(ue))

	if ue.State != amfctx.GMMRegistered || ue.PendingRemoval {
		t.Fatalf("after ICS FAILURE: state=%s pendingRemoval=%v; want 5GMM-REGISTERED kept, no removal", ue.State, ue.PendingRemoval)
	}
}

// TestAUDRegistration19_ICSResponseFailedPSIRelayedToSMF: PSIs in the Failed
// to Setup list of an INITIAL CONTEXT SETUP RESPONSE are only logged; TS 38.413
// §8.3.1.2 requires the AMF to transfer each Unsuccessful Transfer to the SMF.
func TestAUDRegistration19_ICSResponseFailedPSIRelayedToSMF(t *testing.T) {
	s := newRegAudServer(t)
	relayed := make(chan string, 1)
	s.SetPDUSessionSetupFailRelayHandler(func(_ context.Context, ref string, _ []byte) { relayed <- ref })
	ue := s.mgr.AllocateUEContext(7)
	ue.PDUSessions[5] = &amfctx.PDUSession{PDUSessionID: 5, SMFInstanceID: "sm-ctx-5"}

	s.handleInitialContextSetupResponse(context.Background(), newReleaseGNB("10.0.0.1:38412"), &Message{
		Type: 1, ProcedureCode: ProcInitialContextSetup,
		Value: &InitialContextSetupResponseMsg{AMFUENGAPId: ue.AMFUENGAPId, RANUENGAPId: 7, FailedPSIs: []uint8{5}},
	})
	select {
	case <-relayed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("failed PSI 5 of the ICS Response never reached the SMF (TS 38.413 §8.3.1.2)")
	}
}

// TestAUDRegistration24_ICSFailureRacesSnapshot: handleInitialContextSetupFailure
// runs on the SCTP dispatch goroutine and writes UEContext.State (TransitionTo)
// and PendingRemoval without the UE lock, while every other reader takes it.
// Only meaningful under -race (see the file header).
func TestAUDRegistration24_ICSFailureRacesSnapshot(t *testing.T) {
	s := newRegAudServer(t)
	ue := s.mgr.AllocateUEContext(7)
	gnb := newReleaseGNB("10.0.0.1:38412")
	done := make(chan struct{})
	go func() { // the SCTP dispatch goroutine
		defer close(done)
		for i := 0; i < 2000; i++ {
			s.handleInitialContextSetupFailure(context.Background(), gnb, regAudICSFailure(ue))
		}
	}()
	for { // a concurrent reader (mgmt API / MCP ue_list) takes the UE lock
		select {
		case <-done:
			return
		default:
			_ = ue.Snapshot()
		}
	}
}

// TestAUDRegistration30_NewN2ConnectionFlag: the NAS message of an INITIAL UE
// MESSAGE from a returning CM-IDLE UE is processed with NASOnNewN2Connection
// set (the registration update then derives a fresh KgNB and sends the INITIAL
// CONTEXT SETUP REQUEST, TS 33.501 §6.8.1.2.1); an UPLINK NAS TRANSPORT of an
// already connected UE is not (no ICS). The flag is cleared afterwards.
func TestAUDRegistration30_NewN2ConnectionFlag(t *testing.T) {
	h := newAudFixHarness(t)
	ue := h.srv.mgr.AllocateUEContext(5)
	ue.GNBAddr = "10.0.0.1:38412"
	tmsi := h.srv.mgr.AssignGUTI(context.Background(), ue).TMSI
	if got, ok := h.srv.mgr.GetByTMSI(tmsi); !ok || got != ue {
		t.Fatal("test setup: UE not indexed by 5G-TMSI")
	}
	// Security protected (SHT 2) mobility registration update: not a plain initial one.
	pdu := []byte{0x7e, 0x02, 0x01, 0x02, 0x03, 0x04, 0x00, 0x7e, 0x00, 0x41, 0x02}
	tm := tmsi
	h.srv.handleInitialUEMessage(context.Background(), h.gnb, &Message{Value: &InitialUEMessage{
		RANUENGAPId: 9, NASPdu: pdu, FiveGSTMSI: &tm,
	}})
	h.srv.WaitUESerialForTest(ue.AMFUENGAPId)
	h.srv.handleUplinkNASTransport(context.Background(), h.gnb, &Message{Value: &UplinkNASTransport{
		AMFUENGAPId: ue.AMFUENGAPId, RANUENGAPId: 9, NASPdu: pdu,
	}})
	h.srv.WaitUESerialForTest(ue.AMFUENGAPId)

	h.nas.mu.Lock()
	defer h.nas.mu.Unlock()
	if len(h.nas.newN2) != 2 || !h.nas.newN2[0] || h.nas.newN2[1] {
		t.Fatalf("NASOnNewN2Connection per NAS message = %v, want [true false]", h.nas.newN2)
	}
	ue.Lock()
	left := ue.NASOnNewN2Connection
	ue.Unlock()
	if left {
		t.Error("NASOnNewN2Connection not cleared after the NAS message")
	}
}

// TestAUDRegistration31_CipheredUnknownTMSINeverFresh: the registration type is
// never read from a ciphered message (SHT 2/4), even when its bytes happen to
// look like a plain 5GMM header. Ref: TS 24.501 §4.4.5.
func TestAUDRegistration31_CipheredUnknownTMSINeverFresh(t *testing.T) {
	for _, sht := range []byte{0x02, 0x04} {
		pdu := []byte{0x7e, sht, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x7e, 0x00, 0x41, 0x01, 0x00}
		if unknownTMSIStartsFreshRegistration(pdu) {
			t.Errorf("SHT %d: ciphered message treated as a fresh initial registration", sht)
		}
	}
	if unknownTMSIStartsFreshRegistration([]byte{0x7e}) {
		t.Error("truncated PDU treated as fresh registration")
	}
}
