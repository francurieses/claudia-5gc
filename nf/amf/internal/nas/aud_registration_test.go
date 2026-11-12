package nasmsg

// aud_registration_test.go — failing-by-design reproductions for the
// registration spec audit (dev/campaigns/results/audit-registration.md).
// Fixed findings (incl. 08, 09, 13) run as normal regression tests; the still-open ones are
// skipped unless the opt-in flag is given:
//
//	GOWORK=off go test ./nf/amf/internal/nas/ -run TestAUDRegistration -v -args -aud-registration-repro
//
// Ref: TS 24.501 §4.4.4.3, §5.4.1.3.7, §5.4.2.5, §5.5.1.2.8, §5.5.1.3.4, §7.6.3, §7.7.1

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// regAudRepro opts in to the AUD-registration reproductions below; without it
// they are skipped (command in the file header).
var regAudRepro = flag.Bool("aud-registration-repro", false, "run the AUD-registration failing-by-design reproductions")

// regAudSender records every DOWNLINK NAS TRANSPORT payload and the NAS-PDU of
// every INITIAL CONTEXT SETUP REQUEST; the other Sender methods are fakeSender's.
type regAudSender struct {
	fakeSender
	dl  [][]byte
	ics [][]byte
}

func (s *regAudSender) SendDownlinkNASTransport(_ *amfctx.UEContext, pdu []byte) error {
	s.dl = append(s.dl, append([]byte(nil), pdu...))
	return nil
}

func (s *regAudSender) SendInitialContextSetupRequest(_ *amfctx.UEContext, nasPDU []byte,
	_ [32]byte, _, _ byte, _, _ uint16, _ []ngap.PDUSessionSetupItemCxtReq) error {
	s.ics = append(s.ics, append([]byte(nil), nasPDU...))
	return nil
}

// regAudUDM answers UECM and SDM successfully with the given subscribed slices.
type regAudUDM struct{ allowed []amfctx.SNSSAISubscribed }

func (regAudUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (u regAudUDM) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	return &procedures.UDMAMSubscription{AllowedNSSAI: u.allowed}, nil
}
func (regAudUDM) DeregisterUECM(context.Context, string) error { return nil }

// regAudAUSF records the identity of every authentication initiation.
type regAudAUSF struct{ ids []string }

func (a *regAudAUSF) InitiateAuth(_ context.Context, id, _ string) (*procedures.AUSFInitResponse, error) {
	a.ids = append(a.ids, id)
	return &procedures.AUSFInitResponse{AuthCtxID: "auth-1", SUPI: "imsi-001010000000001"}, nil
}
func (a *regAudAUSF) ResyncAuth(context.Context, string, string, [16]byte, []byte) (*procedures.AUSFInitResponse, error) {
	return &procedures.AUSFInitResponse{AuthCtxID: "auth-2"}, nil
}
func (a *regAudAUSF) ConfirmAuth(context.Context, string, string) (*procedures.AUSFConfirmResponse, error) {
	return nil, errors.New("regAudAUSF: confirm not used")
}

// regAudAMPolicy returns a fixed service area restriction.
type regAudAMPolicy struct {
	sar *amfctx.ServiceAreaRestriction
}

func (p regAudAMPolicy) CreateAMPolicyAssociation(context.Context, string, string, string, string) (
	string, int, *amfctx.ServiceAreaRestriction, error) {
	return "ampol-1", 0, p.sar, nil
}
func (regAudAMPolicy) DeleteAMPolicyAssociation(context.Context, string) error { return nil }

// newRegAudHandler builds a Handler over a real RegistrationHandler and a UE
// with an active NIA2/NEA2 context, CM-CONNECTED on a known gNB address.
func newRegAudHandler(t *testing.T, ausf procedures.AUSFClient, udm procedures.UDMClient) (
	*Handler, *procedures.RegistrationHandler, *amfctx.Manager, *amfctx.UEContext, *regAudSender) {
	t.Helper()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01", AMFRegionID: 2, AMFID: 1}, nil, nil, nil)
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, "imsi-001010000000001")
	mgr.AssignGUTI(context.Background(), ue) // a registered UE owns a 5G-GUTI (5G-TMSI 1)
	ue.RANUENGAPId = 1
	ue.GNBAddr = "10.0.0.1:38412"
	ue.CMState = amfctx.CMConnected
	ue.RawUESecCap = []byte{0xe0, 0x60, 0x00, 0x00} // capability stored at the earlier registration (EA0-2, IA1-2)
	ue.SecurityCtx = amfctx.SecurityContext{
		Active: true, NGKSI: 1, IntegrityAlgID: 2, CipheringAlgID: 2,
		KNASint: bytes.Repeat([]byte{0x11}, 16),
		KNASenc: bytes.Repeat([]byte{0x22}, 16),
		KAMF:    bytes.Repeat([]byte{0x33}, 32),
	}
	reg := procedures.NewRegistrationHandler(mgr, ausf, udm, nil, "nf", "001", "01", lg)
	s := &regAudSender{}
	return NewHandler(s, reg, lg), reg, mgr, ue, s
}

// TestAUDRegistration03_ConnectedModeUpdateNoNewICS: a mobility registration
// update received over UPLINK NAS TRANSPORT (UE already CM-CONNECTED) is
// answered with a new INITIAL CONTEXT SETUP REQUEST, a KgNB derived from this
// message's NAS COUNT and a restarted NH chain. KgNB is derived only from the
// message that initiated the CM-IDLE to CM-CONNECTED transition (TS 33.501
// §6.8.1.2.1); the UE derives none here, so AS keys and NCC/NH diverge.
func TestAUDRegistration03_ConnectedModeUpdateNoNewICS(t *testing.T) {
	h, _, _, ue, s := newRegAudHandler(t, nil, regAudUDM{})
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	var k0 [32]byte
	k0[0] = 0xab
	ue.SetKgNB(k0)
	body := regReqWithCap(t, 2, "")[3:]
	body[0] = 0x12 // ngKSI 1 (current context), 5GS registration type 2 (mobility)

	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, body)); err != nil {
		t.Logf("HandleNASMessage: %v", err)
	}
	if len(s.ics) != 0 {
		t.Errorf("CONNECTED-mode registration update sent %d INITIAL CONTEXT SETUP REQUEST(s); want the REGISTRATION ACCEPT in DOWNLINK NAS TRANSPORT", len(s.ics))
	}
	if ue.KgNB != k0 {
		t.Error("KgNB re-derived (and NH chain restarted) without a CM-IDLE to CM-CONNECTED transition (TS 33.501 §6.8.1.2.1)")
	}
}

// TestAUDRegistration06_UnverifiableUpdateRequestAuthenticates: a periodic
// REGISTRATION REQUEST that cannot pass the integrity check (here: unprotected,
// ngKSI 7 "no key is available") is accepted on the AMF's context. TS 24.501
// §4.4.4.3 requires primary authentication and a SECURITY MODE COMMAND (RINMR).
func TestAUDRegistration06_UnverifiableUpdateRequestAuthenticates(t *testing.T) {
	ausf := &regAudAUSF{}
	h, _, _, ue, s := newRegAudHandler(t, ausf, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	ue.TransitionTo(amfctx.GMMRegistered)

	_ = h.HandleNASMessage(context.Background(), ue, regReqWithCap(t, 3, "")) // plain, ngKSI 7
	if len(s.ics) != 0 || len(ausf.ids) == 0 {
		t.Fatalf("unverifiable periodic update: %d ICS (Accept) sent, %d authentications; want 0 and 1 (TS 24.501 §4.4.4.3)",
			len(s.ics), len(ausf.ids))
	}
}

// TestRegistrationUpdateVerifiedForeignNgKSIAccepted: UERANSIM sends its T3512
// periodic REGISTRATION REQUEST integrity protected (MAC verifies) with ngKSI 7.
// TS 24.501 §4.4.4.3 b) triggers AKA only on an integrity-check failure.
func TestRegistrationUpdateVerifiedForeignNgKSIAccepted(t *testing.T) {
	ausf := &regAudAUSF{}
	h, _, _, ue, s := newRegAudHandler(t, ausf, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	body := regReqWithCap(t, 3, "")[3:]
	body[0] = 0x73 // ngKSI 7, periodic

	_ = h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, body))
	if len(ausf.ids) != 0 {
		t.Fatalf("verified periodic update with ngKSI 7 ran authentication (%d); want update path", len(ausf.ids))
	}
	if len(s.ics)+len(s.dl) == 0 {
		t.Fatal("no REGISTRATION ACCEPT sent")
	}
}

// TestAUDRegistration07_PlainSecurityModeCompleteDiscarded: an unprotected
// SECURITY MODE COMPLETE is processed (Phase3 runs) while a security context is
// active. TS 24.501 §4.4.4.3 lists the only messages processed without
// integrity protection; SECURITY MODE COMPLETE is not one of them.
func TestAUDRegistration07_PlainSecurityModeCompleteDiscarded(t *testing.T) {
	h, ue := newEntryHandler(t) // its stub UDM fails as soon as Phase3 is entered
	err := h.HandleNASMessage(context.Background(), ue,
		[]byte{nas.PDMobilityManagement, byte(nas.SecurityHeaderPlainNAS), byte(nas.MsgTypeSecurityModeComplete)})
	if errors.Is(err, errStubUDMFail) {
		t.Fatal("unprotected SECURITY MODE COMPLETE reached Phase3 (UDM called); it must be discarded (TS 24.501 §4.4.4.3)")
	}
}

// TestAUDRegistration09_ProtocolErrorRegistrationReject96: a REGISTRATION
// REQUEST with a syntactically incorrect mandatory IE gets no answer at all.
// TS 24.501 §5.5.1.2.8 b): REGISTRATION REJECT with #96, #99, #100 or #111.
func TestAUDRegistration09_ProtocolErrorRegistrationReject96(t *testing.T) {
	h, _, mgr, _, s := newRegAudHandler(t, nil, regAudUDM{})
	fresh := mgr.AllocateUEContext(2) // initial NAS message on a new N2 connection
	fresh.GNBAddr = "10.0.0.1:38412"
	truncated := []byte{0x7e, 0x00, 0x41, 0x71, 0x00, 0x0b, 0xf2} // 5GS mobile identity: 11 octets announced, 1 present

	_ = h.HandleNASMessage(context.Background(), fresh, truncated)
	if len(s.dl) != 1 || len(s.dl[0]) < 4 ||
		s.dl[0][2] != byte(nas.MsgTypeRegistrationReject) || s.dl[0][3] != byte(nas.CauseInvalidMandatoryInformation) {
		t.Fatalf("DL NAS = %x; want one REGISTRATION REJECT #96 (TS 24.501 §5.5.1.2.8 b))", s.dl)
	}
}

// TestAUDRegistration11_NgKSIInUseReauthenticates: AUTHENTICATION FAILURE #71
// is abandoned silently. TS 24.501 §5.4.1.3.7 e): the network selects a new
// ngKSI and re-sends the challenge; otherwise the UE's T3520 expires and it
// treats the cell as barred (§5.4.1.3.7 g)).
func TestAUDRegistration11_NgKSIInUseReauthenticates(t *testing.T) {
	h, _, _, ue, s := newRegAudHandler(t, &regAudAUSF{}, regAudUDM{})
	ue.SecurityCtx = amfctx.SecurityContext{} // authentication runs before security activation
	ue.PendingNGKSI = 1

	_ = h.HandleNASMessage(context.Background(), ue,
		[]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeAuthenticationFailure), byte(nas.CausengKSIAlreadyInUse)})
	if len(s.dl) == 0 {
		t.Fatal("AUTHENTICATION FAILURE #71 abandoned: no new AUTHENTICATION REQUEST (TS 24.501 §5.4.1.3.7 e))")
	}
}

// TestAUDRegistration12_UpdateIEsDecoded: the PDU session status (0x50) and
// Uplink data status (0x40) IEs of a REGISTRATION REQUEST are never decoded, so
// the §5.5.1.3.4 obligations (local release + PDU session status IE, user-plane
// re-establishment + PDU session reactivation result IE) cannot be met.
func TestAUDRegistration12_UpdateIEsDecoded(t *testing.T) {
	body := append(regReqWithCap(t, 3, "")[3:],
		0x50, 0x02, 0x00, 0x00, // PDU session status: every PSI inactive on the UE side
		0x40, 0x02, 0x20, 0x00) // Uplink data status: PSI 5 has pending UL data
	rr, err := nas.DecodeRegistrationRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if rr.PDUSessionStatus == nil || rr.UplinkDataStatus == nil {
		t.Fatalf("PDUSessionStatus=%x UplinkDataStatus=%x; want both decoded (TS 24.501 §5.5.1.3.4)",
			rr.PDUSessionStatus, rr.UplinkDataStatus)
	}
}

// TestAUDRegistration13_DuplicateSecurityModeCompleteSingleICS: nothing gates
// SECURITY MODE COMPLETE on a pending SECURITY MODE COMMAND; a second one re-runs
// Phase3 (UECM PUT, policy associations, a new 5G-GUTI) and sends a second ICS.
func TestAUDRegistration13_DuplicateSecurityModeCompleteSingleICS(t *testing.T) {
	h, _, _, ue, s := newRegAudHandler(t, nil, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	ue.SetRegStage(amfctx.RegStageSMC) // the SECURITY MODE COMMAND is outstanding; only the first answer may use it
	for i := 0; i < 2; i++ {
		if err := h.HandleNASMessage(context.Background(), ue,
			buildULSecuredPDU(t, ue, nas.MsgTypeSecurityModeComplete, nil)); err != nil {
			t.Fatalf("SECURITY MODE COMPLETE %d: %v", i+1, err)
		}
	}
	if len(s.ics) != 1 {
		t.Fatalf("two SECURITY MODE COMPLETE messages produced %d INITIAL CONTEXT SETUP REQUESTs; want 1", len(s.ics))
	}
}

// TestAUDRegistration16_NonAllowedAreaStillAnswered: when the PCF service area
// restriction excludes the current TA, the REGISTRATION REJECT is built and
// dropped (nothing is sent), and the context stays 5GMM-REGISTERED. TS 23.501
// §3.1 / §5.3.4.1.1: registration is allowed in a Non-Allowed Area.
func TestAUDRegistration16_NonAllowedAreaStillAnswered(t *testing.T) {
	h, reg, _, ue, s := newRegAudHandler(t, nil, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	reg.WithAMPolicy(regAudAMPolicy{sar: &amfctx.ServiceAreaRestriction{
		RestrictionType: "NOT_ALLOWED_AREAS", NotAllowedTACs: []string{"000000"}}}) // UE TAC 0

	ue.SetRegStage(amfctx.RegStageSMC)
	if err := h.HandleNASMessage(context.Background(), ue, buildULSecuredPDU(t, ue, nas.MsgTypeSecurityModeComplete, nil)); err != nil {
		t.Logf("HandleNASMessage: %v", err)
	}
	if len(s.ics) == 0 && len(s.dl) == 0 {
		t.Fatal("UE in a Non-Allowed Area got no NAS answer at all (REGISTRATION REJECT built at nas.go:557 is discarded)")
	}
	if len(s.ics) == 0 {
		t.Fatal("registration in a Non-Allowed Area must be accepted with the service area list (TS 23.501 §5.3.4.1.1)")
	}
}

// TestAUDRegistration29_DecoderOptionalIEHandling: a syntactically incorrect
// optional IE fails the whole REGISTRATION REQUEST instead of being treated as
// absent (TS 24.501 §7.7.1), a repeated IE overwrites the first one (§7.6.3),
// and the SUCI SUPI format is read from the wrong bits (§9.11.3.4: bits 5-7).
func TestAUDRegistration29_DecoderOptionalIEHandling(t *testing.T) {
	base := regReqWithCap(t, 1, "")[3:]

	bad := append(append([]byte(nil), base...), 0x2f, 0x02, 0x05, 0x01) // Requested NSSAI: S-NSSAI length 5, 1 octet present
	if _, err := nas.DecodeRegistrationRequest(bad); err != nil {
		t.Errorf("malformed optional Requested NSSAI failed the message (%v); §7.7.1: treat it as not present", err)
	}

	rep := append(append([]byte(nil), base...), 0x2e, 0x02, 0xf0, 0xf0, 0x2e, 0x02, 0x00, 0x00) // UE security capability twice
	if rr, err := nas.DecodeRegistrationRequest(rep); err != nil || rr.UESecurityCapability == nil || !rr.UESecurityCapability.EA2 {
		t.Errorf("repeated UE security capability: the second occurrence won (err %v); §7.6.3: handle the first only", err)
	}

	// SUCI, SUPI format NAI (001 in bits 7-5 of octet 4), type of identity SUCI.
	mi, err := nas.DecodeMobileIdentity([]byte{0x11, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01})
	switch {
	case err != nil || mi.SUCI == nil:
		t.Errorf("SUCI decode: %v", err)
	case mi.SUCI.SUPIFormat != 1:
		t.Errorf("SUPI format decoded as %d; want 1 (NAI): bits 5-7 of octet 4 (§9.11.3.4)", mi.SUCI.SUPIFormat)
	}
}

// TestAUDRegistration31_SecurityModeRejectKeepsPreviousContext: SECURITY MODE
// REJECT zeroes the whole security context. TS 24.501 §5.4.2.5: both sides keep
// applying the 5G NAS security context in use before the SMC.
func TestAUDRegistration31_SecurityModeRejectKeepsPreviousContext(t *testing.T) {
	h, ue := newEntryHandler(t) // ue holds an active context
	_ = h.HandleNASMessage(context.Background(), ue,
		[]byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeSecurityModeReject), byte(nas.CauseSecurityModeRejectedUnspecified)})
	if !ue.SecurityCtx.Active || len(ue.SecurityCtx.KAMF) == 0 {
		t.Fatal("SECURITY MODE REJECT wiped the security context in use before the SMC (TS 24.501 §5.4.2.5)")
	}
}

// TestAUDRegistration03_IdleModeUpdateStillSendsICS: a mobility update that is
// the INITIAL UE MESSAGE of a CM-IDLE UE keeps today's behaviour: new KgNB from
// this message's UL COUNT and an INITIAL CONTEXT SETUP REQUEST.
// Ref: TS 33.501 §6.8.1.2.1
func TestAUDRegistration03_IdleModeUpdateStillSendsICS(t *testing.T) {
	h, _, _, ue, s := newRegAudHandler(t, nil, regAudUDM{})
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	ue.NASOnNewN2Connection = true
	var k0 [32]byte
	k0[0] = 0xab
	ue.SetKgNB(k0)
	body := regReqWithCap(t, 2, "")[3:]
	body[0] = 0x12

	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, body)); err != nil {
		t.Fatalf("HandleNASMessage: %v", err)
	}
	if len(s.ics) != 1 {
		t.Fatalf("sent %d ICS; want 1 for a CM-IDLE mobility update", len(s.ics))
	}
	if ue.KgNB == k0 {
		t.Error("KgNB not re-derived on the CM-IDLE to CM-CONNECTED transition")
	}
}

// TestAUDRegistration02_RejectNoSlicesCarriesRejectedNSSAI: REGISTRATION REJECT
// #62 lists the requested S-NSSAI (Rejected NSSAI IE 0x69, or Extended rejected
// NSSAI 0x68 for an ER-NSSAI UE) and is sent in DL NAS TRANSPORT.
// Ref: TS 24.501 §5.5.1.2.5
func TestAUDRegistration02_RejectNoSlicesCarriesRejectedNSSAI(t *testing.T) {
	for _, er := range []bool{false, true} {
		h, _, _, ue, s := newRegAudHandler(t, nil, regAudUDM{})
		ue.SecurityCtx.CipheringAlgID = 0 // NEA0: inner PDU readable
		ue.ERNSSAISupported = er
		rej := []nas.RejectedSNSSAI{{Cause: nas.RejectedCauseNotAvailableInPLMN, SNSSAI: nas.SNSSAI{SST: 2, SD: 0xFFFFFF}}}
		// SD 0xFFFFFF = absent in this codec; encode result is checked below.
		if err := h.rejectNoNetworkSlices(context.Background(), ue, rej); err != nil {
			t.Fatal(err)
		}
		if len(s.dl) != 1 {
			t.Fatalf("er=%v: %d DL NAS; want 1", er, len(s.dl))
		}
		// DL NAS is security protected: EPD | SHT | MAC(4) | SN | plain NAS (NEA0).
		if len(s.dl[0]) <= secProtectedHeaderLen+4 {
			t.Fatalf("er=%v: DL NAS %x too short", er, s.dl[0])
		}
		inner := s.dl[0][secProtectedHeaderLen:]
		if inner[2] != byte(nas.MsgTypeRegistrationReject) || inner[3] != 62 {
			t.Fatalf("er=%v: inner %x, want REGISTRATION REJECT #62", er, inner)
		}
		var val []byte
		var err error
		wantIEI := byte(nas.IEIRegistrationRejectRejectedNSSAI)
		if er {
			wantIEI = nas.IEIExtendedRejectedNSSAI
			val, err = nas.EncodeExtendedRejectedNSSAI(nas.ExtendedRejectedNSSAIFromList(rej))
		} else {
			val, err = nas.RejectedNSSAIValue(rej)
		}
		if err != nil {
			t.Fatal(err)
		}
		want := append([]byte{wantIEI, byte(len(val))}, val...)
		if !bytes.Equal(inner[4:], want) {
			t.Fatalf("er=%v: optional IE %x, want %x (IEI %#x with the rejected S-NSSAI)", er, inner[4:], want, wantIEI)
		}
	}
}

// secProtectedHeaderLen is the length of the security protected 5GS NAS header:
// EPD, SHT, MAC (4 octets), sequence number. Ref: TS 24.501 §9.1.1.
const secProtectedHeaderLen = 7
