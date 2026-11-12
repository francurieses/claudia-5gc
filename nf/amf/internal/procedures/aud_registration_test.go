package procedures

// aud_registration_test.go — failing-by-design reproductions for the
// registration spec audit (dev/campaigns/results/audit-registration.md).
// Fixed findings (08, 10, 14) run as normal regression tests; the still-open ones
// are skipped unless the opt-in flag is given:
//
//	GOWORK=off go test ./nf/amf/internal/procedures/ -run TestAUDRegistration -v -args -aud-registration-repro
//
// Ref: TS 24.501 §5.5.1.2.4, §5.5.1.2.5, §5.5.1.2.8; TS 23.003 §2.10.1;
// TS 23.502 §4.2.2.2.2; TS 29.571 §5.3.2

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"regexp"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// regAudRepro opts in to the AUD-registration reproductions below; without it
// they are skipped (command in the file header).
var regAudRepro = flag.Bool("aud-registration-repro", false, "run the AUD-registration failing-by-design reproductions") //nolint:unused // no gated test left here; keeps -aud-registration-repro a valid flag for the campaign command

// regAudAUSF records the identity of every authentication initiation.
type regAudAUSF struct{ ids []string }

func (a *regAudAUSF) InitiateAuth(_ context.Context, id, _ string) (*AUSFInitResponse, error) {
	a.ids = append(a.ids, id)
	return &AUSFInitResponse{AuthCtxID: "auth-1"}, nil
}
func (a *regAudAUSF) ResyncAuth(context.Context, string, string, [16]byte, []byte) (*AUSFInitResponse, error) {
	return &AUSFInitResponse{AuthCtxID: "auth-2"}, nil
}
func (a *regAudAUSF) ConfirmAuth(context.Context, string, string) (*AUSFConfirmResponse, error) {
	return nil, errors.New("regAudAUSF: confirm not used")
}

// regAudUDM answers UECM and SDM successfully with the given subscribed slices.
type regAudUDM struct{ allowed []amfctx.SNSSAISubscribed }

func (regAudUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (u regAudUDM) GetAMSubscriptionData(context.Context, string) (*UDMAMSubscription, error) {
	return &UDMAMSubscription{AllowedNSSAI: u.allowed}, nil
}
func (regAudUDM) DeregisterUECM(context.Context, string) error { return nil }

func newRegAudRegistration(t *testing.T, ausf AUSFClient, udm UDMClient) (*RegistrationHandler, *amfctx.Manager) {
	t.Helper()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01", AMFRegionID: 2, AMFSetID: 1, AMFID: 1}, nil, nil, nil)
	return NewRegistrationHandler(mgr, ausf, udm, nil, "nf", "001", "01", lg), mgr
}

func regAudSUCIRequest(scheme, keyID byte) *nas.RegistrationRequest {
	return &nas.RegistrationRequest{
		RegistrationType: nas.RegistrationTypeInitial,
		MobileIdentity: nas.MobileIdentity{Type: nas.MobileIdentitySUCI, SUCI: &nas.SUCIMobileIdentity{
			MCC: "001", MNC: "01", RoutingIndicator: "0000",
			ProtectionSchemeID: scheme, HomeNetworkPublicKeyID: keyID,
			SchemeOutput: []byte{0x00, 0x00, 0x00, 0x00, 0x10},
		}},
	}
}

// TestAUDRegistration02_EmptyAllowedNSSAIRejected: when no requested S-NSSAI is
// subscribed, Phase3 builds a REGISTRATION ACCEPT with an empty Allowed NSSAI
// (encoded "15 00", below the 4-octet minimum of §9.11.3.37). TS 24.501
// §5.5.1.2.5 requires REGISTRATION REJECT #62 with the rejected NSSAI.
func TestAUDRegistration02_EmptyAllowedNSSAIRejected(t *testing.T) {
	h, mgr := newRegAudRegistration(t, nil, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, "imsi-001010000000001")
	ue.RequestedNSSAI = []amfctx.SNSSAISubscribed{{SST: 2}} // not subscribed

	ra, err := h.Phase3_ProcessSMCComplete(context.Background(), ue)
	var ns *NoNetworkSlicesError
	if !errors.As(err, &ns) || ra != nil {
		t.Fatalf("got ra=%v err=%v; want NoNetworkSlicesError (REGISTRATION REJECT #62, TS 24.501 §5.5.1.2.5)", ra, err)
	}
	if len(ns.Rejected) != 1 || ns.Rejected[0].SNSSAI.SST != 2 || ns.Rejected[0].Cause != nas.RejectedCauseNotAvailableInPLMN {
		t.Fatalf("rejected NSSAI = %+v; want requested SST 2, cause 0", ns.Rejected)
	}
	// The #62 body carries the Rejected NSSAI IE (0x69): 3e | 69 02 | (len 1|cause 0) SST 2.
	body, err := nas.EncodeRegistrationReject(&nas.RegistrationReject{Cause5GMM: byte(nas.CauseNoNetworkSlicesAvailable), RejectedNSSAI: ns.Rejected})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x3e, 0x69, 0x02, 0x10, 0x02}; !bytes.Equal(body, want) {
		t.Fatalf("reject body %x, want %x", body, want)
	}
}

// TestAUDRegistration04_SUCIStringFollowsTS29571: the SUCI handed to the AUSF is
// "suci-<mcc><mnc>-<RI>-0-<scheme>-<output>" and drops the home network public
// key identifier. TS 29.571 §5.3.2 SupiOrSuci (structured branch, without the
// catch-all alternative) is "suci-0-<mcc>-<mnc>-<RI>-<scheme>-<keyId>-<output>".
func TestAUDRegistration04_SUCIStringFollowsTS29571(t *testing.T) {
	structured := regexp.MustCompile(`^suci-(0-[0-9]{3}-[0-9]{2,3}|[1-7]-.+)-[0-9]{1,4}-` +
		`(0-0-.*|[a-fA-F1-9]-([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])-[a-fA-F0-9]+)$`)
	for _, tc := range []struct {
		name          string
		scheme, keyID byte
	}{{"null scheme", 0, 0}, {"profile A, HN key 3", 1, 3}} {
		if got := extractIdentity(regAudSUCIRequest(tc.scheme, tc.keyID)); !structured.MatchString(got) {
			t.Errorf("%s: SUCI %q does not follow TS 29.571 §5.3.2 SupiOrSuci", tc.name, got)
		}
	}
}

// TestAUDRegistration08_NotRegisteredBeforeRegistrationComplete: Phase3 moves
// the UE to 5GMM-REGISTERED before the REGISTRATION ACCEPT is even sent. TS
// 24.501 §5.5.1.2.4: start T3550 and enter 5GMM-COMMON-PROCEDURE-INITIATED;
// 5GMM-REGISTERED only upon REGISTRATION COMPLETE.
func TestAUDRegistration08_NotRegisteredBeforeRegistrationComplete(t *testing.T) {
	h, mgr := newRegAudRegistration(t, nil, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, "imsi-001010000000001")
	if _, err := h.Phase3_ProcessSMCComplete(context.Background(), ue); err != nil {
		t.Fatal(err)
	}
	if ue.State == amfctx.GMMRegistered {
		t.Fatal("5GMM-REGISTERED entered before REGISTRATION ACCEPT/COMPLETE (TS 24.501 §5.5.1.2.4)")
	}
}

// TestAUDRegistration10_ZeroUESecurityCapabilityRejected: a REGISTRATION
// REQUEST whose UE security capability has no 5GS encryption and no 5GS
// integrity algorithm proceeds to authentication (and later NIA0/NEA0 are
// selected). TS 24.501 §5.5.1.2.8 i): the AMF shall return REGISTRATION REJECT.
func TestAUDRegistration10_ZeroUESecurityCapabilityRejected(t *testing.T) {
	ausf := &regAudAUSF{}
	h, mgr := newRegAudRegistration(t, ausf, regAudUDM{})
	rr := regAudSUCIRequest(0, 0)
	rr.UESecurityCapability = &nas.UESecurityCapability{} // all bits zero
	_, err := h.Phase1_InitiateAuthentication(context.Background(), RegistrationInput{UE: mgr.AllocateUEContext(1), RegRequest: rr})
	if err == nil || len(ausf.ids) != 0 {
		t.Fatalf("UE without any 5GS algorithm authenticated (AUSF called %d times, err %v); want REGISTRATION REJECT", len(ausf.ids), err)
	}
}

// TestAUDRegistration14_ForeignGUTINotResolvedByTMSIOnly: a 5G-GUTI allocated by
// another AMF (different AMF Region/Set/Pointer) whose 5G-TMSI collides with a
// local one is mapped to the local subscriber's SUPI. The 5G-TMSI is unique only
// within the allocating AMF (TS 23.003 §2.10.1), so a foreign GUAMI needs SUCI.
func TestAUDRegistration14_ForeignGUTINotResolvedByTMSIOnly(t *testing.T) {
	ausf := &regAudAUSF{}
	h, mgr := newRegAudRegistration(t, ausf, regAudUDM{})
	owner := mgr.AllocateUEContext(1)
	mgr.SetSUPI(owner, "imsi-001010000000001")
	tmsi := mgr.AssignGUTI(context.Background(), owner).TMSI

	rr := &nas.RegistrationRequest{
		RegistrationType: nas.RegistrationTypeInitial,
		MobileIdentity: nas.MobileIdentity{Type: nas.MobileIdentityGUTI, GUTI: &nas.GUTIMobileIdentity{
			MCC: "001", MNC: "01", AMFRegionID: 0x99, AMFSetID: 0x3ff, AMFID: 0x3f, TMSI: tmsi, // other AMF
		}},
		UESecurityCapability: &nas.UESecurityCapability{EA2: true, IA2: true},
	}
	_, err := h.Phase1_InitiateAuthentication(context.Background(), RegistrationInput{UE: mgr.AllocateUEContext(2), RegRequest: rr})
	if !errors.Is(err, ErrNeedSUCI) {
		t.Fatalf("foreign 5G-GUTI resolved by 5G-TMSI alone: AUSF called with %q (err %v); want ErrNeedSUCI", ausf.ids, err)
	}
}

// TestAUDRegistration27_NonSUCIIdentityRequestsSUCI: a REGISTRATION REQUEST
// carrying an IMEI / IMEISV / 5G-S-TMSI / no identity / an undecodable SUCI
// reaches the AUSF as "unknown". TS 23.502 §4.2.2.2.2 step 6: without a SUCI
// the AMF initiates the Identity Request procedure.
func TestAUDRegistration27_NonSUCIIdentityRequestsSUCI(t *testing.T) {
	tests := []struct {
		name string
		mi   nas.MobileIdentity
	}{
		{"IMEI", nas.MobileIdentity{Type: nas.MobileIdentityIMEI, IMEISV: "490154203237518"}},
		{"IMEISV", nas.MobileIdentity{Type: nas.MobileIdentityIMEISV, IMEISV: "4901542032375189"}},
		{"5G-S-TMSI", nas.MobileIdentity{Type: nas.MobileIdentityTMSI}},
		{"no identity", nas.MobileIdentity{Type: nas.MobileIdentityNoIdentity}},
		{"SUCI nil", nas.MobileIdentity{Type: nas.MobileIdentitySUCI}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ausf := &regAudAUSF{}
			h, mgr := newRegAudRegistration(t, ausf, regAudUDM{})
			rr := &nas.RegistrationRequest{
				RegistrationType:     nas.RegistrationTypeInitial,
				MobileIdentity:       tc.mi,
				UESecurityCapability: &nas.UESecurityCapability{EA2: true, IA2: true},
			}
			_, err := h.Phase1_InitiateAuthentication(context.Background(), RegistrationInput{UE: mgr.AllocateUEContext(1), RegRequest: rr})
			if !errors.Is(err, ErrNeedSUCI) {
				t.Fatalf("identity sent to the AUSF as %q (err %v); want ErrNeedSUCI (Identity Request)", ausf.ids, err)
			}
			if len(ausf.ids) != 0 {
				t.Fatalf("AUSF called with %q", ausf.ids)
			}
		})
	}
}

// TestAUDRegistration27_EmergencyPEIRejected: an emergency registration
// (type 4) identified by a PEI is rejected with cause #5 "PEI not accepted"
// since no emergency services are supported (TS 24.501 §5.5.1.2.5, Annex A.2).
func TestAUDRegistration27_EmergencyPEIRejected(t *testing.T) {
	for _, typ := range []nas.MobileIdentityType{nas.MobileIdentityIMEI, nas.MobileIdentityIMEISV} {
		ausf := &regAudAUSF{}
		h, mgr := newRegAudRegistration(t, ausf, regAudUDM{})
		rr := &nas.RegistrationRequest{
			RegistrationType:     nas.RegistrationTypeEmergency,
			MobileIdentity:       nas.MobileIdentity{Type: typ, IMEISV: "490154203237518"},
			UESecurityCapability: &nas.UESecurityCapability{EA2: true, IA2: true},
		}
		_, err := h.Phase1_InitiateAuthentication(context.Background(), RegistrationInput{UE: mgr.AllocateUEContext(1), RegRequest: rr})
		if !errors.Is(err, ErrPEINotAccepted) || len(ausf.ids) != 0 {
			t.Fatalf("type %d: err %v, AUSF %q; want ErrPEINotAccepted and no AUSF call", typ, err, ausf.ids)
		}
	}
	if PEINotAcceptedCause != 5 {
		t.Fatalf("PEINotAcceptedCause = %d, want 5", PEINotAcceptedCause)
	}
}

// TestAUDRegistration28_AllowedNSSAIAtMostEight: nine subscribed S-NSSAIs (and
// no Requested NSSAI) give a nine-entry Allowed NSSAI; an allowed NSSAI holds
// at most 8 S-NSSAIs (TS 24.501 §4.6.2.2) and the NGAP list is SIZE(1..8), so
// the ICS encode fails.
func TestAUDRegistration28_AllowedNSSAIAtMostEight(t *testing.T) {
	subs := make([]amfctx.SNSSAISubscribed, 9)
	for i := range subs {
		subs[i] = amfctx.SNSSAISubscribed{SST: uint8(i + 1)}
	}
	if n := len(buildAllowedNSSAI(filterAllowedNSSAI(nil, subs)).SNSSAIs); n > 8 {
		t.Fatalf("Allowed NSSAI carries %d S-NSSAIs; want at most 8", n)
	}
}
