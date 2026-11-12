package nasmsg

import (
	"context"
	"errors"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// countingAUSF counts InitiateAuth calls.
type countingAUSF struct {
	regAudAUSF
	calls int
}

func (a *countingAUSF) InitiateAuth(ctx context.Context, id, sn string) (*procedures.AUSFInitResponse, error) {
	a.calls++
	return a.regAudAUSF.InitiateAuth(ctx, id, sn)
}

// TestIdentityResponseUnusableSUCIRejected: an Identity Response whose SUCI
// cannot be rendered (Profile A, key id 0) or that is not a SUCI gets
// REGISTRATION REJECT #96, not silence, and the AUSF is not called.
// Ref: TS 24.501 §5.5.1.2.8 b), §5.4.3.3
func TestIdentityResponseUnusableSUCIRejected(t *testing.T) {
	// Plain Identity Response, SUCI: IMSI, 001/01, routing 0000, scheme 1
	// (Profile A), key id 0 (invalid), 5 output octets.
	badSUCI := []byte{0x7e, 0x00, 0x5c, 0x00, 0x0d, 0x01, 0x00, 0xf1, 0x10, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
	// Plain Identity Response carrying an IMEI (type 2), not a SUCI.
	imei := []byte{0x7e, 0x00, 0x5c, 0x00, 0x09, 0x3b, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xf5}
	for _, tc := range []struct {
		name string
		pdu  []byte
	}{{"unrepresentable SUCI", badSUCI}, {"non-SUCI identity", imei}} {
		t.Run(tc.name, func(t *testing.T) {
			ausf := &countingAUSF{}
			h, _, _, ue, s := newRegAudHandler(t, ausf, regAudUDM{})
			ue.SecurityCtx.Active = false
			ue.SetRegStage(amfctx.RegStageIdentity)
			err := h.HandleNASMessage(context.Background(), ue, tc.pdu)
			var rc *procedures.ErrRejectCause
			if !errors.As(err, &rc) || rc.Cause != nas.CauseInvalidMandatoryInformation {
				t.Fatalf("err = %v; want ErrRejectCause #96", err)
			}
			if len(s.dl) != 1 || s.dl[0][2] != byte(nas.MsgTypeRegistrationReject) ||
				s.dl[0][3] != byte(nas.CauseInvalidMandatoryInformation) {
				t.Fatalf("DL NAS = %x; want one REGISTRATION REJECT #96", s.dl)
			}
			if ausf.calls != 0 {
				t.Fatalf("AUSF called %d times", ausf.calls)
			}
		})
	}
}

// TestRegistrationRequestUnusableSUCIRejected: Phase1 returns a #96
// ErrRejectCause for an unrenderable SUCI and never calls the AUSF.
func TestRegistrationRequestUnusableSUCIRejected(t *testing.T) {
	ausf := &countingAUSF{}
	_, reg, mgr, _, _ := newRegAudHandler(t, ausf, regAudUDM{})
	rr := &nas.RegistrationRequest{
		RegistrationType:     nas.RegistrationTypeInitial,
		UESecurityCapability: &nas.UESecurityCapability{EA0: true, IA2: true},
		MobileIdentity: nas.MobileIdentity{Type: nas.MobileIdentitySUCI, SUCI: &nas.SUCIMobileIdentity{
			MCC: "001", MNC: "01", RoutingIndicator: "0000", ProtectionSchemeID: 1,
			SchemeOutput: []byte{1, 2, 3},
		}},
	}
	_, err := reg.Phase1_InitiateAuthentication(context.Background(),
		procedures.RegistrationInput{UE: mgr.AllocateUEContext(9), RegRequest: rr})
	var rc *procedures.ErrRejectCause
	if !errors.As(err, &rc) || rc.Cause != nas.CauseInvalidMandatoryInformation || ausf.calls != 0 {
		t.Fatalf("err = %v, AUSF calls %d; want #96 reject, no AUSF call", err, ausf.calls)
	}
}
