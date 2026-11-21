package nasmsg

// empty_allowed_nssai_test.go — a UE with an empty Allowed NSSAI never gets an
// INITIAL CONTEXT SETUP REQUEST (its Allowed NSSAI IE is mandatory), and is
// still answered over DOWNLINK NAS TRANSPORT.
// Ref: TS 38.413 §9.2.2.1; TS 24.501 §5.6.1.4.1, §5.5.1.3.4

import (
	"context"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func emptyAllowedUE(t *testing.T) (*Handler, *amfctx.UEContext, *regAudSender) {
	t.Helper()
	h, _, _, ue, s := newRegAudHandler(t, nil, regAudUDM{})
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.NASOnNewN2Connection = true
	ue.AllowedNSSAI = nil
	return h, ue, s
}

// TestServiceRequestEmptyAllowedNSSAINoICS: SERVICE ACCEPT in DL NAS TRANSPORT,
// ciphered, no ICS, KgNB untouched.
func TestServiceRequestEmptyAllowedNSSAINoICS(t *testing.T) {
	h, ue, s := emptyAllowedUE(t)
	dlCount := ue.SecurityCtx.DownlinkCount
	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeServiceRequest, srBody(nas.ServiceTypeData))); err != nil {
		t.Fatal(err)
	}
	if len(s.ics) != 0 || len(s.dl) != 1 {
		t.Fatalf("ics=%d dl=%d; want no ICS and one SERVICE ACCEPT in DL NAS TRANSPORT", len(s.ics), len(s.dl))
	}
	if ue.SecurityCtx.DownlinkCount != dlCount+1 {
		t.Fatalf("DL COUNT %d -> %d; want one protected message", dlCount, ue.SecurityCtx.DownlinkCount)
	}
	in := decipherDLPDU(t, ue, dlCount, s.dl[0])
	if in[2] != byte(nas.MsgTypeServiceAccept) {
		t.Fatalf("inner=%x; want SERVICE ACCEPT", in)
	}
	if ue.CMState != amfctx.CMConnected {
		t.Fatalf("CM state %v; want CM-CONNECTED", ue.CMState)
	}
}

// TestRegistrationUpdateEmptyAllowedNSSAINoICS: on a new N2 connection (CM-IDLE
// update) the Accept still goes in DL NAS TRANSPORT, no ICS, KgNB kept.
func TestRegistrationUpdateEmptyAllowedNSSAINoICS(t *testing.T) {
	h, ue, s := emptyAllowedUE(t)
	body := regReqWithCap(t, 2, "")[3:]
	body[0] = 0x12
	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, body)); err != nil {
		t.Fatal(err)
	}
	if len(s.ics) != 0 || len(s.dl) != 1 {
		t.Fatalf("ics=%d dl=%d; want no ICS and one REGISTRATION ACCEPT in DL NAS TRANSPORT", len(s.ics), len(s.dl))
	}
}
