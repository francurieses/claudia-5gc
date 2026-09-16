package procedures

// nas_count_reset_test.go — regression test for the NAS COUNT reset that must
// happen when a new 5G NAS security context is taken into use.
//
// TS 33.501 §6.4.3.1 / TS 24.501 §4.4.3.1: establishing a new 5G NAS security
// context resets both NAS COUNTs to zero. The AMF used to rely on the zero value
// of a freshly allocated UEContext for that, which holds only for a UE seen once.
// A real handset that never sees its Registration Accept retransmits the
// Registration Request on the SAME open NGAP association, so authentication runs
// again on the SAME UEContext: new KAMF, new KNASint/KNASenc, but stale COUNTs.
// The SecurityModeCommand that follows carries SHT=0x03 ("with new security
// context"), so the UE restarts its own COUNTs at 0 while the AMF keeps counting
// from the abandoned attempt. Every MAC after that is computed over a COUNT the
// peer does not expect, the UE silently discards the Registration Accept, and it
// re-registers from SUCI forever. That is indistinguishable, from the bench,
// from a radio fault.

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// fakeAUSF confirms any RES* and returns a fixed SUPI and KAUSF.
type fakeAUSF struct{ supi string }

func (f *fakeAUSF) InitiateAuth(context.Context, string, string) (*AUSFInitResponse, error) {
	return &AUSFInitResponse{}, nil
}

func (f *fakeAUSF) ResyncAuth(context.Context, string, string, [16]byte, []byte) (*AUSFInitResponse, error) {
	return &AUSFInitResponse{}, nil
}

func (f *fakeAUSF) ConfirmAuth(context.Context, string, string) (*AUSFConfirmResponse, error) {
	kausf, _ := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	return &AUSFConfirmResponse{SUPI: f.supi, KAUSF: kausf}, nil
}

func newCountTestHandler() *RegistrationHandler {
	return &RegistrationHandler{
		mgr:            amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil),
		ausf:           &fakeAUSF{supi: "imsi-001010000010011"},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		servingNetName: "5G:mnc01.mcc001.3gppnetwork.org",
	}
}

// TestPhase2_ResetsNASCountsOnNewSecurityContext is the regression: a UEContext
// carrying COUNTs from an abandoned attempt must come out of Phase 2 at zero.
func TestPhase2_ResetsNASCountsOnNewSecurityContext(t *testing.T) {
	h := newCountTestHandler()
	ue := h.mgr.AllocateUEContext(1)

	// Simulate the abandoned first attempt: a security context was activated and
	// several NAS messages were exchanged under it before the UE gave up.
	ue.SecurityCtx.Active = true
	ue.SecurityCtx.DownlinkCount = 7
	ue.SecurityCtx.UplinkCount = 4

	smc, _, err := h.Phase2_ProcessAuthResponse(
		context.Background(), ue, &nas.AuthenticationResponse{RES: []byte{0x01, 0x02, 0x03, 0x04}})
	if err != nil {
		t.Fatalf("Phase2_ProcessAuthResponse: %v", err)
	}
	if smc == nil {
		t.Fatal("Phase2_ProcessAuthResponse returned no SecurityModeCommand")
	}

	if ue.SecurityCtx.DownlinkCount != 0 {
		t.Errorf("DownlinkCount = %d, want 0: TS 33.501 §6.4.3.1 resets both NAS "+
			"COUNTs when a new 5G NAS security context is taken into use; a stale "+
			"DL COUNT makes the UE discard the Registration Accept",
			ue.SecurityCtx.DownlinkCount)
	}
	if ue.SecurityCtx.UplinkCount != 0 {
		t.Errorf("UplinkCount = %d, want 0: TS 33.501 §6.4.3.1 resets both NAS "+
			"COUNTs when a new 5G NAS security context is taken into use; a stale "+
			"UL COUNT makes the AMF reject the UE's Security Mode Complete MAC",
			ue.SecurityCtx.UplinkCount)
	}
}

// TestPhase2_FreshUEContextStartsAtZero pins the ordinary first-attach case, so
// the reset above cannot be "fixed" by something that only zeroes on a retry.
func TestPhase2_FreshUEContextStartsAtZero(t *testing.T) {
	h := newCountTestHandler()
	ue := h.mgr.AllocateUEContext(1)

	if _, _, err := h.Phase2_ProcessAuthResponse(
		context.Background(), ue, &nas.AuthenticationResponse{RES: []byte{0x01}}); err != nil {
		t.Fatalf("Phase2_ProcessAuthResponse: %v", err)
	}
	if ue.SecurityCtx.DownlinkCount != 0 || ue.SecurityCtx.UplinkCount != 0 {
		t.Fatalf("fresh context COUNTs = dl:%d ul:%d, want 0/0",
			ue.SecurityCtx.DownlinkCount, ue.SecurityCtx.UplinkCount)
	}
}
