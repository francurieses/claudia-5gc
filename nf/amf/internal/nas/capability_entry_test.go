package nasmsg

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// errStubUDM fails the AM-data fetch so Phase3 stops right after the
// capability has been applied; the registration outcome is not under test.
type errStubUDM struct{}

var errStubUDMFail = errors.New("stub udm: am-data unavailable")

func (errStubUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (errStubUDM) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	return nil, errStubUDMFail
}
func (errStubUDM) DeregisterUECM(context.Context, string) error { return nil }

// newEntryHandler builds a Handler with a real RegistrationHandler (shared
// manager) so the public HandleNASMessage entry point can run end to end.
func newEntryHandler(t *testing.T) (*Handler, *amfctx.UEContext) {
	t.Helper()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, "imsi-001010000000001")
	ue.RANUENGAPId = 1
	ue.CMState = amfctx.CMConnected
	ue.SecurityCtx = amfctx.SecurityContext{
		Active: true, IntegrityAlgID: 2, CipheringAlgID: 2,
		KNASint: bytes.Repeat([]byte{0x11}, 16),
		KNASenc: bytes.Repeat([]byte{0x22}, 16),
		KAMF:    bytes.Repeat([]byte{0x33}, 32),
	}
	reg := procedures.NewRegistrationHandler(mgr, nil, errStubUDM{}, nil, "nf", "001", "01", lg)
	return NewHandler(&fakeSender{}, reg, lg), ue
}

// TestHandleNASMessage_RegistrationUpdate_Capability5GMM drives the public
// entry point into handleRegistrationUpdate (mobility 2, periodic 3): a request
// with the IE sets Capability5GMM, one without keeps the previous value.
// Ref: TS 24.501 §5.5.1.3.2, §9.11.3.1
func TestHandleNASMessage_RegistrationUpdate_Capability5GMM(t *testing.T) {
	tests := []struct {
		name    string
		regType byte
		capHex  string
		prior   *nas.FiveGMMCapability
		wantHex string
	}{
		{"mobility sets capability", 2, mmCapEnabledHex, nil, mmCapEnabledHex},
		{"periodic sets capability", 3, mmCapEnabledHex, nil, mmCapEnabledHex},
		{"IE replaces prior", 3, mmCapEnabledHex, &nas.FiveGMMCapability{Raw: []byte{0x01}}, mmCapEnabledHex},
		{"periodic without IE keeps prior", 3, "", &nas.FiveGMMCapability{Raw: []byte{0x01}}, "01"},
		{"mobility without IE keeps prior", 2, "", &nas.FiveGMMCapability{Raw: []byte{0x01}}, "01"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, ue := newEntryHandler(t)
			ue.Capability5GMM = tc.prior
			body := regReqWithCap(t, tc.regType, tc.capHex)[3:]
			body[0] = tc.regType // ngKSI 0 = the stored context, TSC native
			err := h.HandleNASMessage(context.Background(), ue,
				buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, body))
			if err != nil {
				t.Logf("update accept path returned %v (capability is applied before it)", err)
			}
			if ue.Capability5GMM == nil {
				t.Fatal("Capability5GMM nil")
			}
			if got := ue.Capability5GMM.RawHex(); got != tc.wantHex {
				t.Errorf("RawHex = %s, want %s", got, tc.wantHex)
			}
		})
	}
}

// TestHandleNASMessage_SecurityModeComplete_RetransmittedCapability reaches
// applyRetransmittedRegistrationRequest through the public entry point with a
// Security Mode Complete whose NAS message container carries the complete
// Registration Request. Ref: TS 24.501 §4.4.6, §5.4.2.3
func TestHandleNASMessage_SecurityModeComplete_RetransmittedCapability(t *testing.T) {
	smc := func(container []byte) []byte {
		b := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeSecurityModeComplete),
			0x71, byte(len(container) >> 8), byte(len(container))}
		return append(b, container...)
	}
	tests := []struct {
		name    string
		capHex  string
		wantHex string
	}{
		{"enabled UE bits stored", mmCapEnabledHex, mmCapEnabledHex},
		{"default UE single octet", "00", "00"},
		{"IE absent stays nil", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, ue := newEntryHandler(t)
			ue.SetRegStage(amfctx.RegStageSMC) // a SECURITY MODE COMMAND is outstanding
			err := h.HandleNASMessage(context.Background(), ue,
				buildULSecuredPDU(t, ue, nas.MsgTypeSecurityModeComplete, smc(regReqWithCap(t, 1, tc.capHex))[3:]))
			if !errors.Is(err, errStubUDMFail) {
				t.Fatalf("err = %v, want it to wrap the stub UDM failure (Phase3 reached)", err)
			}
			if tc.wantHex == "" {
				if ue.Capability5GMM != nil {
					t.Fatalf("Capability5GMM = %x, want nil", ue.Capability5GMM.Raw)
				}
				return
			}
			if ue.Capability5GMM == nil || ue.Capability5GMM.RawHex() != tc.wantHex {
				t.Fatalf("Capability5GMM = %+v, want %s", ue.Capability5GMM, tc.wantHex)
			}
		})
	}
}
