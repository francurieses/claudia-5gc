//go:build functional

// service_area_restriction_steps_test.go -- in-process godog steps for
// service_area_restriction.feature: Service area list IE in REGISTRATION ACCEPT
// (TS 24.501 §5.3.5) and SERVICE REJECT #28 enforcement (§5.6.1.5). Uses a
// private world (own UE context manager, fake PCF/UDM and N2 sender) so it does
// not depend on the shared sbiW seeding.
package features_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/cucumber/godog"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

type sarUDM struct{}

func (sarUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (sarUDM) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	return &procedures.UDMAMSubscription{AllowedNSSAI: []amfctx.SNSSAISubscribed{{SST: 1}}}, nil
}
func (sarUDM) DeregisterUECM(context.Context, string) error { return nil }

type sarPCF struct {
	sar *amfctx.ServiceAreaRestriction
}

func (p sarPCF) CreateAMPolicyAssociation(context.Context, string, string, string, string) (
	string, int, *amfctx.ServiceAreaRestriction, error) {
	return "ampol-1", 0, p.sar, nil
}
func (sarPCF) DeleteAMPolicyAssociation(context.Context, string) error { return nil }

type sarSender struct {
	dl  [][]byte
	ics [][]byte
}

func (s *sarSender) SendDownlinkNASTransport(_ *amfctx.UEContext, pdu []byte) error {
	s.dl = append(s.dl, pdu)
	return nil
}
func (s *sarSender) SendInitialContextSetupRequest(_ *amfctx.UEContext, n []byte, _ [32]byte, _, _ byte,
	_, _ uint16, _ []ngap.PDUSessionSetupItemCxtReq) error {
	s.ics = append(s.ics, n)
	return nil
}
func (*sarSender) SendPDUSessionResourceSetupRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (*sarSender) SendPDUSessionResourceReleaseCommand(*amfctx.UEContext, uint8, []byte) error {
	return nil
}
func (*sarSender) SendPDUSessionResourceModifyRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (*sarSender) SendUEContextReleaseCommandForUE(*amfctx.UEContext, int, int64) error { return nil }

type sarWorld struct {
	sar    *amfctx.ServiceAreaRestriction
	ue     *amfctx.UEContext
	sender *sarSender
	ra     *nas.RegistrationAccept
	regErr error
	preDL  uint32
}

var sarW = &sarWorld{}

func (w *sarWorld) newUE() (*amfctx.Manager, *procedures.RegistrationHandler) {
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01", AMFRegionID: 2, AMFID: 1}, nil, nil, nil)
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, "imsi-001010000000001")
	mgr.AssignGUTI(context.Background(), ue)
	ue.RANUENGAPId, ue.GNBAddr, ue.CMState = 1, "10.0.0.1:38412", amfctx.CMIdle
	ue.RawUESecCap = []byte{0xe0, 0x60, 0x00, 0x00}
	ue.UESecCapEA[2], ue.UESecCapIA[2] = true, true
	ue.SecurityCtx = amfctx.SecurityContext{Active: true, NGKSI: 1, IntegrityAlgID: 2, CipheringAlgID: 2,
		KNASint: bytes.Repeat([]byte{0x11}, 16), KNASenc: bytes.Repeat([]byte{0x22}, 16),
		KAMF: bytes.Repeat([]byte{0x33}, 32)}
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	w.ue = ue
	reg := procedures.NewRegistrationHandler(mgr, nil, sarUDM{}, nil, "nf", "001", "01", lg)
	reg.WithAMPolicy(sarPCF{sar: w.sar})
	return mgr, reg
}

func parseTAC(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	return uint32(v), err
}

func (w *sarWorld) allowsOnly(tac string) error {
	w.sar = &amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS", AllowedTACs: []string{tac}}
	return nil
}
func (w *sarWorld) nonAllowed(tac string) error {
	w.sar = &amfctx.ServiceAreaRestriction{RestrictionType: "NOT_ALLOWED_AREAS", NotAllowedTACs: []string{tac}}
	return nil
}
func (w *sarWorld) noSAR() error { w.sar = nil; return nil }

func (w *sarWorld) register(tac string) error {
	t, err := parseTAC(tac)
	if err != nil {
		return err
	}
	_, reg := w.newUE()
	w.ue.TAI = amfctx.TAI{MCC: "001", MNC: "01", TAC: t}
	w.ra, w.regErr = reg.Phase3_ProcessSMCComplete(context.Background(), w.ue)
	return nil
}
func (w *sarWorld) registerAny() error { return w.register("000005") }

func (w *sarWorld) accepted() error {
	if w.regErr != nil || w.ra == nil {
		return fmt.Errorf("registration not accepted: %v", w.regErr)
	}
	return nil
}

func (w *sarWorld) carriesList(kind, tac string) error {
	if err := w.accepted(); err != nil {
		return err
	}
	l := w.ra.ServiceAreaList
	if l == nil || len(l.Partial) != 1 {
		return fmt.Errorf("Registration Accept has no Service area list: %+v", l)
	}
	t, _ := parseTAC(tac)
	p := l.Partial[0]
	if p.NonAllowed != (kind == "non-allowed") || len(p.TACs) != 1 || p.TACs[0] != t {
		return fmt.Errorf("Service area list = %+v, want %s area TAC %s", p, kind, tac)
	}
	return nil
}
func (w *sarWorld) carriesNoList() error {
	if err := w.accepted(); err != nil {
		return err
	}
	if w.ra.ServiceAreaList != nil {
		return fmt.Errorf("unexpected Service area list %+v", w.ra.ServiceAreaList)
	}
	return nil
}

func (w *sarWorld) serviceRequest(tac, svc string) error {
	st, ok := ntsrServiceTypes[svc]
	if !ok {
		return fmt.Errorf("unknown service type %q", svc)
	}
	t, err := parseTAC(tac)
	if err != nil {
		return err
	}
	mgr, reg := w.newUE()
	_ = mgr
	ue := w.ue
	ue.TAI = amfctx.TAI{MCC: "001", MNC: "01", TAC: t}
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.ServAreaRes = w.sar
	w.sender = &sarSender{}
	w.preDL = ue.SecurityCtx.DownlinkCount
	plain := buildServiceRequest(st, ue.GUTI.TMSI, nil)
	pdu, err := protectUL(ue, plain)
	if err != nil {
		return err
	}
	h := nasmsg.NewHandler(w.sender, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return h.HandleNASMessage(context.Background(), ue, pdu)
}

func (w *sarWorld) serviceReject(cause int) error {
	if len(w.sender.dl) != 1 {
		return fmt.Errorf("DL NAS messages sent = %d, want 1 SERVICE REJECT", len(w.sender.dl))
	}
	pdu := w.sender.dl[0]
	ue := w.ue
	if len(pdu) < 8 || pdu[1] != byte(nas.SecurityHeaderIntegrityProtectedAndCiphered) {
		return fmt.Errorf("SERVICE REJECT not integrity protected and ciphered: %x", pdu)
	}
	if ok, err := nia.Verify(ue.SecurityCtx.KNASint, w.preDL, 0x01, 0x01, pdu[6:], pdu[2:6]); err != nil || !ok {
		return fmt.Errorf("SERVICE REJECT MAC invalid (ok=%v err=%v)", ok, err)
	}
	inner, err := nea.NEA2(ue.SecurityCtx.KNASenc, w.preDL, 0x01, 0x01, pdu[7:])
	if err != nil {
		return err
	}
	if len(inner) < 4 || nas.MessageType(inner[2]) != nas.MsgTypeServiceReject || int(inner[3]) != cause {
		return fmt.Errorf("inner = %x, want SERVICE REJECT cause %d", inner, cause)
	}
	return nil
}
func (w *sarWorld) noICS() error {
	if len(w.sender.ics) != 0 {
		return fmt.Errorf("%d Initial Context Setup Request(s) sent", len(w.sender.ics))
	}
	return nil
}
func (w *sarWorld) icsServiceAccept() error {
	if len(w.sender.ics) != 1 || len(w.sender.dl) != 0 {
		return fmt.Errorf("ics=%d dl=%d, want one ICS with the Service Accept and no reject", len(w.sender.ics), len(w.sender.dl))
	}
	return nil
}

func initServiceAreaRestrictionSteps(sc *godog.ScenarioContext) {
	w := sarW
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		*w = sarWorld{}
		return ctx, nil
	})
	sc.Step(`^the PCF grants access to TAC "([0-9a-fA-F]{6})" for the UE$`, w.allowsOnly)
	sc.Step(`^the PCF only allows TAC "([0-9a-fA-F]{6})" for the UE$`, w.allowsOnly)
	sc.Step(`^the PCF marks TAC "([0-9a-fA-F]{6})" as a non-allowed area for the UE$`, w.nonAllowed)
	sc.Step(`^the PCF returns no service area restriction for the UE$`, w.noSAR)
	sc.Step(`^the UE sends a Registration Request from TAC "([0-9a-fA-F]{6})"$`, w.register)
	sc.Step(`^the UE sends a Registration Request from any TAC$`, w.registerAny)
	sc.Step(`^the AMF accepts the registration$`, w.accepted)
	sc.Step(`^the Registration Accept carries a Service area list of the (allowed|non-allowed) area with TAC "([0-9a-fA-F]{6})"$`, w.carriesList)
	sc.Step(`^the Registration Accept carries no Service area list$`, w.carriesNoList)
	sc.Step(`^a registered UE in TAC "([0-9a-fA-F]{6})" sends a Service Request with service type "([^"]+)"$`, w.serviceRequest)
	sc.Step(`^the AMF sends a Service Reject with 5GMM cause (\d+)$`, w.serviceReject)
	sc.Step(`^the AMF sends no Initial Context Setup Request$`, w.noICS)
	sc.Step(`^the AMF sends an Initial Context Setup Request carrying the Service Accept$`, w.icsServiceAccept)
}
