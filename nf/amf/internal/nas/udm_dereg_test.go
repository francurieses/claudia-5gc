package nasmsg

// udm_dereg_test.go - AMF-037 slice A: UDM-triggered network-initiated
// de-registration (reason/CM-state dispatch, SM/PCF/SDM release, no UECM DELETE,
// T3522 abort, rel17 local-abort guard).
// Ref: TS 23.502 §4.2.2.3.3, §4.11.1.3.2 step 15, §4.11.1.5.3 step 13;
// TS 24.501 §5.5.2.3.1, §5.5.2.3.5 a); TS 29.503 §5.3.2.3

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// udmDeregUDM is the UDM: counts SDM unsubscribes and UECM deletes.
type udmDeregUDM struct {
	mu     sync.Mutex
	unsub  []string
	uecmDL int
}

func (u *udmDeregUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (u *udmDeregUDM) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	return &procedures.UDMAMSubscription{}, nil
}
func (u *udmDeregUDM) DeregisterUECM(context.Context, string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.uecmDL++
	return nil
}
func (u *udmDeregUDM) SubscribeAMData(context.Context, string) (string, error) { return "sub", nil }
func (u *udmDeregUDM) UnsubscribeSDM(_ context.Context, _, id string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.unsub = append(u.unsub, id)
	return nil
}

// udmDeregPCF implements the AM policy and UE policy delete calls.
type udmDeregPCF struct {
	mu          sync.Mutex
	amDel, ueDl []string
}

func (p *udmDeregPCF) CreateUEPolicyAssociation(context.Context, string, string) (string, []byte, error) {
	return "", nil, nil
}
func (p *udmDeregPCF) DeleteUEPolicyAssociation(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ueDl = append(p.ueDl, id)
	return nil
}
func (p *udmDeregPCF) CreateAMPolicyAssociation(context.Context, string, string, string, string) (string, int, *amfctx.ServiceAreaRestriction, error) {
	return "", 0, nil, nil
}
func (p *udmDeregPCF) DeleteAMPolicyAssociation(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.amDel = append(p.amDel, id)
	return nil
}

// udmDeregSender records SM deletes and N2 releases; failNAS breaks the DL send.
type udmDeregSender struct {
	recSender
	mu       sync.Mutex
	smDel    []string
	releases []int64
	failNAS  bool
}

func (s *udmDeregSender) SendDownlinkNASTransport(ue *amfctx.UEContext, pdu []byte) error {
	if s.failNAS {
		return errors.New("no N2 association")
	}
	return s.recSender.SendDownlinkNASTransport(ue, pdu)
}
func (s *udmDeregSender) DeleteSMContext(_ context.Context, ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smDel = append(s.smDel, ref)
	return nil
}
func (s *udmDeregSender) SendUEContextReleaseCommandForUE(_ *amfctx.UEContext, _ int, cause int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releases = append(s.releases, cause)
	return nil
}

type udmDeregEnv struct {
	h   *Handler
	s   *udmDeregSender
	udm *udmDeregUDM
	pcf *udmDeregPCF
	clk *fakeClock
	mgr *amfctx.Manager
	ue  *amfctx.UEContext
}

func newUDMDeregEnv(t *testing.T, spec bool, cm amfctx.CMState) *udmDeregEnv {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &udmDeregEnv{udm: &udmDeregUDM{}, pcf: &udmDeregPCF{}, s: &udmDeregSender{}, clk: &fakeClock{}}
	e.mgr = amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	reg := procedures.NewRegistrationHandler(e.mgr, nil, e.udm, nil, "test-amf", "001", "01", logger)
	reg.WithPCF(e.pcf)
	reg.WithAMPolicy(e.pcf)
	reg.WithNSSAASpecLiteral(spec)
	e.h = NewHandler(e.s, reg, logger)
	e.h.SetTimerSchedulerForTest(e.clk.after)
	ue := newTestUE(t)
	// re-home the UE on this manager so RemoveUEContext acts on it
	e.ue = e.mgr.AllocateUEContext(1)
	e.mgr.SetSUPI(e.ue, ue.SUPI)
	e.ue.RANUENGAPId = 1
	e.ue.SecurityCtx = ue.SecurityCtx
	e.ue.State = amfctx.GMMRegistered
	e.ue.SetCMState(cm)
	e.ue.PDUSessions = map[uint8]*amfctx.PDUSession{1: {PDUSessionID: 1, SMFInstanceID: "smf-ref-1"}}
	e.ue.AMPolicyAssocID = "am-1"
	e.ue.PolicyAssociationID = "ue-1"
	e.ue.SetSDMSubscriptionID("sdm-1")
	return e
}

func (e *udmDeregEnv) notify(t *testing.T, reason, access string) bool {
	t.Helper()
	handled := e.h.HandleUDMDeregistration(context.Background(), e.ue, reason, access)
	barrier(e.ue)
	return handled
}

func (e *udmDeregEnv) gone() bool { _, ok := e.mgr.GetBySUPI(e.ue.SUPI); return !ok }

// assertReleased checks SM released once, both PCF deletes, one SDM unsubscribe
// and no UECM DELETE.
func (e *udmDeregEnv) assertReleased(t *testing.T, sm bool) {
	t.Helper()
	if sm && len(e.s.smDel) != 1 || !sm && len(e.s.smDel) != 0 {
		t.Errorf("SM releases = %v, want release=%v", e.s.smDel, sm)
	}
	if len(e.pcf.amDel) != 1 || len(e.pcf.ueDl) != 1 {
		t.Errorf("PCF deletes am=%v ue=%v, want one each", e.pcf.amDel, e.pcf.ueDl)
	}
	if len(e.udm.unsub) != 1 {
		t.Errorf("SDM unsubscribes = %v, want exactly one", e.udm.unsub)
	}
	if e.udm.uecmDL != 0 {
		t.Errorf("UECM DELETE sent %d times, want 0", e.udm.uecmDL)
	}
}

func (e *udmDeregEnv) onlyDereg(t *testing.T, want bool) *nas.DeregistrationRequestNW {
	t.Helper()
	d := e.s.ofType(t, e.ue, nas.MsgTypeDeregistrationRequestNW)
	if len(d) != 1 {
		t.Fatalf("%d DEREGISTRATION REQUESTs, want 1", len(d))
	}
	req, err := nas.DecodeDeregistrationRequestNW(d[0].body)
	if err != nil {
		t.Fatal(err)
	}
	if req.ReregistrationRequired != want || req.AccessType != 1 || req.Cause5GMM != 0 {
		t.Errorf("request = %+v, want rereg=%v access=3GPP no cause", req, want)
	}
	return req
}

// (1) CM-CONNECTED SUBSCRIPTION_WITHDRAWN: Dereg Request (re-reg bit 0, 3GPP, no
// 5GMM cause), SM/PCF/SDM released at once, N2 release on ACCEPT, no UECM DELETE.
func TestUDMDeregConnectedSubscriptionWithdrawn(t *testing.T) {
	e := newUDMDeregEnv(t, true, amfctx.CMConnected)
	if !e.notify(t, DeregReasonSubscriptionWithdrawn, "3GPP_ACCESS") {
		t.Fatal("not handled")
	}
	e.onlyDereg(t, false)
	if e.ue.State != amfctx.GMMDeregisteredInitiated {
		t.Fatalf("state = %v", e.ue.State)
	}
	e.assertReleased(t, true)
	if len(e.s.releases) != 0 {
		t.Fatal("N2 released before the ACCEPT")
	}
	if err := e.h.handleNWDeregistrationAccept(context.Background(), e.ue); err != nil {
		t.Fatal(err)
	}
	if len(e.s.releases) != 1 || e.s.releases[0] != ngapCauseNasDeregister || !e.ue.PendingRemoval {
		t.Fatalf("releases = %v pendingRemoval=%v, want one nas/deregister", e.s.releases, e.ue.PendingRemoval)
	}
	e.assertReleased(t, true) // idempotent on ACCEPT
}

// (2) REREGISTRATION_REQUIRED: re-registration required bit set.
func TestUDMDeregReregistrationRequired(t *testing.T) {
	e := newUDMDeregEnv(t, true, amfctx.CMConnected)
	e.notify(t, DeregReasonReregistrationRequired, "")
	e.onlyDereg(t, true)
	e.assertReleased(t, true)
}

// (3) CM-IDLE: implicit, no NAS, no N2, everything released, context gone.
func TestUDMDeregIdleImplicit(t *testing.T) {
	for _, reason := range []string{DeregReasonSubscriptionWithdrawn, DeregReasonReregistrationRequired} {
		e := newUDMDeregEnv(t, true, amfctx.CMIdle)
		e.notify(t, reason, "")
		if e.s.n() != 0 || len(e.s.releases) != 0 {
			t.Errorf("%s: NAS=%d N2 releases=%d, want none", reason, e.s.n(), len(e.s.releases))
		}
		e.assertReleased(t, true)
		if !e.gone() || e.ue.State != amfctx.GMMDeregistered {
			t.Errorf("%s: context not removed", reason)
		}
	}
}

// (4) 5GS_TO_EPS_MOBILITY*: SM kept, PCF + SDM released, silent, context gone.
func TestUDMDeregEPSMobilityKeepsSM(t *testing.T) {
	for _, reason := range []string{DeregReasonEPSMobility, DeregReasonEPSMobilityUEInitReg} {
		for _, cm := range []amfctx.CMState{amfctx.CMIdle, amfctx.CMConnected} {
			e := newUDMDeregEnv(t, true, cm)
			e.notify(t, reason, "")
			wantRel := 0
			if cm == amfctx.CMConnected {
				wantRel = 1 // §4.2.2.3.3 step 7: no orphaned gNB UE context
			}
			if e.s.n() != 0 || len(e.s.releases) != wantRel {
				t.Errorf("%s/%v: NAS=%d N2 releases=%d, want no NAS and %d release(s)", reason, cm, e.s.n(), len(e.s.releases), wantRel)
			}
			if wantRel == 1 && (e.s.releases[0] != ngapCauseNasDeregister || !e.ue.PendingRemoval) {
				t.Errorf("%s/%v: release cause %v pendingRemoval=%v", reason, cm, e.s.releases, e.ue.PendingRemoval)
			}
			e.assertReleased(t, false)
			if !e.gone() {
				t.Errorf("%s/%v: context not removed", reason, cm)
			}
		}
	}
}

// (5) rel19: T3522 retransmits 4 times, the 5th expiry aborts: N2 release, no UECM DELETE.
func TestUDMDeregT3522Abort(t *testing.T) {
	e := newUDMDeregEnv(t, true, amfctx.CMConnected)
	e.notify(t, DeregReasonSubscriptionWithdrawn, "")
	for i := 0; i < NWDeregT3522MaxRetransmissions; i++ {
		fire(e.ue, e.clk.last())
	}
	if n := len(e.s.ofType(t, e.ue, nas.MsgTypeDeregistrationRequestNW)); n != 1+NWDeregT3522MaxRetransmissions {
		t.Fatalf("%d DEREGISTRATION REQUESTs, want %d", n, 1+NWDeregT3522MaxRetransmissions)
	}
	if len(e.s.releases) != 0 {
		t.Fatal("aborted too early")
	}
	fire(e.ue, e.clk.last())
	if len(e.s.releases) != 1 || e.ue.State != amfctx.GMMDeregistered {
		t.Fatalf("releases=%v state=%v", e.s.releases, e.ue.State)
	}
	e.assertReleased(t, true)
}

// (5b) rel17: no retransmission (wire identity), one 5 x T3522 guard aborts locally.
func TestUDMDeregRel17LocalAbortGuard(t *testing.T) {
	e := newUDMDeregEnv(t, false, amfctx.CMConnected)
	e.notify(t, DeregReasonSubscriptionWithdrawn, "")
	if e.clk.count() != 1 || e.clk.last().d != (NWDeregT3522MaxRetransmissions+1)*NWDeregT3522Duration {
		t.Fatalf("timers = %d, want one guard of 5 x T3522", e.clk.count())
	}
	e.onlyDereg(t, false)
	fire(e.ue, e.clk.last())
	if n := len(e.s.ofType(t, e.ue, nas.MsgTypeDeregistrationRequestNW)); n != 1 {
		t.Fatalf("%d DEREGISTRATION REQUESTs, want 1 (no retransmission)", n)
	}
	if len(e.s.releases) != 1 || e.s.releases[0] != ngapCauseNasDeregister {
		t.Fatalf("releases = %v, want one nas/deregister", e.s.releases)
	}
	e.assertReleased(t, true)
}

// (6) NON_3GPP_ACCESS: handled, nothing happens.
func TestUDMDeregNon3GPPNoOp(t *testing.T) {
	e := newUDMDeregEnv(t, true, amfctx.CMConnected)
	if !e.notify(t, DeregReasonSubscriptionWithdrawn, "NON_3GPP_ACCESS") {
		t.Fatal("must be handled (204 no-op)")
	}
	if e.s.n() != 0 || len(e.s.smDel)+len(e.pcf.amDel)+len(e.udm.unsub) != 0 || e.gone() || e.ue.State != amfctx.GMMRegistered {
		t.Fatal("NON_3GPP_ACCESS must be a no-op")
	}
}

// Other reasons are not handled here (legacy removal stays with the caller).
func TestUDMDeregOtherReasonsNotHandled(t *testing.T) {
	for _, r := range []string{"UE_INITIAL_REGISTRATION", "UE_REGISTRATION_AREA_CHANGE", "OPERATOR_DETERMINED_BARRING"} {
		e := newUDMDeregEnv(t, true, amfctx.CMIdle)
		if e.notify(t, r, "") {
			t.Errorf("%s handled, want legacy path", r)
		}
		if e.gone() || e.s.n() != 0 {
			t.Errorf("%s: state changed", r)
		}
	}
}

// DL send failure: implicit teardown + N2 release attempt, no UECM DELETE.
func TestUDMDeregSendFailureFallsBack(t *testing.T) {
	e := newUDMDeregEnv(t, true, amfctx.CMConnected)
	e.s.failNAS = true
	e.notify(t, DeregReasonSubscriptionWithdrawn, "")
	e.assertReleased(t, true)
	if !e.gone() || len(e.s.releases) != 1 {
		t.Fatalf("gone=%v releases=%v", e.gone(), e.s.releases)
	}
	if e.ue.DeregByUDM() || e.clk.count() != 0 {
		t.Fatal("no trigger flag/timer may remain after the fallback")
	}
}

// The UE-/operator-initiated path (no UDM trigger) still deletes the UECM registration.
func TestNWDeregWithoutUDMTriggerDeletesUECM(t *testing.T) {
	e := newUDMDeregEnv(t, true, amfctx.CMConnected)
	e.h.completeNWDeregistration(context.Background(), e.ue, e.h.logger)
	if e.udm.uecmDL != 1 {
		t.Fatalf("UECM DELETE = %d, want 1", e.udm.uecmDL)
	}
}

// A second notification on a UE already PendingRemoval / DEREGISTERED is ignored:
// no second NAS, no second release, no second SM/PCF/SDM release.
func TestUDMDeregSecondNotificationIgnored(t *testing.T) {
	for _, mode := range []string{"pendingRemoval", "deregistered", "afterAccept"} {
		e := newUDMDeregEnv(t, true, amfctx.CMConnected)
		switch mode {
		case "pendingRemoval":
			e.ue.Lock()
			e.ue.PendingRemoval = true
			e.ue.Unlock()
		case "deregistered":
			e.ue.TransitionTo(amfctx.GMMDeregistered)
		case "afterAccept":
			e.notify(t, DeregReasonSubscriptionWithdrawn, "")
			if err := e.h.handleNWDeregistrationAccept(context.Background(), e.ue); err != nil {
				t.Fatal(err)
			}
		}
		nas0, rel0, sm0, am0, un0 := e.s.n(), len(e.s.releases), len(e.s.smDel), len(e.pcf.amDel), len(e.udm.unsub)
		if !e.notify(t, DeregReasonReregistrationRequired, "") {
			t.Fatalf("%s: not handled", mode)
		}
		if e.s.n() != nas0 || len(e.s.releases) != rel0 || len(e.s.smDel) != sm0 ||
			len(e.pcf.amDel) != am0 || len(e.udm.unsub) != un0 {
			t.Errorf("%s: second notification acted (NAS %d->%d, releases %d->%d)", mode, nas0, e.s.n(), rel0, len(e.s.releases))
		}
	}
}

// A REGISTRATION REQUEST supersedes the UDM-triggered de-registration: the flag
// is cleared and T3522 stopped. Ref: TS 24.501 §5.5.2.3.5 d)
func TestUDMDeregRegistrationRequestClearsFlag(t *testing.T) {
	e := newUDMDeregEnv(t, true, amfctx.CMConnected)
	e.notify(t, DeregReasonSubscriptionWithdrawn, "")
	if !e.ue.DeregByUDM() || e.clk.liveOf(NWDeregT3522Duration) != 1 {
		t.Fatalf("precondition: flag=%v live T3522=%d", e.ue.DeregByUDM(), e.clk.liveOf(NWDeregT3522Duration))
	}
	body := regReqWithCap(t, 1, "")[3:]
	_ = e.h.HandleNASMessage(context.Background(), e.ue,
		buildULSecuredPDU(t, e.ue, nas.MsgTypeRegistrationRequest, body))
	if e.ue.DeregByUDM() {
		t.Error("UDM flag still set after REGISTRATION REQUEST")
	}
	if e.clk.liveOf(NWDeregT3522Duration) != 0 {
		t.Error("T3522 still running after REGISTRATION REQUEST")
	}
}

// rel17: the guard timer is cancelled by the ACCEPT; firing it later must not
// tear down a second time.
func TestUDMDeregRel17GuardStoppedOnAccept(t *testing.T) {
	e := newUDMDeregEnv(t, false, amfctx.CMConnected)
	e.notify(t, DeregReasonSubscriptionWithdrawn, "")
	guard := e.clk.last()
	if err := e.h.handleNWDeregistrationAccept(context.Background(), e.ue); err != nil {
		t.Fatal(err)
	}
	if !guard.stopped.Load() {
		t.Fatal("guard timer not cancelled by DEREGISTRATION ACCEPT")
	}
	fire(e.ue, guard) // stale callback: generation no longer current
	if len(e.s.releases) != 1 {
		t.Fatalf("releases = %v, want exactly one", e.s.releases)
	}
	e.assertReleased(t, true)
}

// rel17 joined path: the UE is already DEREGISTERED-INITIATED (no T3522 under
// rel17): the guard is armed so the teardown completes locally.
func TestUDMDeregJoinedRel17ArmsGuard(t *testing.T) {
	e := newUDMDeregEnv(t, false, amfctx.CMConnected)
	e.ue.TransitionTo(amfctx.GMMDeregisteredInitiated)
	e.notify(t, DeregReasonSubscriptionWithdrawn, "")
	if e.s.n() != 0 {
		t.Fatal("joined path must not send a second DEREGISTRATION REQUEST")
	}
	if e.clk.count() != 1 || e.clk.last().d != (NWDeregT3522MaxRetransmissions+1)*NWDeregT3522Duration {
		t.Fatalf("timers = %d, want one 5 x T3522 guard", e.clk.count())
	}
	e.assertReleased(t, true)
	fire(e.ue, e.clk.last())
	if len(e.s.releases) != 1 || e.ue.State != amfctx.GMMDeregistered {
		t.Fatalf("releases=%v state=%v, want local abort", e.s.releases, e.ue.State)
	}
}
