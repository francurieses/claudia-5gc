package nasmsg

// reg_timer_test.go - T3550/T3560/T3570 supervision, the pending-procedure gate,
// duplicate REGISTRATION REQUEST handling and the REGISTRATION / AUTHENTICATION
// REJECT outcomes (AUD-registration-08, -09, -13). A fake clock stands in for
// the timers: no test sleeps.
//
// Ref: TS 24.501 §5.4.1.3.7, §5.4.2.7, §5.4.3.6, §5.5.1.2.8, §5.4.1.3.5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/timercfg"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// verifyDL plays the UE side of a downlink protected NAS PDU: it checks the NIA2
// MAC against the sequence number (NAS COUNT < 256 in these tests), deciphers when
// the header says so and returns the plain inner message and the sequence number.
func verifyDL(t *testing.T, ue *amfctx.UEContext, pdu []byte) (inner []byte, sqn byte) {
	t.Helper()
	if len(pdu) < 7 {
		t.Fatalf("short protected PDU %x", pdu)
	}
	sqn = pdu[6]
	macInput := append([]byte{sqn}, pdu[7:]...)
	mac, err := nia.NIA2(ue.SecurityCtx.KNASint, uint32(sqn), 0x01, 0x01, macInput)
	if err != nil || !bytes.Equal(mac, pdu[2:6]) {
		t.Fatalf("DL MAC does not verify for NAS COUNT %d (err %v)", sqn, err)
	}
	inner = pdu[7:]
	if nas.SecurityHeaderType(pdu[1]&0x0f) == nas.SecurityHeaderIntegrityProtectedAndCiphered &&
		ue.SecurityCtx.CipheringAlgID != 0 {
		if inner, err = nea.NEA2(ue.SecurityCtx.KNASenc, uint32(sqn), 0x01, 0x01, inner); err != nil {
			t.Fatal(err)
		}
	}
	return inner, sqn
}

// regTmrSender counts UE CONTEXT RELEASE COMMANDs on top of regAudSender.
type regTmrSender struct {
	regAudSender
	released int
}

func (s *regTmrSender) SendUEContextReleaseCommandForUE(*amfctx.UEContext, int, int64) error {
	s.released++
	return nil
}

// regTmrAUSF answers InitiateAuth / ConfirmAuth with configurable failures.
type regTmrAUSF struct {
	initErr    error
	confirmErr error
	inits      int
}

func (a *regTmrAUSF) InitiateAuth(context.Context, string, string) (*procedures.AUSFInitResponse, error) {
	a.inits++
	if a.initErr != nil {
		return nil, a.initErr
	}
	return &procedures.AUSFInitResponse{AuthCtxID: "auth-1", SUPI: "imsi-001010000000001"}, nil
}
func (a *regTmrAUSF) ResyncAuth(context.Context, string, string, [16]byte, []byte) (*procedures.AUSFInitResponse, error) {
	return &procedures.AUSFInitResponse{AuthCtxID: "auth-2"}, nil
}
func (a *regTmrAUSF) ConfirmAuth(context.Context, string, string) (*procedures.AUSFConfirmResponse, error) {
	if a.confirmErr != nil {
		return nil, a.confirmErr
	}
	return &procedures.AUSFConfirmResponse{SUPI: "imsi-001010000000001", KAUSF: bytes.Repeat([]byte{0x44}, 32)}, nil
}

type regTmrUDMFail struct{ regAudUDM }

func (regTmrUDMFail) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	return nil, errors.New("udm down")
}

// regTmrEnv is a Handler over a fresh (not yet authenticated) UE context and a
// fake clock.
type regTmrEnv struct {
	h    *Handler
	mgr  *amfctx.Manager
	ue   *amfctx.UEContext
	s    *regTmrSender
	clk  *fakeClock
	ausf *regTmrAUSF
}

func newRegTmrEnv(t *testing.T, udm procedures.UDMClient) *regTmrEnv {
	t.Helper()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01", AMFRegionID: 2, AMFID: 1}, nil, nil, nil)
	ausf := &regTmrAUSF{}
	reg := procedures.NewRegistrationHandler(mgr, ausf, udm, nil, "nf", "001", "01", lg)
	s := &regTmrSender{}
	h := NewHandler(s, reg, lg)
	clk := &fakeClock{}
	h.SetTimerSchedulerForTest(clk.after)
	ue := mgr.AllocateUEContext(1)
	ue.RANUENGAPId = 1
	ue.GNBAddr = "10.0.0.1:38412"
	ue.CMState = amfctx.CMConnected
	return &regTmrEnv{h: h, mgr: mgr, ue: ue, s: s, clk: clk, ausf: ausf}
}

// send delivers a plain UL NAS PDU and fails the test on a handler error.
func (e *regTmrEnv) send(t *testing.T, pdu []byte) {
	t.Helper()
	if err := e.h.HandleNASMessage(context.Background(), e.ue, pdu); err != nil {
		t.Fatalf("HandleNASMessage(%x): %v", pdu[:3], err)
	}
}

// regTmrSUCIRegRequest is an initial REGISTRATION REQUEST with a SUCI identity
// and UE security capability EA0/EA2 + IA0/IA2.
func regTmrSUCIRegRequest() []byte {
	suci := []byte{0x01, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
	b := []byte{0x7e, 0x00, 0x41, 0x71, 0x00, byte(len(suci))}
	b = append(b, suci...)
	return append(b, 0x2e, 0x02, 0xa0, 0xa0)
}

// regTmrGUTIRegRequest carries an unknown 5G-GUTI: the AMF asks for the SUCI.
func regTmrGUTIRegRequest() []byte {
	return append(regReqWithCap2(1), 0x2e, 0x02, 0xa0, 0xa0)
}

func regReqWithCap2(regType byte) []byte {
	return []byte{0x7e, 0x00, 0x41, 0x70 | regType, 0x00, 0x0b, 0xf2,
		0x00, 0xf1, 0x10, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}
}

func regTmrIdentityResponse() []byte {
	suci := []byte{0x01, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
	b := []byte{0x7e, 0x00, byte(nas.MsgTypeIdentityResponse), 0x00, byte(len(suci))}
	return append(b, suci...)
}

func regTmrAuthResponse() []byte {
	b := []byte{0x7e, 0x00, byte(nas.MsgTypeAuthenticationResponse), 0x2d, 0x10}
	return append(b, bytes.Repeat([]byte{0x55}, 16)...)
}

// toSMC drives Registration Request -> Authentication Request -> Authentication
// Response -> Security Mode Command and returns the SECURITY MODE COMMAND PDU.
func (e *regTmrEnv) toSMC(t *testing.T) []byte {
	t.Helper()
	e.send(t, regTmrSUCIRegRequest())
	if e.ue.RegStage() != amfctx.RegStageAuth {
		t.Fatalf("stage after REGISTRATION REQUEST = %s, want authentication", e.ue.RegStage())
	}
	e.send(t, regTmrAuthResponse())
	if e.ue.RegStage() != amfctx.RegStageSMC {
		t.Fatalf("stage after AUTHENTICATION RESPONSE = %s, want security-mode", e.ue.RegStage())
	}
	return e.s.dl[len(e.s.dl)-1]
}

// fireLast fires the most recently scheduled timer and waits for its work.
func (e *regTmrEnv) fireLast() { fire(e.ue, e.clk.last()) }

// TestT3560_SMCRetransmittedUnchangedThenAborted: T3560 (6 s default) retransmits
// the SECURITY MODE COMMAND four times, each protected with a fresh NAS COUNT
// (same plain message, different SQN and MAC, all verifying); the fifth expiry
// aborts the procedure and releases the N1 connection. TS 24.501 §5.4.2.7 b),
// §4.4.3.1.
func TestT3560_SMCRetransmittedUnchangedThenAborted(t *testing.T) {
	e := newRegTmrEnv(t, regAudUDM{})
	smc := e.toSMC(t)
	if d := e.clk.last().d; d != 6*time.Second {
		t.Fatalf("T3560 = %v, want the TS 24.501 §10.2 default 6 s", d)
	}
	base := len(e.s.dl)
	wantPlain, prevSQN := verifyDL(t, e.ue, smc)
	prev := smc
	for i := 1; i <= RegProcMaxRetransmissions; i++ {
		e.fireLast()
		if len(e.s.dl) != base+i {
			t.Fatalf("expiry %d: SECURITY MODE COMMAND not retransmitted", i)
		}
		got := e.s.dl[len(e.s.dl)-1]
		plain, sqn := verifyDL(t, e.ue, got)
		if !bytes.Equal(plain, wantPlain) {
			t.Fatalf("expiry %d: retransmission carries a different message", i)
		}
		if sqn != prevSQN+1 || bytes.Equal(got[2:6], prev[2:6]) {
			t.Fatalf("expiry %d: SQN %d (prev %d) / MAC unchanged; want a fresh NAS COUNT", i, sqn, prevSQN)
		}
		prev, prevSQN = got, sqn
		if e.s.released != 0 {
			t.Fatalf("expiry %d: connection released before the fifth expiry", i)
		}
	}
	e.fireLast() // fifth expiry
	if len(e.s.dl) != base+RegProcMaxRetransmissions {
		t.Fatalf("fifth expiry retransmitted again (%d DL messages)", len(e.s.dl))
	}
	if e.s.released != 1 || e.ue.RegStage() != amfctx.RegStageNone {
		t.Fatalf("fifth expiry: released=%d stage=%s; want N1 released and no pending procedure",
			e.s.released, e.ue.RegStage())
	}
}

// TestT3560_StoppedByAnswerAndConfigurable: the answer stops T3560; the duration
// comes from the runtime timer store.
func TestT3560_StoppedByAnswerAndConfigurable(t *testing.T) {
	e := newRegTmrEnv(t, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	e.h.reg.WithTimerStore(timercfg.New(timercfg.Values{T3550Secs: 11, T3560Secs: 9, T3570Secs: 7}))
	e.send(t, regTmrSUCIRegRequest())
	if d := e.clk.last().d; d != 9*time.Second {
		t.Fatalf("T3560 = %v, want the configured 9 s", d)
	}
	e.send(t, regTmrAuthResponse()) // answers the challenge, arms T3560 for the SMC
	if d := e.clk.last().d; d != 9*time.Second {
		t.Fatalf("T3560 (SMC) = %v, want 9 s", d)
	}
	e.send(t, buildULSecuredPDU(t, e.ue, nas.MsgTypeSecurityModeComplete, nil))
	if e.ue.RegStage() != amfctx.RegStageAcceptSent {
		t.Fatalf("stage = %s, want registration-accept", e.ue.RegStage())
	}
	if d := e.clk.last().d; d != 11*time.Second {
		t.Fatalf("T3550 = %v, want the configured 11 s", d)
	}
}

// TestT3570_IdentityRequestRetransmittedThenAborted: T3570 supervises the
// IDENTITY REQUEST. TS 24.501 §5.4.3.6 b).
func TestT3570_IdentityRequestRetransmittedThenAborted(t *testing.T) {
	e := newRegTmrEnv(t, regAudUDM{})
	e.h.reg.WithTimerStore(timercfg.New(timercfg.Values{T3570Secs: 3}))
	e.send(t, regTmrGUTIRegRequest())
	if e.ue.RegStage() != amfctx.RegStageIdentity || len(e.s.dl) != 1 {
		t.Fatalf("stage = %s, DL = %d; want identity, 1 IDENTITY REQUEST", e.ue.RegStage(), len(e.s.dl))
	}
	if d := e.clk.last().d; d != 3*time.Second {
		t.Fatalf("T3570 = %v, want the configured 3 s", d)
	}
	first := e.s.dl[0]
	for i := 1; i <= RegProcMaxRetransmissions; i++ {
		e.fireLast()
		if len(e.s.dl) != 1+i || !bytes.Equal(e.s.dl[i], first) {
			t.Fatalf("expiry %d: IDENTITY REQUEST not retransmitted unchanged", i)
		}
	}
	e.fireLast()
	if e.s.released != 1 || e.ue.RegStage() != amfctx.RegStageNone {
		t.Fatalf("fifth expiry: released=%d stage=%s; want abort + release", e.s.released, e.ue.RegStage())
	}
}

// TestT3570_StoppedByIdentityResponse: the IDENTITY RESPONSE stops T3570 and
// authentication starts (T3560 for the AUTHENTICATION REQUEST).
func TestT3570_StoppedByIdentityResponse(t *testing.T) {
	e := newRegTmrEnv(t, regAudUDM{})
	e.send(t, regTmrGUTIRegRequest())
	idTimer := e.clk.last()
	e.send(t, regTmrIdentityResponse())
	if !idTimer.stopped.Load() {
		t.Error("T3570 still running after the IDENTITY RESPONSE")
	}
	if e.ue.RegStage() != amfctx.RegStageAuth || e.ausf.inits != 1 {
		t.Fatalf("stage = %s, AUSF initiations = %d; want authentication, 1", e.ue.RegStage(), e.ausf.inits)
	}
}

// TestT3550_AcceptRetransmittedThenRegistered: the Accept carries a new 5G-GUTI,
// so the UE is 5GMM-COMMON-PROCEDURE-INITIATED with T3550 running; expiry resends
// the Accept unchanged; the REGISTRATION COMPLETE stops T3550 and registers.
// TS 24.501 §5.5.1.2.4, §5.5.1.2.8 c).
func TestT3550_AcceptRetransmittedThenRegistered(t *testing.T) {
	e := newRegTmrEnv(t, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	e.toSMC(t)
	e.send(t, buildULSecuredPDU(t, e.ue, nas.MsgTypeSecurityModeComplete, nil))
	if len(e.s.ics) != 1 {
		t.Fatalf("ICS = %d, want 1", len(e.s.ics))
	}
	if e.ue.State != amfctx.GMMCommonProcedureInitiated {
		t.Fatalf("state after the Accept = %s, want 5GMM-COMMON-PROCEDURE-INITIATED", e.ue.State)
	}
	accept := e.s.ics[0]
	wantPlain, sqn0 := verifyDL(t, e.ue, accept)
	n := len(e.s.dl)
	e.fireLast()
	if len(e.s.dl) != n+1 {
		t.Fatal("T3550 expiry did not resend the REGISTRATION ACCEPT")
	}
	if plain, sqn := verifyDL(t, e.ue, e.s.dl[n]); !bytes.Equal(plain, wantPlain) || sqn != sqn0+1 {
		t.Fatalf("T3550 retransmission: same message expected with a fresh NAS COUNT (SQN %d -> %d)", sqn0, sqn)
	}
	timer := e.clk.last()
	e.send(t, buildULSecuredPDU(t, e.ue, nas.MsgTypeRegistrationComplete, nil))
	if e.ue.State != amfctx.GMMRegistered || e.ue.RegStage() != amfctx.RegStageNone {
		t.Fatalf("after REGISTRATION COMPLETE: state %s stage %s; want 5GMM-REGISTERED, none", e.ue.State, e.ue.RegStage())
	}
	if !timer.stopped.Load() {
		t.Error("T3550 still running after the REGISTRATION COMPLETE")
	}
}

// TestT3550_FifthExpiryAbortsInitialRegistration: no COMPLETE after four
// retransmissions of the Accept - the initial registration is aborted and the AMF
// enters 5GMM-REGISTERED, context kept, no release. TS 24.501 §5.5.1.2.8 c).
func TestT3550_FifthExpiryAbortsInitialRegistration(t *testing.T) {
	e := newRegTmrEnv(t, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	e.toSMC(t)
	e.send(t, buildULSecuredPDU(t, e.ue, nas.MsgTypeSecurityModeComplete, nil))
	for i := 0; i <= RegProcMaxRetransmissions; i++ {
		e.fireLast()
	}
	if e.ue.State != amfctx.GMMRegistered || e.ue.RegStage() != amfctx.RegStageNone || e.ue.RegTimerRunning() {
		t.Fatalf("state after the aborted initial registration = %s stage %s", e.ue.State, e.ue.RegStage())
	}
	if _, ok := e.mgr.GetByNGAPId(e.ue.AMFUENGAPId); !ok {
		t.Fatal("UE context removed after the aborted initial registration")
	}
	if e.s.released != 0 {
		t.Fatalf("released = %d, want 0 (nothing rejected or released)", e.s.released)
	}
}

// TestT3550_FifthExpiryKeepsRegisteredUE: a mobility update of a registered UE
// whose Accept is never completed returns to 5GMM-REGISTERED, context kept.
func TestT3550_FifthExpiryKeepsRegisteredUE(t *testing.T) {
	h, _, _, ue, s := newRegAudHandler(t, nil, regAudUDM{})
	clk := &fakeClock{}
	h.SetTimerSchedulerForTest(clk.after)
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	body := regReqWithCap(t, 2, "")[3:]
	body[0] = 0x12
	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, body)); err != nil {
		t.Fatal(err)
	}
	if ue.State != amfctx.GMMCommonProcedureInitiated {
		t.Fatalf("state after the update Accept = %s, want COMMON-PROCEDURE-INITIATED", ue.State)
	}
	for i := 0; i <= RegProcMaxRetransmissions; i++ {
		fire(ue, clk.last())
	}
	if ue.State != amfctx.GMMRegistered || len(s.dl) != 1+RegProcMaxRetransmissions {
		t.Fatalf("state %s, DL %d; want 5GMM-REGISTERED after %d Accept retransmissions", ue.State, len(s.dl), RegProcMaxRetransmissions)
	}
}

// TestDuplicateRegistrationRequest: identical retransmission while the procedure
// is in progress is ignored, after the Accept it is answered with the Accept,
// a differing one restarts the procedure. TS 24.501 §5.5.1.2.8 d), e).
func TestDuplicateRegistrationRequest(t *testing.T) {
	t.Run("in progress ignored", func(t *testing.T) {
		e := newRegTmrEnv(t, regAudUDM{})
		e.send(t, regTmrSUCIRegRequest())
		e.send(t, regTmrSUCIRegRequest())
		if e.ausf.inits != 1 || len(e.s.dl) != 1 {
			t.Fatalf("AUSF initiations %d, DL %d; want 1 and 1 (new AV for a duplicate)", e.ausf.inits, len(e.s.dl))
		}
	})
	t.Run("differing restarts", func(t *testing.T) {
		e := newRegTmrEnv(t, regAudUDM{})
		e.send(t, regTmrSUCIRegRequest())
		other := regTmrSUCIRegRequest()
		other[len(other)-1] = 0x20 // different UE security capability
		e.send(t, other)
		if e.ausf.inits != 2 || len(e.s.dl) != 2 {
			t.Fatalf("AUSF initiations %d, DL %d; want 2 and 2", e.ausf.inits, len(e.s.dl))
		}
	})
	t.Run("after accept resent", func(t *testing.T) {
		e := newRegTmrEnv(t, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
		e.toSMC(t)
		e.send(t, buildULSecuredPDU(t, e.ue, nas.MsgTypeSecurityModeComplete, nil))
		want, _ := verifyDL(t, e.ue, e.s.ics[0])
		n := len(e.s.dl)
		// A byte-identical (necessarily unprotected) retransmission can only come
		// on a new N1 connection: once the secure exchange is established every
		// unprotected message is discarded (TS 24.501 §4.4.4.3).
		e.ue.ResetSecureExchange()
		e.send(t, regTmrSUCIRegRequest())
		if len(e.s.dl) != n+1 || len(e.s.ics) != 1 {
			t.Fatal("duplicate REGISTRATION REQUEST after the Accept was not answered with an Accept")
		}
		if got, _ := verifyDL(t, e.ue, e.s.dl[n]); !bytes.Equal(got, want) {
			t.Fatal("resent Accept differs from the first one")
		}
		if e.ausf.inits != 1 {
			t.Fatalf("AUSF initiations = %d, want 1", e.ausf.inits)
		}
	})
}

// TestUnsolicitedMessagesIgnored: UE answers without an outstanding request do
// nothing. TS 24.501 §4.4.4.3 b).
func TestUnsolicitedMessagesIgnored(t *testing.T) {
	e := newRegTmrEnv(t, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	e.send(t, regTmrIdentityResponse())
	e.send(t, regTmrAuthResponse())
	e.send(t, []byte{0x7e, 0x00, byte(nas.MsgTypeRegistrationComplete)})
	if e.ausf.inits != 0 || len(e.s.dl) != 0 || e.ue.State != amfctx.GMMDeregistered || e.clk.count() != 0 {
		t.Fatalf("unsolicited messages acted on: AUSF %d DL %d state %s timers %d",
			e.ausf.inits, len(e.s.dl), e.ue.State, e.clk.count())
	}
}

// TestRejectPaths: terminal failures answer a reject and release the UE.
func TestRejectPaths(t *testing.T) {
	t.Run("AUSF initiation failure -> REGISTRATION REJECT #22 plain", func(t *testing.T) {
		e := newRegTmrEnv(t, regAudUDM{})
		e.ausf.initErr = errors.New("ausf down")
		_ = e.h.HandleNASMessage(context.Background(), e.ue, regTmrSUCIRegRequest())
		if len(e.s.dl) != 1 || e.s.dl[0][1] != 0x00 || e.s.dl[0][2] != byte(nas.MsgTypeRegistrationReject) ||
			e.s.dl[0][3] != byte(nas.CauseCongestion) || e.s.released != 1 {
			t.Fatalf("DL %x released %d; want plain REGISTRATION REJECT #22 and a release", e.s.dl, e.s.released)
		}
	})
	t.Run("UDM failure after SMC -> protected REGISTRATION REJECT", func(t *testing.T) {
		e := newRegTmrEnv(t, regTmrUDMFail{})
		e.toSMC(t)
		_ = e.h.HandleNASMessage(context.Background(), e.ue,
			buildULSecuredPDU(t, e.ue, nas.MsgTypeSecurityModeComplete, nil))
		last := e.s.dl[len(e.s.dl)-1]
		if last[1] != byte(nas.SecurityHeaderIntegrityProtectedAndCiphered) || e.s.released != 1 || len(e.s.ics) != 0 {
			t.Fatalf("last DL %x released %d ICS %d; want a protected reject, a release and no ICS", last, e.s.released, len(e.s.ics))
		}
	})
	t.Run("RES* rejected, SUCI -> AUTHENTICATION REJECT", func(t *testing.T) {
		e := newRegTmrEnv(t, regAudUDM{})
		e.send(t, regTmrSUCIRegRequest())
		e.ausf.confirmErr = errors.Join(errors.New("ausf: authentication rejected"), procedures.ErrAuthenticationRejected)
		e.send(t, regTmrAuthResponse())
		last := e.s.dl[len(e.s.dl)-1]
		if last[2] != byte(nas.MsgTypeAuthenticationReject) || e.s.released != 1 {
			t.Fatalf("last DL %x released %d; want AUTHENTICATION REJECT and a release", last, e.s.released)
		}
	})
	t.Run("RES* rejected, 5G-GUTI -> identification", func(t *testing.T) {
		e := newRegTmrEnv(t, regAudUDM{})
		e.send(t, regTmrSUCIRegRequest())
		e.ue.AuthViaGUTI = true
		e.ausf.confirmErr = errors.Join(errors.New("ausf: authentication rejected"), procedures.ErrAuthenticationRejected)
		e.send(t, regTmrAuthResponse())
		last := e.s.dl[len(e.s.dl)-1]
		if last[2] != byte(nas.MsgTypeIdentityRequest) || e.s.released != 0 || e.ue.RegStage() != amfctx.RegStageIdentity {
			t.Fatalf("last DL %x released %d stage %s; want IDENTITY REQUEST", last, e.s.released, e.ue.RegStage())
		}
	})
	t.Run("AUSF unreachable at RES* check -> REGISTRATION REJECT #22", func(t *testing.T) {
		e := newRegTmrEnv(t, regAudUDM{})
		e.send(t, regTmrSUCIRegRequest())
		e.ausf.confirmErr = errors.New("connection refused")
		_ = e.h.HandleNASMessage(context.Background(), e.ue, regTmrAuthResponse())
		last := e.s.dl[len(e.s.dl)-1]
		if last[2] != byte(nas.MsgTypeRegistrationReject) || last[3] != byte(nas.CauseCongestion) {
			t.Fatalf("last DL %x; want REGISTRATION REJECT #22", last)
		}
	})
}

// TestDuplicateRegistrationRequest_KeepsRetransmissionCounter: resending the Accept
// for a duplicate REGISTRATION REQUEST restarts T3550 but does not reset the
// retransmission counter. TS 24.501 §5.5.1.2.8 d) 2).
func TestDuplicateRegistrationRequest_KeepsRetransmissionCounter(t *testing.T) {
	e := newRegTmrEnv(t, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	e.toSMC(t)
	e.send(t, buildULSecuredPDU(t, e.ue, nas.MsgTypeSecurityModeComplete, nil))
	e.fireLast()
	e.fireLast() // two retransmissions so far
	e.send(t, regTmrSUCIRegRequest())
	if _, n, ok := e.ue.RegTimerState(); !ok || n != 2 {
		t.Fatalf("retransmission counter after the duplicate request = %d (armed %v), want 2", n, ok)
	}
}

// TestRegistrationRejectCongestionCarriesT3346: REGISTRATION REJECT #22 assigns a
// back-off timer T3346. TS 24.501 §5.5.1.2.5.
func TestRegistrationRejectCongestionCarriesT3346(t *testing.T) {
	e := newRegTmrEnv(t, regAudUDM{})
	e.ausf.initErr = errors.New("ausf down")
	_ = e.h.HandleNASMessage(context.Background(), e.ue, regTmrSUCIRegRequest())
	if len(e.s.dl) != 1 {
		t.Fatalf("DL = %d, want 1 REGISTRATION REJECT", len(e.s.dl))
	}
	want, err := nas.EncodeGPRSTimer2(procedures.CongestionBackoffT3346)
	if err != nil {
		t.Fatal(err)
	}
	rej := e.s.dl[0]
	if len(rej) < 7 || rej[4] != nas.IEIRegistrationRejectT3346 || rej[5] != 0x01 || rej[6] != want {
		t.Fatalf("REGISTRATION REJECT %x: want T3346 IE 0x5F len 1 value %#x after the cause", rej, want)
	}
}

// TestMissingRESStarIsInvalidRES: an AUTHENTICATION RESPONSE without RES* is
// handled like a rejected RES*, not as a protocol error. TS 24.501 §5.4.1.3.5.
func TestMissingRESStarIsInvalidRES(t *testing.T) {
	emptyResp := []byte{0x7e, 0x00, byte(nas.MsgTypeAuthenticationResponse)}
	t.Run("SUCI -> AUTHENTICATION REJECT", func(t *testing.T) {
		e := newRegTmrEnv(t, regAudUDM{})
		e.send(t, regTmrSUCIRegRequest())
		e.send(t, emptyResp)
		last := e.s.dl[len(e.s.dl)-1]
		if last[2] != byte(nas.MsgTypeAuthenticationReject) || e.s.released != 1 {
			t.Fatalf("last DL %x released %d; want AUTHENTICATION REJECT", last, e.s.released)
		}
	})
	t.Run("5G-GUTI -> identification", func(t *testing.T) {
		e := newRegTmrEnv(t, regAudUDM{})
		e.send(t, regTmrSUCIRegRequest())
		e.ue.AuthViaGUTI = true
		e.send(t, emptyResp)
		if last := e.s.dl[len(e.s.dl)-1]; last[2] != byte(nas.MsgTypeIdentityRequest) {
			t.Fatalf("last DL %x; want IDENTITY REQUEST", last)
		}
	})
}

// TestMobilityRequestDuringCommonProcedureStaysUpdate: a mobility update received
// while the UE is 5GMM-COMMON-PROCEDURE-INITIATED is tracked as a registration
// update (prior registration), not as an initial registration.
// TS 24.501 §5.5.1.2.8 g), §5.5.1.3.8.
func TestMobilityRequestDuringCommonProcedureStaysUpdate(t *testing.T) {
	h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
	clk := &fakeClock{}
	h.SetTimerSchedulerForTest(clk.after)
	ue.TransitionTo(amfctx.GMMCommonProcedureInitiated) // initial Accept pending
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	body := regReqWithCap(t, 2, "")[3:]
	body[0] = 0x12
	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, body)); err != nil {
		t.Fatal(err)
	}
	if !ue.LastRegIsUpdate() {
		t.Fatal("mobility registration update not tracked on the pending procedure")
	}
	if _, prior, ok := ue.PendingAccept(); !ok || !prior {
		t.Fatalf("pending Accept prior=%v ok=%v; want treated as a registered UE's update", prior, ok)
	}
	if ue.RegistrationNeverCompleted() {
		t.Fatal("update of a registered UE reported as never completed")
	}
}

// TestRegTimerStoppedOnN2Release: the N2 release path stops the registration timer
// and applies the T3550 abort outcome (5GMM-REGISTERED) without rejecting.
func TestRegTimerStoppedOnN2Release(t *testing.T) {
	e := newRegTmrEnv(t, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	e.toSMC(t)
	e.send(t, buildULSecuredPDU(t, e.ue, nas.MsgTypeSecurityModeComplete, nil))
	e.ue.AbortRegAccept() // what handleUEContextReleaseComplete calls first
	e.ue.ClearRegProc()
	if e.ue.RegTimerRunning() || e.ue.State != amfctx.GMMRegistered {
		t.Fatalf("timer running %v state %s; want stopped and 5GMM-REGISTERED", e.ue.RegTimerRunning(), e.ue.State)
	}
}
