package context

// regproc.go - pending registration-procedure marker and the T3550 / T3560 /
// T3570 supervision timer of the UE context.
//
// Exactly one registration common-procedure message is outstanding at a time
// (IDENTITY REQUEST, AUTHENTICATION REQUEST, SECURITY MODE COMMAND or the
// REGISTRATION ACCEPT), so one RetxTimer and one stage marker are enough. The
// marker gates the UE's answers: a message the AMF did not ask for is ignored
// (TS 24.501 §4.4.4.3 b), §5.5.1.2.8 d)/e)).
//
// Ref: TS 24.501 §5.4.1.3.7, §5.4.2.7, §5.4.3.6, §5.5.1.2.8, §5.5.1.3.8

// RegStage is the registration common procedure awaiting the UE's answer.
type RegStage int

const (
	// RegStageNone: no registration procedure message is outstanding.
	RegStageNone RegStage = iota
	// RegStageIdentity: IDENTITY REQUEST sent, T3570 running.
	RegStageIdentity
	// RegStageAuth: AUTHENTICATION REQUEST sent, T3560 running.
	RegStageAuth
	// RegStageSMC: SECURITY MODE COMMAND sent, T3560 running.
	RegStageSMC
	// RegStageAcceptSent: REGISTRATION ACCEPT sent, awaiting REGISTRATION COMPLETE
	// (T3550 running) - 5GMM-COMMON-PROCEDURE-INITIATED.
	RegStageAcceptSent
)

// String returns the stage name for logs.
func (s RegStage) String() string {
	switch s {
	case RegStageIdentity:
		return "identity"
	case RegStageAuth:
		return "authentication"
	case RegStageSMC:
		return "security-mode"
	case RegStageAcceptSent:
		return "registration-accept"
	default:
		return "none"
	}
}

// RegRetx is what the regT timer retransmits: the NAS message, the timer name for
// logs and the stage it belongs to. A security protected message is stored in its
// plain form and re-protected with a fresh downlink NAS COUNT on every
// retransmission (TS 24.501 §4.4.3.1: the sender increases the NAS COUNT after each
// new or retransmitted security protected message); a plain message is resent as is.
type RegRetx struct {
	Stage RegStage
	// Timer is "T3550", "T3560" or "T3570".
	Timer string
	// PDU is the NAS PDU as first sent; it is the retransmission payload only when
	// Plain is empty (unprotected message).
	PDU []byte
	// Plain is the plain NAS message to re-protect on retransmission; empty for an
	// unprotected message.
	Plain []byte
	// SHT is the security header type to protect Plain with (a nas.SecurityHeaderType).
	SHT byte
}

type regProcState struct {
	stage       RegStage
	lastReq     []byte // last REGISTRATION REQUEST (plain NAS PDU)
	acceptPlain []byte // plain REGISTRATION ACCEPT of the pending procedure (re-protected on resend)
	priorReg    bool   // UE was 5GMM-REGISTERED before this registration (mobility/periodic)
	hasLastReq  bool
	lastMobile  bool // last REGISTRATION REQUEST was a mobility / periodic registration update
}

// RegStage returns the pending registration stage.
func (u *UEContext) RegStage() RegStage {
	u.regProcMu.Lock()
	defer u.regProcMu.Unlock()
	return u.regProc.stage
}

// SetRegStage sets the pending stage (RegStageNone ends the procedure).
func (u *UEContext) SetRegStage(s RegStage) {
	u.regProcMu.Lock()
	u.regProc.stage = s
	u.regProcMu.Unlock()
}

// SetLastRegRequest records the REGISTRATION REQUEST being processed and whether
// it is a mobility / periodic registration update (as opposed to an initial
// registration), so a later abort is handled per the right procedure.
// Ref: TS 24.501 §5.5.1.2.8 g), §5.5.1.3.8
func (u *UEContext) SetLastRegRequest(pdu []byte, mobilityOrPeriodic bool) {
	u.regProcMu.Lock()
	u.regProc.lastReq = append([]byte(nil), pdu...)
	u.regProc.hasLastReq = true
	u.regProc.lastMobile = mobilityOrPeriodic
	u.regProcMu.Unlock()
}

// LastRegIsUpdate reports whether the last REGISTRATION REQUEST was a mobility or
// periodic registration update.
func (u *UEContext) LastRegIsUpdate() bool {
	u.regProcMu.Lock()
	defer u.regProcMu.Unlock()
	return u.regProc.lastMobile
}

// SameRegRequest reports whether pdu is byte-identical to the recorded
// REGISTRATION REQUEST (a retransmission). Ref: TS 24.501 §5.5.1.2.8 d) 2), e) 2)
func (u *UEContext) SameRegRequest(pdu []byte) bool {
	u.regProcMu.Lock()
	defer u.regProcMu.Unlock()
	return u.regProc.hasLastReq && string(u.regProc.lastReq) == string(pdu)
}

// SetPendingAccept stores the plain REGISTRATION ACCEPT sent, whether the UE was
// 5GMM-REGISTERED before this registration, and moves to RegStageAcceptSent.
func (u *UEContext) SetPendingAccept(plain []byte, priorRegistered bool) {
	u.regProcMu.Lock()
	u.regProc.stage = RegStageAcceptSent
	u.regProc.acceptPlain = append([]byte(nil), plain...)
	u.regProc.priorReg = priorRegistered
	u.regProcMu.Unlock()
}

// PendingAccept returns the stored plain REGISTRATION ACCEPT of the pending procedure.
func (u *UEContext) PendingAccept() (plain []byte, priorRegistered, ok bool) {
	u.regProcMu.Lock()
	defer u.regProcMu.Unlock()
	if u.regProc.stage != RegStageAcceptSent || u.regProc.acceptPlain == nil {
		return nil, false, false
	}
	return u.regProc.acceptPlain, u.regProc.priorReg, true
}

// ClearRegProc ends the pending registration procedure: stops the supervision
// timer, drops the stored Accept and the prior-registration marker and sets the
// stage to RegStageNone. The last REGISTRATION REQUEST is kept.
func (u *UEContext) ClearRegProc() {
	u.StopRegTimer()
	u.regProcMu.Lock()
	u.regProc.stage = RegStageNone
	u.regProc.acceptPlain = nil
	u.regProc.priorReg = false
	u.regProcMu.Unlock()
}

// AbortRegAccept aborts a registration whose ACCEPT was sent but not completed
// (T3550 fifth expiry, lower-layer failure): the timer is stopped, the stage
// cleared and the UE enters 5GMM-REGISTERED with its context kept - both for an
// initial registration (TS 24.501 §5.5.1.2.8 a), c)) and for a mobility / periodic
// update (§5.5.1.3.8 c)). It returns whether the UE was 5GMM-REGISTERED before
// this registration and whether an Accept was pending at all.
func (u *UEContext) AbortRegAccept() (priorRegistered, wasPending bool) {
	u.regProcMu.Lock()
	wasPending = u.regProc.stage == RegStageAcceptSent
	priorRegistered = u.regProc.priorReg
	u.regProcMu.Unlock()
	if !wasPending {
		return false, false
	}
	u.ClearRegProc()
	u.Lock()
	u.State = GMMRegistered
	u.Unlock()
	return priorRegistered, true
}

// RegistrationNeverCompleted reports whether the UE has never completed a
// registration: 5GMM-DEREGISTERED, or 5GMM-COMMON-PROCEDURE-INITIATED for its
// first (initial) registration. Caller must not hold u.mu.
func (u *UEContext) RegistrationNeverCompleted() bool {
	u.regProcMu.Lock()
	prior := u.regProc.priorReg
	u.regProcMu.Unlock()
	u.Lock()
	defer u.Unlock()
	return u.State == GMMDeregistered || (u.State == GMMCommonProcedureInitiated && !prior)
}

// ArmRegTimer (re)starts the T3550/T3560/T3570 supervision (see RetxTimer.Arm).
func (u *UEContext) ArmRegTimer(msg *RegRetx, expiries int, start func(gen uint64) TimerStopper) {
	u.regT.Arm(msg, expiries, start)
}

// StopRegTimer stops the supervision timer and invalidates callbacks already
// fired. Safe on a UE with no timer, from any goroutine.
func (u *UEContext) StopRegTimer() { u.regT.Stop() }

// RegTimerCurrent returns the message and expiry count of the timer armed with
// generation gen, or ok=false when it was stopped or replaced meanwhile.
func (u *UEContext) RegTimerCurrent(gen uint64) (msg *RegRetx, expiries int, ok bool) {
	m, e, ok := u.regT.Current(gen)
	if !ok {
		return nil, 0, false
	}
	r, _ := m.(*RegRetx)
	return r, e, r != nil
}

// RegTimerRunning reports whether a supervision timer is armed.
func (u *UEContext) RegTimerRunning() bool { return u.regT.Running() }

// RegTimerState returns the message and expiry count of the armed supervision
// timer (any generation), or ok=false when none is armed.
func (u *UEContext) RegTimerState() (msg *RegRetx, expiries int, ok bool) {
	m, e, ok := u.regT.State()
	if !ok {
		return nil, 0, false
	}
	r, _ := m.(*RegRetx)
	return r, e, r != nil
}

// ICSKind identifies the procedure that sent the Initial Context Setup Request
// still awaiting its Response / Failure, so a failure is handled per procedure
// (TS 38.413 §8.3.1; TS 24.501 §5.5.1.2.8, §5.5.1.3.8).
type ICSKind uint8

const (
	// ICSNone: no ICS Request is pending (or the sender did not record one).
	ICSNone ICSKind = iota
	// ICSInitialRegistration: the ICS carries the REGISTRATION ACCEPT of an
	// initial registration that is not yet completed (TS 24.501 §5.5.1.2.4).
	ICSInitialRegistration
	// ICSRegistrationUpdate: the ICS carries the REGISTRATION ACCEPT of a mobility
	// or periodic registration update (TS 24.501 §5.5.1.3.4).
	ICSRegistrationUpdate
	// ICSServiceRequest: the ICS carries the SERVICE ACCEPT (TS 23.502 §4.2.3.2).
	ICSServiceRequest
)

// String returns the log name of the kind.
func (k ICSKind) String() string {
	switch k {
	case ICSInitialRegistration:
		return "InitialRegistration"
	case ICSRegistrationUpdate:
		return "MobilityRegistrationUpdate"
	case ICSServiceRequest:
		return "ServiceRequest"
	default:
		return "None"
	}
}

// SetPendingICS records which procedure sent the ICS Request now in flight.
func (u *UEContext) SetPendingICS(k ICSKind) {
	u.regProcMu.Lock()
	u.pendingICS = k
	u.regProcMu.Unlock()
}

// TakePendingICS returns the pending ICS kind and clears it (ICS Response or
// Failure received).
func (u *UEContext) TakePendingICS() ICSKind {
	u.regProcMu.Lock()
	k := u.pendingICS
	u.pendingICS = ICSNone
	u.regProcMu.Unlock()
	return k
}
