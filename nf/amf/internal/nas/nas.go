// Package nasmsg implements the NAS message handler for the AMF.
//
// The NAS handler receives raw NAS PDUs delivered by the NGAP layer and
// routes them to the appropriate 5GMM procedure handler.
//
// NAS message flow during Initial Registration:
//
//	UE → AMF: RegistrationRequest      (step 1)
//	AMF → UE: AuthenticationRequest    (step 9)   — plain NAS via DownlinkNASTransport
//	UE → AMF: AuthenticationResponse   (step 10)
//	AMF → UE: SecurityModeCommand      (step 14)  — plain NAS via DownlinkNASTransport
//	UE → AMF: SecurityModeComplete     (step 15)
//	AMF → gNB: InitialContextSetupRequest           — carries integrity-protected RegistrationAccept
//	UE → AMF: RegistrationComplete     (step 21)
//
// Ref: 3GPP TS 23.502 §4.2.2.2.2, TS 24.501 §5.5.1, TS 38.413 §8.3.1
package nasmsg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// Sender is the interface to send NAS PDUs and NGAP messages to the UE via the gNB.
type Sender interface {
	SendDownlinkNASTransport(ue *amfctx.UEContext, nasPDU []byte) error
	// SendInitialContextSetupRequest sends the ICS Request. pduSessions is the
	// PDUSessionResourceSetupListCxtReq for Service Request UP re-activation
	// (TS 23.502 §4.2.3 step 6); nil for Initial Registration.
	SendInitialContextSetupRequest(ue *amfctx.UEContext, nasPDU []byte,
		kgnb [32]byte, cipherAlg, integAlg byte,
		encAlgsBitmap, intAlgsBitmap uint16,
		pduSessions []ngap.PDUSessionSetupItemCxtReq) error
	SendPDUSessionResourceSetupRequest(ue *amfctx.UEContext, pduSessionID uint8, nasPDU []byte, n2SmInfo []byte) error
	SendPDUSessionResourceReleaseCommand(ue *amfctx.UEContext, pduSessionID uint8, nasPDU []byte) error
	SendPDUSessionResourceModifyRequest(ue *amfctx.UEContext, pduSessionID uint8, nasPDU []byte, n2SmInfo []byte) error
	// SendUEContextReleaseCommandForUE releases the N2 context at the gNB (AMF-initiated).
	// causePresent/causeValue use NGAP Cause group/value constants (TS 38.413 §9.3.1.2).
	// No-op if the UE is already CM-IDLE. Ref: TS 38.413 §8.3.3
	SendUEContextReleaseCommandForUE(ue *amfctx.UEContext, causePresent int, causeValue int64) error
}

// SMSFClient is the interface the AMF NAS handler uses to forward MO SMS to the SMSF.
// Ref: TS 29.540 §5.2.4 (Nsmsf_SMService_UplinkSMS)
type SMSFClient interface {
	// UplinkSMS forwards the MO SMS payload (base64-encoded SM-CP/RP bytes from the
	// NAS Payload Container) to the SMSF. smsRecordID is a unique correlation ID.
	// Returns an error if the SMSF rejects the message (e.g., 404 CONTEXT_NOT_FOUND).
	// Ref: TS 29.540 §5.2.4
	UplinkSMS(ctx context.Context, supi, smsRecordID, smsPayloadBase64 string) error
}

// Handler is the AMF NAS message handler.
type Handler struct {
	sender Sender
	reg    *procedures.RegistrationHandler
	logger *slog.Logger
	// integrity selects strict (default) or relaxed uplink NAS integrity
	// enforcement. Ref: TS 24.501 §4.4.4.3
	integrity IntegrityEnforcement
	// smsfClient forwards UL NAS Transport SMS containers to the SMSF.
	// Nil = no SMSF configured (UL SMS is dropped with a warning; fail-open).
	// Ref: TS 29.540 §5.2.4, TS 23.502 §4.13.3
	smsfClient SMSFClient

	// onUEReachable is called when the UE enters CM-CONNECTED (Initial
	// Registration complete, Service Request, Periodic/Mobility Registration
	// Update). It must cancel the Mobile Reachable / Implicit Detach timers:
	// those watchdogs only run while the UE is CM-IDLE — they are re-armed on
	// AN Release by the NGAP layer.
	// Ref: TS 23.501 §5.3.2, TS 24.501 §5.3.7
	onUEReachable func(ue *amfctx.UEContext)

	// networkFullName / networkShortName are the operator name this AMF pushes
	// to every UE in a Configuration Update Command once registration completes.
	// Empty = push nothing, which is the behaviour before this was configurable.
	// Ref: TS 24.501 §8.2.19, §9.11.3.35, §9.11.3.36
	networkFullName  string
	networkShortName string

	// pendingLPP holds one pending LPPResult channel per AMF-UE-NGAP-ID.
	// Inserted by SendDownlinkLPP; resolved (and deleted) by handleULLPP when
	// the matching UL NAS Transport (payload container type 0x03) arrives
	// from the UE. Mirrors ngap.Server's pendingNRPPa (LMF-004) — the NAS-
	// transport analogue for LPP (LMF-005), since LPP rides the existing
	// DL/UL NAS Transport rather than a dedicated NGAP procedure.
	// Ref: TS 24.501 §8.7.4; TS 23.273 §7.2.
	pendingLPP sync.Map // map[int64]chan LPPResult

	// pendingRelease holds one pendingReleaseState per NW-initiated PDU Session
	// Release, keyed by "<amfUeNgapId>:<psi>". Inserted by
	// InitiateNetworkPDUSessionRelease after the Release Command is sent;
	// resolved by completeNetworkPDUSessionRelease when the UE's PDU Session
	// Release Complete arrives (or when the T3592 guard fires). The SM context
	// must not be deleted before that point — TS 23.502 §4.3.4.3 orders the
	// Nsmf_PDUSession_UpdateSMContext (and the N4 release it triggers) *after*
	// the UE confirms the release.
	// Ref: TS 23.502 §4.3.4.3 steps 5-8.
	pendingRelease sync.Map // map[string]*pendingReleaseState

	// Supervision timers T3575 (NSSAA COMMAND, nssaa_timer.go) and T3522 (NW
	// DEREGISTRATION REQUEST, dereg_timer.go), rel19 only: the timer state lives
	// on the UEContext; this is only the injectable scheduler (nil =
	// time.AfterFunc), set by SetTimerSchedulerForTest.
	// Ref: TS 24.501 §5.4.7.2.3 a), §5.5.2.3.5 a)
	timerAfter TimerScheduler
}

// pendingReleaseState tracks one in-flight NW-initiated PDU Session Release
// between the Release Command going out on N1/N2 and the UE's Release Complete
// coming back. Ref: TS 23.502 §4.3.4.3.
type pendingReleaseState struct {
	smContextRef string
	guard        *time.Timer
	once         sync.Once
}

// t3592Guard bounds how long the AMF waits for a PDU Session Release Complete
// before releasing the SM context anyway. T3592 is the network-side timer for
// the PDU Session Release Command (8 s); the extra second covers N1/N2 transit
// so a UE that answers just inside T3592 still takes the confirmed path.
// Ref: TS 24.501 §10.3 (T3592), TS 23.502 §4.3.4.3.
const t3592Guard = 9 * time.Second

// releaseSMContextTimeout bounds the detached Nsmf_PDUSession SM context
// deletion. The trigger for a NW-initiated release is an HTTP request whose
// context dies the moment the handler returns, so the SBI call must run on a
// context detached from it — otherwise the DELETE is cancelled in flight.
const releaseSMContextTimeout = 10 * time.Second

// pendingReleaseKey builds the pendingRelease map key for a UE + PDU session.
func pendingReleaseKey(amfUeNgapID int64, psi uint8) string {
	return fmt.Sprintf("%d:%d", amfUeNgapID, psi)
}

// LPPResult carries the outcome of a DL/UL LPP relay round-trip over the NAS
// N1 payload container (payload container type 0x03), mirroring
// ngap.NRPPaResult for the NGAP-layer NRPPa relay (LMF-004).
// Ref: TS 24.501 §8.7.4; TS 23.273 §7.2.
type LPPResult struct {
	// LPPPDU is the opaque UL LPP-PDU bytes received from the UE. The AMF
	// never decodes this content.
	LPPPDU []byte
	// Err is non-nil on a relay/timeout failure.
	Err error
}

// NewHandler constructs the NAS handler.
func NewHandler(sender Sender, reg *procedures.RegistrationHandler, logger *slog.Logger) *Handler {
	return &Handler{
		sender: sender,
		reg:    reg,
		logger: logger.With("component", "nas-handler"),
	}
}

// notifyUEReachable drops the paged PDU session set (a UE reaching CM-CONNECTED
// by any path ends the network-triggered paging, mirroring PendingN1N2) and
// then fires the registered reachability callback. Service Request consumes
// the set in activatePDUSessions before calling this.
// Ref: TS 23.502 §4.2.3.3, TS 23.501 §5.3.2
func (h *Handler) notifyUEReachable(ue *amfctx.UEContext) {
	ue.TakePagedPDUSessions()
	if h.onUEReachable != nil {
		h.onUEReachable(ue)
	}
}

// SetUEReachableHandler registers a callback invoked whenever the UE enters
// CM-CONNECTED (initial registration complete, service request, registration
// update). Wire this to ngapSrv.StopUETimers in main.go.
func (h *Handler) SetUEReachableHandler(fn func(ue *amfctx.UEContext)) {
	h.onUEReachable = fn
}

// WithSMSFClient wires the SMSF client for UL NAS Transport SMS routing.
// If never called the SMS container type (0x02) is dropped with a warning.
// Ref: TS 23.502 §4.13.3, TS 29.540 §5.2.4
func (h *Handler) WithSMSFClient(c SMSFClient) {
	h.smsfClient = c
}

// WithNetworkName sets the operator name delivered to every UE after
// registration completes. full is the "Full name for network" IE and short the
// "Short name for network" IE; either may be empty. When both are empty no
// Configuration Update Command is sent, which is the behaviour of an AMF that
// never had this configured.
//
// This is the only 5G SA mechanism by which the network itself can set the
// label a handset shows. The alternatives live on the card (EF_SPN) or in the
// handset's own PLMN table, and neither is reachable from the core.
// Ref: TS 24.501 §8.2.19, §9.11.3.35, §9.11.3.36
func (h *Handler) WithNetworkName(full, short string) {
	h.networkFullName = full
	h.networkShortName = short
}

// HandleNASMessage is called by the NGAP layer when a NAS PDU arrives.
// It decodes the PDU and dispatches to the appropriate procedure handler.
func (h *Handler) HandleNASMessage(ctx context.Context, ue *amfctx.UEContext, pdu []byte) error {
	// Unwrap NAS security for messages sent after security is active.
	// Ref: TS 24.501 §9.1.1, §4.4.4.3, TS 33.501 §D.3
	wasProtected := false
	verified := true
	ue.Lock()
	if ue.NASOnNewN2Connection {
		// New N1 signalling connection: the secure exchange starts over.
		ue.ResetSecureExchange()
	}
	ue.Unlock()
	if len(pdu) >= 2 && pdu[0] == nas.PDMobilityManagement {
		sht := nas.SecurityHeaderType(pdu[1] & 0x0F)
		switch {
		case sht != nas.SecurityHeaderPlainNAS && ue.SecurityCtx.Active:
			out, err := h.unwrapUplink(ue, pdu, sht)
			switch {
			case err == nil:
				pdu = out
				wasProtected = true
				ue.MarkSecureExchange() // verified with the current context
			case errors.Is(err, ErrNASIntegrity):
				if !h.admitUnverified(ctx, ue, out, sht, true) {
					return nil
				}
				pdu = out
				verified = false
			default:
				return fmt.Errorf("amf: nas security unwrap: %w", err)
			}
		case sht == nas.SecurityHeaderPlainNAS && !h.relaxedIntegrity():
			// Unprotected: only the TS 24.501 §4.4.4.3 list is processed.
			if !h.admitUnverified(ctx, ue, pdu, sht, false) {
				return nil
			}
			verified = false
		case sht != nas.SecurityHeaderPlainNAS && !h.relaxedIntegrity():
			// Security protected but no current 5G NAS security context: the MAC
			// cannot be verified, so the message is unverified. Ciphered PDUs
			// (SHT 2/4) cannot be read at all and are discarded.
			// Ref: TS 24.501 §4.4.4.3
			if sht == nas.SecurityHeaderIntegrityProtectedAndCiphered ||
				sht == nas.SecurityHeaderIntegrityProtectedAndCipheredWithNewSC {
				h.discardNAS(ctx, ue, 0, false, sht, "cannot_be_verified_no_security_context")
				return nil
			}
			if !h.admitUnverified(ctx, ue, pdu, sht, true) {
				return nil
			}
			verified = false
		}
	}
	msg, err := nas.Decode(pdu)
	if err != nil {
		// A REGISTRATION REQUEST with a protocol error is answered with a
		// REGISTRATION REJECT: syntactically incorrect mandatory IE -> #96.
		// Ref: TS 24.501 §5.5.1.2.8 b), §5.5.1.3.8 b)
		if mt, ok := nas.PeekMessageType(pdu); ok && mt == nas.MsgTypeRegistrationRequest {
			h.logger.WarnContext(ctx, "REGISTRATION REQUEST decode failed", "nf", "AMF",
				"procedure", "InitialRegistration", "interface", "N1", "direction", "IN",
				"amf_ue_ngap_id", ue.AMFUENGAPId, "result", "REJECT", "error", err,
				"spec_ref", "TS 24.501 §5.5.1.2.8 b)")
			if rerr := h.rejectRegistration(ctx, ue, nas.CauseInvalidMandatoryInformation,
				"TS 24.501 §5.5.1.2.8 b)", wasProtected); rerr != nil {
				return rerr
			}
			return fmt.Errorf("nas decode: %w", err) // reported after the REGISTRATION REJECT went out
		}
		return fmt.Errorf("nas decode: %w", err)
	}
	log := h.logger.With(
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"message_type", fmt.Sprintf("%02X", msg.Header.MessageType),
		"interface", "N1",
		"direction", "IN",
	)
	log.Info("NAS message received")

	err = h.dispatch(ctx, ue, msg, pdu, verified, log)
	// One place maps a terminal phase failure to REGISTRATION REJECT.
	// Ref: TS 24.501 §5.5.1.2.5
	var rc *procedures.ErrRejectCause
	if errors.As(err, &rc) {
		log.WarnContext(ctx, "registration phase failed - REGISTRATION REJECT", "nf", "AMF",
			"procedure", "InitialRegistration", "interface", "N1", "direction", "IN",
			"result", "REJECT", "cause", int(rc.Cause),
			"error", rc.Err, "spec_ref", rc.SpecRef)
		if rerr := h.rejectRegistration(ctx, ue, rc.Cause, rc.SpecRef, wasProtected); rerr != nil {
			return rerr
		}
		return err // the cause is still reported to the caller's log
	}
	return err
}

// dispatch routes a decoded NAS message to its handler.
func (h *Handler) dispatch(ctx context.Context, ue *amfctx.UEContext, msg *nas.Message,
	pdu []byte, verified bool, log *slog.Logger) error {
	switch msg.Header.MessageType {
	case nas.MsgTypeRegistrationRequest:
		return h.handleRegistrationRequest(ctx, ue, msg, pdu, verified)
	case nas.MsgTypeAuthenticationResponse:
		return h.handleAuthenticationResponse(ctx, ue, msg)
	case nas.MsgTypeAuthenticationFailure:
		return h.handleAuthenticationFailure(ctx, ue, msg)
	case nas.MsgTypeSecurityModeComplete:
		return h.handleSecurityModeComplete(ctx, ue, msg)
	case nas.MsgTypeSecurityModeReject:
		return h.handleSecurityModeReject(ctx, ue, msg)
	case nas.MsgTypeRegistrationComplete:
		return h.handleRegistrationComplete(ctx, ue)
	case nas.MsgTypeULNASTransport:
		return h.handleULNASTransport(ctx, ue, msg)
	case nas.MsgTypeDeregistrationRequestUE:
		return h.handleDeregistration(ctx, ue, msg)
	case nas.MsgTypeDeregistrationAcceptNW:
		return h.handleNWDeregistrationAccept(ctx, ue)
	case nas.MsgTypeIdentityResponse:
		return h.handleIdentityResponse(ctx, ue, msg)
	case nas.MsgTypeServiceRequest:
		return h.handleServiceRequest(ctx, ue, msg)
	case nas.MsgTypeConfigurationUpdateComplete:
		return h.handleConfigurationUpdateComplete(ctx, ue)
	case nas.MsgTypeNetworkSliceSpecificAuthComplete:
		return h.handleNSSAAComplete(ctx, ue, msg)
	default:
		log.Warn("unhandled NAS message type", "msg_type", msg.Header.MessageType)
		return nil
	}
}

// ---- Registration Request -----------------------------------------------

func (h *Handler) handleRegistrationRequest(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message, rawPDU []byte, verified bool) error {

	regReq, ok := msg.Body.(*nas.RegistrationRequest)
	if !ok {
		return fmt.Errorf("nas: RegistrationRequest body decode failed")
	}

	// A REGISTRATION REQUEST during a network-initiated de-registration aborts it
	// (initial registration; mobility/periodic update after cause #62 and the other
	// listed causes) and the registration progresses: T3522 must not fire later on
	// a UE that is registering again. No-op without a running T3522 (rel17).
	// Ref: TS 24.501 §5.5.2.3.5 d), e)
	ue.StopDeregTimer()

	// A REGISTRATION REQUEST received while a registration procedure is pending.
	// Identical retransmission: ignored while the procedure is still in progress,
	// the REGISTRATION ACCEPT is resent (T3550 restarted) once it was sent. IEs
	// differing: the previous procedure is aborted and the new request processed.
	// Ref: TS 24.501 §5.5.1.2.8 d) 2), e) 2), §5.5.1.3.8 d) 2), §5.4.3.6 d)
	if stage := ue.RegStage(); stage != amfctx.RegStageNone {
		if ue.SameRegRequest(rawPDU) {
			return h.handleDuplicateRegistrationRequest(ue, stage)
		}
		h.logger.InfoContext(ctx, "REGISTRATION REQUEST differs from the pending one - previous procedure aborted",
			"nf", "AMF", "procedure", "InitialRegistration", "interface", "N1", "direction", "IN",
			"amf_ue_ngap_id", ue.AMFUENGAPId, "stage", stage.String(),
			"spec_ref", "TS 24.501 §5.5.1.2.8 d) 1), e) 1)")
		// Always roll back: a no-op unless a new context is still unconfirmed.
		h.rollbackSecurityCtx(ue, "superseded_by_registration_request")
		ue.ClearRegProc()
	}
	ue.SetLastRegRequest(rawPDU, regReq.RegistrationType == nas.RegistrationTypePeriodic ||
		regReq.RegistrationType == nas.RegistrationTypeMobility)

	// Initial registration with an existing context: the outer message is integrity
	// protected and its non-cleartext IEs are in the NAS message container
	// (initial/emergency/update alike; the update path decodes it itself).
	// Ref: TS 24.501 §4.4.6, §5.5.1.2.2
	if regReq.RegistrationType != nas.RegistrationTypePeriodic &&
		regReq.RegistrationType != nas.RegistrationTypeMobility && !verified {
		// Integrity unverifiable: the container cannot be trusted. Authenticate
		// + SMC with RINMR; the existing context stays until that succeeds.
		// Ref: TS 24.501 §4.4.4.3 b)
		return h.initiateRegistrationAuth(ctx, ue, regReq, rawPDU)
	}
	if regReq.RegistrationType != nas.RegistrationTypePeriodic &&
		regReq.RegistrationType != nas.RegistrationTypeMobility {
		outerReq := regReq
		var cerr error
		if regReq, cerr = h.registrationRequestFromContainer(ctx, ue, regReq, rawPDU); cerr != nil {
			// Undecipherable container: fresh authentication + SMC with RINMR.
			// Ref: TS 24.501 §4.4.6, §5.4.2.2
			return h.initiateRegistrationAuth(ctx, ue, outerReq, rawPDU)
		}
	}

	// Periodic and Mobility Registration Update: skip re-authentication when the
	// UE already has an active NAS security context with this AMF.
	// Ref: TS 23.502 §4.2.2.2.3 (Mobility), §4.2.2.2.4 (Periodic)
	// Only for a request that passed the integrity check with the current 5G NAS
	// security context (that proves the UE holds it); anything else (plain, MAC
	// failure, no context) is authenticated (AKA + SMC with RINMR) on the existing
	// context, which stays unchanged if that fails. An ngKSI differing from the
	// stored one on a verified request is only logged (UERANSIM sends ngKSI 7 on
	// its T3512 update).
	// Ref: TS 24.501 §4.4.4.3 b), §5.5.1.3.2, §9.11.3.32
	if regReq.RegistrationType == nas.RegistrationTypePeriodic ||
		regReq.RegistrationType == nas.RegistrationTypeMobility {
		if ue.SecurityCtx.Active && verified {
			if regReq.NGKSI.KeySetIdentifier != ue.SecurityCtx.NGKSI {
				h.logger.WarnContext(ctx, "registration update ngKSI differs from stored context, proceeding (MAC verified)",
					"nf", "AMF", "procedure", "RegistrationUpdate", "interface", "N1", "direction", "IN",
					"supi", ue.SUPI, "request_ngksi", regReq.NGKSI.KeySetIdentifier,
					"stored_ngksi", ue.SecurityCtx.NGKSI, "spec_ref", "TS 24.501 §4.4.4.3, §9.11.3.32")
			}
			return h.handleRegistrationUpdate(ctx, ue, regReq, rawPDU)
		}
		h.logger.InfoContext(ctx, "registration update not verifiable - primary authentication + SMC (RINMR)",
			"nf", "AMF", "procedure", "RegistrationUpdate", "interface", "N1", "direction", "IN",
			"amf_ue_ngap_id", ue.AMFUENGAPId, "supi", ue.SUPI, "integrity_verified", verified,
			"request_ngksi", regReq.NGKSI.KeySetIdentifier, "spec_ref", "TS 24.501 §4.4.4.3 b)")
	}

	return h.initiateRegistrationAuth(ctx, ue, regReq, rawPDU)
}

// initiateRegistrationAuth runs Phase 1 (authentication via AUSF) and sends the
// AUTHENTICATION REQUEST; the SECURITY MODE COMMAND that follows carries RINMR so
// the complete REGISTRATION REQUEST comes back in the SECURITY MODE COMPLETE.
// Ref: TS 23.502 §4.2.2.2.2 steps 4-9; TS 24.501 §5.4.2.2
func (h *Handler) initiateRegistrationAuth(
	ctx context.Context, ue *amfctx.UEContext, regReq *nas.RegistrationRequest, rawPDU []byte) error {
	// Phase 1: initiate authentication via AUSF
	authReq, err := h.reg.Phase1_InitiateAuthentication(ctx, procedures.RegistrationInput{
		UE:            ue,
		RegRequest:    regReq,
		RawRegRequest: rawPDU,
	})
	if errors.Is(err, procedures.ErrNeedSUCI) {
		// UE presented a GUTI that AMF cannot resolve. Request SUCI.
		// Ref: TS 24.501 §5.5.1.2.2 step 1b
		return h.sendIdentityRequest(ctx, ue)
	}
	if errors.Is(err, procedures.ErrUESecurityCapabilityUnacceptable) {
		// Ref: TS 24.501 §5.5.1.2.8 i)
		return h.rejectRegistrationPlain(ctx, ue, procedures.UESecCapRejectCause, "TS 24.501 §5.5.1.2.8 i)")
	}
	if errors.Is(err, procedures.ErrPEINotAccepted) {
		// Ref: TS 24.501 §5.5.1.2.5, Annex A.2 (cause #5)
		return h.rejectRegistrationPlain(ctx, ue, procedures.PEINotAcceptedCause, "TS 24.501 §5.5.1.2.5")
	}
	if err != nil {
		return fmt.Errorf("registration phase1: %w", err)
	}

	// Store the UE's requested NSSAI for filtering in Phase 3.
	// Ref: TS 23.502 §4.2.2.2.2 step 1
	if regReq.RequestedNSSAI != nil {
		ue.RequestedNSSAI = nssaiToSubscribed(regReq.RequestedNSSAI)
	}

	// AuthenticationRequest is sent before NAS security is active — plain NAS.
	// Ref: TS 24.501 §5.5.1.2.2 step 3
	pdu, err := h.sendNASPlain(ue, nas.PDMobilityManagement,
		nas.MsgTypeAuthenticationRequest, authReq)
	if err != nil {
		return err
	}
	h.logNASOut(ue, nas.MsgTypeAuthenticationRequest)
	return h.sendRegProc(ue, amfctx.RegStageAuth, pdu) // T3560
}

// handleDuplicateRegistrationRequest answers a retransmitted, identical
// REGISTRATION REQUEST. Ref: TS 24.501 §5.5.1.2.8 d) 2), e) 2)
func (h *Handler) handleDuplicateRegistrationRequest(ue *amfctx.UEContext, stage amfctx.RegStage) error {
	log := h.logger.With("nf", "AMF", "procedure", "InitialRegistration", "interface", "N1",
		"direction", "IN", "amf_ue_ngap_id", ue.AMFUENGAPId, "supi", ue.SUPI, "stage", stage.String(),
		"message_type", "RegistrationRequest", "spec_ref", "TS 24.501 §5.5.1.2.8 d) 2), e) 2)")
	if plain, _, ok := ue.PendingAccept(); ok {
		pdu, err := h.cipherProtectNAS(ue, plain) // fresh NAS COUNT, TS 24.501 §4.4.3.1
		if err != nil {
			return fmt.Errorf("nas: protect RegistrationAccept: %w", err)
		}
		if err := h.sender.SendDownlinkNASTransport(ue, pdu); err != nil {
			return fmt.Errorf("nas: resend RegistrationAccept: %w", err)
		}
		// T3550 restarted, the retransmission counter is not incremented nor reset
		// (TS 24.501 §5.5.1.2.8 d) 2)).
		expiries := 0
		if cur, e, ok := ue.RegTimerState(); ok && cur.Stage == amfctx.RegStageAcceptSent {
			expiries = e
		}
		h.armRegTimer(ue, &amfctx.RegRetx{Stage: amfctx.RegStageAcceptSent, Timer: regTimerT3550,
			PDU: pdu, Plain: plain, SHT: byte(nas.SecurityHeaderIntegrityProtectedAndCiphered)}, expiries)
		log.Info("retransmitted REGISTRATION REQUEST - REGISTRATION ACCEPT resent", "direction", "OUT")
		return nil
	}
	log.Info("retransmitted REGISTRATION REQUEST ignored - procedure in progress")
	return nil
}

// sendIdentityRequest sends a plain NAS Identity Request asking for SUCI.
// Called when the UE presented a GUTI that AMF cannot resolve.
// Ref: TS 24.501 §8.2.13, TS 23.502 §4.2.2.2.2 step 1b
func (h *Handler) sendIdentityRequest(ctx context.Context, ue *amfctx.UEContext) error {
	h.logger.Info("sending Identity Request (requesting SUCI)",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"interface", "N1",
		"direction", "OUT",
		"message_type", "IdentityRequest",
		"spec_ref", "TS 24.501 §8.2.13",
	)
	pdu, err := h.sendNASPlain(ue, nas.PDMobilityManagement,
		nas.MsgTypeIdentityRequest, &nas.IdentityRequest{
			IdentityType: nas.MobileIdentitySUCI,
		})
	if err != nil {
		return err
	}
	return h.sendRegProc(ue, amfctx.RegStageIdentity, pdu) // T3570, TS 24.501 §5.4.3.2
}

// handleIdentityResponse processes the UE's Identity Response (contains SUCI).
// Extracts the SUCI and resumes authentication via Phase1_AuthenticateWithSUCI.
// Ref: TS 24.501 §8.2.14, TS 23.502 §4.2.2.2.2 step 2
func (h *Handler) handleIdentityResponse(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

	idResp, ok := msg.Body.(*nas.IdentityResponse)
	if !ok {
		return fmt.Errorf("nas: IdentityResponse body decode failed")
	}
	// IDENTITY RESPONSE only when requested. Ref: TS 24.501 §4.4.4.3 b), §5.4.3.3
	if !h.acceptSolicited(ue, amfctx.RegStageIdentity, "IdentityResponse", "TS 24.501 §5.4.3.3") {
		return nil
	}
	ue.ClearRegProc() // T3570 stopped

	// A missing or unrepresentable SUCI leaves the UE unanswered until T3510:
	// reject with #96 and release. Ref: TS 24.501 §5.5.1.2.8 b), §5.4.3.3
	mi := idResp.MobileIdentity
	var suci string
	var err error
	if mi.Type != nas.MobileIdentitySUCI || mi.SUCI == nil {
		err = fmt.Errorf("nas: identity response carries identity type %d, not a SUCI", mi.Type)
	} else {
		suci, err = procedures.SUCIString(mi.SUCI)
	}
	if err != nil {
		return &procedures.ErrRejectCause{Cause: procedures.UnusableSUCIRejectCause,
			SpecRef: procedures.UnusableSUCISpecRef, Err: err}
	}

	authReq, err := h.reg.Phase1_AuthenticateWithSUCI(ctx, ue, suci)
	if err != nil {
		return fmt.Errorf("registration phase1 (suci): %w", err)
	}

	pdu, err := h.sendNASPlain(ue, nas.PDMobilityManagement,
		nas.MsgTypeAuthenticationRequest, authReq)
	if err != nil {
		return err
	}
	h.logNASOut(ue, nas.MsgTypeAuthenticationRequest)
	return h.sendRegProc(ue, amfctx.RegStageAuth, pdu) // T3560
}

// ---- Authentication Response --------------------------------------------

func (h *Handler) handleAuthenticationResponse(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

	authResp, ok := msg.Body.(*nas.AuthenticationResponse)
	if !ok {
		return fmt.Errorf("nas: AuthenticationResponse body decode failed")
	}

	// AUTHENTICATION RESPONSE only when a challenge is outstanding.
	// Ref: TS 24.501 §5.4.1.3.3, §4.4.4.3 b)
	if !h.acceptSolicited(ue, amfctx.RegStageAuth, "AuthenticationResponse", "TS 24.501 §5.4.1.3.3") {
		return nil
	}
	ue.ClearRegProc() // T3560 stopped

	// Phase 2: verify RES* with AUSF, derive keys, build Security Mode Command.
	// displaced is the prior UEContext for the same SUPI (non-nil when the UE
	// reconnected without deregistering — e.g. Docker restart). Release it async
	// so we don't block the new registration path.
	smcReq, displaced, err := h.reg.Phase2_ProcessAuthResponse(ctx, ue, authResp)
	if errors.Is(err, procedures.ErrAuthenticationRejected) {
		// RES* rejected: 5G-GUTI-based challenge -> identification procedure; SUCI-based
		// -> AUTHENTICATION REJECT. Ref: TS 24.501 §5.4.1.3.5
		if ue.AuthViaGUTI {
			ue.AuthViaGUTI = false
			return h.sendIdentityRequest(ctx, ue)
		}
		return h.rejectAuthentication(ctx, ue, nas.CauseMACFailure, "TS 24.501 §5.4.1.3.5")
	}
	if err != nil {
		return fmt.Errorf("registration phase2: %w", err) // *ErrRejectCause -> REGISTRATION REJECT
	}
	if displaced != nil {
		go h.releaseDisplacedContext(context.Background(), displaced)
	}

	// Security Mode Command: integrity-protected with NEW security context (SHT=0x03).
	// TS 24.501 §4.4.4.3.1: when no prior current security context exists on the UE,
	// the SMC MUST use SHT=0x03 so the UE processes it via the new-SC path.
	// SHT=0x01 would fail because the UE has no active (current) security context yet.
	plain, err := h.sendNASPlain(ue, nas.PDMobilityManagement, nas.MsgTypeSecurityModeCommand, smcReq)
	if err != nil {
		return err
	}
	pdu, err := h.integrityProtectNAS(ue, plain, nas.SecurityHeaderIntegrityProtectedWithNewSC)
	if err != nil {
		return err
	}
	h.logNASOut(ue, nas.MsgTypeSecurityModeCommand)
	// T3560, TS 24.501 §5.4.2.2; retransmissions re-protect with a fresh NAS COUNT
	return h.sendRegProcProtected(ue, amfctx.RegStageSMC, pdu, plain, nas.SecurityHeaderIntegrityProtectedWithNewSC)
}

// ---- Authentication Failure ---------------------------------------------

func (h *Handler) handleAuthenticationFailure(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

	af, ok := msg.Body.(*nas.AuthenticationFailure)
	if !ok {
		return fmt.Errorf("nas: AuthenticationFailure body decode failed")
	}
	ue.StopRegTimer() // T3560 stopped by the UE's answer, TS 24.501 §5.4.1.3.5
	h.logger.Warn("Authentication Failure from UE",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"cause", af.Cause5GMM,
		"spec_ref", "TS 24.501 §8.2.3",
	)

	switch {
	case af.Cause5GMM == nas.CausengKSIAlreadyInUse && ue.AuthNgKSIFailures < maxNgKSIInUseFailures:
		// First #71: select a new ngKSI and send the same 5G authentication
		// challenge. Ref: TS 24.501 §5.4.1.3.7 e)
		ue.AuthNgKSIFailures++
		authReq := h.reg.RepeatChallengeWithNewNGKSI(ue)
		pdu, err := h.sendNASPlain(ue, nas.PDMobilityManagement, nas.MsgTypeAuthenticationRequest, authReq)
		if err != nil {
			return err
		}
		h.logger.Info("ngKSI already in use — re-sending the same challenge with a new ngKSI",
			"procedure", "InitialRegistration",
			"amf_ue_ngap_id", ue.AMFUENGAPId,
			"interface", "N1",
			"direction", "OUT",
			"message_type", "AuthenticationRequest",
			"ngksi", authReq.NGKSI.KeySetIdentifier,
			"spec_ref", "TS 24.501 §5.4.1.3.7 e)",
		)
		return h.sendRegProc(ue, amfctx.RegStageAuth, pdu)

	case (af.Cause5GMM == nas.CauseMACFailure || af.Cause5GMM == nas.CauseNon5GAuthenticationUnacceptable) &&
		ue.AuthViaGUTI:
		// The challenge ran on the SUPI mapped from a 5G-GUTI: identify the UE
		// (SUCI) and restart authentication with it; a failure of the SUCI-based
		// challenge then ends with AUTHENTICATION REJECT.
		// Ref: TS 24.501 §5.4.1.3.7 c), d), §5.4.1.3.5
		ue.AuthViaGUTI = false
		return h.sendIdentityRequest(ctx, ue)

	case af.Cause5GMM == nas.CauseSynchFailure && len(af.AUTS) == autsLen &&
		ue.AuthSynchFailures < maxSynchFailures:
		// TS 23.502 §4.2.2.2.2 step 11: re-synchronise with the AUTS and restart
		// authentication; a second consecutive #21 ends with AUTHENTICATION REJECT.
		// Ref: TS 33.501 §6.1.3.2 step 11; TS 24.501 §5.4.1.3.7 f) NOTE 4
		ue.AuthSynchFailures++
		h.logger.Info("SQN sync failure — initiating resync with AUSF",
			"procedure", "InitialRegistration",
			"amf_ue_ngap_id", ue.AMFUENGAPId,
			"interface", "N12",
			"direction", "OUT",
			"spec_ref", "TS 33.501 §6.1.3.2 step 11",
		)
		authReq, err := h.reg.Phase1_ResyncAuth(ctx, ue, af.AUTS)
		if err != nil {
			h.logger.Error("resync authentication failed", "error", err,
				"amf_ue_ngap_id", ue.AMFUENGAPId)
			return h.rejectAuthentication(ctx, ue, af.Cause5GMM, "TS 24.501 §5.4.1.3.7 f)")
		}
		// Full plain NAS message (EPD, security header, message type + body):
		// nas.EncodeAuthenticationRequest alone yields only the body, which the
		// UE cannot parse. Ref: TS 24.501 §8.2.1.1
		nasPDU, err := h.sendNASPlain(ue, nas.PDMobilityManagement, nas.MsgTypeAuthenticationRequest, authReq)
		if err != nil {
			return fmt.Errorf("nas: encode AuthenticationRequest: %w", err)
		}
		h.logger.Info("sending new Authentication Request after resync",
			"procedure", "InitialRegistration",
			"amf_ue_ngap_id", ue.AMFUENGAPId,
			"interface", "N1",
			"direction", "OUT",
			"message_type", "AuthenticationRequest",
			"spec_ref", "TS 23.502 §4.2.2.2.2 step 11",
		)
		return h.sendRegProc(ue, amfctx.RegStageAuth, nasPDU)
	}

	// #20 / #26 on a SUCI-based challenge, a repeated #71, a second consecutive
	// #21, #21 without AUTS or any other cause: terminate the authentication with
	// AUTHENTICATION REJECT instead of abandoning it silently (the UE's T3520
	// would expire and it would bar the cell, §5.4.1.3.7 g)).
	// Ref: TS 24.501 §5.4.1.3.5, §5.4.1.3.7 c)-f)
	return h.rejectAuthentication(ctx, ue, af.Cause5GMM, "TS 24.501 §5.4.1.3.5, §5.4.1.3.7")
}

// rejectAuthentication sends a plain AUTHENTICATION REJECT, releases the N1 NAS
// signalling connection and removes the UE context (the registration failed).
// Ref: TS 24.501 §5.4.1.3.5, §8.2.5
func (h *Handler) rejectAuthentication(ctx context.Context, ue *amfctx.UEContext,
	ueCause nas.Cause5GMM, specRef string) error {
	h.logger.WarnContext(ctx, "authentication not accepted — sending AUTHENTICATION REJECT",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"interface", "N1",
		"direction", "OUT",
		"message_type", "AuthenticationReject",
		"result", "REJECT",
		"cause", int(ueCause),
		"spec_ref", specRef,
	)
	metrics.ProcedureTotal.WithLabelValues("AMF", "InitialRegistration", "REJECT").Inc()
	// AUTHENTICATION REJECT without the optional EAP message IE: EPD, plain
	// security header, message type (TS 24.501 §8.2.5.1).
	pdu := []byte{nas.PDMobilityManagement, byte(nas.SecurityHeaderPlainNAS), byte(nas.MsgTypeAuthenticationReject)}
	if err := h.sender.SendDownlinkNASTransport(ue, pdu); err != nil {
		return fmt.Errorf("nas: send AuthenticationReject: %w", err)
	}
	h.releaseAfterReject(ctx, ue, ngapCauseNasAuthenticationFailure)
	return nil
}

// rejectRegistrationPlain sends a plain REGISTRATION REJECT (no NAS security
// context exists yet), releases the N1 NAS signalling connection and removes
// the UE context. Ref: TS 24.501 §5.5.1.2.5, §5.5.1.2.8
func (h *Handler) rejectRegistrationPlain(ctx context.Context, ue *amfctx.UEContext,
	cause nas.Cause5GMM, specRef string) error {
	return h.rejectRegistration(ctx, ue, cause, specRef, false)
}

// rejectRegistration sends a REGISTRATION REJECT with cause - integrity protected
// and ciphered when protected (the UE's message came under the NAS security
// context), plain otherwise - then releases the N1 NAS signalling connection and
// removes the UE context. Ref: TS 24.501 §5.5.1.2.5, §5.5.1.2.8, §4.4.4.3
func (h *Handler) rejectRegistration(ctx context.Context, ue *amfctx.UEContext,
	cause nas.Cause5GMM, specRef string, protected bool) error {
	ue.ClearRegProc()
	var (
		pdu []byte
		err error
	)
	body := &nas.RegistrationReject{Cause5GMM: byte(cause)}
	if cause == nas.CauseCongestion {
		// #22: the AMF assigns a back-off timer T3346. Ref: TS 24.501 §5.5.1.2.5
		backoff := procedures.CongestionBackoffT3346
		body.T3346 = &backoff
	}
	if protected && ue.SecurityCtx.Active {
		pdu, err = h.sendNASSecured(ue, nas.PDMobilityManagement, nas.MsgTypeRegistrationReject, body)
	} else {
		pdu, err = h.sendNASPlain(ue, nas.PDMobilityManagement, nas.MsgTypeRegistrationReject, body)
	}
	if err != nil {
		return err
	}
	h.logger.WarnContext(ctx, "sending REGISTRATION REJECT",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"interface", "N1",
		"direction", "OUT",
		"message_type", "RegistrationReject",
		"result", "REJECT",
		"cause", int(cause),
		"spec_ref", specRef,
	)
	if err := h.sender.SendDownlinkNASTransport(ue, pdu); err != nil {
		return fmt.Errorf("nas: send RegistrationReject: %w", err)
	}
	h.releaseAfterReject(ctx, ue, ngapCauseNasNormalRelease)
	return nil
}

// rejectNoNetworkSlices sends a security-protected REGISTRATION REJECT #62
// "No network slices available" listing every requested S-NSSAI, then releases
// the N2 connection and the UE context. The rejected NSSAI goes in the Extended
// rejected NSSAI IE when the UE set the ER-NSSAI capability (as the NSSAA
// Configuration Update path does), else in the Rejected NSSAI IE.
// Ref: TS 24.501 §5.5.1.2.5, §9.11.3.46, §9.11.3.75
func (h *Handler) rejectNoNetworkSlices(ctx context.Context, ue *amfctx.UEContext,
	rejected []nas.RejectedSNSSAI) error {
	body := &nas.RegistrationReject{Cause5GMM: byte(nas.CauseNoNetworkSlicesAvailable)}
	if ue.ERNSSAISupported {
		body.ExtendedRejectedNSSAI = nas.ExtendedRejectedNSSAIFromList(rejected)
	} else {
		body.RejectedNSSAI = rejected
	}
	// The N2 and UE contexts are released even when the reject cannot be sent.
	defer h.releaseAfterReject(ctx, ue, ngapCauseNasNormalRelease)
	pdu, err := h.sendNASSecured(ue, nas.PDMobilityManagement, nas.MsgTypeRegistrationReject, body)
	if err != nil {
		return fmt.Errorf("nas: build RegistrationReject: %w", err)
	}
	h.logger.WarnContext(ctx, "sending REGISTRATION REJECT",
		"nf", "AMF",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"interface", "N1",
		"direction", "OUT",
		"message_type", "RegistrationReject",
		"result", "REJECT",
		"cause", int(nas.CauseNoNetworkSlicesAvailable),
		"rejected_nssai_count", len(rejected),
		"spec_ref", "TS 24.501 §5.5.1.2.5",
	)
	if err := h.sender.SendDownlinkNASTransport(ue, pdu); err != nil {
		return fmt.Errorf("nas: send RegistrationReject: %w", err)
	}
	return nil
}

// releaseAfterReject releases the N2 UE context with NGAP cause NAS/causeValue
// and removes the UE context: through the release completion when the command
// was sent, locally otherwise. Ref: TS 38.413 §8.3.3
func (h *Handler) releaseAfterReject(ctx context.Context, ue *amfctx.UEContext, causeValue int64) {
	if !h.releaseN2(ue, ngapCausePresentNas, causeValue, true) {
		h.reg.RemoveUEContext(ctx, ue)
	}
}

// n2AssociationChecker is implemented by the NGAP server: it tells a sent UE
// CONTEXT RELEASE COMMAND from the silent skip of SendUEContextReleaseCommandForUE.
type n2AssociationChecker interface {
	HasN2Association(ue *amfctx.UEContext) bool
}

// releaseN2 sends a UE CONTEXT RELEASE COMMAND for ue (remove=true marks the
// context PendingRemoval first so the release completion removes it). It
// returns false when nothing was sent (no N2 association or send error); the
// PendingRemoval mark is then undone. Ref: TS 38.413 §8.3.3
func (h *Handler) releaseN2(ue *amfctx.UEContext, causePresent int, causeValue int64, remove bool) bool {
	if c, ok := h.sender.(n2AssociationChecker); ok && !c.HasN2Association(ue) {
		return false
	}
	if remove {
		ue.Lock()
		ue.PendingRemoval = true
		ue.Unlock()
	}
	if err := h.sender.SendUEContextReleaseCommandForUE(ue, causePresent, causeValue); err != nil {
		h.logger.Warn("UE Context Release Command failed",
			"procedure", "ANRelease", "interface", "N2", "direction", "OUT",
			"amf_ue_ngap_id", ue.AMFUENGAPId, "result", "FAILURE", "error", err,
			"spec_ref", "TS 38.413 §8.3.3")
		if remove {
			ue.Lock()
			ue.PendingRemoval = false
			ue.Unlock()
		}
		return false
	}
	return true
}

// ReleaseAfterPanic is the amfctx.PanicReleaser of the AMF (wired in cmd/amf):
// after a recovered panic on a UE's serial queue it releases the UE's N2
// context with cause misc/unspecified. remove=true (UE not 5GMM-REGISTERED)
// also removes the context on the release completion; a registered UE keeps
// its registration and goes CM-IDLE. Returns true when the command was sent.
// Ref: TS 38.413 §8.3.3
func (h *Handler) ReleaseAfterPanic(ctx context.Context, ue *amfctx.UEContext, remove bool) bool {
	sent := h.releaseN2(ue, ngapCausePresentMisc, ngapCauseMiscUnspecified, remove)
	h.logger.WarnContext(ctx, "UE released after a recovered panic",
		"procedure", amfctx.PanicRecoveryProcedure,
		"interface", "N2",
		"direction", "OUT",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"remove", remove,
		"release_sent", sent,
		"result", "FAILURE",
		"cause", amfctx.PanicRecoveryCause,
		"spec_ref", "TS 38.413 §8.3.3",
	)
	return sent
}

// ---- Security Mode Reject -----------------------------------------------

// handleSecurityModeReject handles Security Mode Reject from the UE.
// Per TS 24.501 §5.5.1.2.7: AMF shall abandon the registration procedure.
// Cause 24 (0x18) from UERANSIM v3.2.8 covers MAC verification failure AND
// UE security capabilities mismatch — add key-chain debug logging so we can
// compare KNASint values between AMF and UE on the next run.
func (h *Handler) handleSecurityModeReject(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

	smr, ok := msg.Body.(*nas.SecurityModeReject)
	if !ok {
		return fmt.Errorf("nas: SecurityModeReject body decode failed")
	}

	h.logger.Error("Security Mode Reject received — registration aborted",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"cause", fmt.Sprintf("%d (0x%02X)", smr.Cause5GMM, smr.Cause5GMM),
		"interface", "N1",
		"direction", "IN",
		"message_type", "SecurityModeReject",
		"spec_ref", "TS 24.501 §8.2.27 / §5.5.1.2.7",
	)

	// The SECURITY MODE COMMAND is answered (T3560 stopped); the procedure is abandoned.
	ue.ClearRegProc()
	// Only the new, unconfirmed context is dropped; the context in use before the
	// SECURITY MODE COMMAND keeps protecting this and every later message.
	// Ref: TS 24.501 §5.4.2.5
	h.rollbackSecurityCtx(ue, "SecurityModeReject")
	return nil
}

// rollbackSecurityCtx drops the security context a pending SECURITY MODE COMMAND
// was taking into use and re-applies the one in use before it.
// Ref: TS 24.501 §5.4.2.5
func (h *Handler) rollbackSecurityCtx(ue *amfctx.UEContext, reason string) {
	pending, restored := ue.RollbackSecurityCtxChange()
	if !pending {
		return
	}
	h.logger.Info("new 5G NAS security context dropped",
		"nf", "AMF", "procedure", "InitialRegistration", "interface", "N1", "direction", "IN",
		"amf_ue_ngap_id", ue.AMFUENGAPId, "supi", ue.SUPI, "reason", reason,
		"previous_context_restored", restored, "result", "REJECT",
		"spec_ref", "TS 24.501 §5.4.2.5")
}

// ---- Security Mode Complete ---------------------------------------------

func (h *Handler) handleSecurityModeComplete(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

	// SECURITY MODE COMPLETE only answers an outstanding SECURITY MODE COMMAND: a
	// duplicate or unsolicited one must not re-run Phase3 (second UECM PUT, PCF
	// associations, 5G-GUTI, ICS). Ref: TS 24.501 §5.4.2.4, §4.4.4.3 b)
	if !h.acceptSolicited(ue, amfctx.RegStageSMC, "SecurityModeComplete", "TS 24.501 §5.4.2.4") {
		return nil
	}
	ue.ClearRegProc() // T3560 stopped
	// SECURITY MODE COMPLETE verified with the new context: it is now the one in use.
	// Ref: TS 24.501 §5.4.2.4
	ue.CommitSecurityCtxChange()

	var sessSync regSessionSync
	// Process the Security Mode Complete payload before completing registration:
	//   - IMEISV: requested in the SMC (IEI 0xE-); store as the UE's PEI.
	//   - NAS message container: the retransmitted complete Registration Request.
	//     A real UE sends only cleartext IEs in the unprotected initial message
	//     (TS 24.501 §4.4.6), so the non-cleartext IEs — Requested NSSAI, 5GMM
	//     capability — are only visible here. Must be applied before Phase3
	//     computes the Allowed NSSAI. Ref: TS 24.501 §5.4.2.3.
	if smcComplete, ok := msg.Body.(*nas.SecurityModeComplete); ok {
		if smcComplete.IMEISV != nil && smcComplete.IMEISV.IMEISV != "" {
			ue.PEI = "imeisv-" + smcComplete.IMEISV.IMEISV
			h.logger.Info("IMEISV received in SecurityModeComplete",
				"procedure", "InitialRegistration",
				"amf_ue_ngap_id", ue.AMFUENGAPId,
				"supi", ue.SUPI,
				"pei", ue.PEI,
				"spec_ref", "TS 24.501 §8.2.26",
			)
		}
		if len(smcComplete.NASMessageContainer) > 0 {
			if inner := h.applyRetransmittedRegistrationRequest(ue, smcComplete.NASMessageContainer); inner != nil {
				// PDU session status / Uplink data status of the complete request.
				// Ref: TS 24.501 §5.5.1.2.2, §5.5.1.3.4
				sessSync = h.syncPDUSessions(ctx, ue, inner, h.logger.With(
					"nf", "AMF", "procedure", "InitialRegistration", "interface", "N1",
					"direction", "IN", "amf_ue_ngap_id", ue.AMFUENGAPId, "supi", ue.SUPI))
			}
		}
	}

	// Phase 3: fetch subscription data, assign GUTI, build RegistrationAccept
	regAccept, err := h.reg.Phase3_ProcessSMCComplete(ctx, ue)
	if err != nil {
		// No allowed slice (and none pending NSSAA): REGISTRATION REJECT #62 with
		// the Rejected NSSAI, then release the N2 connection.
		// Ref: TS 24.501 §5.5.1.2.5; TS 23.502 §4.2.2.2.2 step 21
		var noSlices *procedures.NoNetworkSlicesError
		if errors.As(err, &noSlices) {
			return h.rejectNoNetworkSlices(ctx, ue, noSlices.Rejected)
		}
		return fmt.Errorf("registration phase3: %w", err)
	}

	sessSync.applyTo(regAccept)

	// RegistrationAccept must be integrity-protected (NAS security now active).
	// Ref: TS 24.501 §5.5.1.2.4 step 14, TS 33.501 §6.7.2
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeRegistrationAccept, regAccept)
	if err != nil {
		return err
	}

	// NSSAA-only: every requested slice awaits NSSAA, so there is no Allowed
	// NSSAI and the mandatory Allowed NSSAI IE of the INITIAL CONTEXT SETUP
	// REQUEST cannot be built (TS 38.413 §9.2.2.1): deliver the Accept (with the
	// Pending NSSAI) in DOWNLINK NAS TRANSPORT, no ICS.
	// Ref: TS 24.501 §5.5.1.2.4; TS 23.502 §4.2.9.2
	if len(ue.AllowedNSSAI) == 0 {
		h.logger.Info("Registration Accept without Allowed NSSAI — DL NAS TRANSPORT, no ICS",
			"nf", "AMF",
			"procedure", "InitialRegistration",
			"amf_ue_ngap_id", ue.AMFUENGAPId,
			"supi", ue.SUPI,
			"interface", "N1",
			"direction", "OUT",
			"message_type", "RegistrationAccept",
			"spec_ref", "TS 24.501 §5.5.1.2.4",
		)
		if err := h.sender.SendDownlinkNASTransport(ue, nasPDU); err != nil {
			return err
		}
		h.afterAcceptSent(ue, regAccept, nasPDU)
		return nil
	}

	// KgNB is derived from KAMF and the NAS uplink COUNT of the message that
	// triggered AS security activation — here the Security Mode Complete. The
	// UE derives KgNB from that same count, so the two must match exactly or the
	// gNB's RRC Security Mode Command fails the UE's MAC check (real gNB replies
	// InitialContextSetupFailure, RadioNetwork=failure-in-radio-interface-procedure).
	// unwrapNASSecurity already incremented UplinkCount while decoding the Security
	// Mode Complete, so the triggering message's count is UplinkCount-1 — matching
	// the Service Request and Registration Update paths below.
	// Ref: TS 33.501 §A.9, TS 38.413 §8.3.1
	kgnbBytes := kdf.KgNB(ue.SecurityCtx.KAMF, ue.SecurityCtx.UplinkCount-1, 0x01)
	var secKey [32]byte
	copy(secKey[:], kgnbBytes)
	ue.SetKgNB(secKey) // also restarts the NH chain, TS 33.501 §6.9.2.1.1

	// Build UE security capability bitmasks for NGAP from what the UE reported
	// in the RegistrationRequest (UESecurityCapability IE).
	// Bit 15=NEA1/NIA1, bit 14=NEA2/NIA2, bit 13=NEA3/NIA3.
	var encAlgs, intAlgs uint16
	if ue.UESecCapEA[1] {
		encAlgs |= 1 << 15
	}
	if ue.UESecCapEA[2] {
		encAlgs |= 1 << 14
	}
	if ue.UESecCapEA[3] {
		encAlgs |= 1 << 13
	}
	if ue.UESecCapIA[1] {
		intAlgs |= 1 << 15
	}
	if ue.UESecCapIA[2] {
		intAlgs |= 1 << 14
	}
	if ue.UESecCapIA[3] {
		intAlgs |= 1 << 13
	}

	h.logger.Info("sending InitialContextSetupRequest",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"interface", "N2",
		"direction", "OUT",
		"message_type", "InitialContextSetupRequest",
		"spec_ref", "TS 38.413 §8.3.1",
	)
	ue.SetPendingICS(amfctx.ICSInitialRegistration) // failure -> rollback (AMF-034)
	if err := h.sender.SendInitialContextSetupRequest(ue, nasPDU, secKey,
		ue.SecurityCtx.CipheringAlgID, ue.SecurityCtx.IntegrityAlgID,
		encAlgs, intAlgs, sessSync.Items); err != nil {
		ue.TakePendingICS() // nothing in flight: a stale kind would mis-handle a later failure
		return err
	}
	// N2 context now established — UE is CM-CONNECTED.
	ue.CMState = amfctx.CMConnected
	h.afterAcceptSent(ue, regAccept, nasPDU)
	return nil
}

// afterAcceptSent runs once the REGISTRATION ACCEPT was sent. With a new 5G-GUTI
// (always, today) T3550 is started and the UE enters
// 5GMM-COMMON-PROCEDURE-INITIATED until the REGISTRATION COMPLETE; without one the
// UE enters 5GMM-REGISTERED right away.
// Ref: TS 24.501 §5.5.1.2.4, §5.5.1.3.4
func (h *Handler) afterAcceptSent(ue *amfctx.UEContext, accept *nas.RegistrationAccept, pdu []byte) {
	// A mobility / periodic update received while the UE is still in
	// 5GMM-COMMON-PROCEDURE-INITIATED stays a registration update, not an initial
	// registration. Ref: TS 24.501 §5.5.1.2.8 g), §5.5.1.3.8
	updateReq := ue.LastRegIsUpdate()
	ue.Lock()
	prior := ue.State == amfctx.GMMRegistered ||
		(ue.State == amfctx.GMMCommonProcedureInitiated && updateReq)
	if accept.FiveGGUTI == nil {
		ue.TransitionTo(amfctx.GMMRegistered)
		ue.Unlock()
		ue.ClearRegProc()
		return
	}
	ue.TransitionTo(amfctx.GMMCommonProcedureInitiated)
	ue.Unlock()
	// The plain Accept is kept: every T3550 retransmission re-protects it with a
	// fresh downlink NAS COUNT. Ref: TS 24.501 §4.4.3.1
	plain, err := h.sendNASPlain(ue, nas.PDMobilityManagement, nas.MsgTypeRegistrationAccept, accept)
	if err != nil {
		h.logger.Warn("REGISTRATION ACCEPT re-encode failed - T3550 not started", "error", err,
			"amf_ue_ngap_id", ue.AMFUENGAPId, "spec_ref", "TS 24.501 §5.5.1.2.4")
		return
	}
	ue.SetPendingAccept(plain, prior)
	h.armRegTimer(ue, &amfctx.RegRetx{Stage: amfctx.RegStageAcceptSent, Timer: regTimerT3550,
		PDU: pdu, Plain: plain, SHT: byte(nas.SecurityHeaderIntegrityProtectedAndCiphered)}, 0) // T3550
}

// acceptSolicited reports whether the UE's message answers the outstanding
// procedure (want); an unsolicited or duplicate one is logged and must be ignored.
// Ref: TS 24.501 §4.4.4.3 b), §5.5.1.2.8
func (h *Handler) acceptSolicited(ue *amfctx.UEContext, want amfctx.RegStage, msgName, specRef string) bool {
	if got := ue.RegStage(); got != want {
		h.logger.Warn("unsolicited NAS message ignored",
			"nf", "AMF", "procedure", "InitialRegistration", "interface", "N1", "direction", "IN",
			"amf_ue_ngap_id", ue.AMFUENGAPId, "supi", ue.SUPI, "message_type", msgName,
			"pending_stage", got.String(), "expected_stage", want.String(),
			"result", "IGNORED", "spec_ref", specRef)
		return false
	}
	return true
}

// applyRetransmittedRegistrationRequest decodes the complete Registration
// Request the UE retransmitted in the Security Mode Complete's NAS message
// container (in response to the RINMR bit in the Security Mode Command) and
// applies the non-cleartext IEs to the UE context: Requested NSSAI (drives the
// Allowed NSSAI intersection in Phase3), ER-NSSAI and 5GMM capability. It returns
// the decoded request (nil when unusable) so the caller can also process its PDU
// session IEs. Decode failures are
// logged and ignored — the registration continues with the cleartext IEs.
// Ref: TS 24.501 §4.4.6, §5.4.2.3; TS 23.502 §4.2.2.2.2
func (h *Handler) applyRetransmittedRegistrationRequest(ue *amfctx.UEContext, container []byte) *nas.RegistrationRequest {
	inner, err := nas.Decode(container)
	if err != nil {
		h.logger.Warn("SecurityModeComplete NAS message container decode failed",
			"amf_ue_ngap_id", ue.AMFUENGAPId, "error", err,
			"spec_ref", "TS 24.501 §5.4.2.3")
		return nil
	}
	regReq, ok := inner.Body.(*nas.RegistrationRequest)
	if !ok || inner.Header.MessageType != nas.MsgTypeRegistrationRequest {
		return nil
	}
	if regReq.RequestedNSSAI != nil {
		ue.RequestedNSSAI = nssaiToSubscribed(regReq.RequestedNSSAI)
	}
	ue.ERNSSAISupported = regReq.ERNSSAISupported() // complete IE set of the retransmitted request
	// The 5GMM capability IE is a non-cleartext IE, so the cleartext initial
	// message lacks it; the complete request is the first place it is visible.
	// Ref: TS 24.501 §4.4.6, §9.11.3.1
	if c := regReq.Capability5GMM(); c != nil {
		ue.Capability5GMM = c
	}
	h.logger.Info("retransmitted Registration Request processed from SecurityModeComplete",
		"procedure", "InitialRegistration",
		"interface", "N1",
		"direction", "IN",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"requested_nssai_count", len(ue.RequestedNSSAI),
		"capability_5gmm", ue.Capability5GMM.RawHex(),
		"capability_5gmm_bits", strings.Join(ue.Capability5GMM.SetBitNames(), ","),
		"spec_ref", "TS 24.501 §4.4.6",
	)
	return regReq
}

// ---- Registration Complete ----------------------------------------------

func (h *Handler) handleRegistrationComplete(
	ctx context.Context, ue *amfctx.UEContext) error {

	// REGISTRATION COMPLETE only answers a REGISTRATION ACCEPT awaiting it: T3550 is
	// stopped and the UE enters 5GMM-REGISTERED. Ref: TS 24.501 §5.5.1.2.4, §5.5.1.3.4
	if !h.acceptSolicited(ue, amfctx.RegStageAcceptSent, "RegistrationComplete", "TS 24.501 §5.5.1.2.4") {
		return nil
	}
	ue.ClearRegProc() // T3550 stopped
	ue.Lock()
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.Unlock()

	h.logger.Info("Registration Complete",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"guti", gutiStr(ue),
		"interface", "N1",
		"direction", "IN",
		"message_type", "RegistrationComplete",
		"result", "OK",
		"spec_ref", "TS 23.502 §4.2.2.2.2 step 21",
	)
	// Registration time is refreshed only when a Registration Complete arrives.
	// Per TS 24.501 §5.5.1.3.4 the UE sends it only when the Registration Accept
	// carried a new 5G-GUTI (or another IE requiring acknowledgement), i.e. on
	// initial registration and on updates that reallocate the GUTI; a periodic or
	// mobility update accepted without a new GUTI does not refresh it. Surfaced
	// in the UE snapshot.
	ue.Lock()
	ue.RegistrationTime = time.Now()
	ue.Unlock()

	// The new 5G-GUTI is now in use: the previous 5G-TMSI stops resolving.
	// Ref: TS 24.501 §5.5.1.2.4, §5.5.1.3.8 a) 1) i)
	h.reg.ConfirmGUTI(ue)

	// Persist the fully registered UE context so it survives AMF restarts.
	h.reg.PersistUE(ctx, ue)

	// UE is registered and CM-CONNECTED — cancel the CM-IDLE reachability
	// watchdogs (re-armed on AN Release). Ref: TS 23.501 §5.3.2
	h.notifyUEReachable(ue)

	// Step 17b delivery: if the PCF provided a UE policy container during Phase3,
	// deliver it now via the UE policy delivery service (DL NAS TRANSPORT, payload
	// container type 0x05). The UE is CM-CONNECTED (InitialContextSetupRequest was
	// sent before RegistrationComplete arrived).
	// Ref: TS 23.502 §4.2.2.2.2 step 17b, §4.2.4.3; TS 24.501 Annex D
	ue.Lock()
	pending := ue.PendingPolicyContainer
	ue.PendingPolicyContainer = nil
	ue.Unlock()

	if len(pending) > 0 {
		if sendErr := h.SendUEPolicyContainer(ctx, ue, pending); sendErr != nil &&
			!errors.Is(sendErr, procedures.ErrNotConnected) {
			h.logger.Warn("auto UE policy delivery after RegistrationComplete failed",
				"procedure", "UEPolicyDelivery",
				"supi", ue.SUPI,
				"error", sendErr,
				"spec_ref", "TS 23.502 §4.2.4.3",
			)
		}
	}

	// Push the operator name now that the UE is registered and CM-CONNECTED.
	// No-op unless a name is configured. Ref: TS 24.501 §8.2.19
	h.sendNetworkNameConfigUpdate(ue)

	// Network Slice-Specific Authentication: kick off the first slice's EAP exchange
	// for any S-NSSAI withheld in Phase3 (subjectToNssaa). No-op when none are pending.
	// Ref: TS 23.502 §4.2.9.2, TS 24.501 §5.4.7.
	h.StartNSSAA(ctx, ue)
	return nil
}

// sendNetworkNameConfigUpdate delivers the operator name to the UE in a
// Configuration Update Command. It is a no-op when no name is configured.
//
// The ACK bit is deliberately NOT set. TS 24.501 §9.11.3.18 has the UE reply
// with a Configuration Update Complete only when asked, and nothing here needs
// that confirmation: a name push carries no state the AMF must reconcile. Not
// asking also means a handset that ignores the name cannot leave a procedure
// half-finished.
//
// Whether the name reaches the status bar is up to the handset. The modem may
// prefer the SIM's EF_SPN or its own PLMN table over what the network sends.
// Ref: TS 24.501 §8.2.19, §9.11.3.35, §9.11.3.36
func (h *Handler) sendNetworkNameConfigUpdate(ue *amfctx.UEContext) {
	if h.networkFullName == "" && h.networkShortName == "" {
		return
	}
	cmd := &nas.ConfigurationUpdateCommand{
		FullNameForNetwork:  h.networkFullName,
		ShortNameForNetwork: h.networkShortName,
	}
	if err := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
		nas.MsgTypeConfigurationUpdateCommand, cmd); err != nil {
		h.logger.Warn("network name Configuration Update Command send failed",
			"procedure", "NetworkName", "supi", ue.SUPI, "error", err,
			"spec_ref", "TS 24.501 §8.2.19")
		return
	}
	h.logger.Info("Configuration Update Command sent with network name",
		"procedure", "NetworkName", "supi", ue.SUPI,
		"full_name", h.networkFullName, "short_name", h.networkShortName,
		"interface", "N1", "direction", "OUT",
		"spec_ref", "TS 24.501 §8.2.19")
}

// StartNSSAA sends the NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND for the first
// slice withheld for NSSAA, if any. Safe to call when no slice is pending.
// Ref: TS 23.502 §4.2.9.2, TS 24.501 §8.2.31.
//
// Must run on the UE's serial queue (like every NAS handler): it mutates the
// NSSAA state of the UE. The COMMAND is supervised by T3575 under the rel19
// profile.
func (h *Handler) StartNSSAA(ctx context.Context, ue *amfctx.UEContext) {
	cmd, started := h.reg.StartNSSAA(ctx, ue)
	if !started {
		return
	}
	h.sendNSSAACommand(ue, cmd, 0)
}

// handleNSSAAComplete processes a NETWORK SLICE-SPECIFIC AUTHENTICATION COMPLETE:
// relays the EAP-Response to the AAA-S via AUSF, sends the RESULT, advances to the
// next pending slice, and issues a Configuration Update Command if the Allowed NSSAI
// changed. Ref: TS 23.502 §4.2.9.2 step 5-9, TS 24.501 §5.4.7.3.
func (h *Handler) handleNSSAAComplete(ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {
	complete, ok := msg.Body.(*nas.NSSAAuthComplete)
	if !ok {
		return fmt.Errorf("nas: NSSAAuthComplete body decode failed")
	}
	h.logger.Info("NSSAA COMPLETE received",
		"procedure", "NSSAA", "supi", ue.SUPI,
		"sst", complete.SNSSAI.SST,
		"interface", "N1", "direction", "IN",
		"message_type", "NetworkSliceSpecificAuthComplete",
		"spec_ref", "TS 24.501 §8.2.32",
	)

	// Runs on the UE's serial queue: the Nnssaaf call below holds the queue, not
	// an NSSAA-only lock, so no other path mutates the same fields meanwhile and
	// a T3575 expiry waits behind this task (then finds the timer stopped).
	out, err := h.reg.ProcessNSSAAComplete(ctx, ue, complete)
	if err != nil {
		h.logger.Warn("NSSAA COMPLETE processing failed",
			"procedure", "NSSAA", "supi", ue.SUPI, "error", err)
		return nil
	}
	// COMPLETE accepted: T3575 stops (a following COMMAND restarts it).
	// Ref: TS 24.501 §5.4.7.2.2
	h.stopNSSAAT3575(ue)

	// Send the RESULT (EAP-Success / EAP-Failure) for the resolved slice. A nil
	// Result means the slice was kept PENDING (no EAP result to relay).
	if out.Result != nil {
		if sendErr := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
			nas.MsgTypeNetworkSliceSpecificAuthResult, out.Result); sendErr != nil {
			h.logger.Warn("NSSAA RESULT send failed",
				"procedure", "NSSAA", "supi", ue.SUPI, "error", sendErr)
		}
	}

	// Start the next pending slice, if any.
	if out.NextCommand != nil {
		h.sendNSSAACommand(ue, out.NextCommand, 0)
		return nil
	}

	// Queue drained: one Configuration Update Command with the new Allowed NSSAI
	// (rel19: and the Rejected NSSAI of every failed slice, TS 23.502 §4.2.9.2
	// step 19a). rel17: only when the last COMPLETE was authorized.
	h.finishNSSAA(ctx, ue, out)
	h.reg.PersistUE(ctx, ue)
	return nil
}

// onUESerialQueue runs f on ue's serial queue and waits for it to finish, so a
// caller outside the NGAP path (the O&M trigger endpoints) mutates the UE's
// NSSAA state in the same order as its NAS handlers instead of racing them. It
// must not be called from a task already on that queue.
func onUESerialQueue(ue *amfctx.UEContext, f func()) {
	done := make(chan struct{})
	ue.EnqueueSerial(func() {
		defer close(done)
		f()
	})
	<-done
}

// RevokeNSSAASlice handles an AAA-initiated NSSAA revocation (TS 23.502 §4.2.9.4):
// removes the slice from the Allowed NSSAI and delivers the updated Allowed NSSAI to
// the UE via a Configuration Update Command (rel19: with the Rejected NSSAI too, or
// the network-initiated de-registration when no S-NSSAI is left, TS 24.501
// §4.6.2.4 c)). The UE's NSSAAs state is updated in any case; nothing is sent to a
// UE that is not 5GMM-REGISTERED (e.g. already being de-registered). Returns true
// if the slice was allowed. Runs on the UE's serial queue.
func (h *Handler) RevokeNSSAASlice(ctx context.Context, ue *amfctx.UEContext, sst uint8, sd string) (revoked bool) {
	onUESerialQueue(ue, func() {
		var dereg, cuc bool
		if revoked, dereg, cuc = h.reg.ApplyNSSAARevocation(ue, sst, sd); !revoked {
			return
		}
		if !h.nssaaMayNotifyUE(ue, "revocation") {
			return
		}
		if dereg {
			h.deregisterForNSSAA(ctx, ue)
		} else if cuc {
			h.sendNSSAAConfigUpdate(ctx, ue)
		}
		h.reg.PersistUE(ctx, ue)
	})
	return revoked
}

// ReauthNSSAASlice handles an AAA-initiated NSSAA re-authentication (TS 23.502
// §4.2.9.3): re-queues an allowed slice and starts a fresh EAP exchange. Returns true
// if the slice was allowed and a COMMAND was emitted. Runs on the UE's serial queue.
func (h *Handler) ReauthNSSAASlice(ctx context.Context, ue *amfctx.UEContext, sst uint8, sd string) (queued bool) {
	onUESerialQueue(ue, func() {
		if !h.reg.ReauthNSSAA(ue, sst, sd) {
			return
		}
		queued = true
		h.StartNSSAA(ctx, ue)
	})
	return queued
}

// nssaaMayNotifyUE reports whether an NSSAA outcome may still be signalled to the
// UE: only in 5GMM-REGISTERED. A UE already in 5GMM-DEREGISTERED-INITIATED (a
// DEREGISTRATION REQUEST is in flight, e.g. an earlier NSSAA failure or an
// O&M-triggered de-registration) or 5GMM-DEREGISTERED must not get a second
// DEREGISTRATION REQUEST or a Configuration Update Command (TS 24.501 §5.5.2.3.1:
// the UE is being de-registered; §5.4.4.1: generic UE configuration update is a
// 5GMM-REGISTERED procedure). Runs on the UE's serial queue.
func (h *Handler) nssaaMayNotifyUE(ue *amfctx.UEContext, what string) bool {
	if ue.State == amfctx.GMMRegistered {
		return true
	}
	h.logger.Debug("NSSAA outcome not signalled: UE is not 5GMM-REGISTERED",
		"procedure", "NSSAA", "supi", ue.SUPI, "trigger", what, "gmm_state", ue.State.String(),
		"spec_ref", "TS 24.501 §5.5.2.3.1, §5.4.4.1")
	return false
}

// finishNSSAA acts on a drained NSSAA queue: the network-initiated
// de-registration with the Rejected NSSAI (rel19, no S-NSSAI left) or the
// Configuration Update Command; nothing for a UE that is not 5GMM-REGISTERED
// (nssaaMayNotifyUE). Runs on the UE's serial queue.
// Ref: TS 23.502 §4.2.9.2 steps 19a-19b, TS 24.501 §4.6.2.4 c)
func (h *Handler) finishNSSAA(ctx context.Context, ue *amfctx.UEContext, out *procedures.NSSAACompleteOutcome) {
	if !out.Deregister && !out.ConfigUpdate {
		return
	}
	if !h.nssaaMayNotifyUE(ue, "queue drained") {
		return
	}
	if out.Deregister {
		h.deregisterForNSSAA(ctx, ue)
	} else {
		h.sendNSSAAConfigUpdate(ctx, ue)
	}
}

// deregisterForNSSAA performs the network-initiated de-registration of a UE whose
// NSSAA failed or was revoked for every S-NSSAI: DEREGISTRATION REQUEST (UE
// terminated) built by procedures.NSSAADeregRequest (5GMM cause #62 "No network
// slices available", "re-registration not required", 3GPP access, the rejected
// NSSAI in the Extended rejected NSSAI IE for a UE that supports it, else in the
// Rejected NSSAI IE). The UE's Deregistration Accept then runs the usual teardown
// (PDU sessions via SMF, UDM, PCF, N2 release); T3522 supervises it (rel19).
// A failed send falls back to the Configuration Update Command with the rejected
// NSSAI so the UE is at least told; the REJECT metric counts a request that was
// really sent. A UE that is not 5GMM-REGISTERED is left alone.
// Ref: TS 24.501 §5.5.2.3.1, Table 8.2.14.1.1, §9.11.3.46, §9.11.3.75;
// TS 23.502 §4.2.9.2 step 19b
func (h *Handler) deregisterForNSSAA(ctx context.Context, ue *amfctx.UEContext) {
	if !h.nssaaMayNotifyUE(ue, "de-registration") {
		return
	}
	if len(ue.RejectedNSSAI) > nas.MaxRejectedSNSSAIs {
		h.logger.Warn("Rejected NSSAI truncated to the IE maximum",
			"procedure", "NSSAA", "supi", ue.SUPI, "max", nas.MaxRejectedSNSSAIs,
			"spec_ref", "TS 24.501 §9.11.3.46")
	}
	req := procedures.NSSAADeregRequest(ue, h.reg.UseExtendedRejectedNSSAI(ue))
	err := h.sendNetworkDeregistrationReq(ctx, ue, req,
		"NSSAA", "TS 23.502 §4.2.9.2 step 19b, TS 24.501 §5.5.2.3.1")
	if err != nil {
		h.logger.Warn("NSSAA network-initiated de-registration failed - falling back to the Configuration Update Command with the rejected NSSAI",
			"procedure", "NSSAA", "supi", ue.SUPI, "result", "FAILURE", "error", err,
			"fallback", "ConfigurationUpdateCommand",
			"spec_ref", "TS 24.501 §5.5.2.3.1, §5.4.4.2")
		h.sendNSSAAConfigUpdate(ctx, ue)
		return
	}
	metrics.ProcedureTotal.WithLabelValues("AMF", "NSSAA", "REJECT").Inc()
}

// sendNSSAAConfigUpdate delivers the post-NSSAA NSSAIs to the UE via a
// Configuration Update Command (ACK requested), built by
// procedures.NSSAAConfigUpdateCommand. Ref: TS 23.502 §4.2.9.2 step 9 / 19a,
// TS 24.501 §8.2.19, §5.4.4.2.
//
// rel17 (frozen): Allowed NSSAI only. rel19: the new Allowed NSSAI (IE omitted
// when empty) and the rejected NSSAI (cause "failed or revoked NSSAA", HPLMN
// SST/SD, TS 24.501 §9.11.3.46 NOTEs 5/6) in the Extended rejected NSSAI IE for a
// UE that supports it, else in the Rejected NSSAI IE (IEI 0x11).
func (h *Handler) sendNSSAAConfigUpdate(_ context.Context, ue *amfctx.UEContext) {
	cmd, truncated := h.reg.NSSAAConfigUpdateCommand(ue, h.reg.UseExtendedRejectedNSSAI(ue))
	if truncated {
		h.logger.Warn("Rejected NSSAI truncated to the IE maximum",
			"procedure", "NSSAA", "supi", ue.SUPI, "max", nas.MaxRejectedSNSSAIs,
			"spec_ref", "TS 24.501 §9.11.3.46")
	}
	if err := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
		nas.MsgTypeConfigurationUpdateCommand, cmd); err != nil {
		h.logger.Warn("NSSAA Configuration Update Command send failed",
			"procedure", "NSSAA", "supi", ue.SUPI, "error", err)
		return
	}
	h.logger.Info("Configuration Update Command sent with post-NSSAA Allowed NSSAI",
		"procedure", "NSSAA", "supi", ue.SUPI,
		"allowed_count", len(ue.AllowedNSSAI), "rejected_count", len(ue.RejectedNSSAI),
		"extended_rejected_nssai", cmd.ExtendedRejectedNSSAI != nil,
		"interface", "N1", "direction", "OUT",
		"spec_ref", "TS 23.502 §4.2.9.2")
}

// ---- NAS encoding helpers -----------------------------------------------

// sendNASPlain encodes a plain (unprotected) NAS PDU and returns the bytes.
// Used for AuthenticationRequest and SecurityModeCommand which are sent
// before NAS security is activated.
func (h *Handler) sendNASPlain(ue *amfctx.UEContext, epd byte, msgType nas.MessageType, body interface{}) ([]byte, error) {
	msg := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: epd,
			SecurityHeaderType:            nas.SecurityHeaderPlainNAS,
			MessageType:                   msgType,
		},
		Body: body,
	}
	pdu, err := nas.Encode(msg)
	if err != nil {
		return nil, fmt.Errorf("nas encode %02x: %w", msgType, err)
	}
	return pdu, nil
}

// integrityProtectNAS wraps the plain NAS message innerPDU with the integrity
// protection header sht using the next downlink NAS COUNT, which it increments.
// Called once per new or retransmitted message. Ref: TS 24.501 §4.4.3.1
func (h *Handler) integrityProtectNAS(ue *amfctx.UEContext, innerPDU []byte, sht nas.SecurityHeaderType) ([]byte, error) {
	epd := innerPDU[0]
	count := ue.SecurityCtx.DownlinkCount
	sqn := byte(count & 0xFF)

	macInput := make([]byte, 1+len(innerPDU))
	macInput[0] = sqn
	copy(macInput[1:], innerPDU)

	// bearer=1 for 3GPP access per TS 33.501 §6.4.3 / UERANSIM enc.cpp
	mac, err := nia.NIA2(ue.SecurityCtx.KNASint, count, 0x01, 0x01, macInput)
	if err != nil {
		return nil, fmt.Errorf("nas: NIA2: %w", err)
	}

	pdu := make([]byte, 7+len(innerPDU))
	pdu[0] = epd
	pdu[1] = byte(sht)
	copy(pdu[2:6], mac)
	pdu[6] = sqn
	copy(pdu[7:], innerPDU)

	ue.SecurityCtx.DownlinkCount++
	return pdu, nil
}

// sendNASSecured encodes a NAS PDU and wraps it with a security header
// (integrity protected + ciphered, SHT=0x02) per TS 24.501 §9.1.1.
//
// Per TS 33.501 §D.3.3: cipher first, then MAC over SQN||ciphertext (DL dir=1).
func (h *Handler) sendNASSecured(ue *amfctx.UEContext, epd byte, msgType nas.MessageType, body interface{}) ([]byte, error) {
	innerPDU, err := h.sendNASPlain(ue, epd, msgType, body)
	if err != nil {
		return nil, err
	}
	return h.cipherProtectNAS(ue, innerPDU)
}

// cipherProtectNAS wraps the plain NAS message innerPDU as "integrity protected
// and ciphered" with the next downlink NAS COUNT, which it increments. Called once
// per new or retransmitted message. Ref: TS 24.501 §4.4.3.1
func (h *Handler) cipherProtectNAS(ue *amfctx.UEContext, innerPDU []byte) ([]byte, error) {
	epd := innerPDU[0]
	count := ue.SecurityCtx.DownlinkCount
	sqn := byte(count & 0xFF)

	// Cipher inner PDU (skip for NEA0 — null cipher, inner stays plaintext).
	var ciphered []byte
	if ue.SecurityCtx.CipheringAlgID == 0 {
		ciphered = innerPDU
	} else {
		var err error
		ciphered, err = nea.NEA2(ue.SecurityCtx.KNASenc, count, 0x01, 0x01, innerPDU)
		if err != nil {
			return nil, fmt.Errorf("nas: NEA2: %w", err)
		}
	}

	// MAC over SQN || ciphertext (TS 33.501 §D.3.3 / UERANSIM enc.cpp)
	macInput := make([]byte, 1+len(ciphered))
	macInput[0] = sqn
	copy(macInput[1:], ciphered)

	mac, err := nia.NIA2(ue.SecurityCtx.KNASint, count, 0x01, 0x01, macInput)
	if err != nil {
		return nil, fmt.Errorf("nas: NIA2: %w", err)
	}

	// Once the 5G NAS security context is active, every DL NAS message is sent
	// as "integrity protected and ciphered" (SHT=0x02) per TS 24.501 §4.4.5 —
	// this holds even when the selected ciphering algorithm is 5G-EA0, where the
	// ciphering is a no-op and the inner PDU stays plaintext (handled above). Real
	// UEs (e.g. Nokia) that have activated a security context strictly require
	// SHT=0x02 and silently discard SHT=0x01 messages, breaking Registration
	// Complete and the whole registration. (UERANSIM leniently accepts 0x01.)
	sht := nas.SecurityHeaderIntegrityProtectedAndCiphered

	pdu := make([]byte, 7+len(ciphered))
	pdu[0] = epd
	pdu[1] = byte(sht)
	copy(pdu[2:6], mac)
	pdu[6] = sqn
	copy(pdu[7:], ciphered)

	ue.SecurityCtx.DownlinkCount++
	return pdu, nil
}

// unwrapNASSecurity strips the outer NAS security header from an uplink PDU.
// For ciphered messages (SHT=0x02/0x04), deciphers the inner PDU with NEA2.
// Verifies the NIA2 MAC. Increments UplinkCount.
// Returns a reconstituted PDU (outer header preserved, inner now plaintext)
// that nas.Decode can process normally.
func (h *Handler) unwrapNASSecurity(ue *amfctx.UEContext, pdu []byte) ([]byte, error) {
	return h.unwrapWithContext(&ue.SecurityCtx, pdu)
}

// unwrapWithContext is unwrapNASSecurity on an explicit security context value:
// it verifies/deciphers with sc and advances sc.UplinkCount, touching nothing else.
func (h *Handler) unwrapWithContext(sc *amfctx.SecurityContext, pdu []byte) ([]byte, error) {
	if len(pdu) < 7 {
		return nil, fmt.Errorf("nas: security PDU too short (%d bytes)", len(pdu))
	}

	sht := nas.SecurityHeaderType(pdu[1] & 0x0F)
	receivedMAC := pdu[2:6]
	sqn := pdu[6]
	inner := pdu[7:]
	ciphered := sht == nas.SecurityHeaderIntegrityProtectedAndCiphered ||
		sht == nas.SecurityHeaderIntegrityProtectedAndCipheredWithNewSC

	// Estimate the full NAS COUNT from the received 8-bit SQN. A replayed COUNT
	// (already accepted) maps to the next overflow and fails the MAC.
	// Ref: TS 24.501 §4.4.3.1; TS 33.501 §6.4.3.1
	count := estimateUplinkCount(sc.UplinkCount, sqn)

	// Per TS 33.501 §D.3.3: verify MAC over SQN || ciphertext first, then decipher.
	// MAC is over the received bytes (ciphertext for ciphered messages).
	macInput := make([]byte, 1+len(inner))
	macInput[0] = sqn
	copy(macInput[1:], inner)

	ok, err := nia.Verify(sc.KNASint, count, 0x01, 0x00, macInput, receivedMAC)
	macBad := err != nil || !ok
	if macBad {
		if err != nil {
			h.logger.Warn("NAS MAC verification error", "error", err, "count", count)
		}
		if !h.relaxedIntegrity() {
			// Nothing is trusted or advanced. The caller gets the PDU with the
			// untouched (still ciphered if SHT 2/4) body only to read the message
			// type of an integrity-only message. Ref: TS 24.501 §4.4.4.3
			// A ciphered body (NEA != 0) is never returned: its type is unreadable.
			if ciphered && sc.CipheringAlgID != 0 {
				return nil, fmt.Errorf("%w (count %d, sht %02x)", ErrNASIntegrity, count, byte(sht))
			}
			untrusted := make([]byte, len(pdu))
			copy(untrusted, pdu)
			return untrusted, fmt.Errorf("%w (count %d, sht %02x)", ErrNASIntegrity, count, byte(sht))
		}
		h.logger.Warn("NAS MAC mismatch - relaxed enforcement, processing anyway",
			"count", count, "sht", fmt.Sprintf("%02x", byte(sht)),
			"spec_ref", "TS 24.501 §4.4.4.3")
	}

	// Decipher if ciphered (SHT=0x02 or 0x04). Skip for NEA0 (null cipher — already plaintext).
	var plainInner []byte
	if ciphered && sc.CipheringAlgID != 0 {
		deciphered, err := nea.NEA2(sc.KNASenc, count, 0x01, 0x00, inner)
		if err != nil {
			return nil, fmt.Errorf("nas: NEA2 decipher: %w", err)
		}
		plainInner = deciphered
	} else {
		plainInner = make([]byte, len(inner))
		copy(plainInner, inner)
	}

	// Relaxed mode: a message with a bad MAC is processed but never advances the
	// COUNT (a forged SQN must not desynchronise the real one).
	if !macBad {
		sc.UplinkCount = count + 1 // KgNB for a Service Request uses UplinkCount-1
	}

	// Return PDU with plaintext inner so nas.Decode can strip the header and parse it
	result := make([]byte, 7+len(plainInner))
	copy(result[:7], pdu[:7])
	copy(result[7:], plainInner)
	return result, nil
}

// unwrapUplink verifies/deciphers an uplink security protected PDU with the right
// 5G NAS security context. While a SECURITY MODE COMMAND for a new context is
// outstanding, only a message protected "with new security context" (SECURITY MODE
// COMPLETE, SHT 3/4) uses the new context; anything else the UE protects (SECURITY
// MODE REJECT) uses the context in use before the procedure.
// Ref: TS 24.501 §5.4.2.3, §5.4.2.5
func (h *Handler) unwrapUplink(ue *amfctx.UEContext, pdu []byte, sht nas.SecurityHeaderType) ([]byte, error) {
	newSC := sht == nas.SecurityHeaderIntegrityProtectedWithNewSC ||
		sht == nas.SecurityHeaderIntegrityProtectedAndCipheredWithNewSC
	// The "new" context is chosen only while an SMC is really outstanding
	// (RegStageSMC); otherwise ue.SecurityCtx is the context in use.
	pending := ue.RegStage() == amfctx.RegStageSMC && ue.SecurityCtxChangePending()
	if newSC || !pending {
		return h.unwrapNASSecurity(ue, pdu)
	}
	prev := ue.PreviousSecurityCtx() // a copy: verified on an explicit value, ue.SecurityCtx is never swapped
	if prev == nil || !prev.Active {
		return h.unwrapNASSecurity(ue, pdu)
	}
	out, err := h.unwrapWithContext(prev, pdu)
	ue.StorePreviousSecurityCtx(*prev)
	return out, err
}

// sendNASSecuredViaDownlink encodes a security-protected NAS PDU and sends it
// via DownlinkNASTransport. Use only when InitialContextSetupRequest is not needed.
func (h *Handler) sendNASSecuredViaDownlink(ue *amfctx.UEContext, epd byte, msgType nas.MessageType, body interface{}) error {
	pdu, err := h.sendNASSecured(ue, epd, msgType, body)
	if err != nil {
		return err
	}
	h.logNASOut(ue, msgType)
	return h.sender.SendDownlinkNASTransport(ue, pdu)
}

func (h *Handler) logNASOut(ue *amfctx.UEContext, msgType nas.MessageType) {
	h.logger.Info("sending NAS message",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"message_type", fmt.Sprintf("%02X", msgType),
		"interface", "N1",
		"direction", "OUT",
	)
}

func gutiStr(ue *amfctx.UEContext) string {
	if ue.GUTI != nil {
		return fmt.Sprintf("%s%s-%08x", ue.GUTI.MCC, ue.GUTI.MNC, ue.GUTI.TMSI)
	}
	return ""
}

// causeRestrictedServiceArea is 5GMM cause #28 "Restricted service area"
// (TS 24.501 §9.11.3.2, Table 9.11.3.2.1).
const causeRestrictedServiceArea = uint8(nas.CauseRestrictedServiceArea)

// serviceTypeRestricted reports whether a Service Request of the given service
// type is rejected with #28 in a Non-Allowed Area: "signalling" and "data"
// only; mobile terminated services, emergency services, emergency services
// fallback and elevated signalling continue, and high priority access is
// exempt (the operator policy applying the restriction to it is not
// implemented). Unused values map to signalling/data per Table 9.11.3.50.1.
// Ref: TS 24.501 §5.6.1.5
func serviceTypeRestricted(v byte) bool {
	t, ok := nas.InterpretServiceType(v)
	return ok && (t == nas.ServiceTypeSignalling || t == nas.ServiceTypeData)
}

// rejectServiceRestrictedArea sends an integrity protected and ciphered
// SERVICE REJECT #28 (the UE keeps its 5GMM-REGISTERED state and security
// context) and releases the N2 connection opened by the Service Request.
// Ref: TS 24.501 §5.6.1.5, §8.2.17; TS 23.501 §5.3.4.1
func (h *Handler) rejectServiceRestrictedArea(ctx context.Context, ue *amfctx.UEContext,
	serviceType byte, log *slog.Logger) error {
	log.WarnContext(ctx, "UE in a Non-Allowed Area - SERVICE REJECT #28",
		"direction", "OUT", "service_type", serviceType, "tac", fmt.Sprintf("%06X", ue.TAI.TAC),
		"result", "REJECT", "cause", causeRestrictedServiceArea,
		"spec_ref", "TS 24.501 §5.6.1.5")
	metrics.ProcedureTotal.WithLabelValues("AMF", "ServiceRequest", "REJECT").Inc()
	if err := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement, nas.MsgTypeServiceReject,
		&nas.ServiceReject{Cause5GMM: causeRestrictedServiceArea}); err != nil {
		return fmt.Errorf("service request: send Service Reject: %w", err)
	}
	h.releaseN2(ue, ngapCausePresentNas, ngapCauseNasNormalRelease, false)
	return nil
}

// rejectRestrictedAreaSM answers a UL NAS TRANSPORT 5GSM request that cannot be
// forwarded because the UE is in a Non-Allowed Area: DL NAS TRANSPORT with the
// original payload container and 5GMM cause #28.
// Ref: TS 24.501 §5.4.5.2.5 item 15, §5.4.5.3.1
func (h *Handler) rejectRestrictedAreaSM(ue *amfctx.UEContext, pduSessionID uint8,
	transport *nas.ULNASTransport, log *slog.Logger) error {
	log.Warn("UE in a Non-Allowed Area - 5GSM request not forwarded, DL NAS TRANSPORT #28",
		"pdu_session_id", pduSessionID, "direction", "OUT", "tac", fmt.Sprintf("%06X", ue.TAI.TAC),
		"result", "REJECT", "cause", causeRestrictedServiceArea,
		"spec_ref", "TS 24.501 §5.4.5.2.5, §5.4.5.3.1")
	metrics.ProcedureTotal.WithLabelValues("AMF", "PDUSessionEstablishment", "REJECT").Inc()
	return h.rejectULNASTransport(ue, pduSessionID,
		transport.PayloadContainerType, transport.PayloadContainer, causeRestrictedServiceArea)
}

// Request type IE values (TS 24.501 §9.11.3.47, Table 9.11.3.47.1) that are
// subject to the Non-Allowed Area / Service Area Restriction check.
const (
	requestTypeInitial      uint8 = 0x01 // initial request
	requestTypeExistingPDU  uint8 = 0x02 // existing PDU session
	requestTypeModification uint8 = 0x05 // modification request
	requestTypeMAPDURequest uint8 = 0x06 // MA PDU request
)

// requestTypeExemptFromSAR reports whether a 5GSM message is forwarded to the
// SMF even in a Non-Allowed Area. TS 24.501 §5.4.5.2.5 item 15 restricts only
// messages whose Request type IE is present and set to "initial request",
// "existing PDU session", "modification request" or "MA PDU request"; an absent
// IE and every other value (emergency types included) is forwarded normally.
// Ref: TS 24.501 §5.4.5.2.5 item 15, §9.11.3.47
func requestTypeExemptFromSAR(rt *uint8) bool {
	if rt == nil {
		return true
	}
	switch *rt {
	case requestTypeInitial, requestTypeExistingPDU, requestTypeModification, requestTypeMAPDURequest:
		return false
	}
	return true
}

// ---- Service Request -------------------------------------------------------

// handleServiceRequest handles a 5GMM Service Request from a returning CM-IDLE UE.
// The UE is already registered; this procedure re-establishes the N2 context without
// a full re-registration. UERANSIM will re-establish PDU sessions via UL NAS Transport
// after receiving Service Accept in the InitialContextSetupRequest.
//
// Flow per TS 23.502 §4.2.3:
//  1. Decode ServiceRequest (service type + ngKSI).
//  2. Re-derive KgNB from existing KAMF + current UplinkCount.
//  3. Send Service Accept inside InitialContextSetupRequest to re-establish N2.
//  4. Transition UE to CM-CONNECTED.
func (h *Handler) handleServiceRequest(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

	svcReq, ok := msg.Body.(*nas.ServiceRequest)
	if !ok {
		return fmt.Errorf("nas: ServiceRequest body decode failed")
	}

	log := h.logger.With(
		"procedure", "ServiceRequest",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"service_type", svcReq.ServiceType,
		"interface", "N1",
		"direction", "IN",
		"spec_ref", "TS 23.502 §4.2.3",
	)
	log.Info("Service Request received")

	// UE in a Non-Allowed Area (or outside its Allowed Area): signalling/data
	// service requests are rejected with #28; mobile terminated, emergency and
	// elevated signalling services continue. Ref: TS 24.501 §5.6.1.5
	if ue.InNonAllowedArea() && serviceTypeRestricted(svcReq.ServiceType) {
		return h.rejectServiceRestrictedArea(ctx, ue, svcReq.ServiceType, log)
	}

	// Re-derive KgNB from the existing KAMF and the NAS UL COUNT of this message.
	// unwrapNASSecurity already incremented UplinkCount; the SR's NAS COUNT is
	// UplinkCount-1. Ref: TS 33.501 §A.9
	srCount := ue.SecurityCtx.UplinkCount - 1
	kgnbBytes := kdf.KgNB(ue.SecurityCtx.KAMF, srCount, 0x01)
	var kgnb [32]byte
	copy(kgnb[:], kgnbBytes)
	ue.SetKgNB(kgnb) // also restarts the NH chain, TS 33.501 §6.9.2.1.1

	// Rebuild UE security capability bitmaps from the stored capabilities.
	var encAlgs, intAlgs uint16
	if ue.UESecCapEA[1] {
		encAlgs |= 1 << 15
	}
	if ue.UESecCapEA[2] {
		encAlgs |= 1 << 14
	}
	if ue.UESecCapEA[3] {
		encAlgs |= 1 << 13
	}
	if ue.UESecCapIA[1] {
		intAlgs |= 1 << 15
	}
	if ue.UESecCapIA[2] {
		intAlgs |= 1 << 14
	}
	if ue.UESecCapIA[3] {
		intAlgs |= 1 << 13
	}

	// Collect the PDU sessions to re-activate: those the UE flagged in the
	// Uplink Data Status IE. For each, ask the SMF for the session's
	// PDUSessionResourceSetupRequestTransfer (Nsmf_PDUSession_UpdateSMContext
	// upCnxState=ACTIVATING) so the ICS Request below carries the N2SM info
	// that directly re-establishes user-plane resources at the gNB.
	// Ref: TS 23.502 §4.2.3.2 steps 4/12, TS 29.502 §5.2.2.3.2.2
	//
	// First, PDU sessions the UE reports as PDU SESSION INACTIVE in the PDU
	// session status IE are released locally in the AMF and at the SMF, so
	// they are never re-activated. Ref: TS 24.501 §5.6.1.4.1
	released := h.releaseInactivePDUSessions(ctx, ue, svcReq.PDUSessionStatus)
	pduSessions := h.activatePDUSessions(ctx, ue, svcReq.UplinkDataStatus, released, log)

	// Build the Service Accept: PDU session status (IEI 0x50) when the SR had
	// one, PDU session reactivation result (IEI 0x26) when the SR had Uplink
	// data status. Ref: TS 24.501 §5.6.1.4.1, §8.2.17
	accept := buildServiceAccept(ue, svcReq, released, pduSessions)
	log.Info("Service Accept built",
		"message_type", "ServiceAccept",
		"pdu_session_status_ie", accept.PDUSessionStatus != nil,
		"reactivation_result_ie", accept.PDUSessionReactivationResult != nil,
		"released_locally", len(released),
		"spec_ref", "TS 24.501 §5.6.1.4.1",
	)
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeServiceAccept, accept)
	if err != nil {
		return fmt.Errorf("service request: encode Service Accept: %w", err)
	}

	// Re-establish the N2 context by sending InitialContextSetupRequest with the
	// Service Accept NAS PDU, fresh KgNB, and the PDU sessions to re-activate
	// (PDUSessionResourceSetupListCxtReq). The gNB re-activates AS security and
	// sets up the GTP-U resources; its ICS Response returns the DL tunnel info,
	// which the NGAP layer forwards to the SMF to re-activate DL forwarding.
	// Ref: TS 38.413 §8.3.1, TS 23.502 §4.2.3 step 6
	log.Info("sending InitialContextSetupRequest (Service Request)",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "InitialContextSetupRequest",
		"pdu_sessions_cxt_req", len(pduSessions),
		"spec_ref", "TS 38.413 §8.3.1",
	)
	ue.SetPendingICS(amfctx.ICSServiceRequest) // failure -> keep registration (AMF-034)
	if err := h.sender.SendInitialContextSetupRequest(ue, nasPDU, kgnb,
		ue.SecurityCtx.CipheringAlgID, ue.SecurityCtx.IntegrityAlgID,
		encAlgs, intAlgs, pduSessions); err != nil {
		ue.TakePendingICS() // nothing in flight: a stale kind would mis-handle a later failure
		return fmt.Errorf("service request: SendInitialContextSetupRequest: %w", err)
	}

	ue.CMState = amfctx.CMConnected

	// UE is back to CM-CONNECTED — cancel the CM-IDLE reachability watchdogs
	// (re-armed on AN Release). Ref: TS 23.501 §5.3.2
	h.notifyUEReachable(ue)

	log.Info("Service Request accepted — UE back to CM-CONNECTED",
		"result", "OK",
		"spec_ref", "TS 23.502 §4.2.3",
	)

	// rel19: re-initiate NSSAA for slices left PENDING. Ref: TS 23.502 §4.2.9.2
	h.retryPendingNSSAA(ctx, ue, "service_request")
	return nil
}

// releaseInactivePDUSessionReason tags the local releases triggered by the
// UE's PDU session status IE in logs and in the NW-release completion path.
const releaseInactivePDUSessionReason = "UE_PDU_SESSION_STATUS_INACTIVE"

// releaseInactivePDUSessions performs the local release required when a
// Service Request carries a PDU session status IE: every PDU session that is
// established on the AMF side (has an SM context) but that the UE reports as
// PDU SESSION INACTIVE is removed from the UE context, and the SMF is asked
// to release the SM context (Nsmf_PDUSession_ReleaseSMContext, sent
// asynchronously on a detached context so the Service Request is not
// delayed). A session already in a NW-initiated release is completed through
// that path instead. Returns the set of released PSIs (nil when the IE was
// absent or nothing was released).
// Ref: TS 24.501 §5.6.1.4.1, TS 23.502 §4.2.3.2, TS 29.502 §5.2.2.4
func (h *Handler) releaseInactivePDUSessions(
	ctx context.Context, ue *amfctx.UEContext, pduSessionStatus *uint16) map[uint8]struct{} {

	if pduSessionStatus == nil {
		return nil
	}
	type victim struct {
		psi uint8
		ref string
	}
	var victims []victim
	ue.Lock()
	for psi, sess := range ue.PDUSessions {
		if sess.SMFInstanceID == "" || nas.PSIInStatus(*pduSessionStatus, psi) {
			continue // not established on the AMF side, or active at the UE
		}
		victims = append(victims, victim{psi: psi, ref: sess.SMFInstanceID})
	}
	ue.Unlock()
	if len(victims) == 0 {
		return nil
	}
	sort.Slice(victims, func(i, j int) bool { return victims[i].psi < victims[j].psi })

	base := h.logger
	if base == nil {
		base = slog.Default()
	}
	log := base.With("nf", "AMF", "procedure", "ServiceRequestLocalPDUSessionRelease",
		"supi", ue.SUPI, "amf_ue_ngap_id", ue.AMFUENGAPId)

	smfDel, canDel := h.sender.(interface {
		DeleteSMContext(ctx context.Context, smContextRef string) error
	})
	detached := context.WithoutCancel(ctx)
	released := make(map[uint8]struct{}, len(victims))
	for _, v := range victims {
		released[v.psi] = struct{}{}
		log.Info("PDU session reported inactive by UE — releasing locally",
			"interface", "N1", "direction", "IN",
			"pdu_session_id", v.psi,
			"smContextRef", v.ref,
			"result", "OK",
			"spec_ref", "TS 24.501 §5.6.1.4.1",
		)
		metrics.ProcedureTotal.WithLabelValues("AMF", "ServiceRequestLocalPDUSessionRelease", "OK").Inc()

		// A NW-initiated release already in flight owns the SM context
		// deletion and the UE-context cleanup — finish it now.
		if _, pending := h.pendingRelease.Load(pendingReleaseKey(ue.AMFUENGAPId, v.psi)); pending {
			go h.completeNetworkPDUSessionRelease(detached, ue, v.psi, releaseInactivePDUSessionReason)
			continue
		}

		ue.Lock()
		delete(ue.PDUSessions, v.psi)
		ue.Unlock()

		if !canDel {
			log.Warn("no SMF client wired — SM context of UE-inactive PDU session not released at the SMF",
				"interface", "Nsmf", "direction", "OUT",
				"pdu_session_id", v.psi, "smContextRef", v.ref,
				"result", "FAILURE",
				"spec_ref", "TS 29.502 §5.2.2.4",
			)
			continue
		}
		ref, psi := v.ref, v.psi
		delCtx, cancel := context.WithTimeout(detached, releaseSMContextTimeout)
		go func() {
			defer cancel()
			if err := smfDel.DeleteSMContext(delCtx, ref); err != nil {
				log.Warn("SMF SM context release failed for UE-inactive PDU session",
					"interface", "Nsmf", "direction", "OUT",
					"pdu_session_id", psi, "smContextRef", ref,
					"result", "FAILURE", "error", err,
					"spec_ref", "TS 29.502 §5.2.2.4",
				)
				return
			}
			log.Info("SMF SM context released for UE-inactive PDU session",
				"interface", "Nsmf", "direction", "OUT",
				"pdu_session_id", psi, "smContextRef", ref,
				"result", "OK",
				"spec_ref", "TS 29.502 §5.2.2.4",
			)
		}()
	}
	if h.reg != nil {
		h.reg.PersistUE(ctx, ue)
	}
	return released
}

// buildServiceAccept fills the Service Accept optional IEs from the Service
// Request and the activation outcome:
//   - PDU session status (0x50) iff the SR carried one: the PDU sessions
//     still established in the AMF after the local release.
//   - PDU session reactivation result (0x26) iff the SR carried Uplink data
//     status: for each PSI the UE flagged, bit = 1 when its user-plane
//     resources are not being re-established (not in the ICS
//     PDUSessionResourceSetupListCxtReq), 0 otherwise.
//
// Ref: TS 24.501 §5.6.1.4.1, §8.2.17.1.1, §9.11.3.44, §9.11.3.42
func buildServiceAccept(ue *amfctx.UEContext, svcReq *nas.ServiceRequest,
	released map[uint8]struct{}, activated []ngap.PDUSessionSetupItemCxtReq) *nas.ServiceAccept {

	accept := &nas.ServiceAccept{}
	if svcReq.PDUSessionStatus != nil {
		var active []uint8
		ue.Lock()
		for psi, sess := range ue.PDUSessions {
			if sess.SMFInstanceID == "" {
				continue
			}
			if _, gone := released[psi]; gone {
				continue
			}
			active = append(active, psi)
		}
		ue.Unlock()
		m := nas.PSIMask(active...)
		accept.PDUSessionStatus = &m
	}
	if svcReq.UplinkDataStatus != nil {
		ok := make(map[uint8]struct{}, len(activated))
		for _, it := range activated {
			ok[it.PDUSessionID] = struct{}{}
		}
		var failed []uint8
		for psi := uint8(1); psi <= 15; psi++ {
			if !nas.PSIInStatus(*svcReq.UplinkDataStatus, psi) {
				continue
			}
			if _, done := ok[psi]; !done {
				failed = append(failed, psi)
			}
		}
		m := nas.PSIMask(failed...)
		accept.PDUSessionReactivationResult = &m
	}
	return accept
}

// activatePDUSessions resolves the PDU sessions flagged in the Service
// Request's Uplink Data Status, plus the PDU sessions whose downlink data
// triggered paging (UE context paged set, TS 23.502 §4.2.3.3 step 6), and fetches each session's
// PDUSessionResourceSetupRequestTransfer from the SMF (upCnxState=ACTIVATING).
// PSIs in released were just released locally because the UE reported them
// inactive (releaseInactivePDUSessions) and are never activated.
// Returns the PDUSessionResourceSetupListCxtReq items for the ICS Request, in
// ascending PSI order. Failures are non-fatal per session: the Service Request
// still completes and the UE can fall back to UE-requested re-establishment.
// Ref: TS 23.502 §4.2.3.2 steps 4/12, TS 29.502 §5.2.2.3.2.2
func (h *Handler) activatePDUSessions(
	ctx context.Context, ue *amfctx.UEContext,
	uplinkDataStatus *uint16, released map[uint8]struct{}, log *slog.Logger) []ngap.PDUSessionSetupItemCxtReq {

	// Always consume the paged set so it never leaks into a later Service Request.
	paged := ue.TakePagedPDUSessions()
	if uplinkDataStatus == nil && len(paged) == 0 {
		return nil // signalling-only Service Request — nothing to re-activate
	}
	activator, ok := h.sender.(interface {
		ActivateSMContext(context.Context, string) ([]byte, error)
	})
	if !ok {
		return nil
	}

	type target struct {
		psi uint8
		ref string
		sst uint8
		sd  string
	}
	// plog carries the paged-session step reference; derived from the base
	// logger because log already holds procedure and spec_ref.
	base := h.logger
	if base == nil {
		base = slog.Default()
	}
	plog := base.With("nf", "AMF", "procedure", "NetworkTriggeredServiceRequest",
		"interface", "N1", "supi", ue.SUPI, "amf_ue_ngap_id", ue.AMFUENGAPId)
	// Distinct procedure label: "NetworkTriggeredServiceRequest" is already
	// counted at paging time in the SBI handler; this series counts the
	// UP re-activation outcome per paged PDU session without double counting.
	const upActProc = "NetworkTriggeredServiceRequestUPActivation"
	pagedSet := make(map[uint8]struct{}, len(paged))
	for _, psi := range paged {
		pagedSet[psi] = struct{}{}
	}
	ue.Lock()
	var targets []target
	for psi, sess := range ue.PDUSessions {
		if sess.SMFInstanceID == "" {
			continue
		}
		_, isPaged := pagedSet[psi]
		ulds := uplinkDataStatus != nil && nas.PSIInStatus(*uplinkDataStatus, psi)
		if !ulds && !isPaged {
			continue
		}
		if _, gone := released[psi]; gone {
			// Only reachable for a session whose NW-initiated release is
			// being completed asynchronously (still in the map); the
			// others were already removed. Never re-activate it.
			continue
		}
		if isPaged {
			plog.Info("UP activation: paged PDU session added to activation set",
				"pdu_session_id", psi,
				"result", "OK",
				"spec_ref", "TS 23.502 §4.2.3.3 step 6")
		}
		targets = append(targets, target{psi: psi, ref: sess.SMFInstanceID,
			sst: sess.SNSSAI.SST, sd: sess.SNSSAI.SD})
	}
	for _, psi := range paged {
		if _, gone := released[psi]; gone {
			// The UE reports the paged PSI inactive: it was released
			// locally instead of re-activated. Ref: TS 24.501 §5.6.1.4.1
			plog.Warn("UP activation: paged PDU session not active in UE PDU session status — released locally, not activated",
				"pdu_session_id", psi,
				"result", "REJECT",
				"spec_ref", "TS 24.501 §5.6.1.4.1")
			metrics.ProcedureTotal.WithLabelValues("AMF", upActProc, "REJECT").Inc()
			continue
		}
		if sess, ok := ue.PDUSessions[psi]; !ok || sess.SMFInstanceID == "" {
			plog.Warn("UP activation: paged PDU session unknown or without SMF context — skipped",
				"pdu_session_id", psi,
				"result", "FAILURE",
				"spec_ref", "TS 23.502 §4.2.3.3 step 6")
			metrics.ProcedureTotal.WithLabelValues("AMF", upActProc, "FAILURE").Inc()
		}
	}
	ue.Unlock()
	sort.Slice(targets, func(i, j int) bool { return targets[i].psi < targets[j].psi })

	var items []ngap.PDUSessionSetupItemCxtReq
	for _, t := range targets {
		transfer, err := activator.ActivateSMContext(ctx, t.ref)
		_, wasPaged := pagedSet[t.psi]
		if err != nil {
			if wasPaged {
				metrics.ProcedureTotal.WithLabelValues("AMF", upActProc, "FAILURE").Inc()
			}
			log.Warn("UP activation: SMF ActivateSMContext failed — session skipped",
				"pdu_session_id", t.psi,
				"smContextRef", t.ref,
				"error", err,
				"spec_ref", "TS 29.502 §5.2.2.3.2.2",
			)
			continue
		}
		var sdBytes []byte
		if b, err := hex.DecodeString(t.sd); err == nil && len(b) == 3 {
			sdBytes = b
		}
		items = append(items, ngap.PDUSessionSetupItemCxtReq{
			PDUSessionID: t.psi,
			SST:          t.sst,
			SD:           sdBytes,
			Transfer:     transfer,
		})
		if wasPaged {
			metrics.ProcedureTotal.WithLabelValues("AMF", upActProc, "OK").Inc()
		}
		log.Info("UP activation: N2SM Setup Request Transfer fetched from SMF",
			"pdu_session_id", t.psi,
			"smContextRef", t.ref,
			"n2sm_len", len(transfer),
			"spec_ref", "TS 23.502 §4.2.3.2 step 12",
		)
	}
	return items
}

// ---- Registration Update (Periodic / Mobility) ----------------------------

// handleRegistrationUpdate handles a Periodic or Mobility Registration Update
// when the UE already has an active NAS security context with this AMF.
// No re-authentication is performed; a new GUTI is assigned and Registration
// Accept is sent back inside InitialContextSetupRequest.
//
// Flow per TS 23.502 §4.2.2.2.3/§4.2.2.2.4:
//  1. Assign new GUTI.
//  2. Re-derive KgNB from KAMF + current UplinkCount.
//  3. Send Registration Accept inside InitialContextSetupRequest.
//  4. UE replies with Registration Complete (handled by existing handler).
func (h *Handler) handleRegistrationUpdate(
	ctx context.Context, ue *amfctx.UEContext, regReq *nas.RegistrationRequest, rawPDU []byte) error {

	procedureName := "PeriodicRegistrationUpdate"
	specRef := "TS 23.502 §4.2.2.2.4"
	if regReq.RegistrationType == nas.RegistrationTypeMobility {
		procedureName = "MobilityRegistrationUpdate"
		specRef = "TS 23.502 §4.2.2.2.3"
	}

	log := h.logger.With(
		"procedure", procedureName,
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"interface", "N1",
		"direction", "IN",
		"spec_ref", specRef,
	)
	log.Info("Registration Update received — using existing security context")
	// The non-cleartext IEs are in the NAS message container: decipher it and
	// process the REGISTRATION REQUEST obtained from it. Ref: TS 24.501 §4.4.6
	outerReq := regReq
	var cerr error
	if regReq, cerr = h.registrationRequestFromContainer(ctx, ue, regReq, rawPDU); cerr != nil {
		// Undecipherable container: new authentication + SMC with RINMR instead of
		// continuing with the cleartext IEs. Ref: TS 24.501 §4.4.6, §5.4.2.2
		return h.initiateRegistrationAuth(ctx, ue, outerReq, rawPDU)
	}
	ue.ERNSSAISupported = regReq.ERNSSAISupported() // Ref: TS 24.501 §5.5.1.3.2
	// Keep the previous capability when this update omits the IE (optional in a
	// periodic update). Ref: TS 24.501 §5.5.1.3.2, §9.11.3.1
	if c := regReq.Capability5GMM(); c != nil {
		ue.Capability5GMM = c
	}
	log.Info("UE 5GMM capability",
		"capability_5gmm", ue.Capability5GMM.RawHex(),
		"capability_5gmm_bits", strings.Join(ue.Capability5GMM.SetBitNames(), ","),
	)

	// Requested NSSAI of the (container) request: re-evaluate the Allowed NSSAI.
	// Ref: TS 24.501 §5.5.1.3.2, §5.5.1.3.4; TS 23.502 §4.2.2.2.3
	if regReq.RequestedNSSAI != nil {
		ue.RequestedNSSAI = nssaiToSubscribed(regReq.RequestedNSSAI)
		h.reg.ReevaluateAllowedNSSAI(ctx, ue)
	}
	// PDU session status / Uplink data status IEs. Ref: TS 24.501 §5.5.1.3.4
	sessSync := h.syncPDUSessions(ctx, ue, regReq, log)

	regAccept, err := h.reg.BuildRegistrationUpdateAccept(ctx, ue)
	if err != nil {
		return fmt.Errorf("%s: build accept: %w", procedureName, err)
	}
	sessSync.applyTo(regAccept)

	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeRegistrationAccept, regAccept)
	if err != nil {
		return fmt.Errorf("%s: encode Registration Accept: %w", procedureName, err)
	}

	// CM-CONNECTED update (arrived over an existing N2 connection, UPLINK NAS
	// TRANSPORT): no CM-IDLE to CM-CONNECTED transition, hence no new KgNB and
	// no ICS; KgNB/NH/NCC are kept and the Accept goes in DOWNLINK NAS TRANSPORT.
	// Ref: TS 33.501 §6.8.1.2.1; TS 24.501 §5.5.1.3.2
	ue.Lock()
	onNewN2 := ue.NASOnNewN2Connection
	ue.Unlock()
	if !onNewN2 {
		log.Info("Registration Update over existing N2 connection — Accept in DL NAS TRANSPORT, KgNB kept",
			"interface", "N2",
			"direction", "OUT",
			"message_type", "DownlinkNASTransport",
			"spec_ref", "TS 33.501 §6.8.1.2.1",
		)
		if err := h.sender.SendDownlinkNASTransport(ue, nasPDU); err != nil {
			return fmt.Errorf("%s: send Registration Accept: %w", procedureName, err)
		}
		h.afterAcceptSent(ue, regAccept, nasPDU)
		// Uplink data pending: re-establish the user plane over the existing N2
		// connection, no ICS carries it. Ref: TS 24.501 §5.5.1.3.4
		h.sendReactivatedSessions(ctx, ue, sessSync.Items, log)
		return h.finishRegistrationUpdate(ctx, ue, log, specRef)
	}

	// Re-derive KgNB: use the NAS UL COUNT of this message (UplinkCount-1 since
	// unwrapNASSecurity already incremented it). Ref: TS 33.501 §A.9
	regCount := ue.SecurityCtx.UplinkCount - 1
	kgnbBytes := kdf.KgNB(ue.SecurityCtx.KAMF, regCount, 0x01)
	var kgnb [32]byte
	copy(kgnb[:], kgnbBytes)
	ue.SetKgNB(kgnb) // also restarts the NH chain, TS 33.501 §6.9.2.1.1

	var encAlgs, intAlgs uint16
	if ue.UESecCapEA[1] {
		encAlgs |= 1 << 15
	}
	if ue.UESecCapEA[2] {
		encAlgs |= 1 << 14
	}
	if ue.UESecCapEA[3] {
		encAlgs |= 1 << 13
	}
	if ue.UESecCapIA[1] {
		intAlgs |= 1 << 15
	}
	if ue.UESecCapIA[2] {
		intAlgs |= 1 << 14
	}
	if ue.UESecCapIA[3] {
		intAlgs |= 1 << 13
	}

	log.Info("sending InitialContextSetupRequest (Registration Update)",
		"interface", "N2",
		"direction", "OUT",
		"message_type", "InitialContextSetupRequest",
		"spec_ref", "TS 38.413 §8.3.1",
	)
	ue.SetPendingICS(amfctx.ICSRegistrationUpdate) // failure -> keep registration (AMF-034)
	if err := h.sender.SendInitialContextSetupRequest(ue, nasPDU, kgnb,
		ue.SecurityCtx.CipheringAlgID, ue.SecurityCtx.IntegrityAlgID,
		encAlgs, intAlgs, sessSync.Items); err != nil {
		ue.TakePendingICS() // nothing in flight: a stale kind would mis-handle a later failure
		return fmt.Errorf("%s: SendInitialContextSetupRequest: %w", procedureName, err)
	}
	ue.CMState = amfctx.CMConnected
	h.afterAcceptSent(ue, regAccept, nasPDU)
	return h.finishRegistrationUpdate(ctx, ue, log, specRef)
}

// finishRegistrationUpdate runs the post-Accept steps shared by the CM-IDLE
// (ICS) and CM-CONNECTED (DL NAS TRANSPORT) Registration Update paths.
func (h *Handler) finishRegistrationUpdate(ctx context.Context, ue *amfctx.UEContext,
	log *slog.Logger, specRef string) error {
	log.Info("Registration Update accepted",
		"result", "OK",
		"spec_ref", specRef,
	)

	// UE has checked in via Periodic/Mobility Registration Update and is
	// CM-CONNECTED — cancel the CM-IDLE reachability watchdogs (re-armed on
	// AN Release). Ref: TS 23.501 §5.3.2
	h.notifyUEReachable(ue)

	// rel19: re-initiate NSSAA for slices left PENDING. Ref: TS 23.502 §4.2.9.2
	h.retryPendingNSSAA(ctx, ue, "registration_update")
	return nil
}

// ---- NGAP cause constants (avoids importing ngapType in NAS layer) -------

// NGAP Cause group/value constants for UEContextReleaseCommand.
// Values from TS 38.413 §9.3.1.2 and ngapType package (free5gc/ngap v1.1.3).
const (
	ngapCausePresentNas    int   = 3 // ngapType.CausePresentNas
	ngapCauseNasDeregister int64 = 2 // ngapType.CauseNasPresentDeregister
	// ngapCauseNasNormalRelease is NAS cause normal-release.
	ngapCauseNasNormalRelease int64 = 0 // ngapType.CauseNasPresentNormalRelease
	// ngapCauseNasAuthenticationFailure is NAS cause authentication-failure.
	ngapCauseNasAuthenticationFailure int64 = 1 // ngapType.CauseNasPresentAuthenticationFailure
	// ngapCausePresentMisc / ngapCauseMiscUnspecified: Misc group, unspecified.
	ngapCausePresentMisc     int   = 5 // ngapType.CausePresentMisc
	ngapCauseMiscUnspecified int64 = 5 // ngapType.CauseMiscPresentUnspecified
)

// AUTHENTICATION FAILURE handling limits. Ref: TS 24.501 §5.4.1.3.7
const (
	// autsLen is the length of the AUTS parameter of the Authentication failure
	// parameter IE (TS 24.501 §9.11.3.14; TS 33.102 §6.3.3).
	autsLen = 14
	// maxNgKSIInUseFailures: only the first #71 is answered with the same
	// challenge and a new ngKSI (§5.4.1.3.7 e)); a repeated one is rejected.
	maxNgKSIInUseFailures = 1
	// maxSynchFailures: a second consecutive #21 ends with AUTHENTICATION
	// REJECT (§5.4.1.3.7 f) NOTE 4).
	maxSynchFailures = 1
)

// ---- Deregistration -------------------------------------------------------

// handleDeregistration handles a UE-initiated 5GMM Deregistration Request.
// Flow per TS 23.502 §4.2.2.3.2:
//  1. If not switch-off, send Deregistration Accept.
//  2. Delete all PDU session contexts at SMF.
//  3. Deregister from UDM (Nudm_UECM_Deregistration).
//  4. If CM-CONNECTED, send UEContextReleaseCommand to gNB.
//  5. Transition UE to GMMDeregistered and remove context.
func (h *Handler) handleDeregistration(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

	deregReq, ok := msg.Body.(*nas.DeregistrationRequest)
	if !ok {
		return fmt.Errorf("nas: DeregistrationRequest body decode failed")
	}

	log := h.logger.With(
		"procedure", "Deregistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"switch_off", deregReq.SwitchOff,
		"access_type", deregReq.AccessType,
		"interface", "N1",
		"direction", "IN",
		"spec_ref", "TS 23.502 §4.2.2.3.2",
	)
	log.Info("Deregistration Request received")

	ue.TransitionTo(amfctx.GMMDeregisteredInitiated)
	// An NSSAA exchange (T3575) dies with the registration; a network-initiated
	// de-registration in flight (T3522) is superseded by the UE's own: both
	// procedures are completed (TS 24.501 §5.5.2.3.5 c)).
	ue.StopNSSAATimer()
	ue.StopDeregTimer()
	ue.ClearRegProc() // a pending registration is superseded by the de-registration

	// Step 1: if UE is not switching off, send Deregistration Accept (TS 24.501 §8.2.12.2).
	if !deregReq.SwitchOff {
		if err := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
			nas.MsgTypeDeregistrationAcceptUE, &nas.DeregistrationAcceptUE{}); err != nil {
			log.Warn("failed to send Deregistration Accept — proceeding with teardown", "error", err)
		}
	}

	// Step 2: release all PDU sessions at SMF (PFCP teardown happens in SMF→UPF).
	// Ref: TS 23.502 §4.2.2.3.2 step 2
	smfDel, canDel := h.sender.(interface {
		DeleteSMContext(ctx context.Context, smContextRef string) error
	})
	ue.Lock()
	sessions := make(map[uint8]*amfctx.PDUSession, len(ue.PDUSessions))
	for k, v := range ue.PDUSessions {
		sessions[k] = v
	}
	ue.Unlock()

	for _, sess := range sessions {
		if sess.SMFInstanceID != "" && canDel {
			if err := smfDel.DeleteSMContext(ctx, sess.SMFInstanceID); err != nil {
				log.Warn("SMF DeleteSMContext failed during deregistration",
					"smContextRef", sess.SMFInstanceID, "error", err)
			}
		}
		ue.Lock()
		delete(ue.PDUSessions, sess.PDUSessionID)
		ue.Unlock()
	}

	// Step 3: notify UDM to remove the AMF registration (Nudm_UECM_Deregistration).
	// Ref: TS 23.502 §4.2.2.3.2 step 3, TS 29.503 §5.3.2.4
	if ue.SUPI != "" {
		if err := h.reg.DeregisterUECM(ctx, ue.SUPI); err != nil {
			log.Warn("UDM UECM deregistration failed (non-fatal)", "error", err)
		}
	}

	// Step 3b: release AM policy association at PCF (Npcf_AMPolicyControl).
	// Non-fatal. Ref: TS 29.507 §4.2.5, TS 23.502 §4.2.2.3.2 step 3
	if ue.AMPolicyAssocID != "" {
		if err := h.reg.ReleaseAMPolicy(ctx, ue.AMPolicyAssocID); err != nil {
			log.Warn("PCF AM policy release failed (non-fatal)", "error", err,
				"am_pol_asso_id", ue.AMPolicyAssocID)
		}
		ue.AMPolicyAssocID = ""
	}

	// Step 3c: release UE policy association at PCF (Npcf_UEPolicyControl / URSP).
	// Non-fatal. Ref: TS 29.525 §4.2.5, TS 23.502 §4.2.2.3.2 step 3
	if ue.PolicyAssociationID != "" {
		if err := h.reg.ReleasePCFPolicy(ctx, ue.PolicyAssociationID); err != nil {
			log.Warn("PCF UE policy release failed (non-fatal)", "error", err,
				"pol_asso_id", ue.PolicyAssociationID)
		}
		ue.PolicyAssociationID = ""
	}

	// Step 4: mark context for deferred removal and release the N2 UE context at the gNB.
	// PendingRemoval must be set BEFORE SendUEContextReleaseCommandForUE so that:
	//   (a) the PendingRemoval watchdog timer is armed immediately (TS 38.413 §8.3.3), and
	//   (b) handleUEContextReleaseComplete finds pending=true and removes the context.
	// The actual Remove happens in handleUEContextReleaseComplete so that gnb.UEs
	// is cleaned up before the AMF index entries are deleted. If the gNB never
	// responds (UE was already CM-IDLE), the context will be cleaned by the next
	// registration attempt (new AllocateUEContext replaces by SUPI/TMSI).
	// Ref: TS 23.502 §4.2.2.3.2 step 4, TS 38.413 §8.3.3
	ue.TransitionTo(amfctx.GMMDeregistered)
	ue.PendingRemoval = true

	if err := h.sender.SendUEContextReleaseCommandForUE(
		ue, ngapCausePresentNas, ngapCauseNasDeregister); err != nil {
		log.Warn("SendUEContextReleaseCommandForUE failed — gNB may self-release", "error", err)
	}

	log.Info("UE deregistered — awaiting N2 release",
		"result", "OK",
		"spec_ref", "TS 23.502 §4.2.2.3.2",
	)
	return nil
}

// ---- NW-initiated Deregistration ------------------------------------------

// SendNetworkDeregistration sends a NW-initiated Deregistration Request to a
// registered UE. The AMF is the initiator; the UE responds with a Deregistration
// Accept (handled by handleNWDeregistrationAccept) and then cleans up locally.
//
// cause5GMM: optional 5GMM Cause (0 = omit). Common values:
//
//	0x06 = illegal ME, 0x09 = UE identity not derived, 0x48 = NW failure.
//	Causes 0x03/0x06/0x07 make the UE consider the USIM invalid (5U3, no
//	re-registration until reboot) — TS 24.501 §5.5.2.3.4. For a subscription
//	change where the UE must come back, pass cause 0 + reregRequired=true.
//
// reregRequired: sets de-registration type "re-registration required" so the
// UE initiates a new Initial Registration after the Deregistration Accept.
//
// accessType: 1=3GPP, 2=non-3GPP, 3=both.
//
// Ref: TS 23.502 §4.2.2.3.3, TS 24.501 §8.2.13.1
func (h *Handler) SendNetworkDeregistration(ctx context.Context, ue *amfctx.UEContext, cause5GMM byte, accessType uint8, reregRequired bool) error {
	if accessType == 0 {
		accessType = procedures.AccessType3GPP // default: 3GPP access
	}
	return h.sendNetworkDeregistrationReq(ctx, ue, &nas.DeregistrationRequestNW{
		Cause5GMM:              cause5GMM,
		AccessType:             accessType,
		ReregistrationRequired: reregRequired,
	}, "NetworkDeregistration", "TS 23.502 §4.2.2.3.3")
}

// sendNetworkDeregistrationReq sends deregReq (DEREGISTRATION REQUEST, UE
// terminated) protected on the downlink, moves the UE to
// 5GMM-DEREGISTERED-INITIATED, stops T3575 and, under rel19, starts T3522
// (dereg_timer.go). procedure/specRef label the logs. rel19 also sets the spare
// half octet to zero (rel17 keeps the frozen legacy 0x7 nibble). The state change
// and the timer happen only after a successful send.
// Ref: TS 23.502 §4.2.2.3.3, TS 24.501 §5.5.2.3.1, §8.2.14, Table 8.2.14.1.1
func (h *Handler) sendNetworkDeregistrationReq(_ context.Context, ue *amfctx.UEContext, deregReq *nas.DeregistrationRequestNW, procedure, specRef string) error {
	if h.reg.NSSAASpecLiteral() {
		deregReq.SpareHalfOctetZero = true
	}
	log := h.logger.With(
		"procedure", procedure,
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"cause", deregReq.Cause5GMM,
		"rereg_required", deregReq.ReregistrationRequired,
		"rejected_nssai_count", len(deregReq.RejectedNSSAI),
		"extended_rejected_nssai", deregReq.ExtendedRejectedNSSAI != nil,
		"interface", "N1",
		"direction", "OUT",
		"spec_ref", specRef,
	)
	log.Info("initiating NW-initiated Deregistration")

	if err := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
		nas.MsgTypeDeregistrationRequestNW, deregReq); err != nil {
		return fmt.Errorf("network deregistration: send: %w", err)
	}

	ue.TransitionTo(amfctx.GMMDeregisteredInitiated)
	ue.StopNSSAATimer() // an NSSAA exchange (T3575) dies with the registration
	h.armDeregT3522(ue, deregReq, 0)
	log.Info("Deregistration Request (NW) sent — awaiting UE accept")
	return nil
}

// handleNWDeregistrationAccept processes the UE's Deregistration Accept sent in
// response to a NW-initiated Deregistration Request: T3522 is stopped and the AMF
// tears the UE down (completeNWDeregistration).
//
// Ref: TS 23.502 §4.2.2.3.3, TS 24.501 §8.2.13.2, §5.5.2.3.1
func (h *Handler) handleNWDeregistrationAccept(ctx context.Context, ue *amfctx.UEContext) error {
	log := h.logger.With(
		"procedure", "NetworkDeregistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"interface", "N1",
		"direction", "IN",
		"spec_ref", "TS 23.502 §4.2.2.3.3",
	)
	log.Info("Deregistration Accept (NW) received — tearing down UE context")
	ue.StopNSSAATimer()
	ue.StopDeregTimer() // "shall stop timer T3522 upon receipt of the DEREGISTRATION ACCEPT"
	h.completeNWDeregistration(ctx, ue, log)
	return nil
}

// completeNWDeregistration is the AMF-side teardown of a network-initiated
// de-registration: the PDU sessions are released at the SMF, the AMF registration
// at the UDM and the PCF policy associations are deleted, the UE enters
// 5GMM-DEREGISTERED and the N2 context is released. Run on DEREGISTRATION ACCEPT
// and, locally, when T3522 expires for the fifth time (TS 24.501 §5.5.2.3.5 a)).
// Ref: TS 23.502 §4.2.2.3.3
func (h *Handler) completeNWDeregistration(ctx context.Context, ue *amfctx.UEContext, log *slog.Logger) {
	// Teardown PDU sessions
	smfDel, canDel := h.sender.(interface {
		DeleteSMContext(ctx context.Context, smContextRef string) error
	})
	ue.Lock()
	sessions := make(map[uint8]*amfctx.PDUSession, len(ue.PDUSessions))
	for k, v := range ue.PDUSessions {
		sessions[k] = v
	}
	ue.Unlock()

	for _, sess := range sessions {
		if sess.SMFInstanceID != "" && canDel {
			if err := smfDel.DeleteSMContext(ctx, sess.SMFInstanceID); err != nil {
				log.Warn("SMF DeleteSMContext failed during NW deregistration",
					"smContextRef", sess.SMFInstanceID, "error", err)
			}
		}
		ue.Lock()
		delete(ue.PDUSessions, sess.PDUSessionID)
		ue.Unlock()
	}

	// Deregister from UDM
	if ue.SUPI != "" {
		if err := h.reg.DeregisterUECM(ctx, ue.SUPI); err != nil {
			log.Warn("UDM UECM deregistration failed (non-fatal)", "error", err)
		}
	}

	// Release PCF AM policy association (Npcf_AMPolicyControl, TS 29.507 §4.2.5)
	if ue.AMPolicyAssocID != "" {
		if err := h.reg.ReleaseAMPolicy(ctx, ue.AMPolicyAssocID); err != nil {
			log.Warn("PCF AM policy release failed (non-fatal)", "error", err,
				"am_pol_asso_id", ue.AMPolicyAssocID)
		}
		ue.AMPolicyAssocID = ""
	}

	// Release PCF UE policy association (Npcf_UEPolicyControl / URSP, TS 29.525 §4.2.5)
	if ue.PolicyAssociationID != "" {
		if err := h.reg.ReleasePCFPolicy(ctx, ue.PolicyAssociationID); err != nil {
			log.Warn("PCF UE policy release failed (non-fatal)", "error", err,
				"pol_asso_id", ue.PolicyAssociationID)
		}
		ue.PolicyAssociationID = ""
	}

	// Mark context for deferred removal BEFORE releasing N2, so the watchdog timer
	// in SendUEContextReleaseCommandForUE is armed correctly. Ref: TS 38.413 §8.3.3
	ue.TransitionTo(amfctx.GMMDeregistered)
	ue.PendingRemoval = true

	if err := h.sender.SendUEContextReleaseCommandForUE(
		ue, ngapCausePresentNas, ngapCauseNasDeregister); err != nil {
		log.Warn("SendUEContextReleaseCommandForUE failed", "error", err)
	}

	log.Info("NW-initiated Deregistration complete",
		"result", "OK",
		"spec_ref", "TS 23.502 §4.2.2.3.3",
	)
}

// ---- PDU Session Establishment -----------------------------------------

func (h *Handler) handleULNASTransport(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

	transport, ok := msg.Body.(*nas.ULNASTransport)
	if !ok {
		return fmt.Errorf("nas: UL NAS Transport type assertion failed")
	}

	log := h.logger.With(
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"interface", "N1",
		"direction", "IN",
		"procedure", "PDUSessionEstablishment",
	)

	if transport.PayloadContainer == nil {
		log.Warn("UL NAS Transport with empty payload container")
		return nil
	}

	// UE policy delivery service (TS 24.501 Annex D): the UE acknowledges URSP
	// delivery with a MANAGE UE POLICY COMPLETE carried in payload container
	// type "UE policy container" (0x05) — not a 5GSM message. Stock UERANSIM
	// never sends this; the modified UERANSIM (tools/ueransim) does.
	if transport.PayloadContainerType == nas.PayloadContainerTypeUEPolicy {
		return h.handleUEPolicyDelivery(ctx, ue, transport.PayloadContainer)
	}

	// SMS over NAS (TS 24.501 §8.2.10): Payload Container Type 0x02 = SMS.
	// The AMF is a transparent relay — it never parses SM-CP/SM-RP content.
	// Forward the container to the SMSF via Nsmsf_SMService_UplinkSMS.
	// Ref: TS 23.502 §4.13.3, TS 29.540 §5.2.4, TS 24.501 §9.11.3.40
	if transport.PayloadContainerType == nas.PayloadContainerTypeSMS {
		return h.handleULSMS(ctx, ue, transport.PayloadContainer, log)
	}

	// LPP relay (UE-based/UE-assisted A-GNSS positioning, LMF-005): payload
	// container type 0x03 carries an opaque LPP-PDU (TS 37.355) between the
	// LMF and the UE. The AMF is a pure transparent relay — it MUST NOT
	// decode the LPP bytes; it only resolves the pendingLPP waiter keyed by
	// AMF-UE-NGAP-ID that SendDownlinkLPP registered.
	// Ref: TS 24.501 §8.7.4 / §9.11.3.40 (PCT=0x03, NOT 0x01 N1SM); TS 23.273 §7.2.
	if transport.PayloadContainerType == nas.PayloadContainerTypeLPP {
		return h.handleULLPP(ctx, ue, transport.PayloadContainer)
	}

	// 5GSM header: EPD | PDU session identity | PTI | Message type | body
	// Each field is a full octet. Ref: TS 24.501 §9.1.1
	if len(transport.PayloadContainer) < 4 {
		log.Warn("UL NAS Transport: 5GSM payload too short", "len", len(transport.PayloadContainer))
		return nil
	}
	var pduSessionID uint8
	var pti uint8
	msgType5GSM := transport.PayloadContainer[3]
	pduSessionID = transport.PayloadContainer[1]
	pti = transport.PayloadContainer[2]

	// Use PDU Session ID from transport IE if available (takes precedence over 5GSM header)
	if transport.PDUSessionID != nil {
		pduSessionID = *transport.PDUSessionID
	}

	// Dispatch on 5GSM message type
	switch nas.MessageType(msgType5GSM) {
	case nas.MsgTypePDUSessionEstablishmentRequest:
		// Explicit case — falls through to the establishment handler below.
	case nas.MsgTypePDUSessionReleaseRequest:
		return h.handlePDUSessionRelease(ctx, ue, pduSessionID, pti, log)
	case nas.MsgTypePDUSessionReleaseComplete:
		log.Info("PDU Session Release Complete received",
			"pdu_session_id", pduSessionID,
			"result", "OK",
			"spec_ref", "TS 24.501 §8.3.10",
		)
		// For a NW-initiated release this is step 5 of TS 23.502 §4.3.4.3 — the
		// UE's confirmation is what releases the SM context (and with it the N4
		// session). No-op for a UE-initiated release, which deletes it inline.
		h.completeNetworkPDUSessionRelease(ctx, ue, pduSessionID, "RELEASE_COMPLETE")
		return nil
	case nas.MsgTypePDUSessionModificationRequest:
		if ue.InNonAllowedArea() && !requestTypeExemptFromSAR(transport.RequestType) {
			return h.rejectRestrictedAreaSM(ue, pduSessionID, transport, log)
		}
		return h.handlePDUSessionModification(ctx, ue, pduSessionID, pti, transport.PayloadContainer, log)
	case nas.MsgTypePDUSessionModificationComplete:
		log.Info("PDU Session Modification Complete received",
			"pdu_session_id", pduSessionID,
			"result", "OK",
			"spec_ref", "TS 24.501 §8.3.7",
		)
		return nil
	case nas.MsgTypePDUSessionModificationCommandReject:
		// UE rejects a NW-initiated modification. Log and absorb — no action required.
		// Ref: TS 24.501 §8.3.8 (UE-requested modification reject path)
		log.Warn("PDU Session Modification Command Reject received",
			"pdu_session_id", pduSessionID,
			"spec_ref", "TS 24.501 §8.3.8",
		)
		return nil
	case nas.MsgTypeStatus5GSM:
		// 5GSM Status: procedure-independent error from UE (e.g. INVALID_PTI_VALUE).
		// Per TS 24.501 §8.7: absorb silently; do NOT re-establish the session.
		// Treating this as an Establishment Request creates an infinite retransmission loop.
		cause := uint8(0)
		if len(transport.PayloadContainer) > 4 {
			cause = transport.PayloadContainer[4]
		}
		log.Warn("5GSM Status received from UE — absorbing",
			"pdu_session_id", pduSessionID,
			"5gsm_cause", fmt.Sprintf("0x%02X", cause),
			"spec_ref", "TS 24.501 §8.7",
		)
		return nil
	default:
		log.Warn("Unknown 5GSM message type received — dropping",
			"msg_type", fmt.Sprintf("0x%02X", msgType5GSM),
			"pdu_session_id", pduSessionID,
		)
		return nil
	}

	// Non-Allowed Area: initial/existing/MA PDU session requests are not forwarded
	// to the SMF (emergency request types exempt). Ref: TS 24.501 §5.4.5.2.5 item 15
	if pduSessionID != 0 && ue.InNonAllowedArea() && !requestTypeExemptFromSAR(transport.RequestType) {
		return h.rejectRestrictedAreaSM(ue, pduSessionID, transport, log)
	}

	// PDU Session Establishment Request handler.
	// TS 24.501 §6.3.2.2.3: if the PSI is already active (e.g. a stale AMF entry
	// left when NGAP failed after the SMF context was created, or a genuine T3580
	// retransmit after the UERANSIM UAC race), release the existing session first
	// then accept the new one. Silently dropping is non-compliant and permanently
	// blocks re-establishment of that PSI.
	ue.Lock()
	existingSession, alreadyActive := ue.PDUSessions[pduSessionID]
	ue.Unlock()
	if alreadyActive {
		log.Warn("PDU Session Establishment Request for already-active PSI — releasing existing context per TS 24.501 §6.3.2.2.3",
			"pdu_session_id", pduSessionID,
			"smContextRef", existingSession.SMFInstanceID,
			"spec_ref", "TS 24.501 §6.3.2.2.3",
		)
		if existingSession.SMFInstanceID != "" {
			if smfDel, ok := h.sender.(interface {
				DeleteSMContext(ctx context.Context, smContextRef string) error
			}); ok {
				if err := smfDel.DeleteSMContext(ctx, existingSession.SMFInstanceID); err != nil {
					log.Warn("failed to delete displaced SMF context",
						"pdu_session_id", pduSessionID,
						"smContextRef", existingSession.SMFInstanceID,
						"error", err,
					)
				}
			}
		}
		ue.Lock()
		delete(ue.PDUSessions, pduSessionID)
		ue.Unlock()
		// Fall through to establish the new session below.
	}

	// Decode PDU Session Establishment Request (5GSM body after the 4-octet
	// header EPD|PSI|PTI|MT — len>=4 already checked above). The decoded
	// fields are informational for now; the SMF performs session-type and
	// PCO handling itself.
	pduReq, err := nas.DecodePDUSessionEstablishmentRequest(transport.PayloadContainer[4:])
	if err != nil {
		log.Error("decode PDU Session Establishment Request failed", "error", err)
		return nil
	}
	_ = pduReq

	// Extract DNN from transport or use default.
	// Track whether the UE explicitly provided a DNN (nil = absent in UL NAS Transport).
	ueProvidedDNN := transport.DNN != nil
	dnn := "internet"
	if transport.DNN != nil {
		dnn = *transport.DNN
	}

	// Resolve the S-NSSAI for this session. The UE-requested slice is honoured
	// only if it is in the Allowed NSSAI (TS 23.501 §5.15.5.2.1); otherwise the
	// request is rejected rather than moved to another slice.
	// Ref: TS 23.502 §4.3.2.2.1 step 3a
	snssai, authorised := resolveSessionSNSSAI(transport.SNSSAI, ue.AllowedNSSAI)

	if pduSessionID == 0 {
		log.Warn("UL NAS Transport: invalid PDU Session ID")
		return nil
	}

	// The UE asked for a slice outside its Allowed NSSAI. Do not forward the
	// 5GSM message to the SMF: answer with a DL NAS TRANSPORT carrying 5GMM
	// cause #90 "payload was not forwarded" and echo the payload container back.
	// Ref: TS 24.501 §5.4.5.2.5
	if !authorised {
		reqSST, reqSD := requestedSNSSAIForLog(transport.SNSSAI)
		log.Warn("UE requested S-NSSAI not in Allowed NSSAI — rejecting PDU session",
			"pdu_session_id", pduSessionID,
			"requested_sst", reqSST, "requested_sd", reqSD,
			"allowed_nssai", formatAllowedNSSAI(ue.AllowedNSSAI),
			"result", "REJECT", "cause", nas.CausePayloadNotForwarded,
			"spec_ref", "TS 24.501 §5.4.5.2.5",
		)
		return h.rejectULNASTransport(ue, pduSessionID,
			transport.PayloadContainerType, transport.PayloadContainer,
			uint8(nas.CausePayloadNotForwarded))
	}

	// Use the subscribed DNN as the default only when the UE did NOT provide one.
	// Per TS 23.502 §4.3.2.2.1: the subscribed DNN is substituted only when the
	// UE omits the DNN IE. When the UE provides an explicit DNN it is honoured
	// (the SMF will fall back to the internet pool if the DNN has no pool entry).
	if !ueProvidedDNN && snssai.DNN != "" {
		dnn = snssai.DNN
		log.Info("PDU Session: UE provided no DNN — using subscribed default",
			"subscribed_dnn", snssai.DNN,
			"spec_ref", "TS 23.502 §4.3.2.2.1 step 3a",
		)
	}

	log = log.With("pdu_session_id", pduSessionID, "snssai_sst", snssai.SST, "snssai_sd", snssai.SD)
	log.Info("PDU Session Establishment Request received")

	// Call SMF to create session context
	smfClient, ok := h.sender.(interface {
		CallSMF(context.Context, string, string, uint8, []byte, amfctx.SNSSAISubscribed) (smContextRef string, n1Resp []byte, n2Info []byte, negotiated features.Set, err error)
	})

	if !ok {
		log.Warn("SMF client not available")
		return nil
	}

	smContextRef, n1SmRespBody, n2SmInfo, smfFeatures, err := smfClient.CallSMF(ctx, ue.SUPI, dnn, pduSessionID, transport.PayloadContainer, snssai)
	if err != nil {
		log.Error("SMF CreateSMContext failed", "error", err)
		return nil
	}

	log.Info("SMF CreateSMContext succeeded", "smContextRef", smContextRef)

	// Wrap N1SM body with the 5GSM header → complete PDU Session Establishment
	// Accept (EPD | PSI | PTI | MT | body). Ref: TS 24.501 §8.3.2
	n1SmAccept := nas.WrapPDUSessionEstablishmentAcceptBody(pduSessionID, pti, n1SmRespBody)

	// A 5GSM message is never sent standalone over N1: it must be carried in a
	// 5GMM DL NAS TRANSPORT message (payload container type = N1 SM info) and
	// NAS-security-protected (SHT=0x02) before it becomes the NGAP NAS-PDU.
	// Ref: TS 24.501 §5.4.5.2, §8.7.2; TS 23.502 §4.3.2.2.1
	psi := pduSessionID
	dlTransport := &nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     n1SmAccept,
		PDUSessionID:         &psi,
	}
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeDLNASTransport, dlTransport)
	if err != nil {
		log.Error("encode DL NAS Transport failed", "error", err)
		return err
	}

	// Store PDU session in UE context with the resolved slice.
	// N2SmTransfer is cached for N2 handover: the target gNB needs the UPF's
	// GTP-U endpoint (uL-NGU-UP-TNL-Information) in HandoverRequestTransfer,
	// which has the same APER structure as PDUSessionResourceSetupRequestTransfer.
	ue.PDUSessions[pduSessionID] = &amfctx.PDUSession{
		PDUSessionID:  pduSessionID,
		SMFInstanceID: smContextRef,
		DNN:           dnn,
		SNSSAI:        snssai,
		N2SmTransfer:  n2SmInfo,
		Features:      smfFeatures,
	}
	h.reg.PersistUE(ctx, ue)

	// Send NGAP PDU Session Resource Setup Request to gNB
	return h.sender.SendPDUSessionResourceSetupRequest(ue, pduSessionID, nasPDU, n2SmInfo)
}

// ---- UE Policy Delivery ----------------------------------------------------

// UE policy delivery service message types (TS 24.501 §D.6.1). The container is
// not a 5GMM/5GSM message: octet 0 is the PTI, octet 1 the message type.
const (
	updsManageUEPolicyComplete      uint8 = 0x02
	updsManageUEPolicyCommandReject uint8 = 0x03
)

// handleUEPolicyDelivery processes a UE policy delivery service message carried
// in an UL NAS Transport with payload container type 0x05 (TS 24.501 Annex D).
// The modified UERANSIM sends MANAGE UE POLICY COMPLETE after applying the URSP
// rules the PCF delivered at registration; stock UERANSIM never replies. This
// closes the network-requested UE policy management procedure (TS 23.502
// §4.2.4.3 / TS 29.525).
func (h *Handler) handleUEPolicyDelivery(
	ctx context.Context, ue *amfctx.UEContext, container []byte) error {

	log := h.logger.With(
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"interface", "N1",
		"direction", "IN",
		"procedure", "UEPolicyDelivery",
		"spec_ref", "TS 24.501 Annex D",
	)

	if len(container) < 2 {
		log.Warn("UE policy container too short", "len", len(container))
		return nil
	}
	pti := container[0]
	msgType := container[1]

	switch msgType {
	case updsManageUEPolicyComplete:
		log.Info("MANAGE UE POLICY COMPLETE received — URSP delivery acknowledged",
			"pti", fmt.Sprintf("0x%02X", pti),
			"result", "OK",
		)
	case updsManageUEPolicyCommandReject:
		cause := uint8(0)
		if len(container) > 2 {
			cause = container[2]
		}
		log.Warn("MANAGE UE POLICY COMMAND REJECT received — UE rejected URSP delivery",
			"pti", fmt.Sprintf("0x%02X", pti),
			"cause", fmt.Sprintf("0x%02X", cause),
			"result", "REJECT",
		)
	default:
		log.Warn("Unhandled UE policy delivery message type",
			"msg_type", fmt.Sprintf("0x%02X", msgType),
		)
	}
	return nil
}

// ---- LPP relay (UL path, LMF-005) ------------------------------------------

// handleULLPP processes a UL NAS Transport with payload container type LPP
// (0x03) — the UE's reply to a DL LPP-PDU the LMF sent via SendDownlinkLPP.
// The AMF is a pure transparent relay: it never parses the LPP container; it
// only resolves the pendingLPP waiter keyed by AMF-UE-NGAP-ID so the blocked
// dl-lpp-info SBI handler (nf/amf/internal/sbi) can return the UL LPP-PDU to
// the LMF.
//
// If no matching pending request is found the container is an orphan (e.g.
// the dl-lpp-info handler already timed out) — logged and dropped per the
// same convention as the NRPPa relay's nrppa_orphan case.
//
// Ref: TS 24.501 §8.7.4; TS 23.273 §7.2; docs/procedures/LPPRelay.md
// §Correlation maps.
func (h *Handler) handleULLPP(_ context.Context, ue *amfctx.UEContext, lppPDU []byte) error {
	log := h.logger.With(
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"interface", "N1",
		"direction", "IN",
		"procedure", "LPPRelay",
		"spec_ref", "TS 24.501 §8.7.4",
	)
	log.Info("UplinkLPP received",
		"lpp_pdu_len", len(lppPDU),
		"result", "OK",
		"spec_ref", "TS 24.501 §8.7.4",
	)
	metrics.AMFLPPTransportTotal.WithLabelValues("UL").Inc()

	val, loaded := h.pendingLPP.LoadAndDelete(ue.AMFUENGAPId)
	if !loaded {
		log.Warn("UplinkLPP orphan — no pending dl-lpp-info request",
			"result", "lpp_orphan",
			"spec_ref", "TS 24.501 §8.7.4",
		)
		return nil
	}
	ch, ok := val.(chan LPPResult)
	if !ok {
		return nil
	}
	// Non-blocking send: ch is buffered(1). If the caller has already timed
	// out the send succeeds into the buffer and the channel is GC'd.
	ch <- LPPResult{LPPPDU: lppPDU}
	return nil
}

// SendDownlinkLPP wraps lppPDU (an opaque LPP-PDU built by the LMF) in a DL
// NAS Transport with payload container type LPP (0x03), NAS-security-protects
// it (SHT=0x02), sends it to the UE, and registers a pendingLPP waiter keyed
// by AMF-UE-NGAP-ID. The caller (nf/amf/internal/sbi's dl-lpp-info handler)
// blocks on the returned channel until handleULLPP resolves it or its own
// guard timer expires.
//
// The AMF is a pure relay — it MUST NOT decode lppPDU.
//
// Ref: TS 24.501 §8.7.4 / §9.11.3.40 (PCT=0x03); TS 23.273 §7.2 step C;
// TS 29.518 §5.2.2.6 (Namf_Location dl-lpp-info); docs/procedures/LPPRelay.md.
func (h *Handler) SendDownlinkLPP(ue *amfctx.UEContext, lppPDU []byte) (<-chan LPPResult, error) {
	nasPDU, err := h.encodeDownlinkLPP(ue, lppPDU)
	if err != nil {
		return nil, err
	}

	// Buffer of 1: handleULLPP sends into the buffer and continues even if
	// the caller has already timed out (no goroutine leak) — mirrors
	// ngap.Server.SendDownlinkNRPPa.
	ch := make(chan LPPResult, 1)
	h.pendingLPP.Store(ue.AMFUENGAPId, ch)

	h.logDownlinkLPP(ue, len(lppPDU), true)

	if err := h.sender.SendDownlinkNASTransport(ue, nasPDU); err != nil {
		h.pendingLPP.Delete(ue.AMFUENGAPId)
		return nil, fmt.Errorf("nasmsg: send downlink lpp: %w", err)
	}
	return ch, nil
}

// SendDownlinkLPPNoWait sends lppPDU in a DL NAS Transport (PCT=0x03) WITHOUT
// registering a pendingLPP waiter — the LMF-009 DL-only relay leg
// (ProvideAssistanceData: TS 37.355 assistance-data delivery is unsolicited
// and has no response message, so no UL NAS Transport is expected; a UL for
// this leg would by definition be an lpp_orphan). The AMF remains a pure
// relay and never decodes lppPDU.
//
// Ref: TS 24.501 §8.7.4 / §9.11.3.40 (PCT=0x03); TS 37.355 §6.5.2;
// docs/procedures/LPPRelay.md §Endpoints (expectUlResponse=false → 204).
func (h *Handler) SendDownlinkLPPNoWait(ue *amfctx.UEContext, lppPDU []byte) error {
	nasPDU, err := h.encodeDownlinkLPP(ue, lppPDU)
	if err != nil {
		return err
	}

	h.logDownlinkLPP(ue, len(lppPDU), false)

	if err := h.sender.SendDownlinkNASTransport(ue, nasPDU); err != nil {
		return fmt.Errorf("nasmsg: send downlink lpp (no-wait): %w", err)
	}
	return nil
}

// encodeDownlinkLPP wraps an opaque LPP-PDU in a NAS-security-protected DL
// NAS Transport with payload container type LPP (0x03) — shared by
// SendDownlinkLPP and SendDownlinkLPPNoWait.
func (h *Handler) encodeDownlinkLPP(ue *amfctx.UEContext, lppPDU []byte) ([]byte, error) {
	if len(lppPDU) == 0 {
		return nil, fmt.Errorf("nasmsg: empty LPP PDU")
	}
	dlTransport := &nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeLPP,
		PayloadContainer:     lppPDU,
	}
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement, nas.MsgTypeDLNASTransport, dlTransport)
	if err != nil {
		return nil, fmt.Errorf("nasmsg: encode DL NAS Transport (LPP): %w", err)
	}
	return nasPDU, nil
}

// logDownlinkLPP emits the canonical DownlinkLPP log line + DL metric.
func (h *Handler) logDownlinkLPP(ue *amfctx.UEContext, pduLen int, expectUlResponse bool) {
	h.logger.Info("DownlinkLPP sent",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"procedure", "LPPRelay",
		"interface", "N1",
		"direction", "OUT",
		"lpp_pdu_len", pduLen,
		"expect_ul_response", expectUlResponse,
		"spec_ref", "TS 24.501 §8.7.4",
	)
	metrics.AMFLPPTransportTotal.WithLabelValues("DL").Inc()
}

// ---- SMS over NAS (UL path) ------------------------------------------------

// handleULSMS handles a UL NAS Transport with Payload Container Type = SMS (0x02).
// The AMF is a transparent relay: it never parses SM-CP/SM-RP content; it just
// forwards the opaque container to the SMSF via Nsmsf_SMService_UplinkSMS.
// Fail-open: if no SMSF client is configured the container is dropped with a warning.
// Ref: TS 23.502 §4.13.3, TS 29.540 §5.2.4, TS 24.501 §9.11.3.40
func (h *Handler) handleULSMS(
	ctx context.Context, ue *amfctx.UEContext, smsContainer []byte, log *slog.Logger,
) error {
	log = log.With(
		"procedure", "SmsOverNas",
		"interface", "N1",
		"direction", "IN",
		"spec_ref", "TS 23.502 §4.13.3",
		"supi", ue.SUPI,
	)
	log.Info("UL NAS Transport SMS received — forwarding to SMSF",
		"container_len", len(smsContainer),
		"payload_container_type", "SMS (0x02)",
		"spec_ref", "TS 24.501 §9.11.3.40",
	)

	if h.smsfClient == nil {
		log.Warn("UL SMS: no SMSF client configured — dropping MO SMS (fail-open)",
			"result", "FAILURE",
			"spec_ref", "TS 29.540 §5.2.4",
		)
		return nil
	}

	// Generate a unique SMS record ID for ack correlation.
	// Use time-based ID for simplicity; production should use a proper sequence.
	smsRecordID := fmt.Sprintf("mo-%s-%d", ue.SUPI, time.Now().UnixNano())

	// base64-encode the opaque SM-CP/RP container for the Nsmsf API.
	// Ref: TS 29.540 §6.1.6.2.3 (SmsRecordData.smsPayload)
	smsPayloadB64 := base64.StdEncoding.EncodeToString(smsContainer)

	log.Info("UL SMS: calling Nsmsf UplinkSMS",
		"supi", ue.SUPI,
		"sms_record_id", smsRecordID,
		"interface", "Nsmsf",
		"direction", "OUT",
		"spec_ref", "TS 29.540 §5.2.4",
	)

	if err := h.smsfClient.UplinkSMS(ctx, ue.SUPI, smsRecordID, smsPayloadB64); err != nil {
		// 404 CONTEXT_NOT_FOUND: SMSF has no context. Per spec (TS 29.540 §5.2.4),
		// AMF should re-trigger Activate then retry. For this increment we log and
		// absorb (the BDD scenarios exercise the happy path with a pre-existing context).
		log.Warn("UL SMS: Nsmsf UplinkSMS failed",
			"supi", ue.SUPI,
			"sms_record_id", smsRecordID,
			"error", err,
			"result", "FAILURE",
			"interface", "Nsmsf",
			"direction", "OUT",
			"spec_ref", "TS 29.540 §5.2.4",
		)
		return nil // fail-open — do not propagate error to the NAS handler
	}

	log.Info("UL SMS: Nsmsf UplinkSMS accepted",
		"supi", ue.SUPI,
		"sms_record_id", smsRecordID,
		"result", "OK",
		"spec_ref", "TS 29.540 §5.2.4",
	)
	return nil
}

// ---- PDU Session Release ---------------------------------------------------

// handlePDUSessionRelease handles a 5GSM PDU Session Release Request from the UE.
// Flow per TS 23.502 §4.3.4.2:
//  1. Build 5GSM Release Command + wrap in secured DL NAS Transport
//  2. Call SMF to delete SM context (triggers PFCP teardown on UPF)
//  3. Send NGAP PDU Session Resource Release Command to gNB (NAS-PDU embedded)
//  4. Remove PDU session from UE context
func (h *Handler) handlePDUSessionRelease(
	ctx context.Context, ue *amfctx.UEContext, pduSessionID, pti uint8,
	log *slog.Logger,
) error {
	log = log.With("procedure", "PDUSessionRelease", "pdu_session_id", pduSessionID)
	log.Info("PDU Session Release Request received",
		"interface", "N1", "direction", "IN",
		"spec_ref", "TS 24.501 §8.3.8",
	)

	// Look up the PDU session
	ue.Lock()
	pduSess, ok := ue.PDUSessions[pduSessionID]
	ue.Unlock()
	if !ok {
		log.Warn("PDU Session Release: unknown PDU session ID")
		return nil
	}
	smContextRef := pduSess.SMFInstanceID

	// Build 5GSM PDU Session Release Command and wrap in a secured DL NAS Transport
	releaseCmd := nas.WrapPDUSessionReleaseCommandBody(pduSessionID, pti, nas.Cause5GSMRegularDeactivation)
	psi := pduSessionID
	dlTransport := &nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     releaseCmd,
		PDUSessionID:         &psi,
	}
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeDLNASTransport, dlTransport)
	if err != nil {
		log.Error("encode DL NAS Transport for Release Command failed", "error", err)
		return err
	}

	// Call SMF to delete the SM context (async — fire and forget, PFCP teardown happens there)
	if smContextRef != "" {
		smfDel, canDel := h.sender.(interface {
			DeleteSMContext(ctx context.Context, smContextRef string) error
		})
		if canDel {
			// Detach from the caller's context: this outlives the handler that
			// spawned it, and a cancelled ctx aborts the DELETE in flight.
			delCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseSMContextTimeout)
			go func() {
				defer cancel()
				if err := smfDel.DeleteSMContext(delCtx, smContextRef); err != nil {
					log.Warn("SMF DeleteSMContext failed", "error", err, "smContextRef", smContextRef)
				} else {
					log.Info("SMF DeleteSMContext succeeded", "smContextRef", smContextRef)
				}
			}()
		}
	}

	// Send NGAP PDU Session Resource Release Command to gNB
	if err := h.sender.SendPDUSessionResourceReleaseCommand(ue, pduSessionID, nasPDU); err != nil {
		log.Error("SendPDUSessionResourceReleaseCommand failed", "error", err)
		return err
	}

	// Remove PDU session from UE context
	ue.Lock()
	delete(ue.PDUSessions, pduSessionID)
	ue.Unlock()
	h.reg.PersistUE(ctx, ue)

	log.Info("PDU Session Release Command sent",
		"interface", "N2", "direction", "OUT",
		"spec_ref", "TS 38.413 §8.4.2",
		"result", "OK",
	)
	return nil
}

// ---- NW-Initiated PDU Session Release ----------------------------------------

// InitiateNetworkPDUSessionRelease sends a PDU Session Release Command to the UE
// on behalf of the network (e.g. operator-triggered or timer-based). The flow mirrors
// the UE-initiated path but the initiator is the AMF/network.
//
// Flow per TS 23.502 §4.3.4.3:
//  1. Build 5GSM PDU Session Release Command + wrap in secured DL NAS Transport
//  2. Send NGAP PDU Session Resource Release Command to gNB (steps 3-4)
//  3. Wait for the UE's PDU Session Release Complete on N1 (steps 5-6)
//  4. Call SMF to delete the SM context — this is the Nsmf_PDUSession_UpdateSMContext
//     of step 7, and it is what makes the SMF tear the N4 session down (step 8)
//  5. Remove PDU session from UE context
//
// Steps 3-5 run in completeNetworkPDUSessionRelease, driven either by the UE's
// Release Complete or by the T3592 guard timer if the UE never answers. Deleting
// the SM context here — before the UE has confirmed — would both invert the spec
// ordering and race the caller's request context.
//
// Ref: TS 23.502 §4.3.4.3, TS 24.501 §8.3.9
func (h *Handler) InitiateNetworkPDUSessionRelease(ctx context.Context, ue *amfctx.UEContext, pduSessionID uint8) error {
	log := h.logger.With(
		"procedure", "NetworkPDUSessionRelease",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"pdu_session_id", pduSessionID,
		"interface", "N1",
		"direction", "OUT",
		"spec_ref", "TS 23.502 §4.3.4.3",
	)

	ue.Lock()
	pduSess, ok := ue.PDUSessions[pduSessionID]
	ue.Unlock()
	if !ok {
		return fmt.Errorf("nas: NW PDU release: pduSessionID %d not found", pduSessionID)
	}
	smContextRef := pduSess.SMFInstanceID

	// PTI = 0 for NW-initiated (TS 24.501 §9.4)
	const nwPTI uint8 = 0
	releaseCmd := nas.WrapPDUSessionReleaseCommandBody(pduSessionID, nwPTI, nas.Cause5GSMRegularDeactivation)
	psi := pduSessionID
	dlTransport := &nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     releaseCmd,
		PDUSessionID:         &psi,
	}
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeDLNASTransport, dlTransport)
	if err != nil {
		return fmt.Errorf("nas: NW PDU release: encode DL NAS Transport: %w", err)
	}

	// Send NGAP PDU Session Resource Release Command to gNB (TS 23.502 §4.3.4.3 step 3)
	if err := h.sender.SendPDUSessionResourceReleaseCommand(ue, pduSessionID, nasPDU); err != nil {
		return fmt.Errorf("nas: NW PDU release: SendPDUSessionResourceReleaseCommand: %w", err)
	}

	// Arm the pending release. The SM context lives until the UE confirms with a
	// PDU Session Release Complete (step 5) or T3592 expires — see
	// completeNetworkPDUSessionRelease. The context is detached from the caller's
	// (an HTTP mgmt request whose ctx is cancelled as soon as it returns 202) but
	// keeps its values so the correlation_id survives into the SBI call.
	detached := context.WithoutCancel(ctx)
	key := pendingReleaseKey(ue.AMFUENGAPId, pduSessionID)
	st := &pendingReleaseState{smContextRef: smContextRef}
	st.guard = time.AfterFunc(t3592Guard, func() {
		log.Warn("PDU Session Release Complete not received before T3592 — releasing SM context anyway",
			"spec_ref", "TS 24.501 §10.3",
		)
		h.completeNetworkPDUSessionRelease(detached, ue, pduSessionID, "T3592_EXPIRY")
	})
	h.pendingRelease.Store(key, st)

	log.Info("NW PDU Session Release Command sent",
		"interface", "N2", "direction", "OUT",
		"spec_ref", "TS 23.502 §4.3.4.3",
		"result", "OK",
	)
	return nil
}

// completeNetworkPDUSessionRelease finishes a NW-initiated PDU Session Release
// once the UE has confirmed it (or T3592 has expired): it deletes the SM context
// at the SMF — which is what drives the N4/PFCP teardown on the UPF — and drops
// the session from the UE context. Safe to call more than once and for sessions
// that were never NW-released; both are no-ops.
//
// Ref: TS 23.502 §4.3.4.3 steps 7-8, TS 29.502 §5.2.2.3.3.
func (h *Handler) completeNetworkPDUSessionRelease(ctx context.Context, ue *amfctx.UEContext, pduSessionID uint8, reason string) {
	key := pendingReleaseKey(ue.AMFUENGAPId, pduSessionID)
	v, ok := h.pendingRelease.LoadAndDelete(key)
	if !ok {
		return // not a NW-initiated release, or already completed
	}
	st := v.(*pendingReleaseState)
	st.once.Do(func() {
		if st.guard != nil {
			st.guard.Stop()
		}

		log := h.logger.With(
			"procedure", "NetworkPDUSessionRelease",
			"amf_ue_ngap_id", ue.AMFUENGAPId,
			"supi", ue.SUPI,
			"pdu_session_id", pduSessionID,
			"smContextRef", st.smContextRef,
			"reason", reason,
		)

		if st.smContextRef != "" {
			if smfDel, canDel := h.sender.(interface {
				DeleteSMContext(ctx context.Context, smContextRef string) error
			}); canDel {
				delCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseSMContextTimeout)
				defer cancel()
				if err := smfDel.DeleteSMContext(delCtx, st.smContextRef); err != nil {
					log.Warn("SMF DeleteSMContext failed on NW PDU release",
						"interface", "Nsmf", "direction", "OUT",
						"spec_ref", "TS 29.502 §5.2.2.3.3",
						"result", "FAILURE", "error", err,
					)
				} else {
					log.Info("SM context deleted at SMF",
						"interface", "Nsmf", "direction", "OUT",
						"spec_ref", "TS 23.502 §4.3.4.3 step 7",
						"result", "OK",
					)
				}
			}
		}

		// Remove PDU session from UE context
		ue.Lock()
		delete(ue.PDUSessions, pduSessionID)
		ue.Unlock()
		h.reg.PersistUE(ctx, ue)

		log.Info("NW-initiated PDU Session Release complete",
			"spec_ref", "TS 23.502 §4.3.4.3",
			"result", "OK",
		)
	})
}

// InitiateNetworkQoSModification triggers a NW-initiated PDU Session Modification to
// update QoS parameters (5QI and AMBR) for an active session.
//
// Flow per TS 23.502 §4.3.3.2:
//  1. Trigger SMF policy update (policyUpdate=true) with new 5QI and AMBR.
//  2. SMF returns N1SM Modification Command (5GSM 0xCB) + N2SM Modify Transfer.
//  3. Wrap N1SM in secured DL NAS Transport and send NGAP Modify Request to gNB.
//
// Ref: TS 23.502 §4.3.3.2, TS 29.512 §5.2.2.3
func (h *Handler) InitiateNetworkQoSModification(ctx context.Context, ue *amfctx.UEContext, pduSessionID uint8, fiveQI, ambrDLMbps, ambrULMbps int) error {
	log := h.logger.With(
		"procedure", "NetworkQoSModification",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"pdu_session_id", pduSessionID,
		"5qi", fiveQI,
		"ambr_dl_mbps", ambrDLMbps,
		"ambr_ul_mbps", ambrULMbps,
		"spec_ref", "TS 23.502 §4.3.3.2",
	)

	ue.Lock()
	pduSess, ok := ue.PDUSessions[pduSessionID]
	ue.Unlock()
	if !ok {
		return fmt.Errorf("nas: NW QoS modify: pduSessionID %d not found", pduSessionID)
	}

	smfQoS, canModify := h.sender.(interface {
		ModifyQoSSMContext(ctx context.Context, smContextRef string, pduSessionID uint8, fiveQI, ambrDLMbps, ambrULMbps int) (n1SmResp []byte, n2SmInfo []byte, err error)
	})
	if !canModify {
		return fmt.Errorf("nas: NW QoS modify: ModifyQoSSMContext not available")
	}

	n1SmCmdBody, n2SmInfo, err := smfQoS.ModifyQoSSMContext(ctx, pduSess.SMFInstanceID, pduSessionID, fiveQI, ambrDLMbps, ambrULMbps)
	if err != nil {
		log.Error("SMF ModifyQoSSMContext failed", "error", err, "smContextRef", pduSess.SMFInstanceID)
		return fmt.Errorf("nas: NW QoS modify: SMF: %w", err)
	}

	psi := pduSessionID
	dlTransport := &nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     n1SmCmdBody,
		PDUSessionID:         &psi,
	}
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeDLNASTransport, dlTransport)
	if err != nil {
		return fmt.Errorf("nas: NW QoS modify: encode DL NAS Transport: %w", err)
	}

	log.Info("NW QoS Modification Command sending",
		"interface", "N2", "direction", "OUT",
		"spec_ref", "TS 38.413 §8.2.1",
	)
	return h.sender.SendPDUSessionResourceModifyRequest(ue, pduSessionID, nasPDU, n2SmInfo)
}

// ---- PDU Session Modification (UE-requested) -------------------------------

// handlePDUSessionModification handles a 5GSM PDU Session Modification Request from the UE.
// Flow per TS 23.502 §4.3.3.1:
//  1. Forward to SMF (ModifySMContext) with the N1SM Modification Request.
//  2. SMF returns N1SM Modification Command + N2SM Modify Request Transfer.
//  3. Wrap N1SM Command in secured DL NAS Transport and send NGAP Modify Request to gNB.
//  4. Handle PDU Session Modification Complete (separate dispatch case — no action needed).
func (h *Handler) handlePDUSessionModification(
	ctx context.Context, ue *amfctx.UEContext, pduSessionID, pti uint8,
	n1SmMsg []byte, log *slog.Logger,
) error {
	log = log.With("procedure", "PDUSessionModification", "pdu_session_id", pduSessionID)
	log.Info("PDU Session Modification Request received",
		"interface", "N1", "direction", "IN",
		"spec_ref", "TS 24.501 §8.3.5",
	)

	ue.Lock()
	pduSess, ok := ue.PDUSessions[pduSessionID]
	ue.Unlock()
	if !ok {
		log.Warn("PDU Session Modification: unknown PDU session ID")
		return nil
	}

	smfModify, canModify := h.sender.(interface {
		ModifySMContext(ctx context.Context, smContextRef string, n1SmMsg []byte, pduSessionID uint8) (n1SmResp []byte, n2SmInfo []byte, err error)
	})
	if !canModify {
		log.Warn("ModifySMContext not available")
		return nil
	}

	n1SmCmdBody, n2SmInfo, err := smfModify.ModifySMContext(ctx, pduSess.SMFInstanceID, n1SmMsg, pduSessionID)
	if err != nil {
		log.Error("SMF ModifySMContext failed", "error", err, "smContextRef", pduSess.SMFInstanceID)
		return nil
	}

	// The SMF returns the full 5GSM Modification Command (EPD|PSI|PTI|MT|body).
	// Wrap it in a secured DL NAS Transport for delivery via N1.
	psi := pduSessionID
	dlTransport := &nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     n1SmCmdBody,
		PDUSessionID:         &psi,
	}
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeDLNASTransport, dlTransport)
	if err != nil {
		log.Error("encode DL NAS Transport for Modification Command failed", "error", err)
		return err
	}

	log.Info("PDU Session Modification Command sending",
		"interface", "N2", "direction", "OUT",
		"spec_ref", "TS 38.413 §8.2.1",
	)
	return h.sender.SendPDUSessionResourceModifyRequest(ue, pduSessionID, nasPDU, n2SmInfo)
}

// resolveSessionSNSSAI picks the S-NSSAI to associate with a PDU session.
//
// Per TS 23.501 §5.15.5.2.1, the S-NSSAI of a PDU session must be one of the
// UE's Allowed NSSAI. The slice the UE requests in the UL NAS Transport is
// honoured only when it is in the Allowed NSSAI; a UE configured with a stale
// or unauthorised slice must not be able to establish a session on it — e.g.
// after the operator changes the subscriber's slice.
//
// The bool return reports whether the resolved slice is authorised. False means
// the UE asked for a slice outside its Allowed NSSAI and the caller must reject
// the request; the returned S-NSSAI is then zero and must not be used.
// Falls back to the first allowed slice when the UE indicates none; last resort
// is SST=1/SD="000001" when the UE has no Allowed NSSAI at all.
// Ref: TS 23.501 §5.15.5.2.1, TS 23.502 §4.3.2.2.1 step 3a
func resolveSessionSNSSAI(t *nas.SNSSAITransport, allowed []amfctx.SNSSAISubscribed) (amfctx.SNSSAISubscribed, bool) {
	if t != nil {
		sd := ""
		if t.SD != nil {
			sd = fmt.Sprintf("%06x", *t.SD)
		}
		requested := amfctx.SNSSAISubscribed{SST: t.SST, SD: sd}
		for _, a := range allowed {
			if a.SST == requested.SST && a.SD == requested.SD {
				// Return the subscription entry (not the UE-requested one) so that
				// the portal-assigned DNN is carried through to PDU session setup.
				return a, true
			}
		}
		// Requested slice is not in the Allowed NSSAI. Never substitute another
		// slice here: the session would silently come up on a slice the UE did
		// not ask for, with the wrong QoS and UP path, and both the UE and the
		// operator would see it as a success. The caller rejects instead.
		if len(allowed) > 0 {
			return amfctx.SNSSAISubscribed{}, false
		}
		// No Allowed NSSAI known (e.g. context restored without it) — accept the
		// requested slice rather than blocking the session on missing state.
		return requested, true
	}
	// UE indicated no S-NSSAI — the AMF selects one on its behalf, which is not
	// an authorisation failure.
	if len(allowed) > 0 {
		return allowed[0], true
	}
	return amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}, true
}

// requestedSNSSAIForLog renders the UE-requested S-NSSAI for logging. Returns
// SST=0 and an empty SD when the UE indicated no slice.
func requestedSNSSAIForLog(t *nas.SNSSAITransport) (uint8, string) {
	if t == nil {
		return 0, ""
	}
	sd := ""
	if t.SD != nil {
		sd = fmt.Sprintf("%06x", *t.SD)
	}
	return t.SST, sd
}

// formatAllowedNSSAI renders the Allowed NSSAI as "sst/sd,sst/sd" so a rejected
// request shows what the UE was actually entitled to.
func formatAllowedNSSAI(allowed []amfctx.SNSSAISubscribed) string {
	parts := make([]string, 0, len(allowed))
	for _, a := range allowed {
		parts = append(parts, fmt.Sprintf("%d/%s", a.SST, a.SD))
	}
	return strings.Join(parts, ",")
}

// rejectULNASTransport answers an UL NAS Transport whose 5GSM payload the AMF
// did not forward to the SMF. The payload container of the received message is
// echoed back alongside the 5GMM cause, per TS 24.501 §5.4.5.2.5.
func (h *Handler) rejectULNASTransport(ue *amfctx.UEContext, pduSessionID uint8,
	containerType uint8, container []byte, cause uint8) error {
	psi := pduSessionID
	return h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
		nas.MsgTypeDLNASTransport, &nas.DLNASTransport{
			PayloadContainerType: containerType,
			PayloadContainer:     container,
			PDUSessionID:         &psi,
			Cause5GMM:            &cause,
		})
}

// nssaiToSubscribed converts a NAS NSSAI (SD as uint32) to the AMF context type
// (SD as 6-char hex string, or "" when not present).
func nssaiToSubscribed(n *nas.NSSAI) []amfctx.SNSSAISubscribed {
	if n == nil {
		return nil
	}
	out := make([]amfctx.SNSSAISubscribed, 0, len(n.SNSSAIs))
	for _, s := range n.SNSSAIs {
		sd := ""
		if s.SD != nas.SDNotPresent {
			sd = fmt.Sprintf("%06x", s.SD)
		}
		out = append(out, amfctx.SNSSAISubscribed{SST: s.SST, SD: sd})
	}
	return out
}

// ---- Configuration Update Complete (TS 24.501 §8.2.30) -----------------

// handleConfigurationUpdateComplete processes the UE's acknowledgment of a
// Configuration Update Command (GUTI reallocation, NSSAI update, etc.).
// Note: URSP delivery no longer uses this procedure — it uses the UE policy
// delivery service over DL NAS TRANSPORT (see SendUEPolicyContainer).
// Ref: TS 24.501 §8.2.30
func (h *Handler) handleConfigurationUpdateComplete(_ context.Context, ue *amfctx.UEContext) error {
	h.logger.Info("ConfigurationUpdateComplete received",
		"procedure", "UEConfigurationUpdate",
		"supi", ue.SUPI,
		"interface", "N1", "direction", "IN",
		"result", "OK",
		"spec_ref", "TS 24.501 §8.2.30",
	)
	return nil
}

// SendUEPolicyContainer delivers URSP rules to the UE per the 3GPP UE policy
// delivery service: it wraps the PCF-provided UE policy container (a MANAGE UE
// POLICY COMMAND) in a DL NAS TRANSPORT message with payload container type =
// UE policy container (0x05), NAS-security-protects it (SHT=0x02), and sends it.
//
// Note: the UE policy container is NOT carried in the Configuration Update Command
// and NOT in IEI 0x7B — that IEI is "S-NSSAI location validity information" in the
// Configuration Update Command. URSP delivery uses DL NAS TRANSPORT exclusively.
//
// Returns procedures.ErrNotConnected when the UE is CM-IDLE.
// Ref: TS 24.501 §5.4.5, Annex D; TS 23.502 §4.2.4.3; TS 24.526 §4.2
func (h *Handler) SendUEPolicyContainer(
	ctx context.Context,
	ue *amfctx.UEContext,
	container []byte,
) error {
	if len(container) == 0 {
		return fmt.Errorf("nas: empty UE policy container")
	}

	ue.Lock()
	cmState := ue.CMState
	ue.Unlock()

	if cmState == amfctx.CMIdle {
		h.logger.Warn("UE CM-IDLE — UE policy delivery deferred until reconnection",
			"procedure", "UEPolicyDelivery",
			"supi", ue.SUPI,
			"spec_ref", "TS 23.502 §4.2.4.3",
		)
		return procedures.ErrNotConnected
	}

	dlTransport := &nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeUEPolicy,
		PayloadContainer:     container,
	}
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeDLNASTransport, dlTransport)
	if err != nil {
		return fmt.Errorf("nas: encode DL NAS Transport (UE policy): %w", err)
	}

	ue.Lock()
	ue.URSPVersion++
	version := ue.URSPVersion
	ue.Unlock()

	h.logger.Info("UE policy container sent",
		"procedure", "UEPolicyDelivery",
		"supi", ue.SUPI,
		"policy_container_bytes", len(container),
		"ursp_version", version,
		"nas_pdu_hex", fmt.Sprintf("%X", nasPDU),
		"interface", "N1", "direction", "OUT",
		"spec_ref", "TS 24.501 §5.4.5 / Annex D",
	)
	h.reg.PersistUE(ctx, ue)
	return h.sender.SendDownlinkNASTransport(ue, nasPDU)
}

// releaseDisplacedContext cleans up a UEContext that was superseded by a fresh
// registration for the same SUPI (e.g. UERANSIM UE container restarted without
// sending Deregistration). It releases all PDU sessions at the SMF so IP pools
// are returned and PFCP entries are removed, then removes the stale AMF context.
// Called asynchronously from handleAuthenticationResponse.
// Ref: TS 23.502 §4.2.2.2.2 — new registration supersedes an existing context
func (h *Handler) releaseDisplacedContext(ctx context.Context, stale *amfctx.UEContext) {
	stale.StopNSSAATimer()
	stale.StopDeregTimer()
	stale.Lock()
	stale.StopAllTimers()
	sessions := make(map[uint8]*amfctx.PDUSession, len(stale.PDUSessions))
	for k, v := range stale.PDUSessions {
		sessions[k] = v
	}
	supi := stale.SUPI
	stale.Unlock()

	h.logger.Info("releasing stale UE context displaced by fresh registration",
		"supi", supi,
		"amf_ue_ngap_id", stale.AMFUENGAPId,
		"pdu_sessions", len(sessions),
		"spec_ref", "TS 23.502 §4.2.2.2.2",
	)

	smfDel, canDel := h.sender.(interface {
		DeleteSMContext(ctx context.Context, smContextRef string) error
	})
	for _, sess := range sessions {
		if sess.SMFInstanceID == "" || !canDel {
			continue
		}
		if err := smfDel.DeleteSMContext(ctx, sess.SMFInstanceID); err != nil {
			h.logger.Warn("SMF DeleteSMContext failed for displaced context",
				"supi", supi,
				"smContextRef", sess.SMFInstanceID,
				"pdu_session_id", sess.PDUSessionID,
				"error", err,
			)
		}
	}

	// Remove the stale context from AMF indexes. mgr.Remove guards against
	// accidentally removing the SUPI/DB record that already belongs to the new context.
	h.reg.RemoveUEContext(ctx, stale)
}
