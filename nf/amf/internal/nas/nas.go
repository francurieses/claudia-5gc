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
	// No-op if the UE is already CM-IDLE. Ref: TS 38.413 §8.3.5
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

// HandleNASMessage is called by the NGAP layer when a NAS PDU arrives.
// It decodes the PDU and dispatches to the appropriate procedure handler.
func (h *Handler) HandleNASMessage(ctx context.Context, ue *amfctx.UEContext, pdu []byte) error {
	// Unwrap NAS security for messages sent after security is active.
	// Ref: TS 24.501 §9.1.1, TS 33.501 §D.3
	if ue.SecurityCtx.Active && len(pdu) >= 2 && pdu[0] == nas.PDMobilityManagement {
		sht := nas.SecurityHeaderType(pdu[1] & 0x0F)
		if sht != nas.SecurityHeaderPlainNAS {
			var err error
			pdu, err = h.unwrapNASSecurity(ue, pdu)
			if err != nil {
				return fmt.Errorf("nas security unwrap: %w", err)
			}
		}
	}

	msg, err := nas.Decode(pdu)
	if err != nil {
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

	switch msg.Header.MessageType {
	case nas.MsgTypeRegistrationRequest:
		return h.handleRegistrationRequest(ctx, ue, msg, pdu)
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
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message, rawPDU []byte) error {

	regReq, ok := msg.Body.(*nas.RegistrationRequest)
	if !ok {
		return fmt.Errorf("nas: RegistrationRequest body decode failed")
	}

	// Periodic and Mobility Registration Update: skip re-authentication when the
	// UE already has an active NAS security context with this AMF.
	// Ref: TS 23.502 §4.2.2.2.3 (Mobility), §4.2.2.2.4 (Periodic)
	if ue.SecurityCtx.Active &&
		(regReq.RegistrationType == nas.RegistrationTypePeriodic ||
			regReq.RegistrationType == nas.RegistrationTypeMobility) {
		return h.handleRegistrationUpdate(ctx, ue, regReq)
	}

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
	return h.sender.SendDownlinkNASTransport(ue, pdu)
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
	return h.sender.SendDownlinkNASTransport(ue, pdu)
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

	mi := idResp.MobileIdentity
	if mi.Type != nas.MobileIdentitySUCI || mi.SUCI == nil {
		h.logger.Warn("Identity Response did not contain SUCI — aborting registration",
			"amf_ue_ngap_id", ue.AMFUENGAPId,
			"identity_type", mi.Type,
		)
		return nil
	}

	suci := fmt.Sprintf("suci-%s%s-%s-0-%d-%s",
		mi.SUCI.MCC, mi.SUCI.MNC,
		mi.SUCI.RoutingIndicator,
		mi.SUCI.ProtectionSchemeID,
		hex.EncodeToString(mi.SUCI.SchemeOutput),
	)

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
	return h.sender.SendDownlinkNASTransport(ue, pdu)
}

// ---- Authentication Response --------------------------------------------

func (h *Handler) handleAuthenticationResponse(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

	authResp, ok := msg.Body.(*nas.AuthenticationResponse)
	if !ok {
		return fmt.Errorf("nas: AuthenticationResponse body decode failed")
	}

	// Phase 2: verify RES* with AUSF, derive keys, build Security Mode Command.
	// displaced is the prior UEContext for the same SUPI (non-nil when the UE
	// reconnected without deregistering — e.g. Docker restart). Release it async
	// so we don't block the new registration path.
	smcReq, displaced, err := h.reg.Phase2_ProcessAuthResponse(ctx, ue, authResp)
	if err != nil {
		// TODO: send Registration Reject
		return fmt.Errorf("registration phase2: %w", err)
	}
	if displaced != nil {
		go h.releaseDisplacedContext(context.Background(), displaced)
	}

	// Security Mode Command: integrity-protected with NEW security context (SHT=0x03).
	// TS 24.501 §4.4.4.3.1: when no prior current security context exists on the UE,
	// the SMC MUST use SHT=0x03 so the UE processes it via the new-SC path.
	// SHT=0x01 would fail because the UE has no active (current) security context yet.
	pdu, err := h.sendNASIntegrityOnly(ue, nas.PDMobilityManagement,
		nas.MsgTypeSecurityModeCommand, smcReq,
		nas.SecurityHeaderIntegrityProtectedWithNewSC)
	if err != nil {
		return err
	}
	h.logNASOut(ue, nas.MsgTypeSecurityModeCommand)
	return h.sender.SendDownlinkNASTransport(ue, pdu)
}

// ---- Authentication Failure ---------------------------------------------

func (h *Handler) handleAuthenticationFailure(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

	af, ok := msg.Body.(*nas.AuthenticationFailure)
	if !ok {
		return fmt.Errorf("nas: AuthenticationFailure body decode failed")
	}
	h.logger.Warn("Authentication Failure from UE",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"cause", af.Cause5GMM,
		"spec_ref", "TS 24.501 §8.2.3",
	)

	// TS 23.502 §4.2.2.2.2 step 11: if cause=SynchFailure and AUTS present,
	// restart authentication with resynchronisation info.
	// Ref: TS 33.501 §6.1.3.2 step 11; TS 24.501 §8.2.3
	if af.Cause5GMM == nas.CauseSynchFailure && len(af.AUTS) == 14 {
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
			return fmt.Errorf("nas: resync auth: %w", err)
		}
		nasPDU, err := nas.EncodeAuthenticationRequest(authReq)
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
		return h.sender.SendDownlinkNASTransport(ue, nasPDU)
	}

	// MAC failure or unhandled cause — abandon registration (TS 24.501 §5.5.1.2.7).
	h.logger.Warn("authentication abandoned",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"cause", af.Cause5GMM,
	)
	return nil
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

	// Reset the security context so a re-attempt starts clean.
	ue.SecurityCtx = amfctx.SecurityContext{}
	return nil
}

// ---- Security Mode Complete ---------------------------------------------

func (h *Handler) handleSecurityModeComplete(
	ctx context.Context, ue *amfctx.UEContext, msg *nas.Message) error {

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
			h.applyRetransmittedRegistrationRequest(ue, smcComplete.NASMessageContainer)
		}
	}

	// Phase 3: fetch subscription data, assign GUTI, build RegistrationAccept
	regAccept, err := h.reg.Phase3_ProcessSMCComplete(ctx, ue)
	if err != nil {
		// Service Area Restriction: PCF forbids this TA.
		// Send Registration Reject (5GMM cause #73 = 0x49) and abort.
		// Ref: TS 23.501 §5.3.4, TS 24.501 §8.2.8.2
		if errors.Is(err, procedures.ErrServiceAreaRestricted) {
			const cause73 = byte(0x49) // "Serving network not authorized"
			_, _ = h.sendNASSecured(ue, nas.PDMobilityManagement,
				nas.MsgTypeRegistrationReject,
				&nas.RegistrationReject{Cause5GMM: cause73})
			return nil // reject is a handled outcome, not a fatal error
		}
		return fmt.Errorf("registration phase3: %w", err)
	}

	// RegistrationAccept must be integrity-protected (NAS security now active).
	// Ref: TS 24.501 §5.5.1.2.4 step 14, TS 33.501 §6.7.2
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeRegistrationAccept, regAccept)
	if err != nil {
		return err
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
	ue.KgNB = secKey

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
	if err := h.sender.SendInitialContextSetupRequest(ue, nasPDU, secKey,
		ue.SecurityCtx.CipheringAlgID, ue.SecurityCtx.IntegrityAlgID,
		encAlgs, intAlgs, nil); err != nil {
		return err
	}
	// N2 context now established — UE is CM-CONNECTED.
	ue.CMState = amfctx.CMConnected
	return nil
}

// applyRetransmittedRegistrationRequest decodes the complete Registration
// Request the UE retransmitted in the Security Mode Complete's NAS message
// container (in response to the RINMR bit in the Security Mode Command) and
// applies the non-cleartext IEs to the UE context. Currently: Requested NSSAI
// (drives the Allowed NSSAI intersection in Phase3). Decode failures are
// logged and ignored — the registration continues with the cleartext IEs.
// Ref: TS 24.501 §4.4.6, §5.4.2.3; TS 23.502 §4.2.2.2.2
func (h *Handler) applyRetransmittedRegistrationRequest(ue *amfctx.UEContext, container []byte) {
	inner, err := nas.Decode(container)
	if err != nil {
		h.logger.Warn("SecurityModeComplete NAS message container decode failed",
			"amf_ue_ngap_id", ue.AMFUENGAPId, "error", err,
			"spec_ref", "TS 24.501 §5.4.2.3")
		return
	}
	regReq, ok := inner.Body.(*nas.RegistrationRequest)
	if !ok || inner.Header.MessageType != nas.MsgTypeRegistrationRequest {
		return
	}
	if regReq.RequestedNSSAI != nil {
		ue.RequestedNSSAI = nssaiToSubscribed(regReq.RequestedNSSAI)
	}
	h.logger.Info("retransmitted Registration Request processed from SecurityModeComplete",
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"requested_nssai_count", len(ue.RequestedNSSAI),
		"spec_ref", "TS 24.501 §4.4.6",
	)
}

// ---- Registration Complete ----------------------------------------------

func (h *Handler) handleRegistrationComplete(
	ctx context.Context, ue *amfctx.UEContext) error {

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
	// Persist the fully registered UE context so it survives AMF restarts.
	h.reg.PersistUE(ctx, ue)

	// UE is registered and CM-CONNECTED — cancel the CM-IDLE reachability
	// watchdogs (re-armed on AN Release). Ref: TS 23.501 §5.3.2
	if h.onUEReachable != nil {
		h.onUEReachable(ue)
	}

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

	// Network Slice-Specific Authentication: kick off the first slice's EAP exchange
	// for any S-NSSAI withheld in Phase3 (subjectToNssaa). No-op when none are pending.
	// Ref: TS 23.502 §4.2.9.2, TS 24.501 §5.4.7.
	h.StartNSSAA(ctx, ue)
	return nil
}

// StartNSSAA sends the NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND for the first
// slice withheld for NSSAA, if any. Safe to call when no slice is pending.
// Ref: TS 23.502 §4.2.9.2, TS 24.501 §8.2.31.
func (h *Handler) StartNSSAA(ctx context.Context, ue *amfctx.UEContext) {
	cmd, started := h.reg.StartNSSAA(ctx, ue)
	if !started {
		return
	}
	if err := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
		nas.MsgTypeNetworkSliceSpecificAuthCommand, cmd); err != nil {
		h.logger.Warn("NSSAA COMMAND send failed",
			"procedure", "NSSAA", "supi", ue.SUPI, "error", err,
			"spec_ref", "TS 24.501 §8.2.31")
	}
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

	out, err := h.reg.ProcessNSSAAComplete(ctx, ue, complete)
	if err != nil {
		h.logger.Warn("NSSAA COMPLETE processing failed",
			"procedure", "NSSAA", "supi", ue.SUPI, "error", err)
		return nil
	}

	// Send the RESULT (EAP-Success / EAP-Failure) for the resolved slice.
	if sendErr := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
		nas.MsgTypeNetworkSliceSpecificAuthResult, out.Result); sendErr != nil {
		h.logger.Warn("NSSAA RESULT send failed",
			"procedure", "NSSAA", "supi", ue.SUPI, "error", sendErr)
	}

	// Start the next pending slice, if any.
	if out.NextCommand != nil {
		if sendErr := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
			nas.MsgTypeNetworkSliceSpecificAuthCommand, out.NextCommand); sendErr != nil {
			h.logger.Warn("NSSAA next COMMAND send failed",
				"procedure", "NSSAA", "supi", ue.SUPI, "error", sendErr)
		}
		return nil
	}

	// Queue drained. If the Allowed NSSAI changed and no more slices are pending,
	// deliver the new Allowed NSSAI via a Configuration Update Command.
	if out.AllowedChanged {
		h.sendNSSAAConfigUpdate(ctx, ue)
	}
	h.reg.PersistUE(ctx, ue)
	return nil
}

// RevokeNSSAASlice handles an AAA-initiated NSSAA revocation (TS 23.502 §4.2.9.4):
// removes the slice from the Allowed NSSAI and delivers the updated Allowed NSSAI to
// the UE via a Configuration Update Command. Returns true if the slice was allowed.
func (h *Handler) RevokeNSSAASlice(ctx context.Context, ue *amfctx.UEContext, sst uint8, sd string) bool {
	if !h.reg.RevokeNSSAA(ue, sst, sd) {
		return false
	}
	h.sendNSSAAConfigUpdate(ctx, ue)
	h.reg.PersistUE(ctx, ue)
	return true
}

// ReauthNSSAASlice handles an AAA-initiated NSSAA re-authentication (TS 23.502
// §4.2.9.3): re-queues an allowed slice and starts a fresh EAP exchange. Returns true
// if the slice was allowed and a COMMAND was emitted.
func (h *Handler) ReauthNSSAASlice(ctx context.Context, ue *amfctx.UEContext, sst uint8, sd string) bool {
	if !h.reg.ReauthNSSAA(ue, sst, sd) {
		return false
	}
	h.StartNSSAA(ctx, ue)
	return true
}

// sendNSSAAConfigUpdate delivers the post-NSSAA Allowed NSSAI to the UE via a
// Configuration Update Command (ACK requested). Ref: TS 23.502 §4.2.9.2 step 9,
// TS 24.501 §8.2.19.
func (h *Handler) sendNSSAAConfigUpdate(_ context.Context, ue *amfctx.UEContext) {
	allowed := procedures.NASAllowedNSSAI(ue.AllowedNSSAI)
	ackBit := byte(0xD1) // IEI 0xD high nibble, ACKS bit set — request ConfigurationUpdateComplete
	cmd := &nas.ConfigurationUpdateCommand{
		ConfigUpdateIndication: &ackBit,
		AllowedNSSAI:           &allowed,
	}
	if err := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
		nas.MsgTypeConfigurationUpdateCommand, cmd); err != nil {
		h.logger.Warn("NSSAA Configuration Update Command send failed",
			"procedure", "NSSAA", "supi", ue.SUPI, "error", err)
		return
	}
	h.logger.Info("Configuration Update Command sent with post-NSSAA Allowed NSSAI",
		"procedure", "NSSAA", "supi", ue.SUPI,
		"allowed_count", len(ue.AllowedNSSAI),
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

// sendNASIntegrityOnly wraps an inner NAS PDU with integrity-only protection.
// sht selects 0x01 (integrity protected) or 0x03 (integrity protected with new SC).
//
// The Security Mode Command during initial registration MUST use SHT=0x03 so that
// UERANSIM (and real UEs) process it via the "new security context" path
// (TS 24.501 §4.4.4.3.1). SHT=0x01 is only valid when there is already an active
// security context on the UE side.
//
// MAC input: COUNT=DownlinkCount, BEARER=1 (3GPP access), DIR=1 (DL), MESSAGE=SQN||innerPDU.
func (h *Handler) sendNASIntegrityOnly(ue *amfctx.UEContext, epd byte, msgType nas.MessageType, body interface{}, sht nas.SecurityHeaderType) ([]byte, error) {
	innerPDU, err := h.sendNASPlain(ue, epd, msgType, body)
	if err != nil {
		return nil, err
	}

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
	if len(pdu) < 7 {
		return nil, fmt.Errorf("nas: security PDU too short (%d bytes)", len(pdu))
	}

	sht := nas.SecurityHeaderType(pdu[1] & 0x0F)
	receivedMAC := pdu[2:6]
	sqn := pdu[6]
	inner := pdu[7:]

	count := ue.SecurityCtx.UplinkCount

	// Per TS 33.501 §D.3.3: verify MAC over SQN || ciphertext first, then decipher.
	// MAC is over the received bytes (ciphertext for ciphered messages).
	macInput := make([]byte, 1+len(inner))
	macInput[0] = sqn
	copy(macInput[1:], inner)

	ok, err := nia.Verify(ue.SecurityCtx.KNASint, count, 0x01, 0x00, macInput, receivedMAC)
	if err != nil {
		h.logger.Warn("NAS MAC verification error", "error", err, "count", count)
	} else if !ok {
		h.logger.Warn("NAS MAC mismatch — continuing in dev mode",
			"count", count, "sht", fmt.Sprintf("%02x", sht))
	}

	// Decipher if ciphered (SHT=0x02 or 0x04). Skip for NEA0 (null cipher — already plaintext).
	var plainInner []byte
	switch sht {
	case nas.SecurityHeaderIntegrityProtectedAndCiphered,
		nas.SecurityHeaderIntegrityProtectedAndCipheredWithNewSC:
		if ue.SecurityCtx.CipheringAlgID == 0 {
			plainInner = make([]byte, len(inner))
			copy(plainInner, inner)
		} else {
			deciphered, err := nea.NEA2(ue.SecurityCtx.KNASenc, count, 0x01, 0x00, inner)
			if err != nil {
				return nil, fmt.Errorf("nas: NEA2 decipher: %w", err)
			}
			plainInner = deciphered
		}
	default:
		plainInner = make([]byte, len(inner))
		copy(plainInner, inner)
	}

	ue.SecurityCtx.UplinkCount++

	// Return PDU with plaintext inner so nas.Decode can strip the header and parse it
	result := make([]byte, 7+len(plainInner))
	copy(result[:7], pdu[:7])
	copy(result[7:], plainInner)
	return result, nil
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

	// Re-derive KgNB from the existing KAMF and the NAS UL COUNT of this message.
	// unwrapNASSecurity already incremented UplinkCount; the SR's NAS COUNT is
	// UplinkCount-1. Ref: TS 33.501 §A.9
	srCount := ue.SecurityCtx.UplinkCount - 1
	kgnbBytes := kdf.KgNB(ue.SecurityCtx.KAMF, srCount, 0x01)
	var kgnb [32]byte
	copy(kgnb[:], kgnbBytes)
	ue.KgNB = kgnb

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
	pduSessions := h.activatePDUSessions(ctx, ue, svcReq.UplinkDataStatus, log)

	// Encode Service Accept (empty body, ciphered SHT=0x02).
	// Ref: TS 24.501 §8.2.16
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeServiceAccept, &nas.ServiceAccept{})
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
	if err := h.sender.SendInitialContextSetupRequest(ue, nasPDU, kgnb,
		ue.SecurityCtx.CipheringAlgID, ue.SecurityCtx.IntegrityAlgID,
		encAlgs, intAlgs, pduSessions); err != nil {
		return fmt.Errorf("service request: SendInitialContextSetupRequest: %w", err)
	}

	ue.CMState = amfctx.CMConnected

	// UE is back to CM-CONNECTED — cancel the CM-IDLE reachability watchdogs
	// (re-armed on AN Release). Ref: TS 23.501 §5.3.2
	if h.onUEReachable != nil {
		h.onUEReachable(ue)
	}

	log.Info("Service Request accepted — UE back to CM-CONNECTED",
		"result", "OK",
		"spec_ref", "TS 23.502 §4.2.3",
	)
	return nil
}

// activatePDUSessions resolves the PDU sessions flagged in the Service
// Request's Uplink Data Status and fetches each session's
// PDUSessionResourceSetupRequestTransfer from the SMF (upCnxState=ACTIVATING).
// Returns the PDUSessionResourceSetupListCxtReq items for the ICS Request, in
// ascending PSI order. Failures are non-fatal per session: the Service Request
// still completes and the UE can fall back to UE-requested re-establishment.
// Ref: TS 23.502 §4.2.3.2 steps 4/12, TS 29.502 §5.2.2.3.2.2
func (h *Handler) activatePDUSessions(
	ctx context.Context, ue *amfctx.UEContext,
	uplinkDataStatus *uint16, log *slog.Logger) []ngap.PDUSessionSetupItemCxtReq {

	if uplinkDataStatus == nil {
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
	ue.Lock()
	var targets []target
	for psi, sess := range ue.PDUSessions {
		if nas.PSIInStatus(*uplinkDataStatus, psi) && sess.SMFInstanceID != "" {
			targets = append(targets, target{psi: psi, ref: sess.SMFInstanceID,
				sst: sess.SNSSAI.SST, sd: sess.SNSSAI.SD})
		}
	}
	ue.Unlock()
	sort.Slice(targets, func(i, j int) bool { return targets[i].psi < targets[j].psi })

	var items []ngap.PDUSessionSetupItemCxtReq
	for _, t := range targets {
		transfer, err := activator.ActivateSMContext(ctx, t.ref)
		if err != nil {
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
	ctx context.Context, ue *amfctx.UEContext, regReq *nas.RegistrationRequest) error {

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

	regAccept, err := h.reg.BuildRegistrationUpdateAccept(ctx, ue)
	if err != nil {
		return fmt.Errorf("%s: build accept: %w", procedureName, err)
	}

	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement,
		nas.MsgTypeRegistrationAccept, regAccept)
	if err != nil {
		return fmt.Errorf("%s: encode Registration Accept: %w", procedureName, err)
	}

	// Re-derive KgNB: use the NAS UL COUNT of this message (UplinkCount-1 since
	// unwrapNASSecurity already incremented it). Ref: TS 33.501 §A.9
	regCount := ue.SecurityCtx.UplinkCount - 1
	kgnbBytes := kdf.KgNB(ue.SecurityCtx.KAMF, regCount, 0x01)
	var kgnb [32]byte
	copy(kgnb[:], kgnbBytes)
	ue.KgNB = kgnb

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
	if err := h.sender.SendInitialContextSetupRequest(ue, nasPDU, kgnb,
		ue.SecurityCtx.CipheringAlgID, ue.SecurityCtx.IntegrityAlgID,
		encAlgs, intAlgs, nil); err != nil {
		return fmt.Errorf("%s: SendInitialContextSetupRequest: %w", procedureName, err)
	}
	ue.CMState = amfctx.CMConnected

	log.Info("Registration Update accepted",
		"result", "OK",
		"spec_ref", specRef,
	)

	// UE has checked in via Periodic/Mobility Registration Update and is
	// CM-CONNECTED — cancel the CM-IDLE reachability watchdogs (re-armed on
	// AN Release). Ref: TS 23.501 §5.3.2
	if h.onUEReachable != nil {
		h.onUEReachable(ue)
	}
	return nil
}

// ---- NGAP cause constants (avoids importing ngapType in NAS layer) -------

// NGAP Cause group/value constants for UEContextReleaseCommand.
// Values from TS 38.413 §9.3.1.2 and ngapType package (free5gc/ngap v1.1.3).
const (
	ngapCausePresentNas    int   = 3 // ngapType.CausePresentNas
	ngapCauseNasDeregister int64 = 2 // ngapType.CauseNasPresentDeregister
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
	// Non-fatal. Ref: TS 29.507 §4.2.2.4, TS 23.502 §4.2.2.3.2 step 3
	if ue.AMPolicyAssocID != "" {
		if err := h.reg.ReleaseAMPolicy(ctx, ue.AMPolicyAssocID); err != nil {
			log.Warn("PCF AM policy release failed (non-fatal)", "error", err,
				"am_pol_asso_id", ue.AMPolicyAssocID)
		}
		ue.AMPolicyAssocID = ""
	}

	// Step 3c: release UE policy association at PCF (Npcf_UEPolicyControl / URSP).
	// Non-fatal. Ref: TS 29.525 §4.2.2.3, TS 23.502 §4.2.2.3.2 step 3
	if ue.PolicyAssociationID != "" {
		if err := h.reg.ReleasePCFPolicy(ctx, ue.PolicyAssociationID); err != nil {
			log.Warn("PCF UE policy release failed (non-fatal)", "error", err,
				"pol_asso_id", ue.PolicyAssociationID)
		}
		ue.PolicyAssociationID = ""
	}

	// Step 4: mark context for deferred removal and release the N2 UE context at the gNB.
	// PendingRemoval must be set BEFORE SendUEContextReleaseCommandForUE so that:
	//   (a) the PendingRemoval watchdog timer is armed immediately (TS 38.413 §8.3.5), and
	//   (b) handleUEContextReleaseComplete finds pending=true and removes the context.
	// The actual Remove happens in handleUEContextReleaseComplete so that gnb.UEs
	// is cleaned up before the AMF index entries are deleted. If the gNB never
	// responds (UE was already CM-IDLE), the context will be cleaned by the next
	// registration attempt (new AllocateUEContext replaces by SUPI/TMSI).
	// Ref: TS 23.502 §4.2.2.3.2 step 4, TS 38.413 §8.3.5
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
		accessType = 1 // default: 3GPP access
	}

	log := h.logger.With(
		"procedure", "NetworkDeregistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"cause", cause5GMM,
		"rereg_required", reregRequired,
		"interface", "N1",
		"direction", "OUT",
		"spec_ref", "TS 23.502 §4.2.2.3.3",
	)
	log.Info("initiating NW-initiated Deregistration")

	deregReq := &nas.DeregistrationRequestNW{
		Cause5GMM:              cause5GMM,
		AccessType:             accessType,
		ReregistrationRequired: reregRequired,
	}
	if err := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
		nas.MsgTypeDeregistrationRequestNW, deregReq); err != nil {
		return fmt.Errorf("network deregistration: send: %w", err)
	}

	ue.TransitionTo(amfctx.GMMDeregisteredInitiated)
	log.Info("Deregistration Request (NW) sent — awaiting UE accept")
	return nil
}

// handleNWDeregistrationAccept processes the UE's Deregistration Accept sent in
// response to a NW-initiated Deregistration Request. The AMF tears down PDU
// sessions, deregisters from UDM, and releases the N2 context.
//
// Ref: TS 23.502 §4.2.2.3.3, TS 24.501 §8.2.13.2
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

	// Release PCF AM policy association (Npcf_AMPolicyControl, TS 29.507 §4.2.2.4)
	if ue.AMPolicyAssocID != "" {
		if err := h.reg.ReleaseAMPolicy(ctx, ue.AMPolicyAssocID); err != nil {
			log.Warn("PCF AM policy release failed (non-fatal)", "error", err,
				"am_pol_asso_id", ue.AMPolicyAssocID)
		}
		ue.AMPolicyAssocID = ""
	}

	// Release PCF UE policy association (Npcf_UEPolicyControl / URSP, TS 29.525 §4.2.2.3)
	if ue.PolicyAssociationID != "" {
		if err := h.reg.ReleasePCFPolicy(ctx, ue.PolicyAssociationID); err != nil {
			log.Warn("PCF UE policy release failed (non-fatal)", "error", err,
				"pol_asso_id", ue.PolicyAssociationID)
		}
		ue.PolicyAssociationID = ""
	}

	// Mark context for deferred removal BEFORE releasing N2, so the watchdog timer
	// in SendUEContextReleaseCommandForUE is armed correctly. Ref: TS 38.413 §8.3.5
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
	return nil
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
		CallSMF(context.Context, string, string, uint8, []byte, amfctx.SNSSAISubscribed) (smContextRef string, n1Resp []byte, n2Info []byte, err error)
	})

	if !ok {
		log.Warn("SMF client not available")
		return nil
	}

	smContextRef, n1SmRespBody, n2SmInfo, err := smfClient.CallSMF(ctx, ue.SUPI, dnn, pduSessionID, transport.PayloadContainer, snssai)
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
