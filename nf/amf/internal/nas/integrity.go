package nasmsg

// integrity.go - uplink NAS integrity enforcement (AMF-033, AMF-024):
// the integrity verdict, the NAS COUNT estimation from the received SQN and the
// admission policy for unprotected / integrity-failing messages.
// Ref: TS 24.501 §4.4.3.1, §4.4.4.3; TS 33.501 §6.4.3.1.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// ErrNASIntegrity is returned (wrapped) when an uplink NAS PDU fails the
// integrity check: MAC mismatch, MAC verification error or replayed NAS COUNT.
// Ref: TS 24.501 §4.4.4.3; TS 33.501 §6.4.3.1
var ErrNASIntegrity = errors.New("nas: integrity check failed")

// IntegrityEnforcement selects how the AMF reacts to an uplink NAS message that
// fails the integrity check or arrives unprotected after security activation.
type IntegrityEnforcement string

const (
	// IntegrityStrict (the default) applies TS 24.501 §4.4.4.3 in full.
	IntegrityStrict IntegrityEnforcement = "strict"
	// IntegrityRelaxed is the legacy behaviour (log a warning and process the
	// message). For debugging only; never use in production.
	IntegrityRelaxed IntegrityEnforcement = "relaxed"
)

// EnvIntegrityEnforcement is the environment override of nas_security.integrity_enforcement.
const EnvIntegrityEnforcement = "AMF_NAS_INTEGRITY_ENFORCEMENT"

// ParseIntegrityEnforcement validates a configured mode; empty means strict.
func ParseIntegrityEnforcement(s string) (IntegrityEnforcement, error) {
	switch IntegrityEnforcement(strings.ToLower(strings.TrimSpace(s))) {
	case "", IntegrityStrict:
		return IntegrityStrict, nil
	case IntegrityRelaxed:
		return IntegrityRelaxed, nil
	}
	return "", fmt.Errorf("amf: nas_security.integrity_enforcement %q invalid (want strict|relaxed)", s)
}

// ResolveIntegrityEnforcement applies the AMF_NAS_INTEGRITY_ENFORCEMENT override
// to the YAML value and validates the result.
func ResolveIntegrityEnforcement(yamlValue string) (IntegrityEnforcement, error) {
	if v := os.Getenv(EnvIntegrityEnforcement); v != "" {
		yamlValue = v
	}
	return ParseIntegrityEnforcement(yamlValue)
}

// WithIntegrityEnforcement sets the enforcement mode (default strict).
func (h *Handler) WithIntegrityEnforcement(m IntegrityEnforcement) {
	h.integrity = m
	if m == IntegrityRelaxed {
		h.logger.Warn("NAS integrity enforcement RELAXED - integrity failures and unprotected messages are processed (debug only)",
			"nf", "AMF", "procedure", "NASSecurity", "interface", "N1",
			"spec_ref", "TS 24.501 §4.4.4.3")
	}
}

func (h *Handler) relaxedIntegrity() bool { return h.integrity == IntegrityRelaxed }

// estimateUplinkCount rebuilds the 32-bit uplink NAS COUNT from the 8-bit SQN
// of the received message: the overflow counter is that of the expected COUNT,
// incremented when the SQN wrapped. Ref: TS 24.501 §4.4.3.1; TS 33.501 §6.4.3.1
func estimateUplinkCount(expected uint32, sqn byte) uint32 {
	overflow := expected >> 8
	if sqn < byte(expected) {
		overflow++
	}
	return overflow<<8 | uint32(sqn)
}

// unprotectedAllowed lists the messages 5GMM processes without (successful)
// integrity protection before a secure exchange: TS 24.501 §4.4.4.3 (the first
// seven; SERVICE REQUEST / CONTROL PLANE SERVICE REQUEST only when a current
// context exists, handled by the caller).
func unprotectedAllowed(mt nas.MessageType, haveContext bool) bool {
	switch mt {
	case nas.MsgTypeRegistrationRequest, nas.MsgTypeIdentityResponse,
		nas.MsgTypeAuthenticationResponse, nas.MsgTypeAuthenticationFailure,
		nas.MsgTypeSecurityModeReject, nas.MsgTypeDeregistrationRequestUE,
		nas.MsgTypeDeregistrationAcceptNW:
		return true
	case nas.MsgTypeServiceRequest, nas.MsgTypeControlPlaneServiceRequest:
		return haveContext
	}
	return false
}

// discardNAS logs and counts a discarded uplink NAS message. No UE state changes.
// Ref: TS 24.501 §4.4.4.3
func (h *Handler) discardNAS(ctx context.Context, ue *amfctx.UEContext, mt nas.MessageType, mtKnown bool,
	sht nas.SecurityHeaderType, cause string) {
	mtStr := "unknown"
	if mtKnown {
		mtStr = fmt.Sprintf("%02X", byte(mt))
	}
	h.logger.WarnContext(ctx, "uplink NAS message discarded",
		"nf", "AMF", "procedure", "NASSecurity", "interface", "N1", "direction", "IN",
		"amf_ue_ngap_id", ue.AMFUENGAPId, "supi", ue.SUPI,
		"message_type", mtStr, "sht", fmt.Sprintf("%02x", byte(sht)),
		"result", "FAILURE", "cause", cause, "spec_ref", "TS 24.501 §4.4.4.3")
	metrics.ProcedureTotal.WithLabelValues("AMF", "NASSecurity", "FAILURE").Inc()
}

// admitUnverified decides what to do with an uplink message that is unprotected
// or failed the integrity check. It returns true when the caller must carry on
// processing it (as an unverified message), false when it was discarded or
// fully answered here. Ref: TS 24.501 §4.4.4.3
func (h *Handler) admitUnverified(ctx context.Context, ue *amfctx.UEContext, pdu []byte,
	sht nas.SecurityHeaderType, failedIntegrity bool) bool {
	cause := "unprotected_after_security_activation"
	if failedIntegrity {
		cause = "integrity_check_failed"
	}
	// A ciphered (SHT 2/4, non-NEA0) message that failed the check has an unreadable
	// body: never peek its type from ciphertext, discard it outright.
	if len(pdu) == 0 {
		h.discardNAS(ctx, ue, 0, false, sht, cause)
		return false
	}
	mt, known := nas.PeekMessageType(pdu)
	if !known {
		h.discardNAS(ctx, ue, mt, false, sht, cause)
		return false
	}
	// c) secure exchange established for this connection: no exceptions.
	if ue.SecureExchangeEstablished() {
		h.discardNAS(ctx, ue, mt, true, sht, "unprotected_or_failed_after_secure_exchange")
		return false
	}
	if !unprotectedAllowed(mt, ue.SecurityCtx.Active) {
		h.discardNAS(ctx, ue, mt, true, sht, cause)
		return false
	}
	switch mt {
	case nas.MsgTypeServiceRequest, nas.MsgTypeControlPlaneServiceRequest:
		// b) SERVICE REQUEST not passing the integrity check: SERVICE REJECT #9;
		// the 5GMM context and the NAS security context stay unchanged.
		h.rejectServiceUnverified(ctx, ue, mt, sht, cause)
		return false
	case nas.MsgTypeDeregistrationRequestUE:
		// b) De-registration request failing integrity / unprotected while a current
		// 5G NAS security context exists: ignored (log + metric), acting on an
		// unverifiable request would let anyone detach the UE. NOTE 2: with no
		// current context it is processed.
		if ue.SecurityCtx.Active {
			h.discardNAS(ctx, ue, mt, true, sht, cause+"_dereg_ignored")
			return false
		}
	case nas.MsgTypeIdentityResponse:
		// b) IDENTITY RESPONSE is processed unverified only when the outstanding
		// IDENTITY REQUEST asked for SUCI. sendIdentityRequest is the only sender
		// of IDENTITY REQUEST and always requests the SUCI; RegStageIdentity
		// records that it is outstanding.
		if ue.RegStage() != amfctx.RegStageIdentity {
			h.discardNAS(ctx, ue, mt, true, sht, cause+"_identity_not_requested_suci")
			return false
		}
	}
	return true
}

// rejectServiceUnverified answers an unverifiable SERVICE REQUEST with a plain
// SERVICE REJECT #9 (UE identity cannot be derived by the network) and leaves
// the 5GMM context and the NAS security context untouched.
// Ref: TS 24.501 §4.4.4.3, §5.6.1.5
func (h *Handler) rejectServiceUnverified(ctx context.Context, ue *amfctx.UEContext, mt nas.MessageType,
	sht nas.SecurityHeaderType, cause string) {
	h.logger.WarnContext(ctx, "SERVICE REQUEST failed integrity check - SERVICE REJECT #9",
		"nf", "AMF", "procedure", "ServiceRequest", "interface", "N1", "direction", "IN",
		"amf_ue_ngap_id", ue.AMFUENGAPId, "supi", ue.SUPI,
		"message_type", fmt.Sprintf("%02X", byte(mt)), "sht", fmt.Sprintf("%02x", byte(sht)),
		"result", "REJECT", "cause", cause, "spec_ref", "TS 24.501 §4.4.4.3")
	metrics.ProcedureTotal.WithLabelValues("AMF", "ServiceRequest", "REJECT").Inc()
	pdu, err := h.sendNASPlain(ue, nas.PDMobilityManagement, nas.MsgTypeServiceReject,
		&nas.ServiceReject{Cause5GMM: byte(nas.CauseUEIdentityNotDerived)})
	if err != nil {
		h.logger.Error("encode SERVICE REJECT failed", "error", err, "spec_ref", "TS 24.501 §8.2.18")
		return
	}
	if err := h.sender.SendDownlinkNASTransport(ue, pdu); err != nil {
		h.logger.Error("send SERVICE REJECT failed", "error", err, "spec_ref", "TS 24.501 §8.2.18")
	}
}
