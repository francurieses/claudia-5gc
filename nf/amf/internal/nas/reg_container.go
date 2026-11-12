package nasmsg

// reg_container.go - the NAS message container and the PDU session IEs of a
// REGISTRATION REQUEST (AUD-registration-12).
//
// Ref: TS 24.501 §4.4.6, §5.5.1.2.2, §5.5.1.3.2, §5.5.1.3.4

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// nasEPD5GMM is the extended protocol discriminator of 5GMM messages
// (TS 24.501 §9.2); a deciphered inner message starts with it.
const nasEPD5GMM = byte(0x7E)

// errContainerUnusable marks a NAS message container that cannot be deciphered or
// decoded into a REGISTRATION REQUEST.
var errContainerUnusable = errors.New("nas: NAS message container unusable")

// NAS ciphering algorithm identifiers (5G-EA), TS 33.501 §5.11.1 / TS 24.501 §9.11.3.34.
const (
	nea0ID = 0
	nea1ID = 1
	nea2ID = 2
	nea3ID = 3
)

// decipherNASContainer deciphers the value part of a NAS message container IE with
// the 5G NAS security context in use and the NAS COUNT of the REGISTRATION REQUEST
// that carried it. The algorithm is the one of the context (CipheringAlgID): NEA0
// is the identity, NEA2 uses the shared helper. NEA1/NEA3 have no implementation in
// shared/crypto, and a failing cipher returns (nil, err) - there is no silent
// fallback to the raw bytes. With a non-null cipher a container whose first octet
// is the plain 5GMM EPD is NOT accepted as cleartext: a UE must have ciphered it
// (TS 24.501 §4.4.6), so it is treated as undecipherable.
// Ref: TS 24.501 §4.4.6; TS 33.501 §6.4.6
func decipherNASContainer(ue *amfctx.UEContext, container []byte, count uint32) ([]byte, error) {
	alg := ue.SecurityCtx.CipheringAlgID
	if alg == nea0ID {
		return container, nil
	}
	if len(ue.SecurityCtx.KNASenc) == 0 {
		return nil, fmt.Errorf("nas: decipher container: no KNASenc for NEA%d", alg)
	}
	var plain []byte
	switch alg {
	case nea2ID:
		var err error
		plain, err = nea.NEA2(ue.SecurityCtx.KNASenc, count, 0x01, 0x00, container)
		if err != nil {
			return nil, fmt.Errorf("nas: decipher container NEA2: %w", err)
		}
	case nea1ID, nea3ID:
		return nil, fmt.Errorf("nas: decipher container: NEA%d not implemented", alg)
	default:
		return nil, fmt.Errorf("nas: decipher container: unknown NEA%d", alg)
	}
	if len(plain) == 0 || plain[0] != nasEPD5GMM {
		return nil, fmt.Errorf("nas: decipher container NEA%d: result is not a 5GMM message", alg)
	}
	return plain, nil
}

// registrationRequestFromContainer returns the REGISTRATION REQUEST to process:
// when the (integrity verified) outer message carries a NAS message container IE the
// AMF deciphers it and considers the obtained message the initial NAS message, so
// every non-cleartext IE (Requested NSSAI, 5GMM capability, PDU session status,
// Uplink data status ...) is taken from it. Without a container it returns outer.
// rawPDU is the (already unwrapped) outer PDU.
//
// When the container cannot be deciphered or decoded it returns (nil, err): the
// caller must NOT continue with the cleartext IEs but run a new authentication
// whose SECURITY MODE COMMAND carries RINMR (Additional 5G security information),
// so the UE returns the complete REGISTRATION REQUEST in the SECURITY MODE COMPLETE
// NAS message container. RINMR was chosen over a reject because the SMC/RINMR path
// already exists for the initial registration and needs no new wire element.
// Ref: TS 24.501 §4.4.6, §5.4.2.2, §5.5.1.2.2, §5.5.1.3.2; TS 33.501 §6.4.6
func (h *Handler) registrationRequestFromContainer(ctx context.Context, ue *amfctx.UEContext,
	outer *nas.RegistrationRequest, rawPDU []byte) (*nas.RegistrationRequest, error) {

	if len(outer.NASMessageContainer) == 0 {
		return outer, nil
	}
	log := h.logger.With("nf", "AMF", "procedure", "InitialRegistration", "interface", "N1",
		"direction", "IN", "amf_ue_ngap_id", ue.AMFUENGAPId, "supi", ue.SUPI,
		"spec_ref", "TS 24.501 §4.4.6")
	// Only a security protected outer message under an active context can carry a
	// ciphered container; its NAS COUNT is the one unwrapNASSecurity just consumed.
	if !ue.SecurityCtx.Active || len(rawPDU) < 2 ||
		nas.SecurityHeaderType(rawPDU[1]&0x0F) == nas.SecurityHeaderPlainNAS || ue.SecurityCtx.UplinkCount == 0 {
		log.WarnContext(ctx, "NAS message container ignored - outer REGISTRATION REQUEST not integrity protected")
		return outer, nil
	}
	plain, err := decipherNASContainer(ue, outer.NASMessageContainer, ue.SecurityCtx.UplinkCount-1)
	if err != nil {
		log.WarnContext(ctx, "NAS message container cannot be deciphered - RINMR re-authentication",
			"result", "FAILURE", "error", err.Error())
		return nil, fmt.Errorf("%w: %w", errContainerUnusable, err)
	}
	inner, err := nas.Decode(plain)
	if err != nil {
		log.WarnContext(ctx, "NAS message container decode failed - RINMR re-authentication",
			"result", "FAILURE", "error", err.Error())
		return nil, fmt.Errorf("%w: decode: %w", errContainerUnusable, err)
	}
	rr, ok := inner.Body.(*nas.RegistrationRequest)
	if !ok || inner.Header.MessageType != nas.MsgTypeRegistrationRequest {
		log.WarnContext(ctx, "NAS message container holds no REGISTRATION REQUEST - RINMR re-authentication",
			"result", "FAILURE")
		return nil, fmt.Errorf("%w: not a REGISTRATION REQUEST", errContainerUnusable)
	}
	rr.RegistrationType = outer.RegistrationType // the cleartext type routes the procedure
	log.InfoContext(ctx, "REGISTRATION REQUEST obtained from the NAS message container")
	return rr, nil
}

// statusMaskPtr converts the value octets of a PDU session status / uplink data
// status IE to the mask layout of nas.PSIInStatus; nil when absent or shorter than
// the 2 octets of the IE (TS 24.501 §9.11.3.44).
func statusMaskPtr(v []byte) *uint16 {
	if len(v) < 2 {
		return nil
	}
	m := nas.StatusMaskFromBytes(v)
	return &m
}

// regSessionSync is the outcome of the PDU session IEs of a REGISTRATION REQUEST.
type regSessionSync struct {
	// Items are the PDU sessions whose user plane is re-established (N2 SM info).
	Items []ngap.PDUSessionSetupItemCxtReq
	// StatusIE is the PDU session status for the Accept (nil: IE not requested).
	StatusIE []byte
	// ResultIE is the PDU session reactivation result for the Accept (nil: n/a).
	ResultIE []byte
	// ErrorCauses are the PDU session reactivation result error cause entries
	// (IE 0x72) of the Accept: cause #28 per PSI not re-established in a
	// Non-Allowed Area.
	ErrorCauses []nas.PDUSessionErrorCause
}

// syncPDUSessions processes the PDU session status IE (local release of the
// sessions the UE reports inactive, at the AMF and the SMF) and the Uplink data
// status IE (user-plane re-establishment, N2 SM info from the SMF) of a
// REGISTRATION REQUEST, as the Service Request path does.
// Ref: TS 24.501 §5.5.1.3.4; TS 23.502 §4.2.2.2.2 step 17, §4.2.3.2
func (h *Handler) syncPDUSessions(ctx context.Context, ue *amfctx.UEContext,
	req *nas.RegistrationRequest, log *slog.Logger) regSessionSync {

	status, ulds := statusMaskPtr(req.PDUSessionStatus), statusMaskPtr(req.UplinkDataStatus)
	released := h.releaseInactivePDUSessions(ctx, ue, status)
	// In a Non-Allowed Area the user plane is not re-activated for the Uplink
	// data status PSIs (TS 24.501 §5.5.1.3.4), but the Accept still reports each
	// requested PSI as not re-established: its bit is set in the PDU session
	// reactivation result IE (0x26) and the PDU session reactivation result error
	// cause IE (0x72) carries 5GMM cause #28 for it (§9.11.3.42, §9.11.3.43).
	activateMask := ulds
	var errCauses []nas.PDUSessionErrorCause
	if ulds != nil && ue.InNonAllowedArea() {
		log.WarnContext(ctx, "UE in a Non-Allowed Area - uplink data status PDU sessions not re-activated",
			"result", "REJECT", "cause", causeRestrictedServiceArea,
			"spec_ref", "TS 24.501 §5.5.1.3.4")
		for psi := uint8(1); psi <= 15; psi++ {
			if nas.PSIInStatus(*ulds, psi) {
				errCauses = append(errCauses, nas.PDUSessionErrorCause{
					PDUSessionID: psi, Cause5GMM: causeRestrictedServiceArea})
			}
		}
		z := uint16(0) // empty mask: nothing to activate; ulds keeps the request
		activateMask = &z
	}
	items := h.activatePDUSessions(ctx, ue, activateMask, released, log)
	out := regSessionSync{Items: items, ErrorCauses: errCauses}
	acc := buildServiceAccept(ue, &nas.ServiceRequest{PDUSessionStatus: status, UplinkDataStatus: ulds}, released, items)
	if acc.PDUSessionStatus != nil {
		m := *acc.PDUSessionStatus
		out.StatusIE = []byte{byte(m >> 8), byte(m)}
	}
	if acc.PDUSessionReactivationResult != nil {
		m := *acc.PDUSessionReactivationResult
		out.ResultIE = []byte{byte(m >> 8), byte(m)}
	}
	log.InfoContext(ctx, "REGISTRATION REQUEST PDU session IEs processed",
		"pdu_session_status_ie", status != nil, "uplink_data_status_ie", ulds != nil,
		"released_locally", len(released), "reactivated", len(items),
		"spec_ref", "TS 24.501 §5.5.1.3.4")
	return out
}

// applyTo sets the PDU session status and PDU session reactivation result IEs of
// the REGISTRATION ACCEPT.
func (s regSessionSync) applyTo(a *nas.RegistrationAccept) {
	a.PDUSessionStatus = s.StatusIE
	a.PDUSessionReactivationResult = s.ResultIE
	a.PDUSessionReactivationResultErrorCause = s.ErrorCauses
}

// sendReactivatedSessions sends the PDU SESSION RESOURCE SETUP REQUEST of each
// re-activated PDU session when no INITIAL CONTEXT SETUP REQUEST carries them (UE
// already CM-CONNECTED). Ref: TS 38.413 §8.2.1; TS 23.502 §4.2.2.2.2 step 17
func (h *Handler) sendReactivatedSessions(ctx context.Context, ue *amfctx.UEContext,
	items []ngap.PDUSessionSetupItemCxtReq, log *slog.Logger) {
	for _, it := range items {
		if err := h.sender.SendPDUSessionResourceSetupRequest(ue, it.PDUSessionID, nil, it.Transfer); err != nil {
			log.WarnContext(ctx, "PDU SESSION RESOURCE SETUP REQUEST for reactivated session failed",
				"pdu_session_id", it.PDUSessionID, "error", err, "result", "FAILURE",
				"interface", "N2", "direction", "OUT", "spec_ref", "TS 38.413 §8.2.1")
		}
	}
}
