// Package procedures implements 3GPP 5GC procedures for the AMF.
//
// Each procedure corresponds to a flow in TS 23.502. The procedure
// functions are called from the NGAP or NAS message handlers and
// coordinate calls to peer NFs via SBI clients.
//
// Initial Registration procedure: TS 23.502 §4.2.2.2.2
// Step references in comments follow the spec numbering.
package procedures

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
)

const nfName = "AMF"

// ErrNeedSUCI is returned by Phase1_InitiateAuthentication when the UE
// presented a GUTI that cannot be resolved to a known SUPI. The NAS handler
// must respond with an Identity Request (type = SUCI) and call
// Phase1_AuthenticateWithSUCI once the UE's SUCI arrives.
// Ref: TS 24.501 §5.5.1.2.2 step 1b

// ErrServiceAreaRestricted is returned by Phase3_ProcessSMCComplete when the
// PCF service area restriction forbids the UE from registering in its current TA.
// The NAS handler must respond with a Registration Reject (5GMM cause #73).
// Ref: TS 23.501 §5.3.4, TS 24.501 §8.2.8.2 cause 0x49
var ErrServiceAreaRestricted = errors.New("service area restriction: TAC not allowed (cause #73)")
var ErrNeedSUCI = errors.New("UE presented GUTI not resolvable — need SUCI")

// NRFClient discovers NFs from the NRF.
type NRFClient interface {
	// Discover returns NF endpoints matching the given type and optional slice filter.
	// Ref: TS 29.510 §5.3.2.2.2
	Discover(ctx context.Context, targetNFType, requesterNFType string, snssais []amfctx.SNSSAISubscribed) ([]NFEndpoint, error)
}

// NSSFClient delegates slice selection to the NSSF.
// Optional: when nil, the AMF falls back to local UDM-subscription filtering.
// Ref: TS 29.531 §5.2.2.2, TS 23.502 §4.2.9
type NSSFClient interface {
	// NSSelection returns the allowed NSSAI for the given UE and requested slices.
	NSSelection(ctx context.Context, nfType, nfID string, requested []amfctx.SNSSAISubscribed) ([]amfctx.SNSSAISubscribed, error)
}

// NFEndpoint is a resolved NF address from NRF discovery.
type NFEndpoint struct {
	InstanceID string
	Address    string // host:port
}

// AUSFClient calls the AUSF for authentication.
type AUSFClient interface {
	InitiateAuth(ctx context.Context, supiOrSuci, servingNetName string) (*AUSFInitResponse, error)
	// ResyncAuth re-runs authentication with AUTS resync info.
	// Called when the UE reports AuthenticationFailure cause=SynchFailure.
	// Ref: TS 33.501 §6.1.3.2 step 11; TS 29.509 §5.7.2.2 (resynchronizationInfo)
	ResyncAuth(ctx context.Context, supiOrSuci, servingNetName string, rand [16]byte, auts []byte) (*AUSFInitResponse, error)
	ConfirmAuth(ctx context.Context, authCtxID, resStar string) (*AUSFConfirmResponse, error)
}

// AUSFInitResponse carries the 5G SE AV from AUSF.
type AUSFInitResponse struct {
	AuthCtxID string
	RAND      [16]byte
	AUTN      [16]byte
	HXRESStar []byte // 16 bytes
	SUPI      string
}

// AUSFConfirmResponse carries KAUSF from AUSF after verification.
type AUSFConfirmResponse struct {
	SUPI  string
	KAUSF []byte
}

// UDMClient calls UDM for subscriber data.
type UDMClient interface {
	RegisterAMF(ctx context.Context, supi, amfInstanceID, servingNetName string) error
	GetAMSubscriptionData(ctx context.Context, supi string) (*UDMAMSubscription, error)
	// DeregisterUECM removes the AMF registration from UDM after UE deregistration.
	// Ref: TS 29.503 §5.3.2.4
	DeregisterUECM(ctx context.Context, supi string) error
}

// UDMAMSubscription is a subset of the access/mobility subscription data from UDM.
type UDMAMSubscription struct {
	AllowedNSSAI []amfctx.SNSSAISubscribed
	AMBRUplink   uint64
	AMBRDownlink uint64
}

// PCFClient calls PCF for UE-level policy (N15 interface, Npcf_UEPolicyControl).
// Optional: when nil, no URSP policy is delivered at registration.
// Ref: TS 29.525 §4.2.2.2
type PCFClient interface {
	// CreateUEPolicyAssociation creates a policy association for a UE at registration.
	// Returns the policy association ID and the raw UE Policy Container bytes.
	// Returns polAssoID="", container=nil when the PCF has no policy for the UE.
	CreateUEPolicyAssociation(ctx context.Context, supi, servingPlmn string) (polAssoID string, container []byte, err error)
	// DeleteUEPolicyAssociation releases the policy association.
	DeleteUEPolicyAssociation(ctx context.Context, polAssoID string) error
}

// AMPolicyClient calls PCF for access-and-mobility policy (N15, Npcf_AMPolicyControl).
// Optional: when nil, no AM policy association is created at registration.
// Ref: TS 29.507 §4.2.2
type AMPolicyClient interface {
	// CreateAMPolicyAssociation creates an AM policy association at UE registration.
	// Returns the polAssoId, RFSP index (0 if not provided), and optional service area
	// restriction (nil if PCF returned none = unrestricted).
	// Ref: TS 29.507 §4.2.2.2
	CreateAMPolicyAssociation(ctx context.Context, supi, accessType, mcc, mnc string) (
		polAssoID string, rfsp int, servAreaRes *amfctx.ServiceAreaRestriction, err error)
	// DeleteAMPolicyAssociation releases the AM policy association at deregistration.
	DeleteAMPolicyAssociation(ctx context.Context, polAssoID string) error
}

// RegistrationHandler orchestrates the Initial Registration procedure.
// Ref: TS 23.502 §4.2.2.2.2
type RegistrationHandler struct {
	mgr          *amfctx.Manager
	ausf         AUSFClient
	udm          UDMClient
	nrf          NRFClient
	nssf         NSSFClient     // optional; when nil, local UDM-subscription filter is used
	pcf          PCFClient      // optional; when nil, no UE policy (URSP) N15 call is made
	amPolicy     AMPolicyClient // optional; when nil, no AM policy association is created
	nssaa        NSSAAClient    // optional; when nil, no slice-specific auth is run
	logger       *slog.Logger
	nfInstanceID string
	plmnMCC      string
	plmnMNC      string
	// ServingNetworkName built from MCC+MNC per TS 29.503 §6.1.3
	servingNetName string
	// ABBA value (0x0000 for initial registration without interworking)
	// Ref: TS 33.501 §A.7.1
	abba nas.ABBA
	// t3512Secs is the T3512 Periodic Registration Timer value in seconds.
	// Sent to the UE in Registration Accept (IEI 0x5E, GPRS Timer 3 encoding).
	// Configured via nf/amf/config/dev.yaml "timers.t3512_secs".
	// Ref: TS 24.501 §8.2.7.1, §10.2
	t3512Secs int
	// nullSecurity forces NEA0 (no ciphering) + NIA0 (no integrity) for all UEs.
	// Dev/debug only — NAS PDUs travel in plain text, visible in Wireshark.
	// Set via nf/amf/config/dev.yaml "security.null_ciphering: true".
	// TS 33.501 §6.7.2: NEA0/NIA0 MUST NOT be used in production.
	nullSecurity bool
	// defaultRFSP is the operator-configured Radio Frequency Selection Priority
	// index (1-256) sent in NGAP InitialContextSetupRequest (IE id=31) when PCF
	// does not provide one. 0 means "omit the IE entirely".
	// Ref: TS 38.413 §9.3.1.27, TS 23.501 §5.3.4.2
	defaultRFSP int
	// servedTACs is the registration area sent to the UE as the TAI list in
	// Registration Accept (IEI 0x54). The UE's current TAC is always included
	// even if absent here. Configured via nf/amf/config/dev.yaml "served_tacs".
	// Ref: TS 24.501 §9.11.3.9, TS 23.501 §5.3.2.3
	servedTACs []uint32
}

// NewRegistrationHandler builds a handler wired to the AMF's NF clients.
func NewRegistrationHandler(
	mgr *amfctx.Manager,
	ausf AUSFClient,
	udm UDMClient,
	nrf NRFClient,
	nfInstanceID, mcc, mnc string,
	logger *slog.Logger,
) *RegistrationHandler {
	snName := fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", zeroPad(mnc, 3), mcc)
	return &RegistrationHandler{
		mgr:            mgr,
		ausf:           ausf,
		udm:            udm,
		nrf:            nrf,
		logger:         logger,
		nfInstanceID:   nfInstanceID,
		plmnMCC:        mcc,
		plmnMNC:        mnc,
		servingNetName: snName,
		abba:           nas.ABBA{0x00, 0x00},
	}
}

// WithNSSF enables NSSF-delegated slice selection for this handler.
// Call once after construction if an NSSF address is configured.
// Ref: TS 23.502 §4.2.9
func (h *RegistrationHandler) WithNSSF(nssf NSSFClient) {
	h.nssf = nssf
}

// WithPCF enables N15 UE policy delivery. When set, Phase3 will call PCF
// to retrieve URSP rules and include IEI 0x7B in Registration Accept.
// Non-fatal: if the PCF call fails the registration still completes.
// Ref: TS 29.525 §4.2.2.2, TS 23.502 §4.2.2.2.2 step 17b
func (h *RegistrationHandler) WithPCF(pcf PCFClient) {
	h.pcf = pcf
}

// WithAMPolicy enables AM Policy Association (Npcf_AMPolicyControl). When set,
// Phase3 calls PCF to create an AM policy association and stores the polAssoId +
// RFSP in the UE context. Non-fatal. Ref: TS 29.507 §4.2.2, TS 23.502 §4.2.2.2.2 step 14c
func (h *RegistrationHandler) WithAMPolicy(c AMPolicyClient) {
	h.amPolicy = c
}

// WithDefaultRFSP sets the operator default RFSP index (1-256) included in every
// NGAP InitialContextSetupRequest (IE id=31). It is applied before the PCF call so
// the IE is always present on the wire; PCF can override it per-subscriber.
// Pass 0 to omit the IE when PCF is also not configured.
// Ref: TS 38.413 §9.3.1.27, TS 23.501 §5.3.4.2
func (h *RegistrationHandler) WithDefaultRFSP(rfsp int) {
	h.defaultRFSP = rfsp
}

// rfspSource returns a log-friendly label for where the final RFSP came from.
func rfspSource(pcfRFSP, defaultRFSP int) string {
	if pcfRFSP > 0 {
		return "PCF"
	}
	if defaultRFSP > 0 {
		return "OPERATOR_DEFAULT"
	}
	return "NONE"
}

// WithT3512 sets the T3512 Periodic Registration Timer value (seconds) sent to the UE
// in Registration Accept. Configure via nf/amf/config/dev.yaml "timers.t3512_secs".
// Ref: TS 24.501 §8.2.7.1 (IEI 0x5E), §10.2 (default 54 min)
func (h *RegistrationHandler) WithT3512(secs int) {
	h.t3512Secs = secs
}

// WithServedTACs sets the operator-configured TACs that form the registration
// area (TAI list) sent in Registration Accept.
// Ref: TS 24.501 §9.11.3.9, TS 23.501 §5.3.2.3
func (h *RegistrationHandler) WithServedTACs(tacs []uint32) {
	h.servedTACs = tacs
}

// buildTAIList builds the 5GS tracking area identity list for ue's
// Registration Accept: the configured served TACs plus the UE's current TAC
// (TS 24.501 §5.5.1.2.4 — the registration area assigned by the AMF shall
// include the current TAI, otherwise the UE cancels Service Request from
// CM-IDLE with "current TAI is not in the TAI list").
// Ref: TS 24.501 §9.11.3.9, §8.2.7.1 (IEI 0x54)
func (h *RegistrationHandler) buildTAIList(ue *amfctx.UEContext) []byte {
	tacs := make([]uint32, 0, len(h.servedTACs)+1)
	tacs = append(tacs, h.servedTACs...)
	current := ue.TAI.TAC
	found := false
	for _, t := range tacs {
		if t == current {
			found = true
			break
		}
	}
	if !found {
		tacs = append(tacs, current)
	}
	return nas.EncodeTAIList(h.plmnMCC, h.plmnMNC, tacs)
}

// WithNullSecurity forces NEA0+NIA0 for all UEs when enabled (dev/debug only).
// NAS PDUs travel in plain text — do NOT use in production.
// Ref: TS 33.501 §6.7.2
func (h *RegistrationHandler) WithNullSecurity(enabled bool) {
	h.nullSecurity = enabled
}

// RegistrationInput carries the decoded Registration Request and NGAP context.
type RegistrationInput struct {
	UE         *amfctx.UEContext
	RegRequest *nas.RegistrationRequest
	// Raw Registration Request bytes (needed for SecurityModeCommand replay)
	RawRegRequest []byte
}

// RegistrationOutput carries what the NAS/NGAP layer needs to send back.
type RegistrationOutput struct {
	// Phase 1: send Authentication Request NAS message
	AuthRequest *nas.AuthenticationRequest
	// Phase 2: after auth confirmed, send Security Mode Command
	SecurityModeCmd *nas.SecurityModeCommand
	// Phase 3: after SMC complete, send Registration Accept
	RegAccept *nas.RegistrationAccept
}

// Phase1_InitiateAuthentication handles steps 1-9 of TS 23.502 §4.2.2.2.2:
// receives Registration Request, discovers AUSF via NRF, triggers 5G-AKA.
//
// Returns the Authentication Request NAS message to send to the UE.
func (h *RegistrationHandler) Phase1_InitiateAuthentication(
	ctx context.Context, in RegistrationInput) (*nas.AuthenticationRequest, error) {

	ctx, span := tracing.Tracer(nfName, "procedures").Start(ctx, "InitialRegistration/Phase1")
	defer span.End()

	ue := in.UE
	span.SetAttributes(
		attribute.Int64("amf_ue_ngap_id", ue.AMFUENGAPId),
		attribute.Int64("ran_ue_ngap_id", ue.RANUENGAPId),
	)

	metrics.NASMessagesTotal.WithLabelValues(nfName, "RegistrationRequest", "IN", "OK").Inc()

	log := h.logger.With(
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"ran_ue_ngap_id", ue.RANUENGAPId,
		"spec_ref", "TS 23.502 §4.2.2.2.2",
	)

	// Step 1: extract identity from Registration Request
	// Ref: TS 23.502 §4.2.2.2.2 step 1
	suciOrGUTI := extractIdentity(in.RegRequest)
	ue.SUCI = suciOrGUTI
	ue.RegistrationType = byte(in.RegRequest.RegistrationType)
	log = log.With("suci", suciOrGUTI)

	log.Info("Registration Request received",
		"reg_type", in.RegRequest.RegistrationType,
		"interface", "N1",
		"direction", "IN",
		"message_type", "RegistrationRequest",
	)

	// Store UE security capabilities for later Security Mode Command
	if sc := in.RegRequest.UESecurityCapability; sc != nil {
		ue.UESecCapEA[0] = sc.EA0
		ue.UESecCapEA[1] = sc.EA1
		ue.UESecCapEA[2] = sc.EA2
		ue.UESecCapEA[3] = sc.EA3
		ue.UESecCapIA[0] = sc.IA0
		ue.UESecCapIA[1] = sc.IA1
		ue.UESecCapIA[2] = sc.IA2
		ue.UESecCapIA[3] = sc.IA3
		ue.RawUESecCap = sc.Raw // verbatim bytes for exact SMC replay
	}

	// If the UE presented a GUTI, try to resolve it to a known SUPI.
	// A GUTI issued by this AMF that is still in the context store can be
	// passed to AUSF as SUPI (UDM knows it). If not found — e.g. after a
	// restart or after the UE re-registers following deregistration — we must
	// request the UE's SUCI before we can call AUSF.
	// Ref: TS 24.501 §5.5.1.2.2 step 1b; TS 23.502 §4.2.2.2.2 note on GUTI
	if in.RegRequest.MobileIdentity.Type == nas.MobileIdentityGUTI {
		if guti := in.RegRequest.MobileIdentity.GUTI; guti != nil {
			if existing, ok := h.mgr.GetByTMSI(guti.TMSI); ok && existing.SUPI != "" {
				// AMF recognises this GUTI — use the known SUPI for AUSF
				suciOrGUTI = existing.SUPI
			} else {
				return nil, ErrNeedSUCI
			}
		} else {
			return nil, ErrNeedSUCI
		}
	}

	// Step 5: AMF selects AUSF via NRF discovery
	// Ref: TS 23.502 §4.2.2.2.2 step 5
	log.Info("discovering AUSF via NRF",
		"spec_ref", "TS 23.502 §4.2.2.2.2 step 5",
	)

	// Step 6-8: AUSF authentication initiation
	// Ref: TS 23.502 §4.2.2.2.2 step 6-8 (Nausf_UEAuthentication_Authenticate)
	ausfResp, err := h.ausf.InitiateAuth(ctx, suciOrGUTI, h.servingNetName)
	if err != nil {
		log.Error("AUSF authentication initiation failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "AUSF initiate auth failed")
		metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "FAILURE").Inc()
		return nil, fmt.Errorf("ausf: initiate auth: %w", err)
	}
	ue.AuthCtxID = ausfResp.AuthCtxID
	ue.PendingRAND = ausfResp.RAND

	log.Info("5G SE AV received from AUSF, sending Authentication Request to UE",
		"auth_ctx_id", ausfResp.AuthCtxID,
		"supi", ausfResp.SUPI,
		"interface", "N1",
		"direction", "OUT",
		"message_type", "AuthenticationRequest",
		"spec_ref", "TS 23.502 §4.2.2.2.2 step 8",
	)

	metrics.NASMessagesTotal.WithLabelValues(nfName, "AuthenticationRequest", "OUT", "OK").Inc()
	span.SetAttributes(attribute.String("auth_ctx_id", ausfResp.AuthCtxID))

	// Step 9: send Authentication Request to UE (TS 24.501 §8.2.1)
	return &nas.AuthenticationRequest{
		NGKSI: nas.NGKSI{KeySetIdentifier: 0, Type: 0}, // native, new
		ABBA:  h.abba,
		RAND:  ausfResp.RAND,
		AUTN:  ausfResp.AUTN,
	}, nil
}

// Phase1_AuthenticateWithSUCI is called after receiving an Identity Response
// that contains the UE's SUCI. It resumes the authentication flow that was
// deferred when Phase1_InitiateAuthentication returned ErrNeedSUCI.
//
// Pre-condition: ue.UESecCapEA/IA are already populated by Phase1.
// Ref: TS 23.502 §4.2.2.2.2 steps 6-9
func (h *RegistrationHandler) Phase1_AuthenticateWithSUCI(
	ctx context.Context, ue *amfctx.UEContext, suci string) (*nas.AuthenticationRequest, error) {

	ctx, span := tracing.Tracer(nfName, "procedures").Start(ctx, "InitialRegistration/Phase1-SUCI")
	defer span.End()

	ue.SUCI = suci
	span.SetAttributes(
		attribute.Int64("amf_ue_ngap_id", ue.AMFUENGAPId),
		attribute.String("suci", suci),
	)

	log := h.logger.With(
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"suci", suci,
		"spec_ref", "TS 23.502 §4.2.2.2.2 step 6",
	)
	log.Info("Identity Response received — resuming authentication with SUCI",
		"interface", "N1",
		"direction", "IN",
		"message_type", "IdentityResponse",
	)

	ausfResp, err := h.ausf.InitiateAuth(ctx, suci, h.servingNetName)
	if err != nil {
		log.Error("AUSF authentication initiation failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "AUSF initiate auth failed")
		metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "FAILURE").Inc()
		return nil, fmt.Errorf("ausf: initiate auth: %w", err)
	}
	ue.AuthCtxID = ausfResp.AuthCtxID
	ue.PendingRAND = ausfResp.RAND

	log.Info("5G SE AV received — sending Authentication Request",
		"auth_ctx_id", ausfResp.AuthCtxID,
		"interface", "N1",
		"direction", "OUT",
		"message_type", "AuthenticationRequest",
		"spec_ref", "TS 23.502 §4.2.2.2.2 step 8",
	)
	metrics.NASMessagesTotal.WithLabelValues(nfName, "AuthenticationRequest", "OUT", "OK").Inc()
	span.SetAttributes(attribute.String("auth_ctx_id", ausfResp.AuthCtxID))

	return &nas.AuthenticationRequest{
		NGKSI: nas.NGKSI{KeySetIdentifier: 0, Type: 0},
		ABBA:  h.abba,
		RAND:  ausfResp.RAND,
		AUTN:  ausfResp.AUTN,
	}, nil
}

// Phase1_ResyncAuth handles re-authentication after the UE reports a SQN sync
// failure.  It calls AUSF with resynchronizationInfo so UDM can recover SQN_MS
// from AUTS, then returns a fresh Authentication Request.
// Ref: TS 23.502 §4.2.2.2.2 step 11; TS 33.501 §6.1.3.2 step 11; TS 29.509 §5.7.2.2
func (h *RegistrationHandler) Phase1_ResyncAuth(
	ctx context.Context, ue *amfctx.UEContext, auts []byte) (*nas.AuthenticationRequest, error) {

	ctx, span := tracing.Tracer(nfName, "procedures").Start(ctx, "InitialRegistration/Phase1-Resync")
	defer span.End()

	suciOrSUPI := ue.SUCI
	if suciOrSUPI == "" {
		suciOrSUPI = ue.SUPI
	}
	log := h.logger.With(
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"suci_or_supi", suciOrSUPI,
		"spec_ref", "TS 33.501 §6.1.3.2 step 11",
	)
	log.Info("initiating AUTS re-synchronisation with AUSF",
		"interface", "N12",
		"direction", "OUT",
	)

	ausfResp, err := h.ausf.ResyncAuth(ctx, suciOrSUPI, h.servingNetName, ue.PendingRAND, auts)
	if err != nil {
		log.Error("AUSF resync failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "resync failed")
		return nil, fmt.Errorf("ausf: resync auth: %w", err)
	}

	ue.AuthCtxID = ausfResp.AuthCtxID
	ue.PendingRAND = ausfResp.RAND

	log.Info("resync AV received — sending new Authentication Request",
		"auth_ctx_id", ausfResp.AuthCtxID,
		"interface", "N1",
		"direction", "OUT",
		"message_type", "AuthenticationRequest",
	)
	metrics.NASMessagesTotal.WithLabelValues(nfName, "AuthenticationRequest", "OUT", "OK").Inc()
	span.SetStatus(codes.Ok, "")

	return &nas.AuthenticationRequest{
		NGKSI: nas.NGKSI{KeySetIdentifier: 0, Type: 0},
		ABBA:  h.abba,
		RAND:  ausfResp.RAND,
		AUTN:  ausfResp.AUTN,
	}, nil
}

// Phase2_ProcessAuthResponse handles the UE's Authentication Response (RES*).
// Steps 10-15 of TS 23.502 §4.2.2.2.2.
// Returns the Security Mode Command to send next.
// Phase2_ProcessAuthResponse verifies the UE's RES* with AUSF, derives NAS keys, and
// builds the Security Mode Command. The second return value is the stale UEContext that
// was previously registered for the same SUPI (if any); the caller must release its PDU
// sessions and call RemoveContext on it before proceeding.
// Ref: TS 23.502 §4.2.2.2.2 steps 10-14
func (h *RegistrationHandler) Phase2_ProcessAuthResponse(
	ctx context.Context, ue *amfctx.UEContext, authResp *nas.AuthenticationResponse) (*nas.SecurityModeCommand, *amfctx.UEContext, error) {

	ctx, span := tracing.Tracer(nfName, "procedures").Start(ctx, "InitialRegistration/Phase2")
	defer span.End()
	span.SetAttributes(attribute.Int64("amf_ue_ngap_id", ue.AMFUENGAPId))

	metrics.NASMessagesTotal.WithLabelValues(nfName, "AuthenticationResponse", "IN", "OK").Inc()

	log := h.logger.With(
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"suci", ue.SUCI,
		"spec_ref", "TS 23.502 §4.2.2.2.2",
	)
	log.Info("Authentication Response received from UE",
		"interface", "N1",
		"direction", "IN",
		"message_type", "AuthenticationResponse",
	)

	if len(authResp.RES) == 0 {
		metrics.NASMessagesTotal.WithLabelValues(nfName, "AuthenticationResponse", "IN", "FAILURE").Inc()
		span.SetStatus(codes.Error, "missing RES*")
		return nil, nil, fmt.Errorf("amf: auth response missing RES*")
	}

	// Step 11: forward RES* to AUSF for verification
	// Ref: TS 23.502 §4.2.2.2.2 step 11
	confirmResp, err := h.ausf.ConfirmAuth(ctx, ue.AuthCtxID, hex.EncodeToString(authResp.RES))
	if err != nil {
		log.Error("RES* verification failed at AUSF",
			"result", "REJECT",
			"spec_ref", "TS 33.501 §6.1.3.2 step 8",
		)
		span.RecordError(err)
		span.SetStatus(codes.Error, "RES* verification failed")
		metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "REJECT").Inc()
		return nil, nil, fmt.Errorf("ausf: confirm auth: %w", err)
	}

	// Atomically bind the SUPI to this new context. SetSUPI returns any prior context
	// that held the same SUPI — this happens when a UE reconnects (Docker restart,
	// abrupt disconnect) without having sent a Deregistration NAS message, so its old
	// context was never cleaned up. The caller receives it and releases it async.
	// Ref: TS 23.502 §4.2.2.2.2 step 3b
	displaced := h.mgr.SetSUPI(ue, confirmResp.SUPI)
	ue.KAUSF = confirmResp.KAUSF
	log = log.With("supi", ue.SUPI)
	span.SetAttributes(attribute.String("supi", ue.SUPI))

	// Step 12: derive KSEAF, KAMF
	// TS 33.501 §A.7.1: KAMF P0 = SUPI encoded as raw IMSI digits (without "imsi-" prefix).
	// UERANSIM (and free5GC) both strip the URI scheme prefix before KDF input.
	supiForKDF := strings.TrimPrefix(ue.SUPI, "imsi-")
	kseaf := kdf.KSEAF(confirmResp.KAUSF, h.servingNetName)
	kamf := kdf.KAMF(kseaf, supiForKDF, [2]byte(h.abba))
	ue.SecurityCtx.KAMF = kamf

	// Select NAS security algorithms
	// Policy: prefer NEA2 (AES-CTR), NIA2 (AES-CMAC) if UE supports them
	cipherAlg, integAlg := h.selectSecurityAlgorithms(ue)
	ue.SecurityCtx.CipheringAlgID = cipherAlg
	ue.SecurityCtx.IntegrityAlgID = integAlg

	// Derive NAS keys
	ue.SecurityCtx.KNASint = kdf.KNASint(kamf, integAlg)
	ue.SecurityCtx.KNASenc = kdf.KNASenc(kamf, cipherAlg)
	ue.SecurityCtx.NGKSI = 0 // first native context
	ue.SecurityCtx.Active = true

	log.Info("NAS security context established, sending SecurityModeCommand",
		"supi", ue.SUPI,
		"integ_alg", integAlg,
		"cipher_alg", cipherAlg,
		"interface", "N1",
		"direction", "OUT",
		"message_type", "SecurityModeCommand",
		"spec_ref", "TS 23.502 §4.2.2.2.2 step 14",
	)
	// DEV-ONLY: log NAS keys in hex for Wireshark NAS decryption.
	// cipher_alg: 0=NEA0(null) 1=NEA1(SNOW3G) 2=NEA2(AES-CTR) 3=NEA3(ZUC)
	log.Debug("NAS keys derived [Wireshark]",
		"supi", ue.SUPI,
		"cipher_alg_id", cipherAlg,
		"k_nasenc_hex", hex.EncodeToString(ue.SecurityCtx.KNASenc),
		"k_nasint_hex", hex.EncodeToString(ue.SecurityCtx.KNASint),
		"kamf_hex", hex.EncodeToString(kamf),
		"nas_dl_count", 0,
		"nas_ul_count", 0,
	)

	metrics.NASMessagesTotal.WithLabelValues(nfName, "SecurityModeCommand", "OUT", "OK").Inc()

	// Step 14: send Security Mode Command to UE (TS 24.501 §8.2.25)
	return &nas.SecurityModeCommand{
		SelectedNASSecurityAlgorithms: nas.NASSecurityAlgorithms{
			CipheringAlgorithmID: cipherAlg,
			IntegrityAlgorithmID: integAlg,
		},
		NGKSI: nas.NGKSI{KeySetIdentifier: ue.SecurityCtx.NGKSI, Type: 0},
		ReplayedUESecurityCapabilities: nas.UESecurityCapability{
			EA0: ue.UESecCapEA[0], EA1: ue.UESecCapEA[1],
			EA2: ue.UESecCapEA[2], EA3: ue.UESecCapEA[3],
			IA0: ue.UESecCapIA[0], IA1: ue.UESecCapIA[1],
			IA2: ue.UESecCapIA[2], IA3: ue.UESecCapIA[3],
			Raw: ue.RawUESecCap, // replay verbatim to satisfy UERANSIM byte comparison
		},
	}, displaced, nil
}

// Phase3_ProcessSMCComplete handles Security Mode Complete and finishes registration.
// Steps 15-20 of TS 23.502 §4.2.2.2.2.
func (h *RegistrationHandler) Phase3_ProcessSMCComplete(
	ctx context.Context, ue *amfctx.UEContext) (*nas.RegistrationAccept, error) {

	ctx, span := tracing.Tracer(nfName, "procedures").Start(ctx, "InitialRegistration/Phase3")
	defer span.End()
	span.SetAttributes(
		attribute.Int64("amf_ue_ngap_id", ue.AMFUENGAPId),
		attribute.String("supi", ue.SUPI),
	)

	metrics.NASMessagesTotal.WithLabelValues(nfName, "SecurityModeComplete", "IN", "OK").Inc()

	log := h.logger.With(
		"procedure", "InitialRegistration",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"spec_ref", "TS 23.502 §4.2.2.2.2",
	)
	log.Info("SecurityModeComplete received from UE",
		"interface", "N1",
		"direction", "IN",
		"message_type", "SecurityModeComplete",
	)

	// Step 15: register with UDM (Nudm_UECM_Registration)
	// Ref: TS 23.502 §4.2.2.2.2 step 15
	if err := h.udm.RegisterAMF(ctx, ue.SUPI, h.nfInstanceID, h.servingNetName); err != nil {
		log.Warn("UDM AMF registration failed (non-fatal)", "error", err)
		span.RecordError(err)
	}

	// Step 16: get subscription data from UDM (Nudm_SDM_Get)
	// Ref: TS 23.502 §4.2.2.2.2 step 16
	amSub, err := h.udm.GetAMSubscriptionData(ctx, ue.SUPI)
	if err != nil {
		log.Error("UDM AM subscription data fetch failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "UDM AM subscription fetch failed")
		metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "FAILURE").Inc()
		return nil, fmt.Errorf("udm: get AM subscription: %w", err)
	}
	// Compute AllowedNSSAI: prefer NSSF delegation if configured; fall back to
	// local UDM-subscription filter. NSSF failure is non-fatal — fallback keeps
	// the registration on track. Ref: TS 23.502 §4.2.9
	if h.nssf != nil {
		nssfAllowed, err := h.nssf.NSSelection(ctx, "AMF", h.nfInstanceID, ue.RequestedNSSAI)
		if err != nil {
			log.Warn("NSSF NSSelection failed — falling back to local UDM filter",
				"error", err,
				"spec_ref", "TS 23.502 §4.2.9",
			)
			ue.AllowedNSSAI = filterAllowedNSSAI(ue.RequestedNSSAI, amSub.AllowedNSSAI)
		} else {
			// Intersect NSSF result with UDM subscription to enforce subscription limits.
			ue.AllowedNSSAI = filterAllowedNSSAI(nssfAllowed, amSub.AllowedNSSAI)
			log.Info("NSSF NSSelection completed",
				"nssf_allowed_count", len(nssfAllowed),
				"final_count", len(ue.AllowedNSSAI),
				"spec_ref", "TS 29.531 §5.2.2.2",
			)
		}
	} else {
		ue.AllowedNSSAI = filterAllowedNSSAI(ue.RequestedNSSAI, amSub.AllowedNSSAI)
	}
	if len(ue.AllowedNSSAI) == 0 && len(ue.RequestedNSSAI) > 0 {
		// TODO: send RegistrationReject cause 36 "No network slices available"
		// Ref: TS 24.501 §5.5.1.2.4, cause #36
		log.Warn("NSSAI intersection empty — no requested slices are subscribed",
			"cause", "NSSAI_NOT_ALLOWED",
			"requested_count", len(ue.RequestedNSSAI),
		)
	}
	// Withhold slices subject to NSSAA from the initial Allowed NSSAI; they are
	// granted only after slice-level EAP auth succeeds (run after RegistrationComplete).
	// No-op when NSSAA is unconfigured or no slice is flagged. Ref: TS 23.502 §4.2.9.2.
	h.SplitPendingNSSAA(ue)
	ue.SubscribedAMBR.UL = amSub.AMBRUplink
	ue.SubscribedAMBR.DL = amSub.AMBRDownlink

	// Assign new 5G-GUTI
	guti := h.mgr.AssignGUTI(ctx, ue)
	ue.TransitionTo(amfctx.GMMRegistered)

	metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "OK").Inc()
	metrics.NASMessagesTotal.WithLabelValues(nfName, "RegistrationAccept", "OUT", "OK").Inc()
	span.SetAttributes(attribute.String("guti", guti.String()))

	log.Info("UE registered",
		"guti", guti.String(),
		"snssai_count", len(ue.AllowedNSSAI),
		"result", "OK",
		"interface", "N1",
		"direction", "OUT",
		"message_type", "RegistrationAccept",
		"spec_ref", "TS 23.502 §4.2.2.2.2 step 20",
	)

	// Operator default RFSP — always set before the PCF call so the IE is
	// guaranteed to be present in InitialContextSetupRequest even when PCF is
	// unavailable. PCF overrides this if it returns a non-zero value.
	// Ref: TS 38.413 §9.3.1.27 (IndexToRFSP, range 1-256), TS 23.501 §5.3.4.2
	ue.RFSP = h.defaultRFSP

	// Step 14c (optional): create AM Policy Association with PCF (Npcf_AMPolicyControl).
	// PCF may return servAreaRes (Service Area Restriction); if so, enforce it:
	// reject the registration with 5GMM cause #73 if the UE's TAC is not allowed.
	// Non-fatal when PCF is unavailable — operator default RFSP is used instead.
	// Ref: TS 23.502 §4.2.2.2.2 step 14c; TS 23.501 §5.3.4; TS 29.507 §4.2.2.2
	if h.amPolicy != nil {
		amPolID, rfsp, servAreaRes, amPolErr := h.amPolicy.CreateAMPolicyAssociation(
			ctx, ue.SUPI, "3GPP_ACCESS", h.plmnMCC, h.plmnMNC)
		if amPolErr != nil {
			log.Warn("PCF AM policy association failed — using operator default RFSP",
				"error", amPolErr,
				"rfsp_default", ue.RFSP,
				"interface", "N15",
				"spec_ref", "TS 29.507 §4.2.2.2")
		} else {
			ue.AMPolicyAssocID = amPolID
			if rfsp > 0 {
				ue.RFSP = rfsp // PCF-provided value takes precedence
			}
			ue.ServAreaRes = servAreaRes
			log.Info("PCF AM policy association created",
				"am_pol_asso_id", amPolID,
				"rfsp", ue.RFSP,
				"rfsp_source", rfspSource(rfsp, h.defaultRFSP),
				"has_serv_area_res", servAreaRes != nil,
				"interface", "N15", "direction", "OUT",
				"spec_ref", "TS 29.507 §4.2.2.2")
		}

		// Enforce service area restriction (TS 23.501 §5.3.4, TS 24.501 §8.2.8.2).
		// cause 0x49 = 73 = "Serving network not authorized"
		if ue.ServAreaRes != nil && !h.isAllowedTA(ue.TAI.TAC, ue.ServAreaRes) {
			log.Warn("UE TAC not allowed by PCF service area restriction — rejecting",
				"tac", fmt.Sprintf("%06X", ue.TAI.TAC),
				"restriction_type", ue.ServAreaRes.RestrictionType,
				"cause", "73",
				"spec_ref", "TS 23.501 §5.3.4, TS 24.501 §8.2.8.2",
			)
			metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "REJECT").Inc()
			return nil, ErrServiceAreaRestricted
		}
	}

	log.Info("RFSP assigned",
		"rfsp", ue.RFSP,
		"supi", ue.SUPI,
		"spec_ref", "TS 38.413 §9.3.1.27",
	)

	// Step 17b (optional): fetch URSP policy from PCF (N15 interface).
	// Non-fatal: if PCF is unavailable, registration proceeds without policy delivery.
	// URSP is NOT placed in Registration Accept — the UE policy container is delivered
	// via the UE policy delivery service over DL NAS TRANSPORT (payload container type
	// 0x05) immediately after RegistrationComplete (handleRegistrationComplete). The
	// container is staged in PendingPolicyContainer here.
	// Ref: TS 23.502 §4.2.2.2.2 step 17b, §4.2.4.3; TS 24.501 Annex D; TS 29.525 §4.2.2.2
	if h.pcf != nil {
		servingPlmn := h.plmnMCC + h.plmnMNC
		polAssoID, container, pcfErr := h.pcf.CreateUEPolicyAssociation(ctx, ue.SUPI, servingPlmn)
		if pcfErr != nil {
			log.Warn("PCF N15 CreateUEPolicyAssociation failed (non-fatal)",
				"error", pcfErr, "interface", "N15",
				"spec_ref", "TS 29.525 §4.2.2.2")
		} else if len(container) > 0 {
			ue.PolicyAssociationID = polAssoID
			ue.PendingPolicyContainer = container
			log.Info("PCF N15 policy association created — UE policy delivery queued for post-registration",
				"pol_asso_id", polAssoID,
				"policy_container_bytes", len(container),
				"interface", "N15", "direction", "OUT",
				"spec_ref", "TS 29.525 §4.2.2.2")
		}
	}

	// Step 20: send Registration Accept (TS 24.501 §8.2.7)
	allowedNSSAI := buildAllowedNSSAI(ue.AllowedNSSAI)
	ra := &nas.RegistrationAccept{
		RegistrationResult: 0x01, // 3GPP access
		FiveGGUTI: &nas.MobileIdentity{
			Type: nas.MobileIdentityGUTI,
			GUTI: &nas.GUTIMobileIdentity{
				MCC:         guti.MCC,
				MNC:         guti.MNC,
				AMFRegionID: guti.AMFRegionID,
				AMFSetID:    guti.AMFSetID,
				AMFID:       guti.AMFID,
				TMSI:        guti.TMSI,
			},
		},
		// TAI list (IEI 0x54): registration area. Without it UERANSIM cancels
		// Service Request from CM-IDLE ("current TAI is not in the TAI list").
		// Ref: TS 24.501 §9.11.3.9, §5.5.1.2.4
		TAIList:      h.buildTAIList(ue),
		AllowedNSSAI: &allowedNSSAI,
		// URSP intentionally omitted — delivered via DL NAS TRANSPORT after registration.
	}
	// IEI 0x5E: T3512 Periodic Registration Timer (GPRS Timer 3 encoding).
	// Ref: TS 24.501 §8.2.7.1 Table 8.2.7.1.1
	if h.t3512Secs > 0 {
		t3512 := nas.EncodeGPRSTimer3(h.t3512Secs)
		ra.T3512Value = &t3512
	}
	return ra, nil
}

// ---- helpers ------------------------------------------------------------

func extractIdentity(rr *nas.RegistrationRequest) string {
	mi := rr.MobileIdentity
	switch mi.Type {
	case nas.MobileIdentitySUCI:
		if mi.SUCI != nil {
			return fmt.Sprintf("suci-%s%s-%s-0-%d-%s",
				mi.SUCI.MCC, mi.SUCI.MNC,
				mi.SUCI.RoutingIndicator,
				mi.SUCI.ProtectionSchemeID,
				hex.EncodeToString(mi.SUCI.SchemeOutput),
			)
		}
	case nas.MobileIdentityGUTI:
		if mi.GUTI != nil {
			return fmt.Sprintf("guti-%s%s%02x%04x%08x",
				mi.GUTI.MCC, mi.GUTI.MNC,
				mi.GUTI.AMFRegionID,
				mi.GUTI.AMFSetID,
				mi.GUTI.TMSI,
			)
		}
	}
	return "unknown"
}

// selectSecurityAlgorithms chooses NAS security algorithms based on UE capability
// and AMF operator policy.
// Policy (configurable): prefer NIA2 > NIA1 > NIA0; prefer NEA2 > NEA1 > NEA0.
// When h.nullSecurity is true, forces NEA0+NIA0 (plain-text NAS for debugging).
// Ref: TS 33.501 §6.7.2
func (h *RegistrationHandler) selectSecurityAlgorithms(ue *amfctx.UEContext) (cipher, integ byte) {
	if h.nullSecurity {
		// NEA0 = no ciphering → NAS payload visible in Wireshark.
		// Integrity still uses the best algorithm the UE supports: TS 33.501 §6.7.2
		// forbids accepting IA0+EA0 together in a non-emergency registration, so
		// we must keep a real integrity algorithm or the UE will reject the SMC.
		integ = 0
		if ue.UESecCapIA[2] {
			integ = 2
		} else if ue.UESecCapIA[1] {
			integ = 1
		}
		return 0, integ
	}
	// Integrity: NIA2 preferred
	integ = 0 // NIA0 (null) fallback — should only be used for emergency
	if ue.UESecCapIA[2] {
		integ = 2 // NIA2 (AES-CMAC)
	} else if ue.UESecCapIA[1] {
		integ = 1 // NIA1 (SNOW 3G)
	}
	// Ciphering: NEA2 preferred; NEA0 = no ciphering (acceptable in lab)
	cipher = 0 // NEA0 (null cipher)
	if ue.UESecCapEA[2] {
		cipher = 2 // NEA2 (AES-CTR)
	} else if ue.UESecCapEA[1] {
		cipher = 1 // NEA1 (SNOW 3G)
	}
	return cipher, integ
}

// filterAllowedNSSAI returns the intersection of the UE's requested slices and
// its subscribed slices. If requested is empty, all subscribed slices are allowed
// (backward compatibility when UE sends no RequestedNSSAI IE).
// A requested entry with SD=="" is treated as a wildcard matching any SD with
// the same SST. Ref: TS 23.502 §4.2.2.2.2, TS 24.501 §5.5.1.2.4
func filterAllowedNSSAI(requested, subscribed []amfctx.SNSSAISubscribed) []amfctx.SNSSAISubscribed {
	if len(requested) == 0 {
		return subscribed
	}
	var result []amfctx.SNSSAISubscribed
	for _, sub := range subscribed {
		for _, req := range requested {
			if req.SST != sub.SST {
				continue
			}
			if req.SD == "" || req.SD == sub.SD {
				result = append(result, sub)
				break
			}
		}
	}
	return result
}

func buildAllowedNSSAI(subs []amfctx.SNSSAISubscribed) nas.NSSAI {
	var n nas.NSSAI
	for _, s := range subs {
		sdUint := uint32(0xFFFFFF)
		if s.SD != "" && len(s.SD) == 6 {
			b, err := hex.DecodeString(s.SD)
			if err == nil && len(b) == 3 {
				sdUint = uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
			}
		}
		n.SNSSAIs = append(n.SNSSAIs, nas.SNSSAI{SST: s.SST, SD: sdUint})
	}
	return n
}

// BuildRegistrationUpdateAccept builds a Registration Accept for Periodic or
// Mobility Registration Update when the UE already has an active NAS security
// context (no re-authentication needed).
//
// Assigns a new GUTI and keeps the existing AllowedNSSAI from the UE context.
// For Mobility Registration Update, UDM notification (new TAI) is deferred to
// future work; the TAI is already updated by the NGAP layer before this is called.
//
// Ref: TS 23.502 §4.2.2.2.3 (Mobility), §4.2.2.2.4 (Periodic)
func (h *RegistrationHandler) BuildRegistrationUpdateAccept(
	ctx context.Context, ue *amfctx.UEContext) (*nas.RegistrationAccept, error) {

	guti := h.mgr.AssignGUTI(ctx, ue)
	ue.TransitionTo(amfctx.GMMRegistered)

	metrics.ProcedureTotal.WithLabelValues(nfName, "RegistrationUpdate", "OK").Inc()
	metrics.NASMessagesTotal.WithLabelValues(nfName, "RegistrationAccept", "OUT", "OK").Inc()

	allowedNSSAI := buildAllowedNSSAI(ue.AllowedNSSAI)
	ra := &nas.RegistrationAccept{
		RegistrationResult: 0x01, // 3GPP access
		FiveGGUTI: &nas.MobileIdentity{
			Type: nas.MobileIdentityGUTI,
			GUTI: &nas.GUTIMobileIdentity{
				MCC:         guti.MCC,
				MNC:         guti.MNC,
				AMFRegionID: guti.AMFRegionID,
				AMFSetID:    guti.AMFSetID,
				AMFID:       guti.AMFID,
				TMSI:        guti.TMSI,
			},
		},
		// TAI list (IEI 0x54): registration area — same as Initial Registration.
		// Ref: TS 24.501 §9.11.3.9, §5.5.1.2.4
		TAIList:      h.buildTAIList(ue),
		AllowedNSSAI: &allowedNSSAI,
	}
	if h.t3512Secs > 0 {
		t3512 := nas.EncodeGPRSTimer3(h.t3512Secs)
		ra.T3512Value = &t3512
	}
	return ra, nil
}

// DeregisterUECM removes the AMF registration from UDM after UE deregistration.
// Ref: TS 23.502 §4.2.2.3.2 step 3, TS 29.503 §5.3.2.4
func (h *RegistrationHandler) DeregisterUECM(ctx context.Context, supi string) error {
	return h.udm.DeregisterUECM(ctx, supi)
}

// ReleaseAMPolicy releases the AM policy association at PCF.
// Non-fatal: caller logs and continues on error.
// Ref: TS 29.507 §4.2.2.4, TS 23.502 §4.2.2.3.2 step 3
func (h *RegistrationHandler) ReleaseAMPolicy(ctx context.Context, polAssoID string) error {
	if h.amPolicy == nil {
		return nil
	}
	return h.amPolicy.DeleteAMPolicyAssociation(ctx, polAssoID)
}

// ReleasePCFPolicy releases the UE policy association at PCF (URSP/Npcf_UEPolicyControl).
// Non-fatal: caller logs and continues on error.
// Ref: TS 29.525 §4.2.2.3, TS 23.502 §4.2.2.3.2 step 3
func (h *RegistrationHandler) ReleasePCFPolicy(ctx context.Context, polAssoID string) error {
	if h.pcf == nil {
		return nil
	}
	return h.pcf.DeleteUEPolicyAssociation(ctx, polAssoID)
}

// RemoveUEContext removes the UE context from all AMF indexes after deregistration.
// Ref: TS 23.502 §4.2.2.3.2 step 4
func (h *RegistrationHandler) RemoveUEContext(ctx context.Context, ue *amfctx.UEContext) {
	h.mgr.Remove(ctx, ue)
}

// PersistUE writes the UE context to PostgreSQL. No-op when no store is configured.
func (h *RegistrationHandler) PersistUE(ctx context.Context, ue *amfctx.UEContext) {
	h.mgr.PersistUE(ctx, ue)
}

// isAllowedTA returns true when the UE's TAC is permitted by the PCF service area restriction.
// Empty allowed-area list is treated as unrestricted.
// Ref: TS 23.501 §5.3.4, TS 29.507 §6.1.1.2.5
func (h *RegistrationHandler) isAllowedTA(tac uint32, sar *amfctx.ServiceAreaRestriction) bool {
	tacHex := fmt.Sprintf("%06x", tac)
	switch sar.RestrictionType {
	case "ALLOWED_AREAS":
		if len(sar.AllowedTACs) == 0 {
			return true // empty = unrestricted
		}
		for _, allowed := range sar.AllowedTACs {
			if strings.EqualFold(allowed, tacHex) {
				return true
			}
		}
		return false
	case "NOT_ALLOWED_AREAS":
		for _, blocked := range sar.NotAllowedTACs {
			if strings.EqualFold(blocked, tacHex) {
				return false
			}
		}
		return true
	default:
		return true // unknown restriction type — treat as unrestricted
	}
}

func zeroPad(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}
