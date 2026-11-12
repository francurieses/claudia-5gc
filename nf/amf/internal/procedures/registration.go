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
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/timercfg"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/types"
)

const nfName = "AMF"

// ErrNeedSUCI is returned by Phase1_InitiateAuthentication when the UE
// presented a GUTI that cannot be resolved to a known SUPI. The NAS handler
// must respond with an Identity Request (type = SUCI) and call
// Phase1_AuthenticateWithSUCI once the UE's SUCI arrives.
// Ref: TS 24.501 §5.5.1.2.2 step 1b; TS 23.502 §4.2.2.2.2 step 6 (SUCI neither
// provided nor retrievable from the old AMF: Identity Request is initiated).

var ErrNeedSUCI = errors.New("UE presented GUTI not resolvable — need SUCI")

// ErrUESecurityCapabilityUnacceptable is returned by Phase1_InitiateAuthentication
// when the REGISTRATION REQUEST has no UE security capability IE, or one without a
// 5GS encryption algorithm or a non-null 5GS integrity algorithm this AMF
// implements. The caller answers REGISTRATION REJECT (UESecCapRejectCause).
// Ref: TS 24.501 §5.5.1.2.8 i)
var ErrUESecurityCapabilityUnacceptable = errors.New("UE security capability invalid or unacceptable")

// ErrPEINotAccepted is returned by Phase1_InitiateAuthentication for an
// emergency registration (type 4) identified by a PEI: the AMF supports no
// emergency services. The caller answers REGISTRATION REJECT (PEINotAcceptedCause).
// Ref: TS 24.501 §5.5.1.2.5
var ErrPEINotAccepted = errors.New("emergency registration with PEI not accepted")

// PEINotAcceptedCause is 5GMM cause #5 "PEI not accepted".
// Ref: TS 24.501 Annex A.2 (cause #5), §5.5.1.2.5
const PEINotAcceptedCause nas.Cause5GMM = 5

// UESecCapRejectCause is the 5GMM cause of the REGISTRATION REJECT for an
// unacceptable UE security capability: #23 "UE security capabilities mismatch".
// TS 24.501 §5.5.1.2.8 i) NOTE 2 leaves the cause to the network implementation.
const UESecCapRejectCause = nas.CauseUESecurityCapabilitiesMismatch

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

// UDMSDMSubscriber is the optional Nudm_SDM subscription capability of a
// UDMClient (detected by type assertion, so existing UDMClient stubs keep
// compiling). Ref: TS 29.503 §5.2.2.3 (Subscribe), §5.2.2.4 (Unsubscribe)
type UDMSDMSubscriber interface {
	// SubscribeAMData creates an SDM subscription to the SUPI's am-data and
	// returns the subscription id.
	SubscribeAMData(ctx context.Context, supi string) (subscriptionID string, err error)
	// UnsubscribeSDM deletes the subscription.
	UnsubscribeSDM(ctx context.Context, supi, subscriptionID string) error
}

// UDMAMSubscription is a subset of the access/mobility subscription data from UDM.
type UDMAMSubscription struct {
	AllowedNSSAI []amfctx.SNSSAISubscribed
	AMBRUplink   uint64
	AMBRDownlink uint64
	// GPSI is the UE's GPSI from am-data "gpsis" (msisdn- form preferred), ""
	// when the subscription carries none. Ref: TS 29.503 §6.1.6.2.4
	GPSI string
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
	// Ref: TS 29.507 §4.2.2
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
	nssaaSpec    bool           // rel19: real GPSI, PENDING on non-auth failure (REL19-3.5 slice E)
	logger       *slog.Logger
	nfInstanceID string
	plmnMCC      string
	plmnMNC      string
	// ServingNetworkName built from MCC+MNC per TS 29.503 §6.1.3
	servingNetName string
	// ABBA value (0x0000 for initial registration without interworking)
	// Ref: TS 33.501 §A.7.1
	abba nas.ABBA
	// timers holds the T3512 Periodic Registration Timer value, read at use
	// time (runtime-changeable through the O&M API). Sent to the UE in
	// Registration Accept (IEI 0x5E, GPRS Timer 3 encoding). Base value from
	// nf/amf/config/dev.yaml "timers.t3512_secs".
	// Ref: TS 24.501 §8.2.7.1, §10.2
	timers *timercfg.Store
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
	// imsVoPS3GPP controls the IMS VoPS-3GPP-access bit in the "5GS network
	// feature support" IE (IEI 0x21) sent in every Registration Accept.
	// Defaults to true in NewRegistrationHandler (ClaudIA's SMF advertises an
	// "ims" DNN); override with WithIMSVoPS3GPP. Matches Open5GS's default
	// (gmm-build.c sets this bit to 1 unless operator config sets no_ims).
	// Ref: TS 24.501 §9.11.3.5, §8.2.7.1 (IEI 0x21)
	imsVoPS3GPP bool
	// nfsExt holds the operator-configured bits of the 5GS network feature
	// support IE beyond IMS-VoPS-3GPP (REL19-5.5). Zero by default: the AMF
	// sets no such bit today, so the IE stays at its legacy 2 octets.
	nfsExt nas.NetworkFeatureSupport
	// budgets are the per-step SBI timeouts (AUD-registration-20); zero value =
	// DefaultBudgets. See budget.go.
	budgets Budgets
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
		imsVoPS3GPP:    true,
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
// It installs a private store; use WithTimerStore to share the runtime store.
func (h *RegistrationHandler) WithT3512(secs int) {
	h.timers = timercfg.New(timercfg.Values{T3512Secs: secs})
}

// WithTimerStore shares the runtime timer store, so a T3512 change made through
// the O&M API is used by every Registration Accept built afterwards.
// Call before serving.
func (h *RegistrationHandler) WithTimerStore(s *timercfg.Store) {
	h.timers = s
}

// T3512 returns the effective T3512 in seconds (0 when none is configured).
func (h *RegistrationHandler) T3512() int {
	if h.timers == nil {
		return 0
	}
	return h.timers.T3512Secs()
}

// NASTimers returns the effective runtime timer values; the zero Values (every
// accessor falling back to the TS 24.501 §10.2 defaults) when no store is set.
// Read at use time so a PUT /amf/v1/config/timers takes effect on the next arming.
func (h *RegistrationHandler) NASTimers() timercfg.Values {
	if h.timers == nil {
		return timercfg.Values{}
	}
	return h.timers.Effective()
}

// setT3512Value fills IEI 0x5E in ra from the effective T3512, loaded once, and
// records the value sent on the UE (lowered-T3512 mitigation, TS 24.501 §5.3.7).
func (h *RegistrationHandler) setT3512Value(ra *nas.RegistrationAccept, ue *amfctx.UEContext) {
	secs := h.T3512()
	if secs <= 0 {
		return
	}
	t3512 := nas.EncodeGPRSTimer3(secs)
	ra.T3512Value = &t3512
	ue.SetT3512SentSecs(secs)
}

// WithServedTACs sets the operator-configured TACs that form the registration
// area (TAI list) sent in Registration Accept.
// Ref: TS 24.501 §9.11.3.9, TS 23.501 §5.3.2.3
func (h *RegistrationHandler) WithServedTACs(tacs []uint32) {
	h.servedTACs = tacs
}

// WithIMSVoPS3GPP sets the IMS VoPS-3GPP-access bit advertised in the "5GS
// network feature support" IE (IEI 0x21) of every Registration Accept.
// Defaults to true (set in NewRegistrationHandler). Set false if the
// deployment has no IMS DNN reachable, to avoid a phone attempting VoNR
// registration against a network that cannot serve it.
// Ref: TS 24.501 §9.11.3.5, §8.2.7.1 (IEI 0x21)
func (h *RegistrationHandler) WithIMSVoPS3GPP(supported bool) {
	h.imsVoPS3GPP = supported
}

// FeatureNFSExtended gates the extended (octets 5 and 6) form of the 5GS
// network feature support IE in the Registration Accept. Default off.
// Ref: TS 24.501 §9.11.3.5 (octets 5-6 are Rel-16/17 and Rel-18/19 bits).
const FeatureNFSExtended = "NAS-NFS-EXT"

func init() {
	capability.MustRegister(capability.Feature{
		ID:         FeatureNFSExtended,
		Title:      "5GS network feature support: octets 5-6 in Registration Accept",
		Release:    capability.Rel18,
		Normative:  false,
		Visibility: "public",
		SpecRef:    "TS 24.501 §9.11.3.5",
		NFs:        []string{"AMF"},
	})
}

// WithNetworkFeatureSupportBits sets the 5GS network feature support bits the
// AMF advertises in addition to IMS-VoPS-3GPP (which stays controlled by
// WithIMSVoPS3GPP). Bits in octets 5-6 reach the wire only when
// FeatureNFSExtended is gated on; call once at start-up.
// Ref: TS 24.501 §9.11.3.5
func (h *RegistrationHandler) WithNetworkFeatureSupportBits(n nas.NetworkFeatureSupport) {
	h.nfsExt = n
}

// networkFeatureSupport builds the IEI 0x21 content for a Registration Accept
// (initial and mobility/periodic sites). Rules:
//   - NCR, PIV, RPR, PR, UN-PER, LCS-UPP, SUPL, MLCSUP, EF5L and RSLP are set
//     only if the operator enabled them AND the UE set the matching 5GMM
//     capability bit in its REGISTRATION REQUEST (no capability IE -> none).
//   - Bits introduced after Rel-17 (UN-PER, octet 6) additionally need
//     FeatureNFSExtended gated on. Rel-16/17 bits of octet 5 are not part of
//     that Rel-18 seam, so they are not dropped by it; the AMF sets none by
//     default, so legacy (rel17 / nil profile) bytes stay the 2-octet form.
//
// Ref: TS 24.501 §5.5.1.2.4, §5.5.1.3.4, §9.11.3.5, §8.2.7.1
func (h *RegistrationHandler) networkFeatureSupport(ctx context.Context, ue *amfctx.UEContext) []byte {
	n := h.nfsExt
	n.IMSVoPS3GPP = h.imsVoPS3GPP
	var c *nas.FiveGMMCapability
	if ue != nil {
		c = ue.Capability5GMM
	}
	n = n.LimitToUECapability(c)
	limit := nas.NFSLegacyOctets + 1 // octet 5: Rel-16/17 bits only
	if capability.Gate(ctx, FeatureNFSExtended) {
		limit = nas.NFSMaxOctets
	} else {
		n = n.DropAfterRel17()
	}
	return n.Encode(limit)
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

// allocateFreshNGKSI returns an ngKSI value in the valid range 0..6 that differs
// from currentKSI (the ngKSI the UE reports for its existing native 5G security
// context, or 7 = "no key available"). (currentKSI+1)%7 is guaranteed to differ
// from currentKSI for currentKSI in 0..6, and maps the "no key" value 7 to 1.
// Assigning a colliding ngKSI makes a spec-conformant UE reject the Authentication
// Request with 5GMM cause #71 "ngKSI already in use".
// Ref: TS 24.501 §5.4.1.2.1, §5.4.1.3.2, §5.4.1.3.7.
func allocateFreshNGKSI(currentKSI byte) byte {
	return (currentKSI + 1) % 7
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

	// Allocate a fresh ngKSI for this authentication, distinct from the one the UE
	// reports for its existing native 5G security context. Reusing the same value
	// makes a spec-conformant UE (e.g. a real Nokia UE) reject the Authentication
	// Request with 5GMM cause #71 "ngKSI already in use". Computed once here so the
	// SUCI-retry and AUTS-resync paths reuse it via ue.PendingNGKSI.
	// Ref: TS 24.501 §5.4.1.2.1, §5.4.1.3.2, §5.4.1.3.7.
	ue.PendingNGKSI = allocateFreshNGKSI(in.RegRequest.NGKSI.KeySetIdentifier)

	log.Info("Registration Request received",
		"reg_type", in.RegRequest.RegistrationType,
		"interface", "N1",
		"direction", "IN",
		"message_type", "RegistrationRequest",
	)

	// A new authentication starts: reset the AUTHENTICATION FAILURE bookkeeping.
	// Ref: TS 24.501 §5.4.1.3.7 c)-f)
	ue.AuthViaGUTI = false
	ue.AuthSynchFailures = 0
	ue.AuthNgKSIFailures = 0

	// A mobility/periodic update keeps its non-cleartext IEs in the NAS message
	// container; when authentication runs on the cleartext IEs only (integrity
	// of the request not verifiable, TS 24.501 §4.4.4.3 b)) the capability
	// stored at the earlier registration is used. The UE checks the replayed
	// capability in the SECURITY MODE COMMAND. Ref: TS 24.501 §4.4.6, §5.4.2.2
	ueSecCap := in.RegRequest.UESecurityCapability
	if ueSecCap == nil && len(ue.RawUESecCap) >= 2 &&
		(in.RegRequest.RegistrationType == nas.RegistrationTypePeriodic ||
			in.RegRequest.RegistrationType == nas.RegistrationTypeMobility) {
		if stored, derr := nas.DecodeUESecurityCapability(ue.RawUESecCap); derr == nil {
			stored.Raw = ue.RawUESecCap
			ueSecCap = &stored
		}
	}

	// TS 24.501 §5.5.1.2.8 i): reject a REGISTRATION REQUEST whose UE security
	// capability is missing or offers nothing this AMF can select, before any
	// AUSF call (NIA0/NEA0 would otherwise be selected for a non-emergency UE).
	if !acceptableUESecurityCapability(ueSecCap) {
		log.Warn("REGISTRATION REQUEST with invalid or unacceptable UE security capability",
			"interface", "N1", "direction", "IN",
			"result", "REJECT", "cause", int(UESecCapRejectCause),
			"spec_ref", "TS 24.501 §5.5.1.2.8 i)")
		metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "REJECT").Inc()
		return nil, ErrUESecurityCapabilityUnacceptable
	}

	// Store UE security capabilities for later Security Mode Command
	if sc := ueSecCap; sc != nil {
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

	// ER-NSSAI capability of the 5GMM capability IE: selects the Extended rejected
	// NSSAI IE in the later REGISTRATION ACCEPT / CONFIGURATION UPDATE COMMAND /
	// DEREGISTRATION REQUEST (rel19). Not persisted.
	// Ref: TS 24.501 §5.5.1.2.2, §9.11.3.1
	ue.ERNSSAISupported = in.RegRequest.ERNSSAISupported()
	// Full 5GMM capability (all octets) for capability.PeerUE gating, REL19-5.4.
	ue.Capability5GMM = in.RegRequest.Capability5GMM()
	if ue.Capability5GMM != nil {
		h.logger.InfoContext(ctx, "UE 5GMM capability decoded",
			"procedure", "InitialRegistration",
			"interface", "N1", "direction", "IN",
			"amf_ue_ngap_id", ue.AMFUENGAPId, "supi", ue.SUPI,
			"capability_5gmm", ue.Capability5GMM.RawHex(),
			"capability_5gmm_bits", strings.Join(ue.Capability5GMM.SetBitNames(), ","),
			"spec_ref", "TS 24.501 §5.5.1.2.2, §9.11.3.1",
		)
	}

	// If the UE presented a GUTI, try to resolve it to a known SUPI.
	// A GUTI issued by this AMF that is still in the context store can be
	// passed to AUSF as SUPI (UDM knows it). If not found — e.g. after a
	// restart or after the UE re-registers following deregistration — we must
	// request the UE's SUCI before we can call AUSF.
	// Ref: TS 24.501 §5.5.1.2.2 step 1b; TS 23.502 §4.2.2.2.2 note on GUTI
	if in.RegRequest.MobileIdentity.Type == nas.MobileIdentityGUTI {
		if guti := in.RegRequest.MobileIdentity.GUTI; guti != nil {
			// The 5G-TMSI is unique only within the allocating AMF: a 5G-GUTI of
			// another PLMN / AMF Region / Set / Pointer is unknown here even when its
			// 5G-TMSI collides with a local one. Ref: TS 23.003 §2.10.1
			if !h.gutiAllocatedHere(guti) {
				return nil, ErrNeedSUCI
			}
			if existing, ok := h.mgr.GetByTMSI(guti.TMSI); ok && existing.SUPI != "" {
				// AMF recognises this GUTI — use the known SUPI for AUSF
				suciOrGUTI = existing.SUPI
				ue.AuthViaGUTI = true
			} else {
				return nil, ErrNeedSUCI
			}
		} else {
			return nil, ErrNeedSUCI
		}
	}

	// Step 6: the AMF can only start authentication with a SUCI (or a 5G-GUTI
	// resolved above). Any other identity (IMEI, IMEISV, 5G-S-TMSI, none, or a
	// SUCI IE that failed to decode) must not reach the AUSF: initiate the
	// Identity Request procedure instead.
	// Ref: TS 23.502 §4.2.2.2.2 step 6; TS 24.501 §5.4.3.1
	if mi := in.RegRequest.MobileIdentity; mi.Type == nas.MobileIdentitySUCI && mi.SUCI != nil {
		// A SUCI that cannot be rendered as TS 29.571 §5.3.2 SupiOrSuci is a
		// malformed mandatory 5GS mobile identity: REGISTRATION REJECT #96,
		// never an Identity Request loop. Ref: TS 24.501 §5.5.1.2.8 b)
		if _, serr := SUCIString(mi.SUCI); serr != nil {
			log.Warn("registration SUCI not representable - rejecting",
				"interface", "N1", "direction", "IN",
				"result", "REJECT", "cause", int(UnusableSUCIRejectCause),
				"error", serr, "spec_ref", UnusableSUCISpecRef,
			)
			return nil, &ErrRejectCause{Cause: UnusableSUCIRejectCause,
				SpecRef: UnusableSUCISpecRef, Err: serr}
		}
	}
	if !identityUsableForAuth(in.RegRequest.MobileIdentity) {
		if in.RegRequest.RegistrationType == nas.RegistrationTypeEmergency {
			switch in.RegRequest.MobileIdentity.Type {
			case nas.MobileIdentityIMEI, nas.MobileIdentityIMEISV:
				// Emergency services are not supported: a PEI identity cannot be
				// accepted. Ref: TS 24.501 §5.5.1.2.5, Annex A.2 (cause #5)
				log.Warn("emergency registration with PEI not accepted",
					"interface", "N1", "direction", "IN",
					"result", "REJECT", "cause", int(PEINotAcceptedCause),
					"spec_ref", "TS 24.501 §5.5.1.2.5",
				)
				return nil, ErrPEINotAccepted
			}
		}
		log.Info("registration identity is neither SUCI nor 5G-GUTI — requesting SUCI",
			"interface", "N1", "direction", "OUT",
			"identity_type", int(in.RegRequest.MobileIdentity.Type),
			"cause", "need_suci",
			"spec_ref", "TS 23.502 §4.2.2.2.2 step 6",
		)
		return nil, ErrNeedSUCI
	}

	// Step 8: AMF selects AUSF via NRF discovery
	// Ref: TS 23.502 V19.9.0 §4.2.2.2.2 step 8
	log.Info("discovering AUSF via NRF",
		"spec_ref", "TS 23.502 §4.2.2.2.2 step 8",
	)

	// Step 6-8: AUSF authentication initiation
	// Ref: TS 23.502 §4.2.2.2.2 step 6-8 (Nausf_UEAuthentication_Authenticate)
	aCtx, aCancel := stepCtx(ctx, h.budget().AUSFInit)
	ausfResp, err := h.ausf.InitiateAuth(aCtx, suciOrGUTI, h.servingNetName)
	aCancel()
	if err != nil {
		log.Error("AUSF authentication initiation failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "AUSF initiate auth failed")
		metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "FAILURE").Inc()
		return nil, &ErrRejectCause{Cause: NFUnavailableRejectCause,
			SpecRef: "TS 24.501 §5.5.1.2.5", Err: fmt.Errorf("ausf: initiate auth: %w", err)}
	}
	ue.AuthCtxID = ausfResp.AuthCtxID
	ue.PendingRAND = ausfResp.RAND
	ue.PendingAUTN = ausfResp.AUTN

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
		NGKSI: nas.NGKSI{KeySetIdentifier: ue.PendingNGKSI, Type: 0}, // native, freshly allocated
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
	ue.AuthViaGUTI = false // identification done: the challenge now runs on the SUCI
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

	aCtx, aCancel := stepCtx(ctx, h.budget().AUSFInit)
	ausfResp, err := h.ausf.InitiateAuth(aCtx, suci, h.servingNetName)
	aCancel()
	if err != nil {
		log.Error("AUSF authentication initiation failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "AUSF initiate auth failed")
		metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "FAILURE").Inc()
		return nil, &ErrRejectCause{Cause: NFUnavailableRejectCause,
			SpecRef: "TS 24.501 §5.5.1.2.5", Err: fmt.Errorf("ausf: initiate auth: %w", err)}
	}
	ue.AuthCtxID = ausfResp.AuthCtxID
	ue.PendingRAND = ausfResp.RAND
	ue.PendingAUTN = ausfResp.AUTN

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
		NGKSI: nas.NGKSI{KeySetIdentifier: ue.PendingNGKSI, Type: 0},
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

	aCtx, aCancel := stepCtx(ctx, h.budget().AUSFConfirm)
	ausfResp, err := h.ausf.ResyncAuth(aCtx, suciOrSUPI, h.servingNetName, ue.PendingRAND, auts)
	aCancel()
	if err != nil {
		log.Error("AUSF resync failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "resync failed")
		return nil, fmt.Errorf("ausf: resync auth: %w", err)
	}

	ue.AuthCtxID = ausfResp.AuthCtxID
	ue.PendingRAND = ausfResp.RAND
	ue.PendingAUTN = ausfResp.AUTN

	log.Info("resync AV received — sending new Authentication Request",
		"auth_ctx_id", ausfResp.AuthCtxID,
		"interface", "N1",
		"direction", "OUT",
		"message_type", "AuthenticationRequest",
	)
	metrics.NASMessagesTotal.WithLabelValues(nfName, "AuthenticationRequest", "OUT", "OK").Inc()
	span.SetStatus(codes.Ok, "")

	return &nas.AuthenticationRequest{
		NGKSI: nas.NGKSI{KeySetIdentifier: ue.PendingNGKSI, Type: 0},
		ABBA:  h.abba,
		RAND:  ausfResp.RAND,
		AUTN:  ausfResp.AUTN,
	}, nil
}

// RepeatChallengeWithNewNGKSI handles the first AUTHENTICATION FAILURE #71
// "ngKSI already in use": it selects a new ngKSI (different from the rejected
// one and from the current native security context) and returns the same 5G
// authentication challenge (RAND, AUTN) to re-send. No AUSF call.
// Ref: TS 24.501 §5.4.1.3.7 e)
func (h *RegistrationHandler) RepeatChallengeWithNewNGKSI(ue *amfctx.UEContext) *nas.AuthenticationRequest {
	next := allocateFreshNGKSI(ue.PendingNGKSI)
	if ue.SecurityCtx.Active && next == ue.SecurityCtx.NGKSI {
		next = allocateFreshNGKSI(next)
	}
	ue.PendingNGKSI = next
	metrics.NASMessagesTotal.WithLabelValues(nfName, "AuthenticationRequest", "OUT", "OK").Inc()
	return &nas.AuthenticationRequest{
		NGKSI: nas.NGKSI{KeySetIdentifier: next, Type: 0},
		ABBA:  h.abba,
		RAND:  ue.PendingRAND,
		AUTN:  ue.PendingAUTN,
	}
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
		// A missing RES* is an invalid RES: same outcome as a RES* the AUSF rejects
		// (AUTHENTICATION REJECT for a SUCI, identification for a 5G-GUTI).
		// Ref: TS 24.501 §5.4.1.3.5
		return nil, nil, fmt.Errorf("amf: auth response missing RES*: %w", ErrAuthenticationRejected)
	}

	// Step 11: forward RES* to AUSF for verification
	// Ref: TS 23.502 §4.2.2.2.2 step 11
	aCtx, aCancel := stepCtx(ctx, h.budget().AUSFConfirm)
	confirmResp, err := h.ausf.ConfirmAuth(aCtx, ue.AuthCtxID, hex.EncodeToString(authResp.RES))
	aCancel()
	if err != nil {
		log.Error("RES* verification failed at AUSF",
			"result", "REJECT",
			"spec_ref", "TS 33.501 §6.1.3.2 step 8",
		)
		span.RecordError(err)
		span.SetStatus(codes.Error, "RES* verification failed")
		metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "REJECT").Inc()
		if errors.Is(err, ErrAuthenticationRejected) {
			// RES* rejected: the NAS layer chooses AUTHENTICATION REJECT or the
			// identification procedure. Ref: TS 24.501 §5.4.1.3.5
			return nil, nil, fmt.Errorf("ausf: confirm auth: %w", err)
		}
		return nil, nil, &ErrRejectCause{Cause: NFUnavailableRejectCause,
			SpecRef: "TS 24.501 §5.5.1.2.5", Err: fmt.Errorf("ausf: confirm auth: %w", err)}
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
	// A new context is taken into use only once the SECURITY MODE COMPLETE is
	// verified; the one in use before is kept for a SECURITY MODE REJECT / abort.
	// Ref: TS 24.501 §5.4.2.5
	ue.BeginSecurityCtxChange()
	ue.SecurityCtx.KAMF = kamf

	// Select NAS security algorithms
	// Policy: prefer NEA2 (AES-CTR), NIA2 (AES-CMAC) if UE supports them
	cipherAlg, integAlg := h.selectSecurityAlgorithms(ue)
	ue.SecurityCtx.CipheringAlgID = cipherAlg
	ue.SecurityCtx.IntegrityAlgID = integAlg

	// Derive NAS keys
	ue.SecurityCtx.KNASint = kdf.KNASint(kamf, integAlg)
	ue.SecurityCtx.KNASenc = kdf.KNASenc(kamf, cipherAlg)
	ue.SecurityCtx.NGKSI = ue.PendingNGKSI // must match the ngKSI sent in the Authentication Request / SMC

	// Taking a new 5G NAS security context into use resets both NAS COUNTs to 0.
	// Ref: TS 33.501 §6.4.3.1 / TS 24.501 §4.4.3.1.
	//
	// This is not redundant with the zero value of a freshly allocated UEContext.
	// A real handset that never sees its Registration Accept retransmits the
	// Registration Request over the SAME still-open NGAP association, which
	// re-enters authentication on the SAME *amfctx.UEContext. Without this reset
	// the new KAMF/KNASint/KNASenc derived just above would be used with the
	// COUNTs left over from the abandoned attempt, while the UE — correctly
	// obeying the SHT=0x03 "with new security context" SecurityModeCommand that
	// follows — restarts its own COUNTs at 0. Every MAC from that point is
	// computed over a COUNT the peer does not expect, so the UE silently
	// discards the Registration Accept and re-registers from SUCI. That failure
	// looks exactly like a radio problem and is not one.
	ue.SecurityCtx.DownlinkCount = 0
	ue.SecurityCtx.UplinkCount = 0

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

	// Step 14: send Security Mode Command to UE (TS 24.501 §8.2.25).
	//
	// IMEISV request: retrieve the PEI in the Security Mode Complete
	// (TS 33.501 §6.12.4 — the PEI shall only be sent after security activation).
	//
	// RINMR: the initial Registration Request was sent without integrity
	// protection, so a spec-conformant UE included only the cleartext IEs
	// (TS 24.501 §4.4.6 — no Requested NSSAI, no 5GMM capability). Setting RINMR
	// makes the UE retransmit the complete message in the NAS message container
	// of the Security Mode Complete, where handleSecurityModeComplete processes
	// it. Ref: TS 24.501 §5.4.2.2.
	imeisvReq := nas.IMEISVRequested
	addSecInfo := nas.Additional5GSecInfoRINMR
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
		IMEISVRequest:            &imeisvReq,
		Additional5GSecurityInfo: &addSecInfo,
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

	bud := h.budget()
	// p3ctx bounds every SBI step of Phase3 below T3510 (budget.go); the AMF's
	// own state handling keeps using ctx.
	p3ctx, p3cancel := context.WithTimeout(ctx, bud.Phase3)
	defer p3cancel()
	emergency := ue.RegistrationType == byte(nas.RegistrationTypeEmergency)

	// Step 14a: register with UDM (Nudm_UECM_Registration). A failure rejects the
	// registration with a cause derived from the SBI error; Nudm_SDM_Get is never
	// reached after it. For an Emergency Registration the AMF ignores an
	// unsuccessful UDM response. Ref: TS 23.502 §4.2.2.2.2 step 14a
	uecmCtx, uecmCancel := stepCtx(p3ctx, bud.UECM)
	uecmErr := h.udm.RegisterAMF(uecmCtx, ue.SUPI, h.nfInstanceID, h.servingNetName)
	uecmCancel()
	if uecmErr != nil {
		span.RecordError(uecmErr)
		if emergency {
			log.Warn("UDM AMF registration failed - ignored for an emergency registration",
				"error", uecmErr, "interface", "Nudm", "direction", "IN",
				"spec_ref", "TS 23.502 §4.2.2.2.2 step 14a")
		} else {
			cause, ref := RejectCauseForUDMError(uecmErr)
			log.Error("UDM AMF registration failed - rejecting registration",
				"error", uecmErr, "interface", "Nudm", "direction", "IN",
				"result", "REJECT", "cause", int(cause), "spec_ref", ref)
			span.SetStatus(codes.Error, "UDM UECM registration failed")
			metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "FAILURE").Inc()
			return nil, &ErrRejectCause{Cause: cause, SpecRef: ref,
				Err: fmt.Errorf("udm: uecm registration: %w", uecmErr)}
		}
	}

	// Step 14b: get subscription data from UDM (Nudm_SDM_Get)
	// Ref: TS 23.502 §4.2.2.2.2 step 14b
	sdmCtx, sdmCancel := stepCtx(p3ctx, bud.SDMGet)
	amSub, err := h.udm.GetAMSubscriptionData(sdmCtx, ue.SUPI)
	sdmCancel()
	if err != nil {
		log.Error("UDM AM subscription data fetch failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "UDM AM subscription fetch failed")
		metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "FAILURE").Inc()
		h.rollbackUDMRegistration(ctx, ue, uecmErr == nil)
		return nil, &ErrRejectCause{Cause: NFUnavailableRejectCause,
			SpecRef: "TS 24.501 §5.5.1.2.5", Err: fmt.Errorf("udm: get AM subscription: %w", err)}
	}

	// Step 14b (cont.): Nudm_SDM_Subscribe after the AM-data Get; non-fatal.
	// Ref: TS 23.502 §4.2.2.2.2 step 14b, TS 29.503 §5.2.2.3
	if sub, ok := h.udm.(UDMSDMSubscriber); ok {
		subCtx, subCancel := stepCtx(p3ctx, bud.SDMSubscribe)
		subID, subErr := sub.SubscribeAMData(subCtx, ue.SUPI)
		subCancel()
		if subErr != nil {
			log.Warn("UDM SDM subscribe failed (non-fatal)", "error", subErr,
				"interface", "Nudm", "direction", "OUT", "result", "FAILURE",
				"spec_ref", "TS 29.503 §5.2.2.3")
		} else if subID != "" {
			ue.SetSDMSubscriptionID(subID)
			log.Info("UDM SDM subscription created",
				"subscription_id", subID, "interface", "Nudm", "direction", "OUT",
				"spec_ref", "TS 29.503 §5.2.2.3")
		}
	}

	// Optional peers (NSSF slice selection, PCF AM policy, PCF UE policy) are
	// independent of each other: run them in parallel under one short budget and
	// apply the results below in a fixed order (no UE-context writes from the
	// goroutines). Each failure/timeout degrades as before (non-fatal).
	// Ref: TS 23.502 §4.2.9, §4.2.2.2.2 steps 14c, 17b
	if p3ctx.Err() != nil {
		log.Warn("Phase3 budget already spent - optional peers run with a cancelled context and will degrade",
			"cause", p3ctx.Err().Error(), "result", "FAILURE", "budget_ms", bud.Phase3.Milliseconds(),
			"spec_ref", "TS 24.501 §10.2 Table 10.2.1 (T3510)")
	}
	opt := h.runOptionalPeers(p3ctx, bud.Optional, ue.SUPI, ue.RequestedNSSAI)
	// Compute AllowedNSSAI: prefer NSSF delegation if configured; fall back to
	// local UDM-subscription filter. NSSF failure is non-fatal. Ref: TS 23.502 §4.2.9
	if h.nssf != nil {
		if opt.nssfErr != nil {
			log.Warn("NSSF NSSelection failed — falling back to local UDM filter",
				"error", opt.nssfErr,
				"spec_ref", "TS 23.502 §4.2.9",
			)
			ue.AllowedNSSAI = filterAllowedNSSAI(ue.RequestedNSSAI, amSub.AllowedNSSAI)
		} else {
			// Intersect NSSF result with UDM subscription to enforce subscription limits.
			ue.AllowedNSSAI = filterAllowedNSSAI(opt.nssfAllowed, amSub.AllowedNSSAI)
			log.Info("NSSF NSSelection completed",
				"nssf_allowed_count", len(opt.nssfAllowed),
				"final_count", len(ue.AllowedNSSAI),
				"spec_ref", "TS 29.531 §5.2.2.2",
			)
		}
	} else {
		ue.AllowedNSSAI = filterAllowedNSSAI(ue.RequestedNSSAI, amSub.AllowedNSSAI)
	}
	ue.AllowedNSSAI = h.limitAllowedNSSAI(ctx, ue, ue.AllowedNSSAI)
	ue.SubscribedNSSAI = append([]amfctx.SNSSAISubscribed(nil), amSub.AllowedNSSAI...)
	// Withhold slices subject to NSSAA from the initial Allowed NSSAI; they are
	// granted only after slice-level EAP auth succeeds (run after RegistrationComplete).
	// No-op when NSSAA is unconfigured or no slice is flagged. Ref: TS 23.502 §4.2.9.2.
	h.SplitPendingNSSAA(ue)
	// No allowed slice and none pending NSSAA: REGISTRATION REJECT #62, never an
	// Accept with an empty Allowed NSSAI (min length 4, §9.11.3.37).
	// Ref: TS 24.501 §5.5.1.2.5; TS 23.502 §4.2.2.2.2 step 21
	if len(ue.AllowedNSSAI) == 0 && len(ue.PendingNSSAA) == 0 &&
		ue.NSSAAInProgress == nil && len(ue.NSSAAPendingStatus) == 0 {
		rejected := rejectedNSSAIForRegistration(ue)
		log.Warn("no network slices available — rejecting registration",
			"procedure", "InitialRegistration",
			"interface", "N1",
			"direction", "OUT",
			"message_type", "RegistrationReject",
			"result", "REJECT",
			"cause", int(nas.CauseNoNetworkSlicesAvailable),
			"requested_count", len(ue.RequestedNSSAI),
			"spec_ref", "TS 24.501 §5.5.1.2.5",
		)
		metrics.ProcedureTotal.WithLabelValues(nfName, "InitialRegistration", "REJECT").Inc()
		h.releasePolicyAssociations(ctx, opt)
		h.rollbackUDMRegistration(ctx, ue, uecmErr == nil)
		return nil, &NoNetworkSlicesError{Rejected: rejected}
	}
	ue.SubscribedAMBR.UL = amSub.AMBRUplink
	ue.SubscribedAMBR.DL = amSub.AMBRDownlink
	ue.GPSI = amSub.GPSI

	// Assign new 5G-GUTI
	// The UE is NOT 5GMM-REGISTERED yet: the AMF enters 5GMM-REGISTERED only once the
	// REGISTRATION ACCEPT is sent (no new 5G-GUTI) or the REGISTRATION COMPLETE
	// arrives (T3550 running). The NAS layer drives the transition.
	// Ref: TS 24.501 §5.5.1.2.4
	guti := h.mgr.AssignGUTI(ctx, ue)

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
		"spec_ref", "TS 23.502 §4.2.2.2.2 step 21",
	)

	// Operator default RFSP — always set before the PCF call so the IE is
	// guaranteed to be present in InitialContextSetupRequest even when PCF is
	// unavailable. PCF overrides this if it returns a non-zero value.
	// Ref: TS 38.413 §9.3.1.27 (IndexToRFSP, range 1-256), TS 23.501 §5.3.4.2
	ue.RFSP = h.defaultRFSP

	// Step 14c (optional): AM Policy Association with PCF (Npcf_AMPolicyControl),
	// created in the parallel group above. PCF may return servAreaRes (Service
	// Area Restriction); if so, enforce it: reject the registration with 5GMM
	// cause #73 if the UE's TAC is not allowed. Non-fatal when PCF is
	// unavailable - operator default RFSP is used instead.
	// Ref: TS 23.502 §4.2.2.2.2 step 14c; TS 23.501 §5.3.4; TS 29.507 §4.2.2
	if h.amPolicy != nil {
		if opt.amErr != nil {
			log.Warn("PCF AM policy association failed — using operator default RFSP",
				"error", opt.amErr,
				"rfsp_default", ue.RFSP,
				"interface", "N15",
				"spec_ref", "TS 29.507 §4.2.2")
		} else {
			ue.AMPolicyAssocID = opt.amID
			if opt.amRFSP > 0 {
				ue.RFSP = opt.amRFSP // PCF-provided value takes precedence
			}
			ue.SetServiceAreaRestriction(opt.amSAR)
			log.Info("PCF AM policy association created",
				"am_pol_asso_id", opt.amID,
				"rfsp", ue.RFSP,
				"rfsp_source", rfspSource(opt.amRFSP, h.defaultRFSP),
				"has_serv_area_res", opt.amSAR != nil,
				"interface", "N15", "direction", "OUT",
				"spec_ref", "TS 29.507 §4.2.2")
		}

		// A UE in a Non-Allowed Area is still allowed to register (TS 23.501 §3.1,
		// §5.3.4.1.1); the restriction is conveyed in the Service area list IE of
		// REGISTRATION ACCEPT and enforced on Service Request / UL NAS TRANSPORT.
		if ue.InNonAllowedArea() {
			log.Info("UE in a Non-Allowed Area - registration accepted with service area list",
				"tac", fmt.Sprintf("%06X", ue.TAI.TAC),
				"restriction_type", restrictionType(ue),
				"spec_ref", "TS 23.501 §5.3.4.1.1, TS 24.501 §5.3.5")
		}
	}

	log.Info("RFSP assigned",
		"rfsp", ue.RFSP,
		"supi", ue.SUPI,
		"spec_ref", "TS 38.413 §9.3.1.27",
	)

	// Step 17b (optional): URSP policy from PCF (N15), fetched in the parallel
	// group above. Non-fatal: if PCF is unavailable, registration proceeds
	// without policy delivery. URSP is NOT placed in Registration Accept - the UE
	// policy container is delivered over DL NAS TRANSPORT (payload container type
	// 0x05) after RegistrationComplete (handleRegistrationComplete) and staged in
	// PendingPolicyContainer here.
	// Ref: TS 23.502 §4.2.2.2.2 step 17b, §4.2.4.3; TS 24.501 Annex D; TS 29.525 §4.2.2.2
	if h.pcf != nil {
		if opt.ueErr != nil {
			log.Warn("PCF N15 CreateUEPolicyAssociation failed (non-fatal)",
				"error", opt.ueErr, "interface", "N15",
				"spec_ref", "TS 29.525 §4.2.2.2")
		} else if len(opt.ueContainer) > 0 {
			ue.PolicyAssociationID = opt.uePolID
			ue.PendingPolicyContainer = opt.ueContainer
			log.Info("PCF N15 policy association created — UE policy delivery queued for post-registration",
				"pol_asso_id", opt.uePolID,
				"policy_container_bytes", len(opt.ueContainer),
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
		// IEI 0x27: Service area list, absent without a PCF service area
		// restriction (legacy bytes unchanged). Ref: TS 24.501 §5.3.5
		ServiceAreaList: h.buildServiceAreaList(ue),
		// IEI 0x21: 5GS network feature support (IMS VoPS-3GPP bit only).
		// Ref: TS 24.501 §8.2.7.1 Table 8.2.7.1.1, §9.11.3.5
		NetworkFeatureSupport: h.networkFeatureSupport(ctx, ue),
		// URSP intentionally omitted — delivered via DL NAS TRANSPORT after registration.
	}
	// IEI 0x5E: T3512 Periodic Registration Timer (GPRS Timer 3 encoding).
	// Ref: TS 24.501 §8.2.7.1 Table 8.2.7.1.1
	h.setT3512Value(ra, ue)
	h.applyNSSAAAcceptIEs(ra, ue)
	if len(ue.AllowedNSSAI) == 0 {
		// NSSAA-only case: the Allowed NSSAI IE is omitted (min length 4).
		// Ref: TS 24.501 §5.5.1.2.4, §9.11.3.37
		ra.AllowedNSSAI = nil
	}
	return ra, nil
}

// NoNetworkSlicesError is returned by Phase3_ProcessSMCComplete when the Allowed
// NSSAI is empty and no S-NSSAI is pending NSSAA: the NAS handler answers with
// REGISTRATION REJECT 5GMM cause #62 carrying Rejected.
// Ref: TS 24.501 §5.5.1.2.5
type NoNetworkSlicesError struct {
	// Rejected lists every S-NSSAI of the Requested NSSAI with its cause value.
	Rejected []nas.RejectedSNSSAI
}

// Error implements error.
func (e *NoNetworkSlicesError) Error() string {
	return "no network slices available (cause #62)"
}

// rejectedNSSAIForRegistration lists every requested S-NSSAI (at most
// nas.MaxRejectedSNSSAIs) with cause 2 when it failed NSSAA, else "not
// available in the current PLMN" (not subscribed).
// Ref: TS 24.501 §5.5.1.2.5, Table 9.11.3.46.1
func rejectedNSSAIForRegistration(ue *amfctx.UEContext) []nas.RejectedSNSSAI {
	var out []nas.RejectedSNSSAI
	for _, r := range ue.RequestedNSSAI {
		if len(out) == nas.MaxRejectedSNSSAIs {
			break
		}
		cause := nas.RejectedCauseNotAvailableInPLMN
		if hasSubscribed(ue.RejectedNSSAI, r) {
			cause = nas.RejectedCauseNSSAAFailedOrRevoked
		}
		out = append(out, nas.RejectedSNSSAI{Cause: cause, SNSSAI: toNASSNSSAI(r)})
	}
	return out
}

// ---- helpers ------------------------------------------------------------

// UnusableSUCIRejectCause is the 5GMM cause of the REGISTRATION REJECT for a
// 5GS mobile identity (SUCI) that is malformed or not representable: #96
// "Invalid mandatory information". Ref: TS 24.501 §5.5.1.2.8 b), Annex A.2
const UnusableSUCIRejectCause = nas.CauseInvalidMandatoryInformation

// UnusableSUCISpecRef is the clause behind UnusableSUCIRejectCause.
const UnusableSUCISpecRef = "TS 24.501 §5.5.1.2.8 b)"

// identityUsableForAuth reports whether the Registration Request identity is a
// decoded SUCI or 5G-GUTI, the only identities from which the AMF can start
// authentication. Ref: TS 23.502 §4.2.2.2.2 step 6
func identityUsableForAuth(mi nas.MobileIdentity) bool {
	switch mi.Type {
	case nas.MobileIdentitySUCI:
		if mi.SUCI == nil {
			return false
		}
		_, err := SUCIString(mi.SUCI)
		return err == nil
	case nas.MobileIdentityGUTI:
		return mi.GUTI != nil
	}
	return false
}

// SUCIString renders a NAS SUCI mobile identity in the standard SUCI text form
// of TS 29.571 §5.3.2 (SupiOrSuci), TS 29.509 §6.1.6.2.2 supiOrSuci:
// suci-<type>-<mcc>-<mnc>-<routing>-<scheme>-<key id>-<output>. The null
// scheme output is the MSIN digits (BCD-decoded), Profile A/B output is
// lowercase hex (TS 23.003 §2.2B, TS 24.501 §9.11.3.4). An identity that is
// not representable (NAI format, bad BCD, key id 0 for a non-null scheme, ...)
// returns an error and must not be sent to the AUSF.
func SUCIString(s *nas.SUCIMobileIdentity) (string, error) {
	if s == nil {
		return "", fmt.Errorf("amf: suci string: nil SUCI")
	}
	if s.SUPIFormat != types.SUPITypeIMSI {
		return "", fmt.Errorf("amf: suci string: SUPI format %d (NAI) not representable as IMSI SUCI", s.SUPIFormat)
	}
	c := types.SUCI{
		SUPIType:         types.SUPITypeIMSI,
		MCC:              s.MCC,
		MNC:              s.MNC,
		RoutingIndicator: s.RoutingIndicator,
		ProtectionScheme: s.ProtectionSchemeID,
	}
	if s.ProtectionSchemeID == types.SUCISchemeNull {
		msin, err := types.NullSchemeMSIN(s.SchemeOutput)
		if err != nil {
			return "", fmt.Errorf("amf: suci string: %w", err)
		}
		c.SchemeOutput = msin
	} else {
		c.HNPublicKeyID = s.HomeNetworkPublicKeyID
		c.SchemeOutput = hex.EncodeToString(s.SchemeOutput)
	}
	out := c.String()
	if _, err := types.ParseSUCI(out); err != nil {
		// The parse error quotes the rendered SUCI; do not propagate it, a
		// concealed scheme output must not reach logs.
		return "", fmt.Errorf("amf: suci string: rendered SUCI violates the TS 29.571 §5.3.2 pattern")
	}
	return out, nil
}

func extractIdentity(rr *nas.RegistrationRequest) string {
	mi := rr.MobileIdentity
	switch mi.Type {
	case nas.MobileIdentitySUCI:
		if mi.SUCI != nil {
			suci, err := SUCIString(mi.SUCI)
			if err == nil {
				return suci
			}
			// Phase1 rejects the registration; keep the cause visible.
			slog.Warn("registration SUCI not representable",
				"nf", "AMF", "procedure", "InitialRegistration",
				"interface", "N1", "direction", "IN", "error", err,
				"spec_ref", "TS 29.571 §5.3.2")
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

// gutiAllocatedHere reports whether the 5G-GUTI's GUAMI (MCC, MNC, AMF Region
// ID, AMF Set ID, AMF Pointer) is this AMF's: only then can its 5G-TMSI be
// resolved locally. Ref: TS 23.003 §2.10.1
func (h *RegistrationHandler) gutiAllocatedHere(g *nas.GUTIMobileIdentity) bool {
	id := h.mgr.AMFID
	return g.MCC == id.MCC && g.MNC == id.MNC && g.AMFRegionID == id.AMFRegionID &&
		g.AMFSetID == id.AMFSetID && g.AMFID == id.AMFID
}

// acceptableUESecurityCapability reports whether the UE security capability IE
// is present and offers at least one 5GS encryption algorithm (NEA0..NEA2) and
// one non-null 5GS integrity algorithm (NIA1, NIA2) that selectSecurityAlgorithms
// can choose. NIA0 alone is not acceptable outside emergency services.
// Ref: TS 24.501 §5.5.1.2.8 i); TS 33.501 §5.5.2
func acceptableUESecurityCapability(sc *nas.UESecurityCapability) bool {
	if sc == nil {
		return false
	}
	return (sc.EA0 || sc.EA1 || sc.EA2) && (sc.IA1 || sc.IA2)
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
// the same SST. The result is not limited to MaxAllowedNSSAI; the registration
// path applies limitAllowedNSSAI once after the filter.
// Ref: TS 23.502 §4.2.2.2.2, TS 24.501 §5.5.1.2.4
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

// MaxAllowedNSSAI is the maximum number of S-NSSAIs in an Allowed NSSAI.
// Ref: TS 24.501 §4.6.2.2, §9.11.3.37 (at most 8 S-NSSAIs); TS 38.413
// maxnoofAllowedS-NSSAIs = 8.
const MaxAllowedNSSAI = 8

// capAllowedNSSAI truncates an Allowed NSSAI to MaxAllowedNSSAI entries. It
// returns a copy when it truncates, so the result never aliases the input.
func capAllowedNSSAI(in []amfctx.SNSSAISubscribed) []amfctx.SNSSAISubscribed {
	if len(in) <= MaxAllowedNSSAI {
		return in
	}
	return append([]amfctx.SNSSAISubscribed(nil), in[:MaxAllowedNSSAI]...)
}

// limitAllowedNSSAI applies the MaxAllowedNSSAI limit to the UE's Allowed NSSAI
// and logs the dropped excess once. The Registration Accept path has no
// per-slice rejected-NSSAI mechanism for the excess.
// Ref: TS 24.501 §4.6.2.2
func (h *RegistrationHandler) limitAllowedNSSAI(ctx context.Context, ue *amfctx.UEContext,
	in []amfctx.SNSSAISubscribed) []amfctx.SNSSAISubscribed {
	if len(in) <= MaxAllowedNSSAI {
		return in
	}
	logging.NewProcedureLogger(ctx, h.logger, "InitialRegistration").WarnContext(ctx,
		"allowed NSSAI exceeds maximum — dropping excess S-NSSAIs",
		"nf", nfName,
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"cause", "allowed_nssai_over_limit",
		"count", len(in),
		"max", MaxAllowedNSSAI,
		"spec_ref", "TS 24.501 §4.6.2.2",
	)
	return capAllowedNSSAI(in)
}

func buildAllowedNSSAI(subs []amfctx.SNSSAISubscribed) nas.NSSAI {
	var n nas.NSSAI
	for _, s := range capAllowedNSSAI(subs) {
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

	// 5GMM state is handled by the NAS layer (T3550 / REGISTRATION COMPLETE).
	guti := h.mgr.AssignGUTI(ctx, ue)

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
		// IEI 0x27: Service area list (nil without SAR). Ref: TS 24.501 §5.3.5
		ServiceAreaList: h.buildServiceAreaList(ue),
		// IEI 0x21: 5GS network feature support — same as Initial Registration.
		// Ref: TS 24.501 §8.2.7.1 Table 8.2.7.1.1, §9.11.3.5
		NetworkFeatureSupport: h.networkFeatureSupport(ctx, ue),
	}
	h.setT3512Value(ra, ue)
	h.applyNSSAAAcceptIEs(ra, ue)
	return ra, nil
}

// DeregisterUECM removes the AMF registration from UDM after UE deregistration.
// Ref: TS 23.502 §4.2.2.3.2 step 3, TS 29.503 §5.3.2.4
func (h *RegistrationHandler) DeregisterUECM(ctx context.Context, supi string) error {
	if h.udm == nil {
		h.logger.Warn("UDM client not configured - UECM de-registration skipped",
			"procedure", "Deregistration", "supi", supi,
			"spec_ref", "TS 23.502 §4.2.2.3.2 step 3, TS 29.503 §5.3.2.4")
		return nil
	}
	h.unsubscribeSDM(ctx, supi)
	return h.udm.DeregisterUECM(ctx, supi)
}

// unsubscribeSDM deletes the UE's Nudm_SDM subscription (created at
// registration) where the AMF deregisters from the UDM. Best-effort: logged,
// never fails the deregistration. Ref: TS 29.503 §5.2.2.4
func (h *RegistrationHandler) unsubscribeSDM(ctx context.Context, supi string) {
	sub, ok := h.udm.(UDMSDMSubscriber)
	if !ok || h.mgr == nil {
		return
	}
	ue, found := h.mgr.GetBySUPI(supi)
	if !found {
		return
	}
	id := ue.TakeSDMSubscriptionID()
	if id == "" {
		return
	}
	if err := sub.UnsubscribeSDM(ctx, supi, id); err != nil {
		h.logger.Warn("UDM SDM unsubscribe failed (non-fatal)", "procedure", "Deregistration",
			"interface", "Nudm", "direction", "OUT", "supi", supi, "subscription_id", id,
			"result", "FAILURE", "error", err, "spec_ref", "TS 29.503 §5.2.2.4")
	}
}

// ReleaseAMPolicy releases the AM policy association at PCF.
// Non-fatal: caller logs and continues on error.
// Ref: TS 29.507 §4.2.5, TS 23.502 §4.2.2.3.2 step 3
func (h *RegistrationHandler) ReleaseAMPolicy(ctx context.Context, polAssoID string) error {
	if h.amPolicy == nil {
		return nil
	}
	return h.amPolicy.DeleteAMPolicyAssociation(ctx, polAssoID)
}

// ReleasePCFPolicy releases the UE policy association at PCF (URSP/Npcf_UEPolicyControl).
// Non-fatal: caller logs and continues on error.
// Ref: TS 29.525 §4.2.5, TS 23.502 §4.2.2.3.2 step 3
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

// ConfirmGUTI marks the UE's new 5G-GUTI as in use (REGISTRATION COMPLETE):
// the previous 5G-TMSI no longer resolves. Ref: TS 24.501 §5.5.1.3.8 a) 1) i)
func (h *RegistrationHandler) ConfirmGUTI(ue *amfctx.UEContext) {
	h.mgr.ConfirmGUTI(ue)
}

// PersistUE writes the UE context to PostgreSQL. No-op when no store is configured.
func (h *RegistrationHandler) PersistUE(ctx context.Context, ue *amfctx.UEContext) {
	h.mgr.PersistUE(ctx, ue)
}

// isAllowedTA returns true when the UE's TAC is permitted by the PCF service area
// restriction. It delegates to ServiceAreaRestriction.AllowsTAC, the single
// implementation (ALLOWED_AREAS with a non-nil empty list = allowed nowhere).
// Ref: TS 23.501 §5.3.4.1, TS 29.507 §6.1.1.2.5
func (h *RegistrationHandler) isAllowedTA(tac uint32, sar *amfctx.ServiceAreaRestriction) bool {
	return sar.AllowsTAC(tac)
}

func zeroPad(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

// optionalPeerResults is the outcome of the parallel optional-peer group; the
// goroutines write only their own fields, the caller applies them after Wait.
type optionalPeerResults struct {
	nssfAllowed []amfctx.SNSSAISubscribed
	nssfErr     error

	amID   string
	amRFSP int
	amSAR  *amfctx.ServiceAreaRestriction
	amErr  error

	uePolID     string
	ueContainer []byte
	ueErr       error
}

// runOptionalPeers calls the configured optional peers (NSSF, PCF AM policy, PCF
// UE policy) concurrently, each under the same budget derived from ctx, and
// returns once all have answered or timed out. Inputs are copied before the
// goroutines start so none touches the UE context.
// Ref: TS 23.502 §4.2.9, §4.2.2.2.2 steps 14c, 17b
func (h *RegistrationHandler) runOptionalPeers(ctx context.Context, budget time.Duration,
	supi string, requested []amfctx.SNSSAISubscribed) *optionalPeerResults {
	res := &optionalPeerResults{}
	requested = append([]amfctx.SNSSAISubscribed(nil), requested...)
	pctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var wg sync.WaitGroup
	if h.nssf != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res.nssfAllowed, res.nssfErr = h.nssf.NSSelection(pctx, "AMF", h.nfInstanceID, requested)
		}()
	}
	if h.amPolicy != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res.amID, res.amRFSP, res.amSAR, res.amErr = h.amPolicy.CreateAMPolicyAssociation(
				pctx, supi, "3GPP_ACCESS", h.plmnMCC, h.plmnMNC)
		}()
	}
	if h.pcf != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res.uePolID, res.ueContainer, res.ueErr = h.pcf.CreateUEPolicyAssociation(pctx, supi, h.plmnMCC+h.plmnMNC)
		}()
	}
	wg.Wait()
	return res
}

// rollbackUDMRegistration undoes the UDM side effects of a Phase3 that is then
// rejected: the SDM subscription (id stored on the UE) is deleted and, when the
// Nudm_UECM registration succeeded, the AMF deregisters from the UDM, so no
// subscription/registration is left for a UE that never became registered.
// Best-effort, detached from the caller context. Ref: TS 23.502 §4.2.2.2.2
// step 14, TS 29.503 §5.2.2.4, §5.3.2.4.
func (h *RegistrationHandler) rollbackUDMRegistration(ctx context.Context, ue *amfctx.UEContext, uecmOK bool) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), h.budget().UECM+h.budget().SDMSubscribe)
	defer cancel()
	log := h.logger.With("procedure", "InitialRegistration", "supi", ue.SUPI,
		"interface", "Nudm", "direction", "OUT", "spec_ref", "TS 23.502 §4.2.2.2.2 step 14")
	if sub, ok := h.udm.(UDMSDMSubscriber); ok {
		if id := ue.TakeSDMSubscriptionID(); id != "" {
			if err := sub.UnsubscribeSDM(rctx, ue.SUPI, id); err != nil {
				log.Warn("UDM SDM unsubscribe failed on rejected registration",
					"subscription_id", id, "result", "FAILURE", "error", err.Error())
			}
		}
	}
	if !uecmOK {
		return
	}
	if err := h.udm.DeregisterUECM(rctx, ue.SUPI); err != nil {
		log.Warn("UDM UECM deregistration failed on rejected registration",
			"result", "FAILURE", "error", err.Error())
	}
}

// releasePolicyAssociations best-effort deletes the PCF associations created by
// the parallel group when the registration is then rejected (they would leak:
// no UE context survives to release them). Detached from the caller context.
func (h *RegistrationHandler) releasePolicyAssociations(ctx context.Context, r *optionalPeerResults) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), h.budget().Optional)
	defer cancel()
	if h.amPolicy != nil && r.amErr == nil && r.amID != "" {
		if err := h.amPolicy.DeleteAMPolicyAssociation(rctx, r.amID); err != nil {
			h.logger.Warn("PCF AM policy release failed on rejected registration",
				"procedure", "InitialRegistration", "interface", "N15", "direction", "OUT",
				"result", "FAILURE", "error", err.Error(), "spec_ref", "TS 29.507 §4.2.5")
		}
	}
	if h.pcf != nil && r.ueErr == nil && r.uePolID != "" {
		if err := h.pcf.DeleteUEPolicyAssociation(rctx, r.uePolID); err != nil {
			h.logger.Warn("PCF UE policy release failed on rejected registration",
				"procedure", "InitialRegistration", "interface", "N15", "direction", "OUT",
				"result", "FAILURE", "error", err.Error(), "spec_ref", "TS 29.525 §4.2.5")
		}
	}
}

// restrictionType returns the UE's service area restriction type for logging.
func restrictionType(ue *amfctx.UEContext) string {
	sar, _ := ue.ServiceAreaSnapshot()
	if sar == nil {
		return ""
	}
	return sar.RestrictionType
}
