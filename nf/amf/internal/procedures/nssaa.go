package procedures

import (
	"context"
	"errors"
	"fmt"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// NSSAA — Network Slice-Specific Authentication and Authorization (TS 23.502 §4.2.9).
//
// The AMF is an EAP pass-through authenticator. After Registration it runs an EAP
// exchange with the AAA-S (relayed through the AUSF) for every S-NSSAI flagged
// subjectToNssaa, and gates the Allowed/Rejected NSSAI on the EAP result. This file
// holds the slice-auth logic; the N1 send/receive lives in the nas package.

// NSSAA EAP results returned by the AUSF relay (TS 29.509 AuthResult, reused).
const (
	NSSAAResultSuccess = "EAP_SUCCESS"
	NSSAAResultFailure = "EAP_FAILURE"
)

// NSSAAMaxEAPRounds bounds the number of EAP-Requests the AAA-S may relay for
// one S-NSSAI (rel19 multi-round exchange). It is an implementation limit, not
// a 3GPP value: TS 23.502 §4.2.9.2 steps 7-14 allow "one or more iterations"
// without a bound, and an unbounded loop would let a misbehaving AAA-S pin the
// UE's NAS signalling. Exceeding it keeps the slice PENDING.
const NSSAAMaxEAPRounds = 16

// NSSAAMaxContextRestarts bounds how often one slice's exchange is restarted
// with a new Nnssaaf create after the NSSAAF answered 404 (context lost) to a
// PUT. Implementation limit, not a 3GPP value: one restart, then PENDING.
const NSSAAMaxContextRestarts = 1

// NSSAAPendingRetryMinInterval is the minimum time between two automatic
// re-initiations (UE-initiated mobility/periodic registration update or service
// request) of the same PENDING slice. It is an implementation choice, NOT a
// 3GPP value (TS 23.502 §4.2.9.2 defines no retry policy): it keeps a
// persistently failing NSSAAF from being hit on every Service Request. A full
// registration is not throttled.
const NSSAAPendingRetryMinInterval = 60 * time.Second

// ErrNSSAAContextLost is returned (wrapped) by a NSSAAConfirmer when the NSSAAF
// answers 404 to a PUT, i.e. the slice authentication context no longer exists.
// Ref: TS 29.526 §6.1.3.3.3.1
var ErrNSSAAContextLost = errors.New("amf: nssaa: slice authentication context lost")

// nssaaConfirmSpecRef is the spec reference of the Nnssaaf PUT confirm.
const nssaaConfirmSpecRef = "TS 29.526 §5.2.2.2.1 steps 4-9, §6.1.3.3.3.1"

// NSSAASliceKey is the key of a slice in per-slice UE maps (UEContext.NSSAAPendingAt).
func NSSAASliceKey(s amfctx.SNSSAISubscribed) string { return fmt.Sprintf("%d-%s", s.SST, s.SD) }

// NSSAAAuthResult is the outcome of one Nnssaaf call (create or confirm).
//
// Terminal result: AuthResult is NSSAAResultSuccess/NSSAAResultFailure and
// EAPPayload carries the EAP-Success/Failure for the UE.
// Non-terminal result (rel19 only): AuthResult is empty and EAPRequest carries
// the AAA-S EAP-Request to relay to the UE; AuthCtxID identifies the Nnssaaf
// slice authentication context for the next confirm.
type NSSAAAuthResult struct {
	AuthResult string
	EAPPayload []byte // terminal EAP packet (Success/Failure) to forward to the UE
	EAPRequest []byte // non-terminal EAP-Request to forward to the UE (rel19)
	AuthCtxID  string // Nnssaaf authCtxId of the open context (rel19, non-terminal)
}

// NSSAAConfirmer is the optional second half of the Nnssaaf_NSSAA relay: it
// carries the UE's following EAP-Response of a multi-round exchange to the open
// slice authentication context (PUT, TS 29.526 §5.2.2.2.1 steps 4-9, §6.1.3.3.3.1). A client that does not
// implement it can only run one-round exchanges; a non-terminal EAP-Request then
// keeps the slice PENDING.
type NSSAAConfirmer interface {
	Confirm(ctx context.Context, supi, gpsi string, sst uint8, sd, authCtxID string, eapPayload []byte) (*NSSAAAuthResult, error)
}

// NSSAAClient relays the UE's EAP-Response to the AAA-S via the AUSF.
type NSSAAClient interface {
	Authenticate(ctx context.Context, supi, gpsi string, sst uint8, sd string, eapPayload []byte) (*NSSAAAuthResult, error)
}

// WithNSSAASpecLiteral selects the Rel-19 NSSAA behaviour (REL19-3.5 slice E):
// the real GPSI is passed to the NSSAAF and an NSSAA that cannot be completed
// keeps the slice PENDING instead of rejecting it. Off = frozen rel17 behaviour.
func (h *RegistrationHandler) WithNSSAASpecLiteral(on bool) { h.nssaaSpec = on }

// NSSAASpecLiteral reports whether the rel19 NSSAA behaviour is selected. Safe
// on a nil handler (NAS unit tests build handlers without a registration
// handler): false.
func (h *RegistrationHandler) NSSAASpecLiteral() bool { return h != nil && h.nssaaSpec }

// WithNSSAA enables Network Slice-Specific Authentication. When set, slices flagged
// subjectToNssaa are withheld from the initial Allowed NSSAI and authenticated after
// registration. Ref: TS 23.502 §4.2.9.
func (h *RegistrationHandler) WithNSSAA(c NSSAAClient) {
	h.nssaa = c
}

// SplitPendingNSSAA moves every subjectToNssaa slice out of the freshly-computed
// Allowed NSSAI into PendingNSSAA, so it is not granted until slice auth succeeds.
// No-op (Allowed NSSAI byte-identical) when NSSAA is not configured or no slice is
// flagged — guaranteeing zero regression for non-NSSAA subscribers.
// Ref: TS 23.502 §4.2.9.2 step 1 (pending NSSAI).
func (h *RegistrationHandler) SplitPendingNSSAA(ue *amfctx.UEContext) {
	if h.nssaa == nil {
		return
	}
	// rel19: a registration recomputes the Allowed NSSAI from the subscription,
	// so any half-run exchange and the PENDING list are rebuilt from scratch.
	// Slices whose NSSAA had stayed PENDING are thereby re-initiated; slices
	// holding a stored EAP-Failure result are not (below).
	// Ref: TS 23.502 §4.2.9.2 step 1, step 18 ("store the EAP result for each
	// S-NSSAI"); TS 24.501 §5.4.7.2.3 e)
	var wasPending []amfctx.SNSSAISubscribed
	if h.nssaaSpec {
		// A half-run exchange is abandoned: stop its T3575 (nothing may fire
		// on a state that no longer exists) and log the orphaned context.
		ue.StopNSSAATimer()
		if ue.NSSAAInProgress != nil {
			h.logOrphanedAuthCtx(ue, *ue.NSSAAInProgress, "registration recomputed the Allowed NSSAI")
		}
		wasPending = ue.NSSAAPendingStatus
		ue.NSSAAPendingStatus = nil
		ue.PendingNSSAA = nil
		ue.NSSAAInProgress = nil
		ue.NSSAAResultsChanged = false // the Registration Accept carries the up-to-date NSSAIs
		resetNSSAAExchange(ue)
	}
	var allowed []amfctx.SNSSAISubscribed
	dropped := false
	for _, s := range ue.AllowedNSSAI {
		if s.SubjectToNSSAA {
			if h.nssaaSpec {
				if hasSubscribed(ue.RejectedNSSAI, s) {
					dropped = true
					continue // EAP-Failure retained: not retried, not allowed
				}
				if hasSubscribed(wasPending, s) {
					h.logger.Info("NSSAA re-initiated for PENDING slice",
						"procedure", "NSSAA", "supi", ue.SUPI,
						"sst", s.SST, "sd", s.SD, "trigger", "registration",
						"spec_ref", "TS 23.502 §4.2.9.2")
				}
				ue.PendingNSSAA = appendAllowed(ue.PendingNSSAA, s)
				continue
			}
			ue.PendingNSSAA = append(ue.PendingNSSAA, s)
			continue
		}
		allowed = append(allowed, s)
	}
	if len(ue.PendingNSSAA) > 0 || dropped {
		ue.AllowedNSSAI = allowed
		h.logger.Info("slices withheld for NSSAA",
			"procedure", "NSSAA",
			"supi", ue.SUPI,
			"pending_count", len(ue.PendingNSSAA),
			"allowed_count", len(ue.AllowedNSSAI),
			"spec_ref", "TS 23.502 §4.2.9.2",
		)
	}
}

// StartNSSAA pops the first pending slice and produces the NETWORK SLICE-SPECIFIC
// AUTHENTICATION COMMAND (EAP-Request/Identity). Returns (nil, false) when there is
// nothing to authenticate. The caller sends the COMMAND on N1.
// Ref: TS 23.502 §4.2.9.2 step 2-4, TS 24.501 §5.4.7.2.
func (h *RegistrationHandler) StartNSSAA(_ context.Context, ue *amfctx.UEContext) (*nas.NSSAAuthCommand, bool) {
	if h.nssaa == nil || len(ue.PendingNSSAA) == 0 {
		return nil, false
	}
	if h.nssaaSpec && ue.NSSAAInProgress != nil {
		return nil, false // one exchange at a time: the running one finishes first
	}
	return h.beginSlice(ue, ue.PendingNSSAA[0]), true
}

// beginSlice marks slice as in-progress and builds the COMMAND with a fresh
// EAP-Request/Identity.
func (h *RegistrationHandler) beginSlice(ue *amfctx.UEContext, slice amfctx.SNSSAISubscribed) *nas.NSSAAuthCommand {
	ue.NSSAAEAPID++
	s := slice
	ue.NSSAAInProgress = &s
	h.logger.Info("NSSAA started for slice",
		"procedure", "NSSAA",
		"supi", ue.SUPI,
		"sst", slice.SST, "sd", slice.SD,
		"interface", "N1", "direction", "OUT",
		"message_type", "NetworkSliceSpecificAuthCommand",
		"spec_ref", "TS 24.501 §8.2.31",
	)
	return &nas.NSSAAuthCommand{
		SNSSAI:     toNASSNSSAI(slice),
		EAPMessage: eap.BuildIdentityRequest(ue.NSSAAEAPID),
	}
}

// NSSAACompleteOutcome is what the nas layer needs to act on after a COMPLETE.
type NSSAACompleteOutcome struct {
	Result         *nas.NSSAAuthResult     // RESULT to send to the UE (EAP-Success/Failure)
	NextCommand    *nas.NSSAAuthCommand    // next slice's COMMAND, or nil when the queue is drained
	AllowedChanged bool                    // Allowed NSSAI changed → caller should send Config Update
	Slice          amfctx.SNSSAISubscribed // the slice this COMPLETE resolved
	Authorized     bool
	// ConfigUpdate: the queue drained and the caller shall send ONE
	// CONFIGURATION UPDATE COMMAND now. rel17: the last COMPLETE was authorized
	// (AllowedChanged, frozen behaviour); rel19: any slice of the queue got a new
	// result (EAP-Success/Failure/T3575 abort), TS 23.502 §4.2.9.2 step 19a.
	ConfigUpdate bool
	// Deregister (rel19): the queue drained with no S-NSSAI left and no default
	// S-NSSAI that can be allowed; the caller shall perform the network-initiated
	// de-registration with the Rejected NSSAI (ue.RejectedNSSAI) instead of the
	// CONFIGURATION UPDATE COMMAND (ConfigUpdate is false then).
	// Ref: TS 23.502 §4.2.9.2 step 19b, TS 24.501 §4.6.2.4 c)
	Deregister bool
}

// ProcessNSSAAComplete handles a NETWORK SLICE-SPECIFIC AUTHENTICATION COMPLETE:
// relays the UE's EAP-Response to the AAA-S via AUSF, updates Allowed/Rejected NSSAI,
// builds the RESULT, and advances to the next pending slice.
// Ref: TS 23.502 §4.2.9.2 step 5-9, TS 24.501 §5.4.7.3.
func (h *RegistrationHandler) ProcessNSSAAComplete(
	ctx context.Context, ue *amfctx.UEContext, complete *nas.NSSAAuthComplete) (*NSSAACompleteOutcome, error) {

	if h.nssaa == nil {
		return nil, fmt.Errorf("nssaa: not configured")
	}
	if ue.NSSAAInProgress == nil {
		return nil, fmt.Errorf("nssaa: COMPLETE with no slice in progress")
	}
	slice := *ue.NSSAAInProgress
	if !sameSlice(toNASSNSSAI(slice), complete.SNSSAI) {
		return nil, fmt.Errorf("nssaa: COMPLETE S-NSSAI %v != in-progress %v", complete.SNSSAI, slice)
	}

	// Relay the EAP-Response to the AAA-S via AUSF.
	authorized := false
	var eapResult []byte
	gpsi := ue.SUPI // rel17 legacy body: gpsi = SUPI (frozen wire behaviour)
	if h.nssaaSpec {
		gpsi = ue.GPSI
	}
	var res *NSSAAAuthResult
	var err error
	switch {
	case h.nssaaSpec && gpsi == "":
		err = errors.New("amf: nssaa: UE has no GPSI in its subscription")
	case h.nssaaSpec && ue.NSSAAAuthCtxID != "":
		// Following round of a multi-round exchange: PUT to the open context.
		if cf, ok := h.nssaa.(NSSAAConfirmer); ok {
			res, err = cf.Confirm(ctx, ue.SUPI, gpsi, slice.SST, slice.SD, ue.NSSAAAuthCtxID, complete.EAPMessage)
		} else {
			err = errors.New("amf: nssaa: client cannot confirm a multi-round exchange")
		}
	default:
		res, err = h.nssaa.Authenticate(ctx, ue.SUPI, gpsi, slice.SST, slice.SD, complete.EAPMessage)
	}
	if err != nil {
		if h.nssaaSpec {
			if errors.Is(err, ErrNSSAAContextLost) && ue.NSSAARestarts < NSSAAMaxContextRestarts {
				return h.restartNSSAA(ue, slice, err), nil
			}
			return h.keepNSSAAPending(ue, slice, err), nil
		}
		// rel17: an unreachable AAA-S is a failure so the slice is rejected
		// rather than left dangling.
		h.logger.Warn("NSSAA AAA relay failed — slice rejected",
			"procedure", "NSSAA", "supi", ue.SUPI,
			"sst", slice.SST, "sd", slice.SD, "error", err,
			"spec_ref", "TS 23.502 §4.2.9.2")
		eapResult = eap.BuildFailure(ue.NSSAAEAPID)
	} else if h.nssaaSpec && res.AuthResult == "" && len(res.EAPRequest) > 0 {
		return h.continueNSSAA(ue, slice, res), nil
	} else {
		authorized = res.AuthResult == NSSAAResultSuccess
		eapResult = res.EAPPayload
	}

	out := &NSSAACompleteOutcome{
		Result:     &nas.NSSAAuthResult{SNSSAI: toNASSNSSAI(slice), EAPMessage: eapResult},
		Slice:      slice,
		Authorized: authorized,
	}
	if authorized {
		ue.AllowedNSSAI = appendAllowed(ue.AllowedNSSAI, slice)
		ue.RejectedNSSAI = dropSlice(ue.RejectedNSSAI, slice)
		out.AllowedChanged = true
		ue.NSSAAResultsChanged = true
		delete(ue.NSSAAPendingAt, NSSAASliceKey(slice))
		metrics.ProcedureTotal.WithLabelValues(nfName, "NSSAA", "OK").Inc()
		h.logger.Info("NSSAA succeeded — slice added to Allowed NSSAI",
			"procedure", "NSSAA", "supi", ue.SUPI,
			"sst", slice.SST, "sd", slice.SD, "result", "OK",
			"spec_ref", "TS 23.502 §4.2.9.2")
	} else {
		ue.RejectedNSSAI = appendRejected(ue.RejectedNSSAI, slice)
		ue.NSSAAResultsChanged = true
		delete(ue.NSSAAPendingAt, NSSAASliceKey(slice))
		if h.nssaaSpec {
			// A failed re-authentication also revokes the slice (§4.2.9.3).
			ue.AllowedNSSAI = dropSlice(ue.AllowedNSSAI, slice)
		}
		metrics.ProcedureTotal.WithLabelValues(nfName, "NSSAA", "REJECT").Inc()
		h.logger.Info("NSSAA failed — slice rejected (Rejected NSSAI cause "+rejectedCauseLabel+")",
			"procedure", "NSSAA", "supi", ue.SUPI,
			"sst", slice.SST, "sd", slice.SD, "result", "REJECT",
			"cause", rejectedCauseLabel, "spec_ref", "TS 24.501 §9.11.3.46 Table 9.11.3.46.1")
	}

	// Advance the queue: drop the resolved slice, start the next one if any.
	ue.NSSAAInProgress = nil
	resetNSSAAExchange(ue)
	ue.PendingNSSAA = dropSlice(ue.PendingNSSAA, slice)
	h.advanceNSSAAQueue(ue, out)
	return out, nil
}

// rejectedCauseLabel is the Rejected NSSAI cause value used for a slice whose
// NSSAA failed or was revoked, as text for logs: "S-NSSAI not available due to
// the failed or revoked network slice-specific authentication and
// authorization" (nas.RejectedCauseNSSAAFailedOrRevoked = 0b0010 = 2). The
// rel17 text called it "#3"; only the label is corrected, not the rel17 wire.
// Ref: TS 24.501 §9.11.3.46 Table 9.11.3.46.1
var rejectedCauseLabel = fmt.Sprint(nas.RejectedCauseNSSAAFailedOrRevoked)

// NSSAADeregCause5GMM is the 5GMM cause of a DEREGISTRATION REQUEST triggered by
// a network slice-specific authentication and authorization failure or
// revocation: #62 "No network slices available". The TS mandates it; the
// de-registration type is "re-registration not required" (the UE would only
// fail NSSAA again) and the access type 3GPP.
// Ref: TS 24.501 §5.5.2.3.1 (V19.8.0), §9.11.3.2 Table 9.11.3.2.1
const NSSAADeregCause5GMM byte = 62

// NSSAADeregistrationRequired is the rel19 decision of TS 24.501 §4.6.2.4 c) /
// TS 23.502 §4.2.9.2 step 19b (and the re-authentication / revocation variants
// §4.2.9.3, §4.2.9.4): network-initiated de-registration with the Rejected NSSAI
// when NSSAA failed or was revoked for every S-NSSAI so that
//
//   - the Allowed NSSAI is empty, and
//   - no exchange is queued, running or PENDING (a slice that may still succeed
//     keeps the registration alive: PENDING is an NSSAAF/AAA-side outage, not a
//     failure, TS 23.502 §4.2.9.2), and at least one slice was rejected, and
//   - no default S-NSSAI can be allowed. The AMF reads the subscription's
//     defaultSingleNssais into ue.SubscribedNSSAI; a default S-NSSAI can be
//     allowed when it is not subject to NSSAA and not rejected
//     (allowableDefaultNSSAI). When every default is subject to NSSAA and none
//     succeeded (Allowed NSSAI empty) there is none. When one exists the caller
//     sends the CONFIGURATION UPDATE COMMAND with those defaults as the Allowed
//     NSSAI (decideNSSAAEnd), TS 24.501 §4.6.2.4 b).
//
// The second return value is true when the only reason not to de-register is
// the emergency PDU session exception ("the AMF shall send the CONFIGURATION
// UPDATE COMMAND containing rejected NSSAI"). rel17 never de-registers.
func (h *RegistrationHandler) NSSAADeregistrationRequired(ue *amfctx.UEContext) (dereg, emergency bool) {
	if !h.nssaaSettled(ue) {
		return false, false
	}
	if len(allowableDefaultNSSAI(ue)) > 0 {
		return false, false // a default S-NSSAI can be allowed
	}
	if ue.EmergencyPDUSession {
		return false, true
	}
	return true, false
}

// nssaaSettled reports the rel19 precondition of TS 24.501 §4.6.2.4 b)/c): NSSAA
// ended for every slice (no exchange queued, running or PENDING), nothing is
// allowed and at least one slice was rejected.
func (h *RegistrationHandler) nssaaSettled(ue *amfctx.UEContext) bool {
	return h.nssaaSpec && len(ue.AllowedNSSAI) == 0 && len(ue.RejectedNSSAI) > 0 &&
		len(ue.PendingNSSAA) == 0 && ue.NSSAAInProgress == nil && len(ue.NSSAAPendingStatus) == 0
}

// allowableDefaultNSSAI returns the default S-NSSAIs that can be allowed to the
// UE after NSSAA failed for every requested slice: the subscription's default
// S-NSSAIs (ue.SubscribedNSSAI) that are not subject to NSSAA and not rejected,
// at most nas.MaxRejectedSNSSAIs (8, the Allowed NSSAI limit of TS 24.501
// §9.11.3.37). A default subject to NSSAA that was authenticated successfully
// would already be in the Allowed NSSAI, which callers have checked to be empty.
// Ref: TS 24.501 §4.6.2.4 b), TS 23.502 §4.2.9.2 step 19a
func allowableDefaultNSSAI(ue *amfctx.UEContext) []amfctx.SNSSAISubscribed {
	var out []amfctx.SNSSAISubscribed
	for _, d := range ue.SubscribedNSSAI {
		if len(out) == maxAllowedSNSSAIs {
			break
		}
		if !d.SubjectToNSSAA && !hasSubscribed(ue.RejectedNSSAI, d) {
			out = appendAllowed(out, d)
		}
	}
	return out
}

// maxAllowedSNSSAIs is the maximum number of S-NSSAIs in the Allowed NSSAI IE.
// Ref: TS 24.501 §9.11.3.37
const maxAllowedSNSSAIs = 8

// advanceNSSAAQueue starts the next queued slice or, when the queue is drained,
// decides whether the caller shall send the CONFIGURATION UPDATE COMMAND.
//
// rel17 (frozen): CUC iff the last resolved slice was authorized.
// rel19: ONE CUC for the whole queue iff any slice got a new result; with no
// S-NSSAI left in the Allowed NSSAI and no default S-NSSAI that can be allowed
// the AMF instead performs the network-initiated de-registration carrying the
// Rejected NSSAI (NSSAADeregistrationRequired; Outcome.Deregister), except with
// an emergency PDU session (CUC).
// Ref: TS 23.502 §4.2.9.2 steps 19a-19b, TS 24.501 §4.6.2.4 c)
func (h *RegistrationHandler) advanceNSSAAQueue(ue *amfctx.UEContext, out *NSSAACompleteOutcome) {
	if len(ue.PendingNSSAA) > 0 {
		out.NextCommand = h.beginSlice(ue, ue.PendingNSSAA[0])
		return
	}
	if !h.nssaaSpec {
		out.ConfigUpdate = out.AllowedChanged
		return
	}
	if !ue.NSSAAResultsChanged {
		return
	}
	ue.NSSAAResultsChanged = false
	out.Deregister, out.ConfigUpdate = h.decideNSSAAEnd(ue)
}

// ApplyNSSAARevocation performs the AAA-initiated revocation of one slice
// (RevokeNSSAA) and decides what the caller sends (decideNSSAAEnd). revoked is
// false when the slice was not allowed (nothing to send).
// Ref: TS 23.502 §4.2.9.4, TS 24.501 §4.6.2.4
func (h *RegistrationHandler) ApplyNSSAARevocation(ue *amfctx.UEContext, sst uint8, sd string) (revoked, deregister, configUpdate bool) {
	if !h.RevokeNSSAA(ue, sst, sd) {
		return false, false, false
	}
	deregister, configUpdate = h.decideNSSAAEnd(ue)
	return true, deregister, configUpdate
}

// decideNSSAAEnd turns the end-of-NSSAA state into the (deregister, cuc) pair for
// a drained queue / a revocation and logs the decision (rel19):
//
//   - no S-NSSAI can be allowed: network-initiated de-registration
//     (NSSAADeregistrationRequired); the REJECT metric is counted by the caller
//     once the DEREGISTRATION REQUEST was really sent;
//   - every requested slice failed but default S-NSSAIs can be allowed
//     (TS 24.501 §4.6.2.4 b)): they become the Allowed NSSAI before the
//     CONFIGURATION UPDATE COMMAND, which therefore never carries an empty
//     Allowed NSSAI in that case;
//   - emergency PDU session: CUC with the Rejected NSSAI only.
func (h *RegistrationHandler) decideNSSAAEnd(ue *amfctx.UEContext) (deregister, configUpdate bool) {
	dereg, emergency := h.NSSAADeregistrationRequired(ue)
	switch {
	case dereg:
		h.logger.Warn("NSSAA left no Allowed NSSAI and no default S-NSSAI can be allowed - network-initiated de-registration with Rejected NSSAI",
			"procedure", "NSSAA", "supi", ue.SUPI, "result", "REJECT",
			"rejected_count", len(ue.RejectedNSSAI), "cause", NSSAADeregCause5GMM,
			"spec_ref", "TS 23.502 §4.2.9.2 step 19b, TS 24.501 §4.6.2.4 c)")
		return true, false
	case emergency:
		h.logger.Warn("NSSAA left no Allowed NSSAI but the UE has an emergency PDU session - Configuration Update Command with Rejected NSSAI",
			"procedure", "NSSAA", "supi", ue.SUPI, "result", "REJECT",
			"spec_ref", "TS 24.501 §4.6.2.4 c)")
	case h.nssaaSettled(ue):
		defaults := allowableDefaultNSSAI(ue)
		ue.AllowedNSSAI = defaults
		h.logger.Info("NSSAA failed for every requested S-NSSAI - default S-NSSAIs allowed in the Configuration Update Command",
			"procedure", "NSSAA", "supi", ue.SUPI, "allowed_count", len(defaults),
			"rejected_count", len(ue.RejectedNSSAI),
			"spec_ref", "TS 23.502 §4.2.9.2 step 19a, TS 24.501 §4.6.2.4 b)")
	}
	return false, true
}

// continueNSSAA handles a non-terminal EAP-Request from the AAA-S (rel19): the
// request is relayed to the UE in a further NETWORK SLICE-SPECIFIC
// AUTHENTICATION COMMAND for the same S-NSSAI, and the authCtxId is retained for
// the PUT of the UE's answer. More than NSSAAMaxEAPRounds requests, or a request
// without a usable context, keeps the slice PENDING.
// Ref: TS 23.502 §4.2.9.2 steps 7-14, TS 24.501 §5.4.7.2.1, TS 29.526 §5.2.2.2.1 steps 4-9, §6.1.3.3.3.1
func (h *RegistrationHandler) continueNSSAA(ue *amfctx.UEContext, slice amfctx.SNSSAISubscribed, res *NSSAAAuthResult) *NSSAACompleteOutcome {
	ue.NSSAARounds++
	if ue.NSSAARounds > NSSAAMaxEAPRounds {
		return h.keepNSSAAPending(ue, slice, fmt.Errorf("amf: nssaa: more than %d EAP rounds", NSSAAMaxEAPRounds))
	}
	if res.AuthCtxID == "" {
		return h.keepNSSAAPending(ue, slice, errors.New("amf: nssaa: EAP-Request without authCtxId"))
	}
	id, err := eap.Identifier(res.EAPRequest)
	if err != nil {
		return h.keepNSSAAPending(ue, slice, fmt.Errorf("amf: nssaa: EAP-Request: %w", err))
	}
	ue.NSSAAAuthCtxID = res.AuthCtxID
	ue.NSSAAEAPID = id
	h.logger.Info("NSSAA EAP-Request relayed to UE",
		"procedure", "NSSAA", "supi", ue.SUPI,
		"sst", slice.SST, "sd", slice.SD, "round", ue.NSSAARounds,
		"interface", "N1", "direction", "OUT",
		"message_type", "NetworkSliceSpecificAuthCommand",
		"spec_ref", "TS 24.501 §5.4.7.2.1")
	return &NSSAACompleteOutcome{
		Slice: slice,
		NextCommand: &nas.NSSAAuthCommand{
			SNSSAI:     toNASSNSSAI(slice),
			EAPMessage: res.EAPRequest,
		},
	}
}

// AbortNSSAA aborts the exchange of the slice in progress (rel19) after the fifth
// T3575 expiry. TS 24.501 §5.4.7.2.3 a) says the procedure is "completed as a
// failure" for the S-NSSAI, so: the exchange is stopped (no RESULT is sent, there
// is no EAP result to relay), the slice is recorded as failed — added to the
// Rejected NSSAI, kept out of the Allowed NSSAI and out of the PENDING list, so it
// is never retried while the UE stays registered (treated like an EAP-Failure
// slice) — and the next queued slice, if any, is started. Returns nil when
// nothing is in progress or the rel17 profile is selected (rel17 has no T3575).
//
// PENDING (retry on later UE activity) is reserved for failures on the
// NSSAAF/AAA-S side (see keepNSSAAPending), not for a silent UE.
// Ref: TS 24.501 §5.4.7.2.3 a), TS 23.502 §4.2.9.2
func (h *RegistrationHandler) AbortNSSAA(ue *amfctx.UEContext, cause error) *NSSAACompleteOutcome {
	if !h.nssaaSpec || h.nssaa == nil || ue.NSSAAInProgress == nil {
		return nil
	}
	slice := *ue.NSSAAInProgress
	h.logOrphanedAuthCtx(ue, slice, "T3575 expired")
	h.logger.Warn("NSSAA aborted by T3575 - procedure completed as a failure, slice rejected (no RESULT sent)",
		"procedure", "NSSAA", "supi", ue.SUPI,
		"sst", slice.SST, "sd", slice.SD, "result", "REJECT",
		"eap_result", NSSAAResultFailure, "cause", rejectedCauseLabel, "error", cause,
		"spec_ref", "TS 24.501 §5.4.7.2.3 a)")
	metrics.ProcedureTotal.WithLabelValues(nfName, "NSSAA", "REJECT").Inc()
	ue.NSSAAInProgress = nil
	resetNSSAAExchange(ue)
	ue.PendingNSSAA = dropSlice(ue.PendingNSSAA, slice)
	ue.NSSAAPendingStatus = dropSlice(ue.NSSAAPendingStatus, slice)
	ue.AllowedNSSAI = dropSlice(ue.AllowedNSSAI, slice)
	ue.RejectedNSSAI = appendRejected(ue.RejectedNSSAI, slice)
	delete(ue.NSSAAPendingAt, NSSAASliceKey(slice))
	ue.NSSAAResultsChanged = true
	out := &NSSAACompleteOutcome{Slice: slice}
	h.advanceNSSAAQueue(ue, out)
	return out
}

// RetryPendingNSSAA re-queues the slices left PENDING by an earlier NSSAA
// attempt so a new exchange can start (rel19). It is the trigger used for
// UE-initiated procedures that do not recompute the Allowed NSSAI (mobility /
// periodic registration update, service request); a full registration re-queues
// them in SplitPendingNSSAA. Slices holding a stored EAP-Failure (Rejected NSSAI)
// or already allowed are never re-queued, and a slice left PENDING less than
// NSSAAPendingRetryMinInterval ago stays PENDING for a later trigger. Returns
// true when a slice is queued and no exchange is running, i.e. the caller should
// StartNSSAA.
//
// TS 23.502 §4.2.9.2 defines no retry timer: the retry trigger is UE-initiated
// signalling and the minimum interval an implementation choice.
// Ref: TS 23.502 §4.2.9.2
func (h *RegistrationHandler) RetryPendingNSSAA(ue *amfctx.UEContext) bool {
	if !h.nssaaSpec || h.nssaa == nil || ue.NSSAAInProgress != nil || len(ue.NSSAAPendingStatus) == 0 {
		return false
	}
	now := time.Now()
	var remaining []amfctx.SNSSAISubscribed
	for _, s := range ue.NSSAAPendingStatus {
		if hasSubscribed(ue.RejectedNSSAI, s) || hasSubscribed(ue.AllowedNSSAI, s) {
			continue
		}
		if at, ok := ue.NSSAAPendingAt[NSSAASliceKey(s)]; ok && now.Sub(at) < NSSAAPendingRetryMinInterval {
			remaining = append(remaining, s) // too soon: stays PENDING
			continue
		}
		ue.PendingNSSAA = appendAllowed(ue.PendingNSSAA, s)
		delete(ue.NSSAAPendingAt, NSSAASliceKey(s))
		h.logger.Info("NSSAA re-initiated for PENDING slice",
			"procedure", "NSSAA", "supi", ue.SUPI,
			"sst", s.SST, "sd", s.SD, "trigger", "ue_initiated_procedure",
			"spec_ref", "TS 23.502 §4.2.9.2")
	}
	ue.NSSAAPendingStatus = remaining
	return len(ue.PendingNSSAA) > 0
}

// resetNSSAAExchange clears the per-slice multi-round state.
func resetNSSAAExchange(ue *amfctx.UEContext) {
	ue.NSSAAAuthCtxID = ""
	ue.NSSAARounds = 0
	ue.NSSAARestarts = 0
}

// logOrphanedAuthCtx logs the authCtxId of an exchange the AMF abandons while
// the NSSAAF still holds the context. TS 29.526 defines no DELETE for the
// slice-authentications resource, so the NSSAAF's own context lifetime cleans it
// up; the log lets an operator correlate the leftover context.
// Ref: TS 29.526 §6.1.3 (resources: create and confirm only)
func (h *RegistrationHandler) logOrphanedAuthCtx(ue *amfctx.UEContext, slice amfctx.SNSSAISubscribed, reason string) {
	if ue.NSSAAAuthCtxID == "" {
		return
	}
	h.logger.Warn("NSSAA exchange abandoned - authCtxId left orphaned at the NSSAAF (no DELETE defined, NSSAAF TTL cleans up)",
		"procedure", "NSSAA", "supi", ue.SUPI,
		"sst", slice.SST, "sd", slice.SD,
		"auth_ctx_id", ue.NSSAAAuthCtxID, "reason", reason,
		"spec_ref", "TS 29.526 §6.1.3")
}

// restartNSSAA restarts the exchange of slice once after the NSSAAF lost the
// context (404 on the PUT): the orphaned authCtxId is dropped and the UE is
// sent a fresh EAP-Request/Identity in a new COMMAND, whose answer opens a new
// context with a create. Bounded by NSSAAMaxContextRestarts; the next failure
// keeps the slice PENDING.
// Ref: TS 29.526 §5.2.2.2.1 (create), §6.1.3.3.3.1 (404), TS 24.501 §5.4.7.2.1
func (h *RegistrationHandler) restartNSSAA(ue *amfctx.UEContext, slice amfctx.SNSSAISubscribed, cause error) *NSSAACompleteOutcome {
	h.logOrphanedAuthCtx(ue, slice, "NSSAAF lost the context (404)")
	h.logger.Warn("NSSAA context lost at the NSSAAF - exchange restarted with a new create",
		"procedure", "NSSAA", "supi", ue.SUPI, "sst", slice.SST, "sd", slice.SD,
		"restart", ue.NSSAARestarts+1, "error", cause,
		"interface", "N1", "direction", "OUT",
		"spec_ref", nssaaConfirmSpecRef)
	restarts := ue.NSSAARestarts + 1
	resetNSSAAExchange(ue)
	ue.NSSAARestarts = restarts
	ue.NSSAAEAPID++
	return &NSSAACompleteOutcome{
		Slice: slice,
		NextCommand: &nas.NSSAAuthCommand{
			SNSSAI:     toNASSNSSAI(slice),
			EAPMessage: eap.BuildIdentityRequest(ue.NSSAAEAPID),
		},
	}
}

func hasSubscribed(list []amfctx.SNSSAISubscribed, s amfctx.SNSSAISubscribed) bool {
	for _, e := range list {
		if e.SST == s.SST && e.SD == s.SD {
			return true
		}
	}
	return false
}

// keepNSSAAPending handles an NSSAA that could not be completed for a reason
// other than an authentication failure on the NSSAAF/AAA-S side (transport
// error, 5xx, no GPSI, round cap): the slice stays PENDING — out of the Allowed
// NSSAI and not added to the Rejected NSSAI — and no RESULT is sent (there is no
// EAP result to relay). The AMF re-initiates later on UE-initiated signalling
// (RetryPendingNSSAA), at most once per NSSAAPendingRetryMinInterval.
// Ref: TS 29.526 §5.2.2.2.1 ("keep the status attribute set to PENDING"),
// TS 23.502 §4.2.9.2
func (h *RegistrationHandler) keepNSSAAPending(ue *amfctx.UEContext, slice amfctx.SNSSAISubscribed, cause error) *NSSAACompleteOutcome {
	h.logOrphanedAuthCtx(ue, slice, "exchange kept PENDING")
	h.logger.Warn("NSSAA could not be completed — slice kept PENDING",
		"procedure", "NSSAA", "supi", ue.SUPI,
		"sst", slice.SST, "sd", slice.SD, "result", "PENDING", "error", cause,
		"spec_ref", "TS 29.526 §5.2.2.2.1")
	metrics.ProcedureTotal.WithLabelValues(nfName, "NSSAA", "FAILURE").Inc()
	ue.NSSAAInProgress = nil
	resetNSSAAExchange(ue)
	ue.PendingNSSAA = dropSlice(ue.PendingNSSAA, slice)
	ue.NSSAAPendingStatus = appendAllowed(ue.NSSAAPendingStatus, slice)
	if ue.NSSAAPendingAt == nil {
		ue.NSSAAPendingAt = make(map[string]time.Time)
	}
	ue.NSSAAPendingAt[NSSAASliceKey(slice)] = time.Now()
	out := &NSSAACompleteOutcome{Slice: slice}
	h.advanceNSSAAQueue(ue, out)
	return out
}

// RevokeNSSAA handles an AAA-initiated revocation (TS 23.502 §4.2.9.4): removes the
// slice from Allowed NSSAI and records it in Rejected NSSAI (cause 2, failed or revoked NSSAA). Returns true
// when the slice was previously allowed and an Allowed-NSSAI change occurred.
func (h *RegistrationHandler) RevokeNSSAA(ue *amfctx.UEContext, sst uint8, sd string) bool {
	target := amfctx.SNSSAISubscribed{SST: sst, SD: sd}
	var kept []amfctx.SNSSAISubscribed
	removed := false
	for _, s := range ue.AllowedNSSAI {
		if s.SST == sst && s.SD == sd {
			removed = true
			continue
		}
		kept = append(kept, s)
	}
	if !removed {
		return false
	}
	ue.AllowedNSSAI = kept
	ue.RejectedNSSAI = appendRejected(ue.RejectedNSSAI, target)
	h.logger.Info("NSSAA authorization revoked — slice removed from Allowed NSSAI",
		"procedure", "NSSAA", "supi", ue.SUPI,
		"sst", sst, "sd", sd, "cause", rejectedCauseLabel,
		"spec_ref", "TS 23.502 §4.2.9.4")
	return true
}

// NASRejectedNSSAI converts the slices that failed (or lost) NSSAA into Rejected
// NSSAI entries with cause nas.RejectedCauseNSSAAFailedOrRevoked, using the
// HPLMN SST/SD as sent in the subscription (TS 24.501 §9.11.3.46 NOTEs 5/6). At
// most nas.MaxRejectedSNSSAIs entries are returned (the UE stores no more);
// ok=false tells the caller the list was truncated.
// Ref: TS 24.501 §9.11.3.46, §4.6.2.4, §5.4.4.2
func NASRejectedNSSAI(subs []amfctx.SNSSAISubscribed) (list []nas.RejectedSNSSAI, ok bool) {
	ok = true
	for _, s := range subs {
		if len(list) == nas.MaxRejectedSNSSAIs {
			return list, false
		}
		list = append(list, nas.RejectedSNSSAI{
			Cause:  nas.RejectedCauseNSSAAFailedOrRevoked,
			SNSSAI: toNASSNSSAI(s),
		})
	}
	return list, ok
}

// applyNSSAAAcceptIEs adds the NSSAA-related IEs of a REGISTRATION ACCEPT
// (rel19 only; rel17 bytes are frozen): the Pending NSSAI (IEI 0x39) with the
// S-NSSAIs whose NSSAA is still to be run or pending, and the Rejected NSSAI
// (IEI 0x11, cause 2) with the slices that failed NSSAA.
// Ref: TS 24.501 §4.6.2.4, §5.5.1.2.4, Table 8.2.7.1.1, §9.11.3.46
// regResultNSSAAToBePerformed is the "NSSAA to be performed" indicator of the
// 5GS registration result IE (octet 3, bit 5). Ref: TS 24.501 §9.11.3.6.
const regResultNSSAAToBePerformed = 0x10

func (h *RegistrationHandler) applyNSSAAAcceptIEs(ra *nas.RegistrationAccept, ue *amfctx.UEContext) {
	if !h.nssaaSpec || h.nssaa == nil {
		return
	}
	var pending []amfctx.SNSSAISubscribed
	add := func(list []amfctx.SNSSAISubscribed) {
		for _, s := range list {
			if !hasSubscribed(ue.AllowedNSSAI, s) && !hasSubscribed(ue.RejectedNSSAI, s) {
				pending = appendAllowed(pending, s)
			}
		}
	}
	add(ue.PendingNSSAA)
	if ue.NSSAAInProgress != nil {
		add([]amfctx.SNSSAISubscribed{*ue.NSSAAInProgress})
	}
	add(ue.NSSAAPendingStatus)
	if len(pending) > 0 {
		n := buildAllowedNSSAI(pending)
		ra.PendingNSSAI = &n
	}
	rejectedIE := false
	if rej, complete := NASRejectedNSSAI(ue.RejectedNSSAI); len(rej) > 0 {
		if ue.ERNSSAISupported {
			// The UE set the ER-NSSAI bit: the rejected NSSAI "shall be included in the
			// Extended rejected NSSAI IE" (instead of the Rejected NSSAI IE). NSSAA
			// failures are HPLMN S-NSSAIs: no mapped S-NSSAI, no back-off timer.
			// Ref: TS 24.501 §5.5.1.2.4, §4.6.1, §9.11.3.75
			ra.ExtendedRejectedNSSAI = nas.ExtendedRejectedNSSAIFromList(rej)
			rejectedIE = true
		} else if v, err := nas.RejectedNSSAIValue(rej); err == nil {
			ra.RejectedNSSAI = v
			rejectedIE = true
		}
		if !complete {
			h.logger.Warn("Rejected NSSAI truncated to the IE maximum",
				"procedure", "NSSAA", "supi", ue.SUPI, "max", nas.MaxRejectedSNSSAIs,
				"spec_ref", "TS 24.501 §9.11.3.46")
		}
	}
	// TS 24.501 V19.8.0 §5.5.1.2.4 d) / §9.11.3.6: when no S-NSSAI is allowed the
	// Allowed NSSAI IE is omitted (its minimum length is 4, Table 8.2.7.1.1) and,
	// with a pending NSSAI, the "NSSAA to be performed" indicator (octet 3, bit 5)
	// is set.
	if len(ue.AllowedNSSAI) == 0 {
		ra.AllowedNSSAI = nil
		if ra.PendingNSSAI != nil {
			ra.RegistrationResult |= regResultNSSAAToBePerformed
		}
	}
	if ra.PendingNSSAI != nil || rejectedIE {
		h.logger.Info("Registration Accept carries NSSAA NSSAIs",
			"procedure", "NSSAA", "supi", ue.SUPI,
			"pending_count", len(pending), "rejected_count", len(ue.RejectedNSSAI),
			"extended_rejected_nssai", ra.ExtendedRejectedNSSAI != nil,
			"interface", "N1", "direction", "OUT", "message_type", "RegistrationAccept",
			"spec_ref", "TS 24.501 §4.6.2.4")
	}
}

// UseExtendedRejectedNSSAI reports whether the rejected NSSAI of ue goes into the
// Extended rejected NSSAI IE (instead of the Rejected NSSAI IE): rel19 and a UE
// that set the ER-NSSAI bit in its 5GMM capability. rel17 (frozen) never does.
// Ref: TS 24.501 §5.5.1.2.4, §5.5.2.3.1, §5.4.4.2
func (h *RegistrationHandler) UseExtendedRejectedNSSAI(ue *amfctx.UEContext) bool {
	return h != nil && h.nssaaSpec && ue.ERNSSAISupported
}

// AccessType3GPP is the "3GPP access" value of the access type in the
// de-registration type IE (1 = 3GPP, 2 = non-3GPP, 3 = both): the NSSAA
// de-registration concerns the 3GPP access the slices were authorized for.
// Ref: TS 24.501 §9.11.3.20 Table 9.11.3.20.1
const AccessType3GPP uint8 = 1

// NSSAADeregRequest builds the DEREGISTRATION REQUEST (UE terminated) of a rel19
// NSSAA failure/revocation de-registration: 5GMM cause #62, de-registration type
// "re-registration not required", 3GPP access, spare half octet zero, and every
// failed/revoked slice (ue.RejectedNSSAI, cause 2, HPLMN SST/SD, at most
// nas.MaxRejectedSNSSAIs; callers log the truncation) in
//
//   - the Extended rejected NSSAI IE (0x68, no mapped S-NSSAI) when the UE
//     supports extended rejected NSSAI (erNSSAI), INSTEAD of
//   - the Rejected NSSAI IE (0x6D) otherwise
//
// ("if the UE supports extended rejected NSSAI, the AMF shall include the
// Extended rejected NSSAI IE ...; otherwise, the AMF shall include the Rejected
// NSSAI IE"). Pure: it is the single source of the bytes for the NAS layer and
// the godog steps. Ref: TS 24.501 §5.5.2.3.1 (V19.8.0), Table 8.2.14.1.1
func NSSAADeregRequest(ue *amfctx.UEContext, erNSSAI bool) *nas.DeregistrationRequestNW {
	rejected, _ := NASRejectedNSSAI(ue.RejectedNSSAI)
	req := &nas.DeregistrationRequestNW{
		Cause5GMM:          NSSAADeregCause5GMM,
		AccessType:         AccessType3GPP,
		SpareHalfOctetZero: true,
	}
	if erNSSAI {
		req.ExtendedRejectedNSSAI = nas.ExtendedRejectedNSSAIFromList(rejected)
	} else {
		req.RejectedNSSAI = rejected
	}
	return req
}

// NSSAAConfigUpdateCommand builds the CONFIGURATION UPDATE COMMAND (ACK
// requested) delivering the post-NSSAA NSSAIs. rel17 (frozen): the Allowed NSSAI
// only. rel19: the Allowed NSSAI (IE omitted when empty, an Allowed NSSAI IE
// carries at least one S-NSSAI) and the failed/revoked slices as rejected NSSAI
// with cause nas.RejectedCauseNSSAAFailedOrRevoked, HPLMN SST/SD, in the
// Extended rejected NSSAI IE when the UE supports it (erNSSAI) INSTEAD of the
// Rejected NSSAI IE ("shall be included in the Extended rejected NSSAI IE.
// Otherwise ... in the Rejected NSSAI IE"). truncated reports a Rejected NSSAI
// cut to nas.MaxRejectedSNSSAIs.
// Ref: TS 24.501 §5.4.4.2, §8.2.19, §9.11.3.46, §9.11.3.75
func (h *RegistrationHandler) NSSAAConfigUpdateCommand(ue *amfctx.UEContext, erNSSAI bool) (cmd *nas.ConfigurationUpdateCommand, truncated bool) {
	ackBit := byte(0xD1) // IEI 0xD high nibble, ACKS bit set - request ConfigurationUpdateComplete
	cmd = &nas.ConfigurationUpdateCommand{ConfigUpdateIndication: &ackBit}
	if !h.nssaaSpec {
		allowed := NASAllowedNSSAI(ue.AllowedNSSAI)
		cmd.AllowedNSSAI = &allowed
		return cmd, false
	}
	if len(ue.AllowedNSSAI) > 0 {
		allowed := NASAllowedNSSAI(ue.AllowedNSSAI)
		cmd.AllowedNSSAI = &allowed
	}
	rejected, complete := NASRejectedNSSAI(ue.RejectedNSSAI)
	if erNSSAI {
		cmd.ExtendedRejectedNSSAI = nas.ExtendedRejectedNSSAIFromList(rejected)
	} else {
		cmd.RejectedNSSAI = rejected
	}
	return cmd, !complete
}

// NASAllowedNSSAI converts a slice of subscribed S-NSSAIs to the NAS Allowed NSSAI
// IE form, for inclusion in a Configuration Update Command after NSSAA changes the
// Allowed NSSAI.
func NASAllowedNSSAI(subs []amfctx.SNSSAISubscribed) nas.NSSAI {
	return buildAllowedNSSAI(subs)
}

// ---- helpers ----

func toNASSNSSAI(s amfctx.SNSSAISubscribed) nas.SNSSAI {
	return nas.SNSSAI{SST: s.SST, SD: nas.SDFromString(s.SD)}
}

func sameSlice(a, b nas.SNSSAI) bool { return a.SST == b.SST && a.SD == b.SD }

func dropSlice(list []amfctx.SNSSAISubscribed, s amfctx.SNSSAISubscribed) []amfctx.SNSSAISubscribed {
	var out []amfctx.SNSSAISubscribed
	for _, e := range list {
		if e.SST == s.SST && e.SD == s.SD {
			continue
		}
		out = append(out, e)
	}
	return out
}

func appendAllowed(list []amfctx.SNSSAISubscribed, s amfctx.SNSSAISubscribed) []amfctx.SNSSAISubscribed {
	for _, e := range list {
		if e.SST == s.SST && e.SD == s.SD {
			return list
		}
	}
	return append(list, s)
}

// ReauthNSSAA re-queues an already-authorized slice for a fresh NSSAA round. The
// slice stays in Allowed NSSAI during re-auth (TS 23.502 §4.2.9.3); it is revoked
// only if the new round fails. Returns false if the slice is not currently allowed.
func (h *RegistrationHandler) ReauthNSSAA(ue *amfctx.UEContext, sst uint8, sd string) bool {
	for _, s := range ue.AllowedNSSAI {
		if s.SST == sst && s.SD == sd {
			ue.PendingNSSAA = appendAllowed(ue.PendingNSSAA, s)
			return true
		}
	}
	return false
}

func appendRejected(list []amfctx.SNSSAISubscribed, s amfctx.SNSSAISubscribed) []amfctx.SNSSAISubscribed {
	for _, e := range list {
		if e.SST == s.SST && e.SD == s.SD {
			return list
		}
	}
	return append(list, s)
}
