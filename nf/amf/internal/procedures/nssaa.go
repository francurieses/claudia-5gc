package procedures

import (
	"context"
	"fmt"

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

// NSSAAAuthResult is the outcome of one Nausf_NSSAA_Authenticate call.
type NSSAAAuthResult struct {
	AuthResult string
	EAPPayload []byte // terminal EAP packet (Success/Failure) to forward to the UE
}

// NSSAAClient relays the UE's EAP-Response to the AAA-S via the AUSF.
type NSSAAClient interface {
	Authenticate(ctx context.Context, supi, gpsi string, sst uint8, sd string, eapPayload []byte) (*NSSAAAuthResult, error)
}

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
	var allowed []amfctx.SNSSAISubscribed
	for _, s := range ue.AllowedNSSAI {
		if s.SubjectToNSSAA {
			ue.PendingNSSAA = append(ue.PendingNSSAA, s)
			continue
		}
		allowed = append(allowed, s)
	}
	if len(ue.PendingNSSAA) > 0 {
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

	// Relay the EAP-Response to the AAA-S via AUSF. Treat an unreachable AAA-S as a
	// failure so the slice is rejected rather than left dangling.
	authorized := false
	var eapResult []byte
	res, err := h.nssaa.Authenticate(ctx, ue.SUPI, ue.SUPI, slice.SST, slice.SD, complete.EAPMessage)
	if err != nil {
		h.logger.Warn("NSSAA AAA relay failed — slice rejected",
			"procedure", "NSSAA", "supi", ue.SUPI,
			"sst", slice.SST, "sd", slice.SD, "error", err,
			"spec_ref", "TS 23.502 §4.2.9.2")
		eapResult = eap.BuildFailure(ue.NSSAAEAPID)
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
		metrics.ProcedureTotal.WithLabelValues(nfName, "NSSAA", "OK").Inc()
		h.logger.Info("NSSAA succeeded — slice added to Allowed NSSAI",
			"procedure", "NSSAA", "supi", ue.SUPI,
			"sst", slice.SST, "sd", slice.SD, "result", "OK",
			"spec_ref", "TS 23.502 §4.2.9.2")
	} else {
		ue.RejectedNSSAI = appendRejected(ue.RejectedNSSAI, slice)
		metrics.ProcedureTotal.WithLabelValues(nfName, "NSSAA", "REJECT").Inc()
		h.logger.Info("NSSAA failed — slice rejected (cause #3)",
			"procedure", "NSSAA", "supi", ue.SUPI,
			"sst", slice.SST, "sd", slice.SD, "result", "REJECT",
			"cause", "3", "spec_ref", "TS 24.501 §9.11.3.46")
	}

	// Advance the queue: drop the resolved slice, start the next one if any.
	ue.NSSAAInProgress = nil
	ue.PendingNSSAA = dropSlice(ue.PendingNSSAA, slice)
	if len(ue.PendingNSSAA) > 0 {
		out.NextCommand = h.beginSlice(ue, ue.PendingNSSAA[0])
	}
	return out, nil
}

// RevokeNSSAA handles an AAA-initiated revocation (TS 23.502 §4.2.9.4): removes the
// slice from Allowed NSSAI and records it in Rejected NSSAI (cause #3). Returns true
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
		"sst", sst, "sd", sd, "cause", "3",
		"spec_ref", "TS 23.502 §4.2.9.4")
	return true
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
