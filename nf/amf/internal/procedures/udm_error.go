package procedures

// udm_error.go - typed Nudm failure carrying the HTTP status and the
// ProblemDetails cause, and the documented mapping of such a failure to a
// 5GMM REGISTRATION REJECT cause (AUD-registration-17).
//
// Ref: TS 29.503 §5.3.2.2 / §6.2.7.3 (Nudm_UECM errors), TS 29.500 §5.2.7
// (ProblemDetails), TS 24.501 §5.5.1.2.5

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// UDM ProblemDetails.cause values the registration mapping reacts to.
// Ref: TS 29.503 Table 6.2.7.3-1 (UECM), Table 6.1.7.3-1 (SDM).
const (
	// UDMCauseRoamingNotAllowed - 403, the subscriber may not roam here.
	UDMCauseRoamingNotAllowed = "ROAMING_NOT_ALLOWED"
	// UDMCauseUserNotFound - 404, no such subscriber.
	UDMCauseUserNotFound = "USER_NOT_FOUND"
	// UDMCauseDataNotFound - 404, subscriber without the requested data.
	UDMCauseDataNotFound = "DATA_NOT_FOUND"
)

// UDMError is a failed Nudm exchange: a non-2xx answer (Status > 0, Cause from
// the ProblemDetails body when present) or a transport failure (Status == 0,
// Err set).
type UDMError struct {
	// Op names the Nudm operation, e.g. "uecm register".
	Op string
	// Status is the HTTP status of the answer; 0 for a transport error/timeout.
	Status int
	// Cause is ProblemDetails.cause, "" when the body carried none.
	Cause string
	// Detail is ProblemDetails.detail (logging only).
	Detail string
	// Err is the transport error, nil for an HTTP error answer.
	Err error
}

// Error implements error.
func (e *UDMError) Error() string {
	switch {
	case e.Status != 0:
		return fmt.Sprintf("udm: %s: status %d cause %q", e.Op, e.Status, e.Cause)
	case e.Err != nil:
		return fmt.Sprintf("udm: %s: %v", e.Op, e.Err)
	}
	return "udm: " + e.Op + ": failed"
}

// Unwrap returns the transport error.
func (e *UDMError) Unwrap() error { return e.Err }

// RejectCauseForUDMError maps a failed Nudm_UECM_Registration to the 5GMM cause
// of the REGISTRATION REJECT and the clause justifying it. The mapping:
//
//	403 ROAMING_NOT_ALLOWED         -> #11 PLMN not allowed (TS 24.501 §5.5.1.2.5:
//	                                   the subscription does not allow this PLMN)
//	403 (any other cause), 404      -> #7  5GS services not allowed (no usable
//	                                   5GS subscription for this UE; #3 would
//	                                   invalidate the USIM until power cycle,
//	                                   too harsh for a provisioning gap)
//	5xx, 429, other status, transport error, timeout, unreachable
//	                                -> #22 Congestion with T3346
//	                                   (NFUnavailableRejectCause, retry later)
//
// Ref: TS 24.501 §5.5.1.2.5, Annex A; TS 29.503 §5.3.2.2.2 (errors)
func RejectCauseForUDMError(err error) (nas.Cause5GMM, string) {
	const specRef = "TS 24.501 §5.5.1.2.5; TS 29.503 §5.3.2.2.2"
	var ue *UDMError
	if errors.As(err, &ue) {
		switch {
		case ue.Status == http.StatusForbidden && ue.Cause == UDMCauseRoamingNotAllowed:
			return nas.CausePLMNNotAllowed, specRef
		case ue.Status == http.StatusForbidden, ue.Status == http.StatusNotFound:
			return nas.Cause5GSServicesNotAllowed, specRef
		}
	}
	return NFUnavailableRejectCause, specRef
}
