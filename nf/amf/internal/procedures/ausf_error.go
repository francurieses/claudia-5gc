package procedures

// ausf_error.go - typed Nausf failure (HTTP status + ProblemDetails cause) and
// the roaming-path mapping of such a failure to a 5GMM REGISTRATION REJECT
// cause (ROAM-001). The local (non-roaming) path keeps its historic mapping:
// every AUSF failure is NFUnavailableRejectCause (#22); only a roaming UE
// (home AUSF reached through the SEPP) gets the finer mapping below.
//
// Ref: TS 29.509 §5.2.2.2 / Table 6.1.7.3-1, TS 29.500 §5.2.7,
// TS 24.501 §5.5.1.2.5

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// AUSFCauseServingNetworkNotAuthorized is the 403 ProblemDetails.cause of an
// AUSF that does not authorize the serving network name for the UE's home
// network. Ref: TS 29.509 Table 6.1.7.3-1; TS 33.501 §6.1.2
const AUSFCauseServingNetworkNotAuthorized = "SERVING_NETWORK_NOT_AUTHORIZED"

// AUSFError is a non-2xx answer of the AUSF (or of the SEPP in front of it).
type AUSFError struct {
	// Op names the Nausf operation, e.g. "initiate auth".
	Op string
	// Status is the HTTP status of the answer (> 0).
	Status int
	// Cause is ProblemDetails.cause, "" when the body carried none.
	Cause string
}

// Error implements error. The text equals the pre-ROAM-001 untyped error
// ("ausf: <op>: status N cause=<cause>", "<nil>" for an absent cause).
func (e *AUSFError) Error() string {
	c := e.Cause
	if c == "" {
		c = "<nil>"
	}
	return fmt.Sprintf("ausf: %s: status %d cause=%s", e.Op, e.Status, c)
}

// RejectCauseForRoamingAUSFError maps a failed Nausf exchange of a roaming UE:
//
//	403 SERVING_NETWORK_NOT_AUTHORIZED -> #73 Serving network not authorized
//	                                      (TS 24.501 §5.5.1.2.5 NOTE 3)
//	anything else (SEPP 504, 5xx, transport error, timeout)
//	                                   -> #22 Congestion with T3346
//	                                      (NFUnavailableRejectCause)
//
// Ref: TS 29.509 Table 6.1.7.3-1; TS 24.501 §5.5.1.2.5
func RejectCauseForRoamingAUSFError(err error) (nas.Cause5GMM, string) {
	const specRef = "TS 24.501 §5.5.1.2.5; TS 29.509 §5.2.2.2"
	var ae *AUSFError
	if errors.As(err, &ae) && ae.Status == http.StatusForbidden &&
		ae.Cause == AUSFCauseServingNetworkNotAuthorized {
		return nas.CauseServingNetworkNotAuthorized, specRef
	}
	return NFUnavailableRejectCause, specRef
}
