package procedures

// reject.go - typed terminal outcomes of the registration phases. A phase that
// cannot continue returns an *ErrRejectCause (or wraps ErrAuthenticationRejected);
// the NAS layer maps it to one REGISTRATION REJECT / AUTHENTICATION REJECT in a
// single place (nas.Handler.HandleNASMessage).
//
// Ref: TS 24.501 §5.5.1.2.5, §5.5.1.2.8 b), §5.4.1.3.5

import (
	"errors"
	"time"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

const (
	// NFUnavailableRejectCause is the 5GMM cause sent when a producer NF the
	// registration depends on (AUSF initiation, UDM subscription data, ...) fails:
	// #22 "Congestion", the network cannot serve the request now. Ref: TS 24.501
	// §5.5.1.2.5, Annex A.2 [VERIFY: cause choice for a producer-NF outage]
	NFUnavailableRejectCause = nas.CauseCongestion

	// CongestionBackoffT3346 is the T3346 back-off value sent with REGISTRATION REJECT
	// #22 "Congestion": the UE must not retry a registration before it expires.
	// The value is a project choice (operator policy, not fixed by the TS): 2 minutes
	// is long enough for a failed producer NF (AUSF/UDM) to recover or be replaced
	// and short enough not to strand a UE. Encodes exactly as GPRS timer 2 (2 x 1 min).
	// Ref: TS 24.501 §5.5.1.2.5 (cause #22), §9.11.2.4
	CongestionBackoffT3346 = 2 * time.Minute

	// ProtocolErrorRejectCause is #111 "Protocol error, unspecified", used for a
	// REGISTRATION REQUEST whose body is not a valid registration request.
	// Ref: TS 24.501 §5.5.1.2.8 b)
	ProtocolErrorRejectCause = nas.CauseUnspecified
)

// ErrAuthenticationRejected marks an AUSF answer that rejects the UE's RES*
// (authentication failed, as opposed to the AUSF being unreachable). The NAS
// layer answers AUTHENTICATION REJECT for a SUCI-based challenge and starts the
// identification procedure for a 5G-GUTI-based one.
// Ref: TS 24.501 §5.4.1.3.5
var ErrAuthenticationRejected = errors.New("amf: authentication rejected by the AUSF")

// ErrRejectCause is a terminal registration failure the UE is told about with a
// REGISTRATION REJECT carrying Cause. Err is the underlying error (for logs).
// Ref: TS 24.501 §5.5.1.2.5
type ErrRejectCause struct {
	// Cause is the 5GMM cause of the REGISTRATION REJECT.
	Cause nas.Cause5GMM
	// SpecRef is the spec clause justifying the cause (logged).
	SpecRef string
	// Err is the underlying failure; may be nil.
	Err error
}

// Error implements error.
func (e *ErrRejectCause) Error() string {
	if e.Err == nil {
		return "amf: registration rejected"
	}
	return "amf: registration rejected: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ErrRejectCause) Unwrap() error { return e.Err }
