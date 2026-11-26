package nasmsg

import "fmt"

// SMContextCreateError is the typed form of an Nsmf_PDUSession_CreateSMContext
// failure answer (SmContextCreateError) that carries an N1 SM message, i.e. the
// PDU SESSION ESTABLISHMENT REJECT the AMF must relay to the UE. Answers
// without an N1 SM message stay plain errors.
// Ref: TS 29.502 §5.2.2.2.1, §6.1.6.2.4; TS 23.502 §4.3.2.2.2 step 3b/16;
// TS 24.501 §6.4.1.4.
type SMContextCreateError struct {
	// Status is the HTTP status of the SmContextCreateError answer.
	Status int
	// Cause is the ProblemDetails cause (application error), may be empty.
	Cause string
	// Detail is the ProblemDetails detail, may be empty.
	Detail string
	// N1SmMsg is the complete 5GSM message (EPD | PSI | PTI | MT | ...).
	N1SmMsg []byte
}

// Error implements error.
func (e *SMContextCreateError) Error() string {
	return fmt.Sprintf("smf: status %d cause %q (n1 sm reject, %d bytes)", e.Status, e.Cause, len(e.N1SmMsg))
}

// Cause5GSM returns the 5GSM cause octet of the carried PDU SESSION
// ESTABLISHMENT REJECT (TS 24.501 §8.3.9), or 0 when the message is too short.
func (e *SMContextCreateError) Cause5GSM() uint8 {
	if len(e.N1SmMsg) > 4 {
		return e.N1SmMsg[4]
	}
	return 0
}
