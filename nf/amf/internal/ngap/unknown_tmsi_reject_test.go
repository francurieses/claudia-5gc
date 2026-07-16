package ngap

// unknown_tmsi_reject_test.go — regression tests for the reject the AMF sends
// when an initial NAS message carries a 5G-S-TMSI it has no context for (the
// AMF restarted and purged its contexts, or the context was evicted).
//
// The live bug: every unknown TMSI got a SERVICE REJECT, including a UE doing a
// periodic registration update. That UE is in 5GMM-REGISTERED-INITIATED, where
// TS 24.501 §5.6.1.5.2 does not apply — it discarded the Service Reject
// ("Service Reject ignored since the MM state is not MM_SERVICE_REQUEST_INITIATED"),
// answered with an MM Status, and retried every T3512 forever without ever
// re-registering.
//
// Ref: TS 24.501 §5.5.1.3.5, §5.6.1.5.2, §9.11.3.2.

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestRejectForUnknownTMSI(t *testing.T) {
	tests := []struct {
		name      string
		msgType   nas.MessageType
		known     bool
		wantMT    nas.MessageType
		wantCause nas.Cause5GMM
		wantName  string
	}{
		{
			// The regression: a registration update must NOT get a Service Reject.
			// Cause #10 drives the UE to 5GMM-DEREGISTERED.NORMAL-SERVICE → fresh
			// initial registration with SUCI.
			name:      "RegistrationRequest → RegistrationReject #10",
			msgType:   nas.MsgTypeRegistrationRequest,
			known:     true,
			wantMT:    nas.MsgTypeRegistrationReject,
			wantCause: nas.CauseImplicitlyDeregistered,
			wantName:  "RegistrationReject",
		},
		{
			name:      "ServiceRequest → ServiceReject #9",
			msgType:   nas.MsgTypeServiceRequest,
			known:     true,
			wantMT:    nas.MsgTypeServiceReject,
			wantCause: nas.CauseUEIdentityNotDerived,
			wantName:  "ServiceReject",
		},
		{
			name:      "ControlPlaneServiceRequest → ServiceReject #9",
			msgType:   nas.MsgTypeControlPlaneServiceRequest,
			known:     true,
			wantMT:    nas.MsgTypeServiceReject,
			wantCause: nas.CauseUEIdentityNotDerived,
			wantName:  "ServiceReject",
		},
		{
			// Unreadable (ciphered inner header): fall back rather than guess
			// RegistrationReject at a UE that may be in a service request.
			name:      "unreadable type → ServiceReject #9",
			msgType:   0,
			known:     false,
			wantMT:    nas.MsgTypeServiceReject,
			wantCause: nas.CauseUEIdentityNotDerived,
			wantName:  "ServiceReject",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pdu, name, specRef := rejectForUnknownTMSI(tc.msgType, tc.known)
			if len(pdu) != 4 {
				t.Fatalf("reject PDU = % X, want 4 bytes (EPD|SHT|MT|cause)", pdu)
			}
			if pdu[0] != nas.PDMobilityManagement {
				t.Errorf("EPD = 0x%02X, want 0x%02X (5GMM)", pdu[0], nas.PDMobilityManagement)
			}
			// The reject is sent before any security context exists, so it must be
			// plain NAS. Ref: TS 24.501 §4.4.5.
			if nas.SecurityHeaderType(pdu[1]) != nas.SecurityHeaderPlainNAS {
				t.Errorf("SHT = 0x%02X, want plain (0x00)", pdu[1])
			}
			if nas.MessageType(pdu[2]) != tc.wantMT {
				t.Errorf("message type = 0x%02X, want 0x%02X", pdu[2], byte(tc.wantMT))
			}
			if nas.Cause5GMM(pdu[3]) != tc.wantCause {
				t.Errorf("5GMM cause = %d, want %d", pdu[3], tc.wantCause)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
			if specRef == "" {
				t.Error("spec_ref is empty — the log field is required by the project logging contract")
			}
		})
	}
}

// TestRejectForUnknownTMSI_DecodesAsRealNAS asserts the hand-built PDUs are
// wire-valid, not just the right bytes: a UE must be able to decode them.
func TestRejectForUnknownTMSI_DecodesAsRealNAS(t *testing.T) {
	for _, known := range []bool{true, false} {
		for _, mt := range []nas.MessageType{nas.MsgTypeRegistrationRequest, nas.MsgTypeServiceRequest} {
			pdu, name, _ := rejectForUnknownTMSI(mt, known)
			msg, err := nas.Decode(pdu)
			if err != nil {
				t.Fatalf("%s: reject PDU does not decode: %v (% X)", name, err, pdu)
			}
			if msg.Header.ExtendedProtocolDiscriminator != nas.PDMobilityManagement {
				t.Errorf("%s: decoded EPD = 0x%02X", name, msg.Header.ExtendedProtocolDiscriminator)
			}
		}
	}
}

func TestNASMessageTypeName(t *testing.T) {
	if got := nasMessageTypeName(0, false); got != "UNREADABLE" {
		t.Errorf("unknown type name = %q, want UNREADABLE", got)
	}
	if got := nasMessageTypeName(nas.MsgTypeRegistrationRequest, true); got != "RegistrationRequest" {
		t.Errorf("name = %q, want RegistrationRequest", got)
	}
	// An unexpected initial message must still be diagnosable by value.
	if got := nasMessageTypeName(nas.MessageType(0x99), true); got != "0x99" {
		t.Errorf("name = %q, want 0x99", got)
	}
}
