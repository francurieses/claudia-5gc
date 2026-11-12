package nasmsg

import (
	"context"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// sarUE returns a registered UE in TA 0x000000 under a NOT_ALLOWED_AREAS
// restriction that excludes that TA (TS 23.501 §3.1 Non-Allowed Area).
func sarUE(t *testing.T) (*Handler, *amfctx.UEContext, *regAudSender) {
	t.Helper()
	h, _, _, ue, s := newRegAudHandler(t, nil, regAudUDM{})
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	ue.ServAreaRes = &amfctx.ServiceAreaRestriction{
		RestrictionType: "NOT_ALLOWED_AREAS", NotAllowedTACs: []string{"000000"}}
	return h, ue, s
}

// srBody: service type nibble | ngKSI, then a 5G-S-TMSI LV (TS 24.501 §8.2.16).
func srBody(serviceType byte) []byte {
	return []byte{serviceType<<4 | 0x01, 0x00, 0x07, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x01}
}

// TestServiceRequestNonAllowedAreaRejected28: signalling / data Service Request
// in a Non-Allowed Area -> SERVICE REJECT #28, actually sent, ciphered, no ICS.
func TestServiceRequestNonAllowedAreaRejected28(t *testing.T) {
	for _, st := range []byte{nas.ServiceTypeSignalling, nas.ServiceTypeData} {
		h, ue, s := sarUE(t)
		dlCount := ue.SecurityCtx.DownlinkCount
		if err := h.HandleNASMessage(context.Background(), ue,
			buildULSecuredPDU(t, ue, nas.MsgTypeServiceRequest, srBody(st))); err != nil {
			t.Fatalf("service type %d: %v", st, err)
		}
		if len(s.ics) != 0 || len(s.dl) != 1 {
			t.Fatalf("service type %d: ics=%d dl=%d; want one SERVICE REJECT and no ICS", st, len(s.ics), len(s.dl))
		}
		if s.dl[0][1] != byte(nas.SecurityHeaderIntegrityProtectedAndCiphered) {
			t.Fatalf("SERVICE REJECT SHT=%02x; want integrity protected and ciphered", s.dl[0][1])
		}
		if ue.SecurityCtx.DownlinkCount != dlCount+1 {
			t.Fatalf("DL COUNT %d -> %d; want exactly one protected message", dlCount, ue.SecurityCtx.DownlinkCount)
		}
		in := decipherDLPDU(t, ue, dlCount, s.dl[0])
		if in[2] != byte(nas.MsgTypeServiceReject) || in[3] != 28 {
			t.Fatalf("inner=%x; want SERVICE REJECT #28", in)
		}
		if ue.State != amfctx.GMMRegistered {
			t.Fatalf("state %v; UE must stay 5GMM-REGISTERED", ue.State)
		}
	}
}

// TestServiceRequestNonAllowedAreaExemptions: mobile terminated, emergency,
// emergency fallback and elevated signalling continue normally (TS 24.501 §5.6.1.5).
func TestServiceRequestNonAllowedAreaExemptions(t *testing.T) {
	for _, st := range []byte{nas.ServiceTypeMobileTerminated, nas.ServiceTypeEmergencyServices,
		nas.ServiceTypeEmergencyServicesFallback, nas.ServiceTypeElevatedSignalling} {
		h, ue, s := sarUE(t)
		if err := h.HandleNASMessage(context.Background(), ue,
			buildULSecuredPDU(t, ue, nas.MsgTypeServiceRequest, srBody(st))); err != nil {
			t.Fatalf("service type %d: %v", st, err)
		}
		if len(s.ics) != 1 {
			t.Fatalf("service type %d: ics=%d; want the Service Accept in an ICS", st, len(s.ics))
		}
	}
}

// TestServiceRequestAllowedAreaAccepted: no restriction effect inside the allowed area.
func TestServiceRequestAllowedAreaAccepted(t *testing.T) {
	h, ue, s := sarUE(t)
	ue.ServAreaRes.NotAllowedTACs = []string{"000009"}
	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeServiceRequest, srBody(nas.ServiceTypeData))); err != nil {
		t.Fatal(err)
	}
	if len(s.ics) != 1 {
		t.Fatalf("ics=%d; want 1", len(s.ics))
	}
}

func ulSM(t *testing.T, msgType byte, requestType *uint8) []byte {
	t.Helper()
	psi := uint8(5)
	body, err := nas.EncodeULNASTransport(&nas.ULNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     []byte{0x2e, 0x05, 0x01, msgType, 0xff, 0xff},
		PDUSessionID:         &psi,
		RequestType:          requestType,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestULNASTransportNonAllowedArea28: PDU session establishment / modification
// is not forwarded; DL NAS TRANSPORT carries the 5GSM payload and 5GMM cause #28
// (TS 24.501 §5.4.5.2.5 item 15); emergency request types are exempt.
func TestULNASTransportNonAllowedArea28(t *testing.T) {
	initial, existing, modification, maPDU, emergency := uint8(0x01), uint8(0x02), uint8(0x05), uint8(0x06), uint8(0x03)
	for _, tc := range []struct {
		name    string
		msgType byte
		rt      *uint8
	}{
		{"establishment", byte(nas.MsgTypePDUSessionEstablishmentRequest), &initial},
		{"establishment existing PDU session", byte(nas.MsgTypePDUSessionEstablishmentRequest), &existing},
		{"establishment MA PDU request", byte(nas.MsgTypePDUSessionEstablishmentRequest), &maPDU},
		{"modification request", byte(nas.MsgTypePDUSessionModificationRequest), &modification},
	} {
		h, ue, s := sarUE(t)
		dlCount := ue.SecurityCtx.DownlinkCount
		if err := h.HandleNASMessage(context.Background(), ue,
			buildULSecuredPDU(t, ue, nas.MsgTypeULNASTransport, ulSM(t, tc.msgType, tc.rt))); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(s.dl) != 1 {
			t.Fatalf("%s: dl=%d; want one DL NAS TRANSPORT", tc.name, len(s.dl))
		}
		in := decipherDLPDU(t, ue, dlCount, s.dl[0])
		if in[2] != byte(nas.MsgTypeDLNASTransport) || in[3] != nas.PayloadContainerTypeN1SM {
			t.Fatalf("%s: inner=%x; want DL NAS TRANSPORT / N1 SM", tc.name, in)
		}
		// payload container (LV-E), PDU session ID 0x12 05, 5GMM cause 0x58 1c
		want := []byte{0x2e, 0x05, 0x01, tc.msgType, 0xff, 0xff, 0x12, 0x05, 0x58, 28}
		if got := in[6:]; string(got) != string(want) {
			t.Fatalf("%s: tail=%x want %x", tc.name, got, want)
		}
	}
	// Emergency request type: not restricted -> not answered with #28.
	h, ue, s := sarUE(t)
	_ = h.HandleNASMessage(context.Background(), ue, buildULSecuredPDU(t, ue, nas.MsgTypeULNASTransport,
		ulSM(t, byte(nas.MsgTypePDUSessionEstablishmentRequest), &emergency)))
	for _, d := range s.dl {
		if in := decipherDLPDU(t, ue, 0, d); len(in) > 3 && in[2] == byte(nas.MsgTypeDLNASTransport) {
			t.Fatalf("emergency request answered with a DL NAS TRANSPORT %x", in)
		}
	}
}

// TestInNonAllowedArea covers the single decision point including "allowed
// nowhere" (ALLOWED_AREAS with a non-nil empty list, TS 29.571 §5.4.4.18).
func TestInNonAllowedArea(t *testing.T) {
	ue := &amfctx.UEContext{}
	ue.TAI.TAC = 1
	for _, tc := range []struct {
		name string
		sar  *amfctx.ServiceAreaRestriction
		want bool
	}{
		{"no SAR", nil, false},
		{"allowed list contains TA", &amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS", AllowedTACs: []string{"000001"}}, false},
		{"allowed list excludes TA", &amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS", AllowedTACs: []string{"000002"}}, true},
		{"allowed absent list", &amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS"}, false},
		{"allowed empty list = nowhere", &amfctx.ServiceAreaRestriction{RestrictionType: "ALLOWED_AREAS", AllowedTACs: []string{}}, true},
		{"not allowed contains TA", &amfctx.ServiceAreaRestriction{RestrictionType: "NOT_ALLOWED_AREAS", NotAllowedTACs: []string{"000001"}}, true},
		{"not allowed excludes TA", &amfctx.ServiceAreaRestriction{RestrictionType: "NOT_ALLOWED_AREAS", NotAllowedTACs: []string{"000002"}}, false},
	} {
		ue.ServAreaRes = tc.sar
		if got := ue.InNonAllowedArea(); got != tc.want {
			t.Errorf("%s: InNonAllowedArea=%v want %v", tc.name, got, tc.want)
		}
	}
}

// TestRequestTypeExemptFromSAR: TS 24.501 §5.4.5.2.5 item 15 restricts only an
// present Request type of initial / existing PDU session / modification / MA PDU
// request; an absent IE and all other values are forwarded (§9.11.3.47).
func TestRequestTypeExemptFromSAR(t *testing.T) {
	v := func(x uint8) *uint8 { return &x }
	for _, tc := range []struct {
		name   string
		rt     *uint8
		exempt bool
	}{
		{"absent", nil, true},
		{"initial request", v(1), false},
		{"existing PDU session", v(2), false},
		{"initial emergency", v(3), true},
		{"existing emergency", v(4), true},
		{"modification request", v(5), false},
		{"MA PDU request", v(6), false},
	} {
		if got := requestTypeExemptFromSAR(tc.rt); got != tc.exempt {
			t.Errorf("%s: exempt=%v want %v", tc.name, got, tc.exempt)
		}
	}
}

// TestRegistrationNonAllowedAreaReactivationResult: in a Non-Allowed Area the
// user plane is not re-activated for the Uplink data status PSIs, yet the
// REGISTRATION ACCEPT reports them as not re-established: their bits are set in
// the PDU session reactivation result IE (0x26) and the error cause IE (0x72)
// carries #28 for each (TS 24.501 §5.5.1.3.4, §9.11.3.42, §9.11.3.43).
func TestRegistrationNonAllowedAreaReactivationResult(t *testing.T) {
	h, ue, _ := sarUE(t)
	// Uplink data status: PSI 1 (octet 1 bit 2) and PSI 5 (bit 6).
	req := &nas.RegistrationRequest{UplinkDataStatus: []byte{0x22, 0x00}}
	sync := h.syncPDUSessions(context.Background(), ue, req, h.logger)
	if len(sync.Items) != 0 {
		t.Fatalf("items=%d; UP must not be re-activated in a Non-Allowed Area", len(sync.Items))
	}
	var acc nas.RegistrationAccept
	sync.applyTo(&acc)
	if string(acc.PDUSessionReactivationResult) != string(nas.NewPDUSessionReactivationResult(1, 5)) {
		t.Fatalf("0x26 value=%x; want bits of PSI 1 and 5 set", acc.PDUSessionReactivationResult)
	}
	want := []nas.PDUSessionErrorCause{{PDUSessionID: 1, Cause5GMM: 28}, {PDUSessionID: 5, Cause5GMM: 28}}
	if len(acc.PDUSessionReactivationResultErrorCause) != 2 ||
		acc.PDUSessionReactivationResultErrorCause[0] != want[0] ||
		acc.PDUSessionReactivationResultErrorCause[1] != want[1] {
		t.Fatalf("0x72=%v; want %v", acc.PDUSessionReactivationResultErrorCause, want)
	}
	// Inside the allowed area nothing is flagged.
	ue.ServAreaRes.NotAllowedTACs = []string{"000009"}
	sync = h.syncPDUSessions(context.Background(), ue, req, h.logger)
	if len(sync.ErrorCauses) != 0 {
		t.Fatalf("error causes %v outside a Non-Allowed Area", sync.ErrorCauses)
	}
}
