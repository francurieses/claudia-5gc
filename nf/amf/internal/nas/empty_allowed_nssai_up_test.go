package nasmsg

// empty_allowed_nssai_up_test.go — AMF-042: with an empty Allowed NSSAI no user
// plane is re-activated (no Nsmf activation, no PDU SESSION RESOURCE SETUP
// REQUEST) because the answer goes out without ICS. The Uplink data status
// PSIs are reported not re-established in the reactivation result IE.
// Ref: TS 24.501 §5.5.1.3.4, §5.6.1.4.1; TS 38.413 §8.2.1; TS 23.502 §4.2.3.2 step 12

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// upSender counts Nsmf activations and PDU SESSION RESOURCE SETUP REQUESTs on
// top of regAudSender.
type upSender struct {
	regAudSender
	activations []string
	setups      []uint8
}

func (u *upSender) ActivateSMContext(_ context.Context, ref string) ([]byte, error) {
	u.activations = append(u.activations, ref)
	return []byte{0xAA}, nil
}

func (u *upSender) SendPDUSessionResourceSetupRequest(_ *amfctx.UEContext, psi uint8, _ []byte, _ []byte) error {
	u.setups = append(u.setups, psi)
	return nil
}

// upHandler is newRegAudHandler with the upSender swapped in and PDU sessions
// 1 and 2 established.
func upHandler(t *testing.T) (*Handler, *amfctx.UEContext, *upSender) {
	t.Helper()
	h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
	s := &upSender{}
	h.sender = s
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.PDUSessions[1] = &amfctx.PDUSession{PDUSessionID: 1, SMFInstanceID: "sm-ctx-1"}
	ue.PDUSessions[2] = &amfctx.PDUSession{PDUSessionID: 2, SMFInstanceID: "sm-ctx-2"}
	return h, ue, s
}

// updateWithULDS is a mobility registration update (GUTI) carrying an Uplink
// data status IE (0x40) with the given PSIs.
func updateWithULDS(t *testing.T, psis ...uint8) []byte {
	t.Helper()
	body := regReqWithCap(t, 2, "")[3:]
	body[0] = 0x12
	m := nas.PSIMask(psis...)
	return append(body, nas.IEIUplinkDataStatus, 0x02, byte(m>>8), byte(m))
}

// sentRegistrationAccept returns the decoded REGISTRATION ACCEPT of the single
// DL NAS TRANSPORT sent and its plain bytes (the decoder does not expose IE
// 0x26, so callers check it as the trailing TLV).
func sentRegistrationAccept(t *testing.T, ue *amfctx.UEContext, dlCount uint32, s *upSender) (*nas.RegistrationAccept, []byte) {
	t.Helper()
	if len(s.dl) != 1 {
		t.Fatalf("dl=%d; want one REGISTRATION ACCEPT in DL NAS TRANSPORT", len(s.dl))
	}
	in := decipherDLPDU(t, ue, dlCount, s.dl[0])
	if in[2] != byte(nas.MsgTypeRegistrationAccept) {
		t.Fatalf("inner=%x; want REGISTRATION ACCEPT", in)
	}
	acc, err := nas.DecodeRegistrationAccept(in[3:])
	if err != nil {
		t.Fatalf("decode accept: %v", err)
	}
	return acc, in
}

// TestRegistrationUpdateEmptyAllowedNSSAINoUserPlane: CM-IDLE update (new N2
// connection), empty Allowed NSSAI, ULDS PSIs 1 and 2 -> nothing activated, the
// Accept reports both PSIs not re-established, no error cause IE.
func TestRegistrationUpdateEmptyAllowedNSSAINoUserPlane(t *testing.T) {
	h, ue, s := upHandler(t)
	ue.NASOnNewN2Connection = true
	ue.AllowedNSSAI = nil
	dlCount := ue.SecurityCtx.DownlinkCount

	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, updateWithULDS(t, 1, 2))); err != nil {
		t.Fatal(err)
	}
	if len(s.activations) != 0 || len(s.setups) != 0 || len(s.ics) != 0 {
		t.Fatalf("activations=%v setups=%v ics=%d; want none", s.activations, s.setups, len(s.ics))
	}
	acc, in := sentRegistrationAccept(t, ue, dlCount, s)
	// IE 0x26 is the last IE when the error cause IE 0x72 is absent.
	if want := append([]byte{nas.IEIPDUSessionReactivationResult, 0x02}, nas.NewPDUSessionReactivationResult(1, 2)...); !bytes.HasSuffix(in, want) {
		t.Fatalf("accept=%x; want trailing IE %x (PSI 1 and 2 set)", in, want)
	}
	if len(acc.PDUSessionReactivationResultErrorCause) != 0 {
		t.Fatalf("0x72=%v; want absent", acc.PDUSessionReactivationResultErrorCause)
	}
}

// TestRegistrationUpdateEmptyAllowedNSSAIDrainsPaged: CM-IDLE update on a new N2
// connection, empty Allowed NSSAI, paged PSI 1, no ULDS -> no activation, no PDU
// SESSION RESOURCE SETUP REQUEST, paged set drained.
func TestRegistrationUpdateEmptyAllowedNSSAIDrainsPaged(t *testing.T) {
	h, ue, s := upHandler(t)
	var logs bytes.Buffer
	h.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	ue.NASOnNewN2Connection = true
	ue.AllowedNSSAI = nil
	ue.AddPagedPDUSession(1)
	body := regReqWithCap(t, 2, "")[3:] // update (GUTI), no Uplink data status IE
	body[0] = 0x12

	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, body)); err != nil {
		t.Fatal(err)
	}
	if len(s.activations) != 0 || len(s.setups) != 0 || len(s.ics) != 0 {
		t.Fatalf("activations=%v setups=%v ics=%d; want none", s.activations, s.setups, len(s.ics))
	}
	if left := ue.PagedPDUSessions(); len(left) != 0 {
		t.Fatalf("paged set after update = %v; want empty", left)
	}
	if got := pagedDropLog(t, &logs); fmt.Sprint(got) != "[1]" {
		t.Fatalf("paged_pdu_sessions=%v; want [1]", got)
	}
}

// TestRegistrationUpdateConnectedActivatesUserPlane: regression, CM-CONNECTED
// update (existing N2 connection) with a non-empty Allowed NSSAI and ULDS PSI 1
// -> PSI 1 activated, one PDU SESSION RESOURCE SETUP REQUEST, result bit clear.
func TestRegistrationUpdateConnectedActivatesUserPlane(t *testing.T) {
	h, ue, s := upHandler(t)
	ue.NASOnNewN2Connection = false
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	dlCount := ue.SecurityCtx.DownlinkCount

	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, updateWithULDS(t, 1))); err != nil {
		t.Fatal(err)
	}
	if len(s.activations) != 1 || s.activations[0] != "sm-ctx-1" {
		t.Fatalf("activations=%v; want [sm-ctx-1]", s.activations)
	}
	if len(s.setups) != 1 || s.setups[0] != 1 {
		t.Fatalf("setups=%v; want [1]", s.setups)
	}
	acc, in := sentRegistrationAccept(t, ue, dlCount, s)
	if want := append([]byte{nas.IEIPDUSessionReactivationResult, 0x02}, nas.NewPDUSessionReactivationResult()...); !bytes.HasSuffix(in, want) {
		t.Fatalf("accept=%x; want trailing IE %x (no bit set)", in, want)
	}
	if len(acc.PDUSessionReactivationResultErrorCause) != 0 {
		t.Fatalf("0x72=%v; want absent", acc.PDUSessionReactivationResultErrorCause)
	}
}

// TestServiceRequestEmptyAllowedNSSAIDrainsPaged: SR with an empty Allowed NSSAI
// and paged PSIs 1,2 -> paged set drained, no activation, no ICS; paged-only PSIs
// are not in the result IE, an ULDS PSI is.
func TestServiceRequestEmptyAllowedNSSAIDrainsPaged(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		wantResult *uint16 // nil: IE absent
	}{
		{"no ULDS", srBodyULDS(nil), nil},
		{"ULDS PSI 1", srBodyULDS(u16(nas.PSIMask(1))), u16(nas.PSIMask(1))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, ue, s := upHandler(t)
			var logs bytes.Buffer
			h.logger = slog.New(slog.NewJSONHandler(&logs, nil))
			ue.NASOnNewN2Connection = true
			ue.AllowedNSSAI = nil
			ue.AddPagedPDUSession(1)
			ue.AddPagedPDUSession(2)
			dlCount := ue.SecurityCtx.DownlinkCount

			if err := h.HandleNASMessage(context.Background(), ue,
				buildULSecuredPDU(t, ue, nas.MsgTypeServiceRequest, tc.body)); err != nil {
				t.Fatal(err)
			}
			if left := ue.PagedPDUSessions(); len(left) != 0 {
				t.Fatalf("paged set after SR = %v; want empty", left)
			}
			if len(s.activations) != 0 || len(s.setups) != 0 || len(s.ics) != 0 || len(s.dl) != 1 {
				t.Fatalf("activations=%v setups=%v ics=%d dl=%d; want none/none/0/1",
					s.activations, s.setups, len(s.ics), len(s.dl))
			}
			if got := pagedDropLog(t, &logs); fmt.Sprint(got) != "[1 2]" {
				t.Fatalf("paged-drop warning paged_pdu_sessions=%v; want [1 2]", got)
			}
			in := decipherDLPDU(t, ue, dlCount, s.dl[0])
			if in[2] != byte(nas.MsgTypeServiceAccept) {
				t.Fatalf("inner=%x; want SERVICE ACCEPT", in)
			}
			acc, err := nas.DecodeServiceAccept(in[3:])
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.wantResult == nil && acc.PDUSessionReactivationResult != nil:
				t.Fatalf("0x26=%04x; want absent", *acc.PDUSessionReactivationResult)
			case tc.wantResult != nil && (acc.PDUSessionReactivationResult == nil ||
				*acc.PDUSessionReactivationResult != *tc.wantResult):
				t.Fatalf("0x26=%v; want %04x", acc.PDUSessionReactivationResult, *tc.wantResult)
			}
		})
	}
}

// srBodyULDS is a SERVICE REQUEST body (data) with a well-formed 7-octet
// 5G-S-TMSI (srBody's identity is one octet short) and an optional Uplink data
// status IE.
func srBodyULDS(ulds *uint16) []byte {
	b := []byte{nas.ServiceTypeData<<4 | 0x01, 0x00, 0x07, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	if ulds != nil {
		b = append(b, nas.IEIUplinkDataStatus, 0x02, byte(*ulds>>8), byte(*ulds))
	}
	return b
}

// pagedDropLog returns the paged_pdu_sessions field of the single
// "paged PDU sessions not re-activated" record in the captured JSON log.
func pagedDropLog(t *testing.T, buf *bytes.Buffer) []any {
	t.Helper()
	var found [][]any
	dec := json.NewDecoder(buf)
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("log json: %v", err)
		}
		if msg, _ := rec["msg"].(string); strings.HasPrefix(msg, "paged PDU sessions not re-activated") {
			if rec["cause"] != "empty_allowed_nssai_no_ics" {
				t.Fatalf("cause=%v; want empty_allowed_nssai_no_ics", rec["cause"])
			}
			l, _ := rec["paged_pdu_sessions"].([]any)
			found = append(found, l)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d paged-drop warnings; want 1", len(found))
	}
	return found[0]
}

func u16(v uint16) *uint16 { return &v }
