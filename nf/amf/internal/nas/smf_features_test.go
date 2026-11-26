package nasmsg

// smf_features_test.go - REL19-2.7: the supportedFeatures set negotiated with
// the SMF at CreateSMContext is stored on the PDU session context, and a
// PDU Session Establishment never depends on the negotiation outcome.
// Ref: TS 29.500 §6.6.2; TS 29.502 §6.1.8; TS 23.502 §4.3.2.2.1.

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// smfSender is a fakeSender that also implements the optional CallSMF
// interface the establishment path type-asserts for.
type smfSender struct {
	fakeSender
	negotiated features.Set
	err        error
}

func (s *smfSender) CallSMF(context.Context, string, string, uint8, []byte, amfctx.SNSSAISubscribed) (string, []byte, []byte, features.Set, error) {
	return "sm-ref-5", []byte{0x01}, []byte{0x02}, s.negotiated, s.err
}

func establish(t *testing.T, s *smfSender) *amfctx.UEContext {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	reg := procedures.NewRegistrationHandler(mgr, nil, nil, nil, "test-amf", "001", "01", logger)
	h := NewHandler(s, reg, logger)
	ue := newTestUE(t)
	psi := uint8(5)
	// 5GSM header EPD=0x2E | PSI | PTI | MT=0xC1 + 2 octets integrity max rate.
	payload := []byte{0x2E, psi, 0x01, byte(nas.MsgTypePDUSessionEstablishmentRequest), 0xFF, 0xFF}
	msg := &nas.Message{Body: &nas.ULNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     payload,
		PDUSessionID:         &psi,
	}}
	if err := h.handleULNASTransport(context.Background(), ue, msg); err != nil {
		t.Fatalf("handleULNASTransport: %v", err)
	}
	return ue
}

func TestPDUSessionEstablishment_StoresNegotiatedFeatures(t *testing.T) {
	want := features.Set{}.With(1).With(3)
	for _, tc := range []struct {
		name string
		set  features.Set
	}{
		{"negotiated set stored", want},
		{"empty set stored as empty", features.Set{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ue := establish(t, &smfSender{negotiated: tc.set})
			ue.Lock()
			ps := ue.PDUSessions[5]
			ue.Unlock()
			if ps == nil {
				t.Fatal("PDU session not stored")
			}
			if ps.SMFInstanceID != "sm-ref-5" {
				t.Errorf("SMFInstanceID = %q", ps.SMFInstanceID)
			}
			if !ps.Features.Equal(tc.set) {
				t.Errorf("Features = %s, want %s", ps.Features, tc.set)
			}
		})
	}
}

func TestPDUSessionEstablishment_SMFErrorStoresNothing(t *testing.T) {
	ue := establish(t, &smfSender{err: io.ErrUnexpectedEOF})
	ue.Lock()
	defer ue.Unlock()
	if _, ok := ue.PDUSessions[5]; ok {
		t.Error("PDU session stored despite CreateSMContext failure")
	}
}

// TestPDUSessionEstablishment_SMFRejectRelayed: a SmContextCreateError carrying
// an N1 SM reject yields exactly one DL NAS TRANSPORT and no stored session.
// Ref: TS 23.502 §4.3.2.2.2 step 16; TS 24.501 §6.4.1.4.
func TestPDUSessionEstablishment_SMFRejectRelayed(t *testing.T) {
	rej := nas.WrapPDUSessionEstablishmentRejectBody(5, 1, 26, nil)
	s := &smfSender{err: &SMContextCreateError{Status: 500, Cause: "SYSTEM_FAILURE", N1SmMsg: rej}}
	ue := establish(t, s)
	if s.called != 1 {
		t.Fatalf("DL NAS TRANSPORT sent %d times, want 1", s.called)
	}
	if len(s.lastPDU) == 0 || s.lastPDU[1] != 0x02 { // EPD, SHT=integrity protected+ciphered
		t.Fatalf("PDU not ciphered: % X", s.lastPDU)
	}
	// Decipher (DL COUNT 0 = first DL message of the fresh test UE) and check the
	// DL NAS TRANSPORT: EPD 5GMM | SHT 0 | MT | PCT | LV-E payload | 0x12 PSI.
	in := decipherDLPDU(t, ue, 0, s.lastPDU)
	if in[0] != nas.PDMobilityManagement || in[2] != byte(nas.MsgTypeDLNASTransport) || in[3] != nas.PayloadContainerTypeN1SM {
		t.Fatalf("inner = % X, want DL NAS TRANSPORT with N1 SM container", in)
	}
	n := int(in[4])<<8 | int(in[5])
	if n != len(rej) || !bytes.Equal(in[6:6+n], rej) {
		t.Fatalf("relayed 5GSM = % X, want % X (EPD|PSI=5|PTI=1|REJECT|cause 26)", in[6:6+n], rej)
	}
	if got := in[6+n:]; !bytes.Equal(got, []byte{0x12, 5}) {
		t.Fatalf("trailer = % X, want PDU session ID IE 12 05", got)
	}
	ue.Lock()
	defer ue.Unlock()
	if _, ok := ue.PDUSessions[5]; ok {
		t.Error("PDU session stored despite SMF reject")
	}
}
