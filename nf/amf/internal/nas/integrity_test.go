package nasmsg

import (
	"context"
	"errors"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// buildULAt builds a UL PDU protected under sc with an explicit NAS COUNT.
// cipher=false gives SHT 1 (integrity only), true SHT 2.
func buildULAt(t *testing.T, sc amfctx.SecurityContext, count uint32, cipher bool, mt nas.MessageType, body []byte) []byte {
	t.Helper()
	inner := append([]byte{nas.PDMobilityManagement, 0x00, byte(mt)}, body...)
	payload, sht := inner, nas.SecurityHeaderIntegrityProtected
	if cipher {
		var err error
		if payload, err = nea.NEA2(sc.KNASenc, count, 0x01, 0x00, inner); err != nil {
			t.Fatal(err)
		}
		sht = nas.SecurityHeaderIntegrityProtectedAndCiphered
	}
	sqn := byte(count)
	mac, err := nia.NIA2(sc.KNASint, count, 0x01, 0x00, append([]byte{sqn}, payload...))
	if err != nil {
		t.Fatal(err)
	}
	pdu := append([]byte{nas.PDMobilityManagement, byte(sht)}, mac...)
	return append(append(pdu, sqn), payload...)
}

// TestUnwrapUplinkCountEstimation: replay rejected, SQN wrap, lost messages
// accepted, MAC failure leaves UplinkCount unchanged. Ref: TS 24.501 §4.4.3.1.
func TestUnwrapUplinkCountEstimation(t *testing.T) {
	h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
	sc := ue.SecurityCtx
	body := []byte{0x00}
	unwrap := func(count uint32) error {
		_, err := h.unwrapWithContext(&ue.SecurityCtx, buildULAt(t, sc, count, true, nas.MsgTypeRegistrationComplete, body))
		return err
	}
	if err := unwrap(0); err != nil || ue.SecurityCtx.UplinkCount != 1 {
		t.Fatalf("count 0: err=%v UplinkCount=%d", err, ue.SecurityCtx.UplinkCount)
	}
	if err := unwrap(0); !errors.Is(err, ErrNASIntegrity) || ue.SecurityCtx.UplinkCount != 1 {
		t.Fatalf("replay: err=%v UplinkCount=%d; want ErrNASIntegrity and 1", err, ue.SecurityCtx.UplinkCount)
	}
	if err := unwrap(5); err != nil || ue.SecurityCtx.UplinkCount != 6 { // lost messages 1..4
		t.Fatalf("lost messages: err=%v UplinkCount=%d", err, ue.SecurityCtx.UplinkCount)
	}
	bad := buildULAt(t, sc, 6, true, nas.MsgTypeRegistrationComplete, body)
	bad[2] ^= 0xff
	if _, err := h.unwrapWithContext(&ue.SecurityCtx, bad); !errors.Is(err, ErrNASIntegrity) || ue.SecurityCtx.UplinkCount != 6 {
		t.Fatalf("bad MAC: err=%v UplinkCount=%d; want ErrNASIntegrity and 6", err, ue.SecurityCtx.UplinkCount)
	}
	ue.SecurityCtx.UplinkCount = 0xFF
	if err := unwrap(0xFF); err != nil || ue.SecurityCtx.UplinkCount != 0x100 {
		t.Fatalf("count 0xFF: err=%v UplinkCount=%#x", err, ue.SecurityCtx.UplinkCount)
	}
	if err := unwrap(0x100); err != nil || ue.SecurityCtx.UplinkCount != 0x101 { // SQN wrapped to 0
		t.Fatalf("count 0x100: err=%v UplinkCount=%#x", err, ue.SecurityCtx.UplinkCount)
	}
}

func TestEstimateUplinkCount(t *testing.T) {
	for _, tc := range []struct {
		exp  uint32
		sqn  byte
		want uint32
	}{{0, 0, 0}, {6, 5, 0x105}, {0xFF, 0xFF, 0xFF}, {0x100, 0, 0x100}, {0x1FF, 0x02, 0x202}} {
		if got := estimateUplinkCount(tc.exp, tc.sqn); got != tc.want {
			t.Errorf("estimate(%#x,%#x)=%#x want %#x", tc.exp, tc.sqn, got, tc.want)
		}
	}
}

// TestSecureExchangeDiscardsUnprotected: after a verified uplink message every
// unprotected or integrity-failing message of the connection is discarded
// (TS 24.501 §4.4.4.3 c)); a new N1 connection starts over.
func TestSecureExchangeDiscardsUnprotected(t *testing.T) {
	h, _, _, ue, s := newRegAudHandler(t, &regAudAUSF{}, regAudUDM{})
	ctx := context.Background()
	// the verified message is processed (not discarded); its handler outcome is irrelevant here
	_ = h.HandleNASMessage(ctx, ue, buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationComplete, nil))
	if !ue.SecureExchangeEstablished() {
		t.Fatal("verified uplink message did not establish the secure exchange")
	}
	n := len(s.dl)
	// plain REGISTRATION REQUEST (allowed before the secure exchange) is now discarded
	if err := h.HandleNASMessage(ctx, ue, regReqWithCap(t, 3, "")); err != nil || len(s.dl) != n || ue.RegStage() != amfctx.RegStageNone || !ue.SecurityCtx.Active {
		t.Fatalf("plain RR after secure exchange: err=%v dl=%d stage=%v; want discarded", err, len(s.dl), ue.RegStage())
	}
	// integrity-failing (replayed COUNT) is discarded
	replay := buildULAt(t, ue.SecurityCtx, 0, false, nas.MsgTypeRegistrationRequest, regReqWithCap(t, 3, "")[3:])
	cnt := ue.SecurityCtx.UplinkCount
	if err := h.HandleNASMessage(ctx, ue, replay); err != nil || len(s.dl) != n || ue.SecurityCtx.UplinkCount != cnt {
		t.Fatalf("replay: err=%v dl=%d count=%d->%d; want discarded, count unchanged", err, len(s.dl), cnt, ue.SecurityCtx.UplinkCount)
	}
	// new N1 connection: flag reset, plain RR is processed again (authenticates)
	ue.Lock()
	ue.NASOnNewN2Connection = true
	ue.Unlock()
	if err := h.HandleNASMessage(ctx, ue, regReqWithCap(t, 3, "")); err != nil {
		t.Logf("plain RR on a new N1 connection: %v", err)
	}
	if ue.SecureExchangeEstablished() {
		t.Fatal("secure exchange flag not reset on a new N1 connection")
	}
	if len(s.dl) == n {
		t.Fatal("plain RR on a new N1 connection was discarded")
	}
}

// TestUnverifiedServiceRequestRejected: SERVICE REQUEST failing integrity before
// the secure exchange gets SERVICE REJECT #9 and no state change.
func TestUnverifiedServiceRequestRejected(t *testing.T) {
	h, _, _, ue, s := newRegAudHandler(t, nil, regAudUDM{})
	ue.TransitionTo(amfctx.GMMRegistered)
	pdu := buildULAt(t, ue.SecurityCtx, 0, false, nas.MsgTypeServiceRequest, []byte{0x00, 0x00, 0x07, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x01})
	pdu[3] ^= 0xff
	cnt := ue.SecurityCtx.UplinkCount
	if err := h.HandleNASMessage(context.Background(), ue, pdu); err != nil {
		t.Fatalf("HandleNASMessage: %v", err)
	}
	if len(s.dl) != 1 || s.dl[0][2] != byte(nas.MsgTypeServiceReject) || s.dl[0][3] != byte(nas.CauseUEIdentityNotDerived) {
		t.Fatalf("DL=%x; want one SERVICE REJECT #9", s.dl)
	}
	if ue.State != amfctx.GMMRegistered || !ue.SecurityCtx.Active || ue.SecurityCtx.UplinkCount != cnt || len(s.ics) != 0 {
		t.Fatal("state / security context changed by an unverifiable SERVICE REQUEST")
	}
}

// TestUnverifiedCiphoredAndDeregDiscarded: ciphered failure and unverifiable
// de-registration are dropped without effect.
func TestUnverifiedCipheredAndDeregDiscarded(t *testing.T) {
	h, _, _, ue, s := newRegAudHandler(t, &regAudAUSF{}, regAudUDM{})
	ue.TransitionTo(amfctx.GMMRegistered)
	for name, pdu := range map[string][]byte{
		"ciphered": func() []byte {
			p := buildULAt(t, ue.SecurityCtx, 0, true, nas.MsgTypeRegistrationRequest, regReqWithCap(t, 3, "")[3:])
			p[2] ^= 0xff
			return p
		}(),
		"dereg": func() []byte {
			p := buildULAt(t, ue.SecurityCtx, 0, false, nas.MsgTypeDeregistrationRequestUE, []byte{0x09, 0x00})
			p[2] ^= 0xff
			return p
		}(),
	} {
		cnt := ue.SecurityCtx.UplinkCount
		if err := h.HandleNASMessage(context.Background(), ue, pdu); err != nil {
			t.Fatalf("%s: HandleNASMessage: %v", name, err)
		}
		if ue.State != amfctx.GMMRegistered || len(s.dl) != 0 || !ue.SecurityCtx.Active ||
			ue.SecurityCtx.UplinkCount != cnt || ue.RegStage() != amfctx.RegStageNone {
			t.Fatalf("%s: state=%s dl=%d count=%d->%d; want discarded without effect", name, ue.State, len(s.dl), cnt, ue.SecurityCtx.UplinkCount)
		}
	}
}

// TestUpdateNgKSIMismatchAccepted: a verified update whose ngKSI differs from the
// stored context is accepted (logged), not authenticated (TS 24.501 §4.4.4.3 b)).
func TestUpdateNgKSIMismatchAccepted(t *testing.T) {
	ausf := &regAudAUSF{}
	h, _, _, ue, s := newRegAudHandler(t, ausf, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	ue.TransitionTo(amfctx.GMMRegistered)
	body := regReqWithCap(t, 3, "")[3:]
	body[0] = 0x23 // ngKSI 2 (stored context is 1), periodic
	if err := h.HandleNASMessage(context.Background(), ue, buildULSecuredPDU(t, ue, nas.MsgTypeRegistrationRequest, body)); err != nil {
		t.Fatalf("HandleNASMessage: %v", err)
	}
	if len(ausf.ids) != 0 || len(s.ics)+len(s.dl) == 0 {
		t.Fatalf("authentications=%d ICS=%d DL=%d; want 0 and an Accept", len(ausf.ids), len(s.ics), len(s.dl))
	}
}

// TestRelaxedEnforcementLegacy: relaxed mode processes an integrity failure.
func TestRelaxedEnforcementLegacy(t *testing.T) {
	h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
	h.WithIntegrityEnforcement(IntegrityRelaxed)
	bad := buildULAt(t, ue.SecurityCtx, 0, true, nas.MsgTypeRegistrationComplete, nil)
	bad[2] ^= 0xff
	if _, err := h.unwrapWithContext(&ue.SecurityCtx, bad); err != nil || ue.SecurityCtx.UplinkCount != 0 {
		t.Fatalf("relaxed: err=%v count=%d; want processed, COUNT not advanced", err, ue.SecurityCtx.UplinkCount)
	}
}

func TestParseIntegrityEnforcement(t *testing.T) {
	for in, want := range map[string]IntegrityEnforcement{"": IntegrityStrict, "strict": IntegrityStrict, "Relaxed": IntegrityRelaxed} {
		if got, err := ParseIntegrityEnforcement(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseIntegrityEnforcement("off"); err == nil {
		t.Error("invalid value accepted")
	}
}

func badMAC(p []byte) []byte { p[2] ^= 0xff; return p }

// TestNoSecurityContextProtectedPDU: SHT != 0 while no current 5G NAS security
// context exists is unverifiable (TS 24.501 §4.4.4.3): REGISTRATION REQUEST is
// processed as unverified (re-registration after an AMF restart), SHT 2/4 and any
// other message type are discarded.
func TestNoSecurityContextProtectedPDU(t *testing.T) {
	ctx := context.Background()
	rr := regReqWithCap(t, 1, "")[3:]
	for _, tc := range []struct {
		name      string
		build     func(ue *amfctx.UEContext) []byte
		processed bool
	}{
		{"SHT1 REGISTRATION REQUEST", func(ue *amfctx.UEContext) []byte {
			return badMAC(buildULAt(t, ue.SecurityCtx, 0, false, nas.MsgTypeRegistrationRequest, rr))
		}, true},
		{"plain REGISTRATION REQUEST", func(ue *amfctx.UEContext) []byte { return regReqWithCap(t, 1, "") }, true},
		{"SHT2 REGISTRATION REQUEST", func(ue *amfctx.UEContext) []byte {
			return badMAC(buildULAt(t, ue.SecurityCtx, 0, true, nas.MsgTypeRegistrationRequest, rr))
		}, false},
		{"SHT1 SERVICE REQUEST", func(ue *amfctx.UEContext) []byte {
			return badMAC(buildULAt(t, ue.SecurityCtx, 0, false, nas.MsgTypeServiceRequest, []byte{0x00, 0x00, 0x07, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x01}))
		}, false},
		{"SHT1 REGISTRATION COMPLETE", func(ue *amfctx.UEContext) []byte {
			return badMAC(buildULAt(t, ue.SecurityCtx, 0, false, nas.MsgTypeRegistrationComplete, nil))
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ausf := &regAudAUSF{}
			h, _, _, ue, s := newRegAudHandler(t, ausf, regAudUDM{})
			pdu := tc.build(ue) // built with the keys, then the context is dropped (fresh AMF)
			ue.SecurityCtx = amfctx.SecurityContext{}
			if err := h.HandleNASMessage(ctx, ue, pdu); err != nil && !tc.processed {
				t.Fatalf("HandleNASMessage: %v", err)
			}
			got := len(s.dl)+len(ausf.ids) > 0
			if got != tc.processed {
				t.Fatalf("processed=%v dl=%d auth=%d; want processed=%v", got, len(s.dl), len(ausf.ids), tc.processed)
			}
			if !tc.processed && (ue.SecurityCtx.Active || ue.SecureExchangeEstablished() || ue.SecurityCtx.UplinkCount != 0) {
				t.Fatal("state changed by a discarded PDU")
			}
		})
	}
}

// TestCipheredFailureNeverPeeked: a ciphered PDU that fails the MAC is discarded
// outright; unwrap does not hand back the ciphertext. NEA0 (plaintext body) may
// be answered. Ref: TS 24.501 §4.4.4.3
func TestCipheredFailureNeverPeeked(t *testing.T) {
	h, _, _, ue, s := newRegAudHandler(t, &regAudAUSF{}, regAudUDM{})
	ue.TransitionTo(amfctx.GMMRegistered)
	bad := badMAC(buildULAt(t, ue.SecurityCtx, 0, true, nas.MsgTypeServiceRequest, []byte{0x00}))
	out, err := h.unwrapWithContext(&ue.SecurityCtx, bad)
	if !errors.Is(err, ErrNASIntegrity) || out != nil {
		t.Fatalf("NEA2 bad MAC: out=%x err=%v; want nil PDU + ErrNASIntegrity", out, err)
	}
	if err := h.HandleNASMessage(context.Background(), ue, bad); err != nil || len(s.dl) != 0 {
		t.Fatalf("discard: err=%v dl=%d", err, len(s.dl))
	}
	// NEA0: the body is plaintext, so the failing SERVICE REQUEST gets SERVICE REJECT #9.
	ue.SecurityCtx.CipheringAlgID = 0
	p := badMAC(buildULAt(t, ue.SecurityCtx, 0, false, nas.MsgTypeServiceRequest, []byte{0x00, 0x00, 0x07, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x01}))
	p[1] = byte(nas.SecurityHeaderIntegrityProtectedAndCiphered)
	if err := h.HandleNASMessage(context.Background(), ue, p); err != nil {
		t.Fatalf("NEA0: %v", err)
	}
	if len(s.dl) != 1 || s.dl[0][2] != byte(nas.MsgTypeServiceReject) || s.dl[0][3] != byte(nas.CauseUEIdentityNotDerived) {
		t.Fatalf("NEA0 DL=%x; want SERVICE REJECT #9", s.dl)
	}
}

// TestUnverifiedIdentityResponse: processed unverified only while the outstanding
// IDENTITY REQUEST asked for SUCI (RegStageIdentity), else discarded.
func TestUnverifiedIdentityResponse(t *testing.T) {
	for _, outstanding := range []bool{false, true} {
		ausf := &regAudAUSF{}
		h, _, _, ue, s := newRegAudHandler(t, ausf, regAudUDM{})
		if outstanding {
			ue.SetRegStage(amfctx.RegStageIdentity)
		}
		err := h.HandleNASMessage(context.Background(), ue, regTmrIdentityResponse())
		processed := len(ausf.ids) > 0 || len(s.dl) > 0
		if processed != outstanding {
			t.Fatalf("outstanding=%v: err=%v auth=%d dl=%d", outstanding, err, len(ausf.ids), len(s.dl))
		}
		if !outstanding && (err != nil || ue.SecureExchangeEstablished()) {
			t.Fatalf("discard: err=%v", err)
		}
	}
}

// TestUnverifiedDeregistration: ignored while a current security context exists,
// processed without one (TS 24.501 §4.4.4.3 NOTE 2).
func TestUnverifiedDeregistration(t *testing.T) {
	plain := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeDeregistrationRequestUE), 0x09,
		0x00, 0x0b, 0xf2, 0x00, 0xf1, 0x10, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}
	h, _, _, ue, _ := newRegAudHandler(t, nil, regAudUDM{})
	ue.TransitionTo(amfctx.GMMRegistered)
	if err := h.HandleNASMessage(context.Background(), ue, plain); err != nil || ue.State != amfctx.GMMRegistered {
		t.Fatalf("with context: err=%v state=%s; want ignored", err, ue.State)
	}
	h, _, _, ue, _ = newRegAudHandler(t, nil, regAudUDM{})
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.SecurityCtx = amfctx.SecurityContext{}
	err := h.HandleNASMessage(context.Background(), ue, plain)
	if ue.State == amfctx.GMMRegistered {
		t.Fatalf("without context: de-registration not processed (err=%v)", err)
	}
}
