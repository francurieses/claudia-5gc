package nasmsg

import (
	"bytes"
	"context"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// authRejectPDU is a plain AUTHENTICATION REJECT without EAP message (TS 24.501 §8.2.5).
var authRejectPDU = []byte{0x7e, 0x00, 0x58}

// TestAuthenticationFailureHandling covers the AUTHENTICATION FAILURE branches
// of TS 24.501 §5.4.1.3.7: #71 → same challenge with a new ngKSI once, #20/#26
// on a 5G-GUTI-based challenge → IDENTITY REQUEST, #21 + AUTS → resync once,
// everything else → AUTHENTICATION REJECT and context removal.
func TestAuthenticationFailureHandling(t *testing.T) {
	auts := bytes.Repeat([]byte{0xaa}, 14)
	tests := []struct {
		name     string
		cause    nas.Cause5GMM
		auts     []byte
		prep     func(ue *amfctx.UEContext)
		wantType nas.MessageType // DL message type (0 = AUTHENTICATION REJECT)
		wantGone bool            // UE context left PendingRemoval
	}{
		{name: "#71 first", cause: nas.CausengKSIAlreadyInUse, wantType: nas.MsgTypeAuthenticationRequest},
		{name: "#71 repeated", cause: nas.CausengKSIAlreadyInUse,
			prep: func(ue *amfctx.UEContext) { ue.AuthNgKSIFailures = 1 }, wantGone: true},
		{name: "#20 GUTI-based", cause: nas.CauseMACFailure,
			prep: func(ue *amfctx.UEContext) { ue.AuthViaGUTI = true }, wantType: nas.MsgTypeIdentityRequest},
		{name: "#26 GUTI-based", cause: nas.CauseNon5GAuthenticationUnacceptable,
			prep: func(ue *amfctx.UEContext) { ue.AuthViaGUTI = true }, wantType: nas.MsgTypeIdentityRequest},
		{name: "#20 SUCI-based", cause: nas.CauseMACFailure, wantGone: true},
		{name: "#21 with AUTS first", cause: nas.CauseSynchFailure, auts: auts, wantType: nas.MsgTypeAuthenticationRequest},
		{name: "#21 second consecutive", cause: nas.CauseSynchFailure, auts: auts,
			prep: func(ue *amfctx.UEContext) { ue.AuthSynchFailures = 1 }, wantGone: true},
		{name: "#21 without AUTS", cause: nas.CauseSynchFailure, wantGone: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _, ue, s := newRegAudHandler(t, &regAudAUSF{}, regAudUDM{})
			ue.SecurityCtx = amfctx.SecurityContext{}
			ue.PendingNGKSI = 1
			ue.PendingRAND = [16]byte{1}
			ue.PendingAUTN = [16]byte{2}
			if tc.prep != nil {
				tc.prep(ue)
			}
			pdu := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeAuthenticationFailure), byte(tc.cause)}
			if tc.auts != nil {
				pdu = append(pdu, 0x30, byte(len(tc.auts)))
				pdu = append(pdu, tc.auts...)
			}
			if err := h.HandleNASMessage(context.Background(), ue, pdu); err != nil {
				t.Fatalf("HandleNASMessage: %v", err)
			}
			if len(s.dl) != 1 {
				t.Fatalf("got %d DL NAS messages, want 1", len(s.dl))
			}
			if tc.wantGone {
				if !bytes.Equal(s.dl[0], authRejectPDU) {
					t.Fatalf("DL = %x, want AUTHENTICATION REJECT %x", s.dl[0], authRejectPDU)
				}
				if !ue.PendingRemoval {
					t.Fatal("UE context not marked for removal after AUTHENTICATION REJECT")
				}
				return
			}
			if got := nas.MessageType(s.dl[0][2]); got != tc.wantType {
				t.Fatalf("DL message type 0x%02x, want 0x%02x", got, tc.wantType)
			}
			if tc.cause == nas.CausengKSIAlreadyInUse {
				m, err := nas.Decode(s.dl[0])
				if err != nil {
					t.Fatalf("decode: %v", err)
				}
				ar, ok := m.Body.(*nas.AuthenticationRequest)
				if !ok {
					t.Fatalf("body %T", m.Body)
				}
				if ar.NGKSI.KeySetIdentifier == 1 || ar.RAND != ue.PendingRAND || ar.AUTN != ue.PendingAUTN {
					t.Fatalf("want new ngKSI and same RAND/AUTN, got ngKSI %d RAND %x AUTN %x",
						ar.NGKSI.KeySetIdentifier, ar.RAND, ar.AUTN)
				}
			}
		})
	}
}
