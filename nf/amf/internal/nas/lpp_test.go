package nasmsg

// lpp_test.go — unit tests for the LPP relay additions (LMF-005):
//   - SendDownlinkLPP builds a DL NAS Transport with payload container type
//     0x03 and the correct LV-E length.
//   - handleULNASTransport routes payload container type 0x03 to
//     handleULLPP, which resolves the pendingLPP waiter SendDownlinkLPP
//     registered (full DL->UL round trip).
//   - An orphan UL LPP container (no pending request) is logged and dropped,
//     not panicked.
//   - The pre-existing UEPolicy (0x05) and SMS (0x02) UL branches are
//     unaffected by the additive LPP branch.
//
// Ref: TS 24.501 §8.7.4; TS 23.273 §7.2; docs/procedures/LPPRelay.md.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

var errSendFailed = errors.New("fakeSender: send failed")

// fakeSender is a test double for the Sender interface. Only
// SendDownlinkNASTransport is exercised by the LPP relay tests; the other
// methods are no-ops satisfying the interface.
type fakeSender struct {
	lastPDU []byte
	called  int
	sendErr error
}

func (f *fakeSender) SendDownlinkNASTransport(_ *amfctx.UEContext, nasPDU []byte) error {
	f.called++
	f.lastPDU = nasPDU
	return f.sendErr
}
func (f *fakeSender) SendInitialContextSetupRequest(*amfctx.UEContext, []byte, [32]byte, byte, byte, uint16, uint16, []ngap.PDUSessionSetupItemCxtReq) error {
	return nil
}
func (f *fakeSender) SendPDUSessionResourceSetupRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (f *fakeSender) SendPDUSessionResourceReleaseCommand(*amfctx.UEContext, uint8, []byte) error {
	return nil
}
func (f *fakeSender) SendPDUSessionResourceModifyRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (f *fakeSender) SendUEContextReleaseCommandForUE(*amfctx.UEContext, int, int64) error {
	return nil
}

// newTestUE builds a UE context with an active NAS security context (NIA2/NEA2)
// suitable for exercising sendNASSecured / unwrapNASSecurity-equivalent logic.
func newTestUE(t *testing.T) *amfctx.UEContext {
	t.Helper()
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, "imsi-001010000000001")
	ue.RANUENGAPId = 1
	ue.CMState = amfctx.CMConnected
	ue.SecurityCtx = amfctx.SecurityContext{
		Active:         true,
		IntegrityAlgID: 2, // NIA2
		CipheringAlgID: 2, // NEA2
		KNASint:        bytes.Repeat([]byte{0x11}, 16),
		KNASenc:        bytes.Repeat([]byte{0x22}, 16),
		UplinkCount:    0,
		DownlinkCount:  0,
	}
	return ue
}

// newTestHandler builds a Handler with a fakeSender and a nil registration
// handler (safe — none of the LPP relay code paths touch h.reg).
func newTestHandler(sender *fakeSender) *Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewHandler(sender, nil, logger)
}

// buildULSecuredPDU builds a fully valid NAS-security-protected UL PDU
// (SHT=0x02, NIA2 MAC over SQN||ciphertext, NEA2-ciphered) for the given
// UplinkCount, mirroring sendNASSecured but for the UL direction (dir=0x00) —
// the same construction the real UE-side would perform.
// Ref: TS 33.501 §D.3.3.
func buildULSecuredPDU(t *testing.T, ue *amfctx.UEContext, msgType nas.MessageType, bodyBytes []byte) []byte {
	t.Helper()
	inner := append([]byte{nas.PDMobilityManagement, byte(nas.SecurityHeaderPlainNAS), byte(msgType)}, bodyBytes...)

	count := ue.SecurityCtx.UplinkCount
	ciphered, err := nea.NEA2(ue.SecurityCtx.KNASenc, count, 0x01, 0x00, inner)
	if err != nil {
		t.Fatalf("NEA2 cipher: %v", err)
	}
	sqn := byte(count & 0xFF)
	macInput := append([]byte{sqn}, ciphered...)
	mac, err := nia.NIA2(ue.SecurityCtx.KNASint, count, 0x01, 0x00, macInput)
	if err != nil {
		t.Fatalf("NIA2 mac: %v", err)
	}

	pdu := make([]byte, 7+len(ciphered))
	pdu[0] = nas.PDMobilityManagement
	pdu[1] = byte(nas.SecurityHeaderIntegrityProtectedAndCiphered)
	copy(pdu[2:6], mac)
	pdu[6] = sqn
	copy(pdu[7:], ciphered)
	return pdu
}

// decipherDLPDU deciphers a DL NAS-security-protected PDU built by
// sendNASSecured for the given (pre-call) DownlinkCount, returning the
// plaintext inner PDU (EPD | SHT=plain | MsgType | body). NEA2 is a stream
// cipher, so re-running it with the same key/count/bearer/direction on the
// ciphertext recovers the plaintext.
func decipherDLPDU(t *testing.T, ue *amfctx.UEContext, downlinkCountAtSend uint32, sentPDU []byte) []byte {
	t.Helper()
	if len(sentPDU) < 7 {
		t.Fatalf("sent PDU too short: %d bytes", len(sentPDU))
	}
	ciphered := sentPDU[7:]
	plain, err := nea.NEA2(ue.SecurityCtx.KNASenc, downlinkCountAtSend, 0x01, 0x01, ciphered)
	if err != nil {
		t.Fatalf("NEA2 decipher: %v", err)
	}
	return plain
}

// TestSendDownlinkLPP_BuildsCorrectDLNASTransport verifies SendDownlinkLPP
// wraps the LPP-PDU in a DL NAS Transport with payload container type 0x03
// and the correct LV-E length, sent via the Sender.
func TestSendDownlinkLPP_BuildsCorrectDLNASTransport(t *testing.T) {
	sender := &fakeSender{}
	h := newTestHandler(sender)
	ue := newTestUE(t)

	lppPDU := []byte{0x00, 0x01, 0x80} // sample RequestCapabilities-shaped LPP PDU
	downlinkCountAtSend := ue.SecurityCtx.DownlinkCount

	ch, err := h.SendDownlinkLPP(ue, lppPDU)
	if err != nil {
		t.Fatalf("SendDownlinkLPP: %v", err)
	}
	if ch == nil {
		t.Fatal("SendDownlinkLPP: channel is nil")
	}
	if sender.called != 1 {
		t.Fatalf("SendDownlinkNASTransport called %d times, want 1", sender.called)
	}

	plain := decipherDLPDU(t, ue, downlinkCountAtSend, sender.lastPDU)
	if len(plain) < 6 {
		t.Fatalf("plaintext inner PDU too short: %d bytes", len(plain))
	}
	if plain[0] != nas.PDMobilityManagement {
		t.Errorf("inner EPD = %#x, want %#x", plain[0], nas.PDMobilityManagement)
	}
	if nas.MessageType(plain[2]) != nas.MsgTypeDLNASTransport {
		t.Errorf("inner MessageType = %#x, want %#x (DL NAS Transport)", plain[2], nas.MsgTypeDLNASTransport)
	}

	body := plain[3:]
	pct := body[0]
	if pct != nas.PayloadContainerTypeLPP {
		t.Fatalf("payload container type = %#x, want %#x (LPP, NOT 0x01 N1SM)", pct, nas.PayloadContainerTypeLPP)
	}
	containerLen := int(body[1])<<8 | int(body[2])
	if containerLen != len(lppPDU) {
		t.Fatalf("LV-E length = %d, want %d", containerLen, len(lppPDU))
	}
	container := body[3 : 3+containerLen]
	if !bytes.Equal(container, lppPDU) {
		t.Fatalf("payload container = %v, want %v", container, lppPDU)
	}

	// pendingLPP must now hold a waiter keyed by AMF-UE-NGAP-ID.
	if _, ok := h.pendingLPP.Load(ue.AMFUENGAPId); !ok {
		t.Fatal("pendingLPP: no entry registered for AMF-UE-NGAP-ID")
	}
}

// TestSendDownlinkLPP_SenderErrorCleansUpPending verifies that a Sender
// failure removes the pendingLPP entry (no leaked waiter) and returns an error.
func TestSendDownlinkLPP_SenderErrorCleansUpPending(t *testing.T) {
	sender := &fakeSender{sendErr: errSendFailed}
	h := newTestHandler(sender)
	ue := newTestUE(t)

	_, err := h.SendDownlinkLPP(ue, []byte{0x00, 0x01, 0x80})
	if err == nil {
		t.Fatal("SendDownlinkLPP: err = nil, want error")
	}
	if _, ok := h.pendingLPP.Load(ue.AMFUENGAPId); ok {
		t.Fatal("pendingLPP: entry leaked after Sender error")
	}
}

// TestSendDownlinkLPP_EmptyPDU verifies an empty LPP PDU is rejected.
func TestSendDownlinkLPP_EmptyPDU(t *testing.T) {
	h := newTestHandler(&fakeSender{})
	ue := newTestUE(t)
	if _, err := h.SendDownlinkLPP(ue, nil); err == nil {
		t.Fatal("SendDownlinkLPP(nil): err = nil, want error")
	}
	if err := h.SendDownlinkLPPNoWait(ue, nil); err == nil {
		t.Fatal("SendDownlinkLPPNoWait(nil): err = nil, want error")
	}
}

// TestSendDownlinkLPPNoWait_SendsWithoutPendingWaiter verifies the LMF-009
// DL-only leg: the DL NAS Transport is built exactly as the waiter path
// (PCT=0x03, LV-E length) but NO pendingLPP entry is registered — a
// subsequent UL LPP for this AMF-UE-NGAP-ID would be an lpp_orphan by design.
// Ref: TS 37.355 §6.5.2 (assistance delivery is unsolicited);
// docs/procedures/LPPRelay.md §Endpoints (expectUlResponse=false).
func TestSendDownlinkLPPNoWait_SendsWithoutPendingWaiter(t *testing.T) {
	sender := &fakeSender{}
	h := newTestHandler(sender)
	ue := newTestUE(t)

	lppPDU := []byte{0x90, 0x05, 0x18, 0x22} // sample ProvideAssistanceData prefix
	downlinkCountAtSend := ue.SecurityCtx.DownlinkCount

	if err := h.SendDownlinkLPPNoWait(ue, lppPDU); err != nil {
		t.Fatalf("SendDownlinkLPPNoWait: %v", err)
	}
	if sender.called != 1 {
		t.Fatalf("SendDownlinkNASTransport called %d times, want 1", sender.called)
	}

	plain := decipherDLPDU(t, ue, downlinkCountAtSend, sender.lastPDU)
	if nas.MessageType(plain[2]) != nas.MsgTypeDLNASTransport {
		t.Errorf("inner MessageType = %#x, want DL NAS Transport", plain[2])
	}
	body := plain[3:]
	if body[0] != nas.PayloadContainerTypeLPP {
		t.Fatalf("payload container type = %#x, want %#x (LPP)", body[0], nas.PayloadContainerTypeLPP)
	}
	if !bytes.Equal(body[3:3+len(lppPDU)], lppPDU) {
		t.Fatal("payload container mismatch")
	}

	// The defining property of the no-wait path: no pendingLPP waiter.
	if _, ok := h.pendingLPP.Load(ue.AMFUENGAPId); ok {
		t.Fatal("pendingLPP: entry registered on the no-wait path, want none")
	}
}

// TestSendDownlinkLPPNoWait_SenderError verifies a Sender failure propagates.
func TestSendDownlinkLPPNoWait_SenderError(t *testing.T) {
	h := newTestHandler(&fakeSender{sendErr: errSendFailed})
	ue := newTestUE(t)
	if err := h.SendDownlinkLPPNoWait(ue, []byte{0x90, 0x05}); err == nil {
		t.Fatal("SendDownlinkLPPNoWait: err = nil, want error")
	}
}

// TestHandleULNASTransport_LPPRoutesAndResolvesPending exercises the full
// DL->UL round trip: SendDownlinkLPP registers a pendingLPP waiter, then a
// UL NAS Transport with payload container type 0x03 (built exactly as a real
// UE would) is fed through HandleNASMessage and must resolve that waiter with
// the UL LPP-PDU bytes.
func TestHandleULNASTransport_LPPRoutesAndResolvesPending(t *testing.T) {
	sender := &fakeSender{}
	h := newTestHandler(sender)
	ue := newTestUE(t)

	dlPDU := []byte{0x00, 0x01, 0x80}
	ch, err := h.SendDownlinkLPP(ue, dlPDU)
	if err != nil {
		t.Fatalf("SendDownlinkLPP: %v", err)
	}

	ulLPPPDU := []byte{0x40, 0x01, 0xa2, 0x00} // sample ProvideCapabilities-shaped LPP PDU
	ulBody, err := nas.EncodeULNASTransport(&nas.ULNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeLPP,
		PayloadContainer:     ulLPPPDU,
	})
	if err != nil {
		t.Fatalf("EncodeULNASTransport: %v", err)
	}
	ulWire := buildULSecuredPDU(t, ue, nas.MsgTypeULNASTransport, ulBody)

	if err := h.HandleNASMessage(context.Background(), ue, ulWire); err != nil {
		t.Fatalf("HandleNASMessage: %v", err)
	}

	select {
	case result := <-ch:
		if result.Err != nil {
			t.Fatalf("LPPResult.Err = %v, want nil", result.Err)
		}
		if !bytes.Equal(result.LPPPDU, ulLPPPDU) {
			t.Fatalf("LPPResult.LPPPDU = %v, want %v", result.LPPPDU, ulLPPPDU)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pendingLPP waiter was not resolved")
	}

	// The pendingLPP entry must be removed (LoadAndDelete) so it cannot leak.
	if _, ok := h.pendingLPP.Load(ue.AMFUENGAPId); ok {
		t.Fatal("pendingLPP entry not removed after resolution")
	}
}

// TestHandleULLPP_OrphanNoPendingRequest verifies that a UL LPP container
// with no matching pendingLPP entry is logged and dropped (no panic, no
// error propagated) — mirrors the NRPPa relay's nrppa_orphan behaviour.
func TestHandleULLPP_OrphanNoPendingRequest(t *testing.T) {
	h := newTestHandler(&fakeSender{})
	ue := newTestUE(t)
	// Intentionally do NOT call SendDownlinkLPP first — no pending entry.

	ulBody, err := nas.EncodeULNASTransport(&nas.ULNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeLPP,
		PayloadContainer:     []byte{0xAA, 0xBB},
	})
	if err != nil {
		t.Fatalf("EncodeULNASTransport: %v", err)
	}
	ulWire := buildULSecuredPDU(t, ue, nas.MsgTypeULNASTransport, ulBody)

	if err := h.HandleNASMessage(context.Background(), ue, ulWire); err != nil {
		t.Fatalf("HandleNASMessage (orphan LPP): %v", err)
	}
}

// TestHandleULNASTransport_ExistingBranchesUnaffected proves the additive LPP
// branch does not alter dispatch for the pre-existing UEPolicy (0x05) and SMS
// (0x02) payload container types — both must still be handled (no error, no
// interaction with pendingLPP) exactly as before this change.
func TestHandleULNASTransport_ExistingBranchesUnaffected(t *testing.T) {
	cases := []struct {
		name      string
		container []byte
		pct       uint8
	}{
		{
			name:      "UEPolicy MANAGE UE POLICY COMPLETE",
			container: []byte{0x00, updsManageUEPolicyComplete},
			pct:       nas.PayloadContainerTypeUEPolicy,
		},
		{
			name:      "SMS (no SMSF client wired — fail-open)",
			container: []byte{0x01, 0x02, 0x03},
			pct:       nas.PayloadContainerTypeSMS,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(&fakeSender{})
			ue := newTestUE(t)

			ulBody, err := nas.EncodeULNASTransport(&nas.ULNASTransport{
				PayloadContainerType: tc.pct,
				PayloadContainer:     tc.container,
			})
			if err != nil {
				t.Fatalf("EncodeULNASTransport: %v", err)
			}
			ulWire := buildULSecuredPDU(t, ue, nas.MsgTypeULNASTransport, ulBody)

			if err := h.HandleNASMessage(context.Background(), ue, ulWire); err != nil {
				t.Fatalf("HandleNASMessage: %v", err)
			}
			if _, ok := h.pendingLPP.Load(ue.AMFUENGAPId); ok {
				t.Fatal("pendingLPP should not be touched by non-LPP payload container types")
			}
		})
	}
}
