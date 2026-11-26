package nasmsg

// hr_release_test.go - ROAM-002: UE-initiated release of a home-routed PDU
// session is driven by the V-SMF; non-roaming stays byte-identical.
// Ref: TS 23.502 §4.3.4.3 step 1a, §4.3.4.2; TS 29.502 §5.2.2.3.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

type hrRelSender struct {
	releaseSender
	modCalls int
	modRef   string
	modMsg   []byte
	modPSI   uint8
	modResp  []byte
	modErr   error
	modTTL   time.Duration
	ngapPDUs [][]byte
}

func (s *hrRelSender) ModifySMContext(ctx context.Context, ref string, n1 []byte, psi uint8) ([]byte, []byte, error) {
	s.modCalls++
	if dl, ok := ctx.Deadline(); ok {
		s.modTTL = time.Until(dl)
	}
	s.modRef, s.modMsg, s.modPSI = ref, append([]byte(nil), n1...), psi
	return s.modResp, nil, s.modErr
}

func (s *hrRelSender) SendPDUSessionResourceReleaseCommand(_ *amfctx.UEContext, _ uint8, pdu []byte) error {
	s.ngapPDUs = append(s.ngapPDUs, append([]byte(nil), pdu...))
	return nil
}

func releaseRequest(psi, pti uint8) []byte {
	return []byte{nas.PDGroupSessionManagement, psi, pti, byte(nas.MsgTypePDUSessionReleaseRequest), 0x59, 0x24}
}

func sendRelease(t *testing.T, h *Handler, ue *amfctx.UEContext, raw []byte) {
	t.Helper()
	psi := raw[1]
	msg := &nas.Message{Body: &nas.ULNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     raw,
		PDUSessionID:         &psi,
	}}
	if err := h.handleULNASTransport(context.Background(), ue, msg); err != nil {
		t.Fatalf("handleULNASTransport: %v", err)
	}
}

func sendReleaseComplete(t *testing.T, h *Handler, ue *amfctx.UEContext, psi uint8) {
	t.Helper()
	raw := []byte{nas.PDGroupSessionManagement, psi, 0x00, byte(nas.MsgTypePDUSessionReleaseComplete)}
	msg := &nas.Message{Body: &nas.ULNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     raw,
		PDUSessionID:         &psi,
	}}
	if err := h.handleULNASTransport(context.Background(), ue, msg); err != nil {
		t.Fatalf("handleULNASTransport: %v", err)
	}
}

func hrSetup(t *testing.T, hr bool, resp []byte, modErr error) (*hrRelSender, *Handler, *amfctx.UEContext, *bytes.Buffer) {
	t.Helper()
	s := &hrRelSender{releaseSender: *newReleaseSender(), modResp: resp, modErr: modErr}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	reg := procedures.NewRegistrationHandler(mgr, nil, nil, nil, "test-amf", "001", "01", logger)
	h := NewHandler(s, reg, logger)
	ue := newTestUE(t)
	ps := &amfctx.PDUSession{PDUSessionID: 5, DNN: "internet", SMFInstanceID: "vsmf-ref-5"}
	if hr {
		ps.HSMFURI = "https://smf.h.example:8004/nsmf-pdusession/v1"
	}
	ue.PDUSessions[5] = ps
	return s, h, ue, &buf
}

// innerOf deciphers a secured DL NAS PDU (NEA2, count = SQN).
func innerOf(t *testing.T, ue *amfctx.UEContext, pdu []byte) []byte {
	t.Helper()
	inner, err := nea.NEA2(ue.SecurityCtx.KNASenc, uint32(pdu[6]), 0x01, 0x01, pdu[7:])
	if err != nil {
		t.Fatal(err)
	}
	return inner
}

func (s *hrRelSender) deletes() []string { r, _ := s.calls(); return r }

func hasPSession(ue *amfctx.UEContext, psi uint8) bool {
	ue.Lock()
	defer ue.Unlock()
	_, ok := ue.PDUSessions[psi]
	return ok
}

var vsmfCmd = []byte{0x2E, 5, 0x07, 0xD3, 0x24}

func TestHRRelease_HappyPath(t *testing.T) {
	s, h, ue, buf := hrSetup(t, true, vsmfCmd, nil)
	req := releaseRequest(5, 0x07)
	sendRelease(t, h, ue, req)

	if s.modCalls != 1 || s.modRef != "vsmf-ref-5" || s.modPSI != 5 || !bytes.Equal(s.modMsg, req) {
		t.Fatalf("ModifySMContext call wrong: n=%d ref=%q psi=%d msg=%x", s.modCalls, s.modRef, s.modPSI, s.modMsg)
	}
	if len(s.ngapPDUs) != 1 || !bytes.Contains(innerOf(t, ue, s.ngapPDUs[0]), vsmfCmd) {
		t.Fatalf("NGAP release must carry the V-SMF command in the DL NAS Transport")
	}
	if d := s.deletes(); len(d) != 0 {
		t.Fatalf("DeleteSMContext before Release Complete: %v", d)
	}
	if !hasPSession(ue, 5) {
		t.Fatal("session dropped before Release Complete")
	}

	sendReleaseComplete(t, h, ue, 5)
	if d := s.deletes(); len(d) != 1 || d[0] != "vsmf-ref-5" {
		t.Fatalf("want one DeleteSMContext after 0xD4, got %v", d)
	}
	if hasPSession(ue, 5) {
		t.Fatal("session still present after Release Complete")
	}
	var mine []byte // only the lines added by the HR path (the pre-existing N1 line repeats keys)
	for _, l := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if bytes.Contains(l, []byte("V-SMF")) {
			mine = append(append(mine, l...), '\n')
		}
	}
	if len(mine) == 0 {
		t.Fatal("no V-SMF log lines")
	}
	assertNoDupKeys(t, mine)
	if !bytes.Contains(buf.Bytes(), []byte("Nsmf_PDUSession_UpdateSMContext (UE release request) sent to V-SMF")) {
		t.Error("canonical Nsmf log line missing")
	}
}

func TestHRRelease_GuardDeletes(t *testing.T) {
	s, h, ue, _ := hrSetup(t, true, vsmfCmd, nil)
	sendRelease(t, h, ue, releaseRequest(5, 0x07))
	v, ok := h.pendingRelease.Load(pendingReleaseKey(ue.AMFUENGAPId, 5))
	if !ok {
		t.Fatal("no pending release armed")
	}
	v.(*pendingReleaseState).guard.Reset(time.Millisecond)
	select {
	case <-s.deleteCh:
	case <-time.After(2 * time.Second):
		t.Fatal("T3592 guard did not delete the SM context")
	}
	if d := s.deletes(); len(d) != 1 || d[0] != "vsmf-ref-5" {
		t.Fatalf("got %v", d)
	}
}

func TestHRRelease_FallbackOnErrorOrBadAnswer(t *testing.T) {
	cases := map[string]struct {
		resp []byte
		err  error
	}{
		"error":     {nil, errors.New("boom")},
		"empty":     {nil, nil},
		"bad epd":   {[]byte{0x7E, 5, 7, 0xD3, 0x24}, nil},
		"bad type":  {[]byte{0x2E, 5, 7, 0xCB, 0x24}, nil},
		"bad psi":   {[]byte{0x2E, 6, 7, 0xD3, 0x24}, nil},
		"bad pti":   {[]byte{0x2E, 5, 8, 0xD3, 0x24}, nil},
		"truncated": {[]byte{0x2E, 5, 7, 0xD3}, nil},
		"too long":  {append([]byte{0x2E, 5, 7, 0xD3, 0x24}, make([]byte, maxReleaseCommandLen)...), nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("AMF", "PDUSessionRelease", hrReleaseFallbackResult))
			s, h, ue, _ := hrSetup(t, true, c.resp, c.err)
			sendRelease(t, h, ue, releaseRequest(5, 0x07))
			after := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("AMF", "PDUSessionRelease", hrReleaseFallbackResult))
			if after != before+1 {
				t.Fatalf("fallback metric: before=%v after=%v, want +1", before, after)
			}
			if s.modCalls != 1 {
				t.Fatalf("modCalls=%d", s.modCalls)
			}
			if len(s.ngapPDUs) != 1 {
				t.Fatalf("UE must always be released, got %d NGAP releases", len(s.ngapPDUs))
			}
			want := []byte{0x2E, 5, 0x07, 0xD3, nas.Cause5GSMRegularDeactivation}
			if !bytes.Contains(innerOf(t, ue, s.ngapPDUs[0]), want) {
				t.Fatal("fallback must carry the AMF-built Release Command")
			}
			select {
			case <-s.deleteCh:
			case <-time.After(2 * time.Second):
				t.Fatal("fallback must delete the SM context")
			}
			if hasPSession(ue, 5) {
				t.Fatal("session kept after fallback")
			}
		})
	}
}

// TestNonHRRelease_Unchanged: HSMFURI empty -> no ModifySMContext and the NGAP
// NAS-PDU is byte-identical to the AMF-built secured Release Command.
func TestNonHRRelease_Unchanged(t *testing.T) {
	s, h, ue, _ := hrSetup(t, false, vsmfCmd, nil)
	sendRelease(t, h, ue, releaseRequest(5, 0x07))
	if s.modCalls != 0 {
		t.Fatal("ModifySMContext called for a non-roaming session")
	}
	_, h2, ue2, _ := hrSetup(t, false, nil, nil)
	psi := uint8(5)
	want, err := h2.sendNASSecured(ue2, nas.PDMobilityManagement, nas.MsgTypeDLNASTransport, &nas.DLNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     nas.WrapPDUSessionReleaseCommandBody(5, 0x07, nas.Cause5GSMRegularDeactivation),
		PDUSessionID:         &psi,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ngapPDUs) != 1 || !bytes.Equal(s.ngapPDUs[0], want) {
		t.Fatalf("NGAP NAS-PDU differs:\n got %x\nwant %x", s.ngapPDUs, want)
	}
	select {
	case <-s.deleteCh:
	case <-time.After(2 * time.Second):
		t.Fatal("non-HR path must delete the SM context inline")
	}
}

// assertNoDupKeys fails when one JSON log object repeats a key.
func assertNoDupKeys(t *testing.T, raw []byte) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	for dec.More() {
		var rawMsg json.RawMessage
		if err := dec.Decode(&rawMsg); err != nil {
			t.Fatal(err)
		}
		d := json.NewDecoder(bytes.NewReader(rawMsg))
		d.Token()
		seen := map[string]bool{}
		for d.More() {
			k, _ := d.Token()
			ks := k.(string)
			if seen[ks] {
				t.Errorf("duplicate log key %q in %s", ks, rawMsg)
			}
			seen[ks] = true
			var v json.RawMessage
			d.Decode(&v)
		}
	}
}

// TestHRRelease_UpdateTimeout: the V-SMF call carries the dedicated 9 s budget,
// which must exceed the V-SMF's 7 s bound.
func TestHRRelease_UpdateTimeout(t *testing.T) {
	if hrReleaseUpdateTimeout <= 7*time.Second {
		t.Fatalf("hrReleaseUpdateTimeout %v must exceed the 7 s V-SMF budget", hrReleaseUpdateTimeout)
	}
	s, h, ue, _ := hrSetup(t, true, vsmfCmd, nil)
	sendRelease(t, h, ue, releaseRequest(5, 0x07))
	if s.modTTL <= 8*time.Second || s.modTTL > hrReleaseUpdateTimeout {
		t.Fatalf("ModifySMContext deadline = %v, want (8s, %v]", s.modTTL, hrReleaseUpdateTimeout)
	}
}

func TestValidateReleaseCommand_Cap(t *testing.T) {
	ok := append([]byte{0x2E, 5, 7, 0xD3, 0x24}, make([]byte, maxReleaseCommandLen-5)...)
	if err := validateReleaseCommand(ok, 5, 7); err != nil {
		t.Fatalf("command at the cap rejected: %v", err)
	}
	if err := validateReleaseCommand(append(ok, 0), 5, 7); err == nil {
		t.Fatal("command above the cap accepted")
	}
}
