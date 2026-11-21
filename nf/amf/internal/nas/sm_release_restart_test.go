package nasmsg

// sm_release_restart_test.go - SMF-012: network-initiated release of PDU
// sessions orphaned by an SMF restart (5GSM cause #39), CM-CONNECTED and
// CM-IDLE. Ref: TS 23.502 §4.3.4.2; TS 24.501 §6.3.3.2, §5.6.1.4.1.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// restartSender records the N1/N2 sends and SMF calls of the release paths.
type restartSender struct {
	fakeSender
	mu      sync.Mutex
	dl      [][]byte
	ics     [][]byte
	ngapRel []uint8
	acts    []string
	dels    []string
	actErr  error
	delErr  error
	paged   int
	pageErr error
	delDone chan struct{}
}

func (s *restartSender) SendDownlinkNASTransport(_ *amfctx.UEContext, pdu []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dl = append(s.dl, append([]byte(nil), pdu...))
	return nil
}

func (s *restartSender) SendInitialContextSetupRequest(_ *amfctx.UEContext, pdu []byte,
	_ [32]byte, _, _ byte, _, _ uint16, _ []ngap.PDUSessionSetupItemCxtReq) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ics = append(s.ics, append([]byte(nil), pdu...))
	return nil
}

func (s *restartSender) SendPDUSessionResourceReleaseCommand(_ *amfctx.UEContext, psi uint8, _ []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ngapRel = append(s.ngapRel, psi)
	return nil
}

func (s *restartSender) ActivateSMContext(_ context.Context, ref string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acts = append(s.acts, ref)
	if s.actErr != nil {
		return nil, s.actErr
	}
	return []byte{0xAA}, nil
}

func (s *restartSender) DeleteSMContext(_ context.Context, ref string) error {
	s.mu.Lock()
	s.dels = append(s.dels, ref)
	s.mu.Unlock()
	if s.delDone != nil {
		s.delDone <- struct{}{}
	}
	return s.delErr
}

func (s *restartSender) SendPaging(_ *amfctx.UEContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paged++
	return s.pageErr
}

func (s *restartSender) snapshot() (dl, ics [][]byte, ngapRel []uint8, acts, dels []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.dl...), append([][]byte(nil), s.ics...),
		append([]uint8(nil), s.ngapRel...), append([]string(nil), s.acts...), append([]string(nil), s.dels...)
}

func restartHandler(t *testing.T) (*Handler, *amfctx.UEContext, *restartSender) {
	t.Helper()
	h, ue, _ := upHandler(t)
	s := &restartSender{}
	h.sender = s
	h.SetPager(s)
	return h, ue, s
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func hasPSI(ue *amfctx.UEContext, psi uint8) bool {
	ue.Lock()
	defer ue.Unlock()
	_, ok := ue.PDUSessions[psi]
	return ok
}

// releaseCmdInner is the plain 5GSM payload container of a DL NAS Transport
// sent with the given pre-send DL COUNT: 2E psi 00 D3 cause.
func releaseCmdBytes(t *testing.T, ue *amfctx.UEContext, count uint32, pdu []byte) []byte {
	t.Helper()
	in := decipherDLPDU(t, ue, count, pdu)
	if in[2] != byte(nas.MsgTypeDLNASTransport) {
		t.Fatalf("inner=%x; want DL NAS TRANSPORT", in)
	}
	i := bytes.Index(in, []byte{0x2e})
	if i < 0 {
		t.Fatalf("no 5GSM payload in %x", in)
	}
	return in[i : i+5]
}

func TestInitiateRelease_ConnectedCause39(t *testing.T) {
	h, ue, s := restartHandler(t)
	if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 1, nas.Cause5GSMReactivationRequested); err != nil {
		t.Fatal(err)
	}
	_, _, rel, _, _ := s.snapshot()
	if len(rel) != 1 || rel[0] != 1 {
		t.Fatalf("NGAP release commands=%v; want [1]", rel)
	}
	// The same call again while the release is in flight: no second command.
	if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 1, nas.Cause5GSMReactivationRequested); err != nil {
		t.Fatal(err)
	}
	if _, _, rel, _, _ = s.snapshot(); len(rel) != 1 {
		t.Fatalf("second DELETE sent another release: %v", rel)
	}
	// Bytes of the Release Command: 2E psi PTI=0 D3 cause=0x27 (nothing on the wire
	// here because the fake drops the PDU; rebuild with the same helper).
	pdu, err := h.buildReleaseCommandPDU(ue, 1, nas.Cause5GSMReactivationRequested)
	if err != nil {
		t.Fatal(err)
	}
	got := releaseCmdBytes(t, ue, ue.SecurityCtx.DownlinkCount-1, pdu)
	if want := []byte{0x2e, 0x01, 0x00, 0xd3, 0x27}; !bytes.Equal(got, want) {
		t.Fatalf("release command=%x; want %x", got, want)
	}
}

func TestInitiateRelease_UnknownPSI(t *testing.T) {
	h, ue, _ := restartHandler(t)
	err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 9, nas.Cause5GSMReactivationRequested)
	if !errors.Is(err, ErrPDUSessionNotFound) {
		t.Fatalf("err=%v; want ErrPDUSessionNotFound", err)
	}
}

func TestInitiateRelease_IdleCause39PagesAndGuardReleases(t *testing.T) {
	h, ue, s := restartHandler(t)
	s.delDone = make(chan struct{}, 4)
	h.SetReleaseGuardsForTest(30*time.Millisecond, 0)
	ue.SetCMState(amfctx.CMIdle)

	for i := 0; i < 2; i++ { // second DELETE is idempotent: one paging only
		if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 1, nas.Cause5GSMReactivationRequested); err != nil {
			t.Fatal(err)
		}
	}
	if c, ok := ue.PendingSMReleaseCause(1); !ok || c != 39 {
		t.Fatalf("pending cause=%d ok=%v; want 39", c, ok)
	}
	dl, _, rel, _, _ := s.snapshot()
	if s.paged != 1 || len(rel) != 0 || len(dl) != 0 {
		t.Fatalf("paged=%d ngapRel=%v dl=%d; want 1/none/0", s.paged, rel, len(dl))
	}
	waitUntil(t, "paging guard expiry", func() bool { return !hasPSI(ue, 1) })
	if _, ok := ue.PendingSMReleaseCause(1); ok {
		t.Fatal("pending release survived the guard")
	}
	if dl, _, rel, _, dels := s.snapshot(); len(dl) != 0 || len(rel) != 0 || len(dels) != 1 || dels[0] != "sm-ctx-1" {
		t.Fatalf("after guard dl=%d ngapRel=%v dels=%v; want none and one delete of sm-ctx-1", len(dl), rel, dels)
	}
}

func TestInitiateRelease_IdleOtherCauseLocal(t *testing.T) {
	h, ue, s := restartHandler(t)
	ue.SetCMState(amfctx.CMIdle)
	if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 1, nas.Cause5GSMRegularDeactivation); err != nil {
		t.Fatal(err)
	}
	dl, _, rel, _, dels := s.snapshot()
	if s.paged != 0 || len(dl) != 0 || len(rel) != 0 {
		t.Fatalf("paged=%d dl=%d ngapRel=%v; want none", s.paged, len(dl), rel)
	}
	if hasPSI(ue, 1) || len(dels) != 1 {
		t.Fatalf("psi present=%v dels=%v; want removed + one delete", hasPSI(ue, 1), dels)
	}
}

// Service Request with a pending #39 PSI: never activated, Service Accept via
// ICS first, then the Release Command in a DL NAS Transport, T3592-guarded.
func TestServiceRequest_PendingReleaseDeliveredAfterAccept(t *testing.T) {
	h, ue, s := restartHandler(t)
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	ue.NASOnNewN2Connection = true
	ue.SetCMState(amfctx.CMIdle)
	if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 1, nas.Cause5GSMReactivationRequested); err != nil {
		t.Fatal(err)
	}
	count := ue.SecurityCtx.DownlinkCount

	body := srBodyULDS(u16(nas.PSIMask(1, 2)))
	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeServiceRequest, body)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "release command DL NAS Transport", func() bool { dl, _, _, _, _ := s.snapshot(); return len(dl) == 1 })
	dl, ics, rel, acts, _ := s.snapshot()
	if len(acts) != 1 || acts[0] != "sm-ctx-2" {
		t.Fatalf("activations=%v; want only sm-ctx-2 (pending PSI 1 never activated)", acts)
	}
	if len(ics) != 1 || len(rel) != 0 {
		t.Fatalf("ics=%d ngapRel=%v; want 1 ICS and no N2 release", len(ics), rel)
	}
	if got := releaseCmdBytes(t, ue, count+1, dl[0]); !bytes.Equal(got, []byte{0x2e, 0x01, 0x00, 0xd3, 0x27}) {
		t.Fatalf("release command=%x", got)
	}
	waitUntil(t, "pending cleared", func() bool { _, ok := ue.PendingSMReleaseCause(1); return !ok })
	if _, ok := h.pendingRelease.Load(pendingReleaseKey(ue.AMFUENGAPId, 1)); !ok {
		t.Fatal("T3592 guard (pendingRelease) not armed")
	}
	// UE confirms: SM context released (old ref, 404 tolerated) and PSI removed.
	h.completeNetworkPDUSessionRelease(context.Background(), ue, 1, "RELEASE_COMPLETE")
	if hasPSI(ue, 1) {
		t.Fatal("PSI still present after Release Complete")
	}
}

// 404 from the SMF for an old ref: not activated, #39 release follows the Accept;
// a transport error keeps the PSI and starts no release.
func TestServiceRequest_StaleRef(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantRelease bool
	}{
		{"404 restart orphan", fmt.Errorf("smf: status 404: %w", ErrSMContextNotFound), true},
		{"transport error", errors.New("dial tcp: connection refused"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, ue, s := restartHandler(t)
			s.actErr = tc.err
			ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
			ue.NASOnNewN2Connection = true
			ue.SetCMState(amfctx.CMIdle)
			if err := h.HandleNASMessage(context.Background(), ue,
				buildULSecuredPDU(t, ue, nas.MsgTypeServiceRequest, srBodyULDS(u16(nas.PSIMask(1))))); err != nil {
				t.Fatal(err)
			}
			if tc.wantRelease {
				waitUntil(t, "release command", func() bool { dl, _, _, _, _ := s.snapshot(); return len(dl) == 1 })
			} else {
				time.Sleep(50 * time.Millisecond)
			}
			dl, _, rel, _, _ := s.snapshot()
			if (len(dl) == 1) != tc.wantRelease || len(rel) != 0 {
				t.Fatalf("dl=%d ngapRel=%v; wantRelease=%v", len(dl), rel, tc.wantRelease)
			}
			if !hasPSI(ue, 1) {
				t.Fatal("PSI must be kept until the release completes")
			}
		})
	}
}

// A PSI the UE reports inactive is dropped, not commanded.
func TestServiceRequest_PendingPSIInactiveAtUEDropped(t *testing.T) {
	h, ue, s := restartHandler(t)
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	ue.NASOnNewN2Connection = true
	ue.SetCMState(amfctx.CMIdle)
	if err := h.InitiateNetworkPDUSessionRelease(context.Background(), ue, 1, nas.Cause5GSMReactivationRequested); err != nil {
		t.Fatal(err)
	}
	body := append(srBodyULDS(nil), nas.IEIPDUSessionStatus, 0x02, 0x00, 0x04) // only PSI 2 active
	if err := h.HandleNASMessage(context.Background(), ue,
		buildULSecuredPDU(t, ue, nas.MsgTypeServiceRequest, body)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if dl, _, _, _, _ := s.snapshot(); len(dl) != 0 {
		t.Fatalf("release command sent for a UE-inactive PSI: %d DL", len(dl))
	}
	if hasPSI(ue, 1) {
		t.Fatal("UE-inactive PSI not released locally")
	}
	if _, ok := ue.PendingSMReleaseCause(1); ok {
		t.Fatal("pending entry not dropped")
	}
}

func TestComplete_DeleteSMContext404IsInfo(t *testing.T) {
	h, ue, s := restartHandler(t)
	s.delErr = fmt.Errorf("smf: delete sm context: status 404: %w", ErrSMContextNotFound)
	var logs bytes.Buffer
	h.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	h.pendingRelease.Store(pendingReleaseKey(ue.AMFUENGAPId, 1), &pendingReleaseState{smContextRef: "sm-ctx-1"})
	h.completeNetworkPDUSessionRelease(context.Background(), ue, 1, "RELEASE_COMPLETE")
	if hasPSI(ue, 1) {
		t.Fatal("PSI not removed")
	}
	var info bool
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["level"] == "WARN" || rec["level"] == "ERROR" {
			t.Fatalf("unexpected %v record: %s", rec["level"], line)
		}
		if rec["cause"] == "ALREADY_RELEASED" && rec["level"] == "INFO" {
			info = true
		}
	}
	if !info {
		t.Fatalf("no INFO already-released record in %s", logs.String())
	}
}

func TestDeregistrationClearsPending(t *testing.T) {
	ue := pagedTestUE(1)
	ue.AddPendingSMRelease(1, 39)
	ue.ClearAllPendingSMReleases()
	if len(ue.PendingSMReleases()) != 0 {
		t.Fatal("pending not cleared")
	}
}
