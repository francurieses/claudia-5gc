package ngap

// ics_failure_test.go - Initial Context Setup Failure handling per procedure kind
// (AMF-034, finding AUD-registration-05).
// Ref: TS 38.413 §8.3.1.3; TS 24.501 §5.5.1.2.8, §5.5.1.3.8 a); TS 23.502 §4.2.2.2.2

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// icsFixture is a server with one gNB, an SMF mock (records released SM context
// refs), a registration-abort mock and a counter of UE Context Release Commands.
// relayedFail is one PDU_RES_SETUP_FAIL relay seen by the SMF mock.
type relayedFail struct {
	Ref      string
	Transfer []byte
}

type icsFixture struct {
	s          *Server
	gnb        *GNBContext
	ue         *amfctx.UEContext
	mu         sync.Mutex
	smReleased []string
	relayed    []relayedFail
	abortProcs []string
	abortUEs   []*amfctx.UEContext
	abortCalls atomic.Int32
	n2Releases atomic.Int32
	anReleases atomic.Int32
}

func newICSFixture(t *testing.T) *icsFixture {
	t.Helper()
	f := &icsFixture{s: newRegAudServer(t)}
	const addr = "10.0.0.1:38412"
	f.gnb = newReleaseGNB(addr)
	f.gnb.SetTransportForTest(addr, func(pdu []byte, _ *sctp.SndRcvInfo) (int, error) {
		if len(pdu) > 1 && ProcedureCode(pdu[1]) == ProcUEContextRelease {
			f.n2Releases.Add(1)
		}
		return len(pdu), nil
	})
	f.s.gnbs[addr] = f.gnb
	f.s.SetPDUSessionSetupFailureHandler(func(_ context.Context, ref string) {
		f.mu.Lock()
		f.smReleased = append(f.smReleased, ref)
		f.mu.Unlock()
	})
	f.s.SetPDUSessionSetupFailRelayHandler(func(_ context.Context, ref string, tr []byte) {
		f.mu.Lock()
		f.relayed = append(f.relayed, relayedFail{ref, tr})
		f.mu.Unlock()
	})
	f.s.SetRegistrationAbortHandler(func(_ context.Context, ue *amfctx.UEContext, procedure string) {
		f.mu.Lock()
		f.abortProcs = append(f.abortProcs, procedure)
		f.abortUEs = append(f.abortUEs, ue)
		f.mu.Unlock()
		f.abortCalls.Add(1)
	})
	f.s.SetANReleaseHandler(func(context.Context, *amfctx.UEContext) { f.anReleases.Add(1) })
	f.ue = f.s.mgr.AllocateUEContext(7)
	f.ue.GNBAddr = addr
	f.s.mgr.SetSUPI(f.ue, "imsi-001010000000001")
	f.ue.CMState = amfctx.CMConnected
	f.gnb.UEs[7] = f.ue
	return f
}

func (f *icsFixture) addSessions(psis ...uint8) {
	for _, p := range psis {
		f.ue.PDUSessions[p] = &amfctx.PDUSession{PDUSessionID: p, SMFInstanceID: "sm-ctx-" + string('0'+rune(p))}
	}
}

func (f *icsFixture) relays() []relayedFail {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]relayedFail(nil), f.relayed...)
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

func (f *icsFixture) released() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.smReleased...)
	sort.Strings(out)
	return out
}

// fail drives the ICS FAILURE through the handler and waits for the UE serial
// queue and the async SMF relays to settle.
func (f *icsFixture) fail(failed ...uint8) {
	msg := regAudICSFailure(f.ue)
	fm := msg.Value.(*InitialContextSetupFailureMsg)
	fm.FailedPSIs = failed
	for range failed {
		fm.FailedTransfers = append(fm.FailedTransfers, []byte{0xA0, byte(len(fm.FailedTransfers))})
	}
	f.s.handleInitialContextSetupFailure(context.Background(), f.gnb, msg)
	deadline := time.Now().Add(time.Second)
	for f.n2Releases.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
}

func TestICSFailure_RegisteredUE_KeepsContextAndReleasesN2(t *testing.T) {
	tests := []struct {
		name string
		kind amfctx.ICSKind
		// acceptPending simulates a mobility / periodic update whose ACCEPT awaits COMPLETE.
		acceptPending bool
	}{
		{"service request", amfctx.ICSServiceRequest, false},
		{"mobility or periodic update", amfctx.ICSRegistrationUpdate, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newICSFixture(t)
			f.addSessions(5, 6)
			f.ue.TransitionTo(amfctx.GMMRegistered)
			tmsi := f.s.mgr.AssignGUTI(context.Background(), f.ue).TMSI
			if tc.acceptPending {
				f.ue.TransitionTo(amfctx.GMMCommonProcedureInitiated)
				f.ue.SetPendingAccept([]byte{0x7e}, true)
			}
			f.ue.SetPendingICS(tc.kind)

			f.fail(5)

			if f.ue.State != amfctx.GMMRegistered || f.ue.PendingRemoval {
				t.Fatalf("state=%s pendingRemoval=%v; want 5GMM-REGISTERED kept", f.ue.State, f.ue.PendingRemoval)
			}
			if f.ue.RegStage() != amfctx.RegStageNone {
				t.Fatal("T3550 / registration stage not cleared")
			}
			if got, ok := f.s.mgr.GetByTMSI(tmsi); !ok || got != f.ue {
				t.Fatal("5G-GUTI no longer resolves")
			}
			if got := f.released(); len(got) != 0 {
				t.Fatalf("SMF releases = %v; a registered UE's sessions are never released here (SMF decides)", got)
			}
			if got := f.relays(); len(got) != 1 || got[0].Ref != "sm-ctx-5" ||
				len(got[0].Transfer) != 2 || got[0].Transfer[0] != 0xA0 {
				t.Fatalf("PDU_RES_SETUP_FAIL relays = %+v, want the PSI 5 unsuccessful transfer", got)
			}
			if _, kept := f.ue.PDUSessions[5]; !kept {
				t.Fatal("failed PDU session 5 must stay in the UE context (the SMF decides)")
			}
			if _, kept := f.ue.PDUSessions[6]; !kept {
				t.Fatal("PDU session 6 (not failed) must stay for the AN-release deactivation")
			}
			if f.n2Releases.Load() != 1 {
				t.Fatalf("UE Context Release Commands = %d, want 1", f.n2Releases.Load())
			}
			if f.abortCalls.Load() != 0 {
				t.Fatal("registration abort cleanup must not run for a registered UE")
			}
			if f.ue.TakePendingICS() != amfctx.ICSNone {
				t.Fatal("pending ICS kind not cleared")
			}

			// The release completes through the normal AN-release path: CM-IDLE,
			// user plane deactivated at the SMF, context kept.
			f.s.handleUEContextReleaseComplete(context.Background(), f.gnb, &Message{
				Value: &UEContextReleaseCompleteMsg{AMFUENGAPId: f.ue.AMFUENGAPId, RANUENGAPId: 7}})
			time.Sleep(100 * time.Millisecond)
			if _, ok := f.s.mgr.GetByNGAPId(f.ue.AMFUENGAPId); !ok {
				t.Fatal("registered UE context removed at N2 release complete")
			}
			if f.ue.CMState != amfctx.CMIdle || f.anReleases.Load() != 1 {
				t.Fatalf("cm=%v anRelease calls=%d, want CM-IDLE and 1 deactivation callback", f.ue.CMState, f.anReleases.Load())
			}
		})
	}
}

func TestICSFailure_InitialRegistration_RemovesContextWithoutLeaks(t *testing.T) {
	f := newICSFixture(t)
	f.addSessions(5, 6, 7)
	f.ue.TransitionTo(amfctx.GMMCommonProcedureInitiated)
	f.ue.SetPendingAccept([]byte{0x7e}, false)
	f.ue.SetPendingICS(amfctx.ICSInitialRegistration)

	f.fail(5) // only PSI 5 reported failed; all three must still be released

	if f.ue.State != amfctx.GMMDeregistered || !f.ue.PendingRemoval {
		t.Fatalf("state=%s pendingRemoval=%v; want rollback", f.ue.State, f.ue.PendingRemoval)
	}
	want := []string{"sm-ctx-5", "sm-ctx-6", "sm-ctx-7"}
	got := f.released()
	if len(got) != len(want) {
		t.Fatalf("SMF releases = %v, want %v (leaked sessions)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SMF releases = %v, want %v", got, want)
		}
	}
	if len(f.ue.PDUSessions) != 0 {
		t.Fatalf("UE still holds %d PDU sessions", len(f.ue.PDUSessions))
	}
	if f.abortCalls.Load() != 1 {
		t.Fatalf("PCF/UDM cleanup calls = %d, want 1", f.abortCalls.Load())
	}
	f.mu.Lock()
	if f.abortProcs[0] != "InitialRegistration" || f.abortUEs[0] != f.ue {
		t.Fatalf("abort handler got procedure %q / UE %p", f.abortProcs[0], f.abortUEs[0])
	}
	f.mu.Unlock()
	if got := f.relays(); len(got) != 0 {
		t.Fatalf("rollback must release, not relay: %+v", got)
	}
	if f.n2Releases.Load() != 1 {
		t.Fatalf("UE Context Release Commands = %d, want 1", f.n2Releases.Load())
	}
	f.s.handleUEContextReleaseComplete(context.Background(), f.gnb, &Message{
		Value: &UEContextReleaseCompleteMsg{AMFUENGAPId: f.ue.AMFUENGAPId, RANUENGAPId: 7}})
	if _, ok := f.s.mgr.GetByNGAPId(f.ue.AMFUENGAPId); ok {
		t.Fatal("rolled-back registration context not removed at N2 release complete")
	}
	if f.anReleases.Load() != 0 {
		t.Fatal("no AN-release deactivation expected for a removed context")
	}
}

func TestExtractInitialContextSetupFailure_FailedList(t *testing.T) {
	in := &ngapType.InitialContextSetupFailure{}
	list := &ngapType.PDUSessionResourceFailedToSetupListCxtFail{List: []ngapType.PDUSessionResourceFailedToSetupItemCxtFail{
		{PDUSessionID: ngapType.PDUSessionID{Value: 5}, PDUSessionResourceSetupUnsuccessfulTransfer: []byte{0xAA, 0xBB}},
		{PDUSessionID: ngapType.PDUSessionID{Value: 9}, PDUSessionResourceSetupUnsuccessfulTransfer: []byte{0xCC}},
	}}
	in.ProtocolIEs.List = append(in.ProtocolIEs.List, ngapType.InitialContextSetupFailureIEs{
		Id:    ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListCxtFail},
		Value: ngapType.InitialContextSetupFailureIEsValue{PDUSessionResourceFailedToSetupListCxtFail: list},
	})
	out := extractInitialContextSetupFailure(in)
	if len(out.FailedPSIs) != 2 || out.FailedPSIs[0] != 5 || out.FailedPSIs[1] != 9 {
		t.Fatalf("FailedPSIs = %v, want [5 9]", out.FailedPSIs)
	}
	if len(out.FailedTransfers) != 2 || len(out.FailedTransfers[0]) != 2 || out.FailedTransfers[1][0] != 0xCC {
		t.Fatalf("FailedTransfers = %x", out.FailedTransfers)
	}
}

// TestICSFailure_AbsentKind: no recorded kind. A UE that never completed its
// registration is rolled back (with a Warn); a registered UE is kept.
func TestICSFailure_AbsentKind(t *testing.T) {
	t.Run("never registered -> rollback", func(t *testing.T) {
		f := newICSFixture(t)
		f.addSessions(5)
		f.ue.TransitionTo(amfctx.GMMCommonProcedureInitiated)
		f.fail(5) // no SetPendingICS: stale / absent kind
		if f.ue.State != amfctx.GMMDeregistered || !f.ue.PendingRemoval {
			t.Fatalf("state=%s pendingRemoval=%v; want rollback", f.ue.State, f.ue.PendingRemoval)
		}
		if got := f.released(); len(got) != 1 || f.abortCalls.Load() != 1 {
			t.Fatalf("releases=%v abort=%d; want 1 release + cleanup", got, f.abortCalls.Load())
		}
	})
	t.Run("registered -> kept", func(t *testing.T) {
		f := newICSFixture(t)
		f.addSessions(5)
		f.ue.TransitionTo(amfctx.GMMRegistered)
		f.fail(5)
		if f.ue.State != amfctx.GMMRegistered || f.ue.PendingRemoval {
			t.Fatalf("state=%s pendingRemoval=%v; want kept", f.ue.State, f.ue.PendingRemoval)
		}
		if f.abortCalls.Load() != 0 || len(f.released()) != 0 {
			t.Fatal("registered UE must not be cleaned up")
		}
	})
}
