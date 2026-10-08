package ngap

// n2_source_release_test.go — UEContextReleaseComplete from the source gNB after a
// completed N2 handover must not move the UE to CM-IDLE nor trigger an AN release.
// Ref: TS 23.502 §4.9.1.3.3; TS 38.413 §8.3.3

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

func newReleaseServer(t *testing.T, released *atomic.Int32) *Server {
	t.Helper()
	s := NewServer("", amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil), nil, AMFConfig{}, slog.Default())
	s.SetANReleaseHandler(func(_ context.Context, _ *amfctx.UEContext) { released.Add(1) })
	return s
}

func newReleaseGNB(addr string) *GNBContext {
	return &GNBContext{
		testAddr: addr,
		UEs:      map[int64]*amfctx.UEContext{},
		IdleUEs:  map[int64]*amfctx.UEContext{},
	}
}

func waitReleased(t *testing.T, ue *amfctx.UEContext, released *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for released.Load() < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // settle: a wrongly queued release must have run
}

func TestReleaseComplete_SourceAfterN2HO_StaysConnected(t *testing.T) {
	tests := []struct {
		name       string
		ueGNBAddr  string // serving gNB after migration
		ueRANID    int64
		relGNBAddr string // gNB that sent Release Complete
		relRANID   int64
	}{
		{"different gNB", "10.0.0.2:38412", 7, "10.0.0.1:38412", 3},
		{"same gNB, new RAN UE NGAP ID", "10.0.0.1:38412", 7, "10.0.0.1:38412", 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var released atomic.Int32
			s := newReleaseServer(t, &released)
			ue := s.mgr.AllocateUEContext(tc.ueRANID)
			ue.CMState = amfctx.CMConnected
			ue.UEAMBRSentToRAN = true
			ue.GNBAddr = tc.ueGNBAddr
			src := newReleaseGNB(tc.relGNBAddr)
			src.UEs[tc.relRANID] = ue

			s.handleUEContextReleaseComplete(context.Background(), src, &Message{
				Value: &UEContextReleaseCompleteMsg{AMFUENGAPId: ue.AMFUENGAPId, RANUENGAPId: tc.relRANID}})
			waitReleased(t, ue, &released, 1)

			if ue.CMState != amfctx.CMConnected {
				t.Fatalf("CMState = %v, want CM-CONNECTED", ue.CMState)
			}
			if !ue.UEAMBRSentToRAN {
				t.Fatal("UEAMBRSentToRAN reset")
			}
			if released.Load() != 0 {
				t.Fatalf("onANRelease invoked %d time(s)", released.Load())
			}
			if len(src.UEs) != 0 || len(src.IdleUEs) != 0 {
				t.Fatalf("source gNB still tracks UE: UEs=%d Idle=%d", len(src.UEs), len(src.IdleUEs))
			}
		})
	}
}

func TestReleaseComplete_NormalANRelease_GoesIdle(t *testing.T) {
	var released atomic.Int32
	s := newReleaseServer(t, &released)
	ue := s.mgr.AllocateUEContext(3)
	ue.CMState = amfctx.CMConnected
	ue.GNBAddr = "10.0.0.1:38412"
	g := newReleaseGNB("10.0.0.1:38412")
	g.UEs[3] = ue

	s.handleUEContextReleaseComplete(context.Background(), g, &Message{
		Value: &UEContextReleaseCompleteMsg{AMFUENGAPId: ue.AMFUENGAPId, RANUENGAPId: 3}})
	waitReleased(t, ue, &released, 1)

	if ue.CMState != amfctx.CMIdle {
		t.Fatalf("CMState = %v, want CM-IDLE", ue.CMState)
	}
	if released.Load() != 1 {
		t.Fatalf("onANRelease invoked %d time(s), want 1", released.Load())
	}
	if g.IdleUEs[3] != ue || len(g.UEs) != 0 {
		t.Fatal("UE not moved to IdleUEs")
	}
}

func TestReleaseComplete_Deregistration_RemovesContext(t *testing.T) {
	var released atomic.Int32
	s := newReleaseServer(t, &released)
	ue := s.mgr.AllocateUEContext(3)
	ue.CMState = amfctx.CMConnected
	ue.GNBAddr = "10.0.0.1:38412"
	ue.PendingRemoval = true
	g := newReleaseGNB("10.0.0.1:38412")
	g.UEs[3] = ue

	s.handleUEContextReleaseComplete(context.Background(), g, &Message{
		Value: &UEContextReleaseCompleteMsg{AMFUENGAPId: ue.AMFUENGAPId, RANUENGAPId: 3}})

	if _, ok := s.mgr.GetByNGAPId(ue.AMFUENGAPId); ok {
		t.Fatal("UE context not removed after deregistration release")
	}
	if released.Load() != 0 || len(g.IdleUEs) != 0 {
		t.Fatal("deregistration path must not AN-release nor keep the UE idle")
	}
}
